//! The service-token admin API in `admin_tokens.rs`: create, list, get, rotate
//! and revoke, the actor each change records, and the requested-scope
//! delegation check (`authorize_requested_scopes`) a create or rotate passes
//! before anything is minted. Shared fixtures stay in `app_tests.rs`.
use super::*;

#[tokio::test]
async fn keyed_token_revocation_validates_and_reconciles_through_the_router() {
    let token_db = TempDb::new("keyed-token-revoke");
    let policy = TempPolicyFile::new(&token_policy_document_string());
    let router = token_admin_router(&token_db, &policy, test_audit_log());
    let mut owner = test_principal(&["superadmin"]);
    owner.issuer = Some("https://issuer.example.test".to_owned());
    let create = router
        .clone()
        .oneshot(token_admin_request(
            Method::POST,
            TOKENS_ADMIN_ROUTE,
            Some(owner.clone()),
            Some(json!({ "scopes": ["probe-reader"] }).to_string()),
        ))
        .await
        .unwrap();
    assert_eq!(create.status(), StatusCode::CREATED);
    let token = json_body(create).await;
    let id = token["token"]["id"].as_str().unwrap();
    let route = format!("{TOKENS_ADMIN_ROUTE}/{id}/revoke");
    let key = crate::auth::tokens::test_revoke_operation_id(1).to_string();
    let request = |path: &str, who: auth::Principal, keys: &[&str], body: Option<&str>| {
        let mut request =
            token_admin_request(Method::POST, path, Some(who), body.map(str::to_owned));
        for key in keys {
            request
                .headers_mut()
                .append("idempotency-key", key.parse().unwrap());
        }
        request
    };
    let mut precondition = request(&route, owner.clone(), &[&key], None);
    precondition
        .headers_mut()
        .insert(header::IF_MATCH, "*".parse().unwrap());
    let upper = "AAAAAAAA-AAAA-7AAA-8AAA-AAAAAAAAAAAA";
    for invalid in [
        request(&route, owner.clone(), &[], None),
        request(&route, owner.clone(), &[&key, &key], None),
        request(&route, owner.clone(), &["not-a-uuid"], None),
        request(
            &route,
            owner.clone(),
            &["00000000-0000-0000-0000-000000000000"],
            None,
        ),
        request(&route, owner.clone(), &[upper], None),
        request(&route, owner.clone(), &[&key], Some("{}")),
        request(&format!("{route}?revision=1"), owner.clone(), &[&key], None),
        precondition,
    ] {
        assert_eq!(
            router.clone().oneshot(invalid).await.unwrap().status(),
            StatusCode::BAD_REQUEST
        );
    }
    let denied = request(&route, test_principal(&["superadmin"]), &[&key], None);
    assert_eq!(
        router.clone().oneshot(denied).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    let mut not_writer = owner.clone();
    not_writer.roles.clear();
    let denied = request(&route, not_writer, &[&key], None);
    assert_eq!(
        router.clone().oneshot(denied).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    let first = router
        .clone()
        .oneshot(request(&route, owner.clone(), &[&key], None))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let replay = router
        .clone()
        .oneshot(request(&route, owner.clone(), &[&key], None))
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::OK);
    let receipt = json_body(first).await;
    assert_eq!(receipt["operation_id"], key);
    assert_eq!(receipt["token_id"], id);
    assert!(receipt["revoked_at"].is_string());
    assert_eq!(receipt.as_object().unwrap().len(), 3);
    assert_eq!(json_body(replay).await, receipt);
    let mut other = owner;
    other.issuer = Some("https://other.example.test".to_owned());
    let refused = router
        .oneshot(request(&route, other, &[&key], None))
        .await
        .unwrap();
    assert_eq!(refused.status(), StatusCode::CONFLICT);
    assert!(!body_string(refused).await.contains(&key));
}

#[tokio::test]
async fn token_create_rejects_scopes_the_creator_does_not_hold() {
    let token_db = TempDb::new("token-create-rejects-escalation");
    let policy = TempPolicyFile::new(&token_policy_document_string());
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
    let router = token_admin_router(&token_db, &policy, audit_log);

    let response = router
        .clone()
        .oneshot(token_admin_request(
            Method::POST,
            TOKENS_ADMIN_ROUTE,
            Some(test_principal(&["tokens-writer"])),
            Some(json!({ "scopes": ["token-admin"] }).to_string()),
        ))
        .await
        .expect("token create request should complete");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        body_string(response).await,
        r#"{"error":"requested scopes exceed creator authority: token-admin"}"#
    );

    let list_response = router
        .oneshot(token_admin_request(
            Method::GET,
            TOKENS_ADMIN_ROUTE,
            Some(test_principal(&["tokens-reader"])),
            None,
        ))
        .await
        .expect("token list request should complete");
    assert_eq!(list_response.status(), StatusCode::OK);
    assert_eq!(json_body(list_response).await["tokens"], json!([]));

    let event = captured_token_delegation_rejection(&capture);
    assert_token_change_actor(&event);
    assert!(!event.request_id.is_empty());
    assert_eq!(event.source_ip, "unknown");
    assert_eq!(event.payload["decision"], json!("deny"));
    assert_eq!(
        event.payload["reason"],
        json!("requested_scopes_exceed_creator_authority")
    );
    assert_eq!(event.payload["requested_scopes"], json!(["token-admin"]));
    assert_eq!(event.payload["disallowed_scopes"], json!(["token-admin"]));
    assert!(!capture
        .events()
        .iter()
        .any(|event| event.event_type == audit::event::SERVICE_TOKEN_CHANGED));
}

#[tokio::test]
async fn token_create_rejects_carried_role_inactive_for_creator_identity() {
    let token_db = TempDb::new("token-create-rejects-inactive-role");
    let policy = TempPolicyFile::new(&token_policy_document_string());
    let router = token_admin_router(&token_db, &policy, test_audit_log());

    let response = router
        .oneshot(token_admin_request(
            Method::POST,
            TOKENS_ADMIN_ROUTE,
            Some(test_principal(&["tokens-writer", "service-admin"])),
            Some(json!({ "scopes": ["service-admin"] }).to_string()),
        ))
        .await
        .expect("token create request should complete");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        body_string(response).await,
        r#"{"error":"requested scopes exceed creator authority: service-admin"}"#
    );
}

#[tokio::test]
async fn token_create_allows_wildcard_creator_to_delegate_any_scope() {
    let token_db = TempDb::new("token-create-wildcard-delegation");
    let policy = TempPolicyFile::new(&token_policy_document_string());
    let router = token_admin_router(&token_db, &policy, test_audit_log());

    let response = router
        .oneshot(token_admin_request(
            Method::POST,
            TOKENS_ADMIN_ROUTE,
            Some(test_principal(&["superadmin"])),
            Some(json!({ "scopes": ["some-narrow-role", "mcp:tools"] }).to_string()),
        ))
        .await
        .expect("wildcard token create request should complete");

    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        json_body(response).await["token"]["scopes"],
        json!(["some-narrow-role", "mcp:tools"])
    );
}

#[tokio::test]
async fn token_create_allows_scopes_within_creator_roles() {
    let token_db = TempDb::new("token-create-bounded-delegation");
    let policy = TempPolicyFile::new(&token_policy_document_string());
    let router = token_admin_router(&token_db, &policy, test_audit_log());

    let response = router
        .oneshot(token_admin_request(
            Method::POST,
            TOKENS_ADMIN_ROUTE,
            Some(test_principal(&["tokens-writer", "probe-reader"])),
            Some(json!({ "scopes": ["probe-reader"] }).to_string()),
        ))
        .await
        .expect("bounded token create request should complete");

    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        json_body(response).await["token"]["scopes"],
        json!(["probe-reader"])
    );
}

/// Exercise the same admin handler against both storage implementations.
/// Rejected rotation must preserve the record and the original credential.
async fn assert_token_rotation_delegation_contract(store: Arc<dyn storage::ServiceTokenStore>) {
    let mut policy_json: Value =
        serde_json::from_str(&token_policy_document_string()).expect("token policy should be JSON");
    policy_json["roles"]["issuer-admin"] = json!({
        "permissions": ["*"],
        "issuers": ["https://issuer.example.test/"]
    });
    let policy = parse_policy_body(&Bytes::from(policy_json.to_string()))
        .expect("token policy should parse");
    let config = test_config(Vec::new());

    for (roles, scopes, expected) in [
        (
            vec!["tokens-writer"],
            vec!["probe-reader"],
            StatusCode::FORBIDDEN,
        ),
        (
            vec!["tokens-writer", "unknown-role"],
            vec!["unknown-role"],
            StatusCode::FORBIDDEN,
        ),
        (
            vec!["tokens-writer", "service-admin"],
            vec!["service-admin"],
            StatusCode::FORBIDDEN,
        ),
        (
            vec!["tokens-writer", "issuer-admin"],
            vec!["issuer-admin"],
            StatusCode::FORBIDDEN,
        ),
        (
            vec!["probe-reader"],
            vec!["probe-reader"],
            StatusCode::FORBIDDEN,
        ),
        (
            vec!["tokens-writer", "probe-reader"],
            vec!["probe-reader"],
            StatusCode::OK,
        ),
        (
            vec!["superadmin"],
            vec!["unknown-role", "mcp:tools"],
            StatusCode::OK,
        ),
    ] {
        let created = store
            .create(
                auth::tokens::CreateTokenRequest {
                    scopes: scopes.iter().map(|scope| (*scope).to_owned()).collect(),
                    created_by: "bootstrap-admin".to_owned(),
                    expires_at: None,
                },
                &auth::change_actor::ChangeActor::for_test("bootstrap-admin"),
            )
            .await
            .expect("fixture token should create");
        let capture = audit::sink::tests::CaptureSink::new();
        let audit_log =
            audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
        let rbac_state =
            middleware::rbac::RbacState::new(policy.clone(), Vec::new(), false, audit_log.clone());
        let principal = test_principal(&roles);
        let can_manage =
            rbac_state.principal_has_permission(&principal, ADMIN_TOKENS_WRITE_PERMISSION);
        let state = TokenAdminState {
            store: Some(Arc::clone(&store)),
            validator: None,
            rbac_state: Some(rbac_state),
            authority_evidence: authority_events::required::AuthorityEvidenceGate::best_effort(),
            #[cfg(feature = "postgres")]
            membership: None,
            audit: audit_log,
            client_ip_policy: client_ip::ClientIpPolicy::from_config(&config),
            max_body_size: config.max_body_size,
        };
        let request = token_admin_request(
            Method::POST,
            &format!("{TOKENS_ADMIN_ROUTE}/{}/rotate", created.record.id),
            Some(principal),
            None,
        );
        let response =
            token_rotate_endpoint(State(state), Path(created.record.id.clone()), request).await;
        assert_eq!(
            response.status(),
            expected,
            "roles={roles:?}, scopes={scopes:?}"
        );

        if expected == StatusCode::FORBIDDEN {
            let body = json_body(response).await;
            assert!(body.get("plaintext_token").is_none());
            let unchanged = store
                .get_by_id(&created.record.id)
                .await
                .expect("stored token should read")
                .expect("denied rotation must retain the token");
            assert_eq!(unchanged, created.record);
            assert!(matches!(
                store
                    .verify(&created.plaintext_token)
                    .await
                    .expect("token should verify"),
                auth::tokens::TokenVerification::Valid(_)
            ));
            if can_manage {
                let event = captured_token_delegation_rejection(&capture);
                assert_eq!(event.payload["decision"], json!("deny"));
                assert_eq!(event.payload["requested_scopes"], json!(scopes));
                assert_eq!(event.payload["disallowed_scopes"], json!(scopes));
                let serialized = serde_json::to_string(&event).expect("audit should serialize");
                assert!(!serialized.contains(&created.plaintext_token));
                assert!(!serialized.contains("token_hash"));
            }
            assert!(!capture
                .events()
                .iter()
                .any(|event| { event.event_type == audit::event::SERVICE_TOKEN_CHANGED }));
        } else {
            let body = json_body(response).await;
            assert_eq!(body["token"]["id"], json!(created.record.id));
            assert_eq!(body["token"]["scopes"], json!(scopes));
            let plaintext = body["plaintext_token"]
                .as_str()
                .expect("allowed rotation returns the replacement credential");
            assert!(matches!(
                store
                    .verify(&created.plaintext_token)
                    .await
                    .expect("old token should check"),
                auth::tokens::TokenVerification::Invalid(_)
            ));
            assert!(matches!(
                store
                    .verify(plaintext)
                    .await
                    .expect("replacement should verify"),
                auth::tokens::TokenVerification::Valid(_)
            ));
            let event = captured_token_change(&capture, "token_rotated");
            let serialized = serde_json::to_string(&event).expect("audit should serialize");
            assert!(!serialized.contains(plaintext));
            assert!(!serialized.contains(&created.plaintext_token));
        }
    }
}

#[tokio::test]
async fn token_rotation_delegation_contract_sqlite() {
    let token_db = TempDb::new("token-rotation-delegation");
    let store =
        auth::tokens::SqliteTokenStore::open(&token_db.path).expect("token store should open");
    assert_token_rotation_delegation_contract(Arc::new(store)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn token_rotation_delegation_contract_postgres() {
    use storage::contract_tests::postgres_audit_tests::{
        create_test_database, locator, write_dsn_file, DATABASE,
    };

    let Some(admin_dsn) = locator() else {
        eprintln!("skipping PostgreSQL rotation contract: no test database locator");
        return;
    };
    let _serial = DATABASE.lock().await;
    let database = create_test_database(&admin_dsn).await;
    let dsn_file = write_dsn_file(&database.dsn);
    let mut config = config::Config::test_defaults();
    config.state_backend = config::StateBackend::Postgres;
    config.deployment_id = Some("deploy-token-rotation-contract".to_owned());
    config.database.url_file = Some(dsn_file.path.clone());
    storage::postgres::test_support::use_test_tls(&mut config.database);
    let foundation = storage::postgres::PostgresFoundation::establish(&config)
        .await
        .expect("test database should establish");
    storage::migrations::apply_missing_for_startup(foundation.pool(), &config.database)
        .await
        .expect("test database should migrate");
    let store =
        storage::postgres_service_tokens::PostgresServiceTokenStore::new(foundation.pool().clone());
    assert_token_rotation_delegation_contract(Arc::new(store)).await;
}

/// One service-token change evidence row as the admin endpoints' test reads
/// it: action, token, actor subject, actor issuer, actor kind, auth mode.
type TokenChangeActorRow = (
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
);

/// Issue #425: the admin rotate and revoke endpoints pass the authenticated
/// principal to the store, which records it -- subject, canonical issuer,
/// actor kind and auth mode -- as the change's evidence. Neither the token's
/// creator nor a fixed label stands in for it. A person signed in through
/// one provider rotates, a bearer principal from a second provider revokes
/// that token, and a service token revokes another; the rows the store
/// recorded are returned beside the evidence each should be.
async fn admin_token_changes_record_the_authenticated_actor(
    store: Arc<dyn storage::ServiceTokenStore>,
) -> Vec<TokenChangeActorRow> {
    let policy = parse_policy_body(&Bytes::from(token_policy_document_string()))
        .expect("token policy should parse");
    let config = test_config(Vec::new());
    let audit_log = test_audit_log();
    let state = TokenAdminState {
        store: Some(Arc::clone(&store)),
        validator: None,
        rbac_state: Some(middleware::rbac::RbacState::new(
            policy,
            Vec::new(),
            false,
            audit_log.clone(),
        )),
        authority_evidence: authority_events::required::AuthorityEvidenceGate::best_effort(),
        #[cfg(feature = "postgres")]
        membership: None,
        audit: audit_log,
        client_ip_policy: client_ip::ClientIpPolicy::from_config(&config),
        max_body_size: config.max_body_size,
    };
    let mut ids = Vec::new();
    for _ in 0..2 {
        ids.push(
            store
                .create(
                    auth::tokens::CreateTokenRequest {
                        scopes: vec!["probe-reader".to_owned()],
                        created_by: "bootstrap-admin".to_owned(),
                        expires_at: None,
                    },
                    &auth::change_actor::ChangeActor::for_test("bootstrap-admin"),
                )
                .await
                .expect("fixture token should create")
                .record
                .id,
        );
    }
    let principal = |user_id: &str, issuer: Option<&str>, auth_method| auth::Principal {
        user_id: user_id.to_owned(),
        issuer: issuer.map(str::to_owned),
        auth_method,
        ..test_principal(&["superadmin"])
    };

    let rotated = token_rotate_endpoint(
        State(state.clone()),
        Path(ids[0].clone()),
        token_admin_request(
            Method::POST,
            &format!("{TOKENS_ADMIN_ROUTE}/{}/rotate", ids[0]),
            Some(principal(
                "rotating-admin",
                Some(" https://idp.example.test/ "),
                auth::AuthMethod::Cookie,
            )),
            None,
        ),
    )
    .await;
    assert_eq!(rotated.status(), StatusCode::OK);
    for (id, actor) in [
        (
            &ids[0],
            principal(
                "revoking-admin",
                Some("https://other-idp.example.test"),
                auth::AuthMethod::Bearer,
            ),
        ),
        (
            &ids[1],
            principal(
                "service-token:token_admin",
                None,
                auth::AuthMethod::ServiceToken,
            ),
        ),
    ] {
        let revoked = token_revoke_endpoint(
            State(state.clone()),
            Path(id.clone()),
            token_admin_request(
                Method::DELETE,
                &format!("{TOKENS_ADMIN_ROUTE}/{id}"),
                Some(actor),
                None,
            ),
        )
        .await;
        assert_eq!(revoked.status(), StatusCode::OK);
    }

    let owned = |value: &str| value.to_owned();
    let issued = |id: &String| {
        (
            owned("service_token.issue"),
            id.clone(),
            owned("bootstrap-admin"),
            None,
            Some(owned("principal")),
            Some(owned("bearer_token")),
        )
    };
    vec![
        // The fixture tokens' issues come first, then the changes.
        issued(&ids[0]),
        issued(&ids[1]),
        (
            owned("service_token.rotate"),
            ids[0].clone(),
            owned("rotating-admin"),
            Some(owned("https://idp.example.test")),
            Some(owned("principal")),
            Some(owned("session_cookie")),
        ),
        (
            owned("service_token.revoke"),
            ids[0].clone(),
            owned("revoking-admin"),
            Some(owned("https://other-idp.example.test")),
            Some(owned("principal")),
            Some(owned("bearer_token")),
        ),
        (
            owned("service_token.revoke"),
            ids[1].clone(),
            owned("service-token:token_admin"),
            None,
            Some(owned("service_token")),
            Some(owned("service_token")),
        ),
    ]
}

#[tokio::test]
async fn admin_token_rotate_and_revoke_record_the_authenticated_subject_and_issuer_sqlite() {
    let token_db = TempDb::new("token-change-actor-evidence");
    let store =
        auth::tokens::SqliteTokenStore::open(&token_db.path).expect("token store should open");
    let expected = admin_token_changes_record_the_authenticated_actor(Arc::new(store)).await;
    let connection = Connection::open(&token_db.path).expect("token database should open");
    let mut statement = connection
        .prepare(
            "SELECT action, token_id, actor_user_id, actor_issuer, actor_kind, actor_auth_mode \
             FROM service_token_change_evidence ORDER BY sequence",
        )
        .expect("evidence query should prepare");
    let recorded = statement
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        })
        .expect("evidence query should run")
        .collect::<Result<Vec<TokenChangeActorRow>, _>>()
        .expect("evidence rows should decode");
    assert_eq!(recorded, expected);
}

#[cfg(feature = "postgres")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_token_rotate_and_revoke_record_the_authenticated_subject_and_issuer_postgres() {
    use storage::contract_tests::postgres_audit_tests::{
        create_test_database, locator, write_dsn_file, DATABASE,
    };

    let Some(admin_dsn) = locator() else {
        eprintln!("skipping PostgreSQL change-actor evidence: no test database locator");
        return;
    };
    let _serial = DATABASE.lock().await;
    let database = create_test_database(&admin_dsn).await;
    let dsn_file = write_dsn_file(&database.dsn);
    let mut config = config::Config::test_defaults();
    config.state_backend = config::StateBackend::Postgres;
    config.deployment_id = Some("deploy-token-change-actor".to_owned());
    config.database.url_file = Some(dsn_file.path.clone());
    storage::postgres::test_support::use_test_tls(&mut config.database);
    let foundation = storage::postgres::PostgresFoundation::establish(&config)
        .await
        .expect("test database should establish");
    storage::migrations::apply_missing_for_startup(foundation.pool(), &config.database)
        .await
        .expect("test database should migrate");
    let store =
        storage::postgres_service_tokens::PostgresServiceTokenStore::new(foundation.pool().clone());
    let expected = admin_token_changes_record_the_authenticated_actor(Arc::new(store)).await;
    let recorded = foundation
        .pool()
        .get()
        .await
        .expect("evidence checkout")
        .query(
            "SELECT action, token_id, actor_user_id, actor_issuer, actor_kind, actor_auth_mode \
             FROM greengateway.service_token_change_evidence \
             ORDER BY security_revision",
            &[],
        )
        .await
        .expect("evidence rows should read")
        .iter()
        .map(|row| {
            (
                row.get(0),
                row.get(1),
                row.get(2),
                row.get(3),
                row.get(4),
                row.get(5),
            )
        })
        .collect::<Vec<TokenChangeActorRow>>();
    assert_eq!(recorded, expected);
}

/// What the admin create endpoint should have recorded, and the plaintexts
/// its responses returned, which no evidence row may hold.
struct IssuedThroughTheEndpoint {
    expected: Vec<TokenChangeActorRow>,
    plaintexts: Vec<String>,
}

/// Issue #425: the admin create endpoint passes the authenticated principal
/// to the store, which records it -- subject, canonical issuer, actor kind
/// and auth mode -- as the issue's evidence in the create's own transaction,
/// beside the token row's `created_by`. A person signed in through a provider
/// issues one token and a service token another.
async fn admin_token_create_records_the_authenticated_actor(
    store: Arc<dyn storage::ServiceTokenStore>,
) -> IssuedThroughTheEndpoint {
    let policy = parse_policy_body(&Bytes::from(token_policy_document_string()))
        .expect("token policy should parse");
    let config = test_config(Vec::new());
    let audit_log = test_audit_log();
    let state = TokenAdminState {
        store: Some(store),
        validator: None,
        rbac_state: Some(middleware::rbac::RbacState::new(
            policy,
            Vec::new(),
            false,
            audit_log.clone(),
        )),
        authority_evidence: authority_events::required::AuthorityEvidenceGate::best_effort(),
        #[cfg(feature = "postgres")]
        membership: None,
        audit: audit_log,
        client_ip_policy: client_ip::ClientIpPolicy::from_config(&config),
        max_body_size: config.max_body_size,
    };
    let principal = |user_id: &str, issuer: Option<&str>, auth_method| auth::Principal {
        user_id: user_id.to_owned(),
        issuer: issuer.map(str::to_owned),
        auth_method,
        ..test_principal(&["superadmin"])
    };
    let owned = |value: &str| value.to_owned();
    let mut issued = IssuedThroughTheEndpoint {
        expected: Vec::new(),
        plaintexts: Vec::new(),
    };
    for (actor, issuer, kind, auth_mode) in [
        (
            principal(
                "issuing-admin",
                Some(" https://idp.example.test/ "),
                auth::AuthMethod::Cookie,
            ),
            Some("https://idp.example.test"),
            "principal",
            "session_cookie",
        ),
        (
            principal(
                "service-token:token_issuer",
                None,
                auth::AuthMethod::ServiceToken,
            ),
            None,
            "service_token",
            "service_token",
        ),
    ] {
        let subject = actor.user_id.clone();
        let response = token_create_endpoint(
            State(state.clone()),
            token_admin_request(
                Method::POST,
                TOKENS_ADMIN_ROUTE,
                Some(actor),
                Some(json!({ "scopes": ["probe-reader"] }).to_string()),
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let body = json_body(response).await;
        assert_eq!(
            body["token"]["created_by"],
            json!(subject),
            "the token row still names its creator"
        );
        let id = body["token"]["id"]
            .as_str()
            .expect("the created token carries its id")
            .to_owned();
        issued.plaintexts.push(
            body["plaintext_token"]
                .as_str()
                .expect("the create returns the plaintext once")
                .to_owned(),
        );
        issued.expected.push((
            owned("service_token.issue"),
            id,
            subject,
            issuer.map(owned),
            Some(owned(kind)),
            Some(owned(auth_mode)),
        ));
    }
    issued
}

/// The evidence the create endpoint left is exactly the expected rows, and
/// no stored column holds a plaintext the responses returned or its hash.
fn assert_issue_evidence(
    issued: &IssuedThroughTheEndpoint,
    recorded: &[TokenChangeActorRow],
    stored: &str,
) {
    assert_eq!(recorded, issued.expected.as_slice());
    for plaintext in &issued.plaintexts {
        assert!(
            !stored.contains(plaintext.as_str()),
            "plaintext in evidence"
        );
        assert!(
            !stored.contains(auth::tokens::hash_token(plaintext).as_str()),
            "token hash in evidence"
        );
    }
    assert!(!stored.contains("ggw_"), "no display prefix: {stored}");
}

#[tokio::test]
async fn admin_token_create_records_the_authenticated_actor_as_issue_evidence_sqlite() {
    let token_db = TempDb::new("token-issue-actor-evidence");
    let store =
        auth::tokens::SqliteTokenStore::open(&token_db.path).expect("token store should open");
    let issued = admin_token_create_records_the_authenticated_actor(Arc::new(store)).await;
    let connection = Connection::open(&token_db.path).expect("token database should open");
    let mut statement = connection
        .prepare(
            "SELECT action, token_id, actor_user_id, actor_issuer, actor_kind, actor_auth_mode, \
                    event_id, operation_id, committed_at \
             FROM service_token_change_evidence ORDER BY sequence",
        )
        .expect("evidence query should prepare");
    let mut stored = String::new();
    let recorded = statement
        .query_map([], |row| {
            for index in 6..9 {
                stored.push_str(&row.get::<_, String>(index)?);
                stored.push('|');
            }
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        })
        .expect("evidence query should run")
        .collect::<Result<Vec<TokenChangeActorRow>, _>>()
        .expect("evidence rows should decode");
    for row in &recorded {
        stored.push_str(&format!("{row:?}"));
    }
    assert_issue_evidence(&issued, &recorded, &stored);
}

#[cfg(feature = "postgres")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_token_create_records_the_authenticated_actor_as_issue_evidence_postgres() {
    use storage::contract_tests::postgres_audit_tests::{
        create_test_database, locator, write_dsn_file, DATABASE,
    };

    let Some(admin_dsn) = locator() else {
        eprintln!("skipping PostgreSQL issue-actor evidence: no test database locator");
        return;
    };
    let _serial = DATABASE.lock().await;
    let database = create_test_database(&admin_dsn).await;
    let dsn_file = write_dsn_file(&database.dsn);
    let mut config = config::Config::test_defaults();
    config.state_backend = config::StateBackend::Postgres;
    config.deployment_id = Some("deploy-token-issue-actor".to_owned());
    config.database.url_file = Some(dsn_file.path.clone());
    config.database.tls_mode = config::DatabaseTlsMode::LoopbackDev;
    let foundation = storage::postgres::PostgresFoundation::establish(&config)
        .await
        .expect("test database should establish");
    storage::migrations::apply_missing_for_startup(foundation.pool(), &config.database)
        .await
        .expect("test database should migrate");
    let store =
        storage::postgres_service_tokens::PostgresServiceTokenStore::new(foundation.pool().clone());
    let issued = admin_token_create_records_the_authenticated_actor(Arc::new(store)).await;
    let client = foundation.pool().get().await.expect("evidence checkout");
    let recorded = client
        .query(
            "SELECT action, token_id, actor_user_id, actor_issuer, actor_kind, actor_auth_mode \
             FROM greengateway.service_token_change_evidence \
             ORDER BY security_revision",
            &[],
        )
        .await
        .expect("evidence rows should read")
        .iter()
        .map(|row| {
            (
                row.get(0),
                row.get(1),
                row.get(2),
                row.get(3),
                row.get(4),
                row.get(5),
            )
        })
        .collect::<Vec<TokenChangeActorRow>>();
    let stored = client
        .query(
            "SELECT row_to_json(t)::text FROM greengateway.service_token_change_evidence t",
            &[],
        )
        .await
        .expect("evidence text should read")
        .iter()
        .map(|row| row.get::<_, String>(0))
        .collect::<Vec<_>>()
        .join("\n");
    assert_issue_evidence(&issued, &recorded, &stored);
    // Each issue is journaled for delivery in its own transaction.
    let journaled: i64 = client
        .query_one(
            "SELECT count(*) FROM greengateway.authority_event_journal j \
             JOIN greengateway.service_token_change_evidence e USING (event_id) \
             WHERE e.action = 'service_token.issue'",
            &[],
        )
        .await
        .expect("the journal reads")
        .get(0);
    assert_eq!(journaled, 2);
}

/// Pins the narrowed create mapping restored from the #340 review: a
/// malformed `expires_at` is a `400` naming the field, because it is the
/// one invalid-input case the caller controls on create.
/// An oversized scope list is refused before the store (and before
/// delegation is judged): the bound is the client's error, never the
/// store's check constraint surfacing as a `500`.
#[tokio::test]
async fn token_create_with_an_oversized_scope_list_is_a_bad_request() {
    let token_db = TempDb::new("token-create-oversized-scopes");
    let policy = TempPolicyFile::new(&token_policy_document_string());
    let router = token_admin_router(&token_db, &policy, test_audit_log());
    let scopes = (0..3_000)
        .map(|index| format!("probe-reader-{index:0>40}"))
        .collect::<Vec<_>>();

    let response = router
        .oneshot(token_admin_request(
            Method::POST,
            TOKENS_ADMIN_ROUTE,
            Some(test_principal(&["tokens-writer", "probe-reader"])),
            Some(json!({ "scopes": scopes }).to_string()),
        ))
        .await
        .expect("oversized-scopes create request should complete");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body_string(response).await,
        r#"{"error":"service-token scopes exceed the maximum serialized size"}"#
    );
}

/// Scopes become roles at authentication, so a scope list the validator would
/// refuse is refused when written -- before delegation is judged, which is why
/// an unheld 257-byte scope is a `400` here and not a `403`.
#[tokio::test]
async fn token_create_with_scopes_outside_the_role_bounds_is_a_bad_request() {
    for (index, (scopes, expected)) in [
        (
            json!(["probe-reader", ""]),
            r#"{"error":"service-token scopes out of bounds: an empty role"}"#,
        ),
        (
            json!(["r".repeat(auth::principal::MAX_PRINCIPAL_ROLE_BYTES + 1)]),
            r#"{"error":"service-token scopes out of bounds: a role longer than 256 bytes"}"#,
        ),
        (
            json!((0..=auth::principal::MAX_PRINCIPAL_ROLES)
                .map(|index| format!("probe-reader-{index}"))
                .collect::<Vec<_>>()),
            r#"{"error":"service-token scopes out of bounds: more than 256 roles"}"#,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let token_db = TempDb::new(&format!("token-create-scope-bounds-{index}"));
        let policy = TempPolicyFile::new(&token_policy_document_string());
        let router = token_admin_router(&token_db, &policy, test_audit_log());

        let response = router
            .oneshot(token_admin_request(
                Method::POST,
                TOKENS_ADMIN_ROUTE,
                Some(test_principal(&["tokens-writer", "probe-reader"])),
                Some(json!({ "scopes": scopes }).to_string()),
            ))
            .await
            .expect("out-of-bounds scopes create request should complete");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{expected}");
        assert_eq!(body_string(response).await, expected);
    }
}

/// Scopes are immutable through rotation, so a record outside the principal
/// bounds -- written before the bound existed -- would be re-minted into a
/// credential authentication refuses on first use. Rotation refuses instead,
/// leaves the record untouched, and audits nothing as changed.
#[tokio::test]
async fn token_rotate_of_a_record_with_scopes_outside_the_role_bounds_is_a_conflict() {
    let token_db = TempDb::new("token-rotate-scope-bounds");
    let policy = TempPolicyFile::new(&token_policy_document_string());
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
    let router = token_admin_router(&token_db, &policy, audit_log);
    let store =
        auth::tokens::SqliteTokenStore::open(&token_db.path).expect("token store should open");
    // The store does not judge scopes; this is a record from before the bound.
    let created = store
        .create(
            auth::tokens::CreateTokenRequest {
                scopes: vec!["probe-reader".to_owned(), String::new()],
                created_by: "bootstrap-admin".to_owned(),
                expires_at: None,
            },
            &auth::change_actor::ChangeActor::for_test("bootstrap-admin"),
        )
        .expect("fixture token should create");

    let rotated = router
        .oneshot(token_admin_request(
            Method::POST,
            &format!("{TOKENS_ADMIN_ROUTE}/{}/rotate", created.record.id),
            Some(test_principal(&["superadmin"])),
            None,
        ))
        .await
        .expect("rotate request should complete");

    assert_eq!(rotated.status(), StatusCode::CONFLICT);
    assert_eq!(
        body_string(rotated).await,
        r#"{"error":"cannot rotate service token whose scopes are out of bounds: an empty role; revoke it and create a new token"}"#
    );
    let unchanged = store
        .get_by_id(&created.record.id)
        .expect("stored token should read")
        .expect("refused rotation must retain the token");
    assert_eq!(unchanged, created.record);
    assert!(!capture
        .events()
        .iter()
        .any(|event| event.event_type == audit::event::SERVICE_TOKEN_CHANGED));
}

#[tokio::test]
async fn token_create_with_malformed_expires_at_is_a_bad_request() {
    let token_db = TempDb::new("token-create-malformed-expires-at");
    let policy = TempPolicyFile::new(&token_policy_document_string());
    let router = token_admin_router(&token_db, &policy, test_audit_log());

    let response = router
        .oneshot(token_admin_request(
            Method::POST,
            TOKENS_ADMIN_ROUTE,
            Some(test_principal(&["tokens-writer", "probe-reader"])),
            Some(
                json!({ "scopes": ["probe-reader"], "expires_at": "not-a-timestamp" }).to_string(),
            ),
        ))
        .await
        .expect("malformed-expires-at create request should complete");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body_string(response).await,
        r#"{"error":"invalid service-token expires_at timestamp"}"#
    );
}

/// Pins the one `409` the token store can reach: rotating a revoked
/// token. Every other conflict must fall through to the shared responder.
#[tokio::test]
async fn token_rotate_of_a_revoked_token_is_a_conflict() {
    let token_db = TempDb::new("token-rotate-revoked-conflict");
    let policy = TempPolicyFile::new(&token_policy_document_string());
    let router = token_admin_router(&token_db, &policy, test_audit_log());

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
    let token = json_body(created).await["token"].clone();
    let token_id = token["id"]
        .as_str()
        .expect("created token record carries an id")
        .to_owned();

    let revoked = router
        .clone()
        .oneshot(token_admin_request(
            Method::DELETE,
            &format!("{TOKENS_ADMIN_ROUTE}/{token_id}"),
            Some(test_principal(&["tokens-writer"])),
            None,
        ))
        .await
        .expect("token revoke request should complete");
    assert_eq!(revoked.status(), StatusCode::OK);

    let rotated = router
        .oneshot(token_admin_request(
            Method::POST,
            &format!("{TOKENS_ADMIN_ROUTE}/{token_id}/rotate"),
            Some(test_principal(&["tokens-writer", "probe-reader"])),
            None,
        ))
        .await
        .expect("rotate-of-revoked request should complete");
    assert_eq!(rotated.status(), StatusCode::CONFLICT);
    assert_eq!(
        body_string(rotated).await,
        r#"{"error":"cannot rotate revoked service token"}"#
    );
}

/// The shared responder must not translate a `Conflict` from a non-rotate
/// operation into `409`: before #340 only the revoked-token rejection of
/// rotate answered `409`, and the blanket translation the async-contract
/// refactor introduced would have answered a store-level uniqueness
/// violation with "cannot rotate revoked service token" on an endpoint
/// that never rotated anything.
#[test]
fn non_rotate_store_conflicts_are_internal_errors() {
    let response = token_store_error_response(storage::RepositoryError::new(
        storage::RepositoryErrorKind::Conflict,
        "service_token_create",
    ));

    assert_eq!(
        response.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "a create-path conflict is a store failure, not a rotate-revoked 409"
    );
}

#[test]
fn requested_scope_authorization_enforces_subset_and_wildcard_delegation() {
    let policy = parse_policy_body(&Bytes::from(token_policy_document_string()))
        .expect("token policy should parse");
    let rbac_state = middleware::rbac::RbacState::new(policy, Vec::new(), false, test_audit_log());

    assert_eq!(
        authorize_requested_scopes(
            &rbac_state,
            &test_principal(&["tokens-writer", "probe-reader"]),
            &["probe-reader".to_owned()],
        ),
        Ok(())
    );

    let error = authorize_requested_scopes(
        &rbac_state,
        &test_principal(&["tokens-writer"]),
        &["token-admin".to_owned(), "mcp:tools".to_owned()],
    )
    .expect_err("creator must not delegate roles it does not carry");
    assert_eq!(
        error,
        TokenScopeAuthzError {
            disallowed: vec!["token-admin".to_owned(), "mcp:tools".to_owned()]
        }
    );

    let error = authorize_requested_scopes(
        &rbac_state,
        &test_principal(&["tokens-writer", "unknown-future-role"]),
        &["unknown-future-role".to_owned()],
    )
    .expect_err("unknown roles must not become delegatable by carrying their name");
    assert_eq!(
        error,
        TokenScopeAuthzError {
            disallowed: vec!["unknown-future-role".to_owned()]
        }
    );

    assert_eq!(
        authorize_requested_scopes(
            &rbac_state,
            &test_principal(&["superadmin"]),
            &["unknown-future-role".to_owned(), "mcp:tools".to_owned()],
        ),
        Ok(())
    );
}

#[tokio::test]
async fn token_admin_create_list_get_require_permissions_and_never_list_secret_material() {
    let token_db = TempDb::new("token-admin-create-list");
    let policy = TempPolicyFile::new(&token_policy_document_string());
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
    let router = token_admin_router(&token_db, &policy, audit_log);

    let forbidden_create = router
        .clone()
        .oneshot(token_admin_request(
            Method::POST,
            TOKENS_ADMIN_ROUTE,
            Some(test_principal(&["tokens-reader"])),
            Some(json!({ "scopes": ["probe-reader"] }).to_string()),
        ))
        .await
        .expect("read-only token create request should complete");
    assert_eq!(forbidden_create.status(), StatusCode::FORBIDDEN);

    let create_response = router
        .clone()
        .oneshot(token_admin_request(
            Method::POST,
            TOKENS_ADMIN_ROUTE,
            Some(test_principal(&["tokens-writer", "probe-reader"])),
            Some(
                json!({
                    "scopes": ["tokens-writer", "probe-reader"],
                    "expires_at": "2099-01-01T00:00:00Z"
                })
                .to_string(),
            ),
        ))
        .await
        .expect("token create request should complete");
    assert_eq!(create_response.status(), StatusCode::CREATED);
    let create_body = json_body(create_response).await;
    let plaintext = create_body["plaintext_token"]
        .as_str()
        .expect("created response should include one-time plaintext token")
        .to_owned();
    assert!(plaintext.starts_with("ggw_"));
    assert!(create_body["plaintext_token_notice"]
        .as_str()
        .unwrap_or_default()
        .contains("will not be shown again"));
    let token_id = create_body["token"]["id"]
        .as_str()
        .expect("created response should include token id")
        .to_owned();
    assert_eq!(
        create_body["token"]["scopes"],
        json!(["tokens-writer", "probe-reader"])
    );
    let create_serialized = serde_json::to_string(&create_body).unwrap();
    assert!(!create_serialized.contains("token_hash"));

    let forbidden_list = router
        .clone()
        .oneshot(token_admin_request(
            Method::GET,
            TOKENS_ADMIN_ROUTE,
            Some(test_principal(&["tokens-writer"])),
            None,
        ))
        .await
        .expect("write-only token list request should complete");
    assert_eq!(forbidden_list.status(), StatusCode::FORBIDDEN);

    let list_response = router
        .clone()
        .oneshot(token_admin_request(
            Method::GET,
            TOKENS_ADMIN_ROUTE,
            Some(test_principal(&["tokens-reader"])),
            None,
        ))
        .await
        .expect("token list request should complete");
    assert_eq!(list_response.status(), StatusCode::OK);
    let list_body = json_body(list_response).await;
    assert_eq!(list_body["tokens"][0]["id"], json!(token_id));
    let list_serialized = serde_json::to_string(&list_body).unwrap();
    assert!(!list_serialized.contains(&plaintext));
    assert!(!list_serialized.contains("plaintext_token"));
    assert!(!list_serialized.contains("token_hash"));

    let get_missing = router
        .clone()
        .oneshot(token_admin_request(
            Method::GET,
            &format!("{TOKENS_ADMIN_ROUTE}/missing"),
            Some(test_principal(&["tokens-reader"])),
            None,
        ))
        .await
        .expect("missing token get request should complete");
    assert_eq!(get_missing.status(), StatusCode::NOT_FOUND);

    let get_response = router
        .clone()
        .oneshot(token_admin_request(
            Method::GET,
            &format!("{TOKENS_ADMIN_ROUTE}/{token_id}"),
            Some(test_principal(&["tokens-reader"])),
            None,
        ))
        .await
        .expect("token get request should complete");
    assert_eq!(get_response.status(), StatusCode::OK);
    let get_body = json_body(get_response).await;
    assert_eq!(get_body["id"], json!(token_id));
    let get_serialized = serde_json::to_string(&get_body).unwrap();
    assert!(!get_serialized.contains(&plaintext));
    assert!(!get_serialized.contains("plaintext_token"));
    assert!(!get_serialized.contains("token_hash"));

    let event = captured_token_change(&capture, "token_created");
    assert_token_change_actor(&event);
    assert_eq!(event.payload["action"], json!("token_created"));
    assert_eq!(event.payload["token_id"], json!(token_id));
    assert_eq!(
        event.payload["scopes"],
        json!(["tokens-writer", "probe-reader"])
    );
    let audit_serialized = serde_json::to_string(&event).unwrap();
    assert!(!audit_serialized.contains(&plaintext));
    assert!(!audit_serialized.contains("token_hash"));
}

#[tokio::test]
async fn token_admin_mutation_with_real_jwt_persists_audit_actor_identity() {
    let jwks_addr = spawn_test_jwks_server().await;
    let token_db = TempDb::new("token-admin-real-jwt-audit-token");
    let audit_db = TempDb::new("token-admin-real-jwt-audit-log");
    let policy = TempPolicyFile::new(&token_audit_full_stack_policy_document_string());
    let mut config = test_config(Vec::new());
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    config.service_token_sqlite_path = Some(token_db.path.to_string_lossy().into_owned());
    config.audit_sqlite_path = Some(audit_db.path.to_string_lossy().into_owned());
    config.egress_deny_private_ips = false;
    configure_test_jwt_provider(&mut config, jwks_addr);
    let recorder = PrometheusBuilder::new().build_recorder();
    let (audit_log, audit_event_sender) =
        audit::AuditLog::from_config(&config).expect("audit log should build");
    let router =
        app(config, recorder.handle(), audit_log, audit_event_sender).expect("app should build");
    let token = signed_token("sso-admin", &["admin"]);

    let create_response = router
        .clone()
        .oneshot(bearer_json_request(
            Method::POST,
            TOKENS_ADMIN_ROUTE,
            &token,
            json!({ "scopes": ["admin"] }).to_string(),
        ))
        .await
        .expect("token create request should complete");
    assert_eq!(create_response.status(), StatusCode::CREATED);

    let event = wait_for_bearer_audit_event(
        &router,
        &format!(
            "{AUDIT_ADMIN_ROUTE}?event_type={}",
            audit::event::SERVICE_TOKEN_CHANGED
        ),
        &token,
        |event| event["payload"]["action"] == json!("token_created"),
    )
    .await;
    let actor = event["actor"]
        .as_object()
        .expect("service token audit event should include actor");

    assert_eq!(actor["user_id"], json!("sso-admin"));
    assert_eq!(actor["email"], json!("sso-admin@example.test"));
    assert_eq!(actor["roles"], json!(["admin"]));
    assert_eq!(actor["auth_mode"], json!("bearer_token"));
}

#[tokio::test]
async fn token_admin_revoke_is_idempotent_requires_write_and_audits() {
    let token_db = TempDb::new("token-admin-revoke");
    let policy = TempPolicyFile::new(&token_policy_document_string());
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
    let router = token_admin_router(&token_db, &policy, audit_log);
    let created = create_token_via_endpoint(&router, &["probe-reader"]).await;
    let token_id = created["token"]["id"]
        .as_str()
        .expect("created response should include token id")
        .to_owned();

    let forbidden_revoke = router
        .clone()
        .oneshot(token_admin_request(
            Method::DELETE,
            &format!("{TOKENS_ADMIN_ROUTE}/{token_id}"),
            Some(test_principal(&["tokens-reader"])),
            None,
        ))
        .await
        .expect("read-only token revoke request should complete");
    assert_eq!(forbidden_revoke.status(), StatusCode::FORBIDDEN);

    let first = router
        .clone()
        .oneshot(token_admin_request(
            Method::DELETE,
            &format!("{TOKENS_ADMIN_ROUTE}/{token_id}"),
            Some(test_principal(&["tokens-writer"])),
            None,
        ))
        .await
        .expect("token revoke request should complete");
    assert_eq!(first.status(), StatusCode::OK);
    let first_body = json_body(first).await;
    let first_revoked_at = first_body["revoked_at"]
        .as_str()
        .expect("revoked token should include revoked_at")
        .to_owned();

    let second = router
        .clone()
        .oneshot(token_admin_request(
            Method::DELETE,
            &format!("{TOKENS_ADMIN_ROUTE}/{token_id}"),
            Some(test_principal(&["tokens-writer"])),
            None,
        ))
        .await
        .expect("second token revoke request should complete");
    assert_eq!(second.status(), StatusCode::OK);
    assert_eq!(
        json_body(second).await["revoked_at"],
        json!(first_revoked_at)
    );

    let event = captured_token_change(&capture, "token_revoked");
    assert_token_change_actor(&event);
    assert_eq!(event.payload["action"], json!("token_revoked"));
    assert_eq!(event.payload["token_id"], json!(token_id));
}

#[tokio::test]
async fn token_admin_rotate_returns_new_plaintext_and_invalidates_old_bearer() {
    let token_db = TempDb::new("token-admin-rotate");
    let token_store =
        auth::tokens::SqliteTokenStore::open(&token_db.path).expect("token store should open");
    let created = token_store
        .create(
            auth::tokens::CreateTokenRequest {
                scopes: vec!["token-admin".to_owned(), "probe-reader".to_owned()],
                created_by: "bootstrap-admin".to_owned(),
                expires_at: None,
            },
            &auth::change_actor::ChangeActor::for_test("bootstrap-admin"),
        )
        .expect("service token should create");
    let policy = TempPolicyFile::new(&service_token_policy_document());
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
    let mut config = test_config(Vec::new());
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    config.service_token_sqlite_path = Some(token_db.path.to_string_lossy().into_owned());
    config.service_token_cache_ttl_ms = 5_000;
    config.rbac_exempt_paths.push(TOKENS_ADMIN_ROUTE.to_owned());
    let recorder = PrometheusBuilder::new().build_recorder();
    let router = app(
        config,
        recorder.handle(),
        audit_log,
        test_audit_event_sender(),
    )
    .expect("app should build");

    let before_rotate = authenticated_principal_probe(&router, &created.plaintext_token).await;
    assert_eq!(before_rotate.status(), StatusCode::OK);

    let rotate_response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("{TOKENS_ADMIN_ROUTE}/{}/rotate", created.record.id))
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {}", created.plaintext_token),
                )
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::empty())
                .expect("rotate request should build"),
        )
        .await
        .expect("token rotate request should complete");
    assert_eq!(rotate_response.status(), StatusCode::OK);
    let rotate_body = json_body(rotate_response).await;
    let new_plaintext = rotate_body["plaintext_token"]
        .as_str()
        .expect("rotate response should include new one-time plaintext")
        .to_owned();
    assert_ne!(new_plaintext, created.plaintext_token);
    assert!(rotate_body["plaintext_token_notice"]
        .as_str()
        .unwrap_or_default()
        .contains("will not be shown again"));

    let old_probe = authenticated_principal_probe(&router, &created.plaintext_token).await;
    assert_eq!(old_probe.status(), StatusCode::UNAUTHORIZED);
    let new_probe = authenticated_principal_probe(&router, &new_plaintext).await;
    assert_eq!(new_probe.status(), StatusCode::OK);

    let event = captured_token_change(&capture, "token_rotated");
    let actor = event.actor.as_ref().expect("rotate actor should be set");
    assert_eq!(
        actor.user_id,
        format!("service-token:{}", created.record.id)
    );
    assert_eq!(actor.auth_mode, "service_token");
    assert_eq!(event.payload["action"], json!("token_rotated"));
    assert_eq!(event.payload["token_id"], json!(created.record.id));
    let audit_serialized = serde_json::to_string(&event).unwrap();
    assert!(!audit_serialized.contains(&created.plaintext_token));
    assert!(!audit_serialized.contains(&new_plaintext));
    assert!(!audit_serialized.contains("token_hash"));
}

async fn create_token_via_endpoint(router: &Router, scopes: &[&str]) -> Value {
    let creator_roles = std::iter::once("tokens-writer")
        .chain(scopes.iter().copied())
        .collect::<Vec<_>>();
    let response = router
        .clone()
        .oneshot(token_admin_request(
            Method::POST,
            TOKENS_ADMIN_ROUTE,
            Some(test_principal(&creator_roles)),
            Some(json!({ "scopes": scopes }).to_string()),
        ))
        .await
        .expect("token create request should complete");
    assert_eq!(response.status(), StatusCode::CREATED);
    json_body(response).await
}

fn token_audit_full_stack_policy_document_string() -> String {
    json!({
        "schema_version": "0.1.0",
        "id": "token-audit-full-stack-policy",
        "default_action": "deny",
        "enforcement_mode": "enforce",
        "roles": {
            "admin": {
                "permissions": [
                    ADMIN_TOKENS_WRITE_PERMISSION,
                    ADMIN_AUDIT_READ_PERMISSION
                ]
            }
        },
        "routes": [
            {
                "methods": ["POST"],
                "path_prefix": TOKENS_ADMIN_ROUTE,
                "permission": ADMIN_TOKENS_WRITE_PERMISSION
            },
            {
                "methods": ["GET"],
                "path_prefix": AUDIT_ADMIN_ROUTE,
                "permission": ADMIN_AUDIT_READ_PERMISSION
            }
        ]
    })
    .to_string()
}

fn captured_token_change(
    capture: &audit::sink::tests::CaptureSink,
    action: &str,
) -> audit::AuditEvent {
    assert_eventually(Duration::from_secs(1), || {
        capture.events().iter().any(|event| {
            event.event_type == audit::event::SERVICE_TOKEN_CHANGED
                && event.payload["action"] == json!(action)
        })
    });

    capture
        .events()
        .into_iter()
        .find(|event| {
            event.event_type == audit::event::SERVICE_TOKEN_CHANGED
                && event.payload["action"] == json!(action)
        })
        .expect("service_token.changed event should be captured")
}

fn captured_token_delegation_rejection(
    capture: &audit::sink::tests::CaptureSink,
) -> audit::AuditEvent {
    assert_eventually(Duration::from_secs(1), || {
        capture
            .events()
            .iter()
            .any(|event| event.event_type == audit::event::SERVICE_TOKEN_DELEGATION_REJECTED)
    });

    capture
        .events()
        .into_iter()
        .find(|event| event.event_type == audit::event::SERVICE_TOKEN_DELEGATION_REJECTED)
        .expect("service_token.delegation_rejected event should be captured")
}

fn assert_token_change_actor(event: &audit::AuditEvent) {
    let actor = event.actor.as_ref().expect("actor should be set");
    assert_eq!(actor.user_id, "user-123");
    assert_eq!(actor.auth_mode, "bearer_token");
}

async fn wait_for_bearer_audit_event(
    router: &Router,
    uri: &str,
    token: &str,
    predicate: impl Fn(&Value) -> bool,
) -> Value {
    let started = Instant::now();

    loop {
        let response = router
            .clone()
            .oneshot(bearer_get_request(uri, token))
            .await
            .expect("bearer audit query request should complete");
        let status = response.status();
        if status != StatusCode::OK {
            panic!(
                "bearer audit query returned {status}: {}",
                body_string(response).await
            );
        }
        let body = json_body(response).await;
        if let Some(event) = body["events"]
            .as_array()
            .expect("events should be an array")
            .iter()
            .find(|event| predicate(event))
        {
            return event.clone();
        }

        assert!(
            started.elapsed() < Duration::from_secs(2),
            "bearer audit query did not return matching event: {body}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

// --- keyed service-token issue and rotation (issue #425, plan P5) ----------

/// A provider-authenticated principal with a canonical issuer and `roles`.
fn keyed_token_admin(roles: &[&str]) -> auth::Principal {
    let mut principal = test_principal(roles);
    principal.issuer = Some("https://issuer.example.test".to_owned());
    principal
}

/// A gateway service token holding `roles`.
fn service_token_caller(roles: &[&str]) -> auth::Principal {
    let mut principal = test_principal(roles);
    principal.auth_method = auth::AuthMethod::ServiceToken;
    principal
}

fn token_key(seed: u8) -> String {
    crate::authority_events::caller_operation::test_caller_key(seed).to_string()
}

/// A token admin request carrying `key` as its `Idempotency-Key`.
fn keyed_token_admin_request(
    method: Method,
    uri: &str,
    principal: auth::Principal,
    body: Option<String>,
    key: Option<&str>,
) -> Request<Body> {
    let mut request = token_admin_request(method, uri, Some(principal), body);
    if let Some(key) = key {
        request
            .headers_mut()
            .insert("idempotency-key", key.parse().expect("the key is a header"));
    }
    request
}

/// The status, `Cache-Control` and JSON body of one request.
async fn token_exchange(
    router: &Router,
    request: Request<Body>,
) -> (StatusCode, Option<String>, Value) {
    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("the request completes");
    let status = response.status();
    let cache_control = response
        .headers()
        .get(header::CACHE_CONTROL)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    (status, cache_control, json_body(response).await)
}

/// A standalone token router over `token_db`, with the token admin policy.
fn keyed_token_router(
    token_db: &TempDb,
    policy: &TempPolicyFile,
    audit_log: audit::AuditLog,
    configure: impl FnOnce(&mut config::Config),
) -> Router {
    let mut config = test_config(Vec::new());
    config.auth_enabled = false;
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    config.service_token_sqlite_path = Some(token_db.path.to_string_lossy().into_owned());
    config.rbac_exempt_paths.push(TOKENS_ADMIN_ROUTE.to_owned());
    config.rate_limit_write_burst = 1_000;
    configure(&mut config);
    let recorder = PrometheusBuilder::new().build_recorder();
    app(
        config,
        recorder.handle(),
        audit_log,
        test_audit_event_sender(),
    )
    .expect("app should build")
}

/// Required mode with every delivery criterion a keyed change needs: the
/// negotiated format and the file sink at `events`.
fn keyed_token_required(config: &mut config::Config, events: &TempDb) {
    config.authority_events.durability = config::AuthorityEvidenceDurability::Required;
    config.authority_events.format = config::AuthorityEventFormat::QualifiedV1;
    config.authority_events.sink =
        config::AuthorityEventSinkSetting::File(events.path.to_string_lossy().into_owned());
}

/// Every reservation in a standalone token database.
fn token_reservations(path: &std::path::Path) -> Vec<(String, String, Option<String>)> {
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

/// Every evidence row's (operation ID, action, token ID), in commit order.
fn token_evidence(path: &std::path::Path) -> Vec<(String, String, String)> {
    let connection = rusqlite::Connection::open(path).expect("the database opens");
    let mut statement = connection
        .prepare(
            "SELECT operation_id, action, token_id \
             FROM service_token_change_evidence ORDER BY sequence",
        )
        .expect("the evidence query prepares");
    statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .expect("the evidence reads")
        .collect::<Result<_, _>>()
        .expect("every evidence row reads")
}

/// How many `service_token.changed` events with `action` were delivered.
fn token_changes(capture: &audit::sink::tests::CaptureSink, action: &str) -> usize {
    capture
        .events()
        .iter()
        .filter(|event| {
            event.event_type == audit::event::SERVICE_TOKEN_CHANGED
                && event.payload["action"] == json!(action)
        })
        .count()
}

/// An exact retry of a keyed issue or rotation is answered `200` with the
/// receipt read from the committed evidence and `secret_returned: false`,
/// never the plaintext, and repeats no side effect: no second token, no
/// second evidence row and no second audit event. The binding is the
/// request whatever its whitespace or key order; any other use of the key
/// is `409 caller_operation_conflict`. A caller without the route's
/// permission is `403` before its key is consulted. The token a receipt
/// names can be revoked by its ID.
#[tokio::test]
async fn a_replayed_token_issue_or_rotation_repeats_no_side_effect_and_never_returns_the_plaintext()
{
    // Every log line the handlers write, at every level, on this thread
    // (where the current-thread runtime runs them).
    let (logs, _logging) = capture_all_logs();
    let token_db = TempDb::new("keyed-token-replay");
    let policy = TempPolicyFile::new(&token_policy_document_string());
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
    let router = keyed_token_router(&token_db, &policy, audit_log, |_| {});
    let admin = keyed_token_admin(&["superadmin"]);
    let issue_key = token_key(1);
    let issue = |body: &str, key: &str| {
        keyed_token_admin_request(
            Method::POST,
            TOKENS_ADMIN_ROUTE,
            admin.clone(),
            Some(body.to_owned()),
            Some(key),
        )
    };
    let body = json!({ "scopes": ["probe-reader"] }).to_string();

    let (status, _, created) = token_exchange(&router, issue(&body, &issue_key)).await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let id = created["token"]["id"].as_str().expect("an ID").to_owned();
    let plaintext = created["plaintext_token"]
        .as_str()
        .expect("the first response carries the plaintext")
        .to_owned();

    // The exact retry, and the same request spelled differently.
    let reordered = "{ \"expires_at\" : null,\n \"scopes\" : [ \"probe-reader\" ] }";
    let mut receipts = Vec::new();
    for retry in [body.as_str(), reordered] {
        let (status, cache_control, receipt) =
            token_exchange(&router, issue(retry, &issue_key)).await;
        assert_eq!(status, StatusCode::OK, "{receipt}");
        assert_eq!(cache_control.as_deref(), Some("no-store"));
        receipts.push(receipt);
    }
    assert_eq!(receipts[0], receipts[1]);
    let receipt = &receipts[0];
    assert_eq!(receipt["operation_id"], json!(issue_key));
    assert_eq!(receipt["operation"], json!("service_token.issue"));
    assert_eq!(receipt["resource_id"], json!(id));
    assert_eq!(receipt["revision"], json!(1));
    assert_eq!(receipt["secret_returned"], json!(false));
    assert!(receipt["committed_at"].is_string());
    assert_eq!(
        receipt.as_object().expect("an object").len(),
        6,
        "{receipt}"
    );
    assert!(
        !receipt.to_string().contains(&plaintext),
        "never the plaintext"
    );

    // The same key with another request is a conflict and changes nothing.
    let (status, _, conflict) = token_exchange(
        &router,
        issue(
            &json!({ "scopes": ["tokens-reader"] }).to_string(),
            &issue_key,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{conflict}");
    assert_eq!(conflict["reason"], json!("caller_operation_conflict"));

    // A keyed rotation, its retry and its conflicts.
    let rotate_route = format!("{TOKENS_ADMIN_ROUTE}/{id}/rotate");
    let rotate_key = token_key(2);
    let rotate = |route: &str, key: &str| {
        keyed_token_admin_request(Method::POST, route, admin.clone(), None, Some(key))
    };
    let (status, _, rotated) = token_exchange(&router, rotate(&rotate_route, &rotate_key)).await;
    assert_eq!(status, StatusCode::OK, "{rotated}");
    let rotated_plaintext = rotated["plaintext_token"]
        .as_str()
        .expect("the first rotation carries the plaintext")
        .to_owned();
    let (status, cache_control, rotation_receipt) =
        token_exchange(&router, rotate(&rotate_route, &rotate_key)).await;
    assert_eq!(status, StatusCode::OK, "{rotation_receipt}");
    assert_eq!(cache_control.as_deref(), Some("no-store"));
    assert_eq!(rotation_receipt["operation"], json!("service_token.rotate"));
    assert_eq!(rotation_receipt["resource_id"], json!(id));
    assert_eq!(rotation_receipt["revision"], json!(2));
    assert_eq!(rotation_receipt["secret_returned"], json!(false));
    assert_eq!(rotation_receipt.get("plaintext_token"), None);
    // The retry rotated nothing again: the first rotation's plaintext is live.
    let store = auth::SqliteTokenStore::open(&token_db.path).expect("the store opens");
    assert!(matches!(
        auth::tokens::TokenStore::verify(&store, &rotated_plaintext).expect("verifies"),
        auth::tokens::TokenVerification::Valid(_)
    ));

    let (status, _, other) = token_exchange(
        &router,
        token_admin_request(
            Method::POST,
            TOKENS_ADMIN_ROUTE,
            Some(admin.clone()),
            Some(body.clone()),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let other_route = format!(
        "{TOKENS_ADMIN_ROUTE}/{}/rotate",
        other["token"]["id"].as_str().expect("an ID")
    );
    for (route, key) in [(&other_route, &rotate_key), (&rotate_route, &issue_key)] {
        let (status, _, conflict) = token_exchange(&router, rotate(route, key)).await;
        assert_eq!(status, StatusCode::CONFLICT, "{route}: {conflict}");
        assert_eq!(conflict["reason"], json!("caller_operation_conflict"));
    }

    // Authorization comes before the key: a reader is refused `403` with a
    // key already committed (a handler that consulted the key first would
    // answer it) and with a new one, and nothing is reserved.
    let reservations = token_reservations(&token_db.path);
    let reader = keyed_token_admin(&["tokens-reader", "probe-reader"]);
    for (request, what) in [
        (
            keyed_token_admin_request(
                Method::POST,
                TOKENS_ADMIN_ROUTE,
                reader.clone(),
                Some(body.clone()),
                Some(&issue_key),
            ),
            "a committed issue key",
        ),
        (
            keyed_token_admin_request(
                Method::POST,
                TOKENS_ADMIN_ROUTE,
                reader.clone(),
                Some(body.clone()),
                Some(&token_key(3)),
            ),
            "a new issue key",
        ),
        (
            keyed_token_admin_request(
                Method::POST,
                &rotate_route,
                reader.clone(),
                None,
                Some(&rotate_key),
            ),
            "a committed rotation key",
        ),
    ] {
        let (status, _, refused) = token_exchange(&router, request).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{what}: {refused}");
    }
    assert_eq!(token_reservations(&token_db.path), reservations);

    // What a caller whose issue response was lost does: revoke the token the
    // receipt names, by its ID.
    let (status, _, revoked) = token_exchange(
        &router,
        token_admin_request(
            Method::DELETE,
            &format!(
                "{TOKENS_ADMIN_ROUTE}/{}",
                receipt["resource_id"].as_str().unwrap()
            ),
            Some(admin.clone()),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{revoked}");
    assert!(revoked["revoked_at"].is_string());
    assert!(matches!(
        auth::tokens::TokenStore::verify(&store, &rotated_plaintext).expect("verifies"),
        auth::tokens::TokenVerification::Invalid(auth::tokens::TokenVerificationFailure::Revoked)
    ));

    // One change, one evidence row and one audit event each; the keyed ones
    // are reserved, exactly.
    let evidence = token_evidence(&token_db.path);
    assert_eq!(
        evidence
            .iter()
            .map(|(_, action, _)| action.as_str())
            .collect::<Vec<_>>(),
        [
            "service_token.issue",
            "service_token.rotate",
            "service_token.issue",
            "service_token.revoke"
        ]
    );
    assert_eq!(evidence[0].0, issue_key);
    assert_eq!(evidence[1].0, rotate_key);
    let reserved: Vec<_> = token_reservations(&token_db.path)
        .into_iter()
        .map(|(id, action, digest)| {
            assert!(digest.is_some(), "a bound key keeps its digest");
            (id, action)
        })
        .collect();
    let mut keyed = vec![
        (issue_key.clone(), "service_token.issue".to_owned()),
        (rotate_key.clone(), "service_token.rotate".to_owned()),
    ];
    keyed.sort();
    assert_eq!(reserved, keyed);
    assert_eventually(Duration::from_secs(5), || {
        token_changes(&capture, "token_revoked") == 1
    });
    assert_eq!(token_changes(&capture, "token_created"), 2);
    assert_eq!(token_changes(&capture, "token_rotated"), 1);
    let audited = serde_json::to_string(&capture.events()).expect("events serialize");
    let digests: Vec<String> = token_reservations(&token_db.path)
        .into_iter()
        .map(|reservation| reservation.2.expect("a digest"))
        .collect();
    for digest in &digests {
        assert!(!audited.contains(digest), "no digest in the audit stream");
    }

    // A reservation that cannot be written fails the keyed issue with a
    // server error and mints nothing (test-only fault injection through a
    // second connection).
    rusqlite::Connection::open(&token_db.path)
        .expect("the database opens")
        .execute_batch(
            "CREATE TRIGGER fail_caller_key_reservation \
             BEFORE INSERT ON authority_caller_operation_ids \
             BEGIN SELECT RAISE(ABORT, 'injected reservation failure'); END;",
        )
        .expect("the fault installs");
    let (status, _, failed) = token_exchange(&router, issue(&body, &token_key(4))).await;
    assert!(status.is_server_error(), "{status}: {failed}");
    assert_eq!(token_evidence(&token_db.path).len(), evidence.len());

    // Neither plaintext nor any binding digest reached a log line: the
    // keyed issue, rotation, replays, conflicts, refusals and the failed
    // reservation above all logged through these handlers.
    let logged = logs.contents();
    assert!(!logged.is_empty(), "the handlers logged");
    for marker in [plaintext.as_str(), rotated_plaintext.as_str()]
        .into_iter()
        .chain(digests.iter().map(String::as_str))
    {
        assert!(!logged.contains(marker), "a secret marker reached the logs");
    }
}

#[derive(Clone, Default)]
pub(super) struct CapturedLogs {
    buffer: Arc<std::sync::Mutex<Vec<u8>>>,
}

impl CapturedLogs {
    pub(super) fn contents(&self) -> String {
        String::from_utf8_lossy(&self.buffer.lock().expect("captured logs lock")).into_owned()
    }
}

impl std::io::Write for CapturedLogs {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.buffer
            .lock()
            .map_err(|_| std::io::Error::other("captured logs lock poisoned"))?
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedLogs {
    type Writer = CapturedLogs;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Every level on this thread, so a debug line that carried a plaintext or
/// a digest would show.
pub(super) fn capture_all_logs() -> (CapturedLogs, impl Drop) {
    let logs = CapturedLogs::default();
    let subscriber = trace_subscriber(logs.clone());
    (logs, crate::tracing_test_guard(subscriber))
}

/// Every level, written to `logs`.
fn trace_subscriber(logs: CapturedLogs) -> impl tracing::Subscriber + Send + Sync + 'static {
    tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(logs)
        .finish()
}

/// Runs `test` on a current-thread runtime with [`capture_all_logs`] and a
/// Prometheus recorder installed on every thread that runtime uses: the
/// test's own thread and each thread of its blocking pool, where the SQLite
/// stores and the Connection handlers' store calls run (`spawn_blocking`).
/// A thread-local subscriber or recorder on the test thread alone misses a
/// log line or a metric emitted there. Returns `test`'s output, every
/// captured log line and the metrics rendered after the runtime has ended.
///
/// What it captures is `tracing` events on the runtime's threads. It does
/// not capture `log`-crate records from dependencies (production bridges
/// those into its subscriber through `tracing-log`; this capture installs no
/// global logger), nor events on threads the code under test spawns itself,
/// such as the audit log writer.
///
/// `tracing` caches whether a callsite is enabled process-wide. While only
/// one dispatcher is registered, a callsite first reached on a thread with
/// no subscriber (a sibling test's) is cached as never enabled, and this
/// capture would then skip that line silently. A second TRACE dispatcher
/// is kept registered for the whole capture, so every callsite registered
/// meanwhile consults a TRACE subscriber and stays enabled. The capture
/// checks itself: one line, through a callsite first reached on a thread
/// with no subscriber, must be captured on the test thread before the test
/// starts and on the blocking pool after it ends.
pub(super) fn capture_logs_and_metrics_on_every_runtime_thread<T>(
    test: impl std::future::Future<Output = T>,
) -> (T, String, String) {
    let logs = CapturedLogs::default();
    let _second_dispatcher = tracing::Dispatch::new(trace_subscriber(logs.clone()));
    let _logging = crate::tracing_test_guard(trace_subscriber(logs.clone()));
    std::thread::spawn(|| capture_sentinel("a thread with no subscriber"))
        .join()
        .expect("the sentinel thread ends");
    // Leaked so that each blocking-pool thread can keep it as its default
    // recorder for the rest of the thread's life.
    let recorder: &'static metrics_exporter_prometheus::PrometheusRecorder =
        Box::leak(Box::new(PrometheusBuilder::new().build_recorder()));
    let pool_logs = logs.clone();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .on_thread_start(move || {
            // Both stay installed until the thread ends, which is no later
            // than the runtime's shutdown below.
            std::mem::forget(tracing::subscriber::set_default(trace_subscriber(
                pool_logs.clone(),
            )));
            std::mem::forget(::metrics::set_default_local_recorder(recorder));
        })
        .build()
        .expect("the test runtime builds");
    let output = ::metrics::with_local_recorder(recorder, || {
        runtime.block_on(async {
            // Before any blocking-pool thread starts: each one registers a
            // dispatcher, which re-evaluates every callsite and would mask
            // a callsite cached as never enabled.
            capture_sentinel("test thread");
            let output = test.await;
            tokio::task::spawn_blocking(|| capture_sentinel("blocking pool"))
                .await
                .expect("the sentinel task ends");
            output
        })
    });
    runtime.shutdown_timeout(Duration::from_secs(5));
    let logged = logs.contents();
    for place in ["test thread", "blocking pool"] {
        assert!(
            logged.contains(&format!("capture sentinel on the {place}")),
            "the capture missed a log line on the {place}"
        );
    }
    (output, logged, recorder.handle().render())
}

/// The one callsite of the capture's self-check.
fn capture_sentinel(place: &str) {
    tracing::trace!("capture sentinel on the {place}");
}

/// The capture sees a log line and a metric emitted on the blocking pool,
/// where the SQLite stores run, as well as on the test thread.
#[test]
fn the_capture_sees_logs_and_metrics_on_the_blocking_pool() {
    let ((), logged, rendered) = capture_logs_and_metrics_on_every_runtime_thread(async {
        ::metrics::counter!("capture_test_thread_total").increment(1);
        tokio::task::spawn_blocking(|| {
            tracing::trace!("capture-check-pool-line");
            ::metrics::counter!("capture_test_pool_total").increment(1);
        })
        .await
        .expect("the pool task ends");
    });
    assert!(logged.contains("capture-check-pool-line"), "{logged}");
    for metric in ["capture_test_thread_total 1", "capture_test_pool_total 1"] {
        assert!(rendered.lines().any(|line| line == metric), "{rendered}");
    }
}

/// I4 end to end: under `required`, the unkeyed issue and rotation are
/// refused before anything is written, and the keyed request of an
/// issuer-bound principal under `qualified_v1` with the file sink is
/// admitted.
#[tokio::test]
#[cfg_attr(
    not(unix),
    ignore = "required mode admits keyed token changes only on a Unix build, where the file sink syncs its directory"
)]
async fn required_mode_refuses_the_unkeyed_token_issue_and_rotation_and_admits_the_keyed_principal()
{
    let token_db = TempDb::new("keyed-token-required");
    let events = TempDb::new("keyed-token-required-events");
    let policy = TempPolicyFile::new(&token_policy_document_string());
    let router = keyed_token_router(&token_db, &policy, test_audit_log(), |config| {
        keyed_token_required(config, &events)
    });
    let admin = keyed_token_admin(&["superadmin"]);
    let body = json!({ "scopes": ["probe-reader"] }).to_string();
    let (status, _, refused) = token_exchange(
        &router,
        keyed_token_admin_request(
            Method::POST,
            TOKENS_ADMIN_ROUTE,
            admin.clone(),
            Some(body.clone()),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{refused}");
    assert_eq!(refused["reason"], json!("authority_evidence_unsupported"));
    assert_eq!(
        refused["error"],
        json!("AUTHORITY_EVIDENCE_DURABILITY=required refuses service_token.issue: standalone mode admits it only with an Idempotency-Key, on a route that honours one; nothing was changed")
    );
    assert!(token_evidence(&token_db.path).is_empty());

    let (status, _, created) = token_exchange(
        &router,
        keyed_token_admin_request(
            Method::POST,
            TOKENS_ADMIN_ROUTE,
            admin.clone(),
            Some(body),
            Some(&token_key(20)),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let route = format!(
        "{TOKENS_ADMIN_ROUTE}/{}/rotate",
        created["token"]["id"].as_str().expect("an ID")
    );
    let (status, _, refused) = token_exchange(
        &router,
        keyed_token_admin_request(Method::POST, &route, admin.clone(), None, None),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{refused}");
    assert_eq!(refused["operation"], json!("service_token.rotate"));
    let (status, _, rotated) = token_exchange(
        &router,
        keyed_token_admin_request(Method::POST, &route, admin, None, Some(&token_key(21))),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{rotated}");
    assert_eq!(
        token_evidence(&token_db.path)
            .iter()
            .map(|(_, action, _)| action.as_str())
            .collect::<Vec<_>>(),
        ["service_token.issue", "service_token.rotate"]
    );
}

/// The rest of the gate: required mode refuses a keyed token issue by a
/// gateway service token, under `delivery_v1`, or with the log sink, each
/// refusal naming its criterion, and nothing is written or reserved.
#[tokio::test]
async fn required_mode_refuses_a_keyed_token_issue_by_a_service_token_or_under_delivery_v1_or_with_the_log_sink(
) {
    let policy = TempPolicyFile::new(&token_policy_document_string());
    let events = TempDb::new("keyed-token-refused-events");
    for (case, requirement) in [
        (
            "service token",
            "from a provider-authenticated principal with a canonical issuer",
        ),
        ("delivery_v1", "with AUTHORITY_EVENT_FORMAT=qualified_v1"),
        ("log sink", "with AUTHORITY_EVENT_SINK=file"),
    ] {
        let principal = match case {
            "service token" => service_token_caller(&["superadmin"]),
            _ => keyed_token_admin(&["superadmin"]),
        };
        let token_db = TempDb::new("keyed-token-refused");
        let router = keyed_token_router(&token_db, &policy, test_audit_log(), |config| {
            keyed_token_required(config, &events);
            match case {
                "delivery_v1" => {
                    config.authority_events.format = config::AuthorityEventFormat::DeliveryV1;
                }
                "log sink" => config.authority_events.sink = config::AuthorityEventSinkSetting::Log,
                _ => {}
            }
        });
        let (status, _, refused) = token_exchange(
            &router,
            keyed_token_admin_request(
                Method::POST,
                TOKENS_ADMIN_ROUTE,
                principal,
                Some(json!({ "scopes": ["probe-reader"] }).to_string()),
                Some(&token_key(30)),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{case}: {refused}");
        assert_eq!(
            refused["error"],
            json!(format!(
                "AUTHORITY_EVIDENCE_DURABILITY=required refuses service_token.issue: standalone mode admits it only {requirement}; nothing was changed"
            )),
            "{case}"
        );
        assert!(token_evidence(&token_db.path).is_empty(), "{case}");
        assert!(token_reservations(&token_db.path).is_empty(), "{case}");
    }
}

/// Token revocation is a withdrawal: required mode admits every form of it
/// -- the unkeyed `DELETE`, the keyed `POST` and a gateway service token's --
/// even with the log sink, and each records its evidence (owner ruling 4 on
/// issue #425).
#[tokio::test]
async fn required_mode_admits_every_form_of_token_revocation() {
    let token_db = TempDb::new("keyed-token-withdrawal");
    let policy = TempPolicyFile::new(&token_policy_document_string());
    let best_effort = keyed_token_router(&token_db, &policy, test_audit_log(), |_| {});
    let admin = keyed_token_admin(&["superadmin"]);
    let mut ids = Vec::new();
    for _ in 0..3 {
        let (status, _, created) = token_exchange(
            &best_effort,
            token_admin_request(
                Method::POST,
                TOKENS_ADMIN_ROUTE,
                Some(admin.clone()),
                Some(json!({ "scopes": ["probe-reader"] }).to_string()),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        ids.push(created["token"]["id"].as_str().expect("an ID").to_owned());
    }
    drop(best_effort);
    let required = keyed_token_router(&token_db, &policy, test_audit_log(), |config| {
        config.authority_events.durability = config::AuthorityEvidenceDurability::Required;
        config.authority_events.sink = config::AuthorityEventSinkSetting::Log;
    });
    for (request, form) in [
        (
            keyed_token_admin_request(
                Method::DELETE,
                &format!("{TOKENS_ADMIN_ROUTE}/{}", ids[0]),
                admin.clone(),
                None,
                None,
            ),
            "unkeyed",
        ),
        (
            keyed_token_admin_request(
                Method::POST,
                &format!("{TOKENS_ADMIN_ROUTE}/{}/revoke", ids[1]),
                admin.clone(),
                None,
                Some(&token_key(40)),
            ),
            "keyed",
        ),
        (
            keyed_token_admin_request(
                Method::DELETE,
                &format!("{TOKENS_ADMIN_ROUTE}/{}", ids[2]),
                service_token_caller(&["superadmin"]),
                None,
                None,
            ),
            "service token",
        ),
    ] {
        let (status, _, revoked) = token_exchange(&required, request).await;
        assert_eq!(status, StatusCode::OK, "{form}: {revoked}");
    }
    let revoked: Vec<_> = token_evidence(&token_db.path)
        .into_iter()
        .filter(|(_, action, _)| action == "service_token.revoke")
        .map(|(_, _, token)| token)
        .collect();
    assert_eq!(revoked, ids);
}

/// A standalone token router over `token_db` that authenticates bearer
/// tokens, service tokens included, and caches their verification for a
/// minute, so that only an invalidation can withdraw a cached plaintext.
fn bearer_token_router(
    token_db: &TempDb,
    policy: &TempPolicyFile,
    audit_log: audit::AuditLog,
) -> Router {
    let mut config = test_config(Vec::new());
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    config.service_token_sqlite_path = Some(token_db.path.to_string_lossy().into_owned());
    config.service_token_cache_ttl_ms = 60_000;
    config.rbac_exempt_paths.push(TOKENS_ADMIN_ROUTE.to_owned());
    config.rate_limit_write_burst = 1_000;
    let recorder = PrometheusBuilder::new().build_recorder();
    app(
        config,
        recorder.handle(),
        audit_log,
        test_audit_event_sender(),
    )
    .expect("app should build")
}

/// A service token that may rotate itself: it carries `token-admin` and the
/// `probe-reader` role the probe route needs.
fn self_rotating_token(token_db: &TempDb) -> auth::tokens::CreatedToken {
    auth::tokens::SqliteTokenStore::open(&token_db.path)
        .expect("token store should open")
        .create(
            auth::tokens::CreateTokenRequest {
                scopes: vec!["token-admin".to_owned(), "probe-reader".to_owned()],
                created_by: "bootstrap-admin".to_owned(),
                expires_at: None,
            },
            &auth::change_actor::ChangeActor::for_test("bootstrap-admin"),
        )
        .expect("service token should create")
}

/// A keyed rotation of `id` authenticated by the bearer `plaintext`.
fn keyed_bearer_rotation(id: &str, plaintext: &str, key: &str) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(format!("{TOKENS_ADMIN_ROUTE}/{id}/rotate"))
        .header(header::AUTHORIZATION, format!("Bearer {plaintext}"))
        .header(header::CONTENT_TYPE, "application/json")
        .header("idempotency-key", key)
        .body(Body::empty())
        .expect("rotate request should build")
}

/// An exact retry of a keyed rotation is answered from its receipt and
/// rotates nothing again, but it still drops the replaced plaintext from the
/// answering process's validator cache. Here a second process sharing the
/// token file cached the plaintext before the first one rotated it: before
/// the retry it still accepts the replaced plaintext (its cache outlives the
/// rotation), and after the retry it refuses it.
#[tokio::test]
async fn a_keyed_rotation_retry_drops_the_replaced_plaintext_from_the_answering_cache() {
    let token_db = TempDb::new("keyed-token-replay-cache");
    let created = self_rotating_token(&token_db);
    let policy = TempPolicyFile::new(&service_token_policy_document());
    let first = bearer_token_router(&token_db, &policy, test_audit_log());
    let second = bearer_token_router(&token_db, &policy, test_audit_log());
    let replaced = created.plaintext_token.clone();
    assert_eq!(
        authenticated_principal_probe(&second, &replaced)
            .await
            .status(),
        StatusCode::OK
    );

    let key = token_key(50);
    let (status, _, rotated) = token_exchange(
        &first,
        keyed_bearer_rotation(&created.record.id, &replaced, &key),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{rotated}");
    let current = rotated["plaintext_token"]
        .as_str()
        .expect("the first rotation carries the plaintext")
        .to_owned();
    assert_eq!(
        authenticated_principal_probe(&second, &replaced)
            .await
            .status(),
        StatusCode::OK,
        "the second process still holds the replaced plaintext in its cache"
    );

    let (status, _, receipt) = token_exchange(
        &second,
        keyed_bearer_rotation(&created.record.id, &current, &key),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{receipt}");
    assert_eq!(receipt["operation"], json!("service_token.rotate"));
    assert_eq!(receipt["secret_returned"], json!(false));
    assert_eq!(
        authenticated_principal_probe(&second, &replaced)
            .await
            .status(),
        StatusCode::UNAUTHORIZED,
        "the retry dropped the replaced plaintext from the answering cache"
    );
    assert_eq!(
        authenticated_principal_probe(&second, &current)
            .await
            .status(),
        StatusCode::OK,
        "the retry rotated nothing again"
    );
}

/// A keyed rotation runs to completion once admitted, even when its client
/// goes away while the store is committing it: its audit event is emitted
/// and this process stops accepting the replaced plaintext from its cache,
/// though nobody waited for the response. Before the rotation ran on its own
/// task, the dropped handler left both undone, and the keyed retry, answered
/// from the receipt, repeats no audit event.
#[tokio::test]
async fn an_admitted_token_rotation_finishes_after_its_client_goes_away() {
    let token_db = TempDb::new("keyed-token-abandoned");
    let created = self_rotating_token(&token_db);
    let policy = TempPolicyFile::new(&service_token_policy_document());
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
    let router = bearer_token_router(&token_db, &policy, audit_log);
    let replaced = created.plaintext_token.clone();
    assert_eq!(
        authenticated_principal_probe(&router, &replaced)
            .await
            .status(),
        StatusCode::OK
    );

    let path = token_db.path.clone();
    super::authority_evidence_app_tests::abandon_once_committed(
        &router,
        keyed_bearer_rotation(&created.record.id, &replaced, &token_key(51)),
        move || {
            token_evidence(&path)
                .iter()
                .any(|(_, action, _)| action == "service_token.rotate")
        },
    )
    .await;

    let started = Instant::now();
    loop {
        let refused = authenticated_principal_probe(&router, &replaced)
            .await
            .status()
            == StatusCode::UNAUTHORIZED;
        if (refused && token_changes(&capture, "token_rotated") == 1)
            || started.elapsed() > Duration::from_secs(5)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        authenticated_principal_probe(&router, &replaced)
            .await
            .status(),
        StatusCode::UNAUTHORIZED,
        "the rotation dropped the replaced plaintext from this process's cache"
    );
    assert_eq!(
        token_changes(&capture, "token_rotated"),
        1,
        "the rotation was audited once, though nobody waited for its response"
    );
}

/// Under `required`, a request is validated and the evidence gate asked
/// before anything is read or admitted: a malformed `expires_at` is `400`
/// (keyed or not, never `409 authority_evidence_unsupported`), and an
/// unkeyed rotation is refused before the token is read, so an unknown
/// token is `409`, not `404`.
#[tokio::test]
async fn required_mode_validates_an_issue_and_refuses_an_unkeyed_rotation_before_reading_the_token()
{
    let token_db = TempDb::new("keyed-token-required-order");
    let events = TempDb::new("keyed-token-required-order-events");
    let policy = TempPolicyFile::new(&token_policy_document_string());
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
    let router = keyed_token_router(&token_db, &policy, audit_log, |config| {
        keyed_token_required(config, &events)
    });
    let admin = keyed_token_admin(&["superadmin"]);
    let malformed = json!({ "scopes": ["probe-reader"], "expires_at": "not-a-time" }).to_string();
    for key in [None, Some(token_key(60))] {
        let (status, _, refused) = token_exchange(
            &router,
            keyed_token_admin_request(
                Method::POST,
                TOKENS_ADMIN_ROUTE,
                admin.clone(),
                Some(malformed.clone()),
                key.as_deref(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{key:?}: {refused}");
    }
    let (status, _, refused) = token_exchange(
        &router,
        keyed_token_admin_request(
            Method::POST,
            &format!("{TOKENS_ADMIN_ROUTE}/token_unknown/rotate"),
            admin,
            None,
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{refused}");
    assert_eq!(refused["reason"], json!("authority_evidence_unsupported"));
    assert_eq!(refused["operation"], json!("service_token.rotate"));
    assert!(token_evidence(&token_db.path).is_empty());
    assert!(token_reservations(&token_db.path).is_empty());
}
