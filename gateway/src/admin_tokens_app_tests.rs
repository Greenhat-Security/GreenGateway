//! The service-token admin API in `admin_tokens.rs`: create, list, get, rotate
//! and revoke, the actor each change records, and the requested-scope
//! delegation check (`authorize_requested_scopes`) a create or rotate passes
//! before anything is minted. Shared fixtures stay in `app_tests.rs`.
use super::*;

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
            .create(auth::tokens::CreateTokenRequest {
                scopes: scopes.iter().map(|scope| (*scope).to_owned()).collect(),
                created_by: "bootstrap-admin".to_owned(),
                expires_at: None,
            })
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
    config.database.tls_mode = config::DatabaseTlsMode::LoopbackDev;
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
        audit: audit_log,
        client_ip_policy: client_ip::ClientIpPolicy::from_config(&config),
        max_body_size: config.max_body_size,
    };
    let mut ids = Vec::new();
    for _ in 0..2 {
        ids.push(
            store
                .create(auth::tokens::CreateTokenRequest {
                    scopes: vec!["probe-reader".to_owned()],
                    created_by: "bootstrap-admin".to_owned(),
                    expires_at: None,
                })
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
    vec![
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
    config.database.tls_mode = config::DatabaseTlsMode::LoopbackDev;
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
        .create(auth::tokens::CreateTokenRequest {
            scopes: vec!["probe-reader".to_owned(), String::new()],
            created_by: "bootstrap-admin".to_owned(),
            expires_at: None,
        })
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
        .create(auth::tokens::CreateTokenRequest {
            scopes: vec!["token-admin".to_owned(), "probe-reader".to_owned()],
            created_by: "bootstrap-admin".to_owned(),
            expires_at: None,
        })
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
