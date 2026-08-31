//! Behavior-level contract tests for the repository traits.
//!
//! Every assertion goes through a `&dyn Trait`, never a concrete adapter,
//! so the same contracts can run against the PostgreSQL implementations in
//! later PRs of issue #241. The SQLite adapters here are the reference
//! implementations.
//!
//! These tests also prove the blocking-migration claim: a repository call
//! held hostage by a long-held SQLite write lock (or a deliberately gated
//! store) must not stall Tokio's request executors.

use std::{
    fs,
    path::PathBuf,
    sync::{mpsc, Arc, Mutex},
    time::Duration,
};

use serde_json::{json, Value};

use crate::audit::{
    query::{AuditQueryFilters, AuditQueryPage},
    Actor, AuditEvent,
};
use crate::auth::{
    principal_directory::{
        PrincipalDirectory, PrincipalDirectoryKey, PrincipalDirectoryListFilters,
        PrincipalObservation,
    },
    tokens::{
        CreateTokenRequest, SqliteTokenStore, TokenListFilters, TokenVerification,
        TokenVerificationFailure, VerifiedToken,
    },
    ServiceTokenValidator, SessionCredential, SessionValidator,
};
use crate::rbac::{
    policy_history::{PolicyHistoryListFilters, PolicyHistoryStore},
    Policy,
};
use crate::storage::{
    AuditEventStore, PolicyHistory, PrincipalDirectoryStore, RepositoryError, RepositoryErrorKind,
    ServiceTokenStore, SqliteAuditEventStore,
};

// ---------------------------------------------------------------------------
// Audit event/query store contract
// ---------------------------------------------------------------------------

/// Assert the audit store contract: idempotent inserts keyed by `event_id`,
/// newest-first keyset pagination, and filter behavior.
async fn audit_event_store_contract(store: &dyn AuditEventStore) {
    let mut event_a_payload = json!({ "status": 200 });
    event_a_payload
        .as_object_mut()
        .expect("contract payload is an object")
        .insert("path".to_owned(), json!("/a"));
    let event_a = contract_event("evt-a", "audit.contract", event_a_payload);
    let event_b = contract_event("evt-b", "audit.contract", json!({ "status": 403 }));

    // At-least-once insertion: replaying a batch and duplicating an
    // event_id inside one batch must still store exactly one row per id.
    store
        .insert_events(std::slice::from_ref(&event_a))
        .await
        .expect("first audit insert should succeed");
    store
        .insert_events(&[event_a.clone(), event_b.clone()])
        .await
        .expect("replayed audit insert should succeed");
    store
        .insert_events(&[
            contract_event("evt-c", "audit.contract", json!({ "status": 200 })),
            contract_event("evt-c", "audit.contract", json!({ "status": 200 })),
        ])
        .await
        .expect("audit insert with an intra-batch duplicate should succeed");

    for index in 0..4 {
        store
            .insert_events(&[contract_event(
                &format!("evt-page-{index}"),
                "audit.contract.page",
                json!({ "status": 200 }),
            )])
            .await
            .expect("audit insert should succeed");
    }

    // Keyset pagination: walking the cursor must enumerate every stored row
    // exactly once, newest-first, and terminate.
    let mut collected = Vec::new();
    let mut before_id = None;
    loop {
        let page = store
            .query_events(&query_filters(before_id, 2))
            .await
            .expect("keyset page should query");
        collected.extend(event_ids(&page));
        assert!(
            page.events.len() <= 2,
            "pages must respect the requested limit"
        );
        match page.next_cursor {
            Some(cursor) => before_id = Some(cursor),
            None => break,
        }
    }
    assert_eq!(
        collected,
        [
            "evt-page-3",
            "evt-page-2",
            "evt-page-1",
            "evt-page-0",
            "evt-c",
            "evt-b",
            "evt-a"
        ],
        "keyset walk must be newest-first, gapless, and duplicate-free"
    );

    // Idempotency: exactly one stored row per event_id.
    let all = store
        .query_events(&query_filters(None, 100))
        .await
        .expect("full audit page should query");
    assert_eq!(all.next_cursor, None);
    let mut all_ids = event_ids(&all);
    all_ids.sort();
    assert_eq!(
        all_ids,
        [
            "evt-a",
            "evt-b",
            "evt-c",
            "evt-page-0",
            "evt-page-1",
            "evt-page-2",
            "evt-page-3"
        ],
        "replayed and intra-batch duplicate event_ids must be stored exactly once"
    );

    // Filters: type, method-derived status, and actor.
    let denied = store
        .query_events(&AuditQueryFilters {
            from: None,
            to: None,
            event_type: Some("audit.contract".to_owned()),
            actor: None,
            actor_issuer: None,
            actor_auth_mode: None,
            method: None,
            path: Some("/a".to_owned()),
            status: Some(200),
            matched_rule_id: None,
            limit: 100,
            before_id: None,
        })
        .await
        .expect("filtered audit query should succeed");
    assert_eq!(
        event_ids(&denied),
        ["evt-a"],
        "path and status filters must combine"
    );

    let by_actor = store
        .query_events(&AuditQueryFilters {
            from: None,
            to: None,
            event_type: None,
            actor: Some("user-contract".to_owned()),
            actor_issuer: None,
            actor_auth_mode: None,
            method: None,
            path: None,
            status: None,
            matched_rule_id: None,
            limit: 100,
            before_id: None,
        })
        .await
        .expect("actor-filtered audit query should succeed");
    assert_eq!(
        by_actor.events.len(),
        all.events.len(),
        "every contract event carries the contract actor"
    );
}

#[tokio::test]
async fn sqlite_audit_event_store_satisfies_the_contract() {
    let db = TempDb::new("audit-contract");
    let store = SqliteAuditEventStore::open(&db.path).expect("audit store should open");
    audit_event_store_contract(&store).await;
}

#[tokio::test]
async fn sqlite_audit_event_store_classifies_a_non_database_file_as_unavailable() {
    let db = TempDb::new("audit-notadb");
    fs::write(&db.path, b"this is not a sqlite database at all").expect("junk file should write");

    let error = match SqliteAuditEventStore::open(&db.path) {
        Ok(_) => panic!("opening a non-database file should fail"),
        Err(error) => error,
    };

    assert_eq!(
        error.kind(),
        RepositoryErrorKind::Unavailable,
        "a file that is not a database must classify as unavailable: {error}"
    );
}

// ---------------------------------------------------------------------------
// Service-token store contract
// ---------------------------------------------------------------------------

/// Assert the service-token contract: create/verify/revoke/rotate lifecycle
/// with revocation that is idempotent, monotonic, and never resurrected.
async fn service_token_store_contract(store: &dyn ServiceTokenStore) {
    let created = store
        .create(CreateTokenRequest {
            scopes: vec!["admin:tokens:read".to_owned()],
            created_by: "contract-actor".to_owned(),
            expires_at: None,
        })
        .await
        .expect("token should create");

    assert!(
        created.plaintext_token.starts_with("ggw_"),
        "plaintext tokens must use the service-token marker"
    );
    assert_eq!(
        created.record.token_prefix.len(),
        "ggw_".len() + 10,
        "only a bounded display prefix is exposed"
    );

    // Verify accepts the fresh token and records use.
    match store
        .verify(&created.plaintext_token)
        .await
        .expect("fresh token verification should query")
    {
        TokenVerification::Valid(verified) => {
            assert_eq!(verified.id, created.record.id);
            assert_eq!(verified.scopes, vec!["admin:tokens:read".to_owned()]);
            assert!(
                verified.last_used_at.is_some(),
                "successful verification must update last_used_at"
            );
        }
        other => panic!("fresh token should verify, got {other:?}"),
    }

    // Revoke is idempotent and keeps the first revoked_at.
    let first_revoke = store
        .revoke(&created.record.id)
        .await
        .expect("revoke should query")
        .expect("revoked token should exist");
    let revoked_at = first_revoke
        .revoked_at
        .clone()
        .expect("revoke must set revoked_at");
    let second_revoke = store
        .revoke(&created.record.id)
        .await
        .expect("second revoke should query")
        .expect("revoked token should still exist");
    assert_eq!(
        second_revoke.revoked_at.as_deref(),
        Some(revoked_at.as_str()),
        "revocation must be idempotent and keep the first timestamp"
    );

    assert_eq!(
        store
            .verify(&created.plaintext_token)
            .await
            .expect("revoked verification should query"),
        TokenVerification::Invalid(TokenVerificationFailure::Revoked),
        "a revoked token must never verify again"
    );

    // Rotating a revoked token is a conflict, not a silent success.
    let rotate_error = match store.rotate(&created.record.id).await {
        // `CreatedToken` deliberately has no `Debug`: the plaintext token
        // must never be formattable into a panic message.
        Ok(_) => panic!("rotating a revoked token must fail"),
        Err(error) => error,
    };
    assert_eq!(
        rotate_error.kind(),
        RepositoryErrorKind::Conflict,
        "rotate-after-revoke must classify as conflict: {rotate_error}"
    );

    // Rotation mints a new plaintext and invalidates the old one, while
    // preserving the record's identity, scopes, and expiry.
    let live = store
        .create(CreateTokenRequest {
            scopes: vec!["admin:tokens:read".to_owned(), "mcp:tools".to_owned()],
            created_by: "contract-actor".to_owned(),
            expires_at: Some("2999-01-01T00:00:00Z".to_owned()),
        })
        .await
        .expect("live token should create");
    let rotated = store
        .rotate(&live.record.id)
        .await
        .expect("live rotate should query")
        .expect("live token should exist");
    assert_eq!(rotated.record.id, live.record.id);
    assert_eq!(rotated.record.scopes, live.record.scopes);
    assert_ne!(rotated.plaintext_token, live.plaintext_token);
    assert_eq!(
        store
            .verify(&live.plaintext_token)
            .await
            .expect("old plaintext verification should query"),
        TokenVerification::Invalid(TokenVerificationFailure::NotFound),
        "the pre-rotation plaintext must stop verifying"
    );
    assert!(matches!(
        store
            .verify(&rotated.plaintext_token)
            .await
            .expect("rotated plaintext verification should query"),
        TokenVerification::Valid(_)
    ));
}

#[tokio::test]
async fn sqlite_service_token_store_satisfies_the_contract() {
    let db = TempDb::new("token-contract");
    let store = SqliteTokenStore::open(&db.path).expect("token store should open");
    service_token_store_contract(&store).await;
}

// ---------------------------------------------------------------------------
// Policy-history contract
// ---------------------------------------------------------------------------

/// Assert the policy-history contract: append/list/get with newest-first
/// version cursors and round-trippable snapshots.
async fn policy_history_contract(history: &dyn PolicyHistory) {
    let policy_one = contract_policy("contract-policy-one");
    let policy_two = contract_policy("contract-policy-two");

    let first = history
        .append_version(
            "contract-actor",
            &json!({ "action": "created" }),
            &policy_one,
        )
        .await
        .expect("first version should append");
    let second = history
        .append_version(
            "contract-actor",
            &json!({ "action": "edited" }),
            &policy_two,
        )
        .await
        .expect("second version should append");
    assert!(
        second.version > first.version,
        "appended versions must be ordered"
    );

    let page = history
        .list_versions(&PolicyHistoryListFilters {
            limit: 1,
            cursor: None,
            include_policy: false,
        })
        .await
        .expect("history should list");
    assert_eq!(page.versions.len(), 1);
    assert_eq!(page.versions[0].version, second.version);
    assert!(
        page.versions[0].policy.is_none(),
        "include_policy=false must omit snapshots"
    );
    let cursor = page
        .next_cursor
        .expect("a single-version page of two must have a cursor");

    let rest = history
        .list_versions(&PolicyHistoryListFilters {
            limit: 5,
            cursor: Some(cursor),
            include_policy: false,
        })
        .await
        .expect("keyset history page should list");
    assert_eq!(rest.versions.len(), 1);
    assert_eq!(rest.versions[0].version, first.version);
    assert_eq!(rest.next_cursor, None);

    let snapshot = history
        .get_version(second.version)
        .await
        .expect("history version should load")
        .expect("history version should exist");
    assert_eq!(
        snapshot.policy,
        Some(policy_two),
        "stored snapshots must round-trip the exact policy"
    );

    assert_eq!(
        history
            .get_version(i64::MAX)
            .await
            .expect("missing history version should query"),
        None
    );
}

#[tokio::test]
async fn sqlite_policy_history_satisfies_the_contract() {
    let db = TempDb::new("history-contract");
    let history = PolicyHistoryStore::open(&db.path).expect("history store should open");
    policy_history_contract(&history).await;
}

// ---------------------------------------------------------------------------
// Principal-directory contract
// ---------------------------------------------------------------------------

/// Assert the principal-directory contract: identity-keyed upserts that
/// accumulate counts and merge seen windows, plus keyset listing.
async fn principal_directory_contract(directory: &dyn PrincipalDirectoryStore) {
    let key = PrincipalDirectoryKey {
        subject: "contract-subject".to_owned(),
        issuer: "https://issuer.example/".to_owned(),
        auth_method: "bearer".to_owned(),
    };
    let mut other_method = key.clone();
    other_method.auth_method = "service_token".to_owned();

    directory
        .upsert_principals(&[
            PrincipalObservation {
                subject: key.subject.clone(),
                issuer: key.issuer.clone(),
                auth_method: key.auth_method.clone(),
                email: Some("old@example.com".to_owned()),
                org_id: None,
                seen_at: "2024-06-01T12:00:00Z".to_owned(),
            },
            PrincipalObservation {
                subject: key.subject.clone(),
                issuer: key.issuer.clone(),
                auth_method: key.auth_method.clone(),
                email: Some("new@example.com".to_owned()),
                org_id: Some("org-1".to_owned()),
                seen_at: "2024-06-02T12:00:00Z".to_owned(),
            },
            PrincipalObservation {
                subject: other_method.subject.clone(),
                issuer: other_method.issuer.clone(),
                auth_method: other_method.auth_method.clone(),
                email: None,
                org_id: None,
                seen_at: "2024-06-01T12:00:00Z".to_owned(),
            },
        ])
        .await
        .expect("principal upserts should succeed");

    let record = directory
        .get(&key)
        .await
        .expect("principal get should query")
        .expect("merged principal should exist");
    assert_eq!(record.request_count, 2, "upserts must accumulate counts");
    assert_eq!(
        record.first_seen, "2024-06-01T12:00:00Z",
        "upserts must keep the earliest first_seen"
    );
    assert_eq!(
        record.last_seen, "2024-06-02T12:00:00Z",
        "upserts must keep the latest last_seen"
    );
    assert_eq!(
        record.email.as_deref(),
        Some("new@example.com"),
        "mutable profile fields reflect the most recent observation"
    );

    let separate = directory
        .get(&other_method)
        .await
        .expect("principal get should query")
        .expect("identity triple must key a separate row");
    assert_eq!(separate.request_count, 1);

    // Keyset listing across both identities.
    let page = directory
        .list(&PrincipalDirectoryListFilters {
            issuer: None,
            auth_method: None,
            principal_type: None,
            last_seen_after: None,
            last_seen_before: None,
            limit: 1,
            cursor: None,
        })
        .await
        .expect("principal list should query");
    assert_eq!(page.principals.len(), 1);
    let cursor = page
        .next_cursor
        .expect("a second principal must leave a cursor");
    let rest = directory
        .list(&PrincipalDirectoryListFilters {
            issuer: None,
            auth_method: None,
            principal_type: None,
            last_seen_after: None,
            last_seen_before: None,
            limit: 1,
            cursor: Some(cursor),
        })
        .await
        .expect("keyset principal page should query");
    assert_eq!(rest.principals.len(), 1);
    assert_eq!(rest.next_cursor, None);

    // Unknown keys are absent, not errors.
    let mut unknown = key.clone();
    unknown.subject = "never-seen".to_owned();
    assert_eq!(
        directory
            .get(&unknown)
            .await
            .expect("unknown principal get should query"),
        None
    );
}

#[tokio::test]
async fn sqlite_principal_directory_satisfies_the_contract() {
    let db = TempDb::new("principal-contract");
    let directory =
        PrincipalDirectory::open(db.path.clone()).expect("principal directory should open");
    principal_directory_contract(&directory).await;
}

// ---------------------------------------------------------------------------
// Error classification
// ---------------------------------------------------------------------------

#[tokio::test]
async fn invalid_cursors_classify_as_invalid_request_data_without_leaking_the_value() {
    let token_db = TempDb::new("cursor-token");
    let tokens = SqliteTokenStore::open(&token_db.path).expect("token store should open");
    let error = tokens
        .list(&TokenListFilters {
            limit: 10,
            cursor: Some("not-a-valid-cursor".to_owned()),
        })
        .await
        .expect_err("a malformed cursor must be rejected");
    assert_eq!(error.kind(), RepositoryErrorKind::InvalidData);
    assert_eq!(error.invalid_parameter_name(), Some("cursor"));
    assert!(
        !error.to_string().contains("not-a-valid-cursor"),
        "classified errors must not echo query values: {}",
        error
    );

    let history_db = TempDb::new("cursor-history");
    let history = PolicyHistoryStore::open(&history_db.path).expect("history store should open");
    let error = PolicyHistory::list_versions(
        &history,
        &PolicyHistoryListFilters {
            limit: 10,
            cursor: Some("0".to_owned()),
            include_policy: false,
        },
    )
    .await
    .expect_err("a non-positive version cursor must be rejected");
    assert_eq!(error.kind(), RepositoryErrorKind::InvalidData);
    assert_eq!(error.invalid_parameter_name(), Some("cursor"));

    let principal_db = TempDb::new("cursor-principal");
    let directory =
        PrincipalDirectory::open(principal_db.path.clone()).expect("directory should open");
    let error = PrincipalDirectoryStore::list(
        &directory,
        &PrincipalDirectoryListFilters {
            issuer: None,
            auth_method: None,
            principal_type: None,
            last_seen_after: None,
            last_seen_before: None,
            limit: 10,
            cursor: Some("%zz".to_owned()),
        },
    )
    .await
    .expect_err("a malformed principal cursor must be rejected");
    assert_eq!(error.kind(), RepositoryErrorKind::InvalidData);
    assert_eq!(error.invalid_parameter_name(), Some("cursor"));
}

#[test]
fn rusqlite_constraint_violations_classify_as_conflict() {
    let db = TempDb::new("classify-conflict");
    let connection = rusqlite::Connection::open(&db.path).expect("connection should open");
    connection
        .execute_batch("CREATE TABLE contract_unique (value TEXT UNIQUE);")
        .expect("schema should create");
    connection
        .execute("INSERT INTO contract_unique (value) VALUES ('one')", [])
        .expect("first row should insert");

    let error = connection
        .execute("INSERT INTO contract_unique (value) VALUES ('one')", [])
        .expect_err("duplicate insert must fail");
    let classified = crate::storage::classify_rusqlite("contract_probe", &error);
    assert_eq!(
        classified.kind(),
        RepositoryErrorKind::Conflict,
        "uniqueness violations must classify as conflict: {error}"
    );
}

// ---------------------------------------------------------------------------
// Blocking-migration proof
// ---------------------------------------------------------------------------

/// A hostage SQLite write lock must not stall the request executors: an
/// independent async task keeps making progress while a repository write
/// waits on the lock, and the write completes once the lock is released.
#[tokio::test(flavor = "current_thread")]
async fn hostage_database_write_does_not_stall_the_executor() {
    let db = TempDb::new("executor-hostage");
    let store = Arc::new(SqliteAuditEventStore::open(&db.path).expect("audit store should open"));
    store
        .insert_events(&[contract_event(
            "evt-warm",
            "audit.contract",
            json!({ "warm": true }),
        )])
        .await
        .expect("warm-up insert should succeed");

    let lock_holder = rusqlite::Connection::open(&db.path).expect("lock connection should open");
    lock_holder
        .busy_timeout(Duration::from_secs(5))
        .expect("lock connection busy timeout should set");
    lock_holder
        .execute_batch("BEGIN IMMEDIATE;")
        .expect("write lock should acquire");

    let insert = {
        let store = Arc::clone(&store);
        tokio::spawn(async move {
            store
                .insert_events(&[contract_event(
                    "evt-hostage",
                    "audit.contract",
                    json!({ "hostage": true }),
                )])
                .await
        })
    };

    let (probe_tx, probe_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(25)).await;
        let _ = probe_tx.send(());
    });

    tokio::time::timeout(Duration::from_millis(400), probe_rx)
        .await
        .expect("an async probe must run while a repository write is hostage")
        .expect("probe channel should deliver");

    assert!(
        !insert.is_finished(),
        "the hostage insert must still be waiting on the database write lock"
    );

    drop(lock_holder);

    tokio::time::timeout(Duration::from_secs(5), insert)
        .await
        .expect("the hostage insert must complete after the lock is released")
        .expect("insert task must not panic")
        .expect("released insert must succeed");

    let page = store
        .query_events(&query_filters(None, 100))
        .await
        .expect("post-release query should succeed");
    assert!(
        event_ids(&page).contains(&"evt-hostage".to_owned()),
        "the hostage event must be durably stored after release"
    );
}

/// The authenticated request path stays responsive while service-token
/// verification is hostage inside the store, proving the validator awaits
/// its store off the executor instead of calling it synchronously.
#[tokio::test(flavor = "current_thread")]
async fn request_path_stays_responsive_while_token_verification_is_hostage() {
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let store = Arc::new(GatedTokenStore {
        gate: Mutex::new(Some(release_rx)),
    });
    let validator = Arc::new(ServiceTokenValidator::new(
        Arc::clone(&store) as Arc<dyn ServiceTokenStore>,
        Duration::from_secs(60),
    ));

    let authentication = {
        let validator = Arc::clone(&validator);
        tokio::spawn(async move {
            validator
                .validate_session(&SessionCredential::Bearer("ggw_hostage-token".to_owned()))
                .await
        })
    };

    let (probe_tx, probe_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(25)).await;
        let _ = probe_tx.send(());
    });

    tokio::time::timeout(Duration::from_millis(400), probe_rx)
        .await
        .expect("async work must keep running while token verification is hostage")
        .expect("probe channel should deliver");

    release_tx
        .send(())
        .expect("gated verification should still be waiting for release");

    let principal = tokio::time::timeout(Duration::from_secs(5), authentication)
        .await
        .expect("released verification must complete")
        .expect("authentication task must not panic")
        .expect("gated verification resolves to a valid token");
    assert_eq!(principal.user_id, "service-token:tok-gated");
}

/// A store whose verification blocks until released. The gate blocks on the
/// blocking pool, honoring the repository contract; the contract tests in
/// this module prove the executor survives that hostage call.
struct GatedTokenStore {
    gate: Mutex<Option<mpsc::Receiver<()>>>,
}

#[async_trait::async_trait]
impl ServiceTokenStore for GatedTokenStore {
    async fn create(
        &self,
        _request: CreateTokenRequest,
    ) -> Result<crate::auth::tokens::CreatedToken, RepositoryError> {
        unimplemented!("not needed by the executor proof")
    }

    async fn list(
        &self,
        _filters: &TokenListFilters,
    ) -> Result<crate::auth::tokens::TokenPage, RepositoryError> {
        unimplemented!("not needed by the executor proof")
    }

    async fn get_by_id(
        &self,
        _id: &str,
    ) -> Result<Option<crate::auth::tokens::TokenRecord>, RepositoryError> {
        unimplemented!("not needed by the executor proof")
    }

    async fn revoke(
        &self,
        _id: &str,
    ) -> Result<Option<crate::auth::tokens::TokenRecord>, RepositoryError> {
        unimplemented!("not needed by the executor proof")
    }

    async fn rotate(
        &self,
        _id: &str,
    ) -> Result<Option<crate::auth::tokens::CreatedToken>, RepositoryError> {
        unimplemented!("not needed by the executor proof")
    }

    async fn verify(&self, _plaintext_token: &str) -> Result<TokenVerification, RepositoryError> {
        let gate = self
            .gate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if let Some(gate) = gate {
            super::run_blocking(move || {
                let _ = gate.recv();
                Ok(())
            })
            .await?;
        }
        Ok(TokenVerification::Valid(VerifiedToken {
            id: "tok-gated".to_owned(),
            token_prefix: "ggw_gated1234".to_owned(),
            scopes: vec!["admin:tokens:read".to_owned()],
            expires_at: None,
            last_used_at: None,
        }))
    }

    async fn touch_last_used(
        &self,
        _id: &str,
    ) -> Result<Option<crate::auth::tokens::TokenRecord>, RepositoryError> {
        unimplemented!("not needed by the executor proof")
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn contract_event(event_id: &str, event_type: &str, payload: Value) -> AuditEvent {
    let mut event = AuditEvent::new(
        event_type,
        "request-contract",
        "203.0.113.10",
        Some(Actor {
            user_id: "user-contract".to_owned(),
            issuer: Some("https://issuer.example/".to_owned()),
            email: None,
            roles: Some(vec!["reader".to_owned()]),
            auth_mode: "bearer_token".to_owned(),
        }),
        payload,
    );
    event.event_id = event_id.to_owned();
    event
}

fn query_filters(before_id: Option<i64>, limit: usize) -> AuditQueryFilters {
    AuditQueryFilters {
        from: None,
        to: None,
        event_type: None,
        actor: None,
        actor_issuer: None,
        actor_auth_mode: None,
        method: None,
        path: None,
        status: None,
        matched_rule_id: None,
        limit,
        before_id,
    }
}

fn event_ids(page: &AuditQueryPage) -> Vec<String> {
    page.events
        .iter()
        .map(|event| event.event_id.clone())
        .collect()
}

// ---------------------------------------------------------------------------
// PostgreSQL audit store (issue #241, PR 5): the same contract, plus the
// commit-safe stream proofs, against a real database. Gated on the test
// harness locator (CI sets it; a checkout without a database skips).
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "postgres"))]
mod postgres_audit_tests {
    use super::*;
    use crate::storage::{
        migrations,
        postgres::PostgresFoundation,
        postgres_audit::{IngestIdentity, PostgresAuditEventStore},
    };

    use std::sync::LazyLock;
    use tokio::sync::Mutex;

    /// Serializes the real-database tests and gives each one its OWN
    /// DATABASE: the audit tests reset the schema, the migration tests
    /// reset the schema, and both share one server -- running them against
    /// one database makes every reset a cross-test race. A dedicated
    /// database per test (created from the locator's DSN, dropped on
    /// release) removes the interference entirely.
    static DATABASE: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::const_new(()));

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

    /// One test's disposable database: created on acquisition, dropped
    /// (forced) on release. The `dsn` rewrites only the locator DSN's
    /// database path segment.
    struct TestDatabase {
        dsn: String,
        name: String,
        admin_pool: deadpool_postgres::Pool,
    }

    impl Drop for TestDatabase {
        fn drop(&mut self) {
            // Blocking drop inside a tokio test: run on a dedicated
            // single-thread runtime so teardown cannot be skipped by an
            // already-shutting-down test runtime.
            let name = self.name.clone();
            let pool = self.admin_pool.clone();
            let _ = std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build();
                if let Ok(runtime) = runtime {
                    runtime.block_on(async move {
                        if let Ok(client) = pool.get().await {
                            let _ = client
                                .batch_execute(&format!(
                                    "DROP DATABASE IF EXISTS {name} WITH (FORCE)"
                                ))
                                .await;
                        }
                    });
                }
            })
            .join();
        }
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
            "greengateway-audit-contract-{}",
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

    async fn create_test_database(admin_dsn: &str) -> TestDatabase {
        let name = format!("ggw_audit_test_{}", uuid::Uuid::new_v4().simple());
        let mut config = crate::config::Config::test_defaults();
        config.state_backend = crate::config::StateBackend::Postgres;
        config.deployment_id = Some("deploy-audit-contract".to_owned());
        config.database.tls_mode = crate::config::DatabaseTlsMode::LoopbackDev;

        let directory = std::env::temp_dir().join(format!(
            "greengateway-audit-contract-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&directory).expect("temp directory should create");
        let admin_path = directory.join("database-url");
        std::fs::write(&admin_path, format!("{admin_dsn}\n")).expect("DSN file should write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&admin_path, std::fs::Permissions::from_mode(0o600))
                .expect("DSN permissions should set");
        }
        config.database.url_file = Some(admin_path.display().to_string());
        let admin = PostgresFoundation::establish(&config)
            .await
            .expect("admin connection should establish");

        // Single-statement simple protocol: CREATE DATABASE cannot run in a
        // transaction block.
        admin
            .pool()
            .get()
            .await
            .expect("admin checkout")
            .batch_execute(&format!("CREATE DATABASE {name}"))
            .await
            .unwrap_or_else(|error| panic!("test database should create: {error}"));

        let dsn_path = directory.join("database-url-test");
        std::fs::write(&dsn_path, format!("{admin_dsn}\n")).expect("DSN file should write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dsn_path, std::fs::Permissions::from_mode(0o600))
                .expect("DSN permissions should set");
        }
        drop(admin);
        let _ = std::fs::remove_dir_all(&directory);

        // Rewrite ONLY the database path segment of the DSN: a plain string
        // replace would also rewrite the username, which for these test
        // DSNs is spelled like the database.
        let database_start = admin_dsn
            .rfind('/')
            .expect("locator DSN has a database path segment");
        let dsn = format!("{}/{}", &admin_dsn[..database_start], name);
        // The teardown pool must connect to the ADMIN database, not the
        // disposable one: DROP DATABASE cannot run on a session that has
        // the target open. (An adversarial review caught this exact leak:
        // every teardown failed with "cannot drop the currently open
        // database", stranding 800+ MB of test databases per run.)
        let parsed_admin =
            tokio_postgres::Config::from_str(admin_dsn).expect("admin DSN should parse");
        TestDatabase {
            dsn,
            name,
            admin_pool: deadpool_postgres::Pool::builder(deadpool_postgres::Manager::new(
                parsed_admin,
                tokio_postgres::NoTls,
            ))
            .config({
                let mut pool_config = deadpool_postgres::PoolConfig::new(4);
                pool_config.timeouts.create = Some(std::time::Duration::from_millis(5_000));
                pool_config
            })
            .runtime(deadpool_postgres::Runtime::Tokio1)
            .build()
            .expect("admin pool should build"),
        }
    }

    async fn migrated_store(database: &TestDatabase) -> PostgresAuditEventStore {
        let mut config = crate::config::Config::test_defaults();
        config.state_backend = crate::config::StateBackend::Postgres;
        config.deployment_id = Some("deploy-audit-contract".to_owned());
        let test_dsn_file = write_dsn_file(&database.dsn);
        config.database.url_file = Some(test_dsn_file.path.clone());
        config.database.tls_mode = crate::config::DatabaseTlsMode::LoopbackDev;
        let foundation = PostgresFoundation::establish(&config)
            .await
            .expect("the test database should establish");
        migrations::apply_missing_for_startup(foundation.pool(), &config.database)
            .await
            .expect("the audit schema should migrate");
        PostgresAuditEventStore::new(
            foundation.pool().clone(),
            Some(IngestIdentity {
                instance_id: uuid::Uuid::new_v4(),
                boot_id: uuid::Uuid::new_v4(),
            }),
        )
    }

    #[tokio::test]
    async fn postgres_audit_event_store_satisfies_the_contract() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let store = migrated_store(&database).await;
        super::audit_event_store_contract(&store).await;
    }

    // ------------------------------------------------------------------
    // Versioned policy control plane (issue #241, PR 7)
    // ------------------------------------------------------------------

    use crate::storage::policy_history::{
        PolicyCommitError, PolicyCommitPrecondition, PolicyCommitRequest, PolicyControlPlane,
    };
    use crate::storage::postgres_policy::PostgresPolicyStore;

    async fn migrated_policy_store(
        database: &TestDatabase,
    ) -> (Arc<PostgresPolicyStore>, deadpool_postgres::Pool) {
        let test_dsn_file = write_dsn_file(&database.dsn);
        let mut config = crate::config::Config::test_defaults();
        config.state_backend = crate::config::StateBackend::Postgres;
        config.deployment_id = Some("deploy-policy-contract".to_owned());
        config.database.url_file = Some(test_dsn_file.path.clone());
        config.database.tls_mode = crate::config::DatabaseTlsMode::LoopbackDev;
        let foundation = PostgresFoundation::establish(&config)
            .await
            .expect("the test database should establish");
        migrations::apply_missing_for_startup(foundation.pool(), &config.database)
            .await
            .expect("the policy schema should migrate");
        let pool = foundation.pool().clone();
        (Arc::new(PostgresPolicyStore::new(pool.clone())), pool)
    }

    static TEST_DIFF_SUMMARY: std::sync::LazyLock<Value> =
        std::sync::LazyLock::new(|| json!({ "action": "test_commit" }));

    fn commit_request<'a>(
        precondition: PolicyCommitPrecondition,
        policy: &'a Policy,
        actor: &'a str,
    ) -> PolicyCommitRequest<'a> {
        PolicyCommitRequest {
            precondition,
            candidate: policy,
            actor_user_id: actor,
            diff_summary: &TEST_DIFF_SUMMARY,
        }
    }

    fn policy_with_role(id: &str, role: &str) -> Policy {
        contract_policy_variant(id, role)
    }

    fn contract_policy_variant(id: &str, role: &str) -> Policy {
        Policy::validate_json_value(json!({
            "schema_version": "0.1.0",
            "id": id,
            "default_action": "deny",
            "roles": {
                role: { "permissions": ["data:read"] }
            }
        }))
        .expect("test policy should validate")
    }

    async fn count_rows(pool: &deadpool_postgres::Pool, table: &str) -> i64 {
        let client = pool.get().await.expect("count checkout");
        let row = client
            .query_one(&format!("SELECT count(*) FROM greengateway.{table}"), &[])
            .await
            .expect("count query");
        row.get(0)
    }

    #[tokio::test]
    async fn policy_control_plane_initialize_commits_version_revision_and_outbox_atomically() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let (store, pool) = migrated_policy_store(&database).await;

        assert_eq!(
            store
                .revision_source()
                .current()
                .await
                .expect("initial revision read"),
            0
        );
        assert!(
            PolicyControlPlane::active(&*store)
                .await
                .expect("initial active read")
                .is_none(),
            "an unmigrated deployment has no active policy"
        );

        let initial = policy_with_role("policy-a", "reader");
        let active = PolicyControlPlane::commit(
            &*store,
            commit_request(PolicyCommitPrecondition::Initialize, &initial, "op-1"),
        )
        .await
        .expect("initialize should commit");
        assert_eq!(active.security_revision, 1);
        assert_eq!(active.policy, initial);
        assert_eq!(
            PolicyControlPlane::active(&*store)
                .await
                .expect("active read after initialize")
                .map(|active| (active.version, active.security_revision)),
            Some((active.version, 1))
        );
        assert_eq!(
            count_rows(&pool, "policy_documents").await,
            1,
            "one immutable version"
        );
        assert_eq!(count_rows(&pool, "policy_active").await, 1);
        assert_eq!(
            count_rows(&pool, "security_outbox").await,
            1,
            "the outbox row commits with the mutation"
        );

        // A second Initialize loses: exactly one initialization exists.
        let result = PolicyControlPlane::commit(
            &*store,
            commit_request(PolicyCommitPrecondition::Initialize, &initial, "op-2"),
        )
        .await;
        assert_eq!(result.err(), Some(PolicyCommitError::PreconditionFailed));
        assert_eq!(count_rows(&pool, "policy_documents").await, 1);

        // A commit with the wrong expected ETag is a 412-shaped rejection
        // that writes nothing.
        let stale = PolicyControlPlane::commit(
            &*store,
            commit_request(
                PolicyCommitPrecondition::Expected {
                    etag: "\"sha256:stale\"".to_owned(),
                },
                &policy_with_role("policy-b", "reader"),
                "op-3",
            ),
        )
        .await;
        assert_eq!(stale.err(), Some(PolicyCommitError::PreconditionFailed));
        assert_eq!(count_rows(&pool, "policy_documents").await, 1);
        assert_eq!(count_rows(&pool, "security_outbox").await, 1);
        assert_eq!(
            store
                .revision_source()
                .current()
                .await
                .expect("revision after rejects"),
            1,
            "a rejected precondition must not consume a revision"
        );

        // A correct expected ETag wins: new version, revision 2, outbox 2.
        let second = PolicyControlPlane::commit(
            &*store,
            commit_request(
                PolicyCommitPrecondition::Expected { etag: active.etag },
                &policy_with_role("policy-b", "writer"),
                "op-4",
            ),
        )
        .await
        .expect("second commit should win");
        assert_eq!(second.security_revision, 2);
        assert!(second.version > active.version);
        assert_eq!(count_rows(&pool, "policy_documents").await, 2);
        assert_eq!(count_rows(&pool, "security_outbox").await, 2);

        // The outbox records the revision, resource, and version pair --
        // identifiers and revisions only.
        let entries = store.outbox_after(0, 10).await.expect("outbox should read");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].revision, 1);
        assert_eq!(entries[0].resource_type, "policy");
        assert_eq!(entries[0].from_version, None);
        assert_eq!(entries[0].to_version, active.version);
        assert_eq!(entries[1].revision, 2);
        assert_eq!(entries[1].from_version, Some(active.version));
        assert_eq!(entries[1].to_version, second.version);
    }

    #[tokio::test]
    async fn policy_control_plane_concurrent_same_etag_commits_produce_exactly_one_winner() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        // Two store instances on separate pools: two writers as two
        // replicas would be, racing the same expected ETag.
        let (store_a, _pool_a) = migrated_policy_store(&database).await;
        let (store_b, pool_b) = migrated_policy_store(&database).await;

        let initial = policy_with_role("race-base", "reader");
        let active = PolicyControlPlane::commit(
            &*store_a,
            commit_request(PolicyCommitPrecondition::Initialize, &initial, "op-1"),
        )
        .await
        .expect("initialize should commit");

        let candidate_a = policy_with_role("race-a", "reader");
        let candidate_b = policy_with_role("race-b", "writer");
        let etag = active.etag.clone();
        let (result_a, result_b) = tokio::join!(
            PolicyControlPlane::commit(
                &*store_a,
                commit_request(
                    PolicyCommitPrecondition::Expected { etag: etag.clone() },
                    &candidate_a,
                    "replica-a"
                )
            ),
            PolicyControlPlane::commit(
                &*store_b,
                commit_request(
                    PolicyCommitPrecondition::Expected { etag: etag.clone() },
                    &candidate_b,
                    "replica-b"
                )
            )
        );
        let winners = [result_a, result_b]
            .into_iter()
            .filter(|result| result.is_ok())
            .count();
        assert_eq!(winners, 1, "exactly one of the racing writers wins");
        // And exactly one new document/revision/outbox row exist: the
        // loser's transaction wrote nothing.
        assert_eq!(count_rows(&pool_b, "policy_documents").await, 2);
        assert_eq!(count_rows(&pool_b, "security_outbox").await, 2);
        assert_eq!(
            store_a
                .revision_source()
                .current()
                .await
                .expect("revision after race"),
            2
        );
    }

    #[tokio::test]
    async fn policy_control_plane_concurrent_initializers_produce_exactly_one_winner() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let (store_a, pool) = migrated_policy_store(&database).await;
        let (store_b, _pool_b) = migrated_policy_store(&database).await;

        let candidate_a = policy_with_role("init-a", "reader");
        let candidate_b = policy_with_role("init-b", "writer");
        let (result_a, result_b) = tokio::join!(
            PolicyControlPlane::commit(
                &*store_a,
                commit_request(
                    PolicyCommitPrecondition::Initialize,
                    &candidate_a,
                    "replica-a"
                )
            ),
            PolicyControlPlane::commit(
                &*store_b,
                commit_request(
                    PolicyCommitPrecondition::Initialize,
                    &candidate_b,
                    "replica-b"
                )
            )
        );
        let winners = [result_a, result_b]
            .into_iter()
            .filter(|result| result.is_ok())
            .count();
        assert_eq!(winners, 1, "a deployment is initialized exactly once");
        assert_eq!(count_rows(&pool, "policy_active").await, 1);
        assert_eq!(count_rows(&pool, "policy_documents").await, 1);
        assert_eq!(count_rows(&pool, "security_outbox").await, 1);
    }

    #[tokio::test]
    async fn policy_control_plane_aborted_commit_writes_nothing() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let (store, pool) = migrated_policy_store(&database).await;

        let initial = policy_with_role("abort-base", "reader");
        let active = PolicyControlPlane::commit(
            &*store,
            commit_request(PolicyCommitPrecondition::Initialize, &initial, "op-1"),
        )
        .await
        .expect("initialize should commit");

        // Drive the commit transaction's real statements on a raw
        // connection and roll back: the new immutable document, the
        // reserved revision, the pointer advance, and the outbox row all
        // roll back together, and the revision counter does not consume
        // the aborted reservation.
        let client = pool.get().await.expect("raw checkout");
        client
            .batch_execute("BEGIN")
            .await
            .expect("abort txn should begin");
        client
            .execute(
                "SELECT active_version, document_etag FROM greengateway.policy_active \
                 WHERE singleton FOR UPDATE",
                &[],
            )
            .await
            .expect("abort txn should lock");
        client
            .execute(
                r#"
                INSERT INTO greengateway.policy_documents (
                    actor_user_id, diff_summary, document, document_etag
                )
                VALUES ('abort-op', '{}'::jsonb, '{}'::jsonb, '"sha256:abort"')
                "#,
                &[],
            )
            .await
            .expect("abort document should insert");
        client
            .execute(
                "UPDATE greengateway.security_revision_state \
                 SET last_revision = last_revision + 1 WHERE singleton",
                &[],
            )
            .await
            .expect("abort revision should reserve");
        client
            .batch_execute("ROLLBACK")
            .await
            .expect("abort txn should roll back");
        drop(client);

        assert_eq!(
            count_rows(&pool, "policy_documents").await,
            1,
            "the aborted document must not exist"
        );
        assert_eq!(count_rows(&pool, "security_outbox").await, 1);
        assert_eq!(
            store
                .revision_source()
                .current()
                .await
                .expect("revision after abort"),
            active.security_revision,
            "an aborted commit must not consume a revision"
        );
        let still_active = PolicyControlPlane::active(&*store)
            .await
            .expect("active read");
        assert_eq!(
            still_active.expect("active row persists").version,
            active.version
        );
    }

    #[tokio::test]
    async fn policy_control_plane_active_fails_closed_on_a_tampered_etag() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let (store, pool) = migrated_policy_store(&database).await;

        let initial = policy_with_role("tamper-base", "reader");
        PolicyControlPlane::commit(
            &*store,
            commit_request(PolicyCommitPrecondition::Initialize, &initial, "op-1"),
        )
        .await
        .expect("initialize should commit");

        let client = pool.get().await.expect("tamper checkout");
        client
            .execute(
                "UPDATE greengateway.policy_active SET document_etag = '\"sha256:lie\"'",
                &[],
            )
            .await
            .expect("tamper should apply");
        drop(client);

        let error = PolicyControlPlane::active(&*store)
            .await
            .expect_err("a mismatched ETag must fail closed");
        assert_eq!(error.kind(), RepositoryErrorKind::InvalidData);
        // The commit path performs the same self-consistency check inside
        // its transaction, so a tampered pointer refuses mutations instead
        // of being silently healed by the next writer (a defect this test
        // caught in review: the first version verified the ETag only on
        // the read path).
        let commit_error = PolicyControlPlane::commit(
            &*store,
            commit_request(
                PolicyCommitPrecondition::Expected {
                    etag: "\"sha256:lie\"".to_owned(),
                },
                &policy_with_role("tamper-next", "reader"),
                "op-2",
            ),
        )
        .await
        .expect_err("commit over a tampered pointer must fail closed");
        assert_eq!(
            commit_error,
            PolicyCommitError::Store(RepositoryError::new(
                RepositoryErrorKind::InvalidData,
                "policy_commit"
            )),
            "store errors classify without leaking query values: {commit_error}"
        );
    }

    #[tokio::test]
    async fn policy_history_contract_on_postgres_matches_the_standalone_shape() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let (store, _pool) = migrated_policy_store(&database).await;

        // Three commits: the immutable documents double as the history.
        let mut etag = None;
        for index in 0..3 {
            let policy = policy_with_role(&format!("history-{index}"), "reader");
            let precondition = match etag.clone() {
                Some(etag) => PolicyCommitPrecondition::Expected { etag },
                None => PolicyCommitPrecondition::Initialize,
            };
            etag = Some(
                PolicyControlPlane::commit(&*store, commit_request(precondition, &policy, "op"))
                    .await
                    .expect("history commit should win")
                    .etag,
            );
        }

        let history = store.as_ref() as &dyn PolicyHistory;
        let page = history
            .list_versions(&PolicyHistoryListFilters {
                limit: 2,
                cursor: None,
                include_policy: false,
            })
            .await
            .expect("first page");
        assert_eq!(page.versions.len(), 2);
        assert!(page.next_cursor.is_some());
        assert!(
            page.versions.iter().all(|version| version.policy.is_none()),
            "include_policy=false must omit snapshots"
        );
        // Newest-first.
        assert!(page.versions[0].version > page.versions[1].version);
        assert_eq!(page.versions[0].actor_user_id, "op");

        let second = history
            .list_versions(&PolicyHistoryListFilters {
                limit: 2,
                cursor: page.next_cursor.clone(),
                include_policy: true,
            })
            .await
            .expect("second page");
        assert_eq!(second.versions.len(), 1);
        assert!(second.next_cursor.is_none());
        let snapshot = second.versions[0]
            .policy
            .as_ref()
            .expect("include_policy=true returns the snapshot");
        assert_eq!(snapshot.id.as_deref(), Some("history-0"));

        // Detail reads return the exact stored snapshot.
        let detail = history
            .get_version(page.versions[0].version)
            .await
            .expect("detail read")
            .expect("version exists");
        assert_eq!(
            detail.policy.as_ref().and_then(|policy| policy.id.clone()),
            Some("history-2".to_owned()),
            "the newest version is the last committed document"
        );

        // Bad cursors are caller errors, not store failures.
        let bad = history
            .list_versions(&PolicyHistoryListFilters {
                limit: 2,
                cursor: Some("0".to_owned()),
                include_policy: false,
            })
            .await
            .expect_err("non-positive cursor must be rejected");
        assert_eq!(bad.invalid_parameter_name(), Some("cursor"));

        // History appends outside a commit transaction are refused.
        let append = history
            .append_version("op", &json!({}), &policy_with_role("no-append", "reader"))
            .await
            .expect_err("cluster history is transactional only");
        assert_eq!(append.kind(), RepositoryErrorKind::Internal);
    }

    #[tokio::test]
    async fn postgres_audit_overlapping_retries_keep_the_stream_contiguous() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let store = migrated_store(&database).await;

        // The at-least-once shape the contract performs on audit_events,
        // asserted here on the STREAM: a batch, then an overlapping retry
        // that carries the committed id plus a new one. The already-
        // streamed id must consume no position (an adversarial review
        // falsified an earlier append that assigned row_number() over all
        // input ids before ON CONFLICT skipped them, gapping the stream
        // permanently at 2).
        store
            .insert_events(&[contract_event("overlap-a", "audit.overlap", json!({}))])
            .await
            .expect("first batch should commit");
        store
            .insert_events(&[
                contract_event("overlap-a", "audit.overlap", json!({})),
                contract_event("overlap-b", "audit.overlap", json!({})),
            ])
            .await
            .expect("overlapping retry should commit");

        let walked = store
            .stream_after(0, 100)
            .await
            .expect("stream should walk");
        assert_eq!(
            walked
                .iter()
                .map(|(position, event)| (*position, event.event_id.as_str()))
                .collect::<Vec<_>>(),
            vec![(1, "overlap-a"), (2, "overlap-b")],
            "an overlapping retry must not consume a position for an already-streamed id"
        );
        assert_eq!(store.stream_head().await.expect("head"), 2);
    }

    #[tokio::test]
    async fn postgres_audit_stream_positions_are_commit_ordered() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let store = migrated_store(&database).await;

        // Six concurrent batches of three events. Whatever interleaving the
        // pool allows, the stream must come out contiguous: every position
        // from 1 to 18 exactly once, because position assignment and commit
        // are serialized together by the transaction-scoped advisory lock.
        const BATCHES: usize = 6;
        const PER_BATCH: usize = 3;
        let batches: Vec<Vec<AuditEvent>> = (0..BATCHES)
            .map(|batch| {
                (0..PER_BATCH)
                    .map(|index| {
                        contract_event(
                            &format!("race-{batch}-{index}"),
                            "audit.race",
                            json!({ "status": 200 }),
                        )
                    })
                    .collect()
            })
            .collect();
        let futures: Vec<_> = batches
            .iter()
            .map(|events| store.insert_events(events))
            .collect();
        futures_util::future::try_join_all(futures)
            .await
            .expect("every racing batch should commit");

        let head = store.stream_head().await.expect("head should read");
        assert_eq!(head, (BATCHES * PER_BATCH) as i64);

        let walked = store
            .stream_after(0, 1000)
            .await
            .expect("stream should walk");
        assert_eq!(walked.len(), BATCHES * PER_BATCH);
        let positions: Vec<i64> = walked.iter().map(|(position, _)| *position).collect();
        let expected: Vec<i64> = (1..=(BATCHES * PER_BATCH) as i64).collect();
        assert_eq!(
            positions, expected,
            "commit-ordered positions must be contiguous with no gaps or duplicates"
        );
        // Each event appears exactly once in the stream.
        let mut ids: Vec<&str> = walked
            .iter()
            .map(|(_, event)| event.event_id.as_str())
            .collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), BATCHES * PER_BATCH);
    }

    #[tokio::test]
    async fn postgres_audit_aborted_batch_leaves_no_stream_hole() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let store = migrated_store(&database).await;

        // A committed batch first, so the stream has a position.
        store
            .insert_events(&[contract_event("abort-before", "audit.abort", json!({}))])
            .await
            .expect("setup batch should commit");

        // An aborted batch: the exact statements the store's append
        // protocol runs (advisory lock, then the counter-reserving CTE
        // append), driven on a raw connection and rolled back. The
        // rollback must release the reservation leaving no row and, since
        // the counter update rolls back with the transaction, no consumed
        // position -- the next committed batch reuses the number. Driving
        // the real statement (not a hand-rolled approximation) is
        // load-bearing: the PR-6 review noted the earlier hand-rolled
        // version tested the replaced protocol, not this one.
        let test_dsn_file = write_dsn_file(&database.dsn);
        let mut config = crate::config::Config::test_defaults();
        config.state_backend = crate::config::StateBackend::Postgres;
        config.deployment_id = Some("deploy-audit-contract".to_owned());
        config.database.url_file = Some(test_dsn_file.path.clone());
        config.database.tls_mode = crate::config::DatabaseTlsMode::LoopbackDev;
        let foundation = PostgresFoundation::establish(&config)
            .await
            .expect("raw connection should establish");
        let client = foundation.pool().get().await.expect("raw checkout");
        client
            .batch_execute("BEGIN")
            .await
            .expect("abort batch should begin");
        client
            .execute(
                "INSERT INTO greengateway.audit_events (\
                     event_id, event_type, occurred_at, schema_version, request_id, \
                     source_ip, payload_json\
                 ) VALUES ('abort-mid', 'audit.abort', now(), '0.2.0', 'r', 'ip', '{}'::jsonb)",
                &[],
            )
            .await
            .expect("abort batch event insert should run");
        client
            .execute(
                &format!("SELECT pg_advisory_xact_lock({})", *super_db_key()),
                &[],
            )
            .await
            .expect("abort batch lock should be taken");
        // The real reservation CTE: pending anti-join, counter UPDATE with
        // RETURNING, assignment, INSERT -- identical in shape to
        // APPEND_STREAM_SQL so the rollback exercises the reservation.
        client
            .execute(
                r#"
                WITH pending AS (
                    SELECT batch.event_id
                    FROM UNNEST(ARRAY['abort-mid']::text[]) AS batch(event_id)
                    WHERE NOT EXISTS (
                        SELECT 1 FROM greengateway.audit_stream s
                        WHERE s.event_id = batch.event_id
                    )
                ),
                reserved AS (
                    UPDATE greengateway.audit_stream_state
                    SET last_position = last_position + (SELECT count(*) FROM pending)
                    WHERE singleton
                    RETURNING last_position - (SELECT count(*) FROM pending) AS base_position
                ),
                assigned AS (
                    SELECT reserved.base_position
                           + row_number() OVER (ORDER BY pending.event_id) AS position,
                           pending.event_id
                    FROM pending CROSS JOIN reserved
                )
                INSERT INTO greengateway.audit_stream (position, event_id)
                SELECT position, event_id FROM assigned
                ON CONFLICT (event_id) DO NOTHING
                "#,
                &[],
            )
            .await
            .expect("abort batch stream append should run");
        client
            .batch_execute("ROLLBACK")
            .await
            .expect("abort batch should roll back");

        // The counter rolled back with the transaction: reading it must
        // still report the pre-abort head, not the reserved value.
        let counter_row = foundation
            .pool()
            .get()
            .await
            .expect("counter checkout")
            .query_one(
                "SELECT last_position FROM greengateway.audit_stream_state WHERE singleton",
                &[],
            )
            .await
            .expect("counter should read");
        assert_eq!(
            counter_row.get::<_, i64>(0),
            1,
            "the aborted reservation must roll back with the transaction"
        );

        // The next committed batch continues without a hole.
        store
            .insert_events(&[contract_event("abort-after", "audit.abort", json!({}))])
            .await
            .expect("post-abort batch should commit");

        let head = store.stream_head().await.expect("head should read");
        assert_eq!(head, 2, "an aborted append must not consume a position");
        let walked = store
            .stream_after(0, 100)
            .await
            .expect("stream should walk");
        assert_eq!(
            walked
                .iter()
                .map(|(_, event)| event.event_id.as_str())
                .collect::<Vec<_>>(),
            vec!["abort-before", "abort-after"],
            "the aborted event must be absent and the survivors contiguous"
        );
    }

    fn super_db_key() -> &'static i64 {
        &crate::storage::postgres_audit::AUDIT_STREAM_LOCK_KEY
    }

    #[tokio::test]
    async fn postgres_audit_positions_survive_retention_restart() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let store = migrated_store(&database).await;

        // Batch one occupies positions 1..=2.
        store
            .insert_events(&[
                contract_event("retention-a", "audit.retention", json!({})),
                contract_event("retention-b", "audit.retention", json!({})),
            ])
            .await
            .expect("first batch should commit");
        assert_eq!(store.stream_head().await.expect("head"), 2);

        // Retention removes every stream row. Under PR 5's max(position)
        // assignment this would reset numbering to 1 -- silently stranding
        // every durable cursor at a position that gets renumbered. The
        // persistent counter (migration 3) must keep the number space
        // monotonic.
        {
            let test_dsn_file = write_dsn_file(&database.dsn);
            let mut config = crate::config::Config::test_defaults();
            config.state_backend = crate::config::StateBackend::Postgres;
            config.deployment_id = Some("deploy-audit-contract".to_owned());
            config.database.url_file = Some(test_dsn_file.path.clone());
            config.database.tls_mode = crate::config::DatabaseTlsMode::LoopbackDev;
            let foundation = PostgresFoundation::establish(&config)
                .await
                .expect("retention connection should establish");
            foundation
                .pool()
                .get()
                .await
                .expect("retention checkout")
                .batch_execute("DELETE FROM greengateway.audit_stream")
                .await
                .expect("retention delete should run");
        }

        // The first-available computation now reports one past the
        // counter, not past any row.
        assert_eq!(
            store.stream_first_available().await.expect("first"),
            3,
            "an emptied stream must report the counter as the boundary"
        );

        // The next batch continues from 3: a client that saw position 2
        // resumes without ever observing renumbering.
        store
            .insert_events(&[contract_event("retention-c", "audit.retention", json!({}))])
            .await
            .expect("post-retention batch should commit");
        let walked = store
            .stream_after(0, 100)
            .await
            .expect("stream should walk");
        assert_eq!(
            walked
                .iter()
                .map(|(position, event)| (*position, event.event_id.as_str()))
                .collect::<Vec<_>>(),
            vec![(3, "retention-c")],
            "numbering must continue from the counter, not restart at 1"
        );
    }

    /// The #11 filtered-query benchmark, against PostgreSQL: seed N events
    /// (default 1,000,000; override with the runtime-keyed locator
    /// GATEWAY_TEST_POSTGRES_BENCHMARK_ROWS), then assert a representative
    /// filtered query answers under 500 ms. `#[ignore]`d because seeding is
    /// expensive: CI and operators run it deliberately.
    #[tokio::test]
    #[ignore = "seeds up to a million rows; run deliberately against a disposable database"]
    async fn postgres_audit_filtered_query_benchmark() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator");
            return;
        };
        let row_key = "GATEWAY_TEST_POSTGRES_BENCHMARK_ROWS".to_owned();
        let rows: usize = std::env::var(&row_key)
            .ok()
            .and_then(|value| value.trim().parse().ok())
            .unwrap_or(1_000_000);

        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let store = migrated_store(&database).await;
        let test_dsn_file = write_dsn_file(&database.dsn);
        let mut config = crate::config::Config::test_defaults();
        config.state_backend = crate::config::StateBackend::Postgres;
        config.deployment_id = Some("deploy-audit-contract".to_owned());
        config.database.url_file = Some(test_dsn_file.path.clone());
        config.database.tls_mode = crate::config::DatabaseTlsMode::LoopbackDev;
        let foundation = PostgresFoundation::establish(&config)
            .await
            .expect("benchmark connection should establish");

        let seeded = std::time::Instant::now();
        const BATCH: usize = 500;
        let mut id_base = 0usize;
        while id_base < rows {
            let events: Vec<AuditEvent> = (0..BATCH.min(rows - id_base))
                .map(|index| {
                    let sequence = id_base + index;
                    let status = 200 + sequence.is_multiple_of(4) as i64 * 203;
                    contract_event(
                        &format!("bench-{sequence}"),
                        if sequence.is_multiple_of(10) {
                            "audit.bench.rare"
                        } else {
                            "audit.bench.common"
                        },
                        json!({
                            "status": status,
                            "path": format!("/bench/{}", sequence % 1000),
                            "method": if sequence.is_multiple_of(2) { "GET" } else { "POST" },
                        }),
                    )
                })
                .collect();
            store
                .insert_events(&events)
                .await
                .expect("benchmark seed batch");
            id_base += BATCH;
        }
        eprintln!("seeded {rows} rows in {:?}", seeded.elapsed());

        // The filters deliberately intersect: i % 10 == 0 (rare type) AND
        // i % 1000 == 40 (path) AND i % 4 == 0 (status 403) has solutions
        // (i = 40, 1040, 2040, ...), so the measured query does real work
        // and returns rows -- an empty intersection would make the
        // benchmark vacuous.
        let start = std::time::Instant::now();
        let page = AuditEventStore::query_events(
            &store,
            &AuditQueryFilters {
                event_type: Some("audit.bench.rare".to_owned()),
                path: Some("/bench/40".to_owned()),
                status: Some(403),
                limit: 100,
                ..query_filters(None, 100)
            },
        )
        .await
        .expect("filtered benchmark query should succeed");
        let elapsed = start.elapsed();
        eprintln!(
            "filtered query returned {} events in {:?}",
            page.events.len(),
            elapsed
        );
        assert!(
            !page.events.is_empty(),
            "the benchmark filters must match real rows at {rows} seeded rows"
        );
        assert!(
            elapsed.as_millis() < 500,
            "issue #11's budget: filtered queries under 500 ms at {rows} rows (took {elapsed:?})"
        );
        // The disposable database (millions of seeded rows included) is
        // dropped by `TestDatabase`'s teardown.
        drop(foundation);
        drop(store);
    }

    use std::str::FromStr as _;
}

fn contract_policy(id: &str) -> Policy {
    Policy::validate_json_value(json!({
        "schema_version": "0.1.0",
        "id": id,
        "default_action": "deny",
        "roles": {
            "contract-reader": { "permissions": ["data:read"] }
        }
    }))
    .expect("contract policy should validate")
}

struct TempDb {
    path: PathBuf,
}

impl TempDb {
    fn new(test_name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "greengateway-storage-contract-{test_name}-{}.sqlite",
            uuid::Uuid::new_v4()
        ));

        Self { path }
    }
}

impl Drop for TempDb {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm"] {
            let path = PathBuf::from(format!("{}{}", self.path.display(), suffix));
            let _ = fs::remove_file(path);
        }
    }
}
