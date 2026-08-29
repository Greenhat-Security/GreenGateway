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
