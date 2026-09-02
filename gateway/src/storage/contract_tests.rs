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
            remaining_lifetime: None,
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

    // ------------------------------------------------------------------
    // Shared service-token store (issue #241, PR 9)
    // ------------------------------------------------------------------

    use crate::storage::postgres_service_tokens::PostgresServiceTokenStore;

    /// A migrated store on its own pool. Called twice by the race tests so
    /// the two writers are two replicas, not two tasks on one pool.
    async fn migrated_service_token_store(
        database: &TestDatabase,
    ) -> (Arc<PostgresServiceTokenStore>, deadpool_postgres::Pool) {
        let test_dsn_file = write_dsn_file(&database.dsn);
        let mut config = crate::config::Config::test_defaults();
        config.state_backend = crate::config::StateBackend::Postgres;
        config.deployment_id = Some("deploy-token-contract".to_owned());
        config.database.url_file = Some(test_dsn_file.path.clone());
        config.database.tls_mode = crate::config::DatabaseTlsMode::LoopbackDev;
        let foundation = PostgresFoundation::establish(&config)
            .await
            .expect("the test database should establish");
        migrations::apply_missing_for_startup(foundation.pool(), &config.database)
            .await
            .expect("the service-token schema should migrate");
        let pool = foundation.pool().clone();
        (Arc::new(PostgresServiceTokenStore::new(pool.clone())), pool)
    }

    async fn scalar_i64(pool: &deadpool_postgres::Pool, sql: &str) -> i64 {
        let client = pool.get().await.expect("client");
        client
            .query_one(sql, &[])
            .await
            .expect("scalar query")
            .get(0)
    }

    fn token_request(scopes: &[&str]) -> CreateTokenRequest {
        CreateTokenRequest {
            scopes: scopes.iter().map(|scope| (*scope).to_owned()).collect(),
            created_by: "contract-actor".to_owned(),
            expires_at: None,
        }
    }

    // ------------------------------------------------------------------
    // Shared JWT revocation denylist (issue #241, PR 9)
    // ------------------------------------------------------------------

    use crate::auth::RevocationStore;
    use crate::storage::postgres_jwt_revocations::{
        JwtRevocationOutcome, PostgresJwtRevocationStore,
    };

    /// One revoke through one replica is refused by another replica on its
    /// next lookup; an equal jti under a different issuer is untouched; a
    /// revocation past its expiry is a no-op on read and is removed by
    /// cleanup; a repeat revoke is idempotent and spends no revision.
    #[tokio::test]
    async fn jwt_revocations_are_shared_issuer_scoped_and_expire_on_database_time() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let (_tokens, pool_a) = migrated_service_token_store(&database).await;
        let (_tokens_b, pool_b) = migrated_service_token_store(&database).await;
        const SHARED: &str =
            "SELECT last_revision FROM greengateway.security_revision_state WHERE singleton";
        let deployment = "deploy-jwt-contract";
        let replica_a =
            PostgresJwtRevocationStore::new(pool_a.clone(), deployment, "https://issuer-a.example");
        let replica_b =
            PostgresJwtRevocationStore::new(pool_b.clone(), deployment, "https://issuer-a.example");
        let other_issuer =
            PostgresJwtRevocationStore::new(pool_b.clone(), deployment, "https://issuer-b.example");

        assert!(!replica_b.is_revoked("jti-1").await.expect("lookup"));
        let before = scalar_i64(&pool_a, SHARED).await;
        let first = replica_a
            .revoke("jti-1", None, "operator")
            .await
            .expect("revoke");
        let JwtRevocationOutcome::Revoked { security_revision } = first else {
            panic!("the first revoke inserts");
        };
        assert_eq!(
            security_revision,
            before + 1,
            "a revoke advances the shared revision once"
        );
        assert!(
            replica_b.is_revoked("jti-1").await.expect("lookup"),
            "the other replica refuses the jti on its next lookup"
        );
        assert!(
            !other_issuer.is_revoked("jti-1").await.expect("lookup"),
            "an equal jti under another issuer is a different JWT"
        );
        assert_eq!(
            replica_b
                .revoke("jti-1", None, "operator")
                .await
                .expect("revoke again"),
            JwtRevocationOutcome::AlreadyRevoked
        );
        assert_eq!(
            scalar_i64(&pool_a, SHARED).await,
            before + 1,
            "a repeat revoke spends no revision"
        );
        let digest = replica_a.jti_digest("jti-1");
        let outbox = scalar_i64(
            &pool_a,
            &format!(
                "SELECT COUNT(*) FROM greengateway.security_outbox \
                 WHERE resource_type = 'jwt_revocation' AND resource_id = '{digest}'"
            ),
        )
        .await;
        assert_eq!(outbox, 1, "exactly one outbox row, naming the digest");
        let raw_jti_rows = scalar_i64(
            &pool_a,
            "SELECT COUNT(*) FROM greengateway.security_outbox WHERE resource_id = 'jti-1'",
        )
        .await;
        assert_eq!(raw_jti_rows, 0, "the raw jti is nowhere in the database");

        // Expiry by the database clock: a short retention so the test can
        // watch the row lapse (an expiry already in the past is refused as
        // the caller's error, which the reactivation test covers).
        let short_lived =
            PostgresJwtRevocationStore::new(pool_a.clone(), deployment, "https://issuer-a.example")
                .with_retention_leeway_for_test(0.5);
        let in_one_second = (time::OffsetDateTime::now_utc() + std::time::Duration::from_secs(1))
            .format(&time::format_description::well_known::Rfc3339)
            .expect("rfc3339");
        short_lived
            .revoke("jti-expired", Some(&in_one_second), "operator")
            .await
            .expect("revoke with a short expiry");
        tokio::time::sleep(std::time::Duration::from_millis(1800)).await;
        assert!(
            !short_lived.is_revoked("jti-expired").await.expect("lookup"),
            "a revocation past its expiry and retention is a no-op on read"
        );
        assert_eq!(short_lived.cleanup_expired(100).await.expect("cleanup"), 1);
        assert_eq!(
            short_lived
                .cleanup_expired(100)
                .await
                .expect("cleanup again"),
            0
        );
        assert!(
            replica_b.is_revoked("jti-1").await.expect("lookup"),
            "unexpired rows survive cleanup"
        );
    }

    /// A denylist that cannot be consulted is a dependency failure (503),
    /// never "not revoked" and never an invalid credential.
    #[tokio::test]
    async fn an_unreachable_revocation_authority_is_a_dependency_failure() {
        let mut pg_config = tokio_postgres::Config::new();
        pg_config
            .host("127.0.0.1")
            .port(1)
            .user("nobody")
            .dbname("nowhere")
            .connect_timeout(std::time::Duration::from_millis(200));
        let mut pool_config = deadpool_postgres::PoolConfig::new(1);
        pool_config.timeouts.wait = Some(std::time::Duration::from_millis(500));
        pool_config.timeouts.create = Some(std::time::Duration::from_millis(500));
        let unreachable = deadpool_postgres::Pool::builder(deadpool_postgres::Manager::new(
            pg_config,
            tokio_postgres::NoTls,
        ))
        .config(pool_config)
        .runtime(deadpool_postgres::Runtime::Tokio1)
        .build()
        .expect("pool builds without connecting");
        let store =
            PostgresJwtRevocationStore::new(unreachable, "deploy", "https://issuer.example");
        let error = store
            .is_revoked("jti")
            .await
            .expect_err("no authority, no answer");
        assert!(
            matches!(error, crate::auth::AuthError::Upstream(_)),
            "dependency failure must be Upstream (503), got {error:?}"
        );
    }

    // ------------------------------------------------------------------
    // Shared rate limits and execution leases (issue #241, PR 10)
    // ------------------------------------------------------------------

    use crate::storage::{
        PostgresExecutionLeaseStore, PostgresRateLimitStore, SharedDecision, SharedLane,
        SharedLimit,
    };
    use crate::tools::lease::{ExecutionLeaseStore, LeaseAttempt};
    use std::time::Duration;

    fn limits_keyring() -> LocalSecretKeyring {
        LocalSecretKeyring::from_material_for_test(
            "rl-key-1",
            vec![("rl-key-1".to_owned(), [9u8; 32])],
        )
    }

    async fn migrated_limits_pool(database: &TestDatabase) -> deadpool_postgres::Pool {
        let test_dsn_file = write_dsn_file(&database.dsn);
        let mut config = crate::config::Config::test_defaults();
        config.state_backend = crate::config::StateBackend::Postgres;
        config.deployment_id = Some("deploy-limits-contract".to_owned());
        config.database.url_file = Some(test_dsn_file.path.clone());
        config.database.tls_mode = crate::config::DatabaseTlsMode::LoopbackDev;
        let foundation = PostgresFoundation::establish(&config)
            .await
            .expect("the test database should establish");
        migrations::apply_missing_for_startup(foundation.pool(), &config.database)
            .await
            .expect("the limits schema should migrate");
        foundation.pool().clone()
    }

    async fn decide(
        store: &PostgresRateLimitStore,
        lane: SharedLane,
        key: &str,
        limit: SharedLimit,
    ) -> SharedDecision {
        store
            .decide(lane, key, limit)
            .await
            .expect("the shared limiter decides")
    }

    /// The cluster contract: one configured burst permits that many
    /// requests across every replica together, refills on the database
    /// clock, and keeps lanes and callers apart.
    #[tokio::test]
    async fn one_burst_permits_that_many_requests_across_replicas() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let pool = migrated_limits_pool(&database).await;
        let replica_a =
            PostgresRateLimitStore::new(pool.clone(), "deploy-limits", limits_keyring(), 1_000);
        let replica_b =
            PostgresRateLimitStore::new(pool.clone(), "deploy-limits", limits_keyring(), 1_000);
        let limit = SharedLimit {
            requests_per_second: 1.0,
            burst: 3,
        };
        let caller = "ip:203.0.113.7";
        let mut allowed = 0;
        for (index, replica) in [&replica_a, &replica_b, &replica_a, &replica_b]
            .into_iter()
            .enumerate()
        {
            match decide(replica, SharedLane::Read, caller, limit).await {
                SharedDecision::Allowed => allowed += 1,
                SharedDecision::Denied => assert_eq!(index, 3, "only the fourth request is denied"),
            }
        }
        assert_eq!(
            allowed, 3,
            "a burst of three permits three across both replicas"
        );
        assert_eq!(
            decide(&replica_a, SharedLane::Read, caller, limit).await,
            SharedDecision::Denied
        );
        // Another caller, and the other lane, are separate buckets.
        assert_eq!(
            decide(&replica_b, SharedLane::Read, "ip:203.0.113.8", limit).await,
            SharedDecision::Allowed
        );
        assert_eq!(
            decide(&replica_b, SharedLane::Write, caller, limit).await,
            SharedDecision::Allowed
        );
        // Refill on database time: at one request per second, one permit
        // has returned after a second, and only one.
        tokio::time::sleep(Duration::from_millis(1_200)).await;
        assert_eq!(
            decide(&replica_b, SharedLane::Read, caller, limit).await,
            SharedDecision::Allowed
        );
        assert_eq!(
            decide(&replica_a, SharedLane::Read, caller, limit).await,
            SharedDecision::Denied
        );
        // A zero burst denies the very first request, as the local store does.
        let zero = SharedLimit {
            requests_per_second: 1.0,
            burst: 0,
        };
        assert_eq!(
            decide(&replica_a, SharedLane::Read, "ip:203.0.113.9", zero).await,
            SharedDecision::Denied
        );
        assert_eq!(replica_a.live_buckets().await.expect("count"), 4);
    }

    /// The policy lane keys buckets by rule as well as principal, and what
    /// the table holds is a keyed digest: never the caller key, and never
    /// the plain hash of it that a table reader could precompute.
    #[tokio::test]
    async fn policy_buckets_are_per_rule_and_digests_hide_the_caller() {
        use sha2::{Digest, Sha256};
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let pool = migrated_limits_pool(&database).await;
        let store =
            PostgresRateLimitStore::new(pool.clone(), "deploy-limits", limits_keyring(), 1_000);
        let one = SharedLimit {
            requests_per_second: 1.0,
            burst: 1,
        };
        let principal = "principal:0::jwt:alice";
        let under_rule_a = format!("rule:aaaa:{principal}");
        let under_rule_b = format!("rule:bbbb:{principal}");
        assert_eq!(
            decide(&store, SharedLane::Policy, &under_rule_a, one).await,
            SharedDecision::Allowed
        );
        assert_eq!(
            decide(&store, SharedLane::Policy, &under_rule_b, one).await,
            SharedDecision::Allowed,
            "a second rule is a second bucket"
        );
        assert_eq!(
            decide(&store, SharedLane::Policy, &under_rule_a, one).await,
            SharedDecision::Denied
        );

        let client = pool.get().await.expect("client");
        let rows = client
            .query(
                "SELECT lane, encode(key_digest, 'hex') AS digest FROM greengateway.rate_limit_buckets WHERE deployment_id = $1",
                &[&"deploy-limits"],
            )
            .await
            .expect("query");
        assert_eq!(rows.len(), 2);
        for row in rows {
            let lane: String = row.get("lane");
            let digest: String = row.get("digest");
            assert_eq!(lane, "policy");
            assert_eq!(digest.len(), 64);
            for raw in [&under_rule_a, &under_rule_b] {
                assert!(
                    !digest.contains(&hex::encode(raw.as_bytes())),
                    "the caller key is not stored"
                );
                let plain = hex::encode(Sha256::digest(raw.as_bytes()));
                assert_ne!(
                    digest, plain,
                    "the digest is keyed, not a plain hash of the caller key"
                );
            }
        }
        // A different deployment over the same key is a different digest.
        let other =
            PostgresRateLimitStore::new(pool.clone(), "deploy-other", limits_keyring(), 1_000);
        assert_eq!(
            decide(&other, SharedLane::Policy, &under_rule_a, one).await,
            SharedDecision::Allowed
        );
        let distinct: i64 = client
            .query_one(
                "SELECT count(DISTINCT key_digest) FROM greengateway.rate_limit_buckets",
                &[],
            )
            .await
            .expect("count")
            .get(0);
        assert_eq!(distinct, 3);
    }

    /// The hard cardinality bound: a spray of fresh identities evicts the
    /// oldest buckets rather than growing the table, the counter stays
    /// exact, and the idle sweep reclaims what nobody touches.
    #[tokio::test]
    async fn the_cardinality_bound_evicts_the_oldest_and_the_count_stays_exact() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let pool = migrated_limits_pool(&database).await;
        let store = PostgresRateLimitStore::new(pool.clone(), "deploy-limits", limits_keyring(), 5);
        let one = SharedLimit {
            requests_per_second: 0.0,
            burst: 1,
        };
        for index in 0..8 {
            assert_eq!(
                decide(
                    &store,
                    SharedLane::Read,
                    &format!("ip:198.51.100.{index}"),
                    one
                )
                .await,
                SharedDecision::Allowed
            );
            tokio::time::sleep(Duration::from_millis(15)).await;
        }
        let client = pool.get().await.expect("client");
        let rows: i64 = client
            .query_one(
                "SELECT count(*) FROM greengateway.rate_limit_buckets WHERE deployment_id = $1",
                &[&"deploy-limits"],
            )
            .await
            .expect("count")
            .get(0);
        assert_eq!(rows, 5, "the table never exceeds the bound");
        assert_eq!(
            store.live_buckets().await.expect("counter"),
            5,
            "the counter is exact"
        );
        // The oldest were evicted: the first caller starts a fresh bucket
        // (and is allowed again), while the newest still has its spent one.
        assert_eq!(
            decide(&store, SharedLane::Read, "ip:198.51.100.0", one).await,
            SharedDecision::Allowed
        );
        assert_eq!(
            decide(&store, SharedLane::Read, "ip:198.51.100.7", one).await,
            SharedDecision::Denied
        );
        assert_eq!(store.live_buckets().await.expect("counter"), 5);
        // The idle sweep, on database time, with a bound per call.
        assert_eq!(store.cleanup_idle(0.0, 2).await.expect("sweep"), 2);
        assert_eq!(store.live_buckets().await.expect("counter"), 3);
        assert_eq!(store.cleanup_idle(0.0, 100).await.expect("sweep"), 3);
        assert_eq!(store.live_buckets().await.expect("counter"), 0);
        assert_eq!(store.cleanup_idle(3_600.0, 100).await.expect("sweep"), 0);
    }

    /// Fail closed: a shared limiter that cannot be consulted answers 503
    /// with zero upstream attempts; it is never a silent allow and never a
    /// 429. Then, with the authority back, two replicas' middleware share
    /// one burst: the configured two requests are allowed across both, and
    /// the third is denied by the shared store while each replica's own
    /// bucket would still have allowed it.
    #[tokio::test]
    async fn an_unavailable_shared_limiter_is_a_503_with_no_upstream_attempt() {
        use axum::{
            body::Body, http::Request, middleware::from_fn_with_state, routing::get, Router,
        };
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tower::ServiceExt;
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let pool = migrated_limits_pool(&database).await;
        let store = Arc::new(PostgresRateLimitStore::new(
            pool.clone(),
            "deploy-limits",
            limits_keyring(),
            1_000,
        ));
        let mut config = crate::config::Config::test_defaults();
        config.rate_limit_read_rps = 1.0;
        config.rate_limit_read_burst = 2;
        let upstream_attempts = Arc::new(AtomicUsize::new(0));
        let replica = |store: &Arc<PostgresRateLimitStore>| {
            let state = crate::middleware::rate_limit::RateLimitState::from_config_and_policy(
                &config, None,
            )
            .with_shared_store(Arc::clone(store));
            let counter = Arc::clone(&upstream_attempts);
            Router::new()
                .route(
                    "/echo",
                    get(move || {
                        let counter = Arc::clone(&counter);
                        async move {
                            counter.fetch_add(1, Ordering::SeqCst);
                            "ok"
                        }
                    }),
                )
                .layer(from_fn_with_state(
                    state,
                    crate::middleware::rate_limit::rate_limit_request,
                ))
        };
        let replica_a = replica(&store);
        let replica_b = replica(&store);
        let request = || {
            Request::builder()
                .uri("/echo")
                .body(Body::empty())
                .expect("request")
        };

        // The authority's table is gone: the decision fails and the request
        // is refused with no upstream attempt (the local bucket still spent
        // a token on it: local first, then the authority).
        let client = pool.get().await.expect("client");
        client
            .batch_execute(
                "ALTER TABLE greengateway.rate_limit_buckets RENAME TO rate_limit_buckets_gone",
            )
            .await
            .expect("hide the table");
        let response = replica_a
            .clone()
            .oneshot(request())
            .await
            .expect("response");
        assert_eq!(
            response.status(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            upstream_attempts.load(Ordering::SeqCst),
            0,
            "no upstream attempt behind a 503"
        );
        client
            .batch_execute(
                "ALTER TABLE greengateway.rate_limit_buckets_gone RENAME TO rate_limit_buckets",
            )
            .await
            .expect("restore the table");

        // The authority is back. Replica A has one local token left and the
        // shared burst is untouched (the failed decision spent nothing):
        // A allows one; B, with a fresh local bucket, allows the second;
        // B's third is denied by the shared store, not by B's own bucket.
        let response = replica_a
            .clone()
            .oneshot(request())
            .await
            .expect("response");
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let response = replica_b
            .clone()
            .oneshot(request())
            .await
            .expect("response");
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let response = replica_b
            .clone()
            .oneshot(request())
            .await
            .expect("response");
        assert_eq!(
            response.status(),
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            "one configured burst is shared across both replicas"
        );
        assert_eq!(upstream_attempts.load(Ordering::SeqCst), 2);
    }

    /// Two acquirers that both saw the same slot free race on the row: the
    /// conflict predicate lets only an expired lease be taken over, so the
    /// loser sees no row and the winner's fence is never overwritten.
    #[tokio::test]
    async fn concurrent_acquirers_never_share_a_slot() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let pool = migrated_limits_pool(&database).await;
        let store = Arc::new(PostgresExecutionLeaseStore::new(
            pool.clone(),
            "deploy-limits",
            uuid::Uuid::new_v4(),
            Duration::from_secs(5),
        ));
        let mut attempts = Vec::new();
        for index in 0..12 {
            let store = Arc::clone(&store);
            attempts.push(tokio::spawn(async move {
                store
                    .try_acquire("global", 1, &format!("req-{index}"))
                    .await
                    .expect("acquire")
            }));
        }
        let mut winners = Vec::new();
        for attempt in attempts {
            if let LeaseAttempt::Acquired(lease) = attempt.await.expect("task") {
                winners.push(lease);
            }
        }
        assert_eq!(
            winners.len(),
            1,
            "exactly one acquirer holds the single slot"
        );
        assert!(
            store.is_current(&winners[0]).await.expect("check"),
            "the winner's fence was not overwritten by a losing acquirer"
        );
        let client = pool.get().await.expect("client");
        let fence: i64 = client
            .query_one(
                "SELECT fence FROM greengateway.execution_leases WHERE deployment_id = $1 AND scope = 'global' AND slot = 0",
                &[&"deploy-limits"],
            )
            .await
            .expect("row")
            .get(0);
        assert_eq!(fence, winners[0].fence);
    }

    /// The lease contract on PostgreSQL: slots are bounded across holders,
    /// fences strictly increase, a lapsed holder can neither renew nor
    /// release a successor's slot, and a crashed holder's slot returns only
    /// by database-time expiry.
    #[tokio::test]
    async fn leases_bound_slots_across_holders_and_fence_lapsed_holders() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let pool = migrated_limits_pool(&database).await;
        let ttl = Duration::from_millis(600);
        let holder_a = PostgresExecutionLeaseStore::new(
            pool.clone(),
            "deploy-limits",
            uuid::Uuid::new_v4(),
            ttl,
        );
        let holder_b = PostgresExecutionLeaseStore::new(
            pool.clone(),
            "deploy-limits",
            uuid::Uuid::new_v4(),
            ttl,
        );
        let acquired = |attempt: LeaseAttempt| match attempt {
            LeaseAttempt::Acquired(lease) => lease,
            LeaseAttempt::Full => panic!("expected a free slot"),
        };
        let first = acquired(
            holder_a
                .try_acquire("global", 2, "req-1")
                .await
                .expect("acquire"),
        );
        let second = acquired(
            holder_b
                .try_acquire("global", 2, "x".repeat(300).as_str())
                .await
                .expect("acquire"),
        );
        assert_ne!(first.slot, second.slot);
        assert!(second.fence > first.fence, "fences strictly increase");
        assert!(matches!(
            holder_a
                .try_acquire("global", 2, "req-3")
                .await
                .expect("acquire"),
            LeaseAttempt::Full
        ));
        assert!(matches!(
            holder_b
                .try_acquire("global", 2, "req-3")
                .await
                .expect("acquire"),
            LeaseAttempt::Full
        ));
        // Another scope is another set of slots.
        let tool_slot = acquired(
            holder_a
                .try_acquire("tool:alpha", 1, "req-4")
                .await
                .expect("acquire"),
        );
        assert!(tool_slot.fence > second.fence);

        assert!(holder_a.renew(&first).await.expect("renew"));
        assert!(holder_a.is_current(&first).await.expect("check"));
        assert!(
            !holder_b.is_current(&first).await.expect("check"),
            "a lease is current only for its holder"
        );
        holder_b.release(&second).await.expect("release");
        assert!(!holder_b.is_current(&second).await.expect("check"));
        let third = acquired(
            holder_b
                .try_acquire("global", 2, "req-5")
                .await
                .expect("acquire"),
        );
        assert_eq!(third.slot, second.slot, "a released slot is free at once");
        assert!(third.fence > tool_slot.fence);

        // Nobody renews: after the TTL on the database clock, both slots are
        // reclaimable, and the lapsed holders are fenced out.
        tokio::time::sleep(ttl + Duration::from_millis(300)).await;
        let successor = acquired(
            holder_b
                .try_acquire("global", 2, "req-6")
                .await
                .expect("acquire"),
        );
        assert_eq!(
            successor.slot, first.slot,
            "the lowest expired slot is taken first"
        );
        assert!(successor.fence > third.fence);
        assert!(
            !holder_a.renew(&first).await.expect("renew"),
            "a lapsed lease cannot be renewed"
        );
        assert!(!holder_a.is_current(&first).await.expect("check"));
        holder_a.release(&first).await.expect("release");
        assert!(
            holder_b.is_current(&successor).await.expect("check"),
            "a lapsed holder's release does not free the successor's slot"
        );
        assert!(holder_b.renew(&successor).await.expect("renew"));
    }

    // ------------------------------------------------------------------
    // Shared admin pending-login store (issue #241, PR 9)
    // ------------------------------------------------------------------

    use crate::auth::oidc_login::{PendingLogin, PendingLoginBackend, PendingLoginLimits};
    use crate::connections::local_secret::LocalSecretKeyring;
    use crate::storage::postgres_pending_logins::PostgresPendingLoginStore;

    fn login_keyring() -> LocalSecretKeyring {
        LocalSecretKeyring::from_material_for_test(
            "login-key-1",
            vec![("login-key-1".to_owned(), [7u8; 32])],
        )
    }

    fn pending(client_ip: &str) -> PendingLogin {
        PendingLogin {
            code_verifier: "verifier-abcdefghijklmnopqrstuvwxyz0123456789".to_owned(),
            nonce: "nonce-0123456789".to_owned(),
            created_at: std::time::Instant::now(),
            client_ip: client_ip.to_owned(),
        }
    }

    async fn pending_store(
        database: &TestDatabase,
        limits: PendingLoginLimits,
    ) -> (PostgresPendingLoginStore, deadpool_postgres::Pool) {
        let (_tokens, pool) = migrated_service_token_store(database).await;
        (
            PostgresPendingLoginStore::new(
                pool.clone(),
                "deploy-login-contract",
                login_keyring(),
                limits,
            ),
            pool,
        )
    }

    /// A login begun on one replica is consumed exactly once, on whichever
    /// replica the callback lands; the second callback -- on either -- gets
    /// nothing. Nothing in the database is the state or the verifier.
    #[tokio::test]
    async fn a_pending_login_is_consumed_exactly_once_across_replicas() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let (replica_a, pool) = pending_store(&database, PendingLoginLimits::default()).await;
        let (replica_b, _) = pending_store(&database, PendingLoginLimits::default()).await;

        assert!(replica_a
            .insert("state-1", pending("203.0.113.9"))
            .await
            .expect("insert"));
        let stored_verifiers = scalar_i64(
            &pool,
            "SELECT COUNT(*) FROM greengateway.admin_pending_logins \
             WHERE state_hash = 'state-1' OR client_key = '203.0.113.9' \
             OR verifier_ct = 'verifier-abcdefghijklmnopqrstuvwxyz0123456789'::bytea",
        )
        .await;
        assert_eq!(
            stored_verifiers, 0,
            "no raw state, client, or verifier in the table"
        );

        let consumed = replica_b
            .take("state-1")
            .await
            .expect("take")
            .expect("the other replica consumes the login");
        assert_eq!(
            consumed.code_verifier,
            "verifier-abcdefghijklmnopqrstuvwxyz0123456789"
        );
        assert_eq!(consumed.nonce, "nonce-0123456789");
        assert!(
            replica_a.take("state-1").await.expect("take").is_none(),
            "consumed once"
        );
        assert!(
            replica_b.take("state-1").await.expect("take").is_none(),
            "consumed once"
        );
        assert!(replica_a
            .take("never-issued")
            .await
            .expect("take")
            .is_none());
    }

    /// Two callbacks with the same state race on two replicas: exactly one
    /// wins the row.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_callbacks_consume_a_login_exactly_once() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let (replica_a, _) = pending_store(&database, PendingLoginLimits::default()).await;
        let (replica_b, _) = pending_store(&database, PendingLoginLimits::default()).await;
        let replica_a = Arc::new(replica_a);
        let replica_b = Arc::new(replica_b);
        for round in 0..6 {
            let state = format!("race-{round}");
            assert!(replica_a
                .insert(&state, pending("198.51.100.4"))
                .await
                .expect("insert"));
            let barrier = Arc::new(tokio::sync::Barrier::new(2));
            let take_on = |store: Arc<PostgresPendingLoginStore>, state: String| {
                let barrier = barrier.clone();
                tokio::spawn(async move {
                    barrier.wait().await;
                    store.take(&state).await
                })
            };
            let (first, second) = tokio::join!(
                take_on(replica_a.clone(), state.clone()),
                take_on(replica_b.clone(), state.clone())
            );
            let winners = [
                first.expect("task").expect("take"),
                second.expect("task").expect("take"),
            ]
            .into_iter()
            .filter(Option::is_some)
            .count();
            assert_eq!(winners, 1, "exactly one callback consumes the login");
        }
    }

    /// Expiry is the database clock's; the quotas are enforced in the
    /// insert transaction, per client and globally, without evicting a
    /// still-valid login.
    #[tokio::test]
    async fn pending_logins_expire_on_database_time_and_quotas_hold() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let (short_lived, _) = pending_store(
            &database,
            PendingLoginLimits {
                ttl: std::time::Duration::from_secs(1),
                max_entries: 3,
                max_per_ip: 2,
            },
        )
        .await;
        assert!(short_lived
            .insert("expiring", pending("192.0.2.1"))
            .await
            .expect("insert"));
        tokio::time::sleep(std::time::Duration::from_millis(1300)).await;
        assert!(
            short_lived.take("expiring").await.expect("take").is_none(),
            "an expired login cannot complete"
        );

        assert!(short_lived
            .insert("a-1", pending("192.0.2.1"))
            .await
            .expect("insert"));
        assert!(short_lived
            .insert("a-2", pending("192.0.2.1"))
            .await
            .expect("insert"));
        assert!(
            !short_lived
                .insert("a-3", pending("192.0.2.1"))
                .await
                .expect("insert"),
            "the per-client quota refuses the third login from one client"
        );
        assert!(short_lived
            .insert("b-1", pending("192.0.2.2"))
            .await
            .expect("insert"));
        assert!(
            !short_lived
                .insert("c-1", pending("192.0.2.3"))
                .await
                .expect("insert"),
            "the global quota refuses the fourth login"
        );
        assert!(
            short_lived.take("a-1").await.expect("take").is_some(),
            "a refused admission never evicted a valid login"
        );
    }

    /// A row whose ciphertext was altered, or that was sealed under a key
    /// this replica does not hold, fails closed as a store failure -- the
    /// handlers answer 503 -- never as "unknown state".
    #[tokio::test]
    async fn a_tampered_or_foreign_key_row_fails_closed() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let (store, pool) = pending_store(&database, PendingLoginLimits::default()).await;

        assert!(store
            .insert("tampered", pending("192.0.2.9"))
            .await
            .expect("insert"));
        let digest = store.state_digest("tampered");
        let client = pool.get().await.expect("client");
        client
            .execute(
                "UPDATE greengateway.admin_pending_logins \
                 SET verifier_ct = set_byte(verifier_ct, 0, (get_byte(verifier_ct, 0) # 255)) \
                 WHERE state_hash = $1",
                &[&digest],
            )
            .await
            .expect("tamper");
        let error = store
            .take("tampered")
            .await
            .err()
            .unwrap_or_else(|| panic!("a tampered envelope must not open"));
        assert_eq!(error.0.kind(), RepositoryErrorKind::InvalidData);

        assert!(store
            .insert("foreign", pending("192.0.2.9"))
            .await
            .expect("insert"));
        let digest = store.state_digest("foreign");
        client
            .execute(
                "UPDATE greengateway.admin_pending_logins SET key_id = 'someone-elses-key' \
                 WHERE state_hash = $1",
                &[&digest],
            )
            .await
            .expect("relabel");
        let error = store
            .take("foreign")
            .await
            .err()
            .unwrap_or_else(|| panic!("a key this replica does not hold fails closed"));
        assert_eq!(error.0.kind(), RepositoryErrorKind::InvalidData);

        // The associated data binds each envelope to its own row: two
        // validly sealed verifiers swapped between rows both fail to open.
        assert!(store
            .insert("swap-a", pending("192.0.2.9"))
            .await
            .expect("insert"));
        assert!(store
            .insert("swap-b", pending("192.0.2.9"))
            .await
            .expect("insert"));
        let (digest_a, digest_b) = (store.state_digest("swap-a"), store.state_digest("swap-b"));
        client
            .execute(SWAP_SEALED_VERIFIERS, &[&digest_a, &digest_b])
            .await
            .expect("swap");
        for state in ["swap-a", "swap-b"] {
            let error = store
                .take(state)
                .await
                .err()
                .unwrap_or_else(|| panic!("an envelope moved to another row must not open"));
            assert_eq!(error.0.kind(), RepositoryErrorKind::InvalidData);
        }
    }

    const SWAP_SEALED_VERIFIERS: &str = "WITH a AS (SELECT verifier_nonce, verifier_ct FROM greengateway.admin_pending_logins WHERE state_hash = $1), b AS (SELECT verifier_nonce, verifier_ct FROM greengateway.admin_pending_logins WHERE state_hash = $2), swap_a AS (UPDATE greengateway.admin_pending_logins SET verifier_nonce = b.verifier_nonce, verifier_ct = b.verifier_ct FROM b WHERE state_hash = $1) UPDATE greengateway.admin_pending_logins SET verifier_nonce = a.verifier_nonce, verifier_ct = a.verifier_ct FROM a WHERE state_hash = $2";

    /// A revocation given the token's own `exp` stays effective through the
    /// validator's `exp` leeway -- the token is accepted until then -- and
    /// cleanup reclaims it only afterwards.
    #[tokio::test]
    async fn a_revocation_outlives_its_expiry_by_the_validator_leeway() {
        use crate::auth::RevocationStore;
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let (_tokens, pool) = migrated_service_token_store(&database).await;
        let store = crate::storage::PostgresJwtRevocationStore::new(
            pool.clone(),
            "deploy-leeway",
            "https://issuer.example",
        )
        .with_retention_leeway_for_test(2.0);
        let exp = (time::OffsetDateTime::now_utc() + std::time::Duration::from_secs(1))
            .format(&time::format_description::well_known::Rfc3339)
            .expect("rfc3339");
        store
            .revoke("jti-leeway", Some(&exp), "operator")
            .await
            .expect("revoke");

        // Past `exp`, inside the leeway: the token is still accepted by the
        // validator, so it must still be refused here.
        tokio::time::sleep(std::time::Duration::from_millis(1400)).await;
        assert!(
            store.is_revoked("jti-leeway").await.expect("lookup"),
            "still revoked inside the leeway"
        );
        assert_eq!(
            store.cleanup_expired(100).await.expect("cleanup"),
            0,
            "not reclaimed inside the leeway"
        );

        // Past `exp + leeway`: no validator accepts the token any more.
        tokio::time::sleep(std::time::Duration::from_millis(1900)).await;
        assert!(!store.is_revoked("jti-leeway").await.expect("lookup"));
        assert_eq!(store.cleanup_expired(100).await.expect("cleanup"), 1);
    }

    /// A repeat revoke of a `jti` whose earlier finite row has lapsed
    /// reactivates it; one with a later expiry extends the row; one inside
    /// the effective window with no longer expiry spends nothing.
    #[tokio::test]
    async fn a_repeat_revoke_reactivates_a_lapsed_row_and_extends_a_shorter_one() {
        use crate::auth::RevocationStore;
        use crate::storage::JwtRevocationOutcome;
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let (_tokens, pool) = migrated_service_token_store(&database).await;
        let store = crate::storage::PostgresJwtRevocationStore::new(
            pool.clone(),
            "deploy-reactivate",
            "https://issuer.example",
        )
        .with_retention_leeway_for_test(1.0);
        let in_one_second = || {
            (time::OffsetDateTime::now_utc() + std::time::Duration::from_secs(1))
                .format(&time::format_description::well_known::Rfc3339)
                .expect("rfc3339")
        };
        let in_one_minute = (time::OffsetDateTime::now_utc() + std::time::Duration::from_secs(60))
            .format(&time::format_description::well_known::Rfc3339)
            .expect("rfc3339");

        // Lapsed row, then an unbounded revoke: reactivated, with a new revision.
        store
            .revoke("jti-lapsed", Some(&in_one_second()), "operator")
            .await
            .expect("revoke");
        tokio::time::sleep(std::time::Duration::from_millis(2300)).await;
        assert!(
            !store.is_revoked("jti-lapsed").await.expect("lookup"),
            "lapsed"
        );
        // A repeat carrying an expiry already in the past would produce a
        // row nothing is refused by; it is the caller's error, and no
        // revision is spent.
        let past = (time::OffsetDateTime::now_utc() - std::time::Duration::from_secs(5))
            .format(&time::format_description::well_known::Rfc3339)
            .expect("rfc3339");
        let refused = store
            .revoke("jti-lapsed", Some(&past), "operator")
            .await
            .expect_err("an expiry in the past is refused");
        assert_eq!(refused.invalid_parameter_name(), Some("expires_at"));
        assert!(!store.is_revoked("jti-lapsed").await.expect("lookup"));
        // Only RFC 3339 reaches the database: a PostgreSQL-only spelling is
        // the caller's error, not a server-dependent lifetime.
        for spelling in ["tomorrow", "infinity", "2030-01-01", "2030-01-01 00:00:00"] {
            let refused = store
                .revoke("jti-grammar", Some(spelling), "operator")
                .await
                .expect_err("a non-RFC-3339 expiry is refused");
            assert_eq!(
                refused.invalid_parameter_name(),
                Some("expires_at"),
                "{spelling}"
            );
        }
        assert!(!store.is_revoked("jti-grammar").await.expect("lookup"));
        // An empty jti names no token; the validator never asks about one.
        for empty in ["", "   "] {
            let refused = store
                .revoke(empty, None, "operator")
                .await
                .expect_err("an empty jti is refused");
            assert_eq!(refused.invalid_parameter_name(), Some("jti"));
        }
        let again = store
            .revoke("jti-lapsed", None, "operator")
            .await
            .expect("repeat revoke");
        assert!(
            matches!(again, JwtRevocationOutcome::Revoked { .. }),
            "a lapsed row is reactivated, not reported as already revoked: {again:?}"
        );
        assert!(store.is_revoked("jti-lapsed").await.expect("lookup"));
        assert_eq!(
            store
                .revoke("jti-lapsed", None, "operator")
                .await
                .expect("repeat"),
            JwtRevocationOutcome::AlreadyRevoked,
            "an unbounded row already covers any repeat"
        );

        // A shorter row inside its window, then a longer expiry: extended.
        store
            .revoke("jti-short", Some(&in_one_second()), "operator")
            .await
            .expect("revoke");
        let extended = store
            .revoke("jti-short", Some(&in_one_minute), "operator")
            .await
            .expect("extend");
        assert!(
            matches!(extended, JwtRevocationOutcome::Revoked { .. }),
            "{extended:?}"
        );
        assert_eq!(
            store
                .revoke("jti-short", Some(&in_one_second()), "operator")
                .await
                .expect("repeat"),
            JwtRevocationOutcome::AlreadyRevoked,
            "a shorter repeat inside the window spends nothing"
        );
        tokio::time::sleep(std::time::Duration::from_millis(2300)).await;
        assert!(
            store.is_revoked("jti-short").await.expect("lookup"),
            "the extended row outlives the original expiry"
        );
    }

    /// A revocation keyed on a token's own `exp` a few seconds in the past
    /// is still live: the validator accepts the token through its leeway,
    /// so the store accepts (and honours) an expiry inside the retention
    /// window rather than refusing it as "already past".
    #[tokio::test]
    async fn an_expiry_inside_the_leeway_window_is_a_live_revocation() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let (_tokens, pool) = migrated_service_token_store(&database).await;
        let store = crate::storage::PostgresJwtRevocationStore::new(
            pool.clone(),
            "deploy-jwt-leeway",
            "https://issuer-a.example",
        )
        .with_retention_leeway_for_test(30.0);
        let ten_seconds_ago = (time::OffsetDateTime::now_utc()
            - std::time::Duration::from_secs(10))
        .format(&time::format_description::well_known::Rfc3339)
        .expect("rfc3339");
        let outcome = store
            .revoke("jti-recent", Some(&ten_seconds_ago), "operator")
            .await
            .expect("an expiry inside the leeway window is accepted");
        assert!(matches!(
            outcome,
            crate::storage::JwtRevocationOutcome::Revoked { .. }
        ));
        assert!(
            store.is_revoked("jti-recent").await.expect("lookup"),
            "the revocation is effective for as long as the validator accepts the token"
        );
        assert_eq!(store.cleanup_expired(100).await.expect("cleanup"), 0);
        // Past the window it is refused, as before.
        let a_minute_ago = (time::OffsetDateTime::now_utc() - std::time::Duration::from_secs(60))
            .format(&time::format_description::well_known::Rfc3339)
            .expect("rfc3339");
        let refused = store
            .revoke("jti-stale", Some(&a_minute_ago), "operator")
            .await
            .expect_err("an expiry past the window is refused");
        assert_eq!(refused.invalid_parameter_name(), Some("expires_at"));
    }

    /// `migrate check` is validation only: it reads the deployment binding
    /// and never writes one, so a read-only check role can run it and an
    /// unbound database is not claimed by whichever deployment checked it.
    #[tokio::test]
    async fn migrate_check_reads_the_binding_and_never_writes_it() {
        use crate::storage::migrations::{execute, MigrateError, MigrateOutput};
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let (_tokens, pool) = migrated_service_token_store(&database).await;
        let test_dsn_file = write_dsn_file(&database.dsn);
        let config_for = |deployment: &str| {
            let mut config = crate::config::Config::test_defaults();
            config.state_backend = crate::config::StateBackend::Postgres;
            config.deployment_id = Some(deployment.to_owned());
            config.database.url_file = Some(test_dsn_file.path.clone());
            config.database.tls_mode = crate::config::DatabaseTlsMode::LoopbackDev;
            config
        };
        let bound_rows = || async {
            let client = pool.get().await.expect("client");
            client
                .query_one("SELECT count(*) FROM greengateway.deployment_binding", &[])
                .await
                .expect("count")
                .get::<_, i64>(0)
        };
        assert!(matches!(
            execute(&config_for("deploy-check-a"), true)
                .await
                .expect("check"),
            MigrateOutput::CheckCurrent
        ));
        assert_eq!(
            bound_rows().await,
            0,
            "a check never claims an unbound database"
        );
        crate::storage::postgres::bind_deployment(&pool, "deploy-check-a")
            .await
            .expect("bind");
        assert!(matches!(
            execute(&config_for("deploy-check-a"), true)
                .await
                .expect("check"),
            MigrateOutput::CheckCurrent
        ));
        let refused = execute(&config_for("deploy-check-b"), true)
            .await
            .expect_err("another deployment's database is refused");
        assert!(
            matches!(refused, MigrateError::DeploymentMismatch { ref bound } if bound == "deploy-check-a")
        );
        assert_eq!(bound_rows().await, 1);
    }

    /// An oversized creator ID and a malformed cursor timestamp are the
    /// caller's errors, judged before the insert and the cast that would
    /// otherwise surface them as store failures.
    #[tokio::test]
    async fn oversized_creator_and_malformed_cursor_are_the_callers_errors() {
        use crate::auth::tokens::{
            encode_cursor, CreateTokenRequest, TokenCursor, TokenListFilters,
        };
        use crate::storage::ServiceTokenStore;
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let (store, _pool) = migrated_service_token_store(&database).await;

        let refused = store
            .create(CreateTokenRequest {
                scopes: vec!["admin:tokens:read".to_owned()],
                created_by: "x".repeat(600),
                expires_at: None,
            })
            .await
            .err()
            .unwrap_or_else(|| panic!("a 600-byte creator exceeds the record bound"));
        assert_eq!(refused.invalid_parameter_name(), Some("created_by"));

        let cursor = encode_cursor(&TokenCursor {
            created_at: "not-a-timestamp".to_owned(),
            id: "tok-cursor".to_owned(),
        })
        .expect("cursor encodes");
        let refused = store
            .list(&TokenListFilters {
                limit: 10,
                cursor: Some(cursor),
            })
            .await
            .expect_err("a cursor whose timestamp does not parse is refused");
        assert_eq!(refused.invalid_parameter_name(), Some("cursor"));
    }

    /// A revoke whose expiry passes the retention cutoff while the
    /// transaction waits for the revision lock is refused under the lock,
    /// spends no revision, and records nothing -- never a `Revoked` that
    /// `is_revoked` immediately contradicts.
    #[tokio::test]
    async fn a_revoke_that_lapses_during_the_lock_wait_is_refused() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let (_tokens, pool) = migrated_service_token_store(&database).await;
        let store = crate::storage::PostgresJwtRevocationStore::new(
            pool.clone(),
            "deploy-jwt-lockwait",
            "https://issuer-a.example",
        )
        .with_retention_leeway_for_test(1.0)
        .with_after_lock_delay_for_test(std::time::Duration::from_millis(1_500));
        let revision_before: i64 = pool
            .get()
            .await
            .expect("client")
            .query_one(
                "SELECT last_revision FROM greengateway.security_revision_state WHERE singleton",
                &[],
            )
            .await
            .expect("revision")
            .get(0);
        let soon = (time::OffsetDateTime::now_utc() + std::time::Duration::from_millis(300))
            .format(&time::format_description::well_known::Rfc3339)
            .expect("rfc3339");
        let refused = store
            .revoke("jti-lockwait", Some(&soon), "operator")
            .await
            .expect_err("an expiry that lapsed during the lock wait is refused");
        assert_eq!(refused.invalid_parameter_name(), Some("expires_at"));
        assert!(!store.is_revoked("jti-lockwait").await.expect("lookup"));
        let revision_after: i64 = pool
            .get()
            .await
            .expect("client")
            .query_one(
                "SELECT last_revision FROM greengateway.security_revision_state WHERE singleton",
                &[],
            )
            .await
            .expect("revision")
            .get(0);
        assert_eq!(
            revision_after, revision_before,
            "the refused revoke spent no revision"
        );
    }

    /// A login admitted after waiting for the admission lock gets its full
    /// TTL from the moment it is written, not from the transaction's start
    /// before the wait.
    #[tokio::test]
    async fn a_pending_login_admitted_after_a_lock_wait_keeps_its_full_ttl() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let (store, pool) = pending_store(
            &database,
            PendingLoginLimits {
                ttl: std::time::Duration::from_secs(1),
                max_entries: 10,
                max_per_ip: 10,
            },
        )
        .await;
        let store = store.with_after_lock_delay_for_test(std::time::Duration::from_millis(1_500));
        assert!(store
            .insert("state-lockwait", pending("203.0.113.5"))
            .await
            .expect("insert"));
        let still_valid: bool = pool
            .get()
            .await
            .expect("client")
            .query_one(
                "SELECT bool_and(expires_at > clock_timestamp()) FROM greengateway.admin_pending_logins",
                &[],
            )
            .await
            .expect("query")
            .get(0);
        assert!(
            still_valid,
            "the TTL starts when the login is written, after the lock wait"
        );
        assert!(
            store.take("state-lockwait").await.expect("take").is_some(),
            "the callback still finds the login"
        );
    }

    /// A replica whose keyring cannot open a pending login rolls its
    /// consumption back, so a replica that can still completes it.
    #[tokio::test]
    async fn a_replica_without_the_key_leaves_the_login_for_one_that_has_it() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let (with_key, _) = pending_store(&database, PendingLoginLimits::default()).await;
        let (_tokens, pool) = migrated_service_token_store(&database).await;
        let without_key = PostgresPendingLoginStore::new(
            pool,
            "deploy-login-contract",
            LocalSecretKeyring::from_material_for_test(
                "login-key-2",
                vec![("login-key-2".to_owned(), [9u8; 32])],
            ),
            PendingLoginLimits::default(),
        );

        assert!(with_key
            .insert("state-k", pending("203.0.113.5"))
            .await
            .expect("insert"));
        let error = without_key
            .take("state-k")
            .await
            .err()
            .unwrap_or_else(|| panic!("a replica without the key must not complete the login"));
        assert_eq!(error.0.kind(), RepositoryErrorKind::InvalidData);
        let consumed = with_key
            .take("state-k")
            .await
            .expect("take")
            .expect("the login survived the failed consumption");
        assert_eq!(consumed.nonce, "nonce-0123456789");
        assert!(
            with_key.take("state-k").await.expect("take").is_none(),
            "consumed once"
        );
    }

    /// A database binds to the first deployment that boots against it
    /// and refuses any other: deployments never share a database.
    #[tokio::test]
    async fn a_database_binds_to_its_first_deployment_and_refuses_another() {
        use crate::storage::postgres::{bind_deployment, DeploymentBindingError};
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let (_tokens, pool) = migrated_service_token_store(&database).await;
        bind_deployment(&pool, "deploy-one")
            .await
            .expect("the first boot binds the database");
        bind_deployment(&pool, "deploy-one")
            .await
            .expect("the same deployment binds again");
        let refused = bind_deployment(&pool, "deploy-two")
            .await
            .expect_err("another deployment is refused");
        assert!(
            matches!(&refused, DeploymentBindingError::Mismatch { bound } if bound == "deploy-one"),
            "{refused}"
        );
    }

    /// The per-client quota key is an HMAC under the login keyring, not a
    /// plain digest a database reader could invert by enumerating
    /// addresses.
    #[tokio::test]
    async fn the_client_quota_key_is_keyed_by_the_login_keyring() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let (store_a, pool) = pending_store(&database, PendingLoginLimits::default()).await;
        let store_b = PostgresPendingLoginStore::new(
            pool.clone(),
            "deploy-login-contract",
            LocalSecretKeyring::from_material_for_test(
                "login-key-2",
                vec![("login-key-2".to_owned(), [9u8; 32])],
            ),
            PendingLoginLimits::default(),
        );
        assert!(store_a
            .insert("ck-a", pending("203.0.113.77"))
            .await
            .expect("insert"));
        assert!(store_b
            .insert("ck-b", pending("203.0.113.77"))
            .await
            .expect("insert"));
        let client = pool.get().await.expect("client");
        let mut keys = Vec::new();
        for (store, state) in [(&store_a, "ck-a"), (&store_b, "ck-b")] {
            let key: String = client
                .query_one(
                    "SELECT client_key FROM greengateway.admin_pending_logins WHERE state_hash = $1",
                    &[&store.state_digest(state)],
                )
                .await
                .expect("row")
                .get(0);
            keys.push(key);
        }
        assert_ne!(
            keys[0], keys[1],
            "the key depends on the keyring, not only on the address"
        );
        let plain = {
            use sha2::Digest;
            let mut hasher = sha2::Sha256::new();
            hasher.update(b"deploy-login-contract");
            hasher.update([0u8]);
            hasher.update(b"client");
            hasher.update([0u8]);
            hasher.update(b"203.0.113.77");
            hex::encode(hasher.finalize())
        };
        assert!(
            keys.iter().all(|key| key != &plain),
            "neither key is the unkeyed digest of the address"
        );
    }

    #[tokio::test]
    async fn postgres_service_token_store_satisfies_the_contract() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let (store, _pool) = migrated_service_token_store(&database).await;
        super::service_token_store_contract(&*store).await;
    }

    /// Create, revoke, and rotate are committed control-plane mutations:
    /// each advances the shared counter by exactly one, SETS the token
    /// high-water mark to that same value (never a private count), and
    /// writes one outbox row naming the token. Verify is observational
    /// and moves neither.
    #[tokio::test]
    async fn service_token_mutations_advance_the_shared_revision_and_set_the_high_water_mark() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let (store, pool) = migrated_service_token_store(&database).await;
        const SHARED: &str =
            "SELECT last_revision FROM greengateway.security_revision_state WHERE singleton";

        // Push the shared counter ahead with a resource that is not tokens,
        // so a private increment would be visibly wrong.
        let (policy_store, _) = migrated_policy_store(&database).await;
        PolicyControlPlane::commit(
            &*policy_store,
            commit_request(
                PolicyCommitPrecondition::Initialize,
                &policy_with_role("token-revision", "admin"),
                "seed",
            ),
        )
        .await
        .expect("policy should initialize");
        let before = scalar_i64(&pool, SHARED).await;
        assert!(before >= 1);
        assert_eq!(
            store.state_revision().await.expect("mark"),
            0,
            "no token has ever changed, so the mark is still the seed"
        );

        let created = store.create(token_request(&["a"])).await.expect("create");
        let after_create = scalar_i64(&pool, SHARED).await;
        assert_eq!(
            after_create,
            before + 1,
            "create advances the shared counter once"
        );
        assert_eq!(
            store.state_revision().await.expect("mark"),
            after_create,
            "the mark is SET to the shared revision, not incremented from 0"
        );

        assert!(matches!(
            store
                .verify(&created.plaintext_token)
                .await
                .expect("verify"),
            TokenVerification::Valid(_)
        ));
        assert_eq!(
            scalar_i64(&pool, SHARED).await,
            after_create,
            "verify is observational and reserves no revision"
        );

        store.rotate(&created.record.id).await.expect("rotate");
        let after_rotate = scalar_i64(&pool, SHARED).await;
        assert_eq!(after_rotate, after_create + 1);
        assert_eq!(store.state_revision().await.expect("mark"), after_rotate);

        store.revoke(&created.record.id).await.expect("revoke");
        let after_revoke = scalar_i64(&pool, SHARED).await;
        assert_eq!(after_revoke, after_rotate + 1);
        assert_eq!(store.state_revision().await.expect("mark"), after_revoke);

        // A second revoke is idempotent: no revision, no outbox row.
        store
            .revoke(&created.record.id)
            .await
            .expect("revoke again");
        assert_eq!(scalar_i64(&pool, SHARED).await, after_revoke);

        let outbox_rows = scalar_i64(
            &pool,
            &format!(
                "SELECT COUNT(*) FROM greengateway.security_outbox \
                 WHERE resource_type = 'service_token' AND resource_id = '{}'",
                created.record.id
            ),
        )
        .await;
        assert_eq!(
            outbox_rows, 3,
            "create, rotate, revoke: one outbox row each"
        );
        let chain = {
            let client = pool.get().await.expect("client");
            client
                .query(
                    "SELECT from_version, to_version FROM greengateway.security_outbox \
                     WHERE resource_type = 'service_token' AND resource_id = $1 \
                     ORDER BY revision",
                    &[&created.record.id],
                )
                .await
                .expect("outbox chain")
                .iter()
                .map(|row| (row.get::<_, Option<i64>>(0), row.get::<_, i64>(1)))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            chain,
            vec![(None, 1), (Some(1), 2), (Some(2), 3)],
            "the outbox carries the row revision chain"
        );
    }

    /// Two replicas rotate the same token at once. The row lock serializes
    /// them; both succeed; the documented outcome is that the LATER
    /// rotation's plaintext is the live one and every earlier plaintext --
    /// the original and the first rotation's -- is dead. Exactly two
    /// revisions are spent.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_rotations_serialize_and_leave_exactly_one_live_plaintext() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let (replica_a, pool) = migrated_service_token_store(&database).await;
        let (replica_b, _) = migrated_service_token_store(&database).await;
        let created = replica_a
            .create(token_request(&["a"]))
            .await
            .expect("create");
        let id = created.record.id.clone();

        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let rotate_on = |store: Arc<PostgresServiceTokenStore>, id: String| {
            let barrier = barrier.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                store.rotate(&id).await
            })
        };
        let (first, second) = tokio::join!(
            rotate_on(replica_a.clone(), id.clone()),
            rotate_on(replica_b.clone(), id.clone())
        );
        let first = first.expect("task").expect("rotate a").expect("exists");
        let second = second.expect("task").expect("rotate b").expect("exists");

        let mut live = 0;
        for plaintext in [
            &created.plaintext_token,
            &first.plaintext_token,
            &second.plaintext_token,
        ] {
            if matches!(
                replica_a.verify(plaintext).await.expect("verify"),
                TokenVerification::Valid(_)
            ) {
                live += 1;
            }
        }
        assert_eq!(live, 1, "exactly one plaintext survives two rotations");
        assert_eq!(
            replica_a
                .verify(&created.plaintext_token)
                .await
                .expect("verify"),
            TokenVerification::Invalid(TokenVerificationFailure::NotFound),
            "the original plaintext is dead"
        );
        let revision = scalar_i64(
            &pool,
            &format!("SELECT revision FROM greengateway.service_tokens WHERE id = '{id}'"),
        )
        .await;
        assert_eq!(revision, 3, "two committed rotations, two revisions");
    }

    /// A revoke and a rotate race on two replicas. The row lock picks a
    /// winner and the loser sees the winner's committed state: revoke-first
    /// makes the rotate a conflict; rotate-first lets the revoke close the
    /// rotated token. Either way NO plaintext -- original or rotated -- is
    /// live afterwards, which is the property that matters: a rotation can
    /// never race a revoke into a live token.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn revoke_and_rotate_race_never_leaves_a_live_plaintext() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let (replica_a, _pool) = migrated_service_token_store(&database).await;
        let (replica_b, _) = migrated_service_token_store(&database).await;

        let mut saw_revoke_first = false;
        let mut saw_rotate_first = false;
        for _ in 0..8 {
            let created = replica_a
                .create(token_request(&["a"]))
                .await
                .expect("create");
            let id = created.record.id.clone();
            let barrier = Arc::new(tokio::sync::Barrier::new(2));
            let revoke = {
                let store = replica_a.clone();
                let id = id.clone();
                let barrier = barrier.clone();
                tokio::spawn(async move {
                    barrier.wait().await;
                    store.revoke(&id).await
                })
            };
            let rotate = {
                let store = replica_b.clone();
                let id = id.clone();
                let barrier = barrier.clone();
                tokio::spawn(async move {
                    barrier.wait().await;
                    store.rotate(&id).await
                })
            };
            let (revoke, rotate) = tokio::join!(revoke, rotate);
            let revoked = revoke
                .expect("task")
                .expect("revoke queries")
                .expect("token exists");
            assert!(revoked.revoked_at.is_some(), "the revoke always lands");

            let mut plaintexts = vec![created.plaintext_token.clone()];
            match rotate.expect("task") {
                Err(error) => {
                    assert_eq!(
                        error.kind(),
                        RepositoryErrorKind::Conflict,
                        "revoke-first: the rotate is refused as a conflict"
                    );
                    saw_revoke_first = true;
                }
                Ok(Some(rotated)) => {
                    plaintexts.push(rotated.plaintext_token);
                    saw_rotate_first = true;
                }
                Ok(None) => panic!("the token exists"),
            }
            for plaintext in &plaintexts {
                assert!(
                    matches!(
                        replica_a.verify(plaintext).await.expect("verify"),
                        TokenVerification::Invalid(_)
                    ),
                    "no plaintext may be live after a revoke, whichever order won"
                );
            }
        }
        // Eight rounds through a barrier on two pools reliably produce both
        // orders; if a scheduler ever does not, the property above still
        // held on every round, which is what this test exists to prove.
        eprintln!(
            "orders observed: revoke-first={saw_revoke_first} rotate-first={saw_rotate_first}"
        );
    }

    /// A verify that lands after a revoke reports Revoked and writes
    /// nothing: last_used_at is exactly what it was before the revoke.
    #[tokio::test]
    async fn a_verify_after_revoke_cannot_touch_the_revoked_row() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let (store, _pool) = migrated_service_token_store(&database).await;
        let created = store.create(token_request(&["a"])).await.expect("create");
        assert!(matches!(
            store
                .verify(&created.plaintext_token)
                .await
                .expect("verify"),
            TokenVerification::Valid(_)
        ));
        let before = store
            .get_by_id(&created.record.id)
            .await
            .expect("get")
            .expect("exists");
        assert!(before.last_used_at.is_some());
        store.revoke(&created.record.id).await.expect("revoke");

        assert_eq!(
            store
                .verify(&created.plaintext_token)
                .await
                .expect("verify"),
            TokenVerification::Invalid(TokenVerificationFailure::Revoked)
        );
        let after = store
            .get_by_id(&created.record.id)
            .await
            .expect("get")
            .expect("exists");
        assert_eq!(
            after.last_used_at, before.last_used_at,
            "a revoked row is never written by a verify"
        );
        // And an expired token is judged by the database clock.
        let expired = store
            .create(CreateTokenRequest {
                expires_at: Some("2000-01-01T00:00:00Z".to_owned()),
                ..token_request(&["a"])
            })
            .await
            .expect("create expired");
        assert_eq!(
            store
                .verify(&expired.plaintext_token)
                .await
                .expect("verify"),
            TokenVerification::Invalid(TokenVerificationFailure::Expired)
        );
        let touched = store
            .touch_last_used(&expired.record.id)
            .await
            .expect("touch")
            .expect("exists");
        assert!(
            touched.last_used_at.is_none(),
            "touch never writes an expired row"
        );
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

    // ------------------------------------------------------------------
    // Durable observations and the fenced discovery projector
    // (issue #241, PR 11)
    // ------------------------------------------------------------------

    use crate::discovery::{
        aggregator::{AggregatorState, LoadedRows, ObservedRequest, PendingFlush},
        projector::{BatchOutcome, ProjectorConfig, ProjectorTerm},
        signals::{self, NewSignal, SignalDetectorConfig, SignalLifecycleState},
    };
    use crate::storage::postgres_discovery::PostgresDiscoveryStore;
    use tokio_util::sync::CancellationToken;

    async fn migrated_discovery_pool(database: &TestDatabase) -> deadpool_postgres::Pool {
        let test_dsn_file = write_dsn_file(&database.dsn);
        let mut config = crate::config::Config::test_defaults();
        config.state_backend = crate::config::StateBackend::Postgres;
        config.deployment_id = Some("deploy-discovery-contract".to_owned());
        config.database.url_file = Some(test_dsn_file.path.clone());
        config.database.tls_mode = crate::config::DatabaseTlsMode::LoopbackDev;
        let foundation = PostgresFoundation::establish(&config)
            .await
            .expect("the test database should establish");
        migrations::apply_missing_for_startup(foundation.pool(), &config.database)
            .await
            .expect("the discovery schema should migrate");
        foundation.pool().clone()
    }

    /// An `http.request_observed` event as the observation middleware
    /// emits it, with a sortable event id: the stream numbers a batch's
    /// events in event-id order, so ids that sort like their index make
    /// stream order the order the test wrote them in.
    fn projector_event(
        index: usize,
        method: &str,
        path: &str,
        status: u16,
        latency_ms: u64,
        user_id: Option<&str>,
    ) -> AuditEvent {
        let actor = user_id.map(|user_id| Actor {
            user_id: user_id.to_owned(),
            issuer: Some("https://issuer.example/".to_owned()),
            email: None,
            roles: Some(vec!["reader".to_owned()]),
            auth_mode: "bearer_token".to_owned(),
        });
        let mut event = AuditEvent::new(
            "http.request_observed",
            format!("request-{index}"),
            "203.0.113.10",
            actor,
            json!({
                "method": method,
                "path": path,
                "status": status,
                "latency_ms": latency_ms,
                "routing_context_known": true,
                "upstream_origin": "http://upstream.internal:8080",
                "upstream_route_host": "api.example",
                "upstream_route_path_prefix": "/",
            }),
        );
        event.event_id = format!("evt-{index:06}");
        event.timestamp = format!("2024-06-01T12:{:02}:{:02}Z", (index / 60) % 60, index % 60);
        event
    }

    fn projector_config(batch_size: usize, flush_every: usize) -> ProjectorConfig {
        ProjectorConfig {
            payload_capture_enabled: false,
            endpoint_limit: 0,
            signal_detector_config: SignalDetectorConfig::default(),
            poll_interval: Duration::from_millis(10),
            batch_size,
            flush_every,
        }
    }

    fn ingest_identity() -> IngestIdentity {
        IngestIdentity {
            instance_id: uuid::Uuid::new_v4(),
            boot_id: uuid::Uuid::new_v4(),
        }
    }

    async fn ingest(pool: &deadpool_postgres::Pool, events: &[AuditEvent]) {
        PostgresAuditEventStore::new(pool.clone(), Some(ingest_identity()))
            .insert_events(events)
            .await
            .expect("observed events should ingest");
    }

    async fn begin_term(
        pool: &deadpool_postgres::Pool,
        store: &Arc<PostgresDiscoveryStore>,
        config: ProjectorConfig,
        fence: i64,
        sender: Option<crate::audit::AuditEventSender>,
    ) -> ProjectorTerm {
        let holder = uuid::Uuid::new_v4();
        let checkpoint = store
            .claim_leadership(fence, holder)
            .await
            .expect("the fence should be claimable");
        ProjectorTerm::begin(
            Arc::new(PostgresAuditEventStore::new(pool.clone(), None)),
            Arc::clone(store),
            config,
            sender,
            fence,
            checkpoint,
        )
        .await
        .expect("the term should load its state")
    }

    /// The in-memory reference: the same aggregation the SQLite sink runs,
    /// fed the stream in stream order.
    async fn reference_state(pool: &deadpool_postgres::Pool) -> AggregatorState {
        reference_state_with_limit(pool, 0).await
    }

    async fn reference_state_with_limit(
        pool: &deadpool_postgres::Pool,
        endpoint_limit: usize,
    ) -> AggregatorState {
        let audit = PostgresAuditEventStore::new(pool.clone(), None);
        let mut state = AggregatorState::from_rows(
            LoadedRows::default(),
            false,
            endpoint_limit,
            SignalDetectorConfig::default(),
        )
        .expect("an empty state builds");
        for (_, event) in audit.stream_after(0, 10_000).await.expect("stream") {
            if let Some(observation) = ObservedRequest::from_event(&event) {
                state.observe(observation);
            }
        }
        state
    }

    async fn reloaded_state(store: &PostgresDiscoveryStore) -> AggregatorState {
        AggregatorState::from_rows(
            store.load_rows().await.expect("rows should load"),
            false,
            0,
            SignalDetectorConfig::default(),
        )
        .expect("persisted rows should rebuild")
    }

    /// Endpoint-by-endpoint parity between two working sets: counts,
    /// status histogram, principal set with first/last seen, routing
    /// contexts, latency reservoir, and the detector counters/windows.
    fn assert_same_inventory(left: &AggregatorState, right: &AggregatorState) {
        let mut left_keys = left.aggregates().keys().cloned().collect::<Vec<_>>();
        let mut right_keys = right.aggregates().keys().cloned().collect::<Vec<_>>();
        left_keys.sort_by(|a, b| {
            (&a.method, &a.endpoint_template).cmp(&(&b.method, &b.endpoint_template))
        });
        right_keys.sort_by(|a, b| {
            (&a.method, &a.endpoint_template).cmp(&(&b.method, &b.endpoint_template))
        });
        assert_eq!(left_keys, right_keys, "the endpoint sets differ");
        for key in left_keys {
            let l = &left.aggregates()[&key];
            let r = &right.aggregates()[&key];
            let context = format!("{} {}", key.method, key.endpoint_template);
            assert_eq!(l.call_count, r.call_count, "call_count for {context}");
            assert_eq!(l.error_count, r.error_count, "error_count for {context}");
            assert_eq!(
                l.schema_mismatch_count, r.schema_mismatch_count,
                "schema_mismatch_count for {context}"
            );
            assert_eq!(
                l.status_counts, r.status_counts,
                "status_counts for {context}"
            );
            assert_eq!(l.first_seen, r.first_seen, "first_seen for {context}");
            assert_eq!(l.last_seen, r.last_seen, "last_seen for {context}");
            assert_eq!(
                l.latency_count, r.latency_count,
                "latency_count for {context}"
            );
            assert_eq!(
                l.latency_samples, r.latency_samples,
                "latency_samples for {context}"
            );
            let principals = |aggregate: &crate::discovery::aggregator::EndpointAggregate| {
                let mut seen = aggregate
                    .principals
                    .iter()
                    .map(|(identity, seen)| {
                        (
                            identity.user_id.clone(),
                            identity.issuer.clone(),
                            identity.auth_method.clone(),
                            seen.first_seen.clone(),
                            seen.last_seen.clone(),
                        )
                    })
                    .collect::<Vec<_>>();
                seen.sort();
                seen
            };
            assert_eq!(principals(l), principals(r), "principals for {context}");
            let contexts = |aggregate: &crate::discovery::aggregator::EndpointAggregate| {
                let mut contexts = aggregate
                    .routing_contexts
                    .values()
                    .map(|context| {
                        (
                            context.key.route_host.clone(),
                            context.key.route_path_prefix.clone(),
                            context.key.upstream_origin.clone(),
                            context.first_seen.clone(),
                            context.last_seen.clone(),
                            context.call_count,
                            context.principals.len(),
                        )
                    })
                    .collect::<Vec<_>>();
                contexts.sort();
                contexts
            };
            assert_eq!(contexts(l), contexts(r), "routing contexts for {context}");
            assert_eq!(
                l.routing_context_known_since, r.routing_context_known_since,
                "routing_context_known_since for {context}"
            );
            let ls = &l.classified_signal_state;
            let rs = &r.classified_signal_state;
            assert_eq!(
                ls.call_count, rs.call_count,
                "detector call_count for {context}"
            );
            assert_eq!(
                ls.error_count, rs.error_count,
                "detector error_count for {context}"
            );
            assert_eq!(
                ls.principals.len(),
                rs.principals.len(),
                "detector principals for {context}"
            );
            assert_eq!(
                ls.recent_error_window.samples, rs.recent_error_window.samples,
                "recent error window for {context}"
            );
            assert_eq!(
                serde_json::to_value(&ls.volume_window).expect("window"),
                serde_json::to_value(&rs.volume_window).expect("window"),
                "volume window for {context}"
            );
        }
    }

    async fn signal_count(pool: &deadpool_postgres::Pool, signal_type: &str) -> i64 {
        let client = pool.get().await.expect("client");
        client
            .query_one(
                "SELECT count(*) FROM greengateway.discovery_signals WHERE signal_type = $1",
                &[&signal_type],
            )
            .await
            .expect("count")
            .get(0)
    }

    /// Contract test 1: N observed events ingested by two replicas project
    /// to exactly the inventory the in-memory aggregator computes over the
    /// same stream; a second pass changes nothing; re-ingesting the same
    /// event ids changes nothing.
    #[tokio::test]
    async fn projector_projects_the_stream_exactly_once() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let pool = migrated_discovery_pool(&database).await;
        let store = Arc::new(PostgresDiscoveryStore::new(pool.clone()));

        let paths = ["/orders", "/orders", "/users", "/health"];
        let users = [Some("alice"), Some("bob"), None, Some("alice")];
        let statuses = [200_u16, 201, 404, 500, 200];
        let events = (0..40)
            .map(|index| {
                projector_event(
                    index,
                    if index % 5 == 0 { "POST" } else { "GET" },
                    paths[index % paths.len()],
                    statuses[index % statuses.len()],
                    (index as u64 * 7) % 90 + 1,
                    users[index % users.len()],
                )
            })
            .collect::<Vec<_>>();
        // Two replicas ingest half each, as two ingest identities.
        ingest(&pool, &events[..20]).await;
        ingest(&pool, &events[20..]).await;

        let mut term = begin_term(&pool, &store, projector_config(7, 5), 1, None).await;
        let stop = CancellationToken::new();
        let applied = term
            .project_until_caught_up(&stop)
            .await
            .expect("projection should run")
            .expect("the term should catch up");
        assert_eq!(applied, 40);
        assert_eq!(term.committed_position(), 40);

        let reference = reference_state(&pool).await;
        assert_same_inventory(&reference, &reloaded_state(&store).await);
        let checkpoint = store.checkpoint().await.expect("checkpoint");
        assert_eq!(checkpoint.checkpoint_position, 40);
        assert_eq!(checkpoint.projected_events, 40);
        assert_eq!(checkpoint.fence, 1);
        let endpoint_rows = scalar_i64(
            &pool,
            "SELECT count(*) FROM greengateway.discovery_endpoint_aggregates",
        )
        .await;
        assert_eq!(endpoint_rows as usize, reference.aggregates().len());
        assert_eq!(
            signal_count(&pool, signals::NEW_ENDPOINT_SEEN_SIGNAL_TYPE).await as usize,
            reference.aggregates().len(),
            "one new_endpoint_seen per endpoint"
        );

        // A second pass has nothing to do and changes nothing.
        let again = term
            .project_until_caught_up(&stop)
            .await
            .expect("second pass")
            .expect("still leading");
        assert_eq!(again, 0);
        assert_same_inventory(&reference, &reloaded_state(&store).await);
        assert_eq!(
            store
                .checkpoint()
                .await
                .expect("checkpoint")
                .projected_events,
            40
        );

        // Replaying the same event ids stores nothing new (the audit
        // store's idempotent ingest) and so projects nothing new.
        ingest(&pool, &events).await;
        let audit = PostgresAuditEventStore::new(pool.clone(), None);
        assert_eq!(audit.stream_head().await.expect("head"), 40);
        let replayed = term
            .project_until_caught_up(&stop)
            .await
            .expect("replay pass")
            .expect("still leading");
        assert_eq!(replayed, 0);
        assert_same_inventory(&reference, &reloaded_state(&store).await);
        let after_replay = store.checkpoint().await.expect("checkpoint");
        assert_eq!(after_replay.checkpoint_position, 40);
        assert_eq!(after_replay.projected_events, 40);
    }

    /// Contract test 2: a flush that fails after the fence check leaves
    /// the checkpoint, the counters, and every table untouched, and the
    /// retry commits the same observations exactly once without re-reading
    /// the stream.
    #[tokio::test]
    async fn a_flush_that_fails_leaves_the_checkpoint_and_counters_untouched() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let pool = migrated_discovery_pool(&database).await;
        let store = Arc::new(PostgresDiscoveryStore::new(pool.clone()));

        let events = (0..10)
            .map(|index| projector_event(index, "GET", "/orders", 200, 5, Some("alice")))
            .collect::<Vec<_>>();
        ingest(&pool, &events).await;

        let mut term = begin_term(&pool, &store, projector_config(100, 100), 1, None).await;
        let stop = CancellationToken::new();

        // The flush's aggregate upsert runs after the fence check and
        // after the child-table deletes; failing it there must roll the
        // whole transaction back.
        {
            let client = pool.get().await.expect("client");
            client
                .batch_execute(
                    "ALTER TABLE greengateway.discovery_endpoint_aggregates \
                     RENAME TO discovery_endpoint_aggregates_gone",
                )
                .await
                .expect("rename");
        }
        let error = term
            .project_batch(&stop)
            .await
            .expect_err("the flush must fail while the table is missing");
        assert_ne!(error.kind(), crate::storage::RepositoryErrorKind::Conflict);
        let checkpoint = store.checkpoint().await.expect("checkpoint");
        assert_eq!(
            checkpoint.checkpoint_position, 0,
            "the checkpoint must not move"
        );
        assert_eq!(checkpoint.projected_events, 0, "the counter must not move");
        assert_eq!(term.committed_position(), 0);
        assert_eq!(
            scalar_i64(
                &pool,
                "SELECT count(*) FROM greengateway.discovery_endpoint_status_counts"
            )
            .await,
            0,
            "no child row from the aborted transaction survives"
        );
        assert_eq!(
            signal_count(&pool, signals::NEW_ENDPOINT_SEEN_SIGNAL_TYPE).await,
            0
        );

        {
            let client = pool.get().await.expect("client");
            client
                .batch_execute(
                    "ALTER TABLE greengateway.discovery_endpoint_aggregates_gone \
                     RENAME TO discovery_endpoint_aggregates",
                )
                .await
                .expect("rename back");
        }
        let outcome = term.project_batch(&stop).await.expect("the retry commits");
        assert_eq!(
            outcome,
            BatchOutcome::Projected {
                observed: 10,
                last_position: 10
            }
        );
        let checkpoint = store.checkpoint().await.expect("checkpoint");
        assert_eq!(checkpoint.checkpoint_position, 10);
        assert_eq!(checkpoint.projected_events, 10);
        assert_eq!(
            scalar_i64(
                &pool,
                "SELECT call_count FROM greengateway.discovery_endpoint_aggregates \
                 WHERE method = 'GET' AND endpoint_template = '/orders'"
            )
            .await,
            10,
            "the retried flush applies the ten observations exactly once"
        );
        assert_eq!(
            term.project_batch(&stop).await.expect("nothing left"),
            BatchOutcome::Empty
        );
    }

    /// Contract test 3: leader A projects part of the stream; B claims a
    /// higher fence, reloads A's committed state (detector windows and
    /// learner groups included) and projects the rest; A's next flush is
    /// refused and applies nothing. An error-rate spike whose 20-sample
    /// window straddles the failover fires exactly once.
    #[tokio::test]
    async fn a_successor_resumes_from_the_committed_checkpoint_and_the_old_leader_is_fenced() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let pool = migrated_discovery_pool(&database).await;
        let store = Arc::new(PostgresDiscoveryStore::new(pool.clone()));
        let spike = signals::ERROR_RATE_SPIKE_SIGNAL_TYPE;

        // 20 successes, then 19 errors: one error short of the spike.
        let events = (0..39)
            .map(|index| {
                let status = if index < 20 { 200 } else { 500 };
                projector_event(index, "GET", "/errors/steady", status, 10, Some("alice"))
            })
            .collect::<Vec<_>>();
        ingest(&pool, &events).await;

        let mut leader_a = begin_term(&pool, &store, projector_config(100, 100), 1, None).await;
        let stop = CancellationToken::new();
        assert_eq!(
            leader_a
                .project_until_caught_up(&stop)
                .await
                .expect("A projects")
                .expect("A leads"),
            39
        );
        assert_eq!(
            signal_count(&pool, spike).await,
            0,
            "the spike needs one more sample"
        );
        assert_eq!(
            scalar_i64(
                &pool,
                "SELECT count(*) FROM greengateway.discovery_detector_state"
            )
            .await,
            1,
            "A persisted the endpoint's detector windows"
        );
        assert_eq!(
            scalar_i64(
                &pool,
                "SELECT count(*) FROM greengateway.discovery_template_groups"
            )
            .await,
            1,
            "A persisted the learner's groups"
        );

        // The 40th sample arrives; A fails over before projecting it.
        ingest(
            &pool,
            &[projector_event(
                39,
                "GET",
                "/errors/steady",
                500,
                10,
                Some("alice"),
            )],
        )
        .await;

        let mut leader_b = begin_term(&pool, &store, projector_config(100, 100), 2, None).await;
        assert_eq!(
            leader_b.committed_position(),
            39,
            "B resumes from A's checkpoint"
        );
        assert_eq!(
            leader_b
                .project_until_caught_up(&stop)
                .await
                .expect("B projects")
                .expect("B leads"),
            1,
            "B projects exactly the one pending position"
        );
        assert_eq!(
            signal_count(&pool, spike).await,
            1,
            "the restored window completes the spike exactly once"
        );
        let checkpoint = store.checkpoint().await.expect("checkpoint");
        assert_eq!(checkpoint.checkpoint_position, 40);
        assert_eq!(checkpoint.projected_events, 40);
        assert_eq!(checkpoint.fence, 2);

        // A stale claim at the old fence is refused.
        let stale = store
            .claim_leadership(1, uuid::Uuid::new_v4())
            .await
            .expect_err("a lower fence cannot claim");
        assert_eq!(stale.kind(), crate::storage::RepositoryErrorKind::Conflict);

        // A wakes up, reads the position it never committed, applies it in
        // memory (queueing the same spike), and is refused at the fence:
        // nothing it holds reaches the tables.
        assert_eq!(
            leader_a
                .project_batch(&stop)
                .await
                .expect("A's flush is refused, not failed"),
            BatchOutcome::Fenced
        );
        assert_eq!(leader_a.committed_position(), 39);
        assert_eq!(signal_count(&pool, spike).await, 1, "A inserted nothing");
        let checkpoint = store.checkpoint().await.expect("checkpoint");
        assert_eq!(checkpoint.checkpoint_position, 40);
        assert_eq!(checkpoint.projected_events, 40);
        assert_eq!(
            scalar_i64(
                &pool,
                "SELECT call_count FROM greengateway.discovery_endpoint_aggregates \
                 WHERE method = 'GET' AND endpoint_template = '/errors/steady'"
            )
            .await,
            40,
            "the endpoint counted every observation exactly once across the failover"
        );

        // The persisted inventory is what one uninterrupted aggregator
        // would have computed over the same stream.
        assert_same_inventory(&reference_state(&pool).await, &reloaded_state(&store).await);
    }

    /// Contract test 5: a signal identity inserts once cluster-wide. A
    /// second flush carrying the same identity (a different id, as a
    /// successor or a replayed batch would produce) inserts nothing and
    /// reports nothing opened, and a replayed projection announces no
    /// second `signal.opened`.
    #[tokio::test]
    async fn signal_identities_are_unique_cluster_wide() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let pool = migrated_discovery_pool(&database).await;
        let store = Arc::new(PostgresDiscoveryStore::new(pool.clone()));
        store
            .claim_leadership(1, uuid::Uuid::new_v4())
            .await
            .expect("claim");

        let signal = |id: &str| NewSignal {
            id: id.to_owned(),
            signal_type: signals::SCHEMA_MISMATCH_SIGNAL_TYPE.to_owned(),
            target_kind: signals::ENDPOINT_TARGET_KIND.to_owned(),
            target_key: "POST /orders".to_owned(),
            target_identity: json!({"method": "POST", "endpoint_template": "/orders"}),
            explanation: "schema mismatches crossed the threshold".to_owned(),
            evidence: json!({"schema_mismatch_count": 5}),
            state: SignalLifecycleState::Open,
            created_at: "2024-06-01T12:00:00Z".to_owned(),
        };
        let first = PendingFlush {
            pending_signals: vec![signal("signal-1")],
            ..PendingFlush::default()
        };
        let opened = store
            .flush(
                &first,
                &[],
                None,
                // Position 0: these hand-driven flushes must not move the
                // checkpoint past the stream positions ingested below.
                crate::storage::postgres_discovery::FlushCheckpoint {
                    position: 0,
                    fence: 1,
                    projected_events: 0,
                },
                false,
            )
            .await
            .expect("first flush");
        assert_eq!(opened.len(), 1);
        assert_eq!(opened[0].id, "signal-1");

        let duplicate = PendingFlush {
            pending_signals: vec![signal("signal-2")],
            ..PendingFlush::default()
        };
        let opened = store
            .flush(
                &duplicate,
                &[],
                None,
                crate::storage::postgres_discovery::FlushCheckpoint {
                    position: 0,
                    fence: 1,
                    projected_events: 0,
                },
                false,
            )
            .await
            .expect("duplicate flush commits");
        assert!(opened.is_empty(), "a duplicate identity opens nothing");
        assert_eq!(
            signal_count(&pool, signals::SCHEMA_MISMATCH_SIGNAL_TYPE).await,
            1
        );
        assert_eq!(
            scalar_i64(
                &pool,
                "SELECT count(*) FROM greengateway.discovery_signals WHERE id = 'signal-1'"
            )
            .await,
            1,
            "the first row is kept, not replaced"
        );
        assert_eq!(store.checkpoint().await.expect("checkpoint").fence, 1);

        // Through the projector: one endpoint's new_endpoint_seen is
        // announced once; a successor replaying the same positions (the
        // checkpoint wound back, as a restored backup would leave it)
        // neither inserts nor announces it again.
        let (sender, mut opened_events) = tokio::sync::broadcast::channel(64);
        ingest(
            &pool,
            &[projector_event(
                0,
                "GET",
                "/replayed",
                200,
                5,
                Some("alice"),
            )],
        )
        .await;
        let stop = CancellationToken::new();
        let mut first_term = begin_term(
            &pool,
            &store,
            projector_config(10, 10),
            2,
            Some(sender.clone()),
        )
        .await;
        assert_eq!(
            first_term
                .project_until_caught_up(&stop)
                .await
                .expect("projects")
                .expect("leads"),
            1
        );
        assert_eq!(
            signal_count(&pool, signals::NEW_ENDPOINT_SEEN_SIGNAL_TYPE).await,
            1
        );
        let announced = opened_events
            .try_recv()
            .expect("one signal.opened is announced");
        assert_eq!(announced.event_type, crate::audit::event::SIGNAL_OPENED);
        assert!(
            opened_events.try_recv().is_err(),
            "exactly one announcement"
        );

        {
            let client = pool.get().await.expect("client");
            client
                .batch_execute(
                    "UPDATE greengateway.discovery_projector_state SET checkpoint_position = 0",
                )
                .await
                .expect("wind the checkpoint back");
        }
        let mut replaying_term =
            begin_term(&pool, &store, projector_config(10, 10), 3, Some(sender)).await;
        assert_eq!(replaying_term.committed_position(), 0);
        assert_eq!(
            replaying_term
                .project_until_caught_up(&stop)
                .await
                .expect("replays")
                .expect("leads"),
            1
        );
        assert_eq!(
            signal_count(&pool, signals::NEW_ENDPOINT_SEEN_SIGNAL_TYPE).await,
            1,
            "the replayed crossing inserts no second row"
        );
        assert!(
            opened_events.try_recv().is_err(),
            "a signal that did not insert is not announced"
        );
    }

    /// The endpoint templates the aggregates table holds, sorted.
    async fn resident_templates(pool: &deadpool_postgres::Pool) -> Vec<String> {
        let client = pool.get().await.expect("client");
        client
            .query(
                "SELECT endpoint_template FROM greengateway.discovery_endpoint_aggregates \
                 ORDER BY endpoint_template",
                &[],
            )
            .await
            .expect("resident templates")
            .iter()
            .map(|row| row.get::<_, String>(0))
            .collect()
    }

    /// Rows in `table` keyed by an endpoint template outside `resident`:
    /// what an incomplete eviction leaves behind.
    async fn orphan_rows(pool: &deadpool_postgres::Pool, table: &str, resident: &[&str]) -> i64 {
        let client = pool.get().await.expect("client");
        let resident = resident
            .iter()
            .map(|template| (*template).to_owned())
            .collect::<Vec<_>>();
        client
            .query_one(
                &format!(
                    "SELECT count(*) FROM greengateway.{table} \
                     WHERE NOT (endpoint_template = ANY($1::text[]))"
                ),
                &[&resident],
            )
            .await
            .expect("orphan count")
            .get(0)
    }

    /// The target keys of every `new_endpoint_seen` signal, sorted.
    async fn new_endpoint_signal_targets(pool: &deadpool_postgres::Pool) -> Vec<String> {
        let client = pool.get().await.expect("client");
        client
            .query(
                "SELECT target_key FROM greengateway.discovery_signals \
                 WHERE signal_type = $1 ORDER BY target_key",
                &[&signals::NEW_ENDPOINT_SEEN_SIGNAL_TYPE],
            )
            .await
            .expect("signal targets")
            .iter()
            .map(|row| row.get::<_, String>(0))
            .collect()
    }

    /// Every table keyed by endpoint identity that an eviction must clear.
    const ENDPOINT_KEYED_TABLES: [&str; 9] = [
        "discovery_endpoint_aggregates",
        "discovery_endpoint_status_counts",
        "discovery_endpoint_principals",
        "discovery_endpoint_routing_contexts",
        "discovery_endpoint_routing_principals",
        "discovery_endpoint_routing_classifications",
        "discovery_endpoint_classified_signal_stats",
        "discovery_endpoint_classified_signal_principals",
        "discovery_detector_state",
    ];

    /// Exactly `resident` is persisted: the aggregates table holds those
    /// templates and no other, no endpoint-keyed table has a row outside
    /// them, and the `new_endpoint_seen` signals are theirs alone.
    async fn assert_exactly_resident(pool: &deadpool_postgres::Pool, resident: &[&str]) {
        assert_eq!(
            resident_templates(pool).await,
            resident
                .iter()
                .map(|template| (*template).to_owned())
                .collect::<Vec<_>>(),
            "the aggregates table holds exactly the resident endpoints"
        );
        for table in ENDPOINT_KEYED_TABLES {
            assert_eq!(
                orphan_rows(pool, table, resident).await,
                0,
                "{table} keeps no row of an evicted endpoint"
            );
        }
        assert_eq!(
            new_endpoint_signal_targets(pool).await,
            resident
                .iter()
                .map(|template| signals::endpoint_target_key("GET", template))
                .collect::<Vec<_>>(),
            "an evicted endpoint's signals go with it"
        );
    }

    /// A flush retried with the identical batch and checkpoint -- what the
    /// projector does after a COMMIT the server applied but the client
    /// never heard about -- changes nothing: the aggregates and child rows
    /// are the same, `projected_events` is not counted twice, and the
    /// signals the batch opened (never announced, since the first attempt
    /// errored) are reported again so the retry announces them once.
    #[tokio::test]
    async fn a_retried_flush_of_a_committed_checkpoint_counts_nothing_twice_and_reports_its_signals(
    ) {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let pool = migrated_discovery_pool(&database).await;
        let store = Arc::new(PostgresDiscoveryStore::new(pool.clone()));
        store
            .claim_leadership(1, uuid::Uuid::new_v4())
            .await
            .expect("claim");

        let events = (0..6)
            .map(|index| {
                projector_event(
                    index,
                    "GET",
                    if index % 2 == 0 { "/orders" } else { "/users" },
                    200,
                    5,
                    Some("alice"),
                )
            })
            .collect::<Vec<_>>();
        ingest(&pool, &events).await;
        let mut state = reference_state(&pool).await;
        let batch = state.pending_flush();
        assert_eq!(batch.dirty_aggregates.len(), 2);
        assert_eq!(
            batch.pending_signals.len(),
            2,
            "one new_endpoint_seen per endpoint is queued"
        );
        let detector_states = AggregatorState::detector_states_for(&batch);
        let groups = state.template_groups_json_within(usize::MAX);
        let checkpoint = crate::storage::postgres_discovery::FlushCheckpoint {
            position: 6,
            fence: 1,
            projected_events: 6,
        };

        let opened = store
            .flush(&batch, &detector_states, Some(&groups), checkpoint, false)
            .await
            .expect("first flush");
        let mut opened_ids = opened.iter().map(|s| s.id.clone()).collect::<Vec<_>>();
        opened_ids.sort();
        assert_eq!(opened_ids.len(), 2);
        let committed = store.checkpoint().await.expect("checkpoint");
        assert_eq!(committed.checkpoint_position, 6);
        assert_eq!(committed.projected_events, 6);
        let inventory_after = |pool: deadpool_postgres::Pool| async move {
            (
                scalar_i64(
                    &pool,
                    "SELECT sum(call_count)::bigint FROM greengateway.discovery_endpoint_aggregates",
                )
                .await,
                scalar_i64(
                    &pool,
                    "SELECT count(*) FROM greengateway.discovery_endpoint_principals",
                )
                .await,
                scalar_i64(
                    &pool,
                    "SELECT count(*) FROM greengateway.discovery_endpoint_status_counts",
                )
                .await,
                scalar_i64(&pool, "SELECT count(*) FROM greengateway.discovery_signals").await,
            )
        };
        let first = inventory_after(pool.clone()).await;
        assert_eq!(first, (6, 2, 2, 2));

        // The retry: the same batch, the same checkpoint, the same fence.
        let reopened = store
            .flush(&batch, &detector_states, Some(&groups), checkpoint, false)
            .await
            .expect("the retry commits");
        let mut reopened_ids = reopened.iter().map(|s| s.id.clone()).collect::<Vec<_>>();
        reopened_ids.sort();
        assert_eq!(
            reopened_ids, opened_ids,
            "the retry reports the signals the batch opened, by their ids"
        );
        let retried = store.checkpoint().await.expect("checkpoint");
        assert_eq!(retried.checkpoint_position, 6);
        assert_eq!(
            retried.projected_events, 6,
            "an already-counted checkpoint is not counted again"
        );
        assert_eq!(inventory_after(pool.clone()).await, first);

        // The next real flush still counts: the checkpoint advances.
        ingest(
            &pool,
            &[projector_event(6, "GET", "/orders", 200, 5, Some("bob"))],
        )
        .await;
        let state = reference_state(&pool).await;
        let next = state.pending_flush();
        let next_states = AggregatorState::detector_states_for(&next);
        store
            .flush(
                &next,
                &next_states,
                None,
                crate::storage::postgres_discovery::FlushCheckpoint {
                    position: 7,
                    fence: 1,
                    projected_events: 1,
                },
                false,
            )
            .await
            .expect("the next flush commits");
        let advanced = store.checkpoint().await.expect("checkpoint");
        assert_eq!(advanced.checkpoint_position, 7);
        assert_eq!(advanced.projected_events, 7);
    }

    /// Contract test 4: the endpoint bound is applied by the one leader
    /// over the global stream order, so what is evicted is the least
    /// recently seen endpoint across every replica's traffic, never the
    /// least recent of one replica's. The row count is exactly the limit
    /// after every flush; an evicted endpoint leaves no child row, detector
    /// state, or signal behind; a successor re-seeds the access order from
    /// the persisted `last_seen` and evicts the same endpoint the
    /// uninterrupted aggregator would; and a fenced-out leader's own
    /// eviction decision reaches nothing.
    #[tokio::test]
    async fn the_endpoint_bound_evicts_least_recently_seen_globally() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let pool = migrated_discovery_pool(&database).await;
        let store = Arc::new(PostgresDiscoveryStore::new(pool.clone()));
        const LIMIT: usize = 4;
        // Flush after every observation so each admitted endpoint's signal
        // is committed before a later eviction has to remove it.
        let bounded = || ProjectorConfig {
            endpoint_limit: LIMIT,
            ..projector_config(100, 1)
        };
        let event =
            |index: usize, path: &str| projector_event(index, "GET", path, 200, 5, Some("alice"));

        // Two replicas ingest alternately. The stream orders their batches
        // by commit, so the global order is 0..=6: /alpha is touched again
        // at position 5, which makes /bravo -- replica A's own most recent
        // endpoint at the time -- the least recently seen overall.
        ingest(&pool, &[event(0, "/alpha"), event(1, "/bravo")]).await;
        ingest(&pool, &[event(2, "/charlie"), event(3, "/delta")]).await;
        ingest(&pool, &[event(4, "/alpha"), event(5, "/echo")]).await;
        ingest(&pool, &[event(6, "/foxtrot")]).await;

        let mut leader_a = begin_term(&pool, &store, bounded(), 1, None).await;
        let stop = CancellationToken::new();
        assert_eq!(
            leader_a
                .project_until_caught_up(&stop)
                .await
                .expect("A projects")
                .expect("A leads"),
            7
        );
        // Admitting /echo evicted /bravo; admitting /foxtrot evicted
        // /charlie. /alpha survived because the global order saw it last
        // at position 5.
        assert_exactly_resident(&pool, &["/alpha", "/delta", "/echo", "/foxtrot"]).await;
        let checkpoint = store.checkpoint().await.expect("checkpoint");
        assert_eq!(checkpoint.checkpoint_position, 7);
        assert_eq!(checkpoint.projected_events, 7);
        assert_same_inventory(
            &reference_state_with_limit(&pool, LIMIT).await,
            &reloaded_state(&store).await,
        );

        // Failover. The successor rebuilds its access order from the
        // persisted last_seen, so the next admission evicts /delta (last
        // seen at position 4), exactly as the uninterrupted aggregator
        // would.
        ingest(&pool, &[event(7, "/golf")]).await;
        let mut leader_b = begin_term(&pool, &store, bounded(), 2, None).await;
        assert_eq!(leader_b.committed_position(), 7);
        assert_eq!(
            leader_b
                .project_until_caught_up(&stop)
                .await
                .expect("B projects")
                .expect("B leads"),
            1
        );
        assert_exactly_resident(&pool, &["/alpha", "/echo", "/foxtrot", "/golf"]).await;
        let checkpoint = store.checkpoint().await.expect("checkpoint");
        assert_eq!(checkpoint.checkpoint_position, 8);
        assert_eq!(checkpoint.projected_events, 8);
        assert_same_inventory(
            &reference_state_with_limit(&pool, LIMIT).await,
            &reloaded_state(&store).await,
        );

        // The old leader wakes, reads position 8, evicts /delta in its own
        // memory and is refused at the fence: the tables are B's alone.
        assert_eq!(
            leader_a
                .project_batch(&stop)
                .await
                .expect("A's flush is refused, not failed"),
            BatchOutcome::Fenced
        );
        assert_exactly_resident(&pool, &["/alpha", "/echo", "/foxtrot", "/golf"]).await;
        assert_eq!(
            store
                .checkpoint()
                .await
                .expect("checkpoint")
                .projected_events,
            8
        );
    }

    /// Contract test 6: the retention predicate. No PostgreSQL audit
    /// retention job exists yet (PR 13 owns it); the boundary it must
    /// honour is `minimum_retained_position()`, one past the committed
    /// checkpoint. A trim of every position below that boundary leaves the
    /// projector's next batch in place, so a successor resuming from the
    /// checkpoint still projects the remainder exactly once.
    #[tokio::test]
    async fn retention_never_passes_the_projector_checkpoint() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let pool = migrated_discovery_pool(&database).await;
        let store = Arc::new(PostgresDiscoveryStore::new(pool.clone()));

        let events = (0..40)
            .map(|index| {
                projector_event(
                    index,
                    "GET",
                    "/orders",
                    if index % 4 == 3 { 500 } else { 200 },
                    5,
                    Some(if index % 2 == 0 { "alice" } else { "bob" }),
                )
            })
            .collect::<Vec<_>>();
        ingest(&pool, &events).await;
        // The reference sees the whole stream, before any of it is trimmed.
        let reference = reference_state(&pool).await;

        let mut leader_a = begin_term(&pool, &store, projector_config(20, 20), 1, None).await;
        let stop = CancellationToken::new();
        assert_eq!(
            leader_a.project_batch(&stop).await.expect("A projects"),
            BatchOutcome::Projected {
                observed: 20,
                last_position: 20
            }
        );
        let checkpoint = store.checkpoint().await.expect("checkpoint");
        assert_eq!(checkpoint.checkpoint_position, 20);

        // The trim PR 13's job will run: every event whose stream position
        // is below the boundary, read in the same transaction.
        let boundary = store
            .minimum_retained_position()
            .await
            .expect("the boundary reads");
        let trimmed = {
            let client = pool.get().await.expect("client");
            client
                .execute(
                    "DELETE FROM greengateway.audit_events AS e
                     USING greengateway.audit_stream AS s
                     WHERE s.event_id = e.event_id AND s.position < $1",
                    &[&boundary],
                )
                .await
                .expect("the trim runs")
        };
        assert_eq!(
            trimmed, 20,
            "the trim removes exactly the applied positions"
        );
        let audit = PostgresAuditEventStore::new(pool.clone(), None);
        assert_eq!(
            audit.stream_first_available().await.expect("first"),
            checkpoint.checkpoint_position + 1,
            "the first retained position is the first the projector has not applied"
        );

        // A fails over. B resumes from the checkpoint and finds every
        // position it needs still in the stream.
        let mut leader_b = begin_term(&pool, &store, projector_config(20, 20), 2, None).await;
        assert_eq!(leader_b.committed_position(), 20);
        assert_eq!(
            leader_b
                .project_until_caught_up(&stop)
                .await
                .expect("B projects")
                .expect("B leads"),
            20,
            "every position after the checkpoint survived the trim"
        );
        let checkpoint = store.checkpoint().await.expect("checkpoint");
        assert_eq!(checkpoint.checkpoint_position, 40);
        assert_eq!(checkpoint.projected_events, 40);
        assert_eq!(
            scalar_i64(
                &pool,
                "SELECT call_count FROM greengateway.discovery_endpoint_aggregates \
                 WHERE method = 'GET' AND endpoint_template = '/orders'"
            )
            .await,
            40,
            "the trimmed prefix was applied once and the retained suffix once"
        );
        assert_same_inventory(&reference, &reloaded_state(&store).await);

        // The boundary moves with the checkpoint: a trim at the new one
        // removes only what has been applied, and the stream stays readable
        // from the checkpoint.
        let boundary = store
            .minimum_retained_position()
            .await
            .expect("the boundary reads");
        assert_eq!(boundary, checkpoint.checkpoint_position + 1);
        assert_eq!(
            leader_b.project_batch(&stop).await.expect("nothing left"),
            BatchOutcome::Empty
        );
    }

    // ------------------------------------------------------------------
    // Read-store parity: the PostgreSQL read store answers every read of
    // the trait exactly as the SQLite store does over the same events
    // (issue #241, PR 11, contract test 7)
    // ------------------------------------------------------------------

    use crate::audit::AuditSink;
    use crate::discovery::{
        aggregator::{EndpointAggregatorSink, EndpointAggregatorSinkConfig},
        lifecycle::TransitionPrecondition,
        query::{
            DiscoveryQueryError, DiscoveryQueryStore, DiscoveryReadStore, EndpointListFilters,
            EndpointReviewState, EndpointSort, PrincipalPageFilters, DEFAULT_NEW_SINCE_HOURS,
            MAX_NEW_SINCE_HOURS,
        },
        signals::SignalListFilters,
    };
    use crate::storage::postgres_discovery_read::PostgresDiscoveryReadStore;
    use time::{format_description::well_known::Rfc3339, OffsetDateTime};

    /// An observation as the middleware emits it, with the fields the
    /// parity fixture varies: an unrouted request carries no upstream
    /// context and is not classified; a captured shape feeds the inferred
    /// schema.
    #[allow(clippy::too_many_arguments)]
    fn parity_event(
        index: usize,
        method: &str,
        path: &str,
        status: u16,
        latency_ms: u64,
        user_id: Option<&str>,
        routed: bool,
        payload_shape: Option<Value>,
    ) -> AuditEvent {
        let mut event = projector_event(index, method, path, status, latency_ms, user_id);
        let payload = event.payload.as_object_mut().expect("payload is an object");
        if !routed {
            payload.insert("routing_context_known".to_owned(), json!(false));
            payload.remove("upstream_origin");
            payload.remove("upstream_route_host");
            payload.remove("upstream_route_path_prefix");
        }
        if let Some(shape) = payload_shape {
            payload.insert("payload_shape".to_owned(), shape);
        }
        event
    }

    /// One fixture observation: method, path, status, latency, principal,
    /// routed, captured payload shape.
    type ParitySpec<'a> = (
        &'a str,
        String,
        u16,
        u64,
        Option<&'a str>,
        bool,
        Option<Value>,
    );

    /// 36 observations over six endpoints: two principals sharing one,
    /// captured shapes on another, a learned template, a call-count tie
    /// (to exercise the method/template tiebreak), and two unrouted
    /// endpoints (one anonymous) that never get a routing context.
    fn parity_events() -> Vec<AuditEvent> {
        let order_shape = |with_page: bool| {
            let mut query_params = Vec::new();
            if with_page {
                query_params
                    .push(json!({"name": "page", "redacted": false, "value_type": "number"}));
            }
            json!({
                "query_params": query_params,
                "json_body": {
                    "top_level_keys": [
                        {"name": "sku", "redacted": false},
                        {"name": "quantity", "redacted": false}
                    ]
                }
            })
        };
        let mut specs: Vec<ParitySpec<'_>> = Vec::new();
        for i in 0..12 {
            specs.push((
                "GET",
                "/orders".to_owned(),
                [200, 200, 500, 404][i % 4],
                5 + i as u64,
                Some(["alice", "bob"][i % 2]),
                true,
                None,
            ));
        }
        for i in 0..8 {
            specs.push((
                "POST",
                "/orders".to_owned(),
                201,
                20 + i as u64,
                Some("alice"),
                true,
                Some(order_shape(i % 3 != 0)),
            ));
        }
        for i in 0..6 {
            specs.push((
                "GET",
                format!("/users/{}", 100 + i),
                200,
                3,
                Some("carol"),
                true,
                None,
            ));
        }
        for _ in 0..4 {
            specs.push((
                "DELETE",
                "/orders/42".to_owned(),
                204,
                7,
                Some("bob"),
                true,
                None,
            ));
        }
        for _ in 0..4 {
            specs.push(("GET", "/health".to_owned(), 200, 1, None, false, None));
        }
        for _ in 0..2 {
            specs.push((
                "GET",
                "/legacy/report".to_owned(),
                200,
                9,
                Some("alice"),
                false,
                None,
            ));
        }
        specs
            .into_iter()
            .enumerate()
            .map(
                |(index, (method, path, status, latency, user, routed, shape))| {
                    parity_event(index, method, &path, status, latency, user, routed, shape)
                },
            )
            .collect()
    }

    /// The standalone inventory: the SQLite sink fed the events directly,
    /// flushed, and reopened through the query store.
    fn sqlite_inventory(events: &[AuditEvent], db: &TempDb) -> DiscoveryQueryStore {
        let sink = EndpointAggregatorSink::new(EndpointAggregatorSinkConfig {
            path: db.path.clone(),
            payload_capture_enabled: true,
            endpoint_limit: 0,
            signal_event_sender: None,
            signal_detector_config: SignalDetectorConfig::default(),
        })
        .expect("the SQLite sink should open");
        for event in events {
            sink.emit(event);
        }
        sink.flush().expect("the SQLite sink should flush");
        drop(sink);
        DiscoveryQueryStore::open(&db.path).expect("the SQLite query store should open")
    }

    /// The cluster inventory: the events ingested onto the stream and
    /// projected to completion in small batches (several flushes), then
    /// read through the PostgreSQL read store.
    async fn postgres_inventory(
        pool: &deadpool_postgres::Pool,
        events: &[AuditEvent],
    ) -> PostgresDiscoveryReadStore {
        ingest(pool, events).await;
        let store = Arc::new(PostgresDiscoveryStore::new(pool.clone()));
        let config = ProjectorConfig {
            payload_capture_enabled: true,
            endpoint_limit: 0,
            signal_detector_config: SignalDetectorConfig::default(),
            poll_interval: Duration::from_millis(10),
            batch_size: 7,
            flush_every: 5,
        };
        let mut term = begin_term(pool, &store, config, 1, None).await;
        let projected = term
            .project_until_caught_up(&CancellationToken::new())
            .await
            .expect("the projector should run")
            .expect("the term should catch up");
        assert_eq!(projected, events.len());
        PostgresDiscoveryReadStore::new(pool.clone())
    }

    fn endpoint_filters(sort: EndpointSort, limit: usize) -> EndpointListFilters {
        EndpointListFilters {
            method: None,
            endpoint_template_contains: None,
            endpoint_template_prefix: None,
            first_seen_after: None,
            first_seen_before: None,
            last_seen_after: None,
            last_seen_before: None,
            min_call_count: None,
            new_since_hours: DEFAULT_NEW_SINCE_HOURS,
            is_new: None,
            reviewed: None,
            sort,
            limit,
            cursor: None,
        }
    }

    fn signal_filters(limit: usize) -> SignalListFilters {
        SignalListFilters {
            state: None,
            signal_type: None,
            target_kind: None,
            target_key: None,
            limit,
            cursor: None,
        }
    }

    /// The comparable form of a read. `scrub_keys` are removed from every
    /// object (the ids and write timestamps each backend generates itself);
    /// every RFC 3339 string is re-rendered canonically, because the
    /// durable audit stream renders event times with fixed microseconds
    /// (`...:26.000000Z`) where the standalone sink keeps the event's own
    /// text (`...:26Z`) -- the same instant, which is what every ordering
    /// and filter compares; and page cursors are decoded (they are hex
    /// JSON on both backends) so the timestamps inside them get the same
    /// treatment and the cursor's content, not its bytes, is compared.
    fn comparable<T: serde::Serialize>(value: &T, scrub_keys: &[&str]) -> Value {
        fn canonicalize(value: &mut Value, scrub_keys: &[&str]) {
            match value {
                Value::Object(object) => {
                    for key in scrub_keys {
                        object.remove(*key);
                    }
                    for (key, child) in object.iter_mut() {
                        if key == "next_cursor" {
                            if let Some(decoded) = child
                                .as_str()
                                .and_then(|cursor| hex::decode(cursor).ok())
                                .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
                            {
                                *child = decoded;
                            }
                        }
                        canonicalize(child, scrub_keys);
                    }
                }
                Value::Array(items) => {
                    for item in items {
                        canonicalize(item, scrub_keys);
                    }
                }
                Value::String(text) => {
                    // Token-wise, so a timestamp quoted inside prose (a
                    // signal's explanation) is canonicalized as well.
                    let canonical = text
                        .split(' ')
                        .map(|token| match OffsetDateTime::parse(token, &Rfc3339) {
                            Ok(instant) => instant.format(&Rfc3339).expect("instant formats"),
                            Err(_) => token.to_owned(),
                        })
                        .collect::<Vec<_>>()
                        .join(" ");
                    *text = canonical;
                }
                _ => {}
            }
        }
        let mut value = serde_json::to_value(value).expect("value serializes");
        canonicalize(&mut value, scrub_keys);
        value
    }

    /// Signals compare as a set: ids are per-backend UUIDs, so an order
    /// that breaks a `created_at` tie on the id is legitimately different.
    fn signal_set(signals: &[signals::Signal]) -> Vec<Value> {
        let mut set = signals
            .iter()
            .map(|signal| comparable(signal, &["id", "updated_at", "transitioned_at"]))
            .collect::<Vec<_>>();
        set.sort_by_key(|signal| signal.to_string());
        set
    }

    async fn all_signal_pages(
        store: &dyn DiscoveryReadStore,
        mut filters: SignalListFilters,
    ) -> Vec<signals::Signal> {
        let mut signals = Vec::new();
        loop {
            let page = store.list_signals(&filters).await.expect("signals page");
            signals.extend(page.signals);
            match page.next_cursor {
                Some(cursor) => filters.cursor = Some(cursor),
                None => return signals,
            }
        }
    }

    /// Walk the endpoint pages of both stores in lockstep and require each
    /// page, cursor included, to be identical.
    async fn assert_same_endpoint_pages(
        sqlite: &dyn DiscoveryReadStore,
        postgres: &dyn DiscoveryReadStore,
        mut filters: EndpointListFilters,
        include_open_signals: bool,
        context: &str,
    ) -> usize {
        let mut listed = 0;
        let mut pages = 0;
        loop {
            let left = sqlite
                .list_endpoints_with_open_signal_summaries(&filters, include_open_signals)
                .await
                .expect("SQLite page");
            let right = postgres
                .list_endpoints_with_open_signal_summaries(&filters, include_open_signals)
                .await
                .expect("PostgreSQL page");
            assert_eq!(
                comparable(&left, &[]),
                comparable(&right, &[]),
                "{context}: page {pages} (cursor {:?}) differs",
                filters.cursor
            );
            listed += left.endpoints.len();
            pages += 1;
            match left.next_cursor {
                Some(cursor) => filters.cursor = Some(cursor),
                None => return listed,
            }
        }
    }

    async fn parity_fixture(
        database: &TestDatabase,
        sqlite_db: &TempDb,
    ) -> (DiscoveryQueryStore, PostgresDiscoveryReadStore) {
        let events = parity_events();
        let pool = migrated_discovery_pool(database).await;
        let postgres = postgres_inventory(&pool, &events).await;
        let sqlite = sqlite_inventory(&events, sqlite_db);
        (sqlite, postgres)
    }

    #[tokio::test]
    async fn read_store_lists_endpoints_and_pages_like_the_sqlite_store() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let sqlite_db = TempDb::new("read-parity-endpoints");
        let (sqlite, postgres) = parity_fixture(&database, &sqlite_db).await;
        let sqlite: &dyn DiscoveryReadStore = &sqlite;
        let postgres: &dyn DiscoveryReadStore = &postgres;

        // The observed inventory, routed and unrouted endpoints alike.
        let observed = sqlite.observed_endpoints().await.expect("SQLite observed");
        assert_eq!(
            comparable(&observed, &[]),
            comparable(
                &postgres
                    .observed_endpoints()
                    .await
                    .expect("PostgreSQL observed"),
                &[]
            )
        );
        assert!(
            observed
                .iter()
                .any(|endpoint| endpoint.upstream_origin.is_none()),
            "the fixture has unrouted endpoints"
        );
        assert!(
            observed
                .iter()
                .any(|endpoint| endpoint.upstream_origin.is_some()),
            "the fixture has routed endpoints"
        );
        let endpoint_count = observed
            .iter()
            .map(|endpoint| (&endpoint.method, &endpoint.endpoint_template))
            .collect::<std::collections::BTreeSet<_>>()
            .len();
        assert!(endpoint_count >= 6, "six endpoints were observed");

        // Every sort, paged two at a time, with and without signal
        // summaries: identical pages and identical cursors.
        for sort in [
            EndpointSort::LastSeen,
            EndpointSort::CallCount,
            EndpointSort::FirstSeen,
        ] {
            for include_open_signals in [true, false] {
                let listed = assert_same_endpoint_pages(
                    sqlite,
                    postgres,
                    endpoint_filters(sort, 2),
                    include_open_signals,
                    &format!("sort {sort:?}, open signals {include_open_signals}"),
                )
                .await;
                assert_eq!(listed, endpoint_count, "every endpoint is paged, once");
            }
        }

        // Every filter the list accepts, and a few combinations.
        let mid = "2024-06-01T12:00:20Z".to_owned();
        let filtered = [
            EndpointListFilters {
                method: Some("GET".to_owned()),
                ..endpoint_filters(EndpointSort::LastSeen, 10)
            },
            EndpointListFilters {
                endpoint_template_contains: Some("ORDERS".to_owned()),
                ..endpoint_filters(EndpointSort::CallCount, 10)
            },
            EndpointListFilters {
                endpoint_template_prefix: Some("/users".to_owned()),
                ..endpoint_filters(EndpointSort::FirstSeen, 10)
            },
            EndpointListFilters {
                endpoint_template_contains: Some("%".to_owned()),
                ..endpoint_filters(EndpointSort::LastSeen, 10)
            },
            EndpointListFilters {
                min_call_count: Some(5),
                ..endpoint_filters(EndpointSort::CallCount, 10)
            },
            EndpointListFilters {
                is_new: Some(false),
                ..endpoint_filters(EndpointSort::LastSeen, 10)
            },
            EndpointListFilters {
                is_new: Some(true),
                ..endpoint_filters(EndpointSort::LastSeen, 10)
            },
            EndpointListFilters {
                is_new: Some(true),
                new_since_hours: MAX_NEW_SINCE_HOURS,
                ..endpoint_filters(EndpointSort::FirstSeen, 10)
            },
            EndpointListFilters {
                reviewed: Some(false),
                ..endpoint_filters(EndpointSort::LastSeen, 10)
            },
            EndpointListFilters {
                reviewed: Some(true),
                ..endpoint_filters(EndpointSort::LastSeen, 10)
            },
            EndpointListFilters {
                first_seen_after: Some(mid.clone()),
                ..endpoint_filters(EndpointSort::FirstSeen, 10)
            },
            EndpointListFilters {
                first_seen_before: Some(mid.clone()),
                ..endpoint_filters(EndpointSort::FirstSeen, 10)
            },
            EndpointListFilters {
                last_seen_after: Some(mid.clone()),
                ..endpoint_filters(EndpointSort::LastSeen, 10)
            },
            EndpointListFilters {
                last_seen_before: Some(mid.clone()),
                ..endpoint_filters(EndpointSort::LastSeen, 10)
            },
            EndpointListFilters {
                method: Some("GET".to_owned()),
                endpoint_template_prefix: Some("/".to_owned()),
                min_call_count: Some(4),
                last_seen_after: Some("2024-06-01T12:00:00Z".to_owned()),
                ..endpoint_filters(EndpointSort::CallCount, 1)
            },
        ];
        let mut non_empty = 0;
        for (index, filters) in filtered.into_iter().enumerate() {
            let listed = assert_same_endpoint_pages(
                sqlite,
                postgres,
                filters,
                true,
                &format!("filter set {index}"),
            )
            .await;
            if listed > 0 {
                non_empty += 1;
            }
        }
        assert!(non_empty >= 10, "most filter sets match rows");

        // Detail for every endpoint; `updated_at` is each backend's own
        // write time.
        for endpoint in &observed {
            for include_open_signals in [true, false] {
                let left = sqlite
                    .get_endpoint_with_open_signal_summaries(
                        &endpoint.method,
                        &endpoint.endpoint_template,
                        DEFAULT_NEW_SINCE_HOURS,
                        include_open_signals,
                    )
                    .await
                    .expect("SQLite detail")
                    .expect("the endpoint exists");
                let right = postgres
                    .get_endpoint_with_open_signal_summaries(
                        &endpoint.method,
                        &endpoint.endpoint_template,
                        DEFAULT_NEW_SINCE_HOURS,
                        include_open_signals,
                    )
                    .await
                    .expect("PostgreSQL detail")
                    .expect("the endpoint exists");
                assert_eq!(
                    comparable(&left, &["updated_at"]),
                    comparable(&right, &["updated_at"]),
                    "detail of {} {}",
                    endpoint.method,
                    endpoint.endpoint_template
                );
                assert_eq!(
                    left.open_signals.is_some(),
                    include_open_signals,
                    "the summary follows the permission"
                );
            }
        }
        assert!(sqlite
            .get_endpoint_with_open_signal_summaries("GET", "/nope", 24, true)
            .await
            .expect("SQLite detail")
            .is_none());
        assert!(postgres
            .get_endpoint_with_open_signal_summaries("GET", "/nope", 24, true)
            .await
            .expect("PostgreSQL detail")
            .is_none());

        // The inferred schema over the captured shapes, and none where
        // nothing was captured.
        let left = sqlite
            .inferred_request_schema("POST", "/orders")
            .await
            .expect("SQLite schema")
            .expect("POST /orders has samples");
        let right = postgres
            .inferred_request_schema("POST", "/orders")
            .await
            .expect("PostgreSQL schema")
            .expect("POST /orders has samples");
        assert_eq!(left, right);
        assert_eq!(left.sample_count, 8);
        assert!(left.json_body_keys.iter().any(|key| key.required));
        assert!(sqlite
            .inferred_request_schema("GET", "/orders")
            .await
            .expect("SQLite schema")
            .is_none());
        assert!(postgres
            .inferred_request_schema("GET", "/orders")
            .await
            .expect("PostgreSQL schema")
            .is_none());

        // Cursor validation: garbage, and a cursor minted for another sort.
        let garbage = EndpointListFilters {
            cursor: Some("not-a-cursor".to_owned()),
            ..endpoint_filters(EndpointSort::LastSeen, 2)
        };
        for store in [sqlite, postgres] {
            assert!(matches!(
                store
                    .list_endpoints_with_open_signal_summaries(&garbage, true)
                    .await,
                Err(DiscoveryQueryError::InvalidCursor {
                    parameter: "cursor"
                })
            ));
        }
        let first_page = postgres
            .list_endpoints_with_open_signal_summaries(
                &endpoint_filters(EndpointSort::LastSeen, 1),
                true,
            )
            .await
            .expect("first page");
        let wrong_sort = EndpointListFilters {
            cursor: first_page.next_cursor.clone(),
            ..endpoint_filters(EndpointSort::CallCount, 1)
        };
        for store in [sqlite, postgres] {
            assert!(matches!(
                store
                    .list_endpoints_with_open_signal_summaries(&wrong_sort, true)
                    .await,
                Err(DiscoveryQueryError::InvalidCursor {
                    parameter: "cursor"
                })
            ));
        }
    }

    #[tokio::test]
    async fn read_store_serves_signals_principals_and_reviews_like_the_sqlite_store() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let sqlite_db = TempDb::new("read-parity-signals");
        let (sqlite, postgres) = parity_fixture(&database, &sqlite_db).await;
        let sqlite: &dyn DiscoveryReadStore = &sqlite;
        let postgres: &dyn DiscoveryReadStore = &postgres;

        // Signals, paged three at a time and under every filter.
        let left = all_signal_pages(sqlite, signal_filters(3)).await;
        let right = all_signal_pages(postgres, signal_filters(3)).await;
        assert!(
            left.len() >= 4,
            "each of the four routed endpoints opened a signal (unrouted ones never do)"
        );
        assert_eq!(left.len(), right.len());
        assert_eq!(signal_set(&left), signal_set(&right));
        for filters in [
            SignalListFilters {
                signal_type: Some(signals::NEW_ENDPOINT_SEEN_SIGNAL_TYPE.to_owned()),
                ..signal_filters(10)
            },
            SignalListFilters {
                target_kind: Some(signals::PRINCIPAL_ENDPOINT_TARGET_KIND.to_owned()),
                ..signal_filters(10)
            },
            SignalListFilters {
                state: Some(SignalLifecycleState::Open),
                ..signal_filters(10)
            },
            SignalListFilters {
                state: Some(SignalLifecycleState::Dismissed),
                ..signal_filters(10)
            },
            SignalListFilters {
                target_key: Some(signals::endpoint_target_key("GET", "/orders")),
                ..signal_filters(10)
            },
        ] {
            let left = all_signal_pages(sqlite, filters.clone()).await;
            let right = all_signal_pages(postgres, filters).await;
            assert_eq!(signal_set(&left), signal_set(&right));
        }

        // Principals of the shared endpoint, one per page: identical pages
        // and cursors (nothing here is backend-generated).
        let mut principal_filters = PrincipalPageFilters {
            limit: 1,
            cursor: None,
        };
        let mut principals = Vec::new();
        loop {
            let left = sqlite
                .list_principals("GET", "/orders", &principal_filters)
                .await
                .expect("SQLite principals");
            let right = postgres
                .list_principals("GET", "/orders", &principal_filters)
                .await
                .expect("PostgreSQL principals");
            assert_eq!(comparable(&left, &[]), comparable(&right, &[]));
            principals.extend(left.principals);
            match left.next_cursor {
                Some(cursor) => principal_filters.cursor = Some(cursor),
                None => break,
            }
        }
        assert_eq!(principals.len(), 2, "alice and bob");
        let bob = principals
            .iter()
            .find(|principal| principal.user_id == "bob")
            .expect("bob was seen");

        // Bob's principal_new_to_endpoint history (he arrived on GET
        // /orders after alice), by his identity as the aggregator
        // canonicalized it: the issuer without its trailing slash.
        let issuer = bob.issuer.clone().unwrap_or_default();
        assert_eq!(issuer, "https://issuer.example");
        let left = sqlite
            .list_principal_endpoint_signals("bob", &issuer, &bob.auth_method, 10)
            .await
            .expect("SQLite history");
        let right = postgres
            .list_principal_endpoint_signals("bob", &issuer, &bob.auth_method, 10)
            .await
            .expect("PostgreSQL history");
        assert!(!left.is_empty(), "bob is new to at least one endpoint");
        assert_eq!(signal_set(&left), signal_set(&right));
        for store in [sqlite, postgres] {
            assert!(store
                .list_principal_endpoint_signals("bob", &issuer, &bob.auth_method, 0)
                .await
                .expect("history")
                .is_empty());
            assert!(store
                .list_principal_endpoint_signals(
                    "bob",
                    "https://elsewhere.example",
                    &bob.auth_method,
                    10
                )
                .await
                .expect("history")
                .is_empty());
            assert!(
                store
                    .list_principal_endpoint_signals("alice", &issuer, &bob.auth_method, 10)
                    .await
                    .expect("history")
                    .is_empty(),
                "alice was first everywhere, so she is new nowhere"
            );
        }

        // Reviews: set, observe through detail and the reviewed filter,
        // clear, and the unknown endpoint. `reviewed_at` is each backend's
        // own clock.
        let left = sqlite
            .set_endpoint_review("GET", "/orders", true, Some("reviewer"), None)
            .await
            .expect("SQLite review")
            .expect_applied("the endpoint exists");
        let right = postgres
            .set_endpoint_review("GET", "/orders", true, Some("reviewer"), None)
            .await
            .expect("PostgreSQL review")
            .expect_applied("the endpoint exists");
        assert_eq!(
            comparable(&left, &["reviewed_at"]),
            comparable(&right, &["reviewed_at"])
        );
        assert!(left.reviewed && left.reviewed_at.is_some());
        assert_eq!(left.revision, 1);
        for store in [sqlite, postgres] {
            let detail = store
                .get_endpoint_with_open_signal_summaries("GET", "/orders", 24, true)
                .await
                .expect("detail")
                .expect("exists");
            assert!(detail.reviewed);
            assert_eq!(detail.reviewed_by.as_deref(), Some("reviewer"));
            let reviewed = store
                .list_endpoints_with_open_signal_summaries(
                    &EndpointListFilters {
                        reviewed: Some(true),
                        ..endpoint_filters(EndpointSort::LastSeen, 10)
                    },
                    true,
                )
                .await
                .expect("reviewed list");
            assert_eq!(reviewed.endpoints.len(), 1);
            assert_eq!(reviewed.endpoints[0].endpoint_template, "/orders");
            assert_eq!(reviewed.endpoints[0].method, "GET");
            assert_eq!(detail.review_revision, 1);
            let cleared = store
                .set_endpoint_review("GET", "/orders", false, Some("reviewer"), None)
                .await
                .expect("clear review")
                .expect_applied("exists");
            assert!(!cleared.reviewed && cleared.reviewed_at.is_none());
            assert!(store
                .set_endpoint_review("GET", "/nope", true, Some("reviewer"), None)
                .await
                .expect("unknown review")
                .is_not_found());
        }

        // Signal lifecycle: the same logical signal on each side, moved to
        // acknowledged by the same actor.
        let new_endpoint_signal = |store: &'static str, signals: &[signals::Signal]| {
            signals
                .iter()
                .find(|signal| {
                    signal.signal_type == signals::NEW_ENDPOINT_SEEN_SIGNAL_TYPE
                        && signal.target.identity["endpoint_template"] == json!("/orders")
                        && signal.target.identity["method"] == json!("GET")
                })
                .map(|signal| signal.id.clone())
                .unwrap_or_else(|| panic!("{store} opened new_endpoint_seen for GET /orders"))
        };
        let left_id = new_endpoint_signal("SQLite", &left_signals(sqlite).await);
        let right_id = new_endpoint_signal("PostgreSQL", &left_signals(postgres).await);
        let from_open = TransitionPrecondition::from_state(SignalLifecycleState::Open);
        let left = sqlite
            .transition_signal(
                &left_id,
                SignalLifecycleState::Acknowledged,
                Some("reviewer"),
                from_open,
            )
            .await
            .expect("SQLite transition")
            .expect_applied("the signal exists");
        let right = postgres
            .transition_signal(
                &right_id,
                SignalLifecycleState::Acknowledged,
                Some("reviewer"),
                from_open,
            )
            .await
            .expect("PostgreSQL transition")
            .expect_applied("the signal exists");
        assert_eq!(
            signal_set(std::slice::from_ref(&left)),
            signal_set(std::slice::from_ref(&right))
        );
        assert_eq!(left.state, SignalLifecycleState::Acknowledged);
        assert_eq!(left.transitioned_by.as_deref(), Some("reviewer"));
        assert!(left.transitioned_at.is_some());
        assert_eq!(left.revision, 2);
        assert_eq!(right.revision, 2);
        for store in [sqlite, postgres] {
            let acknowledged = all_signal_pages(
                store,
                SignalListFilters {
                    state: Some(SignalLifecycleState::Acknowledged),
                    ..signal_filters(10)
                },
            )
            .await;
            assert_eq!(acknowledged.len(), 1);
            assert!(store
                .transition_signal(
                    "no-such-signal",
                    SignalLifecycleState::Dismissed,
                    None,
                    from_open
                )
                .await
                .expect("unknown transition")
                .is_not_found());
        }

        // Cursor validation on the signal and principal pages.
        for store in [sqlite, postgres] {
            assert!(matches!(
                store
                    .list_signals(&SignalListFilters {
                        cursor: Some("zz".to_owned()),
                        ..signal_filters(3)
                    })
                    .await,
                Err(DiscoveryQueryError::InvalidCursor {
                    parameter: "cursor"
                })
            ));
            assert!(matches!(
                store
                    .list_principals(
                        "GET",
                        "/orders",
                        &PrincipalPageFilters {
                            limit: 1,
                            cursor: Some("zz".to_owned()),
                        }
                    )
                    .await,
                Err(DiscoveryQueryError::InvalidCursor {
                    parameter: "principal_cursor"
                })
            ));
        }
    }

    async fn left_signals(store: &dyn DiscoveryReadStore) -> Vec<signals::Signal> {
        all_signal_pages(store, signal_filters(50)).await
    }

    /// The bulk schema read the cluster conformance refresher uses answers
    /// every requested endpoint in order, exactly as the single-endpoint
    /// read would, in one query; an endpoint whose samples are corrupt is
    /// answered with no schema instead of failing the whole set.
    #[tokio::test]
    async fn read_store_infers_schemas_in_bulk_and_skips_a_corrupt_endpoint() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let pool = migrated_discovery_pool(&database).await;
        let postgres = postgres_inventory(&pool, &parity_events()).await;
        let postgres: &dyn DiscoveryReadStore = &postgres;

        {
            let client = pool.get().await.expect("client");
            client
                .execute(
                    "INSERT INTO greengateway.discovery_payload_shape_samples
                         (method, endpoint_template, sample_slot, observed_at, shape_hash,
                          shape_json)
                     VALUES ('PUT', '/corrupt', 0, '2024-06-01T12:00:00Z', 'h', $1)",
                    &[&r#"{"json_body": 5}"#],
                )
                .await
                .expect("a corrupt sample row inserts");
        }

        let requested = [
            ("POST".to_owned(), "/orders".to_owned()),
            ("PUT".to_owned(), "/corrupt".to_owned()),
            ("GET".to_owned(), "/orders".to_owned()),
            ("GET".to_owned(), "/never-observed".to_owned()),
        ];
        let schemas = postgres
            .inferred_request_schemas(&requested)
            .await
            .expect("the bulk read answers");
        assert_eq!(schemas.len(), requested.len());
        let single = postgres
            .inferred_request_schema("POST", "/orders")
            .await
            .expect("single read")
            .expect("POST /orders has samples");
        assert_eq!(schemas[0].as_ref(), Some(&single));
        assert!(
            schemas[1].is_none(),
            "the corrupt endpoint is answered with no schema"
        );
        assert!(schemas[2].is_none(), "GET /orders captured nothing");
        assert!(schemas[3].is_none(), "an unknown endpoint has no schema");
        assert!(
            postgres
                .inferred_request_schema("PUT", "/corrupt")
                .await
                .is_err(),
            "the single-endpoint read still reports the corruption"
        );
        assert!(postgres
            .inferred_request_schemas(&[])
            .await
            .expect("an empty request answers")
            .is_empty());
    }

    // ------------------------------------------------------------------
    // Cluster membership and the maintenance ledger (issue #241, PR 13)
    // ------------------------------------------------------------------

    use crate::cluster_membership::{ClusterMembership, FingerprintAgreement};
    use crate::ha::InstanceIdentity;
    use crate::storage::{
        JobOutcome, MemberRegistration, MemberRevisions, PostgresMembershipStore,
    };

    const MEMBERS_DEPLOYMENT: &str = "deploy-members";

    fn registration(fingerprint_byte: char) -> MemberRegistration {
        MemberRegistration {
            binary_version: env!("CARGO_PKG_VERSION").to_owned(),
            schema_version: migrations::schema_version_range(),
            document_version: crate::cluster_membership::DOCUMENT_VERSION_RANGE,
            fingerprint: std::iter::repeat_n(fingerprint_byte, 64).collect(),
        }
    }

    fn member_store(pool: &deadpool_postgres::Pool) -> PostgresMembershipStore {
        PostgresMembershipStore::new(
            pool.clone(),
            MEMBERS_DEPLOYMENT,
            InstanceIdentity::generate(),
        )
    }

    /// Move a member's heartbeat into the past on the database clock, as
    /// a partitioned or crashed replica's row would look.
    async fn backdate_heartbeat(
        pool: &deadpool_postgres::Pool,
        instance_id: uuid::Uuid,
        seconds: f64,
    ) {
        let client = pool.get().await.expect("client");
        let updated = client
            .execute(
                "UPDATE greengateway.cluster_members
                 SET last_heartbeat_at = now() - make_interval(secs => $2::double precision)
                 WHERE instance_id = $1::text::uuid",
                &[&instance_id.to_string(), &seconds],
            )
            .await
            .expect("backdate");
        assert_eq!(updated, 1, "the member row exists to backdate");
    }

    /// Heartbeats create the row with the registration, refresh it with
    /// the revisions and the carried error code, and the ready/draining
    /// stamps are written once and count as heartbeats. Deployments never
    /// see each other's rows, and a malformed fingerprint is refused
    /// before it reaches the schema's check.
    #[tokio::test]
    async fn heartbeats_appear_update_and_carry_the_lifecycle_stamps() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let pool = migrated_limits_pool(&database).await;
        let store = member_store(&pool);
        let registration = registration('a');
        let window = Duration::from_secs(30);

        store
            .heartbeat(&registration, MemberRevisions::default(), None)
            .await
            .expect("boot heartbeat");
        let members = store.members(window).await.expect("members");
        assert_eq!(members.len(), 1);
        let first = &members[0];
        assert_eq!(first.instance_id, store.instance_id());
        assert!(first.live);
        assert_eq!(first.fingerprint, registration.fingerprint);
        assert_eq!(first.binary_version, env!("CARGO_PKG_VERSION"));
        assert_eq!(
            (first.schema_version_min, first.schema_version_max),
            migrations::schema_version_range()
        );
        assert_eq!(
            (first.document_version_min, first.document_version_max),
            (0, 0)
        );
        assert_eq!(first.compiled_security_revision, 0);
        assert_eq!(first.observed_security_revision, 0);
        assert!(first.ready_at.is_none() && first.draining_at.is_none());
        assert!(first.last_error_code.is_none());
        assert!(first.heartbeat_age_secs < 30.0);

        tokio::time::sleep(Duration::from_millis(20)).await;
        store
            .heartbeat(
                &registration,
                MemberRevisions {
                    compiled: 3,
                    observed: 5,
                },
                Some("unavailable"),
            )
            .await
            .expect("second heartbeat");
        let members = store.members(window).await.expect("members");
        assert_eq!(members.len(), 1, "a heartbeat refreshes, never duplicates");
        let second = &members[0];
        assert_eq!(second.started_at, first.started_at, "boot time is kept");
        assert!(
            second.last_heartbeat_at > first.last_heartbeat_at,
            "the heartbeat moved forward: {} -> {}",
            first.last_heartbeat_at,
            second.last_heartbeat_at
        );
        assert_eq!(second.compiled_security_revision, 3);
        assert_eq!(second.observed_security_revision, 5);
        assert_eq!(second.last_error_code.as_deref(), Some("unavailable"));

        store.mark_ready().await.expect("ready stamp");
        let ready_at = store.members(window).await.expect("members")[0]
            .ready_at
            .clone()
            .expect("ready_at is stamped");
        tokio::time::sleep(Duration::from_millis(20)).await;
        store.mark_ready().await.expect("repeat ready stamp");
        store.mark_draining().await.expect("draining stamp");
        let stamped = store.members(window).await.expect("members");
        assert_eq!(
            stamped[0].ready_at.as_deref(),
            Some(ready_at.as_str()),
            "the first ready instant is kept"
        );
        assert!(stamped[0].draining_at.is_some());
        assert!(
            stamped[0].last_heartbeat_at > second.last_heartbeat_at,
            "a stamp counts as a heartbeat"
        );

        let other_deployment = PostgresMembershipStore::new(
            pool.clone(),
            "deploy-elsewhere",
            InstanceIdentity::generate(),
        );
        assert!(
            other_deployment
                .members(window)
                .await
                .expect("members")
                .is_empty(),
            "deployments never see each other's rosters"
        );

        let mut malformed = registration.clone();
        malformed.fingerprint = "not-hex".to_owned();
        let error = store
            .heartbeat(&malformed, MemberRevisions::default(), None)
            .await
            .expect_err("a malformed fingerprint is refused");
        assert_eq!(error.kind(), RepositoryErrorKind::InvalidData);
    }

    /// A member that stops heartbeating is live until the window passes
    /// on the database clock, reported stale after it, and swept only by
    /// the singleton's sweep -- bounded per call, oldest first, and never
    /// touching a live row.
    #[tokio::test]
    async fn stale_members_are_swept_only_after_the_window() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let pool = migrated_limits_pool(&database).await;
        let live = member_store(&pool);
        let silent = member_store(&pool);
        let older = member_store(&pool);
        for store in [&live, &silent, &older] {
            store
                .heartbeat(&registration('a'), MemberRevisions::default(), None)
                .await
                .expect("heartbeat");
        }
        backdate_heartbeat(&pool, silent.instance_id(), 10.0).await;
        backdate_heartbeat(&pool, older.instance_id(), 40.0).await;

        let wide = Duration::from_secs(60);
        let narrow = Duration::from_secs(5);
        let by_id = |members: Vec<crate::storage::ClusterMember>| {
            members
                .into_iter()
                .map(|member| (member.instance_id, member.live))
                .collect::<std::collections::HashMap<_, _>>()
        };
        let within_wide = by_id(live.members(wide).await.expect("members"));
        assert_eq!(within_wide.len(), 3);
        assert!(
            within_wide.values().all(|live| *live),
            "inside the window everyone is live"
        );
        let within_narrow = by_id(live.members(narrow).await.expect("members"));
        assert!(within_narrow[&live.instance_id()]);
        assert!(!within_narrow[&silent.instance_id()]);
        assert!(!within_narrow[&older.instance_id()]);

        assert_eq!(
            live.sweep_stale(wide, 10).await.expect("sweep"),
            0,
            "nothing is stale inside the wide window"
        );
        assert_eq!(
            live.sweep_stale(narrow, 1).await.expect("sweep"),
            1,
            "the sweep is bounded per call"
        );
        let after_one = by_id(live.members(wide).await.expect("members"));
        assert!(
            !after_one.contains_key(&older.instance_id()),
            "the oldest heartbeat goes first"
        );
        assert!(after_one.contains_key(&silent.instance_id()));
        assert_eq!(live.sweep_stale(narrow, 10).await.expect("sweep"), 1);
        let remaining = live.members(wide).await.expect("members");
        assert_eq!(remaining.len(), 1);
        assert_eq!(
            remaining[0].instance_id,
            live.instance_id(),
            "a live row is never swept"
        );
        assert_eq!(live.sweep_stale(narrow, 10).await.expect("sweep"), 0);
    }

    /// The fingerprint gate: a lone replica agrees with itself; a second
    /// replica with another fingerprint is refused readiness while the
    /// first is live and not draining, and admitted once it drains or
    /// goes stale; a replica with the same fingerprint as every live
    /// member is admitted at once; and agreement, once granted, is not
    /// revoked by a later mismatched arrival.
    #[tokio::test]
    async fn readiness_is_refused_on_fingerprint_mismatch_and_granted_on_agreement() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let pool = migrated_limits_pool(&database).await;
        let heartbeat = Duration::from_secs(1);
        let window = Duration::from_secs(30);

        let first_store = member_store(&pool);
        let first_id = first_store.instance_id();
        let first =
            ClusterMembership::new(first_store.clone(), registration('a'), heartbeat, window);
        assert_eq!(
            first.register_boot().await.expect("boot"),
            FingerprintAgreement::Agreed,
            "a lone replica agrees with itself"
        );
        assert_eq!(first.readiness().blocked_reason(), None);

        let second_store = member_store(&pool);
        let second_id = second_store.instance_id();
        let second =
            ClusterMembership::new(second_store.clone(), registration('b'), heartbeat, window);
        assert_eq!(
            second.register_boot().await.expect("boot"),
            FingerprintAgreement::Disagreeing(vec![first_id]),
            "the live member with another fingerprint is named"
        );
        assert_eq!(
            second.readiness().blocked_reason(),
            Some("config_fingerprint_mismatch")
        );
        assert_eq!(
            second.check_fingerprint_agreement().await.expect("check"),
            FingerprintAgreement::Disagreeing(vec![first_id]),
            "the refusal holds while the member is live"
        );
        assert_eq!(
            first.check_fingerprint_agreement().await.expect("check"),
            FingerprintAgreement::Agreed,
            "agreement is sticky: the serving replica is not taken out by the newcomer"
        );

        let same_store = member_store(&pool);
        let same_id = same_store.instance_id();
        let same = ClusterMembership::new(same_store, registration('a'), heartbeat, window);
        assert_eq!(
            same.register_boot().await.expect("boot"),
            FingerprintAgreement::Disagreeing(vec![second_id]),
            "the mismatched newcomer blocks a later replica on the first's fingerprint too"
        );

        first_store.mark_draining().await.expect("drain");
        assert_eq!(
            second.check_fingerprint_agreement().await.expect("check"),
            FingerprintAgreement::Disagreeing(vec![same_id]),
            "a draining member no longer blocks; a live one on the old fingerprint still does"
        );
        backdate_heartbeat(&pool, same_id, 60.0).await;
        assert_eq!(
            second.check_fingerprint_agreement().await.expect("check"),
            FingerprintAgreement::Agreed,
            "a stale member no longer blocks"
        );
        assert_eq!(second.readiness().blocked_reason(), None);

        let third_store = member_store(&pool);
        let third = ClusterMembership::new(third_store, registration('c'), heartbeat, window);
        assert_eq!(
            third.register_boot().await.expect("boot"),
            FingerprintAgreement::Disagreeing(vec![second_id]),
            "only the live, non-draining member with another fingerprint blocks"
        );
        backdate_heartbeat(&pool, second_id, 60.0).await;
        assert_eq!(
            third.check_fingerprint_agreement().await.expect("check"),
            FingerprintAgreement::Agreed,
            "a stale member no longer blocks"
        );

        let fourth_store = member_store(&pool);
        let fourth = ClusterMembership::new(fourth_store, registration('c'), heartbeat, window);
        assert_eq!(
            fourth.register_boot().await.expect("boot"),
            FingerprintAgreement::Agreed,
            "the same fingerprint as every live member is admitted at once"
        );
    }

    /// A swept row comes back as the same boot: a replica partitioned past
    /// the stale window has its row swept by the singleton; when it
    /// reconnects, its next heartbeat re-creates the row with the
    /// `started_at` and `ready_at` the database rendered the first time,
    /// not as a fresh, unready boot -- and the ready stamp stays
    /// idempotent afterwards.
    #[tokio::test]
    async fn a_swept_member_that_reconnects_keeps_its_boot_and_ready_instants() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let pool = migrated_limits_pool(&database).await;
        let window = Duration::from_secs(30);
        let store = member_store(&pool);
        store
            .heartbeat(&registration('a'), MemberRevisions::default(), None)
            .await
            .expect("heartbeat");
        store.mark_ready().await.expect("ready");
        let before = store.members(window).await.expect("members");
        assert_eq!(before.len(), 1);
        let before = before[0].clone();
        assert!(before.ready_at.is_some(), "the ready stamp landed");

        // Partitioned past the window: the singleton sweeps the row.
        backdate_heartbeat(&pool, store.instance_id(), 60.0).await;
        assert_eq!(store.sweep_stale(window, 10).await.expect("sweep"), 1);
        assert!(store.members(window).await.expect("members").is_empty());

        // Reconnected: the next heartbeat is the same boot, still ready.
        store
            .heartbeat(
                &registration('a'),
                MemberRevisions {
                    compiled: 3,
                    observed: 4,
                },
                None,
            )
            .await
            .expect("heartbeat");
        let after = store.members(window).await.expect("members");
        assert_eq!(after.len(), 1);
        let after = &after[0];
        assert!(after.live);
        assert_eq!(after.instance_id, before.instance_id);
        assert_eq!(after.boot_id, before.boot_id);
        assert_eq!(
            after.started_at, before.started_at,
            "the boot instant survives the sweep"
        );
        assert_eq!(
            after.ready_at, before.ready_at,
            "the ready instant survives the sweep"
        );
        assert_eq!(after.compiled_security_revision, 3);
        assert_eq!(after.observed_security_revision, 4);

        // A clone of the store is the same replica and remembers the same
        // instants; a repeat of the ready stamp keeps the first one.
        let clone = store.clone();
        clone.mark_ready().await.expect("ready");
        backdate_heartbeat(&pool, store.instance_id(), 60.0).await;
        assert_eq!(clone.sweep_stale(window, 10).await.expect("sweep"), 1);
        clone
            .heartbeat(&registration('a'), MemberRevisions::default(), None)
            .await
            .expect("heartbeat");
        let again = store.members(window).await.expect("members");
        assert_eq!(again[0].started_at, before.started_at);
        assert_eq!(again[0].ready_at, before.ready_at);
    }

    /// The maintenance ledger's write predicate: a leader adopts the rows
    /// at its lease fence and writes under it while its lease is live; its
    /// writes are refused from the instant the lease lapses -- before any
    /// successor has acquired, and before one that has adopts the rows --
    /// and a successor adopts at a higher fence; the stale leader's late
    /// writes (start, outcome, re-adoption) match no row and change
    /// nothing. A fence no lease carries adopts nothing at all.
    #[tokio::test]
    async fn maintenance_job_writes_are_refused_by_the_fence() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let pool = migrated_limits_pool(&database).await;
        let store = member_store(&pool);
        let jobs = ["alpha", "beta"];
        let ttl = Duration::from_secs(30);
        let leases_a = maintenance_leases(&pool, uuid::Uuid::new_v4(), ttl);
        let leases_b = maintenance_leases(&pool, uuid::Uuid::new_v4(), ttl);
        let acquired = |attempt: LeaseAttempt| match attempt {
            LeaseAttempt::Acquired(lease) => lease,
            LeaseAttempt::Full => panic!("expected the maintenance slot free"),
        };

        assert!(
            !store.adopt_jobs(&jobs, 5).await.expect("adopt"),
            "a fence no live lease carries adopts nothing"
        );
        assert!(store.maintenance_jobs().await.expect("records").is_empty());

        let lease_a = acquired(
            leases_a
                .try_acquire(MAINTENANCE_SCOPE, 1, "a")
                .await
                .expect("acquire"),
        );
        let fence_a = lease_a.fence;
        assert!(store.adopt_jobs(&jobs, fence_a).await.expect("adopt"));
        assert!(store
            .record_job_started("alpha", fence_a)
            .await
            .expect("start"));
        assert!(store
            .record_job_outcome("alpha", fence_a, &JobOutcome::Success { duration_ms: 12 })
            .await
            .expect("outcome"));
        let records = store.maintenance_jobs().await.expect("records");
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].job, "alpha");
        assert_eq!(records[0].fence, fence_a);
        assert!(records[0].last_started_at.is_some());
        assert!(records[0].last_success_at.is_some());
        assert_eq!(records[0].last_failure_code, None);
        assert_eq!(records[0].last_duration_ms, Some(12));
        assert_eq!(records[1].job, "beta");
        assert_eq!(records[1].fence, fence_a);
        assert!(records[1].last_started_at.is_none());

        // The holder's lease lapses on the database clock (it stopped
        // renewing) while the rows still carry its fence and nobody has
        // taken the slot: its writes are already refused.
        let client = pool.get().await.expect("client");
        assert_eq!(
            client
                .execute(
                    "UPDATE greengateway.execution_leases
                     SET expires_at = now() - interval '1 second'
                     WHERE fence = $1",
                    &[&fence_a],
                )
                .await
                .expect("lapse"),
            1
        );
        assert!(
            !leases_a.is_current(&lease_a).await.expect("check"),
            "the lease lapsed"
        );
        assert!(
            !store
                .record_job_started("alpha", fence_a)
                .await
                .expect("start"),
            "a lapsed lease refuses the start though the row still carries its fence"
        );
        assert!(
            !store
                .record_job_outcome(
                    "alpha",
                    fence_a,
                    &JobOutcome::Failure {
                        code: "timeout".to_owned(),
                        duration_ms: 99,
                    },
                )
                .await
                .expect("outcome"),
            "a lapsed lease refuses the outcome though the row still carries its fence"
        );
        assert!(
            !store.adopt_jobs(&jobs, fence_a).await.expect("adopt"),
            "a lapsed lease cannot re-adopt at its own fence"
        );
        let held = store.maintenance_jobs().await.expect("records");
        assert_eq!(held[0].fence, fence_a, "the rows are untouched");
        assert_eq!(held[0].last_failure_code, None);
        assert_eq!(held[0].last_started_at, records[0].last_started_at);

        let lease_b = acquired(
            leases_b
                .try_acquire(MAINTENANCE_SCOPE, 1, "b")
                .await
                .expect("acquire"),
        );
        let fence_b = lease_b.fence;
        assert!(fence_b > fence_a);
        assert!(
            !store
                .record_job_started("alpha", fence_a)
                .await
                .expect("start"),
            "still refused once a successor holds the slot but has not adopted"
        );
        assert!(
            !store
                .record_job_started("alpha", fence_b)
                .await
                .expect("start"),
            "a live holder that has not adopted the rows cannot write them either"
        );
        assert!(
            !store
                .record_job_outcome("alpha", fence_b, &JobOutcome::Success { duration_ms: 1 })
                .await
                .expect("outcome"),
            "nor record an outcome on rows it has not adopted"
        );
        assert!(
            store.adopt_jobs(&jobs, fence_b).await.expect("adopt"),
            "a successor adopts at a higher fence"
        );
        assert!(
            !store
                .record_job_started("alpha", fence_a)
                .await
                .expect("start"),
            "the stale leader's start is refused"
        );
        assert!(
            !store
                .record_job_outcome(
                    "alpha",
                    fence_a,
                    &JobOutcome::Failure {
                        code: "timeout".to_owned(),
                        duration_ms: 99,
                    },
                )
                .await
                .expect("outcome"),
            "the stale leader's outcome is refused"
        );
        assert!(
            !store.adopt_jobs(&jobs, fence_a).await.expect("adopt"),
            "the stale leader cannot lower the fence"
        );
        let unchanged = store.maintenance_jobs().await.expect("records");
        assert_eq!(unchanged[0].fence, fence_b);
        assert_eq!(unchanged[0].last_failure_code, None);
        assert_eq!(unchanged[0].last_duration_ms, Some(12));
        assert_eq!(unchanged[0].last_success_at, records[0].last_success_at);

        assert!(store
            .record_job_outcome(
                "beta",
                fence_b,
                &JobOutcome::Failure {
                    code: "unavailable".to_owned(),
                    duration_ms: 3,
                },
            )
            .await
            .expect("outcome"));
        assert!(
            store.adopt_jobs(&["alpha"], fence_b).await.expect("adopt"),
            "the holder re-adopts at its own fence"
        );
        let after = store.maintenance_jobs().await.expect("records");
        assert_eq!(after[1].fence, fence_b);
        assert_eq!(after[1].last_failure_code.as_deref(), Some("unavailable"));
        assert_eq!(after[1].last_success_at, None);
        assert_eq!(after[1].last_duration_ms, Some(3));

        // A row carried past the holder's fence (a later adoption whose
        // lease has since gone) is never pulled back down, even by a live
        // holder: adoption raises fences only.
        assert_eq!(
            client
                .execute(
                    "UPDATE greengateway.maintenance_jobs SET fence = fence + 1000 WHERE job = 'beta'",
                    &[],
                )
                .await
                .expect("advance"),
            1
        );
        assert!(
            !store.adopt_jobs(&jobs, fence_b).await.expect("adopt"),
            "a live holder never lowers a row's fence"
        );
        let raised = store.maintenance_jobs().await.expect("records");
        assert_eq!(
            raised[0].fence, fence_b,
            "alpha re-adopted at the holder's fence"
        );
        assert_eq!(
            raised[1].fence,
            fence_b + 1000,
            "beta kept the higher fence"
        );
        leases_b.release(&lease_b).await.expect("release");
    }

    // ------------------------------------------------------------------
    // The maintenance singleton (issue #241, PR 13, sections 4 and 5)
    // ------------------------------------------------------------------

    use crate::cluster_maintenance::{
        AuditRetention, AuditRetentionFloor, ExecutionLeaseReaper, JwtRevocationCleanup,
        MaintenanceJob, MaintenanceRunner, OnePassOutcome, PassOutcome, PendingLoginPrune,
        RateLimitIdleSweep, StaleMemberSweep, MAINTENANCE_LOCK_KEY, MAINTENANCE_SCOPE,
    };
    use crate::storage::DedicatedSession;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// A job that counts its runs and can be told to fail, so a pass is
    /// observable without touching a real table.
    struct CountingJob {
        runs: Arc<AtomicU64>,
        fail: bool,
    }

    #[async_trait::async_trait]
    impl MaintenanceJob for CountingJob {
        fn name(&self) -> &'static str {
            "counting"
        }

        async fn run_step(&self, _client: &tokio_postgres::Client) -> Result<u64, RepositoryError> {
            self.runs.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                Err(RepositoryError::new(
                    RepositoryErrorKind::Unavailable,
                    "counting_job",
                ))
            } else {
                Ok(1)
            }
        }
    }

    /// A job whose step is one long statement on the connection it is
    /// handed, so a test can see which backend runs it and cut it short.
    struct SleepingJob {
        secs: f64,
    }

    #[async_trait::async_trait]
    impl MaintenanceJob for SleepingJob {
        fn name(&self) -> &'static str {
            "sleeping"
        }

        async fn run_step(&self, client: &tokio_postgres::Client) -> Result<u64, RepositoryError> {
            client
                .execute("SELECT pg_sleep($1::double precision)", &[&self.secs])
                .await
                .map(|_| 1)
                .map_err(|_| RepositoryError::new(RepositoryErrorKind::Unavailable, "sleeping_job"))
        }
    }

    /// Run one job step over a pooled connection, as the runner would over
    /// its session.
    async fn step(job: &dyn MaintenanceJob, pool: &deadpool_postgres::Pool) -> u64 {
        let client = pool.get().await.expect("client");
        job.run_step(&client).await.expect("step")
    }

    struct FixedFloor(Option<i64>);

    #[async_trait::async_trait]
    impl AuditRetentionFloor for FixedFloor {
        async fn durably_consumed_position(&self) -> Result<Option<i64>, RepositoryError> {
            Ok(self.0)
        }
    }

    fn maintenance_leases(
        pool: &deadpool_postgres::Pool,
        holder: uuid::Uuid,
        ttl: Duration,
    ) -> Arc<dyn ExecutionLeaseStore> {
        Arc::new(PostgresExecutionLeaseStore::new(
            pool.clone(),
            MEMBERS_DEPLOYMENT,
            holder,
            ttl,
        ))
    }

    fn runner_with(
        pool: &deadpool_postgres::Pool,
        ledger: &Arc<PostgresMembershipStore>,
        jobs: Vec<Arc<dyn MaintenanceJob>>,
        interval: Duration,
        ttl: Duration,
    ) -> (Arc<MaintenanceRunner>, Arc<dyn ExecutionLeaseStore>) {
        let holder = uuid::Uuid::new_v4();
        let leases = maintenance_leases(pool, holder, ttl);
        let runner = MaintenanceRunner::new(
            pool.clone(),
            Arc::clone(&leases),
            Arc::clone(ledger),
            jobs,
            interval,
            holder,
        );
        (runner, leases)
    }

    async fn wait_until(deadline: Duration, mut condition: impl FnMut() -> bool) -> bool {
        let started = std::time::Instant::now();
        while started.elapsed() < deadline {
            if condition() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(15)).await;
        }
        condition()
    }

    async fn scalar_count(pool: &deadpool_postgres::Pool, sql: &str) -> i64 {
        let client = pool.get().await.expect("client");
        client.query_one(sql, &[]).await.expect("count").get(0)
    }

    /// Exactly one of two runtimes holds the maintenance lease and runs
    /// the jobs under its fence; when the holder dies without releasing,
    /// the other takes over only after the TTL lapses on the database
    /// clock (plus its jittered backoff), adopts the ledger at a higher
    /// fence, and runs; a drained leader releases at once so the slot is
    /// free without waiting for the TTL.
    #[tokio::test]
    async fn the_maintenance_lease_is_held_by_one_runtime_and_fails_over_with_jitter() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let pool = migrated_limits_pool(&database).await;
        let ledger = Arc::new(member_store(&pool));
        let ttl = Duration::from_millis(900);
        let interval = Duration::from_millis(200);
        let runs_a = Arc::new(AtomicU64::new(0));
        let runs_b = Arc::new(AtomicU64::new(0));
        let job = |runs: &Arc<AtomicU64>| -> Vec<Arc<dyn MaintenanceJob>> {
            vec![Arc::new(CountingJob {
                runs: Arc::clone(runs),
                fail: false,
            })]
        };
        let (runner_a, _leases_a) = runner_with(&pool, &ledger, job(&runs_a), interval, ttl);
        let (runner_b, _leases_b) = runner_with(&pool, &ledger, job(&runs_b), interval, ttl);
        let backoff_b = runner_b.acquisition_backoff();
        assert!(
            backoff_b >= interval / 8 && backoff_b <= interval * 3 / 8,
            "the backoff is jittered inside [interval/8, 3*interval/8]: {backoff_b:?}"
        );

        let cancel_a = CancellationToken::new();
        let task_a = tokio::spawn(Arc::clone(&runner_a).serve(cancel_a.clone()));
        assert!(
            wait_until(Duration::from_secs(5), || runner_a.is_leading()).await,
            "the first runtime takes the free lease"
        );
        let cancel_b = CancellationToken::new();
        let task_b = tokio::spawn(Arc::clone(&runner_b).serve(cancel_b.clone()));
        // Several backoffs' worth of attempts by B: it never gets the slot
        // while A renews, and A keeps running passes on its interval.
        tokio::time::sleep(backoff_b * 4 + interval * 2).await;
        assert!(runner_a.is_leading());
        assert!(!runner_b.is_leading(), "only one runtime leads");
        assert!(
            runner_a.passes_completed() >= 2,
            "the leader runs a pass at once and then every interval: {}",
            runner_a.passes_completed()
        );
        assert_eq!(
            runs_b.load(Ordering::SeqCst),
            0,
            "the follower runs nothing"
        );
        let records = ledger.maintenance_jobs().await.expect("ledger");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].job, "counting");
        let fence_a = records[0].fence;
        assert!(records[0].last_success_at.is_some());
        assert_eq!(records[0].last_failure_code, None);

        // A dies without releasing: its task is aborted, so it stops
        // renewing. B may not take over before the TTL lapses.
        task_a.abort();
        let _ = task_a.await;
        let runs_a_at_death = runs_a.load(Ordering::SeqCst);
        tokio::time::sleep(ttl / 3).await;
        assert!(
            !runner_b.is_leading(),
            "the slot is not free before the TTL lapses on the database clock"
        );
        assert!(
            wait_until(ttl * 3, || runner_b.is_leading()).await,
            "the survivor takes over after the TTL and its backoff"
        );
        assert!(
            wait_until(Duration::from_secs(5), || runner_b.passes_completed() >= 1).await,
            "the new leader runs a pass"
        );
        assert!(runs_b.load(Ordering::SeqCst) >= 1);
        assert_eq!(
            runs_a.load(Ordering::SeqCst),
            runs_a_at_death,
            "the dead leader ran nothing more"
        );
        let records = ledger.maintenance_jobs().await.expect("ledger");
        assert!(
            records[0].fence > fence_a,
            "the successor adopted the ledger at a higher fence: {} > {fence_a}",
            records[0].fence
        );

        // Draining B releases the lease at once: a third acquirer finds
        // the slot free without waiting for the TTL.
        cancel_b.cancel();
        let _ = task_b.await;
        assert!(!runner_b.is_leading());
        let third = maintenance_leases(&pool, uuid::Uuid::new_v4(), ttl);
        assert!(
            matches!(
                third
                    .try_acquire(MAINTENANCE_SCOPE, 1, "test")
                    .await
                    .expect("acquire"),
                LeaseAttempt::Acquired(_)
            ),
            "a drained leader's slot is free at once"
        );
        cancel_a.cancel();
    }

    /// The classic stale-leader test at the pass level: the holder runs a
    /// pass, is paused past its TTL (no renewals), a successor takes the
    /// lease and adopts the ledger at a higher fence, and the resumed
    /// holder's pass is refused by the fence before any job runs -- its
    /// late writes never land. A failing job is recorded with its
    /// classified code and does not block the next job.
    #[tokio::test]
    async fn a_stale_leaders_pass_is_refused_by_the_fence() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let pool = migrated_limits_pool(&database).await;
        let ledger = Arc::new(member_store(&pool));
        let ttl = Duration::from_millis(500);
        let interval = Duration::from_secs(60);
        let runs_a = Arc::new(AtomicU64::new(0));
        let runs_b = Arc::new(AtomicU64::new(0));
        let (runner_a, leases_a) = runner_with(
            &pool,
            &ledger,
            vec![Arc::new(CountingJob {
                runs: Arc::clone(&runs_a),
                fail: false,
            })],
            interval,
            ttl,
        );
        let (runner_b, leases_b) = runner_with(
            &pool,
            &ledger,
            vec![Arc::new(CountingJob {
                runs: Arc::clone(&runs_b),
                fail: true,
            })],
            interval,
            ttl,
        );
        let acquired = |attempt: LeaseAttempt| match attempt {
            LeaseAttempt::Acquired(lease) => lease,
            LeaseAttempt::Full => panic!("expected the maintenance slot free"),
        };

        let lease_a = acquired(
            leases_a
                .try_acquire(MAINTENANCE_SCOPE, 1, "a")
                .await
                .expect("acquire"),
        );
        assert!(ledger
            .adopt_jobs(&runner_a.job_names(), lease_a.fence)
            .await
            .expect("adopt"));
        assert_eq!(
            runner_a.run_pass(lease_a.fence).await,
            PassOutcome::Completed { failed_jobs: 0 }
        );
        assert_eq!(runs_a.load(Ordering::SeqCst), 1);
        let before = ledger.maintenance_jobs().await.expect("ledger");
        assert_eq!(before[0].fence, lease_a.fence);
        let first_success = before[0].last_success_at.clone().expect("stamped");

        // A pauses past its TTL. Nobody renews.
        tokio::time::sleep(ttl + Duration::from_millis(300)).await;
        assert!(
            !leases_a.is_current(&lease_a).await.expect("check"),
            "the paused holder's lease lapsed"
        );
        // A resumes before anyone has taken the slot: the rows still carry
        // its fence, but the lease behind it is gone, and its pass is
        // refused before any job runs.
        assert!(
            !ledger
                .record_job_started("counting", lease_a.fence)
                .await
                .expect("start"),
            "a lapsed lease refuses the write before any successor exists"
        );
        assert_eq!(
            runner_a.run_pass(lease_a.fence).await,
            PassOutcome::Stale,
            "the lapsed leader's pass is refused before any successor exists"
        );
        assert_eq!(runs_a.load(Ordering::SeqCst), 1);
        let lease_b = acquired(
            leases_b
                .try_acquire(MAINTENANCE_SCOPE, 1, "b")
                .await
                .expect("acquire"),
        );
        assert!(lease_b.fence > lease_a.fence);
        // The successor holds the slot but has not adopted the rows yet:
        // still refused, the window between the two is closed.
        assert_eq!(
            runner_a.run_pass(lease_a.fence).await,
            PassOutcome::Stale,
            "the stale leader's pass is refused while the successor has yet to adopt"
        );
        assert_eq!(runs_a.load(Ordering::SeqCst), 1);
        assert_eq!(
            runner_b.run_pass(lease_b.fence).await,
            PassOutcome::Stale,
            "the successor cannot write rows it has not adopted, live lease or not"
        );
        assert_eq!(runs_b.load(Ordering::SeqCst), 0);
        assert!(ledger
            .adopt_jobs(&runner_b.job_names(), lease_b.fence)
            .await
            .expect("adopt"));

        // A resumes and tries to run under its old fence.
        assert_eq!(
            runner_a.run_pass(lease_a.fence).await,
            PassOutcome::Stale,
            "the stale leader's pass is refused before any job runs"
        );
        assert_eq!(
            runs_a.load(Ordering::SeqCst),
            1,
            "no job ran under the stale fence"
        );
        let unchanged = ledger.maintenance_jobs().await.expect("ledger");
        assert_eq!(unchanged[0].fence, lease_b.fence);
        assert_eq!(
            unchanged[0].last_success_at.as_deref(),
            Some(first_success.as_str())
        );

        // The successor's pass lands, failure code and all.
        assert_eq!(
            runner_b.run_pass(lease_b.fence).await,
            PassOutcome::Completed { failed_jobs: 1 }
        );
        assert_eq!(runs_b.load(Ordering::SeqCst), 1);
        let after = ledger.maintenance_jobs().await.expect("ledger");
        assert_eq!(after[0].fence, lease_b.fence);
        assert_eq!(after[0].last_failure_code.as_deref(), Some("unavailable"));
        assert_eq!(
            after[0].last_success_at.as_deref(),
            Some(first_success.as_str()),
            "a failed run keeps the last success instant"
        );
        assert!(after[0].last_started_at > before[0].last_started_at);

        // And A, trying once more, is still refused.
        assert_eq!(runner_a.run_pass(lease_a.fence).await, PassOutcome::Stale);
        assert_eq!(runs_a.load(Ordering::SeqCst), 1);
    }

    /// `gateway maintenance-run`'s one-shot: with the slot free it takes
    /// the lease, runs one pass under its fence, and releases (the slot is
    /// free again at once, not after the TTL); while a leader holds the
    /// slot it runs nothing and says so; a later one-shot's fence is
    /// higher than the leader's, so the leader's ledger writes are then
    /// refused.
    #[tokio::test]
    async fn a_one_shot_pass_takes_the_lease_and_never_runs_beside_a_leader() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let pool = migrated_limits_pool(&database).await;
        let ledger = Arc::new(member_store(&pool));
        let ttl = Duration::from_millis(900);
        let interval = Duration::from_secs(60);
        let runs = Arc::new(AtomicU64::new(0));
        let (one_shot, one_shot_leases) = runner_with(
            &pool,
            &ledger,
            vec![Arc::new(CountingJob {
                runs: Arc::clone(&runs),
                fail: false,
            })],
            interval,
            ttl,
        );

        // Slot free: the pass runs under the one-shot's fence.
        let first = one_shot.run_once().await.expect("one-shot");
        let OnePassOutcome::Ran {
            fence: first_fence,
            outcome,
        } = first
        else {
            panic!("expected the pass to run, got {first:?}");
        };
        assert_eq!(outcome, PassOutcome::Completed { failed_jobs: 0 });
        assert_eq!(runs.load(Ordering::SeqCst), 1);
        let ledger_rows = ledger.maintenance_jobs().await.expect("ledger");
        assert_eq!(ledger_rows[0].fence, first_fence);
        assert!(ledger_rows[0].last_success_at.is_some());

        // Released at once: a leader can take the slot without waiting
        // for the TTL, at a higher fence.
        let leader_runs = Arc::new(AtomicU64::new(0));
        let (leader, leader_leases) = runner_with(
            &pool,
            &ledger,
            vec![Arc::new(CountingJob {
                runs: Arc::clone(&leader_runs),
                fail: false,
            })],
            interval,
            ttl,
        );
        let leader_lease = match leader_leases
            .try_acquire(MAINTENANCE_SCOPE, 1, "leader")
            .await
            .expect("acquire")
        {
            LeaseAttempt::Acquired(lease) => lease,
            LeaseAttempt::Full => panic!("the one-shot did not release its lease"),
        };
        assert!(leader_lease.fence > first_fence);
        assert!(ledger
            .adopt_jobs(&leader.job_names(), leader_lease.fence)
            .await
            .expect("adopt"));

        // A live leader: the one-shot runs nothing.
        assert_eq!(
            one_shot.run_once().await.expect("one-shot"),
            OnePassOutcome::LeaseHeld
        );
        assert_eq!(
            runs.load(Ordering::SeqCst),
            1,
            "nothing ran beside the leader"
        );
        assert!(
            leader_leases
                .is_current(&leader_lease)
                .await
                .expect("check"),
            "the refused one-shot left the leader's lease alone"
        );

        // The leader releases; the next one-shot fences it out of the
        // ledger, so a late write under the leader's fence is refused.
        leader_leases.release(&leader_lease).await.expect("release");
        let OnePassOutcome::Ran {
            fence: second_fence,
            outcome,
        } = one_shot.run_once().await.expect("one-shot")
        else {
            panic!("expected the pass to run after the leader released");
        };
        assert!(second_fence > leader_lease.fence);
        assert_eq!(outcome, PassOutcome::Completed { failed_jobs: 0 });
        assert_eq!(runs.load(Ordering::SeqCst), 2);
        assert_eq!(
            leader.run_pass(leader_lease.fence).await,
            PassOutcome::Stale
        );
        assert_eq!(leader_runs.load(Ordering::SeqCst), 0);
        assert!(
            !one_shot_leases
                .try_acquire(MAINTENANCE_SCOPE, 1, "probe")
                .await
                .map(|attempt| matches!(attempt, LeaseAttempt::Full))
                .expect("acquire"),
            "the one-shot released its lease on the way out"
        );
    }

    /// The dedicated session's advisory lock: a held key refuses a second
    /// session (and a pass finds nothing to do), release frees it, and a
    /// session dropped without release frees it too because the connection
    /// is closed rather than recycled.
    #[tokio::test]
    async fn a_dedicated_session_refuses_a_held_key_and_never_leaks_the_lock() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let pool = migrated_limits_pool(&database).await;
        let ledger = Arc::new(member_store(&pool));
        let runs = Arc::new(AtomicU64::new(0));
        let (runner, leases) = runner_with(
            &pool,
            &ledger,
            vec![Arc::new(CountingJob {
                runs: Arc::clone(&runs),
                fail: false,
            })],
            Duration::from_secs(60),
            Duration::from_secs(5),
        );
        let lease = match leases
            .try_acquire(MAINTENANCE_SCOPE, 1, "x")
            .await
            .expect("acquire")
        {
            LeaseAttempt::Acquired(lease) => lease,
            LeaseAttempt::Full => panic!("free slot"),
        };
        assert!(ledger
            .adopt_jobs(&runner.job_names(), lease.fence)
            .await
            .expect("adopt"));

        let mut held = DedicatedSession::acquire(&pool, *MAINTENANCE_LOCK_KEY)
            .await
            .expect("first session takes the key");
        held.probe().await.expect("the connection is alive");
        let refused = match DedicatedSession::acquire(&pool, *MAINTENANCE_LOCK_KEY).await {
            Ok(_) => panic!("a held key must be refused"),
            Err(error) => error,
        };
        assert_eq!(refused.kind(), RepositoryErrorKind::Conflict);
        assert_eq!(
            runner.run_pass(lease.fence).await,
            PassOutcome::Skipped,
            "a pass that cannot take the key runs nothing"
        );
        assert_eq!(runs.load(Ordering::SeqCst), 0);
        held.release().await.expect("release");

        let dropped = DedicatedSession::acquire(&pool, *MAINTENANCE_LOCK_KEY)
            .await
            .expect("the released key is free");
        drop(dropped);
        let started = std::time::Instant::now();
        loop {
            let held = scalar_count(
                &pool,
                "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND granted",
            )
            .await;
            if held == 0 {
                break;
            }
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "a dropped session closes its connection and the server releases the lock; {held} still held"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert_eq!(
            runner.run_pass(lease.fence).await,
            PassOutcome::Completed { failed_jobs: 0 },
            "the key is free again for a pass"
        );
        assert_eq!(runs.load(Ordering::SeqCst), 1);
        leases.release(&lease).await.expect("release");
    }

    /// The belt covers the statement: a job step runs on the connection
    /// holding the maintenance advisory lock, so the key stays held while
    /// the step runs (a second session is refused), and terminating that
    /// backend fails the step at once -- the pass ends `ConnectionLost`
    /// well inside the step's own duration, the next job never runs, no
    /// outcome is recorded for the cut step, and the key is free again
    /// only once the backend is gone.
    #[tokio::test]
    async fn a_lost_session_fails_the_step_in_flight_and_the_lock_covers_it() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let pool = migrated_limits_pool(&database).await;
        let ledger = Arc::new(member_store(&pool));
        let runs = Arc::new(AtomicU64::new(0));
        let sleep = Duration::from_secs(4);
        let (runner, leases) = runner_with(
            &pool,
            &ledger,
            vec![
                Arc::new(SleepingJob {
                    secs: sleep.as_secs_f64(),
                }),
                Arc::new(CountingJob {
                    runs: Arc::clone(&runs),
                    fail: false,
                }),
            ],
            Duration::from_secs(60),
            Duration::from_secs(30),
        );
        let lease = match leases
            .try_acquire(MAINTENANCE_SCOPE, 1, "x")
            .await
            .expect("acquire")
        {
            LeaseAttempt::Acquired(lease) => lease,
            LeaseAttempt::Full => panic!("free slot"),
        };
        assert!(ledger
            .adopt_jobs(&runner.job_names(), lease.fence)
            .await
            .expect("adopt"));

        let pass = tokio::spawn({
            let runner = Arc::clone(&runner);
            async move {
                let started = std::time::Instant::now();
                (runner.run_pass(lease.fence).await, started.elapsed())
            }
        });

        // The sleeping statement is in flight on the backend that holds
        // the advisory lock.
        let client = pool.get().await.expect("client");
        let mut holder: Option<i32> = None;
        let started = std::time::Instant::now();
        while holder.is_none() && started.elapsed() < Duration::from_secs(5) {
            holder = client
                .query_opt(
                    "SELECT l.pid FROM pg_locks l
                     JOIN pg_stat_activity a ON a.pid = l.pid
                     WHERE l.locktype = 'advisory' AND l.granted
                       AND a.datname = current_database()
                       AND a.query LIKE '%pg_sleep%'",
                    &[],
                )
                .await
                .expect("locks")
                .map(|row| row.get::<_, i32>(0));
            if holder.is_none() {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }
        let holder = holder.expect("the job step runs on the connection holding the advisory lock");
        let refused = match DedicatedSession::acquire(&pool, *MAINTENANCE_LOCK_KEY).await {
            Ok(_) => panic!("the key is held while the step runs"),
            Err(error) => error,
        };
        assert_eq!(refused.kind(), RepositoryErrorKind::Conflict);

        // The session's backend dies under the step.
        let terminated: bool = client
            .query_one("SELECT pg_terminate_backend($1)", &[&holder])
            .await
            .expect("terminate")
            .get(0);
        assert!(terminated);
        let (outcome, elapsed) = pass.await.expect("pass task");
        assert_eq!(outcome, PassOutcome::ConnectionLost);
        assert!(
            elapsed < sleep,
            "the step failed with its connection rather than sleeping out: {elapsed:?}"
        );
        assert_eq!(
            runs.load(Ordering::SeqCst),
            0,
            "the job after the lost session never ran"
        );
        let records = ledger.maintenance_jobs().await.expect("ledger");
        let sleeping = records
            .iter()
            .find(|record| record.job == "sleeping")
            .expect("sleeping row");
        assert!(sleeping.last_started_at.is_some());
        assert_eq!(
            sleeping.last_duration_ms, None,
            "a step cut by its lost session records no outcome"
        );
        assert_eq!(sleeping.last_failure_code, None);
        let counting = records
            .iter()
            .find(|record| record.job == "counting")
            .expect("counting row");
        assert!(counting.last_started_at.is_none());

        // The key is free again once the backend is gone.
        let started = std::time::Instant::now();
        loop {
            match DedicatedSession::acquire(&pool, *MAINTENANCE_LOCK_KEY).await {
                Ok(session) => {
                    session.release().await.expect("release");
                    break;
                }
                Err(error) => {
                    assert_eq!(error.kind(), RepositoryErrorKind::Conflict);
                    assert!(
                        started.elapsed() < Duration::from_secs(5),
                        "the terminated backend releases the key"
                    );
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            }
        }
        leases.release(&lease).await.expect("release");
    }

    /// Every job's step respects its limit: three candidates, a limit of
    /// two, two removed, then one, then nothing; and no live row is ever
    /// touched.
    #[tokio::test]
    async fn each_maintenance_job_is_bounded_per_step() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let pool = migrated_limits_pool(&database).await;
        let client = pool.get().await.expect("client");

        // JWT revocations: three expired, one live.
        let jwt = PostgresJwtRevocationStore::new(
            pool.clone(),
            MEMBERS_DEPLOYMENT,
            "https://issuer.example",
        )
        .with_retention_leeway_for_test(0.0);
        let far = (time::OffsetDateTime::now_utc() + std::time::Duration::from_secs(3600))
            .format(&time::format_description::well_known::Rfc3339)
            .expect("rfc3339");
        for jti in ["jti-1", "jti-2", "jti-3"] {
            jwt.revoke(jti, Some(&far), "operator")
                .await
                .expect("revoke");
        }
        client
            .execute(
                "UPDATE greengateway.jwt_revocations SET expires_at = now() - interval '1 hour'",
                &[],
            )
            .await
            .expect("backdate");
        jwt.revoke("jti-live", Some(&far), "operator")
            .await
            .expect("revoke");
        let job = JwtRevocationCleanup {
            store: jwt,
            limit: 2,
        };
        assert_eq!(step(&job, &pool).await, 2);
        assert_eq!(step(&job, &pool).await, 1);
        assert_eq!(step(&job, &pool).await, 0);
        assert!(job.store.is_revoked("jti-live").await.expect("lookup"));

        // Rate-limit buckets: three idle, one fresh.
        let limits =
            PostgresRateLimitStore::new(pool.clone(), MEMBERS_DEPLOYMENT, limits_keyring(), 100);
        let limit = SharedLimit {
            requests_per_second: 10.0,
            burst: 10,
        };
        for key in ["idle-1", "idle-2", "idle-3"] {
            limits
                .decide(SharedLane::Read, key, limit)
                .await
                .expect("decide");
        }
        client
            .execute(
                "UPDATE greengateway.rate_limit_buckets SET updated_at = now() - interval '1 hour'",
                &[],
            )
            .await
            .expect("backdate");
        limits
            .decide(SharedLane::Read, "fresh", limit)
            .await
            .expect("decide");
        assert_eq!(limits.live_buckets().await.expect("live"), 4);
        let job = RateLimitIdleSweep {
            store: limits,
            idle: Duration::from_secs(60),
            limit: 2,
        };
        assert_eq!(step(&job, &pool).await, 2);
        assert_eq!(step(&job, &pool).await, 1);
        assert_eq!(step(&job, &pool).await, 0);
        assert_eq!(job.store.live_buckets().await.expect("live"), 1);

        // Pending logins: three expired, one live.
        for (index, offset) in [("1", "-1"), ("2", "-1"), ("3", "-1"), ("4", "+1")] {
            client
                .execute(
                    &format!(
                        "INSERT INTO greengateway.admin_pending_logins \
                         (id, state_hash, client_key, key_id, verifier_nonce, verifier_ct, \
                          nonce_nonce, nonce_ct, expires_at) \
                         VALUES ($1::text::uuid, $2, $3, 'k', $4, $5, $4, $5, \
                                 now() + interval '{offset} hour')"
                    ),
                    &[
                        &uuid::Uuid::new_v4().to_string(),
                        &format!("{:0>64}", index),
                        &"a".repeat(64),
                        &vec![0u8; 24],
                        &vec![0u8; 32],
                    ],
                )
                .await
                .expect("insert pending login");
        }
        let job = PendingLoginPrune { limit: 2 };
        assert_eq!(step(&job, &pool).await, 2);
        assert_eq!(step(&job, &pool).await, 1);
        assert_eq!(step(&job, &pool).await, 0);
        assert_eq!(
            scalar_count(
                &pool,
                "SELECT count(*) FROM greengateway.admin_pending_logins"
            )
            .await,
            1
        );

        // Members: three stale, one live.
        let live = member_store(&pool);
        let stale = [
            member_store(&pool),
            member_store(&pool),
            member_store(&pool),
        ];
        for store in stale.iter().chain(std::iter::once(&live)) {
            store
                .heartbeat(&registration('a'), MemberRevisions::default(), None)
                .await
                .expect("heartbeat");
        }
        for store in &stale {
            backdate_heartbeat(&pool, store.instance_id(), 3_600.0).await;
        }
        let job = StaleMemberSweep {
            store: Arc::new(live.clone()),
            stale_window: Duration::from_secs(30),
            limit: 2,
        };
        assert_eq!(step(&job, &pool).await, 2);
        assert_eq!(step(&job, &pool).await, 1);
        assert_eq!(step(&job, &pool).await, 0);
        let remaining = live
            .members(Duration::from_secs(30))
            .await
            .expect("members");
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].instance_id, live.instance_id());

        // Audit events: three old, one fresh.
        let audit = Arc::new(PostgresAuditEventStore::new(pool.clone(), None));
        audit
            .insert_events(&[
                contract_event("old-1", "audit.retention", json!({})),
                contract_event("old-2", "audit.retention", json!({})),
                contract_event("old-3", "audit.retention", json!({})),
            ])
            .await
            .expect("insert");
        client
            .execute(
                "UPDATE greengateway.audit_events SET occurred_at = now() - interval '2 days'",
                &[],
            )
            .await
            .expect("backdate");
        audit
            .insert_events(&[contract_event("fresh", "audit.retention", json!({}))])
            .await
            .expect("insert");
        let job = AuditRetention {
            store: Arc::clone(&audit),
            retention: Duration::from_secs(86_400),
            floor: None,
            limit: 2,
        };
        assert_eq!(step(&job, &pool).await, 2);
        assert_eq!(step(&job, &pool).await, 1);
        assert_eq!(step(&job, &pool).await, 0);
        assert_eq!(
            scalar_count(&pool, "SELECT count(*) FROM greengateway.audit_events").await,
            1
        );
        assert_eq!(audit.stream_first_available().await.expect("first"), 4);

        // Leases: three lapsed, one live -- the reaper test below covers
        // the live-row guarantee in depth; here only the bound.
        let short = PostgresExecutionLeaseStore::new(
            pool.clone(),
            MEMBERS_DEPLOYMENT,
            uuid::Uuid::new_v4(),
            Duration::from_millis(200),
        );
        for index in 0..3 {
            assert!(matches!(
                short
                    .try_acquire("tool:gone", 3, &format!("req-{index}"))
                    .await
                    .expect("acquire"),
                LeaseAttempt::Acquired(_)
            ));
        }
        tokio::time::sleep(Duration::from_millis(400)).await;
        let job = ExecutionLeaseReaper {
            store: short,
            grace: Duration::ZERO,
            limit: 2,
        };
        assert_eq!(step(&job, &pool).await, 2);
        assert_eq!(step(&job, &pool).await, 1);
        assert_eq!(step(&job, &pool).await, 0);
    }

    /// The work of one retention step is bounded by the step, not by the
    /// backlog: over twenty thousand old streamed events, every scan in
    /// either statement's plan touches at most the step's window of rows
    /// (no scan or sort of the whole table), and the step still deletes
    /// its limit, lowest positions first, never at or past the floor.
    #[tokio::test]
    async fn audit_retention_work_is_bounded_by_the_step_not_the_backlog() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let pool = migrated_limits_pool(&database).await;
        let client = pool.get().await.expect("client");
        let backlog: i64 = 20_000;
        client
            .execute(
                "INSERT INTO greengateway.audit_events
                     (event_id, event_type, occurred_at, schema_version, request_id, source_ip, payload_json)
                 SELECT 'ev-' || g, 'audit.retention',
                        now() - interval '100 days' + (g * interval '1 second'),
                        '1', 'req', '203.0.113.10', '{}'::jsonb
                 FROM generate_series(1, $1::bigint) AS g",
                &[&backlog],
            )
            .await
            .expect("events");
        client
            .batch_execute(
                "INSERT INTO greengateway.audit_stream (position, event_id)
                 SELECT id, event_id FROM greengateway.audit_events;
                 ANALYZE greengateway.audit_events;
                 ANALYZE greengateway.audit_stream",
            )
            .await
            .expect("stream");
        let retention_secs = Duration::from_secs(30 * 86_400).as_secs_f64();
        let limit = 100_u32;
        let window = i64::from(limit) * crate::storage::postgres_audit::RETENTION_SCAN_FACTOR;
        let floor: Option<i64> = None;

        // Rows examined by any scan node of an EXPLAIN ANALYZE plan
        // (actual rows times loops, plus rows a filter removed).
        fn rows_examined(plan: &[String]) -> (i64, String) {
            let number = |line: &str, key: &str| -> i64 {
                line.find(key)
                    .map(|at| {
                        line[at + key.len()..]
                            .chars()
                            .take_while(char::is_ascii_digit)
                            .collect::<String>()
                    })
                    .and_then(|digits| digits.parse().ok())
                    .unwrap_or(0)
            };
            let mut worst = 0_i64;
            let mut current = 0_i64;
            let mut loops = 1_i64;
            for line in plan {
                if line.contains("Scan") && line.contains("(actual") {
                    let actual = &line[line.find("(actual").unwrap_or(0)..];
                    loops = number(actual, "loops=").max(1);
                    current = number(actual, "rows=") * loops;
                    worst = worst.max(current);
                } else if line.contains("Rows Removed by") {
                    current += number(line, ": ") * loops;
                    worst = worst.max(current);
                }
            }
            (worst, plan.join("\n"))
        }
        let explain =
            |sql: &'static str, params: Vec<Box<dyn tokio_postgres::types::ToSql + Sync>>| {
                let client = &client;
                async move {
                    client.batch_execute("BEGIN").await.expect("begin");
                    let refs: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> =
                        params.iter().map(|param| param.as_ref()).collect();
                    let rows = client
                        .query(&format!("EXPLAIN (ANALYZE, FORMAT TEXT) {sql}"), &refs)
                        .await
                        .expect("explain");
                    client.batch_execute("ROLLBACK").await.expect("rollback");
                    rows.iter()
                        .map(|row| row.get::<_, String>(0))
                        .collect::<Vec<_>>()
                }
            };
        let streamed = explain(
            crate::storage::postgres_audit::PRUNE_STREAMED_SQL,
            vec![
                Box::new(retention_secs),
                Box::new(floor),
                Box::new(i64::from(limit)),
                Box::new(window),
            ],
        )
        .await;
        // An index walk under a LIMIT reads one row past the window to
        // learn it is done (and an incremental sort a few more), so the
        // bound is a small multiple of the window -- against a backlog
        // twenty times larger.
        let bound = 2 * window;
        let (examined, plan) = rows_examined(&streamed);
        assert!(
            examined <= bound,
            "the streamed step examined {examined} rows over a backlog of {backlog} (window {window}):\n{plan}"
        );
        let unstreamed = explain(
            crate::storage::postgres_audit::PRUNE_UNSTREAMED_SQL,
            vec![
                Box::new(retention_secs),
                Box::new(i64::from(limit)),
                Box::new(window),
            ],
        )
        .await;
        let (examined, plan) = rows_examined(&unstreamed);
        assert!(
            examined <= bound,
            "the unstreamed step examined {examined} rows over a backlog of {backlog} (window {window}):\n{plan}"
        );

        // And the step itself: its limit, lowest positions first, floor
        // respected, the counter untouched.
        let audit = PostgresAuditEventStore::new(pool.clone(), None);
        let retention = Duration::from_secs(30 * 86_400);
        assert_eq!(
            audit
                .prune_older_than(retention, None, limit)
                .await
                .expect("prune"),
            u64::from(limit)
        );
        assert_eq!(audit.stream_first_available().await.expect("first"), 101);
        assert_eq!(
            audit
                .prune_older_than(retention, Some(150), limit)
                .await
                .expect("prune"),
            49,
            "only positions below the floor go"
        );
        assert_eq!(
            audit
                .prune_older_than(retention, Some(150), limit)
                .await
                .expect("prune"),
            0
        );
        assert_eq!(audit.stream_first_available().await.expect("first"), 150);
        assert_eq!(
            scalar_count(&pool, "SELECT count(*) FROM greengateway.audit_events").await,
            backlog - 149
        );
    }

    /// Retention deletes only what is both old enough and at or below the
    /// floor the consumer reports: a consumer that has applied position 2
    /// frees positions 1 and 2, one that has applied nothing frees
    /// nothing, and with no consumer age alone decides. The position
    /// counter survives, so the first available position moves forward
    /// and never restarts.
    #[tokio::test]
    async fn audit_retention_never_passes_the_retention_floor() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let pool = migrated_limits_pool(&database).await;
        let audit = Arc::new(PostgresAuditEventStore::new(pool.clone(), None));
        let events: Vec<AuditEvent> = (1..=5)
            .map(|index| contract_event(&format!("event-{index}"), "audit.retention", json!({})))
            .collect();
        // Sequential inserts so positions follow the names.
        for event in &events {
            audit
                .insert_events(std::slice::from_ref(event))
                .await
                .expect("insert");
        }
        let client = pool.get().await.expect("client");
        client
            .execute(
                "UPDATE greengateway.audit_events SET occurred_at = now() - interval '10 days'",
                &[],
            )
            .await
            .expect("backdate");
        let retention = Duration::from_secs(86_400);
        let remaining = |after: i64| {
            let audit = Arc::clone(&audit);
            async move {
                audit
                    .stream_after(after, 100)
                    .await
                    .expect("stream")
                    .into_iter()
                    .map(|(position, event)| (position, event.event_id))
                    .collect::<Vec<_>>()
            }
        };

        let nothing_consumed = AuditRetention {
            store: Arc::clone(&audit),
            retention,
            floor: Some(Arc::new(FixedFloor(None))),
            limit: 100,
        };
        assert_eq!(
            step(&nothing_consumed, &pool).await,
            0,
            "a consumer that has applied nothing keeps every streamed event"
        );
        assert_eq!(remaining(0).await.len(), 5);

        let consumed_two = AuditRetention {
            store: Arc::clone(&audit),
            retention,
            floor: Some(Arc::new(FixedFloor(Some(2)))),
            limit: 100,
        };
        assert_eq!(step(&consumed_two, &pool).await, 2);
        assert_eq!(
            remaining(0).await,
            vec![
                (3, "event-3".to_owned()),
                (4, "event-4".to_owned()),
                (5, "event-5".to_owned())
            ],
            "only positions at or below the consumed position went"
        );
        assert_eq!(audit.stream_first_available().await.expect("first"), 3);
        assert_eq!(
            step(&consumed_two, &pool).await,
            0,
            "the floor holds however old the rest is"
        );

        // Age bounds too: a floor above everything frees nothing fresh.
        audit
            .insert_events(&[contract_event("event-6", "audit.retention", json!({}))])
            .await
            .expect("insert");
        let far_ahead = AuditRetention {
            store: Arc::clone(&audit),
            retention,
            floor: Some(Arc::new(FixedFloor(Some(100)))),
            limit: 100,
        };
        assert_eq!(
            step(&far_ahead, &pool).await,
            3,
            "old events below the floor go; the fresh one stays"
        );
        assert_eq!(remaining(0).await, vec![(6, "event-6".to_owned())]);

        // No consumer at all: age alone decides, and the counter survives.
        client
            .execute(
                "UPDATE greengateway.audit_events SET occurred_at = now() - interval '10 days'",
                &[],
            )
            .await
            .expect("backdate");
        let unfloored = AuditRetention {
            store: Arc::clone(&audit),
            retention,
            floor: None,
            limit: 100,
        };
        assert_eq!(step(&unfloored, &pool).await, 1);
        assert!(remaining(0).await.is_empty());
        assert_eq!(
            audit.stream_first_available().await.expect("first"),
            7,
            "numbering never restarts after retention empties the stream"
        );
        audit
            .insert_events(&[contract_event("event-7", "audit.retention", json!({}))])
            .await
            .expect("insert");
        assert_eq!(remaining(0).await, vec![(7, "event-7".to_owned())]);
    }

    /// The reaper deletes only rows expired for longer than its grace: a
    /// live lease is never touched (its holder can still renew and its
    /// fence stands), a lapsed one inside the grace is left for
    /// acquisition to take over, and only a lapsed one past the grace goes.
    #[tokio::test]
    async fn the_lease_reaper_never_touches_a_live_lease() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let pool = migrated_limits_pool(&database).await;
        let long_lived = PostgresExecutionLeaseStore::new(
            pool.clone(),
            MEMBERS_DEPLOYMENT,
            uuid::Uuid::new_v4(),
            Duration::from_secs(30),
        );
        let short_lived = PostgresExecutionLeaseStore::new(
            pool.clone(),
            MEMBERS_DEPLOYMENT,
            uuid::Uuid::new_v4(),
            Duration::from_millis(300),
        );
        let acquired = |attempt: LeaseAttempt| match attempt {
            LeaseAttempt::Acquired(lease) => lease,
            LeaseAttempt::Full => panic!("expected a free slot"),
        };
        let live = acquired(
            long_lived
                .try_acquire("global", 1, "live")
                .await
                .expect("acquire"),
        );
        let maintenance = acquired(
            long_lived
                .try_acquire(MAINTENANCE_SCOPE, 1, "leader")
                .await
                .expect("acquire"),
        );
        let lapsed = acquired(
            short_lived
                .try_acquire("tool:gone", 1, "lapsed")
                .await
                .expect("acquire"),
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
        let rows = || scalar_count(&pool, "SELECT count(*) FROM greengateway.execution_leases");
        assert_eq!(rows().await, 3);

        let patient = ExecutionLeaseReaper {
            store: long_lived.clone(),
            grace: Duration::from_secs(30),
            limit: 10,
        };
        assert_eq!(
            step(&patient, &pool).await,
            0,
            "a lapse inside the grace is acquisition's to reclaim, not the reaper's"
        );
        let eager = ExecutionLeaseReaper {
            store: long_lived.clone(),
            grace: Duration::ZERO,
            limit: 10,
        };
        assert_eq!(step(&eager, &pool).await, 1);
        assert_eq!(rows().await, 2);
        assert!(
            long_lived.is_current(&live).await.expect("check"),
            "the live lease stands"
        );
        assert!(
            long_lived.is_current(&maintenance).await.expect("check"),
            "the leader's own lease stands"
        );
        assert!(long_lived.renew(&live).await.expect("renew"));
        assert!(
            !short_lived.is_current(&lapsed).await.expect("check"),
            "the lapsed lease is gone"
        );
        assert!(matches!(
            short_lived
                .try_acquire("tool:gone", 1, "again")
                .await
                .expect("acquire"),
            LeaseAttempt::Acquired(_)
        ));
        assert_eq!(step(&eager, &pool).await, 0);
    }

    // ------------------------------------------------------------------
    // Conditional lifecycle transitions (issue #241, PR 12): two replicas
    // are two stores over two pools, racing for real (`tokio::join!`), and
    // exactly one wins; the loser is handed the winner's row.
    // ------------------------------------------------------------------

    use crate::discovery::{
        lifecycle::{TransitionOutcome, UNREVIEWED_REVISION},
        suggestions::{RuleSuggestionError, RuleSuggestionLifecycleState},
    };
    use crate::storage::postgres_discovery_lifecycle::PostgresDiscoveryLifecycleStore;

    async fn seed_open_signal(pool: &deadpool_postgres::Pool, id: &str, endpoint_template: &str) {
        let client = pool.get().await.expect("client");
        client
            .execute(
                "INSERT INTO greengateway.discovery_signals
                     (id, signal_type, target_kind, target_key, target_identity_json,
                      explanation, evidence_json, state, created_at, updated_at)
                 VALUES ($1, 'new_endpoint_seen', 'endpoint', $2, $3, 'seeded', '{}', 'open',
                         '2024-06-01T00:00:00Z', '2024-06-01T00:00:00Z')",
                &[
                    &id,
                    &signals::endpoint_target_key("GET", endpoint_template),
                    &json!({"method": "GET", "endpoint_template": endpoint_template}).to_string(),
                ],
            )
            .await
            .expect("the open signal seeds");
    }

    async fn seed_open_suggestion(pool: &deadpool_postgres::Pool, id: &str, identity_bound: bool) {
        use crate::rbac::{PrincipalMatcher, Rule, RuleAction, RuleDispatchMatcher};
        let rule = Rule {
            id: None,
            enabled: true,
            methods: vec!["GET".to_owned()],
            path: format!("/raced/{id}"),
            tool_name: None,
            dispatch: Some(RuleDispatchMatcher::contextless()),
            principal: PrincipalMatcher {
                roles: vec!["reader".to_owned()],
                issuers: if identity_bound {
                    vec!["provider:test".to_owned()]
                } else {
                    Vec::new()
                },
                auth_methods: vec!["bearer_token".to_owned()],
                principal_ids: Vec::new(),
            },
            action: RuleAction::Allow,
        };
        let client = pool.get().await.expect("client");
        client
            .execute(
                "INSERT INTO greengateway.discovery_rule_suggestions
                     (id, suggestion_type, method, path_pattern, principal_key,
                      proposed_rule_json, rationale, evidence_json, state, created_at,
                      updated_at)
                 VALUES ($1, 'baseline_allow', 'GET', $2, $3, $4, 'seeded', '{}', 'open',
                         '2024-06-01T00:00:00Z', '2024-06-01T00:00:00Z')",
                &[
                    &id,
                    &rule.path,
                    &format!("seed:{id}"),
                    &serde_json::to_string(&rule).expect("the rule serializes"),
                ],
            )
            .await
            .expect("the open suggestion seeds");
    }

    async fn seed_aggregate(pool: &deadpool_postgres::Pool, method: &str, endpoint_template: &str) {
        let client = pool.get().await.expect("client");
        client
            .execute(
                "INSERT INTO greengateway.discovery_endpoint_aggregates
                     (method, endpoint_template, first_seen, last_seen, call_count,
                      latency_count, latency_p50_ms, latency_p95_ms, latency_p99_ms,
                      latency_samples_json, distinct_principal_count, updated_at)
                 VALUES ($1, $2, '2024-06-01T12:00:00Z', '2024-06-01T12:00:00Z', 1, 1, 1, 1, 1,
                         '[]', 0, '2024-06-01T12:00:00Z')",
                &[&method, &endpoint_template],
            )
            .await
            .expect("the aggregate seeds");
    }

    /// Exactly one of two racing outcomes applied; returns
    /// `(winner, loser's view of the current row)`.
    fn exactly_one_winner<T: Clone + std::fmt::Debug>(
        left: TransitionOutcome<T>,
        right: TransitionOutcome<T>,
    ) -> (T, T) {
        match (left, right) {
            (TransitionOutcome::Applied(winner), TransitionOutcome::Refused(refused))
            | (TransitionOutcome::Refused(refused), TransitionOutcome::Applied(winner)) => {
                (winner, refused.current)
            }
            (left, right) => panic!("exactly one replica must win, got {left:?} and {right:?}"),
        }
    }

    #[tokio::test]
    async fn two_replicas_transitioning_one_signal_get_exactly_one_winner() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let pool_a = migrated_discovery_pool(&database).await;
        let pool_b = migrated_discovery_pool(&database).await;
        let replica_a = PostgresDiscoveryReadStore::new(pool_a.clone());
        let replica_b = PostgresDiscoveryReadStore::new(pool_b.clone());
        let from_open = TransitionPrecondition::from_state(SignalLifecycleState::Open);

        for (id, target) in [
            ("sig-ack", SignalLifecycleState::Acknowledged),
            ("sig-dismiss", SignalLifecycleState::Dismissed),
        ] {
            seed_open_signal(&pool_a, id, &format!("/{id}")).await;
            let (left, right) = tokio::join!(
                replica_a.transition_signal(id, target, Some("admin-a"), from_open),
                replica_b.transition_signal(id, target, Some("admin-b"), from_open),
            );
            let (winner, seen_by_loser) =
                exactly_one_winner(left.expect("replica a"), right.expect("replica b"));
            assert_eq!(winner.state, target);
            assert_eq!(winner.revision, 2);
            assert_eq!(seen_by_loser.state, target);
            assert_eq!(seen_by_loser.revision, 2);
            assert_eq!(
                seen_by_loser.transitioned_by, winner.transitioned_by,
                "the refusal carries the winner's row; nothing was overwritten"
            );
            let stored = replica_b
                .list_signals(&SignalListFilters {
                    state: Some(target),
                    target_key: Some(signals::endpoint_target_key("GET", &format!("/{id}"))),
                    ..signal_filters(10)
                })
                .await
                .expect("signals list")
                .signals;
            assert_eq!(stored.len(), 1);
            assert_eq!(stored[0].transitioned_by, winner.transitioned_by);
            assert_eq!(stored[0].revision, 2);

            // The revision predicate alone: stale refused, exact applied.
            let stale = replica_b
                .transition_signal(
                    id,
                    SignalLifecycleState::Dismissed,
                    Some("admin-b"),
                    TransitionPrecondition::from_state(target).with_revision(Some(1)),
                )
                .await
                .expect("stale transition")
                .expect_refused("a stale revision is refused");
            assert_eq!(stale.revision, 2);
            let moved = replica_b
                .transition_signal(
                    id,
                    SignalLifecycleState::Dismissed,
                    Some("admin-b"),
                    TransitionPrecondition::from_state(target).with_revision(Some(2)),
                )
                .await
                .expect("exact transition")
                .expect_applied("the exact revision applies");
            assert_eq!(moved.revision, 3);
            assert_eq!(moved.transitioned_by.as_deref(), Some("admin-b"));
        }
        assert!(replica_a
            .transition_signal(
                "sig-missing",
                SignalLifecycleState::Dismissed,
                None,
                from_open
            )
            .await
            .expect("unknown transition")
            .is_not_found());
    }

    #[tokio::test]
    async fn two_replicas_dismissing_one_suggestion_get_exactly_one_winner() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let pool_a = migrated_discovery_pool(&database).await;
        let pool_b = migrated_discovery_pool(&database).await;
        let replica_a = PostgresDiscoveryLifecycleStore::new(pool_a.clone());
        let replica_b = PostgresDiscoveryLifecycleStore::new(pool_b.clone());
        let from_open = TransitionPrecondition::from_state(RuleSuggestionLifecycleState::Open);

        seed_open_suggestion(&pool_a, "raced", true).await;
        let seeded = replica_b
            .get_suggestion("raced")
            .await
            .expect("seeded suggestion loads")
            .expect("seeded suggestion exists");
        assert_eq!(seeded.state, RuleSuggestionLifecycleState::Open);
        assert_eq!(seeded.revision, 1);

        let (left, right) = tokio::join!(
            replica_a.transition_suggestion(
                "raced",
                RuleSuggestionLifecycleState::Dismissed,
                Some("admin-a"),
                from_open,
            ),
            replica_b.transition_suggestion(
                "raced",
                RuleSuggestionLifecycleState::Dismissed,
                Some("admin-b"),
                from_open,
            ),
        );
        let (winner, seen_by_loser) =
            exactly_one_winner(left.expect("replica a"), right.expect("replica b"));
        assert_eq!(winner.state, RuleSuggestionLifecycleState::Dismissed);
        assert_eq!(winner.revision, 2);
        assert_eq!(seen_by_loser.state, RuleSuggestionLifecycleState::Dismissed);
        assert_eq!(seen_by_loser.revision, 2);
        assert_eq!(seen_by_loser.transitioned_by, winner.transitioned_by);
        assert_eq!(
            replica_a
                .get_suggestion("raced")
                .await
                .expect("reload")
                .expect("exists")
                .transitioned_by,
            winner.transitioned_by
        );

        // Acceptance: the revision predicate, then the from-state one.
        seed_open_suggestion(&pool_a, "accepted", true).await;
        let stale = replica_b
            .transition_suggestion(
                "accepted",
                RuleSuggestionLifecycleState::Accepted,
                Some("admin-b"),
                from_open.with_revision(Some(9)),
            )
            .await
            .expect("stale accept")
            .expect_refused("a stale revision is refused");
        assert_eq!(stale.state, RuleSuggestionLifecycleState::Open);
        let accepted = replica_a
            .transition_suggestion(
                "accepted",
                RuleSuggestionLifecycleState::Accepted,
                Some("admin-a"),
                from_open.with_revision(Some(1)),
            )
            .await
            .expect("exact accept")
            .expect_applied("the exact revision applies");
        assert_eq!(accepted.state, RuleSuggestionLifecycleState::Accepted);
        assert_eq!(accepted.revision, 2);
        let too_late = replica_b
            .transition_suggestion(
                "accepted",
                RuleSuggestionLifecycleState::Accepted,
                Some("admin-b"),
                from_open,
            )
            .await
            .expect("late accept")
            .expect_refused("an accepted suggestion is not Open");
        assert_eq!(too_late.transitioned_by.as_deref(), Some("admin-a"));

        // The identity-bound rule fails closed here as it does in SQLite.
        seed_open_suggestion(&pool_a, "unbound", false).await;
        assert!(matches!(
            replica_a
                .transition_suggestion(
                    "unbound",
                    RuleSuggestionLifecycleState::Accepted,
                    Some("admin-a"),
                    from_open,
                )
                .await,
            Err(RuleSuggestionError::UnsafeBaselineSuggestion { ref id }) if id == "unbound"
        ));
        assert_eq!(
            replica_a
                .get_suggestion("unbound")
                .await
                .expect("reload")
                .expect("exists")
                .state,
            RuleSuggestionLifecycleState::Open
        );
        assert!(replica_a
            .transition_suggestion(
                "missing",
                RuleSuggestionLifecycleState::Dismissed,
                None,
                from_open
            )
            .await
            .expect("unknown transition")
            .is_not_found());
    }

    #[tokio::test]
    async fn two_replicas_marking_and_clearing_one_review_get_exactly_one_winner() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let pool_a = migrated_discovery_pool(&database).await;
        let pool_b = migrated_discovery_pool(&database).await;
        let replica_a = PostgresDiscoveryReadStore::new(pool_a.clone());
        let replica_b = PostgresDiscoveryReadStore::new(pool_b.clone());
        seed_aggregate(&pool_a, "GET", "/reviewed").await;
        let expect_unreviewed = Some(UNREVIEWED_REVISION);

        // Two first marks, racing: one row, one winner.
        let (left, right) = tokio::join!(
            replica_a.set_endpoint_review(
                "GET",
                "/reviewed",
                true,
                Some("admin-a"),
                expect_unreviewed
            ),
            replica_b.set_endpoint_review(
                "GET",
                "/reviewed",
                true,
                Some("admin-b"),
                expect_unreviewed
            ),
        );
        let (winner, seen_by_loser) =
            exactly_one_winner(left.expect("replica a"), right.expect("replica b"));
        assert!(winner.reviewed);
        assert_eq!(winner.revision, 1);
        assert_eq!(seen_by_loser.reviewed_by, winner.reviewed_by);
        assert_eq!(seen_by_loser.revision, 1);
        let detail = replica_b
            .get_endpoint_with_open_signal_summaries("GET", "/reviewed", 24, false)
            .await
            .expect("detail")
            .expect("exists");
        assert_eq!(detail.reviewed_by, winner.reviewed_by);
        assert_eq!(detail.review_revision, 1);

        // Two clears of revision 1, racing: one deletes, the other is
        // refused and sees no review.
        let (left, right) = tokio::join!(
            replica_a.set_endpoint_review("GET", "/reviewed", false, Some("admin-a"), Some(1)),
            replica_b.set_endpoint_review("GET", "/reviewed", false, Some("admin-b"), Some(1)),
        );
        let (cleared, seen_by_loser) =
            exactly_one_winner(left.expect("replica a"), right.expect("replica b"));
        assert_eq!(cleared, EndpointReviewState::unreviewed());
        assert_eq!(seen_by_loser, EndpointReviewState::unreviewed());
        assert_eq!(
            scalar_i64(
                &pool_a,
                "SELECT count(*) FROM greengateway.discovery_endpoint_reviews"
            )
            .await,
            0
        );

        // Stale, exact, and unconditional re-marks.
        let remarked = replica_a
            .set_endpoint_review("GET", "/reviewed", true, Some("admin-a"), None)
            .await
            .expect("unconditional mark")
            .expect_applied("unconditional");
        assert_eq!(remarked.revision, 1);
        let stale = replica_b
            .set_endpoint_review("GET", "/reviewed", true, Some("admin-b"), Some(7))
            .await
            .expect("stale mark")
            .expect_refused("stale");
        assert_eq!(stale.reviewed_by.as_deref(), Some("admin-a"));
        let exact = replica_b
            .set_endpoint_review("GET", "/reviewed", true, Some("admin-b"), Some(1))
            .await
            .expect("exact mark")
            .expect_applied("exact");
        assert_eq!(exact.revision, 2);
        assert_eq!(exact.reviewed_by.as_deref(), Some("admin-b"));
        let replaced = replica_a
            .set_endpoint_review("GET", "/reviewed", true, Some("admin-a"), None)
            .await
            .expect("unconditional replace")
            .expect_applied("unconditional");
        assert_eq!(replaced.revision, 3);

        // A clear names a revision too: a stale one deletes nothing.
        let stale_clear = replica_b
            .set_endpoint_review("GET", "/reviewed", false, Some("admin-b"), Some(9))
            .await
            .expect("stale clear")
            .expect_refused("a stale clear is refused");
        assert!(stale_clear.reviewed);
        assert_eq!(stale_clear.revision, 3);

        // Clearing nothing while expecting nothing applies; an unknown
        // endpoint is not found.
        replica_a
            .set_endpoint_review("GET", "/reviewed", false, None, None)
            .await
            .expect("clear")
            .expect_applied("clear");
        let noop = replica_b
            .set_endpoint_review("GET", "/reviewed", false, None, expect_unreviewed)
            .await
            .expect("no-op clear")
            .expect_applied("clearing nothing, expecting nothing, applies");
        assert_eq!(noop, EndpointReviewState::unreviewed());
        assert!(replica_a
            .set_endpoint_review("GET", "/missing", true, None, None)
            .await
            .expect("unknown endpoint")
            .is_not_found());
    }

    // ------------------------------------------------------------------
    // Atomic suggestion acceptance (issue #241, PR 12, design section 3):
    // the policy commit and the suggestion transition share one
    // transaction, so neither ever lands without the other.
    // ------------------------------------------------------------------

    use crate::storage::postgres_discovery_lifecycle::{AcceptRefused, AcceptSuggestionRequest};

    /// The policy-side facts an acceptance must leave untouched when it
    /// does not commit: active version/ETag/revision, history rows,
    /// outbox rows.
    #[derive(Debug, PartialEq)]
    struct PolicyFootprint {
        active_version: i64,
        active_etag: String,
        security_revision: i64,
        document_rows: i64,
        outbox_rows: i64,
    }

    async fn policy_footprint(
        store: &PostgresPolicyStore,
        pool: &deadpool_postgres::Pool,
    ) -> PolicyFootprint {
        let active = PolicyControlPlane::active(store)
            .await
            .expect("active policy reads")
            .expect("a policy is active");
        PolicyFootprint {
            active_version: active.version,
            active_etag: active.etag,
            security_revision: active.security_revision,
            document_rows: count_rows(pool, "policy_documents").await,
            outbox_rows: count_rows(pool, "security_outbox").await,
        }
    }

    /// Initialize the policy control plane with `contract_policy_variant
    /// ("accept-initial", "reader")` and return its ETag.
    async fn initialize_policy(store: &PostgresPolicyStore) -> String {
        PolicyControlPlane::commit(
            store,
            commit_request(
                PolicyCommitPrecondition::Initialize,
                &INITIAL_ACCEPT_POLICY,
                "installer",
            ),
        )
        .await
        .expect("the initial policy commits")
        .etag
    }

    static INITIAL_ACCEPT_POLICY: std::sync::LazyLock<Policy> =
        std::sync::LazyLock::new(|| contract_policy_variant("accept-initial", "reader"));

    #[tokio::test]
    async fn accepting_with_a_stale_policy_etag_leaves_suggestion_and_policy_untouched() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let pool = migrated_discovery_pool(&database).await;
        let policy_store = PostgresPolicyStore::new(pool.clone());
        let lifecycle = PostgresDiscoveryLifecycleStore::new(pool.clone());
        let current_etag = initialize_policy(&policy_store).await;
        seed_open_suggestion(&pool, "stale-etag", true).await;
        let before = policy_footprint(&policy_store, &pool).await;
        assert_eq!(before.document_rows, 1);
        assert_eq!(before.outbox_rows, 1);

        let candidate = contract_policy_variant("accept-candidate", "reader");
        let refused = lifecycle
            .accept_suggestion(AcceptSuggestionRequest {
                suggestion_id: "stale-etag",
                expected_revision: Some(1),
                actor: "admin-a",
                policy_commit: commit_request(
                    PolicyCommitPrecondition::Expected {
                        etag: format!("{current_etag}-stale"),
                    },
                    &candidate,
                    "admin-a",
                ),
            })
            .await
            .expect_err("a stale policy ETag refuses the acceptance");
        assert!(
            matches!(
                refused,
                AcceptRefused::Policy(PolicyCommitError::PreconditionFailed)
            ),
            "got {refused:?}"
        );

        // The suggestion did not move and the policy side wrote nothing:
        // no version, no history row, no outbox row, no revision advance.
        let suggestion = lifecycle
            .get_suggestion("stale-etag")
            .await
            .expect("reload")
            .expect("exists");
        assert_eq!(suggestion.state, RuleSuggestionLifecycleState::Open);
        assert_eq!(suggestion.revision, 1);
        assert!(suggestion.transitioned_at.is_none());
        assert_eq!(policy_footprint(&policy_store, &pool).await, before);

        // The other refusals also write nothing: a stale suggestion
        // revision, an unknown id, and an unbound baseline.
        let stale_revision = lifecycle
            .accept_suggestion(AcceptSuggestionRequest {
                suggestion_id: "stale-etag",
                expected_revision: Some(7),
                actor: "admin-a",
                policy_commit: commit_request(
                    PolicyCommitPrecondition::Expected {
                        etag: current_etag.clone(),
                    },
                    &candidate,
                    "admin-a",
                ),
            })
            .await
            .expect_err("a stale suggestion revision refuses");
        match stale_revision {
            AcceptRefused::Suggestion(refused) => {
                assert_eq!(refused.current.revision, 1);
                assert_eq!(refused.current.state, RuleSuggestionLifecycleState::Open);
            }
            other => panic!("expected the current row, got {other:?}"),
        }
        assert!(matches!(
            lifecycle
                .accept_suggestion(AcceptSuggestionRequest {
                    suggestion_id: "missing",
                    expected_revision: None,
                    actor: "admin-a",
                    policy_commit: commit_request(
                        PolicyCommitPrecondition::Expected {
                            etag: current_etag.clone(),
                        },
                        &candidate,
                        "admin-a",
                    ),
                })
                .await,
            Err(AcceptRefused::NotFound)
        ));
        seed_open_suggestion(&pool, "unbound", false).await;
        assert!(matches!(
            lifecycle
                .accept_suggestion(AcceptSuggestionRequest {
                    suggestion_id: "unbound",
                    expected_revision: None,
                    actor: "admin-a",
                    policy_commit: commit_request(
                        PolicyCommitPrecondition::Expected {
                            etag: current_etag.clone(),
                        },
                        &candidate,
                        "admin-a",
                    ),
                })
                .await,
            Err(AcceptRefused::UnsafeBaselineSuggestion { ref id }) if id == "unbound"
        ));
        assert_eq!(policy_footprint(&policy_store, &pool).await, before);

        // With the right ETag the same request commits both halves.
        let accepted = lifecycle
            .accept_suggestion(AcceptSuggestionRequest {
                suggestion_id: "stale-etag",
                expected_revision: Some(1),
                actor: "admin-a",
                policy_commit: commit_request(
                    PolicyCommitPrecondition::Expected {
                        etag: current_etag.clone(),
                    },
                    &candidate,
                    "admin-a",
                ),
            })
            .await
            .expect("the current ETag accepts");
        assert_eq!(
            accepted.suggestion.state,
            RuleSuggestionLifecycleState::Accepted
        );
        assert_eq!(accepted.suggestion.revision, 2);
        assert_eq!(
            accepted.suggestion.transitioned_by.as_deref(),
            Some("admin-a")
        );
        assert_eq!(accepted.policy.version, 2);
        assert_eq!(accepted.policy.policy.id, candidate.id);
        let after = policy_footprint(&policy_store, &pool).await;
        assert_eq!(
            after,
            PolicyFootprint {
                active_version: 2,
                active_etag: accepted.policy.etag.clone(),
                security_revision: before.security_revision + 1,
                document_rows: 2,
                outbox_rows: 2,
            }
        );
        let stored = lifecycle
            .get_suggestion("stale-etag")
            .await
            .expect("reload")
            .expect("exists");
        assert_eq!(stored.state, RuleSuggestionLifecycleState::Accepted);
        assert_eq!(stored.revision, 2);
    }

    #[tokio::test]
    async fn two_replicas_accepting_one_suggestion_commit_exactly_one_policy() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let pool_a = migrated_discovery_pool(&database).await;
        let pool_b = migrated_discovery_pool(&database).await;
        let policy_store = PostgresPolicyStore::new(pool_a.clone());
        let replica_a = PostgresDiscoveryLifecycleStore::new(pool_a.clone());
        let replica_b = PostgresDiscoveryLifecycleStore::new(pool_b.clone());
        let current_etag = initialize_policy(&policy_store).await;
        seed_open_suggestion(&pool_a, "raced-accept", true).await;
        let before = policy_footprint(&policy_store, &pool_a).await;

        // Both replicas read the same suggestion revision and the same
        // policy ETag, and each proposes its own candidate.
        let candidate_a = contract_policy_variant("accepted-by-a", "reader");
        let candidate_b = contract_policy_variant("accepted-by-b", "reader");
        let request_for =
            |candidate: &'static Policy, actor: &'static str| AcceptSuggestionRequest {
                suggestion_id: "raced-accept",
                expected_revision: Some(1),
                actor,
                policy_commit: commit_request(
                    PolicyCommitPrecondition::Expected {
                        etag: current_etag.clone(),
                    },
                    candidate,
                    actor,
                ),
            };
        let candidate_a: &'static Policy = Box::leak(Box::new(candidate_a));
        let candidate_b: &'static Policy = Box::leak(Box::new(candidate_b));
        let (left, right) = tokio::join!(
            replica_a.accept_suggestion(request_for(candidate_a, "admin-a")),
            replica_b.accept_suggestion(request_for(candidate_b, "admin-b")),
        );

        let (winner, loser) = match (left, right) {
            (Ok(winner), Err(loser)) | (Err(loser), Ok(winner)) => (winner, loser),
            (left, right) => panic!("exactly one replica must win, got {left:?} and {right:?}"),
        };
        let winner_actor = winner
            .suggestion
            .transitioned_by
            .clone()
            .expect("the winner recorded its actor");
        let winner_candidate = if winner_actor == "admin-a" {
            candidate_a
        } else {
            candidate_b
        };
        assert_eq!(
            winner.suggestion.state,
            RuleSuggestionLifecycleState::Accepted
        );
        assert_eq!(winner.suggestion.revision, 2);
        assert_eq!(winner.policy.policy.id, winner_candidate.id);

        // The loser was refused by the SUGGESTION (it saw the winner's
        // committed row after the lock), not by the policy ETag, and its
        // policy commit never ran: one new version, one outbox row, and
        // the active policy is the winner's candidate.
        match loser {
            AcceptRefused::Suggestion(refused) => {
                assert_eq!(
                    refused.current.state,
                    RuleSuggestionLifecycleState::Accepted
                );
                assert_eq!(refused.current.revision, 2);
                assert_eq!(
                    refused.current.transitioned_by.as_deref(),
                    Some(winner_actor.as_str())
                );
            }
            other => panic!("the loser must be refused by the suggestion, got {other:?}"),
        }
        let after = policy_footprint(&policy_store, &pool_a).await;
        assert_eq!(
            after,
            PolicyFootprint {
                active_version: 2,
                active_etag: winner.policy.etag.clone(),
                security_revision: before.security_revision + 1,
                document_rows: 2,
                outbox_rows: 2,
            }
        );
        assert_eq!(
            PolicyControlPlane::active(&policy_store)
                .await
                .expect("active")
                .expect("exists")
                .policy
                .id,
            winner_candidate.id
        );
        let stored = replica_b
            .get_suggestion("raced-accept")
            .await
            .expect("reload")
            .expect("exists");
        assert_eq!(
            stored.transitioned_by.as_deref(),
            Some(winner_actor.as_str())
        );
        assert_eq!(stored.revision, 2);
    }

    /// The deterministic form of the race above: replica A is mid-acceptance
    /// (an external transaction holds the suggestion row `FOR UPDATE`),
    /// so replica B must block at the lock BEFORE running its policy
    /// commit, and once A's transition commits B is refused by the
    /// suggestion with its (valid-ETag) policy commit never applied.
    /// Without the row lock B would run to completion inside the wait
    /// window and both assertions below would fail.
    #[tokio::test]
    async fn an_acceptance_waiting_on_the_suggestion_lock_never_commits_its_policy() {
        use crate::storage::postgres_discovery_lifecycle::transition_suggestion_with;

        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let pool_a = migrated_discovery_pool(&database).await;
        let pool_b = migrated_discovery_pool(&database).await;
        let policy_store = PostgresPolicyStore::new(pool_a.clone());
        let replica_b = PostgresDiscoveryLifecycleStore::new(pool_b.clone());
        let current_etag = initialize_policy(&policy_store).await;
        seed_open_suggestion(&pool_a, "held", true).await;
        let before = policy_footprint(&policy_store, &pool_a).await;

        // Replica A: mid-acceptance, holding the row lock.
        let replica_a = pool_a.get().await.expect("replica a's connection");
        replica_a.batch_execute("BEGIN").await.expect("begin");
        replica_a
            .query_one(
                "SELECT id FROM greengateway.discovery_rule_suggestions WHERE id = $1 FOR UPDATE",
                &[&"held"],
            )
            .await
            .expect("replica a locks the row");

        // Replica B: the same suggestion revision, a valid policy ETag.
        let candidate_b = contract_policy_variant("accepted-by-b", "reader");
        let pending = replica_b.accept_suggestion(AcceptSuggestionRequest {
            suggestion_id: "held",
            expected_revision: Some(1),
            actor: "admin-b",
            policy_commit: commit_request(
                PolicyCommitPrecondition::Expected {
                    etag: current_etag.clone(),
                },
                &candidate_b,
                "admin-b",
            ),
        });
        tokio::pin!(pending);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(250), &mut pending)
                .await
                .is_err(),
            "replica b must block on the suggestion row lock"
        );
        assert_eq!(
            policy_footprint(&policy_store, &pool_a).await,
            before,
            "a blocked acceptance has not touched the policy"
        );

        // Replica A finishes: transition, commit.
        transition_suggestion_with(
            &replica_a,
            "held",
            RuleSuggestionLifecycleState::Accepted,
            Some("admin-a"),
            TransitionPrecondition::from_state(RuleSuggestionLifecycleState::Open),
        )
        .await
        .expect("replica a transitions")
        .expect_applied("replica a holds the lock");
        replica_a.batch_execute("COMMIT").await.expect("commit");

        let refused = pending
            .await
            .expect_err("replica b is refused once it sees the committed row");
        match refused {
            AcceptRefused::Suggestion(refused) => {
                assert_eq!(
                    refused.current.state,
                    RuleSuggestionLifecycleState::Accepted
                );
                assert_eq!(refused.current.revision, 2);
                assert_eq!(refused.current.transitioned_by.as_deref(), Some("admin-a"));
            }
            other => panic!("the loser must be refused by the suggestion, got {other:?}"),
        }
        assert_eq!(
            policy_footprint(&policy_store, &pool_a).await,
            before,
            "the loser's policy commit was never applied"
        );
    }

    #[tokio::test]
    async fn a_crash_between_policy_write_and_transition_applies_neither() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let pool = migrated_discovery_pool(&database).await;
        let policy_store = PostgresPolicyStore::new(pool.clone());
        let lifecycle = PostgresDiscoveryLifecycleStore::new(pool.clone());
        let current_etag = initialize_policy(&policy_store).await;
        seed_open_suggestion(&pool, "crashed", true).await;
        let before = policy_footprint(&policy_store, &pool).await;
        let candidate = contract_policy_variant("accept-crashed", "reader");
        let request = || AcceptSuggestionRequest {
            suggestion_id: "crashed",
            expected_revision: Some(1),
            actor: "admin-a",
            policy_commit: commit_request(
                PolicyCommitPrecondition::Expected {
                    etag: current_etag.clone(),
                },
                &candidate,
                "admin-a",
            ),
        };

        // The process dies after the policy's steps ran and before the
        // suggestion transitioned: the connection goes away with the
        // transaction open.
        lifecycle.crash_before_transition_for_tests();
        let crashed = lifecycle
            .accept_suggestion(request())
            .await
            .expect_err("the crash hook fails the acceptance");
        assert!(
            matches!(
                crashed,
                AcceptRefused::Store(RuleSuggestionError::Repository(_))
            ),
            "got {crashed:?}"
        );

        // BOTH halves are unapplied: the policy has no new version,
        // history row, outbox row, or revision, and the suggestion is
        // still Open at revision 1.
        assert_eq!(policy_footprint(&policy_store, &pool).await, before);
        let suggestion = lifecycle
            .get_suggestion("crashed")
            .await
            .expect("reload")
            .expect("exists");
        assert_eq!(suggestion.state, RuleSuggestionLifecycleState::Open);
        assert_eq!(suggestion.revision, 1);

        // The same request, retried after the "restart", commits both.
        let accepted = lifecycle
            .accept_suggestion(request())
            .await
            .expect("the retry accepts");
        assert_eq!(
            accepted.suggestion.state,
            RuleSuggestionLifecycleState::Accepted
        );
        assert_eq!(accepted.suggestion.revision, 2);
        // The aborted transaction consumed identity value 2 (sequences
        // never roll back), so the retry's version is 3 with two rows
        // stored: a gap, never a phantom row. The security revision is a
        // counter row updated inside the transaction, so it has no gap.
        assert_eq!(accepted.policy.version, 3);
        let after = policy_footprint(&policy_store, &pool).await;
        assert_eq!(
            after,
            PolicyFootprint {
                active_version: 3,
                active_etag: accepted.policy.etag.clone(),
                security_revision: before.security_revision + 1,
                document_rows: 2,
                outbox_rows: 2,
            }
        );
    }

    // ------------------------------------------------------------------
    // Generation parity (issue #241, PR 12): the PostgreSQL engine and the
    // SQLite engine, fed the SAME audit events and the SAME discovery
    // inventory, produce the same suggestion set and the same run
    // counters; re-running against PostgreSQL changes nothing.
    // ------------------------------------------------------------------

    use crate::discovery::{
        cluster_suggestions::ClusterRuleSuggestionEngine,
        suggestions::{
            RuleSuggestion, RuleSuggestionConfig, RuleSuggestionEngine, RuleSuggestionListFilters,
            RuleSuggestionRun,
        },
    };

    const PARITY_CLASSIFIED_AT: &str = "2024-05-31T00:00:00Z";
    const PARITY_SIGNAL_CREATED_AT: &str = "2024-06-02T00:00:00Z";

    /// The actor of one generation-fixture observation: user, issuer,
    /// roles, and auth mode -- the facets the baseline keys on.
    struct FixtureActor<'a> {
        user_id: &'a str,
        issuer: Option<&'a str>,
        roles: &'a [&'a str],
        auth_mode: &'a str,
    }

    /// One observation as the middleware emits it; the payload carries the
    /// routing flag and the policy decision the matrix filters on.
    fn generation_event(
        index: usize,
        method: &str,
        path: &str,
        status: u16,
        actor: Option<FixtureActor<'_>>,
        policy_decision: &str,
        routing_context_known: bool,
    ) -> AuditEvent {
        let actor = actor.map(|actor| Actor {
            user_id: actor.user_id.to_owned(),
            issuer: actor.issuer.map(str::to_owned),
            email: None,
            roles: Some(actor.roles.iter().map(|role| (*role).to_owned()).collect()),
            auth_mode: actor.auth_mode.to_owned(),
        });
        let mut event = AuditEvent::new(
            "http.request_observed",
            format!("generation-request-{index}"),
            "203.0.113.10",
            actor,
            json!({
                "method": method,
                "path": path,
                "status": status,
                "latency_ms": 5,
                "policy_decision": policy_decision,
                "routing_context_known": routing_context_known,
            }),
        );
        event.event_id = format!("generation-{index:03}");
        event.timestamp = format!("2024-06-01T12:00:{:02}Z", index % 60);
        event
    }

    /// The fixture: two observed endpoints, and observations that exercise
    /// every matrix branch -- counted (two roles on one call, an error
    /// response, a service token without an issuer), and each skip reason
    /// (denied, unauthenticated, no roles, no issuer, unsupported auth
    /// method, unknown routing context, an endpoint never observed).
    fn generation_events() -> Vec<AuditEvent> {
        let bearer = "bearer_token";
        let issuer = Some("provider:test");
        let actor = |user_id, issuer, roles, auth_mode| {
            Some(FixtureActor {
                user_id,
                issuer,
                roles,
                auth_mode,
            })
        };
        let reader: &[&str] = &["billing-reader"];
        vec![
            generation_event(
                1,
                "GET",
                "/invoices/123",
                200,
                actor("alice", issuer, reader, bearer),
                "allowed",
                true,
            ),
            generation_event(
                2,
                "GET",
                "/invoices/456",
                500,
                actor("bob", issuer, reader, bearer),
                "allowed",
                true,
            ),
            generation_event(
                3,
                "POST",
                "/refunds",
                201,
                actor("carol", issuer, &["billing-writer", "auditor"], bearer),
                "allowed",
                true,
            ),
            generation_event(
                4,
                "GET",
                "/invoices/789",
                403,
                actor("dave", issuer, reader, bearer),
                "denied",
                true,
            ),
            generation_event(5, "GET", "/invoices/1", 401, None, "allowed", true),
            generation_event(
                6,
                "GET",
                "/invoices/2",
                200,
                actor("erin", issuer, &[], bearer),
                "allowed",
                true,
            ),
            generation_event(
                7,
                "GET",
                "/invoices/3",
                200,
                actor("frank", None, reader, bearer),
                "allowed",
                true,
            ),
            generation_event(
                8,
                "POST",
                "/refunds",
                200,
                actor("svc-batch", None, &["batch"], "service_token"),
                "allowed",
                true,
            ),
            generation_event(
                9,
                "GET",
                "/invoices/4",
                200,
                actor("grace", issuer, reader, "mtls"),
                "allowed",
                true,
            ),
            generation_event(
                10,
                "GET",
                "/unobserved/1",
                200,
                actor("alice", issuer, reader, bearer),
                "allowed",
                true,
            ),
            generation_event(
                11,
                "GET",
                "/invoices/5",
                200,
                actor("alice", issuer, reader, bearer),
                "allowed",
                false,
            ),
        ]
    }

    const PARITY_ENDPOINTS: [(&str, &str); 2] = [("GET", "/invoices/{id}"), ("POST", "/refunds")];

    /// The SQLite half of the fixture: the aggregator's tables as the sink
    /// leaves them, plus one open signal.
    fn seed_sqlite_discovery_fixture(path: &PathBuf) {
        DiscoveryQueryStore::open(path).expect("the SQLite discovery schema creates");
        let connection = rusqlite::Connection::open(path).expect("the discovery file opens");
        connection
            .execute_batch(
                r#"
                CREATE TABLE IF NOT EXISTS discovery_endpoint_aggregates (
                    method TEXT NOT NULL,
                    endpoint_template TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    call_count INTEGER NOT NULL,
                    schema_mismatch_count INTEGER NOT NULL DEFAULT 0,
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
            .expect("the aggregate table creates");
        for (method, endpoint_template) in PARITY_ENDPOINTS {
            connection
                .execute(
                    "INSERT INTO discovery_endpoint_aggregates (
                         method, endpoint_template, first_seen, last_seen, call_count,
                         schema_mismatch_count, latency_count, latency_p50_ms, latency_p95_ms,
                         latency_p99_ms, latency_samples_json, distinct_principal_count, updated_at
                     ) VALUES (?1, ?2, '2024-06-01T12:00:00Z', '2024-06-01T12:00:00Z', 1, 0, 1, 1,
                               1, 1, '[]', 0, '2024-06-01T12:00:00Z')",
                    rusqlite::params![method, endpoint_template],
                )
                .expect("the aggregate seeds");
            connection
                .execute(
                    "INSERT INTO discovery_endpoint_routing_classifications
                         (method, endpoint_template, first_classified_at)
                     VALUES (?1, ?2, ?3)",
                    rusqlite::params![method, endpoint_template, PARITY_CLASSIFIED_AT],
                )
                .expect("the classification seeds");
        }
        connection
            .execute(
                "INSERT INTO discovery_signals
                     (id, signal_type, target_kind, target_key, target_identity_json,
                      explanation, evidence_json, state, created_at, updated_at)
                 VALUES (?1, 'new_endpoint_seen', 'endpoint', ?2, ?3, 'seeded', '{}', 'open',
                         ?4, ?4)",
                rusqlite::params![
                    "sig-parity",
                    signals::endpoint_target_key("GET", "/invoices/{id}"),
                    json!({"method": "GET", "endpoint_template": "/invoices/{id}"}).to_string(),
                    PARITY_SIGNAL_CREATED_AT,
                ],
            )
            .expect("the signal seeds");
    }

    /// The PostgreSQL half: the projector's tables with the same rows.
    async fn seed_postgres_discovery_fixture(pool: &deadpool_postgres::Pool) {
        let client = pool.get().await.expect("client");
        for (method, endpoint_template) in PARITY_ENDPOINTS {
            seed_aggregate(pool, method, endpoint_template).await;
            client
                .execute(
                    "INSERT INTO greengateway.discovery_endpoint_routing_classifications
                         (method, endpoint_template, first_classified_at)
                     VALUES ($1, $2, $3)",
                    &[&method, &endpoint_template, &PARITY_CLASSIFIED_AT],
                )
                .await
                .expect("the classification seeds");
        }
        client
            .execute(
                "INSERT INTO greengateway.discovery_signals
                     (id, signal_type, target_kind, target_key, target_identity_json,
                      explanation, evidence_json, state, created_at, updated_at)
                 VALUES ($1, 'new_endpoint_seen', 'endpoint', $2, $3, 'seeded', '{}', 'open',
                         $4, $4)",
                &[
                    &"sig-parity",
                    &signals::endpoint_target_key("GET", "/invoices/{id}"),
                    &json!({"method": "GET", "endpoint_template": "/invoices/{id}"}).to_string(),
                    &PARITY_SIGNAL_CREATED_AT,
                ],
            )
            .await
            .expect("the signal seeds");
    }

    /// A suggestion reduced to what parity means: everything except the
    /// generated id, the run's own timestamps (`created_at`, the window
    /// bounds), and the backend's name in `evidence.source`. The audit
    /// timestamps in the evidence compare as instants, because the durable
    /// stream renders them with fixed microseconds and SQLite keeps the
    /// event's own text.
    fn comparable_suggestion(suggestion: &RuleSuggestion) -> Value {
        let mut evidence = suggestion.evidence.clone();
        if let Some(object) = evidence.as_object_mut() {
            for volatile in ["source", "from", "to"] {
                object.remove(volatile);
            }
            for instant in ["first_seen", "last_seen"] {
                if let Some(text) = object.get(instant).and_then(Value::as_str) {
                    let parsed = OffsetDateTime::parse(text, &Rfc3339)
                        .unwrap_or_else(|_| panic!("{instant} is RFC 3339: {text}"));
                    object.insert(instant.to_owned(), json!(parsed.unix_timestamp_nanos()));
                }
            }
        }
        json!({
            "suggestion_type": suggestion.suggestion_type,
            "method": suggestion.method,
            "path_pattern": suggestion.path_pattern,
            "principal_key": suggestion.principal_key,
            "proposed_rule": suggestion.proposed_rule,
            "rationale": suggestion.rationale,
            "evidence": evidence,
            "state": suggestion.state,
            "source_signal_id": suggestion.source_signal_id,
            "revision": suggestion.revision,
        })
    }

    fn comparable_suggestion_set(suggestions: &[RuleSuggestion]) -> Vec<Value> {
        let mut set = suggestions
            .iter()
            .map(comparable_suggestion)
            .collect::<Vec<_>>();
        set.sort_by_key(|value| value.to_string());
        set
    }

    #[tokio::test]
    async fn postgres_generation_matches_sqlite_for_the_same_fixture_and_is_idempotent() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let events = generation_events();
        let policy = contract_policy("parity");
        let config = RuleSuggestionConfig {
            baseline_window_hours: 876_000,
        };

        // Standalone: the SQLite audit adapter and the SQLite discovery file.
        let audit_db = TempDb::new("parity-audit");
        let discovery_db = TempDb::new("parity-discovery");
        SqliteAuditEventStore::open(&audit_db.path)
            .expect("the SQLite audit store opens")
            .insert_events(&events)
            .await
            .expect("the SQLite audit store ingests");
        seed_sqlite_discovery_fixture(&discovery_db.path);
        let sqlite_engine =
            RuleSuggestionEngine::open(&discovery_db.path, Some(&audit_db.path), config)
                .expect("the SQLite engine opens");
        let sqlite_run = sqlite_engine
            .generate(&policy)
            .expect("the SQLite engine generates");
        let sqlite_suggestions = sqlite_engine
            .list_suggestions()
            .expect("the SQLite suggestions list");

        // Cluster: the same events through the durable audit store, the
        // same inventory in the projector's tables.
        let database = create_test_database(&admin_dsn).await;
        let pool = migrated_discovery_pool(&database).await;
        let audit_store = Arc::new(PostgresAuditEventStore::new(
            pool.clone(),
            Some(ingest_identity()),
        ));
        audit_store
            .insert_events(&events)
            .await
            .expect("the PostgreSQL audit store ingests");
        seed_postgres_discovery_fixture(&pool).await;
        let postgres_engine = ClusterRuleSuggestionEngine::new(
            Arc::new(PostgresDiscoveryReadStore::new(pool.clone())),
            audit_store,
            PostgresDiscoveryLifecycleStore::new(pool.clone()),
            config,
        );
        let postgres_run = postgres_engine
            .generate(&policy)
            .await
            .expect("the PostgreSQL engine generates");
        let postgres_suggestions = postgres_engine
            .list_suggestions()
            .await
            .expect("the PostgreSQL suggestions list");

        // The fixture is not trivial: four baseline candidates (two roles
        // on one call, the reader with one error, the service token
        // without an issuer) and the signal's shadow candidate.
        assert_eq!(sqlite_run.inserted_count, 5, "{sqlite_run:?}");
        assert_eq!(sqlite_run.baseline.observed_role_endpoint_count, 4);
        assert_eq!(sqlite_run.baseline.scanned_event_count, events.len() as u64);
        assert_eq!(sqlite_run.baseline.skipped_denied_observations, 1);
        assert_eq!(sqlite_run.baseline.skipped_unauthenticated_observations, 1);
        assert_eq!(sqlite_run.baseline.skipped_without_roles_observations, 1);
        assert_eq!(sqlite_run.baseline.skipped_without_issuer_observations, 1);
        assert_eq!(
            sqlite_run
                .baseline
                .skipped_unsupported_auth_method_observations,
            1
        );
        assert_eq!(
            sqlite_run
                .baseline
                .skipped_unknown_routing_context_observations,
            1
        );
        assert_eq!(sqlite_run.anomaly.open_signal_count, 1);

        // Parity: the run counters and the suggestion set are the same.
        assert_eq!(postgres_run, sqlite_run);
        assert_eq!(
            comparable_suggestion_set(&postgres_suggestions),
            comparable_suggestion_set(&sqlite_suggestions)
        );
        assert!(postgres_suggestions
            .iter()
            .all(|suggestion| suggestion.evidence["source"] != json!("audit_sqlite")));
        let reader = postgres_suggestions
            .iter()
            .find(|suggestion| {
                suggestion.method == "GET"
                    && suggestion.proposed_rule.principal.roles == vec!["billing-reader".to_owned()]
            })
            .expect("the reader baseline exists");
        assert_eq!(reader.evidence["observation_count"], json!(2));
        assert_eq!(reader.evidence["error_count"], json!(1));

        // Idempotent: a second run inserts nothing and changes nothing,
        // exactly as the SQLite engine's second run does.
        let second = postgres_engine
            .generate(&policy)
            .await
            .expect("the second PostgreSQL run generates");
        assert_eq!(
            second,
            RuleSuggestionRun {
                inserted_count: 0,
                ..postgres_run.clone()
            }
        );
        let after = postgres_engine
            .list_suggestions()
            .await
            .expect("the PostgreSQL suggestions list again");
        assert_eq!(after, postgres_suggestions);
        assert_eq!(
            sqlite_engine
                .generate(&policy)
                .expect("the second SQLite run generates")
                .inserted_count,
            0
        );

        // Paging walks the same set one row at a time through the shared
        // cursor format, newest first.
        let mut paged = Vec::new();
        let mut cursor = None;
        loop {
            let page = postgres_engine
                .list_suggestion_page(&RuleSuggestionListFilters {
                    state: None,
                    suggestion_type: None,
                    limit: 2,
                    cursor,
                })
                .await
                .expect("a page lists");
            paged.extend(page.suggestions);
            let Some(next) = page.next_cursor else {
                break;
            };
            cursor = Some(next);
        }
        assert_eq!(paged, postgres_suggestions);
    }
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
