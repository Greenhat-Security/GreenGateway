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
