//! The stored policy test suite's repository contract (issue #243), against
//! the standalone SQLite adapter everywhere and the cluster PostgreSQL
//! adapter when the test harness names a database (CI does; a checkout
//! without one skips those tests).

use std::path::PathBuf;
use std::sync::Arc;

use serde_json::{json, Value};

use super::*;
use crate::auth::{AuthMethod, Principal};

fn suite(description: &str) -> Value {
    json!({
        "schema_version": "policy-tests.v1",
        "description": description,
        "cases": [
            {
                "id": "health-is-public",
                "kind": "http",
                "request": { "method": "GET", "path": "/health" },
                "principal": "anonymous",
                "expect": { "logical": "allow" }
            },
            {
                "id": "export-rate",
                "kind": "rate",
                "request": { "method": "GET", "path": "/export" },
                "principal": {
                    "subject": "synthetic-reader",
                    "roles": ["reader"],
                    "auth_method": "bearer_token"
                },
                "expect": { "rate_override": null }
            }
        ]
    })
}

fn writer() -> Principal {
    Principal {
        user_id: "suite-writer".to_owned(),
        issuer: Some("https://issuer.example.test".to_owned()),
        email: None,
        org_id: None,
        roles: vec!["admin".to_owned()],
        session_id: "session-suite".to_owned(),
        auth_method: AuthMethod::Cookie,
        scopes: None,
        verified_claims: Vec::new(),
    }
}

fn expected(record: &PolicyTestSuiteRecord) -> PolicyTestSuitePrecondition {
    PolicyTestSuitePrecondition::Expected {
        etag: record.etag.clone(),
    }
}

/// Exactly one of two racing writes stored its suite, and the other lost its
/// precondition rather than failing some other way.
fn assert_one_winner(
    left: &Result<PolicyTestSuiteRecord, PolicyTestSuiteCommitError>,
    right: &Result<PolicyTestSuiteRecord, PolicyTestSuiteCommitError>,
) {
    let lost = |result: &Result<PolicyTestSuiteRecord, PolicyTestSuiteCommitError>| {
        matches!(result, Err(PolicyTestSuiteCommitError::PreconditionFailed))
    };
    assert!(
        (left.is_ok() && lost(right)) || (lost(left) && right.is_ok()),
        "{left:?} {right:?}"
    );
}

fn digest_of(document: &Value) -> String {
    parse_suite(document).expect("fixture suite parses").digest
}

/// The contract both adapters satisfy, over an empty store: nothing is
/// active; the first write needs `Absent` and every later one the active
/// ETag; a refused write changes nothing; the ETag is the semantic digest in
/// quotes, so a suite written differently but meaning the same carries the
/// same tag; and the active version reads back verified.
async fn exercise_versioning(store: &dyn PolicyTestSuiteStore) {
    assert!(store.active().await.expect("empty read").is_none());
    let first = suite("first");
    let stale = PolicyTestSuitePrecondition::Expected {
        etag: policy_test_suite_etag(&digest_of(&first)),
    };
    assert!(matches!(
        store.commit(stale, &first, &writer()).await,
        Err(PolicyTestSuiteCommitError::PreconditionFailed)
    ));
    assert!(store.active().await.expect("read").is_none());

    let created = store
        .commit(PolicyTestSuitePrecondition::Absent, &first, &writer())
        .await
        .expect("the first suite stores");
    assert_eq!(created.digest, digest_of(&first));
    assert_eq!(created.etag, format!("\"{}\"", created.digest));
    assert_eq!(created.case_count(), 2);
    assert!(matches!(
        store
            .commit(PolicyTestSuitePrecondition::Absent, &first, &writer())
            .await,
        Err(PolicyTestSuiteCommitError::PreconditionFailed)
    ));

    let second = suite("second");
    let replaced = store
        .commit(expected(&created), &second, &writer())
        .await
        .expect("the suite replaces under its ETag");
    assert!(replaced.version > created.version);
    assert_ne!(replaced.etag, created.etag);
    // The first version's ETag is stale now: nothing is written.
    assert!(matches!(
        store.commit(expected(&created), &first, &writer()).await,
        Err(PolicyTestSuiteCommitError::PreconditionFailed)
    ));

    let active = store
        .active()
        .await
        .expect("read")
        .expect("a suite is stored");
    assert_eq!(
        (active.version, &active.etag, &active.digest),
        (replaced.version, &replaced.etag, &replaced.digest)
    );
    assert_eq!(active.document, second);
    assert_eq!(active.security_revision, replaced.security_revision);

    // The same suite, members in another order, is the same representation.
    let respelled: Value =
        serde_json::from_str(&serde_json::to_string_pretty(&second).expect("serializes"))
            .expect("parses");
    let again = store
        .commit(expected(&active), &respelled, &writer())
        .await
        .expect("an identical suite stores as a new version");
    assert!(again.version > active.version);
    assert_eq!(again.etag, active.etag);
}

/// Of writers presenting one ETag at once, exactly one stores its suite.
async fn exercise_one_winner(store: Arc<dyn PolicyTestSuiteStore>) {
    let base = match store.active().await.expect("read") {
        Some(active) => active,
        None => store
            .commit(
                PolicyTestSuitePrecondition::Absent,
                &suite("base"),
                &writer(),
            )
            .await
            .expect("the base suite stores"),
    };
    let writers: Vec<_> = (0..6)
        .map(|index| {
            let store = Arc::clone(&store);
            let precondition = expected(&base);
            tokio::spawn(async move {
                store
                    .commit(precondition, &suite(&format!("racer-{index}")), &writer())
                    .await
            })
        })
        .collect();
    let mut winners = Vec::new();
    for writer in writers {
        match writer.await.expect("the writer task completes") {
            Ok(record) => winners.push(record),
            Err(PolicyTestSuiteCommitError::PreconditionFailed) => {}
            Err(error) => panic!("a racing writer failed instead of losing: {error}"),
        }
    }
    assert_eq!(winners.len(), 1, "exactly one writer wins");
    let active = store
        .active()
        .await
        .expect("read")
        .expect("a suite is stored");
    assert_eq!(active.etag, winners[0].etag);
}

/// What no store accepts: a suite the parser refuses, one holding U+0000,
/// and one over the size bound. Each is refused before anything is written.
async fn exercise_refusals(store: &dyn PolicyTestSuiteStore) {
    let mut empty = suite("refused");
    empty["cases"] = json!([]);
    let mut nul = suite("refused");
    nul["description"] = json!("nul\u{0}inside");
    let mut oversized = suite("refused");
    oversized["cases"] = Value::Array(
        (0..512)
            .map(|index| {
                json!({
                    "id": format!("case-{index}"),
                    "description": "d".repeat(1024),
                    "kind": "http",
                    "request": { "method": "GET", "path": format!("/p/{}", "x".repeat(4096)) },
                    "principal": "anonymous",
                    "expect": { "logical": "allow" }
                })
            })
            .collect(),
    );
    assert!(
        crate::canonical_json::canonical_json_bytes(&oversized)
            .expect("canonical")
            .len()
            > MAX_POLICY_TEST_SUITE_BYTES
    );
    for document in [&empty, &nul, &oversized] {
        match store
            .commit(PolicyTestSuitePrecondition::Absent, document, &writer())
            .await
        {
            Err(PolicyTestSuiteCommitError::Store(error)) => {
                assert_eq!(error.invalid_parameter_name(), Some("suite"));
            }
            other => panic!("expected a refused parameter, got {other:?}"),
        }
    }
    assert!(store.active().await.expect("read").is_none());
}

// ---- SQLite -------------------------------------------------------------------

struct TempDb {
    path: PathBuf,
}

impl TempDb {
    fn new(test_name: &str) -> Self {
        Self {
            path: std::env::temp_dir().join(format!(
                "greengateway-policy-tests-{test_name}-{}.sqlite",
                uuid::Uuid::new_v4()
            )),
        }
    }
}

impl Drop for TempDb {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", self.path.display()));
        }
    }
}

#[tokio::test]
async fn sqlite_versions_are_compare_and_set_and_survive_reopen() {
    let db = TempDb::new("versioning");
    let store = SqlitePolicyTestSuiteStore::open(&db.path).expect("store opens");
    exercise_versioning(&store).await;
    let active = store.active().await.expect("read").expect("stored");
    drop(store);

    // The history database's other tables live beside it untouched.
    let history = crate::rbac::PolicyHistoryStore::open(&db.path).expect("history opens");
    drop(history);
    let reopened = SqlitePolicyTestSuiteStore::open(&db.path).expect("store reopens");
    let read = reopened.active().await.expect("read").expect("stored");
    assert_eq!((read.version, read.etag), (active.version, active.etag));
    assert_eq!(read.security_revision, None);
}

#[tokio::test]
async fn sqlite_writers_on_separate_connections_produce_one_winner() {
    let db = TempDb::new("one-winner");
    // Each handle is its own connection to the file, as two stores in one
    // process (or a restarted process beside a running one) would be.
    let first = SqlitePolicyTestSuiteStore::open(&db.path).expect("store opens");
    exercise_one_winner(Arc::new(first)).await;
    let second = SqlitePolicyTestSuiteStore::open(&db.path).expect("store opens");
    let active = second.active().await.expect("read").expect("stored");
    let other = SqlitePolicyTestSuiteStore::open(&db.path).expect("store opens");
    let (left_suite, right_suite, actor) = (suite("left"), suite("right"), writer());
    let (left, right) = tokio::join!(
        second.commit(expected(&active), &left_suite, &actor),
        other.commit(expected(&active), &right_suite, &actor),
    );
    assert_one_winner(&left, &right);
}

#[tokio::test]
async fn sqlite_refuses_suites_it_must_not_store() {
    let db = TempDb::new("refusals");
    let store = SqlitePolicyTestSuiteStore::open(&db.path).expect("store opens");
    exercise_refusals(&store).await;
}

/// A row edited out of band no longer reproduces its ETag, or no longer
/// parses: either way it is refused, never served or run.
#[tokio::test]
async fn sqlite_refuses_a_stored_suite_that_does_not_verify() {
    let db = TempDb::new("tampered");
    let store = SqlitePolicyTestSuiteStore::open(&db.path).expect("store opens");
    store
        .commit(
            PolicyTestSuitePrecondition::Absent,
            &suite("honest"),
            &writer(),
        )
        .await
        .expect("stores");
    let connection = rusqlite::Connection::open(&db.path).expect("raw connection");
    connection
        .execute(
            "UPDATE policy_test_suite_versions SET suite_json = ?1",
            [suite("edited").to_string()],
        )
        .expect("tamper");
    let error = store
        .active()
        .await
        .expect_err("an edited suite is refused");
    assert_eq!(error.kind(), RepositoryErrorKind::InvalidData);
    connection
        .execute(
            "UPDATE policy_test_suite_versions SET suite_json = '{\"schema_version\":\"policy-tests.v2\"}'",
            [],
        )
        .expect("tamper");
    let error = store
        .active()
        .await
        .expect_err("an unparsable suite is refused");
    assert_eq!(error.kind(), RepositoryErrorKind::InvalidData);
}

#[test]
fn nul_characters_are_found_in_any_string() {
    assert!(!contains_nul_character(&suite("clean")));
    let mut nested = suite("clean");
    nested["cases"][1]["principal"]["roles"] = json!(["ok", "bad\u{0}"]);
    assert!(contains_nul_character(&nested));
}

// ---- PostgreSQL -------------------------------------------------------------------

#[cfg(feature = "postgres")]
mod postgres {
    use super::*;
    use crate::storage::contract_tests::postgres_audit_tests::{
        create_test_database, locator, write_dsn_file, TestDatabase, DATABASE,
    };
    use crate::storage::{
        migrations, postgres::PostgresFoundation,
        postgres_policy_tests::PostgresPolicyTestSuiteStore,
    };

    async fn migrated_pool(database: &TestDatabase) -> deadpool_postgres::Pool {
        let dsn_file = write_dsn_file(&database.dsn);
        let mut config = crate::config::Config::test_defaults();
        config.state_backend = crate::config::StateBackend::Postgres;
        config.deployment_id = Some("deploy-policy-tests".to_owned());
        config.database.url_file = Some(dsn_file.path.clone());
        config.database.tls_mode = crate::config::DatabaseTlsMode::LoopbackDev;
        let foundation = PostgresFoundation::establish(&config)
            .await
            .expect("the test database should establish");
        migrations::apply_missing_for_startup(foundation.pool(), &config.database)
            .await
            .expect("the schema should migrate");
        foundation.pool().clone()
    }

    async fn rows(pool: &deadpool_postgres::Pool, sql: &str) -> Vec<tokio_postgres::Row> {
        pool.get()
            .await
            .expect("checkout")
            .query(sql, &[])
            .await
            .expect("query")
    }

    #[tokio::test]
    async fn postgres_versions_are_compare_and_set() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let pool = migrated_pool(&database).await;
        let store = PostgresPolicyTestSuiteStore::new(pool.clone());
        exercise_versioning(&store).await;
    }

    #[tokio::test]
    async fn postgres_racing_writers_produce_one_winner() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let pool = migrated_pool(&database).await;
        // Two initializers at once: the pointer insert's conflict decides.
        let left = PostgresPolicyTestSuiteStore::new(pool.clone());
        let right = PostgresPolicyTestSuiteStore::new(pool.clone());
        let (first_suite, second_suite, actor) = (suite("a"), suite("b"), writer());
        let (first, second) = tokio::join!(
            left.commit(PolicyTestSuitePrecondition::Absent, &first_suite, &actor),
            right.commit(PolicyTestSuitePrecondition::Absent, &second_suite, &actor),
        );
        assert_one_winner(&first, &second);
        let versions = rows(
            &pool,
            "SELECT count(*) FROM greengateway.policy_test_suite_active",
        )
        .await;
        assert_eq!(versions[0].get::<_, i64>(0), 1);
        // The loser's version row rolled back with its transaction.
        let stored = rows(
            &pool,
            "SELECT count(*) FROM greengateway.policy_test_suite_versions",
        )
        .await;
        assert_eq!(stored[0].get::<_, i64>(0), 1);
        drop((left, right));
        // Then writers replacing it under one ETag, each spawned on its own
        // pooled session.
        exercise_one_winner(Arc::new(PostgresPolicyTestSuiteStore::new(pool.clone()))).await;
    }

    #[tokio::test]
    async fn postgres_refuses_suites_it_must_not_store() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let pool = migrated_pool(&database).await;
        exercise_refusals(&PostgresPolicyTestSuiteStore::new(pool.clone())).await;
        let written = rows(
            &pool,
            "SELECT count(*) FROM greengateway.policy_test_suite_versions",
        )
        .await;
        assert_eq!(written[0].get::<_, i64>(0), 0);
    }

    /// A cluster commit is the shared versioned-document transaction: each
    /// write takes the next shared security revision, appends one outbox row
    /// and one evidence row naming the writer, and a refused one writes none
    /// of them. A read verifies the stored suite and refuses one edited out
    /// of band.
    #[tokio::test]
    async fn postgres_commits_record_revision_outbox_and_evidence() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let pool = migrated_pool(&database).await;
        let store = PostgresPolicyTestSuiteStore::new(pool.clone());

        let created = store
            .commit(
                PolicyTestSuitePrecondition::Absent,
                &suite("first"),
                &writer(),
            )
            .await
            .expect("the first suite stores");
        let replaced = store
            .commit(expected(&created), &suite("second"), &writer())
            .await
            .expect("the suite replaces");
        assert!(matches!(
            store
                .commit(expected(&created), &suite("stale"), &writer())
                .await,
            Err(PolicyTestSuiteCommitError::PreconditionFailed)
        ));
        let (first_revision, second_revision) = (
            created.security_revision.expect("cluster revision"),
            replaced.security_revision.expect("cluster revision"),
        );
        assert!(second_revision > first_revision);

        let outbox: Vec<(i64, String, Option<i64>, i64)> = rows(
            &pool,
            "SELECT revision, resource_type, from_version, to_version \
             FROM greengateway.security_outbox ORDER BY revision",
        )
        .await
        .iter()
        .map(|row| (row.get(0), row.get(1), row.get(2), row.get(3)))
        .collect();
        assert_eq!(
            outbox,
            vec![
                (
                    first_revision,
                    "policy_tests".to_owned(),
                    None,
                    created.version
                ),
                (
                    second_revision,
                    "policy_tests".to_owned(),
                    Some(created.version),
                    replaced.version
                ),
            ]
        );
        let revision = rows(
            &pool,
            "SELECT last_revision FROM greengateway.security_revision_state",
        )
        .await;
        assert_eq!(revision[0].get::<_, i64>(0), second_revision);

        type Evidence = (
            String,
            String,
            String,
            Option<String>,
            String,
            Option<i64>,
            i64,
            i64,
        );
        let evidence: Vec<Evidence> = rows(
            &pool,
            "SELECT action, resource_type, actor_user_id, actor_issuer, actor_auth_mode, \
                    prior_version, new_version, security_revision \
             FROM greengateway.document_change_evidence ORDER BY security_revision",
        )
        .await
        .iter()
        .map(|row| {
            (
                row.get(0),
                row.get(1),
                row.get(2),
                row.get(3),
                row.get(4),
                row.get(5),
                row.get(6),
                row.get(7),
            )
        })
        .collect();
        let row = |prior: Option<i64>, new: i64, revision: i64| {
            (
                "policy_tests.publish".to_owned(),
                "policy_tests".to_owned(),
                "suite-writer".to_owned(),
                Some("https://issuer.example.test".to_owned()),
                "session_cookie".to_owned(),
                prior,
                new,
                revision,
            )
        };
        assert_eq!(
            evidence,
            vec![
                row(None, created.version, first_revision),
                row(Some(created.version), replaced.version, second_revision),
            ]
        );
        // The version row is the history entry: counts, never cases.
        let summaries: Vec<String> = rows(
            &pool,
            "SELECT diff_summary::text FROM greengateway.policy_test_suite_versions \
             ORDER BY version",
        )
        .await
        .iter()
        .map(|row| row.get(0))
        .collect();
        assert_eq!(summaries.len(), 2);
        assert!(summaries[0].contains("policy_tests_created"));
        assert!(summaries[1].contains("policy_tests_replaced"));
        assert!(summaries.iter().all(|summary| !summary.contains("health")));

        let active = store.active().await.expect("read").expect("stored");
        assert_eq!(active.version, replaced.version);
        assert_eq!(active.security_revision, Some(second_revision));

        // Edited out of band: refused on read.
        pool.get()
            .await
            .expect("checkout")
            .execute(
                "UPDATE greengateway.policy_test_suite_versions \
                 SET document = jsonb_set(document, '{description}', '\"edited\"') \
                 WHERE version = $1",
                &[&replaced.version],
            )
            .await
            .expect("tamper");
        let error = store
            .active()
            .await
            .expect_err("an edited suite is refused");
        assert_eq!(error.kind(), RepositoryErrorKind::InvalidData);
    }
}
