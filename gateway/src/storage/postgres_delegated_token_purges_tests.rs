//! Verified-PostgreSQL tests for the delegated-token purge record (issue
//! #441). Gated on the test harness locator: CI sets it, a checkout without a
//! database skips.

use super::*;
use crate::storage::contract_tests::postgres_audit_tests::{
    create_test_database, locator, write_dsn_file, TestDatabase, DATABASE,
};
use crate::storage::{migrations, postgres::PostgresFoundation};

async fn migrated_pool(database: &TestDatabase) -> deadpool_postgres::Pool {
    let dsn_file = write_dsn_file(&database.dsn);
    let mut config = crate::config::Config::test_defaults();
    config.state_backend = crate::config::StateBackend::Postgres;
    config.deployment_id = Some("deploy-delegated-token-purges".to_owned());
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

async fn database() -> Option<(
    tokio::sync::MutexGuard<'static, ()>,
    TestDatabase,
    deadpool_postgres::Pool,
)> {
    let admin_dsn = locator()?;
    let guard = DATABASE.lock().await;
    let database = create_test_database(&admin_dsn).await;
    let pool = migrated_pool(&database).await;
    Some((guard, database, pool))
}

async fn bump_revision(pool: &deadpool_postgres::Pool) -> i64 {
    pool.get()
        .await
        .expect("checkout")
        .query_one(
            "UPDATE greengateway.security_revision_state \
             SET last_revision = last_revision + 1 WHERE singleton RETURNING last_revision",
            &[],
        )
        .await
        .expect("another resource's commit")
        .get(0)
}

fn key(fill: char) -> String {
    std::iter::repeat_n(fill, 64).collect()
}

/// A purge is one committed revision of the shared counter with one outbox
/// row naming only its key, and the readers see exactly the purges in the
/// range they ask about, oldest first.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_recorded_purge_takes_a_shared_revision_and_is_read_back_by_range() {
    let Some((_guard, _database, pool)) = database().await else {
        eprintln!("skipping: no test database locator; CI runs this test");
        return;
    };
    let store = PostgresDelegatedTokenPurgeStore::new(pool.clone());
    let before = store.frontier(0).await.expect("the frontier reads");
    assert_eq!(before.latest_purge, None, "nothing was purged yet");

    let first = store.record(&key('a')).await.expect("the purge records");
    assert_eq!(first, before.authority_revision + 1);
    let unrelated = bump_revision(&pool).await;
    let second = store.record(&key('b')).await.expect("the purge records");
    assert_eq!(second, unrelated + 1);

    let row = pool
        .get()
        .await
        .expect("checkout")
        .query_one(
            "SELECT resource_type, from_version, to_version, resource_id \
             FROM greengateway.security_outbox WHERE revision = $1",
            &[&first],
        )
        .await
        .expect("the outbox row exists");
    assert_eq!(row.get::<_, String>(0), RESOURCE_TYPE);
    assert_eq!(row.get::<_, Option<i64>>(1), None);
    assert_eq!(row.get::<_, i64>(2), 1);
    assert_eq!(row.get::<_, Option<String>>(3), Some(key('a')));

    let frontier = store.frontier(0).await.expect("the frontier reads");
    assert_eq!(frontier.authority_revision, second);
    assert_eq!(frontier.latest_purge, Some(second));
    let past_first = store.frontier(first).await.expect("the frontier reads");
    assert_eq!(past_first.latest_purge, Some(second));
    let past_both = store.frontier(second).await.expect("the frontier reads");
    assert_eq!(
        past_both.latest_purge, None,
        "nothing above the second purge"
    );

    let all = store
        .recorded_between(0, second, 16)
        .await
        .expect("the purges read");
    assert_eq!(
        all,
        vec![
            RecordedDelegatedTokenPurge {
                security_revision: first,
                purge_key: Some(key('a')),
            },
            RecordedDelegatedTokenPurge {
                security_revision: second,
                purge_key: Some(key('b')),
            },
        ],
        "another resource's revision between them is not a purge"
    );
    assert_eq!(
        store
            .recorded_between(0, second, 1)
            .await
            .expect("the purges read")
            .len(),
        1,
        "the limit bounds the read"
    );
    assert_eq!(
        store
            .recorded_between(first, first, 16)
            .await
            .expect("the purges read"),
        Vec::new(),
        "the lower bound is exclusive"
    );
}

/// A key of the wrong shape is refused before anything is written, and the
/// revision is not spent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_malformed_purge_key_is_refused_and_spends_nothing() {
    let Some((_guard, _database, pool)) = database().await else {
        eprintln!("skipping: no test database locator; CI runs this test");
        return;
    };
    let store = PostgresDelegatedTokenPurgeStore::new(pool);
    let before = store.frontier(0).await.expect("the frontier reads");
    for malformed in [String::new(), key('A'), key('g'), "ab".repeat(33)] {
        let refused = store
            .record(&malformed)
            .await
            .expect_err("a malformed key is refused");
        assert_eq!(refused.invalid_parameter_name(), Some("purge_key"));
    }
    assert_eq!(
        store.frontier(0).await.expect("the frontier reads"),
        before,
        "no revision was reserved"
    );
}
