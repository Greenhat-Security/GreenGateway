//! Verified-PostgreSQL contract tests for the cluster admin session store
//! (issue #424, ADR-0009). Gated on the test harness locator: CI sets it, a
//! checkout without a database skips.
//!
//! Two replicas are two stores over one database and share nothing else, so
//! everything one replica sees of another's sessions came through the rows.

use std::sync::{atomic::Ordering, Arc, LazyLock};

use http::{HeaderMap, Method};

use super::*;
use crate::auth::admin_session::{
    tests::{
        cookie_headers, front, is_invalid, is_unavailable, issue_across, read,
        run_session_contract, session_config, write, Authority, CSRF,
    },
    AdminSessionStorage, AdminSessions,
};
use crate::authority_events::{
    delivery::DeliveryRecord,
    dispatcher::{DispatcherConfig, DispatcherTerm},
    pseudonym::{test_support::generated_keyring, ReferenceDomain},
    sink::{AuthorityEventSink, SinkError},
};
use crate::cluster_maintenance::{AdminSessionPrune, MaintenanceJob};
use crate::storage::contract_tests::postgres_audit_tests::{
    create_test_database, locator, write_dsn_file, TestDatabase, DATABASE,
};
use crate::storage::{
    migrations, postgres::PostgresFoundation,
    postgres_authority_events::PostgresAuthorityEventStore,
    postgres_service_tokens::PostgresServiceTokenStore, ServiceTokenStore,
};

const DEPLOYMENT: &str = "deploy-session-contract";

/// The login key every replica of one test deployment shares, generated
/// when the tests run: no key material is committed.
static LOGIN_KEY: LazyLock<[u8; 32]> = LazyLock::new(fresh_key);

fn fresh_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    getrandom::fill(&mut key).expect("test key material");
    key
}

fn login_keyring() -> LocalSecretKeyring {
    LocalSecretKeyring::from_material_for_test(
        "login-key-1",
        vec![("login-key-1".to_owned(), *LOGIN_KEY)],
    )
}

async fn migrated_pool(database: &TestDatabase) -> deadpool_postgres::Pool {
    let dsn_file = write_dsn_file(&database.dsn);
    let mut config = crate::config::Config::test_defaults();
    config.state_backend = crate::config::StateBackend::Postgres;
    config.deployment_id = Some(DEPLOYMENT.to_owned());
    config.database.url_file = Some(dsn_file.path.clone());
    config.database.tls_mode = crate::config::DatabaseTlsMode::LoopbackDev;
    let foundation = PostgresFoundation::establish(&config)
        .await
        .expect("the test database should establish");
    migrations::apply_missing_for_startup(foundation.pool(), &config.database)
        .await
        .expect("the session schema should migrate");
    foundation.pool().clone()
}

/// One replica: its own store over the shared pool, its own front.
fn replica(
    authority: &Arc<Authority>,
    pool: &deadpool_postgres::Pool,
    config: AdminSessionConfig,
    keyring: LocalSecretKeyring,
) -> AdminSessions {
    let store = Arc::new(PostgresAdminSessionStore::new(
        pool.clone(),
        DEPLOYMENT,
        keyring,
        config.clone(),
    ));
    front(authority, store as Arc<dyn AdminSessionStore>, config)
}

fn cluster_config(max_entries: usize) -> AdminSessionConfig {
    session_config(AdminSessionStorage::ClusterPostgres, max_entries)
}

async fn count(pool: &deadpool_postgres::Pool, sql: &str) -> i64 {
    pool.get()
        .await
        .expect("checkout")
        .query_one(sql, &[])
        .await
        .expect("count query")
        .get(0)
}

async fn execute(pool: &deadpool_postgres::Pool, sql: &str) {
    pool.get()
        .await
        .expect("checkout")
        .batch_execute(sql)
        .await
        .expect("fixture statement");
}

fn cookie_value(sessions: &AdminSessions, headers: &HeaderMap) -> String {
    sessions.credential(headers).expect("a session cookie")
}

/// The row key of the session in `headers`, as the store writes it.
fn row_key(sessions: &AdminSessions, headers: &HeaderMap) -> String {
    hex::encode(sessions.session_key_for_test(&cookie_value(sessions, headers)))
}

/// A disposable, migrated database for one test, held under the shared
/// real-database lock; `None` when no locator is configured.
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

/// The same contract the memory store passes, across two replicas that
/// share only the database: a login begun on one completes on the other,
/// every request on either is revalidated and admitted on the database
/// clock, and every withdrawal on one is seen by the other on its next
/// request.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn postgres_admin_sessions_satisfy_the_session_contract() {
    let Some((_guard, _database, pool)) = database().await else {
        eprintln!("skipping: no test database locator; CI runs this test");
        return;
    };
    let authority = Arc::new(Authority::default());
    let a = replica(&authority, &pool, cluster_config(8), login_keyring());
    let b = replica(&authority, &pool, cluster_config(8), login_keyring());
    run_session_contract(&a, &b, &authority).await;
    assert_eq!(
        count(&pool, "SELECT count(*) FROM greengateway.admin_sessions").await,
        0,
        "every contract case withdraws the sessions it issued"
    );
}

/// Capacity is the deployment's, not a replica's, and is never met by
/// evicting a live session.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn postgres_admin_session_capacity_is_shared_by_replicas() {
    let Some((_guard, _database, pool)) = database().await else {
        eprintln!("skipping: no test database locator; CI runs this test");
        return;
    };
    let authority = Arc::new(Authority::default());
    let a = replica(&authority, &pool, cluster_config(1), login_keyring());
    let b = replica(&authority, &pool, cluster_config(1), login_keyring());
    crate::auth::admin_session::tests::contract_capacity_is_shared_and_never_evicts(
        &a, &b, &authority,
    )
    .await;
}

/// Two replicas granting the session that fills the last slot at once:
/// exactly one is admitted, because admissions serialize on one lock.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_grants_never_exceed_the_shared_capacity() {
    let Some((_guard, _database, pool)) = database().await else {
        eprintln!("skipping: no test database locator; CI runs this test");
        return;
    };
    let authority = Arc::new(Authority::default());
    let a = replica(&authority, &pool, cluster_config(2), login_keyring());
    let b = replica(&authority, &pool, cluster_config(2), login_keyring());
    let first = cookie_headers(&issue_across(&a, &b, &HeaderMap::new()).await.unwrap());
    read(&a, &first).await.unwrap();
    for binding in ["race-a", "race-b"] {
        a.begin_login(binding, Duration::from_secs(30), &HeaderMap::new())
            .await
            .unwrap();
    }
    let grant = |sessions: AdminSessions, binding: &'static str| {
        tokio::spawn(async move {
            sessions
                .issue(
                    uuid::Uuid::new_v4().to_string(),
                    &HeaderMap::new(),
                    binding,
                    CSRF,
                )
                .await
        })
    };
    let (left, right) = tokio::join!(grant(a.clone(), "race-a"), grant(b.clone(), "race-b"));
    let outcomes = [left.unwrap(), right.unwrap()];
    assert_eq!(
        outcomes.iter().filter(|outcome| outcome.is_ok()).count(),
        1,
        "exactly one grant fills the last slot: {outcomes:?}"
    );
    assert!(outcomes
        .iter()
        .any(|outcome| matches!(outcome, Err(AuthError::Upstream(_)))));
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM greengateway.admin_sessions \
             WHERE idle_expires_at > clock_timestamp()"
        )
        .await,
        2
    );
}

/// Both deadlines are the database's. Use moves the idle deadline and never
/// the absolute one; past either, the session is refused without asking the
/// provider, and the bounded prune withdraws it with evidence.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sessions_expire_idle_and_absolute_on_the_database_clock() {
    let Some((_guard, _database, pool)) = database().await else {
        eprintln!("skipping: no test database locator; CI runs this test");
        return;
    };
    let authority = Arc::new(Authority::default());
    let mut config = cluster_config(8);
    config.idle_timeout = Duration::from_secs(20);
    let a = replica(&authority, &pool, config.clone(), login_keyring());
    let b = replica(&authority, &pool, config, login_keyring());

    // Both sessions exist before either expires: every admission prunes
    // what has already expired, and this test watches the rows directly.
    let idle = cookie_headers(&issue_across(&a, &a, &HeaderMap::new()).await.unwrap());
    let absolute = cookie_headers(&issue_across(&b, &a, &HeaderMap::new()).await.unwrap());
    let key = row_key(&a, &idle);
    let deadlines = |key: String| {
        let pool = pool.clone();
        async move {
            let row = pool
                .get()
                .await
                .expect("checkout")
                .query_one(
                    "SELECT (expires_at - created_at) > (idle_expires_at - created_at), \
                            idle_expires_at = expires_at \
                     FROM greengateway.admin_sessions WHERE session_hash = $1",
                    &[&key],
                )
                .await
                .expect("the session row");
            (row.get::<_, bool>(0), row.get::<_, bool>(1))
        }
    };
    assert_eq!(
        deadlines(key.clone()).await,
        (true, false),
        "the idle limit binds first"
    );
    // Each fixture reads the database clock once and derives every deadline
    // it writes from that one reading: two clock_timestamp() calls in one
    // statement are microseconds apart, and the table's CHECK
    // (idle_expires_at <= expires_at) must hold however they fall.
    execute(
        &pool,
        &format!(
            "UPDATE greengateway.admin_sessions \
             SET idle_expires_at = clock.now + interval '1 second', \
                 expires_at = clock.now + interval '5 seconds' \
             FROM (SELECT clock_timestamp() AS now) AS clock \
             WHERE session_hash = '{key}'"
        ),
    )
    .await;
    read(&b, &idle).await.unwrap();
    assert!(
        deadlines(key.clone()).await.1,
        "use moves the idle deadline up to the absolute one and no further"
    );
    execute(
        &pool,
        &format!(
            "UPDATE greengateway.admin_sessions \
             SET idle_expires_at = clock.now - interval '1 millisecond', \
                 expires_at = GREATEST(expires_at, clock.now + interval '5 seconds') \
             FROM (SELECT clock_timestamp() AS now) AS clock \
             WHERE session_hash = '{key}'"
        ),
    )
    .await;
    let calls = authority.calls.load(Ordering::SeqCst);
    assert!(is_invalid(&read(&a, &idle).await));
    assert!(is_invalid(&read(&b, &idle).await));
    assert_eq!(
        authority.calls.load(Ordering::SeqCst),
        calls,
        "an expired session is refused before the provider is asked"
    );

    let absolute_key = row_key(&a, &absolute);
    execute(
        &pool,
        &format!(
            "UPDATE greengateway.admin_sessions \
             SET created_at = clock.now - interval '2 hours', \
                 expires_at = clock.now - interval '1 second', \
                 idle_expires_at = clock.now - interval '1 second' \
             FROM (SELECT clock_timestamp() AS now) AS clock \
             WHERE session_hash = '{absolute_key}'"
        ),
    )
    .await;
    assert!(is_invalid(&read(&a, &absolute).await));

    // Neither expired row is gone until a prune withdraws it: a refused
    // request deletes nothing.
    assert_eq!(
        count(&pool, "SELECT count(*) FROM greengateway.admin_sessions").await,
        2
    );
    let client = pool.get().await.expect("checkout");
    let job = AdminSessionPrune { limit: 1_000 };
    assert_eq!(job.run_step(&client).await.expect("prune step"), 2);
    assert_eq!(job.run_step(&client).await.expect("prune step"), 0);
    assert_eq!(
        count(&pool, "SELECT count(*) FROM greengateway.admin_sessions").await,
        0
    );
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM greengateway.admin_session_evidence \
             WHERE action = 'admin_session.withdraw' AND reason = 'expired'"
        )
        .await,
        2
    );
}

/// No secret the browser holds is in a row, and the access token is
/// sealed: a database reader learns nothing to present, and a row moved,
/// tampered with, or sealed under a key this replica lacks is a dependency
/// failure, not a sign-in prompt.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nothing_the_browser_holds_is_stored_and_the_token_is_sealed() {
    let Some((_guard, _database, pool)) = database().await else {
        eprintln!("skipping: no test database locator; CI runs this test");
        return;
    };
    let authority = Arc::new(Authority::default());
    let a = replica(&authority, &pool, cluster_config(8), login_keyring());
    a.begin_login(
        "browser-binding",
        Duration::from_secs(30),
        &HeaderMap::new(),
    )
    .await
    .unwrap();
    let token = format!("access-token-{}", uuid::Uuid::new_v4());
    let first = cookie_headers(
        &a.issue(token.clone(), &HeaderMap::new(), "browser-binding", CSRF)
            .await
            .unwrap(),
    );
    let cookie = cookie_value(&a, &first);
    let rows = pool
        .get()
        .await
        .expect("checkout")
        .query(
            "SELECT row_to_json(s)::text FROM greengateway.admin_sessions s \
             UNION ALL SELECT row_to_json(l)::text FROM greengateway.admin_session_logins l \
             UNION ALL SELECT row_to_json(e)::text FROM greengateway.admin_session_evidence e",
            &[],
        )
        .await
        .expect("rows");
    assert!(rows.len() >= 3, "a session, its login and its grant");
    let hex_of = |value: &str| hex::encode(value.as_bytes());
    for row in &rows {
        let row: String = row.get(0);
        for secret in [cookie.as_str(), CSRF, "browser-binding", token.as_str()] {
            assert!(!row.contains(secret), "{row} contains {secret}");
            assert!(!row.contains(&hex_of(secret)), "{row} contains {secret}");
        }
    }
    let sealed: (String, i32) = {
        let row = pool
            .get()
            .await
            .expect("checkout")
            .query_one(
                "SELECT key_id, octet_length(token_ct) FROM greengateway.admin_sessions",
                &[],
            )
            .await
            .expect("the session row");
        (row.get(0), row.get(1))
    };
    assert_eq!(sealed.0, "login-key-1");
    assert_eq!(sealed.1 as usize, token.len() + 16, "ciphertext plus tag");

    // A ciphertext moved to another row does not open there.
    let second = cookie_headers(&issue_across(&a, &a, &HeaderMap::new()).await.unwrap());
    let (first_key, second_key) = (row_key(&a, &first), row_key(&a, &second));
    execute(
        &pool,
        &format!(
            "WITH f AS (SELECT token_nonce, token_ct FROM greengateway.admin_sessions \
                        WHERE session_hash = '{first_key}'), \
                  s AS (SELECT token_nonce, token_ct FROM greengateway.admin_sessions \
                        WHERE session_hash = '{second_key}'), \
                  swap AS (UPDATE greengateway.admin_sessions SET token_nonce = s.token_nonce, \
                           token_ct = s.token_ct FROM s WHERE session_hash = '{first_key}') \
             UPDATE greengateway.admin_sessions SET token_nonce = f.token_nonce, \
                    token_ct = f.token_ct FROM f WHERE session_hash = '{second_key}'"
        ),
    )
    .await;
    assert!(is_unavailable(&read(&a, &first).await));
    assert!(is_unavailable(&read(&a, &second).await));
    assert_eq!(
        count(&pool, "SELECT count(*) FROM greengateway.admin_sessions").await,
        2,
        "a row that cannot be opened is not withdrawn as if it were rejected"
    );
    // Logout needs no keyring: it withdraws by digest.
    a.revoke(&first, None).await.unwrap();
    a.revoke(&second, None).await.unwrap();

    // A key this replica does not hold is a dependency failure too ...
    let third = cookie_headers(&issue_across(&a, &a, &HeaderMap::new()).await.unwrap());
    let third_key = row_key(&a, &third);
    execute(
        &pool,
        &format!(
            "UPDATE greengateway.admin_sessions SET key_id = 'someone-elses-key' \
             WHERE session_hash = '{third_key}'"
        ),
    )
    .await;
    assert!(is_unavailable(&read(&a, &third).await));
    a.revoke(&third, None).await.unwrap();

    // ... while a rotated ring that keeps the old key opens what it sealed,
    // and seals new sessions under its new primary.
    let before_rotation = cookie_headers(&issue_across(&a, &a, &HeaderMap::new()).await.unwrap());
    let rotated = replica(
        &authority,
        &pool,
        cluster_config(8),
        LocalSecretKeyring::from_material_for_test(
            "login-key-2",
            vec![
                ("login-key-1".to_owned(), *LOGIN_KEY),
                ("login-key-2".to_owned(), fresh_key()),
            ],
        ),
    );
    read(&rotated, &before_rotation).await.unwrap();
    let after_rotation = cookie_headers(
        &issue_across(&rotated, &rotated, &HeaderMap::new())
            .await
            .unwrap(),
    );
    let after_key = row_key(&rotated, &after_rotation);
    assert_eq!(
        pool.get()
            .await
            .expect("checkout")
            .query_one(
                "SELECT key_id FROM greengateway.admin_sessions WHERE session_hash = $1",
                &[&after_key],
            )
            .await
            .expect("the rotated session")
            .get::<_, String>(0),
        "login-key-2"
    );
    assert!(
        is_unavailable(&read(&a, &after_rotation).await),
        "a replica without the new key cannot vouch for the session"
    );
}

/// Every grant and every withdrawal leaves exactly one evidence row, in the
/// change's own transaction: the identity, the absolute deadline and a
/// reason, never a credential. A replacement's withdrawal and grant share
/// one operation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_grant_and_withdrawal_leaves_one_evidence_row() {
    let Some((_guard, _database, pool)) = database().await else {
        eprintln!("skipping: no test database locator; CI runs this test");
        return;
    };
    let authority = Arc::new(Authority::default());
    let a = replica(&authority, &pool, cluster_config(8), login_keyring());
    let b = replica(&authority, &pool, cluster_config(8), login_keyring());

    // logout
    let logged_out = cookie_headers(&issue_across(&a, &b, &HeaderMap::new()).await.unwrap());
    let logged_out_id = read(&a, &logged_out).await.unwrap().session_id;
    b.revoke(&logged_out, None).await.unwrap();
    b.revoke(&logged_out, None).await.unwrap();
    // replaced
    let replaced = cookie_headers(&issue_across(&a, &a, &HeaderMap::new()).await.unwrap());
    let replaced_id = read(&b, &replaced).await.unwrap().session_id;
    let replacement = cookie_headers(&issue_across(&b, &a, &replaced).await.unwrap());
    let replacement_id = read(&b, &replacement).await.unwrap().session_id;
    // rejected
    authority.outcome.store(3, Ordering::SeqCst);
    assert!(is_invalid(&read(&a, &replacement).await));
    authority.outcome.store(0, Ordering::SeqCst);
    // logout by binding, before the cookie was ever presented
    a.begin_login("undelivered", Duration::from_secs(30), &HeaderMap::new())
        .await
        .unwrap();
    a.issue(
        uuid::Uuid::new_v4().to_string(),
        &HeaderMap::new(),
        "undelivered",
        CSRF,
    )
    .await
    .unwrap();
    b.revoke(&HeaderMap::new(), Some("undelivered"))
        .await
        .unwrap();
    // expired: a session already past its deadline when the browser signs
    // in again was not replaced
    let stale = cookie_headers(&issue_across(&a, &a, &HeaderMap::new()).await.unwrap());
    let stale_id = read(&a, &stale).await.unwrap().session_id;
    execute(
        &pool,
        &format!(
            "UPDATE greengateway.admin_sessions              SET idle_expires_at = clock_timestamp() - interval '1 second'              WHERE session_hash = '{}'",
            row_key(&a, &stale)
        ),
    )
    .await;
    let after_stale = cookie_headers(&issue_across(&b, &a, &stale).await.unwrap());
    b.revoke(&after_stale, None).await.unwrap();

    let evidence = |sql: &'static str| {
        let pool = pool.clone();
        async move {
            pool.get()
                .await
                .expect("checkout")
                .query(sql, &[])
                .await
                .expect("evidence")
                .iter()
                .map(|row| (row.get::<_, String>(0), row.get::<_, String>(1)))
                .collect::<Vec<_>>()
        }
    };
    let mut reasons = evidence(
        "SELECT action, reason FROM greengateway.admin_session_evidence ORDER BY action, reason",
    )
    .await;
    reasons.sort();
    let grant = || ("admin_session.grant".to_owned(), "issued".to_owned());
    let withdraw = |reason: &str| ("admin_session.withdraw".to_owned(), reason.to_owned());
    assert_eq!(
        reasons,
        vec![
            grant(),
            grant(),
            grant(),
            grant(),
            grant(),
            grant(),
            withdraw("expired"),
            withdraw("logout"),
            withdraw("logout"),
            withdraw("logout"),
            withdraw("rejected"),
            withdraw("replaced"),
        ],
        "a repeat logout writes nothing"
    );
    let for_session = |id: String| {
        let pool = pool.clone();
        async move {
            pool.get()
                .await
                .expect("checkout")
                .query(
                    "SELECT action || ':' || reason, operation_id::text, user_id, \
                            coalesce(issuer, ''), (expires_at > committed_at)::text \
                     FROM greengateway.admin_session_evidence \
                     WHERE session_id = $1::text::uuid ORDER BY committed_at, action",
                    &[&id],
                )
                .await
                .expect("evidence for one session")
                .iter()
                .map(|row| {
                    (0..5)
                        .map(|column| row.get::<_, String>(column))
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>()
        }
    };
    let logged_out_rows = for_session(logged_out_id).await;
    assert_eq!(logged_out_rows.len(), 2);
    assert_eq!(logged_out_rows[0][0], "admin_session.grant:issued");
    assert_eq!(logged_out_rows[1][0], "admin_session.withdraw:logout");
    for row in &logged_out_rows {
        assert_eq!(row[2], "operator");
        assert_eq!(row[3], "https://issuer.example.test");
        assert_eq!(row[4], "true", "the absolute deadline is after the change");
    }
    let replaced_rows = for_session(replaced_id).await;
    let replacement_rows = for_session(replacement_id).await;
    assert_eq!(replaced_rows[1][0], "admin_session.withdraw:replaced");
    assert_eq!(replacement_rows[0][0], "admin_session.grant:issued");
    assert_eq!(
        replaced_rows[1][1], replacement_rows[0][1],
        "one sign-in, one operation: the replacement and its grant"
    );
    assert_eq!(replacement_rows[1][0], "admin_session.withdraw:rejected");
    let stale_rows = for_session(stale_id).await;
    assert_eq!(
        stale_rows
            .iter()
            .map(|row| row[0].as_str())
            .collect::<Vec<_>>(),
        [
            "admin_session.grant:issued",
            "admin_session.withdraw:expired"
        ]
    );
    assert_eq!(
        count(&pool, "SELECT count(*) FROM greengateway.admin_sessions").await,
        0,
        "the evidence outlives every session it describes"
    );

    // Every evidence row is journaled under its own event ID, at a gapless
    // position, and every unit a grant held was spent by its withdrawal.
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM greengateway.admin_session_evidence e \
             JOIN greengateway.authority_event_journal j \
               ON j.event_id = e.event_id AND j.source = 'admin_session_evidence'"
        )
        .await,
        12
    );
    assert_eq!(
        journal_state(&pool).await,
        JournalState {
            head: 12,
            in_use: 12,
            held: 0,
            rows: 12
        }
    );
}

/// The journal's state row as the tests read it: the last position, the
/// units in use, the units held for withdrawals, and the rows retained.
#[derive(Debug, PartialEq, Eq)]
struct JournalState {
    head: i64,
    in_use: i64,
    held: i64,
    rows: i64,
}

async fn journal_state(pool: &deadpool_postgres::Pool) -> JournalState {
    let row = pool
        .get()
        .await
        .expect("checkout")
        .query_one(
            "SELECT last_position, retained_events, reserved_withdrawals, \
                    (SELECT count(*) FROM greengateway.authority_event_journal) \
             FROM greengateway.authority_event_state WHERE singleton",
            &[],
        )
        .await
        .expect("the journal state");
    JournalState {
        head: row.get(0),
        in_use: row.get(1),
        held: row.get(2),
        rows: row.get(3),
    }
}

/// Takes every batch it is offered.
#[derive(Default)]
struct CollectingSink {
    records: std::sync::Mutex<Vec<DeliveryRecord>>,
}

#[async_trait]
impl AuthorityEventSink for CollectingSink {
    fn kind(&self) -> &'static str {
        "collecting"
    }

    async fn deliver(&self, batch: &[DeliveryRecord]) -> Result<(), SinkError> {
        self.records
            .lock()
            .expect("sink lock")
            .extend_from_slice(batch);
        Ok(())
    }
}

/// The capacity decision (migration 26): a grant holds a unit for its own
/// withdrawal, so a full journal refuses new grants -- and every other
/// journaled change -- with `503` and commits nothing, but never a
/// withdrawal. Logout, a provider rejection and the expiry prune all commit
/// with their evidence journaled while the journal is full, no other
/// producer can spend a unit a session holds, and room comes back only
/// through delivery and retention, after which the refused grant completes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_journal_refuses_grants_but_never_a_withdrawal() {
    let Some((_guard, _database, pool)) = database().await else {
        eprintln!("skipping: no test database locator; CI runs this test");
        return;
    };
    let authority = Arc::new(Authority::default());
    let a = replica(&authority, &pool, cluster_config(8), login_keyring());
    let b = replica(&authority, &pool, cluster_config(8), login_keyring());
    let journal = Arc::new(PostgresAuthorityEventStore::new(pool.clone()));
    journal
        .configure_capacity(7)
        .await
        .expect("capacity applies");
    let tokens = PostgresServiceTokenStore::new(pool.clone());
    let token = tokens
        .create(crate::auth::tokens::CreateTokenRequest {
            scopes: vec!["admin:tokens:read".to_owned()],
            created_by: "creating-admin".to_owned(),
            expires_at: None,
        })
        .await
        .expect("a create journals nothing")
        .record
        .id;
    let actor = crate::auth::change_actor::ChangeActor::for_test("rotating-admin");

    // Three sessions take two units each, and a token rotate the last one.
    let logged_out = cookie_headers(&issue_across(&a, &b, &HeaderMap::new()).await.unwrap());
    let rejected = cookie_headers(&issue_across(&a, &a, &HeaderMap::new()).await.unwrap());
    let expiring = cookie_headers(&issue_across(&b, &b, &HeaderMap::new()).await.unwrap());
    assert_eq!(
        journal_state(&pool).await,
        JournalState {
            head: 3,
            in_use: 6,
            held: 3,
            rows: 3
        }
    );
    tokens
        .rotate(&token, &actor)
        .await
        .expect("the last unit is not held")
        .expect("the token exists");
    let full = JournalState {
        head: 4,
        in_use: 7,
        held: 3,
        rows: 4,
    };
    assert_eq!(journal_state(&pool).await, full);

    // Full: a grant is refused as a dependency failure and leaves nothing --
    // no session, no evidence, no journal row -- and neither the token's
    // revoke nor anything else can spend the units the sessions hold.
    let sessions = || count(&pool, "SELECT count(*) FROM greengateway.admin_sessions");
    let evidence = || {
        count(
            &pool,
            "SELECT count(*) FROM greengateway.admin_session_evidence",
        )
    };
    a.begin_login("refused", Duration::from_secs(60), &HeaderMap::new())
        .await
        .unwrap();
    assert!(matches!(
        b.issue(
            uuid::Uuid::new_v4().to_string(),
            &HeaderMap::new(),
            "refused",
            CSRF
        )
        .await,
        Err(AuthError::Upstream(_))
    ));
    assert_eq!((sessions().await, evidence().await), (3, 3));
    assert_eq!(journal_state(&pool).await, full);
    let error = tokens
        .revoke(&token, &actor)
        .await
        .expect_err("a full journal refuses the revoke");
    assert_eq!(error.kind(), RepositoryErrorKind::Unavailable);
    assert_eq!(journal_state(&pool).await, full);

    // Every kind of withdrawal still commits, journaled, each spending the
    // unit its grant held: logout, a rejection, and the expiry prune.
    b.revoke(&logged_out, None).await.unwrap();
    assert!(is_invalid(&read(&a, &logged_out).await));
    authority.outcome.store(3, Ordering::SeqCst);
    assert!(is_invalid(&read(&b, &rejected).await));
    authority.outcome.store(0, Ordering::SeqCst);
    execute(
        &pool,
        &format!(
            "UPDATE greengateway.admin_sessions \
             SET idle_expires_at = clock_timestamp() - interval '1 second' \
             WHERE session_hash = '{}'",
            row_key(&b, &expiring)
        ),
    )
    .await;
    let client = pool.get().await.expect("maintenance session");
    let job = AdminSessionPrune { limit: 1_000 };
    assert_eq!(job.run_step(&client).await.expect("prune step"), 1);
    assert_eq!(sessions().await, 0);
    let mut reasons = pool
        .get()
        .await
        .expect("checkout")
        .query(
            "SELECT e.reason FROM greengateway.admin_session_evidence e \
             JOIN greengateway.authority_event_journal j ON j.event_id = e.event_id \
             WHERE e.action = 'admin_session.withdraw'",
            &[],
        )
        .await
        .expect("journaled withdrawals")
        .iter()
        .map(|row| row.get::<_, String>(0))
        .collect::<Vec<_>>();
    reasons.sort();
    assert_eq!(reasons, ["expired", "logout", "rejected"]);
    let spent = JournalState {
        head: 7,
        in_use: 7,
        held: 0,
        rows: 7,
    };
    assert_eq!(journal_state(&pool).await, spent);
    // Still full, so the refused grant is still refused.
    assert!(matches!(
        b.issue(
            uuid::Uuid::new_v4().to_string(),
            &HeaderMap::new(),
            "refused",
            CSRF
        )
        .await,
        Err(AuthError::Upstream(_))
    ));

    // The dispatcher delivers every session event in commit order, keyed
    // and without any identifier the evidence holds.
    let keyring = Arc::new(generated_keyring(
        journal
            .authority_id(uuid::Uuid::new_v4())
            .await
            .expect("the authority ID persists"),
    ));
    let sink = Arc::new(CollectingSink::default());
    let mut term = DispatcherTerm::begin(
        Arc::clone(&journal),
        Arc::clone(&sink) as Arc<dyn AuthorityEventSink>,
        Arc::clone(&keyring),
        DispatcherConfig::default(),
        1,
        uuid::Uuid::new_v4(),
    )
    .await
    .expect("the cursor claims");
    assert_eq!(
        term.deliver_until_caught_up(&tokio_util::sync::CancellationToken::new())
            .await
            .expect("delivery succeeds"),
        Some(7)
    );
    let delivered = sink.records.lock().expect("sink lock").clone();
    let operations: Vec<&str> = delivered
        .iter()
        .map(|record| record.operation.as_str())
        .collect();
    assert_eq!(
        operations,
        [
            "admin_session.grant",
            "admin_session.grant",
            "admin_session.grant",
            "service_token.rotate",
            "admin_session.withdraw",
            "admin_session.withdraw",
            "admin_session.withdraw",
        ]
    );
    let session_ids = pool
        .get()
        .await
        .expect("checkout")
        .query(
            "SELECT session_id::text FROM greengateway.admin_session_evidence",
            &[],
        )
        .await
        .expect("session IDs")
        .iter()
        .map(|row| row.get::<_, String>(0))
        .collect::<Vec<_>>();
    let operator_ref = keyring
        .derive(ReferenceDomain::ActorRecorded, &["operator"])
        .expect("a recorded actor reference derives");
    for record in delivered
        .iter()
        .filter(|record| record.resource.kind == "admin_session")
    {
        assert_eq!(record.actor.recorded_ref, operator_ref.as_str());
        assert_eq!(
            (
                record.actor.kind.as_deref(),
                record.actor.auth_mode.as_deref()
            ),
            (None, None)
        );
        assert_eq!(record.revision.axis, "session");
        assert_eq!(record.revision.security, None);
        let serialized = serde_json::to_string(record).expect("serializes");
        for identifier in session_ids
            .iter()
            .map(String::as_str)
            .chain(["operator", "https://issuer.example.test"])
        {
            assert!(!serialized.contains(identifier), "{serialized}");
        }
    }

    // Retention frees the delivered rows -- never a held unit -- and the
    // refused grant completes.
    assert_eq!(
        PostgresAuthorityEventStore::prune_with(&client, Duration::ZERO, 1_000)
            .await
            .expect("retention runs"),
        7
    );
    b.issue(
        uuid::Uuid::new_v4().to_string(),
        &HeaderMap::new(),
        "refused",
        CSRF,
    )
    .await
    .expect("room for the grant and its withdrawal");
    assert_eq!(
        journal_state(&pool).await,
        JournalState {
            head: 8,
            in_use: 2,
            held: 1,
            rows: 1
        }
    );
}

/// A withdrawal is never refused for capacity, but it is still refused when
/// its journal row cannot be written at all: the session stays, nothing is
/// half-recorded, and the front answers a dependency failure rather than
/// "signed out". The same holds for the expiry prune.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_withdrawal_whose_journal_row_cannot_be_written_does_not_happen() {
    let Some((_guard, _database, pool)) = database().await else {
        eprintln!("skipping: no test database locator; CI runs this test");
        return;
    };
    let authority = Arc::new(Authority::default());
    let a = replica(&authority, &pool, cluster_config(8), login_keyring());
    let held = cookie_headers(&issue_across(&a, &a, &HeaderMap::new()).await.unwrap());
    let doomed = cookie_headers(&issue_across(&a, &a, &HeaderMap::new()).await.unwrap());
    execute(
        &pool,
        &format!(
            "UPDATE greengateway.admin_sessions \
             SET idle_expires_at = clock_timestamp() - interval '1 second' \
             WHERE session_hash = '{}'",
            row_key(&a, &doomed)
        ),
    )
    .await;
    let before = journal_state(&pool).await;
    execute(
        &pool,
        "ALTER TABLE greengateway.authority_event_journal \
         ADD CONSTRAINT refuse_for_test CHECK (false) NOT VALID",
    )
    .await;
    assert!(matches!(
        a.revoke(&held, None).await,
        Err(AuthError::Upstream(_))
    ));
    authority.outcome.store(3, Ordering::SeqCst);
    assert!(is_unavailable(&read(&a, &held).await));
    authority.outcome.store(0, Ordering::SeqCst);
    let client = pool.get().await.expect("maintenance session");
    assert!(AdminSessionPrune { limit: 1_000 }
        .run_step(&client)
        .await
        .is_err());
    execute(
        &pool,
        "ALTER TABLE greengateway.authority_event_journal DROP CONSTRAINT refuse_for_test",
    )
    .await;
    assert_eq!(
        count(&pool, "SELECT count(*) FROM greengateway.admin_sessions").await,
        2,
        "neither the logout, the rejection nor the prune changed anything"
    );
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM greengateway.admin_session_evidence \
             WHERE action = 'admin_session.withdraw'"
        )
        .await,
        0
    );
    assert_eq!(journal_state(&pool).await, before);
    read(&a, &held).await.unwrap();
    a.revoke(&held, None).await.unwrap();
}

/// A change whose evidence cannot be written does not happen, and is a
/// dependency failure rather than a verdict.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_evidence_insert_rolls_the_change_back() {
    let Some((_guard, _database, pool)) = database().await else {
        eprintln!("skipping: no test database locator; CI runs this test");
        return;
    };
    let authority = Arc::new(Authority::default());
    let a = replica(&authority, &pool, cluster_config(8), login_keyring());
    let held = cookie_headers(&issue_across(&a, &a, &HeaderMap::new()).await.unwrap());
    a.begin_login("blocked", Duration::from_secs(30), &HeaderMap::new())
        .await
        .unwrap();
    execute(
        &pool,
        "ALTER TABLE greengateway.admin_session_evidence \
         ADD CONSTRAINT refuse_for_test CHECK (false) NOT VALID",
    )
    .await;
    assert!(matches!(
        a.issue(
            uuid::Uuid::new_v4().to_string(),
            &HeaderMap::new(),
            "blocked",
            CSRF
        )
        .await,
        Err(AuthError::Upstream(_))
    ));
    assert!(matches!(
        a.revoke(&held, None).await,
        Err(AuthError::Upstream(_))
    ));
    authority.outcome.store(1, Ordering::SeqCst);
    assert!(is_unavailable(&read(&a, &held).await));
    authority.outcome.store(0, Ordering::SeqCst);
    execute(
        &pool,
        "ALTER TABLE greengateway.admin_session_evidence DROP CONSTRAINT refuse_for_test",
    )
    .await;
    assert_eq!(
        count(&pool, "SELECT count(*) FROM greengateway.admin_sessions").await,
        1,
        "neither the grant, the logout nor the rejection changed anything"
    );
    read(&a, &held).await.unwrap();
    // The refused grant left its login pending, so it can still complete.
    a.issue(
        uuid::Uuid::new_v4().to_string(),
        &HeaderMap::new(),
        "blocked",
        CSRF,
    )
    .await
    .unwrap();
}

/// The singleton's step and each admission prune only what is already dead,
/// a bounded number of rows at a time, and need no keyring.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_prune_is_bounded_and_spares_live_rows() {
    let Some((_guard, _database, pool)) = database().await else {
        eprintln!("skipping: no test database locator; CI runs this test");
        return;
    };
    let authority = Arc::new(Authority::default());
    let a = replica(&authority, &pool, cluster_config(16), login_keyring());
    // Every row exists before any expires: each admission prunes what has
    // already expired, and this test runs the prune itself.
    let mut live = Vec::new();
    let mut doomed = Vec::new();
    for index in 0..7 {
        let headers = cookie_headers(&issue_across(&a, &a, &HeaderMap::new()).await.unwrap());
        if index < 4 {
            live.push(headers);
        } else {
            doomed.push(row_key(&a, &headers));
        }
    }
    for binding in ["abandoned-1", "abandoned-2", "abandoned-3"] {
        a.begin_login(binding, Duration::from_secs(30), &HeaderMap::new())
            .await
            .unwrap();
    }
    for key in &doomed {
        execute(
            &pool,
            &format!(
                "UPDATE greengateway.admin_sessions \
                 SET idle_expires_at = clock_timestamp() - interval '1 second' \
                 WHERE session_hash = '{key}'"
            ),
        )
        .await;
    }
    execute(
        &pool,
        "UPDATE greengateway.admin_session_logins \
         SET expires_at = clock_timestamp() - interval '1 second' \
         WHERE issued_session_hash IS NULL",
    )
    .await;
    let client = pool.get().await.expect("checkout");
    // The seven sessions were never presented, so seven logins still track
    // them; an expired session's login goes with it, uncounted. One step
    // removes at most two expired sessions and two expired logins.
    let mut removed = Vec::new();
    loop {
        let step = PostgresAdminSessionStore::prune_expired_with(&client, 2)
            .await
            .expect("bounded prune");
        removed.push(step);
        if step == 0 {
            break;
        }
    }
    assert_eq!(removed, [4, 2, 0]);
    for headers in &live {
        read(&a, headers).await.unwrap();
    }
    assert_eq!(
        count(&pool, "SELECT count(*) FROM greengateway.admin_sessions").await,
        4
    );
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM greengateway.admin_session_evidence WHERE reason = 'expired'"
        )
        .await,
        3
    );
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM greengateway.admin_session_logins"
        )
        .await,
        0,
        "presenting the live sessions released their logins"
    );
}

/// The schema holds the invariants the store relies on, whatever writes to
/// it: digests only, the idle deadline never past the absolute one, and a
/// closed evidence vocabulary with one row per session and action.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_schema_refuses_rows_that_break_the_session_invariants() {
    let Some((_guard, _database, pool)) = database().await else {
        eprintln!("skipping: no test database locator; CI runs this test");
        return;
    };
    let client = pool.get().await.expect("checkout");
    let insert_session = |hash: &str, idle: &str| {
        format!(
            "INSERT INTO greengateway.admin_sessions (session_hash, id, csrf_hash, user_id, \
                 issuer, key_id, token_nonce, token_ct, created_at, last_seen_at, expires_at, \
                 idle_expires_at) \
             VALUES ('{hash}', '{}', repeat('c', 64), 'operator', NULL, 'k', \
                     decode(repeat('00', 24), 'hex'), decode(repeat('00', 17), 'hex'), \
                     now(), now(), now() + interval '1 hour', now() + interval '{idle}')",
            uuid::Uuid::new_v4()
        )
    };
    client
        .batch_execute(&insert_session(&"a".repeat(64), "1 hour"))
        .await
        .expect("a well-formed row");
    for refused in [
        insert_session(&"b".repeat(64), "2 hours"),
        insert_session("not-a-digest", "1 hour"),
        insert_session(&"B".repeat(64), "1 hour"),
    ] {
        assert!(client.batch_execute(&refused).await.is_err(), "{refused}");
    }
    let insert_evidence = |session: &str, action: &str, reason: &str| {
        format!(
            "INSERT INTO greengateway.admin_session_evidence (event_id, operation_id, \
                 session_id, action, reason, user_id, issuer, expires_at) \
             VALUES ('{}', '{}', '{session}', '{action}', '{reason}', 'operator', NULL, now())",
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4()
        )
    };
    let session = uuid::Uuid::new_v4().to_string();
    client
        .batch_execute(&insert_evidence(&session, "admin_session.grant", "issued"))
        .await
        .expect("a grant");
    for (action, reason) in [
        ("admin_session.grant", "issued"),
        ("admin_session.grant", "logout"),
        ("admin_session.withdraw", "issued"),
        ("admin_session.withdraw", "evicted"),
        ("admin_session.renew", "issued"),
    ] {
        assert!(
            client
                .batch_execute(&insert_evidence(&session, action, reason))
                .await
                .is_err(),
            "{action}/{reason}"
        );
    }
    client
        .batch_execute(&insert_evidence(
            &session,
            "admin_session.withdraw",
            "expired",
        ))
        .await
        .expect("one withdrawal");
    assert!(client
        .batch_execute(&insert_evidence(
            &session,
            "admin_session.withdraw",
            "logout"
        ))
        .await
        .is_err());
}

/// A session issued through one replica's front cannot be used for an
/// unsafe request with any CSRF token but the one it was issued with, on any
/// replica.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_csrf_binding_is_shared_by_replicas() {
    let Some((_guard, _database, pool)) = database().await else {
        eprintln!("skipping: no test database locator; CI runs this test");
        return;
    };
    let authority = Arc::new(Authority::default());
    let a = replica(&authority, &pool, cluster_config(8), login_keyring());
    let b = replica(&authority, &pool, cluster_config(8), login_keyring());
    let headers = cookie_headers(&issue_across(&a, &a, &HeaderMap::new()).await.unwrap());
    assert!(matches!(
        write(&b, &headers, Some("a-different-pair")).await,
        Err(crate::auth::admin_session::SessionRefusal::CsrfUnbound)
    ));
    write(&b, &headers, Some(CSRF)).await.unwrap();
    let value = cookie_value(&b, &headers);
    b.authenticate(&value, &Method::GET, &headers)
        .await
        .unwrap();
}
