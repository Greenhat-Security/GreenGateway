use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};

use async_trait::async_trait;

use super::*;
use crate::{
    auth::{change_actor::ChangeActor, tokens::CreateTokenRequest},
    authority_events::pseudonym::{test_support::generated_keyring, ReferenceDomain},
    connections::{
        model::{ConnectionWrite, MAX_CONNECTIONS},
        pg_store::PostgresConnectionStore,
        store::ConnectionStoreError,
    },
    storage::{
        contract_tests::postgres_audit_tests::{
            create_test_database, locator, write_dsn_file, TestDatabase, DATABASE,
        },
        migrations,
        postgres::PostgresFoundation,
        postgres_authority_events::{append_to_journal, JournalSource, OPERATION_JOURNAL_APPEND},
        PostgresJwtRevocationStore, PostgresServiceTokenStore, ServiceTokenStore,
    },
    tools::lease::memory::MemoryLeaseStore,
};

#[test]
fn retry_backoff_doubles_from_the_base_up_to_the_cap() {
    let base = Duration::from_millis(100);
    let cap = Duration::from_secs(2);
    let within = |failures: u32, expected: Duration| {
        let backoff = retry_backoff(base, cap, failures);
        assert!(
            backoff >= expected && backoff <= expected + expected / 4,
            "retry {failures}: {backoff:?} should be {expected:?} plus at most a quarter"
        );
    };
    within(1, Duration::from_millis(100));
    within(2, Duration::from_millis(200));
    within(3, Duration::from_millis(400));
    within(5, Duration::from_millis(1_600));
    within(6, cap);
    within(u32::MAX, cap);
    // A zero base still waits, so a failing sink never spins the authority.
    assert!(retry_backoff(Duration::ZERO, cap, 1) >= Duration::from_millis(1));
}

#[test]
fn every_failure_kind_is_a_distinct_bare_label_value() {
    let mut seen = std::collections::BTreeSet::new();
    for kind in FAILURE_KINDS {
        assert!(seen.insert(kind), "duplicate failure kind {kind}");
        assert!(
            !kind.is_empty()
                && kind
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_'),
            "a label value must be bare lowercase text: {kind}"
        );
    }
    for error in [
        StepError::Read(RepositoryError::new(
            RepositoryErrorKind::Unavailable,
            "test",
        )),
        StepError::Projection {
            position: 1,
            error: ProjectionError::MissingEvidence,
        },
        StepError::Sink(SinkError::new("test")),
        StepError::Cursor(RepositoryError::new(RepositoryErrorKind::Timeout, "test")),
    ] {
        assert!(FAILURE_KINDS.contains(&error.kind()), "{error}");
    }
}

// ---------------------------------------------------------------------------
// Against a real database. Each test gets its own database; a checkout
// without the harness locator skips, and CI runs them.
// ---------------------------------------------------------------------------

const DEPLOYMENT: &str = "deploy-authority-events";
const ISSUER: &str = "https://issuer.example.test";
/// The issuer of an acting principal, distinct from the revoked tokens'.
const ACTOR_ISSUER: &str = "https://actor-idp.example.test";

/// Records every batch it accepts, and refuses the next `failures` offers.
#[derive(Default)]
struct RecordingSink {
    batches: Mutex<Vec<Vec<DeliveryRecord>>>,
    failures: AtomicUsize,
}

impl RecordingSink {
    fn failing(failures: usize) -> Self {
        Self {
            batches: Mutex::new(Vec::new()),
            failures: AtomicUsize::new(failures),
        }
    }

    fn batches(&self) -> Vec<Vec<DeliveryRecord>> {
        self.batches.lock().expect("sink lock").clone()
    }

    fn delivered(&self) -> Vec<DeliveryRecord> {
        self.batches().into_iter().flatten().collect()
    }
}

#[async_trait]
impl AuthorityEventSink for RecordingSink {
    fn kind(&self) -> &'static str {
        "recording"
    }

    async fn deliver(&self, batch: &[DeliveryRecord]) -> Result<(), SinkError> {
        let refuse = self
            .failures
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                left.checked_sub(1)
            })
            .is_ok();
        if refuse {
            return Err(SinkError::new("test_outage"));
        }
        self.batches.lock().expect("sink lock").push(batch.to_vec());
        Ok(())
    }
}

fn test_config(batch_size: usize) -> DispatcherConfig {
    DispatcherConfig {
        poll_interval: Duration::from_millis(10),
        batch_size,
        retry_base: Duration::from_millis(1),
        retry_cap: Duration::from_millis(5),
    }
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
        .expect("the schema should migrate");
    foundation.pool().clone()
}

/// The three producers that journal evidence, on one pool.
struct Producers {
    tokens: PostgresServiceTokenStore,
    jwt: PostgresJwtRevocationStore,
    connections: PostgresConnectionStore,
}

impl Producers {
    fn new(pool: &deadpool_postgres::Pool) -> Self {
        Self {
            tokens: PostgresServiceTokenStore::new(pool.clone()),
            jwt: PostgresJwtRevocationStore::new(pool.clone(), DEPLOYMENT, ISSUER),
            connections: PostgresConnectionStore::new(pool.clone(), MAX_CONNECTIONS)
                .expect("the maximum is within the ceiling"),
        }
    }

    async fn token(&self) -> String {
        self.tokens
            .create(CreateTokenRequest {
                scopes: vec!["admin:tokens:read".to_owned()],
                created_by: "creating-admin".to_owned(),
                expires_at: None,
            })
            .await
            .expect("a token creates")
            .record
            .id
    }

    async fn rotate(&self, id: &str, actor: &ChangeActor) {
        self.tokens
            .rotate(id, actor)
            .await
            .expect("the rotate commits")
            .expect("the token exists");
    }

    async fn revoke(&self, id: &str, actor: &ChangeActor) {
        self.tokens
            .revoke(id, actor)
            .await
            .expect("the revoke commits")
            .expect("the token exists");
    }

    async fn revoke_jwt(&self, jti: &str) {
        self.jwt
            .revoke(jti, None, &ChangeActor::system("operator:revoke-jwt"))
            .await
            .expect("the JWT revoke commits");
    }

    async fn create_and_delete_connection(&self, actor: &ChangeActor) {
        let stored = self
            .connections
            .create(candidate(), actor.subject(), None)
            .await
            .expect("a Connection creates");
        self.connections
            .delete(&stored.id, &stored.etag(), actor)
            .await
            .expect("the delete commits");
    }
}

fn candidate() -> ConnectionWrite {
    serde_json::from_value(serde_json::json!({
        "display_name": "Billing API",
        "enabled": false,
        "kind": "http_api",
        "endpoint": {
            "base_url": "https://billing.example.test",
            "base_path": "/v1"
        },
        "authentication": {
            "type": "none"
        }
    }))
    .expect("the candidate deserializes")
}

async fn scalar(pool: &deadpool_postgres::Pool, sql: &str) -> i64 {
    pool.get()
        .await
        .expect("checkout")
        .query_one(sql, &[])
        .await
        .expect("scalar query")
        .get(0)
}

async fn texts(pool: &deadpool_postgres::Pool, sql: &str) -> Vec<String> {
    pool.get()
        .await
        .expect("checkout")
        .query(sql, &[])
        .await
        .expect("text query")
        .iter()
        .map(|row| row.get(0))
        .collect()
}

async fn begin(
    store: &Arc<PostgresAuthorityEventStore>,
    sink: &Arc<RecordingSink>,
    keyring: &Arc<PseudonymKeyring>,
    batch_size: usize,
    fence: i64,
) -> DispatcherTerm {
    DispatcherTerm::begin(
        Arc::clone(store),
        Arc::clone(sink) as Arc<dyn AuthorityEventSink>,
        Arc::clone(keyring),
        test_config(batch_size),
        fence,
        Uuid::new_v4(),
    )
    .await
    .expect("the cursor claims")
}

/// A keyring under the store's persisted authority ID, as startup builds it.
async fn keyring_for(store: &PostgresAuthorityEventStore) -> Arc<PseudonymKeyring> {
    let authority_id = store
        .authority_id(Uuid::new_v4())
        .await
        .expect("the authority ID persists");
    Arc::new(generated_keyring(authority_id))
}

macro_rules! database_or_skip {
    () => {{
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let guard = DATABASE.lock().await;
        (guard, create_test_database(&admin_dsn).await)
    }};
}

#[tokio::test]
async fn committed_events_are_delivered_in_commit_order_under_their_evidence_ids() {
    let (_guard, database) = database_or_skip!();
    let pool = migrated_pool(&database).await;
    let producers = Producers::new(&pool);
    let rotated = producers.token().await;
    let revoked = producers.token().await;
    // Each change by a different kind of actor: a principal vouched for by
    // a provider, a service token, the revoke-jwt command and a principal
    // without an issuer.
    producers
        .rotate(
            &rotated,
            &ChangeActor::for_test_with_issuer("rotating-admin", ACTOR_ISSUER),
        )
        .await;
    producers
        .revoke(
            &revoked,
            &ChangeActor::service_token_for_test("service-token:revoking-token"),
        )
        .await;
    producers.revoke_jwt("withdrawn-jti").await;
    producers
        .create_and_delete_connection(&ChangeActor::for_test("deleting-admin"))
        .await;

    let store = Arc::new(PostgresAuthorityEventStore::new(pool.clone()));
    let keyring = keyring_for(&store).await;
    let sink = Arc::new(RecordingSink::default());
    let stop = CancellationToken::new();
    let mut term = begin(&store, &sink, &keyring, 100, 1).await;
    assert_eq!(term.committed_position(), 0, "the first claim starts at 0");
    assert_eq!(
        term.deliver_until_caught_up(&stop)
            .await
            .expect("delivery succeeds"),
        Some(4)
    );

    let delivered = sink.delivered();
    assert_eq!(
        delivered
            .iter()
            .map(|record| (record.sequence.as_str(), record.operation.as_str()))
            .collect::<Vec<_>>(),
        [
            ("1", "service_token.rotate"),
            ("2", "service_token.revoke"),
            ("3", "jwt.revoke"),
            ("4", "connection.delete"),
        ]
    );
    // Each event ID is the one its evidence row was committed with.
    let mut evidence_ids = Vec::new();
    for table in [
        "service_token_change_evidence ORDER BY security_revision",
        "jwt_revocation_evidence",
        "connection_change_evidence",
    ] {
        evidence_ids.extend(
            texts(
                &pool,
                &format!("SELECT event_id::text FROM greengateway.{table}"),
            )
            .await,
        );
    }
    assert_eq!(
        delivered
            .iter()
            .map(|record| record.event_id.clone())
            .collect::<Vec<_>>(),
        evidence_ids
    );
    // Each record names its actor's kind and auth mode as the evidence
    // recorded them, and its issuer only by reference.
    let actor_issuer_ref = keyring
        .derive(ReferenceDomain::ActorIssuer, &[ACTOR_ISSUER])
        .expect("an issuer reference derives");
    assert_eq!(
        delivered
            .iter()
            .map(|record| (
                record.actor.kind.as_deref(),
                record.actor.auth_mode.as_deref(),
                record.actor.issuer_ref.as_deref()
            ))
            .collect::<Vec<_>>(),
        [
            (
                Some("principal"),
                Some("bearer_token"),
                Some(actor_issuer_ref.as_str())
            ),
            (Some("service_token"), Some("service_token"), None),
            (Some("system"), Some("system"), None),
            (Some("principal"), Some("bearer_token"), None),
        ]
    );
    for record in &delivered {
        assert_eq!(record.authority_id, keyring.authority_id().to_string());
        // No identifier the evidence holds reaches the delivered record.
        let serialized = serde_json::to_string(record).expect("serializes");
        for identifier in [
            rotated.as_str(),
            revoked.as_str(),
            "rotating-admin",
            "service-token:revoking-token",
            "deleting-admin",
            "operator:revoke-jwt",
            ISSUER,
            ACTOR_ISSUER,
        ] {
            assert!(!serialized.contains(identifier), "{serialized}");
        }
    }

    let stats = store.stats().await.expect("stats read");
    assert_eq!(stats.cursor, Some(4));
    assert_eq!(stats.head, 4);
    assert_eq!(stats.undelivered(), 0);
    assert_eq!(stats.oldest_undelivered_age_secs, None);

    // A restart resumes from the committed cursor and delivers nothing again.
    drop(term);
    let mut restarted = begin(&store, &sink, &keyring, 100, 2).await;
    assert_eq!(restarted.committed_position(), 4);
    assert_eq!(
        restarted
            .deliver_until_caught_up(&stop)
            .await
            .expect("delivery succeeds"),
        Some(0)
    );
    assert_eq!(sink.batches().len(), 1, "nothing is offered twice");
}

/// The crash the at-least-once contract is about: the sink accepted, the
/// process died before the cursor advance committed. The next leader offers
/// the same events again, under the same IDs and as identical records.
#[tokio::test]
async fn a_crash_between_acceptance_and_the_cursor_commit_redelivers_identical_records() {
    let (_guard, database) = database_or_skip!();
    let pool = migrated_pool(&database).await;
    let producers = Producers::new(&pool);
    let token = producers.token().await;
    producers
        .rotate(&token, &ChangeActor::for_test("rotating-admin"))
        .await;
    producers
        .revoke(&token, &ChangeActor::for_test("revoking-admin"))
        .await;

    let store = Arc::new(PostgresAuthorityEventStore::new(pool.clone()));
    let keyring = keyring_for(&store).await;
    let sink = Arc::new(RecordingSink::default());
    let mut crashed = begin(&store, &sink, &keyring, 100, 1).await;
    assert!(crashed.fill().await.expect("the batch reads"));
    crashed.offer().await.expect("the sink accepts");
    // The process dies here: no advance.
    drop(crashed);
    assert_eq!(store.stats().await.expect("stats").cursor, Some(0));

    let mut successor = begin(&store, &sink, &keyring, 100, 2).await;
    assert_eq!(
        successor
            .deliver_until_caught_up(&CancellationToken::new())
            .await
            .expect("delivery succeeds"),
        Some(2)
    );
    let batches = sink.batches();
    assert_eq!(batches.len(), 2);
    assert_eq!(
        batches[0], batches[1],
        "the redelivered batch carries the same event IDs and the same records"
    );
    assert_eq!(store.stats().await.expect("stats").cursor, Some(2));
    assert_eq!(
        scalar(
            &pool,
            "SELECT delivered_events FROM greengateway.authority_event_cursors"
        )
        .await,
        2,
        "only the committed delivery is counted"
    );
}

#[tokio::test]
async fn a_sink_outage_retries_the_same_batch_and_never_advances_past_it() {
    let (_guard, database) = database_or_skip!();
    let pool = migrated_pool(&database).await;
    let producers = Producers::new(&pool);
    for actor in ["first-admin", "second-admin", "third-admin"] {
        let token = producers.token().await;
        producers
            .rotate(&token, &ChangeActor::for_test(actor))
            .await;
    }

    let store = Arc::new(PostgresAuthorityEventStore::new(pool.clone()));
    let keyring = keyring_for(&store).await;
    let sink = Arc::new(RecordingSink::failing(2));
    let stop = CancellationToken::new();
    let mut term = begin(&store, &sink, &keyring, 100, 1).await;
    for _ in 0..2 {
        assert!(matches!(term.step(&stop).await, Err(StepError::Sink(_))));
        let stats = store.stats().await.expect("stats");
        assert_eq!(
            stats.cursor,
            Some(0),
            "a refused batch never moves the cursor"
        );
        assert_eq!(stats.undelivered(), 3);
        assert!(stats.oldest_undelivered_age_secs.is_some());
    }
    assert_eq!(
        term.step(&stop).await.expect("the sink recovers"),
        StepOutcome::Delivered {
            events: 3,
            through: 3
        }
    );
    assert_eq!(sink.batches().len(), 1);
    assert_eq!(
        sink.delivered()
            .iter()
            .map(|record| record.sequence.as_str())
            .collect::<Vec<_>>(),
        ["1", "2", "3"]
    );
}

#[tokio::test]
async fn batches_are_bounded_and_resume_after_each_other() {
    let (_guard, database) = database_or_skip!();
    let pool = migrated_pool(&database).await;
    let producers = Producers::new(&pool);
    for index in 0..5 {
        producers.revoke_jwt(&format!("jti-{index}")).await;
    }

    let store = Arc::new(PostgresAuthorityEventStore::new(pool.clone()));
    let keyring = keyring_for(&store).await;
    let sink = Arc::new(RecordingSink::default());
    let mut term = begin(&store, &sink, &keyring, 2, 1).await;
    assert_eq!(
        term.deliver_until_caught_up(&CancellationToken::new())
            .await
            .expect("delivery succeeds"),
        Some(5)
    );
    assert_eq!(
        sink.batches().iter().map(Vec::len).collect::<Vec<_>>(),
        [2, 2, 1]
    );
}

#[tokio::test]
async fn a_fenced_out_leader_cannot_move_the_cursor() {
    let (_guard, database) = database_or_skip!();
    let pool = migrated_pool(&database).await;
    let producers = Producers::new(&pool);
    let token = producers.token().await;
    producers
        .revoke(&token, &ChangeActor::for_test("revoking-admin"))
        .await;

    let store = Arc::new(PostgresAuthorityEventStore::new(pool.clone()));
    let keyring = keyring_for(&store).await;
    let stale_sink = Arc::new(RecordingSink::default());
    let stop = CancellationToken::new();
    let mut stale = begin(&store, &stale_sink, &keyring, 100, 1).await;
    assert!(stale.fill().await.expect("the batch reads"));
    stale.offer().await.expect("the sink accepts");

    // A successor takes the lease and the cursor while the stale leader
    // was paused between acceptance and its advance.
    let sink = Arc::new(RecordingSink::default());
    let mut successor = begin(&store, &sink, &keyring, 100, 2).await;
    assert_eq!(
        stale.step(&stop).await.expect("the refusal is an outcome"),
        StepOutcome::Fenced
    );
    assert_eq!(store.stats().await.expect("stats").cursor, Some(0));

    // An older fence can never claim the cursor back.
    assert!(matches!(
        DispatcherTerm::begin(
            Arc::clone(&store),
            Arc::clone(&sink) as Arc<dyn AuthorityEventSink>,
            Arc::clone(&keyring),
            test_config(100),
            1,
            Uuid::new_v4(),
        )
        .await,
        Err(error) if error.kind() == RepositoryErrorKind::Conflict
    ));

    assert_eq!(
        successor
            .deliver_until_caught_up(&stop)
            .await
            .expect("delivery succeeds"),
        Some(1)
    );
    assert_eq!(store.stats().await.expect("stats").cursor, Some(1));
}

/// Retention frees exactly what was delivered and is old enough, and an
/// undelivered event stays whatever its age. The evidence the journal
/// indexes is never touched.
#[tokio::test]
async fn retention_never_prunes_an_undelivered_event() {
    let (_guard, database) = database_or_skip!();
    let pool = migrated_pool(&database).await;
    let producers = Producers::new(&pool);
    for index in 0..4 {
        let token = producers.token().await;
        producers
            .rotate(
                &token,
                &ChangeActor::for_test(&format!("rotating-admin-{index}")),
            )
            .await;
    }
    let client = pool.get().await.expect("maintenance session");
    let prune = |retention: Duration| {
        let client = &client;
        async move {
            PostgresAuthorityEventStore::prune_with(client, retention, 1_000)
                .await
                .expect("the retention step runs")
        }
    };

    // Too young to prune by age, before any consumer exists.
    assert_eq!(prune(Duration::from_secs(3_600)).await, 0);

    let store = Arc::new(PostgresAuthorityEventStore::new(pool.clone()));
    let keyring = keyring_for(&store).await;
    let sink = Arc::new(RecordingSink::default());
    let stop = CancellationToken::new();
    let mut term = begin(&store, &sink, &keyring, 2, 1).await;

    // Claimed at 0: nothing is delivered, so nothing is pruned at any age.
    assert_eq!(prune(Duration::ZERO).await, 0);
    assert_eq!(store.stats().await.expect("stats").retained, 4);

    // Half delivered: exactly that half goes, and its capacity comes back.
    assert!(matches!(
        term.step(&stop).await,
        Ok(StepOutcome::Delivered { through: 2, .. })
    ));
    assert_eq!(
        prune(Duration::from_secs(3_600)).await,
        0,
        "the retention window holds delivered events too"
    );
    assert_eq!(prune(Duration::ZERO).await, 2);
    assert_eq!(prune(Duration::ZERO).await, 0);
    let stats = store.stats().await.expect("stats");
    assert_eq!((stats.retained, stats.first_retained), (2, Some(3)));
    assert_eq!(stats.undelivered(), 2);

    // The rest is still there to deliver, and goes once delivered.
    assert_eq!(
        term.deliver_until_caught_up(&stop)
            .await
            .expect("delivery succeeds"),
        Some(2)
    );
    assert_eq!(prune(Duration::ZERO).await, 2);
    assert_eq!(store.stats().await.expect("stats").retained, 0);
    assert_eq!(
        scalar(
            &pool,
            "SELECT count(*) FROM greengateway.service_token_change_evidence"
        )
        .await,
        4,
        "retention never touches the evidence"
    );
    // Positions keep their meaning: the head is unchanged by retention.
    assert_eq!(store.stats().await.expect("stats").head, 4);
}

/// Before any dispatcher has claimed the cursor there is no required
/// consumer: rows past the retention window are pruned by age alone.
#[tokio::test]
async fn without_a_consumer_retention_is_by_age_alone() {
    let (_guard, database) = database_or_skip!();
    let pool = migrated_pool(&database).await;
    let producers = Producers::new(&pool);
    producers.revoke_jwt("unclaimed-jti").await;
    let client = pool.get().await.expect("maintenance session");
    assert_eq!(
        PostgresAuthorityEventStore::prune_with(&client, Duration::ZERO, 1_000)
            .await
            .expect("the retention step runs"),
        1
    );
    assert_eq!(
        scalar(
            &pool,
            "SELECT count(*) FROM greengateway.jwt_revocation_evidence"
        )
        .await,
        1
    );
    assert_eq!(
        PostgresAuthorityEventStore::new(pool.clone())
            .stats()
            .await
            .expect("stats")
            .retained,
        0
    );
}

/// The required-durability decision for a full journal: the mutation that
/// cannot journal its evidence is refused and commits nothing, and no
/// accepted event is evicted to make room. Room comes back only when
/// delivered events are pruned.
#[tokio::test]
async fn capacity_exhaustion_refuses_the_mutation_and_commits_nothing() {
    let (_guard, database) = database_or_skip!();
    let pool = migrated_pool(&database).await;
    let producers = Producers::new(&pool);
    let store = Arc::new(PostgresAuthorityEventStore::new(pool.clone()));
    store.configure_capacity(2).await.expect("capacity applies");
    let first = producers.token().await;
    let second = producers.token().await;
    let refused = producers
        .tokens
        .create(CreateTokenRequest {
            scopes: vec!["admin:tokens:read".to_owned()],
            created_by: "creating-admin".to_owned(),
            expires_at: None,
        })
        .await
        .expect("a create journals nothing and is not refused");
    producers
        .rotate(&first, &ChangeActor::for_test("rotating-admin"))
        .await;
    producers
        .rotate(&second, &ChangeActor::for_test("rotating-admin"))
        .await;
    let connection = producers
        .connections
        .create(candidate(), "deleting-admin", None)
        .await
        .expect("a create journals nothing and is not refused");

    let journal = || {
        texts(
            &pool,
            "SELECT event_id::text FROM greengateway.authority_event_journal ORDER BY position",
        )
    };
    let journal_before = journal().await;
    let revision = || {
        scalar(
            &pool,
            "SELECT last_revision FROM greengateway.security_revision_state",
        )
    };
    let outbox = || scalar(&pool, "SELECT count(*) FROM greengateway.security_outbox");
    let revision_before = revision().await;
    let outbox_before = outbox().await;

    // A rotate's success carries a plaintext, which is deliberately not
    // Debug, so the refusal is matched rather than unwrapped.
    let Err(error) = producers
        .tokens
        .rotate(&refused.record.id, &ChangeActor::for_test("rotating-admin"))
        .await
    else {
        panic!("a full journal refuses the rotate");
    };
    assert_eq!(error.kind(), RepositoryErrorKind::Unavailable);
    let error = producers
        .tokens
        .revoke(&refused.record.id, &ChangeActor::for_test("revoking-admin"))
        .await
        .expect_err("a full journal refuses the revoke");
    assert_eq!(error.kind(), RepositoryErrorKind::Unavailable);
    let error = producers
        .jwt
        .revoke(
            "refused-jti",
            None,
            &ChangeActor::system("operator:revoke-jwt"),
        )
        .await
        .expect_err("a full journal refuses the JWT revoke");
    assert_eq!(error.kind(), RepositoryErrorKind::Unavailable);
    assert!(matches!(
        producers
            .connections
            .delete(
                &connection.id,
                &connection.etag(),
                &ChangeActor::for_test("deleting-admin")
            )
            .await,
        Err(ConnectionStoreError::Unavailable { operation }) if operation == OPERATION_JOURNAL_APPEND
    ));

    // Nothing the refused changes would have written exists -- no revision
    // spent, no outbox row, no evidence -- and nothing already accepted
    // moved.
    assert_eq!(journal().await, journal_before);
    assert_eq!(revision().await, revision_before);
    assert_eq!(outbox().await, outbox_before);
    assert!(
        matches!(
            producers
                .tokens
                .verify(&refused.plaintext_token)
                .await
                .expect("verification answers"),
            crate::auth::tokens::TokenVerification::Valid(_)
        ),
        "the refused revoke left the token live: the cost of failing closed on evidence"
    );
    assert_eq!(
        scalar(
            &pool,
            &format!(
                "SELECT count(*) FROM greengateway.service_token_change_evidence WHERE token_id = '{}'",
                refused.record.id
            )
        )
        .await,
        0
    );
    assert_eq!(
        scalar(&pool, "SELECT count(*) FROM greengateway.jwt_revocations").await,
        0
    );
    assert_eq!(
        scalar(
            &pool,
            "SELECT count(*) FROM greengateway.connection_records"
        )
        .await,
        1,
        "the refused delete left the Connection in place"
    );

    // Delivery and retention free the room; the refused change then commits
    // at the next position.
    let keyring = keyring_for(&store).await;
    let sink = Arc::new(RecordingSink::default());
    let mut term = begin(&store, &sink, &keyring, 100, 1).await;
    assert_eq!(
        term.deliver_until_caught_up(&CancellationToken::new())
            .await
            .expect("delivery succeeds"),
        Some(2)
    );
    let client = pool.get().await.expect("maintenance session");
    assert_eq!(
        PostgresAuthorityEventStore::prune_with(&client, Duration::ZERO, 1_000)
            .await
            .expect("retention runs"),
        2
    );
    producers
        .rotate(&refused.record.id, &ChangeActor::for_test("rotating-admin"))
        .await;
    let stats = store.stats().await.expect("stats");
    assert_eq!((stats.retained, stats.head), (1, 3));
}

/// Make one table refuse every new row from now on. `NOT VALID` keeps the
/// rows already there, so only the next insert fails.
async fn refuse_new_rows(pool: &deadpool_postgres::Pool, table: &str) {
    pool.get()
        .await
        .expect("checkout")
        .batch_execute(&format!(
            "ALTER TABLE greengateway.{table} ADD CONSTRAINT refuse_new_rows CHECK (false) NOT VALID"
        ))
        .await
        .expect("the refusing constraint applies");
}

async fn accept_new_rows(pool: &deadpool_postgres::Pool, table: &str) {
    pool.get()
        .await
        .expect("checkout")
        .batch_execute(&format!(
            "ALTER TABLE greengateway.{table} DROP CONSTRAINT refuse_new_rows"
        ))
        .await
        .expect("the refusing constraint drops");
}

/// The other way required evidence fails to commit: the database refuses
/// the evidence insert or its journal append. Every producer rolls its
/// whole change back, and each refused change is counted exactly once, as
/// an evidence failure and never as a capacity refusal -- the alert rules
/// page on the two separately.
#[tokio::test]
async fn a_refused_evidence_write_rolls_the_mutation_back_and_is_counted_once() {
    let (_guard, database) = database_or_skip!();
    let pool = migrated_pool(&database).await;
    let producers = Producers::new(&pool);
    let token = producers.token().await;
    let connection = producers
        .connections
        .create(candidate(), "deleting-admin", None)
        .await
        .expect("a create journals nothing and is not refused");
    let journal = || {
        scalar(
            &pool,
            "SELECT count(*) FROM greengateway.authority_event_journal",
        )
    };
    let revision = || {
        scalar(
            &pool,
            "SELECT last_revision FROM greengateway.security_revision_state",
        )
    };
    let journal_before = journal().await;
    let revision_before = revision().await;
    let rotating = ChangeActor::for_test("rotating-admin");
    let revoking = ChangeActor::for_test("revoking-admin");
    let deleting = ChangeActor::for_test("deleting-admin");
    let command = ChangeActor::system("operator:revoke-jwt");

    // The recorder is this thread's, and the test's current-thread runtime
    // runs every producer on this thread.
    let recorder = crate::audit::sink::tests::CountingRecorder::default();
    let _recording = ::metrics::set_default_local_recorder(&recorder);
    let evidence_failures =
        || recorder.count(crate::metrics::AUTHORITY_EVENT_EVIDENCE_FAILURES_TOTAL, &[]);

    // A journal that refuses the append refuses every producer.
    refuse_new_rows(&pool, "authority_event_journal").await;
    let Err(_) = producers.tokens.rotate(&token, &rotating).await else {
        panic!("a refused journal append refuses the rotate");
    };
    producers
        .tokens
        .revoke(&token, &revoking)
        .await
        .expect_err("a refused journal append refuses the revoke");
    producers
        .jwt
        .revoke("refused-jti", None, &command)
        .await
        .expect_err("a refused journal append refuses the JWT revoke");
    assert!(producers
        .connections
        .delete(&connection.id, &connection.etag(), &deleting)
        .await
        .is_err());
    assert_eq!(evidence_failures(), 4);
    accept_new_rows(&pool, "authority_event_journal").await;

    // An evidence table that refuses the insert refuses its own producer.
    refuse_new_rows(&pool, "service_token_change_evidence").await;
    let Err(_) = producers.tokens.rotate(&token, &rotating).await else {
        panic!("a refused evidence insert refuses the rotate");
    };
    accept_new_rows(&pool, "service_token_change_evidence").await;
    refuse_new_rows(&pool, "jwt_revocation_evidence").await;
    producers
        .jwt
        .revoke("refused-jti", None, &command)
        .await
        .expect_err("a refused evidence insert refuses the JWT revoke");
    accept_new_rows(&pool, "jwt_revocation_evidence").await;
    refuse_new_rows(&pool, "connection_change_evidence").await;
    assert!(producers
        .connections
        .delete(&connection.id, &connection.etag(), &deleting)
        .await
        .is_err());
    accept_new_rows(&pool, "connection_change_evidence").await;
    assert_eq!(evidence_failures(), 7);

    // Nothing any refused change would have written exists.
    assert_eq!(journal().await, journal_before);
    assert_eq!(revision().await, revision_before);
    assert_eq!(
        scalar(&pool, "SELECT count(*) FROM greengateway.jwt_revocations").await,
        0
    );
    assert_eq!(
        scalar(
            &pool,
            "SELECT count(*) FROM greengateway.connection_records"
        )
        .await,
        1,
        "the refused delete left the Connection in place"
    );

    // The same changes commit once the tables accept rows again, and a
    // success counts nothing.
    producers.rotate(&token, &rotating).await;
    producers.revoke_jwt("refused-jti").await;
    producers
        .connections
        .delete(&connection.id, &connection.etag(), &deleting)
        .await
        .expect("the delete commits");
    assert_eq!(journal().await, journal_before + 3);
    assert_eq!(evidence_failures(), 7);
    assert_eq!(
        recorder.count(crate::metrics::AUTHORITY_EVENT_CAPACITY_REFUSALS_TOTAL, &[]),
        0,
        "a refused write is not a full journal"
    );
}

/// Concurrent producers on two replicas' pools still journal a gapless,
/// commit-ordered sequence: position order is shared-revision order.
#[tokio::test]
async fn concurrent_producers_journal_gapless_commit_ordered_positions() {
    let (_guard, database) = database_or_skip!();
    let pool = migrated_pool(&database).await;
    let other = migrated_pool(&database).await;
    let producers = Producers::new(&pool);
    let mut tokens = Vec::new();
    for _ in 0..8 {
        tokens.push(producers.token().await);
    }
    let stores = [
        Arc::new(PostgresServiceTokenStore::new(pool.clone())),
        Arc::new(PostgresServiceTokenStore::new(other.clone())),
    ];
    let mut tasks = Vec::new();
    for (index, token) in tokens.into_iter().enumerate() {
        let store = Arc::clone(&stores[index % 2]);
        tasks.push(tokio::spawn(async move {
            store
                .rotate(&token, &ChangeActor::for_test("racing-admin"))
                .await
                .expect("the rotate commits")
                .expect("the token exists");
        }));
    }
    for task in tasks {
        task.await.expect("the rotate task completes");
    }

    let rows = pool
        .get()
        .await
        .expect("checkout")
        .query(
            "SELECT j.position, e.security_revision \
             FROM greengateway.authority_event_journal j \
             JOIN greengateway.service_token_change_evidence e USING (event_id) \
             ORDER BY j.position",
            &[],
        )
        .await
        .expect("the journal reads");
    let positions: Vec<i64> = rows.iter().map(|row| row.get(0)).collect();
    let revisions: Vec<i64> = rows.iter().map(|row| row.get(1)).collect();
    assert_eq!(positions, (1..=8).collect::<Vec<i64>>());
    assert!(
        revisions.windows(2).all(|pair| pair[0] < pair[1]),
        "position order is commit order: {revisions:?}"
    );
}

/// An append whose transaction rolls back gives its position back: the next
/// committed event takes it, so the journal has no hole a cursor would wait
/// on forever.
#[tokio::test]
async fn an_aborted_append_leaves_no_gap() {
    let (_guard, database) = database_or_skip!();
    let pool = migrated_pool(&database).await;
    let client = pool.get().await.expect("checkout");
    client.batch_execute("BEGIN").await.expect("begin");
    append_to_journal(
        &client,
        JournalSource::ServiceTokenChange,
        &Uuid::new_v4().to_string(),
    )
    .await
    .expect("the append reserves inside the transaction");
    client.batch_execute("ROLLBACK").await.expect("rollback");
    drop(client);

    let producers = Producers::new(&pool);
    let token = producers.token().await;
    producers
        .revoke(&token, &ChangeActor::for_test("revoking-admin"))
        .await;
    let stats = PostgresAuthorityEventStore::new(pool.clone())
        .stats()
        .await
        .expect("stats");
    assert_eq!(
        (stats.head, stats.retained, stats.first_retained),
        (1, 1, Some(1))
    );
}

/// A journal row whose evidence row is gone is never skipped: delivery stops
/// there and the cursor stays below it.
#[tokio::test]
async fn a_journaled_event_without_its_evidence_stalls_delivery() {
    let (_guard, database) = database_or_skip!();
    let pool = migrated_pool(&database).await;
    let producers = Producers::new(&pool);
    let first = producers.token().await;
    let second = producers.token().await;
    producers
        .rotate(&first, &ChangeActor::for_test("rotating-admin"))
        .await;
    producers
        .rotate(&second, &ChangeActor::for_test("rotating-admin"))
        .await;
    pool.get()
        .await
        .expect("checkout")
        .execute(
            "DELETE FROM greengateway.service_token_change_evidence WHERE token_id = $1",
            &[&first],
        )
        .await
        .expect("the evidence row is removed out of band");

    let store = Arc::new(PostgresAuthorityEventStore::new(pool.clone()));
    let keyring = keyring_for(&store).await;
    let sink = Arc::new(RecordingSink::default());
    let stop = CancellationToken::new();
    let mut term = begin(&store, &sink, &keyring, 100, 1).await;
    for _ in 0..2 {
        assert!(matches!(
            term.step(&stop).await,
            Err(StepError::Projection {
                position: 1,
                error: ProjectionError::MissingEvidence
            })
        ));
    }
    assert!(
        sink.batches().is_empty(),
        "nothing after it is offered either"
    );
    assert_eq!(store.stats().await.expect("stats").cursor, Some(0));
}

#[tokio::test]
async fn the_authority_id_is_written_once_and_read_back() {
    let (_guard, database) = database_or_skip!();
    let pool = migrated_pool(&database).await;
    let store = PostgresAuthorityEventStore::new(pool.clone());
    let first = Uuid::new_v4();
    assert_eq!(store.authority_id(first).await.expect("written"), first);
    assert_eq!(
        store.authority_id(Uuid::new_v4()).await.expect("read back"),
        first,
        "a second replica derives under the same authority"
    );
}

/// The running dispatcher: it takes the lease, delivers what is journaled,
/// keeps delivering what commits afterwards, and stops on shutdown.
#[tokio::test]
async fn the_running_dispatcher_leads_delivers_and_stops_on_shutdown() {
    let (_guard, database) = database_or_skip!();
    let pool = migrated_pool(&database).await;
    let producers = Producers::new(&pool);
    let token = producers.token().await;
    producers
        .rotate(&token, &ChangeActor::for_test("rotating-admin"))
        .await;

    let store = Arc::new(PostgresAuthorityEventStore::new(pool.clone()));
    let keyring = keyring_for(&store).await;
    let sink = Arc::new(RecordingSink::default());
    let shutdown = CancellationToken::new();
    let leases = Arc::new(MemoryLeaseStore::new(Duration::from_secs(5)));
    let running = tokio::spawn(run_dispatcher(
        shutdown.clone(),
        Arc::clone(&store),
        Arc::clone(&sink) as Arc<dyn AuthorityEventSink>,
        Arc::clone(&keyring),
        Arc::clone(&leases) as Arc<dyn ExecutionLeaseStore>,
        Uuid::new_v4(),
        test_config(100),
    ));
    let delivered = |count: usize| {
        let sink = Arc::clone(&sink);
        async move {
            tokio::time::timeout(Duration::from_secs(10), async {
                while sink.delivered().len() < count {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("the dispatcher delivers within the budget");
        }
    };
    delivered(1).await;
    assert_eq!(leases.held(DISPATCHER_LEASE_SCOPE), 1);

    producers
        .revoke(&token, &ChangeActor::for_test("revoking-admin"))
        .await;
    delivered(2).await;

    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(10), running)
        .await
        .expect("the dispatcher stops on shutdown")
        .expect("the dispatcher task completes");
    assert_eq!(
        leases.held(DISPATCHER_LEASE_SCOPE),
        0,
        "the lease is released on the way out"
    );
    assert_eq!(store.stats().await.expect("stats").cursor, Some(2));
}
