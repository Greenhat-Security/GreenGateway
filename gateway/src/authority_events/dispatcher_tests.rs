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
        store::{ConnectionStoreError, StoredConnection, StoredMcpCatalogEntry},
    },
    storage::{
        contract_tests::postgres_audit_tests::{
            create_test_database, locator, write_dsn_file, TestDatabase, DATABASE,
        },
        migrations,
        postgres::PostgresFoundation,
        postgres_authority_events::{append_to_journal, JournalSource, OPERATION_JOURNAL_APPEND},
        ActivePolicy, DocumentAction, DocumentChange, PolicyCommitError, PolicyCommitPrecondition,
        PolicyCommitRequest, PolicyControlPlane, PostgresJwtRevocationStore, PostgresPolicyStore,
        PostgresServiceTokenStore, PostgresToolStore, ServiceTokenStore,
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
    crate::storage::postgres::test_support::use_test_tls(&mut config.database);
    let foundation = PostgresFoundation::establish(&config)
        .await
        .expect("the test database should establish");
    migrations::apply_missing_for_startup(foundation.pool(), &config.database)
        .await
        .expect("the schema should migrate");
    foundation.pool().clone()
}

/// The producers that journal evidence through a store call, on one pool:
/// tokens, JWT revocations, Connections and their catalogs, and the policy
/// and tools documents.
struct Producers {
    tokens: PostgresServiceTokenStore,
    jwt: PostgresJwtRevocationStore,
    connections: PostgresConnectionStore,
    policies: PostgresPolicyStore,
    tools: PostgresToolStore,
}

impl Producers {
    fn new(pool: &deadpool_postgres::Pool) -> Self {
        Self {
            tokens: PostgresServiceTokenStore::new(pool.clone()),
            jwt: PostgresJwtRevocationStore::new(pool.clone(), DEPLOYMENT, ISSUER),
            connections: PostgresConnectionStore::new(pool.clone(), MAX_CONNECTIONS)
                .expect("the maximum is within the ceiling"),
            policies: PostgresPolicyStore::new(pool.clone()),
            tools: PostgresToolStore::new(pool.clone()),
        }
    }

    /// Commit `id` as the policy document: its initialization, or the
    /// successor of `current`.
    async fn publish_policy(
        &self,
        current: Option<&ActivePolicy>,
        id: &str,
        change: DocumentChange,
    ) -> Result<ActivePolicy, PolicyCommitError> {
        let precondition = match current {
            Some(active) => PolicyCommitPrecondition::Expected {
                etag: active.etag.clone(),
            },
            None => PolicyCommitPrecondition::Initialize,
        };
        let candidate = crate::rbac::Policy::validate_json_value(serde_json::json!({
            "schema_version": "0.1.0",
            "id": id,
            "default_action": "deny",
            "roles": { "reader": { "permissions": ["data:read"] } }
        }))
        .expect("the test policy validates");
        PolicyControlPlane::commit(
            &self.policies,
            PolicyCommitRequest {
                precondition,
                candidate: &candidate,
                change,
                diff_summary: &serde_json::json!({ "action": "dispatcher_fixture" }),
            },
        )
        .await
    }

    /// Create a managed MCP Connection: one journaled event.
    async fn mcp_connection(&self, actor: &ChangeActor) -> StoredConnection {
        self.connections
            .create(mcp_candidate(), actor, None)
            .await
            .expect("an MCP Connection creates")
    }

    /// Publish `connection`'s first MCP catalog.
    async fn publish_catalog(
        &self,
        connection: &StoredConnection,
        actor: &ChangeActor,
    ) -> Result<(), ConnectionStoreError> {
        self.connections
            .replace_mcp_catalog(
                &connection.id,
                &connection.etag(),
                &[StoredMcpCatalogEntry {
                    remote_tool_name: "lookup".to_owned(),
                    title: None,
                    description: "lookup description".to_owned(),
                    input_schema: serde_json::json!({ "type": "object", "properties": {} }),
                    annotations: None,
                }],
                &[],
                &[],
                0,
                actor,
            )
            .await
            .map(|_| ())
    }

    async fn token(&self) -> String {
        self.tokens
            .create(
                CreateTokenRequest {
                    scopes: vec!["admin:tokens:read".to_owned()],
                    created_by: "creating-admin".to_owned(),
                    expires_at: None,
                },
                &ChangeActor::for_test("creating-admin"),
            )
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

    /// Create a Connection without credential authority, replace it with
    /// one that configures some (a replace and a credential binding change
    /// under one operation), and delete it: four journaled events.
    async fn create_rebind_and_delete_connection(&self, actor: &ChangeActor) {
        let stored = self
            .connections
            .create(candidate(), actor, None)
            .await
            .expect("a Connection creates");
        let rebound = self
            .connections
            .replace(&stored.id, &stored.etag(), bound_candidate(), actor)
            .await
            .expect("the replace commits");
        self.connections
            .delete(&rebound.id, &rebound.etag(), actor)
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

/// A managed MCP Connection, whose catalog the store publishes.
fn mcp_candidate() -> ConnectionWrite {
    serde_json::from_value(serde_json::json!({
        "display_name": "Managed MCP",
        "enabled": true,
        "kind": "mcp_streamable_http",
        "endpoint": {
            "base_url": "https://mcp.example.test",
            "base_path": "/mcp"
        },
        "authentication": { "type": "none" },
        "tls": {},
        "discovery": {
            "type": "managed_mcp",
            "use_connection_authentication": false
        }
    }))
    .expect("the MCP candidate deserializes")
}

/// The same Connection with a credential binding: replacing [`candidate`]
/// with it advances the credential revision from 0 to 1.
fn bound_candidate() -> ConnectionWrite {
    serde_json::from_value(serde_json::json!({
        "display_name": "Billing API",
        "enabled": false,
        "kind": "http_api",
        "endpoint": {
            "base_url": "https://billing.example.test",
            "base_path": "/v1"
        },
        "authentication": {
            "type": "static_bearer",
            "secret_id": "billing-token"
        }
    }))
    .expect("the bound candidate deserializes")
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

/// The membership gate of a replica every live member agrees with.
fn admitted_gate() -> Arc<ClusterReadiness> {
    let gate = ClusterReadiness::new();
    gate.record_fingerprint_agreement();
    gate
}

/// Wait, within a budget, until `done` holds.
async fn eventually(what: &str, mut done: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while !done() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{what} within the budget"));
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
    let revoke_id = crate::auth::tokens::test_revoke_operation_id(1);
    producers
        .tokens
        .revoke_with_operation(
            &revoked,
            &ChangeActor::service_token_for_test("service-token:revoking-token"),
            Some(revoke_id),
        )
        .await
        .expect("the keyed revoke commits")
        .expect("the token exists");
    producers.revoke_jwt("withdrawn-jti").await;
    producers
        .create_rebind_and_delete_connection(&ChangeActor::for_test("deleting-admin"))
        .await;
    // Since migration 32 the document and catalog sources too, interleaved
    // with a Connection's: a policy published by a service token, a managed
    // Connection and its first catalog, and the first-boot tools seed.
    let policy = producers
        .publish_policy(
            None,
            "dispatcher-policy",
            DocumentChange {
                action: DocumentAction::PolicyPublish,
                actor: ChangeActor::service_token_for_test("service-token:publishing-token"),
            },
        )
        .await
        .expect("the policy commits");
    let mcp = producers
        .mcp_connection(&ChangeActor::for_test("catalog-admin"))
        .await;
    producers
        .publish_catalog(
            &mcp,
            &ChangeActor::for_test_with_issuer("publishing-admin", ACTOR_ISSUER),
        )
        .await
        .expect("the catalog publishes");
    producers
        .tools
        .seed_empty_document()
        .await
        .expect("the tools document seeds");

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
        Some(13)
    );

    let delivered = sink.delivered();
    assert_eq!(delivered[3].operation_id, revoke_id.to_string());
    assert_eq!(
        delivered
            .iter()
            .map(|record| (record.sequence.as_str(), record.operation.as_str()))
            .collect::<Vec<_>>(),
        [
            ("1", "service_token.issue"),
            ("2", "service_token.issue"),
            ("3", "service_token.rotate"),
            ("4", "service_token.revoke"),
            ("5", "jwt.revoke"),
            ("6", "connection.create"),
            ("7", "connection.replace"),
            ("8", "credential.binding_change"),
            ("9", "connection.delete"),
            ("10", "policy.publish"),
            ("11", "connection.create"),
            ("12", "catalog.mcp.publish"),
            ("13", "tools.publish"),
        ]
    );
    // A Connection's create, replace and delete are on its connection axis,
    // and the replace's binding change on its credential axis, from the 0
    // of a Connection created without credential authority, under the
    // replace's operation and shared revision.
    assert_eq!(
        delivered[5..9]
            .iter()
            .map(|record| (
                record.resource.kind.as_str(),
                record.revision.axis.as_str(),
                record.revision.before.as_deref(),
                record.revision.after.as_deref()
            ))
            .collect::<Vec<_>>(),
        [
            ("connection", "connection", None, Some("1")),
            ("connection", "connection", Some("1"), Some("2")),
            ("connection", "credential", Some("0"), Some("1")),
            ("connection", "connection", Some("2"), None),
        ]
    );
    assert_eq!(delivered[6].operation_id, delivered[7].operation_id);
    assert_eq!(
        delivered[6].revision.security,
        delivered[7].revision.security
    );
    assert_ne!(delivered[5].operation_id, delivered[6].operation_id);
    assert!(delivered[5..9]
        .iter()
        .all(|record| record.resource.reference == delivered[5].resource.reference));
    // A document is on its own axis, from its initialization; a catalog on
    // the catalog axis, from its Connection's first catalog, referenced
    // apart from that Connection.
    assert_eq!(
        delivered[9..]
            .iter()
            .map(|record| (
                record.resource.kind.as_str(),
                record.revision.axis.as_str(),
                record.revision.before.as_deref(),
            ))
            .collect::<Vec<_>>(),
        [
            ("policy", "policy", None),
            ("connection", "connection", None),
            ("catalog", "catalog", None),
            ("tools", "tools", None),
        ]
    );
    assert_eq!(
        delivered[9].revision.after,
        Some(policy.version.to_string())
    );
    assert_eq!(
        delivered[9].revision.security,
        Some(policy.security_revision.to_string())
    );
    assert_eq!(delivered[11].revision.after.as_deref(), Some("1"));
    assert_ne!(
        delivered[11].resource.reference,
        delivered[10].resource.reference
    );
    // An issue is the token's first revision on the token axis.
    assert_eq!(
        (
            delivered[0].revision.axis.as_str(),
            delivered[0].revision.before.as_deref(),
            delivered[0].revision.after.as_deref()
        ),
        ("token", None, Some("1"))
    );
    // Each event ID is the one its evidence row was committed with, in commit
    // order, which here is shared-revision order across every source. The
    // replace and its binding change share a revision; the replace row is
    // written first, and sorts first.
    let evidence_ids = texts(
        &pool,
        "SELECT event_id FROM ( \
             SELECT event_id::text, security_revision, action \
                 FROM greengateway.service_token_change_evidence \
             UNION ALL SELECT event_id::text, security_revision, action \
                 FROM greengateway.jwt_revocation_evidence \
             UNION ALL SELECT event_id::text, security_revision, action \
                 FROM greengateway.connection_change_evidence \
             UNION ALL SELECT event_id::text, security_revision, action \
                 FROM greengateway.document_change_evidence \
             UNION ALL SELECT event_id::text, security_revision, action \
                 FROM greengateway.catalog_change_evidence \
         ) AS evidence ORDER BY security_revision, action",
    )
    .await;
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
            (Some("principal"), Some("bearer_token"), None),
            (Some("principal"), Some("bearer_token"), None),
            (
                Some("principal"),
                Some("bearer_token"),
                Some(actor_issuer_ref.as_str())
            ),
            (Some("service_token"), Some("service_token"), None),
            (Some("system"), Some("system"), None),
            (Some("principal"), Some("bearer_token"), None),
            (Some("principal"), Some("bearer_token"), None),
            (Some("principal"), Some("bearer_token"), None),
            (Some("principal"), Some("bearer_token"), None),
            (Some("service_token"), Some("service_token"), None),
            (Some("principal"), Some("bearer_token"), None),
            (
                Some("principal"),
                Some("bearer_token"),
                Some(actor_issuer_ref.as_str())
            ),
            (Some("system"), Some("system"), None),
        ]
    );
    for record in &delivered {
        assert_eq!(record.authority_id, keyring.authority_id().to_string());
        // No identifier the evidence holds reaches the delivered record.
        let serialized = serde_json::to_string(record).expect("serializes");
        for identifier in [
            rotated.as_str(),
            revoked.as_str(),
            "creating-admin",
            "rotating-admin",
            "service-token:revoking-token",
            "deleting-admin",
            "operator:revoke-jwt",
            "billing-token",
            "billing.example.test",
            "service-token:publishing-token",
            "catalog-admin",
            "publishing-admin",
            "bootstrap",
            "dispatcher-policy",
            "mcp.example.test",
            "lookup",
            mcp.id.as_str(),
            ISSUER,
            ACTOR_ISSUER,
        ] {
            assert!(!serialized.contains(identifier), "{serialized}");
        }
    }

    let stats = store.stats().await.expect("stats read");
    assert_eq!(stats.cursor, Some(13));
    assert_eq!(stats.head, 13);
    assert_eq!(stats.undelivered(), 0);
    assert_eq!(stats.oldest_undelivered_age_secs, None);

    // A restart resumes from the committed cursor and delivers nothing again.
    drop(term);
    let mut restarted = begin(&store, &sink, &keyring, 100, 2).await;
    assert_eq!(restarted.committed_position(), 13);
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
        Some(3)
    );
    let batches = sink.batches();
    assert_eq!(batches.len(), 2);
    assert_eq!(
        batches[0], batches[1],
        "the redelivered batch carries the same event IDs and the same records"
    );
    assert_eq!(store.stats().await.expect("stats").cursor, Some(3));
    assert_eq!(
        scalar(
            &pool,
            "SELECT delivered_events FROM greengateway.authority_event_cursors"
        )
        .await,
        3,
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
        // Each token's issue and rotate.
        assert_eq!(stats.undelivered(), 6);
        assert!(stats.oldest_undelivered_age_secs.is_some());
    }
    assert_eq!(
        term.step(&stop).await.expect("the sink recovers"),
        StepOutcome::Delivered {
            events: 6,
            through: 6
        }
    );
    assert_eq!(sink.batches().len(), 1);
    assert_eq!(
        sink.delivered()
            .iter()
            .map(|record| record.sequence.as_str())
            .collect::<Vec<_>>(),
        ["1", "2", "3", "4", "5", "6"]
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
        Some(2)
    );
    assert_eq!(store.stats().await.expect("stats").cursor, Some(2));
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
    let mut term = begin(&store, &sink, &keyring, 4, 1).await;

    // Claimed at 0: nothing is delivered, so nothing is pruned at any age.
    // Each token journaled its issue and its rotate.
    assert_eq!(prune(Duration::ZERO).await, 0);
    assert_eq!(store.stats().await.expect("stats").retained, 8);

    // Half delivered: exactly that half goes, and its capacity comes back.
    assert!(matches!(
        term.step(&stop).await,
        Ok(StepOutcome::Delivered { through: 4, .. })
    ));
    assert_eq!(
        prune(Duration::from_secs(3_600)).await,
        0,
        "the retention window holds delivered events too"
    );
    assert_eq!(prune(Duration::ZERO).await, 4);
    assert_eq!(prune(Duration::ZERO).await, 0);
    let stats = store.stats().await.expect("stats");
    assert_eq!((stats.retained, stats.first_retained), (4, Some(5)));
    assert_eq!(stats.undelivered(), 4);

    // The rest is still there to deliver, and goes once delivered.
    assert_eq!(
        term.deliver_until_caught_up(&stop)
            .await
            .expect("delivery succeeds"),
        Some(4)
    );
    assert_eq!(prune(Duration::ZERO).await, 4);
    assert_eq!(store.stats().await.expect("stats").retained, 0);
    assert_eq!(
        scalar(
            &pool,
            "SELECT count(*) FROM greengateway.service_token_change_evidence"
        )
        .await,
        8,
        "retention never touches the evidence"
    );
    // Positions keep their meaning: the head is unchanged by retention.
    assert_eq!(store.stats().await.expect("stats").head, 8);
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
    store.configure_capacity(3).await.expect("capacity applies");
    let request = || CreateTokenRequest {
        scopes: vec!["admin:tokens:read".to_owned()],
        created_by: "creating-admin".to_owned(),
        expires_at: None,
    };
    let issuing = ChangeActor::for_test("creating-admin");
    // Two issues and a Connection create fill the journal.
    producers.token().await;
    let refused = producers
        .tokens
        .create(request(), &issuing)
        .await
        .expect("the issue fits");
    let connection = producers
        .connections
        .create(candidate(), &issuing, None)
        .await
        .expect("the create fits");

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
    let tokens = || scalar(&pool, "SELECT count(*) FROM greengateway.service_tokens");
    let revision_before = revision().await;
    let outbox_before = outbox().await;
    let tokens_before = tokens().await;

    // An issue's and a rotate's success carry a plaintext, which is
    // deliberately not Debug, so the refusals are matched rather than
    // unwrapped.
    let Err(error) = producers.tokens.create(request(), &issuing).await else {
        panic!("a full journal refuses the issue");
    };
    assert_eq!(error.kind(), RepositoryErrorKind::Unavailable);
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
    assert!(matches!(
        producers
            .connections
            .create(candidate(), &issuing, None)
            .await,
        Err(ConnectionStoreError::Unavailable { operation }) if operation == OPERATION_JOURNAL_APPEND
    ));
    assert!(matches!(
        producers
            .connections
            .replace(
                &connection.id,
                &connection.etag(),
                bound_candidate(),
                &ChangeActor::for_test("editing-admin")
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
    assert_eq!(
        tokens().await,
        tokens_before,
        "the refused issue minted nothing"
    );
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
        1,
        "the token's issue, and nothing of the refused changes"
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
        "the refused delete left the Connection in place, and the refused create made none"
    );
    assert_eq!(
        producers
            .connections
            .get(&connection.id)
            .await
            .expect("the Connection reads"),
        Some(connection.clone()),
        "the refused replace changed nothing"
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
        Some(3)
    );
    let client = pool.get().await.expect("maintenance session");
    assert_eq!(
        PostgresAuthorityEventStore::prune_with(&client, Duration::ZERO, 1_000)
            .await
            .expect("retention runs"),
        3
    );
    producers
        .rotate(&refused.record.id, &ChangeActor::for_test("rotating-admin"))
        .await;
    let stats = store.stats().await.expect("stats");
    assert_eq!((stats.retained, stats.head), (1, 4));
}

/// A full journal refuses a policy publication, a catalog publication and
/// the first-boot tools seed exactly as it refuses every other producer
/// (migration 32): each is answered unavailable, which the admin API answers
/// `503` and a first boot fails closed on, and commits nothing -- no version,
/// active pointer, shared revision, outbox row, catalog, tool name
/// reservation, evidence row or journal row -- and each refusal is counted
/// once. Once delivery and retention free room, the same changes commit and
/// journal.
#[tokio::test]
async fn a_full_journal_refuses_policy_and_catalog_publications_and_commits_nothing() {
    let (_guard, database) = database_or_skip!();
    let pool = migrated_pool(&database).await;
    let producers = Producers::new(&pool);
    let store = Arc::new(PostgresAuthorityEventStore::new(pool.clone()));
    store.configure_capacity(2).await.expect("capacity applies");
    // A managed Connection and the first policy fill the journal.
    let mcp = producers
        .mcp_connection(&ChangeActor::for_test("catalog-admin"))
        .await;
    let initial = producers
        .publish_policy(
            None,
            "capacity-initial",
            DocumentChange::test_policy("installer"),
        )
        .await
        .expect("the first policy fits");

    let journal = || {
        texts(
            &pool,
            "SELECT event_id::text FROM greengateway.authority_event_journal ORDER BY position",
        )
    };
    let counts = || {
        let pool = &pool;
        async move {
            let mut counts = Vec::new();
            for table in [
                "security_outbox",
                "policy_documents",
                "tool_documents",
                "tool_active",
                "connection_mcp_catalogs",
                "connection_mcp_catalog_entries",
                "tool_name_reservations",
                "document_change_evidence",
                "catalog_change_evidence",
            ] {
                counts.push((
                    table,
                    scalar(pool, &format!("SELECT count(*) FROM greengateway.{table}")).await,
                ));
            }
            counts.push((
                "last_revision",
                scalar(
                    pool,
                    "SELECT last_revision FROM greengateway.security_revision_state",
                )
                .await,
            ));
            counts
        }
    };
    let journal_before = journal().await;
    let counts_before = counts().await;
    // The recorder is this thread's, and the test's current-thread runtime
    // runs every producer on this thread.
    let recorder = crate::audit::sink::tests::CountingRecorder::default();
    let _recording = ::metrics::set_default_local_recorder(&recorder);
    let unavailable = |outcome: Result<ActivePolicy, PolicyCommitError>| {
        matches!(outcome, Err(PolicyCommitError::Store(error))
            if error.kind() == RepositoryErrorKind::Unavailable)
    };

    assert!(unavailable(
        producers
            .publish_policy(
                Some(&initial),
                "capacity-refused",
                DocumentChange::test_policy("publishing-admin"),
            )
            .await
    ));
    assert!(matches!(
        producers.tools.seed_empty_document().await,
        Err(PolicyCommitError::Store(error)) if error.kind() == RepositoryErrorKind::Unavailable
    ));
    assert!(matches!(
        producers
            .publish_catalog(&mcp, &ChangeActor::for_test("publishing-admin"))
            .await,
        Err(ConnectionStoreError::Unavailable { operation }) if operation == OPERATION_JOURNAL_APPEND
    ));

    assert_eq!(journal().await, journal_before);
    assert_eq!(counts().await, counts_before);
    let active = PolicyControlPlane::active(&producers.policies)
        .await
        .expect("the active policy reads")
        .expect("the first policy is active");
    assert_eq!(
        (active.version, active.etag.as_str()),
        (initial.version, initial.etag.as_str())
    );
    assert_eq!(
        producers
            .connections
            .mcp_catalog(&mcp.id)
            .await
            .expect("the catalog reads"),
        None
    );
    assert_eq!(
        recorder.count(crate::metrics::AUTHORITY_EVENT_CAPACITY_REFUSALS_TOTAL, &[]),
        3
    );
    assert_eq!(
        recorder.count(crate::metrics::AUTHORITY_EVENT_EVIDENCE_FAILURES_TOTAL, &[]),
        0,
        "a full journal is not a refused write"
    );

    // Delivery and retention free the room; the refused changes then commit
    // and journal at the next positions.
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
        .publish_policy(
            Some(&initial),
            "capacity-refused",
            DocumentChange::test_policy("publishing-admin"),
        )
        .await
        .expect("the publication commits once there is room");
    producers
        .publish_catalog(&mcp, &ChangeActor::for_test("publishing-admin"))
        .await
        .expect("the catalog publishes once there is room");
    let stats = store.stats().await.expect("stats");
    assert_eq!((stats.retained, stats.head), (2, 4));
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
        .create(candidate(), &ChangeActor::for_test("creating-admin"), None)
        .await
        .expect("the create commits");
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
    let issuing = ChangeActor::for_test("creating-admin");
    let rotating = ChangeActor::for_test("rotating-admin");
    let revoking = ChangeActor::for_test("revoking-admin");
    let deleting = ChangeActor::for_test("deleting-admin");
    let editing = ChangeActor::for_test("editing-admin");
    let command = ChangeActor::system("operator:revoke-jwt");
    let request = || CreateTokenRequest {
        scopes: vec!["admin:tokens:read".to_owned()],
        created_by: "creating-admin".to_owned(),
        expires_at: None,
    };

    // The recorder is this thread's, and the test's current-thread runtime
    // runs every producer on this thread.
    let recorder = crate::audit::sink::tests::CountingRecorder::default();
    let _recording = ::metrics::set_default_local_recorder(&recorder);
    let evidence_failures =
        || recorder.count(crate::metrics::AUTHORITY_EVENT_EVIDENCE_FAILURES_TOTAL, &[]);

    // A journal that refuses the append refuses every producer.
    refuse_new_rows(&pool, "authority_event_journal").await;
    let Err(_) = producers.tokens.create(request(), &issuing).await else {
        panic!("a refused journal append refuses the issue");
    };
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
    assert!(producers
        .connections
        .create(candidate(), &issuing, None)
        .await
        .is_err());
    assert!(producers
        .connections
        .replace(
            &connection.id,
            &connection.etag(),
            bound_candidate(),
            &editing
        )
        .await
        .is_err());
    assert_eq!(evidence_failures(), 7);
    accept_new_rows(&pool, "authority_event_journal").await;

    // An evidence table that refuses the insert refuses its own producer:
    // the three service-token changes write the same evidence table, and
    // each counts its own refusal.
    refuse_new_rows(&pool, "service_token_change_evidence").await;
    let Err(_) = producers.tokens.create(request(), &issuing).await else {
        panic!("a refused evidence insert refuses the issue");
    };
    let Err(_) = producers.tokens.rotate(&token, &rotating).await else {
        panic!("a refused evidence insert refuses the rotate");
    };
    producers
        .tokens
        .revoke(&token, &ChangeActor::for_test("revoking-admin"))
        .await
        .expect_err("a refused evidence insert refuses the revoke");
    accept_new_rows(&pool, "service_token_change_evidence").await;
    refuse_new_rows(&pool, "jwt_revocation_evidence").await;
    producers
        .jwt
        .revoke("refused-jti", None, &command)
        .await
        .expect_err("a refused evidence insert refuses the JWT revoke");
    accept_new_rows(&pool, "jwt_revocation_evidence").await;
    // A credential-changing replace is refused at its first row, and counts
    // once.
    refuse_new_rows(&pool, "connection_change_evidence").await;
    assert!(producers
        .connections
        .delete(&connection.id, &connection.etag(), &deleting)
        .await
        .is_err());
    assert!(producers
        .connections
        .create(candidate(), &issuing, None)
        .await
        .is_err());
    assert!(producers
        .connections
        .replace(
            &connection.id,
            &connection.etag(),
            bound_candidate(),
            &editing
        )
        .await
        .is_err());
    accept_new_rows(&pool, "connection_change_evidence").await;
    assert_eq!(evidence_failures(), 14);

    // Nothing any refused change would have written exists.
    assert_eq!(journal().await, journal_before);
    assert_eq!(revision().await, revision_before);
    assert_eq!(
        scalar(&pool, "SELECT count(*) FROM greengateway.service_tokens").await,
        1,
        "neither refused issue minted a token"
    );
    assert_eq!(
        scalar(
            &pool,
            "SELECT count(*) FROM greengateway.service_tokens WHERE revoked_at IS NOT NULL"
        )
        .await,
        0,
        "neither refused revoke left the token revoked"
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
        "the refused delete left the Connection in place, and no refused create made one"
    );
    assert_eq!(
        producers
            .connections
            .get(&connection.id)
            .await
            .expect("the Connection reads"),
        Some(connection.clone()),
        "no refused replace changed it"
    );

    // The same changes commit once the tables accept rows again, and a
    // success counts nothing: the replace journals its binding change too.
    producers.rotate(&token, &rotating).await;
    producers.revoke_jwt("refused-jti").await;
    let rebound = producers
        .connections
        .replace(
            &connection.id,
            &connection.etag(),
            bound_candidate(),
            &editing,
        )
        .await
        .expect("the replace commits");
    producers
        .connections
        .delete(&rebound.id, &rebound.etag(), &deleting)
        .await
        .expect("the delete commits");
    assert_eq!(journal().await, journal_before + 5);
    assert_eq!(evidence_failures(), 14);
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
    // The eight issues, then the eight racing rotates.
    assert_eq!(positions, (1..=16).collect::<Vec<i64>>());
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
    // The issue took the aborted position, and the revoke the next.
    assert_eq!(
        (stats.head, stats.retained, stats.first_retained),
        (2, 2, Some(1))
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
        admitted_gate(),
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
    // The token's issue and its rotate.
    delivered(2).await;
    assert_eq!(leases.held(DISPATCHER_LEASE_SCOPE), 1);

    producers
        .revoke(&token, &ChangeActor::for_test("revoking-admin"))
        .await;
    delivered(3).await;

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
    assert_eq!(store.stats().await.expect("stats").cursor, Some(3));
}

/// A replica the membership has not admitted -- held at the fingerprint door,
/// or excluded by the durable contract fence -- never tries the dispatcher
/// lease, so it can never claim the cursor or offer anything to its sink.
/// Runs without a database: the store is a pool that never connects, and a
/// held dispatcher must not reach the authority at all.
#[tokio::test]
async fn a_replica_the_membership_has_not_admitted_never_contends_for_the_lease() {
    let pool = deadpool_postgres::Pool::builder(deadpool_postgres::Manager::new(
        tokio_postgres::Config::new(),
        tokio_postgres::NoTls,
    ))
    .runtime(deadpool_postgres::Runtime::Tokio1)
    .build()
    .expect("a lazy pool builds without connecting");
    let store = Arc::new(PostgresAuthorityEventStore::new(pool));
    let keyring = Arc::new(generated_keyring(Uuid::new_v4()));
    let sink = Arc::new(RecordingSink::default());
    let leases = Arc::new(MemoryLeaseStore::new(Duration::from_secs(5)));

    let held_at_the_door = ClusterReadiness::new();
    let fenced = admitted_gate();
    assert!(fenced.record_contract_fenced());
    for gate in [held_at_the_door, fenced] {
        let shutdown = CancellationToken::new();
        let running = tokio::spawn(run_dispatcher(
            shutdown.clone(),
            Arc::clone(&store),
            Arc::clone(&sink) as Arc<dyn AuthorityEventSink>,
            Arc::clone(&keyring),
            Arc::clone(&leases) as Arc<dyn ExecutionLeaseStore>,
            Uuid::new_v4(),
            gate,
            test_config(100),
        ));
        // Many turns: the contention backoff under this config is under 50 ms.
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(leases.held(DISPATCHER_LEASE_SCOPE), 0);
        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(10), running)
            .await
            .expect("a held dispatcher stops on shutdown")
            .expect("the dispatcher task completes");
    }

    assert!(sink.batches().is_empty(), "nothing was offered to the sink");
    // The lease store hands out fences in order, so the first acquisition
    // after both held runs getting the first fence proves neither tried it.
    match leases
        .try_acquire(DISPATCHER_LEASE_SCOPE, 1, "probe")
        .await
        .expect("the memory lease store answers")
    {
        LeaseAttempt::Acquired(lease) => assert_eq!(lease.fence, 1, "nobody took the lease"),
        LeaseAttempt::Full => panic!("the lease is free"),
    }
}

/// The fingerprint-door scenario against a real cursor: a replica held at
/// the door, with a sink and a free lease, leaves the cursor unclaimed and
/// the journal undelivered; once agreement is recorded it leads and
/// delivers; and when the durable contract fence then excludes it, it ends
/// its term, gives the lease back, and delivers nothing committed after.
#[tokio::test]
async fn a_dispatcher_leads_only_while_the_membership_admits_its_replica() {
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
    let gate = ClusterReadiness::new();
    let running = tokio::spawn(run_dispatcher(
        shutdown.clone(),
        Arc::clone(&store),
        Arc::clone(&sink) as Arc<dyn AuthorityEventSink>,
        Arc::clone(&keyring),
        Arc::clone(&leases) as Arc<dyn ExecutionLeaseStore>,
        Uuid::new_v4(),
        Arc::clone(&gate),
        test_config(100),
    ));

    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(leases.held(DISPATCHER_LEASE_SCOPE), 0);
    assert!(sink.batches().is_empty());
    let held = store.stats().await.expect("stats");
    assert_eq!(held.cursor, None, "a held replica never claims the cursor");
    assert_eq!(held.undelivered(), 2, "the token's issue and its rotate");

    gate.record_fingerprint_agreement();
    eventually("the admitted replica delivers", || {
        sink.delivered().len() == 2
    })
    .await;
    assert_eq!(leases.held(DISPATCHER_LEASE_SCOPE), 1);
    tokio::time::timeout(Duration::from_secs(10), async {
        while store.stats().await.expect("stats").cursor != Some(2) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the cursor commits past the delivered event within the budget");

    assert!(gate.record_contract_fenced());
    eventually("the fenced leader gives the lease back", || {
        leases.held(DISPATCHER_LEASE_SCOPE) == 0
    })
    .await;
    producers
        .revoke(&token, &ChangeActor::for_test("revoking-admin"))
        .await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(
        sink.delivered().len(),
        2,
        "nothing committed after the fence is delivered by the excluded build"
    );
    assert_eq!(leases.held(DISPATCHER_LEASE_SCOPE), 0);

    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(10), running)
        .await
        .expect("the dispatcher stops on shutdown")
        .expect("the dispatcher task completes");
    let after = store.stats().await.expect("stats");
    assert_eq!(after.cursor, Some(2));
    assert_eq!(
        after.undelivered(),
        1,
        "the revoke waits for an admitted leader"
    );
}
