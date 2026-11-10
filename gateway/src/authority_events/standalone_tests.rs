use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Mutex, MutexGuard,
    },
};

use async_trait::async_trait;
use rusqlite::Connection;
use serde_json::json;

use super::*;
use crate::{
    auth::{
        change_actor::ChangeActor,
        tokens::{CreateTokenRequest, TokenStore},
        SqliteTokenStore,
    },
    authority_events::{
        pseudonym::test_support::{generated_key_hex, keyring_from_hex},
        sink::FileSink,
    },
    connections::{
        model::ConnectionWrite,
        secret::{
            ResolvedSecret, SecretAliasMetadata, SecretPurpose, SecretResolveError,
            SecretResolveErrorKind,
        },
        store::{ConnectionStore, SqliteConnectionStore, StoredMcpCatalogEntry},
    },
    storage::standalone_authority_events::StandaloneEvidence,
};

// Synthetic markers standing in for real identifiers. None may reach a
// delivered record.
const ACTOR_MARKER: &str = "standalone-dispatch-actor@example.test";
const ACTOR_ISSUER_MARKER: &str = "https://standalone-dispatch-idp.example.test";
const CONNECTION_NAME_MARKER: &str = "Standalone Dispatch Marker API";
const CONNECTION_HOST_MARKER: &str = "dispatch-marker.example.test";
const TOOL_MARKER: &str = "dispatch_marker_tool";

/// A scratch directory for one test's SQLite files, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let directory = std::env::temp_dir().join(format!(
            "greengateway-standalone-delivery-{name}-{}",
            Uuid::new_v4()
        ));
        std::fs::create_dir_all(&directory).expect("scratch directory should create");
        Self(directory)
    }

    fn path(&self, file: &str) -> PathBuf {
        self.0.join(file)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Records every batch it accepts, and refuses offers while `down` is set
/// or while `failures` is above zero.
#[derive(Default)]
struct RecordingSink {
    batches: Mutex<Vec<Vec<DeliveryRecord>>>,
    failures: AtomicUsize,
    down: AtomicBool,
    offers: AtomicUsize,
}

impl RecordingSink {
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
        self.offers.fetch_add(1, Ordering::SeqCst);
        let refuse = self.down.load(Ordering::SeqCst)
            || self
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

/// A store whose cursor advance can be made to fail: the moment between a
/// sink's acceptance and the advance, where a crash leaves the cursor
/// behind.
struct CrashingAdvance<A> {
    inner: A,
    crash: AtomicBool,
}

impl<A: StandaloneEvidenceAuthority> StandaloneEvidenceAuthority for CrashingAdvance<A> {
    fn evidence_store(&self) -> StandaloneEvidenceStore {
        self.inner.evidence_store()
    }

    fn evidence_sources(&self) -> &'static [StandaloneEvidenceSource] {
        self.inner.evidence_sources()
    }

    fn evidence_connection(&self) -> MutexGuard<'_, Connection> {
        self.inner.evidence_connection()
    }

    fn advance(
        &self,
        source: StandaloneEvidenceSource,
        from: i64,
        to: i64,
        delivered: i64,
    ) -> Result<(), RepositoryError> {
        if self.crash.load(Ordering::SeqCst) {
            return Err(RepositoryError::new(
                RepositoryErrorKind::Unavailable,
                "test_crash",
            ));
        }
        self.inner.advance(source, from, to, delivered)
    }
}

/// Fixed material per alias, under whatever purpose is asked for.
struct FixedResolver(BTreeMap<String, String>);

#[async_trait]
impl SecretResolver for FixedResolver {
    async fn resolve(
        &self,
        alias_id: &str,
        purpose: SecretPurpose,
    ) -> Result<ResolvedSecret, SecretResolveError> {
        let material = self.0.get(alias_id).ok_or_else(|| {
            SecretResolveError::new(alias_id, SecretResolveErrorKind::UnknownAlias)
        })?;
        ResolvedSecret::new(purpose, material.as_bytes().to_vec())
            .map_err(|_| SecretResolveError::new(alias_id, SecretResolveErrorKind::InvalidMaterial))
    }

    fn aliases(&self) -> Vec<SecretAliasMetadata> {
        Vec::new()
    }
}

#[derive(Default)]
struct CapturingAudit(Mutex<Vec<audit::AuditEvent>>);

impl audit::AuditSink for CapturingAudit {
    fn emit(&self, event: &audit::AuditEvent) {
        self.0.lock().expect("capture lock").push(event.clone());
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

fn actor() -> ChangeActor {
    ChangeActor::for_test_with_issuer(ACTOR_MARKER, ACTOR_ISSUER_MARKER)
}

fn mcp_candidate() -> ConnectionWrite {
    serde_json::from_value(json!({
        "display_name": CONNECTION_NAME_MARKER,
        "enabled": true,
        "kind": "mcp_streamable_http",
        "endpoint": {
            "base_url": format!("https://{CONNECTION_HOST_MARKER}"),
            "base_path": "/mcp"
        },
        "authentication": {"type": "none"},
        "tls": {},
        "discovery": {"type": "managed_mcp", "use_connection_authentication": false}
    }))
    .expect("the candidate should deserialize")
}

/// Issue, rotate and revoke one token: three token-table rows.
fn change_a_token(tokens: &SqliteTokenStore, revoke_id: Option<uuid::Uuid>) -> String {
    let created = tokens
        .create(
            CreateTokenRequest {
                scopes: vec!["admin:connections:read".to_owned()],
                created_by: ACTOR_MARKER.to_owned(),
                expires_at: None,
            },
            &actor(),
        )
        .expect("the token issues");
    let id = created.record.id;
    tokens
        .rotate(&id, &actor())
        .expect("the token rotates")
        .expect("the token exists");
    tokens
        .revoke_with_operation(&id, &actor(), revoke_id)
        .expect("the token revokes")
        .expect("the token exists");
    id
}

/// Create a Connection and publish its catalog, then create a second
/// Connection and delete it: three Connection rows (create, create, delete)
/// and one catalog row. A published catalog's managed tools depend on its
/// Connection, so the deleted one never publishes. Returns both IDs.
fn change_a_connection(connections: &SqliteConnectionStore) -> [String; 2] {
    let published = connections
        .create(mcp_candidate(), &actor())
        .expect("the Connection creates");
    connections
        .replace_mcp_catalog(
            &published.id,
            &published.etag(),
            &[StoredMcpCatalogEntry {
                remote_tool_name: TOOL_MARKER.to_owned(),
                title: None,
                description: "a marker tool".to_owned(),
                input_schema: json!({"type": "object", "properties": {}}),
                annotations: None,
            }],
            &[],
            &[],
            &actor(),
        )
        .expect("the catalog publishes");
    let deleted = connections
        .create(mcp_candidate(), &actor())
        .expect("the second Connection creates");
    connections
        .delete(&deleted.id, &deleted.etag(), &actor())
        .expect("the Connection deletes");
    [published.id.to_string(), deleted.id.to_string()]
}

async fn keyring_for(
    authority: &Arc<dyn StandaloneEvidenceAuthority>,
    material: &str,
) -> Arc<PseudonymKeyring> {
    let authority = Arc::clone(authority);
    let authority_id = run_blocking(move || authority.authority_id(Uuid::new_v4()))
        .await
        .expect("the authority ID persists");
    Arc::new(keyring_from_hex(authority_id, material))
}

async fn lanes_for(
    authority: &Arc<dyn StandaloneEvidenceAuthority>,
    material: &str,
) -> Vec<SourceLane> {
    let keyring = keyring_for(authority, material).await;
    let mut lanes = Vec::new();
    for source in authority.evidence_sources() {
        lanes.push(
            SourceLane::open(Arc::clone(authority), Arc::clone(&keyring), *source)
                .await
                .expect("the cursor opens"),
        );
    }
    lanes
}

fn cursor(path: &Path, source: StandaloneEvidenceSource) -> i64 {
    Connection::open(path)
        .expect("the file opens")
        .query_row(
            "SELECT position FROM authority_event_cursors WHERE source = ?1",
            [source.table()],
            |row| row.get(0),
        )
        .expect("the cursor reads")
}

fn event_ids(path: &Path, source: StandaloneEvidenceSource) -> Vec<String> {
    let connection = Connection::open(path).expect("the file opens");
    let mut statement = connection
        .prepare(&format!(
            "SELECT event_id FROM {} ORDER BY sequence",
            source.table()
        ))
        .expect("the evidence query prepares");
    statement
        .query_map([], |row| row.get(0))
        .expect("the evidence reads")
        .collect::<Result<Vec<String>, _>>()
        .expect("the event IDs read")
}

/// Every owning store's evidence is delivered from its own tables, in each
/// table's commit order, under that store's own authority ID, as records
/// the published schema accepts and that carry no identifier; the cursors
/// end at each table's last sequence.
#[tokio::test]
async fn every_owning_stores_evidence_is_delivered_in_commit_order_under_its_own_authority() {
    let scratch = Scratch::new("order");
    let tokens_path = scratch.path("tokens.sqlite");
    let connections_path = scratch.path("connections.sqlite");
    let tokens = SqliteTokenStore::open(&tokens_path).expect("the token store opens");
    let connections =
        SqliteConnectionStore::open(&connections_path).expect("the Connections store opens");
    let revoke_id = crate::auth::tokens::test_revoke_operation_id(1);
    let token_id = change_a_token(&tokens, Some(revoke_id));
    let connection_ids = change_a_connection(&connections);

    let material = generated_key_hex();
    let token_authority: Arc<dyn StandaloneEvidenceAuthority> = Arc::new(tokens);
    let connection_authority: Arc<dyn StandaloneEvidenceAuthority> = Arc::new(connections);
    let sink = RecordingSink::default();
    let stop = CancellationToken::new();
    let mut delivered = 0;
    for authority in [&token_authority, &connection_authority] {
        for mut lane in lanes_for(authority, &material).await {
            delivered += lane
                .deliver_until_caught_up(&sink, test_config(2), &stop)
                .await
                .expect("delivery succeeds")
                .expect("delivery was not stopped");
        }
    }
    assert_eq!(delivered, 7);

    let records = sink.delivered();
    let operations: Vec<&str> = records.iter().map(|r| r.operation.as_str()).collect();
    assert_eq!(
        operations,
        [
            "service_token.issue",
            "service_token.rotate",
            "service_token.revoke",
            "connection.create",
            "connection.create",
            "connection.delete",
            "catalog.mcp.publish",
        ]
    );
    assert_eq!(records[2].operation_id, revoke_id.to_string());
    // Batches of at most two per table; an empty table offers none.
    assert_eq!(
        sink.batches().iter().map(Vec::len).collect::<Vec<_>>(),
        [2, 1, 2, 1, 1]
    );
    let mut expected_ids = event_ids(&tokens_path, StandaloneEvidenceSource::ServiceTokenChange);
    expected_ids.extend(event_ids(
        &connections_path,
        StandaloneEvidenceSource::ConnectionChange,
    ));
    expected_ids.extend(event_ids(
        &connections_path,
        StandaloneEvidenceSource::CatalogChange,
    ));
    assert_eq!(
        records
            .iter()
            .map(|r| r.event_id.clone())
            .collect::<Vec<_>>(),
        expected_ids
    );
    assert_eq!(
        records
            .iter()
            .map(|r| r.sequence.as_str())
            .collect::<Vec<_>>(),
        ["1", "2", "3", "1", "2", "3", "1"]
    );

    // Each store is its own authority.
    let token_authority_id = records[0].authority_id.clone();
    let connection_authority_id = records[3].authority_id.clone();
    assert_ne!(token_authority_id, connection_authority_id);
    assert!(records[..3]
        .iter()
        .all(|r| r.authority_id == token_authority_id));
    assert!(records[3..]
        .iter()
        .all(|r| r.authority_id == connection_authority_id));

    let schema: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../docs/schemas/authority_event_delivery.v1.schema.json"),
        )
        .expect("the delivery schema should be readable"),
    )
    .expect("the delivery schema should be JSON");
    let validator = jsonschema::validator_for(&schema).expect("the schema compiles");
    let serialized = serde_json::to_string(&records).expect("the records serialize");
    for record in &records {
        let value = serde_json::to_value(record).expect("a record serializes");
        assert!(validator.is_valid(&value), "{value}");
    }
    for marker in [
        ACTOR_MARKER,
        ACTOR_ISSUER_MARKER,
        token_id.as_str(),
        connection_ids[0].as_str(),
        connection_ids[1].as_str(),
        CONNECTION_NAME_MARKER,
        CONNECTION_HOST_MARKER,
        TOOL_MARKER,
        "admin:connections:read",
    ] {
        assert!(
            !serialized.contains(marker),
            "a delivered record must never carry {marker}: {serialized}"
        );
    }

    assert_eq!(
        cursor(&tokens_path, StandaloneEvidenceSource::ServiceTokenChange),
        3
    );
    assert_eq!(
        cursor(
            &connections_path,
            StandaloneEvidenceSource::ConnectionChange
        ),
        3
    );
    assert_eq!(
        cursor(&connections_path, StandaloneEvidenceSource::CatalogChange),
        1
    );
    assert_eq!(
        cursor(
            &connections_path,
            StandaloneEvidenceSource::LocalSecretChange
        ),
        0
    );
}

/// A crash after the sink accepted and before the cursor advance committed
/// leaves the cursor behind. The restarted process reads the same rows and
/// offers them again: the same event IDs and, under the same key, the same
/// bytes. Its advance then counts the batch once.
#[tokio::test]
async fn a_crash_between_acceptance_and_the_cursor_advance_redelivers_identical_records() {
    let scratch = Scratch::new("crash");
    let path = scratch.path("tokens.sqlite");
    let tokens = SqliteTokenStore::open(&path).expect("the token store opens");
    change_a_token(&tokens, None);
    let material = generated_key_hex();

    let crashing: Arc<dyn StandaloneEvidenceAuthority> = Arc::new(CrashingAdvance {
        inner: tokens,
        crash: AtomicBool::new(true),
    });
    let first_sink = RecordingSink::default();
    let stop = CancellationToken::new();
    let mut lanes = lanes_for(&crashing, &material).await;
    let mut lane = lanes.pop().expect("the token table has a lane");
    match lane.step(&first_sink, 100, &stop).await {
        Err(StepError::Cursor(_)) => {}
        other => panic!("the advance must fail after the sink accepted: {other:?}"),
    }
    let accepted = first_sink.delivered();
    assert_eq!(accepted.len(), 3, "the sink accepted the batch");
    assert_eq!(
        cursor(&path, StandaloneEvidenceSource::ServiceTokenChange),
        0
    );
    // The process dies here.
    drop(lane);
    drop(crashing);

    let restarted: Arc<dyn StandaloneEvidenceAuthority> =
        Arc::new(SqliteTokenStore::open(&path).expect("the token store reopens"));
    let second_sink = RecordingSink::default();
    let mut lanes = lanes_for(&restarted, &material).await;
    let mut lane = lanes.pop().expect("the token table has a lane");
    assert_eq!(lane.committed_position(), Some(0));
    assert_eq!(
        lane.deliver_until_caught_up(&second_sink, test_config(100), &stop)
            .await
            .expect("delivery succeeds"),
        Some(3)
    );
    let redelivered = second_sink.delivered();
    assert_eq!(redelivered, accepted, "the same records, field for field");
    assert_eq!(
        serde_json::to_string(&redelivered).expect("serializes"),
        serde_json::to_string(&accepted).expect("serializes"),
        "and byte for byte"
    );
    assert_eq!(
        cursor(&path, StandaloneEvidenceSource::ServiceTokenChange),
        3
    );
    let counted: i64 = Connection::open(&path)
        .expect("the file opens")
        .query_row(
            "SELECT delivered_events FROM authority_event_cursors WHERE source = ?1",
            [StandaloneEvidenceSource::ServiceTokenChange.table()],
            |row| row.get(0),
        )
        .expect("the count reads");
    assert_eq!(counted, 3);
}

/// While the sink is down the same projected batch is offered again and
/// again, the cursor never moves, and nothing after it is offered; once the
/// sink recovers every row is delivered exactly once, in order.
#[tokio::test]
async fn a_sink_outage_retries_the_same_batch_and_never_advances_past_it() {
    let scratch = Scratch::new("outage");
    let path = scratch.path("connections.sqlite");
    let connections = SqliteConnectionStore::open(&path).expect("the Connections store opens");
    change_a_connection(&connections);
    let authority: Arc<dyn StandaloneEvidenceAuthority> = Arc::new(connections);
    let sink = RecordingSink::default();
    sink.down.store(true, Ordering::SeqCst);
    let stop = CancellationToken::new();
    let mut lanes = lanes_for(&authority, &generated_key_hex()).await;
    let connection_lane = lanes
        .iter_mut()
        .find(|lane| lane.source == StandaloneEvidenceSource::ConnectionChange)
        .expect("the Connection table has a lane");
    for _ in 0..3 {
        match connection_lane.step(&sink, 1, &stop).await {
            Err(StepError::Sink(error)) => assert_eq!(error.kind(), "test_outage"),
            other => panic!("the outage must refuse the batch: {other:?}"),
        }
        assert_eq!(cursor(&path, StandaloneEvidenceSource::ConnectionChange), 0);
    }
    assert!(sink.delivered().is_empty());
    assert_eq!(sink.offers.load(Ordering::SeqCst), 3);
    // The sink comes back flaky: two more refusals, then acceptance. The
    // refused row is still the first one delivered.
    sink.down.store(false, Ordering::SeqCst);
    sink.failures.store(2, Ordering::SeqCst);
    assert_eq!(
        connection_lane
            .deliver_until_caught_up(&sink, test_config(1), &stop)
            .await
            .expect("delivery recovers"),
        Some(3)
    );
    assert_eq!(
        sink.delivered()
            .iter()
            .map(|r| (r.operation.as_str(), r.sequence.as_str()))
            .collect::<Vec<_>>(),
        [
            ("connection.create", "1"),
            ("connection.create", "2"),
            ("connection.delete", "3")
        ]
    );
    assert_eq!(cursor(&path, StandaloneEvidenceSource::ConnectionChange), 3);
}

/// A restart resumes after the committed cursor: rows already accepted are
/// not offered again, rows committed since are, under the authority ID the
/// file persisted and therefore the same references.
#[tokio::test]
async fn a_restart_resumes_after_the_cursor_under_the_persisted_authority() {
    let scratch = Scratch::new("restart");
    let path = scratch.path("tokens.sqlite");
    let tokens = SqliteTokenStore::open(&path).expect("the token store opens");
    let first_token = change_a_token(&tokens, None);
    let material = generated_key_hex();
    let authority: Arc<dyn StandaloneEvidenceAuthority> = Arc::new(tokens);
    let before = RecordingSink::default();
    let stop = CancellationToken::new();
    for mut lane in lanes_for(&authority, &material).await {
        lane.deliver_until_caught_up(&before, test_config(100), &stop)
            .await
            .expect("delivery succeeds");
    }
    drop(authority);

    let reopened = SqliteTokenStore::open(&path).expect("the token store reopens");
    let second_token = change_a_token(&reopened, None);
    let authority: Arc<dyn StandaloneEvidenceAuthority> = Arc::new(reopened);
    let after = RecordingSink::default();
    for mut lane in lanes_for(&authority, &material).await {
        assert_eq!(lane.committed_position(), Some(3));
        lane.deliver_until_caught_up(&after, test_config(100), &stop)
            .await
            .expect("delivery succeeds");
    }
    let resumed = after.delivered();
    assert_eq!(
        resumed
            .iter()
            .map(|r| r.sequence.as_str())
            .collect::<Vec<_>>(),
        ["4", "5", "6"]
    );
    assert_eq!(resumed[0].authority_id, before.delivered()[0].authority_id);
    assert_eq!(
        resumed[0].actor.recorded_ref,
        before.delivered()[0].actor.recorded_ref,
        "the same actor, the same reference, across the restart"
    );
    assert_ne!(
        resumed[0].resource.reference,
        before.delivered()[0].resource.reference,
        "two tokens, two references"
    );
    assert_ne!(first_token, second_token);
}

/// A row the projection cannot deliver faithfully stalls its table at that
/// row: nothing after it is offered, the cursor stays before it, and the
/// other tables keep delivering. It is never skipped.
#[tokio::test]
async fn an_unprojectable_row_stalls_its_table_and_is_never_skipped() {
    let scratch = Scratch::new("stall");
    let path = scratch.path("connections.sqlite");
    let connections = SqliteConnectionStore::open(&path).expect("the Connections store opens");
    change_a_connection(&connections);
    // A row no gateway writes: its commit time is not RFC 3339 in UTC. The
    // table's CHECKs admit it, so only the projection can refuse it.
    connections
        .evidence_connection()
        .execute(
            "UPDATE connection_change_evidence SET committed_at = 'yesterday' WHERE sequence = 1",
            [],
        )
        .expect("the fixture row updates");
    let authority: Arc<dyn StandaloneEvidenceAuthority> = Arc::new(connections);
    let sink = RecordingSink::default();
    let stop = CancellationToken::new();
    let mut lanes = lanes_for(&authority, &generated_key_hex()).await;
    for lane in &mut lanes {
        let outcome = lane.step(&sink, 100, &stop).await;
        match lane.source {
            StandaloneEvidenceSource::ConnectionChange => match outcome {
                Err(StepError::Projection { sequence, error }) => {
                    assert_eq!(sequence, 1);
                    assert_eq!(error, ProjectionError::InvalidEvidence);
                }
                other => panic!("the row must stall delivery: {other:?}"),
            },
            StandaloneEvidenceSource::CatalogChange => {
                assert!(matches!(
                    outcome,
                    Ok(StepOutcome::Delivered { events: 1, .. })
                ));
            }
            _ => assert!(matches!(outcome, Ok(StepOutcome::Idle))),
        }
    }
    let stalled = lanes
        .iter_mut()
        .find(|lane| lane.source == StandaloneEvidenceSource::ConnectionChange)
        .expect("the Connection table has a lane");
    for _ in 0..2 {
        assert!(matches!(
            stalled.step(&sink, 100, &stop).await,
            Err(StepError::Projection { sequence: 1, .. })
        ));
    }
    assert_eq!(cursor(&path, StandaloneEvidenceSource::ConnectionChange), 0);
    assert_eq!(
        sink.delivered()
            .iter()
            .map(|r| r.operation.as_str())
            .collect::<Vec<_>>(),
        ["catalog.mcp.publish"],
        "the row after the stalled one is never offered ahead of it"
    );
}

/// The file sink receives one JSON line per delivered record and nothing
/// that names an actor or a resource.
#[tokio::test]
async fn the_file_sink_holds_the_records_and_no_identifier() {
    let scratch = Scratch::new("file");
    let path = scratch.path("tokens.sqlite");
    let tokens = SqliteTokenStore::open(&path).expect("the token store opens");
    let revoke_id = crate::auth::tokens::test_revoke_operation_id(3);
    let token_id = change_a_token(&tokens, Some(revoke_id));
    let authority: Arc<dyn StandaloneEvidenceAuthority> = Arc::new(tokens);
    let events = scratch.path("authority-events.jsonl");
    let sink = FileSink::new(
        events.clone(),
        crate::config::AuthorityEventFormat::QualifiedV1,
    );
    let stop = CancellationToken::new();
    for mut lane in lanes_for(&authority, &generated_key_hex()).await {
        lane.deliver_until_caught_up(&sink, test_config(100), &stop)
            .await
            .expect("delivery succeeds");
    }
    let written = std::fs::read_to_string(&events).expect("the event file reads");
    let lines: Vec<DeliveryRecord> = written
        .lines()
        .map(|line| serde_json::from_str(line).expect("every line is one record"))
        .collect();
    assert_eq!(lines.len(), 3);
    assert_eq!(lines[2].schema_version, "authority_event_delivery.v1");
    assert_eq!(lines[2].operation_id, revoke_id.to_string());
    for marker in [ACTOR_MARKER, ACTOR_ISSUER_MARKER, token_id.as_str()] {
        assert!(!written.contains(marker), "{marker} reached the file");
    }
}

/// Startup resolves a keyring per store under that store's persisted
/// authority ID, audits each by key ID only, and refuses a key that does
/// not resolve before anything runs.
#[tokio::test]
async fn startup_keys_each_store_under_its_own_authority_and_audits_key_ids_only() {
    let scratch = Scratch::new("startup");
    let tokens = SqliteTokenStore::open(scratch.path("tokens.sqlite")).expect("opens");
    let connections =
        SqliteConnectionStore::open(scratch.path("connections.sqlite")).expect("opens");
    let material = generated_key_hex();
    let startup = |resolver: FixedResolver| StandaloneAuthorityEventStartup {
        authorities: vec![
            Arc::new(tokens.clone()) as Arc<dyn StandaloneEvidenceAuthority>,
            Arc::new(connections.clone()) as Arc<dyn StandaloneEvidenceAuthority>,
        ],
        resolver: Arc::new(resolver),
        settings: AuthorityEventSettings {
            sink: crate::config::AuthorityEventSinkSetting::Log,
            pseudonym_key_alias: Some("pseudonym-current".to_owned()),
            ..AuthorityEventSettings::default()
        },
    };
    let capture = Arc::new(CapturingAudit::default());
    let audit_log = audit::AuditLog::new(Arc::clone(&capture) as Arc<dyn audit::AuditSink>);

    assert!(matches!(
        startup(FixedResolver(BTreeMap::new()))
            .open_lanes("log", &audit_log)
            .await,
        Err(StandaloneStartupError::Keyring(
            PseudonymError::KeyUnavailable { .. }
        ))
    ));
    let lanes = startup(FixedResolver(BTreeMap::from([(
        "pseudonym-current".to_owned(),
        material.clone(),
    )])))
    .open_lanes("log", &audit_log)
    .await
    .expect("a resolvable key opens every lane");
    assert_eq!(
        lanes.iter().map(|lane| lane.source).collect::<Vec<_>>(),
        [
            StandaloneEvidenceSource::ServiceTokenChange,
            StandaloneEvidenceSource::ConnectionChange,
            StandaloneEvidenceSource::LocalSecretChange,
            StandaloneEvidenceSource::CatalogChange,
        ]
    );
    audit_log
        .close_and_drain(Duration::from_secs(5))
        .await
        .expect("the audit log drains");
    let loaded: Vec<audit::AuditEvent> = capture
        .0
        .lock()
        .expect("capture lock")
        .iter()
        .filter(|event| event.event_type == audit::event::AUTHORITY_EVENT_KEYRING_LOADED)
        .cloned()
        .collect();
    assert_eq!(loaded.len(), 2, "one keyring per store, only on success");
    assert_eq!(loaded[0].payload["store"], "service_tokens");
    assert_eq!(loaded[1].payload["store"], "connections");
    assert_ne!(
        loaded[0].payload["authority_id"],
        loaded[1].payload["authority_id"]
    );
    assert_eq!(
        loaded[0].payload["authority_id"],
        tokens
            .authority_id(Uuid::new_v4())
            .expect("persisted")
            .to_string()
    );
    for event in &loaded {
        assert_eq!(event.payload["sink"], "log");
        assert_eq!(
            event.payload["current_key_id"].as_str().map(str::len),
            Some(8)
        );
        assert!(!serde_json::to_string(event)
            .expect("serializes")
            .contains(&material));
    }
}

/// The running dispatcher delivers every lane, publishes each store's
/// backlog, and stops on shutdown.
#[tokio::test]
async fn the_running_dispatcher_delivers_every_lane_and_stops_on_shutdown() {
    let scratch = Scratch::new("running");
    let tokens = SqliteTokenStore::open(scratch.path("tokens.sqlite")).expect("opens");
    let connections =
        SqliteConnectionStore::open(scratch.path("connections.sqlite")).expect("opens");
    change_a_token(&tokens, None);
    change_a_connection(&connections);
    let material = generated_key_hex();
    let mut lanes = Vec::new();
    for authority in [
        Arc::new(tokens) as Arc<dyn StandaloneEvidenceAuthority>,
        Arc::new(connections) as Arc<dyn StandaloneEvidenceAuthority>,
    ] {
        lanes.extend(lanes_for(&authority, &material).await);
    }
    let sink = Arc::new(RecordingSink::default());
    sink.failures.store(1, Ordering::SeqCst);
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(run_standalone_dispatcher(
        shutdown.clone(),
        lanes,
        Arc::clone(&sink) as Arc<dyn AuthorityEventSink>,
        test_config(100),
    ));
    let deadline = Instant::now() + Duration::from_secs(10);
    while sink.delivered().len() < 7 {
        assert!(Instant::now() < deadline, "delivery did not catch up");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("the dispatcher stops on shutdown")
        .expect("the dispatcher does not panic");
    let mut operations: Vec<String> = sink
        .delivered()
        .into_iter()
        .map(|record| record.operation)
        .collect();
    operations.sort_unstable();
    assert_eq!(
        operations,
        [
            "catalog.mcp.publish",
            "connection.create",
            "connection.create",
            "connection.delete",
            "service_token.issue",
            "service_token.revoke",
            "service_token.rotate",
        ]
    );
}

/// The failure vocabulary is distinct bare label values, and every error
/// maps into it.
#[test]
fn every_failure_kind_is_a_distinct_bare_label_value() {
    let mut kinds = FAILURE_KINDS.to_vec();
    kinds.sort_unstable();
    kinds.dedup();
    assert_eq!(kinds.len(), FAILURE_KINDS.len());
    for kind in FAILURE_KINDS {
        assert!(kind
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_'));
    }
    for error in [
        StepError::Read(RepositoryError::new(
            RepositoryErrorKind::Unavailable,
            "test",
        )),
        StepError::Projection {
            sequence: 1,
            error: ProjectionError::UnknownAction,
        },
        StepError::Sink(SinkError::new("test")),
        StepError::Cursor(RepositoryError::new(RepositoryErrorKind::Conflict, "test")),
    ] {
        assert!(FAILURE_KINDS.contains(&error.kind()), "{error}");
    }
}

/// An evidence row of every source reads in the one shape the projection
/// takes, revisions included where its table has them.
#[test]
fn every_source_reads_in_the_shared_shape() {
    let scratch = Scratch::new("shape");
    let connections =
        SqliteConnectionStore::open(scratch.path("connections.sqlite")).expect("opens");
    change_a_connection(&connections);
    let rows: Vec<StandaloneEvidence> = connections
        .read_after(StandaloneEvidenceSource::ConnectionChange, 0, 10)
        .expect("reads");
    assert_eq!(
        rows.iter()
            .map(|row| (row.action.as_str(), row.prior_version, row.new_version))
            .collect::<Vec<_>>(),
        [
            ("connection.create", None, Some(1)),
            ("connection.create", None, Some(1)),
            ("connection.delete", Some(1), None)
        ]
    );
    assert!(rows.iter().all(|row| row.actor_user_id == ACTOR_MARKER
        && row.actor_issuer.as_deref() == Some(ACTOR_ISSUER_MARKER)
        && row.actor_kind.as_deref() == Some("principal")));
}
