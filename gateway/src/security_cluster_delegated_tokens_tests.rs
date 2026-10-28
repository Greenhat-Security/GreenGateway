//! Verified-PostgreSQL tests for delegated-token purges across replicas
//! (issue #441): two replicas' runtimes on one authority, replica B behind
//! the real strict security gate. Gated on the test harness locator: CI
//! sets it, a checkout without a database skips.

use std::time::Duration;

use serde_json::json;

use super::*;
use crate::{
    audit::{self, sink::tests::CaptureSink, AuditSink},
    auth::{AuthMethod, Principal},
    connections::{
        caller_assertion::{AssertionAlgorithm, AttestedCaller},
        control_plane::ConnectionControlPlane,
        model::ConnectionId,
        token_exchange::{DelegatedTokenBinding, SubjectTokenSettings},
    },
    egress::{EgressClient, EgressConfig},
    security_cluster::{ClusterSecurityRuntime, PolicyResource, RECONCILE_BACKGROUND_DEADLINE},
    storage::{
        compatibility::BINARY_CAPABILITIES,
        contract_tests::postgres_audit_tests::{
            create_test_database, locator, write_dsn_file, TestDatabase, DATABASE,
        },
        migrations,
        postgres::PostgresFoundation,
        MemberRegistration, PolicyCommitPrecondition, PolicyCommitRequest, PolicyControlPlane as _,
        PostgresMembershipStore, PostgresPolicyStore, SecurityRevisionSource,
    },
};

const DEPLOYMENT: &str = "deploy-delegated-token-replicas";
const ISSUER: &str = "https://idp.example.test";

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

/// A migrated database whose policy authority is initialized, as a cluster
/// is before any replica serves.
async fn deployment() -> Option<(
    tokio::sync::MutexGuard<'static, ()>,
    TestDatabase,
    deadpool_postgres::Pool,
    Arc<PostgresPolicyStore>,
)> {
    let admin_dsn = locator()?;
    let guard = DATABASE.lock().await;
    let database = create_test_database(&admin_dsn).await;
    let pool = migrated_pool(&database).await;
    let policies = Arc::new(PostgresPolicyStore::new(pool.clone()));
    policies
        .commit(PolicyCommitRequest {
            precondition: PolicyCommitPrecondition::Initialize,
            candidate: &policy(),
            change: crate::storage::DocumentChange::test_policy("installer"),
            diff_summary: &json!({ "action": "seed" }),
        })
        .await
        .expect("the policy authority initializes");
    Some((guard, database, pool, policies))
}

fn policy() -> crate::rbac::Policy {
    serde_json::from_value(json!({
        "schema_version": "0.1.0",
        "id": "delegated-token-replicas",
        "default_action": "deny",
        "roles": { "admin": { "permissions": ["admin:policy:read", "admin:policy:write"] } }
    }))
    .expect("the test policy parses")
}

/// One replica's roster row, advertising this build's capabilities.
async fn register_member(pool: &deadpool_postgres::Pool) -> Arc<ClusterMembership> {
    let membership = ClusterMembership::new(
        PostgresMembershipStore::new(
            pool.clone(),
            DEPLOYMENT,
            crate::ha::InstanceIdentity::generate(),
        ),
        MemberRegistration {
            binary_version: env!("CARGO_PKG_VERSION").to_owned(),
            schema_version: migrations::schema_version_range(),
            document_version: crate::cluster_membership::DOCUMENT_VERSION_RANGE,
            fingerprint: "c".repeat(64),
            capabilities: BINARY_CAPABILITIES.to_vec(),
        },
        Duration::from_secs(1),
        Duration::from_secs(30),
    );
    membership.register_boot().await.expect("boot row");
    membership
}

/// A replica's Connection runtime, recording purges through the gate.
fn replica(
    store: &Arc<PostgresDelegatedTokenPurgeStore>,
    membership: &Arc<ClusterMembership>,
    audit: &AuditLog,
) -> ConnectionHttpRuntime {
    let egress = EgressConfig::default();
    let client = Arc::new(EgressClient::new(egress.clone()).expect("egress client builds"));
    let control_plane =
        ConnectionControlPlane::from_config(&crate::config::Config::test_defaults())
            .expect("control plane builds");
    ConnectionHttpRuntime::new(control_plane, egress, client)
        .with_audit(audit.clone())
        .with_delegated_token_purge_ledger(
            ClusterDelegatedTokenPurgeLedger::new(
                Arc::clone(store),
                Some(Arc::clone(membership)),
                audit.clone(),
            ),
            DEPLOYMENT,
        )
}

/// Replica B's strict security gate: the policy resource every gate has,
/// and the recorded purges applied to `replica`'s cache.
fn gate(
    pool: &deadpool_postgres::Pool,
    policies: &Arc<PostgresPolicyStore>,
    store: &Arc<PostgresDelegatedTokenPurgeStore>,
    replica: &ConnectionHttpRuntime,
    boot_revision: i64,
) -> Arc<ClusterSecurityRuntime> {
    let rbac = crate::middleware::rbac::RbacState::new(
        policy(),
        Vec::new(),
        false,
        AuditLog::new(Arc::new(CaptureSink::new()) as Arc<dyn AuditSink>),
    );
    let runtime = ClusterSecurityRuntime::new(
        SecurityRevisionSource::new(pool.clone()),
        PolicyResource::new(Arc::clone(policies), rbac),
    );
    runtime.register_resource(DelegatedTokenPurgesResource::new(
        Arc::clone(store),
        replica.clone(),
        boot_revision,
    ));
    runtime
}

fn binding() -> DelegatedTokenBinding {
    let egress = EgressConfig::default();
    DelegatedTokenBinding {
        connection_id: ConnectionId::parse("mail".to_owned()).expect("a valid Connection id"),
        connection_etag: "etag-1".to_owned(),
        client_id: "greengateway".to_owned(),
        client_secret_id: "unused-client-secret".to_owned(),
        token_exchange_url: format!("{ISSUER}/token-exchange"),
        requested_scopes: Vec::new(),
        audience: None,
        resource: None,
        // Nothing is revoked at an issuer here; the executor tests cover that.
        revocation_url: None,
        subject_token: SubjectTokenSettings {
            signing_key_id: "unused-signing-key".to_owned(),
            kid: "gw-test-1".to_owned(),
            algorithm: AssertionAlgorithm::Es256,
            issuer: "https://gateway.example.test".to_owned(),
            audience: ISSUER.to_owned(),
            token_type: "caller-assertion+jwt".to_owned(),
            lifetime_seconds: 60,
            claims: Vec::new(),
        },
        token_client: Arc::new(EgressClient::new(egress).expect("egress client builds")),
    }
}

fn caller(subject: &str) -> AttestedCaller {
    AttestedCaller::from_principal(&Principal {
        user_id: subject.to_owned(),
        issuer: Some(ISSUER.to_owned()),
        email: None,
        org_id: None,
        roles: vec!["member".to_owned()],
        session_id: format!("session-{subject}"),
        auth_method: AuthMethod::Bearer,
    })
    .expect("a provider-vouched principal is attestable")
}

fn operator() -> DelegatedTokenPurgeTrigger {
    DelegatedTokenPurgeTrigger::Operator {
        actor: crate::auth::actor_from_principal(&Principal {
            user_id: "operator".to_owned(),
            issuer: Some(ISSUER.to_owned()),
            email: None,
            org_id: None,
            roles: vec!["admin".to_owned()],
            session_id: "session-operator".to_owned(),
            auth_method: AuthMethod::Bearer,
        }),
        request_id: "request-purge".to_owned(),
        source_ip: "203.0.113.20".to_owned(),
    }
}

fn purges_of(capture: &CaptureSink, trigger: &str) -> Vec<audit::AuditEvent> {
    capture
        .events()
        .into_iter()
        .filter(|event| {
            event.event_type == audit::event::CONNECTION_DELEGATED_TOKEN_PURGE
                && event.payload["trigger"] == json!(trigger)
        })
        .collect()
}

async fn wait_for_purges(capture: &CaptureSink, trigger: &str, count: usize) {
    let started = std::time::Instant::now();
    while purges_of(capture, trigger).len() < count && started.elapsed() < Duration::from_secs(5) {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(purges_of(capture, trigger).len(), count, "{trigger}");
}

async fn counter(pool: &deadpool_postgres::Pool) -> i64 {
    SecurityRevisionSource::new(pool.clone())
        .current()
        .await
        .expect("the counter reads")
}

/// The slice's acceptance test: an operator's purge on replica A is one
/// shared security revision, and replica B's next gate pass -- before it
/// serves anything at that revision -- retires B's own cached tokens for
/// the principal, and nobody else's.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_purge_on_replica_a_retires_replica_bs_tokens_before_b_serves_again() {
    let Some((_guard, _database, pool, policies)) = deployment().await else {
        eprintln!("skipping: no test database locator; CI runs this test");
        return;
    };
    let membership_a = register_member(&pool).await;
    let membership_b = register_member(&pool).await;
    let store = Arc::new(PostgresDelegatedTokenPurgeStore::new(pool.clone()));
    let capture = CaptureSink::new();
    let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
    let replica_a = replica(&store, &membership_a, &audit);
    let boot_revision = counter(&pool).await;
    let replica_b = replica(&store, &membership_b, &audit);
    let gate_b = gate(&pool, &policies, &store, &replica_b, boot_revision);

    let binding = binding();
    replica_b
        .cache_delegated_token_for_test(&binding, &caller("alice"), "b-alice")
        .await;
    replica_b
        .cache_delegated_token_for_test(&binding, &caller("bob"), "b-bob")
        .await;
    gate_b
        .admit_within(RECONCILE_BACKGROUND_DEADLINE)
        .await
        .expect("B serves before any purge");
    assert_eq!(replica_b.delegated_token_cache_entries(), 2);

    // The issuer is matched in canonical form, as the endpoint gives it.
    let outcome = replica_a
        .purge_delegated_tokens_everywhere(&format!("{ISSUER}/"), "alice", operator())
        .await
        .expect("every live replica applies recorded purges");
    assert_eq!(outcome.purged_entries, 0, "A held nothing for alice");
    let revision = outcome
        .security_revision
        .expect("cluster mode records the purge");
    assert_eq!(
        revision,
        counter(&pool).await,
        "the purge is the latest revision"
    );

    // The authority's row names a digest and nothing else.
    let row = pool
        .get()
        .await
        .expect("checkout")
        .query_one(
            "SELECT resource_type, resource_id FROM greengateway.security_outbox \
             WHERE revision = $1",
            &[&revision],
        )
        .await
        .expect("the purge's outbox row exists");
    assert_eq!(row.get::<_, String>(0), "delegated_token_purge");
    let key: String = row.get(1);
    assert!(
        crate::connections::token_exchange::is_purge_key(&key),
        "{key}"
    );

    // Until B's gate runs, B still holds alice's token; the gate's pass is
    // what retires it, before it admits anything at the purge's revision.
    assert_eq!(replica_b.delegated_token_cache_entries(), 2);
    let admission = gate_b
        .admit_within(RECONCILE_BACKGROUND_DEADLINE)
        .await
        .expect("B's gate applies the purge and admits");
    assert!(admission.revision >= revision);
    assert_eq!(
        replica_b.delegated_token_cache_entries(),
        1,
        "only bob's token is left on B"
    );
    wait_for_purges(&capture, "operator", 1).await;
    let recorded = &purges_of(&capture, "operator")[0];
    assert_eq!(
        recorded.payload["replication"],
        json!({ "outcome": "recorded", "security_revision": revision })
    );
    wait_for_purges(&capture, "replicated", 1).await;
    let applied = purges_of(&capture, "replicated");
    assert_eq!(
        applied[0].payload["principal"],
        json!({ "issuer": ISSUER, "subject": "alice" })
    );
    assert_eq!(applied[0].payload["purged_entries"], json!(1));
    assert_eq!(
        applied[0].payload["replication"],
        json!({ "outcome": "applied", "security_revision": revision })
    );

    // Another gate pass applies nothing again; a repeat purge is a new
    // revision, and is applied once more.
    gate_b
        .admit_within(RECONCILE_BACKGROUND_DEADLINE)
        .await
        .expect("B admits");
    assert_eq!(purges_of(&capture, "replicated").len(), 1);
    replica_b
        .cache_delegated_token_for_test(&binding, &caller("alice"), "b-alice-again")
        .await;
    let again = replica_a
        .purge_delegated_tokens_everywhere(ISSUER, "alice", operator())
        .await
        .expect("a repeat purge records");
    assert!(again.security_revision > Some(revision));
    gate_b
        .admit_within(RECONCILE_BACKGROUND_DEADLINE)
        .await
        .expect("B admits");
    assert_eq!(replica_b.delegated_token_cache_entries(), 1);
    wait_for_purges(&capture, "replicated", 2).await;
}

/// A replica that cannot read the record serves nothing rather than stale
/// tokens: the gate fails closed until the record reads again, and then
/// applies it before it admits.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_replica_that_cannot_read_the_record_fails_closed_until_it_can() {
    let Some((_guard, _database, pool, policies)) = deployment().await else {
        eprintln!("skipping: no test database locator; CI runs this test");
        return;
    };
    let membership = register_member(&pool).await;
    let store = Arc::new(PostgresDelegatedTokenPurgeStore::new(pool.clone()));
    let audit = AuditLog::new(Arc::new(CaptureSink::new()) as Arc<dyn AuditSink>);
    let replica_a = replica(&store, &membership, &audit);
    let boot_revision = counter(&pool).await;
    let replica_b = replica(&store, &membership, &audit);
    let gate_b = gate(&pool, &policies, &store, &replica_b, boot_revision);
    replica_b
        .cache_delegated_token_for_test(&binding(), &caller("alice"), "b-alice")
        .await;
    gate_b
        .admit_within(RECONCILE_BACKGROUND_DEADLINE)
        .await
        .expect("B serves before any purge");

    replica_a
        .purge_delegated_tokens_everywhere(ISSUER, "alice", operator())
        .await
        .expect("the purge records");
    let client = pool.get().await.expect("checkout");
    client
        .batch_execute(
            "ALTER TABLE greengateway.security_outbox RENAME TO security_outbox_unreadable",
        )
        .await
        .expect("hide the record");
    assert_eq!(
        gate_b
            .admit_within(RECONCILE_BACKGROUND_DEADLINE)
            .await
            .err(),
        Some(SecurityRevisionCheckError::Unavailable),
        "a replica that cannot read the record refuses protected traffic"
    );
    client
        .batch_execute(
            "ALTER TABLE greengateway.security_outbox_unreadable RENAME TO security_outbox",
        )
        .await
        .expect("restore the record");
    assert_eq!(
        replica_b.delegated_token_cache_entries(),
        1,
        "nothing was served in between"
    );
    gate_b
        .admit_within(RECONCILE_BACKGROUND_DEADLINE)
        .await
        .expect("B applies the purge and admits");
    assert_eq!(replica_b.delegated_token_cache_entries(), 0);
}

/// The operation gate: while a live replica predates the record, nothing is
/// written, the refusal is audited, and the replica that was asked still
/// purges its own cache; once that replica is gone the purge records.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_purge_waits_for_every_live_replica_to_apply_recorded_purges() {
    let Some((_guard, _database, pool, _policies)) = deployment().await else {
        eprintln!("skipping: no test database locator; CI runs this test");
        return;
    };
    let membership = register_member(&pool).await;
    let earlier = uuid::Uuid::new_v4();
    pool.get()
        .await
        .expect("client")
        .execute(
            "INSERT INTO greengateway.cluster_members
                 (deployment_id, instance_id, boot_id, binary_version,
                  schema_version_min, schema_version_max,
                  document_version_min, document_version_max, fingerprint,
                  capabilities)
             VALUES ($1, $2::text::uuid, $3::text::uuid, '1.0.1', 18, 21, 0, 0,
                     repeat('c', 64),
                     'openapi_swagger2_catalogs,operation_requirements,policy_role_descriptions')",
            &[
                &DEPLOYMENT,
                &earlier.to_string(),
                &uuid::Uuid::new_v4().to_string(),
            ],
        )
        .await
        .expect("an earlier member row inserts");
    let store = Arc::new(PostgresDelegatedTokenPurgeStore::new(pool.clone()));
    let capture = CaptureSink::new();
    let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
    let replica_a = replica(&store, &membership, &audit);
    replica_a
        .cache_delegated_token_for_test(&binding(), &caller("alice"), "a-alice")
        .await;
    let before = counter(&pool).await;

    let failure = replica_a
        .purge_delegated_tokens_everywhere(ISSUER, "alice", operator())
        .await
        .expect_err("a live replica predates the record");
    assert_eq!(failure.purged_entries, 1, "A's own entry is purged anyway");
    assert_eq!(failure.not_recorded.reason(), "capability_not_advertised");
    assert!(matches!(
        failure.not_recorded,
        PurgeNotRecorded::Refused {
            members_lack_capability: true,
            ..
        }
    ));
    assert_eq!(replica_a.delegated_token_cache_entries(), 0);
    assert_eq!(counter(&pool).await, before, "nothing was written");
    // Audit is delivered in order: the purge event follows the refusal.
    wait_for_purges(&capture, "operator", 1).await;
    let refusals: Vec<_> = capture
        .events()
        .into_iter()
        .filter(|event| event.event_type == "cluster.operation_refused")
        .collect();
    assert_eq!(refusals.len(), 1);
    assert_eq!(
        refusals[0].payload["operation"],
        "connections.delegated_token_purge"
    );
    assert_eq!(refusals[0].payload["capability"], "delegated_token_purges");
    assert_eq!(
        refusals[0]
            .actor
            .as_ref()
            .map(|actor| actor.user_id.as_str()),
        Some("operator")
    );
    assert_eq!(
        purges_of(&capture, "operator")[0].payload["replication"],
        json!({ "outcome": "not_recorded", "reason": "capability_not_advertised" })
    );

    // The earlier replica's row goes stale: the same purge records.
    pool.get()
        .await
        .expect("client")
        .execute(
            "UPDATE greengateway.cluster_members
             SET last_heartbeat_at = now() - interval '60 seconds'
             WHERE instance_id = $1::text::uuid",
            &[&earlier.to_string()],
        )
        .await
        .expect("backdate the earlier member");
    let outcome = replica_a
        .purge_delegated_tokens_everywhere(ISSUER, "alice", operator())
        .await
        .expect("every live replica now applies recorded purges");
    assert_eq!(outcome.security_revision, Some(before + 1));
}

/// A record this build cannot read -- written by hand, or by a later build
/// with another key format -- purges every delegated token on the replica
/// that applies it, rather than none.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_record_a_replica_cannot_read_purges_everything_it_caches() {
    let Some((_guard, _database, pool, policies)) = deployment().await else {
        eprintln!("skipping: no test database locator; CI runs this test");
        return;
    };
    let membership = register_member(&pool).await;
    let store = Arc::new(PostgresDelegatedTokenPurgeStore::new(pool.clone()));
    let audit = AuditLog::new(Arc::new(CaptureSink::new()) as Arc<dyn AuditSink>);
    let boot_revision = counter(&pool).await;
    let replica_b = replica(&store, &membership, &audit);
    let gate_b = gate(&pool, &policies, &store, &replica_b, boot_revision);
    let binding = binding();
    for subject in ["alice", "bob"] {
        replica_b
            .cache_delegated_token_for_test(&binding, &caller(subject), "b-token")
            .await;
    }
    let client = pool.get().await.expect("checkout");
    client
        .batch_execute(
            "BEGIN;
             WITH next AS (
                 UPDATE greengateway.security_revision_state
                 SET last_revision = last_revision + 1
                 WHERE singleton
                 RETURNING last_revision
             )
             INSERT INTO greengateway.security_outbox
                 (revision, resource_type, from_version, to_version, resource_id)
             SELECT last_revision, 'delegated_token_purge', NULL, 1, 'unreadable'
             FROM next;
             COMMIT;",
        )
        .await
        .expect("a hand-written record commits");
    gate_b
        .admit_within(RECONCILE_BACKGROUND_DEADLINE)
        .await
        .expect("B applies the record and admits");
    assert_eq!(replica_b.delegated_token_cache_entries(), 0);
}
