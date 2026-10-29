//! Durable change evidence of the shared document core (issue #425, PR 2c).
//!
//! The PostgreSQL tests are gated on the test harness locator: CI sets it, a
//! checkout without a database skips. The vocabulary and bound tests run
//! everywhere.

use std::collections::BTreeSet;

use serde_json::{json, Value};

use super::*;
use crate::auth::AuthMethod;
use crate::rbac::Policy;
use crate::storage::change_evidence::{ChangeActor, DocumentAction, DocumentChange};
use crate::storage::contract_tests::postgres_audit_tests::{
    create_test_database, locator, write_dsn_file, TestDatabase, DATABASE,
};
use crate::storage::{
    migrations, postgres::PostgresFoundation, postgres_policy::PostgresPolicyStore,
    postgres_tools::PostgresToolStore, PolicyCommitPrecondition, PolicyCommitRequest,
    PolicyControlPlane, ToolControlPlane,
};

const MIGRATION_23: &str = include_str!("migrations/0023_document_and_catalog_change_evidence.sql");

const ALL_ACTIONS: [DocumentAction; 9] = [
    DocumentAction::PolicyPublish,
    DocumentAction::PolicyRollback,
    DocumentAction::PolicyRuleCreate,
    DocumentAction::PolicyRuleUpdate,
    DocumentAction::PolicyRuleDelete,
    DocumentAction::PolicyRuleReorder,
    DocumentAction::PolicySuggestionAccept,
    DocumentAction::ToolsPublish,
    DocumentAction::ConfigurationImport,
];

/// The quoted values of the CHECK that follows `column` in migration 23's
/// `document_change_evidence` definition.
fn document_check_values(column: &str) -> BTreeSet<String> {
    let table = MIGRATION_23
        .split("CREATE TABLE greengateway.document_change_evidence")
        .nth(1)
        .and_then(|rest| rest.split("CREATE TABLE").next())
        .expect("migration 23 defines document_change_evidence");
    let check = table
        .split(&format!("{column} IN ("))
        .nth(1)
        .and_then(|rest| rest.split(')').next())
        .unwrap_or_else(|| panic!("migration 23 constrains {column}"));
    check
        .split(',')
        .map(|value| value.trim().trim_matches('\'').to_owned())
        .collect()
}

#[test]
fn the_action_vocabulary_is_the_migrations_and_the_authority_events() {
    let codes: BTreeSet<String> = ALL_ACTIONS
        .iter()
        .map(|action| action.code().to_owned())
        .collect();
    assert_eq!(codes.len(), ALL_ACTIONS.len(), "codes are distinct");
    assert_eq!(codes, document_check_values("action"));

    let schema: Value = serde_json::from_str(include_str!(
        "../../../docs/schemas/authority_event.v1.schema.json"
    ))
    .expect("the authority event schema parses");
    let operations: BTreeSet<String> = schema["properties"]["operation"]["enum"]
        .as_array()
        .expect("the schema enumerates operations")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("operation codes are strings")
                .to_owned()
        })
        .collect();
    assert!(
        codes.is_subset(&operations),
        "every evidence action is a proposed authority-event operation"
    );

    for action in ALL_ACTIONS {
        let policy = action.applies_to("policy");
        let tools = action.applies_to("tools");
        assert_eq!(
            policy,
            action.code().starts_with("policy.") || action == DocumentAction::ConfigurationImport
        );
        assert_eq!(
            tools,
            matches!(
                action,
                DocumentAction::ToolsPublish | DocumentAction::ConfigurationImport
            )
        );
        assert!(!action.applies_to("connection"), "{action:?}");
    }
}

#[test]
fn actor_vocabulary_and_bounds_are_the_migrations() {
    let auth_modes = [
        AuthMethod::Cookie,
        AuthMethod::Bearer,
        AuthMethod::ServiceToken,
        AuthMethod::ClientCertificate,
    ]
    .iter()
    .map(|method| method.audit_mode().to_owned())
    .chain([ChangeActor::System { label: "bootstrap" }
        .auth_mode()
        .to_owned()])
    .collect::<BTreeSet<_>>();
    assert_eq!(auth_modes, document_check_values("actor_auth_mode"));
    assert_eq!(
        document_check_values("actor_kind"),
        BTreeSet::from(["principal".to_owned(), "system".to_owned()])
    );
    assert!(MIGRATION_23.contains(&format!(
        "octet_length(actor_user_id) BETWEEN 1 AND {EVIDENCE_ACTOR_MAX_BYTES}"
    )));
    assert!(MIGRATION_23.contains(&format!(
        "octet_length(actor_issuer) BETWEEN 1 AND {EVIDENCE_ISSUER_MAX_BYTES}"
    )));
}

#[test]
fn a_principal_actor_records_what_the_principal_carries() {
    let mut principal = crate::auth::Principal {
        user_id: "alice".to_owned(),
        issuer: Some("https://issuer.example".to_owned()),
        email: None,
        org_id: None,
        roles: vec!["admin".to_owned()],
        session_id: "session".to_owned(),
        auth_method: AuthMethod::Cookie,
    };
    let actor = ChangeActor::principal(&principal);
    assert_eq!(actor.kind(), "principal");
    assert_eq!(actor.user_id(), "alice");
    assert_eq!(actor.issuer(), Some("https://issuer.example"));
    assert_eq!(actor.auth_mode(), "session_cookie");

    // An empty issuer names no issuer.
    principal.issuer = Some(String::new());
    assert_eq!(ChangeActor::principal(&principal).issuer(), None);

    let system = ChangeActor::System { label: "bootstrap" };
    assert_eq!(
        (
            system.kind(),
            system.user_id(),
            system.issuer(),
            system.auth_mode()
        ),
        ("system", "bootstrap", None, "system")
    );
}

// ---- PostgreSQL ------------------------------------------------------------

async fn migrated_pool(database: &TestDatabase) -> deadpool_postgres::Pool {
    let dsn_file = write_dsn_file(&database.dsn);
    let mut config = crate::config::Config::test_defaults();
    config.state_backend = crate::config::StateBackend::Postgres;
    config.deployment_id = Some("deploy-document-evidence".to_owned());
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

/// One `document_change_evidence` row, every column, UUIDs and the
/// timestamp read as text.
#[derive(Clone, Debug, PartialEq, Eq)]
struct DocumentEvidence {
    event_id: String,
    operation_id: String,
    actor_kind: String,
    actor_user_id: String,
    actor_issuer: Option<String>,
    actor_auth_mode: String,
    action: String,
    resource_type: String,
    prior_version: Option<i64>,
    new_version: i64,
    security_revision: i64,
    committed_at: String,
}

async fn evidence(pool: &deadpool_postgres::Pool) -> Vec<DocumentEvidence> {
    pool.get()
        .await
        .expect("evidence checkout")
        .query(
            r#"
            SELECT event_id::text, operation_id::text, actor_kind, actor_user_id,
                   actor_issuer, actor_auth_mode, action, resource_type, prior_version,
                   new_version, security_revision, committed_at::text
            FROM greengateway.document_change_evidence
            ORDER BY security_revision
            "#,
            &[],
        )
        .await
        .expect("evidence rows should read")
        .iter()
        .map(|row| DocumentEvidence {
            event_id: row.get(0),
            operation_id: row.get(1),
            actor_kind: row.get(2),
            actor_user_id: row.get(3),
            actor_issuer: row.get(4),
            actor_auth_mode: row.get(5),
            action: row.get(6),
            resource_type: row.get(7),
            prior_version: row.get(8),
            new_version: row.get(9),
            security_revision: row.get(10),
            committed_at: row.get(11),
        })
        .collect()
}

/// The outbox as `(revision, resource_type, from_version, to_version)`.
async fn outbox(pool: &deadpool_postgres::Pool) -> Vec<(i64, String, Option<i64>, i64)> {
    pool.get()
        .await
        .expect("outbox checkout")
        .query(
            "SELECT revision, resource_type, from_version, to_version \
             FROM greengateway.security_outbox ORDER BY revision",
            &[],
        )
        .await
        .expect("outbox rows should read")
        .iter()
        .map(|row| (row.get(0), row.get(1), row.get(2), row.get(3)))
        .collect()
}

async fn count(pool: &deadpool_postgres::Pool, table: &str) -> i64 {
    pool.get()
        .await
        .expect("count checkout")
        .query_one(&format!("SELECT count(*) FROM greengateway.{table}"), &[])
        .await
        .expect("count query")
        .get(0)
}

fn policy(id: &str, role: &str) -> Policy {
    Policy::validate_json_value(json!({
        "schema_version": "0.1.0",
        "id": id,
        "default_action": "deny",
        "roles": { role: { "permissions": ["data:read"] } }
    }))
    .expect("test policy should validate")
}

fn tools_document(names: &[&str]) -> Value {
    json!({
        "schema_version": "0.1.0",
        "tools": names.iter().map(|name| json!({
            "name": name,
            "description": "Evidence fixture tool.",
            "input_json_schema": { "type": "object", "properties": {} },
            "upstream": { "method": "GET", "path_template": "/fixture" }
        })).collect::<Vec<_>>(),
    })
}

static DIFF: std::sync::LazyLock<Value> =
    std::sync::LazyLock::new(|| json!({ "action": "evidence_fixture" }));

fn request<'a>(
    precondition: PolicyCommitPrecondition,
    candidate: &'a Policy,
    change: DocumentChange<'a>,
) -> PolicyCommitRequest<'a> {
    PolicyCommitRequest {
        precondition,
        candidate,
        change,
        diff_summary: &DIFF,
    }
}

fn is_uuid_v4(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|uuid| uuid.get_version_num() == 4)
}

/// Every committed policy and tools change leaves exactly one evidence row
/// carrying the actor as the principal presented it (kind, subject, issuer,
/// auth mode), the operation the caller named, fresh event and operation
/// IDs, and the versions and shared revision of its outbox row. The tools
/// seed is the gateway's own write. Refused commits -- a stale ETag, a lost
/// initialize race, a tool name another lane holds -- leave none.
#[tokio::test]
async fn committed_document_changes_record_attributed_evidence_and_refusals_record_none() {
    let Some(admin_dsn) = locator() else {
        eprintln!("skipping: no test database locator; CI runs this test");
        return;
    };
    let _guard = DATABASE.lock().await;
    let database = create_test_database(&admin_dsn).await;
    let pool = migrated_pool(&database).await;
    let policies = PostgresPolicyStore::new(pool.clone());
    let tools = PostgresToolStore::new(pool.clone());

    let alice = crate::auth::Principal {
        user_id: "alice".to_owned(),
        issuer: Some("https://issuer.example".to_owned()),
        email: None,
        org_id: None,
        roles: vec!["admin".to_owned()],
        session_id: "session-a".to_owned(),
        auth_method: AuthMethod::ClientCertificate,
    };
    let initial = policy("evidence-initial", "reader");
    let first = PolicyControlPlane::commit(
        &policies,
        request(
            PolicyCommitPrecondition::Initialize,
            &initial,
            DocumentChange::by_principal(DocumentAction::PolicyPublish, &alice),
        ),
    )
    .await
    .expect("the initial policy commits");

    // A lost initialize race and a stale ETag write no evidence.
    let lost = PolicyControlPlane::commit(
        &policies,
        request(
            PolicyCommitPrecondition::Initialize,
            &initial,
            DocumentChange::test_policy("late-initializer"),
        ),
    )
    .await;
    assert_eq!(lost.err(), Some(PolicyCommitError::PreconditionFailed));
    let stale = PolicyControlPlane::commit(
        &policies,
        request(
            PolicyCommitPrecondition::Expected {
                etag: "\"sha256:stale\"".to_owned(),
            },
            &policy("evidence-stale", "reader"),
            DocumentChange::test_policy("stale-writer"),
        ),
    )
    .await;
    assert_eq!(stale.err(), Some(PolicyCommitError::PreconditionFailed));
    assert_eq!(count(&pool, "document_change_evidence").await, 1);

    let bob = ChangeActor::Principal {
        subject: "bob",
        issuer: None,
        auth_method: &AuthMethod::ServiceToken,
    };
    let second = PolicyControlPlane::commit(
        &policies,
        request(
            PolicyCommitPrecondition::Expected {
                etag: first.etag.clone(),
            },
            &policy("evidence-second", "writer"),
            DocumentChange {
                action: DocumentAction::PolicyRollback,
                actor: bob,
            },
        ),
    )
    .await
    .expect("the rollback-shaped commit wins");

    tools
        .seed_empty_document()
        .await
        .expect("the tools document seeds");
    // A second seed is a no-op that records nothing.
    tools
        .seed_empty_document()
        .await
        .expect("a repeated seed is a no-op");
    let seeded = tools
        .active_tools()
        .await
        .expect("active tools read")
        .expect("the seed is active");

    // A tool name another lane holds refuses the commit with nothing
    // written; the same document without it commits.
    pool.get()
        .await
        .expect("reservation checkout")
        .execute(
            "INSERT INTO greengateway.tool_name_reservations (tool_name, lane, owner_id) \
             VALUES ('held_by_mcp', 'mcp', 'other-connection')",
            &[],
        )
        .await
        .expect("a foreign reservation inserts");
    let taken = tools
        .commit_tools(
            PolicyCommitPrecondition::Expected {
                etag: seeded.etag.clone(),
            },
            &tools_document(&["held_by_mcp"]),
            DocumentChange::test_tools("tools-admin"),
            &DIFF,
        )
        .await;
    assert!(
        matches!(taken, Err(PolicyCommitError::ToolNameTaken { .. })),
        "{taken:?}"
    );
    let published = tools
        .commit_tools(
            PolicyCommitPrecondition::Expected { etag: seeded.etag },
            &tools_document(&["local_echo"]),
            DocumentChange::by_principal(DocumentAction::ToolsPublish, &alice),
            &DIFF,
        )
        .await
        .expect("a document with free names commits");

    let rows = evidence(&pool).await;
    let outbox = outbox(&pool).await;
    assert_eq!(rows.len(), 4, "{rows:#?}");
    assert_eq!(outbox.len(), 4, "{outbox:#?}");
    let expected = [
        (
            (
                "principal",
                "alice",
                Some("https://issuer.example"),
                "client_certificate",
            ),
            (
                "policy.publish",
                "policy",
                None,
                first.version,
                first.security_revision,
            ),
        ),
        (
            ("principal", "bob", None, "service_token"),
            (
                "policy.rollback",
                "policy",
                Some(first.version),
                second.version,
                second.security_revision,
            ),
        ),
        (
            ("system", "bootstrap", None, "system"),
            (
                "tools.publish",
                "tools",
                None,
                seeded.version,
                seeded.security_revision,
            ),
        ),
        (
            (
                "principal",
                "alice",
                Some("https://issuer.example"),
                "client_certificate",
            ),
            (
                "tools.publish",
                "tools",
                Some(seeded.version),
                published.version,
                published.security_revision,
            ),
        ),
    ];
    for (
        (row, outbox_row),
        ((kind, subject, issuer, mode), (action, resource, prior, new, revision)),
    ) in rows.iter().zip(&outbox).zip(expected)
    {
        assert_eq!(
            (
                row.actor_kind.as_str(),
                row.actor_user_id.as_str(),
                row.actor_issuer.as_deref(),
                row.actor_auth_mode.as_str(),
            ),
            (kind, subject, issuer, mode)
        );
        assert_eq!(
            (
                row.action.as_str(),
                row.resource_type.as_str(),
                row.prior_version,
                row.new_version,
                row.security_revision,
            ),
            (action, resource, prior, new, revision)
        );
        // The same change as its outbox row: revision, resource and the
        // version transition.
        assert_eq!(
            outbox_row,
            &(
                row.security_revision,
                row.resource_type.clone(),
                row.prior_version,
                row.new_version
            )
        );
        assert!(is_uuid_v4(&row.event_id), "{row:?}");
        assert!(is_uuid_v4(&row.operation_id), "{row:?}");
        assert_ne!(row.event_id, row.operation_id);
        assert!(!row.committed_at.is_empty());
    }
    let distinct = rows
        .iter()
        .flat_map(|row| [row.event_id.clone(), row.operation_id.clone()])
        .collect::<BTreeSet<_>>();
    assert_eq!(distinct.len(), rows.len() * 2, "no identity is reused");

    // The rows hold identifiers, revisions and the actor only: nothing of
    // either document.
    let rendered = format!("{rows:?}");
    for document_marker in [
        "evidence-initial",
        "evidence-second",
        "local_echo",
        "data:read",
    ] {
        assert!(!rendered.contains(document_marker), "{document_marker}");
    }

    // The version rows still name the subject, exactly as before.
    let version_actor: String = pool
        .get()
        .await
        .expect("version checkout")
        .query_one(
            "SELECT actor_user_id FROM greengateway.policy_documents WHERE version = $1",
            &[&second.version],
        )
        .await
        .expect("version row reads")
        .get(0);
    assert_eq!(version_actor, "bob");
}

/// A commit whose evidence cannot be written does not happen: the version,
/// the pointer, the shared revision and the outbox row roll back with the
/// failed insert, and the caller sees a store failure, never a precondition
/// failure it would answer as a stale ETag.
#[tokio::test]
async fn a_failed_document_evidence_insert_rolls_back_the_whole_commit() {
    let Some(admin_dsn) = locator() else {
        eprintln!("skipping: no test database locator; CI runs this test");
        return;
    };
    let _guard = DATABASE.lock().await;
    let database = create_test_database(&admin_dsn).await;
    let pool = migrated_pool(&database).await;
    let policies = PostgresPolicyStore::new(pool.clone());
    let tools = PostgresToolStore::new(pool.clone());
    let first = PolicyControlPlane::commit(
        &policies,
        request(
            PolicyCommitPrecondition::Initialize,
            &policy("faulted-initial", "reader"),
            DocumentChange::test_policy("installer"),
        ),
    )
    .await
    .expect("the initial policy commits");
    tools
        .seed_empty_document()
        .await
        .expect("the tools document seeds");
    let seeded = tools
        .active_tools()
        .await
        .expect("active tools read")
        .expect("seeded");
    let revision_before = policies
        .revision_source()
        .current()
        .await
        .expect("revision reads");
    let outbox_before = outbox(&pool).await;
    let evidence_before = evidence(&pool).await;
    // The recorder is this thread's, and the test's current-thread runtime
    // runs both stores on this thread.
    let recorder = crate::audit::sink::tests::CountingRecorder::default();
    let _recording = ::metrics::set_default_local_recorder(&recorder);
    let evidence_failures =
        || recorder.count(crate::metrics::AUTHORITY_EVENT_EVIDENCE_FAILURES_TOTAL, &[]);

    pool.get()
        .await
        .expect("failure trigger checkout")
        .batch_execute(
            r#"
            CREATE FUNCTION greengateway.fail_document_change_evidence()
            RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
                RAISE EXCEPTION 'injected evidence failure';
            END;
            $$;
            CREATE TRIGGER fail_document_change_evidence
            BEFORE INSERT ON greengateway.document_change_evidence
            FOR EACH ROW EXECUTE FUNCTION greengateway.fail_document_change_evidence();
            "#,
        )
        .await
        .expect("failure trigger should install");
    let failed_policy = PolicyControlPlane::commit(
        &policies,
        request(
            PolicyCommitPrecondition::Expected {
                etag: first.etag.clone(),
            },
            &policy("faulted-candidate", "writer"),
            DocumentChange::test_policy("faulted-admin"),
        ),
    )
    .await;
    assert!(
        matches!(failed_policy, Err(PolicyCommitError::Store(_))),
        "{failed_policy:?}"
    );
    let failed_tools = tools
        .commit_tools(
            PolicyCommitPrecondition::Expected {
                etag: seeded.etag.clone(),
            },
            &tools_document(&["faulted_tool"]),
            DocumentChange::test_tools("faulted-admin"),
            &DIFF,
        )
        .await;
    assert!(
        matches!(failed_tools, Err(PolicyCommitError::Store(_))),
        "{failed_tools:?}"
    );
    // Each refused commit is counted once, on the counter the evidence
    // write-failure alert pages on.
    assert_eq!(evidence_failures(), 2);
    pool.get()
        .await
        .expect("failure trigger cleanup checkout")
        .batch_execute(
            r#"
            DROP TRIGGER fail_document_change_evidence
                ON greengateway.document_change_evidence;
            DROP FUNCTION greengateway.fail_document_change_evidence();
            "#,
        )
        .await
        .expect("failure trigger should drop");

    let active = PolicyControlPlane::active(&policies)
        .await
        .expect("active policy reads")
        .expect("active policy exists");
    assert_eq!(
        (active.version, active.etag),
        (first.version, first.etag.clone())
    );
    assert_eq!(count(&pool, "policy_documents").await, 1);
    assert_eq!(count(&pool, "tool_documents").await, 1);
    assert_eq!(
        count(&pool, "tool_name_reservations").await,
        0,
        "the refused tools commit reserved nothing"
    );
    assert_eq!(outbox(&pool).await, outbox_before);
    assert_eq!(evidence(&pool).await, evidence_before);
    assert_eq!(
        policies
            .revision_source()
            .current()
            .await
            .expect("revision reads"),
        revision_before,
        "the failed commits consumed no revision"
    );

    // With the fault gone the same commit succeeds and records itself.
    PolicyControlPlane::commit(
        &policies,
        request(
            PolicyCommitPrecondition::Expected { etag: first.etag },
            &policy("faulted-candidate", "writer"),
            DocumentChange::test_policy("faulted-admin"),
        ),
    )
    .await
    .expect("the commit succeeds once evidence can be written");
    assert_eq!(evidence(&pool).await.len(), evidence_before.len() + 1);
    assert_eq!(evidence_failures(), 2, "a recorded commit counts nothing");
}

/// An unattributable or mislabeled change is refused before anything is
/// written, and the bounds are exactly the principal bounds: a 4,096-byte
/// subject and issuer are recorded, one byte more is refused.
#[tokio::test]
async fn unattributable_or_mislabeled_changes_are_refused_and_principal_bounds_are_recorded() {
    let Some(admin_dsn) = locator() else {
        eprintln!("skipping: no test database locator; CI runs this test");
        return;
    };
    let _guard = DATABASE.lock().await;
    let database = create_test_database(&admin_dsn).await;
    let pool = migrated_pool(&database).await;
    let policies = PostgresPolicyStore::new(pool.clone());
    let candidate = policy("bounded", "reader");
    let longest_subject = "s".repeat(EVIDENCE_ACTOR_MAX_BYTES);
    let longest_issuer = "i".repeat(EVIDENCE_ISSUER_MAX_BYTES);
    let too_long_subject = "s".repeat(EVIDENCE_ACTOR_MAX_BYTES + 1);
    let too_long_issuer = "i".repeat(EVIDENCE_ISSUER_MAX_BYTES + 1);
    let refused = [
        DocumentChange::test_policy(""),
        DocumentChange::test_policy(&too_long_subject),
        DocumentChange {
            action: DocumentAction::PolicyPublish,
            actor: ChangeActor::Principal {
                subject: "alice",
                issuer: Some(""),
                auth_method: &AuthMethod::Bearer,
            },
        },
        DocumentChange {
            action: DocumentAction::PolicyPublish,
            actor: ChangeActor::Principal {
                subject: "alice",
                issuer: Some(&too_long_issuer),
                auth_method: &AuthMethod::Bearer,
            },
        },
        // A tools action cannot describe a policy commit.
        DocumentChange::test_tools("alice"),
    ];
    for change in refused {
        let outcome = PolicyControlPlane::commit(
            &policies,
            request(PolicyCommitPrecondition::Initialize, &candidate, change),
        )
        .await;
        assert!(
            matches!(&outcome, Err(PolicyCommitError::Store(error))
                if error.kind() == RepositoryErrorKind::InvalidData),
            "{change:?}: {outcome:?}"
        );
    }
    assert_eq!(count(&pool, "policy_documents").await, 0);
    assert_eq!(count(&pool, "security_outbox").await, 0);
    assert_eq!(count(&pool, "document_change_evidence").await, 0);

    PolicyControlPlane::commit(
        &policies,
        request(
            PolicyCommitPrecondition::Initialize,
            &candidate,
            DocumentChange {
                action: DocumentAction::PolicyPublish,
                actor: ChangeActor::Principal {
                    subject: &longest_subject,
                    issuer: Some(&longest_issuer),
                    auth_method: &AuthMethod::Bearer,
                },
            },
        ),
    )
    .await
    .expect("the longest principal a validator accepts is recorded");
    let rows = evidence(&pool).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].actor_user_id, longest_subject);
    assert_eq!(
        rows[0].actor_issuer.as_deref(),
        Some(longest_issuer.as_str())
    );
}
