use serde_json::Value;
use uuid::Uuid;

use super::*;
use crate::authority_events::pseudonym::{test_support::generated_keyring, ReferenceCheck};

// Synthetic markers standing in for real identifiers. If any of them reaches
// a serialized record, the projection leaked an identifier.
const ACTOR_MARKER: &str = "standalone-actor-marker@example.test";
const ACTOR_ISSUER_MARKER: &str = "https://standalone-issuer-marker.example.test";
const TOKEN_MARKER: &str = "svc-standalone-token-marker";
const CONNECTION_MARKER: &str = "c0ffee00-5b8a-4c39-9a51-2f6c1d0e4b77";
const SECRET_MARKER: &str = "5ec7e700-0000-4000-8000-00000000beef";

/// A well-formed row of `shape`, with the revisions its table records.
fn evidence(shape: &StandaloneShape) -> StandaloneEvidence {
    let (resource_id, prior_version, new_version) = match shape.action {
        "service_token.issue" | "service_token.rotate" | "service_token.revoke" => {
            (Some(TOKEN_MARKER), None, None)
        }
        "connection.create" => (Some(CONNECTION_MARKER), None, Some(1)),
        "connection.replace" => (Some(CONNECTION_MARKER), Some(3), Some(4)),
        // A first binding on a Connection created without one.
        "credential.binding_change" => (Some(CONNECTION_MARKER), Some(0), Some(1)),
        "connection.delete" => (Some(CONNECTION_MARKER), Some(4), None),
        "secret.create" => (Some(SECRET_MARKER), None, Some(1)),
        "secret.rotate" => (Some(SECRET_MARKER), Some(1), Some(2)),
        "secret.delete" => (Some(SECRET_MARKER), Some(2), None),
        "secret.reencrypt" => (None, None, None),
        // A first catalog has nothing before it; the others advance one.
        "catalog.mcp.publish" => (Some(CONNECTION_MARKER), None, Some(1)),
        _ => (Some(CONNECTION_MARKER), Some(1), Some(2)),
    };
    StandaloneEvidence {
        source: shape.source,
        sequence: 7,
        event_id: Uuid::new_v4().to_string(),
        operation_id: Uuid::new_v4().to_string(),
        actor_user_id: ACTOR_MARKER.to_owned(),
        actor_issuer: Some(ACTOR_ISSUER_MARKER.to_owned()),
        actor_kind: Some("principal".to_owned()),
        actor_auth_mode: Some("bearer_token".to_owned()),
        action: shape.action.to_owned(),
        resource_id: resource_id.map(str::to_owned),
        prior_version,
        new_version,
        committed_at: "2026-11-05T12:34:56.123456789Z".to_owned(),
    }
}

fn delivery_schema() -> (Value, jsonschema::Validator) {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../docs/schemas/authority_event_delivery.v1.schema.json");
    let schema: Value = serde_json::from_str(
        &std::fs::read_to_string(&path).expect("the delivery schema should be readable"),
    )
    .expect("the delivery schema should be JSON");
    let validator = jsonschema::validator_for(&schema).expect("the delivery schema should compile");
    (schema, validator)
}

#[test]
fn every_standalone_operation_matches_the_published_schema() {
    let keyring = generated_keyring(Uuid::new_v4());
    let (schema, validator) = delivery_schema();
    let operations = schema["properties"]["operation"]["enum"]
        .as_array()
        .expect("operation is a closed enum");
    for shape in &STANDALONE_SHAPES {
        assert!(
            operations.contains(&Value::from(shape.action)),
            "the schema must name {}",
            shape.action
        );
        let evidence = evidence(shape);
        let record = project_standalone(&evidence, &keyring).expect("well-formed rows project");
        let value = serde_json::to_value(&record).expect("a record serializes");
        if let Err(error) = validator.validate(&value) {
            panic!("the published schema must accept {value}: {error}");
        }
        assert_eq!(record.schema_version, DELIVERY_SCHEMA_VERSION);
        assert_eq!(record.authority_id, keyring.authority_id().to_string());
        assert_eq!(record.event_id, evidence.event_id);
        assert_eq!(record.operation_id, evidence.operation_id);
        assert_eq!(record.sequence, "7");
        assert_eq!(record.operation, shape.action);
        assert_eq!(record.result, "committed");
        assert_eq!(record.committed_at, evidence.committed_at);
        assert_eq!(
            record.revision.security, None,
            "a standalone store has no shared security revision"
        );
        let parsed: DeliveryRecord = serde_json::from_value(value).expect("a record parses back");
        assert_eq!(parsed, record);
    }
}

/// The shape table is each evidence table's closed CHECK vocabulary, read
/// from the tables the real stores create.
#[test]
fn the_shapes_are_each_tables_closed_action_vocabulary() {
    let directory =
        std::env::temp_dir().join(format!("greengateway-standalone-shapes-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&directory).expect("scratch directory");
    let tokens = directory.join("tokens.sqlite");
    let connections = directory.join("connections.sqlite");
    drop(crate::auth::SqliteTokenStore::open(&tokens).expect("the token store opens"));
    drop(
        crate::connections::store::SqliteConnectionStore::open(&connections)
            .expect("the Connections store opens"),
    );
    for source in StandaloneEvidenceSource::ALL {
        let file = match source {
            StandaloneEvidenceSource::ServiceTokenChange => &tokens,
            _ => &connections,
        };
        let definition: String = rusqlite::Connection::open(file)
            .expect("the file opens")
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?1",
                [source.table()],
                |row| row.get(0),
            )
            .expect("the evidence table exists");
        let (_, vocabulary) = definition
            .split_once("action IN (")
            .expect("the table closes its action vocabulary");
        let (vocabulary, _) = vocabulary.split_once(')').expect("the list ends");
        let mut checked: Vec<&str> = vocabulary
            .split(',')
            .map(|action| action.trim().trim_matches('\''))
            .collect();
        checked.sort_unstable();
        let mut shaped: Vec<&str> = STANDALONE_SHAPES
            .iter()
            .filter(|shape| shape.source == source)
            .map(|shape| shape.action)
            .collect();
        shaped.sort_unstable();
        assert_eq!(shaped, checked, "{}", source.table());
    }
    let _ = std::fs::remove_dir_all(directory);
}

#[test]
fn revisions_follow_each_tables_transition() {
    let keyring = generated_keyring(Uuid::new_v4());
    let revision = |action: &str| {
        let shape = STANDALONE_SHAPES
            .iter()
            .find(|shape| shape.action == action)
            .expect("a known action");
        let record = project_standalone(&evidence(shape), &keyring).expect("projects");
        (
            record.resource.kind,
            record.revision.axis,
            record.revision.before,
            record.revision.after,
        )
    };
    let owned = |kind: &str, axis: &str, before: Option<&str>, after: Option<&str>| {
        (
            kind.to_owned(),
            axis.to_owned(),
            before.map(str::to_owned),
            after.map(str::to_owned),
        )
    };
    // The token database keeps no token revision, so nothing is invented.
    for action in [
        "service_token.issue",
        "service_token.rotate",
        "service_token.revoke",
    ] {
        assert_eq!(
            revision(action),
            owned("service_token", "token", None, None),
            "{action}"
        );
    }
    assert_eq!(
        revision("connection.create"),
        owned("connection", "connection", None, Some("1"))
    );
    assert_eq!(
        revision("connection.replace"),
        owned("connection", "connection", Some("3"), Some("4"))
    );
    // A binding change is the Connection's, on its credential axis, from 0
    // before a first binding, exactly as cluster mode delivers it.
    assert_eq!(
        revision("credential.binding_change"),
        owned("connection", "credential", Some("0"), Some("1"))
    );
    assert_eq!(
        revision("connection.delete"),
        owned("connection", "connection", Some("4"), None)
    );
    assert_eq!(
        revision("secret.create"),
        owned("local_secret", "secret", None, Some("1"))
    );
    assert_eq!(
        revision("secret.rotate"),
        owned("local_secret", "secret", Some("1"), Some("2"))
    );
    assert_eq!(
        revision("secret.delete"),
        owned("local_secret", "secret", Some("2"), None)
    );
    assert_eq!(
        revision("secret.reencrypt"),
        owned("local_secret", "maintenance", None, None)
    );
    assert_eq!(
        revision("catalog.mcp.publish"),
        owned("catalog", "catalog", None, Some("1"))
    );
    for action in [
        "catalog.openapi.publish",
        "catalog.overlay.replace",
        "catalog.overlay.delete",
    ] {
        assert_eq!(
            revision(action),
            owned("catalog", "catalog", Some("1"), Some("2")),
            "{action}"
        );
    }
}

#[test]
fn references_name_the_recorded_identities_and_carry_none_of_them() {
    let keyring = generated_keyring(Uuid::new_v4());
    for shape in &STANDALONE_SHAPES {
        let evidence = evidence(shape);
        let record = project_standalone(&evidence, &keyring).expect("projects");
        let serialized = serde_json::to_string(&record).expect("a record serializes");
        for marker in [
            ACTOR_MARKER,
            ACTOR_ISSUER_MARKER,
            TOKEN_MARKER,
            CONNECTION_MARKER,
            SECRET_MARKER,
        ] {
            assert!(
                !serialized.contains(marker),
                "a delivered record must never carry a raw identifier: {serialized}"
            );
        }
        assert_eq!(
            keyring
                .verify(
                    ReferenceDomain::ActorRecorded,
                    &[ACTOR_MARKER],
                    &record.actor.recorded_ref
                )
                .expect("the actor reference checks"),
            ReferenceCheck::Current
        );
        assert_eq!(
            keyring
                .verify(
                    ReferenceDomain::ActorIssuer,
                    &[ACTOR_ISSUER_MARKER],
                    record
                        .actor
                        .issuer_ref
                        .as_deref()
                        .expect("an issuer reference"),
                )
                .expect("the issuer reference checks"),
            ReferenceCheck::Current
        );
        let (domain, component) = match shape.action {
            "secret.reencrypt" => (ReferenceDomain::LocalSecret, LOCAL_SECRET_STORE_COMPONENT),
            action if action.starts_with("service_token.") => {
                (ReferenceDomain::ServiceToken, TOKEN_MARKER)
            }
            action if action.starts_with("secret.") => {
                (ReferenceDomain::LocalSecret, SECRET_MARKER)
            }
            action if action.starts_with("catalog.") => {
                (ReferenceDomain::Catalog, CONNECTION_MARKER)
            }
            _ => (ReferenceDomain::Connection, CONNECTION_MARKER),
        };
        assert_eq!(
            keyring
                .verify(domain, &[component], &record.resource.reference)
                .expect("the resource reference checks"),
            ReferenceCheck::Current,
            "{}",
            shape.action
        );
    }
}

/// A redelivery projects the same row to the same bytes under the same key.
#[test]
fn the_same_row_projects_to_identical_bytes() {
    let keyring = generated_keyring(Uuid::new_v4());
    for shape in &STANDALONE_SHAPES {
        let evidence = evidence(shape);
        let first = serde_json::to_string(&project_standalone(&evidence, &keyring).expect("ok"))
            .expect("serializes");
        let second = serde_json::to_string(&project_standalone(&evidence, &keyring).expect("ok"))
            .expect("serializes");
        assert_eq!(first, second);
    }
}

/// The token table's rows written before its actor columns record no kind,
/// auth mode or issuer, and the record says `null` for all three.
#[test]
fn a_token_row_without_actor_metadata_guesses_none() {
    let keyring = generated_keyring(Uuid::new_v4());
    let mut row = evidence(&STANDALONE_SHAPES[1]);
    row.actor_issuer = None;
    row.actor_kind = None;
    row.actor_auth_mode = None;
    let record = project_standalone(&row, &keyring).expect("projects");
    assert_eq!(
        (
            record.actor.kind,
            record.actor.auth_mode,
            record.actor.issuer_ref
        ),
        (None, None, None)
    );
}

#[test]
fn rows_that_cannot_be_projected_faithfully_are_refused() {
    let keyring = generated_keyring(Uuid::new_v4());
    let by_action = |action: &str| {
        evidence(
            STANDALONE_SHAPES
                .iter()
                .find(|shape| shape.action == action)
                .expect("a known action"),
        )
    };
    let refused = |row: StandaloneEvidence| {
        project_standalone(&row, &keyring).expect_err("the row is refused")
    };

    let mut wrong_table = by_action("connection.delete");
    wrong_table.source = StandaloneEvidenceSource::ServiceTokenChange;
    assert_eq!(refused(wrong_table), ProjectionError::UnknownAction);
    let mut unknown = by_action("connection.delete");
    unknown.action = "connection.purge".to_owned();
    assert_eq!(refused(unknown), ProjectionError::UnknownAction);

    let mut created_twice = by_action("secret.create");
    created_twice.prior_version = Some(1);
    assert_eq!(refused(created_twice), ProjectionError::InvalidEvidence);
    let mut backwards = by_action("secret.rotate");
    backwards.new_version = Some(1);
    assert_eq!(refused(backwards), ProjectionError::InvalidEvidence);
    let mut revived = by_action("connection.delete");
    revived.new_version = Some(5);
    assert_eq!(refused(revived), ProjectionError::InvalidEvidence);
    let mut stale_catalog = by_action("catalog.overlay.replace");
    stale_catalog.new_version = Some(1);
    assert_eq!(refused(stale_catalog), ProjectionError::InvalidEvidence);
    let mut revised_token = by_action("service_token.revoke");
    revised_token.new_version = Some(2);
    assert_eq!(refused(revised_token), ProjectionError::InvalidEvidence);
    let mut named_batch = by_action("secret.reencrypt");
    named_batch.resource_id = Some(SECRET_MARKER.to_owned());
    assert_eq!(refused(named_batch), ProjectionError::InvalidEvidence);
    let mut unnamed_secret = by_action("secret.delete");
    unnamed_secret.resource_id = None;
    assert_eq!(refused(unnamed_secret), ProjectionError::MissingEvidence);

    let mut anonymous = by_action("connection.create");
    anonymous.actor_user_id = String::new();
    assert_eq!(refused(anonymous), ProjectionError::MissingEvidence);
    let mut mismatched = by_action("connection.create");
    mismatched.actor_kind = Some("service_token".to_owned());
    assert_eq!(refused(mismatched), ProjectionError::InvalidEvidence);
    let mut unordered = by_action("connection.create");
    unordered.sequence = 0;
    assert_eq!(refused(unordered), ProjectionError::InvalidEvidence);
    let mut offset = by_action("connection.create");
    offset.committed_at = "2026-11-05T12:34:56+00:00".to_owned();
    assert_eq!(refused(offset), ProjectionError::InvalidEvidence);
    let mut not_a_uuid = by_action("connection.create");
    not_a_uuid.event_id = CONNECTION_MARKER.replace('c', "g");
    assert_eq!(refused(not_a_uuid), ProjectionError::InvalidEvidence);
}
