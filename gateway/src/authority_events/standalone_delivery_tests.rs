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
        let record = project_standalone(&evidence, &keyring, AuthorityEventFormat::DeliveryV1)
            .expect("well-formed rows project");
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
        let record =
            project_standalone(&evidence(shape), &keyring, AuthorityEventFormat::DeliveryV1)
                .expect("projects");
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
        let record = project_standalone(&evidence, &keyring, AuthorityEventFormat::DeliveryV1)
            .expect("projects");
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
        let first = serde_json::to_string(
            &project_standalone(&evidence, &keyring, AuthorityEventFormat::DeliveryV1).expect("ok"),
        )
        .expect("serializes");
        let second = serde_json::to_string(
            &project_standalone(&evidence, &keyring, AuthorityEventFormat::DeliveryV1).expect("ok"),
        )
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
    let record =
        project_standalone(&row, &keyring, AuthorityEventFormat::DeliveryV1).expect("projects");
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
        project_standalone(&row, &keyring, AuthorityEventFormat::DeliveryV1)
            .expect_err("the row is refused")
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

// ---------------------------------------------------------------------------
// The qualification rule in standalone mode (issue #425). A token row records
// no revision, so it stays a delivery record whatever its operation ID: the
// keyed revocations SQLite has written since #765 carry a caller UUIDv7, an
// issuer-bound principal and no revisions, and must keep their delivered
// bytes. The Connection, local-secret and catalog tables record revisions,
// so a keyed principal row there is an `authority_event.v1` under the
// negotiated format, and only there.
// ---------------------------------------------------------------------------

fn v1_schema() -> jsonschema::Validator {
    let schema: Value = serde_json::from_str(include_str!(
        "../../../docs/schemas/authority_event.v1.schema.json"
    ))
    .expect("the v1 schema should be JSON");
    jsonschema::validator_for(&schema).expect("the v1 schema should compile")
}

fn caller_key(seed: u8) -> String {
    crate::auth::tokens::test_revoke_operation_id(seed).to_string()
}

#[test]
fn a_keyed_principal_revoke_with_null_revisions_stays_a_legacy_record_under_qualified_v1() {
    use crate::{
        auth::{
            change_actor::ChangeActor,
            tokens::{CreateTokenRequest, TokenStore},
            SqliteTokenStore,
        },
        storage::standalone_authority_events::StandaloneEvidenceAuthority,
    };

    let directory =
        std::env::temp_dir().join(format!("greengateway-keyed-revoke-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&directory).expect("scratch directory");
    let tokens = SqliteTokenStore::open(directory.join("tokens.sqlite")).expect("the store opens");
    // What the keyed POST route records since #765: a provider-authenticated
    // principal with a canonical issuer, and the caller's UUIDv7.
    let actor = ChangeActor::for_test_with_issuer(ACTOR_MARKER, ACTOR_ISSUER_MARKER);
    let created = tokens
        .create(
            CreateTokenRequest {
                scopes: vec!["admin:connections:read".to_owned()],
                created_by: ACTOR_MARKER.to_owned(),
                expires_at: None,
            },
            &actor,
        )
        .expect("the token issues");
    let key = crate::auth::tokens::test_revoke_operation_id(11);
    tokens
        .revoke_with_operation(&created.record.id, &actor, Some(key))
        .expect("the token revokes")
        .expect("the token exists");
    let rows = tokens
        .read_after(StandaloneEvidenceSource::ServiceTokenChange, 0, 10)
        .expect("the evidence reads");
    let revoke = rows
        .iter()
        .find(|row| row.action == "service_token.revoke")
        .expect("the revoke recorded its evidence");
    assert_eq!(revoke.operation_id, key.to_string());
    assert_eq!(revoke.actor_kind.as_deref(), Some("principal"));
    assert_eq!(revoke.actor_issuer.as_deref(), Some(ACTOR_ISSUER_MARKER));
    assert_eq!((revoke.prior_version, revoke.new_version), (None, None));

    let keyring = generated_keyring(Uuid::new_v4());
    for row in &rows {
        let legacy = project_standalone(row, &keyring, AuthorityEventFormat::DeliveryV1)
            .expect("the row projects");
        let negotiated = project_standalone(row, &keyring, AuthorityEventFormat::QualifiedV1)
            .expect("a #765 row never stalls an opted-in stream");
        assert!(negotiated.qualified.is_none(), "{}", row.action);
        assert_eq!(
            negotiated
                .wire_json(AuthorityEventFormat::QualifiedV1)
                .unwrap(),
            serde_json::to_string(&legacy).unwrap(),
            "{}: the delivered bytes do not change",
            row.action
        );
    }
    drop(tokens);
    let _ = std::fs::remove_dir_all(directory);
}

#[test]
fn a_token_row_with_a_revision_it_should_not_have_stalls() {
    let keyring = generated_keyring(Uuid::new_v4());
    for shape in STANDALONE_SHAPES
        .iter()
        .filter(|shape| shape.source == StandaloneEvidenceSource::ServiceTokenChange)
    {
        for (prior, new) in [(None, Some(1)), (Some(1), Some(2)), (Some(1), None)] {
            let mut row = evidence(shape);
            row.operation_id = caller_key(12);
            row.prior_version = prior;
            row.new_version = new;
            for format in [
                AuthorityEventFormat::DeliveryV1,
                AuthorityEventFormat::QualifiedV1,
            ] {
                assert_eq!(
                    project_standalone(&row, &keyring, format).expect_err("the row stalls"),
                    ProjectionError::InvalidEvidence,
                    "{} {prior:?} {new:?}",
                    shape.action
                );
            }
        }
    }
}

#[test]
fn a_keyed_principal_row_of_a_revised_source_is_qualified_under_the_negotiated_format_only() {
    let keyring = generated_keyring(Uuid::new_v4());
    let validator = v1_schema();
    let subject = keyring
        .derive(
            ReferenceDomain::ActorSubject,
            &[ACTOR_ISSUER_MARKER, ACTOR_MARKER],
        )
        .unwrap();
    let mut sources = Vec::new();
    for shape in STANDALONE_SHAPES.iter().filter(|shape| {
        shape.source != StandaloneEvidenceSource::ServiceTokenChange
            && shape.action != "secret.reencrypt"
    }) {
        let action = shape.action;
        let unkeyed = evidence(shape);
        let mut row = unkeyed.clone();
        row.operation_id = caller_key(13);

        let record = project_standalone(&row, &keyring, AuthorityEventFormat::QualifiedV1)
            .unwrap_or_else(|error| panic!("{action}: a keyed principal row qualifies: {error}"));
        let wire = record.wire_json(AuthorityEventFormat::QualifiedV1).unwrap();
        let event: Value = serde_json::from_str(&wire).unwrap();
        if let Err(error) = validator.validate(&event) {
            panic!("{action}: the v1 schema must accept {event}: {error}");
        }
        assert_eq!(event["schema_version"], "authority_event.v1", "{action}");
        assert_eq!(event["operation_id"], row.operation_id.as_str(), "{action}");
        assert_eq!(event["actor"]["subject_ref"], subject.as_str(), "{action}");
        assert_eq!(event["actor"]["auth_mode"], "bearer_token", "{action}");
        assert_eq!(event["revision"]["security"], Value::Null, "{action}");
        let (kind, reference) = if action == "credential.binding_change" {
            (
                "credential_binding".to_owned(),
                keyring
                    .derive(ReferenceDomain::CredentialBinding, &[CONNECTION_MARKER])
                    .unwrap()
                    .as_str()
                    .to_owned(),
            )
        } else {
            (
                record.resource.kind.clone(),
                record.resource.reference.clone(),
            )
        };
        assert_eq!(event["resource"]["kind"], kind.as_str(), "{action}");
        assert_eq!(event["resource"]["ref"], reference.as_str(), "{action}");
        for marker in [
            ACTOR_MARKER,
            ACTOR_ISSUER_MARKER,
            CONNECTION_MARKER,
            SECRET_MARKER,
        ] {
            assert!(!wire.contains(marker), "{action}: raw identifier in {wire}");
        }

        // The default format delivers the same row as before, byte for byte.
        let legacy = project_standalone(&row, &keyring, AuthorityEventFormat::DeliveryV1)
            .expect("the row projects");
        assert!(legacy.qualified.is_none(), "{action}");
        assert_eq!(
            record.wire_json(AuthorityEventFormat::DeliveryV1).unwrap(),
            serde_json::to_string(&legacy).unwrap(),
            "{action}"
        );

        // An unkeyed row, or a gateway service token behind a key, keeps
        // the delivery record under the negotiated format.
        let mut service_token = row.clone();
        service_token.actor_kind = Some("service_token".to_owned());
        service_token.actor_auth_mode = Some("service_token".to_owned());
        service_token.actor_issuer = None;
        for kept in [unkeyed, service_token] {
            let negotiated = project_standalone(&kept, &keyring, AuthorityEventFormat::QualifiedV1)
                .expect("the row projects");
            let expected = project_standalone(&kept, &keyring, AuthorityEventFormat::DeliveryV1)
                .expect("the row projects");
            assert_eq!(
                negotiated
                    .wire_json(AuthorityEventFormat::QualifiedV1)
                    .unwrap(),
                serde_json::to_string(&expected).unwrap(),
                "{action}"
            );
        }

        // A key on an actor no writer binds one to stalls the opted-in
        // stream, and only that stream.
        let mut issuerless = row.clone();
        issuerless.actor_issuer = None;
        assert_eq!(
            project_standalone(&issuerless, &keyring, AuthorityEventFormat::QualifiedV1)
                .expect_err("the batch stalls"),
            ProjectionError::InvalidEvidence,
            "{action}"
        );
        project_standalone(&issuerless, &keyring, AuthorityEventFormat::DeliveryV1)
            .expect("the default format never stalls on a key");
        if !sources.contains(&shape.source) {
            sources.push(shape.source);
        }
    }
    assert_eq!(
        sources,
        [
            StandaloneEvidenceSource::ConnectionChange,
            StandaloneEvidenceSource::LocalSecretChange,
            StandaloneEvidenceSource::CatalogChange,
        ]
    );
}
