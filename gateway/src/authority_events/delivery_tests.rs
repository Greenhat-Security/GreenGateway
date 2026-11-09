use serde_json::Value;

use super::*;
use crate::authority_events::pseudonym::{test_support::generated_keyring, ReferenceCheck};
use crate::authority_events::standalone_delivery::{StandaloneShape, STANDALONE_SHAPES};

// Synthetic markers standing in for real identifiers. If any of them reaches
// a serialized record, the projection leaked an identifier.
const ACTOR_MARKER: &str = "actor-marker@example.test";
const CONNECTION_MARKER: &str = "7d1f3f0e-5b8a-4c39-9a51-2f6c1d0e4b77";
const TOKEN_MARKER: &str = "svc-token-marker";
const ISSUER_MARKER: &str = "https://issuer-marker.example.test";
/// The acting principal's issuer, distinct from a revoked token's.
const ACTOR_ISSUER_MARKER: &str = "https://actor-issuer-marker.example.test";
const JTI_DIGEST_MARKER: &str = "abababababababababababababababababababababababababababababababab";
/// An admin session's random ID, as the evidence row stores it.
const SESSION_MARKER: &str = "5e551011-0000-4000-8000-000000000001";
/// The Connection a catalog belongs to, as catalog evidence stores it.
const CATALOG_MARKER: &str = "ca7a1060-0000-4000-8000-0000000000c1";

/// The document a row of the document table names by its resource type.
fn document_of(action: &str) -> &'static str {
    match action {
        ACTION_TOOLS_PUBLISH => DOCUMENT_TOOLS,
        ACTION_POLICY_TESTS_PUBLISH => DOCUMENT_POLICY_TESTS,
        // The import's activation of the policy; [`document_evidence`] builds
        // its tools activation.
        _ => DOCUMENT_POLICY,
    }
}

/// A document row of `resource_type` recording `action`.
fn document_evidence(action: &str, resource_type: &str) -> JournaledEvidence {
    JournaledEvidence {
        resource_id: Some(resource_type.to_owned()),
        ..evidence(JournalSource::DocumentChange, action)
    }
}

fn evidence(source: JournalSource, action: &str) -> JournaledEvidence {
    let (resource_owner, resource_id, prior_version, new_version) = match source {
        // A create is the Connection's first version and a replace advances
        // one; a binding change advances the credential revision, here the
        // first binding of a Connection created without one.
        JournalSource::ConnectionChange if action == ACTION_CONNECTION_CREATE => {
            (None, CONNECTION_MARKER, None, Some(1))
        }
        JournalSource::ConnectionChange if action == ACTION_CONNECTION_REPLACE => {
            (None, CONNECTION_MARKER, Some(3), Some(4))
        }
        JournalSource::ConnectionChange if action == ACTION_CREDENTIAL_BINDING_CHANGE => {
            (None, CONNECTION_MARKER, Some(0), Some(1))
        }
        JournalSource::ConnectionChange => (None, CONNECTION_MARKER, Some(3), None),
        // An issue is the token's first revision; a rotate or a revoke
        // advances one.
        JournalSource::ServiceTokenChange if action == ACTION_SERVICE_TOKEN_ISSUE => {
            (None, TOKEN_MARKER, None, Some(1))
        }
        JournalSource::ServiceTokenChange => (None, TOKEN_MARKER, Some(1), Some(2)),
        JournalSource::JwtRevocation => (Some(ISSUER_MARKER), JTI_DIGEST_MARKER, None, None),
        // A document or catalog commit activates its next version.
        JournalSource::DocumentChange => (None, document_of(action), Some(3), Some(4)),
        JournalSource::CatalogChange => (None, CATALOG_MARKER, Some(2), Some(3)),
        // The read leaves every column the session table lacks empty.
        JournalSource::AdminSession => {
            return JournaledEvidence {
                source,
                resource_owner: None,
                resource_id: Some(SESSION_MARKER.to_owned()),
                prior_version: None,
                new_version: None,
                security_revision: None,
                actor_issuer: None,
                actor_kind: None,
                actor_auth_mode: None,
                revision_axis: None,
                ..evidence(JournalSource::JwtRevocation, action)
            };
        }
    };
    // Only a Connection change row names its axis (migration 28).
    let revision_axis = match source {
        JournalSource::ConnectionChange if action == ACTION_CREDENTIAL_BINDING_CHANGE => {
            Some("credential".to_owned())
        }
        JournalSource::ConnectionChange => Some("connection".to_owned()),
        _ => None,
    };
    JournaledEvidence {
        position: 41,
        event_id: Uuid::new_v4().to_string(),
        source,
        operation_id: Some(Uuid::new_v4().to_string()),
        actor_user_id: Some(ACTOR_MARKER.to_owned()),
        action: Some(action.to_owned()),
        resource_owner: resource_owner.map(str::to_owned),
        resource_id: Some(resource_id.to_owned()),
        prior_version,
        new_version,
        security_revision: Some(17),
        committed_at: Some("2026-10-21T12:34:56.123456Z".to_owned()),
        actor_issuer: Some(ACTOR_ISSUER_MARKER.to_owned()),
        actor_kind: Some("principal".to_owned()),
        actor_auth_mode: Some("session_cookie".to_owned()),
        revision_axis,
    }
}

/// The same evidence with the actor metadata a row of the given shape
/// records (`None` everywhere for a row committed before migration 24).
fn with_actor(
    mut evidence: JournaledEvidence,
    kind: Option<&str>,
    auth_mode: Option<&str>,
    issuer: Option<&str>,
) -> JournaledEvidence {
    evidence.actor_kind = kind.map(str::to_owned);
    evidence.actor_auth_mode = auth_mode.map(str::to_owned);
    evidence.actor_issuer = issuer.map(str::to_owned);
    evidence
}

fn every_delivered_shape() -> Vec<JournaledEvidence> {
    let mut shapes = vec![
        evidence(JournalSource::ConnectionChange, ACTION_CONNECTION_CREATE),
        evidence(JournalSource::ConnectionChange, ACTION_CONNECTION_REPLACE),
        evidence(
            JournalSource::ConnectionChange,
            ACTION_CREDENTIAL_BINDING_CHANGE,
        ),
        evidence(JournalSource::ConnectionChange, ACTION_CONNECTION_DELETE),
        evidence(
            JournalSource::ServiceTokenChange,
            ACTION_SERVICE_TOKEN_ISSUE,
        ),
        evidence(
            JournalSource::ServiceTokenChange,
            ACTION_SERVICE_TOKEN_ROTATE,
        ),
        evidence(
            JournalSource::ServiceTokenChange,
            ACTION_SERVICE_TOKEN_REVOKE,
        ),
        evidence(JournalSource::JwtRevocation, ACTION_JWT_REVOKE),
        evidence(JournalSource::AdminSession, ACTION_ADMIN_SESSION_GRANT),
        evidence(JournalSource::AdminSession, ACTION_ADMIN_SESSION_WITHDRAW),
    ];
    shapes.extend(
        POLICY_ACTIONS
            .into_iter()
            .chain([
                ACTION_TOOLS_PUBLISH,
                ACTION_CONFIGURATION_IMPORT,
                ACTION_POLICY_TESTS_PUBLISH,
            ])
            .map(|action| evidence(JournalSource::DocumentChange, action)),
    );
    shapes.push(document_evidence(
        ACTION_CONFIGURATION_IMPORT,
        DOCUMENT_TOOLS,
    ));
    shapes.extend(
        CATALOG_ACTIONS
            .into_iter()
            .map(|action| evidence(JournalSource::CatalogChange, action)),
    );
    shapes
}

const CATALOG_ACTIONS: [&str; 4] = [
    ACTION_CATALOG_MCP_PUBLISH,
    ACTION_CATALOG_OPENAPI_PUBLISH,
    ACTION_CATALOG_OVERLAY_REPLACE,
    ACTION_CATALOG_OVERLAY_DELETE,
];

fn delivery_schema() -> jsonschema::Validator {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../docs/schemas/authority_event_delivery.v1.schema.json");
    let schema: Value = serde_json::from_str(
        &std::fs::read_to_string(&path).expect("the delivery schema should be readable"),
    )
    .expect("the delivery schema should be JSON");
    jsonschema::validator_for(&schema).expect("the delivery schema should compile")
}

#[test]
fn every_delivered_operation_matches_the_published_schema() {
    let keyring = generated_keyring(Uuid::new_v4());
    let validator = delivery_schema();
    for evidence in every_delivered_shape() {
        let record = project(&evidence, &keyring).expect("well-formed evidence projects");
        let value = serde_json::to_value(&record).expect("a record serializes");
        if let Err(error) = validator.validate(&value) {
            panic!("the published schema must accept {value}: {error}");
        }
        assert_eq!(record.schema_version, DELIVERY_SCHEMA_VERSION);
        assert_eq!(record.event_id, evidence.event_id);
        assert_eq!(record.sequence, "41");
        assert_eq!(record.result, "committed");
        assert_eq!(record.committed_at, "2026-10-21T12:34:56.123456Z");
        assert_eq!(record.authority_id, keyring.authority_id().to_string());
        // The record round-trips through its own closed shape.
        let parsed: DeliveryRecord = serde_json::from_value(value).expect("a record parses back");
        assert_eq!(parsed, record);
    }
}

#[test]
fn the_schema_enumerates_exactly_the_delivered_operations() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../docs/schemas/authority_event_delivery.v1.schema.json");
    let schema: Value =
        serde_json::from_str(&std::fs::read_to_string(&path).expect("schema readable"))
            .expect("schema is JSON");
    let operations: Vec<&str> = schema["properties"]["operation"]["enum"]
        .as_array()
        .expect("operation is a closed enum")
        .iter()
        .map(|value| value.as_str().expect("operations are strings"))
        .collect();
    // What either mode delivers: the journal's operations and the
    // standalone stores' (`super::super::standalone_delivery`).
    let shapes = every_delivered_shape();
    let mut delivered: Vec<&str> = shapes
        .iter()
        .map(|evidence| evidence.action.as_deref().expect("fixture has an action"))
        .chain(STANDALONE_SHAPES.iter().map(|shape| shape.action))
        .collect();
    delivered.sort_unstable();
    // The import activates either document under one operation code, and
    // both modes deliver the catalog publications.
    delivered.dedup();
    assert_eq!(operations, delivered);
    // Every resource kind and axis either mode's projection names, and
    // nothing else.
    let keyring = generated_keyring(Uuid::new_v4());
    let enumerated = |path: [&str; 2]| -> Vec<String> {
        let mut values: Vec<String> = schema["properties"][path[0]]["properties"][path[1]]["enum"]
            .as_array()
            .expect("a closed enum")
            .iter()
            .map(|value| value.as_str().expect("strings").to_owned())
            .collect();
        values.sort_unstable();
        values
    };
    let records: Vec<DeliveryRecord> = shapes
        .iter()
        .map(|evidence| project(evidence, &keyring).expect("well-formed evidence projects"))
        .collect();
    let projected = |field: fn(&DeliveryRecord) -> &str,
                     standalone: fn(&StandaloneShape) -> &'static str|
     -> Vec<String> {
        let mut values: Vec<String> = records
            .iter()
            .map(|record| field(record).to_owned())
            .chain(
                STANDALONE_SHAPES
                    .iter()
                    .map(|shape| standalone(shape).to_owned()),
            )
            .collect();
        values.sort_unstable();
        values.dedup();
        values
    };
    assert_eq!(
        enumerated(["resource", "kind"]),
        projected(
            |record| record.resource.kind.as_str(),
            |shape| shape.resource_kind
        )
    );
    assert_eq!(
        enumerated(["revision", "axis"]),
        projected(|record| record.revision.axis.as_str(), |shape| shape.axis)
    );
    // A schema the record does not satisfy is not a closed contract.
    assert_eq!(schema["additionalProperties"], Value::Bool(false));
    for object in ["actor", "resource", "revision"] {
        assert_eq!(
            schema["properties"][object]["additionalProperties"],
            Value::Bool(false),
            "{object} must be closed"
        );
    }
}

#[test]
fn revisions_follow_the_v1_transition_of_each_operation() {
    let keyring = generated_keyring(Uuid::new_v4());
    let revision = |source, action| {
        project(&evidence(source, action), &keyring)
            .expect("well-formed evidence projects")
            .revision
    };

    let deleted = revision(JournalSource::ConnectionChange, ACTION_CONNECTION_DELETE);
    assert_eq!(
        (
            deleted.axis.as_str(),
            deleted.before.as_deref(),
            deleted.after.as_deref()
        ),
        ("connection", Some("3"), None)
    );
    assert_eq!(deleted.security.as_deref(), Some("17"));

    // A Connection create starts its specification version chain, a replace
    // advances it, and a binding change advances the credential revision,
    // from 0 for a Connection that had no credential authority.
    for (action, axis, before, after) in [
        (ACTION_CONNECTION_CREATE, "connection", None, Some("1")),
        (
            ACTION_CONNECTION_REPLACE,
            "connection",
            Some("3"),
            Some("4"),
        ),
        (
            ACTION_CREDENTIAL_BINDING_CHANGE,
            "credential",
            Some("0"),
            Some("1"),
        ),
    ] {
        let changed = revision(JournalSource::ConnectionChange, action);
        assert_eq!(
            (
                changed.axis.as_str(),
                changed.before.as_deref(),
                changed.after.as_deref(),
                changed.security.as_deref()
            ),
            (axis, before, after, Some("17")),
            "{action}"
        );
    }

    // An issue creates the token's first revision: nothing before it.
    let issued = revision(
        JournalSource::ServiceTokenChange,
        ACTION_SERVICE_TOKEN_ISSUE,
    );
    assert_eq!(
        (
            issued.axis.as_str(),
            issued.before.as_deref(),
            issued.after.as_deref(),
            issued.security.as_deref()
        ),
        ("token", None, Some("1"), Some("17"))
    );

    for action in [ACTION_SERVICE_TOKEN_ROTATE, ACTION_SERVICE_TOKEN_REVOKE] {
        let advanced = revision(JournalSource::ServiceTokenChange, action);
        assert_eq!(
            (
                advanced.axis.as_str(),
                advanced.before.as_deref(),
                advanced.after.as_deref()
            ),
            ("token", Some("1"), Some("2"))
        );
    }

    // A JWT revocation has no version chain: the shared revision is its axis.
    let revoked = revision(JournalSource::JwtRevocation, ACTION_JWT_REVOKE);
    assert_eq!(
        (
            revoked.axis.as_str(),
            revoked.before.as_deref(),
            revoked.after.as_deref(),
            revoked.security.as_deref()
        ),
        ("jwt_revocation", None, Some("17"), Some("17"))
    );

    // A session is granted once and withdrawn once: its one revision is
    // created by the grant and deleted by the withdrawal, and it takes no
    // shared revision.
    let granted = revision(JournalSource::AdminSession, ACTION_ADMIN_SESSION_GRANT);
    let withdrawn = revision(JournalSource::AdminSession, ACTION_ADMIN_SESSION_WITHDRAW);
    let shape = |revision: &DeliveryRevision| {
        (
            revision.axis.clone(),
            revision.before.clone(),
            revision.after.clone(),
            revision.security.clone(),
        )
    };
    assert_eq!(
        shape(&granted),
        ("session".to_owned(), None, Some("1".to_owned()), None)
    );
    assert_eq!(
        shape(&withdrawn),
        ("session".to_owned(), Some("1".to_owned()), None, None)
    );
}

#[test]
fn references_name_the_recorded_identities_and_carry_none_of_them() {
    let keyring = generated_keyring(Uuid::new_v4());
    for evidence in every_delivered_shape() {
        let record = project(&evidence, &keyring).expect("well-formed evidence projects");
        let serialized = serde_json::to_string(&record).expect("a record serializes");
        for marker in [
            ACTOR_MARKER,
            ACTOR_ISSUER_MARKER,
            CONNECTION_MARKER,
            TOKEN_MARKER,
            ISSUER_MARKER,
            JTI_DIGEST_MARKER,
            SESSION_MARKER,
            CATALOG_MARKER,
        ] {
            assert!(
                !serialized.contains(marker),
                "a delivered record must never carry a raw identifier: {serialized}"
            );
        }

        assert_eq!(
            keyring.verify(
                ReferenceDomain::ActorRecorded,
                &[ACTOR_MARKER],
                &record.actor.recorded_ref
            ),
            Ok(ReferenceCheck::Current)
        );
        if evidence.actor_issuer.is_some() {
            assert_eq!(
                keyring.verify(
                    ReferenceDomain::ActorIssuer,
                    &[ACTOR_ISSUER_MARKER],
                    record
                        .actor
                        .issuer_ref
                        .as_deref()
                        .expect("a principal with an issuer has an issuer reference")
                ),
                Ok(ReferenceCheck::Current)
            );
        } else {
            assert_eq!(record.actor.issuer_ref, None);
        }
        let (domain, components): (ReferenceDomain, Vec<&str>) = match evidence.source {
            JournalSource::ConnectionChange => {
                (ReferenceDomain::Connection, vec![CONNECTION_MARKER])
            }
            JournalSource::ServiceTokenChange => {
                (ReferenceDomain::ServiceToken, vec![TOKEN_MARKER])
            }
            JournalSource::JwtRevocation => (
                ReferenceDomain::JwtRevocation,
                vec![ISSUER_MARKER, JTI_DIGEST_MARKER],
            ),
            JournalSource::AdminSession => (ReferenceDomain::AdminSession, vec![SESSION_MARKER]),
            // A document is the singleton its resource type names.
            JournalSource::DocumentChange => match evidence.resource_id.as_deref() {
                Some(DOCUMENT_TOOLS) => (ReferenceDomain::Tools, vec![DOCUMENT_TOOLS]),
                Some(DOCUMENT_POLICY_TESTS) => {
                    (ReferenceDomain::Policy, vec![DOCUMENT_POLICY_TESTS])
                }
                _ => (ReferenceDomain::Policy, vec![DOCUMENT_POLICY]),
            },
            JournalSource::CatalogChange => (ReferenceDomain::Catalog, vec![CATALOG_MARKER]),
        };
        assert_eq!(
            keyring.verify(domain, &components, &record.resource.reference),
            Ok(ReferenceCheck::Current)
        );
        // The issuer-less actor reference is never the issuer-scoped one.
        assert_ne!(
            keyring
                .derive(
                    ReferenceDomain::ActorSubject,
                    &[ISSUER_MARKER, ACTOR_MARKER]
                )
                .expect("an issuer-scoped reference derives")
                .as_str(),
            record.actor.recorded_ref
        );
    }
}

/// Two dispatchers holding the same key under the same authority deliver the
/// same record for one row, which is what makes a redelivery after a crash a
/// duplicate a consumer can recognize rather than a second event.
#[test]
fn a_redelivered_row_projects_to_the_identical_record() {
    let authority_id = Uuid::new_v4();
    let material = crate::authority_events::pseudonym::test_support::generated_key_hex();
    let first =
        crate::authority_events::pseudonym::test_support::keyring_from_hex(authority_id, &material);
    let second =
        crate::authority_events::pseudonym::test_support::keyring_from_hex(authority_id, &material);
    for evidence in every_delivered_shape() {
        assert_eq!(
            project(&evidence, &first).expect("projects"),
            project(&evidence, &second).expect("projects")
        );
    }
}

#[test]
fn a_row_that_cannot_be_projected_faithfully_is_refused() {
    let keyring = generated_keyring(Uuid::new_v4());
    let base = evidence(
        JournalSource::ServiceTokenChange,
        ACTION_SERVICE_TOKEN_ROTATE,
    );
    let refused = |mutate: &dyn Fn(&mut JournaledEvidence)| {
        let mut evidence = base.clone();
        mutate(&mut evidence);
        project(&evidence, &keyring).expect_err("the row must be refused")
    };

    // The evidence row is gone: the read's LEFT JOIN left every column empty.
    assert_eq!(
        refused(&|evidence| {
            evidence.operation_id = None;
            evidence.actor_user_id = None;
            evidence.action = None;
            evidence.resource_id = None;
            evidence.prior_version = None;
            evidence.new_version = None;
            evidence.security_revision = None;
            evidence.committed_at = None;
        }),
        ProjectionError::MissingEvidence
    );
    assert_eq!(
        refused(&|evidence| evidence.actor_user_id = Some(String::new())),
        ProjectionError::MissingEvidence
    );
    // An action its table may not hold, or one this build does not know.
    assert_eq!(
        refused(&|evidence| evidence.action = Some(ACTION_CONNECTION_DELETE.to_owned())),
        ProjectionError::UnknownAction
    );
    assert_eq!(
        refused(&|evidence| evidence.action = Some("service_token.create".to_owned())),
        ProjectionError::UnknownAction
    );
    // Out-of-shape stored values.
    assert_eq!(
        refused(&|evidence| evidence.event_id = "not-a-uuid".to_owned()),
        ProjectionError::InvalidEvidence
    );
    assert_eq!(
        refused(&|evidence| evidence.operation_id = Some(Uuid::nil().to_string())),
        ProjectionError::InvalidEvidence
    );
    assert_eq!(
        refused(&|evidence| evidence.new_version = Some(1)),
        ProjectionError::InvalidEvidence
    );
    assert_eq!(
        refused(&|evidence| evidence.prior_version = Some(0)),
        ProjectionError::InvalidEvidence
    );
    assert_eq!(
        refused(&|evidence| evidence.security_revision = Some(0)),
        ProjectionError::InvalidEvidence
    );
    assert_eq!(
        refused(&|evidence| evidence.committed_at = Some("2026-10-21 12:34:56".to_owned())),
        ProjectionError::InvalidEvidence
    );
    // A token resource never has an owner, and a JWT revocation always does.
    assert_eq!(
        refused(&|evidence| evidence.resource_owner = Some(ISSUER_MARKER.to_owned())),
        ProjectionError::MissingEvidence
    );
    let mut ownerless = evidence(JournalSource::JwtRevocation, ACTION_JWT_REVOKE);
    ownerless.resource_owner = None;
    assert_eq!(
        project(&ownerless, &keyring),
        Err(ProjectionError::MissingEvidence)
    );
    // An identifier past the reference bound is refused, not truncated.
    assert!(matches!(
        refused(&|evidence| evidence.resource_id = Some("x".repeat(4097))),
        ProjectionError::Reference(PseudonymError::InvalidComponents)
    ));
}

/// A service-token issue (journaled since migration 27) is delivered only as
/// the token's first revision: a row that claims a revision before it, or
/// any first revision other than 1, is not an issue migration 27 admits and
/// is refused rather than delivered. An issue belongs to the token table
/// alone, and it still requires its shared revision.
#[test]
fn an_issue_projects_only_as_the_tokens_first_revision() {
    let keyring = generated_keyring(Uuid::new_v4());
    let validator = delivery_schema();
    let base = evidence(
        JournalSource::ServiceTokenChange,
        ACTION_SERVICE_TOKEN_ISSUE,
    );
    let record = project(&base, &keyring).expect("an issue projects");
    assert_eq!(record.operation, ACTION_SERVICE_TOKEN_ISSUE);
    assert_eq!(record.resource.kind, "service_token");
    let value = serde_json::to_value(&record).expect("a record serializes");
    if let Err(error) = validator.validate(&value) {
        panic!("the published schema must accept {value}: {error}");
    }

    for (prior_version, new_version, expected) in [
        (Some(1), Some(1), ProjectionError::InvalidEvidence),
        (Some(1), Some(2), ProjectionError::InvalidEvidence),
        (None, Some(2), ProjectionError::InvalidEvidence),
        (None, Some(0), ProjectionError::InvalidEvidence),
        (None, None, ProjectionError::MissingEvidence),
    ] {
        let mut refused = base.clone();
        refused.prior_version = prior_version;
        refused.new_version = new_version;
        assert_eq!(
            project(&refused, &keyring),
            Err(expected),
            "{prior_version:?} -> {new_version:?}"
        );
    }
    let mut unrevisioned = base.clone();
    unrevisioned.security_revision = None;
    assert_eq!(
        project(&unrevisioned, &keyring),
        Err(ProjectionError::MissingEvidence)
    );
    for source in [
        JournalSource::ConnectionChange,
        JournalSource::JwtRevocation,
        JournalSource::AdminSession,
    ] {
        assert_eq!(
            project(&evidence(source, ACTION_SERVICE_TOKEN_ISSUE), &keyring),
            Err(ProjectionError::UnknownAction),
            "{source:?}"
        );
    }
}

/// A Connection create, replace and credential binding change (journaled
/// since migration 28) are delivered only in the shapes migration 28's CHECK
/// admits, on the axis the row recorded: a create as the first specification
/// version, a replace advancing a positive one, and a binding change
/// advancing the credential revision, which may start at 0. Each names the
/// Connection, referenced under the Connection domain, and keeps its shared
/// revision. A row that claims another transition, names no axis or another
/// action's axis, or comes from another table is refused rather than
/// delivered.
#[test]
fn connection_changes_project_only_on_their_recorded_axis() {
    let keyring = generated_keyring(Uuid::new_v4());
    let validator = delivery_schema();
    for action in [
        ACTION_CONNECTION_CREATE,
        ACTION_CONNECTION_REPLACE,
        ACTION_CREDENTIAL_BINDING_CHANGE,
    ] {
        let base = evidence(JournalSource::ConnectionChange, action);
        let record = project(&base, &keyring).expect("a Connection change projects");
        assert_eq!(record.operation, action);
        assert_eq!(record.resource.kind, "connection");
        assert_eq!(
            keyring.verify(
                ReferenceDomain::Connection,
                &[CONNECTION_MARKER],
                &record.resource.reference
            ),
            Ok(ReferenceCheck::Current)
        );
        let value = serde_json::to_value(&record).expect("a record serializes");
        if let Err(error) = validator.validate(&value) {
            panic!("the published schema must accept {value}: {error}");
        }

        let mut unrevisioned = base.clone();
        unrevisioned.security_revision = None;
        assert_eq!(
            project(&unrevisioned, &keyring),
            Err(ProjectionError::MissingEvidence),
            "{action}"
        );
        let mut unrecorded_axis = base.clone();
        unrecorded_axis.revision_axis = None;
        assert_eq!(
            project(&unrecorded_axis, &keyring),
            Err(ProjectionError::MissingEvidence),
            "{action}"
        );
        for axis in ["connection", "credential", "token", ""] {
            if base.revision_axis.as_deref() == Some(axis) {
                continue;
            }
            let mut other_axis = base.clone();
            other_axis.revision_axis = Some(axis.to_owned());
            assert_eq!(
                project(&other_axis, &keyring),
                Err(ProjectionError::InvalidEvidence),
                "{action} on {axis:?}"
            );
        }
        // The Connection table alone holds these actions.
        for source in [
            JournalSource::ServiceTokenChange,
            JournalSource::JwtRevocation,
            JournalSource::AdminSession,
        ] {
            assert_eq!(
                project(&evidence(source, action), &keyring),
                Err(ProjectionError::UnknownAction),
                "{action} from {source:?}"
            );
        }
    }
    // No other table names an axis.
    let mut token_with_axis = evidence(
        JournalSource::ServiceTokenChange,
        ACTION_SERVICE_TOKEN_ROTATE,
    );
    token_with_axis.revision_axis = Some("token".to_owned());
    assert_eq!(
        project(&token_with_axis, &keyring),
        Err(ProjectionError::InvalidEvidence)
    );

    for (action, prior_version, new_version, expected) in [
        // A create is the first version and nothing before it.
        (
            ACTION_CONNECTION_CREATE,
            Some(0),
            Some(1),
            ProjectionError::InvalidEvidence,
        ),
        (
            ACTION_CONNECTION_CREATE,
            None,
            Some(2),
            ProjectionError::InvalidEvidence,
        ),
        (
            ACTION_CONNECTION_CREATE,
            None,
            None,
            ProjectionError::MissingEvidence,
        ),
        // A replace advances a positive version.
        (
            ACTION_CONNECTION_REPLACE,
            None,
            Some(1),
            ProjectionError::MissingEvidence,
        ),
        (
            ACTION_CONNECTION_REPLACE,
            Some(0),
            Some(1),
            ProjectionError::InvalidEvidence,
        ),
        (
            ACTION_CONNECTION_REPLACE,
            Some(3),
            Some(3),
            ProjectionError::InvalidEvidence,
        ),
        (
            ACTION_CONNECTION_REPLACE,
            Some(3),
            None,
            ProjectionError::MissingEvidence,
        ),
        // A binding change advances the credential revision from 0 or more.
        (
            ACTION_CREDENTIAL_BINDING_CHANGE,
            None,
            Some(1),
            ProjectionError::MissingEvidence,
        ),
        (
            ACTION_CREDENTIAL_BINDING_CHANGE,
            Some(-1),
            Some(1),
            ProjectionError::InvalidEvidence,
        ),
        (
            ACTION_CREDENTIAL_BINDING_CHANGE,
            Some(0),
            Some(0),
            ProjectionError::InvalidEvidence,
        ),
        (
            ACTION_CREDENTIAL_BINDING_CHANGE,
            Some(2),
            Some(1),
            ProjectionError::InvalidEvidence,
        ),
        (
            ACTION_CREDENTIAL_BINDING_CHANGE,
            Some(1),
            None,
            ProjectionError::MissingEvidence,
        ),
        // A delete still needs a positive prior version and no successor.
        (
            ACTION_CONNECTION_DELETE,
            Some(0),
            None,
            ProjectionError::InvalidEvidence,
        ),
        (
            ACTION_CONNECTION_DELETE,
            Some(3),
            Some(4),
            ProjectionError::InvalidEvidence,
        ),
    ] {
        let mut refused = evidence(JournalSource::ConnectionChange, action);
        refused.prior_version = prior_version;
        refused.new_version = new_version;
        assert_eq!(
            project(&refused, &keyring),
            Err(expected),
            "{action} {prior_version:?} -> {new_version:?}"
        );
    }
    // A later credential revision advances like any other.
    let mut rebound = evidence(
        JournalSource::ConnectionChange,
        ACTION_CREDENTIAL_BINDING_CHANGE,
    );
    rebound.prior_version = Some(4);
    rebound.new_version = Some(5);
    let revision = project(&rebound, &keyring)
        .expect("a later binding change projects")
        .revision;
    assert_eq!(
        (revision.before.as_deref(), revision.after.as_deref()),
        (Some("4"), Some("5"))
    );
}

/// The actor's kind and auth mode are carried as the evidence recorded them
/// and its issuer only as a reference; evidence committed before migration
/// 24 recorded none of the three and says `null`, never a guess. Every kind
/// the evidence tables admit, and every auth mode, projects.
#[test]
fn the_actor_is_projected_as_the_evidence_recorded_it() {
    let keyring = generated_keyring(Uuid::new_v4());
    let validator = delivery_schema();
    let base = evidence(JournalSource::JwtRevocation, ACTION_JWT_REVOKE);
    let issuer_ref = keyring
        .derive(ReferenceDomain::ActorIssuer, &[ACTOR_ISSUER_MARKER])
        .expect("an issuer reference derives");
    for (kind, auth_mode, issuer, expected_issuer_ref) in [
        (None, None, None, None),
        (
            Some("principal"),
            Some("bearer_token"),
            Some(ACTOR_ISSUER_MARKER),
            Some(issuer_ref.as_str()),
        ),
        (Some("principal"), Some("session_cookie"), None, None),
        (Some("principal"), Some("client_certificate"), None, None),
        (Some("service_token"), Some("service_token"), None, None),
        (Some("system"), Some("system"), None, None),
    ] {
        let record = project(&with_actor(base.clone(), kind, auth_mode, issuer), &keyring)
            .expect("recorded actor metadata projects");
        assert_eq!(
            (
                record.actor.kind.as_deref(),
                record.actor.auth_mode.as_deref(),
                record.actor.issuer_ref.as_deref()
            ),
            (kind, auth_mode, expected_issuer_ref)
        );
        // The subject reference does not depend on the metadata, so a row
        // reads the same whether or not it recorded any.
        assert_eq!(
            keyring.verify(
                ReferenceDomain::ActorRecorded,
                &[ACTOR_MARKER],
                &record.actor.recorded_ref
            ),
            Ok(ReferenceCheck::Current)
        );
        let value = serde_json::to_value(&record).expect("a record serializes");
        if let Err(error) = validator.validate(&value) {
            panic!("the published schema must accept {value}: {error}");
        }
    }
}

/// A row whose actor metadata is not a shape migration 24's CHECK admits is
/// refused rather than delivered with part of it or a guess, and an issuer
/// past the reference bound is refused rather than truncated.
#[test]
fn actor_metadata_that_cannot_be_projected_faithfully_is_refused() {
    let keyring = generated_keyring(Uuid::new_v4());
    let base = evidence(JournalSource::ConnectionChange, ACTION_CONNECTION_DELETE);
    for (kind, auth_mode, issuer) in [
        // Some but not all.
        (Some("principal"), None, None),
        (None, Some("bearer_token"), None),
        (None, None, Some(ACTOR_ISSUER_MARKER)),
        (None, Some("bearer_token"), Some(ACTOR_ISSUER_MARKER)),
        // A kind or mode outside the vocabulary.
        (Some("person"), Some("bearer_token"), None),
        (Some("principal"), Some("password"), None),
        // A pairing authentication cannot produce.
        (Some("principal"), Some("service_token"), None),
        (Some("principal"), Some("system"), None),
        (Some("service_token"), Some("bearer_token"), None),
        (Some("system"), Some("session_cookie"), None),
        // Only a principal is vouched for by an issuer.
        (
            Some("service_token"),
            Some("service_token"),
            Some(ACTOR_ISSUER_MARKER),
        ),
        (Some("system"), Some("system"), Some(ACTOR_ISSUER_MARKER)),
    ] {
        assert_eq!(
            project(&with_actor(base.clone(), kind, auth_mode, issuer), &keyring),
            Err(ProjectionError::InvalidEvidence),
            "{kind:?} {auth_mode:?} {issuer:?}"
        );
    }
    for issuer in [String::new(), "i".repeat(4097)] {
        assert!(matches!(
            project(
                &with_actor(
                    base.clone(),
                    Some("principal"),
                    Some("bearer_token"),
                    Some(&issuer)
                ),
                &keyring
            ),
            Err(ProjectionError::Reference(
                PseudonymError::InvalidComponents
            ))
        ));
    }
}

/// Historical admin session evidence and unauthenticated logout record the
/// session's own subject and nothing of the actor's kind, auth mode or
/// issuer, and takes no shared revision: the record says `null` for all of
/// them rather than a guess. A row that claims a shared revision, a version
/// or a resource owner is not session evidence and is refused, and every
/// other operation still requires its shared revision.
#[test]
fn admin_session_rows_project_without_actor_metadata_or_a_shared_revision() {
    let keyring = generated_keyring(Uuid::new_v4());
    let validator = delivery_schema();
    for action in [ACTION_ADMIN_SESSION_GRANT, ACTION_ADMIN_SESSION_WITHDRAW] {
        let base = evidence(JournalSource::AdminSession, action);
        let record = project(&base, &keyring).expect("session evidence projects");
        assert_eq!(record.operation, action);
        assert_eq!(record.resource.kind, "admin_session");
        assert_eq!(
            (
                record.actor.kind.as_deref(),
                record.actor.auth_mode.as_deref(),
                record.actor.issuer_ref.as_deref()
            ),
            (None, None, None)
        );
        assert_eq!(
            keyring.verify(
                ReferenceDomain::ActorRecorded,
                &[ACTOR_MARKER],
                &record.actor.recorded_ref
            ),
            Ok(ReferenceCheck::Current)
        );
        assert_eq!(record.revision.security, None);
        let value = serde_json::to_value(&record).expect("a record serializes");
        if let Err(error) = validator.validate(&value) {
            panic!("the published schema must accept {value}: {error}");
        }

        for mutate in [
            (|evidence: &mut JournaledEvidence| evidence.security_revision = Some(17))
                as fn(&mut JournaledEvidence),
            |evidence| evidence.prior_version = Some(1),
            |evidence| evidence.new_version = Some(1),
            |evidence| evidence.resource_owner = Some(ISSUER_MARKER.to_owned()),
        ] {
            let mut refused = base.clone();
            mutate(&mut refused);
            assert!(project(&refused, &keyring).is_err(), "{refused:?}");
        }
    }
    // Session actions belong to the session table alone, and the session
    // table holds no other action.
    assert_eq!(
        project(
            &evidence(JournalSource::ConnectionChange, ACTION_ADMIN_SESSION_GRANT),
            &keyring
        ),
        Err(ProjectionError::UnknownAction)
    );
    assert_eq!(
        project(
            &evidence(JournalSource::AdminSession, ACTION_CONNECTION_DELETE),
            &keyring
        ),
        Err(ProjectionError::UnknownAction)
    );
    // The shared revision stays required wherever a change takes one.
    let mut unrevisioned = evidence(JournalSource::ConnectionChange, ACTION_CONNECTION_DELETE);
    unrevisioned.security_revision = None;
    assert_eq!(
        project(&unrevisioned, &keyring),
        Err(ProjectionError::MissingEvidence)
    );
}

/// Policy, tools and stored policy test suite commits (journaled since
/// migration 32) are delivered on the axis of the document their row names,
/// and only in a pairing migration 29's CHECK admits: a policy operation on
/// the policy, `tools.publish` on the tools document, `policy_tests.publish`
/// on the suite, which is a `policy` resource of its own, and the import's
/// `configuration.import` on the policy or the tools document it activated.
/// Each activates a version: none before the document's initialization, a
/// positive one otherwise, and a strictly greater one after, which need not
/// be 1. Anything else is refused rather than delivered.
#[test]
fn document_changes_project_on_the_axis_of_their_document() {
    let keyring = generated_keyring(Uuid::new_v4());
    let validator = delivery_schema();
    let reference = |domain, document| {
        keyring
            .derive(domain, &[document])
            .expect("a document reference derives")
            .as_str()
            .to_owned()
    };
    let policy_ref = reference(ReferenceDomain::Policy, DOCUMENT_POLICY);
    let tools_ref = reference(ReferenceDomain::Tools, DOCUMENT_TOOLS);
    let suite_ref = reference(ReferenceDomain::Policy, DOCUMENT_POLICY_TESTS);
    assert_ne!(policy_ref, suite_ref, "the suite is not the policy");

    let mut cases: Vec<(&str, &str, &str, &str, &str)> = POLICY_ACTIONS
        .into_iter()
        .map(|action| {
            (
                action,
                DOCUMENT_POLICY,
                "policy",
                "policy",
                policy_ref.as_str(),
            )
        })
        .collect();
    cases.extend([
        (
            ACTION_TOOLS_PUBLISH,
            DOCUMENT_TOOLS,
            "tools",
            "tools",
            tools_ref.as_str(),
        ),
        (
            ACTION_CONFIGURATION_IMPORT,
            DOCUMENT_POLICY,
            "policy",
            "policy",
            policy_ref.as_str(),
        ),
        (
            ACTION_CONFIGURATION_IMPORT,
            DOCUMENT_TOOLS,
            "tools",
            "tools",
            tools_ref.as_str(),
        ),
        (
            ACTION_POLICY_TESTS_PUBLISH,
            DOCUMENT_POLICY_TESTS,
            "policy",
            "policy_tests",
            suite_ref.as_str(),
        ),
    ]);
    for (action, document, kind, axis, reference) in cases {
        let base = document_evidence(action, document);
        let record = project(&base, &keyring).expect("a document commit projects");
        assert_eq!(
            (
                record.operation.as_str(),
                record.resource.kind.as_str(),
                record.resource.reference.as_str(),
                record.revision.axis.as_str(),
                record.revision.before.as_deref(),
                record.revision.after.as_deref(),
                record.revision.security.as_deref(),
            ),
            (
                action,
                kind,
                reference,
                axis,
                Some("3"),
                Some("4"),
                Some("17")
            ),
            "{action} on {document}"
        );
        let value = serde_json::to_value(&record).expect("a record serializes");
        if let Err(error) = validator.validate(&value) {
            panic!("the published schema must accept {value}: {error}");
        }

        // The document's initialization, at a version above 1 (the import
        // activates its policy above the history it copied).
        let mut initialized = base.clone();
        initialized.prior_version = None;
        initialized.new_version = Some(12);
        let revision = project(&initialized, &keyring)
            .expect("an initialization projects")
            .revision;
        assert_eq!(
            (revision.before.as_deref(), revision.after.as_deref()),
            (None, Some("12"))
        );
        for (prior_version, new_version, expected) in [
            (Some(0), Some(4), ProjectionError::InvalidEvidence),
            (Some(4), Some(4), ProjectionError::InvalidEvidence),
            (Some(5), Some(4), ProjectionError::InvalidEvidence),
            (Some(3), Some(0), ProjectionError::InvalidEvidence),
            (Some(3), None, ProjectionError::MissingEvidence),
            (None, None, ProjectionError::MissingEvidence),
        ] {
            let mut refused = base.clone();
            refused.prior_version = prior_version;
            refused.new_version = new_version;
            assert_eq!(
                project(&refused, &keyring),
                Err(expected),
                "{action} {prior_version:?} -> {new_version:?}"
            );
        }
        let mut unrevisioned = base.clone();
        unrevisioned.security_revision = None;
        assert_eq!(
            project(&unrevisioned, &keyring),
            Err(ProjectionError::MissingEvidence)
        );
        let mut with_axis = base.clone();
        with_axis.revision_axis = Some(axis.to_owned());
        assert_eq!(
            project(&with_axis, &keyring),
            Err(ProjectionError::InvalidEvidence)
        );
        // The document table alone holds these actions.
        for source in [
            JournalSource::ConnectionChange,
            JournalSource::ServiceTokenChange,
            JournalSource::CatalogChange,
            JournalSource::AdminSession,
        ] {
            assert_eq!(
                project(&evidence(source, action), &keyring),
                Err(ProjectionError::UnknownAction),
                "{action} from {source:?}"
            );
        }
    }

    // Pairings migration 29's CHECK refuses, and a document it does not know.
    for (action, document) in [
        (ACTION_POLICY_PUBLISH, DOCUMENT_TOOLS),
        (ACTION_POLICY_SUGGESTION_ACCEPT, DOCUMENT_POLICY_TESTS),
        (ACTION_TOOLS_PUBLISH, DOCUMENT_POLICY),
        (ACTION_POLICY_TESTS_PUBLISH, DOCUMENT_POLICY),
        (ACTION_CONFIGURATION_IMPORT, DOCUMENT_POLICY_TESTS),
        (ACTION_POLICY_PUBLISH, "connection"),
    ] {
        assert_eq!(
            project(&document_evidence(action, document), &keyring),
            Err(ProjectionError::InvalidEvidence),
            "{action} on {document:?}"
        );
    }
    assert_eq!(
        project(&document_evidence(ACTION_POLICY_PUBLISH, ""), &keyring),
        Err(ProjectionError::MissingEvidence)
    );
    for action in [
        ACTION_CATALOG_MCP_PUBLISH,
        ACTION_CONNECTION_DELETE,
        "policy.import",
    ] {
        assert_eq!(
            project(&document_evidence(action, DOCUMENT_POLICY), &keyring),
            Err(ProjectionError::UnknownAction),
            "{action}"
        );
    }
}

/// Catalog publications (journaled since migration 32) are delivered as a
/// `catalog` resource referenced by its Connection, under the catalog domain,
/// on the `catalog` axis: the catalog revision before (none for a
/// Connection's first catalog of its kind) and after. The overlay revision is
/// not delivered. A catalog row committed before migration 25 recorded no
/// actor kind, auth mode or issuer and says `null` there.
#[test]
fn catalog_publications_project_on_the_catalog_axis() {
    let keyring = generated_keyring(Uuid::new_v4());
    let validator = delivery_schema();
    let catalog_ref = keyring
        .derive(ReferenceDomain::Catalog, &[CATALOG_MARKER])
        .expect("a catalog reference derives");
    let connection_ref = keyring
        .derive(ReferenceDomain::Connection, &[CATALOG_MARKER])
        .expect("a Connection reference derives");
    assert_ne!(catalog_ref.as_str(), connection_ref.as_str());
    for action in CATALOG_ACTIONS {
        let base = evidence(JournalSource::CatalogChange, action);
        let record = project(&base, &keyring).expect("a catalog publication projects");
        assert_eq!(
            (
                record.operation.as_str(),
                record.resource.kind.as_str(),
                record.resource.reference.as_str(),
                record.revision.axis.as_str(),
                record.revision.before.as_deref(),
                record.revision.after.as_deref(),
                record.revision.security.as_deref(),
            ),
            (
                action,
                "catalog",
                catalog_ref.as_str(),
                "catalog",
                Some("2"),
                Some("3"),
                Some("17")
            )
        );
        let mut first = base.clone();
        first.prior_version = None;
        first.new_version = Some(1);
        let revision = project(&first, &keyring)
            .expect("a first catalog projects")
            .revision;
        assert_eq!(
            (revision.before.as_deref(), revision.after.as_deref()),
            (None, Some("1"))
        );
        let unrecorded = project(&with_actor(base.clone(), None, None, None), &keyring)
            .expect("a catalog row from before migration 25 projects");
        assert_eq!(
            (
                unrecorded.actor.kind.as_deref(),
                unrecorded.actor.auth_mode.as_deref(),
                unrecorded.actor.issuer_ref.as_deref()
            ),
            (None, None, None)
        );
        for record in [record, unrecorded] {
            let value = serde_json::to_value(&record).expect("a record serializes");
            if let Err(error) = validator.validate(&value) {
                panic!("the published schema must accept {value}: {error}");
            }
        }
        for (prior_version, new_version) in [(Some(3), Some(3)), (Some(0), Some(1)), (None, None)] {
            let mut refused = base.clone();
            refused.prior_version = prior_version;
            refused.new_version = new_version;
            assert!(project(&refused, &keyring).is_err(), "{action}");
        }
        for source in [
            JournalSource::ConnectionChange,
            JournalSource::DocumentChange,
            JournalSource::AdminSession,
        ] {
            assert_eq!(
                project(&evidence(source, action), &keyring),
                Err(ProjectionError::UnknownAction),
                "{action} from {source:?}"
            );
        }
    }
}

/// A document row committed before migration 32 recorded a service-token
/// caller as kind `principal` with auth mode `service_token`, and the issuer
/// as the principal carried it. It is delivered in migration 24's
/// vocabulary: kind `service_token`, and the issuer canonicalized as
/// authentication canonicalizes it, so it is referenced exactly as the same
/// principal's issuer is from every other table. A row this release writes
/// already records both and reads the same. No other table's row is
/// reinterpreted, and the legacy service-token pairing never claims an
/// issuer.
#[test]
fn legacy_document_actors_are_read_in_migration_24s_vocabulary() {
    let keyring = generated_keyring(Uuid::new_v4());
    let validator = delivery_schema();
    let base = evidence(JournalSource::DocumentChange, ACTION_POLICY_PUBLISH);
    let canonical_ref = keyring
        .derive(ReferenceDomain::ActorIssuer, &[ACTOR_ISSUER_MARKER])
        .expect("an issuer reference derives");
    let as_recorded = format!(" {ACTOR_ISSUER_MARKER}/// ");
    for (kind, auth_mode, issuer, expected) in [
        // A service-token caller in migration 23's vocabulary, and in 32's.
        (
            "principal",
            "service_token",
            None,
            ("service_token", "service_token", None),
        ),
        (
            "service_token",
            "service_token",
            None,
            ("service_token", "service_token", None),
        ),
        // An issuer as the principal carried it, and in canonical form.
        (
            "principal",
            "bearer_token",
            Some(as_recorded.as_str()),
            ("principal", "bearer_token", Some(canonical_ref.as_str())),
        ),
        (
            "principal",
            "session_cookie",
            Some(ACTOR_ISSUER_MARKER),
            ("principal", "session_cookie", Some(canonical_ref.as_str())),
        ),
        // An issuer that canonicalizes to nothing names none.
        (
            "principal",
            "client_certificate",
            Some(" /// "),
            ("principal", "client_certificate", None),
        ),
        ("system", "system", None, ("system", "system", None)),
    ] {
        let record = project(
            &with_actor(base.clone(), Some(kind), Some(auth_mode), issuer),
            &keyring,
        )
        .expect("a document actor projects");
        assert_eq!(
            (
                record.actor.kind.as_deref(),
                record.actor.auth_mode.as_deref(),
                record.actor.issuer_ref.as_deref()
            ),
            (Some(expected.0), Some(expected.1), expected.2),
            "{kind} {auth_mode} {issuer:?}"
        );
        let serialized = serde_json::to_string(&record).expect("a record serializes");
        assert!(!serialized.contains(ACTOR_ISSUER_MARKER), "{serialized}");
        let value = serde_json::to_value(&record).expect("a record serializes");
        if let Err(error) = validator.validate(&value) {
            panic!("the published schema must accept {value}: {error}");
        }
    }

    // Still refused: a service token vouched for by an issuer in either
    // vocabulary, pairings no table admits, and a row recording only part
    // of its actor.
    for (kind, auth_mode, issuer) in [
        (
            Some("principal"),
            Some("service_token"),
            Some(ACTOR_ISSUER_MARKER),
        ),
        (Some("service_token"), Some("bearer_token"), None),
        (Some("principal"), Some("system"), None),
        (Some("system"), Some("system"), Some(ACTOR_ISSUER_MARKER)),
        (Some("principal"), None, None),
        (None, None, None),
    ] {
        assert!(
            project(&with_actor(base.clone(), kind, auth_mode, issuer), &keyring).is_err(),
            "{kind:?} {auth_mode:?} {issuer:?}"
        );
    }

    // The reading is the document table's alone: the tables migration 24
    // aligned never recorded the old pairing, and their issuers are already
    // canonical, so they are referenced as stored.
    let connection = evidence(JournalSource::ConnectionChange, ACTION_CONNECTION_DELETE);
    assert_eq!(
        project(
            &with_actor(
                connection.clone(),
                Some("principal"),
                Some("service_token"),
                None
            ),
            &keyring
        ),
        Err(ProjectionError::InvalidEvidence)
    );
    let stored = project(
        &with_actor(
            connection,
            Some("principal"),
            Some("bearer_token"),
            Some(&as_recorded),
        ),
        &keyring,
    )
    .expect("a stored issuer projects");
    assert_ne!(
        stored.actor.issuer_ref.as_deref(),
        Some(canonical_ref.as_str())
    );
}

#[test]
fn projection_errors_name_a_class_and_never_a_value() {
    for error in [
        ProjectionError::MissingEvidence,
        ProjectionError::UnknownAction,
        ProjectionError::InvalidEvidence,
        ProjectionError::Reference(PseudonymError::InvalidComponents),
    ] {
        let label = error.as_str();
        assert!(label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_'));
        assert!(!error.to_string().contains(ACTOR_MARKER));
    }
}

#[test]
fn the_committed_at_shape_is_the_schemas() {
    for accepted in [
        "2026-10-21T12:34:56Z",
        "2026-10-21T12:34:56.1Z",
        "2026-10-21T12:34:56.123456789Z",
    ] {
        assert!(committed_at_in_shape(accepted), "{accepted}");
    }
    for refused in [
        "",
        "2026-10-21T12:34:56",
        "2026-10-21T12:34:56.Z",
        "2026-10-21T12:34:56.1234567890Z",
        "2026-10-21T12:34:56+00:00",
        "2026-10-21 12:34:56Z",
        "2026-1x-21T12:34:56Z",
    ] {
        assert!(!committed_at_in_shape(refused), "{refused}");
    }
}
