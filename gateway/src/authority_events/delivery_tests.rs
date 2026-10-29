use serde_json::Value;

use super::*;
use crate::authority_events::pseudonym::{test_support::generated_keyring, ReferenceCheck};

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

fn evidence(source: JournalSource, action: &str) -> JournaledEvidence {
    let (resource_owner, resource_id, prior_version, new_version) = match source {
        JournalSource::ConnectionChange => (None, CONNECTION_MARKER, Some(3), None),
        JournalSource::ServiceTokenChange => (None, TOKEN_MARKER, Some(1), Some(2)),
        JournalSource::JwtRevocation => (Some(ISSUER_MARKER), JTI_DIGEST_MARKER, None, None),
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
                ..evidence(JournalSource::JwtRevocation, action)
            };
        }
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
    vec![
        evidence(JournalSource::ConnectionChange, ACTION_CONNECTION_DELETE),
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
    ]
}

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
    let shapes = every_delivered_shape();
    let mut delivered: Vec<&str> = shapes
        .iter()
        .map(|evidence| evidence.action.as_deref().expect("fixture has an action"))
        .collect();
    delivered.sort_unstable();
    assert_eq!(operations, delivered);
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
        refused(&|evidence| evidence.action = Some("service_token.issue".to_owned())),
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

/// Admin session evidence (journaled since migration 26) records the
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
