//! The delivered form of one journaled evidence row (issue #425, PR 3).
//!
//! The dispatcher reads a journal row and the evidence row it indexes, and
//! hands a sink one [`DeliveryRecord`]: identifiers and revisions only, every
//! actor and resource identifier replaced by a keyed safe reference from
//! [`super::pseudonym`]. Its closed shape is
//! `docs/schemas/authority_event_delivery.v1.schema.json`, which the tests
//! below validate every projection against.
//!
//! It is deliberately **not** the proposed `authority_event.v1` event. That
//! contract names every actor by an issuer-scoped subject reference, an issuer
//! reference, a kind and an authentication mode. Since migration 24 the
//! evidence rows record the actor's kind, auth mode and, for a principal that
//! has one, its canonical issuer, and the record carries them as
//! `actor.kind`, `actor.auth_mode` and `actor.issuer_ref` (the `actor.issuer`
//! reference). Evidence committed before migration 24 recorded none of the
//! three, and a service token or an operator command has no issuer, so rather
//! than invent one the record says `null` there. The subject is still named by
//! the one identifier that was recorded, under the separate `actor.recorded`
//! reference domain, so a row reads the same before and after migration 24.
//! The revision fields follow the v1 transition contract.
//!
//! A service-token issue (journaled since migration 27) is delivered as
//! `service_token.issue` on the `token` axis, with no revision before it and
//! the token row's first revision, `1`, after it, beside the shared revision
//! its create took.
//!
//! A Connection create and replace (journaled since migration 28) are
//! delivered as `connection.create` and `connection.replace` on the
//! `connection` axis: a create has no revision before it and the first
//! specification version, `1`, after it; a replace advances an existing one.
//! A replace that changed credential authority is also delivered as
//! `credential.binding_change`, under the same operation ID and shared
//! revision, on the `credential` axis: the Connection's credential revision
//! before and after, where `0` before means no credential authority was
//! configured. Its resource is the Connection, referenced as every other
//! Connection change is; no binding, secret ID or locator is evidence, so
//! none can be referenced. The row's recorded axis must be the action's.
//!
//! Admin session grants and withdrawals (journaled since migration 26) are
//! delivered as `admin_session.grant` and `admin_session.withdraw`. Their
//! evidence records the session's own identity and no actor kind, auth mode
//! or shared revision, so the record names the session's subject as its
//! recorded actor, says `null` for the kind, auth mode, issuer reference and
//! security revision, and puts the session on the v1 `session` axis: a
//! session is granted once and withdrawn once, so its one revision is `1`,
//! created by the grant and deleted by the withdrawal. Which withdrawal it
//! was (logout, replacement, rejection, expiry) stays in the evidence row;
//! the closed record has no field for it.
//!
//! A row that cannot be projected faithfully -- its evidence row is gone, its
//! action is not one this build knows, a stored value is out of shape -- is
//! refused with a [`ProjectionError`] and the dispatcher stops there rather
//! than skipping it. No error carries an identifier, a reference or key
//! material.
//!
//! The record, its errors and the actor projection are shared with standalone
//! mode, whose evidence rows are delivered straight from the SQLite stores
//! that own them (`super::standalone_delivery`); only the journal's own
//! projection below needs the `postgres` feature.

// A build without the `postgres` feature projects standalone rows only, so
// the journal's actions and transitions have no caller there.
#![cfg_attr(not(feature = "postgres"), allow(dead_code))]

use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::pseudonym::{PseudonymError, PseudonymKeyring, ReferenceDomain};
use crate::auth::change_actor::{auth_mode_agrees, ActorKind};
#[cfg(feature = "postgres")]
use crate::storage::postgres_authority_events::{JournalSource, JournaledEvidence};

/// The `schema_version` of every delivered record.
pub(crate) const DELIVERY_SCHEMA_VERSION: &str = "authority_event_delivery.v1";

/// The only result a delivered record carries: the evidence describes a
/// committed change. Refused, rolled-back and no-op changes write no
/// evidence, so they are never delivered.
pub(super) const RESULT_COMMITTED: &str = "committed";

// The evidence tables' closed action vocabularies (migrations 16 and 18,
// the service-token issue since migration 27, the Connection create, replace
// and credential binding change since migration 28), which are the proposed
// authority-event operation codes.
const ACTION_CONNECTION_CREATE: &str = "connection.create";
const ACTION_CONNECTION_REPLACE: &str = "connection.replace";
const ACTION_CREDENTIAL_BINDING_CHANGE: &str = "credential.binding_change";
const ACTION_CONNECTION_DELETE: &str = "connection.delete";
const ACTION_SERVICE_TOKEN_ISSUE: &str = "service_token.issue";
const ACTION_SERVICE_TOKEN_ROTATE: &str = "service_token.rotate";
const ACTION_SERVICE_TOKEN_REVOKE: &str = "service_token.revoke";
const ACTION_JWT_REVOKE: &str = "jwt.revoke";
// Migration 19's admin session vocabulary.
const ACTION_ADMIN_SESSION_GRANT: &str = "admin_session.grant";
const ACTION_ADMIN_SESSION_WITHDRAW: &str = "admin_session.withdraw";

/// The revision a created resource starts at: a service token's row revision
/// after its issue and a Connection's first specification version
/// (migrations 27 and 28 hold the same value in their CHECKs).
const FIRST_REVISION: i64 = 1;

/// The one revision of an admin session on the `session` axis. A session is
/// granted once and withdrawn once (migration 19's `UNIQUE (session_id,
/// action)`), and nothing in between is an authority change.
const SESSION_REVISION: i64 = 1;

/// The longest `committed_at` the schema admits.
const MAX_COMMITTED_AT_CHARS: usize = 30;

/// One delivered authority event. Field order is the serialized order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeliveryRecord {
    pub(crate) schema_version: String,
    /// The persisted evidence-authority ID every reference is derived under.
    /// Consumers deduplicate on `(authority_id, event_id)`.
    pub(crate) authority_id: String,
    /// The evidence row's own event ID, minted once in the committing
    /// transaction; a redelivery carries the same one.
    pub(crate) event_id: String,
    pub(crate) operation_id: String,
    /// The journal position as a decimal string: commit order within this
    /// authority.
    pub(crate) sequence: String,
    pub(crate) operation: String,
    pub(crate) result: String,
    pub(crate) committed_at: String,
    pub(crate) actor: DeliveryActor,
    pub(crate) resource: DeliveryResource,
    pub(crate) revision: DeliveryRevision,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeliveryActor {
    /// `principal`, `service_token` or `system`; `null` for evidence
    /// committed before migration 24.
    pub(crate) kind: Option<String>,
    /// The recorded actor identifier's reference in the `actor.recorded`
    /// domain.
    pub(crate) recorded_ref: String,
    /// The actor's canonical issuer's reference in the `actor.issuer`
    /// domain; `null` for an actor without one and for evidence committed
    /// before migration 24.
    pub(crate) issuer_ref: Option<String>,
    /// The audit auth mode, or `system`; `null` for evidence committed
    /// before migration 24.
    pub(crate) auth_mode: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeliveryResource {
    pub(crate) kind: String,
    #[serde(rename = "ref")]
    pub(crate) reference: String,
}

/// Revisions as decimal strings, so every 64-bit value survives a JSON
/// consumer that reads numbers as doubles.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeliveryRevision {
    pub(crate) axis: String,
    pub(crate) before: Option<String>,
    pub(crate) after: Option<String>,
    /// The shared security revision the change took; `null` for an admin
    /// session, which takes none.
    pub(crate) security: Option<String>,
}

/// Why a journaled row cannot be delivered. Each names a class, never a
/// value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProjectionError {
    /// The journal names an evidence row that does not exist, or a column
    /// the projection needs is empty.
    MissingEvidence,
    /// The evidence row's action is not one its table may hold.
    UnknownAction,
    /// A stored identifier, revision or timestamp is out of shape.
    InvalidEvidence,
    /// A reference could not be derived.
    Reference(PseudonymError),
}

impl ProjectionError {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::MissingEvidence => "missing_evidence",
            Self::UnknownAction => "unknown_action",
            Self::InvalidEvidence => "invalid_evidence",
            Self::Reference(_) => "reference",
        }
    }
}

impl fmt::Display for ProjectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reference(error) => {
                write!(formatter, "authority event projection failed: {error}")
            }
            other => write!(
                formatter,
                "authority event projection failed: {}",
                other.as_str()
            ),
        }
    }
}

impl std::error::Error for ProjectionError {}

/// What one action projects to: its resource kind and domain, its revision
/// axis, and which revisions it carries.
struct ActionShape {
    resource_kind: &'static str,
    domain: ReferenceDomain,
    axis: &'static str,
    transition: Transition,
}

/// The v1 revision transition of each delivered operation.
#[derive(Clone, Copy)]
enum Transition {
    /// No prior version and [`FIRST_REVISION`] after: a resource that did
    /// not exist before the change.
    Create,
    /// A positive prior version and no successor.
    Delete,
    /// A positive prior version and a strictly greater new one.
    Advance,
    /// A prior version of at least 0 and a strictly greater new one: an axis
    /// that reads 0 until something is configured on it, as a Connection's
    /// credential revision does before its first credential binding.
    AdvanceFromZero,
    /// No prior version; the shared security revision is the new one.
    PublishOnSecurityAxis,
    /// An admin session's grant: no prior revision, [`SESSION_REVISION`]
    /// after, and no shared revision.
    SessionGrant,
    /// An admin session's withdrawal: [`SESSION_REVISION`] before, nothing
    /// after, and no shared revision.
    SessionWithdraw,
}

impl Transition {
    /// Whether the change took the shared security revision. Every
    /// delivered change does except an admin session's.
    const fn takes_security_revision(self) -> bool {
        !matches!(self, Self::SessionGrant | Self::SessionWithdraw)
    }
}

#[cfg(feature = "postgres")]
fn action_shape(source: JournalSource, action: &str) -> Option<ActionShape> {
    match (source, action) {
        (JournalSource::ConnectionChange, ACTION_CONNECTION_CREATE) => Some(ActionShape {
            resource_kind: "connection",
            domain: ReferenceDomain::Connection,
            axis: "connection",
            transition: Transition::Create,
        }),
        (JournalSource::ConnectionChange, ACTION_CONNECTION_REPLACE) => Some(ActionShape {
            resource_kind: "connection",
            domain: ReferenceDomain::Connection,
            axis: "connection",
            transition: Transition::Advance,
        }),
        (JournalSource::ConnectionChange, ACTION_CREDENTIAL_BINDING_CHANGE) => Some(ActionShape {
            resource_kind: "connection",
            domain: ReferenceDomain::Connection,
            axis: "credential",
            transition: Transition::AdvanceFromZero,
        }),
        (JournalSource::ConnectionChange, ACTION_CONNECTION_DELETE) => Some(ActionShape {
            resource_kind: "connection",
            domain: ReferenceDomain::Connection,
            axis: "connection",
            transition: Transition::Delete,
        }),
        (JournalSource::ServiceTokenChange, ACTION_SERVICE_TOKEN_ISSUE) => Some(ActionShape {
            resource_kind: "service_token",
            domain: ReferenceDomain::ServiceToken,
            axis: "token",
            transition: Transition::Create,
        }),
        (
            JournalSource::ServiceTokenChange,
            ACTION_SERVICE_TOKEN_ROTATE | ACTION_SERVICE_TOKEN_REVOKE,
        ) => Some(ActionShape {
            resource_kind: "service_token",
            domain: ReferenceDomain::ServiceToken,
            axis: "token",
            transition: Transition::Advance,
        }),
        (JournalSource::JwtRevocation, ACTION_JWT_REVOKE) => Some(ActionShape {
            resource_kind: "jwt_revocation",
            domain: ReferenceDomain::JwtRevocation,
            axis: "jwt_revocation",
            transition: Transition::PublishOnSecurityAxis,
        }),
        (JournalSource::AdminSession, ACTION_ADMIN_SESSION_GRANT) => Some(ActionShape {
            resource_kind: "admin_session",
            domain: ReferenceDomain::AdminSession,
            axis: "session",
            transition: Transition::SessionGrant,
        }),
        (JournalSource::AdminSession, ACTION_ADMIN_SESSION_WITHDRAW) => Some(ActionShape {
            resource_kind: "admin_session",
            domain: ReferenceDomain::AdminSession,
            axis: "session",
            transition: Transition::SessionWithdraw,
        }),
        _ => None,
    }
}

/// Project one journaled evidence row under `keyring`.
#[cfg(feature = "postgres")]
pub(crate) fn project(
    evidence: &JournaledEvidence,
    keyring: &PseudonymKeyring,
) -> Result<DeliveryRecord, ProjectionError> {
    let operation_id = required(evidence.operation_id.as_deref())?;
    let actor = required(evidence.actor_user_id.as_deref())?;
    let action = required(evidence.action.as_deref())?;
    let resource_id = required(evidence.resource_id.as_deref())?;
    let committed_at = required(evidence.committed_at.as_deref())?;

    let shape = action_shape(evidence.source, action).ok_or(ProjectionError::UnknownAction)?;
    let takes_security_revision = shape.transition.takes_security_revision();
    let security_revision = match evidence.security_revision {
        Some(revision) if takes_security_revision && revision >= 1 => Some(revision),
        Some(_) => return Err(ProjectionError::InvalidEvidence),
        None if takes_security_revision => return Err(ProjectionError::MissingEvidence),
        None => None,
    };
    let event_id = canonical_uuid(&evidence.event_id)?;
    let operation_id = canonical_uuid(operation_id)?;
    if evidence.position < 1 || !committed_at_in_shape(committed_at) {
        return Err(ProjectionError::InvalidEvidence);
    }
    // A Connection change row names the axis its revisions count (migration
    // 28, whose CHECK pairs it with the action); no other table has one.
    match (evidence.source, evidence.revision_axis.as_deref()) {
        (JournalSource::ConnectionChange, Some(axis)) if axis == shape.axis => {}
        (JournalSource::ConnectionChange, None) => return Err(ProjectionError::MissingEvidence),
        (_, None) => {}
        (_, Some(_)) => return Err(ProjectionError::InvalidEvidence),
    }

    let (before, after) = match shape.transition {
        Transition::Create => {
            if evidence.prior_version.is_some() {
                return Err(ProjectionError::InvalidEvidence);
            }
            if positive(evidence.new_version)? != FIRST_REVISION {
                return Err(ProjectionError::InvalidEvidence);
            }
            (None, Some(FIRST_REVISION))
        }
        Transition::Delete => {
            let prior = positive(evidence.prior_version)?;
            if evidence.new_version.is_some() {
                return Err(ProjectionError::InvalidEvidence);
            }
            (Some(prior), None)
        }
        Transition::Advance => {
            let prior = positive(evidence.prior_version)?;
            let new = positive(evidence.new_version)?;
            if new <= prior {
                return Err(ProjectionError::InvalidEvidence);
            }
            (Some(prior), Some(new))
        }
        Transition::AdvanceFromZero => {
            let prior = non_negative(evidence.prior_version)?;
            let new = positive(evidence.new_version)?;
            if new <= prior {
                return Err(ProjectionError::InvalidEvidence);
            }
            (Some(prior), Some(new))
        }
        Transition::PublishOnSecurityAxis => {
            if evidence.prior_version.is_some() || evidence.new_version.is_some() {
                return Err(ProjectionError::InvalidEvidence);
            }
            (None, security_revision)
        }
        Transition::SessionGrant => {
            if evidence.prior_version.is_some() || evidence.new_version.is_some() {
                return Err(ProjectionError::InvalidEvidence);
            }
            (None, Some(SESSION_REVISION))
        }
        Transition::SessionWithdraw => {
            if evidence.prior_version.is_some() || evidence.new_version.is_some() {
                return Err(ProjectionError::InvalidEvidence);
            }
            (Some(SESSION_REVISION), None)
        }
    };

    // A JWT revocation's digest is only unique under its issuer, so the
    // issuer owns it in the reference; the other resources stand alone.
    let resource_reference = match evidence.resource_owner.as_deref() {
        Some(owner) if evidence.source == JournalSource::JwtRevocation => {
            keyring.derive(shape.domain, &[owner, resource_id])
        }
        None if evidence.source != JournalSource::JwtRevocation => {
            keyring.derive(shape.domain, &[resource_id])
        }
        _ => return Err(ProjectionError::MissingEvidence),
    }
    .map_err(ProjectionError::Reference)?;
    let actor = project_actor(
        actor,
        evidence.actor_kind.as_deref(),
        evidence.actor_auth_mode.as_deref(),
        evidence.actor_issuer.as_deref(),
        keyring,
    )?;

    Ok(DeliveryRecord {
        schema_version: DELIVERY_SCHEMA_VERSION.to_owned(),
        authority_id: keyring.authority_id().to_string(),
        event_id,
        operation_id,
        sequence: evidence.position.to_string(),
        operation: action.to_owned(),
        result: RESULT_COMMITTED.to_owned(),
        committed_at: committed_at.to_owned(),
        actor,
        resource: DeliveryResource {
            kind: shape.resource_kind.to_owned(),
            reference: resource_reference.as_str().to_owned(),
        },
        revision: DeliveryRevision {
            axis: shape.axis.to_owned(),
            before: before.map(|value| value.to_string()),
            after: after.map(|value| value.to_string()),
            security: security_revision.map(|value| value.to_string()),
        },
    })
}

/// The actor as the evidence recorded it: its recorded `subject`, and its
/// `kind`, `auth_mode` and `issuer` as stored. A row records the last three
/// together or not at all (migration 24's CHECK, and the standalone tables'
/// own), in a pairing authentication produces; anything else is out of
/// shape. An issuer is referenced, never carried.
pub(super) fn project_actor(
    subject: &str,
    kind: Option<&str>,
    auth_mode: Option<&str>,
    issuer: Option<&str>,
    keyring: &PseudonymKeyring,
) -> Result<DeliveryActor, ProjectionError> {
    let recorded_ref = keyring
        .derive(ReferenceDomain::ActorRecorded, &[subject])
        .map_err(ProjectionError::Reference)?;
    let (kind, auth_mode, issuer_ref) = match (kind, auth_mode, issuer) {
        // Committed before migration 24: nothing to say, and nothing guessed.
        (None, None, None) => (None, None, None),
        (Some(kind), Some(auth_mode), issuer) => {
            let kind = ActorKind::from_stored(kind).ok_or(ProjectionError::InvalidEvidence)?;
            if !auth_mode_agrees(kind, auth_mode) {
                return Err(ProjectionError::InvalidEvidence);
            }
            let issuer_ref = match issuer {
                None => None,
                Some(issuer) if kind == ActorKind::Principal => Some(
                    keyring
                        .derive(ReferenceDomain::ActorIssuer, &[issuer])
                        .map_err(ProjectionError::Reference)?
                        .as_str()
                        .to_owned(),
                ),
                Some(_) => return Err(ProjectionError::InvalidEvidence),
            };
            (
                Some(kind.as_str().to_owned()),
                Some(auth_mode.to_owned()),
                issuer_ref,
            )
        }
        _ => return Err(ProjectionError::InvalidEvidence),
    };
    Ok(DeliveryActor {
        kind,
        recorded_ref: recorded_ref.as_str().to_owned(),
        issuer_ref,
        auth_mode,
    })
}

pub(super) fn required(value: Option<&str>) -> Result<&str, ProjectionError> {
    value
        .filter(|value| !value.is_empty())
        .ok_or(ProjectionError::MissingEvidence)
}

pub(super) fn positive(value: Option<i64>) -> Result<i64, ProjectionError> {
    match value {
        Some(value) if value >= 1 => Ok(value),
        Some(_) => Err(ProjectionError::InvalidEvidence),
        None => Err(ProjectionError::MissingEvidence),
    }
}

pub(super) fn non_negative(value: Option<i64>) -> Result<i64, ProjectionError> {
    match value {
        Some(value) if value >= 0 => Ok(value),
        Some(_) => Err(ProjectionError::InvalidEvidence),
        None => Err(ProjectionError::MissingEvidence),
    }
}

/// The lowercase hyphenated form of a versioned RFC 4122 UUID, the shape the
/// schema requires. The stores mint v4 UUIDs; anything else is refused.
pub(super) fn canonical_uuid(value: &str) -> Result<String, ProjectionError> {
    let parsed = Uuid::parse_str(value).map_err(|_| ProjectionError::InvalidEvidence)?;
    let version = parsed.get_version_num();
    if !(1..=8).contains(&version) || parsed.get_variant() != uuid::Variant::RFC4122 {
        return Err(ProjectionError::InvalidEvidence);
    }
    Ok(parsed.hyphenated().to_string())
}

/// `YYYY-MM-DDTHH:MM:SS[.fraction]Z`, as the PostgreSQL store's `to_char`
/// renders the database clock and as a standalone store formats its process
/// clock (RFC 3339 in UTC).
pub(super) fn committed_at_in_shape(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 20 || bytes.len() > MAX_COMMITTED_AT_CHARS || !value.is_ascii() {
        return false;
    }
    let digits = |range: std::ops::Range<usize>| bytes[range].iter().all(u8::is_ascii_digit);
    let fixed = digits(0..4)
        && bytes[4] == b'-'
        && digits(5..7)
        && bytes[7] == b'-'
        && digits(8..10)
        && bytes[10] == b'T'
        && digits(11..13)
        && bytes[13] == b':'
        && digits(14..16)
        && bytes[16] == b':'
        && digits(17..19);
    if !fixed || bytes[bytes.len() - 1] != b'Z' {
        return false;
    }
    match &bytes[19..bytes.len() - 1] {
        [] => true,
        [b'.', fraction @ ..] => {
            (1..=9).contains(&fraction.len()) && fraction.iter().all(u8::is_ascii_digit)
        }
        _ => false,
    }
}

#[cfg(all(test, feature = "postgres"))]
#[path = "delivery_tests.rs"]
mod tests;
