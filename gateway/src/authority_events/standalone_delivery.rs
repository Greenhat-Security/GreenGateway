//! The delivered form of one standalone evidence row (issue #425).
//!
//! Standalone mode has no journal: the dispatcher reads each SQLite store's
//! evidence tables directly (`storage::standalone_authority_events`) and
//! hands a sink the same closed [`DeliveryRecord`] cluster mode delivers
//! (`docs/schemas/authority_event_delivery.v1.schema.json`), every actor and
//! resource identifier replaced by a keyed safe reference derived under the
//! owning store's own `authority_id`.
//!
//! What differs from a journaled row, and what the record says instead:
//!
//! - **`sequence`** is the row's `AUTOINCREMENT` sequence in its own table,
//!   which is commit order within that table. A store with several evidence
//!   tables (the Connections database) has one sequence per table, so
//!   sequences are ordered within an operation family (`connection.*` and
//!   `credential.*`, `secret.*`, `catalog.*`), not across them; consumers
//!   deduplicate on `(authority_id, event_id)` as in cluster mode.
//! - **`revision.security` is `null`**: a standalone store has no shared
//!   security revision.
//! - **Service-token revisions are `null`**: the token database keeps no
//!   revision per token, so an issue, rotate or revoke says nothing before or
//!   after rather than inventing one.
//! - **Local secrets** sit on the v1 `secret` axis with the secret's version
//!   before and after. A re-encryption batch names no secret (its row records
//!   only how many envelopes it rewrote) and changes no version: it sits on
//!   the v1 `maintenance` axis with no revisions, and its resource is the
//!   database's local-secret store as a whole, referenced from the fixed
//!   component [`LOCAL_SECRET_STORE_COMPONENT`], which no gateway-minted
//!   secret ID (a UUID) can equal.
//! - **Catalog publications** sit on the v1 `catalog` axis with the catalog
//!   revision before (none for a first catalog) and after; the resource is
//!   the Connection's managed catalog, referenced under the Connection ID. The
//!   overlay revision a catalog was compiled from stays in the evidence row.
//! - **A credential binding change** is the Connection's, on the `credential`
//!   axis, exactly as cluster mode delivers it: no binding or secret ID is
//!   evidence.
//!
//! A row that cannot be projected faithfully -- an action its table may not
//! hold, a revision out of its transition, a value out of shape -- is refused
//! with a [`ProjectionError`], and the dispatcher stalls at that row rather
//! than skipping it.

use super::{
    delivery::{
        canonical_uuid, committed_at_in_shape, non_negative, positive, project_actor, required,
        DeliveryRecord, DeliveryResource, DeliveryRevision, ProjectionError,
        DELIVERY_SCHEMA_VERSION, RESULT_COMMITTED,
    },
    pseudonym::{PseudonymKeyring, ReferenceDomain},
};
use crate::storage::standalone_authority_events::{StandaloneEvidence, StandaloneEvidenceSource};

/// The component a re-encryption batch's resource reference is derived
/// from: the table of envelopes it rewrote. A secret's own reference is
/// derived from its UUID, so the two never collide.
pub(crate) const LOCAL_SECRET_STORE_COMPONENT: &str = "connection_local_secrets";

/// The revision a created resource starts at, as each table's CHECK holds
/// it: a Connection's first specification version and a local secret's
/// first version.
const FIRST_REVISION: i64 = 1;

/// The v1 revision transition of each delivered standalone operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Transition {
    /// No prior revision and [`FIRST_REVISION`] after.
    Create,
    /// A positive prior revision and a strictly greater new one.
    Advance,
    /// A prior revision of at least 0 and a strictly greater new one: the
    /// credential axis, which reads 0 before a first binding.
    AdvanceFromZero,
    /// A positive prior revision and none after.
    Delete,
    /// An optional positive prior revision and a strictly greater new one: a
    /// catalog publication, whose first catalog has nothing before it.
    Publish,
    /// No revision either side: the row records none.
    Unrevised,
}

/// What one standalone action projects to.
#[derive(Clone, Copy, Debug)]
pub(crate) struct StandaloneShape {
    pub(crate) source: StandaloneEvidenceSource,
    pub(crate) action: &'static str,
    resource_kind: &'static str,
    domain: ReferenceDomain,
    axis: &'static str,
    transition: Transition,
    /// Whether the row names its resource; only a re-encryption batch does
    /// not.
    names_resource: bool,
}

const fn shape(
    source: StandaloneEvidenceSource,
    action: &'static str,
    resource_kind: &'static str,
    domain: ReferenceDomain,
    axis: &'static str,
    transition: Transition,
) -> StandaloneShape {
    StandaloneShape {
        source,
        action,
        resource_kind,
        domain,
        axis,
        transition,
        names_resource: true,
    }
}

/// Every action a standalone evidence table may hold -- each table's closed
/// CHECK vocabulary, which are the proposed authority-event operation codes
/// -- and what it projects to. The tests hold this table to the tables'
/// CHECKs and to the published schema.
pub(crate) const STANDALONE_SHAPES: [StandaloneShape; 15] = [
    shape(
        StandaloneEvidenceSource::ServiceTokenChange,
        "service_token.issue",
        "service_token",
        ReferenceDomain::ServiceToken,
        "token",
        Transition::Unrevised,
    ),
    shape(
        StandaloneEvidenceSource::ServiceTokenChange,
        "service_token.rotate",
        "service_token",
        ReferenceDomain::ServiceToken,
        "token",
        Transition::Unrevised,
    ),
    shape(
        StandaloneEvidenceSource::ServiceTokenChange,
        "service_token.revoke",
        "service_token",
        ReferenceDomain::ServiceToken,
        "token",
        Transition::Unrevised,
    ),
    shape(
        StandaloneEvidenceSource::ConnectionChange,
        "connection.create",
        "connection",
        ReferenceDomain::Connection,
        "connection",
        Transition::Create,
    ),
    shape(
        StandaloneEvidenceSource::ConnectionChange,
        "connection.replace",
        "connection",
        ReferenceDomain::Connection,
        "connection",
        Transition::Advance,
    ),
    shape(
        StandaloneEvidenceSource::ConnectionChange,
        "credential.binding_change",
        "connection",
        ReferenceDomain::Connection,
        "credential",
        Transition::AdvanceFromZero,
    ),
    shape(
        StandaloneEvidenceSource::ConnectionChange,
        "connection.delete",
        "connection",
        ReferenceDomain::Connection,
        "connection",
        Transition::Delete,
    ),
    shape(
        StandaloneEvidenceSource::LocalSecretChange,
        "secret.create",
        "local_secret",
        ReferenceDomain::LocalSecret,
        "secret",
        Transition::Create,
    ),
    shape(
        StandaloneEvidenceSource::LocalSecretChange,
        "secret.rotate",
        "local_secret",
        ReferenceDomain::LocalSecret,
        "secret",
        Transition::Advance,
    ),
    shape(
        StandaloneEvidenceSource::LocalSecretChange,
        "secret.delete",
        "local_secret",
        ReferenceDomain::LocalSecret,
        "secret",
        Transition::Delete,
    ),
    StandaloneShape {
        names_resource: false,
        ..shape(
            StandaloneEvidenceSource::LocalSecretChange,
            "secret.reencrypt",
            "local_secret",
            ReferenceDomain::LocalSecret,
            "maintenance",
            Transition::Unrevised,
        )
    },
    shape(
        StandaloneEvidenceSource::CatalogChange,
        "catalog.mcp.publish",
        "catalog",
        ReferenceDomain::Catalog,
        "catalog",
        Transition::Publish,
    ),
    shape(
        StandaloneEvidenceSource::CatalogChange,
        "catalog.openapi.publish",
        "catalog",
        ReferenceDomain::Catalog,
        "catalog",
        Transition::Publish,
    ),
    shape(
        StandaloneEvidenceSource::CatalogChange,
        "catalog.overlay.replace",
        "catalog",
        ReferenceDomain::Catalog,
        "catalog",
        Transition::Publish,
    ),
    shape(
        StandaloneEvidenceSource::CatalogChange,
        "catalog.overlay.delete",
        "catalog",
        ReferenceDomain::Catalog,
        "catalog",
        Transition::Publish,
    ),
];

fn shape_of(source: StandaloneEvidenceSource, action: &str) -> Option<&'static StandaloneShape> {
    STANDALONE_SHAPES
        .iter()
        .find(|shape| shape.source == source && shape.action == action)
}

/// Project one standalone evidence row under its store's `keyring`.
pub(crate) fn project_standalone(
    evidence: &StandaloneEvidence,
    keyring: &PseudonymKeyring,
) -> Result<DeliveryRecord, ProjectionError> {
    let operation_id = required(Some(evidence.operation_id.as_str()))?;
    let subject = required(Some(evidence.actor_user_id.as_str()))?;
    let action = required(Some(evidence.action.as_str()))?;
    let committed_at = required(Some(evidence.committed_at.as_str()))?;
    let shape = shape_of(evidence.source, action).ok_or(ProjectionError::UnknownAction)?;
    let event_id = canonical_uuid(&evidence.event_id)?;
    let operation_id = canonical_uuid(operation_id)?;
    if evidence.sequence < 1 || !committed_at_in_shape(committed_at) {
        return Err(ProjectionError::InvalidEvidence);
    }

    let (before, after) = revisions(shape.transition, evidence)?;
    let resource_reference = match (shape.names_resource, evidence.resource_id.as_deref()) {
        (true, Some(resource_id)) => keyring.derive(shape.domain, &[required(Some(resource_id))?]),
        (true, None) => return Err(ProjectionError::MissingEvidence),
        (false, None) => keyring.derive(shape.domain, &[LOCAL_SECRET_STORE_COMPONENT]),
        (false, Some(_)) => return Err(ProjectionError::InvalidEvidence),
    }
    .map_err(ProjectionError::Reference)?;
    let actor = project_actor(
        subject,
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
        sequence: evidence.sequence.to_string(),
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
            security: None,
        },
    })
}

/// The revisions before and after the change, exactly as the row recorded
/// them, or the refusal of a row whose revisions are not its transition's.
fn revisions(
    transition: Transition,
    evidence: &StandaloneEvidence,
) -> Result<(Option<i64>, Option<i64>), ProjectionError> {
    let (prior, new) = (evidence.prior_version, evidence.new_version);
    match transition {
        Transition::Create => {
            if prior.is_some() || positive(new)? != FIRST_REVISION {
                return Err(ProjectionError::InvalidEvidence);
            }
            Ok((None, Some(FIRST_REVISION)))
        }
        Transition::Advance | Transition::AdvanceFromZero => {
            let prior = if transition == Transition::Advance {
                positive(prior)?
            } else {
                non_negative(prior)?
            };
            let new = positive(new)?;
            if new <= prior {
                return Err(ProjectionError::InvalidEvidence);
            }
            Ok((Some(prior), Some(new)))
        }
        Transition::Delete => {
            let prior = positive(prior)?;
            if new.is_some() {
                return Err(ProjectionError::InvalidEvidence);
            }
            Ok((Some(prior), None))
        }
        Transition::Publish => {
            let new = positive(new)?;
            let prior = prior.map(|prior| positive(Some(prior))).transpose()?;
            if prior.is_some_and(|prior| new <= prior) {
                return Err(ProjectionError::InvalidEvidence);
            }
            Ok((prior, Some(new)))
        }
        Transition::Unrevised => {
            if prior.is_some() || new.is_some() {
                return Err(ProjectionError::InvalidEvidence);
            }
            Ok((None, None))
        }
    }
}

#[cfg(test)]
#[path = "standalone_delivery_tests.rs"]
mod tests;
