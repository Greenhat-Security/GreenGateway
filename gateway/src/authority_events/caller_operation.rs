//! Caller operation IDs bound to one request (issue #425).
//!
//! A keyed admin request carries one `Idempotency-Key`: a canonical RFC
//! UUIDv7 the caller chose. The key belongs to exactly one request, so an
//! exact retry after a lost response is answered from what the first attempt
//! committed, and any other use of the key is a conflict. "One request" is
//! the [`CallerOperation`]'s binding digest: a domain-separated,
//! length-prefixed SHA-256 over the action, the recorded actor, the target,
//! the precondition and the request with secret values removed.
//!
//! Both stores keep one reservation per key in `authority_caller_operation_ids`
//! (PostgreSQL migration 35, widened by migration 36; in each standalone
//! SQLite file the table `storage::standalone_authority_events` defines). A
//! digest-bound action stores its digest there, inside the transaction that
//! commits the change and its evidence row, and nowhere else: never in a
//! receipt, a delivered record, a log line or a metric. The two actions keyed
//! before the digest existed (`service_token.revoke`, and in PostgreSQL
//! `mutation_approval.prepare`) keep a NULL digest and their own replay
//! checks.
//!
//! What an exact retry gets back, [`OperationReceipt`], is read from the
//! committed evidence row, never stored separately.
//!
//! This module holds the types every keyed operation shares. The stores'
//! reservation functions are `storage::postgres_authority_events::
//! {read_caller_operation, reserve_bound_operation}` and their SQLite
//! counterparts in `storage::standalone_authority_events`. Admin routes bind
//! keys through the helpers in `admin_responses` (Connection create, replace
//! and delete, in `admin_connections::admit_keyed_connection_change`); each
//! other operation family does so in its own change.

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::auth::change_actor::ChangeActor;

/// The domain every binding digest is computed in, so no other digest in the
/// gateway can collide with one by construction.
const BINDING_DOMAIN: &[u8] = b"greengateway.caller_operation.binding.v1";

/// The parts of one keyed request its key is bound to. Each is hashed
/// exactly as given, so the caller decides the canonical form: the target is
/// empty for a create, the precondition is the `If-Match` value as received
/// (empty where the route takes none), and the request is the canonical
/// request bytes with every secret value removed. Opaque references (a
/// credential alias, a provider locator) stay in: they decide what the
/// change does.
#[derive(Clone, Copy)]
pub(crate) struct CallerOperationBinding<'a> {
    /// The operation code the reservation and the evidence row record, such
    /// as `connection.replace`.
    pub(crate) action: &'static str,
    pub(crate) actor: &'a ChangeActor,
    pub(crate) target: &'a str,
    pub(crate) precondition: &'a str,
    pub(crate) request: &'a [u8],
}

/// Why a key cannot be bound to a request. Nothing was read or written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BindingRefusal {
    /// The key is not a canonical RFC UUIDv7. Every gateway-assigned
    /// operation ID is a v4, so a v4 key could claim a change the gateway
    /// committed on its own.
    NotCallerAssigned,
    /// The actor cannot own a key: a system actor, which nobody
    /// authenticated, or a principal without a canonical issuer, whose
    /// subject is not unambiguous within this authority.
    ActorCannotBind,
    /// No action was named.
    MissingAction,
}

/// A caller key bound to one request: the key, the action it is reserved
/// for and the binding digest that makes it this request's.
///
/// `Debug` is written by hand and redacts the digest. The digest is a
/// SHA-256 over low-entropy inputs (credential aliases, provider locators),
/// so it could be confirmed offline; it must never reach a log line, and a
/// derived `Debug` would put it one `{:?}` away from one.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct CallerOperation {
    id: uuid::Uuid,
    action: &'static str,
    binding_digest: String,
}

impl std::fmt::Debug for CallerOperation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CallerOperation")
            .field("id", &self.id)
            .field("action", &self.action)
            .field("binding_digest", &"<redacted>")
            .finish()
    }
}

impl CallerOperation {
    /// Bind `id` to the request `binding` describes. Refused for a key the
    /// caller did not assign, an actor that cannot own a key, or no action.
    pub(crate) fn bind(
        id: uuid::Uuid,
        binding: &CallerOperationBinding<'_>,
    ) -> Result<Self, BindingRefusal> {
        if !crate::auth::tokens::valid_caller_operation_id(id) {
            return Err(BindingRefusal::NotCallerAssigned);
        }
        if !binding.actor.can_bind_operation() {
            return Err(BindingRefusal::ActorCannotBind);
        }
        if binding.action.is_empty() {
            return Err(BindingRefusal::MissingAction);
        }
        Ok(Self {
            id,
            action: binding.action,
            binding_digest: binding_digest(binding),
        })
    }

    pub(crate) fn id(&self) -> uuid::Uuid {
        self.id
    }

    pub(crate) fn action(&self) -> &'static str {
        self.action
    }

    /// Lowercase hex SHA-256: what the reservation row stores and compares.
    pub(crate) fn binding_digest(&self) -> &str {
        &self.binding_digest
    }

    /// Judge a stored reservation of this key against this request. Only the
    /// same action with the same digest is this request; a reservation with
    /// no digest (a key used by a keyed revoke or prepare) is never a
    /// digest-bound request's.
    pub(crate) fn judge(&self, stored_action: &str, stored_digest: Option<&str>) -> CallerKeyState {
        if stored_action == self.action && stored_digest == Some(self.binding_digest.as_str()) {
            CallerKeyState::SameBinding
        } else {
            CallerKeyState::OtherBinding
        }
    }
}

/// The digest: the domain, then each field as its length (eight bytes, big
/// endian) and its bytes, so moving bytes from one field to the next always
/// changes it. The actor is its kind, issuer, subject and auth mode; a
/// service-token actor has no issuer, and a principal that can bind always
/// has a non-empty one, so an empty issuer field is never ambiguous.
fn binding_digest(binding: &CallerOperationBinding<'_>) -> String {
    let actor = binding.actor;
    let mut digest = Sha256::new();
    digest.update(BINDING_DOMAIN);
    for field in [
        binding.action.as_bytes(),
        actor.kind().as_str().as_bytes(),
        actor.issuer().unwrap_or_default().as_bytes(),
        actor.subject().as_bytes(),
        actor.auth_mode().as_bytes(),
        binding.target.as_bytes(),
        binding.precondition.as_bytes(),
        binding.request,
    ] {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field);
    }
    hex::encode(digest.finalize())
}

/// What a store's reservation table says about one key, judged against one
/// request's binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CallerKeyState {
    /// No committed change used the key.
    Unused,
    /// The key is reserved for this action and this binding digest: the
    /// request is an exact retry, answered from the committed evidence.
    SameBinding,
    /// The key is reserved for another action, another binding, or without a
    /// binding: a conflict, and nothing may change.
    OtherBinding,
}

/// What reserving a key inside the change's transaction did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CallerKeyReservation {
    /// The key is now reserved for this request. It commits or rolls back
    /// with the change and its evidence.
    Reserved,
    /// A committed writer holds the key for this same request: answer the
    /// retry from its evidence and change nothing.
    SameBinding,
    /// A committed writer holds the key for something else: a conflict.
    OtherBinding,
}

/// What an exact retry gets back, read from the committed evidence row. It
/// never carries a secret, a binding digest or a raw request field.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct OperationReceipt {
    pub(crate) operation_id: String,
    /// The operation code, such as `connection.replace`.
    pub(crate) operation: String,
    pub(crate) resource_id: String,
    /// The resource's revision after the change, or before it for a change
    /// that removes the resource.
    pub(crate) revision: Option<i64>,
    pub(crate) committed_at: String,
}

/// A keyed store call: the change it committed, or the receipt of the change
/// an earlier attempt with the same key and binding committed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CallerOutcome<T> {
    Committed(T),
    Replayed(OperationReceipt),
}

/// A key for the tests: a canonical UUIDv7 that `seed` tells apart.
#[cfg(test)]
pub(crate) fn test_caller_key(seed: u8) -> uuid::Uuid {
    crate::auth::tokens::test_revoke_operation_id(seed)
}

#[cfg(test)]
#[path = "caller_operation_tests.rs"]
mod tests;
