//! Authority-change evidence events (issue #425).
//!
//! The proposed downstream contract is
//! `docs/schemas/authority_event.v1.schema.json`, and
//! `docs/authority-evidence.md` records which durable records exist today.
//!
//! - [`pseudonym`] derives the keyed, domain-separated safe references every
//!   delivered event names its actor and resource by.
//! - In cluster mode, every committed evidence row is journaled in its own
//!   transaction (`storage::postgres_authority_events`), and the
//!   `dispatcher` delivers the journal to a pluggable `sink` as
//!   `delivery` records (`docs/schemas/authority_event_delivery.v1.schema.json`),
//!   behind a durable, fenced cursor. Standalone mode has no journal and no
//!   dispatcher.

#[cfg(feature = "postgres")]
pub(crate) mod delivery;
#[cfg(feature = "postgres")]
pub(crate) mod dispatcher;
pub(crate) mod pseudonym;
#[cfg(feature = "postgres")]
pub(crate) mod sink;
#[cfg(feature = "postgres")]
pub(crate) mod startup;
