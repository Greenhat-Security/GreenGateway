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
//!   `dispatcher` delivers the journal to a pluggable [`sink`] as
//!   [`delivery`] records (`docs/schemas/authority_event_delivery.v1.schema.json`),
//!   behind a durable, fenced cursor.
//! - Standalone mode has no journal: the [`standalone`] dispatcher delivers
//!   each SQLite store's own evidence tables, after a cursor kept in that
//!   store (`storage::standalone_authority_events`), as the same records
//!   ([`standalone_delivery`]) to the same sinks.
//! - [`required`] refuses, under `AUTHORITY_EVIDENCE_DURABILITY=required`,
//!   every authority change the deployment mode records no evidence of.

/// The poll interval, batch size and retry backoff both dispatchers share.
pub(crate) mod cadence;
pub(crate) mod delivery;
#[cfg(feature = "postgres")]
pub(crate) mod dispatcher;
pub(crate) mod pseudonym;
pub(crate) mod required;
pub(crate) mod sink;
pub(crate) mod standalone;
pub(crate) mod standalone_delivery;
#[cfg(feature = "postgres")]
pub(crate) mod startup;
