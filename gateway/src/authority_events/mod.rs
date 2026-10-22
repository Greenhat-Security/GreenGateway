//! Authority-change evidence events (issue #425).
//!
//! The proposed downstream contract is
//! `docs/schemas/authority_event.v1.schema.json`, and
//! `docs/authority-evidence.md` records which durable records exist today. So
//! far only the keyed reference derivation every producer needs has landed,
//! in [`pseudonym`]; no runtime path emits an authority event yet.

pub(crate) mod pseudonym;
