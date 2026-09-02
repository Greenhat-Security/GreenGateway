//! Discovery utilities for turning observed traffic into endpoint inventory.

#![allow(dead_code)]

pub mod aggregator;
/// Cluster mode's rule-suggestion engine over the PostgreSQL read store,
/// audit store, and lifecycle store (issue #241, PR 12); the planning
/// logic itself lives in `suggestions` and is shared with standalone mode.
#[cfg(feature = "postgres")]
pub mod cluster_suggestions;
pub mod lifecycle;
pub mod openapi;
pub mod path_template;
/// The cluster-mode projector reads the PostgreSQL audit stream and
/// writes the PostgreSQL discovery tables, so it exists only with the
/// `postgres` feature; standalone builds keep the SQLite sink alone.
#[cfg(feature = "postgres")]
pub mod projector;
pub mod query;
pub mod signals;
pub mod suggestions;
