//! Discovery utilities for turning observed traffic into endpoint inventory.

#![allow(dead_code)]

pub mod aggregator;
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
