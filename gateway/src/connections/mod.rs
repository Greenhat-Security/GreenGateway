//! First-class connection vocabulary and security boundaries.
//!
//! The control-plane store, legacy projections, and permission-separated
//! metadata CRUD are active. Static and OAuth client-credentials HTTP
//! authentication are available through explicitly connection-bound proxy
//! routes, manual tools, refreshed streamable-HTTP MCP catalogs, and
//! revision-bound managed OpenAPI catalogs; the remaining protocol migrations
//! stay isolated to their named issue #240 slices.

#![allow(dead_code)]

pub mod admin;
pub mod aws_secret;
pub mod azure_secret;
pub mod control_plane;
pub mod gcp_secret;
pub mod http;
pub mod kubernetes_secret;
pub mod local_secret;
pub mod managed_store;
pub mod mcp;
pub mod model;
pub mod oauth;
pub mod openapi;
pub mod permissions;
#[cfg(feature = "postgres")]
pub mod pg_store;
pub mod projection;
pub mod secret;
pub mod status;
pub mod store;
pub mod test;
pub mod vault_secret;
