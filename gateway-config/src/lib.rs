//! Configuration contracts shared by the `gateway` server and the `ggctl`
//! operator CLI (issue #242, ADR-0008).
//!
//! ADR-0008 moves the configuration compiler, field catalog, bundle reader
//! and digest code into one library that both binaries link, so neither can
//! approximate the other. This crate is that library. Today it holds:
//!
//! - [`documents`]: the versioned documents GreenGateway publishes schemas
//!   for, and those schemas;
//! - [`capabilities`]: the `GatewayCapabilities` document a gateway serves at
//!   `GET /v1{ADMIN_PREFIX}/config/capabilities`, which `ggctl` reads before
//!   any configuration operation and refuses to proceed without;
//! - [`bundle`]: the configuration bundle reader, which `ggctl validate` and
//!   `ggctl doctor` run and the gateway will start from in bundle mode;
//! - [`canonical_json`]: RFC 8785 canonical JSON and ADR-0004's digest frame;
//! - [`opaque_id`] and [`permissions`]: the opaque ID grammar and the
//!   projected-volume permission rule the reader shares with the gateway's
//!   secret providers.
//!
//! Still in the gateway crate: the environment configuration compiler
//! (`Config::from_env_vars`, being extracted by #433) and the production
//! policy and tools validators. The bundle reader takes those validators as a
//! [`bundle::ResourceValidators`] argument, so the gateway runs them and
//! `ggctl`, which cannot link the gateway crate, reports that it did not.
//!
//! Nothing here touches the environment, a clock, a store or the network. The
//! bundle reader is the one part that reads files: only beneath the bundle
//! root it is given, and it never writes.

pub mod bundle;
pub mod canonical_json;
pub mod capabilities;
pub mod documents;
pub mod opaque_id;
pub mod permissions;
