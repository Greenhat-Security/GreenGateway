//! Configuration contracts shared by the `gateway` server and the `ggctl`
//! operator CLI (issue #242, ADR-0008).
//!
//! ADR-0008 moves the configuration compiler, field catalog, bundle reader
//! and digest code into one library that both binaries link, so neither can
//! approximate the other. This crate is that library. It starts with the
//! contracts the two binaries already exchange:
//!
//! - [`documents`]: the versioned documents GreenGateway publishes schemas
//!   for, and those schemas;
//! - [`capabilities`]: the `GatewayCapabilities` document a gateway serves at
//!   `GET /v1{ADMIN_PREFIX}/config/capabilities`, which `ggctl` reads before
//!   any configuration operation and refuses to proceed without.
//!
//! [`archive`] holds the entry admission rules ADR-0008 requires of every
//! archive GreenGateway reads (no traversal, links, special files, duplicate
//! or case-colliding names, and bounded sizes and expansion), ahead of the
//! backup archive reader that will apply them, so that reader cannot
//! approximate them. Bundles themselves are directories only.
//!
//! The bundle reader and the configuration compiler still live in the
//! gateway crate. They move here with the policy and tools validators they
//! call when `ggctl validate` needs them (#242 PR 8); until then `ggctl`
//! cannot validate a bundle and does not claim to.
//!
//! Everything here is side-effect free: no file, environment, clock or
//! network access. The archive guard reads and writes only the readers and
//! writers it is handed.

pub mod archive;
pub mod capabilities;
pub mod documents;
