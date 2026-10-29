//! Configuration contracts shared by the `gateway` server and the `ggctl`
//! operator CLI (issue #242, ADR-0008).
//!
//! ADR-0008 moves the configuration compiler, field catalog, bundle reader
//! and digest code into one library that both binaries link, so neither can
//! approximate the other. This crate is that library. Today it holds:
//!
//! - [`catalog`]: the configuration field catalog, which describes every
//!   setting the gateway's configuration compiler reads and is held to that
//!   compiler, the configuration reference, `.env.example` and the Cloudflare
//!   wrapper by parity tests;
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
//!   secret providers;
//! - [`archive`]: the entry admission rules ADR-0008 requires of every
//!   archive GreenGateway reads (no traversal, links, special files,
//!   duplicate or case-colliding names, and bounded sizes and expansion),
//!   ahead of the backup archive reader that will apply them, so that reader
//!   cannot approximate them. Bundles themselves are directories only;
//! - [`ledger`]: the standalone configuration revision ledger, an
//!   append-only, hash-chained SQLite record of the bundles a standalone
//!   deployment applied, which refuses to open when anything in it no longer
//!   verifies;
//! - [`semantic_diff`]: the semantic diff between two compiled
//!   configurations and its risk classification, which `ggctl diff` reports
//!   for two bundles and the gateway's plans will report.
//!
//! Still in the gateway crate: the environment configuration compiler
//! (`config::compile`, extracted by #433 and described in
//! `docs/architecture/configuration-compiler.md`) and the production policy
//! and tools validators. The bundle reader takes those validators as a
//! [`bundle::ResourceValidators`] argument, so the gateway runs them and
//! `ggctl`, which cannot link the gateway crate, reports that it did not.
//!
//! Nothing here touches the environment, a clock or the network. The bundle
//! reader reads files only beneath the bundle root it is given, and never
//! writes. The archive guard reads and writes only the readers and writers
//! it is handed. The ledger is the one store: it reads and writes only its own
//! database and journal files beneath the state directory it is given.

pub mod archive;
pub mod bundle;
pub mod canonical_json;
pub mod capabilities;
pub mod catalog;
pub mod documents;
pub mod ledger;
pub mod opaque_id;
pub mod permissions;
pub mod semantic_diff;
