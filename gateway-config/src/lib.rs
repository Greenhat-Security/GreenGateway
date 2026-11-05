//! Configuration contracts shared by the `gateway` server and the `ggctl`
//! operator CLI (issue #242, ADR-0008).
//!
//! ADR-0008 moves the configuration compiler, field catalog, bundle reader
//! and digest code into one library that both binaries link, so neither can
//! approximate the other. This crate is that library. Today it holds:
//!
//! - [`compiler`]: the environment configuration compiler (issue #433, moved
//!   here by #242), which reads every setting through the reader its caller
//!   passes, never the process environment, and returns a validated plan or
//!   every problem with a value-free diagnostic. The gateway turns the plan
//!   into the `Config` it starts from; `ggctl` can run the same compiler;
//! - [`catalog`]: the configuration field catalog, which describes every
//!   setting the compiler reads and is held to the compiler, the
//!   configuration reference, `.env.example` and the Cloudflare wrapper by
//!   parity tests;
//! - [`documents`]: the versioned documents GreenGateway publishes schemas
//!   for, and those schemas;
//! - [`capabilities`]: the `GatewayCapabilities` document a gateway serves at
//!   `GET /v1{ADMIN_PREFIX}/config/capabilities`, which `ggctl` reads before
//!   any configuration operation and refuses to proceed without;
//! - [`mcp_client_configs`]: the credential-free MCP client configuration
//!   templates a gateway serves at `GET /v1{ADMIN_PREFIX}/mcp/client-configs`
//!   and `ggctl mcp-config` prints, rendered and read here so the two cannot
//!   disagree about a template;
//! - [`bundle`]: the configuration bundle reader, which `ggctl validate` and
//!   `ggctl doctor` run and the gateway will start from in bundle mode, with
//!   the [`bundle::ProductionValidators`] both pass it;
//! - [`rbac`] and [`tools`]: the policy and tools documents (policy v0 and
//!   v1, tools 0.1.0), their models and their validating parses
//!   ([`rbac::Policy::validate_json_value`] and
//!   [`tools::definitions::definitions_from_json_value`]), which the
//!   gateway's policy and tools loaders run and which are the production
//!   validators a bundle's documents are held to;
//! - [`canonical_json`]: RFC 8785 canonical JSON and ADR-0004's digest frame;
//! - [`opaque_id`] and [`permissions`]: the opaque ID grammar and the
//!   projected-volume permission rule the reader shares with the gateway's
//!   secret providers;
//! - [`archive`]: the entry admission rules ADR-0008 requires of every
//!   archive GreenGateway reads (no traversal, links, special files,
//!   duplicate or case-colliding names, and bounded sizes and expansion),
//!   which the backup archive reader applies to every entry, so it cannot
//!   approximate them. Bundles themselves are directories only;
//! - [`backup`]: standalone backups, one archive of a state directory's
//!   stores taken as consistent SQLite snapshots under its lock, with a
//!   `GatewayBackup` manifest of versions, inventory and checksums, the
//!   reader that verifies one completely in a staging directory, the restore
//!   that switches a verified staging directory into an empty or prepared
//!   state directory's place, and the restore marker the next gateway start
//!   records;
//! - [`state_dir`]: the standalone state directory, with the fixed file
//!   names of the stores beneath it, the rules the directory must meet, the
//!   exclusive lock a process holds on it and a best-effort check for a
//!   network filesystem under it;
//! - [`ledger`]: the standalone configuration revision ledger, an
//!   append-only, hash-chained SQLite record of the bundles a standalone
//!   deployment applied, which opens only under a held state directory and
//!   refuses to open when anything in it no longer verifies;
//! - [`revisions`]: conditional plan, apply, history and rollback over that
//!   ledger, which recompiles every candidate, binds risk acknowledgements
//!   to the exact plan, requires the union of permissions and never
//!   overwrites a revision it did not plan against;
//! - [`semantic_diff`]: the semantic diff between two compiled
//!   configurations and its risk classification, which `ggctl diff` reports
//!   for two bundles and the ledger's plans gate applies on;
//! - the leaves the compiler calls: [`connections`] (the secret alias,
//!   keyring and provider documents and their validators, the Connection
//!   ID grammar and the origin-relative path grammar), [`auth`] (issuer
//!   canonicalization, the principal identity bounds, the JWKS key age bounds,
//!   the cookie-name grammar, the client-certificate identity source and the
//!   admin session settings), [`inbound_tls`], [`path_match`],
//!   [`request_bounds`], [`upstream_route`] (the stable route ID grammar) and
//!   [`discovery`] (the signal and suggestion defaults).
//!
//! The gateway re-exports the compiler, the policy and tools models and each
//! leaf from the module it moved out of, so its call sites keep their paths.
//! An inherent method that needs the gateway -- a file, an authenticated
//! principal, the cluster roster -- is a method of a gateway-side trait of
//! the same name there. With the bundle reader and the
//! compiler both here, `ggctl` can link ADR-0008's pipeline stages 1 to 5:
//! bounded reading and document validation, normalization, the typing of
//! secret locators, and cross-field validation. The compiler's contract is
//! `docs/architecture/configuration-compiler.md`.
//!
//! Still in the gateway crate: `Config` and the startup stages that act on a
//! compiled plan, and everything that acts on a policy or tools document --
//! loading and watching its file, its history, the tool registry, and
//! evaluating policy and executing tools. The bundle reader takes its
//! validators as a [`bundle::ResourceValidators`] argument; the gateway and
//! `ggctl` both pass the production ones.
//!
//! Nothing here touches the environment, a clock or the network, and the
//! compiler, the policy and tools parses and the leaves touch nothing at all:
//! the compiler's one side effect is a log line naming a setting, and the
//! policy 0.x reader's is one naming the unknown top-level members it drops. The bundle reader reads files only
//! beneath the bundle root it is given, and never writes. The archive guard reads and writes only the readers and writers
//! it is handed. The ledger is the one store: it reads and writes only its own
//! database and journal files beneath the state directory it is given, and
//! the revision service reads and writes only through it. The state
//! directory's lock file is the one other file written there: created
//! empty, locked and never removed. A backup reads the stores beneath a
//! held state directory through read-only connections, and writes only the
//! archive it is told to create and the hidden working, partial and staging
//! entries beside that archive, which it removes; verifying one writes only
//! the staging directory beside the archive, which it removes. A restore
//! writes only a staging directory beside the target state directory, which
//! it renames into the target's place or removes, the target's lock file,
//! and the rename of the target aside, which it removes once the switch is
//! done; reading a restore marker reads only that file, and acknowledging it
//! removes only that file.

pub mod archive;
pub mod auth;
pub mod backup;
pub mod bundle;
pub mod canonical_json;
pub mod capabilities;
pub mod catalog;
pub mod compiler;
pub mod connections;
pub mod discovery;
pub mod documents;
pub mod inbound_tls;
pub mod ledger;
pub mod mcp_client_configs;
pub mod opaque_id;
pub mod path_match;
pub mod permissions;
pub mod rbac;
pub mod request_bounds;
pub mod revisions;
pub mod semantic_diff;
pub mod state_dir;
pub mod tools;
pub mod upstream_route;
