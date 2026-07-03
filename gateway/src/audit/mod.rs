//! Audit event primitives.

// These foundational types and re-exports are intentionally added before they
// are wired into sinks. PR 2 consumes them when audit emission is added.
#![allow(dead_code, unused_imports)]

pub mod event;
pub mod redact;

pub use event::{Actor, AuditEvent, SCHEMA_VERSION};
pub use redact::{hash_args, hash_credential, redact_string, sha256_hex};
