//! Policy schema versions, structured diagnostics and canonical digests
//! (issue #243, checklist item 3).
//!
//! The schema dispatch, policy v1's closed vocabulary, the diagnostics and
//! the digests are `gateway_config::rbac::policy_document` (issue #242), so
//! the gateway and `ggctl` read a policy document by one parse. This module
//! re-exports it so call sites keep their paths.

pub use gateway_config::rbac::policy_document::*;

#[cfg(test)]
#[path = "policy_document_tests.rs"]
mod tests;
