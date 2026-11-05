//! The semantic diff of two bundles (issue #242, PR 9).
//!
//! `gateway_config::semantic_diff` is the engine: the risk codes, the change
//! classes and the redaction rules. `gateway_config::compiler::semantic_diff`
//! compares two compiled environment configurations with it. This module
//! compares two bundles the shared bundle reader accepted with the gateway's
//! production validators, with their policy and tools documents in the form
//! those validators produced, so the diff compares exactly what the gateway
//! would run. (`ggctl diff` compares bundles read with the published schemas
//! only, as they were written.)
//!
//! Nothing here reads a file, the environment or the network; values are
//! compared in memory and only the closed-vocabulary ones are shown.
#![allow(dead_code)] // Ledger plans (`config::revisions`) and the tests are the readers.

use gateway_config::{
    bundle::{Bundle, BundledResource},
    semantic_diff::{compare_bundles, BundleView, Comparison, SemanticDiff},
};
use serde_json::{json, Value};

use crate::{rbac::policy::Policy, tools::definitions::ToolDefinition};

/// A bundle the shared reader accepted with the production validators.
type ProductionBundle = Bundle<Policy, Vec<ToolDefinition>>;

/// Compares two bundles the shared reader accepted with the gateway's
/// production validators, by the documents those validators built.
pub(crate) fn bundles(base: &ProductionBundle, candidate: &ProductionBundle) -> SemanticDiff {
    let (base_policy, base_tools) = (policy_value(base), tools_value(base));
    let (candidate_policy, candidate_tools) = (policy_value(candidate), tools_value(candidate));
    let mut comparison = Comparison::new();
    compare_bundles(
        &mut comparison,
        &BundleView::of(base, base_policy.as_ref(), base_tools.as_ref()),
        &BundleView::of(
            candidate,
            candidate_policy.as_ref(),
            candidate_tools.as_ref(),
        ),
    );
    comparison.finish()
}

/// The validated policy as its loader models it, with every default filled
/// in. `None` when it cannot be serialized, which the engine reports as an
/// `unknown` change whenever the pins differ.
fn policy_value(bundle: &ProductionBundle) -> Option<Value> {
    match &bundle.policy {
        Some(BundledResource::Bundle { document, .. }) => policy_document_value(document),
        _ => None,
    }
}

/// The validated tool definitions, as a tools document.
fn tools_value(bundle: &ProductionBundle) -> Option<Value> {
    match &bundle.tools {
        Some(BundledResource::Bundle {
            schema_version,
            document,
            ..
        }) => tools_document_value(schema_version, document),
        _ => None,
    }
}

/// A policy the production validator built, as the JSON its loader models:
/// what a diff and a ledger plan compare.
pub(super) fn policy_document_value(policy: &Policy) -> Option<Value> {
    serde_json::to_value(policy).ok()
}

/// Tool definitions the production validator built, as a tools document of
/// `schema_version`.
pub(super) fn tools_document_value(
    schema_version: &str,
    tools: &[ToolDefinition],
) -> Option<Value> {
    let tools = serde_json::to_value(tools).ok()?;
    Some(json!({"schema_version": schema_version, "tools": tools}))
}

#[cfg(test)]
mod tests {
    use gateway_config::semantic_diff::{DEFAULT_TOOL_MAX_CONCURRENT, DEFAULT_TOOL_TIMEOUT_MS};

    use crate::rbac::policy::{DEFAULT_TOOL_POLICY_MAX_CONCURRENT, DEFAULT_TOOL_POLICY_TIMEOUT_MS};

    /// The policy members the diff models are the shared reader's list, which
    /// `config::bundle`'s tests hold to the loader's.
    #[test]
    fn the_policy_model_takes_the_policy_loaders_defaults() {
        assert_eq!(DEFAULT_TOOL_TIMEOUT_MS, DEFAULT_TOOL_POLICY_TIMEOUT_MS);
        assert_eq!(
            DEFAULT_TOOL_MAX_CONCURRENT,
            u64::from(DEFAULT_TOOL_POLICY_MAX_CONCURRENT)
        );
    }
}
