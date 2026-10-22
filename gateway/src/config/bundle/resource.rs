//! Referenced policy and tools documents.
//!
//! A bundle pins its policy and tools documents but does not define them:
//! each stays its own document, under its own published schema and production
//! validator, exactly as environment mode reads it. The bundle boundary adds
//! only what environment mode cannot promise -- strict JSON (a duplicate
//! member is refused, not overwritten), the exact `schema_version` the
//! manifest declares, and refusal of any top-level member the policy loader
//! would warn about and drop. Validator messages can quote document values,
//! so a refusal is reported by code alone.

use std::sync::LazyLock;

use serde_json::Value;

use crate::{
    rbac::policy::{Policy, KNOWN_TOP_LEVEL_KEYS},
    tools::definitions::{definitions_from_json_value, ToolDefinition},
};

use super::{
    diagnostic::{BundleDiagnostic, Code, Pointer},
    json,
    source::FileName,
    syntax::{Node, SyntaxError, RESOURCE_LIMITS},
};

/// The bound environment mode already applies to each document.
pub(crate) const MAX_RESOURCE_BYTES: usize = 1024 * 1024;

const POLICY_SCHEMA_JSON: &str = include_str!("../../../../docs/schemas/policy.v0.schema.json");

/// The environment-mode policy loader does not apply the published schema;
/// in a bundle the document must pass it as well as the loader.
static POLICY_SCHEMA_VALIDATOR: LazyLock<Option<jsonschema::Validator>> = LazyLock::new(|| {
    let schema: Value = serde_json::from_str(POLICY_SCHEMA_JSON).ok()?;
    jsonschema::validator_for(&schema).ok()
});

/// Validates a referenced policy document.
pub(crate) fn policy(
    text: &str,
    schema_version: &str,
    file: &FileName,
    diagnostics: &mut Vec<BundleDiagnostic>,
) -> Option<Policy> {
    let (node, value) = resource_value(text, schema_version, file, diagnostics)?;
    let unknown: Vec<_> = node
        .as_object()
        .unwrap_or_default()
        .iter()
        .filter(|member| !KNOWN_TOP_LEVEL_KEYS.contains(&member.key.as_str()))
        .map(|member| {
            BundleDiagnostic::at(
                Code::ResourceUnknownMember,
                file,
                Pointer::root(),
                Some(member.key_position),
            )
        })
        .collect();
    if !unknown.is_empty() {
        diagnostics.extend(unknown);
        return None;
    }
    // A schema that does not compile is a build defect the tests catch; it
    // refuses every policy rather than skipping the check.
    let schema_valid = POLICY_SCHEMA_VALIDATOR
        .as_ref()
        .is_some_and(|validator| validator.is_valid(&value));
    if !schema_valid {
        diagnostics.push(BundleDiagnostic::file(Code::ResourceInvalid, file));
        return None;
    }
    match Policy::validate_json_value(value) {
        Ok(policy) => Some(policy),
        Err(_) => {
            diagnostics.push(BundleDiagnostic::file(Code::ResourceInvalid, file));
            None
        }
    }
}

/// Validates a referenced tools document.
pub(crate) fn tools(
    text: &str,
    schema_version: &str,
    file: &FileName,
    diagnostics: &mut Vec<BundleDiagnostic>,
) -> Option<Vec<ToolDefinition>> {
    // The tools validator applies its published schema, which closes the top
    // level, and refuses unknown members throughout.
    let (_, value) = resource_value(text, schema_version, file, diagnostics)?;
    match definitions_from_json_value(value, None) {
        Ok(definitions) => Some(definitions),
        Err(_) => {
            diagnostics.push(BundleDiagnostic::file(Code::ResourceInvalid, file));
            None
        }
    }
}

/// Strictly parses a resource document and checks its declared version.
fn resource_value(
    text: &str,
    schema_version: &str,
    file: &FileName,
    diagnostics: &mut Vec<BundleDiagnostic>,
) -> Option<(Node, Value)> {
    let node = match json::parse(text, RESOURCE_LIMITS) {
        Ok(node) => node,
        Err(SyntaxError { code, position }) => {
            diagnostics.push(BundleDiagnostic::at(
                code,
                file,
                Pointer::root(),
                Some(position),
            ));
            return None;
        }
    };
    let Some(members) = node.as_object() else {
        diagnostics.push(BundleDiagnostic::at(
            Code::WrongType,
            file,
            Pointer::root(),
            Some(node.position),
        ));
        return None;
    };
    let pointer = Pointer::root().member("schema_version");
    match members.iter().find(|member| member.key == "schema_version") {
        None => {
            diagnostics.push(BundleDiagnostic::at(
                Code::MissingMember,
                file,
                pointer,
                Some(node.position),
            ));
            return None;
        }
        Some(member) if member.value.as_str() != Some(schema_version) => {
            diagnostics.push(BundleDiagnostic::at(
                Code::SchemaVersionMismatch,
                file,
                pointer,
                Some(member.value.position),
            ));
            return None;
        }
        Some(_) => {}
    }
    let value = node.to_json();
    Some((node, value))
}

#[cfg(test)]
pub(crate) fn policy_schema_compiles() -> bool {
    POLICY_SCHEMA_VALIDATOR.is_some()
}
