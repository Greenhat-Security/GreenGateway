//! Referenced policy and tools documents.
//!
//! A bundle pins its policy and tools documents but does not define them:
//! each stays its own document, under its own published schema and production
//! validator, exactly as environment mode reads it. The bundle boundary adds
//! only what environment mode cannot promise -- strict JSON (a duplicate
//! member is refused, not overwritten), the exact `schema_version` the
//! manifest declares, refusal of any top-level member the policy loader
//! would warn about and drop, and the published schema of each document,
//! which the environment-mode policy loader does not apply. The production
//! validators run after these checks, through the caller's
//! [`ResourceValidators`](super::ResourceValidators). Validator messages can
//! quote document values, so a refusal is reported by code alone.

use std::sync::LazyLock;

use serde_json::Value;

use super::{
    diagnostic::{BundleDiagnostic, Code, Pointer},
    document::POLICY_V0_VERSION,
    json,
    profile::ProfileRules,
    source::FileName,
    syntax::{Node, SyntaxError, RESOURCE_LIMITS},
};
use crate::rbac::{policy::V1_TOP_LEVEL_KEYS, policy_document::POLICY_V1_SCHEMA_VERSION};

/// The bound environment mode already applies to each document.
pub const MAX_RESOURCE_BYTES: usize = 1024 * 1024;

/// The policy loader's top-level vocabulary for v0. The bundle reader
/// refuses unrecognized members at their source position.
pub const POLICY_TOP_LEVEL_MEMBERS: &[&str] = crate::rbac::policy::KNOWN_TOP_LEVEL_KEYS;

const POLICY_V0_SCHEMA_JSON: &str = include_str!("../../../docs/schemas/policy.v0.schema.json");
const POLICY_V1_SCHEMA_JSON: &str = include_str!("../../../docs/schemas/policy.v1.schema.json");
const TOOLS_SCHEMA_JSON: &str = include_str!("../../../docs/schemas/tools.v0.schema.json");

/// The environment-mode policy loader does not apply the published schema;
/// in a bundle the document must pass it as well as the loader.
static POLICY_V0_SCHEMA_VALIDATOR: LazyLock<Option<jsonschema::Validator>> =
    LazyLock::new(|| compile(POLICY_V0_SCHEMA_JSON));
static POLICY_V1_SCHEMA_VALIDATOR: LazyLock<Option<jsonschema::Validator>> =
    LazyLock::new(|| compile(POLICY_V1_SCHEMA_JSON));

/// The production tools validator applies this schema first as well; the
/// reader applies it so that a caller without that validator still does.
static TOOLS_SCHEMA_VALIDATOR: LazyLock<Option<jsonschema::Validator>> =
    LazyLock::new(|| compile(TOOLS_SCHEMA_JSON));

fn compile(schema: &str) -> Option<jsonschema::Validator> {
    let schema: Value = serde_json::from_str(schema).ok()?;
    jsonschema::validator_for(&schema).ok()
}

/// Checks a referenced policy document at the bundle boundary and returns
/// its JSON value for the production validator.
///
/// With the deployment's profile, the policy is also held to that
/// profile's invariants once it has passed its schema. A broken invariant is
/// reported, an acknowledged one as a warning, and the production validator
/// still runs, so every problem is.
pub(crate) fn policy(
    text: &str,
    schema_version: &str,
    profile: Option<&ProfileRules>,
    file: &FileName,
    diagnostics: &mut Vec<BundleDiagnostic>,
) -> Option<Value> {
    let (node, value) = resource_value(text, schema_version, file, diagnostics)?;
    let (known_members, schema) = match schema_version {
        POLICY_V0_VERSION => (POLICY_TOP_LEVEL_MEMBERS, &POLICY_V0_SCHEMA_VALIDATOR),
        POLICY_V1_SCHEMA_VERSION => (V1_TOP_LEVEL_KEYS, &POLICY_V1_SCHEMA_VALIDATOR),
        _ => {
            diagnostics.push(BundleDiagnostic::file(Code::UnsupportedSchemaVersion, file));
            return None;
        }
    };
    let unknown: Vec<_> = node
        .as_object()
        .unwrap_or_default()
        .iter()
        .filter(|member| !known_members.contains(&member.key.as_str()))
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
    let value = published_schema(schema, value, file, diagnostics)?;
    if let Some(rules) = profile {
        super::profile::policy(rules, &node, file, diagnostics);
    }
    Some(value)
}

/// Checks a referenced tools document at the bundle boundary and returns
/// its JSON value for the production validator.
pub(crate) fn tools(
    text: &str,
    schema_version: &str,
    file: &FileName,
    diagnostics: &mut Vec<BundleDiagnostic>,
) -> Option<Value> {
    // The published tools schema closes the top level and refuses unknown
    // members throughout.
    let (_, value) = resource_value(text, schema_version, file, diagnostics)?;
    published_schema(&TOOLS_SCHEMA_VALIDATOR, value, file, diagnostics)
}

fn published_schema(
    validator: &LazyLock<Option<jsonschema::Validator>>,
    value: Value,
    file: &FileName,
    diagnostics: &mut Vec<BundleDiagnostic>,
) -> Option<Value> {
    // A schema that does not compile is a build defect the tests catch; it
    // refuses every document rather than skipping the check.
    let valid = validator
        .as_ref()
        .is_some_and(|validator| validator.is_valid(&value));
    if valid {
        Some(value)
    } else {
        diagnostics.push(BundleDiagnostic::file(Code::ResourceInvalid, file));
        None
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
pub(crate) fn published_schemas_compile() -> bool {
    POLICY_V0_SCHEMA_VALIDATOR.is_some()
        && POLICY_V1_SCHEMA_VALIDATOR.is_some()
        && TOOLS_SCHEMA_VALIDATOR.is_some()
}
