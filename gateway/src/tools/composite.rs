//! Compiled composite-tool mappings and the pure parts of saga execution.
//!
//! The overlay compiler owns proving that references are well formed and that
//! step tools belong to the same OpenAPI catalog.  This module deliberately
//! repeats the inexpensive runtime bounds and reference checks: persisted
//! definitions are an authority boundary, and the executor must fail closed if
//! a corrupt definition reaches it.

use std::collections::BTreeMap;

use http::Method;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};

pub const MAX_COMPOSITE_STEPS: usize = 16;
pub const MAX_COMPOSITE_ITERATIONS: usize = 64;
pub const MAX_COMPOSITE_RESULT_PROPERTIES: usize = 32;
pub const MAX_COMPOSITE_ARGUMENTS: usize = 64;
pub const MAX_COMPOSITE_BODY_BYTES: usize = 64 * 1024;
pub const MAX_COMPOSITE_JSON_DEPTH: usize = 64;
pub const DEFAULT_MAX_ITERATIONS: usize = 32;
pub const DEFAULT_COMPENSATION_TIMEOUT_MS: u64 = 30_000;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompositeMapping {
    pub steps: Vec<CompositeStep>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<BTreeMap<String, CompositeBinding>>,
    #[serde(default, skip_serializing_if = "CompositeLimits::is_default")]
    pub limits: CompositeLimits,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompositeStep {
    pub id: String,
    pub tool: String,
    #[serde(default)]
    pub arguments: BTreeMap<String, CompositeBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub for_each: Option<CompositeForEach>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub success_statuses: Option<Vec<u16>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ambiguous_statuses: Option<Vec<u16>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compensate: Option<CompositeCompensation>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompositeForEach {
    pub over: CompositeBinding,
    #[serde(rename = "as")]
    pub item_name: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompositeCompensation {
    pub tool: String,
    pub arguments: BTreeMap<String, CompositeBinding>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompositeLimits {
    #[serde(default = "default_max_iterations")]
    pub max_iterations: usize,
    #[serde(default = "default_compensation_timeout_ms")]
    pub compensation_timeout_ms: u64,
}

impl Default for CompositeLimits {
    fn default() -> Self {
        Self {
            max_iterations: DEFAULT_MAX_ITERATIONS,
            compensation_timeout_ms: DEFAULT_COMPENSATION_TIMEOUT_MS,
        }
    }
}

impl CompositeLimits {
    pub(crate) fn is_default(&self) -> bool {
        self == &Self::default()
    }
}

const fn default_max_iterations() -> usize {
    DEFAULT_MAX_ITERATIONS
}

const fn default_compensation_timeout_ms() -> u64 {
    DEFAULT_COMPENSATION_TIMEOUT_MS
}

/// A literal JSON value or one of the four closed reference forms accepted by
/// the overlay schema.  Deserialization is custom so an object containing an
/// unknown `$...` key cannot silently fall through to `Literal`.
#[derive(Debug, Clone, PartialEq)]
pub enum CompositeBinding {
    Literal(Value),
    Input {
        input: String,
        pointer: Option<String>,
    },
    Step {
        step: String,
        pointer: Option<String>,
        collect: bool,
    },
    Item {
        item: String,
        pointer: Option<String>,
    },
    SelfValue {
        pointer: String,
    },
}

/// The shorter name is convenient in compiler code and matches the issue's
/// compiled-form vocabulary.
#[allow(dead_code)]
pub type Binding = CompositeBinding;

impl Serialize for CompositeBinding {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Literal(value) => value.serialize(serializer),
            Self::Input { input, pointer } => {
                let mut object = Map::new();
                object.insert("$input".to_owned(), Value::String(input.clone()));
                if let Some(pointer) = pointer {
                    object.insert("pointer".to_owned(), Value::String(pointer.clone()));
                }
                Value::Object(object).serialize(serializer)
            }
            Self::Step {
                step,
                pointer,
                collect,
            } => {
                let mut object = Map::new();
                object.insert("$step".to_owned(), Value::String(step.clone()));
                if let Some(pointer) = pointer {
                    object.insert("pointer".to_owned(), Value::String(pointer.clone()));
                }
                if *collect {
                    object.insert("collect".to_owned(), Value::Bool(true));
                }
                Value::Object(object).serialize(serializer)
            }
            Self::Item { item, pointer } => {
                let mut object = Map::new();
                object.insert("$item".to_owned(), Value::String(item.clone()));
                if let Some(pointer) = pointer {
                    object.insert("pointer".to_owned(), Value::String(pointer.clone()));
                }
                Value::Object(object).serialize(serializer)
            }
            Self::SelfValue { pointer } => Value::Object(Map::from_iter([(
                "$self".to_owned(),
                Value::String(pointer.clone()),
            )]))
            .serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for CompositeBinding {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        let Value::Object(object) = &value else {
            return Ok(Self::Literal(value));
        };
        let dollar_keys = object
            .keys()
            .filter(|key| key.starts_with('$'))
            .map(String::as_str)
            .collect::<Vec<_>>();
        if dollar_keys.is_empty() {
            return Ok(Self::Literal(value));
        }
        if dollar_keys.len() != 1 {
            return Err(de::Error::custom(
                "a composite binding must contain exactly one reference key",
            ));
        }

        match dollar_keys[0] {
            "$input" => parse_named_pointer_binding(object, "$input", &["$input", "pointer"])
                .map(|(input, pointer)| Self::Input { input, pointer })
                .map_err(de::Error::custom),
            "$step" => {
                reject_unknown_keys(object, &["$step", "pointer", "collect"])
                    .map_err(de::Error::custom)?;
                let step = required_string(object, "$step").map_err(de::Error::custom)?;
                let pointer = optional_string(object, "pointer").map_err(de::Error::custom)?;
                let collect = match object.get("collect") {
                    Some(Value::Bool(value)) => *value,
                    Some(_) => {
                        return Err(de::Error::custom(
                            "composite binding 'collect' must be a boolean",
                        ));
                    }
                    None => false,
                };
                Ok(Self::Step {
                    step,
                    pointer,
                    collect,
                })
            }
            "$item" => parse_named_pointer_binding(object, "$item", &["$item", "pointer"])
                .map(|(item, pointer)| Self::Item { item, pointer })
                .map_err(de::Error::custom),
            "$self" => {
                reject_unknown_keys(object, &["$self"]).map_err(de::Error::custom)?;
                let pointer = required_string(object, "$self").map_err(de::Error::custom)?;
                Ok(Self::SelfValue { pointer })
            }
            key => Err(de::Error::custom(format!(
                "unknown composite binding reference key '{key}'"
            ))),
        }
    }
}

fn parse_named_pointer_binding(
    object: &Map<String, Value>,
    key: &str,
    allowed: &[&str],
) -> Result<(String, Option<String>), String> {
    reject_unknown_keys(object, allowed)?;
    Ok((
        required_string(object, key)?,
        optional_string(object, "pointer")?,
    ))
}

fn reject_unknown_keys(object: &Map<String, Value>, allowed: &[&str]) -> Result<(), String> {
    if let Some(key) = object.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(format!("unknown field '{key}' in composite binding"));
    }
    Ok(())
}

fn required_string(object: &Map<String, Value>, key: &str) -> Result<String, String> {
    object
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("composite binding '{key}' must be a string"))
}

fn optional_string(object: &Map<String, Value>, key: &str) -> Result<Option<String>, String> {
    match object.get(key) {
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(format!("composite binding '{key}' must be a string")),
        None => Ok(None),
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct CompositeStepOutput {
    /// Only a successfully parsed JSON response is referenceable by `$step`.
    pub json_body: Option<Value>,
    /// The safe agent-facing value used by the default composite result.
    pub result_body: Value,
}

pub(crate) type CompositeOutputs = BTreeMap<String, Vec<CompositeStepOutput>>;

pub(crate) struct BindingScope<'a> {
    pub input: &'a Map<String, Value>,
    pub steps: &'a CompositeOutputs,
    pub item: Option<(&'a str, &'a Value)>,
    pub self_body: Option<&'a Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BindingResolutionError {
    PointerUnresolved,
    ForEachNotArray,
}

impl BindingResolutionError {
    pub const fn reason(self) -> &'static str {
        match self {
            Self::PointerUnresolved => "pointer_unresolved",
            Self::ForEachNotArray => "for_each_not_array",
        }
    }
}

pub(crate) fn resolve_binding(
    binding: &CompositeBinding,
    scope: &BindingScope<'_>,
) -> Result<Value, BindingResolutionError> {
    match binding {
        CompositeBinding::Literal(value) => Ok(value.clone()),
        CompositeBinding::Input { input, pointer } => scope
            .input
            .get(input)
            .and_then(|value| value_at_pointer(value, pointer.as_deref()))
            .cloned()
            .ok_or(BindingResolutionError::PointerUnresolved),
        CompositeBinding::Step {
            step,
            pointer,
            collect,
        } => {
            let outputs = scope
                .steps
                .get(step)
                .ok_or(BindingResolutionError::PointerUnresolved)?;
            if *collect {
                outputs
                    .iter()
                    .map(|output| {
                        output
                            .json_body
                            .as_ref()
                            .and_then(|body| value_at_pointer(body, pointer.as_deref()))
                            .cloned()
                            .ok_or(BindingResolutionError::PointerUnresolved)
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .map(Value::Array)
            } else {
                let [output] = outputs.as_slice() else {
                    return Err(BindingResolutionError::PointerUnresolved);
                };
                output
                    .json_body
                    .as_ref()
                    .and_then(|body| value_at_pointer(body, pointer.as_deref()))
                    .cloned()
                    .ok_or(BindingResolutionError::PointerUnresolved)
            }
        }
        CompositeBinding::Item { item, pointer } => scope
            .item
            .filter(|(name, _)| *name == item)
            .and_then(|(_, value)| value_at_pointer(value, pointer.as_deref()))
            .cloned()
            .ok_or(BindingResolutionError::PointerUnresolved),
        CompositeBinding::SelfValue { pointer } => scope
            .self_body
            .and_then(|body| value_at_pointer(body, Some(pointer)))
            .cloned()
            .ok_or(BindingResolutionError::PointerUnresolved),
    }
}

pub(crate) fn resolve_arguments(
    bindings: &BTreeMap<String, CompositeBinding>,
    scope: &BindingScope<'_>,
) -> Result<Value, BindingResolutionError> {
    bindings
        .iter()
        .map(|(name, binding)| resolve_binding(binding, scope).map(|value| (name.clone(), value)))
        .collect::<Result<Map<_, _>, _>>()
        .map(Value::Object)
}

pub(crate) fn resolve_for_each(
    binding: &CompositeBinding,
    scope: &BindingScope<'_>,
) -> Result<Vec<Value>, BindingResolutionError> {
    match resolve_binding(binding, scope)? {
        Value::Array(items) => Ok(items),
        _ => Err(BindingResolutionError::ForEachNotArray),
    }
}

fn value_at_pointer<'a>(value: &'a Value, pointer: Option<&str>) -> Option<&'a Value> {
    match pointer {
        None | Some("") => Some(value),
        Some(pointer) => value.pointer(pointer),
    }
}

pub(crate) fn status_is_success(step: &CompositeStep, status: u16) -> bool {
    step.success_statuses
        .as_ref()
        .map_or((200..=299).contains(&status), |statuses| {
            statuses.contains(&status)
        })
}

pub(crate) fn status_is_ambiguous(step: &CompositeStep, method: &Method, status: u16) -> bool {
    step.ambiguous_statuses.as_ref().map_or_else(
        || {
            method != Method::GET
                && method != Method::HEAD
                && matches!(status, 500 | 502 | 503 | 504)
        },
        |statuses| statuses.contains(&status),
    )
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompositeResult {
    pub body: Value,
    pub steps_summary: Vec<CompositeStepSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompositeStepOutcome {
    Succeeded,
    Failed,
    Ambiguous,
    Skipped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompositeStepSummary {
    pub index: usize,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iteration: Option<usize>,
    pub tool: String,
    pub method: String,
    pub path_template: String,
    pub outcome: CompositeStepOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_status: Option<u16>,
    pub latency_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompositeCompensationOutcome {
    Succeeded,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompositeCompensationSummary {
    pub for_step: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iteration: Option<usize>,
    pub tool: String,
    pub outcome: CompositeCompensationOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompositeOrphanCertainty {
    Confirmed,
    Possible,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompositeOrphan {
    pub step: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iteration: Option<usize>,
    pub tool: String,
    pub certainty: CompositeOrphanCertainty,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_status: Option<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompositeCompensationState {
    Complete,
    Incomplete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingCompensation {
    pub step: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iteration: Option<usize>,
    pub tool: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompositeCompletionAudit {
    pub tool_name: String,
    pub request_id: String,
    pub outcome: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failed_step: Option<String>,
    pub steps: Vec<CompositeStepSummary>,
    pub compensations: Vec<CompositeCompensationSummary>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub pending_compensation: Vec<PendingCompensation>,
    pub invocation_source: String,
    pub connection_id: String,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn bindings_round_trip_and_unknown_dollar_keys_fail_closed() {
        let cases = [
            json!(7),
            json!({"literal": true}),
            json!({"$input":"ids","pointer":"/0"}),
            json!({"$step":"create","pointer":"/data/id","collect":true}),
            json!({"$item":"company","pointer":"/id"}),
            json!({"$self":"/data/id"}),
        ];
        for value in cases {
            let binding: CompositeBinding =
                serde_json::from_value(value.clone()).expect("binding should deserialize");
            assert_eq!(serde_json::to_value(binding).expect("serialize"), value);
        }
        assert!(serde_json::from_value::<CompositeBinding>(json!({"$future":"unsafe"})).is_err());
        assert!(serde_json::from_value::<CompositeBinding>(
            json!({"$input":"ids","unexpected":true})
        )
        .is_err());
    }

    #[test]
    fn omitted_and_explicit_empty_results_remain_distinct() {
        let omitted: CompositeMapping = serde_json::from_value(json!({
            "steps": [{"id":"read","tool":"read","arguments":{}}]
        }))
        .expect("mapping without result should deserialize");
        assert_eq!(omitted.result, None);

        let explicit: CompositeMapping = serde_json::from_value(json!({
            "steps": [{"id":"read","tool":"read","arguments":{}}],
            "result": {}
        }))
        .expect("mapping with an explicit empty result should deserialize");
        assert_eq!(explicit.result, Some(BTreeMap::new()));
        assert!(serde_json::to_value(explicit)
            .expect("mapping should serialize")
            .get("result")
            .is_some());
    }

    #[test]
    fn step_collect_and_item_bindings_resolve_without_exposing_wire_state() {
        let input = json!({"ids":["one","two"]});
        let input = input.as_object().expect("object");
        let outputs = BTreeMap::from([(
            "create".to_owned(),
            vec![
                CompositeStepOutput {
                    json_body: Some(json!({"data":{"id":"a"}})),
                    result_body: json!({"data":{"id":"a"}}),
                },
                CompositeStepOutput {
                    json_body: Some(json!({"data":{"id":"b"}})),
                    result_body: json!({"data":{"id":"b"}}),
                },
            ],
        )]);
        let item = json!({"id":"company"});
        let scope = BindingScope {
            input,
            steps: &outputs,
            item: Some(("record", &item)),
            self_body: None,
        };
        assert_eq!(
            resolve_binding(
                &CompositeBinding::Step {
                    step: "create".to_owned(),
                    pointer: Some("/data/id".to_owned()),
                    collect: true,
                },
                &scope,
            ),
            Ok(json!(["a", "b"]))
        );
        assert_eq!(
            resolve_binding(
                &CompositeBinding::Item {
                    item: "record".to_owned(),
                    pointer: Some("/id".to_owned()),
                },
                &scope,
            ),
            Ok(json!("company"))
        );
    }

    #[test]
    fn write_status_defaults_are_ambiguous_but_read_statuses_are_not() {
        let step = CompositeStep {
            id: "write".to_owned(),
            tool: "create".to_owned(),
            arguments: BTreeMap::new(),
            for_each: None,
            success_statuses: None,
            ambiguous_statuses: None,
            compensate: None,
        };
        assert!(status_is_success(&step, 201));
        assert!(status_is_ambiguous(&step, &Method::POST, 502));
        assert!(!status_is_ambiguous(&step, &Method::GET, 502));
        assert!(!status_is_ambiguous(&step, &Method::POST, 400));
    }
}
