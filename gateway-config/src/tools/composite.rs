//! The compiled composite-tool mapping a tool definition carries: its
//! steps, bindings and limits, and the closed binding grammar its
//! deserialization enforces (issue #360).
//!
//! The pure parts of saga execution that act on a mapping -- binding
//! resolution and the status classification -- are the gateway's
//! (`gateway/src/tools/composite.rs`), which re-exports this module.

use std::collections::BTreeMap;

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
    pub fn is_default(&self) -> bool {
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
