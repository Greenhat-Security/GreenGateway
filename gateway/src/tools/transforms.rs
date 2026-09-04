use std::borrow::Cow;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::{
    codecs::Codec,
    selector::{visit_selected_objects_mut, JsonPointer, Selector, SelectorSegment},
};

pub const MAX_TRANSFORM_WARNINGS: usize = 32;

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ToolTransform {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parameters: Vec<ParameterShape>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub response_fields: Vec<ParameterShape>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_root: Option<Selector>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ParameterShape {
    pub wire_property: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub wire_required: bool,
    pub agent: Vec<AgentProperty>,
    pub wire: Vec<WireBinding>,
    pub response: Vec<ResponseBinding>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentProperty {
    pub name: String,
    pub schema: Value,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct WireBinding {
    pub pointer: JsonPointer,
    #[serde(flatten)]
    pub source: WireSource,
    #[serde(default, rename = "codec", skip_serializing_if = "Vec::is_empty")]
    pub codecs: Vec<Codec>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum WireSource {
    From { from: String },
    Const { r#const: Value },
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseBinding {
    pub agent_property: String,
    pub from: JsonPointer,
    #[serde(default, rename = "codec", skip_serializing_if = "Vec::is_empty")]
    pub codecs: Vec<Codec>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransformError {
    pub parameter: String,
    pub path: String,
    pub reason: String,
}

impl std::fmt::Display for TransformError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{} at {}: {}",
            self.parameter, self.path, self.reason
        )
    }
}

impl std::error::Error for TransformError {}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransformWarning {
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DeclaredResponseSchema {
    pub status: String,
    pub schema: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)] // Stable seam consumed by issue #360 PR4 composite compilation.
pub struct ResponseSchemaProjectionError {
    pub path: String,
    pub reason: String,
}

impl std::fmt::Display for ResponseSchemaProjectionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.path, self.reason)
    }
}

impl std::error::Error for ResponseSchemaProjectionError {}

pub fn apply_request_transform<'a>(
    transform: Option<&ToolTransform>,
    args: &'a Value,
) -> Result<Cow<'a, Value>, TransformError> {
    let Some(transform) = transform.filter(|transform| !transform.parameters.is_empty()) else {
        return Ok(Cow::Borrowed(args));
    };
    let mut wire_args = args.clone();
    let Some(arguments) = wire_args.as_object_mut() else {
        return Err(TransformError {
            parameter: String::new(),
            path: "/".to_owned(),
            reason: "tool arguments must be an object".to_owned(),
        });
    };

    for shape in &transform.parameters {
        materialize_parameter(arguments, shape)?;
    }
    Ok(Cow::Owned(wire_args))
}

pub fn apply_response_transform(
    transform: &ToolTransform,
    body: &mut Value,
) -> Vec<TransformWarning> {
    let mut warnings = Vec::new();
    let mut apply = |path: &str, object: &mut Map<String, Value>| {
        for shape in transform
            .parameters
            .iter()
            .chain(transform.response_fields.iter())
        {
            decode_parameter(object, path, shape, &mut warnings);
        }
    };

    let objects = if let Some(selector) = &transform.response_root {
        visit_selected_objects_mut(body, selector, &mut apply).objects
    } else if let Value::Object(object) = body {
        apply("/", object);
        1
    } else {
        0
    };

    if objects == 0 {
        push_warning(
            &mut warnings,
            TransformWarning {
                path: transform
                    .response_root
                    .as_ref()
                    .map_or_else(|| "/".to_owned(), ToString::to_string),
                reason: "response_root_selected_nothing".to_owned(),
            },
        );
    }
    warnings
}

#[allow(dead_code)] // Stable seam consumed by issue #360 PR4 composite compilation.
pub fn project_success_response_schemas(
    raw: &[DeclaredResponseSchema],
    transform: Option<&ToolTransform>,
) -> Result<Vec<Value>, ResponseSchemaProjectionError> {
    let mut projected = raw
        .iter()
        .map(|declared| declared.schema.clone())
        .collect::<Vec<_>>();
    let Some(transform) = transform else {
        return Ok(projected);
    };

    for schema in &mut projected {
        if let Some(selector) = &transform.response_root {
            let mut visited = 0usize;
            project_selected_schema_objects(
                schema,
                &selector.segments,
                0,
                transform,
                &mut visited,
            )?;
            if visited == 0 {
                return Err(ResponseSchemaProjectionError {
                    path: selector.to_string(),
                    reason: "response selector resolves to no object schema".to_owned(),
                });
            }
        } else {
            project_object_schema(schema, transform, "/")?;
        }
    }
    Ok(projected)
}

fn materialize_parameter(
    arguments: &mut Map<String, Value>,
    shape: &ParameterShape,
) -> Result<(), TransformError> {
    let any_source_present = shape.wire.iter().any(|binding| match &binding.source {
        WireSource::From { from } => arguments.contains_key(from),
        WireSource::Const { .. } => false,
    });

    if !any_source_present && !shape.wire_required {
        for agent in &shape.agent {
            arguments.remove(&agent.name);
        }
        return Ok(());
    }

    let mut wire_value = Value::Object(Map::new());
    let mut wrote_value = false;
    for binding in &shape.wire {
        let (parameter, value) = match &binding.source {
            WireSource::From { from } => {
                let Some(value) = arguments.get(from) else {
                    continue;
                };
                (from.as_str(), value.clone())
            }
            WireSource::Const { r#const } => (shape.wire_property.as_str(), r#const.clone()),
        };
        let value = super::codecs::encode_chain(&binding.codecs, value).map_err(|error| {
            TransformError {
                parameter: parameter.to_owned(),
                path: argument_path(parameter),
                reason: error.reason,
            }
        })?;
        write_pointer(&mut wire_value, &binding.pointer, value).map_err(|reason| {
            TransformError {
                parameter: parameter.to_owned(),
                path: argument_path(parameter),
                reason,
            }
        })?;
        wrote_value = true;
    }

    if shape.wire_required && !wrote_value {
        let parameter = shape
            .agent
            .first()
            .map_or(shape.wire_property.as_str(), |agent| agent.name.as_str());
        return Err(TransformError {
            parameter: parameter.to_owned(),
            path: argument_path(parameter),
            reason: "required transformed value is missing".to_owned(),
        });
    }

    for agent in &shape.agent {
        arguments.remove(&agent.name);
    }
    if wrote_value {
        arguments.insert(shape.wire_property.clone(), wire_value);
    }
    Ok(())
}

fn write_pointer(root: &mut Value, pointer: &JsonPointer, value: Value) -> Result<(), String> {
    let tokens = pointer_tokens(pointer);
    if tokens.is_empty() {
        return Err("wire binding pointer must not be empty".to_owned());
    }
    write_pointer_tokens(root, &tokens, value)
}

fn write_pointer_tokens(root: &mut Value, tokens: &[String], value: Value) -> Result<(), String> {
    let Some((token, remaining)) = tokens.split_first() else {
        *root = value;
        return Ok(());
    };
    if remaining.is_empty() {
        match root {
            Value::Object(object) => {
                if object.insert(token.clone(), value).is_some() {
                    return Err("wire bindings write the same pointer more than once".to_owned());
                }
                Ok(())
            }
            _ => Err("wire binding pointer crosses a scalar value".to_owned()),
        }
    } else {
        let empty_child = || Value::Object(Map::new());
        let child = match root {
            Value::Object(object) => object.entry(token.clone()).or_insert_with(empty_child),
            _ => return Err("wire binding pointer crosses a scalar value".to_owned()),
        };
        write_pointer_tokens(child, remaining, value)
    }
}

fn pointer_tokens(pointer: &JsonPointer) -> Vec<String> {
    if pointer.as_str().is_empty() {
        return Vec::new();
    }
    pointer.as_str()[1..]
        .split('/')
        .map(|token| token.replace("~1", "/").replace("~0", "~"))
        .collect()
}

fn decode_parameter(
    object: &mut Map<String, Value>,
    object_path: &str,
    shape: &ParameterShape,
    warnings: &mut Vec<TransformWarning>,
) {
    let Some(wire_value) = object.get(&shape.wire_property).cloned() else {
        return;
    };
    if shape.response.is_empty() {
        return;
    }
    let wire_path = join_path(object_path, &shape.wire_property);
    let mut decoded = Vec::with_capacity(shape.response.len());
    for binding in &shape.response {
        if object.contains_key(&binding.agent_property)
            && binding.agent_property != shape.wire_property
        {
            push_warning(
                warnings,
                TransformWarning {
                    path: wire_path,
                    reason: format!(
                        "response agent property '{}' already exists",
                        binding.agent_property
                    ),
                },
            );
            return;
        }
        let Some(source) = wire_value.pointer(binding.from.as_str()).cloned() else {
            push_warning(
                warnings,
                TransformWarning {
                    path: join_pointer(&wire_path, &binding.from),
                    reason: "response binding pointer is missing".to_owned(),
                },
            );
            return;
        };
        let value = match super::codecs::decode_chain(&binding.codecs, source) {
            Ok(value) => value,
            Err(error) => {
                push_warning(
                    warnings,
                    TransformWarning {
                        path: join_pointer(&wire_path, &binding.from),
                        reason: error.reason,
                    },
                );
                return;
            }
        };
        decoded.push((binding.agent_property.clone(), value));
    }

    object.remove(&shape.wire_property);
    for (name, value) in decoded {
        object.insert(name, value);
    }
}

fn push_warning(warnings: &mut Vec<TransformWarning>, warning: TransformWarning) {
    if warnings.len() < MAX_TRANSFORM_WARNINGS.saturating_sub(1) {
        warnings.push(warning);
    } else if warnings.len() == MAX_TRANSFORM_WARNINGS.saturating_sub(1) {
        warnings.push(TransformWarning {
            path: "/".to_owned(),
            reason: "warnings_truncated".to_owned(),
        });
    }
}

fn argument_path(parameter: &str) -> String {
    join_path("", parameter)
}

fn join_path(base: &str, token: &str) -> String {
    let escaped = token.replace('~', "~0").replace('/', "~1");
    if base == "/" || base.is_empty() {
        format!("/{escaped}")
    } else {
        format!("{base}/{escaped}")
    }
}

fn join_pointer(base: &str, pointer: &JsonPointer) -> String {
    if pointer.as_str().is_empty() {
        base.to_owned()
    } else if base == "/" {
        pointer.to_string()
    } else {
        format!("{base}{}", pointer.as_str())
    }
}

#[allow(dead_code)]
fn project_selected_schema_objects(
    schema: &mut Value,
    segments: &[SelectorSegment],
    index: usize,
    transform: &ToolTransform,
    visited: &mut usize,
) -> Result<(), ResponseSchemaProjectionError> {
    if index == segments.len() {
        project_object_schema(schema, transform, "/")?;
        *visited = visited.saturating_add(1);
        return Ok(());
    }
    let Some(object) = schema.as_object_mut() else {
        return Ok(());
    };
    match &segments[index] {
        SelectorSegment::Key(key) => {
            if let Some(child) = object
                .get_mut("properties")
                .and_then(Value::as_object_mut)
                .and_then(|properties| properties.get_mut(key))
            {
                project_selected_schema_objects(child, segments, index + 1, transform, visited)?;
            } else if let Some(child) = object.get_mut("additionalProperties") {
                if child.is_object() {
                    project_selected_schema_objects(
                        child,
                        segments,
                        index + 1,
                        transform,
                        visited,
                    )?;
                }
            }
        }
        SelectorSegment::Wildcard => {
            if let Some(items) = object.get_mut("items") {
                project_selected_schema_objects(items, segments, index + 1, transform, visited)?;
            } else if let Some(properties) =
                object.get_mut("properties").and_then(Value::as_object_mut)
            {
                for child in properties.values_mut() {
                    project_selected_schema_objects(
                        child,
                        segments,
                        index + 1,
                        transform,
                        visited,
                    )?;
                }
            }
        }
        SelectorSegment::Filter { key, .. } => {
            if let Some(items) = object
                .get_mut("properties")
                .and_then(Value::as_object_mut)
                .and_then(|properties| properties.get_mut(key))
                .and_then(Value::as_object_mut)
                .and_then(|array| array.get_mut("items"))
            {
                project_selected_schema_objects(items, segments, index + 1, transform, visited)?;
            }
        }
    }
    Ok(())
}

#[allow(dead_code)]
fn project_object_schema(
    schema: &mut Value,
    transform: &ToolTransform,
    path: &str,
) -> Result<(), ResponseSchemaProjectionError> {
    let Some(object) = schema.as_object_mut() else {
        return Err(ResponseSchemaProjectionError {
            path: path.to_owned(),
            reason: "selected response schema is not an object".to_owned(),
        });
    };
    let mut required = object
        .get("required")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let Some(properties) = object.get_mut("properties").and_then(Value::as_object_mut) else {
        return Err(ResponseSchemaProjectionError {
            path: path.to_owned(),
            reason: "selected response object schema has no properties".to_owned(),
        });
    };
    for shape in transform
        .parameters
        .iter()
        .chain(transform.response_fields.iter())
    {
        if properties.remove(&shape.wire_property).is_none() {
            continue;
        }
        let was_required = required
            .iter()
            .any(|name| name.as_str() == Some(&shape.wire_property));
        required.retain(|name| name.as_str() != Some(&shape.wire_property));
        for binding in &shape.response {
            let Some(agent) = shape
                .agent
                .iter()
                .find(|agent| agent.name == binding.agent_property)
            else {
                return Err(ResponseSchemaProjectionError {
                    path: join_path(path, &binding.agent_property),
                    reason: "response binding names an unknown agent property".to_owned(),
                });
            };
            properties.insert(agent.name.clone(), agent.schema.clone());
            if was_required
                && !required
                    .iter()
                    .any(|name| name.as_str() == Some(&agent.name))
            {
                required.push(Value::String(agent.name.clone()));
            }
        }
    }
    if required.is_empty() {
        object.remove("required");
    } else {
        object.insert("required".to_owned(), Value::Array(required));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use serde_json::json;

    use super::*;
    use crate::tools::codecs::{DecimalWireEncoding, MarkdownDialect};

    fn pointer(value: &str) -> JsonPointer {
        value.parse().expect("fixture pointer should parse")
    }

    fn money_shape() -> ParameterShape {
        ParameterShape {
            wire_property: "annualRecurringRevenue".to_owned(),
            wire_required: true,
            agent: vec![
                AgentProperty {
                    name: "amount".to_owned(),
                    schema: json!({"type":"number"}),
                },
                AgentProperty {
                    name: "currency".to_owned(),
                    schema: json!({"type":"string"}),
                },
            ],
            wire: vec![
                WireBinding {
                    pointer: pointer("/amountMicros"),
                    source: WireSource::From {
                        from: "amount".to_owned(),
                    },
                    codecs: vec![Codec::DecimalScale {
                        scale: 6,
                        wire_encoding: DecimalWireEncoding::IntegerString,
                        max_integer_digits: 24,
                    }],
                },
                WireBinding {
                    pointer: pointer("/currencyCode"),
                    source: WireSource::From {
                        from: "currency".to_owned(),
                    },
                    codecs: Vec::new(),
                },
            ],
            response: vec![
                ResponseBinding {
                    agent_property: "amount".to_owned(),
                    from: pointer("/amountMicros"),
                    codecs: vec![Codec::DecimalScale {
                        scale: 6,
                        wire_encoding: DecimalWireEncoding::IntegerString,
                        max_integer_digits: 24,
                    }],
                },
                ResponseBinding {
                    agent_property: "currency".to_owned(),
                    from: pointer("/currencyCode"),
                    codecs: Vec::new(),
                },
            ],
        }
    }

    #[test]
    fn no_transform_returns_the_original_arguments_borrowed() {
        let args = json!({"value": 1});
        assert!(matches!(
            apply_request_transform(None, &args).expect("no transform cannot fail"),
            Cow::Borrowed(value) if std::ptr::eq(value, &args)
        ));

        let response_only = ToolTransform {
            parameters: Vec::new(),
            response_fields: Vec::new(),
            response_root: Some("/data".parse().expect("selector")),
        };
        assert!(matches!(
            apply_request_transform(Some(&response_only), &args)
                .expect("response-only transform cannot affect request arguments"),
            Cow::Borrowed(value) if std::ptr::eq(value, &args)
        ));
    }

    #[test]
    fn flattened_wire_source_deserializes_from_the_persisted_shape() {
        let binding: WireBinding = serde_json::from_value(json!({
            "pointer":"/amountMicros",
            "from":"amount",
            "codec":[{
                "kind":"decimal_scale",
                "scale":6,
                "wire_encoding":"integer_string",
                "max_integer_digits":24
            }]
        }))
        .expect("persisted wire binding should deserialize");
        assert_eq!(
            binding.source,
            WireSource::From {
                from: "amount".to_owned()
            }
        );
        assert_eq!(binding.pointer.as_str(), "/amountMicros");
        assert_eq!(
            serde_json::to_value(binding).expect("binding should serialize")["from"],
            "amount"
        );
    }

    #[test]
    fn request_and_response_money_transforms_round_trip() {
        let transform = ToolTransform {
            parameters: vec![money_shape()],
            response_fields: Vec::new(),
            response_root: Some("/data/*".parse().expect("selector")),
        };
        let args = json!({"amount":24000,"currency":"USD","name":"Acme"});
        let encoded = apply_request_transform(Some(&transform), &args)
            .expect("money should encode")
            .into_owned();
        assert_eq!(
            encoded,
            json!({
                "annualRecurringRevenue": {
                    "amountMicros":"24000000000",
                    "currencyCode":"USD"
                },
                "name":"Acme"
            })
        );
        assert_eq!(args, json!({"amount":24000,"currency":"USD","name":"Acme"}));

        let mut response = json!({
            "data": {
                "createOneCompany": {
                    "annualRecurringRevenue": {
                        "amountMicros":"24000000000",
                        "currencyCode":"USD"
                    }
                }
            }
        });
        assert!(apply_response_transform(&transform, &mut response).is_empty());
        assert_eq!(
            response,
            json!({"data":{"createOneCompany":{"amount":24000,"currency":"USD"}}})
        );
    }

    #[test]
    fn failed_response_decode_is_atomic_per_wire_property() {
        let transform = ToolTransform {
            parameters: vec![money_shape()],
            response_fields: Vec::new(),
            response_root: None,
        };
        let original = json!({
            "annualRecurringRevenue": {
                "amountMicros":"not-an-integer",
                "currencyCode":"USD"
            }
        });
        let mut response = original.clone();
        let warnings = apply_response_transform(&transform, &mut response);
        assert_eq!(response, original);
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].path, "/annualRecurringRevenue/amountMicros");
        assert!(!response.as_object().expect("object").contains_key("amount"));
    }

    #[test]
    fn markdown_and_json_string_chain_materializes_both_wire_fields() {
        let shape = ParameterShape {
            wire_property: "bodyV2".to_owned(),
            wire_required: true,
            agent: vec![AgentProperty {
                name: "markdown".to_owned(),
                schema: json!({"type":"string"}),
            }],
            wire: vec![
                WireBinding {
                    pointer: pointer("/markdown"),
                    source: WireSource::From {
                        from: "markdown".to_owned(),
                    },
                    codecs: Vec::new(),
                },
                WireBinding {
                    pointer: pointer("/blocknote"),
                    source: WireSource::From {
                        from: "markdown".to_owned(),
                    },
                    codecs: vec![
                        Codec::MarkdownBlocks {
                            dialect: MarkdownDialect::Blocknote,
                            max_input_bytes: 65_536,
                        },
                        Codec::JsonString,
                    ],
                },
            ],
            response: vec![ResponseBinding {
                agent_property: "markdown".to_owned(),
                from: pointer("/markdown"),
                codecs: Vec::new(),
            }],
        };
        let transform = ToolTransform {
            parameters: vec![shape],
            response_fields: Vec::new(),
            response_root: None,
        };
        let encoded = apply_request_transform(Some(&transform), &json!({"markdown":"# Hi"}))
            .expect("rich text should encode")
            .into_owned();
        assert_eq!(encoded["bodyV2"]["markdown"], "# Hi");
        let blocknote = encoded["bodyV2"]["blocknote"]
            .as_str()
            .expect("BlockNote wire value is a JSON string");
        let parsed: Value = serde_json::from_str(blocknote).expect("string contains JSON");
        assert_eq!(parsed[0]["type"], "heading");
    }

    #[test]
    fn response_warning_collection_is_bounded_at_the_source() {
        let shape = money_shape();
        let transform = ToolTransform {
            parameters: vec![shape],
            response_fields: Vec::new(),
            response_root: Some("/items/*".parse().expect("selector")),
        };
        let mut response = json!({
            "items": (0..100).map(|_| json!({
                "annualRecurringRevenue": {
                    "amountMicros":"bad",
                    "currencyCode":"USD"
                }
            })).collect::<Vec<_>>()
        });
        let warnings = apply_response_transform(&transform, &mut response);
        assert_eq!(warnings.len(), MAX_TRANSFORM_WARNINGS);
        assert_eq!(warnings.last().expect("sentinel").path, "/");
        assert_eq!(
            warnings.last().expect("sentinel").reason,
            "warnings_truncated"
        );
    }

    #[test]
    fn projected_response_schema_uses_agent_properties() {
        let transform = ToolTransform {
            parameters: vec![money_shape()],
            response_fields: Vec::new(),
            response_root: Some("/data/*".parse().expect("selector")),
        };
        let raw = vec![DeclaredResponseSchema {
            status: "200".to_owned(),
            schema: json!({
                "type":"object",
                "properties": {
                    "data": {
                        "type":"object",
                        "properties": {
                            "createOneCompany": {
                                "type":"object",
                                "properties": {
                                    "annualRecurringRevenue": {"type":"object"}
                                },
                                "required":["annualRecurringRevenue"]
                            }
                        }
                    }
                }
            }),
        }];
        let projected = project_success_response_schemas(&raw, Some(&transform))
            .expect("declared response should project");
        let company = &projected[0]["properties"]["data"]["properties"]["createOneCompany"];
        assert!(company["properties"]
            .get("annualRecurringRevenue")
            .is_none());
        assert_eq!(company["properties"]["amount"]["type"], "number");
        assert_eq!(company["required"], json!(["amount", "currency"]));
    }
}
