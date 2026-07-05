#![allow(dead_code)] // PR2 will wire this generator into an admin review workflow.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt, fs, io,
    path::{Path, PathBuf},
};

use serde_json::{json, Map, Value};

use crate::{
    discovery::openapi::{OpenApiOperation, OpenApiSpec, OpenApiSpecError},
    tools::definitions::{
        BodyMapping, BodyMappingMode, QueryParamMapping, ToolDefinition, UpstreamMapping,
    },
};

const TOOLS_FILE_SCHEMA_VERSION: &str = "0.1.0";
const MAX_TOOL_NAME_LENGTH: usize = 128;

#[derive(Debug, Clone, PartialEq)]
pub struct OpenApiToolGeneration {
    pub definitions: Vec<ToolDefinition>,
    pub operation_id_fallbacks: Vec<OpenApiToolNameFallback>,
    pub api_key_header_auth_requirements: Vec<OpenApiApiKeyHeaderAuthRequirement>,
}

impl OpenApiToolGeneration {
    pub fn tools_file_value(&self) -> Value {
        tools_file_value(&self.definitions)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenApiToolNameFallback {
    pub method: String,
    pub path_template: String,
    pub original_operation_id: Option<String>,
    pub generated_name: String,
    pub reason: OpenApiToolNameFallbackReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenApiToolNameFallbackReason {
    MissingOperationId,
    InvalidOperationId,
    DuplicateToolName,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenApiApiKeyHeaderAuthRequirement {
    pub tool_name: String,
    pub method: String,
    pub path_template: String,
    pub scheme_name: String,
    pub header_name: String,
}

#[derive(Debug)]
pub enum OpenApiToolGenerationError {
    Io { path: PathBuf, source: io::Error },
    Spec { source: OpenApiSpecError },
    Json { source: serde_json::Error },
    Yaml { source: yaml_serde::Error },
    Reference { reference: String, message: String },
}

#[derive(Clone)]
struct GeneratedParameter {
    name: String,
    location: GeneratedParameterLocation,
    required: bool,
    schema: Value,
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
enum GeneratedParameterLocation {
    Path,
    Query,
}

impl GeneratedParameterLocation {
    fn from_str(value: &str) -> Option<Self> {
        if value.eq_ignore_ascii_case("path") {
            Some(Self::Path)
        } else if value.eq_ignore_ascii_case("query") {
            Some(Self::Query)
        } else {
            None
        }
    }
}

impl fmt::Display for OpenApiToolGenerationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(
                    formatter,
                    "failed to read OpenAPI spec {}: {source}",
                    path.display()
                )
            }
            Self::Spec { source } => write!(formatter, "{source}"),
            Self::Json { source } => write!(formatter, "invalid OpenAPI JSON: {source}"),
            Self::Yaml { source } => write!(formatter, "invalid OpenAPI YAML: {source}"),
            Self::Reference { reference, message } => {
                write!(
                    formatter,
                    "invalid OpenAPI reference '{reference}': {message}"
                )
            }
        }
    }
}

impl Error for OpenApiToolGenerationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Spec { source } => Some(source),
            Self::Json { source } => Some(source),
            Self::Yaml { source } => Some(source),
            Self::Reference { .. } => None,
        }
    }
}

impl From<OpenApiSpecError> for OpenApiToolGenerationError {
    fn from(source: OpenApiSpecError) -> Self {
        Self::Spec { source }
    }
}

pub fn generate_tools_from_openapi_path(
    path: impl AsRef<Path>,
) -> Result<OpenApiToolGeneration, OpenApiToolGenerationError> {
    let path = path.as_ref();
    let contents = fs::read_to_string(path).map_err(|source| OpenApiToolGenerationError::Io {
        path: path.to_owned(),
        source,
    })?;
    generate_tools_from_openapi_str(&path.to_string_lossy(), &contents)
}

pub fn generate_tools_from_openapi_str(
    source: &str,
    contents: &str,
) -> Result<OpenApiToolGeneration, OpenApiToolGenerationError> {
    let parsed_spec = OpenApiSpec::parse_str(source, contents)?;
    let document = parse_document_value(source, contents)?;

    let mut definitions = Vec::new();
    let mut operation_id_fallbacks = Vec::new();
    let mut api_key_header_auth_requirements = Vec::new();
    let mut used_names = BTreeSet::new();

    for operation in &parsed_spec.operations {
        let operation_value = operation_value(&document, operation);
        let (tool_name, fallback) = tool_name_for(operation, &mut used_names);
        if let Some(fallback) = fallback {
            operation_id_fallbacks.push(fallback);
        }

        api_key_header_auth_requirements.extend(api_key_header_requirements(
            &document,
            operation,
            operation_value,
            &tool_name,
        )?);

        let parameters = operation_parameters(&document, operation)?;
        let body_schema = json_request_body_schema(&document, operation_value)?;
        let input_schema = input_schema_for(operation, &parameters, body_schema.as_ref());
        let query_params = parameters
            .iter()
            .filter(|parameter| parameter.location == GeneratedParameterLocation::Query)
            .map(|parameter| QueryParamMapping {
                arg_name: parameter.name.clone(),
                query_name: parameter.name.clone(),
                required: parameter.required,
            })
            .collect();

        definitions.push(ToolDefinition {
            name: tool_name,
            description: description_for(operation, operation_value),
            input_schema,
            upstream: UpstreamMapping {
                method: operation.method.clone(),
                path_template: operation.path_template.clone(),
                query_params,
                body: body_schema.map(|_| BodyMapping {
                    mode: BodyMappingMode::WholeArgsJson,
                }),
            },
        });
    }

    Ok(OpenApiToolGeneration {
        definitions,
        operation_id_fallbacks,
        api_key_header_auth_requirements,
    })
}

pub fn tools_file_value(definitions: &[ToolDefinition]) -> Value {
    json!({
        "schema_version": TOOLS_FILE_SCHEMA_VERSION,
        "tools": definitions,
    })
}

fn parse_document_value(source: &str, contents: &str) -> Result<Value, OpenApiToolGenerationError> {
    let extension = Path::new(source)
        .extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase);

    match extension.as_deref() {
        Some("json") => serde_json::from_str(contents)
            .map_err(|source| OpenApiToolGenerationError::Json { source }),
        Some("yaml" | "yml") => yaml_serde::from_str(contents)
            .map_err(|source| OpenApiToolGenerationError::Yaml { source }),
        _ => serde_json::from_str(contents).or_else(|_| {
            yaml_serde::from_str(contents)
                .map_err(|source| OpenApiToolGenerationError::Yaml { source })
        }),
    }
}

fn operation_value<'a>(document: &'a Value, operation: &OpenApiOperation) -> Option<&'a Value> {
    let pointer = format!(
        "/paths/{}/{}",
        json_pointer_escape(&operation.path_template),
        operation.method.to_ascii_lowercase()
    );
    document.pointer(&pointer)
}

fn operation_path_item<'a>(document: &'a Value, operation: &OpenApiOperation) -> Option<&'a Value> {
    let pointer = format!("/paths/{}", json_pointer_escape(&operation.path_template));
    document.pointer(&pointer)
}

fn description_for(operation: &OpenApiOperation, operation_value: Option<&Value>) -> String {
    operation
        .summary
        .as_deref()
        .map(str::trim)
        .filter(|summary| !summary.is_empty())
        .map(str::to_owned)
        .or_else(|| {
            operation_value
                .and_then(|value| value.get("description"))
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|description| !description.is_empty())
                .map(str::to_owned)
        })
        .unwrap_or_else(|| format!("{} {}", operation.method, operation.path_template))
}

fn tool_name_for(
    operation: &OpenApiOperation,
    used_names: &mut BTreeSet<String>,
) -> (String, Option<OpenApiToolNameFallback>) {
    let operation_id = operation
        .operation_id
        .as_deref()
        .map(str::trim)
        .filter(|operation_id| !operation_id.is_empty());

    let (candidate, reason) = match operation_id {
        Some(operation_id) if is_valid_tool_name(operation_id) => (operation_id.to_owned(), None),
        Some(operation_id) => (
            sanitize_tool_name(operation_id)
                .unwrap_or_else(|| fallback_tool_name(&operation.method, &operation.path_template)),
            Some(OpenApiToolNameFallbackReason::InvalidOperationId),
        ),
        None => (
            fallback_tool_name(&operation.method, &operation.path_template),
            Some(OpenApiToolNameFallbackReason::MissingOperationId),
        ),
    };

    let (name, duplicate_renamed) = unique_tool_name(&candidate, used_names);
    if let Some(reason) = reason {
        return (
            name.clone(),
            Some(OpenApiToolNameFallback {
                method: operation.method.clone(),
                path_template: operation.path_template.clone(),
                original_operation_id: operation_id.map(str::to_owned),
                generated_name: name,
                reason,
            }),
        );
    }

    if duplicate_renamed {
        return (
            name.clone(),
            Some(OpenApiToolNameFallback {
                method: operation.method.clone(),
                path_template: operation.path_template.clone(),
                original_operation_id: operation_id.map(str::to_owned),
                generated_name: name,
                reason: OpenApiToolNameFallbackReason::DuplicateToolName,
            }),
        );
    }

    (name, None)
}

fn is_valid_tool_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TOOL_NAME_LENGTH
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

fn unique_tool_name(candidate: &str, used_names: &mut BTreeSet<String>) -> (String, bool) {
    let base = truncate_tool_name(candidate, MAX_TOOL_NAME_LENGTH);
    if used_names.insert(base.clone()) {
        return (base, false);
    }

    for suffix_number in 2.. {
        let suffix = format!("_{suffix_number}");
        let prefix_limit = MAX_TOOL_NAME_LENGTH.saturating_sub(suffix.len());
        let candidate = format!("{}{}", truncate_tool_name(&base, prefix_limit), suffix);
        if used_names.insert(candidate.clone()) {
            return (candidate, true);
        }
    }

    unreachable!("unbounded suffix search should always find a unique tool name")
}

fn truncate_tool_name(value: &str, max_len: usize) -> String {
    value.chars().take(max_len).collect()
}

fn fallback_tool_name(method: &str, path_template: &str) -> String {
    let mut parts = vec![method.to_ascii_lowercase()];
    let path = path_template.trim_matches('/');
    if path.is_empty() {
        parts.push("root".to_owned());
    }

    for segment in path.split('/').filter(|segment| !segment.is_empty()) {
        if let Some(name) = placeholder_name(segment) {
            parts.push("by".to_owned());
            parts.push(name.to_owned());
        } else {
            parts.push(segment.to_owned());
        }
    }

    sanitize_tool_name(&parts.join("_")).unwrap_or_else(|| "operation".to_owned())
}

fn sanitize_tool_name(value: &str) -> Option<String> {
    let mut sanitized = String::with_capacity(value.len());
    let mut previous_was_separator = false;

    for character in value.chars() {
        if character.is_ascii_alphanumeric() || matches!(character, '_' | '.' | '-') {
            sanitized.push(character);
            previous_was_separator = false;
        } else if !previous_was_separator {
            sanitized.push('_');
            previous_was_separator = true;
        }
    }

    let sanitized = sanitized.trim_matches('_').to_owned();
    if sanitized.is_empty() {
        None
    } else {
        Some(truncate_tool_name(&sanitized, MAX_TOOL_NAME_LENGTH))
    }
}

fn operation_parameters(
    document: &Value,
    operation: &OpenApiOperation,
) -> Result<Vec<GeneratedParameter>, OpenApiToolGenerationError> {
    let mut parameters =
        BTreeMap::<(GeneratedParameterLocation, String), GeneratedParameter>::new();
    let path_item = operation_path_item(document, operation);
    collect_parameters(
        document,
        path_item.and_then(|value| value.get("parameters")),
        &mut parameters,
    )?;
    collect_parameters(
        document,
        operation_value(document, operation).and_then(|value| value.get("parameters")),
        &mut parameters,
    )?;

    for path_parameter_name in path_parameter_names(&operation.path_template) {
        let key = (
            GeneratedParameterLocation::Path,
            path_parameter_name.clone(),
        );
        parameters.entry(key).or_insert_with(|| GeneratedParameter {
            name: path_parameter_name,
            location: GeneratedParameterLocation::Path,
            required: true,
            schema: json!({ "type": "string" }),
        });
    }

    Ok(parameters.into_values().collect())
}

fn collect_parameters(
    document: &Value,
    parameters_value: Option<&Value>,
    parameters: &mut BTreeMap<(GeneratedParameterLocation, String), GeneratedParameter>,
) -> Result<(), OpenApiToolGenerationError> {
    let Some(parameters_value) = parameters_value else {
        return Ok(());
    };
    let Some(parameter_values) = parameters_value.as_array() else {
        return Ok(());
    };

    for parameter_value in parameter_values {
        let parameter_value = resolve_reference(document, parameter_value, &mut BTreeSet::new())?;
        let Some(parameter) = generated_parameter(document, parameter_value)? else {
            continue;
        };
        parameters.insert((parameter.location, parameter.name.clone()), parameter);
    }

    Ok(())
}

fn generated_parameter(
    document: &Value,
    parameter_value: &Value,
) -> Result<Option<GeneratedParameter>, OpenApiToolGenerationError> {
    let Some(object) = parameter_value.as_object() else {
        return Ok(None);
    };
    let Some(name) = object
        .get("name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|name| !name.is_empty())
    else {
        return Ok(None);
    };
    let Some(location) = object
        .get("in")
        .and_then(Value::as_str)
        .and_then(GeneratedParameterLocation::from_str)
    else {
        return Ok(None);
    };

    let schema = match object.get("schema") {
        Some(schema) => dereference_schema(document, schema, &mut BTreeSet::new())?,
        None => json!({}),
    };

    Ok(Some(GeneratedParameter {
        name: name.to_owned(),
        location,
        required: object
            .get("required")
            .and_then(Value::as_bool)
            .unwrap_or(false)
            || location == GeneratedParameterLocation::Path,
        schema,
    }))
}

fn input_schema_for(
    operation: &OpenApiOperation,
    parameters: &[GeneratedParameter],
    body_schema: Option<&Value>,
) -> Value {
    let mut properties = Map::new();
    let mut required = BTreeSet::<String>::new();

    for parameter in parameters {
        properties.insert(parameter.name.clone(), parameter.schema.clone());
        if parameter.required {
            required.insert(parameter.name.clone());
        }
    }

    for path_parameter_name in path_parameter_names(&operation.path_template) {
        properties
            .entry(path_parameter_name.clone())
            .or_insert_with(|| json!({ "type": "string" }));
        required.insert(path_parameter_name);
    }

    if let Some(body_schema) = body_schema {
        merge_body_schema(body_schema, &mut properties, &mut required);
    }

    json!({
        "type": "object",
        "required": required.into_iter().collect::<Vec<_>>(),
        "properties": properties,
        "additionalProperties": false,
    })
}

fn merge_body_schema(
    schema: &Value,
    properties: &mut Map<String, Value>,
    required: &mut BTreeSet<String>,
) {
    if let Some(all_of) = schema
        .as_object()
        .and_then(|object| object.get("allOf"))
        .and_then(Value::as_array)
    {
        for schema in all_of {
            merge_body_schema(schema, properties, required);
        }
    }

    let Some(object) = schema.as_object() else {
        return;
    };

    if let Some(schema_properties) = object.get("properties").and_then(Value::as_object) {
        for (name, schema) in schema_properties {
            let name = name.trim();
            if !name.is_empty() {
                properties
                    .entry(name.to_owned())
                    .or_insert_with(|| schema.clone());
            }
        }
    }

    if let Some(required_values) = object.get("required").and_then(Value::as_array) {
        for name in required_values
            .iter()
            .filter_map(Value::as_str)
            .map(str::trim)
            .filter(|name| !name.is_empty())
        {
            required.insert(name.to_owned());
        }
    }
}

fn json_request_body_schema(
    document: &Value,
    operation_value: Option<&Value>,
) -> Result<Option<Value>, OpenApiToolGenerationError> {
    let Some(request_body) = operation_value.and_then(|value| value.get("requestBody")) else {
        return Ok(None);
    };
    let request_body = resolve_reference(document, request_body, &mut BTreeSet::new())?;
    let Some(content) = request_body.get("content").and_then(Value::as_object) else {
        return Ok(None);
    };
    let Some(media_type) = content
        .iter()
        .find(|(media_type, _)| is_json_media_type(media_type))
        .map(|(_, media_type)| media_type)
    else {
        return Ok(None);
    };
    let Some(schema) = media_type.get("schema") else {
        return Ok(None);
    };

    Ok(Some(dereference_schema(
        document,
        schema,
        &mut BTreeSet::new(),
    )?))
}

fn dereference_schema(
    document: &Value,
    schema: &Value,
    seen_references: &mut BTreeSet<String>,
) -> Result<Value, OpenApiToolGenerationError> {
    if schema.get("$ref").and_then(Value::as_str).is_some() {
        let resolved = resolve_reference(document, schema, seen_references)?;
        return dereference_schema(document, resolved, seen_references);
    }

    match schema {
        Value::Array(values) => values
            .iter()
            .map(|value| {
                let mut branch_references = seen_references.clone();
                dereference_schema(document, value, &mut branch_references)
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        Value::Object(object) => {
            let mut dereferenced = Map::new();
            for (key, value) in object {
                let mut branch_references = seen_references.clone();
                dereferenced.insert(
                    key.clone(),
                    dereference_schema(document, value, &mut branch_references)?,
                );
            }
            Ok(Value::Object(dereferenced))
        }
        _ => Ok(schema.clone()),
    }
}

fn resolve_reference<'a>(
    document: &'a Value,
    value: &'a Value,
    seen_references: &mut BTreeSet<String>,
) -> Result<&'a Value, OpenApiToolGenerationError> {
    let Some(reference) = value.get("$ref").and_then(Value::as_str) else {
        return Ok(value);
    };

    if !seen_references.insert(reference.to_owned()) {
        return Err(OpenApiToolGenerationError::Reference {
            reference: reference.to_owned(),
            message: "circular local reference".to_owned(),
        });
    }
    let Some(pointer) = reference.strip_prefix('#') else {
        return Err(OpenApiToolGenerationError::Reference {
            reference: reference.to_owned(),
            message: "only local OpenAPI references are supported".to_owned(),
        });
    };
    let Some(resolved) = document.pointer(pointer) else {
        return Err(OpenApiToolGenerationError::Reference {
            reference: reference.to_owned(),
            message: "target does not exist".to_owned(),
        });
    };

    resolve_reference(document, resolved, seen_references)
}

fn api_key_header_requirements(
    document: &Value,
    operation: &OpenApiOperation,
    operation_value: Option<&Value>,
    tool_name: &str,
) -> Result<Vec<OpenApiApiKeyHeaderAuthRequirement>, OpenApiToolGenerationError> {
    let security = operation_value
        .and_then(|value| value.get("security"))
        .or_else(|| document.get("security"));
    let Some(security_requirements) = security.and_then(Value::as_array) else {
        return Ok(Vec::new());
    };

    let mut requirements = BTreeMap::<(String, String), OpenApiApiKeyHeaderAuthRequirement>::new();
    for requirement in security_requirements {
        let Some(requirement) = requirement.as_object() else {
            continue;
        };
        for scheme_name in requirement.keys() {
            if let Some(header_name) = api_key_header_name(document, scheme_name)? {
                requirements.insert(
                    (scheme_name.clone(), header_name.clone()),
                    OpenApiApiKeyHeaderAuthRequirement {
                        tool_name: tool_name.to_owned(),
                        method: operation.method.clone(),
                        path_template: operation.path_template.clone(),
                        scheme_name: scheme_name.clone(),
                        header_name,
                    },
                );
            }
        }
    }

    Ok(requirements.into_values().collect())
}

fn api_key_header_name(
    document: &Value,
    scheme_name: &str,
) -> Result<Option<String>, OpenApiToolGenerationError> {
    let pointer = format!(
        "/components/securitySchemes/{}",
        json_pointer_escape(scheme_name)
    );
    let Some(scheme) = document.pointer(&pointer) else {
        return Ok(None);
    };
    let scheme = resolve_reference(document, scheme, &mut BTreeSet::new())?;
    let Some(object) = scheme.as_object() else {
        return Ok(None);
    };

    let is_api_key = object
        .get("type")
        .and_then(Value::as_str)
        .is_some_and(|value| value.eq_ignore_ascii_case("apiKey"));
    let is_header = object
        .get("in")
        .and_then(Value::as_str)
        .is_some_and(|value| value.eq_ignore_ascii_case("header"));
    let header_name = object
        .get("name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());

    Ok(if is_api_key && is_header {
        header_name.map(str::to_owned)
    } else {
        None
    })
}

fn path_parameter_names(path_template: &str) -> Vec<String> {
    let mut names = BTreeSet::new();
    let mut rest = path_template;

    while let Some(open) = rest.find('{') {
        let after_open = &rest[open + 1..];
        let Some(close) = after_open.find('}') else {
            break;
        };
        let name = after_open[..close].trim();
        if !name.is_empty() {
            names.insert(name.to_owned());
        }
        rest = &after_open[close + 1..];
    }

    names.into_iter().collect()
}

fn placeholder_name(segment: &str) -> Option<&str> {
    segment
        .strip_prefix('{')
        .and_then(|segment| segment.strip_suffix('}'))
        .map(str::trim)
        .filter(|name| !name.is_empty())
}

fn is_json_media_type(media_type: &str) -> bool {
    let media_type = media_type
        .split(';')
        .next()
        .map(str::trim)
        .unwrap_or_default();
    if media_type.eq_ignore_ascii_case("application/json") {
        return true;
    }

    let Some((_, subtype)) = media_type.split_once('/') else {
        return false;
    };
    subtype.to_ascii_lowercase().ends_with("+json")
}

fn json_pointer_escape(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::tools::definitions::{BodyMappingMode, ToolRegistry};

    #[test]
    fn generates_valid_tools_from_realistic_multi_operation_spec() {
        let generation = generate_tools_from_openapi_str("test.yaml", realistic_spec())
            .expect("OpenAPI spec should generate tools");

        assert_eq!(generation.definitions.len(), 3);
        ToolRegistry::from_json_value(generation.tools_file_value())
            .expect("generated tools file should pass schema and semantic validation");

        let get_widget = generation
            .definitions
            .iter()
            .find(|definition| definition.name == "getWidget")
            .expect("getWidget should be generated");
        assert_eq!(get_widget.description, "Fetch a widget");
        assert_eq!(get_widget.upstream.method, "GET");
        assert_eq!(get_widget.upstream.path_template, "/widgets/{widgetId}");
        assert_eq!(get_widget.upstream.query_params.len(), 2);

        let create_widget = generation
            .definitions
            .iter()
            .find(|definition| definition.name == "createWidget")
            .expect("createWidget should be generated");
        assert_eq!(create_widget.upstream.method, "POST");
        assert_eq!(create_widget.upstream.path_template, "/widgets");
        assert_eq!(
            create_widget.upstream.body.as_ref().map(|body| body.mode),
            Some(BodyMappingMode::WholeArgsJson)
        );
        assert_eq!(
            create_widget.input_schema["properties"]["name"],
            json!({ "type": "string" })
        );
        assert_eq!(
            create_widget.input_schema["properties"]["quantity"],
            json!({ "type": "integer", "minimum": 1 })
        );
    }

    #[test]
    fn preserves_parameter_schema_types() {
        let generation = generate_tools_from_openapi_str("test.yaml", realistic_spec())
            .expect("OpenAPI spec should generate tools");
        let get_widget = generation
            .definitions
            .iter()
            .find(|definition| definition.name == "getWidget")
            .expect("getWidget should be generated");

        assert_eq!(
            get_widget.input_schema["properties"]["page"],
            json!({ "type": "integer", "minimum": 1 })
        );
    }

    #[test]
    fn declares_path_placeholders_in_input_schema_properties() {
        let generation = generate_tools_from_openapi_str("test.yaml", realistic_spec())
            .expect("OpenAPI spec should generate tools");
        let get_widget = generation
            .definitions
            .iter()
            .find(|definition| definition.name == "getWidget")
            .expect("getWidget should be generated");

        assert_eq!(get_widget.upstream.path_template, "/widgets/{widgetId}");
        assert_eq!(
            get_widget.input_schema["properties"]["widgetId"],
            json!({ "type": "string" })
        );
        assert!(
            get_widget.input_schema["required"]
                .as_array()
                .expect("required should be an array")
                .iter()
                .any(|value| value == "widgetId"),
            "path placeholder should be required by generated input schema"
        );
    }

    #[test]
    fn falls_back_when_operation_id_is_missing() {
        let generation = generate_tools_from_openapi_str(
            "fallback.yaml",
            r#"
openapi: 3.0.3
info:
  title: Fallback API
  version: 1.0.0
paths:
  /reports/{reportId}/summary:
    get:
      summary: Read report summary
      parameters:
        - in: path
          name: reportId
          required: true
          schema:
            type: string
"#,
        )
        .expect("OpenAPI spec should generate tools");

        assert_eq!(
            generation.definitions[0].name,
            "get_reports_by_reportId_summary"
        );
        assert_eq!(
            generation.operation_id_fallbacks,
            vec![OpenApiToolNameFallback {
                method: "GET".to_owned(),
                path_template: "/reports/{reportId}/summary".to_owned(),
                original_operation_id: None,
                generated_name: "get_reports_by_reportId_summary".to_owned(),
                reason: OpenApiToolNameFallbackReason::MissingOperationId,
            }]
        );
    }

    #[test]
    fn reports_api_key_header_security_requirements() {
        let generation = generate_tools_from_openapi_str("test.yaml", realistic_spec())
            .expect("OpenAPI spec should generate tools");

        assert_eq!(
            generation.api_key_header_auth_requirements,
            vec![OpenApiApiKeyHeaderAuthRequirement {
                tool_name: "getWidget".to_owned(),
                method: "GET".to_owned(),
                path_template: "/widgets/{widgetId}".to_owned(),
                scheme_name: "ApiKeyAuth".to_owned(),
                header_name: "X-API-Key".to_owned(),
            }]
        );
    }

    fn realistic_spec() -> &'static str {
        r#"
openapi: 3.0.3
info:
  title: Widget API
  version: 1.0.0
components:
  securitySchemes:
    ApiKeyAuth:
      type: apiKey
      in: header
      name: X-API-Key
  parameters:
    WidgetId:
      in: path
      name: widgetId
      required: true
      schema:
        type: string
  schemas:
    WidgetCreate:
      type: object
      required: [name]
      properties:
        name:
          type: string
        quantity:
          type: integer
          minimum: 1
paths:
  /widgets/{widgetId}:
    parameters:
      - $ref: '#/components/parameters/WidgetId'
    get:
      operationId: getWidget
      summary: Fetch a widget
      security:
        - ApiKeyAuth: []
      parameters:
        - in: query
          name: includeDetails
          required: false
          schema:
            type: boolean
        - in: query
          name: page
          required: true
          schema:
            type: integer
            minimum: 1
    delete:
      operationId: deleteWidget
      description: Deletes a widget when it is no longer needed.
  /widgets:
    post:
      operationId: createWidget
      summary: Create a widget
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/WidgetCreate'
"#
    }
}
