#![allow(dead_code)] // PR2 will wire this generator into an admin review workflow.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt, fs, io,
    path::{Path, PathBuf},
};

use http::HeaderName;
use serde_json::{json, Map, Value};
use url::Url;

use crate::{
    connections::model::{
        normalize_origin_relative_path, ConnectionAuthentication, ConnectionId,
        MAX_CATALOG_ENTRIES, MAX_MANAGED_OPENAPI_CATALOG_BYTES,
    },
    discovery::openapi::{OpenApiOperation, OpenApiSpec, OpenApiSpecError},
    tools::definitions::{
        BodyMapping, BodyMappingMode, QueryParamMapping, ToolDefinition, ToolSource, ToolTarget,
        ToolVisibility, UpstreamMapping,
    },
};

const TOOLS_FILE_SCHEMA_VERSION: &str = "0.1.0";
const MAX_TOOL_NAME_LENGTH: usize = 128;
const MAX_OPENAPI_REFERENCE_DEPTH: usize = 64;
const MAX_OPENAPI_SCHEMA_EXPANSION_NODES: usize = 65_536;
/// Total recursive descent allowed while expanding a single schema, counting
/// both structural nesting and resolved references. The parser bounds how deep
/// one document may nest, but reference expansion splices independent subtrees
/// together, so the expanded depth needs a bound of its own to keep
/// `dereference_schema` off the end of the worker stack.
const MAX_OPENAPI_SCHEMA_EXPANSION_DEPTH: usize = 256;
const MAX_OPENAPI_SECURITY_SIZE_CACHE_ENTRIES: usize = MAX_CATALOG_ENTRIES * 2;

#[derive(Debug, Clone, PartialEq)]
pub struct OpenApiToolGeneration {
    pub definitions: Vec<ToolDefinition>,
    pub operation_id_fallbacks: Vec<OpenApiToolNameFallback>,
    pub skipped_operations: Vec<OpenApiSkippedOperation>,
    pub api_key_header_auth_requirements: Vec<OpenApiApiKeyHeaderAuthRequirement>,
    pub security_requirements: Vec<OpenApiOperationSecurity>,
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
pub struct OpenApiSkippedOperation {
    pub method: String,
    pub path_template: String,
    pub original_operation_id: Option<String>,
    pub reason: OpenApiSkippedOperationReason,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenApiSkippedOperationReason {
    BodyPropertyParameterNameCollision { property_name: String },
    UnsafeTraceMethod,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenApiApiKeyHeaderAuthRequirement {
    pub tool_name: String,
    pub method: String,
    pub path_template: String,
    pub scheme_name: String,
    pub header_name: String,
}

/// The OpenAPI security requirements for one generated operation.
///
/// `alternatives` preserves OpenAPI's outer OR semantics, while each
/// alternative preserves the inner AND semantics of a Security Requirement
/// Object. An empty or absent OpenAPI security requirement is represented by
/// one [`OpenApiSecuritySchemeRequirement::Anonymous`] alternative.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenApiOperationSecurity {
    pub tool_name: String,
    pub method: String,
    pub path_template: String,
    pub operation_id: Option<String>,
    pub alternatives: Vec<OpenApiSecurityAlternative>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenApiSecurityAlternative {
    pub members: Vec<OpenApiSecuritySchemeRequirement>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenApiSecuritySchemeRequirement {
    Anonymous,
    HeaderApiKey {
        scheme_name: String,
        header_name: String,
    },
    HttpBearer {
        scheme_name: String,
    },
    OAuth2ClientCredentials {
        scheme_name: String,
        token_url: String,
        required_scopes: Vec<String>,
    },
    Unsupported {
        scheme_name: String,
        category: OpenApiUnsupportedSecurityScheme,
    },
}

impl OpenApiSecuritySchemeRequirement {
    pub fn scheme_name(&self) -> Option<&str> {
        match self {
            Self::Anonymous => None,
            Self::HeaderApiKey { scheme_name, .. }
            | Self::HttpBearer { scheme_name }
            | Self::OAuth2ClientCredentials { scheme_name, .. }
            | Self::Unsupported { scheme_name, .. } => Some(scheme_name),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum OpenApiUnsupportedSecurityScheme {
    MissingDefinition,
    InvalidDefinition,
    ApiKeyQuery,
    ApiKeyCookie,
    ApiKeyUnsupportedLocation,
    HttpBasic,
    HttpUnsupportedScheme,
    OAuth2WithoutClientCredentials,
    OpenIdConnect,
    MutualTls,
    UnsupportedType,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpenApiToolBinding {
    pub definitions: Vec<ToolDefinition>,
    pub security_selections: Vec<OpenApiToolSecuritySelection>,
    pub incompatibilities: Vec<OpenApiToolIncompatibility>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenApiToolSecuritySelection {
    pub tool_name: String,
    pub selected_scheme_names: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenApiToolIncompatibility {
    pub tool_name: String,
    pub reason: OpenApiToolIncompatibilityReason,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenApiToolIncompatibilityReason {
    MissingSecurityMetadata,
    NoCompatibleSecurityAlternative,
    InvalidMappingPath {
        path_template: String,
        message: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenApiToolBindingError {
    MissingSecurityMetadata {
        tool_name: String,
    },
    DuplicateSecurityConfirmation {
        tool_name: String,
    },
    UnexpectedSecurityConfirmation {
        tool_name: String,
    },
    InvalidSecurityConfirmation {
        tool_name: String,
        selected_scheme_names: Vec<String>,
    },
    InvalidMappingPath {
        tool_name: String,
        path_template: String,
        message: String,
    },
}

#[derive(Debug)]
pub enum OpenApiToolGenerationError {
    Io {
        path: PathBuf,
        source: io::Error,
    },
    Spec {
        source: OpenApiSpecError,
    },
    Json {
        source: serde_json::Error,
    },
    Yaml {
        source: yaml_serde::Error,
    },
    Reference {
        reference: String,
        message: String,
    },
    GenerationLimit {
        limit: OpenApiToolGenerationLimit,
        maximum: usize,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenApiToolGenerationLimit {
    OperationCount,
    DefinitionCount,
    CumulativeDefinitionBytes,
    SchemaExpansionNodes,
    SchemaExpansionBytes,
    SchemaExpansionDepth,
    SecurityMetadataBytes,
    SecurityMetadataCacheEntries,
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

struct OpenApiSchemaExpansionBudget {
    remaining_nodes: usize,
    remaining_bytes: usize,
}

/// Depth accounting for one root-to-leaf path through `dereference_schema`.
///
/// `references` is the documented `$ref` chain length, and it has to survive
/// descent into `properties`/`items`/any other wrapper: a real chain reaches its
/// next `$ref` through an intervening object, so resetting the count per level
/// leaves `MAX_OPENAPI_REFERENCE_DEPTH` bounding only bare alias chains.
/// `nesting` counts every frame, which is what bounds stack use once reference
/// expansion has spliced several documents' worth of nesting onto one path.
#[derive(Clone, Copy, Debug, Default)]
struct SchemaExpansionDepth {
    references: usize,
    nesting: usize,
}

impl SchemaExpansionDepth {
    fn child(self) -> Result<Self, OpenApiToolGenerationError> {
        let nesting = self.nesting.saturating_add(1);
        if nesting > MAX_OPENAPI_SCHEMA_EXPANSION_DEPTH {
            return Err(OpenApiToolGenerationError::GenerationLimit {
                limit: OpenApiToolGenerationLimit::SchemaExpansionDepth,
                maximum: MAX_OPENAPI_SCHEMA_EXPANSION_DEPTH,
            });
        }
        Ok(Self { nesting, ..self })
    }

    fn resolved_reference(self) -> Result<Self, OpenApiToolGenerationError> {
        let child = self.child()?;
        Ok(Self {
            references: child.references.saturating_add(1),
            ..child
        })
    }
}

struct OpenApiSecurityMetadataBudget {
    remaining_bytes: usize,
    value_sizes: BTreeMap<usize, usize>,
    scheme_entry_sizes: BTreeMap<usize, usize>,
}

impl OpenApiSecurityMetadataBudget {
    fn new() -> Self {
        Self {
            remaining_bytes: MAX_MANAGED_OPENAPI_CATALOG_BYTES,
            value_sizes: BTreeMap::new(),
            scheme_entry_sizes: BTreeMap::new(),
        }
    }

    fn consume(&mut self, bytes: usize) -> Result<(), OpenApiToolGenerationError> {
        if bytes > self.remaining_bytes {
            return Err(OpenApiToolGenerationError::GenerationLimit {
                limit: OpenApiToolGenerationLimit::SecurityMetadataBytes,
                maximum: MAX_MANAGED_OPENAPI_CATALOG_BYTES,
            });
        }
        self.remaining_bytes -= bytes;
        Ok(())
    }

    fn consume_retained_bytes(&mut self, bytes: usize) -> Result<(), OpenApiToolGenerationError> {
        // The compatibility report and typed security model retain overlapping
        // operation/scheme strings, so charge both representations.
        self.consume(bytes.saturating_mul(2))
    }

    fn charge_value(&mut self, value: &Value) -> Result<usize, OpenApiToolGenerationError> {
        let identity = value_identity(value);
        if let Some(bytes) = self.value_sizes.get(&identity).copied() {
            self.consume_retained_bytes(bytes)?;
            return Ok(bytes);
        }
        if self.value_sizes.len() >= MAX_OPENAPI_SECURITY_SIZE_CACHE_ENTRIES {
            return Err(OpenApiToolGenerationError::GenerationLimit {
                limit: OpenApiToolGenerationLimit::SecurityMetadataCacheEntries,
                maximum: MAX_OPENAPI_SECURITY_SIZE_CACHE_ENTRIES,
            });
        }

        let bytes = self.measure_and_charge_value(value)?;
        self.value_sizes.insert(identity, bytes);
        Ok(bytes)
    }

    fn charge_scheme_entry(
        &mut self,
        document: &Value,
        scheme_entry: &Value,
    ) -> Result<(), OpenApiToolGenerationError> {
        let mut current = scheme_entry;
        let mut uncached_references = Vec::<(usize, usize)>::new();
        let mut seen_references = BTreeSet::new();
        let mut depth = 0usize;

        loop {
            let identity = value_identity(current);
            if let Some(mut suffix_bytes) = self.scheme_entry_sizes.get(&identity).copied() {
                self.consume_retained_bytes(suffix_bytes)?;
                for (identity, reference_bytes) in uncached_references.into_iter().rev() {
                    suffix_bytes = suffix_bytes.saturating_add(reference_bytes);
                    self.scheme_entry_sizes.insert(identity, suffix_bytes);
                }
                return Ok(());
            }
            if self
                .scheme_entry_sizes
                .len()
                .saturating_add(uncached_references.len())
                >= MAX_OPENAPI_SECURITY_SIZE_CACHE_ENTRIES
            {
                return Err(OpenApiToolGenerationError::GenerationLimit {
                    limit: OpenApiToolGenerationLimit::SecurityMetadataCacheEntries,
                    maximum: MAX_OPENAPI_SECURITY_SIZE_CACHE_ENTRIES,
                });
            }

            let Some(reference) = current.get("$ref").and_then(Value::as_str) else {
                let mut suffix_bytes = self.charge_value(current)?;
                self.scheme_entry_sizes.insert(identity, suffix_bytes);
                for (identity, reference_bytes) in uncached_references.into_iter().rev() {
                    suffix_bytes = suffix_bytes.saturating_add(reference_bytes);
                    self.scheme_entry_sizes.insert(identity, suffix_bytes);
                }
                return Ok(());
            };
            let reference_bytes = self.charge_value(current)?;
            uncached_references.push((identity, reference_bytes));
            if depth >= MAX_OPENAPI_REFERENCE_DEPTH {
                return Err(OpenApiToolGenerationError::Reference {
                    reference: reference.to_owned(),
                    message: format!("reference depth exceeds {MAX_OPENAPI_REFERENCE_DEPTH}"),
                });
            }
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
            current = resolved;
            depth += 1;
        }
    }

    fn measure_and_charge_value(
        &mut self,
        value: &Value,
    ) -> Result<usize, OpenApiToolGenerationError> {
        let mut total = 0usize;
        let mut remaining = vec![value];
        while let Some(value) = remaining.pop() {
            let bytes = match value {
                Value::Null => 4,
                Value::Bool(value) => {
                    if *value {
                        4
                    } else {
                        5
                    }
                }
                Value::Number(number) => number.to_string().len(),
                Value::String(value) => json_string_bytes(value),
                Value::Array(values) => {
                    let bytes = 2usize.saturating_add(values.len().saturating_sub(1));
                    self.consume_retained_bytes(bytes)?;
                    total = total.saturating_add(bytes);
                    remaining.extend(values);
                    continue;
                }
                Value::Object(object) => {
                    let shell = 2usize.saturating_add(object.len().saturating_sub(1));
                    self.consume_retained_bytes(shell)?;
                    total = total.saturating_add(shell);
                    for (key, value) in object {
                        let key_bytes = json_string_bytes(key).saturating_add(1);
                        self.consume_retained_bytes(key_bytes)?;
                        total = total.saturating_add(key_bytes);
                        remaining.push(value);
                    }
                    continue;
                }
            };
            self.consume_retained_bytes(bytes)?;
            total = total.saturating_add(bytes);
        }
        Ok(total)
    }
}

fn value_identity(value: &Value) -> usize {
    std::ptr::from_ref(value) as usize
}

impl OpenApiSchemaExpansionBudget {
    fn new() -> Self {
        Self {
            remaining_nodes: MAX_OPENAPI_SCHEMA_EXPANSION_NODES,
            remaining_bytes: MAX_MANAGED_OPENAPI_CATALOG_BYTES,
        }
    }

    fn consume_node(&mut self, value: &Value) -> Result<(), OpenApiToolGenerationError> {
        let bytes = match value {
            Value::Null => 4,
            Value::Bool(value) => {
                if *value {
                    4
                } else {
                    5
                }
            }
            Value::Number(number) => number.to_string().len(),
            Value::String(value) => json_string_bytes(value),
            Value::Array(values) => 2usize.saturating_add(values.len().saturating_sub(1)),
            Value::Object(object) => object.iter().fold(
                2usize.saturating_add(object.len().saturating_sub(1)),
                |bytes, (key, _)| {
                    bytes
                        .saturating_add(json_string_bytes(key))
                        .saturating_add(1)
                },
            ),
        };
        self.consume(1, bytes)
    }

    fn consume_reference(&mut self, reference: &str) -> Result<(), OpenApiToolGenerationError> {
        self.consume(1, json_string_bytes(reference))
    }

    fn consume(&mut self, nodes: usize, bytes: usize) -> Result<(), OpenApiToolGenerationError> {
        if nodes > self.remaining_nodes {
            return Err(OpenApiToolGenerationError::GenerationLimit {
                limit: OpenApiToolGenerationLimit::SchemaExpansionNodes,
                maximum: MAX_OPENAPI_SCHEMA_EXPANSION_NODES,
            });
        }
        if bytes > self.remaining_bytes {
            return Err(OpenApiToolGenerationError::GenerationLimit {
                limit: OpenApiToolGenerationLimit::SchemaExpansionBytes,
                maximum: MAX_MANAGED_OPENAPI_CATALOG_BYTES,
            });
        }
        self.remaining_nodes -= nodes;
        self.remaining_bytes -= bytes;
        Ok(())
    }
}

fn json_string_bytes(value: &str) -> usize {
    value.chars().fold(2usize, |bytes, character| {
        bytes.saturating_add(match character {
            '"' | '\\' | '\u{0008}' | '\u{000c}' | '\n' | '\r' | '\t' => 2,
            '\u{0000}'..='\u{001f}' => 6,
            _ => character.len_utf8(),
        })
    })
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
            Self::GenerationLimit { limit, maximum } => match limit {
                OpenApiToolGenerationLimit::OperationCount => write!(
                    formatter,
                    "OpenAPI operation count exceeds the maximum of {maximum}"
                ),
                OpenApiToolGenerationLimit::DefinitionCount => write!(
                    formatter,
                    "generated OpenAPI tool definition count exceeds the maximum of {maximum}"
                ),
                OpenApiToolGenerationLimit::CumulativeDefinitionBytes => write!(
                    formatter,
                    "generated OpenAPI tool definitions exceed the cumulative byte maximum of {maximum}"
                ),
                OpenApiToolGenerationLimit::SchemaExpansionNodes => write!(
                    formatter,
                    "expanded OpenAPI schemas exceed the node maximum of {maximum}"
                ),
                OpenApiToolGenerationLimit::SchemaExpansionBytes => write!(
                    formatter,
                    "expanded OpenAPI schemas exceed the cumulative byte maximum of {maximum}"
                ),
                OpenApiToolGenerationLimit::SchemaExpansionDepth => write!(
                    formatter,
                    "expanded OpenAPI schemas exceed the nesting depth maximum of {maximum}"
                ),
                OpenApiToolGenerationLimit::SecurityMetadataBytes => write!(
                    formatter,
                    "generated OpenAPI security metadata exceeds the cumulative byte maximum of {maximum}"
                ),
                OpenApiToolGenerationLimit::SecurityMetadataCacheEntries => write!(
                    formatter,
                    "OpenAPI security metadata size cache exceeds the entry maximum of {maximum}"
                ),
            },
        }
    }
}

impl fmt::Display for OpenApiToolBindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSecurityMetadata { tool_name } => {
                write!(
                    formatter,
                    "generated OpenAPI tool '{tool_name}' is missing security metadata"
                )
            }
            Self::DuplicateSecurityConfirmation { tool_name } => {
                write!(
                    formatter,
                    "generated OpenAPI tool '{tool_name}' has duplicate security confirmations"
                )
            }
            Self::UnexpectedSecurityConfirmation { tool_name } => {
                write!(
                    formatter,
                    "security confirmation names unknown generated OpenAPI tool '{tool_name}'"
                )
            }
            Self::InvalidSecurityConfirmation {
                tool_name,
                selected_scheme_names,
            } => write!(
                formatter,
                "security confirmation {:?} does not identify one complete compatible OpenAPI security alternative for tool '{tool_name}'",
                selected_scheme_names
            ),
            Self::InvalidMappingPath {
                tool_name,
                path_template,
                message,
            } => write!(
                formatter,
                "generated OpenAPI tool '{tool_name}' has unsafe path template '{path_template}': {message}"
            ),
        }
    }
}

impl Error for OpenApiToolBindingError {}

impl Error for OpenApiToolGenerationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Spec { source } => Some(source),
            Self::Json { source } => Some(source),
            Self::Yaml { source } => Some(source),
            Self::Reference { .. } => None,
            Self::GenerationLimit { .. } => None,
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
    if parsed_spec.operations.len() > MAX_CATALOG_ENTRIES {
        return Err(OpenApiToolGenerationError::GenerationLimit {
            limit: OpenApiToolGenerationLimit::OperationCount,
            maximum: MAX_CATALOG_ENTRIES,
        });
    }
    let document = parse_document_value(source, contents)?;
    reject_non_local_references(&document)?;

    let mut definitions = Vec::new();
    let mut operation_id_fallbacks = Vec::new();
    let mut skipped_operations = Vec::new();
    let mut api_key_header_auth_requirements = Vec::new();
    let mut security_requirements = Vec::new();
    let mut used_names = BTreeSet::new();
    let mut cumulative_definition_bytes = 0usize;
    let mut schema_expansion_budget = OpenApiSchemaExpansionBudget::new();
    let mut security_metadata_budget = OpenApiSecurityMetadataBudget::new();

    for operation in &parsed_spec.operations {
        if operation.method.eq_ignore_ascii_case("TRACE") {
            skipped_operations.push(OpenApiSkippedOperation {
                method: operation.method.clone(),
                path_template: operation.path_template.clone(),
                original_operation_id: operation.operation_id.clone(),
                reason: OpenApiSkippedOperationReason::UnsafeTraceMethod,
            });
            continue;
        }
        let operation_value = operation_value(&document, operation);
        let parameters = operation_parameters(&document, operation, &mut schema_expansion_budget)?;
        let body_schema =
            json_request_body_schema(&document, operation_value, &mut schema_expansion_budget)?;
        let input_schema = match input_schema_for(operation, &parameters, body_schema.as_ref()) {
            Ok(input_schema) => input_schema,
            Err(reason) => {
                skipped_operations.push(OpenApiSkippedOperation {
                    method: operation.method.clone(),
                    path_template: operation.path_template.clone(),
                    original_operation_id: operation.operation_id.clone(),
                    reason,
                });
                continue;
            }
        };

        let (tool_name, fallback) = tool_name_for(operation, &mut used_names);
        if let Some(fallback) = fallback {
            operation_id_fallbacks.push(fallback);
        }

        consume_operation_security_metadata_budget(
            &document,
            operation,
            operation_value,
            &tool_name,
            &mut security_metadata_budget,
        )?;
        api_key_header_auth_requirements.extend(api_key_header_requirements(
            &document,
            operation,
            operation_value,
            &tool_name,
        )?);
        security_requirements.push(operation_security_requirements(
            &document,
            operation,
            operation_value,
            &tool_name,
        )?);

        let query_params = parameters
            .iter()
            .filter(|parameter| parameter.location == GeneratedParameterLocation::Query)
            .map(|parameter| QueryParamMapping {
                arg_name: parameter.name.clone(),
                query_name: parameter.name.clone(),
                required: parameter.required,
            })
            .collect();

        if definitions.len() >= MAX_CATALOG_ENTRIES {
            return Err(OpenApiToolGenerationError::GenerationLimit {
                limit: OpenApiToolGenerationLimit::DefinitionCount,
                maximum: MAX_CATALOG_ENTRIES,
            });
        }
        let definition = ToolDefinition {
            name: tool_name,
            description: description_for(operation, operation_value),
            input_schema,
            target: None,
            source: ToolSource::Legacy,
            upstream: UpstreamMapping {
                method: operation.method.clone(),
                path_template: operation.path_template.clone(),
                query_params,
                body: body_schema.map(|_| BodyMapping {
                    mode: BodyMappingMode::WholeArgsJson,
                }),
            },
            visibility: ToolVisibility::Listed,
        };
        let definition_bytes = serde_json::to_vec(&definition)
            .map_err(|source| OpenApiToolGenerationError::Json { source })?
            .len();
        cumulative_definition_bytes = cumulative_definition_bytes
            .checked_add(definition_bytes)
            .ok_or(OpenApiToolGenerationError::GenerationLimit {
                limit: OpenApiToolGenerationLimit::CumulativeDefinitionBytes,
                maximum: MAX_MANAGED_OPENAPI_CATALOG_BYTES,
            })?;
        if cumulative_definition_bytes > MAX_MANAGED_OPENAPI_CATALOG_BYTES {
            return Err(OpenApiToolGenerationError::GenerationLimit {
                limit: OpenApiToolGenerationLimit::CumulativeDefinitionBytes,
                maximum: MAX_MANAGED_OPENAPI_CATALOG_BYTES,
            });
        }
        definitions.push(definition);
    }

    Ok(OpenApiToolGeneration {
        definitions,
        operation_id_fallbacks,
        skipped_operations,
        api_key_header_auth_requirements,
        security_requirements,
    })
}

pub fn tools_file_value(definitions: &[ToolDefinition]) -> Value {
    json!({
        "schema_version": TOOLS_FILE_SCHEMA_VERSION,
        "tools": definitions,
    })
}

/// Produces typed Connection-backed OpenAPI tools for compatible operations,
/// suggests the first complete security alternative for each, and reports
/// safe per-tool incompatibility reasons for the rest.
///
/// This is suitable for preview/review. Persisted registration and refresh
/// should use [`bind_generated_openapi_tools_with_confirmations`] so a change
/// in OR-branch order cannot silently select different authentication.
pub fn bind_generated_openapi_tools(
    generation: &OpenApiToolGeneration,
    connection_id: &ConnectionId,
    authentication: &ConnectionAuthentication,
) -> Result<OpenApiToolBinding, OpenApiToolBindingError> {
    bind_generated_openapi_tools_internal(generation, connection_id, authentication, None)
}

/// Produces typed Connection-backed OpenAPI tools for the confirmed subset only
/// when every supplied confirmation names one whole compatible OpenAPI
/// security alternative.
///
/// Scheme names are compared as an exact sorted set. Anonymous operations must
/// be confirmed with an empty `selected_scheme_names` list.
pub fn bind_generated_openapi_tools_with_confirmations(
    generation: &OpenApiToolGeneration,
    connection_id: &ConnectionId,
    authentication: &ConnectionAuthentication,
    confirmations: &[OpenApiToolSecuritySelection],
) -> Result<OpenApiToolBinding, OpenApiToolBindingError> {
    let mut by_tool_name = BTreeMap::<String, Vec<String>>::new();
    for confirmation in confirmations {
        let mut selected_scheme_names = confirmation.selected_scheme_names.clone();
        selected_scheme_names.sort();
        if by_tool_name
            .insert(confirmation.tool_name.clone(), selected_scheme_names)
            .is_some()
        {
            return Err(OpenApiToolBindingError::DuplicateSecurityConfirmation {
                tool_name: confirmation.tool_name.clone(),
            });
        }
    }

    let known_tool_names = generation
        .definitions
        .iter()
        .map(|definition| definition.name.as_str())
        .collect::<BTreeSet<_>>();
    if let Some(unexpected) = by_tool_name
        .keys()
        .find(|tool_name| !known_tool_names.contains(tool_name.as_str()))
    {
        return Err(OpenApiToolBindingError::UnexpectedSecurityConfirmation {
            tool_name: unexpected.clone(),
        });
    }

    bind_generated_openapi_tools_internal(
        generation,
        connection_id,
        authentication,
        Some(&by_tool_name),
    )
}

fn bind_generated_openapi_tools_internal(
    generation: &OpenApiToolGeneration,
    connection_id: &ConnectionId,
    authentication: &ConnectionAuthentication,
    confirmations: Option<&BTreeMap<String, Vec<String>>>,
) -> Result<OpenApiToolBinding, OpenApiToolBindingError> {
    let security_by_tool_name = generation
        .security_requirements
        .iter()
        .map(|security| (security.tool_name.as_str(), security))
        .collect::<BTreeMap<_, _>>();
    let mut definitions = Vec::with_capacity(generation.definitions.len());
    let mut security_selections = Vec::with_capacity(generation.definitions.len());
    let mut incompatibilities = Vec::new();

    for definition in &generation.definitions {
        if confirmations.is_some_and(|confirmations| !confirmations.contains_key(&definition.name))
        {
            continue;
        }
        let Some(security) = security_by_tool_name.get(definition.name.as_str()).copied() else {
            if confirmations.is_some() {
                return Err(OpenApiToolBindingError::MissingSecurityMetadata {
                    tool_name: definition.name.clone(),
                });
            }
            incompatibilities.push(OpenApiToolIncompatibility {
                tool_name: definition.name.clone(),
                reason: OpenApiToolIncompatibilityReason::MissingSecurityMetadata,
            });
            continue;
        };
        let confirmed_scheme_names = match confirmations {
            Some(confirmations) => confirmations.get(&definition.name),
            None => None,
        };
        let selected = security.alternatives.iter().find(|alternative| {
            let selected_scheme_names = alternative_scheme_names(alternative);
            confirmed_scheme_names.is_none_or(|confirmed| confirmed == &selected_scheme_names)
                && security_alternative_matches(alternative, authentication)
        });
        let Some(selected) = selected else {
            if let Some(selected_scheme_names) = confirmed_scheme_names {
                return Err(OpenApiToolBindingError::InvalidSecurityConfirmation {
                    tool_name: definition.name.clone(),
                    selected_scheme_names: selected_scheme_names.clone(),
                });
            }
            incompatibilities.push(OpenApiToolIncompatibility {
                tool_name: definition.name.clone(),
                reason: OpenApiToolIncompatibilityReason::NoCompatibleSecurityAlternative,
            });
            continue;
        };

        let path_template = match normalize_origin_relative_path(
            "openapi.path_template",
            &definition.upstream.path_template,
        ) {
            Ok(path_template) => path_template,
            Err(error) => {
                if confirmations.is_some() {
                    return Err(OpenApiToolBindingError::InvalidMappingPath {
                        tool_name: definition.name.clone(),
                        path_template: definition.upstream.path_template.clone(),
                        message: error.message,
                    });
                }
                incompatibilities.push(OpenApiToolIncompatibility {
                    tool_name: definition.name.clone(),
                    reason: OpenApiToolIncompatibilityReason::InvalidMappingPath {
                        path_template: definition.upstream.path_template.clone(),
                        message: error.message,
                    },
                });
                continue;
            }
        };
        let mut mapping = definition.upstream.clone();
        mapping.path_template = path_template;
        let connection_id = connection_id.as_str().to_owned();
        let mut typed_definition = definition.clone();
        typed_definition.upstream = mapping.clone();
        typed_definition.target = Some(ToolTarget::Http {
            connection_id: connection_id.clone(),
            mapping,
        });
        typed_definition.source = ToolSource::OpenApi {
            connection_id,
            operation_id: security.operation_id.clone(),
            catalog_revision: None,
        };

        security_selections.push(OpenApiToolSecuritySelection {
            tool_name: definition.name.clone(),
            selected_scheme_names: alternative_scheme_names(selected),
        });
        definitions.push(typed_definition);
    }

    Ok(OpenApiToolBinding {
        definitions,
        security_selections,
        incompatibilities,
    })
}

fn alternative_scheme_names(alternative: &OpenApiSecurityAlternative) -> Vec<String> {
    let mut names = alternative
        .members
        .iter()
        .filter_map(OpenApiSecuritySchemeRequirement::scheme_name)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    names.sort();
    names
}

fn security_alternative_matches(
    alternative: &OpenApiSecurityAlternative,
    authentication: &ConnectionAuthentication,
) -> bool {
    if alternative.members.len() == 1
        && matches!(
            alternative.members.first(),
            Some(OpenApiSecuritySchemeRequirement::Anonymous)
        )
    {
        return true;
    }
    if alternative.members.len() != 1
        || alternative
            .members
            .iter()
            .any(|member| matches!(member, OpenApiSecuritySchemeRequirement::Anonymous))
    {
        return false;
    }

    alternative
        .members
        .iter()
        .all(|member| match (member, authentication) {
            (
                OpenApiSecuritySchemeRequirement::HeaderApiKey { header_name, .. },
                ConnectionAuthentication::HeaderApiKey {
                    header_name: configured_header_name,
                    ..
                },
            ) => header_name.eq_ignore_ascii_case(configured_header_name),
            (
                OpenApiSecuritySchemeRequirement::HttpBearer { .. },
                ConnectionAuthentication::StaticBearer { .. },
            ) => true,
            (
                OpenApiSecuritySchemeRequirement::OAuth2ClientCredentials {
                    token_url,
                    required_scopes,
                    ..
                },
                ConnectionAuthentication::OAuth2ClientCredentials {
                    token_url: configured_token_url,
                    scopes: configured_scopes,
                    ..
                },
            ) => {
                normalized_token_url(token_url)
                    .zip(normalized_token_url(configured_token_url))
                    .is_some_and(|(required, configured)| required == configured)
                    && required_scopes
                        .iter()
                        .all(|required| configured_scopes.contains(required))
            }
            _ => false,
        })
}

fn normalized_token_url(value: &str) -> Option<String> {
    let parsed = Url::parse(value).ok()?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return None;
    }
    let raw_path = raw_url_path(value)?;
    normalize_origin_relative_path(
        "openapi.oauth2.token_url",
        if raw_path.is_empty() { "/" } else { raw_path },
    )
    .ok()?;
    Some(parsed.to_string())
}

fn raw_url_path(value: &str) -> Option<&str> {
    let scheme_end = value.find("://")? + 3;
    let after_scheme = value.get(scheme_end..)?;
    let path_start = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let suffix = after_scheme.get(path_start..)?;
    if !suffix.starts_with('/') {
        return Some("");
    }
    let path_end = suffix.find(['?', '#']).unwrap_or(suffix.len());
    suffix.get(..path_end)
}

fn reject_non_local_references(document: &Value) -> Result<(), OpenApiToolGenerationError> {
    let mut remaining = vec![document];
    while let Some(value) = remaining.pop() {
        match value {
            Value::Array(values) => remaining.extend(values),
            Value::Object(object) => {
                if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
                    if !reference.starts_with('#') {
                        return Err(OpenApiToolGenerationError::Reference {
                            reference: reference.to_owned(),
                            message: "only local OpenAPI references are supported".to_owned(),
                        });
                    }
                }
                remaining.extend(object.values());
            }
            _ => {}
        }
    }
    Ok(())
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
    expansion_budget: &mut OpenApiSchemaExpansionBudget,
) -> Result<Vec<GeneratedParameter>, OpenApiToolGenerationError> {
    let mut parameters =
        BTreeMap::<(GeneratedParameterLocation, String), GeneratedParameter>::new();
    let path_item = operation_path_item(document, operation);
    collect_parameters(
        document,
        path_item.and_then(|value| value.get("parameters")),
        &mut parameters,
        expansion_budget,
    )?;
    collect_parameters(
        document,
        operation_value(document, operation).and_then(|value| value.get("parameters")),
        &mut parameters,
        expansion_budget,
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
    expansion_budget: &mut OpenApiSchemaExpansionBudget,
) -> Result<(), OpenApiToolGenerationError> {
    let Some(parameters_value) = parameters_value else {
        return Ok(());
    };
    let Some(parameter_values) = parameters_value.as_array() else {
        return Ok(());
    };

    for parameter_value in parameter_values {
        let parameter_value = resolve_reference_with_schema_budget(
            document,
            parameter_value,
            &mut BTreeSet::new(),
            expansion_budget,
        )?;
        let Some(parameter) = generated_parameter(document, parameter_value, expansion_budget)?
        else {
            continue;
        };
        parameters.insert((parameter.location, parameter.name.clone()), parameter);
    }

    Ok(())
}

fn generated_parameter(
    document: &Value,
    parameter_value: &Value,
    expansion_budget: &mut OpenApiSchemaExpansionBudget,
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
        Some(schema) => dereference_schema(
            document,
            schema,
            &mut BTreeSet::new(),
            SchemaExpansionDepth::default(),
            expansion_budget,
        )?,
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
) -> Result<Value, OpenApiSkippedOperationReason> {
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

    let parameter_property_names = properties.keys().cloned().collect::<BTreeSet<_>>();
    if let Some(body_schema) = body_schema {
        merge_body_schema(
            body_schema,
            &parameter_property_names,
            &mut properties,
            &mut required,
        )?;
    }

    Ok(json!({
        "type": "object",
        "required": required.into_iter().collect::<Vec<_>>(),
        "properties": properties,
        "additionalProperties": false,
    }))
}

fn merge_body_schema(
    schema: &Value,
    parameter_property_names: &BTreeSet<String>,
    properties: &mut Map<String, Value>,
    required: &mut BTreeSet<String>,
) -> Result<(), OpenApiSkippedOperationReason> {
    if let Some(all_of) = schema
        .as_object()
        .and_then(|object| object.get("allOf"))
        .and_then(Value::as_array)
    {
        for schema in all_of {
            merge_body_schema(schema, parameter_property_names, properties, required)?;
        }
    }

    let Some(object) = schema.as_object() else {
        return Ok(());
    };

    if let Some(schema_properties) = object.get("properties").and_then(Value::as_object) {
        for (name, schema) in schema_properties {
            let name = name.trim();
            if !name.is_empty() {
                if parameter_property_names.contains(name) {
                    return Err(
                        OpenApiSkippedOperationReason::BodyPropertyParameterNameCollision {
                            property_name: name.to_owned(),
                        },
                    );
                }

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

    Ok(())
}

fn json_request_body_schema(
    document: &Value,
    operation_value: Option<&Value>,
    expansion_budget: &mut OpenApiSchemaExpansionBudget,
) -> Result<Option<Value>, OpenApiToolGenerationError> {
    let Some(request_body) = operation_value.and_then(|value| value.get("requestBody")) else {
        return Ok(None);
    };
    let request_body = resolve_reference_with_schema_budget(
        document,
        request_body,
        &mut BTreeSet::new(),
        expansion_budget,
    )?;
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
        SchemaExpansionDepth::default(),
        expansion_budget,
    )?))
}

fn dereference_schema(
    document: &Value,
    schema: &Value,
    reference_ancestry: &mut BTreeSet<usize>,
    depth: SchemaExpansionDepth,
    expansion_budget: &mut OpenApiSchemaExpansionBudget,
) -> Result<Value, OpenApiToolGenerationError> {
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        expansion_budget.consume_reference(reference)?;
        if depth.references >= MAX_OPENAPI_REFERENCE_DEPTH {
            return Err(OpenApiToolGenerationError::Reference {
                reference: reference.to_owned(),
                message: format!("reference depth exceeds {MAX_OPENAPI_REFERENCE_DEPTH}"),
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
        let target_identity = value_identity(resolved);
        if !reference_ancestry.insert(target_identity) {
            return Err(OpenApiToolGenerationError::Reference {
                reference: reference.to_owned(),
                message: "circular local reference".to_owned(),
            });
        }

        let result = dereference_schema(
            document,
            resolved,
            reference_ancestry,
            depth.resolved_reference()?,
            expansion_budget,
        );
        let removed = reference_ancestry.remove(&target_identity);
        debug_assert!(removed);
        return result;
    }

    expansion_budget.consume_node(schema)?;
    match schema {
        Value::Array(values) => {
            let child_depth = depth.child()?;
            let mut dereferenced = Vec::with_capacity(values.len());
            for value in values {
                dereferenced.push(dereference_schema(
                    document,
                    value,
                    reference_ancestry,
                    child_depth,
                    expansion_budget,
                )?);
            }
            Ok(Value::Array(dereferenced))
        }
        Value::Object(object) => {
            let child_depth = depth.child()?;
            let mut dereferenced = Map::new();
            for (key, value) in object {
                dereferenced.insert(
                    key.clone(),
                    dereference_schema(
                        document,
                        value,
                        reference_ancestry,
                        child_depth,
                        expansion_budget,
                    )?,
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
    resolve_reference_with_depth(document, value, seen_references, 0)
}

fn resolve_reference_with_depth<'a>(
    document: &'a Value,
    value: &'a Value,
    seen_references: &mut BTreeSet<String>,
    depth: usize,
) -> Result<&'a Value, OpenApiToolGenerationError> {
    let Some(reference) = value.get("$ref").and_then(Value::as_str) else {
        return Ok(value);
    };

    if depth >= MAX_OPENAPI_REFERENCE_DEPTH {
        return Err(OpenApiToolGenerationError::Reference {
            reference: reference.to_owned(),
            message: format!("reference depth exceeds {MAX_OPENAPI_REFERENCE_DEPTH}"),
        });
    }
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

    resolve_reference_with_depth(document, resolved, seen_references, depth + 1)
}

fn resolve_reference_with_schema_budget<'a>(
    document: &'a Value,
    value: &'a Value,
    seen_references: &mut BTreeSet<String>,
    expansion_budget: &mut OpenApiSchemaExpansionBudget,
) -> Result<&'a Value, OpenApiToolGenerationError> {
    resolve_reference_with_schema_budget_and_depth(
        document,
        value,
        seen_references,
        expansion_budget,
        0,
    )
}

fn resolve_reference_with_schema_budget_and_depth<'a>(
    document: &'a Value,
    value: &'a Value,
    seen_references: &mut BTreeSet<String>,
    expansion_budget: &mut OpenApiSchemaExpansionBudget,
    depth: usize,
) -> Result<&'a Value, OpenApiToolGenerationError> {
    let Some(reference) = value.get("$ref").and_then(Value::as_str) else {
        return Ok(value);
    };

    expansion_budget.consume_reference(reference)?;
    if depth >= MAX_OPENAPI_REFERENCE_DEPTH {
        return Err(OpenApiToolGenerationError::Reference {
            reference: reference.to_owned(),
            message: format!("reference depth exceeds {MAX_OPENAPI_REFERENCE_DEPTH}"),
        });
    }
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

    resolve_reference_with_schema_budget_and_depth(
        document,
        resolved,
        seen_references,
        expansion_budget,
        depth + 1,
    )
}

fn effective_security_value<'a>(
    document: &'a Value,
    operation_value: Option<&'a Value>,
) -> Option<&'a Value> {
    operation_value
        .and_then(|value| value.as_object())
        .and_then(|operation| operation.get("security"))
        .or_else(|| document.get("security"))
}

fn security_scheme_value<'a>(document: &'a Value, scheme_name: &str) -> Option<&'a Value> {
    document
        .get("components")
        .and_then(|components| components.get("securitySchemes"))
        .and_then(Value::as_object)
        .and_then(|schemes| schemes.get(scheme_name))
}

fn consume_operation_security_metadata_budget(
    document: &Value,
    operation: &OpenApiOperation,
    operation_value: Option<&Value>,
    tool_name: &str,
    budget: &mut OpenApiSecurityMetadataBudget,
) -> Result<(), OpenApiToolGenerationError> {
    let bytes = 64usize
        .saturating_add(json_string_bytes(tool_name))
        .saturating_add(json_string_bytes(&operation.method))
        .saturating_add(json_string_bytes(&operation.path_template))
        .saturating_add(
            operation
                .operation_id
                .as_deref()
                .map(json_string_bytes)
                .unwrap_or(4),
        );
    budget.consume_retained_bytes(bytes)?;
    if let Some(security) = effective_security_value(document, operation_value) {
        budget.charge_value(security)?;
        if let Some(alternatives) = security.as_array() {
            for requirement in alternatives.iter().filter_map(Value::as_object) {
                for scheme_name in requirement.keys() {
                    if let Some(scheme_entry) = security_scheme_value(document, scheme_name) {
                        budget.charge_scheme_entry(document, scheme_entry)?;
                    }
                }
            }
        }
    } else {
        budget.consume_retained_bytes(16)?;
    }
    Ok(())
}

fn operation_security_requirements(
    document: &Value,
    operation: &OpenApiOperation,
    operation_value: Option<&Value>,
    tool_name: &str,
) -> Result<OpenApiOperationSecurity, OpenApiToolGenerationError> {
    let security = effective_security_value(document, operation_value);
    let alternatives = match security {
        None => vec![anonymous_security_alternative()],
        Some(Value::Array(requirements)) if requirements.is_empty() => {
            vec![anonymous_security_alternative()]
        }
        Some(Value::Array(requirements)) => requirements
            .iter()
            .map(|requirement| security_alternative(document, requirement))
            .collect::<Result<Vec<_>, _>>()?,
        Some(_) => vec![invalid_security_alternative()],
    };

    Ok(OpenApiOperationSecurity {
        tool_name: tool_name.to_owned(),
        method: operation.method.clone(),
        path_template: operation.path_template.clone(),
        operation_id: operation.operation_id.clone(),
        alternatives,
    })
}

fn anonymous_security_alternative() -> OpenApiSecurityAlternative {
    OpenApiSecurityAlternative {
        members: vec![OpenApiSecuritySchemeRequirement::Anonymous],
    }
}

fn invalid_security_alternative() -> OpenApiSecurityAlternative {
    OpenApiSecurityAlternative {
        members: vec![OpenApiSecuritySchemeRequirement::Unsupported {
            scheme_name: "<invalid-security-requirement>".to_owned(),
            category: OpenApiUnsupportedSecurityScheme::InvalidDefinition,
        }],
    }
}

fn security_alternative(
    document: &Value,
    requirement: &Value,
) -> Result<OpenApiSecurityAlternative, OpenApiToolGenerationError> {
    let Some(requirement) = requirement.as_object() else {
        return Ok(invalid_security_alternative());
    };
    if requirement.is_empty() {
        return Ok(anonymous_security_alternative());
    }

    let mut members = Vec::with_capacity(requirement.len());
    for (scheme_name, scope_value) in requirement {
        let required_scopes = match scope_value.as_array() {
            Some(scopes)
                if scopes.iter().all(|scope| {
                    scope.as_str().is_some_and(|scope| {
                        !scope.is_empty() && !scope.chars().any(char::is_whitespace)
                    })
                }) =>
            {
                let mut scopes = scopes
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect::<Vec<_>>();
                scopes.sort();
                scopes.dedup();
                scopes
            }
            _ => {
                members.push(OpenApiSecuritySchemeRequirement::Unsupported {
                    scheme_name: scheme_name.clone(),
                    category: OpenApiUnsupportedSecurityScheme::InvalidDefinition,
                });
                continue;
            }
        };
        members.push(security_scheme_requirement(
            document,
            scheme_name,
            required_scopes,
        )?);
    }
    members.sort_by(|left, right| left.scheme_name().cmp(&right.scheme_name()));

    Ok(OpenApiSecurityAlternative { members })
}

fn security_scheme_requirement(
    document: &Value,
    scheme_name: &str,
    required_scopes: Vec<String>,
) -> Result<OpenApiSecuritySchemeRequirement, OpenApiToolGenerationError> {
    let Some(scheme) = security_scheme_value(document, scheme_name) else {
        return Ok(OpenApiSecuritySchemeRequirement::Unsupported {
            scheme_name: scheme_name.to_owned(),
            category: OpenApiUnsupportedSecurityScheme::MissingDefinition,
        });
    };
    let scheme = resolve_reference(document, scheme, &mut BTreeSet::new())?;
    let Some(scheme) = scheme.as_object() else {
        return Ok(OpenApiSecuritySchemeRequirement::Unsupported {
            scheme_name: scheme_name.to_owned(),
            category: OpenApiUnsupportedSecurityScheme::InvalidDefinition,
        });
    };
    let Some(scheme_type) = scheme.get("type").and_then(Value::as_str) else {
        return Ok(OpenApiSecuritySchemeRequirement::Unsupported {
            scheme_name: scheme_name.to_owned(),
            category: OpenApiUnsupportedSecurityScheme::InvalidDefinition,
        });
    };

    if scheme_type.eq_ignore_ascii_case("apiKey") {
        if !required_scopes.is_empty() {
            return Ok(OpenApiSecuritySchemeRequirement::Unsupported {
                scheme_name: scheme_name.to_owned(),
                category: OpenApiUnsupportedSecurityScheme::InvalidDefinition,
            });
        }
        let location = scheme.get("in").and_then(Value::as_str);
        let name = scheme
            .get("name")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|name| !name.is_empty());
        return Ok(match (location, name) {
            (Some(location), Some(header_name))
                if location.eq_ignore_ascii_case("header")
                    && header_name.len() <= 64
                    && HeaderName::from_bytes(header_name.as_bytes()).is_ok() =>
            {
                OpenApiSecuritySchemeRequirement::HeaderApiKey {
                    scheme_name: scheme_name.to_owned(),
                    header_name: header_name.to_owned(),
                }
            }
            (Some(location), _) if location.eq_ignore_ascii_case("header") => {
                OpenApiSecuritySchemeRequirement::Unsupported {
                    scheme_name: scheme_name.to_owned(),
                    category: OpenApiUnsupportedSecurityScheme::InvalidDefinition,
                }
            }
            (Some(location), _) if location.eq_ignore_ascii_case("query") => {
                OpenApiSecuritySchemeRequirement::Unsupported {
                    scheme_name: scheme_name.to_owned(),
                    category: OpenApiUnsupportedSecurityScheme::ApiKeyQuery,
                }
            }
            (Some(location), _) if location.eq_ignore_ascii_case("cookie") => {
                OpenApiSecuritySchemeRequirement::Unsupported {
                    scheme_name: scheme_name.to_owned(),
                    category: OpenApiUnsupportedSecurityScheme::ApiKeyCookie,
                }
            }
            (Some(_), _) => OpenApiSecuritySchemeRequirement::Unsupported {
                scheme_name: scheme_name.to_owned(),
                category: OpenApiUnsupportedSecurityScheme::ApiKeyUnsupportedLocation,
            },
            (None, _) => OpenApiSecuritySchemeRequirement::Unsupported {
                scheme_name: scheme_name.to_owned(),
                category: OpenApiUnsupportedSecurityScheme::InvalidDefinition,
            },
        });
    }

    if scheme_type.eq_ignore_ascii_case("http") {
        if !required_scopes.is_empty() {
            return Ok(OpenApiSecuritySchemeRequirement::Unsupported {
                scheme_name: scheme_name.to_owned(),
                category: OpenApiUnsupportedSecurityScheme::InvalidDefinition,
            });
        }
        let http_scheme = scheme.get("scheme").and_then(Value::as_str);
        return Ok(match http_scheme {
            Some(http_scheme) if http_scheme.eq_ignore_ascii_case("bearer") => {
                OpenApiSecuritySchemeRequirement::HttpBearer {
                    scheme_name: scheme_name.to_owned(),
                }
            }
            Some(http_scheme) if http_scheme.eq_ignore_ascii_case("basic") => {
                OpenApiSecuritySchemeRequirement::Unsupported {
                    scheme_name: scheme_name.to_owned(),
                    category: OpenApiUnsupportedSecurityScheme::HttpBasic,
                }
            }
            Some(_) => OpenApiSecuritySchemeRequirement::Unsupported {
                scheme_name: scheme_name.to_owned(),
                category: OpenApiUnsupportedSecurityScheme::HttpUnsupportedScheme,
            },
            None => OpenApiSecuritySchemeRequirement::Unsupported {
                scheme_name: scheme_name.to_owned(),
                category: OpenApiUnsupportedSecurityScheme::InvalidDefinition,
            },
        });
    }

    if scheme_type.eq_ignore_ascii_case("oauth2") {
        let client_credentials = scheme
            .get("flows")
            .and_then(|flows| flows.get("clientCredentials"))
            .and_then(Value::as_object);
        let Some(client_credentials) = client_credentials else {
            return Ok(OpenApiSecuritySchemeRequirement::Unsupported {
                scheme_name: scheme_name.to_owned(),
                category: OpenApiUnsupportedSecurityScheme::OAuth2WithoutClientCredentials,
            });
        };
        let token_url = client_credentials
            .get("tokenUrl")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|token_url| !token_url.is_empty());
        let declared_scopes = client_credentials.get("scopes").and_then(Value::as_object);
        let Some(token_url) = token_url else {
            return Ok(OpenApiSecuritySchemeRequirement::Unsupported {
                scheme_name: scheme_name.to_owned(),
                category: OpenApiUnsupportedSecurityScheme::InvalidDefinition,
            });
        };
        if normalized_token_url(token_url).is_none()
            || declared_scopes.is_none()
            || required_scopes.iter().any(|required| {
                !declared_scopes.is_some_and(|declared| declared.contains_key(required))
            })
        {
            return Ok(OpenApiSecuritySchemeRequirement::Unsupported {
                scheme_name: scheme_name.to_owned(),
                category: OpenApiUnsupportedSecurityScheme::InvalidDefinition,
            });
        }
        return Ok(OpenApiSecuritySchemeRequirement::OAuth2ClientCredentials {
            scheme_name: scheme_name.to_owned(),
            token_url: token_url.to_owned(),
            required_scopes,
        });
    }

    Ok(OpenApiSecuritySchemeRequirement::Unsupported {
        scheme_name: scheme_name.to_owned(),
        category: if scheme_type.eq_ignore_ascii_case("openIdConnect") {
            OpenApiUnsupportedSecurityScheme::OpenIdConnect
        } else if scheme_type.eq_ignore_ascii_case("mutualTLS") {
            OpenApiUnsupportedSecurityScheme::MutualTls
        } else {
            OpenApiUnsupportedSecurityScheme::UnsupportedType
        },
    })
}

fn api_key_header_requirements(
    document: &Value,
    operation: &OpenApiOperation,
    operation_value: Option<&Value>,
    tool_name: &str,
) -> Result<Vec<OpenApiApiKeyHeaderAuthRequirement>, OpenApiToolGenerationError> {
    let security = effective_security_value(document, operation_value);
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
    let Some(scheme) = security_scheme_value(document, scheme_name) else {
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
    use std::collections::BTreeMap;

    use serde_json::{json, Value};

    use super::*;
    use crate::{
        connections::model::OAuthClientAuthMethod,
        tools::definitions::{
            BodyMappingMode, QueryParamMapping, ToolRegistry, ToolSource, ToolTarget,
        },
    };

    #[test]
    fn generates_valid_tools_from_realistic_multi_operation_spec() {
        let generation = generate_tools_from_openapi_str("test.yaml", realistic_spec())
            .expect("OpenAPI spec should generate tools");

        assert_eq!(generation.definitions.len(), 3);
        assert!(generation.skipped_operations.is_empty());
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
    fn realistic_spec_generates_same_non_colliding_tools_without_skips() {
        let generation = generate_tools_from_openapi_str("test.yaml", realistic_spec())
            .expect("OpenAPI spec should generate tools");

        assert!(generation.skipped_operations.is_empty());

        let actual: BTreeMap<String, Value> = generation
            .definitions
            .iter()
            .map(|definition| {
                (
                    definition.name.clone(),
                    serde_json::to_value(definition)
                        .expect("generated definition should serialize"),
                )
            })
            .collect();
        let expected = BTreeMap::from([
            (
                "createWidget".to_owned(),
                json!({
                    "name": "createWidget",
                    "description": "Create a widget",
                    "input_json_schema": {
                        "type": "object",
                        "required": ["name"],
                        "properties": {
                            "name": { "type": "string" },
                            "quantity": { "type": "integer", "minimum": 1 }
                        },
                        "additionalProperties": false
                    },
                    "upstream": {
                        "method": "POST",
                        "path_template": "/widgets",
                        "body": { "mode": "whole_args_json" }
                    }
                }),
            ),
            (
                "deleteWidget".to_owned(),
                json!({
                    "name": "deleteWidget",
                    "description": "Deletes a widget when it is no longer needed.",
                    "input_json_schema": {
                        "type": "object",
                        "required": ["widgetId"],
                        "properties": {
                            "widgetId": { "type": "string" }
                        },
                        "additionalProperties": false
                    },
                    "upstream": {
                        "method": "DELETE",
                        "path_template": "/widgets/{widgetId}"
                    }
                }),
            ),
            (
                "getWidget".to_owned(),
                json!({
                    "name": "getWidget",
                    "description": "Fetch a widget",
                    "input_json_schema": {
                        "type": "object",
                        "required": ["page", "widgetId"],
                        "properties": {
                            "includeDetails": { "type": "boolean" },
                            "page": { "type": "integer", "minimum": 1 },
                            "widgetId": { "type": "string" }
                        },
                        "additionalProperties": false
                    },
                    "upstream": {
                        "method": "GET",
                        "path_template": "/widgets/{widgetId}",
                        "query_params": [
                            {
                                "arg_name": "includeDetails",
                                "query_name": "includeDetails",
                                "required": false
                            },
                            {
                                "arg_name": "page",
                                "query_name": "page",
                                "required": true
                            }
                        ]
                    }
                }),
            ),
        ]);

        assert_eq!(actual, expected);
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
    fn skips_operation_when_body_property_collides_with_path_parameter() {
        let generation = generate_tools_from_openapi_str(
            "collision.yaml",
            r#"
openapi: 3.0.3
info:
  title: Collision API
  version: 1.0.0
paths:
  /widgets/{id}:
    put:
      operationId: updateWidget
      parameters:
        - in: path
          name: id
          required: true
          schema:
            type: string
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [id]
              properties:
                id:
                  type: object
                  properties:
                    external:
                      type: string
                name:
                  type: string
"#,
        )
        .expect("OpenAPI spec should generate a report");

        assert!(generation.definitions.is_empty());
        assert_eq!(
            generation.skipped_operations,
            vec![OpenApiSkippedOperation {
                method: "PUT".to_owned(),
                path_template: "/widgets/{id}".to_owned(),
                original_operation_id: Some("updateWidget".to_owned()),
                reason: OpenApiSkippedOperationReason::BodyPropertyParameterNameCollision {
                    property_name: "id".to_owned(),
                },
            }]
        );
        assert!(
            generation
                .definitions
                .iter()
                .all(|definition| definition.name != "updateWidget"),
            "colliding operation must not be emitted as a broken tool"
        );
    }

    #[test]
    fn rejects_indirect_request_body_reference_chain() {
        // A real reference chain reaches its next `$ref` through a wrapper
        // object, which is the shape the bare-alias fixture below never builds.
        let spec = indirect_request_body_reference_chain_spec(MAX_OPENAPI_REFERENCE_DEPTH + 1);
        let error = generate_tools_from_openapi_str("indirect-refs.json", &spec)
            .expect_err("indirect reference chains must respect the reference depth limit");

        let OpenApiToolGenerationError::Reference { reference, message } = error else {
            panic!("deep indirect references should return a reference error: {error}");
        };
        assert!(
            reference.starts_with("#/components/schemas/S"),
            "unexpected reference: {reference}"
        );
        assert!(
            message.contains("reference depth exceeds"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn expands_indirect_request_body_reference_chain_within_the_depth_limit() {
        let spec = indirect_request_body_reference_chain_spec(8);
        let generation = generate_tools_from_openapi_str("indirect-refs.json", &spec)
            .expect("an indirect chain inside the depth limit should still expand");

        let definition = generation
            .definitions
            .iter()
            .find(|definition| definition.name == "createWidget")
            .expect("createWidget should be generated");
        let mut schema = definition
            .input_schema
            .pointer("/properties/next")
            .expect("the first hop should be expanded in place");
        for _ in 1..8 {
            schema = schema
                .pointer("/properties/next")
                .expect("every hop should be expanded in place");
        }
        assert_eq!(
            schema.pointer("/properties/name/type"),
            Some(&json!("string")),
            "the terminal schema should survive expansion: {schema}"
        );
    }

    #[test]
    fn rejects_request_body_schema_nested_beyond_the_expansion_depth_limit() {
        // Few enough hops to stay inside the reference limit, but each hop
        // splices in its own nesting, so the expanded schema is far deeper than
        // any single parsed document may be.
        let spec = nested_request_body_reference_chain_spec(32, 10);
        let error = generate_tools_from_openapi_str("nested-refs.json", &spec)
            .expect_err("expanded schema nesting must be bounded");

        assert!(
            matches!(
                &error,
                OpenApiToolGenerationError::GenerationLimit {
                    limit: OpenApiToolGenerationLimit::SchemaExpansionDepth,
                    maximum: MAX_OPENAPI_SCHEMA_EXPANSION_DEPTH,
                }
            ),
            "unexpected error: {error:?}"
        );
        assert!(
            error.to_string().contains("nesting depth maximum of 256"),
            "the limit should be named: {error}"
        );
    }

    #[test]
    fn rejects_deep_request_body_reference_chain() {
        let spec = deep_request_body_reference_chain_spec(65);
        let error = generate_tools_from_openapi_str("deep-refs.json", &spec)
            .expect_err("overly deep OpenAPI schema references should reject");

        let OpenApiToolGenerationError::Reference { reference, message } = error else {
            panic!("deep references should return a reference error");
        };
        assert!(
            reference.starts_with("#/components/schemas/S"),
            "unexpected reference: {reference}"
        );
        assert!(
            message.contains("reference depth exceeds"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn rejects_operation_count_above_catalog_limit_before_generation() {
        let mut paths = serde_json::Map::new();
        for index in 0..=MAX_CATALOG_ENTRIES {
            paths.insert(
                format!("/operations/{index}"),
                json!({
                    "get": {
                        "operationId": format!("operation_{index}")
                    }
                }),
            );
        }
        let spec = json!({
            "openapi": "3.0.3",
            "info": {
                "title": "Too many operations",
                "version": "1.0.0"
            },
            "paths": paths
        })
        .to_string();

        let error = generate_tools_from_openapi_str("too-many.json", &spec)
            .expect_err("operation count must be bounded before tool generation");
        assert!(matches!(
            error,
            OpenApiToolGenerationError::GenerationLimit {
                limit: OpenApiToolGenerationLimit::OperationCount,
                maximum: MAX_CATALOG_ENTRIES,
            }
        ));
    }

    #[test]
    fn rejects_cumulative_definition_schema_amplification() {
        let mut paths = serde_json::Map::new();
        for index in 0..70 {
            paths.insert(
                format!("/amplified/{index}"),
                json!({
                    "post": {
                        "operationId": format!("amplified_{index}"),
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "$ref": "#/components/schemas/LargeBody"
                                    }
                                }
                            }
                        }
                    }
                }),
            );
        }
        let spec = json!({
            "openapi": "3.0.3",
            "info": {
                "title": "Schema amplification",
                "version": "1.0.0"
            },
            "paths": paths,
            "components": {
                "schemas": {
                    "LargeBody": {
                        "type": "object",
                        "properties": {
                            "payload": {
                                "type": "string",
                                "description": "x".repeat(256 * 1024)
                            }
                        }
                    }
                }
            }
        })
        .to_string();
        assert!(
            spec.len() < 2 * 1024 * 1024,
            "regression fixture must remain a plausibly accepted managed spec"
        );

        let error = generate_tools_from_openapi_str("amplification.json", &spec)
            .expect_err("cumulative generated definitions must be bounded");
        assert!(
            matches!(
                &error,
                OpenApiToolGenerationError::GenerationLimit {
                    limit: OpenApiToolGenerationLimit::CumulativeDefinitionBytes
                        | OpenApiToolGenerationLimit::SchemaExpansionBytes,
                    maximum: MAX_MANAGED_OPENAPI_CATALOG_BYTES,
                }
            ),
            "unexpected amplification error: {error:?}"
        );
    }

    #[test]
    fn rejects_exponential_local_reference_fan_out_before_materializing_it() {
        let mut schemas = serde_json::Map::new();
        schemas.insert("S0".to_owned(), json!({ "type": "string" }));
        for depth in 1..=25 {
            schemas.insert(
                format!("S{depth}"),
                json!({
                    "type": "object",
                    "properties": {
                        "left": {
                            "$ref": format!("#/components/schemas/S{}", depth - 1)
                        },
                        "right": {
                            "$ref": format!("#/components/schemas/S{}", depth - 1)
                        }
                    }
                }),
            );
        }
        let spec = json!({
            "openapi": "3.0.3",
            "info": {
                "title": "Reference fan-out",
                "version": "1.0.0"
            },
            "paths": {
                "/fan-out": {
                    "post": {
                        "operationId": "fanOut",
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "$ref": "#/components/schemas/S25"
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "components": {
                "schemas": schemas
            }
        })
        .to_string();
        assert!(
            spec.len() < 64 * 1024,
            "fan-out regression must remain a small input"
        );

        let error = generate_tools_from_openapi_str("fan-out.json", &spec)
            .expect_err("expanded local references must share a strict output budget");
        assert!(matches!(
            error,
            OpenApiToolGenerationError::GenerationLimit {
                limit: OpenApiToolGenerationLimit::SchemaExpansionNodes,
                maximum: MAX_OPENAPI_SCHEMA_EXPANSION_NODES,
            }
        ));
    }

    #[test]
    fn rejects_wide_schema_without_cloning_long_reference_ancestry_per_child() {
        let name_suffix = "x".repeat(11 * 1024);
        let names = (0..MAX_OPENAPI_REFERENCE_DEPTH)
            .map(|index| format!("S{index}_{name_suffix}"))
            .collect::<Vec<_>>();
        let mut schemas = serde_json::Map::new();
        for (index, name) in names.iter().enumerate() {
            let schema = match names.get(index + 1) {
                Some(next) => {
                    json!({ "$ref": format!("#/components/schemas/{next}") })
                }
                None => json!({
                    "enum": vec![Value::Null; MAX_OPENAPI_SCHEMA_EXPANSION_NODES]
                }),
            };
            schemas.insert(name.clone(), schema);
        }
        let spec = json!({
            "openapi": "3.0.3",
            "info": {
                "title": "Wide schema with long ancestry",
                "version": "1.0.0"
            },
            "paths": {
                "/wide": {
                    "post": {
                        "operationId": "wide",
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "$ref": format!(
                                            "#/components/schemas/{}",
                                            names[0]
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "components": {
                "schemas": schemas
            }
        })
        .to_string();
        assert!(
            spec.len() < 2 * 1024 * 1024,
            "wide-schema regression must remain a bounded managed spec"
        );

        let error = generate_tools_from_openapi_str("wide-ancestry.json", &spec)
            .expect_err("wide schemas must stop at the shared expansion-node budget");
        assert!(
            matches!(
                &error,
                OpenApiToolGenerationError::GenerationLimit {
                    limit: OpenApiToolGenerationLimit::SchemaExpansionNodes,
                    maximum: MAX_OPENAPI_SCHEMA_EXPANSION_NODES,
                }
            ),
            "unexpected wide-schema error: {error:?}"
        );
    }

    #[test]
    fn rejects_repeated_long_alias_pointer_work_with_schema_byte_budget() {
        let target_name = format!("Target_{}", "t".repeat(512 * 1024));
        let mut properties = serde_json::Map::new();
        for index in 0..4_096 {
            properties.insert(
                format!("property_{index}"),
                json!({ "$ref": "#/components/schemas/Alias" }),
            );
        }
        let mut schemas = serde_json::Map::new();
        schemas.insert(target_name.clone(), json!({ "type": "string" }));
        schemas.insert(
            "Alias".to_owned(),
            json!({
                "$ref": format!("#/components/schemas/{target_name}")
            }),
        );
        schemas.insert(
            "Wide".to_owned(),
            json!({
                "type": "object",
                "properties": properties
            }),
        );
        let spec = json!({
            "openapi": "3.0.3",
            "info": {
                "title": "Repeated long alias pointer",
                "version": "1.0.0"
            },
            "paths": {
                "/wide": {
                    "post": {
                        "operationId": "wideAlias",
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "$ref": "#/components/schemas/Wide"
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "components": {
                "schemas": schemas
            }
        })
        .to_string();
        assert!(
            spec.len() < 2 * 1024 * 1024,
            "long-alias regression must remain a bounded managed spec"
        );

        let error = generate_tools_from_openapi_str("long-alias.json", &spec)
            .expect_err("repeated long local references must consume the byte budget");
        assert!(
            matches!(
                &error,
                OpenApiToolGenerationError::GenerationLimit {
                    limit: OpenApiToolGenerationLimit::SchemaExpansionBytes,
                    maximum: MAX_MANAGED_OPENAPI_CATALOG_BYTES,
                }
            ),
            "unexpected long-alias error: {error:?}"
        );
    }

    #[test]
    fn rejects_root_security_metadata_amplification_before_retaining_it() {
        let scheme_name = "S".repeat(256 * 1024);
        let mut security_requirement = serde_json::Map::new();
        security_requirement.insert(scheme_name.clone(), json!([]));
        let mut security_schemes = serde_json::Map::new();
        security_schemes.insert(
            scheme_name,
            json!({
                "type": "apiKey",
                "in": "header",
                "name": "X-API-Key"
            }),
        );
        let mut paths = serde_json::Map::new();
        for index in 0..40 {
            paths.insert(
                format!("/secured/{index}"),
                json!({
                    "get": {
                        "operationId": format!("secured_{index}")
                    }
                }),
            );
        }
        let spec = json!({
            "openapi": "3.0.3",
            "info": {
                "title": "Security metadata amplification",
                "version": "1.0.0"
            },
            "security": [Value::Object(security_requirement)],
            "components": {
                "securitySchemes": security_schemes
            },
            "paths": paths
        })
        .to_string();
        assert!(
            spec.len() < 2 * 1024 * 1024,
            "security amplification fixture must remain a bounded managed spec"
        );

        let error = generate_tools_from_openapi_str("security-amplification.json", &spec)
            .expect_err("shared inherited security metadata must be cumulatively bounded");
        assert!(
            matches!(
                &error,
                OpenApiToolGenerationError::GenerationLimit {
                    limit: OpenApiToolGenerationLimit::SecurityMetadataBytes,
                    maximum: MAX_MANAGED_OPENAPI_CATALOG_BYTES,
                }
            ),
            "unexpected security amplification error: {error:?}"
        );
    }

    #[test]
    fn rejects_many_security_aliases_without_rescanning_common_long_reference() {
        let mut security_schemes = serde_json::Map::new();
        let target_name = "T".repeat(256 * 1024);
        security_schemes.insert(
            target_name.clone(),
            json!({
                "type": "apiKey",
                "in": "header",
                "name": "X-API-Key"
            }),
        );
        security_schemes.insert(
            "Common".to_owned(),
            json!({
                "$ref": format!("#/components/securitySchemes/{target_name}")
            }),
        );
        let mut security = Vec::new();
        for index in 0..64 {
            let alias = format!("Alias{index}");
            security_schemes.insert(
                alias.clone(),
                json!({ "$ref": "#/components/securitySchemes/Common" }),
            );
            let mut requirement = serde_json::Map::new();
            requirement.insert(alias, json!([]));
            security.push(Value::Object(requirement));
        }
        let spec = json!({
            "openapi": "3.0.3",
            "info": {
                "title": "Security alias amplification",
                "version": "1.0.0"
            },
            "security": security,
            "components": {
                "securitySchemes": security_schemes
            },
            "paths": {
                "/secured": {
                    "get": {
                        "operationId": "secured"
                    }
                }
            }
        })
        .to_string();
        assert!(
            spec.len() < 2 * 1024 * 1024,
            "alias amplification fixture must remain a bounded managed spec"
        );

        let error = generate_tools_from_openapi_str("security-aliases.json", &spec)
            .expect_err("repeated aliases to one large scheme must be bounded incrementally");
        assert!(
            matches!(
                &error,
                OpenApiToolGenerationError::GenerationLimit {
                    limit: OpenApiToolGenerationLimit::SecurityMetadataBytes,
                    maximum: MAX_MANAGED_OPENAPI_CATALOG_BYTES,
                }
            ),
            "unexpected security alias amplification error: {error:?}"
        );
    }

    #[test]
    fn continues_generating_other_operations_when_collision_is_skipped() {
        let generation =
            generate_tools_from_openapi_str("mixed-batch.yaml", colliding_and_valid_spec())
                .expect("OpenAPI spec should generate non-colliding tools");

        assert_eq!(
            generation
                .definitions
                .iter()
                .map(|definition| definition.name.as_str())
                .collect::<Vec<_>>(),
            vec!["getStatus"]
        );
        assert_eq!(
            generation.skipped_operations,
            vec![OpenApiSkippedOperation {
                method: "PUT".to_owned(),
                path_template: "/widgets/{id}".to_owned(),
                original_operation_id: Some("updateWidget".to_owned()),
                reason: OpenApiSkippedOperationReason::BodyPropertyParameterNameCollision {
                    property_name: "id".to_owned(),
                },
            }]
        );
    }

    #[test]
    fn whole_args_json_mixed_operation_includes_path_query_and_body_properties() {
        let generation = generate_tools_from_openapi_str(
            "mixed-operation.yaml",
            r#"
openapi: 3.0.3
info:
  title: Mixed API
  version: 1.0.0
paths:
  /widgets/{id}:
    put:
      operationId: updateWidgetName
      parameters:
        - in: path
          name: id
          required: true
          schema:
            type: string
        - in: query
          name: dryRun
          required: false
          schema:
            type: boolean
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [name]
              properties:
                name:
                  type: string
                quantity:
                  type: integer
"#,
        )
        .expect("OpenAPI spec should generate tools");

        assert!(generation.skipped_operations.is_empty());
        let definition = generation
            .definitions
            .iter()
            .find(|definition| definition.name == "updateWidgetName")
            .expect("mixed operation should generate a tool");

        assert_eq!(
            definition.input_schema["properties"]["id"],
            json!({ "type": "string" })
        );
        assert_eq!(
            definition.input_schema["properties"]["dryRun"],
            json!({ "type": "boolean" })
        );
        assert_eq!(
            definition.input_schema["properties"]["name"],
            json!({ "type": "string" })
        );
        assert_eq!(
            definition.input_schema["properties"]["quantity"],
            json!({ "type": "integer" })
        );
        assert!(
            definition.input_schema["required"]
                .as_array()
                .expect("required should be an array")
                .iter()
                .any(|value| value == "id"),
            "path parameter should remain required"
        );
        assert!(
            definition.input_schema["required"]
                .as_array()
                .expect("required should be an array")
                .iter()
                .any(|value| value == "name"),
            "body-required property should remain required"
        );
        assert_eq!(
            definition.upstream.query_params,
            vec![QueryParamMapping {
                arg_name: "dryRun".to_owned(),
                query_name: "dryRun".to_owned(),
                required: false,
            }]
        );
        assert_eq!(
            definition.upstream.body.as_ref().map(|body| body.mode),
            Some(BodyMappingMode::WholeArgsJson)
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

    #[test]
    fn preserves_security_or_alternatives_and_and_members() {
        let generation =
            generate_tools_from_openapi_str("security.yaml", security_semantics_spec())
                .expect("security semantics should parse");

        let or_security = generation
            .security_requirements
            .iter()
            .find(|security| security.tool_name == "orAuth")
            .expect("OR operation should have security metadata");
        assert_eq!(or_security.operation_id.as_deref(), Some("orAuth"));
        assert_eq!(or_security.alternatives.len(), 2);
        assert_eq!(
            or_security.alternatives[0].members,
            vec![OpenApiSecuritySchemeRequirement::Unsupported {
                scheme_name: "QueryKey".to_owned(),
                category: OpenApiUnsupportedSecurityScheme::ApiKeyQuery,
            }]
        );
        assert_eq!(
            or_security.alternatives[1].members,
            vec![OpenApiSecuritySchemeRequirement::HeaderApiKey {
                scheme_name: "HeaderKey".to_owned(),
                header_name: "X-API-Key".to_owned(),
            }]
        );

        let and_security = generation
            .security_requirements
            .iter()
            .find(|security| security.tool_name == "andAuth")
            .expect("AND operation should have security metadata");
        assert_eq!(
            and_security.alternatives,
            vec![OpenApiSecurityAlternative {
                members: vec![
                    OpenApiSecuritySchemeRequirement::HttpBearer {
                        scheme_name: "BearerAuth".to_owned(),
                    },
                    OpenApiSecuritySchemeRequirement::HeaderApiKey {
                        scheme_name: "HeaderKey".to_owned(),
                        header_name: "X-API-Key".to_owned(),
                    },
                ],
            }]
        );

        let anonymous = generation
            .security_requirements
            .iter()
            .find(|security| security.tool_name == "anonymous")
            .expect("anonymous operation should have security metadata");
        assert_eq!(
            anonymous.alternatives,
            vec![anonymous_security_alternative()]
        );
    }

    #[test]
    fn preview_skips_unsupported_or_branch_and_suggests_complete_supported_branch() {
        let generation =
            generate_tools_from_openapi_str("security.yaml", security_semantics_spec())
                .expect("security semantics should parse");
        let connection_id =
            ConnectionId::parse("billing-api").expect("connection ID should be valid");
        let authentication = ConnectionAuthentication::HeaderApiKey {
            header_name: "x-api-key".to_owned(),
            secret_id: Some("billing-secret".to_owned()),
        };

        let binding = bind_generated_openapi_tools(&generation, &connection_id, &authentication)
            .expect("preview binding should report incompatible tools rather than fail");

        assert!(binding
            .definitions
            .iter()
            .any(|definition| definition.name == "orAuth"));
        assert_eq!(
            binding
                .security_selections
                .iter()
                .find(|selection| selection.tool_name == "orAuth")
                .expect("OR operation should have a selected branch")
                .selected_scheme_names,
            vec!["HeaderKey"]
        );
        assert!(binding.incompatibilities.iter().any(|incompatibility| {
            incompatibility.tool_name == "andAuth"
                && incompatibility.reason
                    == OpenApiToolIncompatibilityReason::NoCompatibleSecurityAlternative
        }));
        assert!(
            !binding
                .definitions
                .iter()
                .any(|definition| definition.name == "andAuth"),
            "one Header API key must not partially satisfy an AND branch that also requires bearer"
        );

        let mismatched_header = ConnectionAuthentication::HeaderApiKey {
            header_name: "X-Different-Key".to_owned(),
            secret_id: Some("billing-secret".to_owned()),
        };
        let mismatch =
            bind_generated_openapi_tools(&generation, &connection_id, &mismatched_header)
                .expect("header mismatch should remain a preview result");
        assert!(!mismatch
            .definitions
            .iter()
            .any(|definition| definition.name == "orAuth"));
    }

    #[test]
    fn static_bearer_satisfies_only_http_bearer() {
        let generation =
            generate_tools_from_openapi_str("security.yaml", security_semantics_spec())
                .expect("security semantics should parse");
        let connection_id =
            ConnectionId::parse("bearer-api").expect("connection ID should be valid");

        let binding = bind_generated_openapi_tools(
            &generation,
            &connection_id,
            &ConnectionAuthentication::StaticBearer {
                secret_id: Some("bearer-secret".to_owned()),
            },
        )
        .expect("bearer preview should succeed");

        assert_eq!(
            binding
                .definitions
                .iter()
                .map(|definition| definition.name.as_str())
                .collect::<Vec<_>>(),
            vec!["anonymous", "bearerOnly"]
        );
        assert_eq!(
            binding
                .security_selections
                .iter()
                .find(|selection| selection.tool_name == "bearerOnly")
                .expect("bearer operation should have a selected branch")
                .selected_scheme_names,
            vec!["BearerAuth"]
        );
    }

    #[test]
    fn unsupported_query_cookie_basic_and_openid_schemes_fail_closed() {
        let generation = generate_tools_from_openapi_str(
            "unsupported-security.yaml",
            r#"
openapi: 3.0.3
info: { title: Unsupported security, version: 1.0.0 }
components:
  securitySchemes:
    QueryKey: { type: apiKey, in: query, name: token }
    CookieKey: { type: apiKey, in: cookie, name: session }
    BasicAuth: { type: http, scheme: basic }
    OpenId: { type: openIdConnect, openIdConnectUrl: https://id.example.test/.well-known/openid-configuration }
paths:
  /query:
    get: { operationId: queryOnly, security: [ { QueryKey: [] } ] }
  /cookie:
    get: { operationId: cookieOnly, security: [ { CookieKey: [] } ] }
  /basic:
    get: { operationId: basicOnly, security: [ { BasicAuth: [] } ] }
  /openid:
    get: { operationId: openidOnly, security: [ { OpenId: [] } ] }
"#,
        )
        .expect("unsupported schemes should remain reviewable");
        let connection_id =
            ConnectionId::parse("unsupported-api").expect("connection ID should be valid");
        let binding = bind_generated_openapi_tools(
            &generation,
            &connection_id,
            &ConnectionAuthentication::StaticBearer {
                secret_id: Some("secret".to_owned()),
            },
        )
        .expect("preview should report unsupported operations");

        assert!(binding.definitions.is_empty());
        assert_eq!(binding.incompatibilities.len(), 4);
        let categories = generation
            .security_requirements
            .iter()
            .filter_map(|security| security.alternatives.first())
            .filter_map(|alternative| alternative.members.first())
            .filter_map(|requirement| match requirement {
                OpenApiSecuritySchemeRequirement::Unsupported { category, .. } => Some(*category),
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(
            categories,
            BTreeSet::from([
                OpenApiUnsupportedSecurityScheme::ApiKeyQuery,
                OpenApiUnsupportedSecurityScheme::ApiKeyCookie,
                OpenApiUnsupportedSecurityScheme::HttpBasic,
                OpenApiUnsupportedSecurityScheme::OpenIdConnect,
            ])
        );
    }

    #[test]
    fn oauth_binding_requires_matching_token_url_and_scope_subset() {
        let generation = generate_tools_from_openapi_str(
            "oauth.yaml",
            r#"
openapi: 3.0.3
info: { title: OAuth API, version: 1.0.0 }
servers:
  - url: https://attacker.example.test/ignored
components:
  securitySchemes:
    OAuth:
      type: oauth2
      flows:
        clientCredentials:
          tokenUrl: https://IDP.EXAMPLE.TEST:443/oauth/token
          scopes:
            widgets.read: Read widgets
            widgets.write: Write widgets
paths:
  /widgets/{id}:
    get:
      operationId: getWidgetOauth
      security:
        - OAuth: [widgets.read]
      parameters:
        - { in: path, name: id, required: true, schema: { type: string } }
"#,
        )
        .expect("OAuth spec should parse");
        let connection_id =
            ConnectionId::parse("oauth-api").expect("connection ID should be valid");
        let authentication = ConnectionAuthentication::OAuth2ClientCredentials {
            client_id: "client".to_owned(),
            client_secret_id: Some("client-secret".to_owned()),
            token_url: "https://idp.example.test/oauth/token".to_owned(),
            scopes: vec!["widgets.read".to_owned(), "widgets.write".to_owned()],
            audience: None,
            resource: None,
            client_auth_method: OAuthClientAuthMethod::ClientSecretBasic,
        };

        let binding = bind_generated_openapi_tools(&generation, &connection_id, &authentication)
            .expect("matching normalized OAuth authentication should bind");
        assert!(binding.incompatibilities.is_empty());
        assert_eq!(binding.definitions.len(), 1);
        let definition = &binding.definitions[0];
        assert_eq!(definition.upstream.path_template, "/widgets/{id}");
        assert_eq!(
            definition.target,
            Some(ToolTarget::Http {
                connection_id: "oauth-api".to_owned(),
                mapping: definition.upstream.clone(),
            })
        );
        assert_eq!(
            definition.source,
            ToolSource::OpenApi {
                connection_id: "oauth-api".to_owned(),
                operation_id: Some("getWidgetOauth".to_owned()),
                catalog_revision: None,
            }
        );

        let wrong_token_url = ConnectionAuthentication::OAuth2ClientCredentials {
            client_id: "client".to_owned(),
            client_secret_id: Some("client-secret".to_owned()),
            token_url: "https://idp.example.test/other-token".to_owned(),
            scopes: vec!["widgets.read".to_owned(), "widgets.write".to_owned()],
            audience: None,
            resource: None,
            client_auth_method: OAuthClientAuthMethod::ClientSecretBasic,
        };
        let mismatch = bind_generated_openapi_tools(&generation, &connection_id, &wrong_token_url)
            .expect("mismatch should be a preview incompatibility");
        assert!(mismatch.definitions.is_empty());
        assert_eq!(
            mismatch.incompatibilities[0].reason,
            OpenApiToolIncompatibilityReason::NoCompatibleSecurityAlternative
        );

        let missing_scope = ConnectionAuthentication::OAuth2ClientCredentials {
            client_id: "client".to_owned(),
            client_secret_id: Some("client-secret".to_owned()),
            token_url: "https://idp.example.test/oauth/token".to_owned(),
            scopes: Vec::new(),
            audience: None,
            resource: None,
            client_auth_method: OAuthClientAuthMethod::ClientSecretBasic,
        };
        let mismatch = bind_generated_openapi_tools(&generation, &connection_id, &missing_scope)
            .expect("missing scope should be a preview incompatibility");
        assert!(mismatch.definitions.is_empty());
    }

    #[test]
    fn authoritative_binding_uses_exact_confirmed_subset() {
        let generation =
            generate_tools_from_openapi_str("security.yaml", security_semantics_spec())
                .expect("security semantics should parse");
        let connection_id =
            ConnectionId::parse("billing-api").expect("connection ID should be valid");
        let authentication = ConnectionAuthentication::HeaderApiKey {
            header_name: "X-Api-Key".to_owned(),
            secret_id: Some("secret".to_owned()),
        };
        let confirmations = vec![OpenApiToolSecuritySelection {
            tool_name: "orAuth".to_owned(),
            selected_scheme_names: vec!["HeaderKey".to_owned()],
        }];

        let binding = bind_generated_openapi_tools_with_confirmations(
            &generation,
            &connection_id,
            &authentication,
            &confirmations,
        )
        .expect("an exact compatible subset should bind");
        assert_eq!(binding.definitions.len(), 1);
        assert_eq!(binding.definitions[0].name, "orAuth");
        assert!(binding.incompatibilities.is_empty());

        let wrong_confirmation = vec![OpenApiToolSecuritySelection {
            tool_name: "orAuth".to_owned(),
            selected_scheme_names: vec!["QueryKey".to_owned()],
        }];
        assert!(matches!(
            bind_generated_openapi_tools_with_confirmations(
                &generation,
                &connection_id,
                &authentication,
                &wrong_confirmation,
            ),
            Err(OpenApiToolBindingError::InvalidSecurityConfirmation { .. })
        ));
    }

    #[test]
    fn none_authentication_satisfies_only_anonymous_operations() {
        let generation =
            generate_tools_from_openapi_str("security.yaml", security_semantics_spec())
                .expect("security semantics should parse");
        let connection_id =
            ConnectionId::parse("anonymous-api").expect("connection ID should be valid");

        let binding = bind_generated_openapi_tools(
            &generation,
            &connection_id,
            &ConnectionAuthentication::None,
        )
        .expect("anonymous preview should succeed");
        assert_eq!(
            binding
                .definitions
                .iter()
                .map(|definition| definition.name.as_str())
                .collect::<Vec<_>>(),
            vec!["anonymous"]
        );
        assert!(binding.security_selections[0]
            .selected_scheme_names
            .is_empty());
    }

    #[test]
    fn credentialed_connection_can_bind_anonymous_operation() {
        let generation = generate_tools_from_openapi_str(
            "anonymous.yaml",
            r#"
openapi: 3.0.3
info: { title: Anonymous API, version: 1.0.0 }
paths:
  /status:
    get:
      operationId: status
      security: []
"#,
        )
        .expect("anonymous operation should parse");
        let connection_id =
            ConnectionId::parse("credentialed-api").expect("connection ID should be valid");

        let binding = bind_generated_openapi_tools(
            &generation,
            &connection_id,
            &ConnectionAuthentication::HeaderApiKey {
                header_name: "X-API-Key".to_owned(),
                secret_id: Some("credential".to_owned()),
            },
        )
        .expect("credentialed connection should remain compatible with anonymous operation");

        assert_eq!(binding.definitions.len(), 1);
        assert!(binding.incompatibilities.is_empty());
        assert!(binding.security_selections[0]
            .selected_scheme_names
            .is_empty());
    }

    #[test]
    fn rejects_non_local_reference_nested_in_unrelated_document_branch() {
        let error = generate_tools_from_openapi_str(
            "external-ref.yaml",
            r#"
openapi: 3.0.3
info: { title: External ref, version: 1.0.0 }
paths:
  /status:
    get: { operationId: status }
x-unrelated:
  nested:
    schema:
      $ref: https://attacker.example.test/schema.json
"#,
        )
        .expect_err("every nested non-local reference must be rejected");

        assert!(matches!(
            error,
            OpenApiToolGenerationError::Reference { reference, message }
                if reference == "https://attacker.example.test/schema.json"
                    && message.contains("only local")
        ));
    }

    #[test]
    fn typed_binding_rejects_authority_like_operation_paths() {
        let generation = generate_tools_from_openapi_str(
            "unsafe-path.yaml",
            r#"
openapi: 3.0.3
info: { title: Unsafe path, version: 1.0.0 }
paths:
  //attacker.example.test/steal:
    get: { operationId: steal, security: [] }
"#,
        )
        .expect("parser currently permits the path for safe binding review");
        let connection_id =
            ConnectionId::parse("safe-origin").expect("connection ID should be valid");

        let preview = bind_generated_openapi_tools(
            &generation,
            &connection_id,
            &ConnectionAuthentication::None,
        )
        .expect("unsafe mapping should be reported without aborting preview");
        assert!(preview.definitions.is_empty());
        assert!(matches!(
            preview.incompatibilities[0].reason,
            OpenApiToolIncompatibilityReason::InvalidMappingPath { .. }
        ));

        let confirmed = vec![OpenApiToolSecuritySelection {
            tool_name: "steal".to_owned(),
            selected_scheme_names: Vec::new(),
        }];
        assert!(matches!(
            bind_generated_openapi_tools_with_confirmations(
                &generation,
                &connection_id,
                &ConnectionAuthentication::None,
                &confirmed,
            ),
            Err(OpenApiToolBindingError::InvalidMappingPath { .. })
        ));
    }

    #[test]
    fn credentialed_trace_operation_is_never_generated_or_bound() {
        let generation = generate_tools_from_openapi_str(
            "trace.yaml",
            r#"
openapi: 3.0.3
info: { title: TRACE API, version: 1.0.0 }
components:
  securitySchemes:
    HeaderKey: { type: apiKey, in: header, name: X-API-Key }
paths:
  /diagnostics:
    trace:
      operationId: traceRequest
      security:
        - HeaderKey: []
"#,
        )
        .expect("TRACE should be reported as skipped rather than generated");
        assert!(generation.definitions.is_empty());
        assert!(generation.security_requirements.is_empty());
        assert_eq!(
            generation.skipped_operations,
            vec![OpenApiSkippedOperation {
                method: "TRACE".to_owned(),
                path_template: "/diagnostics".to_owned(),
                original_operation_id: Some("traceRequest".to_owned()),
                reason: OpenApiSkippedOperationReason::UnsafeTraceMethod,
            }]
        );

        let connection_id =
            ConnectionId::parse("credentialed-api").expect("connection ID should be valid");
        let authentication = ConnectionAuthentication::HeaderApiKey {
            header_name: "X-API-Key".to_owned(),
            secret_id: Some("upstream-secret".to_owned()),
        };
        let preview = bind_generated_openapi_tools(&generation, &connection_id, &authentication)
            .expect("skipped TRACE should leave an empty safe preview");
        assert!(preview.definitions.is_empty());

        let confirmation = vec![OpenApiToolSecuritySelection {
            tool_name: "traceRequest".to_owned(),
            selected_scheme_names: vec!["HeaderKey".to_owned()],
        }];
        assert!(matches!(
            bind_generated_openapi_tools_with_confirmations(
                &generation,
                &connection_id,
                &authentication,
                &confirmation,
            ),
            Err(OpenApiToolBindingError::UnexpectedSecurityConfirmation { tool_name })
                if tool_name == "traceRequest"
        ));
    }

    fn security_semantics_spec() -> &'static str {
        r#"
openapi: 3.0.3
info: { title: Security semantics, version: 1.0.0 }
components:
  securitySchemes:
    HeaderKey: { type: apiKey, in: header, name: X-API-Key }
    QueryKey: { type: apiKey, in: query, name: token }
    BearerAuth: { type: http, scheme: bearer }
paths:
  /or:
    get:
      operationId: orAuth
      security:
        - QueryKey: []
        - HeaderKey: []
  /and:
    get:
      operationId: andAuth
      security:
        - HeaderKey: []
          BearerAuth: []
  /anonymous:
    get:
      operationId: anonymous
      security: []
  /bearer:
    get:
      operationId: bearerOnly
      security:
        - BearerAuth: []
"#
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

    fn colliding_and_valid_spec() -> &'static str {
        r#"
openapi: 3.0.3
info:
  title: Batch API
  version: 1.0.0
paths:
  /widgets/{id}:
    put:
      operationId: updateWidget
      parameters:
        - in: path
          name: id
          required: true
          schema:
            type: string
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                id:
                  type: integer
                name:
                  type: string
  /status:
    get:
      operationId: getStatus
      summary: Read status
"#
    }

    fn reference_chain_spec(schemas: serde_json::Map<String, Value>) -> String {
        json!({
            "openapi": "3.0.3",
            "info": {
                "title": "Chained Ref API",
                "version": "1.0.0"
            },
            "paths": {
                "/widgets": {
                    "post": {
                        "operationId": "createWidget",
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/S0" }
                                }
                            }
                        }
                    }
                }
            },
            "components": {
                "schemas": schemas
            }
        })
        .to_string()
    }

    fn terminal_chain_schema() -> Value {
        json!({
            "type": "object",
            "properties": {
                "name": { "type": "string" }
            }
        })
    }

    /// `S{i}` reaches `S{i+1}` through a `properties` wrapper, so the reference
    /// depth counter has to survive an intervening object to bound it.
    fn indirect_request_body_reference_chain_spec(depth: usize) -> String {
        let mut schemas = serde_json::Map::new();
        for index in 0..depth {
            schemas.insert(
                format!("S{index}"),
                json!({
                    "type": "object",
                    "properties": {
                        "next": { "$ref": format!("#/components/schemas/S{}", index + 1) }
                    }
                }),
            );
        }
        schemas.insert(format!("S{depth}"), terminal_chain_schema());

        reference_chain_spec(schemas)
    }

    /// Every hop buries its `$ref` under `nesting` plain object levels, so a
    /// short reference chain still expands into a very deep schema.
    fn nested_request_body_reference_chain_spec(hops: usize, nesting: usize) -> String {
        let mut schemas = serde_json::Map::new();
        for index in 0..hops {
            let mut schema = json!({ "$ref": format!("#/components/schemas/S{}", index + 1) });
            for _ in 0..nesting {
                schema = json!({ "type": "object", "properties": { "next": schema } });
            }
            schemas.insert(format!("S{index}"), schema);
        }
        schemas.insert(format!("S{hops}"), terminal_chain_schema());

        reference_chain_spec(schemas)
    }

    fn deep_request_body_reference_chain_spec(depth: usize) -> String {
        let mut schemas = serde_json::Map::new();
        for index in 0..depth {
            schemas.insert(
                format!("S{index}"),
                json!({ "$ref": format!("#/components/schemas/S{}", index + 1) }),
            );
        }
        schemas.insert(
            format!("S{depth}"),
            json!({
                "type": "object",
                "properties": {
                    "name": { "type": "string" }
                }
            }),
        );

        json!({
            "openapi": "3.0.3",
            "info": {
                "title": "Deep Ref API",
                "version": "1.0.0"
            },
            "paths": {
                "/widgets": {
                    "post": {
                        "operationId": "createWidget",
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/S0" }
                                }
                            }
                        }
                    }
                }
            },
            "components": {
                "schemas": schemas
            }
        })
        .to_string()
    }
}
