//! The tool definitions document (`TOOLS_FILE`, tools 0.1.0): the
//! [`ToolDefinition`] model and its validating parse, shared by the gateway
//! and `ggctl` (issue #242).
//!
//! [`definitions_from_json_value`] is the one validating parse: the published
//! schema, then the typed reading, then the semantic checks every registry
//! update is held to, and the provenance a local document may claim. The
//! gateway runs it on startup, reload and every admin write; a configuration
//! bundle's tools document goes through it in both the gateway and `ggctl`.
//! Nothing here reads a file or the network. Loading and watching the tools
//! file, the merged registry and executing a tool are the gateway's
//! (`gateway/src/tools`), which re-exports this module.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt, io,
    path::{Path, PathBuf},
    sync::LazyLock,
};

use http::Method;
use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{
    codecs::Codec,
    composite::CompositeMapping,
    transforms::{ParameterShape, ToolTransform, WireSource},
};

const MAX_INPUT_SCHEMA_REFERENCE_DEPTH: usize = 64;
/// Most nodes the precheck walks in one definition's input schema.
pub const MAX_INPUT_SCHEMA_PRECHECK_NODES: usize = 4_096;
/// Ceiling on precheck nodes across every definition in the merged registry.
///
/// Sized against the published catalog bound rather than the 1 MiB tools file:
/// `MAX_CATALOG_ENTRIES` (4,096) entries at 256 nodes each. A merged registry
/// carries managed OpenAPI and MCP catalogs whose only size bound is an entry
/// count, so a ceiling sized for one local file would reject ordinary catalogs.
pub const MAX_REGISTRY_INPUT_SCHEMA_PRECHECK_NODES: usize = 1_048_576;
/// Exact-comparison budget for the numbers in one schema or argument object,
/// stated as the width in decimal digits of the single widest number it buys.
///
/// jsonschema is built with `arbitrary-precision`, so a number that `u64` and
/// `f64` cannot hold exactly is compared as a big integer or fraction, and the
/// work grows with the square of the digits it spans: its mantissa digits plus
/// the magnitude of its exponent. A short exponent buys a very wide number;
/// measured against jsonschema 0.58.6, validating the eight-byte argument
/// `1e-99999` against `{"minimum": 0}` ran for more than five seconds. Each
/// number wider than `MAX_UNMETERED_NUMBER_DIGITS` is charged its span
/// squared, and a document may spend what one number this wide costs: `1e400`
/// spans 401 digits and fits six times.
const MAX_EXACT_NUMBER_DIGITS: u64 = 1_024;
/// Numbers no wider than `u64::MAX` (20 digits) cost a bounded amount to
/// compare however they are written, so they are not charged.
const MAX_UNMETERED_NUMBER_DIGITS: u64 = 20;
const TOOLS_FILE_SCHEMA_JSON: &str = include_str!("../../../docs/schemas/tools.v0.schema.json");
const MCP_PROXY_METHOD: &str = "MCP_PROXY";
pub const COMPOSITE_METHOD: &str = "COMPOSITE";

static TOOLS_FILE_SCHEMA_VALIDATOR: LazyLock<jsonschema::Validator> = LazyLock::new(|| {
    let schema = serde_json::from_str(TOOLS_FILE_SCHEMA_JSON)
        .expect("embedded tools file schema should be valid JSON");
    jsonschema::validator_for(&schema).expect("embedded tools file schema should compile")
});

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ToolDefinition {
    pub name: String,
    /// Optional agent-facing display title. Omission preserves the serialized
    /// representation of definitions created before MCP metadata pass-through.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub description: String,
    #[serde(rename = "input_json_schema")]
    pub input_schema: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<ToolTarget>,
    #[serde(default, skip_serializing_if = "ToolSource::is_legacy")]
    pub source: ToolSource,
    pub upstream: UpstreamMapping,
    /// The compiled saga plan for a synthetic overlay-owned composite tool.
    /// Omitted for every legacy, HTTP, and MCP definition so their stored
    /// representation and digest remain byte-for-byte compatible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub composite: Option<CompositeMapping>,
    /// Who may see and call this tool (issue #360, D2). `Listed` is the
    /// default and is never serialised, so a definition that predates the
    /// field keeps its exact stored bytes and digest.
    #[serde(default, skip_serializing_if = "ToolVisibility::is_listed")]
    pub visibility: ToolVisibility,
    /// Declarative agent-to-wire and wire-to-agent mapping compiled from a
    /// Connection OpenAPI overlay. Omission preserves legacy definitions and
    /// their serialized bytes exactly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transform: Option<ToolTransform>,
    /// Stable dynamic-enum bindings compiled from a Connection overlay.
    /// Current values are intentionally absent: they are applied only to an
    /// owned serve/validation clone so the durable definition digest does not
    /// churn when upstream metadata changes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub enum_bindings: Vec<EnumBinding>,
    /// MCP client hints. These never affect GreenGateway authorization or
    /// execution; they are preserved for clients that choose to display or
    /// interpret them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<ToolAnnotations>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ToolAnnotations {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_only_hint: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destructive_hint: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotent_hint: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub open_world_hint: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnumBinding {
    /// Top-level agent-facing property whose `enum` is supplied at serve time.
    pub property: String,
    /// Overlay-local enum source identifier.
    pub source_id: String,
    /// SHA-256 of the normalized source plan, as lowercase hexadecimal.
    pub source_digest: String,
}

/// Where a tool is reachable from (issue #360).
///
/// `CompositeOnly` tools are compiled from a Connection overlay: they are
/// not advertised by `tools/list` and not callable through `tools/call`,
/// only as a step or compensation of a composite tool (PR 4) and from the
/// admin playground. The registry keeps them so policy, inventory, and
/// the catalog digest see one definition per operation.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolVisibility {
    #[default]
    Listed,
    CompositeOnly,
}

impl ToolVisibility {
    pub fn is_listed(&self) -> bool {
        matches!(self, Self::Listed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HttpToolMapping {
    pub method: String,
    pub path_template: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub query_params: Vec<QueryParamMapping>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<BodyMapping>,
}

/// Compatibility name for the legacy tools-file field.
///
/// Runtime execution continues to read `ToolDefinition::upstream` until the
/// connection-aware executor lands. New code should use `HttpToolMapping`.
pub type UpstreamMapping = HttpToolMapping;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ToolTarget {
    Http {
        connection_id: String,
        mapping: HttpToolMapping,
    },
    Mcp {
        connection_id: String,
        remote_tool_name: String,
    },
    Composite {
        connection_id: String,
    },
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ToolSource {
    Manual,
    OpenApi {
        connection_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        operation_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        catalog_revision: Option<u64>,
    },
    Mcp {
        connection_id: String,
        remote_tool_name: String,
    },
    #[default]
    Legacy,
}

impl ToolSource {
    fn is_legacy(&self) -> bool {
        matches!(self, Self::Legacy)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpProxyMapping {
    pub server_name: String,
    pub tool_name: String,
}

#[derive(Deserialize, Serialize)]
struct SerializedMcpProxyMapping {
    server_name: String,
    tool_name: String,
}

impl ToolDefinition {
    pub fn mcp_proxy(
        name: String,
        description: String,
        input_schema: Value,
        server_name: String,
        tool_name: String,
    ) -> Self {
        Self {
            name,
            title: None,
            description,
            input_schema,
            target: None,
            source: ToolSource::Legacy,
            upstream: UpstreamMapping::mcp_proxy(server_name, tool_name),
            composite: None,
            visibility: ToolVisibility::Listed,
            transform: None,
            enum_bindings: Vec::new(),
            annotations: None,
        }
    }

    pub fn mcp_connection(
        connection_id: String,
        description: String,
        input_schema: Value,
        remote_tool_name: String,
    ) -> Self {
        let mut definition = Self::mcp_proxy(
            format!("{connection_id}:{remote_tool_name}"),
            description,
            input_schema,
            connection_id.clone(),
            remote_tool_name.clone(),
        );
        definition.target = Some(ToolTarget::Mcp {
            connection_id: connection_id.clone(),
            remote_tool_name: remote_tool_name.clone(),
        });
        definition.source = ToolSource::Mcp {
            connection_id,
            remote_tool_name,
        };
        definition
    }
}

impl HttpToolMapping {
    pub fn composite_sentinel() -> Self {
        Self {
            method: COMPOSITE_METHOD.to_owned(),
            path_template: "/".to_owned(),
            query_params: Vec::new(),
            body: None,
        }
    }

    pub fn is_composite_sentinel(&self) -> bool {
        self.method == COMPOSITE_METHOD
            && self.path_template == "/"
            && self.query_params.is_empty()
            && self.body.is_none()
    }

    pub fn uses_composite_method(&self) -> bool {
        self.method == COMPOSITE_METHOD
    }

    pub fn mcp_proxy(server_name: String, tool_name: String) -> Self {
        let path_template = serde_json::to_string(&SerializedMcpProxyMapping {
            server_name,
            tool_name,
        })
        .expect("serialized MCP proxy mapping should be valid JSON");

        Self {
            method: MCP_PROXY_METHOD.to_owned(),
            path_template,
            query_params: Vec::new(),
            body: None,
        }
    }

    pub fn mcp_proxy_mapping(&self) -> Option<McpProxyMapping> {
        if self.method != MCP_PROXY_METHOD {
            return None;
        }

        let mapping =
            serde_json::from_str::<SerializedMcpProxyMapping>(&self.path_template).ok()?;
        Some(McpProxyMapping {
            server_name: mapping.server_name,
            tool_name: mapping.tool_name,
        })
    }

    pub fn is_mcp_proxy(&self) -> bool {
        self.method == MCP_PROXY_METHOD
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QueryParamMapping {
    pub arg_name: String,
    pub query_name: String,
    #[serde(default)]
    pub required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BodyMapping {
    pub mode: BodyMappingMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BodyMappingMode {
    /// The entire validated argument object is the JSON body, path and
    /// query arguments included. Today's behaviour for every generated
    /// tool that is not named under a Connection overlay.
    WholeArgsJson,
    /// The argument object minus path placeholders and mapped query
    /// arguments is the JSON body (issue #360). The overlay compiler sets
    /// this on overlaid tools; a hand-written tools file may too.
    BodyArgsJson,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ToolsFile {
    #[allow(dead_code)]
    schema_version: String,
    #[serde(default)]
    tools: Vec<ToolDefinition>,
}

#[derive(Debug)]
pub enum ToolRegistryError {
    Io {
        path: PathBuf,
        source: io::Error,
    },
    Parse {
        path: Option<PathBuf>,
        source: serde_json::Error,
    },
    Invalid {
        problems: Vec<String>,
    },
}

impl ToolRegistryError {
    /// A refusal listing every problem found.
    pub fn invalid(problems: Vec<String>) -> Self {
        Self::Invalid { problems }
    }
}

impl fmt::Display for ToolRegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(
                    formatter,
                    "failed to read tools file {}: {source}",
                    path.display()
                )
            }
            Self::Parse {
                path: Some(path),
                source,
            } => write!(
                formatter,
                "failed to parse tools file {} as JSON: {source}",
                path.display()
            ),
            Self::Parse { path: None, source } => {
                write!(formatter, "failed to parse tools JSON: {source}")
            }
            Self::Invalid { problems } => {
                write!(formatter, "invalid tools registry: {}", problems.join("; "))
            }
        }
    }
}

impl Error for ToolRegistryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Parse { source, .. } => Some(source),
            Self::Invalid { .. } => None,
        }
    }
}

/// The definitions that claim managed OpenAPI or MCP provenance, which a
/// local document may not.
pub fn local_definition_provenance_problems(definitions: &[ToolDefinition]) -> Vec<String> {
    definitions
        .iter()
        .enumerate()
        .filter_map(|(index, definition)| match &definition.source {
            ToolSource::OpenApi { .. } => Some(format!(
                "tools[{index}].source must not claim managed OpenAPI provenance in local definitions"
            )),
            ToolSource::Mcp { .. } => Some(format!(
                "tools[{index}].source must not claim managed MCP provenance in local definitions"
            )),
            ToolSource::Manual | ToolSource::Legacy => None,
        })
        .collect()
}

pub fn definitions_from_json_value(
    value: Value,
    path: Option<&Path>,
) -> Result<Vec<ToolDefinition>, ToolRegistryError> {
    let schema_problems = tools_file_schema_problems(&value);
    if !schema_problems.is_empty() {
        return Err(ToolRegistryError::invalid(schema_problems));
    }

    let tools_file: ToolsFile =
        serde_json::from_value(value).map_err(|source| ToolRegistryError::Parse {
            path: path.map(Path::to_owned),
            source,
        })?;

    let semantic_problems = tool_definition_problems(&tools_file.tools);
    if !semantic_problems.is_empty() {
        return Err(ToolRegistryError::invalid(semantic_problems));
    }
    let provenance_problems = local_definition_provenance_problems(&tools_file.tools);
    if !provenance_problems.is_empty() {
        return Err(ToolRegistryError::invalid(provenance_problems));
    }

    Ok(tools_file.tools)
}

fn tools_file_schema_problems(value: &Value) -> Vec<String> {
    TOOLS_FILE_SCHEMA_VALIDATOR
        .iter_errors(value)
        .map(|error| {
            format!(
                "tools file schema validation failed at {}: {}",
                error.instance_path(),
                error
            )
        })
        .collect()
}

/// The semantic problems of a set of definitions, checked together: one
/// local document, or the merged registry a write would produce.
pub fn tool_definition_problems(definitions: &[ToolDefinition]) -> Vec<String> {
    let mut problems = Vec::new();
    let mut seen = BTreeMap::new();
    let mut input_schema_precheck_budget = InputSchemaPrecheckBudget::new();

    for (index, definition) in definitions.iter().enumerate() {
        input_schema_precheck_budget.begin_definition();
        let is_http_mapping =
            !definition.upstream.is_mcp_proxy() && !definition.upstream.uses_composite_method();

        if let Some(first_index) = seen.insert(definition.name.as_str(), index) {
            problems.push(format!(
                "duplicate tool name '{}' at tools[{index}] (first defined at tools[{first_index}])",
                definition.name
            ));
        }

        problems.extend(typed_tool_metadata_problems(index, definition));
        problems.extend(enum_binding_problems(index, definition));

        if let Some(mapping) = definition.upstream.mcp_proxy_mapping() {
            if mapping.server_name.trim().is_empty() {
                problems.push(format!(
                    "tools[{index}].upstream MCP proxy server_name must be non-empty"
                ));
            }
            if mapping.tool_name.trim().is_empty() {
                problems.push(format!(
                    "tools[{index}].upstream MCP proxy tool_name must be non-empty"
                ));
            }
        } else if definition.upstream.is_mcp_proxy() {
            problems.push(format!(
                "tools[{index}].upstream MCP proxy mapping is invalid"
            ));
        } else if definition.upstream.uses_composite_method() {
            if !definition.upstream.is_composite_sentinel() {
                problems.push(format!(
                    "tools[{index}].upstream COMPOSITE sentinel must use path_template '/', no query_params, and no body"
                ));
            }
        } else if !is_known_http_method(&definition.upstream.method) {
            problems.push(format!(
                "tools[{index}].upstream.method contains unknown HTTP method '{}'",
                definition.upstream.method
            ));
        }

        if let Some(problem) = input_schema_precheck_problem(
            &definition.input_schema,
            &mut input_schema_precheck_budget,
        ) {
            problems.push(format!(
                "tool '{}' input_json_schema {problem}",
                definition.name
            ));
            continue;
        }

        if let Err(err) = jsonschema::validator_for(&definition.input_schema) {
            problems.push(format!(
                "tool '{}' input_json_schema is not a valid JSON Schema: {err}",
                definition.name
            ));
            continue;
        }

        if is_http_mapping {
            problems.extend(tool_mapping_schema_problems(index, definition));
        }
        problems.extend(tool_transform_problems(index, definition));
    }

    problems
}

fn tool_transform_problems(index: usize, definition: &ToolDefinition) -> Vec<String> {
    let Some(transform) = &definition.transform else {
        return Vec::new();
    };
    let mut problems = Vec::new();
    if definition.upstream.is_mcp_proxy()
        || matches!(&definition.target, Some(ToolTarget::Composite { .. }))
    {
        problems.push(format!(
            "tools[{index}].transform is only supported for HTTP tools"
        ));
    }
    if !transform.parameters.is_empty()
        && definition.upstream.body.as_ref().map(|body| body.mode)
            != Some(BodyMappingMode::BodyArgsJson)
    {
        problems.push(format!(
            "tools[{index}].transform requires upstream.body.mode body_args_json"
        ));
    }
    if transform.parameters.len() > 256 {
        problems.push(format!(
            "tools[{index}].transform.parameters exceeds 256 entries"
        ));
    }
    if transform.response_fields.len() > 64 {
        problems.push(format!(
            "tools[{index}].transform.response_fields exceeds 64 entries"
        ));
    }
    if transform.parameters.is_empty()
        && transform.response_fields.is_empty()
        && transform.response_root.is_none()
    {
        problems.push(format!(
            "tools[{index}].transform must contain a parameter, response field, or response root"
        ));
    }

    let input_properties = definition
        .input_schema
        .get("properties")
        .and_then(Value::as_object);
    if !transform.parameters.is_empty()
        && definition.input_schema.get("additionalProperties") != Some(&Value::Bool(false))
    {
        problems.push(format!(
            "tools[{index}].transform requires input_json_schema.additionalProperties false so callers cannot bypass agent fields with raw wire properties"
        ));
    }
    let mut wire_properties = BTreeSet::new();
    for (lane, shapes) in [
        ("parameters", transform.parameters.as_slice()),
        ("response_fields", transform.response_fields.as_slice()),
    ] {
        for (shape_index, shape) in shapes.iter().enumerate() {
            let path = format!("tools[{index}].transform.{lane}[{shape_index}]");
            if !wire_properties.insert(shape.wire_property.as_str()) {
                problems.push(format!(
                    "{path}.wire_property duplicates transformed wire property '{}'",
                    shape.wire_property
                ));
            }
            if lane == "parameters" {
                if input_properties
                    .is_some_and(|properties| properties.contains_key(&shape.wire_property))
                {
                    problems.push(format!(
                        "{path}.wire_property must be removed from the compiled agent input schema"
                    ));
                }
                for agent in &shape.agent {
                    if !input_properties
                        .is_some_and(|properties| properties.contains_key(&agent.name))
                    {
                        problems.push(format!(
                            "{path}.agent property '{}' is absent from the compiled agent input schema",
                            agent.name
                        ));
                    }
                }
            }
            parameter_shape_problems(&path, shape, &mut problems);
        }
    }
    problems
}

fn parameter_shape_problems(path: &str, shape: &ParameterShape, problems: &mut Vec<String>) {
    if shape.wire_property.is_empty() {
        problems.push(format!("{path}.wire_property must be non-empty"));
    }
    if shape.agent.is_empty() || shape.agent.len() > 16 {
        problems.push(format!("{path}.agent must contain 1-16 properties"));
    }
    if shape.wire.is_empty() || shape.wire.len() > 16 {
        problems.push(format!("{path}.wire must contain 1-16 bindings"));
    }
    if shape.response.is_empty() || shape.response.len() > 16 {
        problems.push(format!("{path}.response must contain 1-16 bindings"));
    }

    let mut agent_names = BTreeSet::new();
    for agent in &shape.agent {
        if agent.name.is_empty() || !agent_names.insert(agent.name.as_str()) {
            problems.push(format!(
                "{path}.agent contains an empty or duplicate property name"
            ));
        }
        if agent.schema.get("type").and_then(Value::as_str).is_none() {
            problems.push(format!(
                "{path}.agent property '{}' must have a single schema type",
                agent.name
            ));
        }
        if contains_json_keyword(&agent.schema, "format") {
            problems.push(format!(
                "{path}.agent property '{}' must not contain format",
                agent.name
            ));
        }
        if numbers_exceed_exact_comparison_budget(&agent.schema) {
            problems.push(format!(
                "{path}.agent property '{}' {}",
                agent.name,
                exact_comparison_budget_problem()
            ));
        } else if let Err(error) = jsonschema::validator_for(&agent.schema) {
            problems.push(format!(
                "{path}.agent property '{}' is not a valid JSON Schema: {error}",
                agent.name
            ));
        }
    }

    let mut pointers = Vec::new();
    let mut used_agents = BTreeSet::new();
    for (binding_index, binding) in shape.wire.iter().enumerate() {
        let binding_path = format!("{path}.wire[{binding_index}]");
        let pointer = binding.pointer.as_str();
        if pointer.is_empty() {
            problems.push(format!("{binding_path}.pointer must be non-empty"));
        }
        if pointers.iter().any(|other: &&str| {
            json_pointer_is_prefix(other, pointer) || json_pointer_is_prefix(pointer, other)
        }) {
            problems.push(format!(
                "{binding_path}.pointer overlaps another wire binding"
            ));
        }
        pointers.push(pointer);
        if let WireSource::From { from } = &binding.source {
            if !agent_names.contains(from.as_str()) {
                problems.push(format!(
                    "{binding_path}.from names unknown agent property '{from}'"
                ));
            }
            used_agents.insert(from.as_str());
        }
        codec_problems(&binding_path, &binding.codecs, true, problems);
    }
    for name in &agent_names {
        if !used_agents.contains(name) {
            problems.push(format!(
                "{path}.agent property '{name}' is not used by a wire binding"
            ));
        }
    }

    let mut response_agents = BTreeSet::new();
    for (binding_index, binding) in shape.response.iter().enumerate() {
        let binding_path = format!("{path}.response[{binding_index}]");
        if !agent_names.contains(binding.agent_property.as_str()) {
            problems.push(format!(
                "{binding_path}.agent_property names unknown agent property '{}'",
                binding.agent_property
            ));
        }
        if !response_agents.insert(binding.agent_property.as_str()) {
            problems.push(format!("{binding_path}.agent_property is duplicated"));
        }
        codec_problems(&binding_path, &binding.codecs, false, problems);
    }
}

fn codec_problems(path: &str, codecs: &[Codec], encode: bool, problems: &mut Vec<String>) {
    if codecs.len() > 4 {
        problems.push(format!("{path}.codec exceeds four codecs"));
    }
    for codec in codecs {
        match codec {
            Codec::DecimalScale {
                scale,
                max_integer_digits,
                ..
            } => {
                if *scale > 18 || !(1..=38).contains(max_integer_digits) {
                    problems.push(format!(
                        "{path}.codec decimal_scale options are outside their supported bounds"
                    ));
                }
            }
            Codec::MarkdownBlocks {
                max_input_bytes, ..
            } => {
                if !(1..=262_144).contains(max_input_bytes) {
                    problems.push(format!(
                        "{path}.codec markdown_blocks max_input_bytes is outside 1-262144"
                    ));
                }
                if !encode {
                    problems.push(format!(
                        "{path}.codec markdown_blocks has no response decode direction"
                    ));
                }
            }
            Codec::JsonString => {}
        }
    }
}

fn contains_json_keyword(value: &Value, keyword: &str) -> bool {
    match value {
        Value::Object(object) => object
            .iter()
            .any(|(key, value)| key == keyword || contains_json_keyword(value, keyword)),
        Value::Array(values) => values
            .iter()
            .any(|value| contains_json_keyword(value, keyword)),
        _ => false,
    }
}

fn json_pointer_is_prefix(left: &str, right: &str) -> bool {
    left == right
        || right
            .strip_prefix(left)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn enum_binding_problems(index: usize, definition: &ToolDefinition) -> Vec<String> {
    const MAX_ENUM_BINDINGS: usize = 256;

    let mut problems = Vec::new();
    if definition.enum_bindings.len() > MAX_ENUM_BINDINGS {
        problems.push(format!(
            "tools[{index}].enum_bindings contains {} entries; the limit is {MAX_ENUM_BINDINGS}",
            definition.enum_bindings.len()
        ));
    }

    let properties = definition
        .input_schema
        .get("properties")
        .and_then(Value::as_object);
    let mut seen = BTreeSet::new();
    for (binding_index, binding) in definition.enum_bindings.iter().enumerate() {
        let path = format!("tools[{index}].enum_bindings[{binding_index}]");
        if binding.property.is_empty()
            || binding.property.chars().count() > 256
            || binding.property.chars().any(char::is_control)
        {
            problems.push(format!(
                "{path}.property must contain 1-256 characters without controls"
            ));
        }
        if !seen.insert(binding.property.as_str()) {
            problems.push(format!(
                "{path}.property duplicates dynamic enum property '{}'",
                binding.property
            ));
        }
        if !valid_overlay_local_name(&binding.source_id) {
            problems.push(format!(
                "{path}.source_id must match ^[A-Za-z][A-Za-z0-9_]{{0,63}}$"
            ));
        }
        if binding.source_digest.len() != 64
            || !binding
                .source_digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            problems.push(format!(
                "{path}.source_digest must be 64 lowercase hexadecimal characters"
            ));
        }

        let Some(property_schema) = properties.and_then(|items| items.get(&binding.property))
        else {
            problems.push(format!(
                "{path}.property '{}' must name input_json_schema.properties",
                binding.property
            ));
            continue;
        };
        let Some(enum_schema) = dynamic_enum_schema(property_schema) else {
            problems.push(format!(
                "{path}.property '{}' must have type string or boolean, or be an array whose items have type string or boolean",
                binding.property
            ));
            continue;
        };
        if enum_schema.get("enum").is_some() {
            problems.push(format!(
                "{path}.property '{}' must not persist enum values; values are injected only into a served clone",
                binding.property
            ));
        }
    }
    problems
}

fn valid_overlay_local_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(first) if first.is_ascii_alphabetic())
        && bytes.clone().count() <= 63
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

/// Return the schema node that receives the resolved enum. Arrays bind their
/// item schema; scalar string/boolean properties bind the property itself.
pub fn dynamic_enum_schema(schema: &Value) -> Option<&Value> {
    match schema.get("type")?.as_str()? {
        "string" | "boolean" => Some(schema),
        "array" => {
            let items = schema.get("items")?;
            matches!(
                items.get("type").and_then(Value::as_str),
                Some("string" | "boolean")
            )
            .then_some(items)
        }
        _ => None,
    }
}

/// Mutable twin of [`dynamic_enum_schema`], used only on owned served clones.
pub fn dynamic_enum_schema_mut(schema: &mut Value) -> Option<&mut Value> {
    let schema_type = schema.get("type")?.as_str()?.to_owned();
    match schema_type.as_str() {
        "string" | "boolean" => Some(schema),
        "array" => {
            let items = schema.get_mut("items")?;
            matches!(
                items.get("type").and_then(Value::as_str),
                Some("string" | "boolean")
            )
            .then_some(items)
        }
        _ => None,
    }
}

fn typed_tool_metadata_problems(index: usize, definition: &ToolDefinition) -> Vec<String> {
    use crate::connections::is_valid_connection_id;

    const MAX_REMOTE_TOOL_NAME_CHARS: usize = 128;
    const MAX_OPERATION_ID_CHARS: usize = 256;

    let mut problems = Vec::new();
    let validate_connection_id = |field: &str, connection_id: &str, problems: &mut Vec<String>| {
        if !is_valid_connection_id(connection_id) {
            problems.push(format!(
                "tools[{index}].{field} must be a stable URL-safe connection ID"
            ));
        }
    };
    let validate_remote_name = |field: &str, remote_tool_name: &str, problems: &mut Vec<String>| {
        let length = remote_tool_name.chars().count();
        if length == 0 || length > MAX_REMOTE_TOOL_NAME_CHARS {
            problems.push(format!(
                "tools[{index}].{field} must contain 1-{MAX_REMOTE_TOOL_NAME_CHARS} characters"
            ));
        }
    };

    if let Some(target) = &definition.target {
        match target {
            ToolTarget::Http {
                connection_id,
                mapping,
            } => {
                validate_connection_id("target.connection_id", connection_id, &mut problems);
                if let Err(error) = crate::connections::normalize_origin_relative_path(
                    "target.mapping.path_template",
                    &mapping.path_template,
                ) {
                    problems.push(format!(
                        "tools[{index}].target.mapping.path_template {}",
                        error.message
                    ));
                }
                if mapping != &definition.upstream {
                    problems.push(format!(
                        "tools[{index}].target.mapping must equal the legacy upstream mapping during migration"
                    ));
                }
                if mapping.is_mcp_proxy() {
                    problems.push(format!(
                        "tools[{index}].target HTTP mapping must not use the legacy MCP sentinel"
                    ));
                }
                if mapping.uses_composite_method() {
                    problems.push(format!(
                        "tools[{index}].target HTTP mapping must not use the COMPOSITE sentinel"
                    ));
                }
            }
            ToolTarget::Mcp {
                connection_id,
                remote_tool_name,
            } => {
                validate_connection_id("target.connection_id", connection_id, &mut problems);
                validate_remote_name("target.remote_tool_name", remote_tool_name, &mut problems);
                match definition.upstream.mcp_proxy_mapping() {
                    Some(mapping)
                        if mapping.server_name == *connection_id
                            && mapping.tool_name == *remote_tool_name => {}
                    _ => problems.push(format!(
                        "tools[{index}].target MCP metadata must equal the legacy MCP proxy mapping during migration"
                    )),
                }
            }
            ToolTarget::Composite { connection_id } => {
                validate_connection_id("target.connection_id", connection_id, &mut problems);
                if !definition.upstream.is_composite_sentinel() {
                    problems.push(format!(
                        "tools[{index}].target composite metadata requires the exact COMPOSITE upstream sentinel"
                    ));
                }
                if definition.composite.is_none() {
                    problems.push(format!(
                        "tools[{index}].target composite metadata requires a compiled composite mapping"
                    ));
                }
            }
        }
    }

    if definition.composite.is_some()
        && !matches!(&definition.target, Some(ToolTarget::Composite { .. }))
    {
        problems.push(format!(
            "tools[{index}].composite is only valid with a composite target"
        ));
    }
    if definition.upstream.uses_composite_method()
        && !matches!(&definition.target, Some(ToolTarget::Composite { .. }))
    {
        problems.push(format!(
            "tools[{index}].upstream COMPOSITE sentinel is only valid with a composite target"
        ));
    }
    if matches!(&definition.target, Some(ToolTarget::Composite { .. }))
        && !matches!(&definition.source, ToolSource::OpenApi { .. })
    {
        problems.push(format!(
            "tools[{index}].target composite metadata requires managed OpenAPI provenance"
        ));
    }

    match &definition.source {
        ToolSource::Manual | ToolSource::Legacy => {}
        ToolSource::OpenApi {
            connection_id,
            operation_id,
            ..
        } => {
            validate_connection_id("source.connection_id", connection_id, &mut problems);
            if !matches!(
                &definition.target,
                Some(ToolTarget::Http {
                    connection_id: target_connection_id,
                    ..
                }) | Some(ToolTarget::Composite {
                    connection_id: target_connection_id,
                }) if target_connection_id == connection_id
            ) {
                problems.push(format!(
                    "tools[{index}].source OpenAPI connection must equal an HTTP or composite target connection"
                ));
            }
            if operation_id.as_ref().is_some_and(|operation_id| {
                operation_id.is_empty() || operation_id.chars().count() > MAX_OPERATION_ID_CHARS
            }) {
                problems.push(format!(
                    "tools[{index}].source.operation_id must contain 1-{MAX_OPERATION_ID_CHARS} characters when present"
                ));
            }
            if matches!(&definition.target, Some(ToolTarget::Composite { .. }))
                && operation_id.is_some()
            {
                problems.push(format!(
                    "tools[{index}].source.operation_id must be absent for a composite tool"
                ));
            }
        }
        ToolSource::Mcp {
            connection_id,
            remote_tool_name,
        } => {
            validate_connection_id("source.connection_id", connection_id, &mut problems);
            validate_remote_name("source.remote_tool_name", remote_tool_name, &mut problems);
            if !matches!(
                &definition.target,
                Some(ToolTarget::Mcp {
                    connection_id: target_connection_id,
                    remote_tool_name: target_remote_tool_name,
                }) if target_connection_id == connection_id
                    && target_remote_tool_name == remote_tool_name
            ) {
                problems.push(format!(
                    "tools[{index}].source MCP metadata must equal the MCP target metadata"
                ));
            }
        }
    }

    problems
}

fn tool_mapping_schema_problems(index: usize, definition: &ToolDefinition) -> Vec<String> {
    let mut problems = Vec::new();
    let required_args = input_schema_required_args(&definition.input_schema);

    match path_template_placeholders(&definition.upstream.path_template) {
        Ok(placeholders) => {
            for arg_name in placeholders {
                if !required_args.contains(arg_name.as_str()) {
                    problems.push(format!(
                        "tool '{}' path_template placeholder '{}' must be listed in input_json_schema.required",
                        definition.name, arg_name
                    ));
                }
                if let Some(problem) = mapped_arg_schema_problem(definition, "path", &arg_name) {
                    problems.push(problem);
                }
            }
        }
        Err(problem) => problems.push(format!("tools[{index}].upstream.path_template {problem}")),
    }

    for mapping in &definition.upstream.query_params {
        if mapping.required && !required_args.contains(mapping.arg_name.as_str()) {
            problems.push(format!(
                "tool '{}' required query argument '{}' must be listed in input_json_schema.required",
                definition.name, mapping.arg_name
            ));
        }
        if let Some(problem) = mapped_arg_schema_problem(definition, "query", &mapping.arg_name) {
            problems.push(problem);
        }
    }

    problems
}

fn path_template_placeholders(path_template: &str) -> Result<Vec<String>, String> {
    if !path_template.starts_with('/') {
        return Err("must start with '/'".to_owned());
    }
    if path_template.contains('?') || path_template.contains('#') {
        return Err("must not include query strings or fragments".to_owned());
    }

    let mut placeholders = Vec::new();
    let mut rest = path_template;
    loop {
        if let Some(close) = rest.find('}') {
            match rest.find('{') {
                Some(open) if open < close => {}
                _ => return Err("contains an unmatched '}'".to_owned()),
            }
        }

        let Some(open) = rest.find('{') else {
            break;
        };

        let after_open = &rest[open + 1..];
        let Some(close) = after_open.find('}') else {
            return Err("contains an unmatched '{'".to_owned());
        };
        let arg_name = &after_open[..close];
        if arg_name.is_empty() {
            return Err("contains an empty placeholder".to_owned());
        }
        if arg_name.contains('{') || arg_name.contains('}') {
            return Err(format!("placeholder '{arg_name}' contains a brace"));
        }

        placeholders.push(arg_name.to_owned());
        rest = &after_open[close + 1..];
    }

    Ok(placeholders)
}

fn input_schema_required_args(schema: &Value) -> BTreeSet<&str> {
    schema
        .get("required")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect()
}

fn input_schema_property<'a>(schema: &'a Value, arg_name: &str) -> Option<&'a Value> {
    schema.get("properties")?.as_object()?.get(arg_name)
}

fn mapped_arg_schema_problem(
    definition: &ToolDefinition,
    location: &'static str,
    arg_name: &str,
) -> Option<String> {
    let Some(schema) = input_schema_property(&definition.input_schema, arg_name) else {
        return Some(format!(
            "tool '{}' {location} argument '{}' must be declared in input_json_schema.properties",
            definition.name, arg_name
        ));
    };

    if is_scalar_constrained_schema(schema) {
        None
    } else {
        Some(format!(
            "tool '{}' {location} argument '{}' must be constrained to scalar JSON Schema types",
            definition.name, arg_name
        ))
    }
}

fn is_scalar_constrained_schema(schema: &Value) -> bool {
    match schema.get("type") {
        Some(Value::String(schema_type)) => is_scalar_json_schema_type(schema_type),
        Some(Value::Array(schema_types)) => {
            !schema_types.is_empty()
                && schema_types
                    .iter()
                    .all(|schema_type| schema_type.as_str().is_some_and(is_scalar_json_schema_type))
        }
        _ => false,
    }
}

fn is_scalar_json_schema_type(schema_type: &str) -> bool {
    matches!(schema_type, "string" | "number" | "integer" | "boolean")
}

fn input_schema_precheck_problem(
    schema: &Value,
    budget: &mut InputSchemaPrecheckBudget,
) -> Option<String> {
    let mut stack = vec![(schema, SchemaPrecheckContext::Schema)];
    let mut local_references = Vec::new();
    let mut anchors = BTreeMap::new();

    while let Some((value, context)) = stack.pop() {
        if let Some(problem) = budget.consume_node() {
            return Some(problem);
        }

        if context == SchemaPrecheckContext::Schema {
            for keyword in ["$ref", "$dynamicRef"] {
                if let Some(reference) = value.get(keyword).and_then(Value::as_str) {
                    if reference.starts_with('#') {
                        local_references.push(reference);
                    }
                }
            }
            if let Some(problem) = record_schema_anchors(value, &mut anchors) {
                return Some(problem);
            }
        }

        match value {
            Value::Array(values) => stack.extend(values.iter().map(|value| (value, context))),
            Value::Object(object) => stack.extend(
                object
                    .iter()
                    .map(|(keyword, value)| (value, schema_child_context(context, keyword))),
            ),
            _ => {}
        }
    }

    if numbers_exceed_exact_comparison_budget(schema) {
        return Some(exact_comparison_budget_problem());
    }

    for reference in local_references {
        if let Some(problem) = local_reference_chain_problem(schema, &anchors, reference, budget) {
            return Some(problem);
        }
    }

    None
}

/// The problem reported for a schema whose numbers exceed the exact
/// comparison budget.
///
/// With exact comparison, jsonschema parses a schema's numeric limits when it
/// compiles, at a cost that grows with the square of their digits, so every
/// compile of a schema that did not ship with the gateway checks
/// [`numbers_exceed_exact_comparison_budget`] first and reports this instead.
/// An overlay document is checked the same way before the shipped overlay
/// schema compares its numbers.
pub fn exact_comparison_budget_problem() -> String {
    format!(
        "contains numbers that would cost more to compare exactly than one {MAX_EXACT_NUMBER_DIGITS}-digit number"
    )
}

/// Whether comparing every number in `value` exactly would cost more than one
/// `MAX_EXACT_NUMBER_DIGITS`-digit number. Tool arguments and served schemas
/// reach this without a depth bound, so it walks with an explicit stack.
pub fn numbers_exceed_exact_comparison_budget(value: &Value) -> bool {
    let budget = MAX_EXACT_NUMBER_DIGITS * MAX_EXACT_NUMBER_DIGITS;
    let mut spent = 0_u64;
    let mut stack = vec![value];
    while let Some(value) = stack.pop() {
        match value {
            Value::Number(number) => {
                let digits = number_digit_span(number.as_str());
                if digits > MAX_UNMETERED_NUMBER_DIGITS {
                    spent = spent.saturating_add(digits.saturating_mul(digits));
                    if spent > budget {
                        return true;
                    }
                }
            }
            Value::Array(values) => stack.extend(values),
            Value::Object(object) => stack.extend(object.values()),
            Value::Null | Value::Bool(_) | Value::String(_) => {}
        }
    }
    false
}

/// Decimal digits a JSON number literal spans: every mantissa digit plus the
/// magnitude of its exponent, so `1e400` spans 401 and `-0.05` spans 3.
pub fn number_digit_span(literal: &str) -> u64 {
    let (mantissa, exponent) = literal.split_once(['e', 'E']).unwrap_or((literal, ""));
    let mantissa_digits = mantissa
        .bytes()
        .filter(|byte| byte.is_ascii_digit())
        .count();
    let exponent_magnitude =
        exponent
            .bytes()
            .filter(|byte| byte.is_ascii_digit())
            .fold(0_u64, |magnitude, digit| {
                magnitude
                    .saturating_mul(10)
                    .saturating_add(u64::from(digit - b'0'))
            });
    u64::try_from(mantissa_digits)
        .unwrap_or(u64::MAX)
        .saturating_add(exponent_magnitude)
}

/// Two-level node budget for the input-schema precheck.
///
/// One ceiling cannot serve both roles: the per-definition ceiling bounds the
/// traversal a single hostile schema can force, while the registry ceiling
/// bounds the merged set. Charging every definition against a single ceiling
/// made a catalog's publishability depend on how many tools preceded it.
struct InputSchemaPrecheckBudget {
    definition_remaining: usize,
    registry_remaining: usize,
}

impl InputSchemaPrecheckBudget {
    fn new() -> Self {
        Self {
            definition_remaining: MAX_INPUT_SCHEMA_PRECHECK_NODES,
            registry_remaining: MAX_REGISTRY_INPUT_SCHEMA_PRECHECK_NODES,
        }
    }

    fn begin_definition(&mut self) {
        self.definition_remaining = MAX_INPUT_SCHEMA_PRECHECK_NODES;
    }

    fn consume_node(&mut self) -> Option<String> {
        let Some(definition_remaining) = self.definition_remaining.checked_sub(1) else {
            return Some(format!(
                "precheck node budget exceeds {MAX_INPUT_SCHEMA_PRECHECK_NODES} nodes for one tool"
            ));
        };
        let Some(registry_remaining) = self.registry_remaining.checked_sub(1) else {
            return Some(format!(
                "precheck node budget exceeds {MAX_REGISTRY_INPUT_SCHEMA_PRECHECK_NODES} nodes across the tool registry"
            ));
        };
        self.definition_remaining = definition_remaining;
        self.registry_remaining = registry_remaining;
        None
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SchemaPrecheckContext {
    Schema,
    SchemaMap,
    Literal,
}

fn local_reference_chain_problem(
    root: &Value,
    anchors: &BTreeMap<String, &Value>,
    first_reference: &str,
    budget: &mut InputSchemaPrecheckBudget,
) -> Option<String> {
    let mut reference = first_reference.to_owned();
    let mut seen_references = BTreeSet::new();
    let mut depth = 1;

    loop {
        if let Some(problem) = budget.consume_node() {
            return Some(format!(
                "{problem} while following local reference {reference}"
            ));
        }
        if depth > MAX_INPUT_SCHEMA_REFERENCE_DEPTH {
            return Some(format!(
                "reference depth exceeds {MAX_INPUT_SCHEMA_REFERENCE_DEPTH} at {reference}"
            ));
        }
        if !seen_references.insert(reference.to_owned()) {
            return Some(format!("contains circular local reference at {reference}"));
        }

        let target = match resolve_local_reference_target(root, anchors, &reference) {
            Ok(Some(target)) => target,
            Ok(None) => return None,
            Err(problem) => return Some(problem),
        };
        let next_reference = local_reference_from_schema(target)?;

        reference = next_reference.to_owned();
        depth += 1;
    }
}

fn resolve_local_reference_target<'a>(
    root: &'a Value,
    anchors: &BTreeMap<String, &'a Value>,
    reference: &str,
) -> Result<Option<&'a Value>, String> {
    let Some(fragment) = reference.strip_prefix('#') else {
        return Ok(None);
    };
    let Ok(decoded_fragment) = percent_decode_str(fragment).decode_utf8() else {
        return Ok(None);
    };
    if decoded_fragment.is_empty() {
        return Ok(Some(root));
    }
    if decoded_fragment.starts_with('/') {
        return Ok(root.pointer(decoded_fragment.as_ref()));
    }

    Ok(anchors.get(decoded_fragment.as_ref()).copied())
}

fn local_reference_from_schema(value: &Value) -> Option<&str> {
    ["$ref", "$dynamicRef"]
        .into_iter()
        .filter_map(|keyword| value.get(keyword).and_then(Value::as_str))
        .find(|reference| reference.starts_with('#'))
}

fn record_schema_anchors<'a>(
    value: &'a Value,
    anchors: &mut BTreeMap<String, &'a Value>,
) -> Option<String> {
    for keyword in ["$anchor", "$dynamicAnchor"] {
        if let Some(anchor) = value.get(keyword).and_then(Value::as_str) {
            if anchors.insert(anchor.to_owned(), value).is_some() {
                return Some(format!(
                    "contains duplicate local schema anchor '{anchor}', which is not supported by the precheck resolver"
                ));
            }
        }
    }
    None
}

fn schema_child_context(
    parent_context: SchemaPrecheckContext,
    keyword: &str,
) -> SchemaPrecheckContext {
    match parent_context {
        SchemaPrecheckContext::Literal => SchemaPrecheckContext::Literal,
        SchemaPrecheckContext::SchemaMap => SchemaPrecheckContext::Schema,
        SchemaPrecheckContext::Schema => match keyword {
            "$defs" | "definitions" | "properties" | "patternProperties" | "dependentSchemas" => {
                SchemaPrecheckContext::SchemaMap
            }
            "const" | "default" | "enum" | "examples" => SchemaPrecheckContext::Literal,
            _ => SchemaPrecheckContext::Schema,
        },
    }
}

fn is_known_http_method(method: &str) -> bool {
    matches!(
        method,
        "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS" | "TRACE" | "CONNECT"
    ) && method.parse::<Method>().is_ok()
}
