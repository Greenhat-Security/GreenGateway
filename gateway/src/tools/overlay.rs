//! Per-Connection OpenAPI overlays (issue #360, through PR 4).
//!
//! An overlay is a declarative document stored beside a Connection's OpenAPI
//! catalog. It is compiled into the same `ToolDefinition`s the catalog
//! already stores, digests, replays, and serves, so nothing downstream of
//! `publish_candidate` has to know it exists. This revision compiles:
//!
//! - `tools.<generated>.rename` -- the served name (tools/list, inventory,
//!   audit, and the policy file), while every overlay-internal reference
//!   keeps the generated name;
//! - `tools.<generated>.description` -- replaces the operation summary;
//! - `tools.<generated>.visibility` -- `composite_only` hides a tool from
//!   `tools/list` and `tools/call`;
//! - `tools.<generated>.parameters.<p>.{title,description,shape}` -- rewrites
//!   or replaces one top-level property of the generated input schema;
//! - reusable `shapes`, request/response codecs, and
//!   `tools.<generated>.response` / `defaults.response_root` -- compile an
//!   ergonomic agent schema plus deterministic wire and response mappings;
//! - `defaults.body_mode` -- `body_args_json` (the default for overlaid
//!   tools) omits path and query arguments from the JSON body;
//! - `defaults.disambiguation` -- when two properties of one tool carry the
//!   same human label (resolved label source, document `title`, or first
//!   `description` line), both descriptions are rewritten through a fixed
//!   template that names the field and its static options.
//!
//! Dynamic enum and label sources compile to stable bindings; their current
//! values never enter the stored catalog definition. Composite tools compile
//! into synthetic catalog definitions whose step references retain
//! generated-name authority and whose enum sources bind their top-level
//! agent properties in the same fail-closed way as generated tools.
//!
//! Two rules are load-bearing and pinned by tests below:
//!
//! - **"Overlaid" means named under `tools.*`.** A tool the overlay does not
//!   name keeps its generated definition byte-for-byte, `whole_args_json`
//!   body included, even when the catalog has an overlay.
//! - **An overlay can only narrow.** Method and path template are never
//!   touched; a rename may not collide with a generated name of the
//!   catalog, another registry lane, or a live policy entry it did not
//!   already own, because tool policy is keyed by bare served name
//!   (`runtime.rs` `lookup_tool`, `rbac.rs` `policy.tools.get`) and a rename
//!   onto a granted name would adopt that grant.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    sync::LazyLock,
};

use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::connections::model::{
    normalize_origin_relative_path, MAX_CATALOG_ENTRIES, MAX_MANAGED_OPENAPI_CATALOG_BYTES,
};

use super::{
    codecs::{Codec, DecimalWireEncoding},
    composite::{
        CompositeBinding, CompositeLimits, CompositeMapping, CompositeStep,
        MAX_COMPOSITE_ITERATIONS, MAX_COMPOSITE_JSON_DEPTH, MAX_COMPOSITE_RESULT_PROPERTIES,
        MAX_COMPOSITE_STEPS,
    },
    definitions::{
        dynamic_enum_schema, dynamic_enum_schema_mut, BodyMappingMode, EnumBinding,
        HttpToolMapping, QueryParamMapping, ToolAnnotations, ToolDefinition, ToolSource,
        ToolTarget, ToolVisibility,
    },
    openapi::{OpenApiToolBinding, OpenApiToolGeneration, OpenApiToolSecuritySelection},
    selector::{
        resolve_pointer_schemas, select_object_schemas, JsonPointer, SchemaResolution, Selector,
    },
    transforms::{
        self, AgentProperty, ParameterShape, ResponseBinding, ToolTransform, WireBinding,
        WireSource,
    },
};

/// The overlay document revision this build authors and accepts.
pub const OVERLAY_SCHEMA_VERSION: &str = "0.1.0";
/// Upper bound on the serialised overlay (section 1.2 "Budgets").
pub const MAX_OVERLAY_BYTES: usize = 1_048_576;
/// Per-entry limit the catalog store enforces on `definition_json`
/// (`connections/store.rs` `MAX_OPENAPI_CATALOG_ENTRY_BYTES`); checked here
/// so an overlay that grows a description past it fails at PUT with the
/// tool named, not at the store with a generic validation error.
const MAX_COMPILED_DEFINITION_BYTES: usize = 262_144;
/// Static enum values rendered into a qualified description before the
/// list is elided with `…`.
const MAX_OPTIONS_SHOWN: usize = 16;
/// Characters of one rendered option value; longer values are truncated
/// with `…`. Document enum values are already served verbatim in the
/// schema, so this bounds description growth rather than exposure.
const MAX_OPTION_CHARS: usize = 64;
/// Schema nodes inspected while proving that an agent fragment carries no
/// unsupported `format` assertion, including nested applicator schemas.
const MAX_AGENT_FRAGMENT_SCHEMA_NODES: usize = 4_096;
const AGENT_FRAGMENT_DIALECT: &str = "https://json-schema.org/draft/2020-12/schema";
/// Maximum schema nodes inspected while proving one JSON pointer. OpenAPI
/// schemas are graphs: a small `anyOf`/`oneOf` DAG can otherwise duplicate
/// the same `$ref` exponentially before the depth limit is reached.
const MAX_SCHEMA_POINTER_VISITS: usize = 4_096;
const MAX_SOURCE_LABEL_BYTES: usize = 64;
const MAX_SERVED_ENUM_DESCRIPTION_BYTES: usize = 4_096;
const SOURCE_PATH_SEGMENT_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'.')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'`')
    .add(b'{')
    .add(b'}')
    .add(b'/')
    .add(b'\\');
const DEFAULT_DISAMBIGUATION_TEMPLATE: &str = "{label} (field `{name}`{options})";
const OVERLAY_SCHEMA_JSON: &str =
    include_str!("../../../docs/schemas/connection-overlay.v0.schema.json");

static OVERLAY_SCHEMA_VALIDATOR: LazyLock<jsonschema::Validator> = LazyLock::new(|| {
    let schema = serde_json::from_str(OVERLAY_SCHEMA_JSON)
        .expect("embedded connection overlay schema should be valid JSON");
    jsonschema::validator_for(&schema).expect("embedded connection overlay schema should compile")
});

// ---------------------------------------------------------------------------
// The authoring model (mirrors docs/schemas/connection-overlay.v0.schema.json;
// pinned in lockstep by the tests at the bottom of this file)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OverlayDocument {
    pub schema_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub defaults: Option<OverlayDefaults>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub shapes: BTreeMap<String, Shape>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub enum_sources: BTreeMap<String, EnumSource>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub label_sources: BTreeMap<String, LabelSource>,
    /// Keyed by the GENERATED tool name (the document's `operationId`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub tools: BTreeMap<String, ToolOverlay>,
    /// Keyed by the served composite tool name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub composites: BTreeMap<String, CompositeOverlay>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompositeOverlay {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<ToolAnnotations>,
    pub input: CompositeInput,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub parameters: BTreeMap<String, CompositeParameterOverlay>,
    pub steps: Vec<CompositeStep>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<BTreeMap<String, CompositeBinding>>,
    #[serde(default, skip_serializing_if = "CompositeLimits::is_default")]
    pub limits: CompositeLimits,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompositeInput {
    pub properties: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompositeParameterOverlay {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enum_source: Option<String>,
}

impl OverlayDocument {
    /// Whether applying this overlay can introduce a credentialed read whose
    /// path was not declared by the OpenAPI document. Admin authorization uses
    /// this typed predicate to require the secrets-write permission.
    pub fn has_raw_path_sources(&self) -> bool {
        self.enum_sources
            .values()
            .any(|source| source.request.path.is_some())
            || self
                .label_sources
                .values()
                .any(|source| source.request.path.is_some())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OverlayDefaults {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disambiguation: Option<DisambiguationConfig>,
    /// Body serialisation for overlaid tools only. Default `body_args_json`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_mode: Option<BodyMappingMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_root: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DisambiguationConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<DisambiguationMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label_from: Option<Vec<LabelOrigin>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DisambiguationMode {
    Off,
    #[default]
    QualifyCollidingLabels,
}

/// Where a property's human label is read from, in priority order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LabelOrigin {
    /// The tool's compile-time `labels_from` source.
    LabelSource,
    Title,
    Description,
}

impl LabelOrigin {
    const DEFAULT_ORDER: [Self; 3] = [Self::LabelSource, Self::Title, Self::Description];
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ToolOverlay {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rename: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visibility: Option<ToolVisibility>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<ToolAnnotations>,
    /// Compile-time labels keyed by this tool's generated property names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub labels_from: Option<String>,
    /// Keyed by a top-level property name of the generated input schema.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub parameters: BTreeMap<String, ParameterOverlay>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response: Option<ResponseOverlay>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ParameterOverlay {
    /// Replaces the property description and is exempt from disambiguation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shape: Option<ShapeOrUse>,
    /// Overlay-local dynamic enum source. Values are never persisted in the
    /// compiled definition; only a stable [`EnumBinding`] is stored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enum_source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ShapeOrUse {
    Inline(Shape),
    Use(ShapeReference),
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ShapeReference {
    #[serde(rename = "$use")]
    pub shape_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Shape {
    pub agent: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<Vec<String>>,
    pub wire: BTreeMap<String, OverlayWireBinding>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub response: BTreeMap<String, OverlayResponseBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum OverlayWireBinding {
    From {
        from: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        codec: Option<CodecChain>,
    },
    Const {
        r#const: Value,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        codec: Option<CodecChain>,
    },
}

impl OverlayWireBinding {
    fn codecs(&self) -> Vec<Codec> {
        match self {
            Self::From { codec, .. } | Self::Const { codec, .. } => {
                codec.as_ref().map(CodecChain::to_vec).unwrap_or_default()
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OverlayResponseBinding {
    pub from: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub codec: Option<CodecChain>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum CodecChain {
    One(Codec),
    Many(Vec<Codec>),
}

impl CodecChain {
    fn to_vec(&self) -> Vec<Codec> {
        match self {
            Self::One(codec) => vec![codec.clone()],
            Self::Many(codecs) => codecs.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseOverlay {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, ShapeOrUse>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub query: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnumSource {
    pub request: SourceRequest,
    pub select: EnumSourceSelection,
    #[serde(default, skip_serializing_if = "is_default_source_cache")]
    pub cache: SourceCache,
    #[serde(default, skip_serializing_if = "is_default_source_limits")]
    pub limits: SourceLimits,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnumSourceSelection {
    pub items: String,
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LabelSource {
    pub request: SourceRequest,
    pub select: LabelSourceSelection,
    #[serde(default, skip_serializing_if = "is_default_source_limits")]
    pub limits: SourceLimits,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LabelSourceSelection {
    pub items: String,
    pub key: String,
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceCache {
    #[serde(default = "default_source_ttl_secs")]
    pub ttl_secs: u64,
    #[serde(default = "default_source_max_stale_secs")]
    pub max_stale_secs: u64,
}

impl Default for SourceCache {
    fn default() -> Self {
        Self {
            ttl_secs: default_source_ttl_secs(),
            max_stale_secs: default_source_max_stale_secs(),
        }
    }
}

fn default_source_ttl_secs() -> u64 {
    300
}

fn default_source_max_stale_secs() -> u64 {
    604_800
}

fn is_default_source_cache(value: &SourceCache) -> bool {
    value == &SourceCache::default()
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceLimits {
    #[serde(default = "default_source_min_items")]
    pub min_items: usize,
    #[serde(default = "default_source_max_items")]
    pub max_items: usize,
    #[serde(default = "default_source_max_value_bytes")]
    pub max_value_bytes: usize,
    #[serde(default = "default_source_max_label_bytes")]
    pub max_label_bytes: usize,
    #[serde(default = "default_source_max_response_bytes")]
    pub max_response_bytes: usize,
}

impl Default for SourceLimits {
    fn default() -> Self {
        Self {
            min_items: default_source_min_items(),
            max_items: default_source_max_items(),
            max_value_bytes: default_source_max_value_bytes(),
            max_label_bytes: default_source_max_label_bytes(),
            max_response_bytes: default_source_max_response_bytes(),
        }
    }
}

fn default_source_min_items() -> usize {
    1
}

fn default_source_max_items() -> usize {
    256
}

fn default_source_max_value_bytes() -> usize {
    256
}

fn default_source_max_label_bytes() -> usize {
    MAX_SOURCE_LABEL_BYTES
}

fn default_source_max_response_bytes() -> usize {
    1_048_576
}

fn is_default_source_limits(value: &SourceLimits) -> bool {
    value == &SourceLimits::default()
}

/// A normalized, catalog-checked source plan. It is safe for the resolver to
/// execute as a GET: raw paths have passed the Connection path normalizer and
/// generated-tool requests have been resolved to a GET mapping.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OverlaySourcePlan {
    pub enum_sources: BTreeMap<String, EnumSourcePlan>,
    pub label_sources: BTreeMap<String, LabelSourcePlan>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnumSourcePlan {
    pub id: String,
    pub source_digest: String,
    pub request: SourceRequestPlan,
    pub select: EnumSourceSelectionPlan,
    pub cache: SourceCache,
    pub limits: SourceLimits,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabelSourcePlan {
    pub id: String,
    pub source_digest: String,
    pub request: SourceRequestPlan,
    pub select: LabelSourceSelectionPlan,
    pub limits: SourceLimits,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceRequestPlan {
    /// Present for a request derived from one generated OpenAPI GET tool.
    /// Authoring references always use the generated name, but this normalized
    /// value is the served name because tool policy is keyed after rename.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    /// Fully rendered origin-relative path and deterministic query string.
    /// The resolver can authorize and fetch this value without compiler state.
    pub path_and_query: String,
    pub path_template: String,
    pub query: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub query_params: Vec<QueryParamMapping>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnumSourceSelectionPlan {
    pub items: Selector,
    pub value: String,
    pub label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabelSourceSelectionPlan {
    pub items: Selector,
    pub key: String,
    pub label: String,
}

/// Successful synchronous resolutions supplied to the compiler. Missing enum
/// entries are allowed only when the admin caller explicitly selected the
/// fail-closed unresolved mode; missing label entries always reject compile.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ResolvedOverlaySources {
    pub enum_sources: BTreeMap<String, ResolvedEnumSource>,
    pub label_sources: BTreeMap<String, ResolvedLabelSource>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedEnumSource {
    pub values: Vec<Value>,
    pub labels: Option<Vec<String>>,
    pub resolved_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedLabelSource {
    pub labels: BTreeMap<String, String>,
    pub resolved_at: String,
}

// ---------------------------------------------------------------------------
// Problems, warnings, reports
// ---------------------------------------------------------------------------

/// One rejection, naming the JSON path in the overlay it applies to. The
/// admin API returns these as `422 { problems: [...] }`; nothing is stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OverlayProblem {
    pub path: String,
    pub message: String,
}

/// One non-blocking observation reported beside a successful compile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OverlayWarning {
    pub path: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlayError {
    pub problems: Vec<OverlayProblem>,
}

impl OverlayError {
    fn one(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            problems: vec![OverlayProblem {
                path: path.into(),
                message: message.into(),
            }],
        }
    }
}

impl fmt::Display for OverlayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "connection overlay rejected with {} problem(s): ",
            self.problems.len()
        )?;
        for (index, problem) in self.problems.iter().enumerate() {
            if index > 0 {
                formatter.write_str("; ")?;
            }
            write!(formatter, "{}: {}", problem.path, problem.message)?;
        }
        Ok(())
    }
}

impl Error for OverlayError {}

/// What the compiler did to one overlaid tool, so a PUT or preview response
/// can say plainly which labels it found and where a no-op came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OverlayToolReport {
    pub generated_name: String,
    pub served_name: String,
    pub visibility: ToolVisibility,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_mode: Option<BodyMappingMode>,
    /// Properties for which a label was found, by origin.
    pub labels_found: usize,
    pub labels_from_source: usize,
    pub labels_from_title: usize,
    pub labels_from_description: usize,
    /// Properties whose description was rewritten because their label
    /// collided with another property's.
    pub qualified_properties: Vec<String>,
    pub label_summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OverlayCompositeReport {
    pub name: String,
    pub steps_max: usize,
    pub policy_entry_present: bool,
}

fn label_summary(
    labels_found: usize,
    labels_from_source: usize,
    labels_from_title: usize,
    labels_from_description: usize,
    qualified: usize,
) -> String {
    if labels_found == 0 {
        "0 labels matched the configured label sources; disambiguation is a \
             no-op for this tool"
            .to_owned()
    } else {
        format!(
            "{} labels found (source: {}, title: {}, description: {}); {} qualified",
            labels_found, labels_from_source, labels_from_title, labels_from_description, qualified
        )
    }
}

/// Names the compiler must not let a rename adopt (section 1.2 "Names").
#[derive(Debug, Clone, Default)]
pub struct OverlayCompileContext {
    /// `tools.<name>` keys of the live policy file (`runtime.rs` `lookup_tool`).
    pub policy_tool_names: BTreeSet<String>,
    /// Tool names published by the local file and MCP registry lanes
    /// (`definitions.rs` duplicate-name check covers them at install; this
    /// check reports them at PUT with the overlay path named).
    pub other_lane_tool_names: BTreeSet<String>,
    /// Served name -> generated name ownership in the stored overlay
    /// revision being replaced. A policy entry is safe to retain only when
    /// the same generated operation still owns that served name; tracking a
    /// set here would let a different operation adopt an existing grant.
    pub prior_overlay_name_owners: BTreeMap<String, String>,
}

/// The result of applying an overlay to a bound catalog: the binding
/// `publish_candidate` stores as-is, plus what to tell the operator.
#[derive(Debug, Clone, PartialEq)]
pub struct CompiledCatalog {
    pub binding: OpenApiToolBinding,
    /// Normalized source configuration used by the synchronous resolver and
    /// the timer-driven enum refresher. Current values are not stored here.
    pub source_plan: OverlaySourcePlan,
    /// generated name -> served name, for every renamed tool.
    pub renames: BTreeMap<String, String>,
    pub tools: Vec<OverlayToolReport>,
    pub composites: Vec<OverlayCompositeReport>,
    pub warnings: Vec<OverlayWarning>,
}

// ---------------------------------------------------------------------------
// validate: schema + model + catalog-free semantics
// ---------------------------------------------------------------------------

/// Validate an overlay document against the published JSON Schema, the Rust
/// model, and the semantic checks that need no catalog. Returns every
/// problem found, not the first.
pub fn validate(document: &Value) -> Result<OverlayDocument, OverlayError> {
    let encoded = serde_json::to_vec(document)
        .map_err(|error| OverlayError::one("/", format!("overlay is not JSON: {error}")))?;
    if encoded.len() > MAX_OVERLAY_BYTES {
        return Err(OverlayError::one(
            "/",
            format!(
                "overlay serialises to {} bytes; the limit is {MAX_OVERLAY_BYTES}",
                encoded.len()
            ),
        ));
    }

    let schema_problems = OVERLAY_SCHEMA_VALIDATOR
        .iter_errors(document)
        .map(|error| OverlayProblem {
            path: pointer_or_root(&error.instance_path().to_string()),
            message: error.to_string(),
        })
        .collect::<Vec<_>>();
    if !schema_problems.is_empty() {
        return Err(OverlayError {
            problems: schema_problems,
        });
    }

    let overlay: OverlayDocument = serde_json::from_value(document.clone()).map_err(|error| {
        OverlayError::one(
            "/",
            format!("overlay does not match the Rust model: {error}"),
        )
    })?;

    let problems = document_problems(&overlay);
    if !problems.is_empty() {
        return Err(OverlayError { problems });
    }
    Ok(overlay)
}

fn pointer_or_root(pointer: &str) -> String {
    if pointer.is_empty() {
        "/".to_owned()
    } else {
        pointer.to_owned()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TemplatePlaceholder {
    Label,
    Name,
    Options,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TemplateToken<'a> {
    Literal(&'a str),
    Placeholder(TemplatePlaceholder),
}

/// Split a disambiguation template into literal text and the three documented
/// placeholders. Braces are syntax, not escapable literal characters: accepting
/// a stray or nested brace would make a string such as `{{name}}` look like it
/// contains the mandatory placeholder while rendering it as something else.
fn tokenize_template(template: &str) -> Result<Vec<TemplateToken<'_>>, String> {
    let mut tokens = Vec::new();
    let mut cursor = 0;

    while cursor < template.len() {
        let Some((offset, brace)) = template[cursor..]
            .char_indices()
            .find(|(_, character)| matches!(character, '{' | '}'))
        else {
            tokens.push(TemplateToken::Literal(&template[cursor..]));
            break;
        };
        let brace_index = cursor + offset;
        if brace_index > cursor {
            tokens.push(TemplateToken::Literal(&template[cursor..brace_index]));
        }
        if brace == '}' {
            return Err(format!(
                "unexpected closing brace at byte {brace_index}; only {{label}}, {{name}}, and \
                 {{options}} are valid"
            ));
        }

        let placeholder_start = brace_index + 1;
        let Some((end_offset, terminator)) = template[placeholder_start..]
            .char_indices()
            .find(|(_, character)| matches!(character, '{' | '}'))
        else {
            return Err(format!(
                "unclosed placeholder starting at byte {brace_index}; only {{label}}, {{name}}, \
                 and {{options}} are valid"
            ));
        };
        if terminator == '{' {
            return Err(format!(
                "nested opening brace at byte {}; placeholders cannot be nested",
                placeholder_start + end_offset
            ));
        }

        let placeholder_end = placeholder_start + end_offset;
        let placeholder = match &template[placeholder_start..placeholder_end] {
            "label" => TemplatePlaceholder::Label,
            "name" => TemplatePlaceholder::Name,
            "options" => TemplatePlaceholder::Options,
            unknown => {
                return Err(format!(
                    "unknown placeholder '{{{unknown}}}' at byte {brace_index}; only {{label}}, \
                     {{name}}, and {{options}} are valid"
                ));
            }
        };
        tokens.push(TemplateToken::Placeholder(placeholder));
        cursor = placeholder_end + 1;
    }

    Ok(tokens)
}

/// Semantic checks that need only the document: the template can qualify,
/// rename targets are unique, and no `tools.*` key is a rename target.
fn document_problems(overlay: &OverlayDocument) -> Vec<OverlayProblem> {
    let mut problems = Vec::new();

    // The persisted row is replayed by this compiler version. Accepting a
    // future patch version here would let PUT store a document that replay
    // correctly refuses after restart, poisoning every later operation on
    // the Connection.
    if overlay.schema_version != OVERLAY_SCHEMA_VERSION {
        problems.push(OverlayProblem {
            path: "/schema_version".to_owned(),
            message: format!(
                "unsupported overlay schema version '{}'; this gateway accepts exactly \
                 {OVERLAY_SCHEMA_VERSION}",
                overlay.schema_version
            ),
        });
    }

    for (source_id, source) in &overlay.enum_sources {
        validate_source_request(
            &format!("/enum_sources/{source_id}/request"),
            &source.request,
            &mut problems,
        );
        validate_source_limits(
            &format!("/enum_sources/{source_id}/limits"),
            &source.limits,
            &mut problems,
        );
        if let Err(error) = Selector::parse(&source.select.items) {
            problems.push(OverlayProblem {
                path: format!("/enum_sources/{source_id}/select/items"),
                message: format!("invalid selector: {error}"),
            });
        }
    }
    for (source_id, source) in &overlay.label_sources {
        validate_source_request(
            &format!("/label_sources/{source_id}/request"),
            &source.request,
            &mut problems,
        );
        validate_source_limits(
            &format!("/label_sources/{source_id}/limits"),
            &source.limits,
            &mut problems,
        );
        if let Err(error) = Selector::parse(&source.select.items) {
            problems.push(OverlayProblem {
                path: format!("/label_sources/{source_id}/select/items"),
                message: format!("invalid selector: {error}"),
            });
        }
    }

    if let Some(template) = overlay
        .defaults
        .as_ref()
        .and_then(|defaults| defaults.disambiguation.as_ref())
        .and_then(|config| config.template.as_deref())
    {
        match tokenize_template(template) {
            Err(message) => problems.push(OverlayProblem {
                path: "/defaults/disambiguation/template".to_owned(),
                message: format!("invalid template syntax: {message}"),
            }),
            Ok(tokens)
                if !tokens.iter().any(|token| {
                    *token == TemplateToken::Placeholder(TemplatePlaceholder::Name)
                }) =>
            {
                problems.push(OverlayProblem {
                    path: "/defaults/disambiguation/template".to_owned(),
                    message: "template must contain {name}; without the field name two colliding \
                              labels stay indistinguishable"
                        .to_owned(),
                });
            }
            Ok(_) => {}
        }
    }

    let mut rename_owner: BTreeMap<&str, &str> = BTreeMap::new();
    for (generated_name, tool) in &overlay.tools {
        if let Some(source_id) = tool.labels_from.as_deref() {
            if !overlay.label_sources.contains_key(source_id) {
                problems.push(OverlayProblem {
                    path: format!("/tools/{generated_name}/labels_from"),
                    message: format!("unknown label source '{source_id}'"),
                });
            }
        }
        for (property, parameter) in &tool.parameters {
            if let Some(source_id) = parameter.enum_source.as_deref() {
                if !overlay.enum_sources.contains_key(source_id) {
                    problems.push(OverlayProblem {
                        path: format!("/tools/{generated_name}/parameters/{property}/enum_source"),
                        message: format!("unknown enum source '{source_id}'"),
                    });
                }
            }
        }
        let Some(target) = tool.rename.as_deref() else {
            continue;
        };
        if target == generated_name {
            problems.push(OverlayProblem {
                path: format!("/tools/{generated_name}/rename"),
                message: "rename target equals the generated name; omit rename".to_owned(),
            });
            continue;
        }
        if let Some(first) = rename_owner.insert(target, generated_name) {
            problems.push(OverlayProblem {
                path: format!("/tools/{generated_name}/rename"),
                message: format!("rename target '{target}' is already used by tools.{first}"),
            });
        }
    }
    for generated_name in overlay.tools.keys() {
        if let Some(owner) = rename_owner.get(generated_name.as_str()) {
            problems.push(OverlayProblem {
                path: format!("/tools/{generated_name}"),
                message: format!(
                    "'{generated_name}' is the rename target of tools.{owner}; overlay \
                     references use the generated name: use the generated name '{owner}'"
                ),
            });
        }
    }

    for (shape_name, shape) in &overlay.shapes {
        shape_document_problems(&format!("/shapes/{shape_name}"), shape, &mut problems);
    }
    for (tool_name, tool) in &overlay.tools {
        for (property, parameter) in &tool.parameters {
            if parameter.shape.is_some() {
                for (field, present) in [
                    ("description", parameter.description.is_some()),
                    ("title", parameter.title.is_some()),
                ] {
                    if present {
                        problems.push(OverlayProblem {
                            path: format!("/tools/{tool_name}/parameters/{property}/{field}"),
                            message: format!(
                                "`{field}` cannot be combined with `shape`; move agent-facing \
                                 metadata into the relevant \
                                 `shape.agent.<agent_property>.{field}` schema fragment"
                            ),
                        });
                    }
                }
                if parameter.enum_source.is_some() {
                    problems.push(OverlayProblem {
                        path: format!(
                            "/tools/{tool_name}/parameters/{property}/enum_source"
                        ),
                        message: "`enum_source` cannot be combined with `shape`; dynamic enum sources bind one top-level agent property"
                            .to_owned(),
                    });
                }
            }
            if let Some(ShapeOrUse::Inline(shape)) = parameter.shape.as_ref() {
                shape_document_problems(
                    &format!("/tools/{tool_name}/parameters/{property}/shape"),
                    shape,
                    &mut problems,
                );
            }
        }
        if let Some(response) = tool.response.as_ref() {
            for (property, shape) in &response.fields {
                if let ShapeOrUse::Inline(shape) = shape {
                    shape_document_problems(
                        &format!("/tools/{tool_name}/response/fields/{property}"),
                        shape,
                        &mut problems,
                    );
                }
            }
        }
    }
    for (name, composite) in &overlay.composites {
        let path = format!("/composites/{name}");
        let required = composite.input.required.iter().collect::<BTreeSet<_>>();
        if required.len() != composite.input.required.len() {
            problems.push(OverlayProblem {
                path: format!("{path}/input/required"),
                message: "required property names must be unique".to_owned(),
            });
        }
        for required_name in &composite.input.required {
            if !composite.input.properties.contains_key(required_name) {
                problems.push(OverlayProblem {
                    path: format!("{path}/input/required"),
                    message: format!(
                        "required input '{required_name}' is not declared in input.properties"
                    ),
                });
            }
        }
        for (property, fragment) in &composite.input.properties {
            let fragment_path = format!("{path}/input/properties/{property}");
            let Some(object) = fragment.as_object() else {
                problems.push(OverlayProblem {
                    path: fragment_path,
                    message: "agent schema fragment must be an object".to_owned(),
                });
                continue;
            };
            if !object.get("type").is_some_and(Value::is_string) {
                problems.push(OverlayProblem {
                    path: fragment_path.clone(),
                    message: "agent schema fragment must declare a string type".to_owned(),
                });
            }
            let mut remaining_nodes = MAX_AGENT_FRAGMENT_SCHEMA_NODES;
            let mut limit_reported = false;
            reject_agent_fragment_formats(
                fragment,
                &fragment_path,
                0,
                &mut remaining_nodes,
                &mut limit_reported,
                &mut problems,
            );
            if let Err(error) = jsonschema::validator_for(fragment) {
                problems.push(OverlayProblem {
                    path: fragment_path,
                    message: format!("agent schema fragment is not valid JSON Schema: {error}"),
                });
            }
        }
        for (property, parameter) in &composite.parameters {
            let Some(schema) = composite.input.properties.get(property) else {
                problems.push(OverlayProblem {
                    path: format!("{path}/parameters/{property}"),
                    message: format!(
                        "'{property}' is not declared in this composite's input.properties"
                    ),
                });
                continue;
            };
            if let Some(source_id) = parameter.enum_source.as_deref() {
                let enum_path = format!("{path}/parameters/{property}/enum_source");
                if !overlay.enum_sources.contains_key(source_id) {
                    problems.push(OverlayProblem {
                        path: enum_path.clone(),
                        message: format!("unknown enum source '{source_id}'"),
                    });
                }
                if dynamic_enum_schema(schema).is_none() {
                    problems.push(OverlayProblem {
                        path: enum_path,
                        message: format!(
                            "'{property}' must have type string or boolean, or be an array whose items have type string or boolean"
                        ),
                    });
                }
            }
        }
        if composite.steps.is_empty() || composite.steps.len() > MAX_COMPOSITE_STEPS {
            problems.push(OverlayProblem {
                path: format!("{path}/steps"),
                message: format!("a composite must contain 1-{MAX_COMPOSITE_STEPS} steps"),
            });
        }
        if composite
            .result
            .as_ref()
            .is_some_and(|result| result.len() > MAX_COMPOSITE_RESULT_PROPERTIES)
        {
            problems.push(OverlayProblem {
                path: format!("{path}/result"),
                message: format!(
                    "a composite result may contain at most {MAX_COMPOSITE_RESULT_PROPERTIES} properties"
                ),
            });
        }
        if !(1..=MAX_COMPOSITE_ITERATIONS).contains(&composite.limits.max_iterations) {
            problems.push(OverlayProblem {
                path: format!("{path}/limits/max_iterations"),
                message: format!("max_iterations must be between 1 and {MAX_COMPOSITE_ITERATIONS}"),
            });
        }
        if !(100..=120_000).contains(&composite.limits.compensation_timeout_ms) {
            problems.push(OverlayProblem {
                path: format!("{path}/limits/compensation_timeout_ms"),
                message: "compensation_timeout_ms must be between 100 and 120000".to_owned(),
            });
        }
    }
    problems
}

fn shape_document_problems(path: &str, shape: &Shape, problems: &mut Vec<OverlayProblem>) {
    for (name, fragment) in &shape.agent {
        let fragment_path = format!("{path}/agent/{name}");
        if contains_keyword(fragment, "format") {
            problems.push(OverlayProblem {
                path: fragment_path.clone(),
                message: "agent schema fragments must not contain format; this gateway does not assert formats (use pattern)".to_owned(),
            });
        }
        if let Err(error) = jsonschema::validator_for(fragment) {
            problems.push(OverlayProblem {
                path: fragment_path,
                message: format!("agent schema fragment is not valid JSON Schema: {error}"),
            });
        }
    }

    if let Some(required_names) = &shape.required {
        for required in required_names {
            if !shape.agent.contains_key(required) {
                problems.push(OverlayProblem {
                    path: format!("{path}/required"),
                    message: format!(
                        "required agent property '{required}' is not declared in agent"
                    ),
                });
            }
        }
    }

    let pointers = shape.wire.keys().collect::<Vec<_>>();
    for (index, pointer) in pointers.iter().enumerate() {
        if pointer.is_empty() {
            problems.push(OverlayProblem {
                path: format!("{path}/wire"),
                message: "wire pointers must be non-empty; the empty RFC 6901 pointer would replace the whole wire value".to_owned(),
            });
        }
        for other in pointers.iter().skip(index + 1) {
            if pointer_is_prefix(pointer, other) || pointer_is_prefix(other, pointer) {
                problems.push(OverlayProblem {
                    path: format!("{path}/wire/{other}"),
                    message: format!(
                        "wire pointers '{pointer}' and '{other}' overlap; no pointer may be a prefix of another"
                    ),
                });
            }
        }
    }

    let mut uses = BTreeMap::<&str, usize>::new();
    let mut noninvertible = BTreeSet::<&str>::new();
    for (pointer, binding) in &shape.wire {
        let OverlayWireBinding::From { from, codec } = binding else {
            continue;
        };
        if !shape.agent.contains_key(from) {
            problems.push(OverlayProblem {
                path: format!("{path}/wire/{pointer}/from"),
                message: format!("unknown agent property '{from}'"),
            });
            continue;
        }
        *uses.entry(from).or_default() += 1;
        let codecs = codec.as_ref().map(CodecChain::to_vec).unwrap_or_default();
        if codecs
            .iter()
            .any(|codec| matches!(codec, Codec::MarkdownBlocks { .. }))
        {
            noninvertible.insert(from);
        }
        if let Some(agent_type) = fragment_type(&shape.agent[from]) {
            if let Err(message) = check_codec_input(agent_type, &codecs) {
                problems.push(OverlayProblem {
                    path: format!("{path}/wire/{pointer}/codec"),
                    message,
                });
            }
        }
    }
    for name in shape.agent.keys() {
        if !uses.contains_key(name.as_str()) {
            problems.push(OverlayProblem {
                path: format!("{path}/agent/{name}"),
                message: format!("agent property '{name}' is not used by any wire binding"),
            });
        }
    }
    for (name, response) in &shape.response {
        if !shape.agent.contains_key(name) {
            problems.push(OverlayProblem {
                path: format!("{path}/response/{name}"),
                message: format!("response binding names unknown agent property '{name}'"),
            });
        }
        let codecs = response
            .codec
            .as_ref()
            .map(CodecChain::to_vec)
            .unwrap_or_default();
        if codecs
            .iter()
            .any(|codec| matches!(codec, Codec::MarkdownBlocks { .. }))
        {
            problems.push(OverlayProblem {
                path: format!("{path}/response/{name}/codec"),
                message: "markdown_blocks has no decode direction and cannot appear in a response codec chain".to_owned(),
            });
        }
        if let Some(agent_type) = shape.agent.get(name).and_then(fragment_type) {
            if let Err(message) = check_codec_input(agent_type, &codecs) {
                problems.push(OverlayProblem {
                    path: format!("{path}/response/{name}/codec"),
                    message,
                });
            }
        }
    }
    for (name, count) in uses {
        if (count > 1 || noninvertible.contains(name)) && !shape.response.contains_key(name) {
            problems.push(OverlayProblem {
                path: format!("{path}/response"),
                message: format!(
                    "response binding for '{name}' is required because its wire mapping is ambiguous or non-invertible"
                ),
            });
        }
    }
}

fn contains_keyword(value: &Value, keyword: &str) -> bool {
    match value {
        Value::Object(object) => object
            .iter()
            .any(|(key, value)| key == keyword || contains_keyword(value, keyword)),
        Value::Array(values) => values.iter().any(|value| contains_keyword(value, keyword)),
        _ => false,
    }
}

fn pointer_is_prefix(prefix: &str, value: &str) -> bool {
    value
        .strip_prefix(prefix)
        .is_some_and(|suffix| suffix.starts_with('/'))
}

fn reject_agent_fragment_formats(
    schema: &Value,
    path: &str,
    depth: usize,
    remaining_nodes: &mut usize,
    limit_reported: &mut bool,
    problems: &mut Vec<OverlayProblem>,
) {
    if depth >= MAX_COMPOSITE_JSON_DEPTH || *remaining_nodes == 0 {
        if !*limit_reported {
            problems.push(OverlayProblem {
                path: path.to_owned(),
                message: "agent schema fragment is too complex to verify that format is absent"
                    .to_owned(),
            });
            *limit_reported = true;
        }
        return;
    }
    *remaining_nodes -= 1;
    let Some(object) = schema.as_object() else {
        return;
    };
    if object
        .get("$schema")
        .is_some_and(|dialect| dialect.as_str() != Some(AGENT_FRAGMENT_DIALECT))
    {
        problems.push(OverlayProblem {
            path: format!("{path}/$schema"),
            message: format!(
                "agent schema fragments must use JSON Schema 2020-12 ('{AGENT_FRAGMENT_DIALECT}')"
            ),
        });
    }
    if object.contains_key("format") {
        problems.push(OverlayProblem {
            path: format!("{path}/format"),
            message: "format is not accepted in agent schema fragments; use pattern".to_owned(),
        });
    }

    for keyword in [
        "additionalProperties",
        "unevaluatedProperties",
        "propertyNames",
        "items",
        "contains",
        "not",
        "if",
        "then",
        "else",
        "contentSchema",
        "unevaluatedItems",
    ] {
        if let Some(child) = object.get(keyword).filter(|child| child.is_object()) {
            reject_agent_fragment_formats(
                child,
                &format!("{path}/{keyword}"),
                depth + 1,
                remaining_nodes,
                limit_reported,
                problems,
            );
        }
    }
    for keyword in [
        "properties",
        "patternProperties",
        "$defs",
        "definitions",
        "dependentSchemas",
    ] {
        let Some(children) = object.get(keyword).and_then(Value::as_object) else {
            continue;
        };
        for (name, child) in children {
            let name = name.replace('~', "~0").replace('/', "~1");
            reject_agent_fragment_formats(
                child,
                &format!("{path}/{keyword}/{name}"),
                depth + 1,
                remaining_nodes,
                limit_reported,
                problems,
            );
        }
    }
    for keyword in ["prefixItems", "allOf", "anyOf", "oneOf"] {
        let Some(children) = object.get(keyword).and_then(Value::as_array) else {
            continue;
        };
        for (index, child) in children.iter().enumerate() {
            reject_agent_fragment_formats(
                child,
                &format!("{path}/{keyword}/{index}"),
                depth + 1,
                remaining_nodes,
                limit_reported,
                problems,
            );
        }
    }
}

fn validate_source_request(
    path: &str,
    request: &SourceRequest,
    problems: &mut Vec<OverlayProblem>,
) {
    if request.tool.is_some() == request.path.is_some() {
        problems.push(OverlayProblem {
            path: path.to_owned(),
            message: "source request must declare exactly one of tool or path".to_owned(),
        });
    }
    if let Some(raw_path) = request.path.as_deref() {
        if let Err(error) = normalize_origin_relative_path("source request path", raw_path) {
            problems.push(OverlayProblem {
                path: format!("{path}/path"),
                message: error.message,
            });
        }
    }
}

fn validate_source_limits(path: &str, limits: &SourceLimits, problems: &mut Vec<OverlayProblem>) {
    if limits.min_items > limits.max_items {
        problems.push(OverlayProblem {
            path: format!("{path}/min_items"),
            message: format!(
                "min_items {} exceeds max_items {}",
                limits.min_items, limits.max_items
            ),
        });
    }
}

// ---------------------------------------------------------------------------
// Source planning (catalog checked, deterministic, no upstream I/O)
// ---------------------------------------------------------------------------

/// Resolve every authoring source declaration to a bounded GET plan and a
/// canonical digest. This function performs no upstream I/O.
pub fn plan_sources(
    generation: &OpenApiToolGeneration,
    overlay: &OverlayDocument,
) -> Result<OverlaySourcePlan, OverlayError> {
    let generated = generation
        .definitions
        .iter()
        .map(|definition| (definition.name.as_str(), definition))
        .collect::<BTreeMap<_, _>>();
    let rename_owners = overlay
        .tools
        .iter()
        .filter_map(|(generated, tool)| {
            tool.rename
                .as_deref()
                .map(|served| (served, generated.as_str()))
        })
        .collect::<BTreeMap<_, _>>();
    let served_names = overlay
        .tools
        .iter()
        .filter_map(|(generated, tool)| {
            tool.rename
                .as_deref()
                .map(|served| (generated.as_str(), served))
        })
        .collect::<BTreeMap<_, _>>();
    let mut problems = Vec::new();
    let mut plan = OverlaySourcePlan::default();

    for (source_id, source) in &overlay.enum_sources {
        let root = format!("/enum_sources/{source_id}");
        let request = planned_source_request(
            &source.request,
            &format!("{root}/request"),
            &generated,
            &rename_owners,
            &served_names,
            &mut problems,
        );
        let items = match Selector::parse(&source.select.items) {
            Ok(selector) => Some(selector),
            Err(error) => {
                problems.push(OverlayProblem {
                    path: format!("{root}/select/items"),
                    message: format!("invalid selector: {error}"),
                });
                None
            }
        };
        let (Some(request), Some(items)) = (request, items) else {
            continue;
        };
        let select = EnumSourceSelectionPlan {
            items,
            value: source.select.value.clone(),
            label: source.select.label.clone(),
        };
        let source_digest = enum_source_digest(&request, &select, &source.cache, &source.limits);
        plan.enum_sources.insert(
            source_id.clone(),
            EnumSourcePlan {
                id: source_id.clone(),
                source_digest,
                request,
                select,
                cache: source.cache.clone(),
                limits: source.limits.clone(),
            },
        );
    }

    for (source_id, source) in &overlay.label_sources {
        let root = format!("/label_sources/{source_id}");
        let request = planned_source_request(
            &source.request,
            &format!("{root}/request"),
            &generated,
            &rename_owners,
            &served_names,
            &mut problems,
        );
        let items = match Selector::parse(&source.select.items) {
            Ok(selector) => Some(selector),
            Err(error) => {
                problems.push(OverlayProblem {
                    path: format!("{root}/select/items"),
                    message: format!("invalid selector: {error}"),
                });
                None
            }
        };
        let (Some(request), Some(items)) = (request, items) else {
            continue;
        };
        let select = LabelSourceSelectionPlan {
            items,
            key: source.select.key.clone(),
            label: source.select.label.clone(),
        };
        let source_digest = label_source_digest(&request, &select, &source.limits);
        plan.label_sources.insert(
            source_id.clone(),
            LabelSourcePlan {
                id: source_id.clone(),
                source_digest,
                request,
                select,
                limits: source.limits.clone(),
            },
        );
    }

    if problems.is_empty() {
        Ok(plan)
    } else {
        Err(OverlayError { problems })
    }
}

fn planned_source_request(
    request: &SourceRequest,
    path: &str,
    generated: &BTreeMap<&str, &ToolDefinition>,
    rename_owners: &BTreeMap<&str, &str>,
    served_names: &BTreeMap<&str, &str>,
    problems: &mut Vec<OverlayProblem>,
) -> Option<SourceRequestPlan> {
    match (request.tool.as_deref(), request.path.as_deref()) {
        (Some(_), Some(_)) | (None, None) => {
            problems.push(OverlayProblem {
                path: path.to_owned(),
                message: "source request must declare exactly one of tool or path".to_owned(),
            });
            None
        }
        (None, Some(raw_path)) => {
            let normalized = match normalize_origin_relative_path("source request path", raw_path) {
                Ok(path) => path,
                Err(error) => {
                    problems.push(OverlayProblem {
                        path: format!("{path}/path"),
                        message: error.message,
                    });
                    return None;
                }
            };
            let query_params = request
                .query
                .keys()
                .map(|name| QueryParamMapping {
                    arg_name: name.clone(),
                    query_name: name.clone(),
                    required: false,
                })
                .collect::<Vec<_>>();
            Some(SourceRequestPlan {
                tool: None,
                path_and_query: append_source_query(&normalized, &request.query, &query_params),
                path_template: normalized,
                query: request.query.clone(),
                query_params,
            })
        }
        (Some(tool_name), None) => {
            let Some(definition) = generated.get(tool_name).copied() else {
                let hint = rename_owners
                    .get(tool_name)
                    .map(|generated_name| format!("; use the generated name '{generated_name}'"))
                    .or_else(|| {
                        generated
                            .keys()
                            .find(|candidate| candidate.eq_ignore_ascii_case(tool_name))
                            .map(|candidate| format!("; did you mean '{candidate}'"))
                    })
                    .unwrap_or_default();
                problems.push(OverlayProblem {
                    path: format!("{path}/tool"),
                    message: format!("unknown generated tool '{tool_name}'{hint}"),
                });
                return None;
            };
            if definition.upstream.method != "GET" {
                problems.push(OverlayProblem {
                    path: format!("{path}/tool"),
                    message: format!(
                        "source tool '{tool_name}' uses {}; metadata sources are GET-only",
                        definition.upstream.method
                    ),
                });
            }

            let properties = definition
                .input_schema
                .get("properties")
                .and_then(Value::as_object);
            let path_arguments = source_path_arguments(&definition.upstream.path_template);
            let query_arguments = definition
                .upstream
                .query_params
                .iter()
                .map(|mapping| mapping.arg_name.as_str())
                .collect::<BTreeSet<_>>();
            for argument in request.query.keys() {
                if properties.is_none_or(|properties| !properties.contains_key(argument)) {
                    problems.push(OverlayProblem {
                        path: format!("{path}/query/{argument}"),
                        message: format!(
                            "'{argument}' is not an input property of source tool '{tool_name}'"
                        ),
                    });
                } else if !path_arguments.contains(argument.as_str())
                    && !query_arguments.contains(argument.as_str())
                {
                    problems.push(OverlayProblem {
                        path: format!("{path}/query/{argument}"),
                        message: format!(
                            "'{argument}' is not a path or query argument of GET source tool '{tool_name}'"
                        ),
                    });
                }
            }
            let missing = definition
                .input_schema
                .get("required")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .filter(|argument| !request.query.contains_key(*argument))
                .collect::<Vec<_>>();
            if !missing.is_empty() {
                problems.push(OverlayProblem {
                    path: format!("{path}/query"),
                    message: format!(
                        "source tool '{tool_name}' has required arguments not supplied by query: {}",
                        missing.join(", ")
                    ),
                });
            }
            if definition.upstream.method != "GET" || !missing.is_empty() {
                return None;
            }

            let normalized = match normalize_origin_relative_path(
                "source tool path",
                &definition.upstream.path_template,
            ) {
                Ok(path) => path,
                Err(error) => {
                    problems.push(OverlayProblem {
                        path: format!("{path}/tool"),
                        message: format!("source tool has an invalid path: {}", error.message),
                    });
                    return None;
                }
            };
            let mut query_params = definition
                .upstream
                .query_params
                .iter()
                .filter(|mapping| request.query.contains_key(&mapping.arg_name))
                .cloned()
                .collect::<Vec<_>>();
            query_params.sort_by(|left, right| {
                (&left.arg_name, &left.query_name).cmp(&(&right.arg_name, &right.query_name))
            });
            let rendered_path = render_source_path(
                &normalized,
                &request.query,
                &format!("{path}/query"),
                problems,
            )?;
            Some(SourceRequestPlan {
                tool: Some(
                    served_names
                        .get(tool_name)
                        .copied()
                        .unwrap_or(tool_name)
                        .to_owned(),
                ),
                path_and_query: append_source_query(&rendered_path, &request.query, &query_params),
                path_template: normalized,
                query: request.query.clone(),
                query_params,
            })
        }
    }
}

fn render_source_path(
    template: &str,
    arguments: &BTreeMap<String, String>,
    path: &str,
    problems: &mut Vec<OverlayProblem>,
) -> Option<String> {
    let mut rendered = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        rendered.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        let Some(close) = after.find('}') else {
            problems.push(OverlayProblem {
                path: path.to_owned(),
                message: "source tool path contains an unmatched '{'".to_owned(),
            });
            return None;
        };
        let argument = &after[..close];
        let Some(value) = arguments.get(argument) else {
            problems.push(OverlayProblem {
                path: path.to_owned(),
                message: format!("source tool path argument '{argument}' is missing"),
            });
            return None;
        };
        if matches!(value.as_str(), "." | "..") {
            problems.push(OverlayProblem {
                path: format!("{path}/{argument}"),
                message: "source path argument must not be a dot segment".to_owned(),
            });
            return None;
        }
        rendered.push_str(&utf8_percent_encode(value, SOURCE_PATH_SEGMENT_ENCODE_SET).to_string());
        rest = &after[close + 1..];
    }
    rendered.push_str(rest);
    match normalize_origin_relative_path("rendered source path", &rendered) {
        Ok(path) => Some(path),
        Err(error) => {
            problems.push(OverlayProblem {
                path: path.to_owned(),
                message: error.message,
            });
            None
        }
    }
}

fn append_source_query(
    path: &str,
    arguments: &BTreeMap<String, String>,
    mappings: &[QueryParamMapping],
) -> String {
    if mappings.is_empty() {
        return path.to_owned();
    }
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for mapping in mappings {
        if let Some(value) = arguments.get(&mapping.arg_name) {
            serializer.append_pair(&mapping.query_name, value);
        }
    }
    let query = serializer.finish();
    if query.is_empty() {
        path.to_owned()
    } else {
        format!("{path}?{query}")
    }
}

fn source_path_arguments(path_template: &str) -> BTreeSet<&str> {
    let mut arguments = BTreeSet::new();
    let mut rest = path_template;
    while let Some(open) = rest.find('{') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('}') else {
            break;
        };
        arguments.insert(&after[..close]);
        rest = &after[close + 1..];
    }
    arguments
}

#[derive(Serialize)]
struct CanonicalEnumSource<'a> {
    kind: &'static str,
    request: &'a SourceRequestPlan,
    items: &'a str,
    value: &'a str,
    label: Option<&'a str>,
    cache: &'a SourceCache,
    limits: &'a SourceLimits,
}

#[derive(Serialize)]
struct CanonicalLabelSource<'a> {
    kind: &'static str,
    request: &'a SourceRequestPlan,
    items: &'a str,
    key: &'a str,
    label: &'a str,
    limits: &'a SourceLimits,
}

fn enum_source_digest(
    request: &SourceRequestPlan,
    select: &EnumSourceSelectionPlan,
    cache: &SourceCache,
    limits: &SourceLimits,
) -> String {
    canonical_source_digest(&CanonicalEnumSource {
        kind: "enum",
        request,
        items: select.items.as_str(),
        value: &select.value,
        label: select.label.as_deref(),
        cache,
        limits,
    })
}

fn label_source_digest(
    request: &SourceRequestPlan,
    select: &LabelSourceSelectionPlan,
    limits: &SourceLimits,
) -> String {
    canonical_source_digest(&CanonicalLabelSource {
        kind: "label",
        request,
        items: select.items.as_str(),
        key: &select.key,
        label: &select.label,
        limits,
    })
}

fn canonical_source_digest(source: &impl Serialize) -> String {
    let encoded = serde_json::to_vec(source).expect("source plan serialization is infallible");
    hex::encode(Sha256::digest(encoded))
}

// ---------------------------------------------------------------------------
// compile
// ---------------------------------------------------------------------------

/// Apply an overlay to a bound catalog (after `bind_selected_tools`, before
/// `publish_candidate`). `generation` supplies every generated name of the
/// catalog, selected or not, for the collision and did-you-mean checks;
/// `binding` carries the selected definitions that will be published.
///
/// On `Err` nothing was produced: the caller keeps the Connection's tools
/// exactly as they were (section 6, S6).
#[cfg(test)]
pub fn compile(
    generation: &OpenApiToolGeneration,
    binding: OpenApiToolBinding,
    overlay: &OverlayDocument,
    context: &OverlayCompileContext,
) -> Result<CompiledCatalog, OverlayError> {
    compile_with_resolved_sources(
        generation,
        binding,
        overlay,
        context,
        &ResolvedOverlaySources::default(),
    )
}

/// Compile with the synchronous source results produced from [`plan_sources`].
/// Enum values are checked but deliberately not copied into the durable
/// definition. Label-source results are compile input and therefore required.
pub fn compile_with_resolved_sources(
    generation: &OpenApiToolGeneration,
    binding: OpenApiToolBinding,
    overlay: &OverlayDocument,
    context: &OverlayCompileContext,
    resolved: &ResolvedOverlaySources,
) -> Result<CompiledCatalog, OverlayError> {
    let source_plan = plan_sources(generation, overlay)?;
    let resolved_problems = resolved_source_problems(&source_plan, resolved);
    if !resolved_problems.is_empty() {
        return Err(OverlayError {
            problems: resolved_problems,
        });
    }
    let generated_names = generation
        .definitions
        .iter()
        .map(|definition| definition.name.as_str())
        .collect::<BTreeSet<_>>();
    let generated_index = generation
        .definitions
        .iter()
        .map(|definition| (definition.name.as_str(), definition))
        .collect::<BTreeMap<_, _>>();
    let bound_index = binding
        .definitions
        .iter()
        .enumerate()
        .map(|(index, definition)| (definition.name.clone(), index))
        .collect::<BTreeMap<_, _>>();

    let mut problems = Vec::new();
    let mut warnings = Vec::new();
    let mut renames = BTreeMap::new();
    let mut transformed = BTreeMap::new();

    // Name checks first, over the whole overlay, so the operator sees every
    // naming problem in one round trip.
    let mut active_tools = Vec::new();
    for (generated_name, tool) in &overlay.tools {
        if !generated_names.contains(generated_name.as_str()) {
            let hint = generated_names
                .iter()
                .find(|candidate| candidate.eq_ignore_ascii_case(generated_name))
                .map(|candidate| format!("; did you mean '{candidate}'"))
                .unwrap_or_default();
            problems.push(OverlayProblem {
                path: format!("/tools/{generated_name}"),
                message: format!("unknown generated tool '{generated_name}'{hint}"),
            });
            continue;
        }
        if let Some(target) = tool.rename.as_deref() {
            let path = format!("/tools/{generated_name}/rename");
            if generated_names.contains(target) {
                problems.push(OverlayProblem {
                    path: path.clone(),
                    message: format!(
                        "rename target '{target}' collides with a generated tool of this catalog"
                    ),
                });
            }
            if context.other_lane_tool_names.contains(target) {
                problems.push(OverlayProblem {
                    path: path.clone(),
                    message: format!(
                        "rename target '{target}' is already published by another registry lane"
                    ),
                });
            }
            if context.policy_tool_names.contains(target)
                && context
                    .prior_overlay_name_owners
                    .get(target)
                    .is_none_or(|owner| owner != generated_name)
            {
                problems.push(OverlayProblem {
                    path,
                    message: format!(
                        "rename target '{target}' would adopt the existing policy entry \
                         tools.{target}; tool policy is keyed by served name, so choose another \
                         name or store the overlay before adding the policy entry"
                    ),
                });
            }
            renames.insert(generated_name.clone(), target.to_owned());
        }
        if let Some(definition) = generated_index.get(generated_name.as_str()) {
            validate_parameter_names(
                generated_name,
                tool,
                definition,
                generation.transform_metadata.get(generated_name),
                &source_plan,
                resolved,
                &mut problems,
            );
            if let Some(compiled) = compile_tool_transform(
                generation,
                generated_name,
                tool,
                overlay,
                definition,
                &mut warnings,
                &mut problems,
            ) {
                transformed.insert(generated_name.clone(), compiled);
            }
        }
        let Some(&index) = bound_index.get(generated_name) else {
            warnings.push(OverlayWarning {
                path: format!("/tools/{generated_name}"),
                message: format!(
                    "'{generated_name}' is generated but not selected in this catalog; its \
                     overlay entry is inactive until the tool is registered"
                ),
            });
            continue;
        };
        active_tools.push((generated_name.as_str(), tool, index));
    }
    let rename_targets = renames
        .values()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    for composite_name in overlay.composites.keys() {
        let path = format!("/composites/{composite_name}");
        if generated_names.contains(composite_name.as_str()) {
            problems.push(OverlayProblem {
                path: path.clone(),
                message: format!(
                    "composite name '{composite_name}' collides with a generated tool of this catalog"
                ),
            });
        }
        if rename_targets.contains(composite_name.as_str()) {
            problems.push(OverlayProblem {
                path: path.clone(),
                message: format!(
                    "composite name '{composite_name}' collides with an overlay rename target"
                ),
            });
        }
        if context.other_lane_tool_names.contains(composite_name) {
            problems.push(OverlayProblem {
                path: path.clone(),
                message: format!(
                    "composite name '{composite_name}' is already published by another registry lane"
                ),
            });
        }
        if context.policy_tool_names.contains(composite_name)
            && context
                .prior_overlay_name_owners
                .get(composite_name)
                .is_none_or(|owner| owner != composite_name)
        {
            problems.push(OverlayProblem {
                path,
                message: format!(
                    "composite name '{composite_name}' would adopt the existing policy entry tools.{composite_name}; store the overlay before adding the policy entry"
                ),
            });
        }
    }
    if !problems.is_empty() {
        return Err(OverlayError { problems });
    }

    let defaults = overlay.defaults.clone().unwrap_or_default();
    let disambiguation = defaults.disambiguation.clone().unwrap_or_default();
    let body_mode = defaults.body_mode.unwrap_or(BodyMappingMode::BodyArgsJson);

    let OpenApiToolBinding {
        mut definitions,
        mut security_selections,
        incompatibilities,
    } = binding;
    let mut reports = Vec::with_capacity(active_tools.len());

    for (generated_name, tool, index) in active_tools {
        let definition = &mut definitions[index];
        let tool_path = format!("/tools/{generated_name}");

        // Agent-facing shape replacement must happen before label
        // disambiguation so labels and collisions are computed over exactly
        // the schema tools/list will advertise.
        if let Some(compiled) = transformed.get(generated_name) {
            definition.input_schema = compiled.input_schema.clone();
            definition.transform = Some(compiled.transform.clone());
        }

        if let Some(description) = tool.description.as_deref() {
            definition.description = description.to_owned();
        }
        definition.title = tool.title.clone();
        definition.annotations = tool.annotations.clone();
        let visibility = tool.visibility.unwrap_or_default();
        definition.visibility = visibility;
        if visibility == ToolVisibility::CompositeOnly {
            // The tool remains present for composite steps and the admin
            // playground, but direct agent discovery and calls are refused.
            warnings.push(OverlayWarning {
                path: format!("{tool_path}/visibility"),
                message: format!(
                    "'{generated_name}' is composite_only: hidden from tools/list and \
                     direct tools/call, reachable only from composites and the admin playground"
                ),
            });
        }

        let applied_body_mode = apply_body_mode(definition, body_mode);

        let mut overridden = BTreeSet::new();
        let mut label_inputs = BTreeMap::new();
        let mut enum_bound = BTreeSet::new();
        let mut enum_bindings = Vec::new();
        let source_labels = tool
            .labels_from
            .as_deref()
            .and_then(|source_id| resolved.label_sources.get(source_id))
            .map(|source| &source.labels);
        let Some(properties) = definition
            .input_schema
            .get_mut("properties")
            .and_then(Value::as_object_mut)
        else {
            return Err(OverlayError::one(
                tool_path,
                "generated input schema has no properties object; this tool cannot be overlaid",
            ));
        };
        for (property, parameter) in &tool.parameters {
            if parameter.shape.is_some() {
                continue;
            }
            let parameter_path = format!("{tool_path}/parameters/{property}");
            let Some(schema) = properties.get_mut(property) else {
                let known = properties.keys().cloned().collect::<Vec<_>>().join(", ");
                problems.push(OverlayProblem {
                    path: parameter_path,
                    message: format!(
                        "'{property}' is not a top-level property of the generated schema \
                         (properties: {known})"
                    ),
                });
                continue;
            };
            let Some(schema) = schema.as_object_mut() else {
                problems.push(OverlayProblem {
                    path: parameter_path,
                    message: format!("the generated schema of '{property}' is not an object"),
                });
                continue;
            };
            if let Some(title) = parameter.title.as_deref() {
                schema.insert("title".to_owned(), Value::String(title.to_owned()));
            }
            if let Some(source_id) = parameter.enum_source.as_deref() {
                let Some(source) = source_plan.enum_sources.get(source_id) else {
                    problems.push(OverlayProblem {
                        path: format!("{parameter_path}/enum_source"),
                        message: format!("unknown enum source '{source_id}'"),
                    });
                    continue;
                };
                remove_static_enum(schema);
                enum_bound.insert(property.clone());
                enum_bindings.push(EnumBinding {
                    property: property.clone(),
                    source_id: source_id.to_owned(),
                    source_digest: source.source_digest.clone(),
                });
            }
            if let Some(description) = parameter.description.as_deref() {
                // Keep the document label for collision grouping. The
                // explicit description wins in the served schema and is
                // exempt from rewriting, but must not make a colliding
                // sibling appear unique merely because it was overridden.
                label_inputs.insert(property.clone(), Value::Object(schema.clone()));
                schema.insert(
                    "description".to_owned(),
                    Value::String(description.to_owned()),
                );
                overridden.insert(property.clone());
            }
        }
        if !problems.is_empty() {
            return Err(OverlayError { problems });
        }

        enum_bindings.sort_by(|left, right| left.property.cmp(&right.property));
        definition.enum_bindings = enum_bindings;
        let labels = disambiguate(
            properties,
            &disambiguation,
            &overridden,
            &label_inputs,
            source_labels,
            &enum_bound,
        );

        let served_name = renames
            .get(generated_name)
            .cloned()
            .unwrap_or_else(|| generated_name.to_owned());
        if served_name != definition.name {
            definition.name = served_name.clone();
            for selection in &mut security_selections {
                if selection.tool_name == generated_name {
                    selection.tool_name = served_name.clone();
                }
            }
        }

        let summary = label_summary(
            labels.found,
            labels.from_source,
            labels.from_title,
            labels.from_description,
            labels.qualified.len(),
        );
        reports.push(OverlayToolReport {
            generated_name: generated_name.to_owned(),
            served_name,
            visibility,
            body_mode: applied_body_mode,
            labels_found: labels.found,
            labels_from_source: labels.from_source,
            labels_from_title: labels.from_title,
            labels_from_description: labels.from_description,
            qualified_properties: labels.qualified,
            label_summary: summary,
        });
    }

    let (composite_reports, referenced_generated_tools) = compile_composites(
        generation,
        overlay,
        context,
        &bound_index,
        &renames,
        &transformed,
        &source_plan,
        resolved,
        &mut definitions,
        &mut security_selections,
        &mut warnings,
        &mut problems,
    );

    for (generated_name, tool) in &overlay.tools {
        if tool.visibility == Some(ToolVisibility::CompositeOnly)
            && bound_index.contains_key(generated_name)
            && !referenced_generated_tools.contains(generated_name)
        {
            problems.push(OverlayProblem {
                path: format!("/tools/{generated_name}/visibility"),
                message: format!(
                    "composite_only tool '{generated_name}' is not referenced by any composite step or compensation"
                ),
            });
        }
    }

    budget_problems(&definitions, &renames, &mut problems);
    if !problems.is_empty() {
        return Err(OverlayError { problems });
    }

    Ok(CompiledCatalog {
        binding: OpenApiToolBinding {
            definitions,
            security_selections,
            incompatibilities,
        },
        source_plan,
        renames,
        tools: reports,
        composites: composite_reports,
        warnings,
    })
}

#[derive(Debug, Clone)]
struct CompiledToolTransform {
    input_schema: Value,
    transform: ToolTransform,
}

#[derive(Debug)]
struct CompiledShape {
    parameter: ParameterShape,
    required_agent_names: Vec<String>,
}

#[allow(clippy::too_many_arguments)]
fn compile_tool_transform(
    generation: &OpenApiToolGeneration,
    generated_name: &str,
    tool: &ToolOverlay,
    overlay: &OverlayDocument,
    definition: &ToolDefinition,
    warnings: &mut Vec<OverlayWarning>,
    problems: &mut Vec<OverlayProblem>,
) -> Option<CompiledToolTransform> {
    let tool_path = format!("/tools/{generated_name}");
    let request_shapes = tool
        .parameters
        .iter()
        .filter_map(|(property, parameter)| parameter.shape.as_ref().map(|shape| (property, shape)))
        .collect::<Vec<_>>();
    let response_fields = tool
        .response
        .as_ref()
        .map(|response| &response.fields)
        .filter(|fields| !fields.is_empty());
    let response_root_text = tool
        .response
        .as_ref()
        .and_then(|response| response.root.as_deref())
        .or_else(|| {
            overlay
                .defaults
                .as_ref()
                .and_then(|defaults| defaults.response_root.as_deref())
        });
    let response_root_path = if tool
        .response
        .as_ref()
        .and_then(|response| response.root.as_ref())
        .is_some()
    {
        format!("{tool_path}/response/root")
    } else if overlay
        .defaults
        .as_ref()
        .and_then(|defaults| defaults.response_root.as_ref())
        .is_some()
    {
        "/defaults/response_root".to_owned()
    } else {
        tool_path.clone()
    };
    if request_shapes.is_empty() && response_fields.is_none() && response_root_text.is_none() {
        return None;
    }

    let metadata = generation.transform_metadata.get(generated_name);
    let Some(properties) = definition
        .input_schema
        .get("properties")
        .and_then(Value::as_object)
    else {
        problems.push(OverlayProblem {
            path: tool_path,
            message:
                "generated input schema has no properties object; this tool cannot be transformed"
                    .to_owned(),
        });
        return None;
    };
    let required = definition
        .input_schema
        .get("required")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();

    let mut compiled_parameters = Vec::new();
    for (wire_property, shape_or_use) in request_shapes {
        let shape_path = format!("{tool_path}/parameters/{wire_property}/shape");
        let Some(metadata) = metadata else {
            problems.push(OverlayProblem {
                path: shape_path,
                message: "OpenAPI request metadata is unavailable for this generated tool"
                    .to_owned(),
            });
            continue;
        };
        if metadata.array_request_body {
            // `validate_parameter_names` already reports this in the common
            // path. Keep this guard for direct/manual compiler callers.
            continue;
        }
        if !metadata.body_properties.contains(wire_property.as_str()) {
            problems.push(OverlayProblem {
                path: shape_path,
                message: format!(
                    "'{wire_property}' is not a JSON request-body property; path and query parameters cannot be shaped"
                ),
            });
            continue;
        }
        let Some(wire_schema) = properties.get(wire_property) else {
            continue;
        };
        if !schema_definitely_has_type(wire_schema, JsonType::Object) {
            problems.push(OverlayProblem {
                path: shape_path,
                message: format!(
                    "generated request-body property '{wire_property}' must have type object to be shaped"
                ),
            });
            continue;
        }
        let Some((shape, prefix)) = resolve_shape(
            shape_or_use,
            &overlay.shapes,
            wire_property,
            &shape_path,
            problems,
        ) else {
            continue;
        };
        if let Some(compiled) = compile_shape(
            wire_property,
            required.contains(wire_property.as_str()),
            shape,
            prefix.as_deref(),
            std::slice::from_ref(wire_schema),
            true,
            false,
            &shape_path,
            warnings,
            problems,
        ) {
            compiled_parameters.push(compiled);
        }
    }

    let response_root =
        response_root_text.and_then(|selector| match selector.parse::<Selector>() {
            Ok(selector) => Some(selector),
            Err(message) => {
                problems.push(OverlayProblem {
                    path: tool
                        .response
                        .as_ref()
                        .and_then(|response| response.root.as_ref())
                        .map_or_else(
                            || "/defaults/response_root".to_owned(),
                            |_| format!("{tool_path}/response/root"),
                        ),
                    message,
                });
                None
            }
        });
    let needs_response_schema =
        !compiled_parameters.is_empty() || response_fields.is_some() || response_root.is_some();
    let response_roots = if needs_response_schema {
        selected_response_root_schemas(
            generation,
            generated_name,
            response_root.as_ref(),
            &response_root_path,
            warnings,
            problems,
        )
    } else {
        None
    };

    for compiled in &compiled_parameters {
        validate_compiled_shape_response(
            &compiled.parameter,
            response_roots.as_deref(),
            &format!(
                "{tool_path}/parameters/{}/shape",
                compiled.parameter.wire_property
            ),
            warnings,
            problems,
        );
    }

    let mut compiled_response_fields = Vec::new();
    if let Some(fields) = response_fields {
        for (wire_property, shape_or_use) in fields {
            let shape_path = format!("{tool_path}/response/fields/{wire_property}");
            let Some((shape, prefix)) = resolve_shape(
                shape_or_use,
                &overlay.shapes,
                wire_property,
                &shape_path,
                problems,
            ) else {
                continue;
            };
            let wire_schemas = match response_roots.as_deref() {
                Some(roots) => {
                    let pointer = format!("/{}", json_pointer_escape(wire_property))
                        .parse::<JsonPointer>()
                        .expect("an escaped property name is a valid JSON pointer");
                    match resolve_pointer_schemas(roots, &pointer) {
                        SchemaResolution::Verified(schemas) => schemas,
                        SchemaResolution::Unverifiable => {
                            warnings.push(OverlayWarning {
                                path: shape_path.clone(),
                                message: format!(
                                    "response field '{wire_property}' cannot be verified against a free-form declared success schema"
                                ),
                            });
                            Vec::new()
                        }
                        SchemaResolution::Missing => {
                            problems.push(OverlayProblem {
                                path: shape_path.clone(),
                                message: format!(
                                    "response field '{wire_property}' is absent from the selected object schema"
                                ),
                            });
                            continue;
                        }
                    }
                }
                None => Vec::new(),
            };
            if let Some(compiled) = compile_shape(
                wire_property,
                false,
                shape,
                prefix.as_deref(),
                &wire_schemas,
                false,
                true,
                &shape_path,
                warnings,
                problems,
            ) {
                compiled_response_fields.push(compiled.parameter);
            }
        }
    }

    let response_shapes = compiled_parameters
        .iter()
        .map(|compiled| {
            (
                &compiled.parameter,
                format!(
                    "{tool_path}/parameters/{}/shape",
                    compiled.parameter.wire_property
                ),
            )
        })
        .chain(compiled_response_fields.iter().map(|compiled| {
            (
                compiled,
                format!("{tool_path}/response/fields/{}", compiled.wire_property),
            )
        }))
        .collect::<Vec<_>>();
    let mut response_wire_owners = BTreeMap::<String, String>::new();
    let mut response_agent_owners = BTreeMap::<String, String>::new();
    for (parameter, shape_path) in &response_shapes {
        if let Some(first_path) =
            response_wire_owners.insert(parameter.wire_property.clone(), shape_path.clone())
        {
            problems.push(OverlayProblem {
                path: shape_path.clone(),
                message: format!(
                    "wire property '{}' is already transformed by shape at {first_path}",
                    parameter.wire_property
                ),
            });
        }
        for agent in &parameter.agent {
            if let Some(first_path) =
                response_agent_owners.insert(agent.name.clone(), shape_path.clone())
            {
                problems.push(OverlayProblem {
                    path: format!("{shape_path}/agent/{}", agent.name),
                    message: format!(
                        "response agent property '{}' is already produced by shape at {first_path}",
                        agent.name
                    ),
                });
            }
        }
    }
    if let Some(roots) = response_roots.as_deref() {
        let existing_response_properties = roots
            .iter()
            .filter_map(|root| root.get("properties").and_then(Value::as_object))
            .flat_map(|properties| properties.keys().cloned())
            .collect::<BTreeSet<_>>();
        for (parameter, shape_path) in &response_shapes {
            for agent in &parameter.agent {
                if agent.name != parameter.wire_property
                    && existing_response_properties.contains(&agent.name)
                {
                    problems.push(OverlayProblem {
                        path: format!("{shape_path}/agent/{}", agent.name),
                        message: format!(
                            "response agent property '{}' collides with an existing property of the selected response object",
                            agent.name
                        ),
                    });
                }
            }
        }
    }

    let mut input_schema = definition.input_schema.clone();
    let input_properties = input_schema
        .get_mut("properties")
        .and_then(Value::as_object_mut)?;
    let shaped_names = compiled_parameters
        .iter()
        .map(|compiled| compiled.parameter.wire_property.as_str())
        .collect::<BTreeSet<_>>();
    let mut occupied = input_properties
        .keys()
        .filter(|name| !shaped_names.contains(name.as_str()))
        .cloned()
        .collect::<BTreeSet<_>>();
    for compiled in &compiled_parameters {
        for agent in &compiled.parameter.agent {
            let aliases_other_wire_property = agent.name != compiled.parameter.wire_property
                && shaped_names.contains(agent.name.as_str());
            if aliases_other_wire_property || !occupied.insert(agent.name.clone()) {
                problems.push(OverlayProblem {
                    path: format!(
                        "{tool_path}/parameters/{}/shape/agent/{}",
                        compiled.parameter.wire_property, agent.name
                    ),
                    message: format!(
                        "agent-facing property '{}' collides with another top-level property after all shapes are applied",
                        agent.name
                    ),
                });
            }
        }
    }
    if problems
        .iter()
        .any(|problem| problem.path.starts_with(&tool_path))
    {
        return None;
    }

    let mut rewritten_required = required;
    for compiled in &compiled_parameters {
        input_properties.remove(&compiled.parameter.wire_property);
        rewritten_required.remove(&compiled.parameter.wire_property);
        for agent in &compiled.parameter.agent {
            input_properties.insert(agent.name.clone(), agent.schema.clone());
        }
        rewritten_required.extend(compiled.required_agent_names.iter().cloned());
    }
    if let Some(object) = input_schema.as_object_mut() {
        object.insert(
            "required".to_owned(),
            Value::Array(rewritten_required.into_iter().map(Value::String).collect()),
        );
    }
    if let Err(error) = jsonschema::validator_for(&input_schema) {
        problems.push(OverlayProblem {
            path: tool_path,
            message: format!("transformed agent input schema does not compile: {error}"),
        });
        return None;
    }

    Some(CompiledToolTransform {
        input_schema,
        transform: ToolTransform {
            parameters: compiled_parameters
                .into_iter()
                .map(|compiled| compiled.parameter)
                .collect(),
            response_fields: compiled_response_fields,
            response_root,
        },
    })
}

fn resolve_shape<'a>(
    shape_or_use: &'a ShapeOrUse,
    shapes: &'a BTreeMap<String, Shape>,
    wire_property: &str,
    path: &str,
    problems: &mut Vec<OverlayProblem>,
) -> Option<(&'a Shape, Option<String>)> {
    match shape_or_use {
        ShapeOrUse::Inline(shape) => Some((shape, None)),
        ShapeOrUse::Use(reference) => match shapes.get(&reference.shape_id) {
            Some(shape) => Some((
                shape,
                Some(
                    reference
                        .prefix
                        .clone()
                        .unwrap_or_else(|| wire_property.to_owned()),
                ),
            )),
            None => {
                problems.push(OverlayProblem {
                    path: format!("{path}/$use"),
                    message: format!("unknown reusable shape '{}'", reference.shape_id),
                });
                None
            }
        },
    }
}

#[allow(clippy::too_many_arguments)]
fn compile_shape(
    wire_property: &str,
    wire_required: bool,
    shape: &Shape,
    prefix: Option<&str>,
    wire_schemas: &[Value],
    validate_wire_bindings: bool,
    validate_response_bindings: bool,
    path: &str,
    warnings: &mut Vec<OverlayWarning>,
    problems: &mut Vec<OverlayProblem>,
) -> Option<CompiledShape> {
    let compiled_name = |name: &str| match prefix {
        Some(prefix) => format!("{prefix}_{name}"),
        None => name.to_owned(),
    };
    let names = shape
        .agent
        .keys()
        .map(|name| (name.as_str(), compiled_name(name)))
        .collect::<BTreeMap<_, _>>();
    let agent = shape
        .agent
        .iter()
        .map(|(name, schema)| AgentProperty {
            name: names[name.as_str()].clone(),
            schema: schema.clone(),
        })
        .collect::<Vec<_>>();
    let required_agent_names = match &shape.required {
        Some(required) => required
            .iter()
            .filter_map(|name| names.get(name.as_str()).cloned())
            .collect(),
        None if wire_required => agent.iter().map(|agent| agent.name.clone()).collect(),
        None => Vec::new(),
    };

    let mut wire = Vec::new();
    let mut derived = BTreeMap::<&str, Vec<(&str, Vec<Codec>)>>::new();
    for (pointer_text, authored) in &shape.wire {
        let pointer = match pointer_text.parse::<JsonPointer>() {
            Ok(pointer) => pointer,
            Err(message) => {
                problems.push(OverlayProblem {
                    path: format!("{path}/wire/{pointer_text}"),
                    message,
                });
                continue;
            }
        };
        let codecs = authored.codecs();
        let source = match authored {
            OverlayWireBinding::From { from, .. } => {
                let Some(compiled_from) = names.get(from.as_str()) else {
                    continue;
                };
                derived
                    .entry(from.as_str())
                    .or_default()
                    .push((pointer_text.as_str(), codecs.clone()));
                WireSource::From {
                    from: compiled_from.clone(),
                }
            }
            OverlayWireBinding::Const { r#const, .. } => WireSource::Const {
                r#const: r#const.clone(),
            },
        };
        let input_type = match authored {
            OverlayWireBinding::From { from, .. } => shape.agent.get(from).and_then(fragment_type),
            OverlayWireBinding::Const { r#const, .. } => value_type(r#const),
        };
        if validate_wire_bindings {
            if pointer_crosses_declared_array(wire_schemas, &pointer) {
                problems.push(OverlayProblem {
                    path: format!("{path}/wire/{pointer_text}"),
                    message: format!(
                        "wire pointer '{}' crosses an array; request-shape pointers may only build object containers in overlay schema 0.1.0",
                        pointer.as_str()
                    ),
                });
            }
            validate_wire_pointer_and_chain(
                wire_schemas,
                &pointer,
                input_type,
                &codecs,
                &format!("{path}/wire/{pointer_text}"),
                warnings,
                problems,
            );
        }
        wire.push(WireBinding {
            pointer,
            source,
            codecs,
        });
    }

    let mut response = Vec::new();
    for (local_name, compiled_name) in &names {
        if let Some(authored) = shape.response.get(*local_name) {
            let from = match authored.from.parse::<JsonPointer>() {
                Ok(pointer) => pointer,
                Err(message) => {
                    problems.push(OverlayProblem {
                        path: format!("{path}/response/{local_name}/from"),
                        message,
                    });
                    continue;
                }
            };
            let codecs = authored
                .codec
                .as_ref()
                .map(CodecChain::to_vec)
                .unwrap_or_default();
            if validate_response_bindings {
                validate_wire_pointer_and_chain(
                    wire_schemas,
                    &from,
                    shape.agent.get(*local_name).and_then(fragment_type),
                    &codecs,
                    &format!("{path}/response/{local_name}"),
                    warnings,
                    problems,
                );
            }
            response.push(ResponseBinding {
                agent_property: compiled_name.clone(),
                from,
                codecs,
            });
        } else if let Some(bindings) = derived.get(local_name).filter(|bindings| {
            bindings.len() == 1
                && !bindings[0]
                    .1
                    .iter()
                    .any(|codec| matches!(codec, Codec::MarkdownBlocks { .. }))
        }) {
            let (pointer, codecs) = &bindings[0];
            let from = pointer
                .parse()
                .expect("wire pointer was parsed successfully above");
            if validate_response_bindings {
                validate_wire_pointer_and_chain(
                    wire_schemas,
                    &from,
                    shape.agent.get(*local_name).and_then(fragment_type),
                    codecs,
                    &format!("{path}/response/{local_name}"),
                    warnings,
                    problems,
                );
            }
            response.push(ResponseBinding {
                agent_property: compiled_name.clone(),
                from,
                codecs: codecs.clone(),
            });
        }
    }

    if problems
        .iter()
        .any(|problem| problem.path.starts_with(path))
    {
        return None;
    }
    Some(CompiledShape {
        parameter: ParameterShape {
            wire_property: wire_property.to_owned(),
            wire_required,
            agent,
            wire,
            response,
        },
        required_agent_names,
    })
}

fn selected_response_root_schemas(
    generation: &OpenApiToolGeneration,
    generated_name: &str,
    selector: Option<&Selector>,
    root_path: &str,
    warnings: &mut Vec<OverlayWarning>,
    problems: &mut Vec<OverlayProblem>,
) -> Option<Vec<Value>> {
    let declared = match generation.declared_success_response_schemas(generated_name) {
        Ok(declared) => declared,
        Err(error) => {
            problems.push(OverlayProblem {
                path: root_path.to_owned(),
                message: format!("declared success response schema cannot be resolved: {error}"),
            });
            return None;
        }
    };
    if declared.is_empty() {
        warnings.push(OverlayWarning {
            path: root_path.to_owned(),
            message: format!(
                "'{generated_name}' declares no JSON 2xx response schema; the response transform is unverified"
            ),
        });
        return None;
    }

    let mut selected = Vec::new();
    for response in declared {
        let resolution = match selector {
            Some(selector) => {
                select_object_schemas(std::slice::from_ref(&response.schema), selector)
            }
            None => root_object_schema(response.schema.clone()),
        };
        match resolution {
            SchemaResolution::Verified(mut schemas) if !schemas.is_empty() => {
                selected.append(&mut schemas);
            }
            SchemaResolution::Verified(_) | SchemaResolution::Missing => {
                let selected_root = selector.map_or("the response root", Selector::as_str);
                problems.push(OverlayProblem {
                    path: root_path.to_owned(),
                    message: format!(
                        "response root '{selected_root}' selects no object in the {} response of {generated_name}",
                        response.status
                    ),
                });
            }
            SchemaResolution::Unverifiable => warnings.push(OverlayWarning {
                path: root_path.to_owned(),
                message: format!(
                    "response root for '{generated_name}' cannot be verified against the free-form {} response schema",
                    response.status
                ),
            }),
        }
    }
    (!selected.is_empty()).then_some(selected)
}

fn root_object_schema(schema: Value) -> SchemaResolution {
    match fragment_type(&schema) {
        Some(JsonType::Object) => SchemaResolution::Verified(vec![schema]),
        Some(_) => SchemaResolution::Missing,
        None if schema.get("properties").is_some() => SchemaResolution::Verified(vec![schema]),
        None => SchemaResolution::Unverifiable,
    }
}

fn validate_compiled_shape_response(
    shape: &ParameterShape,
    response_roots: Option<&[Value]>,
    path: &str,
    warnings: &mut Vec<OverlayWarning>,
    problems: &mut Vec<OverlayProblem>,
) {
    let Some(response_roots) = response_roots else {
        return;
    };
    let property_pointer = format!("/{}", json_pointer_escape(&shape.wire_property))
        .parse::<JsonPointer>()
        .expect("escaped property name is a valid JSON pointer");
    let wire_schemas = match resolve_pointer_schemas(response_roots, &property_pointer) {
        SchemaResolution::Verified(schemas) if !schemas.is_empty() => schemas,
        SchemaResolution::Verified(_) | SchemaResolution::Missing => {
            problems.push(OverlayProblem {
                path: path.to_owned(),
                message: format!(
                    "wire property '{}' is absent from the selected success-response object schema",
                    shape.wire_property
                ),
            });
            return;
        }
        SchemaResolution::Unverifiable => {
            warnings.push(OverlayWarning {
                path: path.to_owned(),
                message: format!(
                    "wire property '{}' cannot be verified against a free-form success-response schema",
                    shape.wire_property
                ),
            });
            return;
        }
    };

    let agent_types = shape
        .agent
        .iter()
        .filter_map(|agent| fragment_type(&agent.schema).map(|kind| (agent.name.as_str(), kind)))
        .collect::<BTreeMap<_, _>>();
    for response in &shape.response {
        validate_wire_pointer_and_chain(
            &wire_schemas,
            &response.from,
            agent_types.get(response.agent_property.as_str()).copied(),
            &response.codecs,
            &format!("{path}/response/{}", response.agent_property),
            warnings,
            problems,
        );
    }
}

fn validate_wire_pointer_and_chain(
    wire_schemas: &[Value],
    pointer: &JsonPointer,
    input_type: Option<JsonType>,
    codecs: &[Codec],
    path: &str,
    warnings: &mut Vec<OverlayWarning>,
    problems: &mut Vec<OverlayProblem>,
) {
    let output_type = match input_type {
        Some(input_type) => match check_codec_input(input_type, codecs) {
            Ok(output_type) => Some(output_type),
            Err(message) => {
                problems.push(OverlayProblem {
                    path: format!("{path}/codec"),
                    message,
                });
                None
            }
        },
        None => None,
    };
    if wire_schemas.is_empty() {
        return;
    }
    match resolve_pointer_schemas(wire_schemas, pointer) {
        SchemaResolution::Missing => {
            problems.push(OverlayProblem {
                path: path.to_owned(),
                message: format!(
                    "wire pointer '{}' does not exist in the declared wire schema",
                    pointer.as_str()
                ),
            });
        }
        SchemaResolution::Verified(schemas) if schemas.is_empty() => {
            problems.push(OverlayProblem {
                path: path.to_owned(),
                message: format!(
                    "wire pointer '{}' does not exist in the declared wire schema",
                    pointer.as_str()
                ),
            });
        }
        SchemaResolution::Unverifiable => warnings.push(OverlayWarning {
            path: path.to_owned(),
            message: format!(
                "wire pointer '{}' cannot be verified because the declared wire schema is free-form",
                pointer.as_str()
            ),
        }),
        SchemaResolution::Verified(schemas) => {
            let mut saw_unknown = false;
            for schema in schemas {
                let Some(wire_type) = fragment_type(&schema) else {
                    saw_unknown = true;
                    continue;
                };
                if output_type.is_some_and(|output| !types_compatible(output, wire_type)) {
                    problems.push(OverlayProblem {
                        path: format!("{path}/codec"),
                        message: format!(
                            "codec chain output type {} does not match wire pointer '{}' type {}",
                            output_type.expect("checked Some"),
                            pointer.as_str(),
                            wire_type
                        ),
                    });
                }
            }
            if saw_unknown {
                warnings.push(OverlayWarning {
                    path: path.to_owned(),
                    message: format!(
                        "wire pointer '{}' has no definite schema type; codec output is unverified",
                        pointer.as_str()
                    ),
                });
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JsonType {
    String,
    Number,
    Integer,
    Boolean,
    Array,
    Object,
    Null,
}

impl fmt::Display for JsonType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::String => "string",
            Self::Number => "number",
            Self::Integer => "integer",
            Self::Boolean => "boolean",
            Self::Array => "array",
            Self::Object => "object",
            Self::Null => "null",
        })
    }
}

fn fragment_type(schema: &Value) -> Option<JsonType> {
    match schema.get("type")?.as_str()? {
        "string" => Some(JsonType::String),
        "number" => Some(JsonType::Number),
        "integer" => Some(JsonType::Integer),
        "boolean" => Some(JsonType::Boolean),
        "array" => Some(JsonType::Array),
        "object" => Some(JsonType::Object),
        "null" => Some(JsonType::Null),
        _ => None,
    }
}

fn value_type(value: &Value) -> Option<JsonType> {
    match value {
        Value::Null => Some(JsonType::Null),
        Value::Bool(_) => Some(JsonType::Boolean),
        Value::Number(number) => Some(if number.is_i64() || number.is_u64() {
            JsonType::Integer
        } else {
            JsonType::Number
        }),
        Value::String(_) => Some(JsonType::String),
        Value::Array(_) => Some(JsonType::Array),
        Value::Object(_) => Some(JsonType::Object),
    }
}

fn schema_definitely_has_type(schema: &Value, expected: JsonType) -> bool {
    fragment_type(schema).is_some_and(|actual| types_compatible(actual, expected))
}

fn types_compatible(actual: JsonType, expected: JsonType) -> bool {
    actual == expected || (actual == JsonType::Integer && expected == JsonType::Number)
}

fn check_codec_input(mut current: JsonType, codecs: &[Codec]) -> Result<JsonType, String> {
    for codec in codecs {
        current = match codec {
            Codec::DecimalScale { wire_encoding, .. } => {
                if !matches!(current, JsonType::Number | JsonType::Integer) {
                    return Err(format!(
                        "decimal_scale requires number or integer input, got {current}"
                    ));
                }
                match wire_encoding {
                    DecimalWireEncoding::IntegerString => JsonType::String,
                    DecimalWireEncoding::Integer => JsonType::Integer,
                }
            }
            Codec::MarkdownBlocks { .. } => {
                if current != JsonType::String {
                    return Err(format!(
                        "markdown_blocks requires string input, got {current}"
                    ));
                }
                JsonType::Array
            }
            Codec::JsonString => JsonType::String,
        };
    }
    Ok(current)
}

fn json_pointer_escape(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

/// Request materialisation deliberately creates object containers. RFC 6901
/// text cannot distinguish an object key named `0` from array index zero, so
/// compiling an encode pointer through a declared array without retaining
/// container metadata would silently put the value at the wrong wire shape.
/// Response pointers remain free to traverse arrays because they read an
/// already-materialised JSON value.
fn pointer_crosses_declared_array(roots: &[Value], pointer: &JsonPointer) -> bool {
    let tokens = if pointer.as_str().is_empty() {
        Vec::new()
    } else {
        pointer.as_str()[1..]
            .split('/')
            .map(|token| token.replace("~1", "/").replace("~0", "~"))
            .collect::<Vec<_>>()
    };
    let mut candidates = roots.to_vec();
    for token in tokens {
        let mut next = Vec::new();
        for candidate in candidates {
            if collect_object_property_schemas(&candidate, &token, &mut next) {
                return true;
            }
        }
        candidates = next;
        if candidates.is_empty() {
            break;
        }
    }
    false
}

/// Returns true when this schema can be an array at the point where the next
/// pointer token would be applied. Otherwise, append any statically-known
/// object-property schemas for that token.
fn collect_object_property_schemas(schema: &Value, token: &str, next: &mut Vec<Value>) -> bool {
    let Value::Object(object) = schema else {
        return false;
    };
    for keyword in ["allOf", "anyOf", "oneOf"] {
        if let Some(branches) = object.get(keyword).and_then(Value::as_array) {
            for branch in branches {
                if collect_object_property_schemas(branch, token, next) {
                    return true;
                }
            }
        }
    }
    let declares_array = object
        .get("type")
        .is_some_and(|schema_type| match schema_type {
            Value::String(schema_type) => schema_type == "array",
            Value::Array(schema_types) => schema_types
                .iter()
                .any(|schema_type| schema_type.as_str() == Some("array")),
            _ => false,
        })
        || (object.contains_key("items") && !object.contains_key("properties"));
    if declares_array {
        return true;
    }
    if let Some(property) = object
        .get("properties")
        .and_then(Value::as_object)
        .and_then(|properties| properties.get(token))
    {
        next.push(property.clone());
    } else if let Some(additional) = object.get("additionalProperties") {
        if additional.is_object() {
            next.push(additional.clone());
        }
    }
    false
}

#[derive(Debug, Clone)]
struct CompiledStepInfo {
    generated_tool: String,
    max_runs: usize,
}

#[allow(clippy::too_many_arguments)]
fn compile_composites(
    generation: &OpenApiToolGeneration,
    overlay: &OverlayDocument,
    context: &OverlayCompileContext,
    bound_index: &BTreeMap<String, usize>,
    renames: &BTreeMap<String, String>,
    transformed: &BTreeMap<String, CompiledToolTransform>,
    source_plan: &OverlaySourcePlan,
    resolved: &ResolvedOverlaySources,
    definitions: &mut Vec<ToolDefinition>,
    security_selections: &mut Vec<OpenApiToolSecuritySelection>,
    warnings: &mut Vec<OverlayWarning>,
    problems: &mut Vec<OverlayProblem>,
) -> (Vec<OverlayCompositeReport>, BTreeSet<String>) {
    let generated_names = generation
        .definitions
        .iter()
        .map(|definition| definition.name.as_str())
        .collect::<BTreeSet<_>>();
    let mut reports = Vec::with_capacity(overlay.composites.len());
    let mut referenced_generated_tools = BTreeSet::new();

    for (composite_name, authored) in &overlay.composites {
        let problem_count = problems.len();
        let composite_path = format!("/composites/{composite_name}");
        let mut prior_steps = BTreeMap::<String, CompiledStepInfo>::new();
        let mut compiled_steps = authored.steps.clone();
        let mut all_steps_read_only = true;
        let mut iteration_bound = 0_usize;
        let mut steps_max = 0_usize;
        let mut first_definition_index = None;

        for (step_index, (step, compiled_step)) in authored
            .steps
            .iter()
            .zip(compiled_steps.iter_mut())
            .enumerate()
        {
            let step_path = format!("{composite_path}/steps/{step_index}");
            if prior_steps.contains_key(&step.id) {
                problems.push(OverlayProblem {
                    path: format!("{step_path}/id"),
                    message: format!("duplicate composite step id '{}'", step.id),
                });
            }

            let target_index = composite_tool_index(
                &step.tool,
                &format!("{step_path}/tool"),
                &generated_names,
                bound_index,
                renames,
                overlay,
                problems,
            );
            if let Some(index) = target_index {
                all_steps_read_only &= definitions[index].upstream.method == "GET";
                first_definition_index.get_or_insert(index);
                referenced_generated_tools.insert(step.tool.clone());
                validate_bound_arguments(
                    &step.arguments,
                    &definitions[index],
                    &format!("{step_path}/arguments"),
                    problems,
                );
                compiled_step.tool = definitions[index].name.clone();
            }

            for (argument, binding) in &step.arguments {
                validate_composite_binding(
                    binding,
                    &format!("{step_path}/arguments/{argument}"),
                    &authored.input,
                    &prior_steps,
                    step.for_each.as_ref(),
                    None,
                    generation,
                    transformed,
                    warnings,
                    problems,
                );
            }

            let max_runs = if let Some(for_each) = &step.for_each {
                validate_composite_binding(
                    &for_each.over,
                    &format!("{step_path}/for_each/over"),
                    &authored.input,
                    &prior_steps,
                    None,
                    None,
                    generation,
                    transformed,
                    warnings,
                    problems,
                );
                let bound = for_each_iteration_bound(
                    &for_each.over,
                    &authored.input,
                    &prior_steps,
                    &format!("{step_path}/for_each/over"),
                    problems,
                );
                iteration_bound = iteration_bound.saturating_add(bound);
                steps_max = steps_max.saturating_add(bound);
                bound
            } else {
                steps_max = steps_max.saturating_add(1);
                1
            };

            if let Some(compensation) = &step.compensate {
                let compensation_path = format!("{step_path}/compensate");
                let compensation_index = composite_tool_index(
                    &compensation.tool,
                    &format!("{compensation_path}/tool"),
                    &generated_names,
                    bound_index,
                    renames,
                    overlay,
                    problems,
                );
                if let Some(index) = compensation_index {
                    all_steps_read_only &= definitions[index].upstream.method == "GET";
                    referenced_generated_tools.insert(compensation.tool.clone());
                    validate_bound_arguments(
                        &compensation.arguments,
                        &definitions[index],
                        &format!("{compensation_path}/arguments"),
                        problems,
                    );
                    if let Some(compiled) = compiled_step.compensate.as_mut() {
                        compiled.tool = definitions[index].name.clone();
                    }
                }
                for (argument, binding) in &compensation.arguments {
                    validate_composite_binding(
                        binding,
                        &format!("{compensation_path}/arguments/{argument}"),
                        &authored.input,
                        &prior_steps,
                        step.for_each.as_ref(),
                        Some(step.tool.as_str()),
                        generation,
                        transformed,
                        warnings,
                        problems,
                    );
                }
            }

            prior_steps.insert(
                step.id.clone(),
                CompiledStepInfo {
                    generated_tool: step.tool.clone(),
                    max_runs,
                },
            );
        }

        if iteration_bound > authored.limits.max_iterations {
            problems.push(OverlayProblem {
                path: format!("{composite_path}/limits/max_iterations"),
                message: format!(
                    "for_each bounds total {iteration_bound} iterations, exceeding max_iterations {}",
                    authored.limits.max_iterations
                ),
            });
        }

        if authored
            .annotations
            .as_ref()
            .and_then(|annotations| annotations.read_only_hint)
            == Some(true)
            && !all_steps_read_only
        {
            problems.push(OverlayProblem {
                path: format!("{composite_path}/annotations/readOnlyHint"),
                message: "a composite containing a non-GET step or compensation cannot declare readOnlyHint true".to_owned(),
            });
        }

        if let Some(result) = &authored.result {
            for (property, binding) in result {
                validate_composite_binding(
                    binding,
                    &format!("{composite_path}/result/{property}"),
                    &authored.input,
                    &prior_steps,
                    None,
                    None,
                    generation,
                    transformed,
                    warnings,
                    problems,
                );
            }
        }

        let mut input_properties = authored.input.properties.clone();
        let mut enum_bindings = Vec::new();
        for (property, parameter) in &authored.parameters {
            let Some(source_id) = parameter.enum_source.as_deref() else {
                continue;
            };
            let enum_path = format!("{composite_path}/parameters/{property}/enum_source");
            let Some(source) = source_plan.enum_sources.get(source_id) else {
                problems.push(OverlayProblem {
                    path: enum_path,
                    message: format!("unknown enum source '{source_id}'"),
                });
                continue;
            };
            let Some(schema) = input_properties.get_mut(property) else {
                problems.push(OverlayProblem {
                    path: format!("{composite_path}/parameters/{property}"),
                    message: format!(
                        "'{property}' is not declared in this composite's input.properties"
                    ),
                });
                continue;
            };
            let Some(target) = dynamic_enum_schema(schema) else {
                problems.push(OverlayProblem {
                    path: enum_path,
                    message: format!(
                        "'{property}' must have type string or boolean, or be an array whose items have type string or boolean"
                    ),
                });
                continue;
            };
            let expects_boolean = target.get("type").and_then(Value::as_str) == Some("boolean");
            if let Some(resolved_source) = resolved.enum_sources.get(source_id) {
                if resolved_source.values.iter().any(|value| {
                    if expects_boolean {
                        !value.is_boolean()
                    } else {
                        !value.is_string()
                    }
                }) {
                    problems.push(OverlayProblem {
                        path: enum_path,
                        message: format!(
                            "enum source '{source_id}' values do not match the composite '{}' property type",
                            target.get("type").and_then(Value::as_str).unwrap_or("unknown")
                        ),
                    });
                    continue;
                }
            }
            if let Some(schema) = schema.as_object_mut() {
                remove_static_enum(schema);
            }
            enum_bindings.push(EnumBinding {
                property: property.clone(),
                source_id: source_id.to_owned(),
                source_digest: source.source_digest.clone(),
            });
        }
        enum_bindings.sort_by(|left, right| left.property.cmp(&right.property));

        if problems.len() != problem_count {
            continue;
        }

        let Some(first_definition_index) = first_definition_index else {
            continue;
        };
        let (connection_id, catalog_revision) = match &definitions[first_definition_index].source {
            ToolSource::OpenApi {
                connection_id,
                catalog_revision,
                ..
            } => (connection_id.clone(), *catalog_revision),
            _ => {
                problems.push(OverlayProblem {
                    path: composite_path,
                    message: "composite steps must resolve to an OpenAPI catalog".to_owned(),
                });
                continue;
            }
        };

        let input_schema = Value::Object(Map::from_iter([
            ("type".to_owned(), Value::String("object".to_owned())),
            (
                "properties".to_owned(),
                Value::Object(Map::from_iter(input_properties)),
            ),
            (
                "required".to_owned(),
                Value::Array(
                    authored
                        .input
                        .required
                        .iter()
                        .cloned()
                        .map(Value::String)
                        .collect(),
                ),
            ),
            ("additionalProperties".to_owned(), Value::Bool(false)),
        ]));
        if let Err(error) = jsonschema::validator_for(&input_schema) {
            problems.push(OverlayProblem {
                path: format!("{composite_path}/input"),
                message: format!("compiled composite input is not valid JSON Schema: {error}"),
            });
            continue;
        }

        let mapping = CompositeMapping {
            steps: compiled_steps,
            result: authored.result.clone(),
            limits: authored.limits,
        };
        definitions.push(ToolDefinition {
            name: composite_name.clone(),
            title: authored.title.clone(),
            description: authored.description.clone(),
            input_schema,
            target: Some(ToolTarget::Composite {
                connection_id: connection_id.clone(),
            }),
            source: ToolSource::OpenApi {
                connection_id,
                operation_id: None,
                catalog_revision,
            },
            upstream: HttpToolMapping::composite_sentinel(),
            transform: None,
            composite: Some(mapping),
            visibility: ToolVisibility::Listed,
            enum_bindings,
            annotations: authored.annotations.clone(),
        });
        security_selections.push(OpenApiToolSecuritySelection {
            tool_name: composite_name.clone(),
            selected_scheme_names: Vec::new(),
        });

        let policy_entry_present = context.policy_tool_names.contains(composite_name);
        if !policy_entry_present {
            warnings.push(OverlayWarning {
                path: composite_path,
                message: format!(
                    "no policy entry for '{composite_name}': under default-deny it is invisible; under default-allow it uses the runtime default timeout, which must cover steps_max = {steps_max}"
                ),
            });
        }
        reports.push(OverlayCompositeReport {
            name: composite_name.clone(),
            steps_max,
            policy_entry_present,
        });
    }

    (reports, referenced_generated_tools)
}

#[allow(clippy::too_many_arguments)]
fn composite_tool_index(
    tool_name: &str,
    path: &str,
    generated_names: &BTreeSet<&str>,
    bound_index: &BTreeMap<String, usize>,
    renames: &BTreeMap<String, String>,
    overlay: &OverlayDocument,
    problems: &mut Vec<OverlayProblem>,
) -> Option<usize> {
    if let Some((generated, _)) = renames
        .iter()
        .find(|(_, served)| served.as_str() == tool_name)
    {
        problems.push(OverlayProblem {
            path: path.to_owned(),
            message: format!(
                "'{tool_name}' is a served rename; overlay references use the generated name '{generated}'"
            ),
        });
        return None;
    }
    if overlay.composites.contains_key(tool_name) {
        problems.push(OverlayProblem {
            path: path.to_owned(),
            message: format!(
                "'{tool_name}' is a composite; composite steps must name non-composite generated tools"
            ),
        });
        return None;
    }
    if !generated_names.contains(tool_name) {
        let hint = generated_names
            .iter()
            .find(|candidate| candidate.eq_ignore_ascii_case(tool_name))
            .map(|candidate| format!("; did you mean '{candidate}'"))
            .unwrap_or_default();
        problems.push(OverlayProblem {
            path: path.to_owned(),
            message: format!("unknown generated tool '{tool_name}'{hint}"),
        });
        return None;
    }
    let Some(index) = bound_index.get(tool_name).copied() else {
        problems.push(OverlayProblem {
            path: path.to_owned(),
            message: format!(
                "generated tool '{tool_name}' is not selected in this catalog and cannot be used by a composite"
            ),
        });
        return None;
    };
    Some(index)
}

fn validate_bound_arguments(
    arguments: &BTreeMap<String, CompositeBinding>,
    definition: &ToolDefinition,
    path: &str,
    problems: &mut Vec<OverlayProblem>,
) {
    let properties = definition
        .input_schema
        .get("properties")
        .and_then(Value::as_object);
    for required in definition
        .input_schema
        .get("required")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
    {
        if !arguments.contains_key(required) {
            problems.push(OverlayProblem {
                path: path.to_owned(),
                message: format!(
                    "required argument '{required}' of tool '{}' is not bound",
                    definition.name
                ),
            });
        }
    }
    if definition.input_schema.get("additionalProperties") == Some(&Value::Bool(false)) {
        for argument in arguments.keys() {
            if properties.is_none_or(|properties| !properties.contains_key(argument)) {
                problems.push(OverlayProblem {
                    path: format!("{path}/{argument}"),
                    message: format!(
                        "'{argument}' is not an input property of tool '{}'",
                        definition.name
                    ),
                });
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_composite_binding(
    binding: &CompositeBinding,
    path: &str,
    input: &CompositeInput,
    visible_steps: &BTreeMap<String, CompiledStepInfo>,
    item_scope: Option<&crate::tools::composite::CompositeForEach>,
    self_tool: Option<&str>,
    generation: &OpenApiToolGeneration,
    transformed: &BTreeMap<String, CompiledToolTransform>,
    warnings: &mut Vec<OverlayWarning>,
    problems: &mut Vec<OverlayProblem>,
) {
    match binding {
        CompositeBinding::Literal(_) => {}
        CompositeBinding::Input {
            input: input_name,
            pointer,
        } => {
            let Some(fragment) = input.properties.get(input_name) else {
                problems.push(OverlayProblem {
                    path: path.to_owned(),
                    message: format!("unknown composite input '{input_name}'"),
                });
                return;
            };
            if let Some(pointer) = pointer {
                match schema_pointer_check(fragment, fragment, pointer, 0) {
                    PointerCheck::Exists => {}
                    PointerCheck::Unverifiable => warnings.push(OverlayWarning {
                        path: path.to_owned(),
                        message: format!(
                            "input pointer '{pointer}' enters a free-form schema and cannot be verified"
                        ),
                    }),
                    PointerCheck::Missing
                    | PointerCheck::AlternativeForbidden
                    | PointerCheck::Forbidden => {
                        problems.push(OverlayProblem {
                        path: path.to_owned(),
                        message: format!(
                            "input pointer '{pointer}' does not exist in input '{input_name}'"
                        ),
                        })
                    }
                }
            }
        }
        CompositeBinding::Step {
            step,
            pointer,
            collect,
        } => {
            let Some(info) = visible_steps.get(step) else {
                problems.push(OverlayProblem {
                    path: path.to_owned(),
                    message: format!(
                        "$step '{step}' must name an earlier step (forward and missing references are rejected)"
                    ),
                });
                return;
            };
            if info.max_runs > 1 && !collect {
                problems.push(OverlayProblem {
                    path: path.to_owned(),
                    message: format!("$step '{step}' may run more than once; set collect to true"),
                });
            }
            validate_response_pointer(
                generation,
                transformed,
                &info.generated_tool,
                pointer.as_deref(),
                path,
                warnings,
                problems,
            );
        }
        CompositeBinding::Item { item, pointer } => {
            let Some(item_scope) = item_scope.filter(|scope| scope.item_name == *item) else {
                problems.push(OverlayProblem {
                    path: path.to_owned(),
                    message: format!(
                        "$item '{item}' is only valid inside a for_each step whose 'as' value matches"
                    ),
                });
                return;
            };
            if let Some(pointer) = pointer.as_deref().filter(|pointer| !pointer.is_empty()) {
                validate_item_pointer(
                    &item_scope.over,
                    pointer,
                    input,
                    visible_steps,
                    generation,
                    transformed,
                    path,
                    warnings,
                    problems,
                );
            }
        }
        CompositeBinding::SelfValue { pointer } => {
            let Some(tool_name) = self_tool else {
                problems.push(OverlayProblem {
                    path: path.to_owned(),
                    message: "$self is only valid inside compensate.arguments".to_owned(),
                });
                return;
            };
            validate_response_pointer(
                generation,
                transformed,
                tool_name,
                Some(pointer),
                path,
                warnings,
                problems,
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_item_pointer(
    over: &CompositeBinding,
    item_pointer: &str,
    input: &CompositeInput,
    visible_steps: &BTreeMap<String, CompiledStepInfo>,
    generation: &OpenApiToolGeneration,
    transformed: &BTreeMap<String, CompiledToolTransform>,
    path: &str,
    warnings: &mut Vec<OverlayWarning>,
    problems: &mut Vec<OverlayProblem>,
) {
    match over {
        CompositeBinding::Input {
            input: input_name,
            pointer: None,
        } => {
            let Some(fragment) = input.properties.get(input_name) else {
                return;
            };
            let Some(items) = fragment.get("items") else {
                warnings.push(OverlayWarning {
                    path: path.to_owned(),
                    message: format!(
                        "$item pointer '{item_pointer}' enters the unconstrained items of input '{input_name}' and cannot be verified"
                    ),
                });
                return;
            };
            match schema_pointer_check(fragment, items, item_pointer, 0) {
                PointerCheck::Exists => {}
                PointerCheck::Unverifiable => warnings.push(OverlayWarning {
                    path: path.to_owned(),
                    message: format!(
                        "$item pointer '{item_pointer}' enters a free-form item schema and cannot be verified"
                    ),
                }),
                PointerCheck::Missing
                | PointerCheck::AlternativeForbidden
                | PointerCheck::Forbidden => problems.push(OverlayProblem {
                    path: path.to_owned(),
                    message: format!(
                        "$item pointer '{item_pointer}' does not exist in the items schema of input '{input_name}'"
                    ),
                }),
            }
        }
        CompositeBinding::Step {
            step,
            pointer: over_pointer,
            collect: true,
        } => {
            let Some(info) = visible_steps.get(step) else {
                return;
            };
            let combined = match over_pointer.as_deref() {
                Some(pointer) if !pointer.is_empty() => format!("{pointer}{item_pointer}"),
                _ => item_pointer.to_owned(),
            };
            validate_response_pointer(
                generation,
                transformed,
                &info.generated_tool,
                Some(&combined),
                path,
                warnings,
                problems,
            );
        }
        _ => {}
    }
}

fn for_each_iteration_bound(
    binding: &CompositeBinding,
    input: &CompositeInput,
    prior_steps: &BTreeMap<String, CompiledStepInfo>,
    path: &str,
    problems: &mut Vec<OverlayProblem>,
) -> usize {
    match binding {
        CompositeBinding::Input {
            input: input_name,
            pointer: None,
        } => {
            let Some(fragment) = input.properties.get(input_name) else {
                return 0;
            };
            if fragment.get("type").and_then(Value::as_str) != Some("array") {
                problems.push(OverlayProblem {
                    path: path.to_owned(),
                    message: format!("'{input_name}' must have type array for for_each"),
                });
                return 0;
            }
            let Some(max_items) = fragment.get("maxItems").and_then(Value::as_u64) else {
                problems.push(OverlayProblem {
                    path: path.to_owned(),
                    message: format!(
                        "{input_name} needs maxItems so the iteration bound is checkable"
                    ),
                });
                return 0;
            };
            usize::try_from(max_items).unwrap_or(usize::MAX)
        }
        CompositeBinding::Step {
            step,
            collect: true,
            ..
        } => prior_steps.get(step).map_or(0, |info| info.max_runs),
        _ => {
            problems.push(OverlayProblem {
                path: path.to_owned(),
                message: "for_each.over must be an unpointed $input array or a $step binding with collect: true"
                    .to_owned(),
            });
            0
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PointerCheck {
    Exists,
    Unverifiable,
    Missing,
    /// At least one `oneOf`/`anyOf` arm explicitly forbids the pointer. This
    /// remains unsafe even when a sibling keyword declares it.
    AlternativeForbidden,
    /// The schema explicitly disallows the pointer. Unlike an ordinary
    /// undeclared property, this vetoes a declaration from another `allOf`
    /// member.
    Forbidden,
}

fn validate_response_pointer(
    generation: &OpenApiToolGeneration,
    transformed: &BTreeMap<String, CompiledToolTransform>,
    tool_name: &str,
    pointer: Option<&str>,
    path: &str,
    warnings: &mut Vec<OverlayWarning>,
    problems: &mut Vec<OverlayProblem>,
) {
    let declared = match generation.declared_success_response_schemas(tool_name) {
        Ok(declared) => declared,
        Err(error) => {
            problems.push(OverlayProblem {
                path: path.to_owned(),
                message: format!(
                    "declared success response schema for tool '{tool_name}' cannot be resolved: {error}"
                ),
            });
            return;
        }
    };
    if declared.is_empty() {
        warnings.push(OverlayWarning {
            path: path.to_owned(),
            message: format!(
                "tool '{tool_name}' declares no JSON 2xx response schema; the response pointer is unverified"
            ),
        });
        return;
    }
    let Some(pointer) = pointer.filter(|pointer| !pointer.is_empty()) else {
        return;
    };
    let schemas = match transforms::project_success_response_schemas(
        &declared,
        transformed
            .get(tool_name)
            .map(|compiled| &compiled.transform),
    ) {
        Ok(schemas) => schemas,
        Err(error) => {
            problems.push(OverlayProblem {
                path: path.to_owned(),
                message: format!(
                    "response transform for tool '{tool_name}' cannot be projected: {error}"
                ),
            });
            return;
        }
    };
    let result = schemas
        .iter()
        .map(|schema| schema_pointer_check(schema, schema, pointer, 0))
        .min_by_key(|result| match result {
            PointerCheck::Missing
            | PointerCheck::AlternativeForbidden
            | PointerCheck::Forbidden => 0,
            PointerCheck::Unverifiable => 1,
            PointerCheck::Exists => 2,
        })
        .unwrap_or(PointerCheck::Missing);
    match result {
        PointerCheck::Exists => {}
        PointerCheck::Unverifiable => warnings.push(OverlayWarning {
            path: path.to_owned(),
            message: format!(
                "response pointer '{pointer}' for tool '{tool_name}' enters a free-form schema and cannot be verified"
            ),
        }),
        PointerCheck::Missing | PointerCheck::AlternativeForbidden | PointerCheck::Forbidden => {
            problems.push(OverlayProblem {
                path: path.to_owned(),
                message: format!(
                    "response pointer '{pointer}' does not exist in a declared 2xx response schema of tool '{tool_name}'"
                ),
            });
        }
    }
}

fn schema_pointer_check(
    document: &Value,
    schema: &Value,
    pointer: &str,
    depth: usize,
) -> PointerCheck {
    if depth >= 64 {
        return PointerCheck::Unverifiable;
    }
    let Some(tokens) = decode_json_pointer(pointer) else {
        return PointerCheck::Missing;
    };
    let mut remaining_visits = MAX_SCHEMA_POINTER_VISITS;
    schema_tokens_check(document, schema, &tokens, depth + 1, &mut remaining_visits)
}

fn schema_tokens_check(
    document: &Value,
    schema: &Value,
    tokens: &[String],
    depth: usize,
    remaining_visits: &mut usize,
) -> PointerCheck {
    if schema == &Value::Bool(false) {
        return PointerCheck::Forbidden;
    }
    if tokens.is_empty() && schema.get("$ref").is_none() {
        return PointerCheck::Exists;
    }
    if depth >= 64 || *remaining_visits == 0 {
        return PointerCheck::Unverifiable;
    }
    *remaining_visits -= 1;

    // JSON Schema 2020-12 (and therefore OpenAPI 3.1) applies keywords beside
    // `$ref`. Treat the target and every understood sibling as an
    // intersection; an unsupported validation sibling makes the proof
    // unverifiable instead of being silently discarded.
    if let Some(reference) = schema.get("$ref") {
        let Some(resolved) = reference
            .as_str()
            .and_then(|reference| reference.strip_prefix('#'))
            .and_then(|pointer| document.pointer(pointer))
        else {
            return PointerCheck::Unverifiable;
        };
        let mut checks = vec![schema_tokens_check(
            document,
            resolved,
            tokens,
            depth + 1,
            remaining_visits,
        )];
        let mut structural_siblings = Map::new();
        let mut has_unsupported_validation_sibling = false;
        if let Some(object) = schema.as_object() {
            for (keyword, value) in object {
                match keyword.as_str() {
                    "$ref" | "$id" | "$schema" | "$anchor" | "$dynamicAnchor" | "$comment"
                    | "$defs" | "definitions" | "title" | "description" | "default"
                    | "deprecated" | "readOnly" | "writeOnly" | "examples" | "example"
                    | "externalDocs" | "xml" | "discriminator" => {}
                    "type"
                    | "properties"
                    | "additionalProperties"
                    | "items"
                    | "allOf"
                    | "anyOf"
                    | "oneOf" => {
                        structural_siblings.insert(keyword.clone(), value.clone());
                    }
                    _ if keyword.starts_with("x-") => {}
                    _ => has_unsupported_validation_sibling = true,
                }
            }
        }
        if !structural_siblings.is_empty() {
            checks.push(schema_tokens_check(
                document,
                &Value::Object(structural_siblings),
                tokens,
                depth + 1,
                remaining_visits,
            ));
        }
        if has_unsupported_validation_sibling {
            checks.push(PointerCheck::Unverifiable);
        }
        return all_of_pointer_check(&checks);
    }
    if tokens.is_empty() {
        return PointerCheck::Exists;
    }

    let token = &tokens[0];
    let property = schema
        .get("properties")
        .and_then(Value::as_object)
        .and_then(|properties| properties.get(token));
    let mut constraints = Vec::new();
    let has_explicit_type = schema.get("type").is_some();
    let is_array_only = schema_declares_only_type(schema, "array");
    let is_object_only = schema_declares_only_type(schema, "object");
    if is_array_only {
        if is_json_pointer_array_index(token) {
            constraints.push(
                schema
                    .get("items")
                    .map_or(PointerCheck::Unverifiable, |items| {
                        schema_tokens_check(
                            document,
                            items,
                            &tokens[1..],
                            depth + 1,
                            remaining_visits,
                        )
                    }),
            );
        } else {
            constraints.push(PointerCheck::Forbidden);
        }
    } else if has_explicit_type && !is_object_only {
        constraints.push(PointerCheck::Forbidden);
    } else if let Some(property) = property {
        constraints.push(schema_tokens_check(
            document,
            property,
            &tokens[1..],
            depth + 1,
            remaining_visits,
        ));
    } else if schema.get("properties").is_some()
        || schema.get("additionalProperties").is_some()
        || schema.get("type").is_some()
    {
        constraints.push(match schema.get("additionalProperties") {
            Some(Value::Bool(true)) => PointerCheck::Unverifiable,
            Some(value) if value.is_object() => PointerCheck::Unverifiable,
            None if schema.get("properties").is_none()
                && schema
                    .get("type")
                    .and_then(Value::as_str)
                    .is_none_or(|kind| kind == "object") =>
            {
                PointerCheck::Unverifiable
            }
            None if schema.get("properties").is_some() => PointerCheck::Missing,
            _ => PointerCheck::Forbidden,
        });
    }

    // `allOf` is an intersection. A branch that definitively forbids the
    // pointer vetoes a declaration in another branch (for example, a sibling
    // closed object with `additionalProperties: false`). Unknown branches
    // keep the overall proof conservative rather than letting a compile-clean
    // composite fail later with `pointer_unresolved`.
    if let Some(branches) = schema.get("allOf").and_then(Value::as_array) {
        for branch in branches {
            if *remaining_visits == 0 {
                constraints.push(PointerCheck::Unverifiable);
                break;
            }
            constraints.push(schema_tokens_check(
                document,
                branch,
                tokens,
                depth + 1,
                remaining_visits,
            ));
        }
    }

    // A oneOf/anyOf pointer is statically safe only when every possible arm
    // declares it. Each union keyword is itself another constraint on the
    // enclosing schema, so combine it with direct properties and `allOf`.
    for keyword in ["anyOf", "oneOf"] {
        let Some(branches) = schema.get(keyword).and_then(Value::as_array) else {
            continue;
        };
        if branches.is_empty() {
            constraints.push(PointerCheck::Forbidden);
            continue;
        }
        let mut union_checks = Vec::new();
        for branch in branches {
            if *remaining_visits == 0 {
                union_checks.push(PointerCheck::Unverifiable);
                break;
            }
            union_checks.push(schema_tokens_check(
                document,
                branch,
                tokens,
                depth + 1,
                remaining_visits,
            ));
        }
        constraints.push(union_pointer_check(&union_checks));
    }

    all_of_pointer_check(&constraints)
}

fn all_of_pointer_check(checks: &[PointerCheck]) -> PointerCheck {
    if checks.contains(&PointerCheck::Forbidden) {
        PointerCheck::Forbidden
    } else if checks.contains(&PointerCheck::AlternativeForbidden) {
        PointerCheck::AlternativeForbidden
    } else if checks.contains(&PointerCheck::Unverifiable) || checks.is_empty() {
        PointerCheck::Unverifiable
    } else if checks.contains(&PointerCheck::Exists) {
        PointerCheck::Exists
    } else {
        PointerCheck::Missing
    }
}

fn union_pointer_check(checks: &[PointerCheck]) -> PointerCheck {
    if checks.is_empty() || checks.iter().all(|check| *check == PointerCheck::Forbidden) {
        PointerCheck::Forbidden
    } else if checks.iter().all(|check| *check == PointerCheck::Exists) {
        PointerCheck::Exists
    } else if checks.iter().any(|check| {
        matches!(
            check,
            PointerCheck::AlternativeForbidden | PointerCheck::Forbidden
        )
    }) {
        PointerCheck::AlternativeForbidden
    } else if checks.contains(&PointerCheck::Missing) {
        PointerCheck::Missing
    } else {
        PointerCheck::Unverifiable
    }
}

fn is_json_pointer_array_index(token: &str) -> bool {
    let bytes = token.as_bytes();
    match bytes {
        [b'0'] => true,
        [b'1'..=b'9', rest @ ..] => {
            rest.iter().all(u8::is_ascii_digit) && token.parse::<usize>().is_ok()
        }
        _ => false,
    }
}

fn schema_declares_only_type(schema: &Value, expected: &str) -> bool {
    match schema.get("type") {
        Some(Value::String(kind)) => kind == expected,
        Some(Value::Array(kinds)) if !kinds.is_empty() => kinds
            .iter()
            .all(|kind| kind.as_str().is_some_and(|kind| kind == expected)),
        _ => false,
    }
}

fn decode_json_pointer(pointer: &str) -> Option<Vec<String>> {
    if pointer.is_empty() {
        return Some(Vec::new());
    }
    if !pointer.starts_with('/') {
        return None;
    }
    pointer[1..]
        .split('/')
        .map(|token| {
            let mut decoded = String::new();
            let mut characters = token.chars();
            while let Some(character) = characters.next() {
                if character != '~' {
                    decoded.push(character);
                    continue;
                }
                match characters.next()? {
                    '0' => decoded.push('~'),
                    '1' => decoded.push('/'),
                    _ => return None,
                }
            }
            Some(decoded)
        })
        .collect()
}

/// Parameter overlays are validated against the generated catalog, not only
/// the selected binding. Otherwise a typo on an unselected tool is accepted
/// at PUT time and turns into a delayed failure when that tool is registered.
fn validate_parameter_names(
    generated_name: &str,
    tool: &ToolOverlay,
    definition: &ToolDefinition,
    metadata: Option<&super::openapi::OpenApiTransformMetadata>,
    source_plan: &OverlaySourcePlan,
    resolved: &ResolvedOverlaySources,
    problems: &mut Vec<OverlayProblem>,
) {
    let tool_path = format!("/tools/{generated_name}");
    let Some(properties) = definition
        .input_schema
        .get("properties")
        .and_then(Value::as_object)
    else {
        if !tool.parameters.is_empty() {
            problems.push(OverlayProblem {
                path: format!("{tool_path}/parameters"),
                message:
                    "generated input schema has no properties object; parameters cannot be overlaid"
                        .to_owned(),
            });
        }
        return;
    };
    for (property, parameter) in &tool.parameters {
        if parameter.shape.is_some() && metadata.is_some_and(|metadata| metadata.array_request_body)
        {
            problems.push(OverlayProblem {
                path: format!("{tool_path}/parameters/{property}/shape"),
                message: "array body operations are not shapeable in overlay schema 0.1.0"
                    .to_owned(),
            });
            continue;
        }
        match properties.get(property) {
            None => {
                let known = properties.keys().cloned().collect::<Vec<_>>().join(", ");
                problems.push(OverlayProblem {
                    path: format!("{tool_path}/parameters/{property}"),
                    message: format!(
                        "'{property}' is not a top-level property of the generated schema \
                         (properties: {known})"
                    ),
                });
            }
            Some(schema) if !schema.is_object() => problems.push(OverlayProblem {
                path: format!("{tool_path}/parameters/{property}"),
                message: format!("the generated schema of '{property}' is not an object"),
            }),
            Some(schema) => {
                let Some(source_id) = parameter.enum_source.as_deref() else {
                    continue;
                };
                let enum_path = format!("{tool_path}/parameters/{property}/enum_source");
                if !source_plan.enum_sources.contains_key(source_id) {
                    problems.push(OverlayProblem {
                        path: enum_path,
                        message: format!("unknown enum source '{source_id}'"),
                    });
                    continue;
                }
                let Some(target) = dynamic_enum_schema(schema) else {
                    problems.push(OverlayProblem {
                        path: enum_path,
                        message: format!(
                            "'{property}' must have type string or boolean, or be an array whose items have type string or boolean"
                        ),
                    });
                    continue;
                };
                if let Some(source) = resolved.enum_sources.get(source_id) {
                    let expects_boolean =
                        target.get("type").and_then(Value::as_str) == Some("boolean");
                    if source.values.iter().any(|value| {
                        if expects_boolean {
                            !value.is_boolean()
                        } else {
                            !value.is_string()
                        }
                    }) {
                        problems.push(OverlayProblem {
                            path: enum_path,
                            message: format!(
                                "enum source '{source_id}' values do not match the generated '{}' property type",
                                target.get("type").and_then(Value::as_str).unwrap_or("unknown")
                            ),
                        });
                    }
                }
            }
        }
    }
}

fn remove_static_enum(schema: &mut Map<String, Value>) {
    match schema.get("type").and_then(Value::as_str) {
        Some("string" | "boolean") => {
            schema.remove("enum");
        }
        Some("array") => {
            if let Some(items) = schema.get_mut("items").and_then(Value::as_object_mut) {
                items.remove("enum");
            }
        }
        _ => {}
    }
}

fn resolved_source_problems(
    plan: &OverlaySourcePlan,
    resolved: &ResolvedOverlaySources,
) -> Vec<OverlayProblem> {
    let mut problems = Vec::new();
    for (source_id, source_plan) in &plan.enum_sources {
        let Some(source) = resolved.enum_sources.get(source_id) else {
            // An explicitly allowed unresolved enum remains fail-closed at
            // serve/call time. The admin layer decides whether this omission
            // is permitted for the current mutation.
            continue;
        };
        if source.values.len() < source_plan.limits.min_items
            || source.values.len() > source_plan.limits.max_items
        {
            problems.push(OverlayProblem {
                path: format!("/enum_sources/{source_id}/select/items"),
                message: format!(
                    "enum source '{source_id}' resolved {} items; expected {}-{}",
                    source.values.len(),
                    source_plan.limits.min_items,
                    source_plan.limits.max_items
                ),
            });
        }
        let mut seen = BTreeSet::new();
        for (index, value) in source.values.iter().enumerate() {
            if !valid_source_value(value, source_plan.limits.max_value_bytes) {
                problems.push(OverlayProblem {
                    path: format!("/enum_sources/{source_id}/select/value"),
                    message: format!(
                        "enum source '{source_id}' item {index} is not a bounded printable string or boolean"
                    ),
                });
            }
            let canonical = serde_json::to_string(value).unwrap_or_default();
            if !seen.insert(canonical) {
                problems.push(OverlayProblem {
                    path: format!("/enum_sources/{source_id}/select/value"),
                    message: format!(
                        "enum source '{source_id}' contains duplicate values; the resolver must deduplicate while preserving upstream order"
                    ),
                });
                break;
            }
        }
        if let Some(labels) = source.labels.as_deref() {
            if labels.len() != source.values.len() {
                problems.push(OverlayProblem {
                    path: format!("/enum_sources/{source_id}/select/label"),
                    message: "resolved labels must align one-for-one with resolved values"
                        .to_owned(),
                });
            }
            for (index, label) in labels.iter().enumerate() {
                if !valid_source_text(label, source_plan.limits.max_label_bytes) {
                    problems.push(OverlayProblem {
                        path: format!("/enum_sources/{source_id}/select/label"),
                        message: format!(
                            "enum source '{source_id}' label {index} is not bounded printable single-line UTF-8"
                        ),
                    });
                }
            }
        }
    }

    for (source_id, source_plan) in &plan.label_sources {
        let Some(source) = resolved.label_sources.get(source_id) else {
            problems.push(OverlayProblem {
                path: format!("/label_sources/{source_id}"),
                message: format!(
                    "label source '{source_id}' must resolve before the overlay can compile"
                ),
            });
            continue;
        };
        if source.labels.len() < source_plan.limits.min_items
            || source.labels.len() > source_plan.limits.max_items
        {
            problems.push(OverlayProblem {
                path: format!("/label_sources/{source_id}/select/items"),
                message: format!(
                    "label source '{source_id}' resolved {} items; expected {}-{}",
                    source.labels.len(),
                    source_plan.limits.min_items,
                    source_plan.limits.max_items
                ),
            });
        }
        for (key, label) in &source.labels {
            if !valid_source_text(key, source_plan.limits.max_value_bytes) {
                problems.push(OverlayProblem {
                    path: format!("/label_sources/{source_id}/select/key"),
                    message: format!("label source '{source_id}' contains an invalid key"),
                });
            }
            if !valid_source_text(label, source_plan.limits.max_label_bytes) {
                problems.push(OverlayProblem {
                    path: format!("/label_sources/{source_id}/select/label"),
                    message: format!(
                        "label source '{source_id}' label for '{key}' is not bounded printable single-line UTF-8"
                    ),
                });
            }
        }
    }
    problems
}

fn valid_source_value(value: &Value, maximum_bytes: usize) -> bool {
    match value {
        Value::String(value) => valid_source_text(value, maximum_bytes),
        Value::Bool(_) => true,
        _ => false,
    }
}

pub fn valid_source_text(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum_bytes
        && !value.chars().any(|character| character.is_control())
}

/// Set the body mode on both copies of the mapping (`upstream` and
/// `target.mapping`, which the registry requires to be equal). A tool with
/// no JSON body keeps `body: None`; the mode has nothing to apply to.
fn apply_body_mode(
    definition: &mut ToolDefinition,
    mode: BodyMappingMode,
) -> Option<BodyMappingMode> {
    let body = definition.upstream.body.as_mut()?;
    body.mode = mode;
    if let Some(ToolTarget::Http { mapping, .. }) = definition.target.as_mut() {
        if let Some(target_body) = mapping.body.as_mut() {
            target_body.mode = mode;
        }
    }
    Some(mode)
}

/// Compiled definitions must still fit the store's per-entry limit and the
/// catalog byte budget; an overlay can only grow descriptions.
fn budget_problems(
    definitions: &[ToolDefinition],
    renames: &BTreeMap<String, String>,
    problems: &mut Vec<OverlayProblem>,
) {
    if definitions.len() > MAX_CATALOG_ENTRIES {
        problems.push(OverlayProblem {
            path: "/composites".to_owned(),
            message: format!(
                "compiled catalog contains {} definitions; the limit is {MAX_CATALOG_ENTRIES}",
                definitions.len()
            ),
        });
    }
    let served_to_generated = renames
        .iter()
        .map(|(generated, served)| (served.as_str(), generated.as_str()))
        .collect::<BTreeMap<_, _>>();
    let mut total = 0_usize;
    for definition in definitions {
        let Ok(encoded) = serde_json::to_vec(definition) else {
            problems.push(OverlayProblem {
                path: "/".to_owned(),
                message: format!(
                    "compiled definition '{}' does not serialise",
                    definition.name
                ),
            });
            continue;
        };
        total = total.saturating_add(encoded.len());
        if encoded.len() > MAX_COMPILED_DEFINITION_BYTES {
            let generated = served_to_generated
                .get(definition.name.as_str())
                .copied()
                .unwrap_or(definition.name.as_str());
            problems.push(OverlayProblem {
                path: if definition.composite.is_some() {
                    format!("/composites/{}", definition.name)
                } else {
                    format!("/tools/{generated}")
                },
                message: format!(
                    "compiled definition is {} bytes; the per-tool limit is \
                     {MAX_COMPILED_DEFINITION_BYTES}",
                    encoded.len()
                ),
            });
        }
    }
    if total > MAX_MANAGED_OPENAPI_CATALOG_BYTES {
        problems.push(OverlayProblem {
            path: "/".to_owned(),
            message: format!(
                "compiled catalog is {total} bytes; the limit is \
                 {MAX_MANAGED_OPENAPI_CATALOG_BYTES}"
            ),
        });
    }
}

// ---------------------------------------------------------------------------
// Label disambiguation (section 2.1; document labels only in this revision)
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct LabelOutcome {
    found: usize,
    from_source: usize,
    from_title: usize,
    from_description: usize,
    qualified: Vec<String>,
}

/// For every top-level property compute its label in `label_from` order,
/// group properties by identical label, and rewrite the description of every
/// member of a group of two or more through the template. Properties whose
/// description the overlay set are counted but never rewritten.
fn disambiguate(
    properties: &mut Map<String, Value>,
    config: &DisambiguationConfig,
    overridden: &BTreeSet<String>,
    label_inputs: &BTreeMap<String, Value>,
    source_labels: Option<&BTreeMap<String, String>>,
    enum_bound: &BTreeSet<String>,
) -> LabelOutcome {
    let mut outcome = LabelOutcome::default();
    let origins = config
        .label_from
        .clone()
        .unwrap_or_else(|| LabelOrigin::DEFAULT_ORDER.to_vec());

    let mut labelled: Vec<(String, String)> = Vec::new();
    for (name, schema) in properties.iter() {
        let label_schema = label_inputs.get(name).unwrap_or(schema);
        let Some((label, origin)) = property_label(name, label_schema, &origins, source_labels)
        else {
            continue;
        };
        outcome.found += 1;
        match origin {
            LabelOrigin::LabelSource => outcome.from_source += 1,
            LabelOrigin::Title => outcome.from_title += 1,
            LabelOrigin::Description => outcome.from_description += 1,
        }
        labelled.push((name.clone(), label));
    }
    if config.mode.unwrap_or_default() == DisambiguationMode::Off {
        return outcome;
    }

    let mut groups: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (name, label) in &labelled {
        groups
            .entry(label.as_str())
            .or_default()
            .push(name.as_str());
    }
    let template = config
        .template
        .as_deref()
        .unwrap_or(DEFAULT_DISAMBIGUATION_TEMPLATE);
    for (label, members) in groups {
        if members.len() < 2 {
            continue;
        }
        for name in members {
            if overridden.contains(name) {
                continue;
            }
            let Some(schema) = properties.get_mut(name).and_then(Value::as_object_mut) else {
                continue;
            };
            let options = if enum_bound.contains(name) {
                "; options: see the enum in this schema".to_owned()
            } else {
                render_options(schema.get("enum"))
            };
            let description = render_template(template, label, name, &options);
            schema.insert("description".to_owned(), Value::String(description));
            outcome.qualified.push(name.to_owned());
        }
    }
    outcome.qualified.sort();
    outcome
}

/// The first non-empty label in `origins` order: the resolved source label,
/// `title`, or the first line of `description`, all trimmed. Case-sensitive,
/// as the contract says; two labels that differ only in case are two labels.
fn property_label(
    property: &str,
    schema: &Value,
    origins: &[LabelOrigin],
    source_labels: Option<&BTreeMap<String, String>>,
) -> Option<(String, LabelOrigin)> {
    let object = schema.as_object()?;
    for origin in origins {
        let text = match origin {
            LabelOrigin::LabelSource => source_labels
                .and_then(|labels| labels.get(property))
                .map(String::as_str)
                .map(str::trim),
            LabelOrigin::Title => object.get("title").and_then(Value::as_str).map(str::trim),
            LabelOrigin::Description => object
                .get("description")
                .and_then(Value::as_str)
                .and_then(|description| description.lines().next())
                .map(str::trim),
        };
        if let Some(text) = text.filter(|text| !text.is_empty()) {
            return Some((single_line(text), *origin));
        }
    }
    None
}

/// `{options}` for the template: `; options: A, B, C` from a static enum
/// (at most `MAX_OPTIONS_SHOWN`, then `…`), empty otherwise. Enum-source-bound
/// properties instead render `; options: see the enum in this schema` so a
/// compiled description can never disagree with the served enum.
fn render_options(static_enum: Option<&Value>) -> String {
    let Some(values) = static_enum.and_then(Value::as_array) else {
        return String::new();
    };
    if values.is_empty() {
        return String::new();
    }
    let mut shown = values
        .iter()
        .take(MAX_OPTIONS_SHOWN)
        .map(|value| {
            let text = match value {
                Value::String(text) => text.clone(),
                other => other.to_string(),
            };
            truncate_chars(&single_line(&text), MAX_OPTION_CHARS)
        })
        .collect::<Vec<_>>();
    if values.len() > MAX_OPTIONS_SHOWN {
        shown.push("…".to_owned());
    }
    format!("; options: {}", shown.join(", "))
}

/// Inject one resolved enum into an owned list/validation clone.
///
/// The registry's durable [`ToolDefinition`] must never be passed here: the
/// helper intentionally requires mutable ownership at the call site, and its
/// name documents the digest boundary. Values retain upstream order. Optional
/// labels are rendered only through a fixed, bounded data block.
pub fn apply_enum_to_served_clone(
    definition: &mut ToolDefinition,
    binding: &EnumBinding,
    values: &[Value],
    labels: Option<&[String]>,
) -> Result<(), String> {
    let properties = definition
        .input_schema
        .get_mut("properties")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| "input schema has no properties object".to_owned())?;
    let property_schema = properties
        .get_mut(&binding.property)
        .ok_or_else(|| format!("property '{}' is absent", binding.property))?;
    let expected_type = dynamic_enum_schema(property_schema)
        .and_then(|schema| schema.get("type"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            format!(
                "property '{}' is not a string/boolean dynamic-enum target",
                binding.property
            )
        })?
        .to_owned();
    for value in values {
        let valid_type = match expected_type.as_str() {
            "string" => value.is_string(),
            "boolean" => value.is_boolean(),
            _ => false,
        };
        if !valid_type || !valid_source_value(value, 1_024) {
            return Err(format!(
                "source '{}' contains a value incompatible with property '{}'",
                binding.source_id, binding.property
            ));
        }
    }
    if let Some(labels) = labels {
        if labels.len() != values.len() {
            return Err("resolved enum labels must align one-for-one with values".to_owned());
        }
        if labels
            .iter()
            .any(|label| !valid_source_text(label, MAX_SOURCE_LABEL_BYTES))
        {
            return Err(
                "resolved enum label is not bounded printable single-line UTF-8".to_owned(),
            );
        }
    }
    let enum_schema = dynamic_enum_schema_mut(property_schema)
        .expect("the immutable dynamic-enum check above succeeded");
    let enum_schema = enum_schema
        .as_object_mut()
        .expect("dynamic enum schema is an object");
    if values.is_empty() {
        // JSON Schema requires `enum` to contain at least one item. The
        // overlay contract deliberately permits `min_items: 0`, so represent
        // a successfully resolved empty set with a valid fail-all subschema.
        enum_schema.remove("enum");
        enum_schema.insert("not".to_owned(), Value::Object(Map::new()));
    } else {
        enum_schema.insert("enum".to_owned(), Value::Array(values.to_vec()));
    }

    let Some(labels) = labels else {
        return Ok(());
    };

    let property = property_schema
        .as_object_mut()
        .expect("generated property schema is an object");
    let base = property
        .get("description")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let mut rendered = base.to_owned();
    let heading = if rendered.is_empty() {
        "Allowed values:"
    } else {
        "\n\nAllowed values:"
    };
    if rendered.len().saturating_add(heading.len()) > MAX_SERVED_ENUM_DESCRIPTION_BYTES {
        return Ok(());
    }
    rendered.push_str(heading);
    for (index, (value, label)) in values.iter().zip(labels).enumerate() {
        if index == MAX_OPTIONS_SHOWN {
            if rendered.len() + "\n- …".len() <= MAX_SERVED_ENUM_DESCRIPTION_BYTES {
                rendered.push_str("\n- …");
            }
            break;
        }
        let value = serde_json::to_string(value)
            .map_err(|error| format!("enum value does not serialize: {error}"))?;
        let label = serde_json::to_string(label)
            .map_err(|error| format!("enum label does not serialize: {error}"))?;
        let line = format!("\n- {value} — {label}");
        if rendered.len().saturating_add(line.len()) > MAX_SERVED_ENUM_DESCRIPTION_BYTES {
            if rendered.len() + "\n- …".len() <= MAX_SERVED_ENUM_DESCRIPTION_BYTES {
                rendered.push_str("\n- …");
            }
            break;
        }
        rendered.push_str(&line);
    }
    property.insert("description".to_owned(), Value::String(rendered));
    Ok(())
}

/// Mark a bound property unavailable on an owned served clone. There is no
/// `enum` fallback: an unavailable dynamic source must fail closed at call
/// time, and the served schema explains why without leaking resolver detail.
pub fn mark_enum_unavailable_on_served_clone(
    definition: &mut ToolDefinition,
    binding: &EnumBinding,
) -> Result<(), String> {
    const SUFFIX: &str = " [allowed values are currently unavailable; calls will be rejected until the gateway can read them]";

    let property = definition
        .input_schema
        .get_mut("properties")
        .and_then(Value::as_object_mut)
        .and_then(|properties| properties.get_mut(&binding.property))
        .and_then(Value::as_object_mut)
        .ok_or_else(|| format!("property '{}' is absent", binding.property))?;
    remove_static_enum(property);
    let description = property
        .get("description")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !description.ends_with(SUFFIX)
        && description.len().saturating_add(SUFFIX.len()) <= MAX_SERVED_ENUM_DESCRIPTION_BYTES
    {
        property.insert(
            "description".to_owned(),
            Value::String(format!("{description}{SUFFIX}")),
        );
    }
    Ok(())
}

/// Substitute the validated template tokens in one pass, so a substituted
/// value can never be re-expanded as a placeholder.
fn render_template(template: &str, label: &str, name: &str, options: &str) -> String {
    let Ok(tokens) = tokenize_template(template) else {
        // Public callers normally obtain `OverlayDocument` through `validate`.
        // Keep a manually constructed invalid document inert instead of
        // partially interpreting syntax that validation would reject.
        return template.to_owned();
    };
    let mut rendered = String::with_capacity(template.len() + label.len() + name.len());
    for token in tokens {
        match token {
            TemplateToken::Literal(literal) => rendered.push_str(literal),
            TemplateToken::Placeholder(TemplatePlaceholder::Label) => rendered.push_str(label),
            TemplateToken::Placeholder(TemplatePlaceholder::Name) => rendered.push_str(name),
            TemplateToken::Placeholder(TemplatePlaceholder::Options) => {
                rendered.push_str(options);
            }
        }
    }
    rendered
}

/// Collapse control characters (line breaks included) to spaces so document
/// text can never break the fixed template across lines.
fn single_line(text: &str) -> String {
    text.chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect::<String>()
        .trim()
        .to_owned()
}

fn truncate_chars(text: &str, maximum: usize) -> String {
    if text.chars().count() <= maximum {
        return text.to_owned();
    }
    let mut truncated = text.chars().take(maximum).collect::<String>();
    truncated.push('…');
    truncated
}

#[cfg(test)]
#[path = "overlay_tests.rs"]
mod tests;
