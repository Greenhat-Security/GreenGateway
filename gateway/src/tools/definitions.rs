use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt, fs,
    io::{self, Read},
    path::{Path, PathBuf},
    sync::{Arc, LazyLock, Mutex},
    time::Duration,
};

use arc_swap::ArcSwap;
use http::Method;
use notify::{RecursiveMode, Watcher};
use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::mpsc;

use crate::{
    audit::{self, AuditEvent, AuditLog},
    config::Config,
};

const TOOL_REGISTRY_RELOAD_DEBOUNCE: Duration = Duration::from_millis(200);
const MAX_TOOLS_FILE_BYTES: u64 = 1_048_576;
const MAX_INPUT_SCHEMA_REFERENCE_DEPTH: usize = 64;
const MAX_INPUT_SCHEMA_PRECHECK_NODES: usize = 4_096;
const TOOLS_FILE_SCHEMA_JSON: &str = include_str!("../../../docs/schemas/tools.v0.schema.json");
const MCP_PROXY_METHOD: &str = "MCP_PROXY";

static TOOLS_FILE_SCHEMA_VALIDATOR: LazyLock<jsonschema::Validator> = LazyLock::new(|| {
    let schema = serde_json::from_str(TOOLS_FILE_SCHEMA_JSON)
        .expect("embedded tools file schema should be valid JSON");
    jsonschema::validator_for(&schema).expect("embedded tools file schema should compile")
});

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    #[serde(rename = "input_json_schema")]
    pub input_schema: Value,
    pub upstream: UpstreamMapping,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamMapping {
    pub method: String,
    pub path_template: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub query_params: Vec<QueryParamMapping>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<BodyMapping>,
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
            description,
            input_schema,
            upstream: UpstreamMapping::mcp_proxy(server_name, tool_name),
        }
    }
}

impl UpstreamMapping {
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
    WholeArgsJson,
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
    fn invalid(problems: Vec<String>) -> Self {
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

#[derive(Clone)]
pub struct ToolRegistry {
    state: Arc<ArcSwap<ToolRegistryState>>,
    write_lock: Arc<Mutex<()>>,
    audit: Option<AuditLog>,
}

pub type McpProxyDefinitionsProvider =
    Arc<dyn Fn() -> Option<Vec<ToolDefinition>> + Send + Sync + 'static>;

impl fmt::Debug for ToolRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ToolRegistry")
            .field("tool_count", &self.state.load().tools.len())
            .finish_non_exhaustive()
    }
}

#[allow(dead_code)] // Future MCP executor and admin surfaces will query this registry state.
struct ToolRegistryState {
    tools: BTreeMap<String, Arc<ToolDefinition>>,
    local_definitions: Vec<ToolDefinition>,
    mcp_proxy_definitions: Vec<ToolDefinition>,
}

impl ToolRegistry {
    #[allow(dead_code)] // Exposed for callers that intentionally run without TOOLS_FILE.
    pub fn disabled() -> Self {
        Self::from_definitions_with_audit(Vec::new(), None)
    }

    #[allow(dead_code)] // Future callers without audit wiring can construct the registry from Config.
    pub fn from_config(config: &Config) -> Result<Self, ToolRegistryError> {
        match config.tools_file.as_deref() {
            Some(path) => Self::from_file(path),
            None => Ok(Self::disabled()),
        }
    }

    pub fn from_config_with_audit(
        config: &Config,
        audit: AuditLog,
    ) -> Result<Self, ToolRegistryError> {
        match config.tools_file.as_deref() {
            Some(path) => Self::from_file_with_audit(path, audit),
            None => Ok(Self::from_definitions_with_audit(Vec::new(), Some(audit))),
        }
    }

    #[allow(dead_code)] // Tests and future startup variants load registries directly from files.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, ToolRegistryError> {
        let definitions = definitions_from_file(path.as_ref())?;
        Ok(Self::from_definitions_with_audit(definitions, None))
    }

    pub fn from_file_with_audit(
        path: impl AsRef<Path>,
        audit: AuditLog,
    ) -> Result<Self, ToolRegistryError> {
        let path = path.as_ref();
        match definitions_from_file(path) {
            Ok(definitions) => {
                let count = definitions.len();
                let registry = Self::from_definitions_with_audit(definitions, Some(audit));
                registry.emit_loaded(path, count);
                Ok(registry)
            }
            Err(err) => {
                emit_registry_failure(Some(&audit), path, &err);
                Err(err)
            }
        }
    }

    #[allow(dead_code)] // Useful for API-side validation without a temporary file.
    pub fn from_json_value(value: Value) -> Result<Self, ToolRegistryError> {
        let definitions = definitions_from_json_value(value, None)?;
        Ok(Self::from_definitions_with_audit(definitions, None))
    }

    #[allow(dead_code)] // Future MCP call handling will query by tool name.
    pub fn get(&self, name: &str) -> Option<Arc<ToolDefinition>> {
        self.state.load().tools.get(name).cloned()
    }

    #[allow(dead_code)] // Future MCP list-tools handling will expose registry contents.
    pub fn list(&self) -> Vec<Arc<ToolDefinition>> {
        self.state.load().tools.values().cloned().collect()
    }

    pub fn has_http_tools(&self) -> bool {
        self.state
            .load()
            .tools
            .values()
            .any(|definition| !definition.upstream.is_mcp_proxy())
    }

    pub fn merge_definitions(
        &self,
        definitions: Vec<ToolDefinition>,
    ) -> Result<(), ToolRegistryError> {
        if definitions.is_empty() {
            return Ok(());
        }

        let _guard = match self.write_lock.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        let state = self.state.load();
        let mut local_definitions = state.local_definitions.clone();
        let mut mcp_proxy_definitions = state.mcp_proxy_definitions.clone();
        drop(state);

        let (new_local_definitions, new_mcp_proxy_definitions) =
            split_definitions_by_source(definitions);
        local_definitions.extend(new_local_definitions);
        mcp_proxy_definitions.extend(new_mcp_proxy_definitions);

        let merged = combined_definitions(&local_definitions, &mcp_proxy_definitions);
        let semantic_problems = tool_definition_problems(&merged);
        if !semantic_problems.is_empty() {
            return Err(ToolRegistryError::invalid(semantic_problems));
        }

        self.state
            .store(Arc::new(ToolRegistryState::from_definition_sources(
                local_definitions,
                mcp_proxy_definitions,
            )));
        Ok(())
    }

    fn from_definitions_with_audit(
        definitions: Vec<ToolDefinition>,
        audit: Option<AuditLog>,
    ) -> Self {
        Self {
            state: Arc::new(ArcSwap::from_pointee(ToolRegistryState::from_definitions(
                definitions,
            ))),
            write_lock: Arc::new(Mutex::new(())),
            audit,
        }
    }

    fn replace_local_definitions(
        &self,
        local_definitions: Vec<ToolDefinition>,
    ) -> Result<(), ToolRegistryError> {
        let _guard = match self.write_lock.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        let state = self.state.load();
        let mcp_proxy_definitions = state.mcp_proxy_definitions.clone();
        drop(state);

        self.replace_definition_sources_locked(local_definitions, mcp_proxy_definitions)
    }

    fn replace_definition_sources(
        &self,
        local_definitions: Vec<ToolDefinition>,
        mcp_proxy_definitions: Vec<ToolDefinition>,
    ) -> Result<(), ToolRegistryError> {
        let _guard = match self.write_lock.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        self.replace_definition_sources_locked(local_definitions, mcp_proxy_definitions)
    }

    fn replace_definition_sources_locked(
        &self,
        local_definitions: Vec<ToolDefinition>,
        mcp_proxy_definitions: Vec<ToolDefinition>,
    ) -> Result<(), ToolRegistryError> {
        let merged = combined_definitions(&local_definitions, &mcp_proxy_definitions);
        let semantic_problems = tool_definition_problems(&merged);
        if !semantic_problems.is_empty() {
            return Err(ToolRegistryError::invalid(semantic_problems));
        }

        self.state
            .store(Arc::new(ToolRegistryState::from_definition_sources(
                local_definitions,
                mcp_proxy_definitions,
            )));
        Ok(())
    }

    fn emit_loaded(&self, path: &Path, tool_count: usize) {
        if let Some(audit) = &self.audit {
            audit.emit(AuditEvent::new(
                audit::event::TOOL_REGISTRY_LOADED,
                "tool-registry",
                "internal",
                None,
                json!({
                    "tools_file": path.display().to_string(),
                    "tool_count": tool_count,
                    "outcome": "success",
                }),
            ));
        }
    }

    fn emit_reload_failed(&self, path: &Path, error: &ToolRegistryError) {
        emit_registry_failure(self.audit.as_ref(), path, error);
    }
}

impl ToolRegistryState {
    fn from_definitions(definitions: Vec<ToolDefinition>) -> Self {
        let (local_definitions, mcp_proxy_definitions) = split_definitions_by_source(definitions);
        Self::from_definition_sources(local_definitions, mcp_proxy_definitions)
    }

    fn from_definition_sources(
        local_definitions: Vec<ToolDefinition>,
        mcp_proxy_definitions: Vec<ToolDefinition>,
    ) -> Self {
        let tools = local_definitions
            .iter()
            .chain(mcp_proxy_definitions.iter())
            .map(|definition| (definition.name.clone(), Arc::new(definition.clone())))
            .collect();

        Self {
            tools,
            local_definitions,
            mcp_proxy_definitions,
        }
    }
}

fn split_definitions_by_source(
    definitions: Vec<ToolDefinition>,
) -> (Vec<ToolDefinition>, Vec<ToolDefinition>) {
    let mut local_definitions = Vec::new();
    let mut mcp_proxy_definitions = Vec::new();

    for definition in definitions {
        if definition.upstream.is_mcp_proxy() {
            mcp_proxy_definitions.push(definition);
        } else {
            local_definitions.push(definition);
        }
    }

    (local_definitions, mcp_proxy_definitions)
}

fn combined_definitions(
    local_definitions: &[ToolDefinition],
    mcp_proxy_definitions: &[ToolDefinition],
) -> Vec<ToolDefinition> {
    local_definitions
        .iter()
        .chain(mcp_proxy_definitions.iter())
        .cloned()
        .collect()
}

#[allow(dead_code)] // Retained for callers that only reload local tool definitions.
pub fn reload_tool_registry_from_file(
    registry: &ToolRegistry,
    path: impl AsRef<Path>,
) -> Result<(), ToolRegistryError> {
    reload_tool_registry_from_file_with_optional_mcp_proxy_definitions(registry, path, None)
}

#[allow(dead_code)] // Used by config reload paths that can rediscover upstream MCP tools.
pub fn reload_tool_registry_from_file_with_mcp_proxy_definitions(
    registry: &ToolRegistry,
    path: impl AsRef<Path>,
    mcp_proxy_definitions: Vec<ToolDefinition>,
) -> Result<(), ToolRegistryError> {
    reload_tool_registry_from_file_with_optional_mcp_proxy_definitions(
        registry,
        path,
        Some(mcp_proxy_definitions),
    )
}

pub fn reload_tool_registry_from_file_with_mcp_proxy_definitions_provider(
    registry: &ToolRegistry,
    path: impl AsRef<Path>,
    mcp_proxy_definitions_provider: Option<&McpProxyDefinitionsProvider>,
) -> Result<(), ToolRegistryError> {
    let mcp_proxy_definitions = mcp_proxy_definitions_provider.and_then(|provider| provider());
    reload_tool_registry_from_file_with_optional_mcp_proxy_definitions(
        registry,
        path,
        mcp_proxy_definitions,
    )
}

fn reload_tool_registry_from_file_with_optional_mcp_proxy_definitions(
    registry: &ToolRegistry,
    path: impl AsRef<Path>,
    mcp_proxy_definitions: Option<Vec<ToolDefinition>>,
) -> Result<(), ToolRegistryError> {
    let path = path.as_ref();

    match definitions_from_file(path) {
        Ok(definitions) => {
            let tool_count = definitions.len();
            let replace_result = match mcp_proxy_definitions {
                Some(mcp_proxy_definitions) => {
                    registry.replace_definition_sources(definitions, mcp_proxy_definitions)
                }
                None => registry.replace_local_definitions(definitions),
            };
            if let Err(err) = replace_result {
                registry.emit_reload_failed(path, &err);
                tracing::error!(
                    tools_file = %path.display(),
                    error = %err,
                    "tool registry reload rejected; existing registry remains active"
                );
                return Err(err);
            }
            registry.emit_loaded(path, tool_count);
            tracing::info!(
                tools_file = %path.display(),
                tool_count,
                "tool registry reload accepted"
            );
            Ok(())
        }
        Err(err) => {
            registry.emit_reload_failed(path, &err);
            tracing::error!(
                tools_file = %path.display(),
                error = %err,
                "tool registry reload rejected; existing registry remains active"
            );
            Err(err)
        }
    }
}

#[allow(dead_code)] // Retained for callers that do not refresh MCP proxy definitions.
pub fn spawn_tool_registry_reload_tasks(
    tools_file: impl Into<PathBuf>,
    registry: ToolRegistry,
) -> notify::Result<()> {
    spawn_tool_registry_reload_tasks_with_mcp_proxy_definitions_provider(tools_file, registry, None)
}

pub fn spawn_tool_registry_reload_tasks_with_mcp_proxy_definitions_provider(
    tools_file: impl Into<PathBuf>,
    registry: ToolRegistry,
    mcp_proxy_definitions_provider: Option<McpProxyDefinitionsProvider>,
) -> notify::Result<()> {
    let tools_file = tools_file.into();
    spawn_tool_registry_file_watcher(
        tools_file.clone(),
        registry.clone(),
        mcp_proxy_definitions_provider.clone(),
    )?;
    spawn_sighup_reload_task(tools_file, registry, mcp_proxy_definitions_provider);
    Ok(())
}

fn spawn_tool_registry_file_watcher(
    tools_file: PathBuf,
    registry: ToolRegistry,
    mcp_proxy_definitions_provider: Option<McpProxyDefinitionsProvider>,
) -> notify::Result<()> {
    let (sender, receiver) = mpsc::unbounded_channel();
    let mut watcher = notify::recommended_watcher(move |event| {
        let _ = sender.send(event);
    })?;
    watcher.watch(&watch_directory(&tools_file), RecursiveMode::NonRecursive)?;

    tokio::spawn(tool_registry_file_watch_loop(
        tools_file,
        registry,
        mcp_proxy_definitions_provider,
        receiver,
        watcher,
    ));

    Ok(())
}

async fn tool_registry_file_watch_loop(
    tools_file: PathBuf,
    registry: ToolRegistry,
    mcp_proxy_definitions_provider: Option<McpProxyDefinitionsProvider>,
    mut events: mpsc::UnboundedReceiver<notify::Result<notify::Event>>,
    _watcher: notify::RecommendedWatcher,
) {
    while let Some(event) = events.recv().await {
        if !handle_tool_registry_watch_event(&tools_file, event) {
            continue;
        }

        tokio::time::sleep(TOOL_REGISTRY_RELOAD_DEBOUNCE).await;
        while let Ok(event) = events.try_recv() {
            let _ = handle_tool_registry_watch_event(&tools_file, event);
        }

        let _ = reload_tool_registry_from_file_with_mcp_proxy_definitions_provider(
            &registry,
            &tools_file,
            mcp_proxy_definitions_provider.as_ref(),
        );
    }
}

fn handle_tool_registry_watch_event(
    tools_file: &Path,
    event: notify::Result<notify::Event>,
) -> bool {
    match event {
        Ok(event) => tool_registry_reload_event(&event, tools_file),
        Err(err) => {
            tracing::error!(error = %err, "tool registry file watch error");
            false
        }
    }
}

fn tool_registry_reload_event(event: &notify::Event, tools_file: &Path) -> bool {
    !matches!(event.kind, notify::EventKind::Access(_))
        && event
            .paths
            .iter()
            .any(|path| path_matches_tools_file(path, tools_file))
}

fn path_matches_tools_file(path: &Path, tools_file: &Path) -> bool {
    path == tools_file
        || path
            .file_name()
            .is_some_and(|file_name| Some(file_name) == tools_file.file_name())
}

fn watch_directory(tools_file: &Path) -> PathBuf {
    tools_file
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .to_owned()
}

#[cfg(unix)]
fn spawn_sighup_reload_task(
    tools_file: PathBuf,
    registry: ToolRegistry,
    mcp_proxy_definitions_provider: Option<McpProxyDefinitionsProvider>,
) {
    tokio::spawn(async move {
        let mut sighup = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        {
            Ok(signal) => signal,
            Err(err) => {
                tracing::error!(
                    error = %err,
                    "failed to register SIGHUP tool registry reload handler"
                );
                return;
            }
        };

        while sighup.recv().await.is_some() {
            let _ = reload_tool_registry_from_file_with_mcp_proxy_definitions_provider(
                &registry,
                &tools_file,
                mcp_proxy_definitions_provider.as_ref(),
            );
        }
    });
}

#[cfg(not(unix))]
fn spawn_sighup_reload_task(
    _tools_file: PathBuf,
    _registry: ToolRegistry,
    _mcp_proxy_definitions_provider: Option<McpProxyDefinitionsProvider>,
) {
}

fn definitions_from_file(path: &Path) -> Result<Vec<ToolDefinition>, ToolRegistryError> {
    let contents = read_tools_file_to_string(path)?;
    let value = serde_json::from_str(&contents).map_err(|source| ToolRegistryError::Parse {
        path: Some(path.to_owned()),
        source,
    })?;

    definitions_from_json_value(value, Some(path))
}

fn read_tools_file_to_string(path: &Path) -> Result<String, ToolRegistryError> {
    let file = fs::File::open(path).map_err(|source| ToolRegistryError::Io {
        path: path.to_owned(),
        source,
    })?;
    let metadata = file.metadata().map_err(|source| ToolRegistryError::Io {
        path: path.to_owned(),
        source,
    })?;
    if metadata.len() > MAX_TOOLS_FILE_BYTES {
        return Err(tools_file_too_large(path));
    }

    let mut contents = String::new();
    let mut reader = file.take(MAX_TOOLS_FILE_BYTES + 1);
    reader
        .read_to_string(&mut contents)
        .map_err(|source| ToolRegistryError::Io {
            path: path.to_owned(),
            source,
        })?;
    if contents.len() as u64 > MAX_TOOLS_FILE_BYTES {
        return Err(tools_file_too_large(path));
    }

    Ok(contents)
}

fn tools_file_too_large(path: &Path) -> ToolRegistryError {
    ToolRegistryError::Io {
        path: path.to_owned(),
        source: io::Error::new(
            io::ErrorKind::InvalidData,
            format!("tools file exceeds maximum size of {MAX_TOOLS_FILE_BYTES} bytes"),
        ),
    }
}

fn definitions_from_json_value(
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

fn tool_definition_problems(definitions: &[ToolDefinition]) -> Vec<String> {
    let mut problems = Vec::new();
    let mut seen = BTreeMap::new();
    let mut input_schema_precheck_budget = MAX_INPUT_SCHEMA_PRECHECK_NODES;

    for (index, definition) in definitions.iter().enumerate() {
        let is_http_mapping = !definition.upstream.is_mcp_proxy();

        if let Some(first_index) = seen.insert(definition.name.as_str(), index) {
            problems.push(format!(
                "duplicate tool name '{}' at tools[{index}] (first defined at tools[{first_index}])",
                definition.name
            ));
        }

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

fn input_schema_precheck_problem(schema: &Value, remaining_budget: &mut usize) -> Option<String> {
    let mut stack = vec![(schema, SchemaPrecheckContext::Schema)];
    let mut local_references = Vec::new();
    let mut anchors = BTreeMap::new();

    while let Some((value, context)) = stack.pop() {
        if !consume_input_schema_precheck_node(remaining_budget) {
            return Some(format!(
                "precheck node budget exceeds {MAX_INPUT_SCHEMA_PRECHECK_NODES} across tools file"
            ));
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

    for reference in local_references {
        if let Some(problem) =
            local_reference_chain_problem(schema, &anchors, reference, remaining_budget)
        {
            return Some(problem);
        }
    }

    None
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
    remaining_budget: &mut usize,
) -> Option<String> {
    let mut reference = first_reference.to_owned();
    let mut seen_references = BTreeSet::new();
    let mut depth = 1;

    loop {
        if !consume_input_schema_precheck_node(remaining_budget) {
            return Some(format!(
                "precheck node budget exceeds {MAX_INPUT_SCHEMA_PRECHECK_NODES} across tools file while following local reference {reference}"
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

fn consume_input_schema_precheck_node(remaining_budget: &mut usize) -> bool {
    let Some(updated_budget) = remaining_budget.checked_sub(1) else {
        return false;
    };
    *remaining_budget = updated_budget;
    true
}

fn is_known_http_method(method: &str) -> bool {
    matches!(
        method,
        "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS" | "TRACE" | "CONNECT"
    ) && method.parse::<Method>().is_ok()
}

fn emit_registry_failure(audit: Option<&AuditLog>, path: &Path, error: &ToolRegistryError) {
    if let Some(audit) = audit {
        audit.emit(AuditEvent::new(
            audit::event::TOOL_REGISTRY_RELOAD_FAILED,
            "tool-registry",
            "internal",
            None,
            json!({
                "tools_file": path.display().to_string(),
                "outcome": "failure",
                "reason": error.to_string(),
            }),
        ));
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::Arc,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    use jsonschema::Validator;
    use serde_json::{json, Value};

    use super::*;
    use crate::audit::sink::tests::CaptureSink;
    use crate::config::{self, AuthMode, Config};

    #[test]
    fn valid_tools_file_loads_registry_and_exposes_get_and_list() {
        let file = TempToolsFile::new(&tools_document(&[
            echo_tool("echo", "POST", "/v1/echo"),
            echo_tool("get_widget", "GET", "/v1/widgets/{widget_id}"),
        ]));

        let registry = ToolRegistry::from_file(file.path()).expect("tools file should load");

        let echo = registry.get("echo").expect("echo tool should exist");
        assert_eq!(echo.name, "echo");
        assert_eq!(echo.description, "Echoes the provided message.");
        assert_eq!(echo.input_schema["type"], json!("object"));
        assert_eq!(echo.upstream.method, "POST");
        assert_eq!(echo.upstream.path_template, "/v1/echo");
        assert_eq!(
            echo.upstream.body,
            Some(BodyMapping {
                mode: BodyMappingMode::WholeArgsJson,
            })
        );

        let widget = registry
            .get("get_widget")
            .expect("get_widget tool should exist");
        assert_eq!(widget.upstream.method, "GET");
        assert_eq!(widget.upstream.path_template, "/v1/widgets/{widget_id}");
        assert_eq!(
            widget.upstream.query_params,
            vec![QueryParamMapping {
                arg_name: "include_details".to_owned(),
                query_name: "include_details".to_owned(),
                required: false,
            }]
        );

        let listed: Vec<_> = registry
            .list()
            .into_iter()
            .map(|tool| tool.name.clone())
            .collect();
        assert_eq!(listed, vec!["echo".to_owned(), "get_widget".to_owned()]);
    }

    #[test]
    fn duplicate_tool_name_is_rejected_with_clear_error() {
        let file = TempToolsFile::new(&tools_document(&[
            echo_tool("echo", "POST", "/v1/echo"),
            echo_tool("echo", "GET", "/v1/other"),
        ]));

        let error =
            ToolRegistry::from_file(file.path()).expect_err("duplicate tool names should reject");

        assert!(
            error
                .to_string()
                .contains("duplicate tool name 'echo' at tools[1]"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn unrecognized_http_method_is_rejected() {
        let file = TempToolsFile::new(&tools_document(&[echo_tool("echo", "BREW", "/v1/echo")]));

        let error =
            ToolRegistry::from_file(file.path()).expect_err("unknown methods should reject");

        assert!(
            error
                .to_string()
                .contains("tools[0].upstream.method contains unknown HTTP method 'BREW'"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn malformed_input_schema_is_rejected_and_names_tool() {
        let tool = malformed_input_schema_tool("bad_schema", "POST", "/v1/echo");
        let file = TempToolsFile::new(&tools_document(&[tool]));

        let error = ToolRegistry::from_file(file.path())
            .expect_err("invalid input_json_schema should reject");

        let message = error.to_string();
        assert!(
            message.contains("tool 'bad_schema' input_json_schema is not a valid JSON Schema"),
            "unexpected error: {message}"
        );
        assert!(
            message.contains("not-a-json-schema-type"),
            "schema compiler error should be included: {message}"
        );
    }

    #[test]
    fn deep_input_schema_reference_chain_is_rejected_before_jsonschema_compile() {
        let mut tool = echo_tool("deep_schema", "POST", "/v1/echo");
        tool["input_json_schema"] = deep_ref_schema(65);

        let error = ToolRegistry::from_json_value(json!({
            "schema_version": "0.1.0",
            "tools": [tool]
        }))
        .expect_err("overly deep input_json_schema references should reject");

        let message = error.to_string();
        assert!(
            message.contains("tool 'deep_schema' input_json_schema reference depth exceeds"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn deep_input_schema_anchor_reference_chain_is_rejected_before_jsonschema_compile() {
        let mut tool = echo_tool("deep_anchor_schema", "POST", "/v1/echo");
        tool["input_json_schema"] = deep_anchor_ref_schema(65);

        let error = ToolRegistry::from_json_value(json!({
            "schema_version": "0.1.0",
            "tools": [tool]
        }))
        .expect_err("overly deep anchor input_json_schema references should reject");

        let message = error.to_string();
        assert!(
            message.contains("tool 'deep_anchor_schema' input_json_schema reference depth exceeds"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn deep_input_schema_percent_encoded_reference_chain_is_rejected_before_jsonschema_compile() {
        let mut tool = echo_tool("deep_encoded_schema", "POST", "/v1/echo");
        tool["input_json_schema"] = deep_percent_encoded_ref_schema(65);

        let error = ToolRegistry::from_json_value(json!({
            "schema_version": "0.1.0",
            "tools": [tool]
        }))
        .expect_err("overly deep percent-encoded input_json_schema references should reject");

        let message = error.to_string();
        assert!(
            message
                .contains("tool 'deep_encoded_schema' input_json_schema reference depth exceeds"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn deep_input_schema_dynamic_anchor_reference_chain_is_rejected_before_jsonschema_compile() {
        let mut tool = echo_tool("deep_dynamic_schema", "POST", "/v1/echo");
        tool["input_json_schema"] = deep_dynamic_anchor_ref_schema(65);

        let error = ToolRegistry::from_json_value(json!({
            "schema_version": "0.1.0",
            "tools": [tool]
        }))
        .expect_err("overly deep dynamic anchor input_json_schema references should reject");

        let message = error.to_string();
        assert!(
            message
                .contains("tool 'deep_dynamic_schema' input_json_schema reference depth exceeds"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn duplicate_input_schema_anchor_names_are_rejected_before_jsonschema_compile() {
        let mut tool = echo_tool("duplicate_anchor_schema", "POST", "/v1/echo");
        tool["input_json_schema"] = duplicate_anchor_schema();

        let error = ToolRegistry::from_json_value(json!({
            "schema_version": "0.1.0",
            "tools": [tool]
        }))
        .expect_err("duplicate local anchor names should reject");

        let message = error.to_string();
        assert!(
            message.contains(
                "tool 'duplicate_anchor_schema' input_json_schema contains duplicate local schema anchor 'S0'"
            ),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn anchor_like_literal_schema_data_does_not_create_duplicate_anchor_rejection() {
        let mut tool = echo_tool("literal_anchor_data", "POST", "/v1/echo");
        tool["input_json_schema"] = literal_anchor_data_schema();

        ToolRegistry::from_json_value(json!({
            "schema_version": "0.1.0",
            "tools": [tool]
        }))
        .expect("literal data containing repeated $anchor keys should not count as schema anchors");
    }

    #[test]
    fn schema_named_like_literal_keyword_is_still_traversed() {
        let mut tool = echo_tool("schema_named_default", "POST", "/v1/echo");
        tool["input_json_schema"] = schema_named_like_literal_keyword();

        let error = ToolRegistry::from_json_value(json!({
            "schema_version": "0.1.0",
            "tools": [tool]
        }))
        .expect_err("subschema named like a literal keyword should still be traversed");

        let message = error.to_string();
        assert!(
            message
                .contains("tool 'schema_named_default' input_json_schema reference depth exceeds"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn aggregate_input_schema_precheck_budget_is_shared_across_tools() {
        let tools = (0..80)
            .map(|index| {
                let mut tool = echo_tool(
                    &format!("schema_budget_{index}"),
                    "POST",
                    &format!("/v1/schema-budget/{index}"),
                );
                tool["input_json_schema"] = object_schema_with_properties(64);
                tool
            })
            .collect::<Vec<_>>();

        let error = ToolRegistry::from_json_value(json!({
            "schema_version": "0.1.0",
            "tools": tools
        }))
        .expect_err("aggregate input_json_schema precheck budget should reject");

        let ToolRegistryError::Invalid { problems } = error else {
            panic!("budget exhaustion should return ToolRegistryError::Invalid");
        };
        let message = problems.join("; ");
        assert!(
            message.contains("input_json_schema")
                && (message.contains("budget")
                    || message.contains("reference")
                    || message.contains("node")),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn reasonable_multi_tool_input_schemas_stay_within_precheck_budget() {
        let tools = (0..3)
            .map(|index| {
                let mut tool = echo_tool(
                    &format!("reasonable_schema_{index}"),
                    "POST",
                    &format!("/v1/reasonable-schema/{index}"),
                );
                tool["input_json_schema"] = object_schema_with_properties(8);
                tool
            })
            .collect::<Vec<_>>();

        ToolRegistry::from_json_value(json!({
            "schema_version": "0.1.0",
            "tools": tools
        }))
        .expect("reasonable multi-tool schemas should stay within the shared precheck budget");
    }

    #[test]
    fn semantic_validation_reports_all_tool_definition_problems() {
        let file = TempToolsFile::new(&tools_document(&[
            echo_tool("echo", "POST", "/v1/echo"),
            echo_tool("echo", "BREW", "/v1/other"),
        ]));

        let error = ToolRegistry::from_file(file.path())
            .expect_err("multiple semantic problems should reject");
        let ToolRegistryError::Invalid { problems } = error else {
            panic!("semantic problems should return ToolRegistryError::Invalid");
        };

        assert_eq!(problems.len(), 2, "unexpected problems: {problems:?}");
        assert!(
            problems
                .iter()
                .any(|problem| problem.contains("duplicate tool name 'echo' at tools[1]")),
            "duplicate tool name problem missing: {problems:?}"
        );
        assert!(
            problems.iter().any(|problem| {
                problem.contains("tools[1].upstream.method contains unknown HTTP method 'BREW'")
            }),
            "unknown HTTP method problem missing: {problems:?}"
        );
    }

    #[test]
    fn input_schema_without_properties_is_rejected_at_load_time() {
        let mut tool = echo_tool("properties_less", "GET", "/v1/widgets/{widget_id}");
        tool["input_json_schema"] = json!({
            "type": "object"
        });
        let file = TempToolsFile::new(&tools_document(&[tool]));

        let error = ToolRegistry::from_file(file.path())
            .expect_err("properties-less input_json_schema should reject");
        let ToolRegistryError::Invalid { problems } = error else {
            panic!("properties-less input_json_schema should fail schema validation");
        };
        let message = problems.join("; ");

        assert!(
            message.contains("/tools/0/input_json_schema"),
            "schema error should identify the tool input schema path: {message}"
        );
        assert!(
            message.contains("properties"),
            "schema error should mention the missing properties key: {message}"
        );
    }

    #[test]
    fn path_placeholder_missing_from_required_is_rejected_at_load_time() {
        let mut tool = echo_tool("get_widget", "GET", "/v1/widgets/{widget_id}");
        tool["input_json_schema"] = json!({
            "type": "object",
            "required": ["message"],
            "properties": {
                "message": { "type": "string" },
                "widget_id": { "type": "string" }
            },
            "additionalProperties": false
        });

        let error = ToolRegistry::from_json_value(json!({
            "schema_version": "0.1.0",
            "tools": [tool]
        }))
        .expect_err("path placeholders missing from required should reject");

        let message = error.to_string();
        assert!(
            message.contains(
                "tool 'get_widget' path_template placeholder 'widget_id' must be listed in input_json_schema.required"
            ),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn required_query_mapping_missing_from_required_is_rejected_at_load_time() {
        let mut tool = echo_tool("get_widget", "GET", "/v1/widgets");
        tool["upstream"]["query_params"][0]["required"] = json!(true);

        let error = ToolRegistry::from_json_value(json!({
            "schema_version": "0.1.0",
            "tools": [tool]
        }))
        .expect_err("required query mappings missing from required should reject");

        let message = error.to_string();
        assert!(
            message.contains(
                "tool 'get_widget' required query argument 'include_details' must be listed in input_json_schema.required"
            ),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn path_mapped_argument_with_object_schema_is_rejected_at_load_time() {
        let mut tool = echo_tool("get_widget", "GET", "/v1/widgets/{widget_id}");
        tool["input_json_schema"] = json!({
            "type": "object",
            "required": ["message", "widget_id"],
            "properties": {
                "message": { "type": "string" },
                "widget_id": { "type": "object" }
            },
            "additionalProperties": false
        });

        let error = ToolRegistry::from_json_value(json!({
            "schema_version": "0.1.0",
            "tools": [tool]
        }))
        .expect_err("path mapped object arguments should reject");

        let message = error.to_string();
        assert!(
            message.contains(
                "tool 'get_widget' path argument 'widget_id' must be constrained to scalar JSON Schema types"
            ),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn query_mapped_argument_with_array_schema_is_rejected_at_load_time() {
        let mut tool = echo_tool("get_widget", "GET", "/v1/widgets");
        tool["input_json_schema"]["properties"]["include_details"] = json!({ "type": "array" });

        let error = ToolRegistry::from_json_value(json!({
            "schema_version": "0.1.0",
            "tools": [tool]
        }))
        .expect_err("query mapped array arguments should reject");

        let message = error.to_string();
        assert!(
            message.contains(
                "tool 'get_widget' query argument 'include_details' must be constrained to scalar JSON Schema types"
            ),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn optional_query_params_may_remain_optional_when_mapped_schemas_are_scalar() {
        let mut tool = echo_tool("get_widget", "GET", "/v1/widgets/{widget_id}");
        tool["input_json_schema"] = json!({
            "type": "object",
            "required": ["message", "widget_id"],
            "properties": {
                "message": { "type": "string" },
                "widget_id": { "type": "integer" },
                "include_details": { "type": ["boolean", "string"] }
            },
            "additionalProperties": false
        });

        ToolRegistry::from_json_value(json!({
            "schema_version": "0.1.0",
            "tools": [tool]
        }))
        .expect("optional query mappings with scalar schemas should load");
    }

    #[tokio::test]
    async fn file_watch_reload_applies_valid_tools_update() {
        let file = TempToolsFile::new(&tools_document(&[echo_tool("echo", "POST", "/v1/echo")]));
        let registry = ToolRegistry::from_file(file.path()).expect("initial registry should load");
        spawn_tool_registry_reload_tasks(file.path().to_owned(), registry.clone())
            .expect("tool registry watcher should start");

        assert!(registry.get("get_widget").is_none());

        file.write(&tools_document(&[
            echo_tool("echo", "POST", "/v1/echo"),
            echo_tool("get_widget", "GET", "/v1/widgets/{widget_id}"),
        ]));

        wait_until(Duration::from_secs(5), || {
            registry.get("get_widget").is_some()
        })
        .await;
    }

    #[tokio::test]
    async fn file_watch_reload_preserves_merged_mcp_proxy_tools() {
        let file = TempToolsFile::new(&tools_document(&[echo_tool("echo", "POST", "/v1/echo")]));
        let registry = ToolRegistry::from_file(file.path()).expect("initial registry should load");
        registry
            .merge_definitions(vec![mcp_proxy_tool(
                "weather:get_forecast",
                "weather",
                "get_forecast",
            )])
            .expect("MCP proxy tool should merge");
        spawn_tool_registry_reload_tasks(file.path().to_owned(), registry.clone())
            .expect("tool registry watcher should start");

        file.write(&tools_document(&[
            echo_tool("echo", "POST", "/v1/echo"),
            echo_tool("get_widget", "GET", "/v1/widgets/{widget_id}"),
        ]));

        wait_until(Duration::from_secs(5), || {
            registry.get("get_widget").is_some()
        })
        .await;
        let mcp_tool = registry
            .get("weather:get_forecast")
            .expect("local reload must preserve merged MCP proxy tool");
        assert_eq!(
            mcp_tool.upstream.mcp_proxy_mapping().unwrap().server_name,
            "weather"
        );
    }

    #[tokio::test]
    async fn file_watch_reload_updates_local_tools_when_mcp_proxy_tools_are_present() {
        let file = TempToolsFile::new(&tools_document(&[echo_tool("echo", "POST", "/v1/echo")]));
        let registry = ToolRegistry::from_file(file.path()).expect("initial registry should load");
        registry
            .merge_definitions(vec![mcp_proxy_tool(
                "weather:get_forecast",
                "weather",
                "get_forecast",
            )])
            .expect("MCP proxy tool should merge");
        spawn_tool_registry_reload_tasks(file.path().to_owned(), registry.clone())
            .expect("tool registry watcher should start");

        file.write(&tools_document(&[echo_tool(
            "get_widget",
            "GET",
            "/v1/widgets/{widget_id}",
        )]));

        wait_until(Duration::from_secs(5), || {
            registry.get("echo").is_none() && registry.get("get_widget").is_some()
        })
        .await;
        assert!(registry.get("weather:get_forecast").is_some());
    }

    #[test]
    fn reload_rejects_local_tool_colliding_with_preserved_mcp_proxy_tool_name() {
        let file = TempToolsFile::new(&tools_document(&[echo_tool("echo", "POST", "/v1/echo")]));
        let registry = ToolRegistry::from_file(file.path()).expect("initial registry should load");
        registry
            .merge_definitions(vec![mcp_proxy_tool(
                "weather.get_forecast",
                "weather",
                "get_forecast",
            )])
            .expect("MCP proxy tool should merge");

        file.write(&tools_document(&[echo_tool(
            "weather.get_forecast",
            "GET",
            "/v1/widgets/{widget_id}",
        )]));

        let error = reload_tool_registry_from_file(&registry, file.path())
            .expect_err("local collision with preserved MCP proxy name should reject");
        assert!(
            error
                .to_string()
                .contains("duplicate tool name 'weather.get_forecast'"),
            "unexpected error: {error}"
        );
        assert!(registry.get("echo").is_some());
        let mcp_tool = registry
            .get("weather.get_forecast")
            .expect("rejected reload must keep existing MCP proxy tool");
        assert!(
            mcp_tool.upstream.is_mcp_proxy(),
            "collision must not replace MCP proxy tool with local HTTP tool"
        );
        assert_eq!(
            registry.list().len(),
            2,
            "rejected collision reload must keep last-known-good registry"
        );
    }

    #[test]
    fn refreshed_mcp_proxy_reload_prunes_missing_proxy_tools_and_keeps_local_tools() {
        let file = TempToolsFile::new(&tools_document(&[echo_tool("echo", "POST", "/v1/echo")]));
        let registry = ToolRegistry::from_file(file.path()).expect("initial registry should load");
        registry
            .merge_definitions(vec![
                mcp_proxy_tool("weather:get_forecast", "weather", "get_forecast"),
                mcp_proxy_tool("weather:get_alerts", "weather", "get_alerts"),
            ])
            .expect("MCP proxy tools should merge");

        file.write(&tools_document(&[
            echo_tool("echo", "POST", "/v1/echo"),
            echo_tool("get_widget", "GET", "/v1/widgets/{widget_id}"),
        ]));

        reload_tool_registry_from_file_with_mcp_proxy_definitions(
            &registry,
            file.path(),
            vec![mcp_proxy_tool(
                "weather:get_forecast",
                "weather",
                "get_forecast",
            )],
        )
        .expect("refreshed MCP proxy reload should apply");

        assert!(registry.get("echo").is_some());
        assert!(registry.get("get_widget").is_some());
        assert!(registry.get("weather:get_forecast").is_some());
        assert!(
            registry.get("weather:get_alerts").is_none(),
            "refreshed MCP proxy set should prune missing proxy tools"
        );
        assert_eq!(registry.list().len(), 3);
    }

    #[test]
    fn refreshed_mcp_proxy_reload_rejects_collision_and_keeps_last_known_good_registry() {
        let file = TempToolsFile::new(&tools_document(&[echo_tool("echo", "POST", "/v1/echo")]));
        let registry = ToolRegistry::from_file(file.path()).expect("initial registry should load");
        registry
            .merge_definitions(vec![mcp_proxy_tool(
                "weather:get_forecast",
                "weather",
                "get_forecast",
            )])
            .expect("MCP proxy tool should merge");

        let error = reload_tool_registry_from_file_with_mcp_proxy_definitions(
            &registry,
            file.path(),
            vec![mcp_proxy_tool("echo", "weather", "echo")],
        )
        .expect_err("refreshed MCP proxy collision should reject");

        assert!(
            error.to_string().contains("duplicate tool name 'echo'"),
            "unexpected error: {error}"
        );
        let local_tool = registry
            .get("echo")
            .expect("rejected refresh must keep local tool");
        assert!(
            !local_tool.upstream.is_mcp_proxy(),
            "collision must not replace local HTTP tool with MCP proxy tool"
        );
        assert!(registry.get("weather:get_forecast").is_some());
        assert_eq!(
            registry.list().len(),
            2,
            "rejected refreshed reload must keep last-known-good registry"
        );
    }

    #[test]
    fn provider_backed_reload_preserves_mcp_proxy_tools_when_refresh_is_unavailable() {
        let file = TempToolsFile::new(&tools_document(&[echo_tool("echo", "POST", "/v1/echo")]));
        let registry = ToolRegistry::from_file(file.path()).expect("initial registry should load");
        registry
            .merge_definitions(vec![
                mcp_proxy_tool("weather:get_forecast", "weather", "get_forecast"),
                mcp_proxy_tool("weather:get_alerts", "weather", "get_alerts"),
            ])
            .expect("MCP proxy tools should merge");
        let unavailable_provider: McpProxyDefinitionsProvider = Arc::new(|| None);

        file.write(&tools_document(&[echo_tool(
            "get_widget",
            "GET",
            "/v1/widgets/{widget_id}",
        )]));

        reload_tool_registry_from_file_with_mcp_proxy_definitions_provider(
            &registry,
            file.path(),
            Some(&unavailable_provider),
        )
        .expect("local reload should still apply when MCP proxy refresh is unavailable");

        assert!(registry.get("echo").is_none());
        assert!(registry.get("get_widget").is_some());
        assert!(registry.get("weather:get_forecast").is_some());
        assert!(registry.get("weather:get_alerts").is_some());
        assert_eq!(registry.list().len(), 3);
    }

    #[test]
    fn reload_rejects_colon_namespaced_local_tool_name_without_replacing_mcp_proxy_tool() {
        let file = TempToolsFile::new(&tools_document(&[echo_tool("echo", "POST", "/v1/echo")]));
        let registry = ToolRegistry::from_file(file.path()).expect("initial registry should load");
        registry
            .merge_definitions(vec![mcp_proxy_tool(
                "weather:get_forecast",
                "weather",
                "get_forecast",
            )])
            .expect("MCP proxy tool should merge");

        file.write(&tools_document(&[echo_tool(
            "weather:get_forecast",
            "GET",
            "/v1/widgets/{widget_id}",
        )]));

        let error = reload_tool_registry_from_file(&registry, file.path())
            .expect_err("colon namespaced local tool names should reject");
        assert!(
            error.to_string().contains("/tools/0/name"),
            "unexpected error: {error}"
        );
        assert!(registry.get("echo").is_some());
        let mcp_tool = registry
            .get("weather:get_forecast")
            .expect("schema-rejected reload must keep existing MCP proxy tool");
        assert!(
            mcp_tool.upstream.is_mcp_proxy(),
            "schema rejection must not replace MCP proxy tool with local HTTP tool"
        );
    }

    #[test]
    fn reload_rejects_invalid_tool_mapping_without_replacing_existing_registry() {
        let file = TempToolsFile::new(&tools_document(&[echo_tool("echo", "POST", "/v1/echo")]));
        let registry = ToolRegistry::from_file(file.path()).expect("initial registry should load");
        let mut invalid_tool = echo_tool("get_widget", "GET", "/v1/widgets/{widget_id}");
        invalid_tool["input_json_schema"] = json!({
            "type": "object",
            "required": ["message"],
            "properties": {
                "message": { "type": "string" },
                "widget_id": { "type": "string" },
                "include_details": { "type": "boolean" }
            },
            "additionalProperties": false
        });

        file.write(&tools_document(&[invalid_tool]));

        let error = reload_tool_registry_from_file(&registry, file.path())
            .expect_err("invalid path mapping should reject reload");
        assert!(
            error.to_string().contains(
                "tool 'get_widget' path_template placeholder 'widget_id' must be listed in input_json_schema.required"
            ),
            "unexpected error: {error}"
        );
        assert!(registry.get("echo").is_some());
        assert!(registry.get("get_widget").is_none());
        assert_eq!(
            registry.list().len(),
            1,
            "mapping validation failure must keep last-known-good registry"
        );
    }

    #[tokio::test]
    async fn file_watch_invalid_update_keeps_local_and_mcp_proxy_tools() {
        let file = TempToolsFile::new(&tools_document(&[echo_tool("echo", "POST", "/v1/echo")]));
        let capture = CaptureSink::new();
        let audit_log = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
        let registry = ToolRegistry::from_file_with_audit(file.path(), audit_log)
            .expect("initial registry should load");
        registry
            .merge_definitions(vec![mcp_proxy_tool(
                "weather:get_forecast",
                "weather",
                "get_forecast",
            )])
            .expect("MCP proxy tool should merge");
        spawn_tool_registry_reload_tasks(file.path().to_owned(), registry.clone())
            .expect("tool registry watcher should start");

        let failure_count = audit_event_count(&capture, audit::event::TOOL_REGISTRY_RELOAD_FAILED);
        file.write(&tools_document(&[
            echo_tool("echo", "POST", "/v1/echo"),
            echo_tool("echo", "GET", "/v1/other"),
        ]));

        wait_until(Duration::from_secs(5), || {
            audit_event_count(&capture, audit::event::TOOL_REGISTRY_RELOAD_FAILED) > failure_count
        })
        .await;

        assert!(registry.get("echo").is_some());
        assert!(registry.get("weather:get_forecast").is_some());
        assert_eq!(
            registry.list().len(),
            2,
            "invalid watched reload must keep local and MCP proxy tools"
        );
    }

    #[tokio::test]
    async fn file_watch_invalid_updates_keep_old_registry_and_accept_later_valid_update() {
        let file = TempToolsFile::new(&tools_document(&[echo_tool("echo", "POST", "/v1/echo")]));
        let capture = CaptureSink::new();
        let audit_log = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
        let registry = ToolRegistry::from_file_with_audit(file.path(), audit_log)
            .expect("initial registry should load");
        spawn_tool_registry_reload_tasks(file.path().to_owned(), registry.clone())
            .expect("tool registry watcher should start");

        for invalid_update in [
            r#"{ "schema_version": "#.to_owned(),
            tools_document(&[
                echo_tool("echo", "POST", "/v1/echo"),
                echo_tool("echo", "GET", "/v1/other"),
            ]),
            tools_document(&[echo_tool("get_widget", "BREW", "/v1/widgets/{widget_id}")]),
            tools_document(&[malformed_input_schema_tool(
                "bad_schema",
                "POST",
                "/v1/echo",
            )]),
        ] {
            let failure_count =
                audit_event_count(&capture, audit::event::TOOL_REGISTRY_RELOAD_FAILED);

            file.write(&invalid_update);

            wait_until(Duration::from_secs(5), || {
                audit_event_count(&capture, audit::event::TOOL_REGISTRY_RELOAD_FAILED)
                    > failure_count
            })
            .await;

            assert!(
                registry.get("echo").is_some(),
                "invalid watched reload must keep last-known-good registry"
            );
            assert!(
                registry.get("get_widget").is_none(),
                "invalid watched reload must not partially apply"
            );
            assert_eq!(
                registry.list().len(),
                1,
                "invalid watched reload must not change tool count"
            );
        }

        file.write(&tools_document(&[echo_tool(
            "get_widget",
            "GET",
            "/v1/widgets/{widget_id}",
        )]));

        wait_until(Duration::from_secs(5), || registry.get("echo").is_none()).await;
        assert!(registry.get("get_widget").is_some());
    }

    #[test]
    fn from_config_returns_disabled_empty_registry_when_tools_file_unset() {
        let config = test_config(None);

        let registry =
            ToolRegistry::from_config(&config).expect("unset TOOLS_FILE should not error");

        assert!(registry.get("anything").is_none());
        assert!(registry.list().is_empty());
    }

    #[test]
    fn from_config_with_audit_returns_disabled_empty_registry_when_tools_file_unset() {
        let config = test_config(None);
        let capture = CaptureSink::new();
        let audit_log = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);

        let registry = ToolRegistry::from_config_with_audit(&config, audit_log)
            .expect("unset TOOLS_FILE should not error");

        assert!(registry.get("anything").is_none());
        assert!(registry.list().is_empty());
        assert_eq!(
            capture.len(),
            0,
            "unset TOOLS_FILE should not emit load events"
        );
    }

    #[test]
    fn from_config_loads_registry_when_tools_file_is_set() {
        let file = TempToolsFile::new(&tools_document(&[echo_tool("echo", "POST", "/v1/echo")]));
        let config = test_config(Some(file.path().to_string_lossy().into_owned()));

        let registry = ToolRegistry::from_config(&config).expect("TOOLS_FILE should load");

        assert!(registry.get("echo").is_some());
    }

    #[test]
    fn published_schema_accepts_valid_tools_file() {
        let validator = tools_schema_validator();
        let document = json!({
            "schema_version": "0.1.0",
            "tools": [
                {
                    "name": "echo",
                    "description": "Echoes the provided message.",
                    "input_json_schema": {
                        "type": "object",
                        "required": ["message"],
                        "properties": {
                            "message": { "type": "string" }
                        },
                        "additionalProperties": false
                    },
                    "upstream": {
                        "method": "POST",
                        "path_template": "/v1/echo",
                        "body": { "mode": "whole_args_json" }
                    }
                }
            ]
        });

        assert_schema_accepts(&validator, &document);
        ToolRegistry::from_json_value(document).expect("schema-valid tools should parse");
    }

    #[test]
    fn starter_and_dev_tools_files_parse_and_match_published_schema() {
        for path in [
            repo_root().join("docs/examples/tools.starter.json"),
            repo_root().join("dev/tools.json"),
        ] {
            let registry = ToolRegistry::from_file(&path)
                .unwrap_or_else(|err| panic!("{} should parse: {err}", path.display()));
            assert!(
                !registry.list().is_empty(),
                "{} should include at least one example tool",
                path.display()
            );

            let contents = fs::read_to_string(&path)
                .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
            let value: Value = serde_json::from_str(&contents)
                .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()));
            assert_schema_accepts(&tools_schema_validator(), &value);
        }
    }

    #[test]
    fn oversized_tools_file_is_rejected_with_clear_error() {
        let file = TempToolsFile::new(&" ".repeat(1_048_577));

        let error =
            ToolRegistry::from_file(file.path()).expect_err("oversized tools file should reject");
        let message = error.to_string();

        assert!(
            message.contains("tools file exceeds maximum size of 1048576 bytes"),
            "unexpected error: {message}"
        );
    }

    fn tools_document(tools: &[Value]) -> String {
        serde_json::to_string_pretty(&json!({
            "schema_version": "0.1.0",
            "tools": tools
        }))
        .expect("test tools document should serialize")
    }

    fn echo_tool(name: &str, method: &str, path_template: &str) -> Value {
        let mut tool = json!({
            "name": name,
            "description": "Echoes the provided message.",
            "input_json_schema": {
                "type": "object",
                "required": ["message"],
                "properties": {
                    "message": { "type": "string" },
                    "include_details": { "type": "boolean" }
                },
                "additionalProperties": false
            },
            "upstream": {
                "method": method,
                "path_template": path_template,
                "query_params": [
                    {
                        "arg_name": "include_details",
                        "query_name": "include_details",
                        "required": false
                    }
                ],
                "body": {
                    "mode": "whole_args_json"
                }
            }
        });

        if path_template.contains("{widget_id}") {
            tool["input_json_schema"]["required"] = json!(["message", "widget_id"]);
            tool["input_json_schema"]["properties"]["widget_id"] = json!({ "type": "string" });
        }

        tool
    }

    fn malformed_input_schema_tool(name: &str, method: &str, path_template: &str) -> Value {
        let mut tool = echo_tool(name, method, path_template);
        tool["input_json_schema"] = json!({
            "type": "not-a-json-schema-type",
            "properties": {}
        });
        tool
    }

    fn deep_ref_schema(depth: usize) -> Value {
        let mut defs = serde_json::Map::new();
        for index in 0..depth {
            defs.insert(
                format!("S{index}"),
                json!({ "$ref": format!("#/$defs/S{}", index + 1) }),
            );
        }
        defs.insert(format!("S{depth}"), json!({ "type": "string" }));

        json!({
            "$ref": "#/$defs/S0",
            "properties": {},
            "$defs": defs
        })
    }

    fn deep_anchor_ref_schema(depth: usize) -> Value {
        let mut defs = serde_json::Map::new();
        for index in 0..depth {
            defs.insert(
                format!("S{index}"),
                json!({
                    "$anchor": format!("S{index}"),
                    "$ref": format!("#S{}", index + 1)
                }),
            );
        }
        defs.insert(
            format!("S{depth}"),
            json!({
                "$anchor": format!("S{depth}"),
                "type": "string"
            }),
        );

        json!({
            "$ref": "#S0",
            "properties": {},
            "$defs": defs
        })
    }

    fn deep_dynamic_anchor_ref_schema(depth: usize) -> Value {
        let mut defs = serde_json::Map::new();
        for index in 0..depth {
            defs.insert(
                format!("S{index}"),
                json!({
                    "$dynamicAnchor": format!("S{index}"),
                    "$dynamicRef": format!("#S{}", index + 1)
                }),
            );
        }
        defs.insert(
            format!("S{depth}"),
            json!({
                "$dynamicAnchor": format!("S{depth}"),
                "type": "string"
            }),
        );

        json!({
            "$dynamicRef": "#S0",
            "properties": {},
            "$defs": defs
        })
    }

    fn deep_percent_encoded_ref_schema(depth: usize) -> Value {
        let mut defs = serde_json::Map::new();
        for index in 0..depth {
            defs.insert(
                format!("S{index}"),
                json!({ "$ref": format!("#/%24defs/S{}", index + 1) }),
            );
        }
        defs.insert(format!("S{depth}"), json!({ "type": "string" }));

        json!({
            "$ref": "#/%24defs/S0",
            "properties": {},
            "$defs": defs
        })
    }

    fn literal_anchor_data_schema() -> Value {
        json!({
            "type": "object",
            "properties": {
                "const_value": {
                    "const": { "$anchor": "literal" }
                },
                "default_value": {
                    "type": "object",
                    "default": { "$anchor": "literal" }
                },
                "example_value": {
                    "type": "object",
                    "examples": [{ "$anchor": "literal" }]
                },
                "include_details": {
                    "type": "boolean"
                }
            },
            "additionalProperties": false
        })
    }

    fn schema_named_like_literal_keyword() -> Value {
        let mut defs = serde_json::Map::new();
        for index in 0..65 {
            defs.insert(
                format!("S{index}"),
                json!({ "$ref": format!("#/$defs/S{}", index + 1) }),
            );
        }
        defs.insert("S65".to_owned(), json!({ "type": "string" }));

        json!({
            "type": "object",
            "properties": {
                "default": {
                    "$ref": "#/$defs/S0"
                }
            },
            "$defs": defs,
            "additionalProperties": false
        })
    }

    fn duplicate_anchor_schema() -> Value {
        json!({
            "$ref": "#S0",
            "properties": {},
            "$defs": {
                "first": {
                    "$anchor": "S0",
                    "type": "string"
                },
                "second": {
                    "$anchor": "S0",
                    "$ref": "#/$defs/second"
                }
            }
        })
    }

    fn object_schema_with_properties(property_count: usize) -> Value {
        let mut properties = (0..property_count)
            .map(|index| (format!("field_{index}"), json!({ "type": "string" })))
            .collect::<serde_json::Map<_, _>>();
        properties.insert("include_details".to_owned(), json!({ "type": "boolean" }));

        json!({
            "type": "object",
            "properties": properties,
            "additionalProperties": false
        })
    }

    fn mcp_proxy_tool(name: &str, server_name: &str, tool_name: &str) -> ToolDefinition {
        ToolDefinition::mcp_proxy(
            name.to_owned(),
            "Gets the forecast from an upstream MCP server.".to_owned(),
            json!({
                "type": "object",
                "properties": {
                    "city": { "type": "string" }
                },
                "additionalProperties": false
            }),
            server_name.to_owned(),
            tool_name.to_owned(),
        )
    }

    fn tools_schema_validator() -> Validator {
        let schema_path = repo_root().join("docs/schemas/tools.v0.schema.json");
        let schema = fs::read_to_string(&schema_path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", schema_path.display()));
        let schema = serde_json::from_str(&schema)
            .unwrap_or_else(|err| panic!("failed to parse {}: {err}", schema_path.display()));

        jsonschema::validator_for(&schema)
            .unwrap_or_else(|err| panic!("failed to compile {}: {err}", schema_path.display()))
    }

    fn assert_schema_accepts(validator: &Validator, value: &Value) {
        if let Err(error) = validator.validate(value) {
            panic!("published schema should accept tools document: {error}");
        }
    }

    fn audit_event_count(capture: &CaptureSink, event_type: &str) -> usize {
        capture
            .events()
            .iter()
            .filter(|event| event.event_type == event_type)
            .count()
    }

    async fn wait_until(timeout: Duration, condition: impl Fn() -> bool) {
        let started = std::time::Instant::now();

        while started.elapsed() < timeout {
            if condition() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }

        assert!(
            condition(),
            "condition did not become true within {timeout:?}"
        );
    }

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("gateway crate should live directly under the repo root")
            .to_owned()
    }

    fn test_config(tools_file: Option<String>) -> Config {
        Config {
            listen_addr: "127.0.0.1:0"
                .parse()
                .expect("test listen address should parse"),
            admin_listen_addr: None,
            admin_prefix: "/admin".to_owned(),
            admin_login_provider: None,
            gateway_public_url: None,
            audit_log_file: None,
            audit_sqlite_path: None,
            audit_sqlite_retention_days: None,
            discovery_sqlite_path: None,
            principal_sqlite_path: None,
            payload_capture_enabled: false,
            payload_capture_sample_rate: config::DEFAULT_PAYLOAD_CAPTURE_SAMPLE_RATE,
            schema_mismatch_signal_threshold:
                crate::discovery::signals::DEFAULT_SCHEMA_MISMATCH_SIGNAL_THRESHOLD,
            error_rate_spike_signal_threshold:
                crate::discovery::signals::DEFAULT_ERROR_RATE_SPIKE_SIGNAL_THRESHOLD,
            principal_new_to_endpoint_signal_threshold:
                crate::discovery::signals::DEFAULT_PRINCIPAL_NEW_TO_ENDPOINT_SIGNAL_THRESHOLD,
            volume_outlier_signal_threshold:
                crate::discovery::signals::DEFAULT_VOLUME_OUTLIER_SIGNAL_THRESHOLD,
            rule_suggestion_baseline_window_hours:
                crate::discovery::suggestions::DEFAULT_RULE_SUGGESTION_BASELINE_WINDOW_HOURS,
            openapi_spec_path: None,
            policy_file: None,
            tools_file,
            policy_history_sqlite_path: None,
            cors_allow_origins: Vec::new(),
            max_body_size: 1_048_576,
            rate_limit_read_rps: 50.0,
            rate_limit_read_burst: 100,
            rate_limit_write_rps: 10.0,
            rate_limit_write_burst: 20,
            trust_proxy_headers: false,
            trusted_proxy_cidrs: Vec::new(),
            rbac_exempt_paths: vec![
                "/health".to_owned(),
                "/version".to_owned(),
                "/metrics".to_owned(),
            ],
            validation_allowed_content_types: vec!["application/json".to_owned()],
            auth_enabled: true,
            auth_mode: AuthMode::Required,
            auth_cookie_name: "session".to_owned(),
            auth_exempt_paths: vec![
                "/health".to_owned(),
                "/version".to_owned(),
                "/metrics".to_owned(),
            ],
            auth_providers: Vec::new(),
            jwt_jwks_url: None,
            jwt_issuer: None,
            jwt_audience: None,
            jwt_jwks_timeout_ms: 2000,
            jwt_require_jti: false,
            roles_claim: "roles".to_owned(),
            service_token_sqlite_path: None,
            service_token_cache_ttl_ms: config::DEFAULT_SERVICE_TOKEN_CACHE_TTL_MS,
            tool_runtime_queue_depth: config::DEFAULT_TOOL_RUNTIME_QUEUE_DEPTH,
            tool_runtime_global_concurrency: config::DEFAULT_TOOL_RUNTIME_GLOBAL_CONCURRENCY,
            tool_runtime_queue_timeout_ms: config::DEFAULT_TOOL_RUNTIME_QUEUE_TIMEOUT_MS,
            tool_runtime_default_timeout_ms: config::DEFAULT_TOOL_RUNTIME_DEFAULT_TIMEOUT_MS,
            csrf_enabled: true,
            csrf_cookie_name: "csrf_token".to_owned(),
            csrf_header_name: "x-csrf-token".to_owned(),
            csrf_cookie_domain: None,
            csrf_exempt_paths: vec![
                "/health".to_owned(),
                "/version".to_owned(),
                "/metrics".to_owned(),
            ],
            upstream_url: None,
            upstream_routes: Vec::new(),
            mcp_upstream_servers: Vec::new(),
            upstream_timeout_ms: None,
            upstream_response_idle_timeout_ms: None,
            upstream_connect_timeout_ms: None,
            egress_allowed_hosts: Vec::new(),
            egress_timeout_ms: 30_000,
            egress_response_idle_timeout_ms: 30_000,
            egress_connect_timeout_ms: 10_000,
            egress_max_response_bytes: 5_242_880,
            egress_max_request_body_bytes: 1_048_576,
            egress_nat64_prefixes: Vec::new(),
            egress_deny_private_ips: true,
        }
    }

    struct TempToolsFile {
        path: PathBuf,
    }

    impl TempToolsFile {
        fn new(contents: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "greengateway-tools-test-{}-{}.json",
                std::process::id(),
                unique_suffix()
            ));
            fs::write(&path, contents)
                .unwrap_or_else(|err| panic!("failed to write {}: {err}", path.display()));

            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }

        fn write(&self, contents: &str) {
            fs::write(&self.path, contents)
                .unwrap_or_else(|err| panic!("failed to write {}: {err}", self.path.display()));
        }
    }

    impl Drop for TempToolsFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }

    fn unique_suffix() -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after Unix epoch")
            .as_nanos()
    }
}
