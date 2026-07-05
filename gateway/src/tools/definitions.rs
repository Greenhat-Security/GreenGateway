use std::{
    collections::BTreeMap,
    error::Error,
    fmt, fs, io,
    path::{Path, PathBuf},
    sync::{Arc, LazyLock, Mutex},
    time::Duration,
};

use arc_swap::ArcSwap;
use http::Method;
use notify::{RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::mpsc;

use crate::{
    audit::{self, AuditEvent, AuditLog},
    config::Config,
};

const TOOL_REGISTRY_RELOAD_DEBOUNCE: Duration = Duration::from_millis(200);
const TOOLS_FILE_SCHEMA_JSON: &str = include_str!("../../../docs/schemas/tools.v0.schema.json");

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

    fn replace_definitions(&self, definitions: Vec<ToolDefinition>) {
        let _guard = match self.write_lock.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        self.state
            .store(Arc::new(ToolRegistryState::from_definitions(definitions)));
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
        Self {
            tools: definitions
                .into_iter()
                .map(|definition| (definition.name.clone(), Arc::new(definition)))
                .collect(),
        }
    }
}

pub fn reload_tool_registry_from_file(
    registry: &ToolRegistry,
    path: impl AsRef<Path>,
) -> Result<(), ToolRegistryError> {
    let path = path.as_ref();

    match definitions_from_file(path) {
        Ok(definitions) => {
            let tool_count = definitions.len();
            registry.replace_definitions(definitions);
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

pub fn spawn_tool_registry_reload_tasks(
    tools_file: impl Into<PathBuf>,
    registry: ToolRegistry,
) -> notify::Result<()> {
    let tools_file = tools_file.into();
    spawn_tool_registry_file_watcher(tools_file.clone(), registry.clone())?;
    spawn_sighup_reload_task(tools_file, registry);
    Ok(())
}

fn spawn_tool_registry_file_watcher(
    tools_file: PathBuf,
    registry: ToolRegistry,
) -> notify::Result<()> {
    let (sender, receiver) = mpsc::unbounded_channel();
    let mut watcher = notify::recommended_watcher(move |event| {
        let _ = sender.send(event);
    })?;
    watcher.watch(&watch_directory(&tools_file), RecursiveMode::NonRecursive)?;

    tokio::spawn(tool_registry_file_watch_loop(
        tools_file, registry, receiver, watcher,
    ));

    Ok(())
}

async fn tool_registry_file_watch_loop(
    tools_file: PathBuf,
    registry: ToolRegistry,
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

        let _ = reload_tool_registry_from_file(&registry, &tools_file);
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
fn spawn_sighup_reload_task(tools_file: PathBuf, registry: ToolRegistry) {
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
            let _ = reload_tool_registry_from_file(&registry, &tools_file);
        }
    });
}

#[cfg(not(unix))]
fn spawn_sighup_reload_task(_tools_file: PathBuf, _registry: ToolRegistry) {}

fn definitions_from_file(path: &Path) -> Result<Vec<ToolDefinition>, ToolRegistryError> {
    let contents = fs::read_to_string(path).map_err(|source| ToolRegistryError::Io {
        path: path.to_owned(),
        source,
    })?;
    let value = serde_json::from_str(&contents).map_err(|source| ToolRegistryError::Parse {
        path: Some(path.to_owned()),
        source,
    })?;

    definitions_from_json_value(value, Some(path))
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

    for (index, definition) in definitions.iter().enumerate() {
        if let Some(first_index) = seen.insert(definition.name.as_str(), index) {
            problems.push(format!(
                "duplicate tool name '{}' at tools[{index}] (first defined at tools[{first_index}])",
                definition.name
            ));
        }

        if !is_known_http_method(&definition.upstream.method) {
            problems.push(format!(
                "tools[{index}].upstream.method contains unknown HTTP method '{}'",
                definition.upstream.method
            ));
        }

        if let Err(err) = jsonschema::validator_for(&definition.input_schema) {
            problems.push(format!(
                "tool '{}' input_json_schema is not a valid JSON Schema: {err}",
                definition.name
            ));
        }
    }

    problems
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
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    use jsonschema::Validator;
    use serde_json::{json, Value};

    use super::*;
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
        let mut tool = echo_tool("bad_schema", "POST", "/v1/echo");
        tool["input_json_schema"] = json!({
            "type": "not-a-json-schema-type"
        });
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

        wait_until(Duration::from_secs(2), || {
            registry.get("get_widget").is_some()
        })
        .await;
    }

    #[tokio::test]
    async fn file_watch_invalid_update_keeps_old_registry_and_accepts_later_valid_update() {
        let file = TempToolsFile::new(&tools_document(&[echo_tool("echo", "POST", "/v1/echo")]));
        let registry = ToolRegistry::from_file(file.path()).expect("initial registry should load");
        spawn_tool_registry_reload_tasks(file.path().to_owned(), registry.clone())
            .expect("tool registry watcher should start");

        file.write(r#"{ "schema_version": "#);
        tokio::time::sleep(Duration::from_millis(500)).await;

        assert!(
            registry.get("echo").is_some(),
            "invalid watched reload must keep last-known-good registry"
        );
        assert!(
            registry.get("get_widget").is_none(),
            "invalid watched reload must not partially apply"
        );

        file.write(&tools_document(&[echo_tool(
            "get_widget",
            "GET",
            "/v1/widgets/{widget_id}",
        )]));

        wait_until(Duration::from_secs(2), || registry.get("echo").is_none()).await;
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

    fn tools_document(tools: &[Value]) -> String {
        serde_json::to_string_pretty(&json!({
            "schema_version": "0.1.0",
            "tools": tools
        }))
        .expect("test tools document should serialize")
    }

    fn echo_tool(name: &str, method: &str, path_template: &str) -> Value {
        json!({
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
        })
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
            rbac_exempt_paths: vec![
                "/health".to_owned(),
                "/version".to_owned(),
                "/metrics".to_owned(),
            ],
            session_cookie_name: String::new(),
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
            upstream_timeout_ms: None,
            upstream_response_idle_timeout_ms: None,
            upstream_connect_timeout_ms: None,
            egress_allowed_hosts: Vec::new(),
            egress_timeout_ms: 30_000,
            egress_response_idle_timeout_ms: 30_000,
            egress_connect_timeout_ms: 10_000,
            egress_max_response_bytes: 5_242_880,
            egress_max_request_body_bytes: 1_048_576,
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
