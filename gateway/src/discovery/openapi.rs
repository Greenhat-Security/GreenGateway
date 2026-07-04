use std::{collections::BTreeMap, error::Error, fmt, fs, path::Path};

use serde::{Deserialize, Serialize};

use crate::config;
pub use crate::discovery::query::ObservedEndpoint;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenApiSpec {
    pub source: String,
    pub operations: Vec<OpenApiOperation>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OpenApiOperation {
    pub method: String,
    pub path_template: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    pub source: String,
    #[serde(skip)]
    pub request_shape: OpenApiRequestShape,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OpenApiRequestShape {
    pub query_params: Vec<OpenApiQueryParam>,
    pub json_body_keys: Vec<OpenApiJsonBodyKey>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenApiQueryParam {
    pub name: String,
    pub required: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenApiJsonBodyKey {
    pub name: String,
    pub required: bool,
}

impl OpenApiRequestShape {
    pub fn is_empty(&self) -> bool {
        self.query_params.is_empty() && self.json_body_keys.is_empty()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SchemaCoverageReport {
    pub spec_configured: bool,
    pub discovery_configured: bool,
    pub undocumented_endpoints: Vec<ObservedEndpoint>,
    pub unused_operations: Vec<OpenApiOperation>,
}

#[derive(Clone, Debug, Default)]
pub struct SchemaCoverage {
    specs: Vec<ConfiguredOpenApiSpec>,
}

#[derive(Clone, Debug)]
struct ConfiguredOpenApiSpec {
    spec: OpenApiSpec,
    path_prefix: Option<String>,
}

#[derive(Debug)]
pub enum OpenApiSpecError {
    Io { source: std::io::Error },
    Json { source: serde_json::Error },
    Yaml { source: yaml_serde::Error },
    UnsupportedVersion { version: String },
    InvalidPathTemplate { path_template: String },
}

#[derive(Debug)]
pub struct SchemaCoverageConfigError {
    problems: Vec<String>,
}

#[derive(Deserialize)]
struct RawOpenApiDocument {
    openapi: String,
    #[serde(default)]
    paths: BTreeMap<String, RawPathItem>,
}

#[derive(Default, Deserialize)]
struct RawPathItem {
    #[serde(default)]
    parameters: Vec<RawParameter>,
    #[serde(default)]
    get: Option<RawOperation>,
    #[serde(default)]
    put: Option<RawOperation>,
    #[serde(default)]
    post: Option<RawOperation>,
    #[serde(default)]
    delete: Option<RawOperation>,
    #[serde(default)]
    options: Option<RawOperation>,
    #[serde(default)]
    head: Option<RawOperation>,
    #[serde(default)]
    patch: Option<RawOperation>,
    #[serde(default)]
    trace: Option<RawOperation>,
}

#[derive(Clone, Default, Deserialize)]
struct RawOperation {
    #[serde(default, rename = "operationId")]
    operation_id: Option<String>,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    parameters: Vec<RawParameter>,
    #[serde(default, rename = "requestBody")]
    request_body: Option<RawRequestBody>,
}

#[derive(Clone, Default, Deserialize)]
struct RawParameter {
    #[serde(default)]
    name: Option<String>,
    #[serde(default, rename = "in")]
    location: Option<String>,
    #[serde(default)]
    required: bool,
}

#[derive(Clone, Default, Deserialize)]
struct RawRequestBody {
    #[serde(default)]
    content: BTreeMap<String, RawMediaType>,
}

#[derive(Clone, Default, Deserialize)]
struct RawMediaType {
    #[serde(default)]
    schema: Option<RawSchema>,
}

#[derive(Clone, Default, Deserialize)]
struct RawSchema {
    #[serde(default)]
    required: Vec<String>,
    #[serde(default)]
    properties: BTreeMap<String, RawSchema>,
}

impl OpenApiSpec {
    pub fn from_path(path: &Path) -> Result<Self, OpenApiSpecError> {
        let contents =
            fs::read_to_string(path).map_err(|source| OpenApiSpecError::Io { source })?;
        Self::parse_str(&path.to_string_lossy(), &contents)
    }

    pub fn parse_str(source: &str, contents: &str) -> Result<Self, OpenApiSpecError> {
        let document = parse_document(source, contents)?;
        if !document.openapi.starts_with("3.") {
            return Err(OpenApiSpecError::UnsupportedVersion {
                version: document.openapi,
            });
        }

        let mut operations = Vec::new();
        for (path_template, path_item) in document.paths {
            if !path_template.starts_with('/') {
                return Err(OpenApiSpecError::InvalidPathTemplate { path_template });
            }

            for (method, operation, path_parameters) in path_item.operations() {
                let request_shape = request_shape(&path_parameters, &operation);
                operations.push(OpenApiOperation {
                    method: method.to_owned(),
                    path_template: path_template.clone(),
                    operation_id: non_empty_optional_string(operation.operation_id),
                    summary: non_empty_optional_string(operation.summary),
                    source: source.to_owned(),
                    request_shape,
                });
            }
        }
        operations.sort_by(compare_operations);

        Ok(Self {
            source: source.to_owned(),
            operations,
        })
    }

    #[cfg(test)]
    fn from_operations(operations: Vec<OpenApiOperation>) -> Self {
        Self {
            source: "inline".to_owned(),
            operations,
        }
    }
}

impl SchemaCoverage {
    pub fn from_config(config: &config::Config) -> Result<Self, SchemaCoverageConfigError> {
        let mut specs = Vec::new();
        let mut problems = Vec::new();

        if let Some(path) = config.openapi_spec_path.as_ref() {
            push_configured_spec("OPENAPI_SPEC_PATH", path, None, &mut specs, &mut problems);
        }

        for (index, route) in config.upstream_routes.iter().enumerate() {
            let Some(path) = route.openapi_spec_path.as_ref() else {
                continue;
            };
            push_configured_spec(
                &format!("UPSTREAM_ROUTES[{index}].openapi_spec_path"),
                path,
                route.path_prefix.clone(),
                &mut specs,
                &mut problems,
            );
        }

        if problems.is_empty() {
            Ok(Self { specs })
        } else {
            Err(SchemaCoverageConfigError { problems })
        }
    }

    pub fn spec_configured(&self) -> bool {
        !self.specs.is_empty()
    }

    #[cfg(test)]
    pub(crate) fn global_for_test(spec: OpenApiSpec) -> Self {
        Self {
            specs: vec![ConfiguredOpenApiSpec {
                spec,
                path_prefix: None,
            }],
        }
    }

    pub fn compare(&self, observed: &[ObservedEndpoint]) -> SchemaCoverageReport {
        let operation_shapes = self.operation_shapes();
        let undocumented_endpoints = observed
            .iter()
            .filter(|endpoint| {
                !operation_shapes
                    .iter()
                    .any(|operation| operation.matches_observed(endpoint))
            })
            .cloned()
            .collect::<Vec<_>>();
        let unused_operations = operation_shapes
            .iter()
            .filter(|operation| {
                !observed
                    .iter()
                    .any(|endpoint| operation.matches_observed(endpoint))
            })
            .map(|operation| operation.operation.clone())
            .collect::<Vec<_>>();

        SchemaCoverageReport {
            spec_configured: self.spec_configured(),
            discovery_configured: true,
            undocumented_endpoints,
            unused_operations,
        }
    }

    pub fn request_shape_for(&self, method: &str, path: &str) -> Option<OpenApiRequestShape> {
        self.operation_shapes()
            .into_iter()
            .find(|operation| operation.matches_request(method, path))
            .map(|operation| operation.operation.request_shape)
    }

    fn operation_shapes(&self) -> Vec<OperationShape> {
        self.specs
            .iter()
            .flat_map(|configured| {
                configured
                    .spec
                    .operations
                    .iter()
                    .cloned()
                    .map(|operation| OperationShape {
                        candidate_templates: candidate_templates(
                            &operation.path_template,
                            configured.path_prefix.as_deref(),
                        ),
                        scope_path_prefix: configured.path_prefix.clone(),
                        operation,
                    })
            })
            .collect()
    }
}

impl fmt::Display for SchemaCoverageConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "OpenAPI schema configuration is invalid:")?;
        for problem in &self.problems {
            write!(formatter, "\n- {problem}")?;
        }
        Ok(())
    }
}

impl Error for SchemaCoverageConfigError {}

impl fmt::Display for OpenApiSpecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { source } => write!(formatter, "failed to read spec file: {source}"),
            Self::Json { source } => write!(formatter, "invalid OpenAPI JSON: {source}"),
            Self::Yaml { source } => write!(formatter, "invalid OpenAPI YAML: {source}"),
            Self::UnsupportedVersion { version } => write!(
                formatter,
                "expected an OpenAPI 3.x document, got version '{version}'"
            ),
            Self::InvalidPathTemplate { path_template } => write!(
                formatter,
                "OpenAPI path template must start with '/', got '{path_template}'"
            ),
        }
    }
}

impl Error for OpenApiSpecError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source } => Some(source),
            Self::Json { source } => Some(source),
            Self::Yaml { source } => Some(source),
            Self::UnsupportedVersion { .. } | Self::InvalidPathTemplate { .. } => None,
        }
    }
}

impl RawPathItem {
    fn operations(self) -> Vec<(&'static str, RawOperation, Vec<RawParameter>)> {
        let mut operations = Vec::new();
        let parameters = self.parameters;
        push_operation(&mut operations, "GET", self.get, &parameters);
        push_operation(&mut operations, "POST", self.post, &parameters);
        push_operation(&mut operations, "PUT", self.put, &parameters);
        push_operation(&mut operations, "PATCH", self.patch, &parameters);
        push_operation(&mut operations, "DELETE", self.delete, &parameters);
        push_operation(&mut operations, "HEAD", self.head, &parameters);
        push_operation(&mut operations, "OPTIONS", self.options, &parameters);
        push_operation(&mut operations, "TRACE", self.trace, &parameters);
        operations
    }
}

struct OperationShape {
    operation: OpenApiOperation,
    candidate_templates: Vec<String>,
    scope_path_prefix: Option<String>,
}

impl OperationShape {
    fn matches_observed(&self, observed: &ObservedEndpoint) -> bool {
        self.operation.method == observed.method
            && self
                .scope_path_prefix
                .as_deref()
                .is_none_or(|prefix| path_prefix_matches(&observed.endpoint_template, prefix))
            && self
                .candidate_templates
                .iter()
                .any(|candidate| path_shapes_match(candidate, &observed.endpoint_template))
    }

    fn matches_request(&self, method: &str, path: &str) -> bool {
        self.operation.method == method
            && self
                .scope_path_prefix
                .as_deref()
                .is_none_or(|prefix| path_prefix_matches(path, prefix))
            && self
                .candidate_templates
                .iter()
                .any(|candidate| path_template_matches_request(candidate, path))
    }
}

pub fn path_shapes_match(left: &str, right: &str) -> bool {
    let left_segments = split_path(left);
    let right_segments = split_path(right);

    left_segments.len() == right_segments.len()
        && left_segments
            .iter()
            .zip(right_segments.iter())
            .all(|(left, right)| segment_shape(left) == segment_shape(right))
}

pub fn path_template_matches_request(template: &str, path: &str) -> bool {
    let template_segments = split_path(template);
    let path_segments = split_path(path);

    template_segments.len() == path_segments.len()
        && template_segments
            .iter()
            .zip(path_segments.iter())
            .all(|(template, segment)| is_placeholder_segment(template) || *template == *segment)
}

fn push_configured_spec(
    config_name: &str,
    path: &Path,
    path_prefix: Option<String>,
    specs: &mut Vec<ConfiguredOpenApiSpec>,
    problems: &mut Vec<String>,
) {
    if !path.exists() {
        problems.push(format!(
            "{config_name} points to {}, but the file does not exist",
            path.display()
        ));
        return;
    }

    match OpenApiSpec::from_path(path) {
        Ok(spec) => specs.push(ConfiguredOpenApiSpec { spec, path_prefix }),
        Err(err) => problems.push(format!(
            "{config_name} at {} failed to parse: {err}",
            path.display()
        )),
    }
}

fn parse_document(source: &str, contents: &str) -> Result<RawOpenApiDocument, OpenApiSpecError> {
    let extension = Path::new(source)
        .extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase);

    match extension.as_deref() {
        Some("json") => {
            serde_json::from_str(contents).map_err(|source| OpenApiSpecError::Json { source })
        }
        Some("yaml" | "yml") => {
            yaml_serde::from_str(contents).map_err(|source| OpenApiSpecError::Yaml { source })
        }
        _ => serde_json::from_str(contents).or_else(|_| {
            yaml_serde::from_str(contents).map_err(|source| OpenApiSpecError::Yaml { source })
        }),
    }
}

fn push_operation(
    operations: &mut Vec<(&'static str, RawOperation, Vec<RawParameter>)>,
    method: &'static str,
    operation: Option<RawOperation>,
    path_parameters: &[RawParameter],
) {
    if let Some(operation) = operation {
        operations.push((method, operation, path_parameters.to_vec()));
    }
}

fn request_shape(
    path_parameters: &[RawParameter],
    operation: &RawOperation,
) -> OpenApiRequestShape {
    OpenApiRequestShape {
        query_params: query_params(path_parameters, &operation.parameters),
        json_body_keys: json_body_keys(operation),
    }
}

fn query_params(
    path_parameters: &[RawParameter],
    operation_parameters: &[RawParameter],
) -> Vec<OpenApiQueryParam> {
    let mut params = BTreeMap::<String, bool>::new();
    for parameter in path_parameters.iter().chain(operation_parameters.iter()) {
        if !parameter
            .location
            .as_deref()
            .is_some_and(|location| location.eq_ignore_ascii_case("query"))
        {
            continue;
        }
        let Some(name) = parameter.name.as_ref().map(|name| name.trim()) else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        params.insert(name.to_owned(), parameter.required);
    }

    params
        .into_iter()
        .map(|(name, required)| OpenApiQueryParam { name, required })
        .collect()
}

fn json_body_keys(operation: &RawOperation) -> Vec<OpenApiJsonBodyKey> {
    let Some(request_body) = operation.request_body.as_ref() else {
        return Vec::new();
    };
    let Some(media_type) = request_body
        .content
        .iter()
        .find(|(media_type, _)| is_json_media_type(media_type))
        .map(|(_, media_type)| media_type)
    else {
        return Vec::new();
    };
    let Some(schema) = media_type.schema.as_ref() else {
        return Vec::new();
    };

    let mut keys = BTreeMap::<String, bool>::new();
    for name in schema.properties.keys().map(|name| name.trim()) {
        if !name.is_empty() {
            keys.insert(name.to_owned(), false);
        }
    }
    for name in schema.required.iter().map(|name| name.trim()) {
        if !name.is_empty() {
            keys.insert(name.to_owned(), true);
        }
    }

    keys.into_iter()
        .map(|(name, required)| OpenApiJsonBodyKey { name, required })
        .collect()
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

fn non_empty_optional_string(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn compare_operations(left: &OpenApiOperation, right: &OpenApiOperation) -> std::cmp::Ordering {
    method_rank(&left.method)
        .cmp(&method_rank(&right.method))
        .then_with(|| left.path_template.cmp(&right.path_template))
        .then_with(|| left.operation_id.cmp(&right.operation_id))
}

fn method_rank(method: &str) -> usize {
    match method {
        "GET" => 0,
        "POST" => 1,
        "PUT" => 2,
        "PATCH" => 3,
        "DELETE" => 4,
        "HEAD" => 5,
        "OPTIONS" => 6,
        "TRACE" => 7,
        _ => 8,
    }
}

fn candidate_templates(path_template: &str, path_prefix: Option<&str>) -> Vec<String> {
    let mut candidates = Vec::from([path_template.to_owned()]);
    if let Some(path_prefix) = path_prefix {
        let prefixed = prefixed_path_template(path_prefix, path_template);
        if !candidates.iter().any(|candidate| candidate == &prefixed) {
            candidates.push(prefixed);
        }
    }
    candidates
}

fn prefixed_path_template(path_prefix: &str, path_template: &str) -> String {
    if path_prefix_matches(path_template, path_prefix) {
        return path_template.to_owned();
    }

    let prefix = path_prefix.trim_end_matches('/');
    let template = path_template.trim_start_matches('/');
    if prefix.is_empty() {
        format!("/{template}")
    } else if template.is_empty() {
        prefix.to_owned()
    } else {
        format!("{prefix}/{template}")
    }
}

fn path_prefix_matches(path: &str, path_prefix: &str) -> bool {
    let prefix_segments = split_path(path_prefix);
    let path_segments = split_path(path);
    prefix_segments.len() <= path_segments.len()
        && prefix_segments
            .iter()
            .zip(path_segments.iter())
            .all(|(prefix, segment)| prefix == segment)
}

fn split_path(path: &str) -> Vec<&str> {
    let path = path.split_once('?').map_or(path, |(path, _)| path);
    let path = path.strip_prefix('/').unwrap_or(path);

    if path.is_empty() {
        Vec::new()
    } else {
        path.split('/').collect()
    }
}

#[derive(Eq, PartialEq)]
enum SegmentShape<'a> {
    Placeholder,
    Literal(&'a str),
}

fn segment_shape(segment: &str) -> SegmentShape<'_> {
    if is_placeholder_segment(segment) {
        SegmentShape::Placeholder
    } else {
        SegmentShape::Literal(segment)
    }
}

fn is_placeholder_segment(segment: &str) -> bool {
    segment.len() >= 3 && segment.starts_with('{') && segment.ends_with('}')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_yaml_and_json_openapi_operations() {
        let yaml = r#"
openapi: 3.0.3
info:
  title: Test API
  version: 1.0.0
paths:
  /users/{userId}:
    get:
      operationId: getUser
      summary: Fetch a user
    post:
      summary: Replace a user
  /status:
    head:
      operationId: statusHead
"#;
        let spec = OpenApiSpec::parse_str("test.yaml", yaml).expect("YAML spec should parse");
        assert_eq!(
            spec.operations,
            vec![
                OpenApiOperation {
                    method: "GET".to_owned(),
                    path_template: "/users/{userId}".to_owned(),
                    operation_id: Some("getUser".to_owned()),
                    summary: Some("Fetch a user".to_owned()),
                    source: "test.yaml".to_owned(),
                    request_shape: OpenApiRequestShape::default(),
                },
                OpenApiOperation {
                    method: "POST".to_owned(),
                    path_template: "/users/{userId}".to_owned(),
                    operation_id: None,
                    summary: Some("Replace a user".to_owned()),
                    source: "test.yaml".to_owned(),
                    request_shape: OpenApiRequestShape::default(),
                },
                OpenApiOperation {
                    method: "HEAD".to_owned(),
                    path_template: "/status".to_owned(),
                    operation_id: Some("statusHead".to_owned()),
                    summary: None,
                    source: "test.yaml".to_owned(),
                    request_shape: OpenApiRequestShape::default(),
                },
            ]
        );

        let json = r#"{
          "openapi": "3.1.0",
          "info": { "title": "Test API", "version": "1.0.0" },
          "paths": {
            "/widgets/{widgetId}": {
              "delete": {
                "operationId": "deleteWidget"
              }
            }
          }
        }"#;
        let spec = OpenApiSpec::parse_str("test.json", json).expect("JSON spec should parse");
        assert_eq!(
            spec.operations,
            vec![OpenApiOperation {
                method: "DELETE".to_owned(),
                path_template: "/widgets/{widgetId}".to_owned(),
                operation_id: Some("deleteWidget".to_owned()),
                summary: None,
                source: "test.json".to_owned(),
                request_shape: OpenApiRequestShape::default(),
            }]
        );
    }

    #[test]
    fn matches_spec_and_discovery_templates_by_parameter_shape() {
        let spec = OpenApiSpec::from_operations(vec![
            operation("GET", "/users/{userId}", "getUser"),
            operation("POST", "/users", "createUser"),
            operation(
                "DELETE",
                "/teams/{teamId}/members/{memberId}",
                "removeMember",
            ),
            operation("PATCH", "/users/{userId}", "updateUser"),
        ]);
        let observed_endpoints = vec![
            observed("GET", "/users/{id}"),
            observed("POST", "/users"),
            observed("DELETE", "/teams/{id}/members/{id}"),
            observed("GET", "/internal/health"),
        ];

        let report = SchemaCoverage::global_for_test(spec).compare(&observed_endpoints);

        assert_eq!(
            report.undocumented_endpoints,
            vec![observed("GET", "/internal/health")]
        );
        assert_eq!(
            report.unused_operations,
            vec![operation("PATCH", "/users/{userId}", "updateUser")]
        );
    }

    #[test]
    fn parses_request_shape_from_operation_parameters_and_json_body_schema() {
        let yaml = r#"
openapi: 3.0.3
info:
  title: Shape API
  version: 1.0.0
paths:
  /users/{userId}:
    parameters:
      - in: query
        name: tenant
        required: true
    post:
      operationId: updateUser
      parameters:
        - in: query
          name: dry_run
          required: false
      requestBody:
        content:
          application/json:
            schema:
              type: object
              required: [display_name]
              properties:
                display_name:
                  type: string
                nickname:
                  type: string
"#;
        let spec = OpenApiSpec::parse_str("shape.yaml", yaml).expect("spec should parse");

        assert_eq!(spec.operations.len(), 1);
        assert_eq!(
            spec.operations[0].request_shape.query_params,
            vec![
                OpenApiQueryParam {
                    name: "dry_run".to_owned(),
                    required: false,
                },
                OpenApiQueryParam {
                    name: "tenant".to_owned(),
                    required: true,
                },
            ]
        );
        assert_eq!(
            spec.operations[0].request_shape.json_body_keys,
            vec![
                OpenApiJsonBodyKey {
                    name: "display_name".to_owned(),
                    required: true,
                },
                OpenApiJsonBodyKey {
                    name: "nickname".to_owned(),
                    required: false,
                },
            ]
        );

        let coverage = SchemaCoverage::global_for_test(spec);
        assert_eq!(
            coverage.request_shape_for("POST", "/users/123"),
            Some(OpenApiRequestShape {
                query_params: vec![
                    OpenApiQueryParam {
                        name: "dry_run".to_owned(),
                        required: false,
                    },
                    OpenApiQueryParam {
                        name: "tenant".to_owned(),
                        required: true,
                    },
                ],
                json_body_keys: vec![
                    OpenApiJsonBodyKey {
                        name: "display_name".to_owned(),
                        required: true,
                    },
                    OpenApiJsonBodyKey {
                        name: "nickname".to_owned(),
                        required: false,
                    },
                ],
            })
        );
    }

    #[test]
    fn segment_count_mismatch_does_not_match() {
        assert!(!path_shapes_match(
            "/reports/{reportId}/summary",
            "/reports/{id}/summary/details"
        ));
        assert!(!path_shapes_match(
            "/reports/{reportId}/summary/details",
            "/reports/{id}/summary"
        ));
    }

    fn operation(method: &str, path_template: &str, operation_id: &str) -> OpenApiOperation {
        OpenApiOperation {
            method: method.to_owned(),
            path_template: path_template.to_owned(),
            operation_id: Some(operation_id.to_owned()),
            summary: None,
            source: "inline".to_owned(),
            request_shape: OpenApiRequestShape::default(),
        }
    }

    fn observed(method: &str, endpoint_template: &str) -> ObservedEndpoint {
        ObservedEndpoint {
            method: method.to_owned(),
            endpoint_template: endpoint_template.to_owned(),
        }
    }
}
