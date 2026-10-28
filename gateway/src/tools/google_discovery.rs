//! Google Discovery import for managed OpenAPI Connections (issue #443).
//!
//! Google publishes its APIs as Discovery documents (a REST description
//! with `kind` `discovery#restDescription` and `discoveryVersion` `v1`),
//! which are not OpenAPI. A Discovery document is converted here into the
//! OpenAPI 3.0 document it describes, and that document is what the
//! generator sees, exactly as for Swagger 2.0:
//!
//! - Every method under `methods`, and recursively under
//!   `resources.*.methods` and `resources.*.resources`, becomes one
//!   operation at `/` plus its `path`, named by the Discovery method `id`
//!   (`gmail.users.messages.list`) as its `operationId`.
//! - `path` and `query` parameters become OpenAPI parameters; a `repeated`
//!   query parameter is an exploded `form` array. The document-level
//!   `parameters` are Google's system parameters (`key`, `access_token`,
//!   `alt`, `fields`, ...): they are never tool arguments, and each one is
//!   named in a warning.
//! - `schemas` become `components.schemas`, and every `$ref` (a bare schema
//!   name in Discovery) is rewritten to `#/components/schemas/{name}`;
//!   `request` becomes a required JSON request body and `response` a JSON
//!   `200` response.
//! - Method `scopes` become requirements on one `oauth2` scheme, one
//!   alternative per scope, because any one listed scope grants the method.
//!   Discovery documents name scopes but no endpoints, so the scheme is an
//!   `authorizationCode` flow at Google's published OAuth 2.0 endpoints; the
//!   gateway never contacts them on this path, and the generator reports
//!   the flow as user consent, which no client-credentials Connection binds.
//!
//! The conversion fails closed like the Swagger 2.0 one. Malformed
//! structure, an unknown `kind`, `discoveryVersion` or `protocol`, a `$ref`
//! naming no schema, more than [`MAX_CATALOG_ENTRIES`] methods and nesting
//! beyond [`MAX_DISCOVERY_NESTING_DEPTH`] refuse the whole document. A
//! method that uses a construct with no faithful OpenAPI 3.0 form (a
//! `{+name}` or other URI template expansion, a repeated path parameter, an
//! unknown field or parameter location, an HTTP method OpenAPI does not
//! define, a request schema that refers to itself, which the generator
//! cannot expand) is left out and named in a warning, so no tool can send a
//! request the document did not describe.
//!
//! Nothing is inlined: every input node is copied into the output once, a
//! repeated parameter adds one wrapper, and a scope adds one requirement
//! object plus, once per distinct scope, its scheme entry. The 2 MiB input
//! cap therefore bounds the output, and no duplication budget is needed.
//! Every membership check uses a set, so conversion stays near linear in
//! the input.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
};

use serde_json::{json, Map, Number, Value};

use crate::connections::model::MAX_CATALOG_ENTRIES;

use super::{
    openapi::{
        json_pointer_escape, OpenApiConversionWarning, OpenApiConversionWarningCode,
        OpenApiToolGenerationError, OpenApiToolGenerationLimit,
    },
    swagger2::{bounded_subject, json_type_name, Warnings, CONVERTED_OPENAPI_VERSION},
};

/// The only Discovery format version this module reads.
pub const DISCOVERY_VERSION: &str = "v1";
/// The `kind` of a Discovery REST description; absent is also accepted.
pub const DISCOVERY_KIND: &str = "discovery#restDescription";
/// Nesting bound for resources and schemas, above the parsers' own limit so
/// that it only ever trips on input those parsers would also refuse.
pub const MAX_DISCOVERY_NESTING_DEPTH: usize = 256;
/// The security scheme that carries the document's OAuth 2.0 scopes.
pub const OAUTH2_SCHEME_NAME: &str = "Oauth2";
/// Google's published OAuth 2.0 endpoints. Discovery documents do not name
/// them; they make the converted scheme a complete OpenAPI 3.0 flow and are
/// never contacted on this path.
const GOOGLE_AUTHORIZATION_URL: &str = "https://accounts.google.com/o/oauth2/auth";
const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const JSON_MEDIA_TYPE: &str = "application/json";
const SUCCESS_RESPONSE_DESCRIPTION: &str = "Successful response";
const SCHEMA_REFERENCE_PREFIX: &str = "#/components/schemas/";

const HTTP_METHODS: [&str; 7] = ["get", "put", "post", "delete", "options", "head", "patch"];
/// Top-level fields of a REST description. Anything else is reported and
/// ignored; none of these changes how a request is sent except as converted
/// below.
const DOCUMENT_FIELDS: [&str; 33] = [
    "auth",
    "basePath",
    "baseUrl",
    "batchPath",
    "canonicalName",
    "description",
    "discoveryVersion",
    "documentationLink",
    "endpoints",
    "etag",
    "exponentialBackoffDefault",
    "features",
    "fullyEncodeReservedExpansion",
    "icons",
    "id",
    "kind",
    "labels",
    "methods",
    "mtlsRootUrl",
    "name",
    "ownerDomain",
    "ownerName",
    "packagePath",
    "parameters",
    "protocol",
    "resources",
    "revision",
    "rootUrl",
    "schemas",
    "servicePath",
    "title",
    "version",
    "version_module",
];
const METHOD_FIELDS: [&str; 18] = [
    "apiVersion",
    "deprecated",
    "description",
    "etagRequired",
    "flatPath",
    "httpMethod",
    "id",
    "mediaUpload",
    "parameterOrder",
    "parameters",
    "path",
    "request",
    "response",
    "scopes",
    "supportsMediaDownload",
    "supportsMediaUpload",
    "supportsSubscription",
    "useMediaDownloadService",
];
const PARAMETER_FIELDS: [&str; 14] = [
    "default",
    "deprecated",
    "description",
    "enum",
    "enumDeprecated",
    "enumDescriptions",
    "format",
    "location",
    "maximum",
    "minimum",
    "pattern",
    "repeated",
    "required",
    "type",
];
/// Schema keywords that are documentation only, or (`id`) the schema's own
/// name; they are dropped without a warning.
const IGNORED_SCHEMA_KEYWORDS: [&str; 4] =
    ["annotations", "enumDeprecated", "enumDescriptions", "id"];

/// A Google Discovery document rewritten as OpenAPI 3.0, with what the
/// operator should review about the rewrite.
#[derive(Debug, Clone, PartialEq)]
pub struct DiscoveryConversion {
    pub document: Value,
    pub warnings: Vec<OpenApiConversionWarning>,
}

/// Why a Google Discovery document was rejected as a whole.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryConversionError {
    /// `discoveryVersion` is missing or is not the string `"v1"`.
    UnsupportedVersion {
        version: String,
    },
    /// `kind` is present and is not `discovery#restDescription`, such as a
    /// Discovery directory list.
    UnsupportedKind {
        kind: String,
    },
    /// `protocol` is present and is not `rest`.
    UnsupportedProtocol {
        protocol: String,
    },
    /// A structural field has the wrong JSON type.
    InvalidField {
        field: &'static str,
    },
    NestingDepth {
        maximum: usize,
    },
}

impl fmt::Display for DiscoveryConversionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion { version } => write!(
                formatter,
                "expected a Google Discovery document whose 'discoveryVersion' is the string \"{DISCOVERY_VERSION}\", got {version}"
            ),
            Self::UnsupportedKind { kind } => write!(
                formatter,
                "expected a Google Discovery REST description (kind '{DISCOVERY_KIND}'), got {kind}"
            ),
            Self::UnsupportedProtocol { protocol } => write!(
                formatter,
                "Google Discovery protocol {protocol} is not supported; only 'rest' is"
            ),
            Self::InvalidField { field } => {
                write!(formatter, "Google Discovery field '{field}' has an invalid shape")
            }
            Self::NestingDepth { maximum } => write!(
                formatter,
                "Google Discovery document nesting exceeds the maximum depth of {maximum}"
            ),
        }
    }
}

impl Error for DiscoveryConversionError {}

/// Whether a parsed document is a Google Discovery document: it has neither
/// an `openapi` nor a `swagger` field, and it has a `discoveryVersion` or a
/// `kind` in the `discovery#` namespace. Which version or kind it declares
/// is checked by [`convert`], so a wrong one is refused rather than
/// reported as some other format's error.
pub fn is_discovery_document(document: &Value) -> bool {
    let Some(root) = document.as_object() else {
        return false;
    };
    if root.contains_key("openapi") || root.contains_key("swagger") {
        return false;
    }
    root.contains_key("discoveryVersion")
        || root
            .get("kind")
            .and_then(Value::as_str)
            .is_some_and(|kind| kind.starts_with("discovery#"))
}

/// Convert a Google Discovery document to OpenAPI 3.0. The caller has
/// already applied the input size cap and parsed the document.
pub fn convert(document: &Value) -> Result<DiscoveryConversion, OpenApiToolGenerationError> {
    let Some(root) = document.as_object() else {
        return Err(invalid_field("document"));
    };
    match root.get("kind") {
        None => {}
        Some(Value::String(kind)) if kind == DISCOVERY_KIND => {}
        other => {
            return Err(conversion_error(
                DiscoveryConversionError::UnsupportedKind {
                    kind: value_label(other),
                },
            ))
        }
    }
    match root.get("discoveryVersion") {
        Some(Value::String(version)) if version == DISCOVERY_VERSION => {}
        other => {
            return Err(conversion_error(
                DiscoveryConversionError::UnsupportedVersion {
                    version: value_label(other),
                },
            ))
        }
    }
    match root.get("protocol") {
        None => {}
        Some(Value::String(protocol)) if protocol == "rest" => {}
        other => {
            return Err(conversion_error(
                DiscoveryConversionError::UnsupportedProtocol {
                    protocol: value_label(other),
                },
            ))
        }
    }
    let schemas = match root.get("schemas") {
        None => None,
        Some(Value::Object(schemas)) => Some(schemas),
        Some(_) => return Err(invalid_field("schemas")),
    };
    let mut converter = Converter {
        root,
        schemas,
        service_path: service_path(root)?,
        warnings: Warnings::default(),
        reported_keywords: BTreeSet::new(),
        reaches_cycle: BTreeMap::new(),
    };
    let document = converter.convert_document()?;
    Ok(DiscoveryConversion {
        document,
        warnings: converter.warnings.finish(),
    })
}

fn conversion_error(source: DiscoveryConversionError) -> OpenApiToolGenerationError {
    OpenApiToolGenerationError::GoogleDiscovery { source }
}

fn invalid_field(field: &'static str) -> OpenApiToolGenerationError {
    conversion_error(DiscoveryConversionError::InvalidField { field })
}

fn value_label(value: Option<&Value>) -> String {
    match value {
        None => "nothing".to_owned(),
        Some(Value::String(value)) => format!("'{}'", bounded_subject(value)),
        Some(other) => format!("a JSON {}", json_type_name(other)),
    }
}

/// `servicePath` without its surrounding slashes; empty when absent.
fn service_path(root: &Map<String, Value>) -> Result<String, OpenApiToolGenerationError> {
    match root.get("servicePath") {
        None => Ok(String::new()),
        Some(Value::String(path)) => Ok(path.trim().trim_matches('/').to_owned()),
        Some(_) => Err(invalid_field("servicePath")),
    }
}

/// How converting one method can fail: either the whole document is
/// rejected, or only the method is left out.
enum Failure {
    Document(OpenApiToolGenerationError),
    Method {
        code: OpenApiConversionWarningCode,
        subject: Option<String>,
    },
}

impl From<OpenApiToolGenerationError> for Failure {
    fn from(error: OpenApiToolGenerationError) -> Self {
        Self::Document(error)
    }
}

fn omit(code: OpenApiConversionWarningCode, subject: Option<&str>) -> Failure {
    Failure::Method {
        code,
        subject: subject.map(str::to_owned),
    }
}

/// What identifies a method in its warnings, read before anything about it
/// is validated so that a method left out can still be named.
struct MethodContext<'d> {
    id: Option<&'d str>,
    http_method: Option<&'static str>,
    path: Option<String>,
}

struct ConvertedMethod {
    operation: Value,
    media_upload: bool,
    secured: bool,
}

struct Converter<'d> {
    root: &'d Map<String, Value>,
    schemas: Option<&'d Map<String, Value>>,
    service_path: String,
    warnings: Warnings,
    /// Schema keywords already reported, so each is reported once.
    reported_keywords: BTreeSet<String>,
    /// Whether a named schema reaches a reference cycle; see
    /// [`Converter::schema_reaches_cycle`].
    reaches_cycle: BTreeMap<&'d str, bool>,
}

impl<'d> Converter<'d> {
    fn convert_document(&mut self) -> Result<Value, OpenApiToolGenerationError> {
        for field in self.root.keys() {
            if !DOCUMENT_FIELDS.contains(&field.as_str()) {
                self.warnings.document(
                    OpenApiConversionWarningCode::UnsupportedDocumentField,
                    Some(field),
                );
            }
        }
        if !self.service_path.is_empty() {
            let base_path = format!("/{}", self.service_path);
            self.warnings.document(
                OpenApiConversionWarningCode::BasePathNotInPaths,
                Some(&base_path),
            );
        }
        match self.root.get("parameters") {
            None => {}
            Some(Value::Object(parameters)) => {
                for name in parameters.keys() {
                    self.warnings.document(
                        OpenApiConversionWarningCode::GlobalParameterNotMapped,
                        Some(name),
                    );
                }
            }
            Some(_) => return Err(invalid_field("parameters")),
        }
        let declared_scopes = self.declared_scopes()?;

        let mut converted = Map::new();
        converted.insert(
            "openapi".to_owned(),
            Value::String(CONVERTED_OPENAPI_VERSION.to_owned()),
        );
        converted.insert("info".to_owned(), self.info());
        if let Some(servers) = self.servers() {
            converted.insert("servers".to_owned(), servers);
        }

        let mut components = Map::new();
        if let Some(schemas) = self.schemas {
            let mut converted_schemas = Map::new();
            for (name, schema) in schemas {
                converted_schemas.insert(name.clone(), self.convert_schema(schema, 0)?);
            }
            components.insert("schemas".to_owned(), Value::Object(converted_schemas));
        }

        let methods = self.collect_methods()?;
        let mut paths = BTreeMap::<String, Map<String, Value>>::new();
        let mut used_scopes = BTreeSet::new();
        let mut any_secured = false;
        for method in methods {
            let Some(method) = method.as_object() else {
                return Err(invalid_field("method"));
            };
            let context = self.method_context(method);
            let converted_method = match self.convert_method(method, &context) {
                Ok(converted_method) => converted_method,
                Err(Failure::Document(error)) => return Err(error),
                Err(Failure::Method { code, subject }) => {
                    self.warnings.push(OpenApiConversionWarning {
                        code,
                        method: context.http_method.map(str::to_ascii_uppercase),
                        path_template: context.path.as_deref().map(bounded_subject),
                        subject: subject.as_deref().map(bounded_subject),
                    });
                    continue;
                }
            };
            // `convert_method` succeeds only with both of these present.
            let (Some(http_method), Some(path)) = (context.http_method, context.path) else {
                continue;
            };
            let path_item = paths.entry(path.clone()).or_default();
            if path_item.contains_key(http_method) {
                self.warnings.operation(
                    OpenApiConversionWarningCode::DuplicateOperation,
                    http_method,
                    &path,
                    context.id,
                );
                continue;
            }
            if converted_method.media_upload {
                self.warnings.operation(
                    OpenApiConversionWarningCode::MediaUploadNotMapped,
                    http_method,
                    &path,
                    None,
                );
            }
            if converted_method.secured {
                any_secured = true;
                if let Some(scopes) = method.get("scopes").and_then(Value::as_array) {
                    used_scopes.extend(scopes.iter().filter_map(Value::as_str));
                }
            }
            path_item.insert(http_method.to_owned(), converted_method.operation);
        }

        if declared_scopes.is_some() || any_secured {
            let mut scopes = declared_scopes.unwrap_or_default();
            for scope in used_scopes {
                scopes
                    .entry(scope.to_owned())
                    .or_insert_with(|| Value::String(String::new()));
            }
            components.insert(
                "securitySchemes".to_owned(),
                json!({
                    OAUTH2_SCHEME_NAME: {
                        "type": "oauth2",
                        "flows": {
                            "authorizationCode": {
                                "authorizationUrl": GOOGLE_AUTHORIZATION_URL,
                                "tokenUrl": GOOGLE_TOKEN_URL,
                                "scopes": scopes,
                            }
                        }
                    }
                }),
            );
        }
        if !components.is_empty() {
            converted.insert("components".to_owned(), Value::Object(components));
        }
        converted.insert(
            "paths".to_owned(),
            Value::Object(
                paths
                    .into_iter()
                    .filter(|(_, item)| !item.is_empty())
                    .map(|(path, item)| (path, Value::Object(item)))
                    .collect(),
            ),
        );
        Ok(Value::Object(converted))
    }

    /// `auth.oauth2.scopes` as an OpenAPI scopes map (scope to description),
    /// or `None` when the document declares no OAuth 2.0 block.
    fn declared_scopes(&self) -> Result<Option<Map<String, Value>>, OpenApiToolGenerationError> {
        let auth = match self.root.get("auth") {
            None => return Ok(None),
            Some(Value::Object(auth)) => auth,
            Some(_) => return Err(invalid_field("auth")),
        };
        let oauth2 = match auth.get("oauth2") {
            None => return Ok(None),
            Some(Value::Object(oauth2)) => oauth2,
            Some(_) => return Err(invalid_field("auth.oauth2")),
        };
        let scopes = match oauth2.get("scopes") {
            None => return Ok(Some(Map::new())),
            Some(Value::Object(scopes)) => scopes,
            Some(_) => return Err(invalid_field("auth.oauth2.scopes")),
        };
        Ok(Some(
            scopes
                .iter()
                .map(|(scope, declaration)| {
                    let description = declaration
                        .get("description")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    (scope.clone(), Value::String(description.to_owned()))
                })
                .collect(),
        ))
    }

    fn info(&self) -> Value {
        let text = |field: &str| self.root.get(field).and_then(Value::as_str);
        let mut info = Map::new();
        info.insert(
            "title".to_owned(),
            Value::String(
                text("title")
                    .or_else(|| text("name"))
                    .unwrap_or("Google Discovery document")
                    .to_owned(),
            ),
        );
        info.insert(
            "version".to_owned(),
            Value::String(text("version").unwrap_or_default().to_owned()),
        );
        if let Some(description) = text("description") {
            info.insert(
                "description".to_owned(),
                Value::String(description.to_owned()),
            );
        }
        Value::Object(info)
    }

    /// `servers` is informational: generated tools call the Connection's own
    /// endpoint, so a `servicePath` has to be repeated in the Connection
    /// base path, which the `base_path_not_in_paths` warning says.
    fn servers(&self) -> Option<Value> {
        let root_url = self
            .root
            .get("rootUrl")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|url| !url.is_empty())?;
        let root_url = root_url.trim_end_matches('/');
        let url = if self.service_path.is_empty() {
            root_url.to_owned()
        } else {
            format!("{root_url}/{}", self.service_path)
        };
        Some(json!([{ "url": url }]))
    }

    /// Every method in the document, top-level methods first and then each
    /// resource's in name order, depth first.
    fn collect_methods(&self) -> Result<Vec<&'d Value>, OpenApiToolGenerationError> {
        let mut methods = Vec::new();
        collect_resource_methods(self.root, 0, &mut methods)?;
        Ok(methods)
    }

    fn method_context(&self, method: &'d Map<String, Value>) -> MethodContext<'d> {
        MethodContext {
            id: method.get("id").and_then(Value::as_str),
            http_method: method
                .get("httpMethod")
                .and_then(Value::as_str)
                .and_then(|http_method| {
                    HTTP_METHODS
                        .into_iter()
                        .find(|known| http_method.eq_ignore_ascii_case(known))
                }),
            path: method
                .get("path")
                .and_then(Value::as_str)
                .and_then(|path| self.operation_path(path)),
        }
    }

    /// The OpenAPI path of a Discovery method path, which is relative to
    /// `servicePath`. A path starting with `/` is relative to `rootUrl`
    /// instead; that is only expressible when `servicePath` is empty.
    fn operation_path(&self, path: &str) -> Option<String> {
        if path.is_empty() {
            return None;
        }
        if path.starts_with('/') {
            return self.service_path.is_empty().then(|| path.to_owned());
        }
        Some(format!("/{path}"))
    }

    fn convert_method(
        &mut self,
        method: &'d Map<String, Value>,
        context: &MethodContext<'d>,
    ) -> Result<ConvertedMethod, Failure> {
        if let Some(field) = method
            .keys()
            .find(|field| !METHOD_FIELDS.contains(&field.as_str()))
        {
            return Err(omit(
                OpenApiConversionWarningCode::UnsupportedOperationField,
                Some(field),
            ));
        }
        if method.get("id").is_some_and(|id| !id.is_string()) {
            return Err(omit(
                OpenApiConversionWarningCode::InvalidMethodDefinition,
                None,
            ));
        }
        match method.get("httpMethod") {
            Some(Value::String(http_method)) if context.http_method.is_none() => {
                return Err(omit(
                    OpenApiConversionWarningCode::UnsupportedHttpMethod,
                    Some(http_method),
                ));
            }
            Some(Value::String(_)) => {}
            _ => {
                return Err(omit(
                    OpenApiConversionWarningCode::InvalidMethodDefinition,
                    context.id,
                ))
            }
        }
        let Some(path) = context.path.as_deref() else {
            return Err(omit(
                OpenApiConversionWarningCode::InvalidMethodDefinition,
                context.id,
            ));
        };
        let placeholders = match path_placeholders(path) {
            Ok(placeholders) => placeholders,
            Err(PathProblem::Malformed) => {
                return Err(omit(
                    OpenApiConversionWarningCode::InvalidMethodDefinition,
                    context.id,
                ))
            }
            Err(PathProblem::Expansion(placeholder)) => {
                return Err(omit(
                    OpenApiConversionWarningCode::UnsupportedPathExpansion,
                    Some(placeholder),
                ))
            }
        };

        let mut converted = Map::new();
        if let Some(id) = context.id {
            converted.insert("operationId".to_owned(), Value::String(id.to_owned()));
        }
        if let Some(description) = method.get("description").filter(|value| value.is_string()) {
            converted.insert("description".to_owned(), description.clone());
        }
        if let Some(deprecated) = method.get("deprecated").filter(|value| value.is_boolean()) {
            converted.insert("deprecated".to_owned(), deprecated.clone());
        }
        let parameters = self.convert_parameters(method.get("parameters"), &placeholders)?;
        if !parameters.is_empty() {
            converted.insert("parameters".to_owned(), Value::Array(parameters));
        }
        if let Some(request) = method.get("request") {
            let schema = self.method_schema(request, "request")?;
            if let Some(schema_name) = self.recursive_root(request) {
                return Err(omit(
                    OpenApiConversionWarningCode::RecursiveRequestSchema,
                    Some(schema_name),
                ));
            }
            converted.insert(
                "requestBody".to_owned(),
                json!({
                    "required": true,
                    "content": { JSON_MEDIA_TYPE: { "schema": schema } }
                }),
            );
        }
        let mut success = Map::new();
        success.insert(
            "description".to_owned(),
            Value::String(SUCCESS_RESPONSE_DESCRIPTION.to_owned()),
        );
        if let Some(response) = method.get("response") {
            let schema = self.method_schema(response, "response")?;
            success.insert(
                "content".to_owned(),
                json!({ JSON_MEDIA_TYPE: { "schema": schema } }),
            );
        }
        converted.insert("responses".to_owned(), json!({ "200": success }));

        let security = match method.get("scopes") {
            None => Vec::new(),
            Some(Value::Array(scopes)) => {
                let mut seen = BTreeSet::new();
                let mut alternatives = Vec::with_capacity(scopes.len());
                for scope in scopes {
                    // A scope that is not a string is kept, and the
                    // generator classifies the requirement as invalid.
                    if scope.as_str().is_some_and(|scope| !seen.insert(scope)) {
                        continue;
                    }
                    alternatives.push(json!({ OAUTH2_SCHEME_NAME: [scope] }));
                }
                alternatives
            }
            Some(_) => {
                return Err(omit(
                    OpenApiConversionWarningCode::InvalidMethodDefinition,
                    context.id,
                ))
            }
        };
        let secured = !security.is_empty();
        if secured {
            converted.insert("security".to_owned(), Value::Array(security));
        }
        let media_upload = method.get("supportsMediaUpload").and_then(Value::as_bool) == Some(true)
            || method.contains_key("mediaUpload");
        Ok(ConvertedMethod {
            operation: Value::Object(converted),
            media_upload,
            secured,
        })
    }

    fn convert_parameters(
        &mut self,
        parameters: Option<&'d Value>,
        placeholders: &BTreeSet<&str>,
    ) -> Result<Vec<Value>, Failure> {
        let parameters = match parameters {
            None => return Ok(Vec::new()),
            Some(Value::Object(parameters)) => parameters,
            Some(_) => return Err(omit(OpenApiConversionWarningCode::InvalidParameter, None)),
        };
        let mut converted = Vec::with_capacity(parameters.len());
        for (name, parameter) in parameters {
            converted.push(convert_parameter(name, parameter, placeholders)?);
        }
        Ok(converted)
    }

    /// The schema of a method's `request` or `response`: a reference to a
    /// named schema, as Discovery always writes it, or an inline schema.
    fn method_schema(&mut self, value: &Value, field: &'static str) -> Result<Value, Failure> {
        if !value.is_object() {
            return Err(invalid_field(field).into());
        }
        let mut schema = value.clone();
        if let Some(object) = schema.as_object_mut() {
            // `parameterName` names the body argument in Google's client
            // libraries; it is not a schema keyword.
            object.remove("parameterName");
        }
        Ok(self.convert_schema(&schema, 0)?)
    }

    /// The first schema named in a request that reaches a reference cycle,
    /// if any. The generator expands request schemas fully and refuses the
    /// whole document on a cycle, so such a method is left out instead.
    fn recursive_root(&mut self, request: &'d Value) -> Option<&'d str> {
        schema_references(request)
            .into_iter()
            .find(|name| self.schema_reaches_cycle(name))
    }

    /// Whether the named schema reaches a reference cycle. A depth-first
    /// walk over schema references: a reference to a schema still on the
    /// walk closes a cycle, and a finished schema's answer is kept, so every
    /// schema is walked at most once per document.
    fn schema_reaches_cycle(&mut self, start: &'d str) -> bool {
        if let Some(known) = self.reaches_cycle.get(start) {
            return *known;
        }
        let Some(schemas) = self.schemas else {
            return false;
        };
        let Some(schema) = schemas.get(start) else {
            return false;
        };
        let mut on_walk = BTreeSet::from([start]);
        let mut stack = vec![(start, schema_references(schema), false)];
        while let Some((_, pending, reaches)) = stack.last_mut() {
            if let Some(next) = pending.pop() {
                if on_walk.contains(next) {
                    *reaches = true;
                } else if let Some(known) = self.reaches_cycle.get(next) {
                    *reaches |= *known;
                } else if let Some(schema) = schemas.get(next) {
                    on_walk.insert(next);
                    stack.push((next, schema_references(schema), false));
                }
                continue;
            }
            let Some((name, _, reaches)) = stack.pop() else {
                break;
            };
            on_walk.remove(name);
            self.reaches_cycle.insert(name, reaches);
            if let Some((_, _, parent_reaches)) = stack.last_mut() {
                *parent_reaches |= reaches;
            }
        }
        self.reaches_cycle.get(start).copied().unwrap_or(false)
    }

    /// Convert a Discovery schema. Discovery schemas are a subset of JSON
    /// Schema draft 3: a property's `required: true` moves into its parent's
    /// `required` list, `minimum`, `maximum` and `default` are strings that
    /// become typed values, and `type: any` is a schema without a type.
    /// Documentation-only keywords are dropped; any other keyword has no
    /// OpenAPI 3.0 form and is dropped with a warning, once per keyword.
    fn convert_schema(
        &mut self,
        schema: &Value,
        depth: usize,
    ) -> Result<Value, OpenApiToolGenerationError> {
        if depth > MAX_DISCOVERY_NESTING_DEPTH {
            return Err(conversion_error(DiscoveryConversionError::NestingDepth {
                maximum: MAX_DISCOVERY_NESTING_DEPTH,
            }));
        }
        let Some(object) = schema.as_object() else {
            return Err(invalid_field("schema"));
        };
        if let Some(reference) = object.get("$ref") {
            // OpenAPI 3.0 ignores a reference's siblings, so only the
            // reference is kept.
            return Ok(json!({ "$ref": self.schema_reference(reference)? }));
        }
        let schema_type = object.get("type").and_then(Value::as_str);
        let mut converted = Map::new();
        let mut required = Vec::new();
        let mut required_names = BTreeSet::new();
        for (keyword, value) in object {
            let value = match keyword.as_str() {
                "type" if value.as_str() == Some("any") => continue,
                "type" | "format" | "pattern" | "description" | "readOnly" | "deprecated"
                | "enum" => value.clone(),
                "default" => match typed_default(value, schema_type) {
                    Some(value) => value,
                    None => continue,
                },
                "minimum" | "maximum" => {
                    numeric(value).ok_or_else(|| invalid_field("minimum or maximum"))?
                }
                "properties" => {
                    let Some(properties) = value.as_object() else {
                        return Err(invalid_field("properties"));
                    };
                    let mut converted_properties = Map::new();
                    for (name, property) in properties {
                        if property.get("required").and_then(Value::as_bool) == Some(true)
                            && required_names.insert(name.clone())
                        {
                            required.push(Value::String(name.clone()));
                        }
                        converted_properties
                            .insert(name.clone(), self.convert_schema(property, depth + 2)?);
                    }
                    Value::Object(converted_properties)
                }
                "additionalProperties" if value.is_boolean() => value.clone(),
                "items" | "additionalProperties" => self.convert_schema(value, depth + 1)?,
                // A draft 3 property flag, moved to the parent above; a
                // draft 4 list is already OpenAPI's form.
                "required" if value.is_boolean() => continue,
                "required" if value.is_array() => {
                    for name in value.as_array().into_iter().flatten() {
                        let Some(name) = name.as_str() else {
                            return Err(invalid_field("required"));
                        };
                        if required_names.insert(name.to_owned()) {
                            required.push(Value::String(name.to_owned()));
                        }
                    }
                    continue;
                }
                keyword if IGNORED_SCHEMA_KEYWORDS.contains(&keyword) => continue,
                keyword => {
                    if self.reported_keywords.insert(keyword.to_owned()) {
                        self.warnings.document(
                            OpenApiConversionWarningCode::UnsupportedSchemaKeyword,
                            Some(keyword),
                        );
                    }
                    continue;
                }
            };
            converted.insert(keyword.clone(), value);
        }
        if !required.is_empty() {
            converted.insert("required".to_owned(), Value::Array(required));
        }
        Ok(Value::Object(converted))
    }

    /// A Discovery `$ref` (a schema name) as an OpenAPI reference. The name
    /// must be a schema of this document; anything else, a remote document
    /// included, refuses the document.
    fn schema_reference(&self, reference: &Value) -> Result<String, OpenApiToolGenerationError> {
        let Some(name) = reference.as_str() else {
            return Err(invalid_field("$ref"));
        };
        if !self
            .schemas
            .is_some_and(|schemas| schemas.contains_key(name))
        {
            return Err(OpenApiToolGenerationError::Reference {
                reference: bounded_subject(name),
                message: "target does not exist".to_owned(),
            });
        }
        Ok(format!(
            "{SCHEMA_REFERENCE_PREFIX}{}",
            json_pointer_escape(name)
        ))
    }
}

fn collect_resource_methods<'d>(
    container: &'d Map<String, Value>,
    depth: usize,
    methods: &mut Vec<&'d Value>,
) -> Result<(), OpenApiToolGenerationError> {
    if depth > MAX_DISCOVERY_NESTING_DEPTH {
        return Err(conversion_error(DiscoveryConversionError::NestingDepth {
            maximum: MAX_DISCOVERY_NESTING_DEPTH,
        }));
    }
    match container.get("methods") {
        None => {}
        Some(Value::Object(declared)) => {
            if methods.len().saturating_add(declared.len()) > MAX_CATALOG_ENTRIES {
                return Err(OpenApiToolGenerationError::GenerationLimit {
                    limit: OpenApiToolGenerationLimit::OperationCount,
                    maximum: MAX_CATALOG_ENTRIES,
                });
            }
            methods.extend(declared.values());
        }
        Some(_) => return Err(invalid_field("methods")),
    }
    match container.get("resources") {
        None => {}
        Some(Value::Object(resources)) => {
            for resource in resources.values() {
                let Some(resource) = resource.as_object() else {
                    return Err(invalid_field("resources"));
                };
                collect_resource_methods(resource, depth + 1, methods)?;
            }
        }
        Some(_) => return Err(invalid_field("resources")),
    }
    Ok(())
}

/// One Discovery parameter as an OpenAPI 3.0 Parameter Object.
fn convert_parameter(
    name: &str,
    parameter: &Value,
    placeholders: &BTreeSet<&str>,
) -> Result<Value, Failure> {
    let invalid = || omit(OpenApiConversionWarningCode::InvalidParameter, Some(name));
    let Some(object) = parameter.as_object() else {
        return Err(invalid());
    };
    if name.trim().is_empty() {
        return Err(omit(OpenApiConversionWarningCode::InvalidParameter, None));
    }
    if let Some(field) = object
        .keys()
        .find(|field| !PARAMETER_FIELDS.contains(&field.as_str()))
    {
        return Err(omit(
            OpenApiConversionWarningCode::UnsupportedParameterField,
            Some(field),
        ));
    }
    let Some(location) = object.get("location").and_then(Value::as_str) else {
        return Err(invalid());
    };
    let location = ["path", "query"]
        .into_iter()
        .find(|known| location.eq_ignore_ascii_case(known))
        .ok_or_else(|| {
            omit(
                OpenApiConversionWarningCode::UnsupportedParameterLocation,
                Some(location),
            )
        })?;
    let repeated = match object.get("repeated") {
        None => false,
        Some(Value::Bool(repeated)) => *repeated,
        Some(_) => return Err(invalid()),
    };
    if location == "path" {
        if repeated {
            return Err(omit(
                OpenApiConversionWarningCode::RepeatedPathParameter,
                Some(name),
            ));
        }
        // A path parameter the path does not use could never be sent.
        if !placeholders.contains(name) {
            return Err(invalid());
        }
    }

    let schema_type = match object.get("type") {
        None => None,
        Some(Value::String(schema_type)) => Some(schema_type.as_str()),
        Some(_) => return Err(invalid()),
    };
    let mut schema = Map::new();
    if let Some(schema_type) = schema_type.filter(|schema_type| *schema_type != "any") {
        schema.insert("type".to_owned(), Value::String(schema_type.to_owned()));
    }
    for field in ["format", "pattern"] {
        match object.get(field) {
            None => {}
            Some(Value::String(value)) => {
                schema.insert(field.to_owned(), Value::String(value.clone()));
            }
            Some(_) => return Err(invalid()),
        }
    }
    match object.get("enum") {
        None => {}
        Some(Value::Array(values)) => {
            schema.insert("enum".to_owned(), Value::Array(values.clone()));
        }
        Some(_) => return Err(invalid()),
    }
    for field in ["minimum", "maximum"] {
        if let Some(value) = object.get(field) {
            schema.insert(field.to_owned(), numeric(value).ok_or_else(invalid)?);
        }
    }
    if let Some(default) = object
        .get("default")
        .and_then(|value| typed_default(value, schema_type))
    {
        schema.insert("default".to_owned(), default);
    }

    let mut converted = Map::new();
    converted.insert("name".to_owned(), Value::String(name.to_owned()));
    converted.insert("in".to_owned(), Value::String(location.to_owned()));
    if let Some(description) = object.get("description").filter(|value| value.is_string()) {
        converted.insert("description".to_owned(), description.clone());
    }
    let required = match object.get("required") {
        None => false,
        Some(Value::Bool(required)) => *required,
        Some(_) => return Err(invalid()),
    };
    // Every path parameter is required, whatever the document says.
    if required || location == "path" {
        converted.insert("required".to_owned(), Value::Bool(true));
    }
    if let Some(deprecated) = object.get("deprecated").filter(|value| value.is_boolean()) {
        converted.insert("deprecated".to_owned(), deprecated.clone());
    }
    if repeated {
        // Google reads a repeated query parameter as the key repeated once
        // per value: OpenAPI's exploded form style.
        converted.insert(
            "schema".to_owned(),
            json!({ "type": "array", "items": schema }),
        );
        converted.insert("style".to_owned(), Value::String("form".to_owned()));
        converted.insert("explode".to_owned(), Value::Bool(true));
    } else {
        converted.insert("schema".to_owned(), Value::Object(schema));
    }
    Ok(Value::Object(converted))
}

enum PathProblem<'p> {
    Malformed,
    Expansion(&'p str),
}

/// The `{name}` placeholders of a path. An unmatched or nested brace is
/// malformed; a placeholder that is not a plain variable name is an RFC 6570
/// expansion (`{+name}`, `{/name}`, `{name*}`, ...) with no OpenAPI form.
fn path_placeholders(path: &str) -> Result<BTreeSet<&str>, PathProblem<'_>> {
    let mut placeholders = BTreeSet::new();
    let mut rest = path;
    loop {
        let open = rest.find('{');
        let close = rest.find('}');
        let open = match (open, close) {
            (None, None) => return Ok(placeholders),
            (Some(open), Some(close)) if open < close => open,
            _ => return Err(PathProblem::Malformed),
        };
        let after_open = &rest[open + 1..];
        let Some(close) = after_open.find('}') else {
            return Err(PathProblem::Malformed);
        };
        let placeholder = &after_open[..close];
        if placeholder.contains('{') {
            return Err(PathProblem::Malformed);
        }
        if !is_plain_variable(placeholder) {
            return Err(PathProblem::Expansion(placeholder));
        }
        placeholders.insert(placeholder);
        rest = &after_open[close + 1..];
    }
}

fn is_plain_variable(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|first| first.is_ascii_alphanumeric() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

/// Every `$ref` string anywhere in a schema.
fn schema_references(schema: &Value) -> Vec<&str> {
    let mut references = Vec::new();
    let mut remaining = vec![schema];
    while let Some(value) = remaining.pop() {
        match value {
            Value::Object(object) => {
                if let Some(Value::String(reference)) = object.get("$ref") {
                    references.push(reference.as_str());
                }
                remaining.extend(object.values());
            }
            Value::Array(values) => remaining.extend(values),
            _ => {}
        }
    }
    references
}

/// A Discovery `minimum` or `maximum`, which is a decimal string.
fn numeric(value: &Value) -> Option<Value> {
    match value {
        Value::Number(_) => Some(value.clone()),
        Value::String(text) => text.trim().parse::<Number>().ok().map(Value::Number),
        _ => None,
    }
}

/// A Discovery `default`, which is always a string, as a value of the
/// schema's type. A default that does not parse is documentation the
/// gateway never applies, so it is dropped.
fn typed_default(value: &Value, schema_type: Option<&str>) -> Option<Value> {
    let Value::String(text) = value else {
        return Some(value.clone());
    };
    match schema_type {
        Some("integer" | "number") => text.trim().parse::<Number>().ok().map(Value::Number),
        Some("boolean") => match text.trim() {
            "true" => Some(Value::Bool(true)),
            "false" => Some(Value::Bool(false)),
            _ => None,
        },
        _ => Some(value.clone()),
    }
}

#[cfg(test)]
#[path = "google_discovery_tests.rs"]
mod tests;
