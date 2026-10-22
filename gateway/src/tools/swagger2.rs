//! Swagger 2.0 import for managed OpenAPI Connections (issue #443).
//!
//! The tool generator reads OpenAPI 3.x only. A Swagger 2.0 document is
//! converted here into the OpenAPI 3.0 document it describes, and that
//! document is what the generator sees, so a converted document generates
//! exactly what its hand-converted OpenAPI 3.0 equivalent would.
//!
//! The conversion is deliberately narrow and fails closed:
//!
//! - Document-shape problems (a non-object `paths`, a reference this module
//!   cannot rewrite, a missing reference target, the duplication budget)
//!   reject the whole document, as the 3.x path rejects malformed documents.
//! - An operation that uses a construct with no faithful OpenAPI 3.0 form
//!   (two body parameters, a body beside form fields, an unknown parameter
//!   location or field, an unsupported `collectionFormat`, a `file` outside
//!   a form) is left out of the converted document, and a warning names it.
//!   Nothing is generated for it, so no tool can send a request the document
//!   did not describe.
//! - Lossless or documentation-only differences are converted silently;
//!   assumptions an operator should know about (`basePath`, defaulted media
//!   types, security definitions that cannot be converted, request bodies the
//!   generator cannot map) become warnings.
//!
//! Work is bounded by the 2 MiB input cap plus a separate budget for the
//! nodes that conversion copies more than once: inlined `#/parameters/` and
//! `#/responses/` references, path-level body fields copied into each
//! operation, and a schema repeated under several media types.

use std::{collections::BTreeSet, error::Error, fmt};

use serde_json::{json, Map, Value};

use crate::connections::model::MAX_CATALOG_ENTRIES;

use super::openapi::{
    is_json_media_type, reject_non_local_references, OpenApiConversionWarning,
    OpenApiConversionWarningCode, OpenApiToolGenerationError, OpenApiToolGenerationLimit,
};

/// The OpenAPI version a converted document declares.
pub const CONVERTED_OPENAPI_VERSION: &str = "3.0.3";
/// Nodes conversion may copy beyond the single copy every input node gets.
pub const MAX_SWAGGER2_DUPLICATED_NODES: usize = 262_144;
/// Nesting bound for the recursive schema walk, above the parsers' own limit
/// so that it only ever trips on input those parsers would also refuse.
pub const MAX_SWAGGER2_NESTING_DEPTH: usize = 256;
/// Warnings beyond this are summarized by one `warnings_truncated` entry.
const MAX_CONVERSION_WARNINGS: usize = MAX_CATALOG_ENTRIES;
/// A warning subject is an operator-supplied name; keep the report bounded.
const MAX_WARNING_SUBJECT_BYTES: usize = 256;

const DEFAULT_MEDIA_TYPE: &str = "application/json";
const FORM_URLENCODED: &str = "application/x-www-form-urlencoded";
const MULTIPART_FORM_DATA: &str = "multipart/form-data";

const METHODS: [&str; 7] = ["get", "put", "post", "delete", "options", "head", "patch"];
const DOCUMENT_FIELDS: [&str; 15] = [
    "swagger",
    "info",
    "host",
    "basePath",
    "schemes",
    "consumes",
    "produces",
    "paths",
    "definitions",
    "parameters",
    "responses",
    "securityDefinitions",
    "security",
    "tags",
    "externalDocs",
];
const OPERATION_FIELDS: [&str; 12] = [
    "tags",
    "summary",
    "description",
    "externalDocs",
    "operationId",
    "consumes",
    "produces",
    "parameters",
    "responses",
    "schemes",
    "deprecated",
    "security",
];
/// Fields a non-body parameter shares with an Items object; all of them move
/// into the OpenAPI 3.0 parameter `schema`.
const SCHEMA_FIELDS: [&str; 16] = [
    "type",
    "format",
    "items",
    "default",
    "maximum",
    "exclusiveMaximum",
    "minimum",
    "exclusiveMinimum",
    "maxLength",
    "minLength",
    "pattern",
    "maxItems",
    "minItems",
    "uniqueItems",
    "enum",
    "multipleOf",
];
const PARAMETER_FIELDS: [&str; 6] = [
    "name",
    "in",
    "description",
    "required",
    "allowEmptyValue",
    "collectionFormat",
];
const BODY_PARAMETER_FIELDS: [&str; 5] = ["name", "in", "description", "required", "schema"];

/// A Swagger 2.0 document rewritten as OpenAPI 3.0, with what the operator
/// should review about the rewrite.
#[derive(Debug, Clone, PartialEq)]
pub struct Swagger2Conversion {
    pub document: Value,
    pub warnings: Vec<OpenApiConversionWarning>,
}

/// Why a Swagger 2.0 document was rejected as a whole.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Swagger2ConversionError {
    /// `swagger` is present but is not the string `"2.0"`.
    UnsupportedVersion {
        version: String,
    },
    /// A structural field has the wrong JSON type.
    InvalidField {
        field: &'static str,
    },
    /// A local reference outside `#/definitions/`, `#/parameters/` and
    /// `#/responses/`, a parameter or response reference that points into a
    /// component rather than at one or at another reference, or a path-item
    /// reference. None has an OpenAPI 3.0 location to map to.
    UnsupportedReference {
        reference: String,
    },
    DuplicatedNodes {
        maximum: usize,
    },
    NestingDepth {
        maximum: usize,
    },
}

impl fmt::Display for Swagger2ConversionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion { version } => write!(
                formatter,
                "expected a Swagger document whose 'swagger' field is the string \"2.0\", got {version}"
            ),
            Self::InvalidField { field } => {
                write!(formatter, "Swagger 2.0 field '{field}' has an invalid shape")
            }
            Self::UnsupportedReference { reference } => write!(
                formatter,
                "Swagger 2.0 reference '{reference}' cannot be converted; only #/definitions/, #/parameters/ and #/responses/ references are supported"
            ),
            Self::DuplicatedNodes { maximum } => write!(
                formatter,
                "Swagger 2.0 conversion would copy more than {maximum} duplicated nodes"
            ),
            Self::NestingDepth { maximum } => write!(
                formatter,
                "Swagger 2.0 document nesting exceeds the maximum depth of {maximum}"
            ),
        }
    }
}

impl Error for Swagger2ConversionError {}

/// Whether a parsed document is Swagger rather than OpenAPI 3.x: it has a
/// `swagger` field and no `openapi` field. A document declaring both stays
/// on the OpenAPI 3.x path exactly as before this module existed.
pub fn is_swagger_document(document: &Value) -> bool {
    document
        .as_object()
        .is_some_and(|root| root.contains_key("swagger") && !root.contains_key("openapi"))
}

/// Convert a Swagger 2.0 document to OpenAPI 3.0. The caller has already
/// applied the input size cap and parsed the document.
pub fn convert(document: &Value) -> Result<Swagger2Conversion, OpenApiToolGenerationError> {
    let Some(root) = document.as_object() else {
        return Err(conversion_error(Swagger2ConversionError::InvalidField {
            field: "document",
        }));
    };
    match root.get("swagger") {
        Some(Value::String(version)) if version == "2.0" => {}
        other => {
            return Err(conversion_error(
                Swagger2ConversionError::UnsupportedVersion {
                    version: version_label(other),
                },
            ));
        }
    }
    // The generator refuses remote references in every OpenAPI 3.x document;
    // refusing them before conversion means none is ever resolved here.
    reject_non_local_references(document)?;
    let mut converter = Converter {
        root,
        warnings: Warnings::default(),
        duplicated_nodes: 0,
    };
    let document = converter.convert_document()?;
    Ok(Swagger2Conversion {
        document,
        warnings: converter.warnings.finish(),
    })
}

fn conversion_error(source: Swagger2ConversionError) -> OpenApiToolGenerationError {
    OpenApiToolGenerationError::Swagger2 { source }
}

fn version_label(version: Option<&Value>) -> String {
    match version {
        None => "no version".to_owned(),
        Some(Value::String(version)) => format!("'{}'", bounded_subject(version)),
        Some(other) => format!(
            "a JSON {} (quote the version in YAML)",
            json_type_name(other)
        ),
    }
}

fn json_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn bounded_subject(value: &str) -> String {
    if value.len() <= MAX_WARNING_SUBJECT_BYTES {
        return value.to_owned();
    }
    let mut end = MAX_WARNING_SUBJECT_BYTES;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

#[derive(Default)]
struct Warnings {
    entries: Vec<OpenApiConversionWarning>,
    document_codes: BTreeSet<OpenApiConversionWarningCode>,
    truncated: bool,
}

impl Warnings {
    fn push(&mut self, warning: OpenApiConversionWarning) {
        if self.entries.len() + 1 >= MAX_CONVERSION_WARNINGS {
            self.truncated = true;
            return;
        }
        self.entries.push(warning);
    }

    fn document(&mut self, code: OpenApiConversionWarningCode, subject: Option<&str>) {
        self.push(OpenApiConversionWarning {
            code,
            method: None,
            path_template: None,
            subject: subject.map(bounded_subject),
        });
    }

    /// A document-level note that applies however many operations caused it.
    fn document_once(&mut self, code: OpenApiConversionWarningCode) {
        if self.document_codes.insert(code) {
            self.document(code, None);
        }
    }

    fn operation(
        &mut self,
        code: OpenApiConversionWarningCode,
        method: &str,
        path_template: &str,
        subject: Option<&str>,
    ) {
        self.push(OpenApiConversionWarning {
            code,
            method: Some(method.to_ascii_uppercase()),
            path_template: Some(bounded_subject(path_template)),
            subject: subject.map(bounded_subject),
        });
    }

    fn finish(mut self) -> Vec<OpenApiConversionWarning> {
        if self.truncated {
            self.entries.push(OpenApiConversionWarning {
                code: OpenApiConversionWarningCode::WarningsTruncated,
                method: None,
                path_template: None,
                subject: None,
            });
        }
        self.entries
    }
}

/// How converting one piece of a document can fail: either the whole
/// document is rejected, or only the operation being converted is left out.
enum Failure {
    Document(OpenApiToolGenerationError),
    Operation {
        code: OpenApiConversionWarningCode,
        subject: Option<String>,
    },
}

impl From<OpenApiToolGenerationError> for Failure {
    fn from(error: OpenApiToolGenerationError) -> Self {
        Self::Document(error)
    }
}

impl From<Swagger2ConversionError> for Failure {
    fn from(error: Swagger2ConversionError) -> Self {
        Self::Document(conversion_error(error))
    }
}

fn omit(code: OpenApiConversionWarningCode, subject: Option<&str>) -> Failure {
    Failure::Operation {
        code,
        subject: subject.map(str::to_owned),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum BodyLocation {
    Body,
    FormData,
}

/// A `body` or `formData` parameter, held until the operation's request
/// body is assembled. `shared` marks a parameter that reached this operation
/// through a reference or from its path item, so each copy is budgeted.
#[derive(Clone, Copy)]
struct BodyParameter<'d> {
    location: BodyLocation,
    name: &'d str,
    object: &'d Map<String, Value>,
    shared: bool,
}

#[derive(Default)]
struct PathParameters<'d> {
    converted: Vec<Value>,
    bodies: Vec<BodyParameter<'d>>,
}

/// What an operation contributes to document-level notes once it converts.
#[derive(Default)]
struct OperationNotes {
    request_body_not_mapped: bool,
    consumes_defaulted: bool,
    produces_defaulted: bool,
}

struct Converter<'d> {
    root: &'d Map<String, Value>,
    warnings: Warnings,
    duplicated_nodes: usize,
}

impl<'d> Converter<'d> {
    fn convert_document(&mut self) -> Result<Value, OpenApiToolGenerationError> {
        for field in self.root.keys() {
            if !field.starts_with("x-") && !DOCUMENT_FIELDS.contains(&field.as_str()) {
                self.warnings.document(
                    OpenApiConversionWarningCode::UnsupportedDocumentField,
                    Some(field),
                );
            }
        }
        for field in ["parameters", "responses"] {
            if self.root.get(field).is_some_and(|value| !value.is_object()) {
                return Err(conversion_error(Swagger2ConversionError::InvalidField {
                    field,
                }));
            }
        }

        let mut converted = Map::new();
        converted.insert(
            "openapi".to_owned(),
            Value::String(CONVERTED_OPENAPI_VERSION.to_owned()),
        );
        converted.insert(
            "info".to_owned(),
            self.root.get("info").cloned().unwrap_or_else(|| json!({})),
        );
        if let Some(servers) = self.servers() {
            converted.insert("servers".to_owned(), servers);
        }

        let mut components = Map::new();
        if let Some(definitions) = self.root.get("definitions") {
            let Some(definitions) = definitions.as_object() else {
                return Err(conversion_error(Swagger2ConversionError::InvalidField {
                    field: "definitions",
                }));
            };
            let mut schemas = Map::new();
            for (name, schema) in definitions {
                let schema = self.convert_schema(schema, 0).map_err(document_failure)?;
                schemas.insert(name.clone(), schema);
            }
            components.insert("schemas".to_owned(), Value::Object(schemas));
        }
        if let Some(security_definitions) = self.root.get("securityDefinitions") {
            let Some(security_definitions) = security_definitions.as_object() else {
                return Err(conversion_error(Swagger2ConversionError::InvalidField {
                    field: "securityDefinitions",
                }));
            };
            let mut schemes = Map::new();
            for (name, definition) in security_definitions {
                match convert_security_scheme(definition) {
                    Some(scheme) => {
                        schemes.insert(name.clone(), scheme);
                    }
                    None => self.warnings.document(
                        OpenApiConversionWarningCode::SecurityDefinitionNotConverted,
                        Some(name),
                    ),
                }
            }
            components.insert("securitySchemes".to_owned(), Value::Object(schemes));
        }
        if !components.is_empty() {
            converted.insert("components".to_owned(), Value::Object(components));
        }
        // A Security Requirement Object has the same shape in both versions;
        // a malformed one is copied unchanged so the generator classifies it.
        if let Some(security) = self.root.get("security") {
            converted.insert("security".to_owned(), security.clone());
        }
        if let Some(tags) = self.root.get("tags") {
            converted.insert("tags".to_owned(), tags.clone());
        }
        converted.insert("paths".to_owned(), self.convert_paths()?);
        Ok(Value::Object(converted))
    }

    /// `servers` is informational: generated tools call the Connection's own
    /// endpoint. A `basePath` therefore has to be repeated in the Connection
    /// base path, which the warning says.
    fn servers(&mut self) -> Option<Value> {
        let base_path = self
            .root
            .get("basePath")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|base_path| !base_path.is_empty());
        if let Some(base_path) = base_path.filter(|base_path| *base_path != "/") {
            self.warnings.document(
                OpenApiConversionWarningCode::BasePathNotInPaths,
                Some(base_path),
            );
        }
        let base_path = base_path.unwrap_or("");
        let Some(host) = self
            .root
            .get("host")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|host| !host.is_empty())
        else {
            return (!base_path.is_empty()).then(|| json!([{ "url": base_path }]));
        };
        let mut schemes = self
            .root
            .get("schemes")
            .and_then(Value::as_array)
            .map(|schemes| {
                schemes
                    .iter()
                    .filter_map(Value::as_str)
                    .filter(|scheme| matches!(*scheme, "http" | "https"))
                    .collect::<BTreeSet<_>>()
            })
            .unwrap_or_default();
        if schemes.is_empty() {
            schemes.insert("https");
        }
        Some(Value::Array(
            schemes
                .into_iter()
                .map(|scheme| json!({ "url": format!("{scheme}://{host}{base_path}") }))
                .collect(),
        ))
    }

    fn convert_paths(&mut self) -> Result<Value, OpenApiToolGenerationError> {
        let Some(paths) = self.root.get("paths") else {
            return Ok(json!({}));
        };
        let Some(paths) = paths.as_object() else {
            return Err(conversion_error(Swagger2ConversionError::InvalidField {
                field: "paths",
            }));
        };
        let mut operation_count = 0usize;
        for (path_template, path_item) in paths {
            if path_template.starts_with("x-") {
                continue;
            }
            let Some(path_item) = path_item.as_object() else {
                return Err(conversion_error(Swagger2ConversionError::InvalidField {
                    field: "path item",
                }));
            };
            operation_count += METHODS
                .iter()
                .filter(|method| path_item.contains_key(**method))
                .count();
        }
        if operation_count > MAX_CATALOG_ENTRIES {
            return Err(OpenApiToolGenerationError::GenerationLimit {
                limit: OpenApiToolGenerationLimit::OperationCount,
                maximum: MAX_CATALOG_ENTRIES,
            });
        }

        let mut converted = Map::new();
        for (path_template, path_item) in paths {
            if path_template.starts_with("x-") {
                continue;
            }
            let Some(path_item) = path_item.as_object() else {
                return Err(conversion_error(Swagger2ConversionError::InvalidField {
                    field: "path item",
                }));
            };
            let item = self.convert_path_item(path_template, path_item)?;
            converted.insert(path_template.clone(), item);
        }
        Ok(Value::Object(converted))
    }

    fn convert_path_item(
        &mut self,
        path_template: &str,
        path_item: &'d Map<String, Value>,
    ) -> Result<Value, OpenApiToolGenerationError> {
        if let Some(reference) = path_item.get("$ref") {
            return Err(conversion_error(
                Swagger2ConversionError::UnsupportedReference {
                    reference: reference
                        .as_str()
                        .map(bounded_subject)
                        .unwrap_or_else(|| "<non-string>".to_owned()),
                },
            ));
        }
        for field in path_item.keys() {
            if !field.starts_with("x-")
                && field != "parameters"
                && !METHODS.contains(&field.as_str())
            {
                self.warnings.push(OpenApiConversionWarning {
                    code: OpenApiConversionWarningCode::UnsupportedPathItemField,
                    method: None,
                    path_template: Some(bounded_subject(path_template)),
                    subject: Some(bounded_subject(field)),
                });
            }
        }

        let path_parameters = match self.path_parameters(path_item.get("parameters")) {
            Ok(parameters) => Ok(parameters),
            Err(Failure::Document(error)) => return Err(error),
            Err(Failure::Operation { code, subject }) => Err((code, subject)),
        };

        let mut converted = Map::new();
        if let Ok(parameters) = &path_parameters {
            if !parameters.converted.is_empty() {
                converted.insert(
                    "parameters".to_owned(),
                    Value::Array(parameters.converted.clone()),
                );
            }
        }
        for method in METHODS {
            let Some(operation) = path_item.get(method) else {
                continue;
            };
            let parameters = match &path_parameters {
                Ok(parameters) => parameters,
                Err((code, subject)) => {
                    self.warnings
                        .operation(*code, method, path_template, subject.as_deref());
                    continue;
                }
            };
            match self.convert_operation(operation, &parameters.bodies) {
                Ok((operation, notes)) => {
                    self.record_notes(method, path_template, &notes);
                    converted.insert(method.to_owned(), operation);
                }
                Err(Failure::Document(error)) => return Err(error),
                Err(Failure::Operation { code, subject }) => {
                    self.warnings
                        .operation(code, method, path_template, subject.as_deref());
                }
            }
        }
        Ok(Value::Object(converted))
    }

    fn record_notes(&mut self, method: &str, path_template: &str, notes: &OperationNotes) {
        if notes.request_body_not_mapped {
            self.warnings.operation(
                OpenApiConversionWarningCode::RequestBodyNotMapped,
                method,
                path_template,
                None,
            );
        }
        if notes.consumes_defaulted {
            self.warnings
                .document_once(OpenApiConversionWarningCode::ConsumesDefaulted);
        }
        if notes.produces_defaulted {
            self.warnings
                .document_once(OpenApiConversionWarningCode::ProducesDefaulted);
        }
    }

    fn path_parameters(
        &mut self,
        parameters: Option<&'d Value>,
    ) -> Result<PathParameters<'d>, Failure> {
        let mut collected = PathParameters::default();
        for parameter in parameter_list(parameters)? {
            match self.collect_parameter(parameter)? {
                Collected::Converted(parameter) => collected.converted.push(parameter),
                Collected::Body(mut body) => {
                    body.shared = true;
                    collected.bodies.push(body);
                }
            }
        }
        Ok(collected)
    }

    fn convert_operation(
        &mut self,
        operation: &'d Value,
        path_bodies: &[BodyParameter<'d>],
    ) -> Result<(Value, OperationNotes), Failure> {
        let Some(operation) = operation.as_object() else {
            return Err(Swagger2ConversionError::InvalidField { field: "operation" }.into());
        };
        if let Some(field) = operation
            .keys()
            .find(|field| !field.starts_with("x-") && !OPERATION_FIELDS.contains(&field.as_str()))
        {
            return Err(omit(
                OpenApiConversionWarningCode::UnsupportedOperationField,
                Some(field),
            ));
        }

        let mut notes = OperationNotes::default();
        let mut converted = Map::new();
        for field in [
            "operationId",
            "summary",
            "description",
            "tags",
            "deprecated",
            "security",
        ] {
            if let Some(value) = operation.get(field) {
                converted.insert(field.to_owned(), value.clone());
            }
        }

        let mut parameters = Vec::new();
        let mut bodies = path_bodies.to_vec();
        for parameter in parameter_list(operation.get("parameters"))? {
            match self.collect_parameter(parameter)? {
                Collected::Converted(parameter) => parameters.push(parameter),
                Collected::Body(body) => {
                    // An operation parameter overrides the path item's
                    // parameter with the same name and location.
                    bodies.retain(|existing| {
                        existing.location != body.location || existing.name != body.name
                    });
                    bodies.push(body);
                }
            }
        }
        if !parameters.is_empty() {
            converted.insert("parameters".to_owned(), Value::Array(parameters));
        }
        if let Some(request_body) = self.request_body(operation, &bodies, &mut notes)? {
            converted.insert("requestBody".to_owned(), request_body);
        }
        if let Some(responses) = operation.get("responses") {
            let produces = self.media_types(operation, "produces");
            let responses = self.convert_responses(responses, produces.as_deref(), &mut notes)?;
            converted.insert("responses".to_owned(), responses);
        }
        Ok((Value::Object(converted), notes))
    }

    fn collect_parameter(&mut self, parameter: &'d Value) -> Result<Collected<'d>, Failure> {
        let (object, referenced) = self.resolve_component(parameter, "parameters")?;
        let Some(raw_name) = object.get("name").and_then(Value::as_str) else {
            return Err(omit(OpenApiConversionWarningCode::InvalidParameter, None));
        };
        if raw_name.trim().is_empty() {
            return Err(omit(OpenApiConversionWarningCode::InvalidParameter, None));
        }
        let Some(location) = object.get("in").and_then(Value::as_str) else {
            return Err(omit(
                OpenApiConversionWarningCode::InvalidParameter,
                Some(raw_name),
            ));
        };
        let body_location = if location.eq_ignore_ascii_case("body") {
            Some(BodyLocation::Body)
        } else if location.eq_ignore_ascii_case("formData") {
            Some(BodyLocation::FormData)
        } else {
            None
        };
        if let Some(body_location) = body_location {
            let allowed: &[&str] = match body_location {
                BodyLocation::Body => &BODY_PARAMETER_FIELDS,
                BodyLocation::FormData => &PARAMETER_FIELDS,
            };
            check_parameter_fields(object, allowed, body_location == BodyLocation::FormData)?;
            return Ok(Collected::Body(BodyParameter {
                location: body_location,
                name: raw_name,
                object,
                shared: referenced,
            }));
        }
        let location = ["query", "header", "path"]
            .into_iter()
            .find(|known| location.eq_ignore_ascii_case(known))
            .ok_or_else(|| {
                omit(
                    OpenApiConversionWarningCode::UnsupportedParameterLocation,
                    Some(location),
                )
            })?;
        if referenced {
            self.charge_object(object)?;
        }
        check_parameter_fields(object, &PARAMETER_FIELDS, true)?;
        Ok(Collected::Converted(
            self.convert_parameter(object, raw_name, location)?,
        ))
    }

    fn convert_parameter(
        &mut self,
        object: &'d Map<String, Value>,
        name: &str,
        location: &'static str,
    ) -> Result<Value, Failure> {
        if is_file_type(object) {
            return Err(omit(
                OpenApiConversionWarningCode::FileParameterOutsideForm,
                Some(name),
            ));
        }
        let mut converted = Map::new();
        converted.insert("name".to_owned(), Value::String(name.to_owned()));
        converted.insert("in".to_owned(), Value::String(location.to_owned()));
        for field in ["description", "required"] {
            if let Some(value) = object.get(field) {
                converted.insert(field.to_owned(), value.clone());
            }
        }
        if location == "query" {
            if let Some(value) = object.get("allowEmptyValue") {
                converted.insert("allowEmptyValue".to_owned(), value.clone());
            }
        }
        converted.insert("schema".to_owned(), self.items_schema(object, name, 0)?);
        if let Some((style, explode)) = collection_style(object, location, name)? {
            converted.insert("style".to_owned(), Value::String(style.to_owned()));
            converted.insert("explode".to_owned(), Value::Bool(explode));
        }
        Ok(Value::Object(converted))
    }

    /// The OpenAPI 3.0 schema for a non-body parameter or Items object.
    fn items_schema(
        &mut self,
        object: &'d Map<String, Value>,
        name: &str,
        depth: usize,
    ) -> Result<Value, Failure> {
        if depth > MAX_SWAGGER2_NESTING_DEPTH {
            return Err(Swagger2ConversionError::NestingDepth {
                maximum: MAX_SWAGGER2_NESTING_DEPTH,
            }
            .into());
        }
        let mut schema = Map::new();
        for field in SCHEMA_FIELDS {
            let Some(value) = object.get(field) else {
                continue;
            };
            match field {
                "items" => {
                    let Some(items) = value.as_object() else {
                        return Err(omit(
                            OpenApiConversionWarningCode::InvalidParameter,
                            Some(name),
                        ));
                    };
                    // Nested arrays have no OpenAPI 3.0 serialization style.
                    if items
                        .get("collectionFormat")
                        .is_some_and(|format| format.as_str() != Some("csv"))
                    {
                        return Err(omit(
                            OpenApiConversionWarningCode::UnsupportedCollectionFormat,
                            Some(name),
                        ));
                    }
                    let items = self.items_schema(items, name, depth + 1)?;
                    schema.insert("items".to_owned(), items);
                }
                "type" if value.as_str() == Some("file") => {
                    schema.insert("type".to_owned(), Value::String("string".to_owned()));
                    schema
                        .entry("format".to_owned())
                        .or_insert_with(|| Value::String("binary".to_owned()));
                }
                _ => {
                    let value = self.rewrite_references(value, depth + 1)?;
                    schema.insert(field.to_owned(), value);
                }
            }
        }
        Ok(Value::Object(schema))
    }

    fn request_body(
        &mut self,
        operation: &'d Map<String, Value>,
        bodies: &[BodyParameter<'d>],
        notes: &mut OperationNotes,
    ) -> Result<Option<Value>, Failure> {
        let body_count = bodies
            .iter()
            .filter(|body| body.location == BodyLocation::Body)
            .count();
        let form_count = bodies.len() - body_count;
        let request_body = match (body_count, form_count) {
            (0, 0) => return Ok(None),
            (1, 0) => self.body_request_body(operation, &bodies[0], notes)?,
            (0, _) => self.form_request_body(operation, bodies)?,
            (_, 0) => {
                return Err(omit(
                    OpenApiConversionWarningCode::MultipleBodyParameters,
                    None,
                ))
            }
            _ => {
                return Err(omit(
                    OpenApiConversionWarningCode::BodyAndFormParameters,
                    None,
                ))
            }
        };
        notes.request_body_not_mapped = !request_body
            .get("content")
            .and_then(Value::as_object)
            .is_some_and(|content| {
                content
                    .keys()
                    .any(|media_type| is_json_media_type(media_type))
            });
        Ok(Some(request_body))
    }

    fn body_request_body(
        &mut self,
        operation: &'d Map<String, Value>,
        body: &BodyParameter<'d>,
        notes: &mut OperationNotes,
    ) -> Result<Value, Failure> {
        if body.shared {
            self.charge_object(body.object)?;
        }
        let Some(schema) = body.object.get("schema") else {
            return Err(omit(
                OpenApiConversionWarningCode::InvalidParameter,
                Some(body.name),
            ));
        };
        let schema = self.convert_schema(schema, 0)?;
        let media_types = match self.media_types(operation, "consumes") {
            Some(media_types) => media_types,
            None => {
                notes.consumes_defaulted = true;
                vec![DEFAULT_MEDIA_TYPE.to_owned()]
            }
        };
        let mut request_body = Map::new();
        if let Some(description) = body.object.get("description") {
            request_body.insert("description".to_owned(), description.clone());
        }
        if let Some(required) = body.object.get("required") {
            request_body.insert("required".to_owned(), required.clone());
        }
        request_body.insert(
            "content".to_owned(),
            self.content(&media_types, &schema, None)?,
        );
        Ok(Value::Object(request_body))
    }

    fn form_request_body(
        &mut self,
        operation: &'d Map<String, Value>,
        bodies: &[BodyParameter<'d>],
    ) -> Result<Value, Failure> {
        let mut properties = Map::new();
        let mut required = Vec::new();
        let mut encoding = Map::new();
        let mut has_file = false;
        for body in bodies {
            if body.shared {
                self.charge_object(body.object)?;
            }
            let Value::Object(mut property) = self.items_schema(body.object, body.name, 0)? else {
                return Err(omit(
                    OpenApiConversionWarningCode::InvalidParameter,
                    Some(body.name),
                ));
            };
            has_file |= is_file_type(body.object);
            if let Some(description) = body.object.get("description") {
                property.insert("description".to_owned(), description.clone());
            }
            if body.object.get("required").and_then(Value::as_bool) == Some(true) {
                required.push(Value::String(body.name.to_owned()));
            }
            if let Some((style, explode)) = collection_style(body.object, "formData", body.name)? {
                encoding.insert(
                    body.name.to_owned(),
                    json!({ "style": style, "explode": explode }),
                );
            }
            properties.insert(body.name.to_owned(), Value::Object(property));
        }

        let mut schema = Map::new();
        schema.insert("type".to_owned(), Value::String("object".to_owned()));
        schema.insert("properties".to_owned(), Value::Object(properties));
        let any_required = !required.is_empty();
        if any_required {
            schema.insert("required".to_owned(), Value::Array(required));
        }
        let mut media_types = self
            .media_types(operation, "consumes")
            .unwrap_or_default()
            .into_iter()
            .filter(|media_type| is_form_media_type(media_type))
            .collect::<Vec<_>>();
        if media_types.is_empty() {
            media_types.push(
                if has_file {
                    MULTIPART_FORM_DATA
                } else {
                    FORM_URLENCODED
                }
                .to_owned(),
            );
        }
        let encoding = (!encoding.is_empty()).then_some(Value::Object(encoding));
        let mut request_body = Map::new();
        if any_required {
            request_body.insert("required".to_owned(), Value::Bool(true));
        }
        request_body.insert(
            "content".to_owned(),
            self.content(&media_types, &Value::Object(schema), encoding.as_ref())?,
        );
        Ok(Value::Object(request_body))
    }

    /// One Media Type Object per media type, each with its own copy of the
    /// schema; every copy after the first is budgeted.
    fn content(
        &mut self,
        media_types: &[String],
        schema: &Value,
        encoding: Option<&Value>,
    ) -> Result<Value, Failure> {
        let mut content = Map::new();
        for (index, media_type) in media_types.iter().enumerate() {
            if index > 0 {
                self.charge(schema, 1)?;
                if let Some(encoding) = encoding {
                    self.charge(encoding, 1)?;
                }
            }
            let mut media = Map::new();
            media.insert("schema".to_owned(), schema.clone());
            if let Some(encoding) = encoding {
                media.insert("encoding".to_owned(), encoding.clone());
            }
            content.insert(media_type.clone(), Value::Object(media));
        }
        Ok(Value::Object(content))
    }

    /// The operation's media types, else the document's; `None` when neither
    /// declares one, so the caller decides the default and notes it.
    fn media_types(&self, operation: &Map<String, Value>, field: &str) -> Option<Vec<String>> {
        let declared = operation
            .get(field)
            .or_else(|| self.root.get(field))?
            .as_array()?
            .iter()
            .filter_map(Value::as_str)
            .map(str::trim)
            .filter(|media_type| !media_type.is_empty())
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        (!declared.is_empty()).then(|| declared.into_iter().collect())
    }

    fn convert_responses(
        &mut self,
        responses: &'d Value,
        produces: Option<&[String]>,
        notes: &mut OperationNotes,
    ) -> Result<Value, Failure> {
        let Some(responses) = responses.as_object() else {
            return self.rewrite_references(responses, 0);
        };
        let mut converted = Map::new();
        for (status, response) in responses {
            if status.starts_with("x-") {
                continue;
            }
            let (response, referenced) = match response.as_object() {
                Some(_) => self.resolve_component(response, "responses")?,
                None => {
                    converted.insert(status.clone(), response.clone());
                    continue;
                }
            };
            if referenced {
                self.charge_object(response)?;
            }
            let mut out = Map::new();
            out.insert(
                "description".to_owned(),
                response
                    .get("description")
                    .cloned()
                    .unwrap_or_else(|| Value::String(String::new())),
            );
            if let Some(schema) = response.get("schema") {
                let schema = self.convert_schema(schema, 0)?;
                let media_types = match produces {
                    Some(media_types) => media_types.to_vec(),
                    None => {
                        notes.produces_defaulted = true;
                        vec![DEFAULT_MEDIA_TYPE.to_owned()]
                    }
                };
                out.insert(
                    "content".to_owned(),
                    self.content(&media_types, &schema, None)?,
                );
            }
            converted.insert(status.clone(), Value::Object(out));
        }
        Ok(Value::Object(converted))
    }

    /// Follow one `#/{section}/{name}` reference to the object it names.
    /// The second value is true when the object came from a reference.
    fn resolve_component(
        &self,
        value: &'d Value,
        section: &'static str,
    ) -> Result<(&'d Map<String, Value>, bool), Failure> {
        let invalid = || Failure::from(Swagger2ConversionError::InvalidField { field: section });
        let object = value.as_object().ok_or_else(invalid)?;
        let Some(reference) = object.get("$ref") else {
            return Ok((object, false));
        };
        let reference = reference.as_str().ok_or_else(invalid)?;
        let unsupported = || {
            Failure::from(Swagger2ConversionError::UnsupportedReference {
                reference: reference.to_owned(),
            })
        };
        let pointer = reference.strip_prefix('#').ok_or_else(unsupported)?;
        // Exactly `#/{section}/{name}`: a deeper pointer would read a schema
        // or another fragment as if it were a whole parameter or response.
        let name = pointer
            .strip_prefix('/')
            .and_then(|rest| rest.strip_prefix(section))
            .and_then(|rest| rest.strip_prefix('/'));
        if name.is_none_or(|name| name.contains('/')) {
            return Err(unsupported());
        }
        let target = pointer_into(self.root, pointer).ok_or_else(|| {
            Failure::from(OpenApiToolGenerationError::Reference {
                reference: reference.to_owned(),
                message: "target does not exist".to_owned(),
            })
        })?;
        let target = target.as_object().ok_or_else(invalid)?;
        if target.contains_key("$ref") {
            return Err(unsupported());
        }
        Ok((target, true))
    }

    /// Convert a Schema Object. Keywords that hold schemas are walked as
    /// schemas; every other value is copied with its references rewritten,
    /// because the generator dereferences `$ref` anywhere inside a schema.
    fn convert_schema(&mut self, schema: &Value, depth: usize) -> Result<Value, Failure> {
        if depth > MAX_SWAGGER2_NESTING_DEPTH {
            return Err(Swagger2ConversionError::NestingDepth {
                maximum: MAX_SWAGGER2_NESTING_DEPTH,
            }
            .into());
        }
        let Some(object) = schema.as_object() else {
            return self.rewrite_references(schema, depth);
        };
        let mut converted = Map::new();
        let mut file_type = false;
        for (keyword, value) in object {
            let value = match keyword.as_str() {
                "$ref" => match value.as_str() {
                    Some(reference) => Value::String(schema_reference(reference)?),
                    None => self.rewrite_references(value, depth + 1)?,
                },
                "properties" => match value.as_object() {
                    Some(properties) => {
                        let mut converted_properties = Map::new();
                        for (name, property) in properties {
                            converted_properties
                                .insert(name.clone(), self.convert_schema(property, depth + 2)?);
                        }
                        Value::Object(converted_properties)
                    }
                    None => self.rewrite_references(value, depth + 1)?,
                },
                "items" | "allOf" | "anyOf" | "oneOf" => match value.as_array() {
                    Some(schemas) => {
                        let mut converted_schemas = Vec::with_capacity(schemas.len());
                        for schema in schemas {
                            converted_schemas.push(self.convert_schema(schema, depth + 2)?);
                        }
                        Value::Array(converted_schemas)
                    }
                    None => self.convert_schema(value, depth + 1)?,
                },
                "not" | "additionalProperties" => self.convert_schema(value, depth + 1)?,
                "discriminator" if value.is_string() => json!({ "propertyName": value }),
                "type" if value.as_str() == Some("file") => {
                    file_type = true;
                    Value::String("string".to_owned())
                }
                "x-nullable" if value.is_boolean() => {
                    converted.insert("nullable".to_owned(), value.clone());
                    continue;
                }
                _ => self.rewrite_references(value, depth + 1)?,
            };
            converted.insert(keyword.clone(), value);
        }
        if file_type {
            converted
                .entry("format".to_owned())
                .or_insert_with(|| Value::String("binary".to_owned()));
        }
        Ok(Value::Object(converted))
    }

    /// Copy a value, rewriting every `#/definitions/` reference inside it.
    fn rewrite_references(&mut self, value: &Value, depth: usize) -> Result<Value, Failure> {
        if depth > MAX_SWAGGER2_NESTING_DEPTH {
            return Err(Swagger2ConversionError::NestingDepth {
                maximum: MAX_SWAGGER2_NESTING_DEPTH,
            }
            .into());
        }
        match value {
            Value::Array(values) => {
                let mut rewritten = Vec::with_capacity(values.len());
                for value in values {
                    rewritten.push(self.rewrite_references(value, depth + 1)?);
                }
                Ok(Value::Array(rewritten))
            }
            Value::Object(object) => {
                let mut rewritten = Map::new();
                for (key, value) in object {
                    let value = match (key.as_str(), value.as_str()) {
                        ("$ref", Some(reference)) => Value::String(schema_reference(reference)?),
                        _ => self.rewrite_references(value, depth + 1)?,
                    };
                    rewritten.insert(key.clone(), value);
                }
                Ok(Value::Object(rewritten))
            }
            _ => Ok(value.clone()),
        }
    }

    fn charge_object(&mut self, object: &Map<String, Value>) -> Result<(), Failure> {
        let mut nodes = 1usize;
        for value in object.values() {
            nodes = nodes.saturating_add(node_count_up_to(value, self.remaining_budget()));
        }
        self.consume(nodes)
    }

    fn charge(&mut self, value: &Value, copies: usize) -> Result<(), Failure> {
        let nodes = node_count_up_to(value, self.remaining_budget()).saturating_mul(copies);
        self.consume(nodes)
    }

    fn remaining_budget(&self) -> usize {
        MAX_SWAGGER2_DUPLICATED_NODES.saturating_sub(self.duplicated_nodes)
    }

    fn consume(&mut self, nodes: usize) -> Result<(), Failure> {
        self.duplicated_nodes = self.duplicated_nodes.saturating_add(nodes);
        if self.duplicated_nodes > MAX_SWAGGER2_DUPLICATED_NODES {
            return Err(Swagger2ConversionError::DuplicatedNodes {
                maximum: MAX_SWAGGER2_DUPLICATED_NODES,
            }
            .into());
        }
        Ok(())
    }
}

enum Collected<'d> {
    Converted(Value),
    Body(BodyParameter<'d>),
}

fn document_failure(failure: Failure) -> OpenApiToolGenerationError {
    match failure {
        Failure::Document(error) => error,
        // Definitions belong to no operation, so nothing can be left out
        // in their place; an operation-level refusal there rejects the
        // document instead.
        Failure::Operation { .. } => conversion_error(Swagger2ConversionError::InvalidField {
            field: "definitions",
        }),
    }
}

fn parameter_list(parameters: Option<&Value>) -> Result<&[Value], Failure> {
    match parameters {
        None => Ok(&[]),
        Some(Value::Array(parameters)) => Ok(parameters),
        Some(_) => Err(Swagger2ConversionError::InvalidField {
            field: "parameters",
        }
        .into()),
    }
}

/// `Value::pointer` over the root object without cloning it.
fn pointer_into<'d>(root: &'d Map<String, Value>, pointer: &str) -> Option<&'d Value> {
    let mut tokens = pointer.strip_prefix('/')?.split('/');
    let first = unescape_pointer_token(tokens.next()?);
    let mut target = root.get(&first)?;
    for token in tokens {
        target = target.pointer(&format!("/{token}"))?;
    }
    Some(target)
}

fn unescape_pointer_token(token: &str) -> String {
    token.replace("~1", "/").replace("~0", "~")
}

fn check_parameter_fields(
    object: &Map<String, Value>,
    allowed: &[&str],
    schema_fields_allowed: bool,
) -> Result<(), Failure> {
    let unknown = object.keys().find(|field| {
        !field.starts_with("x-")
            && !allowed.contains(&field.as_str())
            && !(schema_fields_allowed && SCHEMA_FIELDS.contains(&field.as_str()))
    });
    match unknown {
        Some(field) => Err(omit(
            OpenApiConversionWarningCode::UnsupportedParameterField,
            Some(field),
        )),
        None => Ok(()),
    }
}

fn is_file_type(object: &Map<String, Value>) -> bool {
    object.get("type").and_then(Value::as_str) == Some("file")
}

/// Swagger 2.0 `collectionFormat` as OpenAPI 3.0 `style`/`explode`. Only
/// arrays carry one; Swagger's default is `csv`, which for query and form
/// fields is not OpenAPI 3.0's default, so it is always written explicitly.
fn collection_style(
    object: &Map<String, Value>,
    location: &str,
    name: &str,
) -> Result<Option<(&'static str, bool)>, Failure> {
    if object.get("type").and_then(Value::as_str) != Some("array") {
        return Ok(None);
    }
    let format = match object.get("collectionFormat") {
        None => Some("csv"),
        Some(format) => format.as_str(),
    };
    let form_like = matches!(location, "query" | "formData");
    let style = match (form_like, format) {
        (true, Some("csv")) => ("form", false),
        (true, Some("multi")) => ("form", true),
        (true, Some("ssv")) => ("spaceDelimited", false),
        (true, Some("pipes")) => ("pipeDelimited", false),
        (false, Some("csv")) => ("simple", false),
        _ => {
            return Err(omit(
                OpenApiConversionWarningCode::UnsupportedCollectionFormat,
                Some(name),
            ))
        }
    };
    Ok(Some(style))
}

fn is_form_media_type(media_type: &str) -> bool {
    let essence = media_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    essence == FORM_URLENCODED || essence == MULTIPART_FORM_DATA
}

/// A schema reference rewritten from `#/definitions/` to
/// `#/components/schemas/`. JSON-pointer escaping carries over unchanged.
fn schema_reference(reference: &str) -> Result<String, Failure> {
    match reference.strip_prefix("#/definitions/") {
        Some(rest) => Ok(format!("#/components/schemas/{rest}")),
        None => Err(Swagger2ConversionError::UnsupportedReference {
            reference: reference.to_owned(),
        }
        .into()),
    }
}

/// Swagger 2.0 Security Scheme Object as OpenAPI 3.0, or `None` when the
/// definition is incomplete or of a type OpenAPI 3.0 cannot express. The
/// scheme is then left out, so operations requiring it bind as incompatible.
fn convert_security_scheme(definition: &Value) -> Option<Value> {
    let object = definition.as_object()?;
    if object.contains_key("$ref") {
        return None;
    }
    let scheme_type = object.get("type")?.as_str()?;
    let mut scheme = if scheme_type.eq_ignore_ascii_case("basic") {
        json!({ "type": "http", "scheme": "basic" })
    } else if scheme_type.eq_ignore_ascii_case("apiKey") {
        let name = object.get("name")?.as_str()?;
        let location = object.get("in")?.as_str()?;
        let location = ["header", "query"]
            .into_iter()
            .find(|known| location.eq_ignore_ascii_case(known))?;
        json!({ "type": "apiKey", "name": name, "in": location })
    } else if scheme_type.eq_ignore_ascii_case("oauth2") {
        let flow = object.get("flow")?.as_str()?;
        let (flow_name, authorization_url, token_url) = match flow {
            "implicit" => ("implicit", true, false),
            "password" => ("password", false, true),
            "application" => ("clientCredentials", false, true),
            "accessCode" => ("authorizationCode", true, true),
            _ => return None,
        };
        let mut converted_flow = Map::new();
        if authorization_url {
            let url = object.get("authorizationUrl")?.as_str()?;
            converted_flow.insert("authorizationUrl".to_owned(), Value::String(url.to_owned()));
        }
        if token_url {
            let url = object.get("tokenUrl")?.as_str()?;
            converted_flow.insert("tokenUrl".to_owned(), Value::String(url.to_owned()));
        }
        let scopes = object.get("scopes")?.as_object()?;
        converted_flow.insert("scopes".to_owned(), Value::Object(scopes.clone()));
        json!({ "type": "oauth2", "flows": { flow_name: converted_flow } })
    } else {
        return None;
    };
    if let Some(description) = object.get("description").filter(|value| value.is_string()) {
        scheme["description"] = description.clone();
    }
    Some(scheme)
}

/// Nodes in `value`, counting stops once `limit` is passed.
fn node_count_up_to(value: &Value, limit: usize) -> usize {
    let mut count = 0usize;
    let mut remaining = vec![value];
    while let Some(value) = remaining.pop() {
        count += 1;
        if count > limit {
            return count;
        }
        match value {
            Value::Array(values) => remaining.extend(values),
            Value::Object(object) => remaining.extend(object.values()),
            _ => {}
        }
    }
    count
}

#[cfg(test)]
#[path = "swagger2_tests.rs"]
mod tests;
