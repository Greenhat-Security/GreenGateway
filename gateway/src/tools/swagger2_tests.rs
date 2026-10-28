use serde_json::{json, Value};

use super::*;
use crate::{
    connections::model::{
        ConnectionAuthentication, ConnectionId, OAuthClientAuthMethod, SubjectTokenSource,
    },
    tools::openapi::{
        bind_generated_openapi_tools, generate_tools_from_api_document_str,
        generate_tools_from_openapi_str, OpenApiSecurityMismatch, OpenApiSecurityMismatchReason,
        OpenApiSourceFormat, OpenApiToolGeneration, OpenApiToolIncompatibilityReason,
    },
};

use OpenApiConversionWarningCode as Code;

fn converted(document: Value) -> Swagger2Conversion {
    convert(&document).expect("Swagger 2.0 document should convert")
}

fn conversion_error_of(document: Value) -> OpenApiToolGenerationError {
    convert(&document).expect_err("Swagger 2.0 document should be rejected")
}

fn swagger(paths: Value) -> Value {
    json!({
        "swagger": "2.0",
        "info": { "title": "Swagger test", "version": "1.0.0" },
        "paths": paths
    })
}

fn codes(conversion: &Swagger2Conversion) -> Vec<Code> {
    conversion
        .warnings
        .iter()
        .map(|warning| warning.code)
        .collect()
}

fn warning(
    code: Code,
    method: Option<&str>,
    path_template: Option<&str>,
    subject: Option<&str>,
) -> OpenApiConversionWarning {
    OpenApiConversionWarning {
        code,
        method: method.map(str::to_owned),
        path_template: path_template.map(str::to_owned),
        subject: subject.map(str::to_owned),
    }
}

fn tool_names(generation: &OpenApiToolGeneration) -> Vec<&str> {
    generation
        .definitions
        .iter()
        .map(|definition| definition.name.as_str())
        .collect()
}

/// A small but complete Swagger 2.0 document and, below it, the OpenAPI 3.0
/// document an operator would have written by hand for the same API.
const WIDGETS_SWAGGER: &str = r#"
swagger: "2.0"
info: { title: Widgets, version: 1.0.0 }
host: api.example.test
basePath: /v2
schemes: [https]
consumes: [application/json]
produces: [application/json]
securityDefinitions:
  ApiKey: { type: apiKey, in: header, name: X-API-Key }
  Service:
    type: oauth2
    flow: application
    tokenUrl: https://idp.example.test/oauth/token
    scopes: { widgets.read: Read widgets }
security:
  - ApiKey: []
parameters:
  WidgetId: { name: widgetId, in: path, required: true, type: string }
  Limit: { name: limit, in: query, type: integer, minimum: 1, maximum: 50 }
responses:
  WidgetResponse:
    description: One widget
    schema: { $ref: '#/definitions/Widget' }
definitions:
  Widget:
    type: object
    required: [id]
    properties:
      id: { type: string }
      name: { type: string }
      owner: { $ref: '#/definitions/Owner' }
  Owner:
    type: object
    properties:
      login: { type: string }
  WidgetCreate:
    type: object
    required: [name]
    properties:
      name: { type: string }
      quantity: { type: integer, minimum: 1 }
paths:
  /widgets:
    get:
      operationId: listWidgets
      summary: List widgets
      security:
        - Service: [widgets.read]
      parameters:
        - $ref: '#/parameters/Limit'
        - { name: cursor, in: query, type: string }
      responses:
        "200":
          description: Widgets
          schema:
            type: array
            items: { $ref: '#/definitions/Widget' }
    post:
      operationId: createWidget
      parameters:
        - name: widget
          in: body
          required: true
          schema: { $ref: '#/definitions/WidgetCreate' }
      responses:
        "201": { $ref: '#/responses/WidgetResponse' }
  /widgets/{widgetId}:
    parameters:
      - $ref: '#/parameters/WidgetId'
    get:
      operationId: getWidget
      description: Fetch one widget
      responses:
        "200": { $ref: '#/responses/WidgetResponse' }
    delete:
      operationId: deleteWidget
      security: []
      responses:
        "204": { description: Deleted }
"#;

const WIDGETS_OPENAPI_3: &str = r#"
openapi: 3.0.3
info: { title: Widgets, version: 1.0.0 }
servers:
  - url: https://api.example.test/v2
components:
  securitySchemes:
    ApiKey: { type: apiKey, in: header, name: X-API-Key }
    Service:
      type: oauth2
      flows:
        clientCredentials:
          tokenUrl: https://idp.example.test/oauth/token
          scopes: { widgets.read: Read widgets }
  schemas:
    Widget:
      type: object
      required: [id]
      properties:
        id: { type: string }
        name: { type: string }
        owner: { $ref: '#/components/schemas/Owner' }
    Owner:
      type: object
      properties:
        login: { type: string }
    WidgetCreate:
      type: object
      required: [name]
      properties:
        name: { type: string }
        quantity: { type: integer, minimum: 1 }
security:
  - ApiKey: []
paths:
  /widgets:
    get:
      operationId: listWidgets
      summary: List widgets
      security:
        - Service: [widgets.read]
      parameters:
        - { name: limit, in: query, schema: { type: integer, minimum: 1, maximum: 50 } }
        - { name: cursor, in: query, schema: { type: string } }
      responses:
        "200":
          description: Widgets
          content:
            application/json:
              schema:
                type: array
                items: { $ref: '#/components/schemas/Widget' }
    post:
      operationId: createWidget
      requestBody:
        required: true
        content:
          application/json:
            schema: { $ref: '#/components/schemas/WidgetCreate' }
      responses:
        "201":
          description: One widget
          content:
            application/json:
              schema: { $ref: '#/components/schemas/Widget' }
  /widgets/{widgetId}:
    parameters:
      - { name: widgetId, in: path, required: true, schema: { type: string } }
    get:
      operationId: getWidget
      description: Fetch one widget
      responses:
        "200":
          description: One widget
          content:
            application/json:
              schema: { $ref: '#/components/schemas/Widget' }
    delete:
      operationId: deleteWidget
      security: []
      responses:
        "204": { description: Deleted }
"#;

#[test]
fn converted_document_generates_what_the_hand_converted_openapi_3_document_generates() {
    let from_swagger = generate_tools_from_api_document_str("widgets.yaml", WIDGETS_SWAGGER)
        .expect("Swagger 2.0 widgets should generate");
    let from_openapi = generate_tools_from_openapi_str("widgets.yaml", WIDGETS_OPENAPI_3)
        .expect("OpenAPI 3.0 widgets should generate");

    assert_eq!(from_swagger.definitions, from_openapi.definitions);
    assert_eq!(
        from_swagger.operation_id_fallbacks,
        from_openapi.operation_id_fallbacks
    );
    assert_eq!(
        from_swagger.skipped_operations,
        from_openapi.skipped_operations
    );
    assert_eq!(
        from_swagger.api_key_header_auth_requirements,
        from_openapi.api_key_header_auth_requirements
    );
    assert_eq!(
        from_swagger.security_requirements,
        from_openapi.security_requirements
    );
    assert_eq!(
        from_swagger.transform_metadata,
        from_openapi.transform_metadata
    );
    for definition in &from_openapi.definitions {
        assert_eq!(
            from_swagger
                .declared_success_response_schemas(&definition.name)
                .expect("converted response schemas should resolve"),
            from_openapi
                .declared_success_response_schemas(&definition.name)
                .expect("hand-converted response schemas should resolve"),
            "declared success responses for {}",
            definition.name
        );
    }

    let connection_id = ConnectionId::parse("widgets-api").expect("connection ID should be valid");
    for authentication in [
        ConnectionAuthentication::HeaderApiKey {
            header_name: "x-api-key".to_owned(),
            secret_id: Some("widgets-header-secret".to_owned()),
        },
        ConnectionAuthentication::OAuth2ClientCredentials {
            client_id: "widgets-client".to_owned(),
            client_secret_id: Some("widgets-client-secret".to_owned()),
            token_url: "https://idp.example.test/oauth/token".to_owned(),
            scopes: vec!["widgets.read".to_owned()],
            audience: None,
            resource: None,
            client_auth_method: OAuthClientAuthMethod::ClientSecretBasic,
        },
    ] {
        assert_eq!(
            bind_generated_openapi_tools(&from_swagger, &connection_id, &authentication)
                .expect("converted binding should succeed"),
            bind_generated_openapi_tools(&from_openapi, &connection_id, &authentication)
                .expect("hand-converted binding should succeed"),
        );
    }

    let conversion = from_swagger
        .conversion
        .as_ref()
        .expect("a converted generation reports its conversion");
    assert_eq!(conversion.source_format, OpenApiSourceFormat::Swagger2);
    assert_eq!(
        conversion.warnings,
        vec![warning(Code::BasePathNotInPaths, None, None, Some("/v2"))]
    );
    assert!(from_openapi.conversion.is_none());
}

#[test]
fn converts_document_structure_to_openapi_3() {
    let conversion = converted(
        yaml_serde::from_str(WIDGETS_SWAGGER).expect("widgets fixture should be valid YAML"),
    );
    let expected: Value =
        yaml_serde::from_str(WIDGETS_OPENAPI_3).expect("expected fixture should be valid YAML");
    assert_eq!(conversion.document, expected);
}

#[test]
fn yaml_and_json_inputs_convert_identically_and_deterministically() {
    let yaml: Value = yaml_serde::from_str(WIDGETS_SWAGGER).expect("fixture should be YAML");
    let json_text = serde_json::to_string(&yaml).expect("fixture should serialize");
    let from_yaml = generate_tools_from_api_document_str("widgets.yaml", WIDGETS_SWAGGER)
        .expect("YAML should generate");
    let from_json = generate_tools_from_api_document_str("widgets.json", &json_text)
        .expect("JSON should generate");
    let again = generate_tools_from_api_document_str("widgets.json", &json_text)
        .expect("JSON should generate again");
    assert_eq!(from_yaml, from_json);
    assert_eq!(from_json, again);
}

#[test]
fn only_documents_without_an_openapi_field_take_the_swagger_path() {
    assert!(is_swagger_document(&json!({ "swagger": "2.0" })));
    assert!(is_swagger_document(&json!({ "swagger": "1.2" })));
    assert!(!is_swagger_document(
        &json!({ "swagger": "2.0", "openapi": "3.0.3" })
    ));
    assert!(!is_swagger_document(&json!({ "openapi": "3.0.3" })));
    assert!(!is_swagger_document(&json!(["swagger"])));

    // The legacy entry point stays OpenAPI 3.x only.
    let error = generate_tools_from_openapi_str("widgets.yaml", WIDGETS_SWAGGER)
        .expect_err("the OpenAPI 3.x entry point must not convert Swagger documents");
    assert!(
        error.to_string().contains("openapi"),
        "unexpected legacy error: {error}"
    );
}

#[test]
fn rejects_versions_other_than_the_string_2_0() {
    for (version, expected) in [
        (json!("1.2"), "got '1.2'"),
        (json!("2.0.1"), "got '2.0.1'"),
        (json!(2.0), "got a JSON number (quote the version in YAML)"),
        (Value::Null, "got a JSON null"),
    ] {
        let error = conversion_error_of(json!({ "swagger": version, "paths": {} }));
        assert!(
            error.to_string().contains(expected),
            "unexpected version error: {error}"
        );
    }
    let error = generate_tools_from_api_document_str("old.yaml", "swagger: 2.0\npaths: {}\n")
        .expect_err("an unquoted YAML version is a number");
    assert!(error.to_string().contains("quote the version"), "{error}");
}

#[test]
fn form_data_becomes_a_form_request_body_reported_as_unmapped() {
    let conversion = converted(swagger(json!({
        "/chat.postMessage": {
            "post": {
                "operationId": "chat.postMessage",
                "consumes": ["application/x-www-form-urlencoded", "application/json"],
                "parameters": [
                    { "name": "token", "in": "header", "required": true, "type": "string" },
                    { "name": "channel", "in": "formData", "required": true, "type": "string", "description": "Channel ID" },
                    { "name": "text", "in": "formData", "type": "string" },
                    { "name": "blocks", "in": "formData", "type": "array", "items": { "type": "string" } }
                ],
                "responses": { "200": { "description": "ok" } }
            }
        }
    })));
    assert_eq!(
        conversion.document["paths"]["/chat.postMessage"]["post"],
        json!({
            "operationId": "chat.postMessage",
            "parameters": [
                {
                    "name": "token",
                    "in": "header",
                    "required": true,
                    "schema": { "type": "string" }
                }
            ],
            "requestBody": {
                "required": true,
                "content": {
                    "application/x-www-form-urlencoded": {
                        "schema": {
                            "type": "object",
                            "required": ["channel"],
                            "properties": {
                                "channel": { "type": "string", "description": "Channel ID" },
                                "text": { "type": "string" },
                                "blocks": { "type": "array", "items": { "type": "string" } }
                            }
                        },
                        "encoding": {
                            "blocks": { "style": "form", "explode": false }
                        }
                    }
                }
            },
            "responses": { "200": { "description": "ok" } }
        })
    );
    assert_eq!(
        conversion.warnings,
        vec![warning(
            Code::RequestBodyNotMapped,
            Some("POST"),
            Some("/chat.postMessage"),
            None
        )]
    );

    let upload = swagger(json!({
        "/upload": {
            "post": {
                "operationId": "upload",
                "parameters": [
                    { "name": "file", "in": "formData", "type": "file", "required": true }
                ]
            }
        }
    }));
    assert_eq!(
        converted(upload.clone()).document.pointer(
            "/paths/~1upload/post/requestBody/content/multipart~1form-data/schema/properties/file"
        ),
        Some(&json!({ "type": "string", "format": "binary" }))
    );
    let generation = generate_tools_from_api_document_str("form.json", &conversion_source(upload))
        .expect("a file form should generate");
    assert!(
        generation.definitions[0].upstream.body.is_none(),
        "form fields are not JSON tool arguments, exactly as for OpenAPI 3.x form bodies"
    );
}

fn conversion_source(document: Value) -> String {
    serde_json::to_string(&document).expect("test document should serialize")
}

#[test]
fn body_media_types_default_to_json_once_and_non_json_bodies_are_reported() {
    let conversion = converted(swagger(json!({
        "/a": { "post": { "parameters": [ { "name": "a", "in": "body", "schema": { "type": "object" } } ] } },
        "/b": { "post": { "parameters": [ { "name": "b", "in": "body", "schema": { "type": "object" } } ] } },
        "/xml": {
            "post": {
                "consumes": ["application/xml"],
                "produces": ["application/xml", "application/json"],
                "parameters": [ { "name": "c", "in": "body", "schema": { "type": "object" } } ],
                "responses": { "200": { "description": "ok", "schema": { "type": "string" } } }
            }
        },
        "/c": { "get": { "responses": { "200": { "description": "ok", "schema": { "type": "string" } } } } }
    })));
    assert_eq!(
        conversion.document["paths"]["/a"]["post"]["requestBody"],
        json!({ "content": { "application/json": { "schema": { "type": "object" } } } })
    );
    assert_eq!(
        conversion.document["paths"]["/xml"]["post"]["responses"]["200"]["content"],
        json!({
            "application/json": { "schema": { "type": "string" } },
            "application/xml": { "schema": { "type": "string" } }
        })
    );
    assert_eq!(
        conversion.warnings,
        vec![
            warning(Code::ConsumesDefaulted, None, None, None),
            warning(Code::ProducesDefaulted, None, None, None),
            warning(Code::RequestBodyNotMapped, Some("POST"), Some("/xml"), None),
        ]
    );
}

#[test]
fn security_definitions_convert_and_unconvertible_ones_bind_as_incompatible() {
    let conversion = converted(json!({
        "swagger": "2.0",
        "info": { "title": "Security", "version": "1.0.0" },
        "securityDefinitions": {
            "Basic": { "type": "basic", "description": "Basic auth" },
            "Header": { "type": "apiKey", "in": "header", "name": "X-API-Key" },
            "Query": { "type": "apiKey", "in": "query", "name": "key" },
            "Implicit": { "type": "oauth2", "flow": "implicit", "authorizationUrl": "https://idp.example.test/authorize", "scopes": {} },
            "Password": { "type": "oauth2", "flow": "password", "tokenUrl": "https://idp.example.test/token", "scopes": { "a": "A" } },
            "Application": { "type": "oauth2", "flow": "application", "tokenUrl": "https://idp.example.test/token", "scopes": { "a": "A" } },
            "AccessCode": { "type": "oauth2", "flow": "accessCode", "authorizationUrl": "https://idp.example.test/authorize", "tokenUrl": "https://idp.example.test/token", "scopes": { "a": "A" } },
            "NoTokenUrl": { "type": "oauth2", "flow": "application", "scopes": {} },
            "UnknownFlow": { "type": "oauth2", "flow": "device", "tokenUrl": "https://idp.example.test/token", "scopes": {} },
            "CookieKey": { "type": "apiKey", "in": "cookie", "name": "session" },
            "Custom": { "type": "openIdConnect" }
        },
        "paths": {
            "/application": { "get": { "operationId": "application", "security": [ { "Application": ["a"] } ] } },
            "/access-code": { "get": { "operationId": "accessCode", "security": [ { "AccessCode": ["a"] } ] } },
            "/broken": { "get": { "operationId": "broken", "security": [ { "NoTokenUrl": [] } ] } },
            "/header": { "get": { "operationId": "header", "security": [ { "Header": [] } ] } }
        }
    }));
    assert_eq!(
        conversion.document["components"]["securitySchemes"],
        json!({
            "Basic": { "type": "http", "scheme": "basic", "description": "Basic auth" },
            "Header": { "type": "apiKey", "in": "header", "name": "X-API-Key" },
            "Query": { "type": "apiKey", "in": "query", "name": "key" },
            "Implicit": { "type": "oauth2", "flows": { "implicit": { "authorizationUrl": "https://idp.example.test/authorize", "scopes": {} } } },
            "Password": { "type": "oauth2", "flows": { "password": { "tokenUrl": "https://idp.example.test/token", "scopes": { "a": "A" } } } },
            "Application": { "type": "oauth2", "flows": { "clientCredentials": { "tokenUrl": "https://idp.example.test/token", "scopes": { "a": "A" } } } },
            "AccessCode": { "type": "oauth2", "flows": { "authorizationCode": { "authorizationUrl": "https://idp.example.test/authorize", "tokenUrl": "https://idp.example.test/token", "scopes": { "a": "A" } } } }
        })
    );
    assert_eq!(
        conversion.warnings,
        ["CookieKey", "Custom", "NoTokenUrl", "UnknownFlow"]
            .into_iter()
            .map(|name| warning(Code::SecurityDefinitionNotConverted, None, None, Some(name)))
            .collect::<Vec<_>>()
    );

    let generation = generate_tools_from_api_document_str(
        "security.json",
        &conversion_source(json!({
            "swagger": "2.0",
            "securityDefinitions": {
                "Application": { "type": "oauth2", "flow": "application", "tokenUrl": "https://idp.example.test/token", "scopes": { "a": "A" } },
                "AccessCode": { "type": "oauth2", "flow": "accessCode", "authorizationUrl": "https://idp.example.test/authorize", "tokenUrl": "https://idp.example.test/token", "scopes": { "a": "A" } },
                "NoTokenUrl": { "type": "oauth2", "flow": "application", "scopes": {} }
            },
            "paths": {
                "/application": { "get": { "operationId": "application", "security": [ { "Application": ["a"] } ] } },
                "/access-code": { "get": { "operationId": "accessCode", "security": [ { "AccessCode": ["a"] } ] } },
                "/broken": { "get": { "operationId": "broken", "security": [ { "NoTokenUrl": [] } ] } }
            }
        })),
    )
    .expect("security document should generate");
    let binding = bind_generated_openapi_tools(
        &generation,
        &ConnectionId::parse("security-api").expect("connection ID should be valid"),
        &ConnectionAuthentication::OAuth2ClientCredentials {
            client_id: "security-client".to_owned(),
            client_secret_id: Some("security-client-secret".to_owned()),
            token_url: "https://idp.example.test/token".to_owned(),
            scopes: vec!["a".to_owned()],
            audience: None,
            resource: None,
            client_auth_method: OAuthClientAuthMethod::ClientSecretBasic,
        },
    )
    .expect("binding should report incompatibilities");
    assert_eq!(
        binding
            .definitions
            .iter()
            .map(|definition| definition.name.as_str())
            .collect::<Vec<_>>(),
        vec!["application"]
    );
    let mut incompatible = binding
        .incompatibilities
        .iter()
        .map(|incompatibility| {
            assert_eq!(
                incompatibility.reason,
                OpenApiToolIncompatibilityReason::NoCompatibleSecurityAlternative
            );
            incompatibility.tool_name.as_str()
        })
        .collect::<Vec<_>>();
    incompatible.sort_unstable();
    assert_eq!(incompatible, vec!["accessCode", "broken"]);
}

#[test]
fn operations_with_unsupported_constructs_are_omitted_and_named() {
    let cases = [
        (
            "/two-bodies",
            json!([
                { "name": "a", "in": "body", "schema": {} },
                { "name": "b", "in": "body", "schema": {} }
            ]),
            Code::MultipleBodyParameters,
            None,
        ),
        (
            "/body-and-form",
            json!([
                { "name": "a", "in": "body", "schema": {} },
                { "name": "b", "in": "formData", "type": "string" }
            ]),
            Code::BodyAndFormParameters,
            None,
        ),
        (
            "/cookie",
            json!([{ "name": "session", "in": "cookie", "type": "string" }]),
            Code::UnsupportedParameterLocation,
            Some("cookie"),
        ),
        (
            "/tsv",
            json!([{ "name": "ids", "in": "query", "type": "array", "items": { "type": "string" }, "collectionFormat": "tsv" }]),
            Code::UnsupportedCollectionFormat,
            Some("ids"),
        ),
        (
            "/path-multi",
            json!([{ "name": "ids", "in": "path", "required": true, "type": "array", "items": { "type": "string" }, "collectionFormat": "multi" }]),
            Code::UnsupportedCollectionFormat,
            Some("ids"),
        ),
        (
            "/nested-array",
            json!([{ "name": "grid", "in": "query", "type": "array", "items": { "type": "array", "items": { "type": "integer" }, "collectionFormat": "pipes" } }]),
            Code::UnsupportedCollectionFormat,
            Some("grid"),
        ),
        (
            "/query-file",
            json!([{ "name": "upload", "in": "query", "type": "file" }]),
            Code::FileParameterOutsideForm,
            Some("upload"),
        ),
        (
            "/openapi3-parameter",
            json!([{ "name": "limit", "in": "query", "schema": { "type": "integer" } }]),
            Code::UnsupportedParameterField,
            Some("schema"),
        ),
        (
            "/nameless",
            json!([{ "in": "query", "type": "string" }]),
            Code::InvalidParameter,
            None,
        ),
        (
            "/locationless",
            json!([{ "name": "q", "type": "string" }]),
            Code::InvalidParameter,
            Some("q"),
        ),
        (
            "/schemaless-body",
            json!([{ "name": "payload", "in": "body" }]),
            Code::InvalidParameter,
            Some("payload"),
        ),
    ];
    let mut paths = serde_json::Map::new();
    for (path, parameters, _, _) in &cases {
        paths.insert(
            (*path).to_owned(),
            json!({ "post": { "operationId": path.trim_start_matches('/'), "parameters": parameters } }),
        );
    }
    paths.insert(
        "/request-body".to_owned(),
        json!({ "post": { "operationId": "requestBody", "requestBody": { "content": {} } } }),
    );
    paths.insert(
        "/fine".to_owned(),
        json!({ "get": { "operationId": "fine" } }),
    );
    let document = swagger(Value::Object(paths));
    let conversion = converted(document.clone());

    let mut expected = cases
        .iter()
        .map(|(path, _, code, subject)| warning(*code, Some("POST"), Some(path), *subject))
        .collect::<Vec<_>>();
    expected.push(warning(
        Code::UnsupportedOperationField,
        Some("POST"),
        Some("/request-body"),
        Some("requestBody"),
    ));
    expected.sort_by_key(|warning| warning.path_template.clone());
    assert_eq!(conversion.warnings, expected);
    for warning in &conversion.warnings {
        assert!(warning.code.omits_operation(), "{:?}", warning.code);
    }

    let generation =
        generate_tools_from_api_document_str("omitted.json", &conversion_source(document))
            .expect("the remaining operations should generate");
    assert_eq!(tool_names(&generation), vec!["fine"]);
}

#[test]
fn invalid_path_level_parameters_omit_every_operation_on_the_path() {
    let conversion = converted(swagger(json!({
        "/widgets/{id}": {
            "parameters": [
                { "name": "id", "in": "path", "required": true, "type": "string" },
                { "name": "session", "in": "cookie", "type": "string" }
            ],
            "get": { "operationId": "getWidget" },
            "delete": { "operationId": "deleteWidget" }
        }
    })));
    assert_eq!(conversion.document["paths"]["/widgets/{id}"], json!({}));
    assert_eq!(
        conversion.warnings,
        vec![
            warning(
                Code::UnsupportedParameterLocation,
                Some("GET"),
                Some("/widgets/{id}"),
                Some("cookie")
            ),
            warning(
                Code::UnsupportedParameterLocation,
                Some("DELETE"),
                Some("/widgets/{id}"),
                Some("cookie")
            ),
        ]
    );
}

#[test]
fn path_level_parameters_merge_and_operation_parameters_override_them() {
    let conversion = converted(swagger(json!({
        "/widgets/{id}": {
            "parameters": [
                { "name": "id", "in": "path", "required": true, "type": "string" },
                { "name": "verbose", "in": "query", "type": "boolean" },
                { "name": "payload", "in": "body", "schema": { "type": "object", "properties": { "name": { "type": "string" } } } }
            ],
            "put": {
                "operationId": "replaceWidget",
                "parameters": [
                    { "name": "verbose", "in": "query", "type": "string", "enum": ["yes", "no"] },
                    { "name": "payload", "in": "body", "required": true, "schema": { "type": "object", "properties": { "label": { "type": "string" } } } }
                ]
            },
            "patch": {
                "operationId": "patchWidget"
            }
        }
    })));
    let path_item = &conversion.document["paths"]["/widgets/{id}"];
    assert_eq!(
        path_item["parameters"],
        json!([
            { "name": "id", "in": "path", "required": true, "schema": { "type": "string" } },
            { "name": "verbose", "in": "query", "schema": { "type": "boolean" } }
        ])
    );
    assert_eq!(
        path_item["put"]["requestBody"]["content"]["application/json"]["schema"]["properties"],
        json!({ "label": { "type": "string" } })
    );
    assert_eq!(path_item["put"]["requestBody"]["required"], json!(true));
    assert_eq!(
        path_item["patch"]["requestBody"]["content"]["application/json"]["schema"]["properties"],
        json!({ "name": { "type": "string" } })
    );

    let generation = generate_tools_from_api_document_str(
        "merge.json",
        &conversion_source(swagger(json!({
            "/widgets/{id}": {
                "parameters": [ { "name": "verbose", "in": "query", "type": "boolean" } ],
                "get": {
                    "operationId": "getWidget",
                    "parameters": [ { "name": "verbose", "in": "query", "type": "string" } ]
                }
            }
        }))),
    )
    .expect("merge document should generate");
    assert_eq!(
        generation.definitions[0].input_schema["properties"]["verbose"],
        json!({ "type": "string" }),
        "the generator applies the operation override exactly as for OpenAPI 3.x"
    );
}

#[test]
fn collection_formats_map_to_explicit_openapi_3_styles() {
    let conversion = converted(swagger(json!({
        "/search/{tags}": {
            "get": {
                "operationId": "search",
                "parameters": [
                    { "name": "tags", "in": "path", "required": true, "type": "array", "items": { "type": "string" } },
                    { "name": "csv", "in": "query", "type": "array", "items": { "type": "string" } },
                    { "name": "multi", "in": "query", "type": "array", "items": { "type": "string" }, "collectionFormat": "multi" },
                    { "name": "ssv", "in": "query", "type": "array", "items": { "type": "string" }, "collectionFormat": "ssv" },
                    { "name": "pipes", "in": "query", "type": "array", "items": { "type": "integer", "minimum": 0 }, "collectionFormat": "pipes" },
                    { "name": "X-Ids", "in": "header", "type": "array", "items": { "type": "string" }, "collectionFormat": "csv" },
                    { "name": "flag", "in": "query", "type": "boolean", "collectionFormat": "multi", "allowEmptyValue": true }
                ]
            }
        }
    })));
    let styles = conversion.document["paths"]["/search/{tags}"]["get"]["parameters"]
        .as_array()
        .expect("parameters should convert")
        .iter()
        .map(|parameter| {
            (
                parameter["name"].as_str().unwrap_or_default().to_owned(),
                parameter.get("style").cloned(),
                parameter.get("explode").cloned(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        styles,
        vec![
            ("tags".to_owned(), Some(json!("simple")), Some(json!(false))),
            ("csv".to_owned(), Some(json!("form")), Some(json!(false))),
            ("multi".to_owned(), Some(json!("form")), Some(json!(true))),
            (
                "ssv".to_owned(),
                Some(json!("spaceDelimited")),
                Some(json!(false))
            ),
            (
                "pipes".to_owned(),
                Some(json!("pipeDelimited")),
                Some(json!(false))
            ),
            (
                "X-Ids".to_owned(),
                Some(json!("simple")),
                Some(json!(false))
            ),
            ("flag".to_owned(), None, None),
        ]
    );
    assert_eq!(
        conversion.document["paths"]["/search/{tags}"]["get"]["parameters"][4]["schema"],
        json!({ "type": "array", "items": { "type": "integer", "minimum": 0 } })
    );
    assert_eq!(
        conversion.document["paths"]["/search/{tags}"]["get"]["parameters"][6]["allowEmptyValue"],
        json!(true)
    );
    assert!(conversion.warnings.is_empty());
}

#[test]
fn schema_keywords_convert_to_their_openapi_3_forms() {
    let conversion = converted(json!({
        "swagger": "2.0",
        "definitions": {
            "Pet": {
                "type": "object",
                "discriminator": "kind",
                "required": ["kind"],
                "properties": {
                    "kind": { "type": "string" },
                    "photo": { "type": "file" },
                    "nickname": { "type": "string", "x-nullable": true },
                    "discriminator": { "type": "string" },
                    "tags": { "type": "array", "items": { "$ref": "#/definitions/Tag" } },
                    "extra": { "type": "object", "additionalProperties": { "$ref": "#/definitions/Tag" } }
                },
                "example": { "kind": "cat", "nested": { "$ref": "#/definitions/Tag" } }
            },
            "Cat": {
                "allOf": [ { "$ref": "#/definitions/Pet" }, { "type": "object", "properties": { "lives": { "type": "integer" } } } ]
            },
            "Tag": { "type": "string" },
            "a/b~c": { "type": "string" },
            "Escaped": { "$ref": "#/definitions/a~1b~0c" }
        },
        "paths": {}
    }));
    assert_eq!(
        conversion.document["components"]["schemas"],
        json!({
            "Pet": {
                "type": "object",
                "discriminator": { "propertyName": "kind" },
                "required": ["kind"],
                "properties": {
                    "kind": { "type": "string" },
                    "photo": { "type": "string", "format": "binary" },
                    "nickname": { "type": "string", "nullable": true },
                    "discriminator": { "type": "string" },
                    "tags": { "type": "array", "items": { "$ref": "#/components/schemas/Tag" } },
                    "extra": { "type": "object", "additionalProperties": { "$ref": "#/components/schemas/Tag" } }
                },
                "example": { "kind": "cat", "nested": { "$ref": "#/components/schemas/Tag" } }
            },
            "Cat": {
                "allOf": [ { "$ref": "#/components/schemas/Pet" }, { "type": "object", "properties": { "lives": { "type": "integer" } } } ]
            },
            "Tag": { "type": "string" },
            "a/b~c": { "type": "string" },
            "Escaped": { "$ref": "#/components/schemas/a~1b~0c" }
        })
    );
    assert_eq!(conversion.document["paths"], json!({}));
}

#[test]
fn references_are_inlined_for_parameters_and_responses_and_rewritten_for_schemas() {
    let conversion = converted(json!({
        "swagger": "2.0",
        "produces": ["application/json"],
        "parameters": {
            "a/b": { "name": "slashed", "in": "query", "type": "string" },
            "Body": { "name": "body", "in": "body", "schema": { "$ref": "#/definitions/Thing" } }
        },
        "responses": {
            "Thing": { "description": "A thing", "schema": { "$ref": "#/definitions/Thing" } }
        },
        "definitions": { "Thing": { "type": "object" } },
        "paths": {
            "/things": {
                "post": {
                    "parameters": [ { "$ref": "#/parameters/a~1b" }, { "$ref": "#/parameters/Body" } ],
                    "responses": { "200": { "$ref": "#/responses/Thing" }, "x-note": "ignored" }
                }
            }
        }
    }));
    assert_eq!(
        conversion.document["paths"]["/things"]["post"],
        json!({
            "parameters": [ { "name": "slashed", "in": "query", "schema": { "type": "string" } } ],
            "requestBody": {
                "content": { "application/json": { "schema": { "$ref": "#/components/schemas/Thing" } } }
            },
            "responses": {
                "200": {
                    "description": "A thing",
                    "content": { "application/json": { "schema": { "$ref": "#/components/schemas/Thing" } } }
                }
            }
        })
    );
    assert_eq!(codes(&conversion), vec![Code::ConsumesDefaulted]);
}

#[test]
fn rejects_references_and_shapes_that_cannot_be_converted() {
    let unsupported = |document: Value, expected: &str| {
        let error = conversion_error_of(document);
        assert!(
            error.to_string().contains(expected),
            "expected {expected:?} in {error}"
        );
    };
    unsupported(
        swagger(json!({ "/a": { "$ref": "#/paths/~1b" } })),
        "reference '#/paths/~1b' cannot be converted",
    );
    unsupported(
        json!({ "swagger": "2.0", "definitions": { "A": { "$ref": "#/parameters/B" } }, "paths": {} }),
        "reference '#/parameters/B' cannot be converted",
    );
    unsupported(
        swagger(json!({ "/a": { "get": { "parameters": [ { "$ref": "#/definitions/A" } ] } } })),
        "reference '#/definitions/A' cannot be converted",
    );
    unsupported(
        json!({
            "swagger": "2.0",
            "parameters": { "A": { "$ref": "#/parameters/B" }, "B": { "name": "b", "in": "query", "type": "string" } },
            "paths": { "/a": { "get": { "parameters": [ { "$ref": "#/parameters/A" } ] } } }
        }),
        "reference '#/parameters/A' cannot be converted",
    );
    // A pointer into a component, rather than at one, is not a parameter or
    // response reference even when its target is an object.
    unsupported(
        json!({
            "swagger": "2.0",
            "parameters": { "Body": { "name": "body", "in": "body", "schema": { "name": "q", "in": "query", "type": "string" } } },
            "paths": { "/a": { "get": { "parameters": [ { "$ref": "#/parameters/Body/schema" } ] } } }
        }),
        "reference '#/parameters/Body/schema' cannot be converted",
    );
    unsupported(
        json!({
            "swagger": "2.0",
            "responses": { "Thing": { "description": "A thing", "schema": { "description": "nested", "type": "object" } } },
            "paths": { "/a": { "get": { "responses": { "200": { "$ref": "#/responses/Thing/schema" } } } } }
        }),
        "reference '#/responses/Thing/schema' cannot be converted",
    );
    unsupported(
        swagger(
            json!({ "/a": { "get": { "parameters": [ { "$ref": "#/parameters/Missing" } ] } } }),
        ),
        "target does not exist",
    );
    unsupported(
        swagger(
            json!({ "/a": { "get": { "responses": { "200": { "$ref": "#/responses/Missing" } } } } }),
        ),
        "target does not exist",
    );
    unsupported(
        swagger(
            json!({ "/a": { "get": { "responses": { "200": { "$ref": "shared.json#/responses/A" } } } } }),
        ),
        "only local OpenAPI references are supported",
    );
    unsupported(swagger(json!([])), "field 'paths' has an invalid shape");
    unsupported(
        swagger(json!({ "/a": "not-a-path-item" })),
        "field 'path item' has an invalid shape",
    );
    unsupported(
        swagger(json!({ "/a": { "get": "not-an-operation" } })),
        "field 'operation' has an invalid shape",
    );
    unsupported(
        swagger(json!({ "/a": { "get": { "parameters": "query" } } })),
        "field 'parameters' has an invalid shape",
    );
    unsupported(
        swagger(json!({ "/a": { "get": { "parameters": [ "query" ] } } })),
        "field 'parameters' has an invalid shape",
    );
    unsupported(
        json!({ "swagger": "2.0", "definitions": [], "paths": {} }),
        "field 'definitions' has an invalid shape",
    );
    unsupported(
        json!({ "swagger": "2.0", "securityDefinitions": [], "paths": {} }),
        "field 'securityDefinitions' has an invalid shape",
    );
    unsupported(
        json!({ "swagger": "2.0", "parameters": [], "paths": {} }),
        "field 'parameters' has an invalid shape",
    );

    let error = generate_tools_from_api_document_str(
        "relative.json",
        &conversion_source(swagger(json!({ "widgets": { "get": {} } }))),
    )
    .expect_err("a relative path template is still rejected after conversion");
    assert!(
        error.to_string().contains("must start with '/'"),
        "unexpected path error: {error}"
    );
}

#[test]
fn document_level_notes_name_ignored_fields_and_the_base_path() {
    let conversion = converted(json!({
        "swagger": "2.0",
        "info": { "title": "Hybrid", "version": "1.0.0" },
        "basePath": "/api",
        "servers": [ { "url": "https://ignored.example.test" } ],
        "x-vendor": true,
        "paths": {
            "x-paths-extension": {},
            "/a": { "trace": { "operationId": "traceA" }, "x-item-extension": {}, "get": { "operationId": "getA" } }
        }
    }));
    assert_eq!(
        conversion.warnings,
        vec![
            warning(Code::UnsupportedDocumentField, None, None, Some("servers")),
            warning(Code::BasePathNotInPaths, None, None, Some("/api")),
            warning(
                Code::UnsupportedPathItemField,
                None,
                Some("/a"),
                Some("trace")
            ),
        ]
    );
    assert_eq!(conversion.document["servers"], json!([ { "url": "/api" } ]));
    assert_eq!(
        conversion.document["paths"],
        json!({ "/a": { "get": { "operationId": "getA" } } })
    );

    let with_host = converted(json!({
        "swagger": "2.0",
        "host": "api.example.test",
        "basePath": "/",
        "schemes": ["https", "http", "ws"],
        "paths": {}
    }));
    assert!(with_host.warnings.is_empty());
    assert_eq!(
        with_host.document["servers"],
        json!([ { "url": "http://api.example.test/" }, { "url": "https://api.example.test/" } ])
    );
}

#[test]
fn duplicated_nodes_are_budgeted_across_references_and_media_types() {
    let wide_schema = Value::Object(
        (0..1024)
            .map(|index| (format!("p{index}"), json!({ "type": "string" })))
            .collect(),
    );
    let mut paths = serde_json::Map::new();
    for index in 0..200 {
        paths.insert(
            format!("/r{index}"),
            json!({ "post": { "parameters": [ { "$ref": "#/parameters/Wide" } ] } }),
        );
    }
    let error = conversion_error_of(json!({
        "swagger": "2.0",
        "consumes": ["application/json"],
        "parameters": {
            "Wide": { "name": "wide", "in": "body", "schema": { "type": "object", "properties": wide_schema } }
        },
        "paths": paths
    }));
    assert!(
        matches!(
            &error,
            OpenApiToolGenerationError::Swagger2 {
                source: Swagger2ConversionError::DuplicatedNodes {
                    maximum: MAX_SWAGGER2_DUPLICATED_NODES
                }
            }
        ),
        "unexpected amplification error: {error:?}"
    );

    let media_types = (0..400)
        .map(|index| format!("application/vnd.type{index}+json"))
        .collect::<Vec<_>>();
    let error = conversion_error_of(json!({
        "swagger": "2.0",
        "produces": media_types,
        "paths": {
            "/a": { "get": { "responses": { "200": { "description": "ok", "schema": { "type": "object", "properties": wide_schema_value() } } } } }
        }
    }));
    assert!(
        matches!(
            &error,
            OpenApiToolGenerationError::Swagger2 {
                source: Swagger2ConversionError::DuplicatedNodes { .. }
            }
        ),
        "unexpected media type amplification error: {error:?}"
    );

    // The same references stay well inside the budget at realistic scale.
    let mut paths = serde_json::Map::new();
    for index in 0..200 {
        paths.insert(
            format!("/r{index}"),
            json!({ "get": { "parameters": [ { "$ref": "#/parameters/Limit" } ] } }),
        );
    }
    let conversion = converted(json!({
        "swagger": "2.0",
        "parameters": { "Limit": { "name": "limit", "in": "query", "type": "integer" } },
        "paths": paths
    }));
    assert_eq!(
        conversion.document["paths"]["/r199"]["get"]["parameters"][0]["schema"],
        json!({ "type": "integer" })
    );
}

fn wide_schema_value() -> Value {
    Value::Object(
        (0..1024)
            .map(|index| (format!("p{index}"), json!({ "type": "string" })))
            .collect(),
    )
}

#[test]
fn operation_count_is_bounded_before_conversion() {
    let paths = (0..=MAX_CATALOG_ENTRIES)
        .map(|index| (format!("/o{index}"), json!({ "get": {} })))
        .collect::<serde_json::Map<_, _>>();
    let error = conversion_error_of(swagger(Value::Object(paths)));
    assert!(
        matches!(
            &error,
            OpenApiToolGenerationError::GenerationLimit {
                limit: OpenApiToolGenerationLimit::OperationCount,
                maximum: MAX_CATALOG_ENTRIES,
            }
        ),
        "unexpected operation count error: {error:?}"
    );
}

#[test]
fn nesting_is_bounded() {
    let mut schema = json!({ "type": "string" });
    for _ in 0..(MAX_SWAGGER2_NESTING_DEPTH + 1) {
        schema = json!({ "not": schema });
    }
    let error = conversion_error_of(json!({
        "swagger": "2.0",
        "definitions": { "Deep": schema },
        "paths": {}
    }));
    assert!(
        matches!(
            &error,
            OpenApiToolGenerationError::Swagger2 {
                source: Swagger2ConversionError::NestingDepth { .. }
            }
        ),
        "unexpected nesting error: {error:?}"
    );
}

#[test]
fn warnings_are_bounded_and_truncation_is_reported() {
    let paths = (0..MAX_CATALOG_ENTRIES)
        .map(|index| {
            (
                format!("/o{index}"),
                json!({ "post": { "parameters": [ { "name": "f", "in": "formData", "type": "string" } ] } }),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    let conversion = converted(swagger(Value::Object(paths)));
    assert_eq!(conversion.warnings.len(), MAX_CATALOG_ENTRIES);
    assert_eq!(
        conversion.warnings.last().map(|warning| warning.code),
        Some(Code::WarningsTruncated)
    );

    let long_name = "n".repeat(10_000);
    let conversion = converted(swagger(json!({
        "/a": { "get": { "parameters": [ { "name": long_name, "in": "cookie", "type": "string" } ] } },
        "/b": { "get": { "parameters": [ { "name": "x", "in": long_name } ] } }
    })));
    assert!(conversion.warnings.iter().all(|warning| warning
        .subject
        .as_ref()
        .is_some_and(|subject| subject.len() <= 256)));
}

fn slack_style_generation() -> OpenApiToolGeneration {
    generate_tools_from_api_document_str(
        "slack-style.json",
        &conversion_source(json!({
            "swagger": "2.0",
            "info": { "title": "Slack-style Web API", "version": "1.0.0" },
            "host": "chat.example.test",
            "basePath": "/api",
            "schemes": ["https"],
            "produces": ["application/json"],
            "securityDefinitions": {
                "chatAuth": {
                    "type": "oauth2",
                    "flow": "accessCode",
                    "authorizationUrl": "https://chat.example.test/oauth/authorize",
                    "tokenUrl": "https://chat.example.test/api/oauth.access",
                    "scopes": { "channels:history": "Read history", "chat:write": "Post" }
                }
            },
            "paths": {
                "/conversations.history": {
                    "get": {
                        "operationId": "conversations_history",
                        "description": "Fetches a conversation's history.",
                        "security": [ { "chatAuth": ["channels:history"] } ],
                        "parameters": [
                            { "name": "token", "in": "header", "required": true, "type": "string" },
                            { "name": "channel", "in": "query", "required": true, "type": "string" },
                            { "name": "limit", "in": "query", "type": "integer" },
                            { "name": "inclusive", "in": "query", "type": "boolean" }
                        ],
                        "responses": {
                            "200": {
                                "description": "ok",
                                "schema": { "type": "object", "properties": { "ok": { "type": "boolean" } } }
                            }
                        }
                    }
                },
                "/chat.postMessage": {
                    "post": {
                        "operationId": "chat_postMessage",
                        "consumes": ["application/x-www-form-urlencoded", "application/json"],
                        "security": [ { "chatAuth": ["chat:write"] } ],
                        "parameters": [
                            { "name": "token", "in": "header", "required": true, "type": "string" },
                            { "name": "channel", "in": "formData", "required": true, "type": "string" }
                        ],
                        "responses": { "200": { "description": "ok" } }
                    }
                }
            }
        })),
    )
    .expect("Slack-style Swagger 2.0 document should generate")
}

#[test]
fn slack_style_document_generates_its_query_operations() {
    let generation = slack_style_generation();
    assert_eq!(
        tool_names(&generation),
        vec!["conversations_history", "chat_postMessage"]
    );
    let history = generation
        .definitions
        .iter()
        .find(|definition| definition.name == "conversations_history")
        .expect("history tool should be generated");
    assert_eq!(history.upstream.path_template, "/conversations.history");
    assert_eq!(
        history.input_schema,
        json!({
            "type": "object",
            "required": ["channel"],
            "properties": {
                "channel": { "type": "string" },
                "inclusive": { "type": "boolean" },
                "limit": { "type": "integer" }
            },
            "additionalProperties": false
        })
    );
    let conversion = generation
        .conversion
        .as_ref()
        .expect("conversion should be reported");
    assert_eq!(
        conversion.warnings,
        vec![
            warning(Code::BasePathNotInPaths, None, None, Some("/api")),
            warning(
                Code::RequestBodyNotMapped,
                Some("POST"),
                Some("/chat.postMessage"),
                None
            ),
        ]
    );
}

/// The acceptance case of issue #443 for Swagger 2.0: an `accessCode` flow
/// becomes a user-consent `authorizationCode` flow, which a delegated
/// Connection binds for the scopes it requests, so a read-only Connection
/// registers the history read and is told why posting does not bind.
#[test]
fn slack_style_read_operations_bind_to_a_delegated_connection() {
    let generation = slack_style_generation();
    let delegated = |requested_scopes: &[&str]| ConnectionAuthentication::DelegatedIssuerToken {
        token_exchange_url: "https://issuer.example.test/oauth2/token-exchange".to_owned(),
        client_id: "greengateway".to_owned(),
        client_secret_id: Some("chat-exchange-secret".to_owned()),
        requested_scopes: requested_scopes
            .iter()
            .map(|scope| (*scope).to_owned())
            .collect(),
        audience: None,
        resource: None,
        revocation_url: None,
        subject_token_source: SubjectTokenSource::CallerAssertion,
    };
    let connection_id = ConnectionId::parse("chat").expect("connection ID should be valid");
    let binding = bind_generated_openapi_tools(
        &generation,
        &connection_id,
        &delegated(&["channels:history"]),
    )
    .expect("binding should report incompatibilities, not fail");
    assert_eq!(
        binding
            .definitions
            .iter()
            .map(|definition| definition.name.as_str())
            .collect::<Vec<_>>(),
        vec!["conversations_history"]
    );
    assert_eq!(
        binding.security_selections[0].selected_scheme_names,
        vec!["chatAuth"]
    );
    assert_eq!(binding.incompatibilities.len(), 1);
    let post = &binding.incompatibilities[0];
    assert_eq!(post.tool_name, "chat_postMessage");
    assert_eq!(
        post.security_mismatches,
        vec![OpenApiSecurityMismatch {
            scheme_names: vec!["chatAuth".to_owned()],
            reason: OpenApiSecurityMismatchReason::MissingScopes {
                scopes: vec!["chat:write".to_owned()],
            },
        }]
    );

    let both = bind_generated_openapi_tools(
        &generation,
        &connection_id,
        &delegated(&["channels:history", "chat:write"]),
    )
    .expect("binding should succeed");
    assert_eq!(both.definitions.len(), 2);
    assert!(both.incompatibilities.is_empty());
}

#[test]
fn warning_codes_have_stable_names_messages_and_omission_flags() {
    let all = [
        Code::BasePathNotInPaths,
        Code::UnsupportedDocumentField,
        Code::UnsupportedPathItemField,
        Code::SecurityDefinitionNotConverted,
        Code::ConsumesDefaulted,
        Code::ProducesDefaulted,
        Code::RequestBodyNotMapped,
        Code::UnsupportedOperationField,
        Code::InvalidParameter,
        Code::UnsupportedParameterLocation,
        Code::UnsupportedParameterField,
        Code::UnsupportedCollectionFormat,
        Code::FileParameterOutsideForm,
        Code::MultipleBodyParameters,
        Code::BodyAndFormParameters,
        Code::WarningsTruncated,
    ];
    let names = all
        .iter()
        .map(|code| code.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(names.len(), all.len(), "warning code names must be unique");
    for code in all {
        assert!(code
            .as_str()
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_'));
        assert!(!code.message().is_empty());
    }
    assert_eq!(
        all.iter()
            .filter(|code| code.omits_operation())
            .map(|code| code.as_str())
            .collect::<Vec<_>>(),
        vec![
            "unsupported_operation_field",
            "invalid_parameter",
            "unsupported_parameter_location",
            "unsupported_parameter_field",
            "unsupported_collection_format",
            "file_parameter_outside_form",
            "multiple_body_parameters",
            "body_and_form_parameters",
        ]
    );
}
