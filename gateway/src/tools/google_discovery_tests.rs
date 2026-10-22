use serde_json::{json, Value};

use super::*;
use crate::{
    connections::model::{
        ConnectionAuthentication, ConnectionId, OAuthClientAuthMethod, SubjectTokenSource,
    },
    tools::openapi::{
        bind_generated_openapi_tools, bind_generated_openapi_tools_with_confirmations,
        generate_tools_from_api_document_str, generate_tools_from_openapi_str,
        OpenApiSecurityMismatch, OpenApiSecurityMismatchReason, OpenApiSecuritySchemeRequirement,
        OpenApiSourceFormat, OpenApiToolGeneration, OpenApiToolIncompatibilityReason,
    },
};

use OpenApiConversionWarningCode as Code;

/// A trimmed Gmail-shaped Discovery document and what converting and
/// generating from it produce. `expected.json` was recorded from this
/// converter and reviewed by hand; a difference is a behaviour change for
/// stored Discovery catalogs and needs its own review, not a refresh.
const GMAIL_SUBSET: &str = include_str!("testdata/discovery-golden/gmail-subset.json");
const GMAIL_EXPECTED: &str = include_str!("testdata/discovery-golden/expected.json");

fn converted(document: Value) -> DiscoveryConversion {
    convert(&document).expect("Discovery document should convert")
}

fn conversion_error_of(document: Value) -> OpenApiToolGenerationError {
    convert(&document).expect_err("Discovery document should be rejected")
}

fn discovery(resources: Value) -> Value {
    json!({
        "kind": "discovery#restDescription",
        "discoveryVersion": "v1",
        "name": "widgets",
        "version": "v1",
        "rootUrl": "https://widgets.example.test/",
        "servicePath": "",
        "schemas": {
            "Widget": {
                "id": "Widget",
                "type": "object",
                "properties": { "id": { "type": "string" }, "name": { "type": "string" } }
            }
        },
        "resources": resources
    })
}

fn one_method(method: Value) -> Value {
    discovery(json!({ "widgets": { "methods": { "only": method } } }))
}

fn codes(conversion: &DiscoveryConversion) -> Vec<Code> {
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

fn gmail_generation() -> OpenApiToolGeneration {
    generate_tools_from_api_document_str("gmail-subset.json", GMAIL_SUBSET)
        .expect("the Gmail-shaped Discovery document should generate")
}

fn golden_summary() -> Value {
    let document: Value =
        serde_json::from_str(GMAIL_SUBSET).expect("golden Discovery document should parse");
    let conversion = converted(document);
    let generation = gmail_generation();
    json!({
        "converted_document": conversion.document,
        "warnings": conversion
            .warnings
            .iter()
            .map(|warning| json!({
                "code": warning.code.as_str(),
                "operation_omitted": warning.code.omits_operation(),
                "method": warning.method,
                "path_template": warning.path_template,
                "subject": warning.subject,
            }))
            .collect::<Vec<_>>(),
        "tools_file": generation.tools_file_value(),
        "skipped_operations": generation
            .skipped_operations
            .iter()
            .map(|skipped| json!({
                "method": skipped.method,
                "path_template": skipped.path_template,
                "reason": format!("{:?}", skipped.reason),
            }))
            .collect::<Vec<_>>(),
        "operation_id_fallbacks": generation.operation_id_fallbacks.len(),
        "security_requirements": generation
            .security_requirements
            .iter()
            .map(|security| json!({
                "tool_name": security.tool_name,
                "alternatives": security
                    .alternatives
                    .iter()
                    .map(|alternative| alternative
                        .members
                        .iter()
                        .map(|member| format!("{member:?}"))
                        .collect::<Vec<_>>())
                    .collect::<Vec<_>>(),
            }))
            .collect::<Vec<_>>(),
    })
}

#[test]
fn gmail_subset_conversion_and_generation_match_the_golden() {
    let expected: Value =
        serde_json::from_str(GMAIL_EXPECTED).expect("golden expectation should be valid JSON");
    let actual = golden_summary();
    let keys = |value: &Value| {
        value
            .as_object()
            .map(|object| object.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default()
    };
    assert_eq!(keys(&actual), keys(&expected), "golden sections changed");
    for (section, expected_section) in expected
        .as_object()
        .expect("golden expectation should be an object")
    {
        assert_eq!(
            &actual[section],
            expected_section,
            "Discovery golden section {section} changed; actual:\n{}",
            serde_json::to_string_pretty(&actual[section]).unwrap_or_default()
        );
    }
}

/// The acceptance subset of issue #443: reading messages and threads.
#[test]
fn gmail_methods_are_named_by_their_discovery_ids_and_keep_their_requests() {
    let generation = gmail_generation();
    let conversion = generation
        .conversion
        .as_ref()
        .expect("a Discovery document is reported as converted");
    assert_eq!(
        conversion.source_format,
        OpenApiSourceFormat::GoogleDiscovery
    );
    let mut names = tool_names(&generation);
    names.sort_unstable();
    assert_eq!(
        names,
        vec![
            "gmail.users.getProfile",
            "gmail.users.messages.delete",
            "gmail.users.messages.get",
            "gmail.users.messages.list",
            "gmail.users.messages.modify",
            "gmail.users.messages.trash",
            "gmail.users.threads.delete",
            "gmail.users.threads.get",
            "gmail.users.threads.list",
            "gmail.users.threads.modify",
            "gmail.users.threads.trash",
            "gmail.users.threads.untrash",
        ]
    );
    assert!(generation.operation_id_fallbacks.is_empty());
    let list = generation
        .definitions
        .iter()
        .find(|definition| definition.name == "gmail.users.messages.list")
        .expect("messages.list should generate");
    assert_eq!(list.upstream.method, "GET");
    assert_eq!(
        list.upstream.path_template,
        "/gmail/v1/users/{userId}/messages"
    );
    assert_eq!(
        list.input_schema["properties"]["maxResults"],
        json!({
            "type": "integer",
            "format": "uint32",
            "minimum": 1,
            "maximum": 500,
            "default": 100
        })
    );
    assert_eq!(
        list.input_schema["properties"]["labelIds"],
        json!({ "type": "array", "items": { "type": "string" } })
    );
    assert_eq!(
        list.input_schema["properties"]["includeSpamTrash"],
        json!({ "type": "boolean", "default": false })
    );
    assert_eq!(list.input_schema["required"], json!(["userId"]));
    assert!(
        list.input_schema["properties"].get("key").is_none()
            && list.input_schema["properties"]
                .get("access_token")
                .is_none(),
        "system parameters are never tool arguments"
    );
    let modify = generation
        .definitions
        .iter()
        .find(|definition| definition.name == "gmail.users.threads.modify")
        .expect("threads.modify should generate");
    assert!(modify.upstream.body.is_some());
    assert_eq!(
        modify.input_schema["properties"]["addLabelIds"],
        json!({ "type": "array", "items": { "type": "string" } })
    );
    assert_eq!(
        conversion
            .warnings
            .iter()
            .filter(|warning| warning.code.omits_operation())
            .cloned()
            .collect::<Vec<_>>(),
        vec![warning(
            Code::RecursiveRequestSchema,
            Some("POST"),
            Some("/gmail/v1/users/{userId}/messages/send"),
            Some("Message"),
        )],
        "only send is left out: Message reaches itself through MessagePart"
    );
}

/// Any one listed scope grants a Discovery method, so each scope is its own
/// alternative on one authorization-code scheme. The generator reports that
/// flow as user consent, which a client-credentials Connection cannot bind;
/// a per-caller one can (see
/// `a_delegated_connection_binds_the_read_operations_its_scopes_grant`).
#[test]
fn scopes_become_alternative_requirements_on_one_authorization_code_scheme() {
    let generation = gmail_generation();
    let document = &converted(
        serde_json::from_str(GMAIL_SUBSET).expect("golden Discovery document should parse"),
    )
    .document;
    assert_eq!(
        document["components"]["securitySchemes"][OAUTH2_SCHEME_NAME]["flows"]["authorizationCode"]
            ["tokenUrl"],
        json!(GOOGLE_TOKEN_URL)
    );
    assert_eq!(
        document["components"]["securitySchemes"][OAUTH2_SCHEME_NAME]["flows"]["authorizationCode"]
            ["scopes"]["https://www.googleapis.com/auth/gmail.readonly"],
        json!("View your email messages and settings")
    );
    assert_eq!(
        document["paths"]["/gmail/v1/users/{userId}/threads/{id}/modify"]["post"]["security"],
        json!([
            { "Oauth2": ["https://mail.google.com/"] },
            { "Oauth2": ["https://www.googleapis.com/auth/gmail.modify"] }
        ])
    );
    let security = generation
        .security_requirements
        .iter()
        .find(|security| security.tool_name == "gmail.users.messages.list")
        .expect("messages.list should carry security metadata");
    assert_eq!(
        security
            .alternatives
            .iter()
            .map(|alternative| alternative.members.clone())
            .collect::<Vec<_>>(),
        [
            "https://mail.google.com/",
            "https://www.googleapis.com/auth/gmail.metadata",
            "https://www.googleapis.com/auth/gmail.modify",
            "https://www.googleapis.com/auth/gmail.readonly",
        ]
        .map(
            |scope| vec![OpenApiSecuritySchemeRequirement::OAuth2UserConsent {
                scheme_name: OAUTH2_SCHEME_NAME.to_owned(),
                required_scopes: vec![scope.to_owned()],
            }]
        )
    );

    let connection_id = ConnectionId::parse("gmail").expect("connection ID should be valid");
    let binding = bind_generated_openapi_tools(
        &generation,
        &connection_id,
        &ConnectionAuthentication::OAuth2ClientCredentials {
            client_id: "gmail-client".to_owned(),
            client_secret_id: Some("gmail-client-secret".to_owned()),
            token_url: GOOGLE_TOKEN_URL.to_owned(),
            scopes: vec!["https://www.googleapis.com/auth/gmail.readonly".to_owned()],
            audience: None,
            resource: None,
            client_auth_method: OAuthClientAuthMethod::ClientSecretBasic,
        },
    )
    .expect("binding should report incompatibilities, not fail");
    assert!(binding.definitions.is_empty());
    assert_eq!(
        binding.incompatibilities.len(),
        generation.definitions.len()
    );
    assert!(binding.incompatibilities.iter().all(|incompatibility| {
        incompatibility.reason == OpenApiToolIncompatibilityReason::NoCompatibleSecurityAlternative
            && !incompatibility.security_mismatches.is_empty()
            && incompatibility.security_mismatches.iter().all(|mismatch| {
                mismatch.scheme_names == [OAUTH2_SCHEME_NAME]
                    && mismatch.reason
                        == OpenApiSecurityMismatchReason::OAuth2WithoutClientCredentials
            })
    }));
}

fn delegated_gmail_connection(requested_scopes: &[&str]) -> ConnectionAuthentication {
    ConnectionAuthentication::DelegatedIssuerToken {
        token_exchange_url: "https://issuer.example.test/oauth2/token-exchange".to_owned(),
        client_id: "greengateway".to_owned(),
        client_secret_id: Some("gmail-exchange-secret".to_owned()),
        requested_scopes: requested_scopes
            .iter()
            .map(|scope| (*scope).to_owned())
            .collect(),
        audience: None,
        resource: None,
        revocation_url: None,
        subject_token_source: SubjectTokenSource::CallerAssertion,
    }
}

/// The acceptance case of issue #443: a delegated Connection that requests
/// Gmail's read-only scope binds exactly the methods that scope grants, the
/// messages and threads reads among them, and the preview says, for every
/// other method, which scopes it would need.
#[test]
fn a_delegated_connection_binds_the_read_operations_its_scopes_grant() {
    let generation = gmail_generation();
    let connection_id = ConnectionId::parse("gmail").expect("connection ID should be valid");
    let readonly = "https://www.googleapis.com/auth/gmail.readonly";
    let binding = bind_generated_openapi_tools(
        &generation,
        &connection_id,
        &delegated_gmail_connection(&[readonly]),
    )
    .expect("binding should report incompatibilities, not fail");
    let mut bound = binding
        .definitions
        .iter()
        .map(|definition| {
            (
                definition.name.as_str(),
                definition.upstream.method.as_str(),
            )
        })
        .collect::<Vec<_>>();
    bound.sort_unstable();
    assert_eq!(
        bound,
        vec![
            ("gmail.users.getProfile", "GET"),
            ("gmail.users.messages.get", "GET"),
            ("gmail.users.messages.list", "GET"),
            ("gmail.users.threads.get", "GET"),
            ("gmail.users.threads.list", "GET"),
        ]
    );
    assert!(binding
        .security_selections
        .iter()
        .all(|selection| selection.selected_scheme_names == [OAUTH2_SCHEME_NAME]));

    let missing = |scope: &str| OpenApiSecurityMismatch {
        scheme_names: vec![OAUTH2_SCHEME_NAME.to_owned()],
        reason: OpenApiSecurityMismatchReason::MissingScopes {
            scopes: vec![scope.to_owned()],
        },
    };
    let full = missing("https://mail.google.com/");
    let modify = missing("https://www.googleapis.com/auth/gmail.modify");
    let mut incompatible = binding
        .incompatibilities
        .iter()
        .map(|incompatibility| {
            (
                incompatibility.tool_name.as_str(),
                incompatibility.security_mismatches.clone(),
            )
        })
        .collect::<Vec<_>>();
    incompatible.sort_by(|left, right| left.0.cmp(right.0));
    assert_eq!(
        incompatible,
        vec![
            ("gmail.users.messages.delete", vec![full.clone()]),
            (
                "gmail.users.messages.modify",
                vec![full.clone(), modify.clone()]
            ),
            (
                "gmail.users.messages.trash",
                vec![full.clone(), modify.clone()]
            ),
            ("gmail.users.threads.delete", vec![full.clone()]),
            (
                "gmail.users.threads.modify",
                vec![full.clone(), modify.clone()]
            ),
            (
                "gmail.users.threads.trash",
                vec![full.clone(), modify.clone()]
            ),
            ("gmail.users.threads.untrash", vec![full, modify]),
        ]
    );

    // The registration an operator confirms from that preview binds the
    // same read operations, and nothing else.
    let confirmed = bind_generated_openapi_tools_with_confirmations(
        &generation,
        &connection_id,
        &delegated_gmail_connection(&[readonly]),
        &binding.security_selections,
    )
    .expect("the preview selections should confirm");
    assert_eq!(confirmed.definitions, binding.definitions);
    assert!(confirmed.incompatibilities.is_empty());

    // Without any requested scope nothing that requires one binds.
    let unscoped = bind_generated_openapi_tools(
        &generation,
        &connection_id,
        &delegated_gmail_connection(&[]),
    )
    .expect("binding should report incompatibilities, not fail");
    assert!(unscoped.definitions.is_empty());
}

/// The converted document generates exactly what an operator's hand
/// conversion to OpenAPI 3.0 would.
#[test]
fn converted_document_generates_what_its_hand_conversion_generates() {
    let discovery_document = json!({
        "kind": "discovery#restDescription",
        "discoveryVersion": "v1",
        "name": "widgets",
        "title": "Widgets",
        "version": "v2",
        "rootUrl": "https://widgets.example.test/",
        "servicePath": "widgets/v2/",
        "auth": { "oauth2": { "scopes": { "https://widgets.example.test/read": { "description": "Read widgets" } } } },
        "schemas": {
            "Widget": {
                "id": "Widget",
                "type": "object",
                "properties": {
                    "id": { "type": "string", "required": true },
                    "quantity": { "type": "integer", "format": "int32", "minimum": "1" },
                    "tags": { "type": "array", "items": { "type": "string" } }
                }
            },
            "WidgetList": {
                "id": "WidgetList",
                "type": "object",
                "properties": { "widgets": { "type": "array", "items": { "$ref": "Widget" } } }
            }
        },
        "resources": {
            "widgets": {
                "methods": {
                    "list": {
                        "id": "widgets.widgets.list",
                        "path": "widgets",
                        "httpMethod": "GET",
                        "description": "List widgets.",
                        "parameters": {
                            "pageSize": { "type": "integer", "format": "int32", "location": "query", "default": "20" },
                            "tag": { "type": "string", "location": "query", "repeated": true }
                        },
                        "response": { "$ref": "WidgetList" },
                        "scopes": ["https://widgets.example.test/read"]
                    },
                    "insert": {
                        "id": "widgets.widgets.insert",
                        "path": "shelves/{shelf}/widgets",
                        "httpMethod": "POST",
                        "parameters": {
                            "shelf": { "type": "string", "location": "path", "required": true }
                        },
                        "request": { "$ref": "Widget", "parameterName": "body" },
                        "response": { "$ref": "Widget" }
                    }
                }
            }
        }
    });
    let hand_converted = r##"
openapi: 3.0.3
info: { title: Widgets, version: v2 }
servers:
  - url: https://widgets.example.test/widgets/v2
components:
  schemas:
    Widget:
      type: object
      required: [id]
      properties:
        id: { type: string }
        quantity: { type: integer, format: int32, minimum: 1 }
        tags: { type: array, items: { type: string } }
    WidgetList:
      type: object
      properties:
        widgets: { type: array, items: { $ref: '#/components/schemas/Widget' } }
  securitySchemes:
    Oauth2:
      type: oauth2
      flows:
        authorizationCode:
          authorizationUrl: https://accounts.google.com/o/oauth2/auth
          tokenUrl: https://oauth2.googleapis.com/token
          scopes: { "https://widgets.example.test/read": Read widgets }
paths:
  /widgets:
    get:
      operationId: widgets.widgets.list
      description: List widgets.
      parameters:
        - { name: pageSize, in: query, schema: { type: integer, format: int32, default: 20 } }
        - { name: tag, in: query, style: form, explode: true, schema: { type: array, items: { type: string } } }
      responses:
        "200":
          description: Successful response
          content:
            application/json:
              schema: { $ref: '#/components/schemas/WidgetList' }
      security:
        - Oauth2: ["https://widgets.example.test/read"]
  /shelves/{shelf}/widgets:
    post:
      operationId: widgets.widgets.insert
      parameters:
        - { name: shelf, in: path, required: true, schema: { type: string } }
      requestBody:
        required: true
        content:
          application/json:
            schema: { $ref: '#/components/schemas/Widget' }
      responses:
        "200":
          description: Successful response
          content:
            application/json:
              schema: { $ref: '#/components/schemas/Widget' }
"##;
    let hand_document: Value =
        yaml_serde::from_str(hand_converted).expect("the hand conversion should parse");
    assert_eq!(
        converted(discovery_document.clone()).document,
        hand_document
    );
    let from_discovery =
        generate_tools_from_api_document_str("widgets.json", &discovery_document.to_string())
            .expect("the Discovery document should generate");
    let by_hand = generate_tools_from_openapi_str("widgets.yaml", hand_converted)
        .expect("the hand conversion should generate");
    assert_eq!(from_discovery.definitions, by_hand.definitions);
    assert_eq!(
        from_discovery.security_requirements,
        by_hand.security_requirements
    );
    assert_eq!(
        from_discovery.skipped_operations,
        by_hand.skipped_operations
    );
    assert_eq!(
        from_discovery
            .conversion
            .as_ref()
            .map(|conversion| conversion.warnings.clone()),
        Some(vec![warning(
            Code::BasePathNotInPaths,
            None,
            None,
            Some("/widgets/v2")
        )])
    );
    assert!(by_hand.conversion.is_none());
}

#[test]
fn only_documents_without_openapi_or_swagger_fields_are_discovery_documents() {
    assert!(is_discovery_document(&json!({ "discoveryVersion": "v1" })));
    assert!(is_discovery_document(
        &json!({ "kind": "discovery#restDescription" })
    ));
    assert!(is_discovery_document(
        &json!({ "kind": "discovery#directoryList" })
    ));
    assert!(!is_discovery_document(
        &json!({ "openapi": "3.0.3", "discoveryVersion": "v1" })
    ));
    assert!(!is_discovery_document(
        &json!({ "swagger": "2.0", "discoveryVersion": "v1" })
    ));
    assert!(!is_discovery_document(&json!({ "kind": "storage#object" })));
    assert!(!is_discovery_document(&json!(["discoveryVersion"])));
}

#[test]
fn wrong_versions_kinds_and_protocols_refuse_the_document() {
    let base = discovery(json!({}));
    let mutate = |field: &str, value: Option<Value>| {
        let mut document = base.clone();
        match value {
            Some(value) => document[field] = value,
            None => {
                document.as_object_mut().map(|object| object.remove(field));
            }
        }
        conversion_error_of(document).to_string()
    };
    assert_eq!(
        mutate("discoveryVersion", Some(json!("v2"))),
        "expected a Google Discovery document whose 'discoveryVersion' is the string \"v1\", got 'v2'"
    );
    assert_eq!(
        mutate("discoveryVersion", None),
        "expected a Google Discovery document whose 'discoveryVersion' is the string \"v1\", got nothing"
    );
    assert_eq!(
        mutate("discoveryVersion", Some(json!(1))),
        "expected a Google Discovery document whose 'discoveryVersion' is the string \"v1\", got a JSON number"
    );
    assert_eq!(
        mutate("kind", Some(json!("discovery#directoryList"))),
        "expected a Google Discovery REST description (kind 'discovery#restDescription'), got 'discovery#directoryList'"
    );
    assert_eq!(
        mutate("protocol", Some(json!("rpc"))),
        "Google Discovery protocol 'rpc' is not supported; only 'rest' is"
    );
    let mut without_kind = base.clone();
    without_kind
        .as_object_mut()
        .map(|object| object.remove("kind"));
    assert!(convert(&without_kind).is_ok(), "kind is optional");
}

#[test]
fn parameters_convert_types_defaults_bounds_and_repeated_query_arrays() {
    let conversion = converted(one_method(json!({
        "id": "widgets.widgets.list",
        "path": "shelves/{shelf}/widgets",
        "httpMethod": "get",
        "parameters": {
            "shelf": { "type": "string", "location": "path" },
            "limit": { "type": "integer", "location": "query", "minimum": "0", "maximum": "1000", "default": "10" },
            "ratio": { "type": "number", "location": "query", "default": "0.5" },
            "verbose": { "type": "boolean", "location": "query", "default": "yes" },
            "anything": { "type": "any", "location": "query", "required": true, "deprecated": true },
            "view": { "type": "string", "location": "query", "enum": ["BASIC", "FULL"], "default": "BASIC" },
            "ids": { "type": "string", "location": "query", "repeated": true, "pattern": "^[a-z]+$" }
        }
    })));
    assert!(codes(&conversion).is_empty(), "{:?}", conversion.warnings);
    let parameters = &conversion.document["paths"]["/shelves/{shelf}/widgets"]["get"]["parameters"];
    assert_eq!(
        parameters,
        &json!([
            { "name": "anything", "in": "query", "required": true, "deprecated": true, "schema": {} },
            {
                "name": "ids",
                "in": "query",
                "schema": { "type": "array", "items": { "type": "string", "pattern": "^[a-z]+$" } },
                "style": "form",
                "explode": true
            },
            { "name": "limit", "in": "query", "schema": { "type": "integer", "minimum": 0, "maximum": 1000, "default": 10 } },
            { "name": "ratio", "in": "query", "schema": { "type": "number", "default": 0.5 } },
            { "name": "shelf", "in": "path", "required": true, "schema": { "type": "string" } },
            { "name": "verbose", "in": "query", "schema": { "type": "boolean" } },
            { "name": "view", "in": "query", "schema": { "type": "string", "enum": ["BASIC", "FULL"], "default": "BASIC" } }
        ])
    );
    assert_eq!(
        conversion.document["paths"]["/shelves/{shelf}/widgets"]["get"]["operationId"],
        json!("widgets.widgets.list")
    );
    assert!(
        conversion.document["paths"]["/shelves/{shelf}/widgets"]["get"]
            .get("security")
            .is_none(),
        "a method without scopes declares no security"
    );
    assert!(
        conversion.document["components"]
            .get("securitySchemes")
            .is_none(),
        "no OAuth 2.0 block and no scopes means no scheme"
    );
}

#[test]
fn schemas_convert_draft_3_keywords_and_report_unknown_ones_once() {
    let mut document = discovery(json!({}));
    document["schemas"] = json!({
        "Shape": {
            "id": "Shape",
            "type": "object",
            "description": "A shape.",
            "annotations": { "required": ["shapes.insert"] },
            "variant": { "discriminant": "kind", "map": [] },
            "properties": {
                "kind": { "type": "string", "required": true, "enum": ["circle"], "enumDescriptions": ["A circle"] },
                "radius": { "type": "number", "minimum": "0", "default": "1" },
                "labels": { "type": "object", "additionalProperties": { "type": "string" } },
                "extra": { "type": "any", "description": "Anything." },
                "child": { "$ref": "Shape", "description": "dropped beside a reference" },
                "nested": {
                    "type": "object",
                    "variant": { "discriminant": "x", "map": [] },
                    "properties": { "x": { "type": "integer", "format": "int64", "required": true } }
                }
            }
        }
    });
    let conversion = converted(document);
    assert_eq!(
        conversion.document["components"]["schemas"]["Shape"],
        json!({
            "type": "object",
            "description": "A shape.",
            "required": ["kind"],
            "properties": {
                "kind": { "type": "string", "enum": ["circle"] },
                "radius": { "type": "number", "minimum": 0, "default": 1 },
                "labels": { "type": "object", "additionalProperties": { "type": "string" } },
                "extra": { "description": "Anything." },
                "child": { "$ref": "#/components/schemas/Shape" },
                "nested": {
                    "type": "object",
                    "required": ["x"],
                    "properties": { "x": { "type": "integer", "format": "int64" } }
                }
            }
        })
    );
    assert_eq!(
        conversion.warnings,
        vec![warning(
            Code::UnsupportedSchemaKeyword,
            None,
            None,
            Some("variant")
        )],
        "an unknown keyword is reported once however often it appears"
    );
}

#[test]
fn document_level_parameters_unknown_fields_and_service_paths_are_reported() {
    let mut document = discovery(json!({}));
    document["servicePath"] = json!("/storage/v1/");
    document["parameters"] = json!({
        "key": { "type": "string", "location": "query" },
        "alt": { "type": "string", "location": "query" }
    });
    document["x-vendor"] = json!(true);
    let conversion = converted(document);
    assert_eq!(
        conversion.warnings,
        vec![
            warning(Code::UnsupportedDocumentField, None, None, Some("x-vendor")),
            warning(Code::BasePathNotInPaths, None, None, Some("/storage/v1")),
            warning(Code::GlobalParameterNotMapped, None, None, Some("alt")),
            warning(Code::GlobalParameterNotMapped, None, None, Some("key")),
        ]
    );
    assert_eq!(
        conversion.document["servers"],
        json!([{ "url": "https://widgets.example.test/storage/v1" }])
    );
    assert_eq!(
        conversion.document["info"],
        json!({ "title": "widgets", "version": "v1" })
    );
}

#[test]
fn methods_without_a_faithful_openapi_form_are_left_out_and_named() {
    let method = |path: &str, http_method: &str| {
        json!({
            "id": format!("widgets.{http_method}"),
            "path": path,
            "httpMethod": http_method,
        })
    };
    let mut methods = serde_json::Map::new();
    let mut add = |name: &str, value: Value| {
        methods.insert(name.to_owned(), value);
    };
    add("a_reserved", {
        let mut value = method("v1/{+name}", "GET");
        value["parameters"] =
            json!({ "name": { "type": "string", "location": "path", "required": true } });
        value
    });
    add("b_repeated_path", {
        let mut value = method("v1/{ids}", "GET");
        value["parameters"] =
            json!({ "ids": { "type": "string", "location": "path", "repeated": true } });
        value
    });
    add("c_unknown_field", {
        let mut value = method("v1/c", "GET");
        value["streamingType"] = json!("SERVER_STREAMING");
        value
    });
    add("d_unknown_http_method", method("v1/d", "CONNECT"));
    add("e_header_parameter", {
        let mut value = method("v1/e", "GET");
        value["parameters"] = json!({ "trace": { "type": "string", "location": "header" } });
        value
    });
    add("f_unknown_parameter_field", {
        let mut value = method("v1/f", "GET");
        value["parameters"] =
            json!({ "q": { "type": "string", "location": "query", "style": "deepObject" } });
        value
    });
    add("g_unused_path_parameter", {
        let mut value = method("v1/g", "GET");
        value["parameters"] = json!({ "id": { "type": "string", "location": "path" } });
        value
    });
    add(
        "h_no_path",
        json!({ "id": "widgets.nopath", "httpMethod": "GET" }),
    );
    add("i_duplicate", method("v1/c", "GET"));
    add("j_first", method("v1/c", "GET"));
    add("k_recursive", {
        let mut value = method("v1/k", "POST");
        value["request"] = json!({ "$ref": "Node" });
        value
    });
    add("l_bad_scopes", {
        let mut value = method("v1/l", "GET");
        value["scopes"] = json!("https://widgets.example.test/read");
        value
    });
    add("m_unbalanced", method("v1/{m", "GET"));
    add("n_upload", {
        let mut value = method("v1/n", "POST");
        value["supportsMediaUpload"] = json!(true);
        value["request"] = json!({ "$ref": "Widget" });
        value
    });
    let mut document = discovery(json!({ "widgets": { "methods": methods } }));
    document["schemas"]["Node"] = json!({
        "id": "Node",
        "type": "object",
        "properties": { "children": { "type": "array", "items": { "$ref": "Node" } } }
    });

    let conversion = converted(document);
    assert_eq!(
        conversion.warnings,
        vec![
            warning(
                Code::UnsupportedPathExpansion,
                Some("GET"),
                Some("/v1/{+name}"),
                Some("+name")
            ),
            warning(
                Code::RepeatedPathParameter,
                Some("GET"),
                Some("/v1/{ids}"),
                Some("ids")
            ),
            warning(
                Code::UnsupportedOperationField,
                Some("GET"),
                Some("/v1/c"),
                Some("streamingType")
            ),
            warning(
                Code::UnsupportedHttpMethod,
                None,
                Some("/v1/d"),
                Some("CONNECT")
            ),
            warning(
                Code::UnsupportedParameterLocation,
                Some("GET"),
                Some("/v1/e"),
                Some("header")
            ),
            warning(
                Code::UnsupportedParameterField,
                Some("GET"),
                Some("/v1/f"),
                Some("style")
            ),
            warning(
                Code::InvalidParameter,
                Some("GET"),
                Some("/v1/g"),
                Some("id")
            ),
            warning(
                Code::InvalidMethodDefinition,
                Some("GET"),
                None,
                Some("widgets.nopath")
            ),
            warning(
                Code::DuplicateOperation,
                Some("GET"),
                Some("/v1/c"),
                Some("widgets.GET")
            ),
            warning(
                Code::RecursiveRequestSchema,
                Some("POST"),
                Some("/v1/k"),
                Some("Node")
            ),
            warning(
                Code::InvalidMethodDefinition,
                Some("GET"),
                Some("/v1/l"),
                Some("widgets.GET")
            ),
            warning(
                Code::InvalidMethodDefinition,
                Some("GET"),
                Some("/v1/{m"),
                Some("widgets.GET")
            ),
            warning(
                Code::MediaUploadNotMapped,
                Some("POST"),
                Some("/v1/n"),
                None
            ),
        ]
    );
    for warning in &conversion.warnings {
        assert_eq!(
            warning.code.omits_operation(),
            warning.code != Code::MediaUploadNotMapped,
            "{:?}",
            warning.code
        );
    }
    let paths = conversion.document["paths"]
        .as_object()
        .expect("paths should be an object");
    assert_eq!(
        paths.keys().map(String::as_str).collect::<Vec<_>>(),
        vec!["/v1/c", "/v1/n"],
        "only the first of two identical operations and the upload method remain"
    );
    assert!(paths["/v1/n"]["post"].get("requestBody").is_some());
    // The recursive schema itself stays a component, so responses may use it.
    assert!(conversion.document["components"]["schemas"]
        .get("Node")
        .is_some());
}

#[test]
fn recursive_responses_are_kept_and_the_document_still_generates() {
    let mut document = one_method(json!({
        "id": "widgets.tree.get",
        "path": "tree",
        "httpMethod": "GET",
        "response": { "$ref": "Node" }
    }));
    document["schemas"]["Node"] = json!({
        "id": "Node",
        "type": "object",
        "properties": { "children": { "type": "array", "items": { "$ref": "Node" } } }
    });
    let generation = generate_tools_from_api_document_str("tree.json", &document.to_string())
        .expect("a recursive response does not stop generation");
    assert_eq!(tool_names(&generation), vec!["widgets.tree.get"]);
}

#[test]
fn absolute_method_paths_are_only_kept_without_a_service_path() {
    let method = json!({ "id": "widgets.root", "path": "/v1/root", "httpMethod": "GET" });
    let conversion = converted(one_method(method.clone()));
    assert!(conversion.document["paths"].get("/v1/root").is_some());

    let mut document = one_method(method);
    document["servicePath"] = json!("widgets/v1/");
    let conversion = converted(document);
    assert_eq!(
        conversion.warnings,
        vec![
            warning(Code::BasePathNotInPaths, None, None, Some("/widgets/v1")),
            warning(
                Code::InvalidMethodDefinition,
                Some("GET"),
                None,
                Some("widgets.root")
            ),
        ]
    );
}

#[test]
fn structural_errors_and_missing_references_refuse_the_document() {
    let message = |document: Value| conversion_error_of(document).to_string();
    let mut document = discovery(json!({}));
    document["schemas"] = json!([]);
    assert_eq!(
        message(document),
        "Google Discovery field 'schemas' has an invalid shape"
    );
    assert_eq!(
        message(discovery(json!([]))),
        "Google Discovery field 'resources' has an invalid shape"
    );
    assert_eq!(
        message(discovery(json!({ "widgets": { "methods": [] } }))),
        "Google Discovery field 'methods' has an invalid shape"
    );
    assert_eq!(
        message(discovery(
            json!({ "widgets": { "methods": { "a": "GET" } } })
        )),
        "Google Discovery field 'method' has an invalid shape"
    );
    let mut document = discovery(json!({}));
    document["schemas"]["Widget"]["properties"]["owner"] = json!({ "$ref": "Owner" });
    assert_eq!(
        message(document),
        "invalid OpenAPI reference 'Owner': target does not exist"
    );
    assert_eq!(
        message(one_method(json!({
            "id": "widgets.get",
            "path": "w",
            "httpMethod": "GET",
            "response": { "$ref": "https://other.example.test/schemas#Widget" }
        }))),
        "invalid OpenAPI reference 'https://other.example.test/schemas#Widget': target does not exist",
        "a remote reference is never resolved"
    );
    let mut document = discovery(json!({}));
    document["schemas"]["Widget"]["properties"]["id"]["minimum"] = json!("zero");
    assert_eq!(
        message(document),
        "Google Discovery field 'minimum or maximum' has an invalid shape"
    );
    let mut document = discovery(json!({}));
    document["auth"] = json!({ "oauth2": { "scopes": ["a"] } });
    assert_eq!(
        message(document),
        "Google Discovery field 'auth.oauth2.scopes' has an invalid shape"
    );

    let mut nested = json!({ "methods": {} });
    for _ in 0..=MAX_DISCOVERY_NESTING_DEPTH {
        nested = json!({ "resources": { "r": nested } });
    }
    let error = convert(&discovery(nested["resources"].clone()))
        .expect_err("over-deep resources should be refused");
    assert_eq!(
        error.to_string(),
        "Google Discovery document nesting exceeds the maximum depth of 256"
    );
}

#[test]
fn more_methods_than_a_catalog_holds_refuse_the_document() {
    let methods = (0..=MAX_CATALOG_ENTRIES)
        .map(|index| {
            (
                format!("m{index}"),
                json!({ "id": format!("widgets.m{index}"), "path": format!("m/{index}"), "httpMethod": "GET" }),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    let error = convert(&discovery(json!({ "widgets": { "methods": methods } })))
        .expect_err("too many methods should be refused");
    assert!(matches!(
        error,
        OpenApiToolGenerationError::GenerationLimit {
            limit: OpenApiToolGenerationLimit::OperationCount,
            maximum: MAX_CATALOG_ENTRIES,
        }
    ));
}

/// The managed entry point recognizes a Discovery document in JSON or
/// YAML; the legacy tools-file entry point stays OpenAPI 3.x only.
#[test]
fn only_the_managed_entry_point_converts_discovery_documents() {
    let document = one_method(json!({
        "id": "widgets.widgets.get",
        "path": "widgets/{id}",
        "httpMethod": "GET",
        "parameters": { "id": { "type": "string", "location": "path", "required": true } },
        "response": { "$ref": "Widget" }
    }));
    let json_source = document.to_string();
    let yaml_source = yaml_serde::to_string(&document).expect("document should render as YAML");
    for (source, contents) in [
        ("widgets.json", json_source.as_str()),
        ("widgets.yaml", yaml_source.as_str()),
    ] {
        let generation = generate_tools_from_api_document_str(source, contents)
            .expect("the managed entry point should convert");
        assert_eq!(tool_names(&generation), vec!["widgets.widgets.get"]);
        assert_eq!(
            generation
                .conversion
                .as_ref()
                .map(|conversion| conversion.source_format.as_str()),
            Some("google_discovery_v1")
        );
        assert!(
            generate_tools_from_openapi_str(source, contents).is_err(),
            "the legacy entry point stays OpenAPI 3.x only"
        );
    }
}

/// Unscoped methods bind to a Connection without authentication, so a
/// public Discovery API registers without any OAuth 2.0 support.
#[test]
fn unscoped_methods_bind_without_authentication() {
    let document = one_method(json!({
        "id": "widgets.widgets.get",
        "path": "widgets/{id}",
        "httpMethod": "GET",
        "parameters": { "id": { "type": "string", "location": "path", "required": true } },
        "response": { "$ref": "Widget" }
    }));
    let generation = generate_tools_from_api_document_str("widgets.json", &document.to_string())
        .expect("document should generate");
    let binding = bind_generated_openapi_tools(
        &generation,
        &ConnectionId::parse("widgets").expect("connection ID should be valid"),
        &ConnectionAuthentication::None,
    )
    .expect("binding should succeed");
    assert_eq!(binding.definitions.len(), 1);
    assert!(binding.incompatibilities.is_empty());
}

/// A scope listed twice is one alternative; a scope no `auth` block
/// declares still gets a scheme entry, with an empty description.
#[test]
fn repeated_and_undeclared_scopes_are_one_alternative_each() {
    let conversion = converted(one_method(json!({
        "id": "widgets.widgets.list",
        "path": "widgets",
        "httpMethod": "GET",
        "scopes": [
            "https://widgets.example.test/read",
            "https://widgets.example.test/read",
            "https://widgets.example.test/admin"
        ]
    })));
    assert_eq!(
        conversion.document["paths"]["/widgets"]["get"]["security"],
        json!([
            { "Oauth2": ["https://widgets.example.test/read"] },
            { "Oauth2": ["https://widgets.example.test/admin"] }
        ])
    );
    assert_eq!(
        conversion.document["components"]["securitySchemes"]["Oauth2"]["flows"]
            ["authorizationCode"]["scopes"],
        json!({
            "https://widgets.example.test/admin": "",
            "https://widgets.example.test/read": ""
        })
    );
}
