use serde_json::{json, Value};
use std::collections::{BTreeSet, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

const OPENAPI_RELATIVE_PATH: &str = "openapi/admin-connections.v1.openapi.json";
const SCHEMA_RELATIVE_PATH: &str = "schemas/connection-admin.v1.schema.json";

#[derive(Clone, Copy)]
struct ExpectedOperation {
    path: &'static str,
    method: &'static str,
    operation_id: &'static str,
    request_definition: Option<&'static str>,
    success_status: &'static str,
    response_definition: &'static str,
}

const EXPECTED_OPERATIONS: &[ExpectedOperation] = &[
    ExpectedOperation {
        path: "/v1/admin/connections",
        method: "get",
        operation_id: "listConnections",
        request_definition: None,
        success_status: "200",
        response_definition: "ConnectionList",
    },
    ExpectedOperation {
        path: "/v1/admin/connections",
        method: "post",
        operation_id: "createConnection",
        request_definition: Some("ConnectionCreateRequest"),
        success_status: "201",
        response_definition: "ConnectionDetail",
    },
    ExpectedOperation {
        path: "/v1/admin/connections/{id}",
        method: "get",
        operation_id: "getConnection",
        request_definition: None,
        success_status: "200",
        response_definition: "ConnectionDetail",
    },
    ExpectedOperation {
        path: "/v1/admin/connections/{id}",
        method: "put",
        operation_id: "replaceConnection",
        request_definition: Some("ConnectionReplaceRequest"),
        success_status: "200",
        response_definition: "ConnectionDetail",
    },
    ExpectedOperation {
        path: "/v1/admin/connections/{id}",
        method: "delete",
        operation_id: "deleteConnection",
        request_definition: None,
        success_status: "200",
        response_definition: "ConnectionDeleted",
    },
    ExpectedOperation {
        path: "/v1/admin/connections/{id}/test",
        method: "post",
        operation_id: "testConnection",
        request_definition: None,
        success_status: "200",
        response_definition: "ConnectionTestResult",
    },
    ExpectedOperation {
        path: "/v1/admin/connections/{id}/refresh",
        method: "post",
        operation_id: "refreshConnectionCatalog",
        request_definition: None,
        success_status: "200",
        response_definition: "CatalogPublishResult",
    },
    ExpectedOperation {
        path: "/v1/admin/connections/{id}/overlay",
        method: "get",
        operation_id: "getConnectionOpenApiOverlay",
        request_definition: None,
        success_status: "200",
        response_definition: "OpenApiOverlayGetResponse",
    },
    ExpectedOperation {
        path: "/v1/admin/connections/{id}/overlay",
        method: "put",
        operation_id: "putConnectionOpenApiOverlay",
        request_definition: Some("OpenApiOverlayDocument"),
        success_status: "200",
        response_definition: "OpenApiOverlayMutationResponse",
    },
    ExpectedOperation {
        path: "/v1/admin/connections/{id}/overlay",
        method: "delete",
        operation_id: "deleteConnectionOpenApiOverlay",
        request_definition: None,
        success_status: "200",
        response_definition: "OpenApiOverlayMutationResponse",
    },
    ExpectedOperation {
        path: "/v1/admin/connections/{id}/openapi/preview",
        method: "post",
        operation_id: "previewManagedOpenApi",
        request_definition: Some("OpenApiPreviewRequest"),
        success_status: "200",
        response_definition: "OpenApiPreviewResponse",
    },
    ExpectedOperation {
        path: "/v1/admin/connections/{id}/openapi/register",
        method: "post",
        operation_id: "registerManagedOpenApi",
        request_definition: Some("OpenApiRegisterRequest"),
        success_status: "201",
        response_definition: "CatalogPublishResult",
    },
    ExpectedOperation {
        path: "/v1/admin/connection-secrets",
        method: "get",
        operation_id: "listConnectionSecretAliases",
        request_definition: None,
        success_status: "200",
        response_definition: "SecretList",
    },
    ExpectedOperation {
        path: "/v1/admin/connection-secrets",
        method: "post",
        operation_id: "createEncryptedConnectionSecret",
        request_definition: Some("SecretCreateRequest"),
        success_status: "201",
        response_definition: "SafeSecretAlias",
    },
    ExpectedOperation {
        path: "/v1/admin/connection-secrets/{id}",
        method: "put",
        operation_id: "rotateEncryptedConnectionSecret",
        request_definition: Some("SecretRotateRequest"),
        success_status: "200",
        response_definition: "SafeSecretAlias",
    },
    ExpectedOperation {
        path: "/v1/admin/connection-secrets/{id}",
        method: "delete",
        operation_id: "deleteEncryptedConnectionSecret",
        request_definition: None,
        success_status: "200",
        response_definition: "SecretDeleted",
    },
    ExpectedOperation {
        path: "/v1/admin/tools",
        method: "get",
        operation_id: "listCapabilities",
        request_definition: None,
        success_status: "200",
        response_definition: "CapabilityList",
    },
    ExpectedOperation {
        path: "/v1/admin/tools/{id}",
        method: "get",
        operation_id: "getCapability",
        request_definition: None,
        success_status: "200",
        response_definition: "CapabilityDetail",
    },
    ExpectedOperation {
        path: "/v1/admin/tools/{id}/execute",
        method: "post",
        operation_id: "executeCapabilityInPlayground",
        request_definition: Some("PlaygroundRequest"),
        success_status: "200",
        response_definition: "PlaygroundResult",
    },
];

fn docs_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("gateway crate should have a workspace parent")
        .join("docs")
}

fn load_json(path: &Path) -> Value {
    let contents = fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    serde_json::from_str(&contents)
        .unwrap_or_else(|error| panic!("failed to parse {} as JSON: {error}", path.display()))
}

fn schema_reference(definition: &str) -> String {
    format!("../schemas/connection-admin.v1.schema.json#/$defs/{definition}")
}

fn collect_references<'a>(value: &'a Value, references: &mut Vec<&'a str>) {
    match value {
        Value::Object(object) => {
            if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
                references.push(reference);
            }
            for child in object.values() {
                collect_references(child, references);
            }
        }
        Value::Array(array) => {
            for child in array {
                collect_references(child, references);
            }
        }
        _ => {}
    }
}

fn assert_references_resolve(document_path: &Path, document: &Value) {
    let document_path = document_path.canonicalize().unwrap_or_else(|error| {
        panic!(
            "failed to canonicalize {}: {error}",
            document_path.display()
        )
    });
    let mut references = Vec::new();
    collect_references(document, &mut references);
    assert!(
        !references.is_empty(),
        "{} should contain contract references",
        document_path.display()
    );

    for reference in references {
        let (relative_path, fragment) = reference.split_once('#').unwrap_or((reference, ""));
        assert!(
            !relative_path.contains("://"),
            "{} contains a non-local reference {reference:?}",
            document_path.display()
        );

        let target_path = if relative_path.is_empty() {
            document_path.clone()
        } else {
            document_path
                .parent()
                .expect("contract document should have a parent directory")
                .join(relative_path)
                .canonicalize()
                .unwrap_or_else(|error| {
                    panic!(
                        "{} has missing reference target {reference:?}: {error}",
                        document_path.display()
                    )
                })
        };
        let target_document = if target_path == document_path {
            document.clone()
        } else {
            load_json(&target_path)
        };

        if !fragment.is_empty() {
            assert!(
                fragment.starts_with('/'),
                "{} contains a non-JSON-Pointer fragment in {reference:?}",
                document_path.display()
            );
            assert!(
                target_document.pointer(fragment).is_some(),
                "{} contains unresolved reference {reference:?}",
                document_path.display()
            );
        }
    }
}

fn definition<'a>(schema: &'a Value, name: &str) -> &'a Value {
    schema
        .pointer(&format!("/$defs/{name}"))
        .unwrap_or_else(|| panic!("schema is missing $defs/{name}"))
}

fn assert_closed_object(schema: &Value, name: &str) {
    let value = definition(schema, name);
    assert_eq!(
        value.get("type").and_then(Value::as_str),
        Some("object"),
        "$defs/{name} should be an object"
    );
    assert_eq!(
        value.get("additionalProperties").and_then(Value::as_bool),
        Some(false),
        "$defs/{name} must reject undeclared fields"
    );
    assert!(
        value.get("properties").and_then(Value::as_object).is_some(),
        "$defs/{name} should declare properties"
    );
}

fn assert_one_of_objects_are_closed(schema: &Value, name: &str) {
    let variants = definition(schema, name)
        .get("oneOf")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("$defs/{name} should contain oneOf"));
    assert!(!variants.is_empty(), "$defs/{name} should contain variants");
    for (index, variant) in variants.iter().enumerate() {
        assert_eq!(
            variant.get("type").and_then(Value::as_str),
            Some("object"),
            "$defs/{name}/oneOf/{index} should be an object"
        );
        assert_eq!(
            variant.get("additionalProperties").and_then(Value::as_bool),
            Some(false),
            "$defs/{name}/oneOf/{index} must reject undeclared fields"
        );
    }
}

fn collect_reachable_property_names(
    schema: &Value,
    value: &Value,
    visited_definitions: &mut HashSet<String>,
    property_names: &mut BTreeSet<String>,
) {
    match value {
        Value::Object(object) => {
            if let Some(properties) = object.get("properties").and_then(Value::as_object) {
                property_names.extend(properties.keys().cloned());
            }

            if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
                if let Some(name) = reference.strip_prefix("#/$defs/") {
                    if visited_definitions.insert(name.to_owned()) {
                        collect_reachable_property_names(
                            schema,
                            definition(schema, name),
                            visited_definitions,
                            property_names,
                        );
                    }
                }
            }

            for child in object.values() {
                collect_reachable_property_names(
                    schema,
                    child,
                    visited_definitions,
                    property_names,
                );
            }
        }
        Value::Array(array) => {
            for child in array {
                collect_reachable_property_names(
                    schema,
                    child,
                    visited_definitions,
                    property_names,
                );
            }
        }
        _ => {}
    }
}

fn reachable_property_names(schema: &Value, root_definition: &str) -> BTreeSet<String> {
    let mut visited_definitions = HashSet::from([root_definition.to_owned()]);
    let mut property_names = BTreeSet::new();
    collect_reachable_property_names(
        schema,
        definition(schema, root_definition),
        &mut visited_definitions,
        &mut property_names,
    );
    property_names
}

#[test]
fn connection_admin_openapi_has_exact_routes_operations_and_safe_contracts() {
    let docs = docs_root();
    let openapi_path = docs.join(OPENAPI_RELATIVE_PATH);
    let openapi = load_json(&openapi_path);

    assert_eq!(
        openapi.get("openapi").and_then(Value::as_str),
        Some("3.1.0")
    );
    assert_references_resolve(&openapi_path, &openapi);

    let paths = openapi
        .get("paths")
        .and_then(Value::as_object)
        .expect("OpenAPI paths should be an object");
    let expected_paths: BTreeSet<_> = EXPECTED_OPERATIONS
        .iter()
        .map(|operation| operation.path)
        .collect();
    let actual_paths: BTreeSet<_> = paths.keys().map(String::as_str).collect();
    assert_eq!(
        actual_paths, expected_paths,
        "the v1 Connection admin path surface changed"
    );

    let mut actual_operation_count = 0;
    let mut operation_ids = BTreeSet::new();
    for operation in EXPECTED_OPERATIONS {
        let operation_value = paths
            .get(operation.path)
            .and_then(|path| path.get(operation.method))
            .unwrap_or_else(|| {
                panic!(
                    "OpenAPI is missing {} {}",
                    operation.method.to_ascii_uppercase(),
                    operation.path
                )
            });
        assert_eq!(
            operation_value.get("operationId").and_then(Value::as_str),
            Some(operation.operation_id),
            "{} {} has the wrong operationId",
            operation.method.to_ascii_uppercase(),
            operation.path
        );
        assert!(
            operation_ids.insert(operation.operation_id),
            "operationId {} is duplicated",
            operation.operation_id
        );

        match operation.request_definition {
            Some(request_definition) => assert_eq!(
                operation_value.pointer("/requestBody/content/application~1json/schema/$ref"),
                Some(&Value::String(schema_reference(request_definition))),
                "{} {} should use the documented request schema",
                operation.method.to_ascii_uppercase(),
                operation.path
            ),
            None => assert!(
                operation_value.get("requestBody").is_none(),
                "{} {} must not accept a request body",
                operation.method.to_ascii_uppercase(),
                operation.path
            ),
        }

        assert_eq!(
            operation_value.pointer(&format!(
                "/responses/{}/content/application~1json/schema/$ref",
                operation.success_status
            )),
            Some(&Value::String(schema_reference(
                operation.response_definition
            ))),
            "{} {} should use the documented safe response schema",
            operation.method.to_ascii_uppercase(),
            operation.path
        );
    }

    const HTTP_METHODS: &[&str] = &[
        "get", "put", "post", "delete", "options", "head", "patch", "trace",
    ];
    for path in paths.values() {
        let path = path
            .as_object()
            .expect("each OpenAPI path should be an object");
        actual_operation_count += path
            .keys()
            .filter(|key| HTTP_METHODS.contains(&key.as_str()))
            .count();
    }
    assert_eq!(
        actual_operation_count,
        EXPECTED_OPERATIONS.len(),
        "the v1 Connection admin operation surface changed"
    );

    let security = openapi
        .get("security")
        .and_then(Value::as_array)
        .expect("OpenAPI should declare global authentication alternatives");
    assert_eq!(
        security.len(),
        2,
        "bearer and session-cookie authentication must be alternatives"
    );
    assert_eq!(security[0].as_object().map(|value| value.len()), Some(1));
    assert_eq!(
        security[0].pointer("/bearerAuth"),
        Some(&Value::Array(Vec::new()))
    );
    assert_eq!(security[1].as_object().map(|value| value.len()), Some(1));
    assert_eq!(
        security[1].pointer("/cookieAuth"),
        Some(&Value::Array(Vec::new()))
    );

    let session_cookie = openapi
        .pointer("/components/securitySchemes/cookieAuth")
        .expect("OpenAPI should document session-cookie authentication");
    assert_eq!(
        session_cookie.get("type").and_then(Value::as_str),
        Some("apiKey")
    );
    assert_eq!(
        session_cookie.get("in").and_then(Value::as_str),
        Some("cookie")
    );
    assert_eq!(
        session_cookie.get("name").and_then(Value::as_str),
        Some("session"),
        "the schema should show the default cookie name"
    );
    let session_description = session_cookie
        .get("description")
        .and_then(Value::as_str)
        .expect("cookieAuth should describe configurable cookie and CSRF behavior");
    for required_text in [
        "AUTH_COOKIE_NAME",
        "CSRF_COOKIE_NAME",
        "CSRF_HEADER_NAME",
        "x-csrf-token",
    ] {
        assert!(
            session_description.contains(required_text),
            "cookieAuth description should mention {required_text}"
        );
    }
    let lowercase_description = session_description.to_ascii_lowercase();
    assert!(
        lowercase_description.contains("double-submit"),
        "cookieAuth should document the double-submit CSRF requirement"
    );

    for (scheme, location, name, setting) in [
        ("csrfCookie", "cookie", "csrf_token", "CSRF_COOKIE_NAME"),
        ("csrfHeader", "header", "x-csrf-token", "CSRF_HEADER_NAME"),
    ] {
        let value = openapi
            .pointer(&format!("/components/securitySchemes/{scheme}"))
            .unwrap_or_else(|| panic!("OpenAPI should define {scheme}"));
        assert_eq!(value.get("type").and_then(Value::as_str), Some("apiKey"));
        assert_eq!(value.get("in").and_then(Value::as_str), Some(location));
        assert_eq!(value.get("name").and_then(Value::as_str), Some(name));
        let description = value
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("{scheme} should have a description"));
        assert!(description.contains(setting));
    }

    let expected_mutation_security = json!([
        {"bearerAuth": []},
        {"cookieAuth": [], "csrfCookie": [], "csrfHeader": []}
    ]);
    for operation in EXPECTED_OPERATIONS
        .iter()
        .filter(|operation| matches!(operation.method, "post" | "put" | "delete"))
    {
        let actual = paths
            .get(operation.path)
            .and_then(|path| path.get(operation.method))
            .and_then(|value| value.get("security"));
        assert_eq!(
            actual,
            Some(&expected_mutation_security),
            "{} {} must require bearer auth or cookie auth plus both CSRF values",
            operation.method.to_ascii_uppercase(),
            operation.path
        );
    }
}

#[test]
fn connection_admin_json_schema_is_strict_resolvable_and_secret_safe() {
    let docs = docs_root();
    let schema_path = docs.join(SCHEMA_RELATIVE_PATH);
    let schema = load_json(&schema_path);

    assert_eq!(
        schema.get("$schema").and_then(Value::as_str),
        Some("https://json-schema.org/draft/2020-12/schema")
    );
    let definitions = schema
        .get("$defs")
        .and_then(Value::as_object)
        .expect("JSON Schema should contain a non-empty $defs object");
    assert!(
        !definitions.is_empty(),
        "JSON Schema $defs must not be empty"
    );
    assert_references_resolve(&schema_path, &schema);
    jsonschema::validator_for(&schema).expect("connection admin JSON Schema should compile");

    for name in [
        "ConnectionCreateRequest",
        "ConnectionReplaceRequest",
        "CreateTls",
        "MutationTls",
        "SecretCreateRequest",
        "SecretRotateRequest",
        "OpenApiPreviewRequest",
        "OpenApiRegisterRequest",
        "PlaygroundRequest",
        "ToolDefinition",
        "ToolTransform",
        "TransformParameterShape",
        "TransformAgentProperty",
        "TransformWireBinding",
        "TransformResponseBinding",
        "OpenApiOverlayDocument",
        "OpenApiOverlayTool",
        "OpenApiOverlayParameter",
        "OpenApiOverlayShape",
        "OpenApiOverlayWireBinding",
        "OpenApiOverlayResponseBinding",
        "OpenApiOverlayResponse",
        "CapabilityTransformSummary",
        "CapabilityTransformShapeSummary",
        "TransformWarning",
        "TransformProblem",
    ] {
        assert_closed_object(&schema, name);
    }
    for name in [
        "CreateAuthentication",
        "MutationAuthentication",
        "Discovery",
    ] {
        assert_one_of_objects_are_closed(&schema, name);
    }

    let create = definition(&schema, "ConnectionCreateRequest");
    assert_eq!(
        create
            .pointer("/properties/authentication/$ref")
            .and_then(Value::as_str),
        Some("#/$defs/CreateAuthentication")
    );
    assert_eq!(
        create
            .pointer("/properties/tls/$ref")
            .and_then(Value::as_str),
        Some("#/$defs/CreateTls")
    );
    let create_properties = reachable_property_names(&schema, "ConnectionCreateRequest");
    assert!(
        create_properties
            .iter()
            .all(|property| !property.ends_with("_configured")),
        "POST requests must reject PUT-only configured markers"
    );

    let replace = definition(&schema, "ConnectionReplaceRequest");
    assert!(
        replace
            .get("required")
            .and_then(Value::as_array)
            .is_some_and(|required| required.iter().any(|field| field == "enabled")),
        "replacement requests should require enabled"
    );
    let replace_properties = reachable_property_names(&schema, "ConnectionReplaceRequest");
    assert!(
        replace_properties.contains("secret_configured")
            && replace_properties.contains("client_private_key_configured"),
        "PUT requests should retain explicit redaction markers"
    );

    for name in [
        "ConnectionList",
        "ConnectionDetail",
        "ConnectionDeleted",
        "ConnectionTestResult",
        "CatalogPublishResult",
        "OpenApiPreviewResponse",
        "SecretList",
        "SafeSecretAlias",
        "SecretDeleted",
        "CapabilityList",
        "CapabilityDetail",
        "PlaygroundHttpResult",
        "PlaygroundMcpResult",
        "PlaygroundCompositeStepSummary",
        "PlaygroundCompositeResult",
        "Error",
        "ReasonedError",
        "ValidationError",
        "DependencyConflict",
    ] {
        assert_closed_object(&schema, name);
    }

    let safe_response_definitions = [
        "ConnectionList",
        "ConnectionDetail",
        "ConnectionDeleted",
        "ConnectionTestResult",
        "CatalogPublishResult",
        "OpenApiPreviewResponse",
        "SecretList",
        "SafeSecretAlias",
        "SecretDeleted",
        "CapabilityList",
        "CapabilityDetail",
        "PlaygroundResult",
        "Error",
        "ReasonedError",
        "ValidationError",
        "DependencyConflict",
    ];
    let forbidden_secret_fields = [
        "secret_id",
        "client_secret_id",
        "client_private_key_id",
        "client_certificate_id",
        "ca_bundle_alias",
        "provider_locator",
        "provider_path",
        "provider_key",
        "environment_variable",
        "file_path",
        "ciphertext",
        "nonce",
        "key_id",
        "master_key",
        "private_key",
    ];
    for response_definition in safe_response_definitions {
        let properties = reachable_property_names(&schema, response_definition);
        for forbidden in forbidden_secret_fields {
            assert!(
                !properties.contains(forbidden),
                "$defs/{response_definition} exposes protected field {forbidden:?}"
            );
        }
    }

    let safe_alias_properties = reachable_property_names(&schema, "SafeSecretAlias");
    assert!(
        !safe_alias_properties.contains("value"),
        "safe secret-alias responses must never expose secret values"
    );
    assert_eq!(
        definition(&schema, "SafeSecretAlias")
            .pointer("/properties/provider/$ref")
            .and_then(Value::as_str),
        Some("#/$defs/SecretProvider"),
        "safe aliases may identify a provider class but not a provider locator"
    );

    let mutation_authentication = reachable_property_names(&schema, "MutationAuthentication");
    assert!(
        mutation_authentication.contains("secret_id"),
        "credential write requests should permit an explicit secret binding"
    );
    assert!(
        mutation_authentication.contains("client_secret_id"),
        "OAuth write requests should permit an explicit client-secret binding"
    );
    for name in ["SecretCreateRequest", "SecretRotateRequest"] {
        assert_eq!(
            definition(&schema, name)
                .pointer("/properties/value/writeOnly")
                .and_then(Value::as_bool),
            Some(true),
            "$defs/{name}.value should be accepted only as write-only input"
        );
    }
}

#[test]
fn connection_admin_request_schema_tracks_additional_header_validation() {
    let schema = load_json(&docs_root().join(SCHEMA_RELATIVE_PATH));
    let candidate = |enabled: bool, base_url: &str| {
        json!({
            "display_name": "Proxy-fronted API",
            "enabled": enabled,
            "kind": "http_api",
            "endpoint": {
                "base_url": base_url,
                "base_path": "/"
            },
            "authentication": { "type": "none" },
            "additional_headers": [
                { "header_name": "x-proxy-token" }
            ]
        })
    };

    for definition_name in ["ConnectionCreateRequest", "ConnectionReplaceRequest"] {
        let mut request_schema = schema.clone();
        request_schema
            .as_object_mut()
            .expect("admin schema should be an object")
            .insert(
                "$ref".to_owned(),
                Value::String(format!("#/$defs/{definition_name}")),
            );
        let validator = jsonschema::validator_for(&request_schema)
            .unwrap_or_else(|error| panic!("{definition_name} should compile: {error}"));

        assert!(
            validator.is_valid(&candidate(false, "https://api.example.test")),
            "{definition_name} should accept an HTTPS disabled draft without a secret binding"
        );
        assert!(
            !validator.is_valid(&candidate(false, "http://api.example.test")),
            "{definition_name} should reject every non-empty additional-header list over HTTP"
        );
        assert!(
            !validator.is_valid(&candidate(true, "https://api.example.test")),
            "{definition_name} should reject an enabled additional header without a secret binding"
        );

        let mut enabled_with_secret = candidate(true, "https://api.example.test");
        enabled_with_secret["additional_headers"][0]["secret_id"] = json!("proxy-token");
        assert!(
            validator.is_valid(&enabled_with_secret),
            "{definition_name} should accept an enabled additional header with a secret binding"
        );

        if definition_name == "ConnectionReplaceRequest" {
            let mut enabled_with_retained_secret = candidate(true, "https://api.example.test");
            enabled_with_retained_secret["additional_headers"][0]["secret_configured"] =
                json!(true);
            assert!(
                validator.is_valid(&enabled_with_retained_secret),
                "replacement should accept a true configured marker for a retained binding"
            );

            enabled_with_retained_secret["additional_headers"][0]["secret_configured"] =
                json!(false);
            assert!(
                !validator.is_valid(&enabled_with_retained_secret),
                "replacement should reject a cleared binding on an enabled additional header"
            );
        }
    }
}

#[test]
fn connection_admin_closed_copies_accept_overlay_runtime_fields_and_exact_version() {
    let schema = load_json(&docs_root().join(SCHEMA_RELATIVE_PATH));
    let validates = |name: &str, instance: &Value| {
        let envelope = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$defs": schema["$defs"].clone(),
            "$ref": format!("#/$defs/{name}")
        });
        jsonschema::validator_for(&envelope)
            .unwrap_or_else(|error| panic!("$defs/{name} should compile: {error}"))
            .is_valid(instance)
    };

    let mapping = json!({
        "method": "POST",
        "path_template": "/companies/{id}",
        "query_params": [],
        "body": {"mode": "body_args_json"}
    });
    let definition = json!({
        "name": "UpdateOneCompany",
        "description": "Update one company",
        "input_json_schema": {
            "type": "object",
            "properties": {
                "revenue_amount": {"type": "number"},
                "revenue_currency": {"type": "string"}
            },
            "required": ["revenue_amount", "revenue_currency"],
            "additionalProperties": false
        },
        "source": {
            "type": "open_api",
            "connection_id": "billing-api",
            "operation_id": "UpdateOneCompany",
            "catalog_revision": 1
        },
        "target": {
            "type": "http",
            "connection_id": "billing-api",
            "mapping": mapping.clone()
        },
        "upstream": mapping,
        "visibility": "composite_only",
        "transform": {
            "parameters": [{
                "wire_property": "annualRecurringRevenue",
                "wire_required": true,
                "agent": [
                    {"name": "revenue_amount", "schema": {"type": "number"}},
                    {"name": "revenue_currency", "schema": {"type": "string"}}
                ],
                "wire": [
                    {
                        "pointer": "/amountMicros",
                        "from": "revenue_amount",
                        "codec": [{
                            "kind": "decimal_scale",
                            "scale": 6,
                            "wire_encoding": "integer_string",
                            "max_integer_digits": 24
                        }]
                    },
                    {
                        "pointer": "/currencyCode",
                        "const": "USD"
                    }
                ],
                "response": [{
                    "agent_property": "revenue_amount",
                    "from": "/amountMicros",
                    "codec": [{
                        "kind": "decimal_scale",
                        "scale": 6,
                        "wire_encoding": "integer_string",
                        "max_integer_digits": 24
                    }]
                }]
            }],
            "response_root": "/data/updateCompany"
        }
    });
    assert!(
        validates("ToolDefinition", &definition),
        "the closed stored-definition copy must accept the compiled transform"
    );
    assert!(validates(
        "CapabilityMapping",
        &json!({
            "type": "http",
            "method": "POST",
            "path_template": "/companies/{id}",
            "query_params": [],
            "body": {"mode": "body_args_json"}
        })
    ));

    assert!(validates(
        "OpenApiOverlayDocument",
        &json!({
            "schema_version": "0.1.0",
            "defaults": {"response_root": "/data/*"},
            "shapes": {
                "money": {
                    "agent": {
                        "amount": {"type": "number"},
                        "currency": {"type": "string"}
                    },
                    "required": ["amount", "currency"],
                    "wire": {
                        "/amountMicros": {
                            "from": "amount",
                            "codec": {
                                "kind": "decimal_scale",
                                "scale": 6
                            }
                        },
                        "/currencyCode": {"from": "currency"}
                    }
                }
            },
            "tools": {
                "UpdateOneCompany": {
                    "parameters": {
                        "annualRecurringRevenue": {
                            "shape": {"$use": "money", "prefix": "revenue"}
                        }
                    },
                    "response": {
                        "root": "/data/updateCompany",
                        "fields": {
                            "annualRecurringRevenue": {"$use": "money"}
                        }
                    }
                }
            }
        })
    ));
    assert!(!validates(
        "OpenApiOverlayDocument",
        &json!({"schema_version": "0.1.1"})
    ));

    let safe_summary = json!({
        "parameters": [{
            "wire_property": "annualRecurringRevenue",
            "agent_properties": ["revenue_amount", "revenue_currency"],
            "wire_pointer_count": 2,
            "response_properties": ["revenue_amount"],
            "constant_binding_count": 1
        }],
        "response_fields": [],
        "has_response_root": true
    });
    assert!(validates("CapabilityTransformSummary", &safe_summary));
    for (field, value) in [
        ("wire_pointers", json!(["/amountMicros"])),
        ("constant_values", json!(["USD"])),
        ("codecs", json!(["decimal_scale"])),
        ("agent_schemas", json!([{"type": "number"}])),
    ] {
        let mut unsafe_summary = safe_summary.clone();
        unsafe_summary["parameters"][0][field] = value;
        assert!(
            !validates("CapabilityTransformSummary", &unsafe_summary),
            "inventory summaries must not expose {field}"
        );
    }
    let mut selector_leak = safe_summary;
    selector_leak["response_root"] = json!("/data/updateCompany");
    assert!(
        !validates("CapabilityTransformSummary", &selector_leak),
        "inventory summaries expose only has_response_root, never selector text"
    );

    assert!(validates(
        "PlaygroundHttpResult",
        &json!({
            "kind": "http",
            "status": 200,
            "body": {"type": "json", "value": {}},
            "warnings": [{"path": "/data/0/value", "reason": "response binding pointer is missing"}]
        })
    ));
    let exact_warning_limit = (0..32)
        .map(|index| json!({"path": format!("/data/{index}"), "reason": "decode failed"}))
        .collect::<Vec<_>>();
    assert!(validates(
        "PlaygroundHttpResult",
        &json!({
            "kind": "http",
            "status": 200,
            "body": {"type": "json", "value": {}},
            "warnings": exact_warning_limit
        })
    ));
    let too_many_warnings = (0..33)
        .map(|index| json!({"path": format!("/data/{index}"), "reason": "decode failed"}))
        .collect::<Vec<_>>();
    assert!(!validates(
        "PlaygroundHttpResult",
        &json!({
            "kind": "http",
            "status": 200,
            "body": {"type": "json", "value": {}},
            "warnings": too_many_warnings
        })
    ));
    assert!(validates(
        "ReasonedError",
        &json!({
            "error": "invalid_params",
            "reason": "transform rejected",
            "problems": [{
                "path": "/revenue_amount",
                "keyword": "codec",
                "reason": "value has too many fraction digits"
            }]
        })
    ));
    assert!(!validates(
        "ReasonedError",
        &json!({
            "error": "invalid_params",
            "reason": "transform rejected",
            "problems": [{
                "path": "/revenue_amount",
                "keyword": "coercion",
                "reason": "not part of the wire contract"
            }]
        })
    ));

    let composite_definition = json!({
        "name": "create_note_for_records",
        "description": "Create and attach a note.",
        "input_json_schema": {
            "type": "object",
            "properties": { "title": { "type": "string" } },
            "required": ["title"],
            "additionalProperties": false
        },
        "target": { "type": "composite", "connection_id": "billing-api" },
        "source": {
            "type": "open_api",
            "connection_id": "billing-api",
            "catalog_revision": 2
        },
        "upstream": { "method": "COMPOSITE", "path_template": "/" },
        "composite": {
            "steps": [{
                "id": "create",
                "tool": "createOneNote",
                "arguments": { "title": { "$input": "title" } }
            }],
            "result": {
                "id": { "$step": "create", "pointer": "/data/createNote/id" }
            }
        }
    });
    assert!(
        validates("ToolDefinition", &composite_definition),
        "the stored-definition copy must accept the exact composite sentinel and mapping"
    );
    let mut malformed_sentinel = composite_definition.clone();
    malformed_sentinel["upstream"]["path_template"] = json!("/network");
    assert!(
        !validates("ToolDefinition", &malformed_sentinel),
        "a composite target must use the exact non-network sentinel"
    );

    let overlay_with_composite = json!({
        "schema_version": "0.1.0",
        "composites": {
            "create_note_for_records": {
                "description": "Create and attach a note.",
                "input": {
                    "properties": { "title": { "type": "string" } },
                    "required": ["title"]
                },
                "steps": [{
                    "id": "create",
                    "tool": "createOneNote",
                    "arguments": { "title": { "$input": "title" } }
                }]
            }
        }
    });
    assert!(
        validates("OpenApiOverlayDocument", &overlay_with_composite),
        "the admin contract must accept the closed composite authoring model"
    );
    assert!(validates(
        "OpenApiOverlayCompositeReport",
        &json!({
            "name": "create_note_for_records",
            "steps_max": 0,
            "policy_entry_present": false
        })
    ));
    assert!(validates(
        "CapabilityMapping",
        &json!({
            "type": "composite",
            "steps": [{
                "id": "create",
                "tool": "createOneNote",
                "method": "POST",
                "path_template": "/notes",
                "has_compensation": true,
                "for_each": false
            }]
        })
    ));
    assert!(validates(
        "PlaygroundResult",
        &json!({
            "kind": "composite",
            "status": 200,
            "body": { "note_id": "note-1" },
            "steps_summary": [{
                "index": 0,
                "id": "create",
                "tool": "createOneNote",
                "method": "POST",
                "path_template": "/notes",
                "outcome": "succeeded",
                "upstream_status": 201,
                "latency_ms": 4
            }]
        })
    ));
}
