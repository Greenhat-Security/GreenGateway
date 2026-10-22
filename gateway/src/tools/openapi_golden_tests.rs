//! Golden tests pinning what the OpenAPI 3.x generator and binder produce.
//!
//! `testdata/openapi3-golden/expected.json` was recorded from the generator
//! before Swagger 2.0 import existed (issue #443). Converting other document
//! formats is layered in front of the 3.x path, so every 3.x document must
//! keep producing exactly this output: tool definitions, name fallbacks,
//! skips, security metadata, transform metadata, declared response schemas,
//! the bindings for each authentication profile, and the error text for
//! rejected documents. A difference here is a behaviour change for stored
//! catalogs and needs its own review, not a fixture refresh.

use serde_json::{json, Map, Value};

use super::*;
use crate::connections::model::{OAuthClientAuthMethod, SubjectTokenSource};

const EXPECTED: &str = include_str!("testdata/openapi3-golden/expected.json");

fn golden_documents() -> [(&'static str, &'static str); 3] {
    [
        (
            "core.yaml",
            include_str!("testdata/openapi3-golden/core.yaml"),
        ),
        (
            "security.yaml",
            include_str!("testdata/openapi3-golden/security.yaml"),
        ),
        (
            "json-document.json",
            include_str!("testdata/openapi3-golden/json-document.json"),
        ),
    ]
}

/// Documents the 3.x path accepts or rejects that sit closest to the new
/// conversion branch: wrong or missing versions, a document carrying both
/// version fields, and the generator's own reference and path checks.
fn golden_edge_documents() -> [(&'static str, &'static str); 7] {
    [
        (
            "openapi-2-version.yaml",
            "openapi: \"2.0\"\ninfo: { title: Old, version: 1.0.0 }\npaths: {}\n",
        ),
        (
            "missing-version.yaml",
            "info: { title: Missing, version: 1.0.0 }\npaths: {}\n",
        ),
        (
            "both-version-fields.yaml",
            "openapi: 3.0.3\nswagger: \"2.0\"\ninfo: { title: Both, version: 1.0.0 }\npaths:\n  /ping:\n    get:\n      operationId: ping\n",
        ),
        (
            "non-local-reference.yaml",
            "openapi: 3.0.3\ninfo: { title: Remote, version: 1.0.0 }\npaths:\n  /widgets:\n    post:\n      operationId: createWidget\n      requestBody:\n        $ref: 'shared.yaml#/components/requestBodies/Widget'\n",
        ),
        (
            "relative-path.yaml",
            "openapi: 3.0.3\ninfo: { title: Relative, version: 1.0.0 }\npaths:\n  widgets:\n    get:\n      operationId: listWidgets\n",
        ),
        ("truncated.json", "{\"openapi\": \"3.0.3\", \"paths\": {"),
        ("not-a-document.yaml", "- just\n- a list\n"),
    ]
}

fn golden_authentications() -> Vec<(&'static str, ConnectionAuthentication)> {
    vec![
        ("none", ConnectionAuthentication::None),
        (
            "header_api_key",
            ConnectionAuthentication::HeaderApiKey {
                header_name: "x-api-key".to_owned(),
                secret_id: Some("golden-header-secret".to_owned()),
            },
        ),
        (
            "static_bearer",
            ConnectionAuthentication::StaticBearer {
                secret_id: Some("golden-bearer-secret".to_owned()),
            },
        ),
        (
            "oauth2_client_credentials",
            ConnectionAuthentication::OAuth2ClientCredentials {
                client_id: "golden-client".to_owned(),
                client_secret_id: Some("golden-client-secret".to_owned()),
                token_url: "https://idp.example.test/oauth/token".to_owned(),
                scopes: vec!["widgets.read".to_owned()],
                audience: None,
                resource: None,
                client_auth_method: OAuthClientAuthMethod::ClientSecretBasic,
            },
        ),
        (
            "delegated_issuer_token",
            ConnectionAuthentication::DelegatedIssuerToken {
                token_exchange_url: "https://issuer.example.test/token".to_owned(),
                client_id: "golden-client".to_owned(),
                client_secret_id: Some("golden-client-secret".to_owned()),
                requested_scopes: vec!["widgets.read".to_owned()],
                audience: None,
                resource: None,
                subject_token_source: SubjectTokenSource::CallerAssertion,
                revocation_url: None,
            },
        ),
    ]
}

fn debug_string(value: &impl fmt::Debug) -> Value {
    Value::String(format!("{value:?}"))
}

fn generation_summary(generation: &OpenApiToolGeneration) -> Value {
    let transform_metadata = generation
        .transform_metadata
        .iter()
        .map(|(tool_name, metadata)| {
            (
                tool_name.clone(),
                json!({
                    "body_properties": metadata.body_properties,
                    "array_request_body": metadata.array_request_body,
                    "responses": metadata.responses,
                }),
            )
        })
        .collect::<Map<_, _>>();
    let declared_success_response_schemas = generation
        .definitions
        .iter()
        .map(|definition| {
            let schemas = generation
                .declared_success_response_schemas(&definition.name)
                .expect("golden response schemas should resolve")
                .into_iter()
                .map(|declared| json!({ "status": declared.status, "schema": declared.schema }))
                .collect::<Vec<_>>();
            (definition.name.clone(), Value::Array(schemas))
        })
        .collect::<Map<_, _>>();
    json!({
        "tools_file": generation.tools_file_value(),
        "operation_id_fallbacks": generation
            .operation_id_fallbacks
            .iter()
            .map(|fallback| json!({
                "method": fallback.method,
                "path_template": fallback.path_template,
                "original_operation_id": fallback.original_operation_id,
                "generated_name": fallback.generated_name,
                "reason": debug_string(&fallback.reason),
            }))
            .collect::<Vec<_>>(),
        "skipped_operations": generation
            .skipped_operations
            .iter()
            .map(|skipped| json!({
                "method": skipped.method,
                "path_template": skipped.path_template,
                "original_operation_id": skipped.original_operation_id,
                "reason": debug_string(&skipped.reason),
            }))
            .collect::<Vec<_>>(),
        "api_key_header_auth_requirements": generation
            .api_key_header_auth_requirements
            .iter()
            .map(|requirement| json!({
                "tool_name": requirement.tool_name,
                "method": requirement.method,
                "path_template": requirement.path_template,
                "scheme_name": requirement.scheme_name,
                "header_name": requirement.header_name,
            }))
            .collect::<Vec<_>>(),
        "security_requirements": generation
            .security_requirements
            .iter()
            .map(|security| json!({
                "tool_name": security.tool_name,
                "method": security.method,
                "path_template": security.path_template,
                "operation_id": security.operation_id,
                "alternatives": security
                    .alternatives
                    .iter()
                    .map(|alternative| alternative
                        .members
                        .iter()
                        .map(debug_string)
                        .collect::<Vec<_>>())
                    .collect::<Vec<_>>(),
            }))
            .collect::<Vec<_>>(),
        "transform_metadata": transform_metadata,
        "declared_success_response_schemas": declared_success_response_schemas,
    })
}

fn binding_summary(binding: &OpenApiToolBinding) -> Value {
    json!({
        "definitions": binding.definitions,
        "security_selections": binding
            .security_selections
            .iter()
            .map(|selection| json!({
                "tool_name": selection.tool_name,
                "selected_scheme_names": selection.selected_scheme_names,
            }))
            .collect::<Vec<_>>(),
        "incompatibilities": binding
            .incompatibilities
            .iter()
            .map(|incompatibility| json!({
                "tool_name": incompatibility.tool_name,
                "reason": debug_string(&incompatibility.reason),
            }))
            .collect::<Vec<_>>(),
    })
}

type Generate = fn(&str, &str) -> Result<OpenApiToolGeneration, OpenApiToolGenerationError>;

fn document_summary(generate: Generate, source: &str, contents: &str) -> Value {
    let generation = match generate(source, contents) {
        Ok(generation) => generation,
        Err(error) => return json!({ "error": error.to_string() }),
    };
    let connection_id = ConnectionId::parse("golden-api").expect("golden ID should be valid");
    let mut bindings = Map::new();
    for (name, authentication) in golden_authentications() {
        let preview = bind_generated_openapi_tools(&generation, &connection_id, &authentication)
            .expect("golden preview binding should succeed");
        let confirmed = bind_generated_openapi_tools_with_confirmations(
            &generation,
            &connection_id,
            &authentication,
            &preview.security_selections,
        )
        .expect("golden preview selections should confirm");
        bindings.insert(
            name.to_owned(),
            json!({
                "preview": binding_summary(&preview),
                "confirmed": binding_summary(&confirmed),
            }),
        );
    }
    json!({
        "generation": generation_summary(&generation),
        "bindings": bindings,
    })
}

fn actual_golden(generate: Generate) -> Value {
    let documents = golden_documents()
        .into_iter()
        .chain(golden_edge_documents())
        .map(|(source, contents)| {
            (
                source.to_owned(),
                document_summary(generate, source, contents),
            )
        })
        .collect::<Map<_, _>>();
    json!({ "documents": documents })
}

fn assert_matches_golden(generate: Generate, entry_point: &str) {
    let expected: Value =
        serde_json::from_str(EXPECTED).expect("golden expectation should be valid JSON");
    let actual = actual_golden(generate);
    let expected_documents = expected["documents"]
        .as_object()
        .expect("golden expectation should list documents");
    let actual_documents = actual["documents"]
        .as_object()
        .expect("actual golden should list documents");
    assert_eq!(
        actual_documents.keys().collect::<Vec<_>>(),
        expected_documents.keys().collect::<Vec<_>>(),
        "golden document set changed"
    );
    for (source, expected_summary) in expected_documents {
        assert_eq!(
            &actual_documents[source], expected_summary,
            "{entry_point} output for golden OpenAPI 3.x document {source} changed"
        );
    }
}

#[test]
fn openapi_3_generation_and_binding_match_the_pre_conversion_golden() {
    assert_matches_golden(
        generate_tools_from_openapi_str,
        "generate_tools_from_openapi_str",
    );
}

/// Managed Connections switched to the converting entry point; for every
/// OpenAPI 3.x document, and every document it rejects, it must be the old
/// entry point exactly.
#[test]
fn managed_connection_entry_point_matches_the_golden_for_openapi_3_documents() {
    assert_matches_golden(
        generate_tools_from_api_document_str,
        "generate_tools_from_api_document_str",
    );
    for (source, contents) in golden_documents()
        .into_iter()
        .chain(golden_edge_documents())
    {
        if let Ok(generation) = generate_tools_from_api_document_str(source, contents) {
            assert!(
                generation.conversion.is_none(),
                "{source} must not be reported as converted"
            );
        }
    }
}

#[test]
fn golden_documents_exercise_every_reported_category() {
    let actual = actual_golden(generate_tools_from_openapi_str);
    let core = &actual["documents"]["core.yaml"]["generation"];
    assert!(
        !core["operation_id_fallbacks"]
            .as_array()
            .expect("fallbacks should be an array")
            .is_empty()
            && !core["skipped_operations"]
                .as_array()
                .expect("skips should be an array")
                .is_empty(),
        "the core golden document must keep covering name fallbacks and skips"
    );
    let security = &actual["documents"]["security.yaml"]["bindings"];
    for profile in [
        "header_api_key",
        "static_bearer",
        "oauth2_client_credentials",
    ] {
        assert!(
            !security[profile]["preview"]["security_selections"]
                .as_array()
                .expect("selections should be an array")
                .is_empty(),
            "the security golden document must bind at least one tool for {profile}"
        );
    }
    for (source, _) in golden_edge_documents() {
        let summary = &actual["documents"][source];
        if source == "both-version-fields.yaml" {
            assert!(
                summary.get("generation").is_some(),
                "a document declaring openapi 3.x stays on the 3.x path"
            );
        } else {
            assert!(
                summary.get("error").is_some(),
                "{source} must stay rejected"
            );
        }
    }
}
