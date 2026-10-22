//! Which Connection credential binds which OpenAPI security scheme, and the
//! reason the preview gives for every alternative that does not (issue #443).
//!
//! A user-consent `oauth2` flow (`authorizationCode`, `implicit` or
//! `password`) and `openIdConnect` need a token obtained for the user. A
//! `delegated_issuer_token` Connection supplies exactly that, one token per
//! caller, so it binds those schemes when it requests every scope the
//! operation requires; a credential shared by every caller never does.

use std::collections::BTreeMap;

use super::*;
use crate::connections::model::{OAuthClientAuthMethod, SubjectTokenSource};

const TOKEN_URL: &str = "https://idp.example.test/oauth/token";

fn delegated(requested_scopes: &[&str]) -> ConnectionAuthentication {
    ConnectionAuthentication::DelegatedIssuerToken {
        token_exchange_url: "https://issuer.example.test/oauth2/token-exchange".to_owned(),
        client_id: "greengateway".to_owned(),
        client_secret_id: Some("issuer-exchange-secret".to_owned()),
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

fn client_credentials(token_url: &str, scopes: &[&str]) -> ConnectionAuthentication {
    ConnectionAuthentication::OAuth2ClientCredentials {
        client_id: "service-client".to_owned(),
        client_secret_id: Some("service-client-secret".to_owned()),
        token_url: token_url.to_owned(),
        scopes: scopes.iter().map(|scope| (*scope).to_owned()).collect(),
        audience: None,
        resource: None,
        client_auth_method: OAuthClientAuthMethod::ClientSecretBasic,
    }
}

fn connection_id() -> ConnectionId {
    ConnectionId::parse("widgets-api").expect("connection ID should be valid")
}

const USER_CONSENT_SPEC: &str = r#"
openapi: 3.0.3
info: { title: User consent, version: 1.0.0 }
components:
  securitySchemes:
    AuthorizationCode:
      type: oauth2
      flows:
        authorizationCode:
          authorizationUrl: https://idp.example.test/oauth/authorize
          tokenUrl: https://idp.example.test/oauth/token
          scopes: { widgets.read: Read, widgets.write: Write }
    Implicit:
      type: oauth2
      flows:
        implicit:
          authorizationUrl: https://idp.example.test/oauth/authorize
          scopes: { widgets.read: Read }
    Password:
      type: oauth2
      flows:
        password:
          tokenUrl: https://idp.example.test/oauth/token
          scopes: { widgets.read: Read }
    Mixed:
      type: oauth2
      flows:
        clientCredentials:
          tokenUrl: https://idp.example.test/oauth/token
          scopes: { widgets.read: Read }
        authorizationCode:
          authorizationUrl: https://idp.example.test/oauth/authorize
          tokenUrl: https://idp.example.test/oauth/token
          scopes: { widgets.read: Read }
    Service:
      type: oauth2
      flows:
        clientCredentials:
          tokenUrl: https://idp.example.test/oauth/token
          scopes: { widgets.read: Read }
    OpenId:
      type: openIdConnect
      openIdConnectUrl: https://idp.example.test/.well-known/openid-configuration
paths:
  /code:
    get: { operationId: codeRead, security: [ { AuthorizationCode: [widgets.read] } ] }
    post: { operationId: codeWrite, security: [ { AuthorizationCode: [widgets.write, widgets.read] } ] }
  /implicit:
    get: { operationId: implicitRead, security: [ { Implicit: [widgets.read] } ] }
  /password:
    get: { operationId: passwordRead, security: [ { Password: [widgets.read] } ] }
  /mixed:
    get: { operationId: mixedRead, security: [ { Mixed: [widgets.read] } ] }
  /service:
    get: { operationId: serviceRead, security: [ { Service: [widgets.read] } ] }
  /openid:
    get: { operationId: openIdRead, security: [ { OpenId: [] } ] }
    post: { operationId: openIdWrite, security: [ { OpenId: [widgets.write] } ] }
"#;

fn user_consent_generation() -> OpenApiToolGeneration {
    generate_tools_from_openapi_str("user-consent.yaml", USER_CONSENT_SPEC)
        .expect("user-consent document should generate")
}

fn bound_names(binding: &OpenApiToolBinding) -> Vec<&str> {
    let mut names = binding
        .definitions
        .iter()
        .map(|definition| definition.name.as_str())
        .collect::<Vec<_>>();
    names.sort_unstable();
    names
}

/// Every incompatible tool with the reason code of each of its alternatives.
fn mismatch_codes(binding: &OpenApiToolBinding) -> BTreeMap<&str, Vec<&'static str>> {
    binding
        .incompatibilities
        .iter()
        .map(|incompatibility| {
            (
                incompatibility.tool_name.as_str(),
                incompatibility
                    .security_mismatches
                    .iter()
                    .map(|mismatch| mismatch.reason.as_str())
                    .collect(),
            )
        })
        .collect()
}

#[test]
fn user_consent_flows_and_open_id_connect_parse_with_their_required_scopes() {
    let generation = user_consent_generation();
    let members = generation
        .security_requirements
        .iter()
        .map(|security| {
            (
                security.tool_name.as_str(),
                security.alternatives[0].members.clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let read = vec!["widgets.read".to_owned()];
    assert_eq!(
        members["codeWrite"],
        vec![OpenApiSecuritySchemeRequirement::OAuth2UserConsent {
            scheme_name: "AuthorizationCode".to_owned(),
            required_scopes: vec!["widgets.read".to_owned(), "widgets.write".to_owned()],
        }]
    );
    for (tool_name, scheme_name) in [("implicitRead", "Implicit"), ("passwordRead", "Password")] {
        assert_eq!(
            members[tool_name],
            vec![OpenApiSecuritySchemeRequirement::OAuth2UserConsent {
                scheme_name: scheme_name.to_owned(),
                required_scopes: read.clone(),
            }]
        );
    }
    assert_eq!(
        members["mixedRead"],
        vec![OpenApiSecuritySchemeRequirement::OAuth2ClientCredentials {
            scheme_name: "Mixed".to_owned(),
            token_url: TOKEN_URL.to_owned(),
            required_scopes: read.clone(),
            user_consent: true,
        }]
    );
    assert_eq!(
        members["serviceRead"],
        vec![OpenApiSecuritySchemeRequirement::OAuth2ClientCredentials {
            scheme_name: "Service".to_owned(),
            token_url: TOKEN_URL.to_owned(),
            required_scopes: read,
            user_consent: false,
        }]
    );
    assert_eq!(
        members["openIdWrite"],
        vec![OpenApiSecuritySchemeRequirement::OpenIdConnect {
            scheme_name: "OpenId".to_owned(),
            required_scopes: vec!["widgets.write".to_owned()],
        }]
    );
}

#[test]
fn a_per_caller_credential_binds_user_consent_schemes_with_every_required_scope() {
    let generation = user_consent_generation();
    let binding =
        bind_generated_openapi_tools(&generation, &connection_id(), &delegated(&["widgets.read"]))
            .expect("binding should report incompatibilities, not fail");
    assert_eq!(
        bound_names(&binding),
        vec![
            "codeRead",
            "implicitRead",
            "mixedRead",
            "openIdRead",
            "passwordRead"
        ]
    );
    assert_eq!(
        mismatch_codes(&binding),
        BTreeMap::from([
            ("codeWrite", vec!["missing_scopes"]),
            ("openIdWrite", vec!["missing_scopes"]),
            ("serviceRead", vec!["requires_oauth2_client_credentials"]),
        ])
    );
    let code_write = binding
        .incompatibilities
        .iter()
        .find(|incompatibility| incompatibility.tool_name == "codeWrite")
        .expect("codeWrite should be incompatible");
    assert_eq!(
        code_write.security_mismatches,
        vec![OpenApiSecurityMismatch {
            scheme_names: vec!["AuthorizationCode".to_owned()],
            reason: OpenApiSecurityMismatchReason::MissingScopes {
                scopes: vec!["widgets.write".to_owned()],
            },
        }]
    );

    // Registration confirms exactly what the preview selected.
    let confirmed = bind_generated_openapi_tools_with_confirmations(
        &generation,
        &connection_id(),
        &delegated(&["widgets.read"]),
        &binding.security_selections,
    )
    .expect("the preview selections should confirm");
    assert_eq!(confirmed.definitions, binding.definitions);
    assert!(confirmed.incompatibilities.is_empty());

    // A confirmation naming an operation the credential cannot satisfy is
    // refused rather than bound.
    assert!(matches!(
        bind_generated_openapi_tools_with_confirmations(
            &generation,
            &connection_id(),
            &delegated(&["widgets.read"]),
            &[OpenApiToolSecuritySelection {
                tool_name: "codeWrite".to_owned(),
                selected_scheme_names: vec!["AuthorizationCode".to_owned()],
            }],
        ),
        Err(OpenApiToolBindingError::InvalidSecurityConfirmation { .. })
    ));

    // Every required scope must be requested: with both, the writes bind
    // too, and with none, only the scope-free OpenID Connect read does.
    let both = bind_generated_openapi_tools(
        &generation,
        &connection_id(),
        &delegated(&["widgets.read", "widgets.write"]),
    )
    .expect("binding should succeed");
    assert_eq!(
        mismatch_codes(&both),
        BTreeMap::from([("serviceRead", vec!["requires_oauth2_client_credentials"])])
    );
    let unscoped = bind_generated_openapi_tools(&generation, &connection_id(), &delegated(&[]))
        .expect("binding should succeed");
    assert_eq!(bound_names(&unscoped), vec!["openIdRead"]);
}

#[test]
fn a_shared_credential_never_binds_a_user_consent_scheme() {
    let generation = user_consent_generation();
    let binding = bind_generated_openapi_tools(
        &generation,
        &connection_id(),
        &client_credentials(TOKEN_URL, &["widgets.read", "widgets.write"]),
    )
    .expect("binding should report incompatibilities, not fail");
    assert_eq!(bound_names(&binding), vec!["mixedRead", "serviceRead"]);
    assert_eq!(
        mismatch_codes(&binding),
        BTreeMap::from([
            ("codeRead", vec!["oauth2_without_client_credentials"]),
            ("codeWrite", vec!["oauth2_without_client_credentials"]),
            ("implicitRead", vec!["oauth2_without_client_credentials"]),
            ("openIdRead", vec!["open_id_connect"]),
            ("openIdWrite", vec!["open_id_connect"]),
            ("passwordRead", vec!["oauth2_without_client_credentials"]),
        ])
    );

    for authentication in [
        ConnectionAuthentication::None,
        ConnectionAuthentication::StaticBearer {
            secret_id: Some("bearer-secret".to_owned()),
        },
        ConnectionAuthentication::HeaderApiKey {
            header_name: "x-api-key".to_owned(),
            secret_id: Some("header-secret".to_owned()),
        },
    ] {
        let binding = bind_generated_openapi_tools(&generation, &connection_id(), &authentication)
            .expect("binding should report incompatibilities, not fail");
        assert!(binding.definitions.is_empty());
        let codes = mismatch_codes(&binding);
        assert_eq!(codes["codeRead"], vec!["oauth2_without_client_credentials"]);
        assert_eq!(codes["openIdRead"], vec!["open_id_connect"]);
        assert_eq!(
            codes["mixedRead"],
            vec!["requires_oauth2_client_credentials"]
        );
    }
}

#[test]
fn malformed_user_consent_and_open_id_connect_schemes_fail_closed() {
    let generation = generate_tools_from_openapi_str(
        "malformed.yaml",
        r#"
openapi: 3.0.3
info: { title: Malformed, version: 1.0.0 }
components:
  securitySchemes:
    NoScopes:
      type: oauth2
      flows:
        authorizationCode:
          authorizationUrl: https://idp.example.test/oauth/authorize
          tokenUrl: https://idp.example.test/oauth/token
    UndeclaredScope:
      type: oauth2
      flows:
        implicit:
          authorizationUrl: https://idp.example.test/oauth/authorize
          scopes: { widgets.read: Read }
    NotAnObject:
      type: oauth2
      flows:
        password: https://idp.example.test/oauth/token
    NoFlows:
      type: oauth2
      flows: {}
    UnknownFlow:
      type: oauth2
      flows:
        deviceCode:
          tokenUrl: https://idp.example.test/oauth/token
          scopes: { widgets.read: Read }
    MixedUndeclared:
      type: oauth2
      flows:
        clientCredentials:
          tokenUrl: https://idp.example.test/oauth/token
          scopes: { widgets.read: Read }
        authorizationCode:
          authorizationUrl: https://idp.example.test/oauth/authorize
          tokenUrl: https://idp.example.test/oauth/token
          scopes: { widgets.other: Other }
    OpenIdWithoutUrl:
      type: openIdConnect
paths:
  /no-scopes:
    get: { operationId: noScopes, security: [ { NoScopes: [] } ] }
  /undeclared:
    get: { operationId: undeclaredScope, security: [ { UndeclaredScope: [widgets.write] } ] }
  /not-an-object:
    get: { operationId: notAnObject, security: [ { NotAnObject: [] } ] }
  /no-flows:
    get: { operationId: noFlows, security: [ { NoFlows: [] } ] }
  /unknown-flow:
    get: { operationId: unknownFlow, security: [ { UnknownFlow: [widgets.read] } ] }
  /mixed:
    get: { operationId: mixedUndeclared, security: [ { MixedUndeclared: [widgets.read] } ] }
  /openid:
    get: { operationId: openIdWithoutUrl, security: [ { OpenIdWithoutUrl: [] } ] }
"#,
    )
    .expect("malformed schemes should remain reviewable");
    let binding = bind_generated_openapi_tools(
        &generation,
        &connection_id(),
        &delegated(&["widgets.read", "widgets.write", "widgets.other"]),
    )
    .expect("binding should report incompatibilities, not fail");
    assert!(binding.definitions.is_empty());
    assert_eq!(
        mismatch_codes(&binding),
        BTreeMap::from([
            (
                "mixedUndeclared",
                vec!["requires_oauth2_client_credentials"]
            ),
            ("noFlows", vec!["oauth2_without_supported_flow"]),
            ("noScopes", vec!["invalid_security_scheme"]),
            ("notAnObject", vec!["invalid_security_scheme"]),
            ("openIdWithoutUrl", vec!["invalid_security_scheme"]),
            ("undeclaredScope", vec!["invalid_security_scheme"]),
            ("unknownFlow", vec!["oauth2_without_supported_flow"]),
        ])
    );
    // The client-credentials half of the mixed scheme still binds as before.
    let shared = bind_generated_openapi_tools(
        &generation,
        &connection_id(),
        &client_credentials(TOKEN_URL, &["widgets.read"]),
    )
    .expect("binding should succeed");
    assert_eq!(bound_names(&shared), vec!["mixedUndeclared"]);
}

/// The reasons for every alternative of the security golden document under
/// every credential type: the explanation an operator reads in the preview.
#[test]
fn every_incompatible_alternative_of_the_golden_document_says_why() {
    let generation = generate_tools_from_openapi_str(
        "security.yaml",
        include_str!("testdata/openapi3-golden/security.yaml"),
    )
    .expect("golden security document should generate");
    let expectations: [(&str, ConnectionAuthentication, &[(&str, &[&str])]); 5] = [
        (
            "none",
            ConnectionAuthentication::None,
            &[
                ("andAlternative", &["multiple_schemes"]),
                ("basicOnly", &["http_basic"]),
                ("bearerOnly", &["requires_static_bearer"]),
                ("cookieOnly", &["api_key_cookie"]),
                ("customOnly", &["unsupported_security_scheme_type"]),
                ("digestOnly", &["http_unsupported_scheme"]),
                ("inheritsDocumentSecurity", &["requires_header_api_key"]),
                ("invalidRequirementShape", &["invalid_security_scheme"]),
                ("invalidScopes", &["invalid_security_scheme"]),
                ("missingScheme", &["missing_security_scheme"]),
                ("mtlsOnly", &["mutual_tls"]),
                ("openIdOnly", &["open_id_connect"]),
                (
                    "orAlternatives",
                    &[
                        "api_key_query",
                        "requires_header_api_key",
                        "requires_header_api_key",
                    ],
                ),
                ("serviceRead", &["requires_oauth2_client_credentials"]),
                ("serviceUndeclaredScope", &["invalid_security_scheme"]),
                ("serviceWrite", &["requires_oauth2_client_credentials"]),
                ("userConsent", &["oauth2_without_client_credentials"]),
            ],
        ),
        (
            "header_api_key",
            ConnectionAuthentication::HeaderApiKey {
                header_name: "x-api-key".to_owned(),
                secret_id: Some("golden-header-secret".to_owned()),
            },
            &[
                ("andAlternative", &["multiple_schemes"]),
                ("basicOnly", &["http_basic"]),
                ("bearerOnly", &["requires_static_bearer"]),
                ("cookieOnly", &["api_key_cookie"]),
                ("customOnly", &["unsupported_security_scheme_type"]),
                ("digestOnly", &["http_unsupported_scheme"]),
                ("invalidRequirementShape", &["invalid_security_scheme"]),
                ("invalidScopes", &["invalid_security_scheme"]),
                ("missingScheme", &["missing_security_scheme"]),
                ("mtlsOnly", &["mutual_tls"]),
                ("openIdOnly", &["open_id_connect"]),
                ("serviceRead", &["requires_oauth2_client_credentials"]),
                ("serviceUndeclaredScope", &["invalid_security_scheme"]),
                ("serviceWrite", &["requires_oauth2_client_credentials"]),
                ("userConsent", &["oauth2_without_client_credentials"]),
            ],
        ),
        (
            "header_api_key_other_header",
            ConnectionAuthentication::HeaderApiKey {
                header_name: "x-unrelated-key".to_owned(),
                secret_id: Some("golden-header-secret".to_owned()),
            },
            &[
                ("andAlternative", &["multiple_schemes"]),
                ("basicOnly", &["http_basic"]),
                ("bearerOnly", &["requires_static_bearer"]),
                ("cookieOnly", &["api_key_cookie"]),
                ("customOnly", &["unsupported_security_scheme_type"]),
                ("digestOnly", &["http_unsupported_scheme"]),
                ("inheritsDocumentSecurity", &["api_key_header_mismatch"]),
                ("invalidRequirementShape", &["invalid_security_scheme"]),
                ("invalidScopes", &["invalid_security_scheme"]),
                ("missingScheme", &["missing_security_scheme"]),
                ("mtlsOnly", &["mutual_tls"]),
                ("openIdOnly", &["open_id_connect"]),
                (
                    "orAlternatives",
                    &[
                        "api_key_query",
                        "api_key_header_mismatch",
                        "api_key_header_mismatch",
                    ],
                ),
                ("serviceRead", &["requires_oauth2_client_credentials"]),
                ("serviceUndeclaredScope", &["invalid_security_scheme"]),
                ("serviceWrite", &["requires_oauth2_client_credentials"]),
                ("userConsent", &["oauth2_without_client_credentials"]),
            ],
        ),
        (
            "oauth2_client_credentials_elsewhere",
            client_credentials("https://other-idp.example.test/oauth/token", &[]),
            &[
                ("andAlternative", &["multiple_schemes"]),
                ("basicOnly", &["http_basic"]),
                ("bearerOnly", &["requires_static_bearer"]),
                ("cookieOnly", &["api_key_cookie"]),
                ("customOnly", &["unsupported_security_scheme_type"]),
                ("digestOnly", &["http_unsupported_scheme"]),
                ("inheritsDocumentSecurity", &["requires_header_api_key"]),
                ("invalidRequirementShape", &["invalid_security_scheme"]),
                ("invalidScopes", &["invalid_security_scheme"]),
                ("missingScheme", &["missing_security_scheme"]),
                ("mtlsOnly", &["mutual_tls"]),
                ("openIdOnly", &["open_id_connect"]),
                (
                    "orAlternatives",
                    &[
                        "api_key_query",
                        "requires_header_api_key",
                        "requires_header_api_key",
                    ],
                ),
                ("serviceRead", &["token_url_mismatch"]),
                ("serviceUndeclaredScope", &["invalid_security_scheme"]),
                ("serviceWrite", &["token_url_mismatch"]),
                ("userConsent", &["oauth2_without_client_credentials"]),
            ],
        ),
        (
            "delegated_issuer_token",
            delegated(&["widgets.read"]),
            &[
                ("andAlternative", &["multiple_schemes"]),
                ("basicOnly", &["http_basic"]),
                ("bearerOnly", &["requires_static_bearer"]),
                ("cookieOnly", &["api_key_cookie"]),
                ("customOnly", &["unsupported_security_scheme_type"]),
                ("digestOnly", &["http_unsupported_scheme"]),
                ("inheritsDocumentSecurity", &["requires_header_api_key"]),
                ("invalidRequirementShape", &["invalid_security_scheme"]),
                ("invalidScopes", &["invalid_security_scheme"]),
                ("missingScheme", &["missing_security_scheme"]),
                ("mtlsOnly", &["mutual_tls"]),
                (
                    "orAlternatives",
                    &[
                        "api_key_query",
                        "requires_header_api_key",
                        "requires_header_api_key",
                    ],
                ),
                ("serviceRead", &["requires_oauth2_client_credentials"]),
                ("serviceUndeclaredScope", &["invalid_security_scheme"]),
                ("serviceWrite", &["requires_oauth2_client_credentials"]),
            ],
        ),
    ];
    for (profile, authentication, expected) in expectations {
        let binding = bind_generated_openapi_tools(&generation, &connection_id(), &authentication)
            .expect("golden binding should succeed");
        let expected = expected
            .iter()
            .map(|(tool_name, codes)| (*tool_name, codes.to_vec()))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(mismatch_codes(&binding), expected, "{profile}");
        for incompatibility in &binding.incompatibilities {
            assert_eq!(
                incompatibility.reason,
                OpenApiToolIncompatibilityReason::NoCompatibleSecurityAlternative,
                "{profile}"
            );
        }
    }
}

/// Every reason the binder can give, each once.
fn every_mismatch_reason() -> Vec<OpenApiSecurityMismatchReason> {
    [
        OpenApiUnsupportedSecurityScheme::MissingDefinition,
        OpenApiUnsupportedSecurityScheme::InvalidDefinition,
        OpenApiUnsupportedSecurityScheme::ApiKeyQuery,
        OpenApiUnsupportedSecurityScheme::ApiKeyCookie,
        OpenApiUnsupportedSecurityScheme::ApiKeyUnsupportedLocation,
        OpenApiUnsupportedSecurityScheme::HttpBasic,
        OpenApiUnsupportedSecurityScheme::HttpUnsupportedScheme,
        OpenApiUnsupportedSecurityScheme::OAuth2WithoutSupportedFlow,
        OpenApiUnsupportedSecurityScheme::MutualTls,
        OpenApiUnsupportedSecurityScheme::UnsupportedType,
    ]
    .map(OpenApiSecurityMismatchReason::UnsupportedScheme)
    .into_iter()
    .chain([
        OpenApiSecurityMismatchReason::MultipleSchemes,
        OpenApiSecurityMismatchReason::RequiresHeaderApiKey,
        OpenApiSecurityMismatchReason::ApiKeyHeaderMismatch,
        OpenApiSecurityMismatchReason::RequiresStaticBearer,
        OpenApiSecurityMismatchReason::RequiresOAuth2ClientCredentials,
        OpenApiSecurityMismatchReason::TokenUrlMismatch,
        OpenApiSecurityMismatchReason::MissingScopes {
            scopes: vec!["widgets.read".to_owned()],
        },
        OpenApiSecurityMismatchReason::OAuth2WithoutClientCredentials,
        OpenApiSecurityMismatchReason::OpenIdConnect,
    ])
    .collect()
}

#[test]
fn every_mismatch_reason_has_a_stable_code_and_a_fixed_message() {
    let mut codes = BTreeSet::new();
    let mut messages = BTreeSet::new();
    for reason in every_mismatch_reason() {
        let code = reason.as_str();
        assert!(
            !code.is_empty()
                && code
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'),
            "{code} should be a snake_case code"
        );
        assert!(codes.insert(code), "{code} should be unique");
        assert!(
            messages.insert(reason.message()),
            "{code} message should be unique"
        );
        assert_eq!(
            reason.missing_scopes().is_empty(),
            code != "missing_scopes",
            "{code}"
        );
    }
    assert_eq!(codes.len(), 19);
}

/// The admin schema's closed set of reason codes and its bound on explained
/// alternatives are exactly the binder's.
#[test]
fn the_admin_schema_lists_every_mismatch_reason_and_the_explanation_bound() {
    let schema_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("gateway crate should live inside the workspace")
        .join("docs/schemas/connection-admin.v1.schema.json");
    let schema: Value = serde_json::from_str(
        &std::fs::read_to_string(schema_path).expect("published admin schema should read"),
    )
    .expect("published admin schema should parse");
    let listed = schema
        .pointer("/$defs/OpenApiSecurityMismatch/properties/reason/enum")
        .and_then(Value::as_array)
        .expect("schema should list the mismatch reasons")
        .iter()
        .map(|code| code.as_str().expect("reason codes are strings"))
        .collect::<BTreeSet<_>>();
    let reasons = every_mismatch_reason();
    let expected = reasons
        .iter()
        .map(OpenApiSecurityMismatchReason::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(listed, expected);
    assert_eq!(
        schema
            .pointer("/$defs/OpenApiIncompatibility/properties/security_alternatives/maxItems")
            .and_then(Value::as_u64),
        u64::try_from(MAX_EXPLAINED_SECURITY_ALTERNATIVES).ok()
    );
}

/// An operation with more alternatives than the preview explains keeps its
/// response bounded: the first ones are explained and the rest only counted.
#[test]
fn explanations_stop_at_their_bound_and_count_the_rest() {
    let alternatives = (0..MAX_EXPLAINED_SECURITY_ALTERNATIVES + 4)
        .map(|index| {
            format!(
                "      - {{ Code: [scope.{index}] }}
"
            )
        })
        .collect::<String>();
    let scopes = (0..MAX_EXPLAINED_SECURITY_ALTERNATIVES + 4)
        .map(|index| format!("scope.{index}: Scope {index}"))
        .collect::<Vec<_>>()
        .join(", ");
    let document = format!(
        "openapi: 3.0.3
info: {{ title: Many, version: 1.0.0 }}
components:
  securitySchemes:
    Code:
      type: oauth2
      flows:
        authorizationCode:
          authorizationUrl: https://idp.example.test/oauth/authorize
          tokenUrl: https://idp.example.test/oauth/token
          scopes: {{ {scopes} }}
paths:
  /many:
    get:
      operationId: manyScopes
      security:
{alternatives}"
    );
    let generation = generate_tools_from_openapi_str("many.yaml", &document)
        .expect("a document with many alternatives should generate");
    let binding = bind_generated_openapi_tools(&generation, &connection_id(), &delegated(&[]))
        .expect("binding should report incompatibilities, not fail");
    let [incompatibility] = binding.incompatibilities.as_slice() else {
        panic!("the one operation should be incompatible");
    };
    assert_eq!(
        incompatibility.security_mismatches.len(),
        MAX_EXPLAINED_SECURITY_ALTERNATIVES
    );
    assert_eq!(incompatibility.unexplained_security_alternatives, 4);
    assert_eq!(
        incompatibility.security_mismatches[0].reason,
        OpenApiSecurityMismatchReason::MissingScopes {
            scopes: vec!["scope.0".to_owned()],
        }
    );
}
