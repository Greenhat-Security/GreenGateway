//! The structured forms of the JSON-valued deployment fields and the
//! document's own members, held to the compiler's types, to the environment
//! form and to the published schema.
//!
//! The forms are tables beside the compiler's types, so these tests are what
//! keeps them the same: every form lists exactly its type's members, with the
//! type's own required members and integer ranges, and every environment
//! fixture converts to a document that the reader accepts and that compiles,
//! back in its environment form, to exactly the configuration the fixture
//! compiles to.

use std::env::VarError;

use serde::de::{self, DeserializeOwned, Visitor};
use serde_json::{json, Map, Value as JsonValue};

use super::{
    render::forms,
    structured::{
        Document, Form, Kind, AUTH_PROVIDER, MCP_UPSTREAM_SERVER, UPSTREAM_CIRCUIT_BREAKER,
        UPSTREAM_ENDPOINT, UPSTREAM_GRPC, UPSTREAM_HEALTH_CHECK, UPSTREAM_LIMITS,
        UPSTREAM_LOAD_BALANCING, UPSTREAM_REQUEST_BODY, UPSTREAM_RETRY, UPSTREAM_ROUTE,
        UPSTREAM_SSE, UPSTREAM_WEBSOCKET,
    },
    tests::{envelope, read, refusals, repository_text, set, validator, with, CANARY},
    OwnValue, SettingValue, Settings, ACKNOWLEDGED_PATH, OWN_MEMBERS,
};
use crate::{
    bundle::{diagnostic::Code, syntax::MAX_SAFE_INTEGER, value::SecretReference},
    compiler::{
        self, ConfigPlan, McpUpstreamServerConfig, RawAuthProviderConfig,
        UpstreamCircuitBreakerConfig, UpstreamEndpointConfig, UpstreamGrpcConfig,
        UpstreamHealthCheckConfig, UpstreamLoadBalancingConfig, UpstreamPoolLimitsConfig,
        UpstreamRequestBodyConfig, UpstreamRetryConfig, UpstreamRouteConfig, UpstreamSseConfig,
        UpstreamWebSocketConfig, ADMIN_LOGIN_PROVIDER, AUTH_PROVIDERS,
    },
};

const SAFE: u64 = MAX_SAFE_INTEGER.unsigned_abs();

// --- the forms are the compiler's types ------------------------------------------

/// A deserializer that answers only the question of which members a derived
/// `Deserialize` struct reads: serde passes them to `deserialize_struct`.
struct Members<'a>(&'a mut Option<&'static [&'static str]>);

impl<'de> de::Deserializer<'de> for Members<'_> {
    type Error = de::value::Error;

    fn deserialize_any<V: Visitor<'de>>(self, _: V) -> Result<V::Value, Self::Error> {
        Err(de::Error::custom("only a struct names its members"))
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _: &'static str,
        fields: &'static [&'static str],
        _: V,
    ) -> Result<V::Value, Self::Error> {
        *self.0 = Some(fields);
        Err(de::Error::custom("members captured"))
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string bytes
        byte_buf option unit unit_struct newtype_struct seq tuple tuple_struct map
        enum identifier ignored_any
    }
}

fn members_of<T: DeserializeOwned>() -> Vec<&'static str> {
    let mut captured = None;
    let _ = T::deserialize(Members(&mut captured));
    captured
        .expect("a derived struct names its members")
        .to_vec()
}

fn reads<T: DeserializeOwned>(value: &JsonValue) -> bool {
    serde_json::from_value::<T>(value.clone()).is_ok()
}

/// Each form beside its compiler type: the type's members, and whether the
/// type reads one environment-form object.
fn compiler_type(form: &Form) -> (Vec<&'static str>, fn(&JsonValue) -> bool) {
    let pairs: [(&Form, Vec<&'static str>, fn(&JsonValue) -> bool); 13] = [
        (
            &AUTH_PROVIDER,
            members_of::<RawAuthProviderConfig>(),
            reads::<RawAuthProviderConfig>,
        ),
        (
            &UPSTREAM_ROUTE,
            members_of::<UpstreamRouteConfig>(),
            reads::<UpstreamRouteConfig>,
        ),
        (
            &UPSTREAM_ENDPOINT,
            members_of::<UpstreamEndpointConfig>(),
            reads::<UpstreamEndpointConfig>,
        ),
        (
            &UPSTREAM_LOAD_BALANCING,
            members_of::<UpstreamLoadBalancingConfig>(),
            reads::<UpstreamLoadBalancingConfig>,
        ),
        (
            &UPSTREAM_REQUEST_BODY,
            members_of::<UpstreamRequestBodyConfig>(),
            reads::<UpstreamRequestBodyConfig>,
        ),
        (
            &UPSTREAM_SSE,
            members_of::<UpstreamSseConfig>(),
            reads::<UpstreamSseConfig>,
        ),
        (
            &UPSTREAM_WEBSOCKET,
            members_of::<UpstreamWebSocketConfig>(),
            reads::<UpstreamWebSocketConfig>,
        ),
        (
            &UPSTREAM_GRPC,
            members_of::<UpstreamGrpcConfig>(),
            reads::<UpstreamGrpcConfig>,
        ),
        (
            &UPSTREAM_LIMITS,
            members_of::<UpstreamPoolLimitsConfig>(),
            reads::<UpstreamPoolLimitsConfig>,
        ),
        (
            &UPSTREAM_HEALTH_CHECK,
            members_of::<UpstreamHealthCheckConfig>(),
            reads::<UpstreamHealthCheckConfig>,
        ),
        (
            &UPSTREAM_RETRY,
            members_of::<UpstreamRetryConfig>(),
            reads::<UpstreamRetryConfig>,
        ),
        (
            &UPSTREAM_CIRCUIT_BREAKER,
            members_of::<UpstreamCircuitBreakerConfig>(),
            reads::<UpstreamCircuitBreakerConfig>,
        ),
        (
            &MCP_UPSTREAM_SERVER,
            members_of::<McpUpstreamServerConfig>(),
            reads::<McpUpstreamServerConfig>,
        ),
    ];
    pairs
        .into_iter()
        .find(|(candidate, _, _)| std::ptr::eq(*candidate, form))
        .map(|(_, members, reads)| (members, reads))
        .unwrap_or_else(|| panic!("{} has a compiler type", form.name))
}

/// A value of `kind` in the environment form, as the reader writes it.
fn sample(kind: Kind) -> Option<JsonValue> {
    Some(match kind {
        Kind::Boolean => json!(false),
        Kind::Integer(_) => json!(1),
        Kind::Text => json!("sample"),
        Kind::Exact => json!(" "),
        Kind::Word(words) => json!(words[0]),
        Kind::TextList | Kind::IntegerList(_) | Kind::ObjectList(_) => json!([]),
        Kind::Object(form) => minimal(form),
        // A secret member is an empty string until it is resolved.
        Kind::Secret => json!(""),
        Kind::Headers => json!({}),
        Kind::HostPath | Kind::AdminLogin => return None,
    })
}

/// An environment-form object with only `form`'s required members.
fn minimal(form: &Form) -> JsonValue {
    let mut object = Map::new();
    for member in form.members.iter().filter(|member| member.required) {
        let value = sample(member.kind).expect("a required member has a document form");
        object.insert(member.name.to_owned(), value);
    }
    JsonValue::Object(object)
}

#[test]
fn every_form_lists_exactly_its_compiler_types_members() {
    let all = forms();
    for document in Document::ALL {
        assert!(all.contains(&document.entry()));
    }
    for form in &all {
        let (members, reads) = compiler_type(form);
        let listed: Vec<&str> = form.members.iter().map(|member| member.name).collect();
        assert_eq!(
            listed, members,
            "{}: one member per compiler member, in its order",
            form.name
        );

        // The compiler's type reads an object of the required members alone,
        // and refuses it without any one of them.
        let base = minimal(form);
        assert!(reads(&base), "{}: {base}", form.name);
        for member in form.members.iter().filter(|member| member.required) {
            let mut without = base.clone();
            without
                .as_object_mut()
                .expect("an object")
                .remove(member.name);
            assert!(
                !reads(&without),
                "{}.{} is required",
                form.name,
                member.name
            );
        }

        // Each member, alone beside the required ones, is read; each word
        // and each integer at the form's maximum is read, and one past a
        // maximum below the safe range is not.
        for member in form.members {
            let Some(value) = sample(member.kind) else {
                continue;
            };
            let with_member = |value: JsonValue| {
                let mut object = base.clone();
                object
                    .as_object_mut()
                    .expect("an object")
                    .insert(member.name.to_owned(), value);
                object
            };
            assert!(reads(&with_member(value)), "{}.{}", form.name, member.name);
            match member.kind {
                Kind::Integer(maximum) | Kind::IntegerList(maximum) => {
                    let list = matches!(member.kind, Kind::IntegerList(_));
                    let shaped = |value: u64| if list { json!([value]) } else { json!(value) };
                    let top = maximum.min(SAFE);
                    assert!(
                        reads(&with_member(shaped(top))),
                        "{}.{}",
                        form.name,
                        member.name
                    );
                    if maximum < SAFE {
                        assert!(
                            !reads(&with_member(shaped(maximum + 1))),
                            "{}.{} is bounded by its type",
                            form.name,
                            member.name
                        );
                    }
                }
                Kind::Word(words) => {
                    for word in words {
                        assert!(
                            reads(&with_member(json!(word))),
                            "{}.{}",
                            form.name,
                            member.name
                        );
                    }
                }
                _ => {}
            }
        }
    }
}

#[test]
fn the_admin_login_members_are_the_ones_the_provider_form_moves() {
    let moved: Vec<&str> = AUTH_PROVIDER
        .members
        .iter()
        .filter(|member| member.kind == Kind::AdminLogin)
        .map(|member| member.name)
        .collect();
    assert_eq!(moved, ["client_id", "client_secret", "redirect_uri"]);
    for name in moved {
        let path = format!("/spec/admin_login/{name}");
        let own = OWN_MEMBERS
            .iter()
            .find(|member| member.path == path)
            .unwrap_or_else(|| panic!("{path} is a member of the document's own"));
        let expected = if name == "client_secret" {
            OwnValue::Secret
        } else {
            OwnValue::Text
        };
        assert_eq!(own.value, expected, "{path}");
    }
    // Only provider and URL members can carry a secret, and each such member
    // is a reference; no other form has an admin login member.
    for form in forms() {
        for member in form.members {
            if member.kind == Kind::AdminLogin {
                assert!(std::ptr::eq(form, &AUTH_PROVIDER), "{}", form.name);
            }
            if member.kind == Kind::Secret {
                assert!(
                    member.name == "url" || member.name == "upstream_url",
                    "{}.{}",
                    form.name,
                    member.name
                );
            }
        }
    }
}

// --- environment fixtures convert to the document form ------------------------------

/// The admin login provider fixture the compiler's own tests use.
const ADMIN_LOGIN_PROVIDERS: &str = r#"[{"name":"primary","type":"jwt","issuer":"https://issuer.example.test","client_id":"admin-ui","client_secret":"generated-fixture-placeholder","redirect_uri":"https://management.example.test/v1/operations/auth/callback"}]"#;

/// Every provider member the document can hold.
const EVERY_PROVIDER_MEMBER: &str = r#"[
    {"name":"primary","type":"jwt","jwks_url":"https://issuer.example.test/jwks","issuer":"https://issuer.example.test/","audience":"greengateway","jwks_timeout_ms":2500,"jwks_max_key_age_secs":600,"require_jti":true,"roles_claim":"scope","roles_claim_delimiter":" ","org_claim":"org","client_id":"admin-ui","client_secret":"generated-fixture-placeholder","redirect_uri":"https://management.example.test/v1/admin/auth/callback"},
    {"name":"sessions","type":"cookie_session","introspection_url":"https://sessions.example.test/introspect","introspection_timeout_ms":1500,"cache_ttl_ms":30000,"user_id_claim":"sub","email_claim":"email","roles_claim":"roles"}
]"#;

/// Routes using every route member the document can hold.
const EVERY_ROUTE_MEMBER: &str = r#"[
    {"id":"events","path_prefix":"/events","upstream_url":"https://events.example.test","sse":{"max_duration_ms":7200000,"max_response_bytes":1048576},"timeout_ms":3000,"response_idle_timeout_ms":2000,"connect_timeout_ms":500,"strip_request_headers":["x-debug"],"add_request_headers":{}},
    {"id":"origins","path_prefix":"/origins","upstreams":[{"id":"a","url":"https://a.example.test"}],"websocket":{"max_connections":32,"max_connections_per_endpoint":16,"queue_depth":8,"queue_timeout_ms":50,"handshake_timeout_ms":5000,"idle_timeout_ms":60000,"max_duration_ms":600000,"max_frame_bytes":65536,"max_message_bytes":262144,"max_write_buffer_bytes":131072,"allowed_origins":["https://app.example.test"],"require_origin":true,"allowed_subprotocols":["chat"]}},
    {"id":"calls","host":"calls.example.test","upstreams":[{"id":"b","url":"https://b.example.test","weight":2}],"grpc":{"max_concurrent_calls":8,"max_concurrent_calls_per_endpoint":4,"queue_depth":16,"queue_timeout_ms":100,"connect_timeout_ms":1000,"idle_timeout_ms":60000,"max_duration_ms":600000,"max_message_bytes":1048576,"max_request_bytes":4194304,"max_response_bytes":4194304,"max_metadata_entries":32}},
    {"id":"payments","path_prefix":"/payments","upstreams":[{"id":"payments-a","url":"https://payments-a.example.test","weight":3},{"id":"payments-b","url":"https://payments-b.example.test","weight":1}],"load_balancing":{"strategy":"weighted_round_robin"},"request_body":{"mode":"buffered"},"limits":{"max_in_flight":64,"queue_depth":128,"queue_timeout_ms":200},"health_check":{"method":"GET","path":"/ready","interval_ms":5000,"jitter_ms":100,"timeout_ms":500,"healthy_threshold":2,"unhealthy_threshold":3,"expected_statuses":[200,204],"passive_failure_statuses":[502,503],"required_for_readiness":true,"minimum_healthy":1},"retry":{"max_attempts":2,"methods":["GET","HEAD"],"statuses":[502,503]},"circuit_breaker":{"failure_threshold":4,"open_ms":10000,"half_open_max_requests":1,"recovery_threshold":2}}
]"#;

/// The cookie-session delegation route the compiler's own tests use.
const COOKIE_SESSION_ROUTE: &str = r#"[{"id":"pm-session","path_prefix":"/api/exponential","upstream_url":"https://pm-backend.example.test","forward_cookie_session":true,"upstream_csrf_cookie_name":"pm_csrf"}]"#;

const MCP_SERVERS: &str = r#"[{"name":"tools","url":"https://mcp.example.test/mcp","timeout_ms":5000,"response_idle_timeout_ms":3000,"connect_timeout_ms":1000},{"name":"search","url":"https://search.example.test/mcp"}]"#;

/// The development stack's `UPSTREAM_ROUTES`, read from its Compose file.
fn compose_routes() -> String {
    let text = repository_text("docker-compose.dev.yml");
    let line = text
        .lines()
        .find_map(|line| line.trim().strip_prefix("UPSTREAM_ROUTES: '"))
        .expect("the development stack sets UPSTREAM_ROUTES");
    line.strip_suffix('\'')
        .expect("a single-quoted value")
        .to_owned()
}

/// The secret values a conversion moved out, by the alias it gave each.
type Aliases = Vec<(String, JsonValue)>;

/// The document form of an environment-form value of `kind`, as an export
/// would write it: each secret member a reference to a fresh alias and each
/// member with no document form an unresolved placeholder.
fn to_document(kind: Kind, value: &JsonValue, aliases: &mut Aliases) -> JsonValue {
    match (kind, value) {
        (Kind::Secret, _) => {
            let alias = format!("fixture-secret-{}", aliases.len());
            aliases.push((alias.clone(), value.clone()));
            json!({ "secret": alias })
        }
        (Kind::HostPath, _) => json!({ "unresolved": "not_representable" }),
        (Kind::Headers, JsonValue::Object(entries)) if !entries.is_empty() => {
            json!({ "unresolved": "not_representable" })
        }
        (Kind::Object(form), JsonValue::Object(members)) => JsonValue::Object(
            members
                .iter()
                .filter_map(|(name, value)| {
                    let member = form
                        .members
                        .iter()
                        .find(|member| member.name == name)
                        .unwrap_or_else(|| panic!("{}.{name} has a form", form.name));
                    (member.kind != Kind::AdminLogin)
                        .then(|| (name.clone(), to_document(member.kind, value, aliases)))
                })
                .collect(),
        ),
        (Kind::ObjectList(form), JsonValue::Array(items)) => JsonValue::Array(
            items
                .iter()
                .map(|item| to_document(Kind::Object(form), item, aliases))
                .collect(),
        ),
        _ => value.clone(),
    }
}

/// An environment fixture as a deployment document: each JSON setting in
/// its form at its path, the admin login provider's client under
/// `spec.admin_login`, and the aliases the secrets were moved to.
fn fixture_document(fixture: &[(&str, String)]) -> (JsonValue, Aliases) {
    let mut document = envelope();
    let mut aliases = Aliases::new();
    let login = fixture
        .iter()
        .find(|(name, _)| *name == ADMIN_LOGIN_PROVIDER)
        .map(|(_, value)| value.clone());
    for (name, value) in fixture {
        let field = crate::catalog::field(name).unwrap_or_else(|| panic!("{name} is a field"));
        let path = field
            .document_path()
            .expect("a fixture sets deployment fields");
        let Some(document_kind) = Document::of(field) else {
            set(&mut document, path, json!(value));
            continue;
        };
        let parsed: JsonValue = serde_json::from_str(value).expect("fixtures are JSON");
        let converted = to_document(
            Kind::ObjectList(document_kind.entry()),
            &parsed,
            &mut aliases,
        );
        set(&mut document, path, converted);
        if *name != AUTH_PROVIDERS {
            continue;
        }
        for provider in parsed.as_array().expect("an array") {
            let admin = login.as_deref() == provider["name"].as_str();
            for member in ["client_id", "client_secret", "redirect_uri"] {
                let Some(value) = provider.get(member) else {
                    continue;
                };
                assert!(admin, "only the admin login provider reads {member}");
                let value = if member == "client_secret" {
                    to_document(Kind::Secret, value, &mut aliases)
                } else {
                    value.clone()
                };
                set(&mut document, &format!("/spec/admin_login/{member}"), value);
            }
        }
    }
    (document, aliases)
}

/// The environment a read document describes, with each secret reference
/// resolved from `aliases`: what the compiler front end does with a
/// document's structured settings once it reads them.
fn document_environment(settings: &Settings, aliases: &Aliases) -> Vec<(String, String)> {
    let resolve = |reference: &SecretReference| {
        aliases
            .iter()
            .find(|(alias, _)| alias == reference.alias_id())
            .map(|(_, value)| value.clone())
            .expect("every reference names a fixture alias")
    };
    let login = settings.values.iter().find_map(|setting| {
        match (&setting.value, setting.field.environment) {
            (SettingValue::Text(name), ADMIN_LOGIN_PROVIDER) => Some(name.clone()),
            _ => None,
        }
    });
    let mut environment = Vec::new();
    for setting in &settings.values {
        let value = match &setting.value {
            SettingValue::Structured(structured) => {
                let mut value = structured.environment.clone();
                for slot in &structured.secrets {
                    *value
                        .pointer_mut(&slot.pointer)
                        .expect("a slot points into the setting") = resolve(&slot.reference);
                }
                if setting.field.environment == AUTH_PROVIDERS {
                    let provider = value
                        .as_array_mut()
                        .expect("an array")
                        .iter_mut()
                        .find(|provider| provider["name"].as_str() == login.as_deref());
                    if let Some(provider) = provider {
                        for member in ["client_id", "client_secret", "redirect_uri"] {
                            let own =
                                match settings.own_value(&format!("/spec/admin_login/{member}")) {
                                    Some(SettingValue::Text(text)) => json!(text),
                                    Some(SettingValue::Secret(reference)) => resolve(reference),
                                    _ => continue,
                                };
                            provider[member] = own;
                        }
                    }
                }
                value.to_string()
            }
            SettingValue::Text(text) => text.clone(),
            other => panic!(
                "{}: {other:?} is not a fixture setting",
                setting.field.environment
            ),
        };
        environment.push((setting.field.environment.to_owned(), value));
    }
    environment
}

fn compiled(environment: &[(String, String)]) -> ConfigPlan {
    compiler::compile(|name| {
        environment
            .iter()
            .find(|(variable, _)| variable == name)
            .map(|(_, value)| value.clone())
            .ok_or(VarError::NotPresent)
    })
    .unwrap_or_else(|error| panic!("the fixture compiles: {error}"))
}

#[test]
fn every_environment_fixture_converts_to_a_document_that_compiles_to_the_same_values() {
    // Each fixture is the settings it converts and the environment both
    // sides share: a host-matched route needs a policy file, which a bundle
    // supplies as a resource rather than as a setting.
    let policy_file = [("POLICY_FILE", "/etc/greengateway/policy.json")];
    let fixtures: Vec<(Vec<(&str, String)>, &[(&str, &str)])> = vec![
        (
            vec![
                ("AUTH_PROVIDERS", ADMIN_LOGIN_PROVIDERS.to_owned()),
                ("ADMIN_LOGIN_PROVIDER", "primary".to_owned()),
            ],
            &[],
        ),
        (
            vec![
                ("AUTH_PROVIDERS", EVERY_PROVIDER_MEMBER.to_owned()),
                ("ADMIN_LOGIN_PROVIDER", "primary".to_owned()),
            ],
            &[],
        ),
        (vec![("AUTH_PROVIDERS", "[]".to_owned())], &[]),
        (
            vec![("UPSTREAM_ROUTES", EVERY_ROUTE_MEMBER.to_owned())],
            &policy_file,
        ),
        (vec![("UPSTREAM_ROUTES", compose_routes())], &[]),
        (
            vec![("UPSTREAM_ROUTES", COOKIE_SESSION_ROUTE.to_owned())],
            &[],
        ),
        (vec![("MCP_UPSTREAM_SERVERS", MCP_SERVERS.to_owned())], &[]),
    ];
    for (fixture, shared) in fixtures {
        let label = fixture
            .iter()
            .map(|(name, _)| *name)
            .collect::<Vec<_>>()
            .join(",");
        let (document, aliases) = fixture_document(&fixture);
        let (deployment, diagnostics) = read(&document);
        let deployment = deployment.unwrap_or_else(|| panic!("{label}: {diagnostics:?}"));
        assert!(
            validator().is_valid(&document),
            "{label}: the schema agrees"
        );
        let shared = shared
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()));
        let environment: Vec<(String, String)> = fixture
            .iter()
            .map(|(name, value)| ((*name).to_owned(), value.clone()))
            .chain(shared.clone())
            .collect();
        let from_document = document_environment(&deployment.settings, &aliases);
        let mut names: Vec<&str> = from_document
            .iter()
            .map(|(name, _)| name.as_str())
            .collect();
        names.sort_unstable();
        let mut expected: Vec<&str> = fixture.iter().map(|(name, _)| *name).collect();
        expected.sort_unstable();
        assert_eq!(
            names, expected,
            "{label}: the document sets the same variables"
        );
        let from_document: Vec<(String, String)> =
            from_document.into_iter().chain(shared).collect();
        assert_eq!(
            compiled(&from_document),
            compiled(&environment),
            "{label}: the document compiles to the fixture's configuration"
        );
        // No secret value the conversion moved out is in the document.
        let text = document.to_string();
        for (_, value) in &aliases {
            let value = value.as_str().expect("secret members are strings");
            assert!(!text.contains(value), "{label}: {value} was moved out");
        }
    }
}

#[test]
fn an_environment_fixture_with_no_document_form_converts_to_unresolved_placeholders() {
    let example = repository_text("docs/examples/upstream-pool.json");
    let headers = format!(
        r#"[{{"id":"labelled","path_prefix":"/labelled","upstream_url":"https://labelled.example.test","add_request_headers":{{"x-route-label":"{CANARY}"}},"openapi_spec_path":"/srv/{CANARY}/openapi.json"}}]"#
    );
    for (fixture, unresolved) in [
        (
            example,
            vec![
                "/spec/upstream/routes/0/upstreams/1/tls_ca_bundle_path",
                "/spec/upstream/routes/0/upstreams/1/client_identity_pem_path",
            ],
        ),
        (
            headers,
            vec![
                "/spec/upstream/routes/0/add_request_headers",
                "/spec/upstream/routes/0/openapi_spec_path",
            ],
        ),
    ] {
        let (document, _) = fixture_document(&[("UPSTREAM_ROUTES", fixture)]);
        let mut expected: Vec<(Code, String)> = unresolved
            .into_iter()
            .map(|at| (Code::Unresolved, at.to_owned()))
            .collect();
        expected.sort_unstable_by_key(|(_, at)| at.clone());
        let mut found = refusals(&document);
        found.sort_unstable_by_key(|(_, at)| at.clone());
        assert_eq!(found, expected);
        assert!(!validator().is_valid(&document));
        let (_, diagnostics) = read(&document);
        for diagnostic in &diagnostics {
            let rendered = format!("{diagnostic} {diagnostic:?}");
            assert!(!rendered.contains(CANARY), "{rendered}");
        }
    }
}

// --- reading the forms -------------------------------------------------------------------

/// A document with one route that is `route` plus a valid matcher and URL.
fn route(members: JsonValue) -> JsonValue {
    let mut route = json!({
        "path_prefix": "/r",
        "upstream_url": { "secret": "route-url" },
    });
    for (name, value) in members.as_object().expect("route members") {
        route[name] = value.clone();
    }
    with("/spec/upstream/routes", json!([route]))
}

#[test]
fn each_structured_member_is_held_to_its_form() {
    let at = |pointer: &str| format!("/spec/upstream/routes/0{pointer}");
    let cases: Vec<(JsonValue, Vec<(Code, String)>)> = vec![
        (route(json!({})), vec![]),
        // A URL that may carry a credential is a reference, never a literal.
        (
            route(json!({ "upstream_url": format!("https://{CANARY}.example.test") })),
            vec![(Code::InlineSecretValue, at("/upstream_url"))],
        ),
        (
            route(json!({ "upstream_url": { "unresolved": "legacy_inline_secret" } })),
            vec![(Code::Unresolved, at("/upstream_url"))],
        ),
        (
            route(json!({ "upstream_url": { "secret": format!("../{CANARY}") } })),
            vec![(Code::InvalidSecretReference, at("/upstream_url"))],
        ),
        // Static headers: only an empty object; each literal is refused at
        // the object, never by name.
        (route(json!({ "add_request_headers": {} })), vec![]),
        (
            route(json!({ "add_request_headers": { CANARY: CANARY, "x-two": "two" } })),
            vec![
                (Code::NotRepresentable, at("/add_request_headers")),
                (Code::NotRepresentable, at("/add_request_headers")),
            ],
        ),
        (
            route(json!({ "add_request_headers": { "x-one": { "secret": "header-value" } } })),
            vec![(Code::NotRepresentable, at("/add_request_headers"))],
        ),
        (
            route(json!({ "add_request_headers": [] })),
            vec![(Code::WrongType, at("/add_request_headers"))],
        ),
        // Host paths never enter a bundle.
        (
            route(json!({ "tls_ca_bundle_path": format!("/run/{CANARY}.pem") })),
            vec![(Code::NotRepresentable, at("/tls_ca_bundle_path"))],
        ),
        (
            route(json!({ "openapi_spec_path": "/srv/openapi.json" })),
            vec![(Code::NotRepresentable, at("/openapi_spec_path"))],
        ),
        // Nested objects and lists report the member at fault.
        (
            route(json!({
                "upstream_url": null,
                "upstreams": [
                    { "id": "a", "url": { "secret": "endpoint-a" } },
                    { "id": "b", "url": "https://b.example.test", "weight": 65536 },
                    { "url": { "secret": "endpoint-c" }, "client_identity_pem_path": "/run/c.pem" }
                ]
            })),
            vec![
                (Code::InvalidSecretReference, at("/upstream_url")),
                (Code::InlineSecretValue, at("/upstreams/1/url")),
                (Code::InvalidValue, at("/upstreams/1/weight")),
                (Code::MissingMember, at("/upstreams/2/id")),
                (
                    Code::NotRepresentable,
                    at("/upstreams/2/client_identity_pem_path"),
                ),
            ],
        ),
        (
            route(json!({
                "retry": { "max_attempts": 256, "statuses": [502, -1], "methods": ["GET", " PUT"] },
                "health_check": { "expected_statuses": "200", "required_for_readiness": "yes" },
                "request_body": { "mode": "chunked" },
                "websocket": { CANARY: 1 },
                "timeout_ms": SAFE,
                "connect_timeout_ms": "1"
            })),
            vec![
                (Code::InvalidValue, at("/retry/max_attempts")),
                (Code::InvalidValue, at("/retry/statuses/1")),
                (Code::InvalidValue, at("/retry/methods/1")),
                (Code::WrongType, at("/health_check/expected_statuses")),
                (Code::WrongType, at("/health_check/required_for_readiness")),
                (Code::InvalidValue, at("/request_body/mode")),
                (Code::UnknownMember, at("/websocket")),
                (Code::WrongType, at("/connect_timeout_ms")),
            ],
        ),
        (
            with("/spec/upstream/routes", json!({})),
            vec![(Code::WrongType, "/spec/upstream/routes".to_owned())],
        ),
        (
            with(
                "/spec/upstream/routes",
                json!({ "unresolved": "not_representable" }),
            ),
            vec![(Code::Unresolved, "/spec/upstream/routes".to_owned())],
        ),
        (
            with("/spec/upstream/routes", json!([[]])),
            vec![(Code::WrongType, "/spec/upstream/routes/0".to_owned())],
        ),
        // Providers: the admin login client is not a provider member, the
        // type is a word, and a delimiter is kept exactly.
        (
            with(
                "/spec/authentication/providers",
                json!([
                    { "name": "corp", "type": "jwt", "roles_claim_delimiter": " " },
                    { "name": " padded", "type": CANARY, "client_secret": CANARY },
                    { "type": "cookie_session", "roles_claim_delimiter": "" }
                ]),
            ),
            vec![
                (
                    Code::UnknownMember,
                    "/spec/authentication/providers/1".to_owned(),
                ),
                (
                    Code::InvalidValue,
                    "/spec/authentication/providers/1/name".to_owned(),
                ),
                (
                    Code::InvalidValue,
                    "/spec/authentication/providers/1/type".to_owned(),
                ),
                (
                    Code::MissingMember,
                    "/spec/authentication/providers/2/name".to_owned(),
                ),
                (
                    Code::InvalidValue,
                    "/spec/authentication/providers/2/roles_claim_delimiter".to_owned(),
                ),
            ],
        ),
        (
            with(
                "/spec/upstream/mcp_servers",
                json!([
                    { "name": "tools", "url": { "secret": "mcp-tools" }, "timeout_ms": 1 },
                    { "name": "search", "url": format!("https://{CANARY}.example.test/mcp") },
                    { "name": "other" }
                ]),
            ),
            vec![
                (
                    Code::InlineSecretValue,
                    "/spec/upstream/mcp_servers/1/url".to_owned(),
                ),
                (
                    Code::MissingMember,
                    "/spec/upstream/mcp_servers/2/url".to_owned(),
                ),
            ],
        ),
    ];
    for (document, mut expected) in cases {
        // A JSON object's member order is the serializer's, so the refusals
        // are compared as a set.
        let mut found = refusals(&document);
        found.sort_unstable_by_key(|(code, at)| (at.clone(), code.as_str()));
        expected.sort_unstable_by_key(|(code, at)| (at.clone(), code.as_str()));
        assert_eq!(found, expected, "{document}");
        assert_eq!(
            validator().is_valid(&document),
            expected.is_empty(),
            "the schema agrees on {document}"
        );
        let (_, diagnostics) = read(&document);
        for diagnostic in &diagnostics {
            let rendered = format!("{diagnostic} {diagnostic:?}");
            assert!(!rendered.contains(CANARY), "{rendered}");
        }
    }
}

#[test]
fn a_structured_setting_reads_to_its_environment_form_with_the_secrets_moved_out() {
    let document = with(
        "/spec/upstream/routes",
        json!([{
            "id": "pool",
            "path_prefix": "/pool",
            "upstreams": [
                { "id": "a", "url": { "secret": "pool-a" } },
                { "id": "b", "url": { "secret": "pool-b" }, "weight": 2 }
            ],
            "retry": { "statuses": [503] }
        }]),
    );
    let (deployment, diagnostics) = read(&document);
    let settings = deployment
        .unwrap_or_else(|| panic!("{diagnostics:?}"))
        .settings;
    let [setting] = settings.values.as_slice() else {
        panic!("one setting: {settings:?}");
    };
    let SettingValue::Structured(structured) = &setting.value else {
        panic!("a structured setting: {setting:?}");
    };
    assert_eq!(
        structured.environment,
        json!([{
            "id": "pool",
            "path_prefix": "/pool",
            "upstreams": [
                { "id": "a", "url": "" },
                { "id": "b", "url": "", "weight": 2 }
            ],
            "retry": { "statuses": [503] }
        }])
    );
    let slots: Vec<(&str, &str)> = structured
        .secrets
        .iter()
        .map(|slot| (slot.pointer.as_str(), slot.reference.alias_id()))
        .collect();
    assert_eq!(
        slots,
        [
            ("/0/upstreams/0/url", "pool-a"),
            ("/0/upstreams/1/url", "pool-b")
        ]
    );
    // The canonical form keeps the document as written.
    let mut canonical = document.clone();
    settings.canonicalize(&mut canonical);
    assert_eq!(canonical, document);
}

// --- the document's own members ------------------------------------------------------------

#[test]
fn the_listener_intents_and_the_admin_login_client_are_typed() {
    let cases: Vec<(&str, JsonValue, Option<Code>)> = vec![
        ("/spec/listeners/public/tls", json!("required"), None),
        ("/spec/listeners/admin/tls", json!("off"), None),
        (
            "/spec/listeners/public/tls",
            json!("optional"),
            Some(Code::InvalidValue),
        ),
        (
            "/spec/listeners/admin/tls",
            json!(true),
            Some(Code::WrongType),
        ),
        (
            "/spec/listeners/public/client_certificate_crl",
            json!("required"),
            None,
        ),
        (
            "/spec/listeners/admin/client_certificate_crl",
            json!({ "unresolved": "template_value" }),
            Some(Code::Unresolved),
        ),
        ("/spec/admin_login/client_id", json!("admin-ui"), None),
        (
            "/spec/admin_login/client_id",
            json!(" admin-ui"),
            Some(Code::InvalidValue),
        ),
        (
            "/spec/admin_login/redirect_uri",
            json!("https://admin.example.test/v1/admin/auth/callback"),
            None,
        ),
        (
            "/spec/admin_login/redirect_uri",
            json!(1),
            Some(Code::WrongType),
        ),
        (
            "/spec/admin_login/client_secret",
            json!({ "secret": "admin-client" }),
            None,
        ),
        (
            "/spec/admin_login/client_secret",
            json!(format!("{CANARY}-literal")),
            Some(Code::InlineSecretValue),
        ),
        (
            "/spec/admin_login/client_secret",
            json!({ "unresolved": "legacy_inline_secret" }),
            Some(Code::Unresolved),
        ),
    ];
    for (path, value, expected) in cases {
        let document = with(path, value.clone());
        let expected: Vec<(Code, String)> = expected
            .into_iter()
            .map(|code| (code, path.to_owned()))
            .collect();
        assert_eq!(refusals(&document), expected, "{path} = {value}");
        assert_eq!(
            validator().is_valid(&document),
            expected.is_empty(),
            "the schema agrees on {path} = {value}"
        );
        let (_, diagnostics) = read(&document);
        for diagnostic in &diagnostics {
            assert!(!format!("{diagnostic} {diagnostic:?}").contains(CANARY));
        }
    }
}

fn migration(path: &str, value: JsonValue) -> JsonValue {
    let mut document = with(path, value);
    document["spec"]["profile"] = json!("migration");
    document
}

#[test]
fn only_a_migration_document_acknowledges_distinct_known_behaviors() {
    for (value, expected) in [
        (json!([]), vec![]),
        (json!(["wildcard_role", "policy_default_allow"]), vec![]),
        (
            json!(["policy_shadow_mode", "policy_shadow_mode"]),
            vec![(Code::InvalidValue, "/spec/compatibility/acknowledged/1")],
        ),
        (
            json!(["authentication_observe"]),
            vec![(Code::InvalidValue, "/spec/compatibility/acknowledged/0")],
        ),
        (
            json!([{ "unresolved": "template_value" }]),
            vec![(Code::Unresolved, "/spec/compatibility/acknowledged/0")],
        ),
        (
            json!("policy_default_allow"),
            vec![(Code::WrongType, "/spec/compatibility/acknowledged")],
        ),
    ] {
        let document = migration(ACKNOWLEDGED_PATH, value.clone());
        let expected: Vec<(Code, String)> = expected
            .into_iter()
            .map(|(code, at)| (code, at.to_owned()))
            .collect();
        assert_eq!(refusals(&document), expected, "{value}");
        assert_eq!(
            validator().is_valid(&document),
            expected.is_empty(),
            "{value}"
        );
    }

    let (deployment, _) = read(&migration(
        ACKNOWLEDGED_PATH,
        json!(["wildcard_role", "policy_default_allow"]),
    ));
    let settings = deployment.expect("a valid acknowledgment").settings;
    assert_eq!(
        settings
            .acknowledged()
            .iter()
            .map(|behavior| behavior.as_str())
            .collect::<Vec<_>>(),
        ["policy_default_allow", "wildcard_role"],
        "kept in canonical order"
    );
    let mut canonical = migration(
        ACKNOWLEDGED_PATH,
        json!(["wildcard_role", "policy_default_allow"]),
    );
    settings.canonicalize(&mut canonical);
    assert_eq!(
        canonical.pointer(ACKNOWLEDGED_PATH),
        Some(&json!(["policy_default_allow", "wildcard_role"]))
    );

    // Production and development cannot acknowledge anything; an empty list
    // acknowledges nothing anywhere.
    for profile in ["production", "development"] {
        let mut document = with(ACKNOWLEDGED_PATH, json!(["policy_shadow_mode"]));
        document["spec"]["profile"] = json!(profile);
        assert_eq!(
            refusals(&document),
            [(Code::NotApplicable, ACKNOWLEDGED_PATH.to_owned())],
            "{profile}"
        );
        let mut document = with(ACKNOWLEDGED_PATH, json!([]));
        document["spec"]["profile"] = json!(profile);
        assert!(refusals(&document).is_empty(), "{profile}");
    }
}

#[test]
fn the_compilers_secret_canary_fixtures_are_never_echoed_in_their_document_form() {
    // The structured canaries of the compiler's own value-free test, written
    // as a document would carry them.
    let mut document = envelope();
    set(
        &mut document,
        "/spec/authentication/providers",
        json!([{ "name": "corp", "type": CANARY, "client_secret": CANARY }]),
    );
    set(
        &mut document,
        "/spec/admin_login/client_secret",
        json!(CANARY),
    );
    set(
        &mut document,
        "/spec/upstream/routes",
        json!([{
            "upstream_url": format!("https://{CANARY}.example.test"),
            "add_request_headers": { "x-route-label": CANARY, CANARY: "x" }
        }]),
    );
    set(
        &mut document,
        "/spec/upstream/mcp_servers",
        json!([{ "name": CANARY, "url": CANARY }]),
    );
    let (deployment, diagnostics) = read(&document);
    assert!(deployment.is_none());
    assert_eq!(diagnostics.len(), 7, "{diagnostics:?}");
    for diagnostic in &diagnostics {
        let rendered = format!("{diagnostic} {diagnostic:?}");
        assert!(!rendered.contains(CANARY), "{rendered}");
    }
}

#[test]
fn every_structured_setting_and_member_of_the_documents_own_is_in_the_reference() {
    let reference = super::render_deployment_reference();
    for form in forms() {
        assert!(
            reference.contains(&format!("\n#### {}\n", form.title)),
            "{}",
            form.title
        );
        assert!(
            form.title
                .bytes()
                .all(|byte| byte.is_ascii_alphabetic() || byte == b' ' || byte == b'-'),
            "{}: a title that is its own anchor",
            form.title
        );
    }
    let schema = super::tests::schema();
    for form in forms() {
        assert_eq!(
            schema["$defs"][form.name]["additionalProperties"], false,
            "{} is closed",
            form.name
        );
    }
    for document in Document::ALL {
        let path = crate::catalog::field(document.environment())
            .and_then(|field| field.document_path())
            .expect("a structured setting has a path");
        let pointer = path
            .trim_start_matches('/')
            .split('/')
            .fold(String::new(), |pointer, segment| {
                format!("{pointer}/properties/{segment}")
            });
        assert_eq!(
            schema.pointer(&format!("{pointer}/items/$ref")),
            Some(&json!(format!("#/$defs/{}", document.entry().name))),
            "{path}"
        );
    }
}
