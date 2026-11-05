//! The closed structured forms of the JSON-valued deployment fields
//! (`AUTH_PROVIDERS`, `UPSTREAM_ROUTES`, `MCP_UPSTREAM_SERVERS`).
//!
//! Each form is the environment variable's own JSON shape: the same entry
//! objects with the same member names, which the configuration compiler
//! deserializes into its own types (`RawAuthProviderConfig`,
//! `UpstreamRouteConfig`, `McpUpstreamServerConfig` and the types beneath
//! them). The reader holds every entry to the [`Form`] tables here, which
//! classify each member of those types, then rebuilds the setting in its
//! environment form and deserializes it into the compiler's types, so a
//! document can never hold what the compiler would not read the same way.
//! `bundle::settings::tests` hold the tables to the compiler types' own
//! member lists, so a member the compiler gains is refused until its form is
//! decided here.
//!
//! The document form differs from the environment's in four ways only:
//!
//! - a member whose value may carry a secret (an upstream or MCP server URL,
//!   whose user information or query can hold a credential) accepts only a
//!   secret reference, which is moved out into a [`SecretSlot`]; a literal is
//!   `secret.inline_value` and is never echoed;
//! - a member that names a host path (a route's or endpoint's CA bundle, an
//!   endpoint's client identity, a route's OpenAPI document) and every
//!   literal `add_request_headers` value are `schema.not_representable`:
//!   host paths never enter a bundle, and a static request header can carry
//!   a credential, which belongs in a managed Connection;
//! - a provider's `client_id`, `client_secret` and `redirect_uri`, which only
//!   the admin login provider reads, are set as `spec.admin_login` members
//!   instead;
//! - strings are non-empty with no whitespace at either end, as the scalar
//!   settings' are, and `null` is never a value: leave the member out.
//!
//! Everything else -- defaults, each member's own grammar and bounds, and
//! every rule relating members -- is the compiler's, exactly as for the
//! environment form.

use serde_json::{Map, Number};

use crate::{
    catalog::Field,
    compiler::{
        McpUpstreamServerConfig, RawAuthProviderConfig, UpstreamRouteConfig, AUTH_PROVIDERS,
        MCP_UPSTREAM_SERVERS, UPSTREAM_ROUTES,
    },
};

use super::{
    super::{
        diagnostic::{Code, Pointer},
        document::Checker,
        syntax::{Node, Value, MAX_SAFE_INTEGER},
        value::{SecretReference, Unresolved},
    },
    is_trimmed,
};

/// The largest value of each integer type a compiler member is read as.
const U8: u64 = u8::MAX as u64;
const U16: u64 = u16::MAX as u64;
const U32: u64 = u32::MAX as u64;
const U64: u64 = u64::MAX;
const USIZE: u64 = usize::MAX as u64;

/// What one member of a structured form holds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Kind {
    Boolean,
    /// An integer from 0 to this maximum, the range of the compiler's own
    /// integer type, which the I-JSON safe range bounds further.
    Integer(u64),
    /// A non-empty string with no whitespace at either end.
    Text,
    /// A non-empty string kept exactly as written, whitespace included: a
    /// delimiter.
    Exact,
    /// Exactly one of these words.
    Word(&'static [&'static str]),
    /// An array of [`Kind::Text`] strings.
    TextList,
    /// An array of integers from 0 to this maximum.
    IntegerList(u64),
    /// One object of this form.
    Object(&'static Form),
    /// An array of objects of this form.
    ObjectList(&'static Form),
    /// A value that may carry a secret: a secret reference only.
    Secret,
    /// Static request headers, whose literal values the document cannot
    /// hold; only an empty object is accepted.
    Headers,
    /// A host path, which never enters a bundle.
    HostPath,
    /// Set as the `spec.admin_login` member of the same name instead.
    AdminLogin,
}

/// One member of a structured form.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FormMember {
    pub(crate) name: &'static str,
    pub(crate) kind: Kind,
    /// Whether an entry must give it, as the compiler's type requires.
    pub(crate) required: bool,
}

const fn optional(name: &'static str, kind: Kind) -> FormMember {
    FormMember {
        name,
        kind,
        required: false,
    }
}

const fn required(name: &'static str, kind: Kind) -> FormMember {
    FormMember {
        name,
        kind,
        required: true,
    }
}

/// A closed object of a structured setting, mirroring one compiler type.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Form {
    /// Its name in the published schema's `$defs`.
    pub(crate) name: &'static str,
    /// Its heading in the settings reference.
    pub(crate) title: &'static str,
    pub(crate) description: &'static str,
    pub(crate) members: &'static [FormMember],
}

impl Form {
    /// The members a document may write in this object.
    pub(crate) fn allowed(&self) -> Vec<&'static str> {
        self.members
            .iter()
            .filter(|member| member.kind != Kind::AdminLogin)
            .map(|member| member.name)
            .collect()
    }

    pub(crate) fn required(&self) -> Vec<&'static str> {
        self.members
            .iter()
            .filter(|member| member.required)
            .map(|member| member.name)
            .collect()
    }

    fn member(&self, name: &str) -> Option<&'static FormMember> {
        self.members
            .iter()
            .find(|member| member.name == name && member.kind != Kind::AdminLogin)
    }

    /// This form and every form beneath it, each once, depth first.
    pub(crate) fn with_nested(&'static self, forms: &mut Vec<&'static Form>) {
        if forms.contains(&self) {
            return;
        }
        forms.push(self);
        for member in self.members {
            if let Kind::Object(form) | Kind::ObjectList(form) = member.kind {
                form.with_nested(forms);
            }
        }
    }
}

/// `AUTH_PROVIDERS[]`: `RawAuthProviderConfig`.
pub(crate) static AUTH_PROVIDER: Form = Form {
    name: "authProvider",
    title: "Authentication provider",
    description: "One authentication provider, an AUTH_PROVIDERS entry. client_id, client_secret and redirect_uri, which only the admin login provider reads, are set under spec.admin_login.",
    members: &[
        required("name", Kind::Text),
        required("type", Kind::Word(&["jwt", "cookie_session"])),
        optional("jwks_url", Kind::Text),
        optional("issuer", Kind::Text),
        optional("audience", Kind::Text),
        optional("jwks_timeout_ms", Kind::Integer(U64)),
        optional("jwks_max_key_age_secs", Kind::Integer(U64)),
        optional("require_jti", Kind::Boolean),
        optional("roles_claim", Kind::Text),
        optional("roles_claim_delimiter", Kind::Exact),
        optional("org_claim", Kind::Text),
        optional("introspection_url", Kind::Text),
        optional("introspection_timeout_ms", Kind::Integer(U64)),
        optional("cache_ttl_ms", Kind::Integer(U64)),
        optional("user_id_claim", Kind::Text),
        optional("email_claim", Kind::Text),
        optional("client_id", Kind::AdminLogin),
        optional("client_secret", Kind::AdminLogin),
        optional("redirect_uri", Kind::AdminLogin),
    ],
};

/// `UPSTREAM_ROUTES[]`: `UpstreamRouteConfig`.
pub(crate) static UPSTREAM_ROUTE: Form = Form {
    name: "upstreamRoute",
    title: "Upstream route",
    description: "One upstream route, an UPSTREAM_ROUTES entry.",
    members: &[
        optional("id", Kind::Text),
        optional("forward_cookie_session", Kind::Boolean),
        optional("body_limit_profile", Kind::Word(&["greenpm_research_v1"])),
        optional("upstream_csrf_cookie_name", Kind::Text),
        optional("connection_id", Kind::Text),
        optional("path_prefix", Kind::Text),
        optional("host", Kind::Text),
        optional("upstream_url", Kind::Secret),
        optional("upstreams", Kind::ObjectList(&UPSTREAM_ENDPOINT)),
        optional("load_balancing", Kind::Object(&UPSTREAM_LOAD_BALANCING)),
        optional("request_body", Kind::Object(&UPSTREAM_REQUEST_BODY)),
        optional("sse", Kind::Object(&UPSTREAM_SSE)),
        optional("websocket", Kind::Object(&UPSTREAM_WEBSOCKET)),
        optional("grpc", Kind::Object(&UPSTREAM_GRPC)),
        optional("limits", Kind::Object(&UPSTREAM_LIMITS)),
        optional("health_check", Kind::Object(&UPSTREAM_HEALTH_CHECK)),
        optional("retry", Kind::Object(&UPSTREAM_RETRY)),
        optional("circuit_breaker", Kind::Object(&UPSTREAM_CIRCUIT_BREAKER)),
        optional("timeout_ms", Kind::Integer(U64)),
        optional("response_idle_timeout_ms", Kind::Integer(U64)),
        optional("connect_timeout_ms", Kind::Integer(U64)),
        optional("add_request_headers", Kind::Headers),
        optional("strip_request_headers", Kind::TextList),
        optional("tls_ca_bundle_path", Kind::HostPath),
        optional("openapi_spec_path", Kind::HostPath),
    ],
};

/// `UpstreamEndpointConfig`.
pub(crate) static UPSTREAM_ENDPOINT: Form = Form {
    name: "upstreamEndpoint",
    title: "Upstream endpoint",
    description: "One endpoint of an upstream route's pool.",
    members: &[
        required("id", Kind::Text),
        required("url", Kind::Secret),
        optional("weight", Kind::Integer(U16)),
        optional("tls_ca_bundle_path", Kind::HostPath),
        optional("client_identity_pem_path", Kind::HostPath),
    ],
};

/// `UpstreamLoadBalancingConfig`.
pub(crate) static UPSTREAM_LOAD_BALANCING: Form = Form {
    name: "upstreamLoadBalancing",
    title: "Upstream load balancing",
    description: "How a route's pool chooses an endpoint.",
    members: &[optional("strategy", Kind::Word(&["weighted_round_robin"]))],
};

/// `UpstreamRequestBodyConfig`.
pub(crate) static UPSTREAM_REQUEST_BODY: Form = Form {
    name: "upstreamRequestBody",
    title: "Upstream request body",
    description: "How a route forwards request bodies.",
    members: &[optional("mode", Kind::Word(&["buffered", "stream"]))],
};

/// `UpstreamSseConfig`.
pub(crate) static UPSTREAM_SSE: Form = Form {
    name: "upstreamSse",
    title: "Upstream server-sent events",
    description: "A route's server-sent event streams.",
    members: &[
        optional("max_duration_ms", Kind::Integer(U64)),
        optional("max_response_bytes", Kind::Integer(USIZE)),
    ],
};

/// `UpstreamWebSocketConfig`.
pub(crate) static UPSTREAM_WEBSOCKET: Form = Form {
    name: "upstreamWebSocket",
    title: "Upstream WebSocket",
    description: "A route's WebSocket proxying.",
    members: &[
        optional("max_connections", Kind::Integer(USIZE)),
        optional("max_connections_per_endpoint", Kind::Integer(USIZE)),
        optional("queue_depth", Kind::Integer(USIZE)),
        optional("queue_timeout_ms", Kind::Integer(U64)),
        optional("handshake_timeout_ms", Kind::Integer(U64)),
        optional("idle_timeout_ms", Kind::Integer(U64)),
        optional("max_duration_ms", Kind::Integer(U64)),
        optional("max_frame_bytes", Kind::Integer(USIZE)),
        optional("max_message_bytes", Kind::Integer(USIZE)),
        optional("max_write_buffer_bytes", Kind::Integer(USIZE)),
        optional("allowed_origins", Kind::TextList),
        optional("require_origin", Kind::Boolean),
        optional("allowed_subprotocols", Kind::TextList),
    ],
};

/// `UpstreamGrpcConfig`.
pub(crate) static UPSTREAM_GRPC: Form = Form {
    name: "upstreamGrpc",
    title: "Upstream gRPC",
    description: "A route's transparent gRPC proxying.",
    members: &[
        optional("max_concurrent_calls", Kind::Integer(USIZE)),
        optional("max_concurrent_calls_per_endpoint", Kind::Integer(USIZE)),
        optional("queue_depth", Kind::Integer(USIZE)),
        optional("queue_timeout_ms", Kind::Integer(U64)),
        optional("connect_timeout_ms", Kind::Integer(U64)),
        optional("idle_timeout_ms", Kind::Integer(U64)),
        optional("max_duration_ms", Kind::Integer(U64)),
        optional("max_message_bytes", Kind::Integer(USIZE)),
        optional("max_request_bytes", Kind::Integer(U64)),
        optional("max_response_bytes", Kind::Integer(U64)),
        optional("max_metadata_entries", Kind::Integer(USIZE)),
    ],
};

/// `UpstreamPoolLimitsConfig`.
pub(crate) static UPSTREAM_LIMITS: Form = Form {
    name: "upstreamLimits",
    title: "Upstream limits",
    description: "A route's in-flight and queue bounds.",
    members: &[
        optional("max_in_flight", Kind::Integer(USIZE)),
        optional("queue_depth", Kind::Integer(USIZE)),
        optional("queue_timeout_ms", Kind::Integer(U64)),
    ],
};

/// `UpstreamHealthCheckConfig`.
pub(crate) static UPSTREAM_HEALTH_CHECK: Form = Form {
    name: "upstreamHealthCheck",
    title: "Upstream health check",
    description: "Active and passive health checks of a route's pool.",
    members: &[
        optional("method", Kind::Text),
        optional("path", Kind::Text),
        optional("interval_ms", Kind::Integer(U64)),
        optional("jitter_ms", Kind::Integer(U64)),
        optional("timeout_ms", Kind::Integer(U64)),
        optional("healthy_threshold", Kind::Integer(U32)),
        optional("unhealthy_threshold", Kind::Integer(U32)),
        optional("expected_statuses", Kind::IntegerList(U16)),
        optional("passive_failure_statuses", Kind::IntegerList(U16)),
        optional("required_for_readiness", Kind::Boolean),
        optional("minimum_healthy", Kind::Integer(USIZE)),
    ],
};

/// `UpstreamRetryConfig`.
pub(crate) static UPSTREAM_RETRY: Form = Form {
    name: "upstreamRetry",
    title: "Upstream retry",
    description: "Which failed requests a route retries.",
    members: &[
        optional("max_attempts", Kind::Integer(U8)),
        optional("methods", Kind::TextList),
        optional("statuses", Kind::IntegerList(U16)),
    ],
};

/// `UpstreamCircuitBreakerConfig`.
pub(crate) static UPSTREAM_CIRCUIT_BREAKER: Form = Form {
    name: "upstreamCircuitBreaker",
    title: "Upstream circuit breaker",
    description: "When a route stops sending to a failing endpoint.",
    members: &[
        optional("failure_threshold", Kind::Integer(U32)),
        optional("open_ms", Kind::Integer(U64)),
        optional("half_open_max_requests", Kind::Integer(U32)),
        optional("recovery_threshold", Kind::Integer(U32)),
    ],
};

/// `MCP_UPSTREAM_SERVERS[]`: `McpUpstreamServerConfig`.
pub(crate) static MCP_UPSTREAM_SERVER: Form = Form {
    name: "mcpUpstreamServer",
    title: "MCP upstream server",
    description: "One MCP upstream server, an MCP_UPSTREAM_SERVERS entry.",
    members: &[
        required("name", Kind::Text),
        required("url", Kind::Secret),
        optional("timeout_ms", Kind::Integer(U64)),
        optional("response_idle_timeout_ms", Kind::Integer(U64)),
        optional("connect_timeout_ms", Kind::Integer(U64)),
    ],
};

/// A JSON-valued deployment field: an array of entries of one form.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Document {
    AuthProviders,
    UpstreamRoutes,
    McpUpstreamServers,
}

impl Document {
    pub(crate) const ALL: &'static [Self] = &[
        Self::AuthProviders,
        Self::UpstreamRoutes,
        Self::McpUpstreamServers,
    ];

    /// The structured form of a catalog field, if it holds a JSON document
    /// a deployment document can set.
    pub(crate) fn of(field: &Field) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|document| document.environment() == field.environment)
    }

    pub(crate) fn environment(self) -> &'static str {
        match self {
            Self::AuthProviders => AUTH_PROVIDERS,
            Self::UpstreamRoutes => UPSTREAM_ROUTES,
            Self::McpUpstreamServers => MCP_UPSTREAM_SERVERS,
        }
    }

    /// The form of each entry.
    pub(crate) fn entry(self) -> &'static Form {
        match self {
            Self::AuthProviders => &AUTH_PROVIDER,
            Self::UpstreamRoutes => &UPSTREAM_ROUTE,
            Self::McpUpstreamServers => &MCP_UPSTREAM_SERVER,
        }
    }

    /// Whether the compiler's own type reads `environment`, the setting in
    /// its environment form.
    fn types(self, environment: &serde_json::Value) -> bool {
        let value = environment.clone();
        match self {
            Self::AuthProviders => {
                serde_json::from_value::<Vec<RawAuthProviderConfig>>(value).is_ok()
            }
            Self::UpstreamRoutes => {
                serde_json::from_value::<Vec<UpstreamRouteConfig>>(value).is_ok()
            }
            Self::McpUpstreamServers => {
                serde_json::from_value::<Vec<McpUpstreamServerConfig>>(value).is_ok()
            }
        }
    }
}

/// A secret reference moved out of a structured setting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SecretSlot {
    /// Where the resolved value belongs: an RFC 6901 pointer into the
    /// setting's environment form, built from the form's member names and
    /// array indices only.
    pub(crate) pointer: String,
    pub(crate) reference: SecretReference,
}

/// A structured setting as the document gave it, in its environment form.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Structured {
    /// The setting as its environment variable's JSON would hold it, with
    /// each secret member an empty string. The compiler's type reads it.
    pub(crate) environment: serde_json::Value,
    /// The secret members' references, in document order.
    pub(crate) secrets: Vec<SecretSlot>,
}

/// Reads one structured setting, reporting every problem in it.
pub(super) fn read(
    checker: &mut Checker<'_>,
    document: Document,
    node: &Node,
    pointer: &Pointer,
) -> Option<Structured> {
    let mut reader = Reader {
        checker,
        secrets: Vec::new(),
        failed: false,
    };
    let environment = reader.value(Kind::ObjectList(document.entry()), node, pointer, "");
    if reader.failed {
        return None;
    }
    let environment = environment?;
    // The tables above follow the compiler's types, so this holds; if it
    // ever did not, the setting is refused rather than read differently.
    if !document.types(&environment) {
        reader
            .checker
            .report(Code::InvalidValue, pointer.clone(), node);
        return None;
    }
    Some(Structured {
        environment,
        secrets: reader.secrets,
    })
}

struct Reader<'c, 'a> {
    checker: &'c mut Checker<'a>,
    secrets: Vec<SecretSlot>,
    failed: bool,
}

impl Reader<'_, '_> {
    fn refuse(&mut self, code: Code, pointer: &Pointer, node: &Node) -> Option<serde_json::Value> {
        self.failed = true;
        self.checker.report(code, pointer.clone(), node);
        None
    }

    /// The environment form of `node`, a value of `kind` at `pointer` in the
    /// document and at `environment` in the setting's environment form.
    fn value(
        &mut self,
        kind: Kind,
        node: &Node,
        pointer: &Pointer,
        environment: &str,
    ) -> Option<serde_json::Value> {
        if kind == Kind::Secret {
            return match SecretReference::from_node(node) {
                Ok(reference) => {
                    self.secrets.push(SecretSlot {
                        pointer: environment.to_owned(),
                        reference,
                    });
                    Some(serde_json::Value::String(String::new()))
                }
                Err(code) => self.refuse(code, pointer, node),
            };
        }
        if Unresolved::from_node(node).is_some() {
            return self.refuse(Code::Unresolved, pointer, node);
        }
        match kind {
            Kind::Boolean => match node.value {
                Value::Bool(value) => Some(serde_json::Value::Bool(value)),
                _ => self.refuse(Code::WrongType, pointer, node),
            },
            Kind::Integer(maximum) => self.integer(maximum, node, pointer),
            Kind::Text | Kind::Exact => {
                let Some(text) = node.as_str() else {
                    return self.refuse(Code::WrongType, pointer, node);
                };
                let shaped = if kind == Kind::Text {
                    is_trimmed(text)
                } else {
                    !text.is_empty()
                };
                if shaped {
                    Some(serde_json::Value::String(text.to_owned()))
                } else {
                    self.refuse(Code::InvalidValue, pointer, node)
                }
            }
            Kind::Word(words) => {
                let Some(text) = node.as_str() else {
                    return self.refuse(Code::WrongType, pointer, node);
                };
                if words.contains(&text) {
                    Some(serde_json::Value::String(text.to_owned()))
                } else {
                    self.refuse(Code::InvalidValue, pointer, node)
                }
            }
            Kind::TextList => self.list(Kind::Text, node, pointer, environment),
            Kind::IntegerList(maximum) => {
                self.list(Kind::Integer(maximum), node, pointer, environment)
            }
            Kind::ObjectList(form) => self.list(Kind::Object(form), node, pointer, environment),
            Kind::Object(form) => self.object(form, node, pointer, environment),
            Kind::Headers => {
                let Some(entries) = node.as_object() else {
                    return self.refuse(Code::WrongType, pointer, node);
                };
                // Header names are document content, so each entry is
                // reported at the object and its own position.
                for entry in entries {
                    let code = if Unresolved::from_node(&entry.value).is_some() {
                        Code::Unresolved
                    } else {
                        Code::NotRepresentable
                    };
                    self.refuse(code, pointer, &entry.value);
                }
                entries
                    .is_empty()
                    .then(|| serde_json::Value::Object(Map::new()))
            }
            // `object` refuses an admin login member before it gets here.
            Kind::HostPath | Kind::AdminLogin => self.refuse(Code::NotRepresentable, pointer, node),
            // Read above, before the placeholder check.
            Kind::Secret => None,
        }
    }

    fn integer(
        &mut self,
        maximum: u64,
        node: &Node,
        pointer: &Pointer,
    ) -> Option<serde_json::Value> {
        let Value::Integer(value) = node.value else {
            return self.refuse(Code::WrongType, pointer, node);
        };
        let maximum = maximum.min(MAX_SAFE_INTEGER.unsigned_abs());
        match u64::try_from(value) {
            Ok(value) if value <= maximum => Some(serde_json::Value::Number(Number::from(value))),
            _ => self.refuse(Code::InvalidValue, pointer, node),
        }
    }

    fn list(
        &mut self,
        item: Kind,
        node: &Node,
        pointer: &Pointer,
        environment: &str,
    ) -> Option<serde_json::Value> {
        let Value::Array(items) = &node.value else {
            return self.refuse(Code::WrongType, pointer, node);
        };
        let mut values = Vec::with_capacity(items.len());
        let mut valid = true;
        for (index, node) in items.iter().enumerate() {
            match self.value(
                item,
                node,
                &pointer.index(index),
                &format!("{environment}/{index}"),
            ) {
                Some(value) => values.push(value),
                None => valid = false,
            }
        }
        valid.then_some(serde_json::Value::Array(values))
    }

    fn object(
        &mut self,
        form: &'static Form,
        node: &Node,
        pointer: &Pointer,
        environment: &str,
    ) -> Option<serde_json::Value> {
        let reported = self.checker.diagnostics.len();
        let members = self
            .checker
            .object(node, pointer, &form.allowed(), &form.required());
        // `object` reports an unknown or missing member itself.
        self.failed |= self.checker.diagnostics.len() > reported;
        let members = members?;
        let mut values = Map::new();
        let mut valid = true;
        for member in members {
            let Some(definition) = form.member(&member.key) else {
                continue;
            };
            match self.value(
                definition.kind,
                &member.value,
                &pointer.member(definition.name),
                &format!("{environment}/{}", definition.name),
            ) {
                Some(value) => {
                    values.insert(definition.name.to_owned(), value);
                }
                None => valid = false,
            }
        }
        valid.then_some(serde_json::Value::Object(values))
    }
}
