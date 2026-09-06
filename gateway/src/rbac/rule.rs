use serde::{Deserialize, Deserializer, Serialize};

use crate::auth::{AuthMethod, Principal};

pub const AUTH_METHOD_BEARER_TOKEN: &str = "bearer_token";
pub const AUTH_METHOD_SESSION_COOKIE: &str = "session_cookie";
pub const AUTH_METHOD_SERVICE_TOKEN: &str = "service_token";
pub const AUTH_METHOD_CLIENT_CERTIFICATE: &str = "client_certificate";

/// Every auth method name a policy may name, in one place.
///
/// [`valid_auth_method_name`] is defined over this list rather than repeating
/// it, and `docs/schemas/policy.v0.schema.json` is checked against it, because
/// the three used to be three separate copies: adding
/// `client_certificate` to the parser and the admin UI while leaving the
/// published schema at three entries produced a name the gateway accepted, the
/// rule editor offered, and every operator's schema validation rejected.
pub const ALL_AUTH_METHOD_NAMES: &[&str] = &[
    AUTH_METHOD_BEARER_TOKEN,
    AUTH_METHOD_SESSION_COOKIE,
    AUTH_METHOD_SERVICE_TOKEN,
    AUTH_METHOD_CLIENT_CERTIFICATE,
];

/// Action applied by a first-match-wins firewall rule.
///
/// HTTP path rules normally run before, and take precedence over, the
/// routes/permission model. Host-qualified proxy fallback is the exception:
/// direct allow and shadow rules cannot authorize a selected virtual upstream,
/// a matching deny still blocks, and authorization must come from a host-bound
/// route rule. A first-matching shadow still records policy-authoring telemetry.
/// MCP tool-name rules are an additional restriction layered after per-tool
/// `allowed_roles`; an `Allow` or `Shadow` tool rule does not override a failed
/// role check. `Shadow` records a would-deny observation event while still
/// permitting the rule layer.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    Allow,
    Deny,
    Shadow,
}

/// Principal constraints for a firewall rule.
///
/// Non-empty fields are ANDed together: a principal must satisfy the role
/// constraint, the issuer constraint, the authentication-method constraint, and the principal-id
/// constraint when each is configured. Within one field, any listed value
/// matches. Empty fields are unconstrained, and a completely empty matcher
/// matches any caller, including unauthenticated requests.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalMatcher {
    /// Role names this rule matches. Empty means any role set.
    #[serde(default)]
    pub roles: Vec<String>,
    /// Exact authenticated issuer or configured provider-boundary values this
    /// rule matches. Empty means any issuer.
    #[serde(default)]
    pub issuers: Vec<String>,
    /// Authentication methods this rule matches: "bearer_token",
    /// "session_cookie", or "service_token". Empty means any authentication
    /// method.
    #[serde(default)]
    pub auth_methods: Vec<String>,
    /// Exact principal user_id values this rule matches. Empty means any
    /// principal id.
    #[serde(default)]
    pub principal_ids: Vec<String>,
}

/// Dispatch class captured when a traffic-derived HTTP rule is authored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleDispatchKind {
    Contextless,
    Legacy,
    Route,
}

/// Optional proxy-dispatch provenance for an HTTP firewall rule.
///
/// Presence binds a rule either to classified traffic with no selected proxy
/// dispatch, to the legacy fallback upstream at the configured origin, or to
/// a stable logical proxy route.
/// Omitting `dispatch` preserves the historical globally scoped behavior.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuleDispatchMatcher {
    pub kind: RuleDispatchKind,
    #[serde(
        default,
        deserialize_with = "deserialize_present_value",
        skip_serializing_if = "Option::is_none"
    )]
    pub upstream_origin: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_present_value",
        skip_serializing_if = "Option::is_none"
    )]
    pub route_id: Option<String>,
}

impl RuleDispatchMatcher {
    pub fn contextless() -> Self {
        Self {
            kind: RuleDispatchKind::Contextless,
            upstream_origin: None,
            route_id: None,
        }
    }

    pub fn legacy(upstream_origin: String) -> Self {
        Self {
            kind: RuleDispatchKind::Legacy,
            upstream_origin: Some(upstream_origin),
            route_id: None,
        }
    }

    pub fn route(route_id: String) -> Self {
        Self {
            kind: RuleDispatchKind::Route,
            upstream_origin: None,
            route_id: Some(route_id),
        }
    }
}

impl PrincipalMatcher {
    #[allow(dead_code)]
    pub fn is_unconstrained(&self) -> bool {
        self.roles.is_empty()
            && self.issuers.is_empty()
            && self.auth_methods.is_empty()
            && self.principal_ids.is_empty()
    }

    /// Returns true when the optional principal satisfies every configured
    /// constraint. A completely empty matcher returns true for authenticated
    /// and unauthenticated callers.
    #[allow(dead_code)]
    pub fn matches(&self, principal: Option<&Principal>) -> bool {
        if self.is_unconstrained() {
            return true;
        }

        let Some(principal) = principal else {
            return false;
        };

        constraint_matches(&self.roles, |role| {
            principal
                .roles
                .iter()
                .any(|principal_role| principal_role == role)
        }) && principal_identity_matches(&self.issuers, &self.auth_methods, principal)
            && constraint_matches(&self.principal_ids, |principal_id| {
                principal.user_id == principal_id
            })
    }
}

/// Direct firewall rule model for HTTP paths or exact MCP tool names.
///
/// Rules are stored in policy order and are intended to be evaluated with
/// first-match-wins semantics.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// Optional stable identifier for audit/observation attribution and future
    /// rule-management APIs. When omitted, live evaluation falls back to the
    /// rule's array index.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Whether this rule participates in live evaluation. Omitted legacy rules
    /// default to enabled.
    #[serde(default = "default_rule_enabled")]
    #[serde(skip_serializing_if = "is_default_rule_enabled")]
    pub enabled: bool,
    /// HTTP methods this rule matches. Empty or ["*"] matches any method.
    #[serde(default)]
    pub methods: Vec<String>,
    /// Absolute HTTP path pattern matched against the whole request path and
    /// fully rendered local tool HTTP operations before upstream egress.
    ///
    /// Syntax is segment-based and anchored, never substring-based. Literal
    /// segments match exactly and case-sensitively. `*` matches exactly one
    /// non-empty path segment. `**` matches zero or more complete path
    /// segments. `{name}` matches exactly one non-empty path segment and names
    /// the capture for future rule-preview/discovery UI; capture names use
    /// ASCII letters, digits, and `_`, and must start with a letter or `_`.
    #[serde(default)]
    #[serde(skip_serializing_if = "String::is_empty")]
    pub path: String,
    /// Exact MCP tool name this rule matches. Tool-name rules apply only to
    /// MCP tool calls and never to HTTP requests.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    /// Optional dispatch provenance. `kind: "contextless"` restricts the rule
    /// to classified requests without proxy dispatch; `kind: "legacy"` also
    /// requires the configured fallback origin and excludes routed upstreams;
    /// `kind: "route"` binds to one stable logical proxy route ID.
    /// Omitted means any dispatch context for backward compatibility.
    #[serde(
        default,
        deserialize_with = "deserialize_present_value",
        skip_serializing_if = "Option::is_none"
    )]
    pub dispatch: Option<RuleDispatchMatcher>,
    /// Optional principal constraints. Empty or omitted means any principal,
    /// authenticated or not.
    #[serde(default)]
    pub principal: PrincipalMatcher,
    pub action: RuleAction,
}

fn deserialize_present_value<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

impl Rule {
    /// Returns true when this rule matches the request tuple.
    ///
    /// Policy-level evaluation should use `RuleMatcher` so path patterns are
    /// parsed once per loaded policy instead of once per request.
    #[allow(dead_code)]
    pub fn matches(&self, method: &str, path: &str, principal: Option<&Principal>) -> bool {
        super::matcher::rule_matches(self, method, path, principal)
    }
}

pub fn default_rule_enabled() -> bool {
    true
}

fn is_default_rule_enabled(value: &bool) -> bool {
    *value
}

pub fn valid_auth_method_name(value: &str) -> bool {
    ALL_AUTH_METHOD_NAMES.contains(&value)
}

pub(crate) fn principal_identity_matches(
    issuers: &[String],
    auth_methods: &[String],
    principal: &Principal,
) -> bool {
    constraint_matches(issuers, |issuer| {
        principal.issuer.as_deref() == Some(issuer)
    }) && constraint_matches(auth_methods, |auth_method| {
        auth_method == auth_method_policy_value(&principal.auth_method)
    })
}

pub(crate) fn auth_method_policy_value(auth_method: &AuthMethod) -> &'static str {
    match auth_method {
        AuthMethod::Bearer => AUTH_METHOD_BEARER_TOKEN,
        AuthMethod::Cookie => AUTH_METHOD_SESSION_COOKIE,
        AuthMethod::ServiceToken => AUTH_METHOD_SERVICE_TOKEN,
        AuthMethod::ClientCertificate => AUTH_METHOD_CLIENT_CERTIFICATE,
    }
}

fn constraint_matches(values: &[String], matches_value: impl Fn(&str) -> bool) -> bool {
    values.is_empty() || values.iter().any(|value| matches_value(value))
}

#[cfg(test)]
#[path = "rule_tests.rs"]
mod tests;
