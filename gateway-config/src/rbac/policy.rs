//! The RBAC policy document: its model and its validating parse, for policy
//! v0 and policy v1 (`super::policy_document`), shared by the gateway and
//! `ggctl` (issue #242).
//!
//! [`Policy::validate_json_value`] and [`Policy::from_source`] are the one
//! validating parse every path a policy is accepted by runs: startup and
//! reload, the admin API, drafts, simulations, test runs, the cluster store,
//! and configuration bundles in both the gateway and `ggctl`. Nothing here
//! reads a file, a clock or the network. Loading a policy file, persisting
//! one, watching it and evaluating a policy are the gateway's
//! (`gateway/src/rbac`), which re-exports this module.

use std::{
    collections::{HashMap, HashSet},
    error::Error,
    fmt, io,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

use super::conditions::{canonicalize_condition_issuers, validate_condition, ConditionTarget};
use super::identity_mappings::{
    canonicalize_identity_mapping_issuers, validate_identity_mappings, IdentityMapping,
};
use super::path_pattern::find_malformed_capture_segment;
use super::policy_document::{self, pointer_token, IssueCode, PolicyIssue, PolicySchema};
use super::rule::{
    valid_auth_method_name, PrincipalMatcher, Rule, RuleDispatchKind, AUTH_METHOD_BEARER_TOKEN,
    AUTH_METHOD_SESSION_COOKIE,
};
use crate::{auth::canonical_issuer, request_bounds::MAX_TOOL_NAME_BYTES};

/// The top-level members a 0.x document may have. A 0.x reader warns about
/// any other member and drops it, except one of [`V1_ONLY_TOP_LEVEL_KEYS`],
/// which it refuses.
pub const KNOWN_TOP_LEVEL_KEYS: &[&str] = &[
    "schema_version",
    "id",
    "default_action",
    "enforcement_mode",
    "roles",
    "routes",
    "rules",
    "egress",
    "rate_limits",
    "tools",
];
/// The top-level members only policy v1 defines.
pub const V1_ONLY_TOP_LEVEL_KEYS: &[&str] = &["identity_mappings"];
/// The closed top-level vocabulary of policy v1, in the order the gateway
/// writes the members.
pub const V1_TOP_LEVEL_KEYS: &[&str] = &[
    "schema_version",
    "id",
    "default_action",
    "enforcement_mode",
    "roles",
    "identity_mappings",
    "routes",
    "rules",
    "egress",
    "rate_limits",
    "tools",
];
/// The largest policy document the gateway reads from a file, and the
/// largest policy v1 document it accepts from any source.
pub const MAX_POLICY_FILE_BYTES: u64 = 1_048_576;
/// The longest role description, in bytes.
pub const MAX_ROLE_DESCRIPTION_BYTES: usize = 512;

pub const DEFAULT_TOOL_POLICY_TIMEOUT_MS: u64 = 30_000;
pub const DEFAULT_TOOL_POLICY_MAX_CONCURRENT: u32 = 8;

/// Action to apply when no route rule matches.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DefaultAction {
    Allow,
    Deny,
}

#[allow(clippy::derivable_impls)]
impl Default for DefaultAction {
    fn default() -> Self {
        Self::Deny
    }
}

/// Enforcement behavior for authorization denials.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum EnforcementMode {
    #[default]
    Enforce,
    Shadow,
}

/// RBAC policy document.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Policy {
    pub schema_version: String,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Governs routes not matched by any rule.
    ///
    /// Enforcement happens in the RBAC middleware in PR 2; the pure engine
    /// kernel only stores this value.
    #[serde(default)]
    pub default_action: DefaultAction,
    /// Governs whether deny decisions block or are observed as would-deny events.
    #[serde(default)]
    pub enforcement_mode: EnforcementMode,
    #[serde(default)]
    pub roles: HashMap<String, RoleEntry>,
    /// Ordered identity mappings (`super::identity_mappings`). Present, even
    /// empty, puts the policy in mapped-role mode: a principal's internal
    /// roles are then the ones the mappings grant it, never its claimed roles.
    /// Policy v1 only: a 0.x document that sets it is refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_mappings: Option<Vec<IdentityMapping>>,
    /// Ordered route-to-permission rules. First matching rule wins.
    #[serde(default)]
    pub routes: Vec<RouteRule>,
    /// Ordered direct firewall rules for inbound requests and rendered local
    /// tool HTTP operations. First matching rule wins per target type.
    #[serde(default)]
    pub rules: Vec<Rule>,
    /// Policy-driven outbound egress rules layered on top of env-var defaults.
    #[serde(default)]
    #[serde(skip_serializing_if = "EgressPolicy::is_empty")]
    pub egress: EgressPolicy,
    /// Ordered rate-limit override rules. First matching rule wins.
    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rate_limits: Vec<RateLimitRule>,
    /// Per-tool invocation policy used by the generic MCP tool runtime.
    #[serde(default)]
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub tools: HashMap<String, ToolPolicyEntry>,
}

/// Permissions granted by one role.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RoleEntry {
    #[serde(default)]
    pub permissions: Vec<String>,
    /// Issuers allowed to activate this role's permissions. Empty means any issuer.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issuers: Vec<String>,
    /// Authentication methods allowed to activate this role's permissions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub auth_methods: Vec<String>,
    /// What the role is for, for the people who maintain the policy. It
    /// grants and restricts nothing. A gateway that predates it refuses a
    /// document that sets it, so in cluster mode writing one is a gated
    /// operation (`storage::compatibility`, issue #426).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Permission required for requests matching a path prefix and optional method set.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouteRule {
    /// Stable identifier. Policy v1 requires one, unique across rules,
    /// routes and rate overrides; a 0.x document must omit it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// HTTP methods this rule matches. Empty or ["*"] matches any method.
    #[serde(default)]
    pub methods: Vec<String>,
    /// Exact request hosts this route rule matches. Empty matches only
    /// upstream routes that are not host-qualified.
    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<String>,
    /// Absolute path prefix this rule matches. Rules are evaluated in order.
    pub path_prefix: String,
    /// Permission required to access a matching route.
    pub permission: String,
    /// Optional per-rule enforcement override. Unset inherits the policy default.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enforcement_mode: Option<EnforcementMode>,
}

/// Policy-driven outbound egress rules.
///
/// `hosts` are case-insensitive hostname patterns. A pattern without `*`
/// matches exactly. A wildcard is only valid as the entire leftmost label in
/// a `*.` prefix, such as `*.example.com`; it matches any non-empty DNS label
/// prefix ending in `.example.com`, including `foo.example.com` and
/// `bar.baz.example.com`, but not `example.com`.
///
/// These rules are additive to `EGRESS_ALLOWED_HOSTS` and auto-seeded
/// infrastructure endpoint hosts. `cidrs` explicitly permit matching private
/// resolved IPs through `EGRESS_DENY_PRIVATE_IPS=true`; non-global IPs outside
/// these CIDRs still fail closed. If `ports` is non-empty, the destination port
/// must be listed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EgressPolicy {
    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<String>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub cidrs: Vec<String>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<u16>,
}

/// Policy-driven rate-limit override rule.
///
/// Rules are evaluated in document order with first-match-wins semantics.
/// Empty `methods` match any method. An omitted `path` matches any request
/// path; when present, it uses the same anchored segment glob syntax as
/// direct firewall rule paths.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitRule {
    /// Stable identifier. Policy v1 requires one, unique across rules,
    /// routes and rate overrides; a 0.x document must omit it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Optional principal constraints. Empty or omitted means any principal,
    /// authenticated or not.
    #[serde(default)]
    pub principal: PrincipalMatcher,
    /// HTTP methods this rule matches. Empty or ["*"] matches any method.
    #[serde(default)]
    pub methods: Vec<String>,
    /// Absolute path pattern matched against the whole request path.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub requests_per_second: f64,
    pub burst: u32,
}

/// Per-tool runtime policy for generic tool invocation admission.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ToolPolicyEntry {
    /// Whether this tool is available for invocation.
    #[serde(default = "default_tool_policy_enabled")]
    pub enabled: bool,
    /// Role names allowed to invoke this tool. Empty means no role constraint.
    #[serde(default)]
    pub allowed_roles: Vec<String>,
    /// Issuers allowed to invoke this tool. Empty means any issuer.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issuers: Vec<String>,
    /// Authentication methods allowed to invoke this tool.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub auth_methods: Vec<String>,
    /// Execution timeout for a single invocation, in milliseconds.
    #[serde(default = "default_tool_policy_timeout_ms")]
    pub timeout_ms: u64,
    /// Maximum concurrent executions for this tool.
    #[serde(default = "default_tool_policy_max_concurrent")]
    pub max_concurrent: u32,
}

#[derive(Debug)]
pub enum PolicyError {
    Io {
        path: PathBuf,
        source: io::Error,
    },
    Parse {
        path: Option<PathBuf>,
        source: serde_json::Error,
    },
    Serialize {
        path: PathBuf,
        source: serde_json::Error,
    },
    Write {
        path: PathBuf,
        temp_path: Option<PathBuf>,
        source: io::Error,
    },
    Invalid(String),
    /// A reload/replace changed the `egress` section, which cannot be applied
    /// without a restart. The existing policy remains active.
    EgressReloadRejected,
}

/// Why [`Policy::persisted_bytes`] produced no bytes.
#[derive(Debug)]
pub enum PersistedPolicyError {
    Serialize(serde_json::Error),
    /// The policy file would be `len` bytes, more than
    /// [`MAX_POLICY_FILE_BYTES`].
    TooLarge {
        len: usize,
    },
}

impl fmt::Display for PersistedPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Serialize(source) => write!(formatter, "failed to serialize policy: {source}"),
            Self::TooLarge { len } => write!(
                formatter,
                "the policy file would be {len} bytes, more than the maximum size of \
                 {MAX_POLICY_FILE_BYTES} bytes a policy file is read under"
            ),
        }
    }
}

impl Policy {
    /// Parses and validates a policy document from the bytes it was read
    /// from. A v1 document is also held to what only its bytes can show:
    /// its size, and that no object repeats a member name.
    pub fn from_source(source: &[u8], path: Option<&Path>) -> Result<Self, PolicyError> {
        let value: Value = serde_json::from_slice(source).map_err(|source| PolicyError::Parse {
            path: path.map(Path::to_owned),
            source,
        })?;
        if PolicySchema::of_document(&value) == Some(PolicySchema::V1) {
            return policy_document::parse_v1_source(source, &value)
                .map_err(PolicyError::from_issues);
        }

        Self::from_json_value(value, path)
    }

    pub fn validate_json_value(value: Value) -> Result<Self, PolicyError> {
        Self::from_json_value(value, None)
    }

    /// Whether any role carries a `description`, which a gateway that
    /// predates the field cannot parse. Cluster-mode writers ask the
    /// operation gate before committing such a document.
    pub fn uses_role_descriptions(&self) -> bool {
        self.roles.values().any(|role| role.description.is_some())
    }

    /// Whether this is a policy v1 document (document format 1), which a
    /// gateway that does not serve format 1 in cluster mode refuses.
    /// Cluster-mode writers ask the operation gate before committing one
    /// (the gateway's `storage::compatibility::POLICY_DOCUMENT_V1`).
    pub fn is_document_format_v1(&self) -> bool {
        PolicySchema::of_version(&self.schema_version) == Some(PolicySchema::V1)
    }

    /// The exact bytes the gateway's `persist_to_file` writes: the
    /// pretty-printed document and a final newline. Refused when they exceed
    /// [`MAX_POLICY_FILE_BYTES`], the bound the gateway's `from_file` reads a
    /// policy file under, so the gateway never writes a policy file it would
    /// then refuse to read back. The pretty form is larger than the compact
    /// one a request body or a draft is measured in, so a writer asks this
    /// before anything is written.
    pub fn persisted_bytes(&self) -> Result<Vec<u8>, PersistedPolicyError> {
        let mut contents =
            serde_json::to_vec_pretty(self).map_err(PersistedPolicyError::Serialize)?;
        contents.push(b'\n');
        if contents.len() as u64 > MAX_POLICY_FILE_BYTES {
            return Err(PersistedPolicyError::TooLarge {
                len: contents.len(),
            });
        }
        Ok(contents)
    }

    /// Parses and validates a document already read as JSON. `path` only
    /// names the file in a parse error.
    pub fn from_json_value(value: Value, path: Option<&Path>) -> Result<Self, PolicyError> {
        // Exact dispatch: only `1.0.0` reads as v1. Everything else takes the
        // 0.x path, which refuses any version that does not start with `0.`.
        if PolicySchema::of_document(&value) == Some(PolicySchema::V1) {
            return policy_document::parse_v1(&value).map_err(PolicyError::from_issues);
        }
        warn_unknown_top_level_keys(&value);

        Self::parse_v0(&value).map_err(|rejection| match rejection {
            V0Rejection::Parse(source) => PolicyError::Parse {
                path: path.map(Path::to_owned),
                source,
            },
            V0Rejection::Invalid(issue) => issue.into(),
        })
    }

    /// Reads a document under the 0.x rules, exactly as every release before
    /// policy v1 did. Logs nothing: the caller decides whether this reading
    /// warns about the top-level members it drops.
    pub(super) fn parse_v0(value: &Value) -> Result<Self, V0Rejection> {
        validate_rule_target_properties(value).map_err(V0Rejection::Invalid)?;

        let mut policy = Self::deserialize(value).map_err(V0Rejection::Parse)?;
        policy.canonicalize_issuers();
        policy.check_semantics().map_err(V0Rejection::Invalid)?;

        Ok(policy)
    }

    pub(super) fn canonicalize_issuers(&mut self) {
        for role in self.roles.values_mut() {
            canonicalize_issuer_list(&mut role.issuers);
        }
        for rule in &mut self.rules {
            canonicalize_principal_matcher_issuers(&mut rule.principal);
            if let Some(conditions) = rule.conditions.as_mut() {
                canonicalize_condition_issuers(conditions);
            }
        }
        if let Some(mappings) = self.identity_mappings.as_mut() {
            canonicalize_identity_mapping_issuers(mappings);
        }
        for rule in &mut self.rate_limits {
            canonicalize_principal_matcher_issuers(&mut rule.principal);
        }
        for tool in self.tools.values_mut() {
            canonicalize_issuer_list(&mut tool.issuers);
        }
    }

    /// The semantic validation both schemas share, stopping at the first
    /// problem. The schema version is checked first, then the members only
    /// policy v1 defines, then every section.
    pub(super) fn check_semantics(&self) -> Result<(), PolicyIssue> {
        match PolicySchema::of_version(&self.schema_version) {
            None => {
                return Err(PolicyIssue::new(
                    IssueCode::SchemaVersionUnsupported,
                    "/schema_version".to_owned(),
                    format!(
                        "policy schema_version must start with \"0.\" or be exactly \"{}\", \
                         got '{}'",
                        policy_document::POLICY_V1_SCHEMA_VERSION,
                        self.schema_version
                    ),
                ));
            }
            Some(PolicySchema::V0) => validate_v0_has_no_v1_members(self)?,
            Some(PolicySchema::V1) => {}
        }

        validate_routes(&self.routes)?;
        validate_rules(&self.rules)?;
        validate_rate_limits(&self.rate_limits)?;
        validate_roles(&self.roles)?;
        if let Some(mappings) = self.identity_mappings.as_deref() {
            validate_identity_mappings(mappings, &self.roles)?;
        }
        validate_tools(&self.tools)?;

        self.egress.validate()
    }
}

/// Why a 0.x reading refused a document.
#[derive(Debug)]
pub(super) enum V0Rejection {
    /// The document does not have the policy's shape.
    Parse(serde_json::Error),
    /// It has the shape, and a value is invalid.
    Invalid(PolicyIssue),
}

/// A 0.x document cannot carry the ids policy v1 adds to routes and rate
/// overrides, nor its identity mappings or rule conditions. Refusing them
/// keeps a 0.x document's meaning the same in every gateway that accepts it,
/// a release that predates v1 included: that one refuses an id or a condition
/// outright, and ignores `identity_mappings` -- which this release therefore
/// refuses rather than also ignore, so that no 0.x document is accepted
/// while it asks for a mapping nothing applies.
fn validate_v0_has_no_v1_members(policy: &Policy) -> Result<(), PolicyIssue> {
    if policy.identity_mappings.is_some() {
        return Err(PolicyIssue::new(
            IssueCode::MemberRequiresV1,
            "/identity_mappings".to_owned(),
            format!(
                "identity_mappings requires schema_version \"{}\"",
                policy_document::POLICY_V1_SCHEMA_VERSION
            ),
        ));
    }
    if let Some(rule_index) = policy
        .rules
        .iter()
        .position(|rule| rule.conditions.is_some())
    {
        return Err(PolicyIssue::new(
            IssueCode::MemberRequiresV1,
            format!("/rules/{rule_index}/conditions"),
            format!(
                "rules[{rule_index}].conditions requires schema_version \"{}\"",
                policy_document::POLICY_V1_SCHEMA_VERSION
            ),
        ));
    }
    if let Some(route_index) = policy.routes.iter().position(|route| route.id.is_some()) {
        return Err(PolicyIssue::new(
            IssueCode::MemberRequiresV1,
            format!("/routes/{route_index}/id"),
            format!(
                "routes[{route_index}].id requires schema_version \"{}\"; a 0.x document's \
                 routes carry no id",
                policy_document::POLICY_V1_SCHEMA_VERSION
            ),
        ));
    }
    if let Some(rule_index) = policy.rate_limits.iter().position(|rule| rule.id.is_some()) {
        return Err(PolicyIssue::new(
            IssueCode::MemberRequiresV1,
            format!("/rate_limits/{rule_index}/id"),
            format!(
                "rate_limits[{rule_index}].id requires schema_version \"{}\"; a 0.x \
                 document's rate overrides carry no id",
                policy_document::POLICY_V1_SCHEMA_VERSION
            ),
        ));
    }
    Ok(())
}

fn validate_routes(routes: &[RouteRule]) -> Result<(), PolicyIssue> {
    for (route_index, route) in routes.iter().enumerate() {
        if !route.path_prefix.starts_with('/') {
            return Err(PolicyIssue::new(
                IssueCode::PathNotAbsolute,
                format!("/routes/{route_index}/path_prefix"),
                format!("routes[{route_index}].path_prefix must start with '/'"),
            ));
        }
        let mut seen = HashSet::new();
        for (host_index, host) in route.hosts.iter().enumerate() {
            if host.trim() != host || !is_valid_hostname_without_port(host) {
                return Err(PolicyIssue::new(
                    IssueCode::RouteHostInvalid,
                    format!("/routes/{route_index}/hosts/{host_index}"),
                    format!(
                        "routes[{route_index}].hosts must contain hostnames without ports, got \
                         '{host}'"
                    ),
                ));
            }
            if !seen.insert(host.to_ascii_lowercase()) {
                return Err(PolicyIssue::new(
                    IssueCode::RouteHostDuplicate,
                    format!("/routes/{route_index}/hosts/{host_index}"),
                    format!("routes[{route_index}].hosts contains duplicate hostname '{host}'"),
                ));
            }
        }
    }

    Ok(())
}

pub(super) fn validate_rule_target_properties(value: &Value) -> Result<(), PolicyIssue> {
    let Some(rules) = value.get("rules").and_then(Value::as_array) else {
        return Ok(());
    };

    for (rule_index, rule) in rules.iter().enumerate() {
        let Some(rule) = rule.as_object() else {
            continue;
        };
        let has_path = rule.contains_key("path");
        let has_tool_name = rule.contains_key("tool_name");

        if has_path == has_tool_name {
            return Err(rule_target_issue(rule_index));
        }
    }

    Ok(())
}

fn rule_target_issue(rule_index: usize) -> PolicyIssue {
    PolicyIssue::new(
        IssueCode::RuleTargetInvalid,
        format!("/rules/{rule_index}"),
        format!("rules[{rule_index}] must set exactly one of path or tool_name"),
    )
}

fn validate_rules(rules: &[Rule]) -> Result<(), PolicyIssue> {
    for (rule_index, rule) in rules.iter().enumerate() {
        let has_path = !rule.path.is_empty();
        let has_tool_name = rule.tool_name.is_some();
        let pointer = format!("/rules/{rule_index}");

        if has_path == has_tool_name {
            return Err(rule_target_issue(rule_index));
        }

        if let Some(tool_name) = rule.tool_name.as_deref() {
            if tool_name.trim().is_empty() {
                return Err(PolicyIssue::new(
                    IssueCode::ToolNameEmpty,
                    format!("{pointer}/tool_name"),
                    format!("rules[{rule_index}].tool_name must not be empty"),
                ));
            }

            // The bound the tool lane evaluates names under, so no rule can name
            // a tool the evaluator cannot be asked about.
            if tool_name.len() > MAX_TOOL_NAME_BYTES {
                return Err(PolicyIssue::new(
                    IssueCode::ToolNameTooLong,
                    format!("{pointer}/tool_name"),
                    format!(
                        "rules[{rule_index}].tool_name must not exceed {MAX_TOOL_NAME_BYTES} bytes"
                    ),
                ));
            }

            if !rule.methods.is_empty() {
                return Err(PolicyIssue::new(
                    IssueCode::ToolRuleMethodsPresent,
                    format!("{pointer}/methods"),
                    format!("rules[{rule_index}].methods must be empty when tool_name is set"),
                ));
            }

            if rule.dispatch.is_some() {
                return Err(PolicyIssue::new(
                    IssueCode::ToolRuleDispatchPresent,
                    format!("{pointer}/dispatch"),
                    format!("rules[{rule_index}].dispatch is only valid for HTTP path rules"),
                ));
            }
        }

        if let Some(dispatch) = rule.dispatch.as_ref() {
            let dispatch_pointer = format!("{pointer}/dispatch");
            match dispatch.kind {
                RuleDispatchKind::Contextless => {
                    if dispatch.upstream_origin.is_some() || dispatch.route_id.is_some() {
                        return Err(PolicyIssue::new(
                            IssueCode::DispatchMemberNotAllowed,
                            dispatch_pointer,
                            format!(
                                "rules[{rule_index}].dispatch upstream_origin and route_id must be omitted for a contextless dispatch"
                            ),
                        ));
                    }
                }
                RuleDispatchKind::Legacy => {
                    if dispatch.route_id.is_some() {
                        return Err(PolicyIssue::new(
                            IssueCode::DispatchMemberNotAllowed,
                            format!("{dispatch_pointer}/route_id"),
                            format!(
                                "rules[{rule_index}].dispatch.route_id must be omitted for a legacy dispatch"
                            ),
                        ));
                    }
                    let upstream_origin = dispatch.upstream_origin.as_deref().ok_or_else(|| {
                        PolicyIssue::new(
                            IssueCode::DispatchMemberMissing,
                            format!("{dispatch_pointer}/upstream_origin"),
                            format!(
                                "rules[{rule_index}].dispatch.upstream_origin is required for a legacy dispatch"
                            ),
                        )
                    })?;
                    validate_rule_dispatch_origin(upstream_origin, rule_index)?;
                }
                RuleDispatchKind::Route => {
                    if dispatch.upstream_origin.is_some() {
                        return Err(PolicyIssue::new(
                            IssueCode::DispatchMemberNotAllowed,
                            format!("{dispatch_pointer}/upstream_origin"),
                            format!(
                                "rules[{rule_index}].dispatch.upstream_origin must be omitted for a route dispatch"
                            ),
                        ));
                    }
                    let route_id = dispatch.route_id.as_deref().ok_or_else(|| {
                        PolicyIssue::new(
                            IssueCode::DispatchMemberMissing,
                            format!("{dispatch_pointer}/route_id"),
                            format!(
                                "rules[{rule_index}].dispatch.route_id is required for a route dispatch"
                            ),
                        )
                    })?;
                    if !crate::upstream_route::is_valid_stable_route_id(route_id) {
                        return Err(PolicyIssue::new(
                            IssueCode::DispatchRouteIdInvalid,
                            format!("{dispatch_pointer}/route_id"),
                            format!(
                                "rules[{rule_index}].dispatch.route_id must be a valid stable route ID"
                            ),
                        ));
                    }
                }
            }
        }

        if has_path && !rule.path.starts_with('/') {
            return Err(PolicyIssue::new(
                IssueCode::PathNotAbsolute,
                format!("{pointer}/path"),
                format!(
                    "rules[{rule_index}].path must start with '/', got '{}'",
                    rule.path
                ),
            ));
        }
        if has_path {
            if let Some(segment) = find_malformed_capture_segment(&rule.path) {
                return Err(PolicyIssue::new(
                    IssueCode::PathCaptureMalformed,
                    format!("{pointer}/path"),
                    format!(
                        "rules[{rule_index}].path segment '{segment}' looks like a capture but is not \
                         valid (capture names must start with a letter or underscore and contain only \
                         ASCII letters, digits, and underscores, e.g. '{{id}}'); as written this rule \
                         would never match any request"
                    ),
                ));
            }
        }
        validate_principal_matcher(
            &rule.principal,
            &format!("rules[{rule_index}].principal"),
            &format!("{pointer}/principal"),
        )?;
        if let Some(conditions) = rule.conditions.as_ref() {
            let target = if has_tool_name {
                ConditionTarget::ToolName
            } else {
                ConditionTarget::HttpPath
            };
            validate_condition(
                conditions,
                target,
                &format!("{pointer}/conditions"),
                &format!("rules[{rule_index}].conditions"),
            )?;
        }
    }

    Ok(())
}

fn validate_rule_dispatch_origin(
    upstream_origin: &str,
    rule_index: usize,
) -> Result<(), PolicyIssue> {
    let invalid = |detail: &str| {
        PolicyIssue::new(
            IssueCode::DispatchOriginInvalid,
            format!("/rules/{rule_index}/dispatch/upstream_origin"),
            format!("rules[{rule_index}].dispatch.upstream_origin {detail}"),
        )
    };
    upstream_origin
        .strip_prefix("http://")
        .or_else(|| upstream_origin.strip_prefix("https://"))
        .filter(|authority| {
            !authority.is_empty()
                && !authority
                    .chars()
                    .any(|character| matches!(character, '/' | '?' | '#' | '@'))
        })
        .ok_or_else(|| {
            invalid("must be an HTTP(S) origin without credentials, path, query, or fragment")
        })?;
    let parsed =
        Url::parse(upstream_origin).map_err(|_| invalid("must be a valid HTTP(S) origin"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(invalid("must be a valid HTTP(S) origin"));
    }

    Ok(())
}

fn validate_tools(tools: &HashMap<String, ToolPolicyEntry>) -> Result<(), PolicyIssue> {
    // In name order, so the first problem reported is the same on every run.
    let mut tool_names: Vec<&String> = tools.keys().collect();
    tool_names.sort();
    for tool_name in tool_names {
        // Checked first, and reported without the name: an entry the tool lane
        // could never be asked about must not load, nor echo a payload back.
        // Its pointer is the map for the same reason.
        if tool_name.len() > MAX_TOOL_NAME_BYTES {
            return Err(PolicyIssue::new(
                IssueCode::ToolNameTooLong,
                "/tools".to_owned(),
                format!("tools entry names must not exceed {MAX_TOOL_NAME_BYTES} bytes"),
            ));
        }
        let Some(entry) = tools.get(tool_name) else {
            continue;
        };
        let pointer = format!("/tools/{}", pointer_token(tool_name));
        if entry.timeout_ms == 0 {
            return Err(PolicyIssue::new(
                IssueCode::ToolTimeoutInvalid,
                format!("{pointer}/timeout_ms"),
                format!("tools.{tool_name}.timeout_ms must be positive"),
            ));
        }
        validate_identity_constraints(
            &entry.issuers,
            &entry.auth_methods,
            &format!("tools.{tool_name}"),
            &pointer,
        )?;
    }

    Ok(())
}

fn canonicalize_issuer_list(issuers: &mut Vec<String>) {
    let mut seen = HashSet::new();
    issuers.retain_mut(|issuer| {
        *issuer = canonical_issuer(issuer).unwrap_or_default();
        seen.insert(issuer.clone())
    });
}

pub fn canonicalize_principal_matcher_issuers(principal: &mut PrincipalMatcher) {
    canonicalize_issuer_list(&mut principal.issuers);
}

fn validate_roles(roles: &HashMap<String, RoleEntry>) -> Result<(), PolicyIssue> {
    // In name order, so the first problem reported is the same on every run.
    let mut role_names: Vec<&String> = roles.keys().collect();
    role_names.sort();
    for role_name in role_names {
        let Some(entry) = roles.get(role_name) else {
            continue;
        };
        let pointer = format!("/roles/{}", pointer_token(role_name));
        validate_identity_constraints(
            &entry.issuers,
            &entry.auth_methods,
            &format!("roles.{role_name}"),
            &pointer,
        )?;
        if let Some(description) = entry.description.as_deref() {
            validate_role_description(description, role_name).map_err(|detail| {
                PolicyIssue::new(
                    IssueCode::RoleDescriptionInvalid,
                    format!("{pointer}/description"),
                    detail,
                )
            })?;
        }
    }

    Ok(())
}

/// A role description is free text shown to policy maintainers, so it is
/// bounded and printable: no control characters that could forge a log
/// line or a terminal sequence, and no empty or blank value (omit the field
/// instead).
fn validate_role_description(description: &str, role_name: &str) -> Result<(), String> {
    if description.trim().is_empty() {
        return Err(format!(
            "roles.{role_name}.description must not be empty; omit it instead"
        ));
    }
    if description.len() > MAX_ROLE_DESCRIPTION_BYTES {
        return Err(format!(
            "roles.{role_name}.description must not exceed {MAX_ROLE_DESCRIPTION_BYTES} bytes"
        ));
    }
    if description.chars().any(char::is_control) {
        return Err(format!(
            "roles.{role_name}.description must not contain control characters"
        ));
    }
    Ok(())
}

fn default_tool_policy_enabled() -> bool {
    true
}

fn default_tool_policy_timeout_ms() -> u64 {
    DEFAULT_TOOL_POLICY_TIMEOUT_MS
}

fn default_tool_policy_max_concurrent() -> u32 {
    DEFAULT_TOOL_POLICY_MAX_CONCURRENT
}

fn validate_rate_limits(rate_limits: &[RateLimitRule]) -> Result<(), PolicyIssue> {
    for (rule_index, rule) in rate_limits.iter().enumerate() {
        let pointer = format!("/rate_limits/{rule_index}");
        if !rule.requests_per_second.is_finite() || rule.requests_per_second <= 0.0 {
            return Err(PolicyIssue::new(
                IssueCode::RateLimitRateInvalid,
                format!("{pointer}/requests_per_second"),
                format!(
                    "rate_limits[{rule_index}].requests_per_second must be finite and positive"
                ),
            ));
        }

        if rule.burst == 0 {
            return Err(PolicyIssue::new(
                IssueCode::RateLimitBurstInvalid,
                format!("{pointer}/burst"),
                format!("rate_limits[{rule_index}].burst must be positive"),
            ));
        }

        if let Some(path) = rule.path.as_ref() {
            if !path.starts_with('/') {
                return Err(PolicyIssue::new(
                    IssueCode::PathNotAbsolute,
                    format!("{pointer}/path"),
                    format!("rate_limits[{rule_index}].path must start with '/', got '{path}'"),
                ));
            }
            if let Some(segment) = find_malformed_capture_segment(path) {
                return Err(PolicyIssue::new(
                    IssueCode::PathCaptureMalformed,
                    format!("{pointer}/path"),
                    format!(
                        "rate_limits[{rule_index}].path segment '{segment}' looks like a capture but \
                         is not valid (capture names must start with a letter or underscore and \
                         contain only ASCII letters, digits, and underscores, e.g. '{{id}}'); as \
                         written this override would never match any request"
                    ),
                ));
            }
        }

        validate_principal_matcher(
            &rule.principal,
            &format!("rate_limits[{rule_index}].principal"),
            &format!("{pointer}/principal"),
        )?;
    }

    Ok(())
}

fn validate_principal_matcher(
    principal: &PrincipalMatcher,
    field_path: &str,
    pointer: &str,
) -> Result<(), PolicyIssue> {
    validate_identity_constraints(
        &principal.issuers,
        &principal.auth_methods,
        field_path,
        pointer,
    )
}

/// `field_path` names the constrained object in the historical error text;
/// `pointer` locates it for a structured diagnostic.
fn validate_identity_constraints(
    issuers: &[String],
    auth_methods: &[String],
    field_path: &str,
    pointer: &str,
) -> Result<(), PolicyIssue> {
    if let Some(issuer_index) = issuers.iter().position(|issuer| issuer.trim().is_empty()) {
        return Err(PolicyIssue::new(
            IssueCode::IssuerEmpty,
            format!("{pointer}/issuers/{issuer_index}"),
            format!("{field_path}.issuers must not contain empty values"),
        ));
    }

    for (method_index, auth_method) in auth_methods.iter().enumerate() {
        if !valid_auth_method_name(auth_method) {
            return Err(PolicyIssue::new(
                IssueCode::AuthMethodUnknown,
                format!("{pointer}/auth_methods/{method_index}"),
                format!(
                    "{field_path}.auth_methods contains unknown auth method '{auth_method}', expected \
                     '{AUTH_METHOD_BEARER_TOKEN}', '{AUTH_METHOD_SESSION_COOKIE}', or 'service_token'"
                ),
            ));
        }
    }

    Ok(())
}

impl EgressPolicy {
    /// Whether the section lists nothing, so a document omits it.
    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty() && self.cidrs.is_empty() && self.ports.is_empty()
    }

    fn validate(&self) -> Result<(), PolicyIssue> {
        for (host_index, host) in self.hosts.iter().enumerate() {
            if !is_valid_egress_host_pattern(host) {
                return Err(PolicyIssue::new(
                    IssueCode::EgressHostInvalid,
                    format!("/egress/hosts/{host_index}"),
                    format!(
                        "egress host pattern must be an ASCII hostname or wildcard prefix like \"*.example.com\", got '{host}'"
                    ),
                ));
            }
        }

        for (cidr_index, cidr) in self.cidrs.iter().enumerate() {
            cidr.parse::<ipnet::IpNet>().map_err(|err| {
                PolicyIssue::new(
                    IssueCode::EgressCidrInvalid,
                    format!("/egress/cidrs/{cidr_index}"),
                    format!("egress CIDR '{cidr}' is invalid: {err}"),
                )
            })?;
        }

        if let Some(port_index) = self.ports.iter().position(|port| *port == 0) {
            return Err(PolicyIssue::new(
                IssueCode::EgressPortInvalid,
                format!("/egress/ports/{port_index}"),
                "egress ports must be in the range 1..=65535".to_owned(),
            ));
        }

        Ok(())
    }
}

impl fmt::Display for PolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(
                    formatter,
                    "failed to read policy file {}: {source}",
                    path.display()
                )
            }
            Self::Parse {
                path: Some(path),
                source,
            } => write!(
                formatter,
                "failed to parse policy file {} as JSON: {source}",
                path.display()
            ),
            Self::Parse { path: None, source } => {
                write!(formatter, "failed to parse policy JSON: {source}")
            }
            Self::Serialize { path, source } => write!(
                formatter,
                "failed to serialize policy for {}: {source}",
                path.display()
            ),
            Self::Write {
                path,
                temp_path: Some(temp_path),
                source,
            } => write!(
                formatter,
                "failed to write policy file {} via temporary file {}: {source}",
                path.display(),
                temp_path.display()
            ),
            Self::Write {
                path,
                temp_path: None,
                source,
            } => write!(
                formatter,
                "failed to write policy file {}: {source}",
                path.display()
            ),
            Self::Invalid(message) => write!(formatter, "invalid policy: {message}"),
            Self::EgressReloadRejected => write!(
                formatter,
                "egress allowlist changes cannot be applied by hot reload; edit the policy file and restart the gateway to change egress rules"
            ),
        }
    }
}

impl PolicyError {
    /// A v1 refusal: every issue's detail, joined, so a startup or reload
    /// error names them all.
    pub fn from_issues(issues: Vec<PolicyIssue>) -> Self {
        let details: Vec<String> = issues.into_iter().map(|issue| issue.detail).collect();
        Self::Invalid(details.join("; "))
    }
}

impl From<PolicyIssue> for PolicyError {
    fn from(issue: PolicyIssue) -> Self {
        Self::Invalid(issue.detail)
    }
}

impl Error for PolicyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Parse { source, .. } => Some(source),
            Self::Serialize { source, .. } => Some(source),
            Self::Write { source, .. } => Some(source),
            Self::Invalid(_) => None,
            Self::EgressReloadRejected => None,
        }
    }
}

pub(super) fn warn_unknown_top_level_keys(value: &Value) {
    let unknown_keys = unknown_top_level_keys(value);

    if !unknown_keys.is_empty() {
        tracing::warn!(
            unknown_keys = ?unknown_keys,
            "policy document contains unknown top-level keys"
        );
    }
}

pub fn unknown_top_level_keys(value: &Value) -> Vec<String> {
    let Some(object) = value.as_object() else {
        return Vec::new();
    };

    // A member only v1 defines is not ignored but refused, as
    // `validate_v0_has_no_v1_members` does, so it is not reported as dropped.
    object
        .keys()
        .filter(|key| {
            !KNOWN_TOP_LEVEL_KEYS.contains(&key.as_str())
                && !V1_ONLY_TOP_LEVEL_KEYS.contains(&key.as_str())
        })
        .cloned()
        .collect()
}

fn is_valid_egress_host_pattern(value: &str) -> bool {
    if value.trim() != value {
        return false;
    }

    if let Some(suffix) = value.strip_prefix("*.") {
        is_valid_hostname_without_port(suffix)
    } else {
        !value.contains('*') && is_valid_hostname_without_port(value)
    }
}

fn is_valid_hostname_without_port(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && !value.contains(':')
        && value.split('.').all(is_valid_hostname_label)
}

fn is_valid_hostname_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}
