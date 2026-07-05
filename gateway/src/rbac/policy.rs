use std::{
    collections::HashMap,
    error::Error,
    ffi::OsString,
    fmt, fs, io,
    io::Write,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::rule::{
    valid_auth_method_name, PrincipalMatcher, Rule, AUTH_METHOD_BEARER_TOKEN,
    AUTH_METHOD_SESSION_COOKIE,
};
use crate::config::Config;

const KNOWN_TOP_LEVEL_KEYS: &[&str] = &[
    "schema_version",
    "id",
    "default_action",
    "enforcement_mode",
    "roles",
    "routes",
    "rules",
    "egress",
    "rate_limits",
];
#[allow(dead_code)]
const TEMP_FILE_CREATE_ATTEMPTS: u8 = 16;

#[allow(dead_code)]
static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

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
    /// Ordered route-to-permission rules. First matching rule wins.
    #[serde(default)]
    pub routes: Vec<RouteRule>,
    /// Ordered direct firewall rules. First matching rule wins.
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
}

/// Permissions granted by one role.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RoleEntry {
    #[serde(default)]
    pub permissions: Vec<String>,
}

/// Permission required for requests matching a path prefix and optional method set.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouteRule {
    /// HTTP methods this rule matches. Empty or ["*"] matches any method.
    #[serde(default)]
    pub methods: Vec<String>,
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
/// resolved IPs through `EGRESS_DENY_PRIVATE_IPS=true`; private IPs outside
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
    #[allow(dead_code)]
    Serialize {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[allow(dead_code)]
    Write {
        path: PathBuf,
        temp_path: Option<PathBuf>,
        source: io::Error,
    },
    Invalid(String),
}

impl Policy {
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, PolicyError> {
        let path = path.as_ref();
        let contents = fs::read_to_string(path).map_err(|source| PolicyError::Io {
            path: path.to_owned(),
            source,
        })?;
        let value = serde_json::from_str(&contents).map_err(|source| PolicyError::Parse {
            path: Some(path.to_owned()),
            source,
        })?;

        Self::from_json_value(value, Some(path))
    }

    pub fn from_config(config: &Config) -> Result<Option<Self>, PolicyError> {
        match config.policy_file.as_deref() {
            Some(path) => Self::from_file(path).map(Some),
            None => Ok(None),
        }
    }

    pub fn validate_json_value(value: Value) -> Result<Self, PolicyError> {
        Self::from_json_value(value, None)
    }

    #[allow(dead_code)]
    pub fn persist_to_file(&self, path: impl AsRef<Path>) -> Result<(), PolicyError> {
        self.persist_to_file_with_rename(path.as_ref(), |temp_path, target_path| {
            fs::rename(temp_path, target_path)
        })
    }

    #[allow(dead_code)]
    fn persist_to_file_with_rename<F>(&self, path: &Path, rename: F) -> Result<(), PolicyError>
    where
        F: FnOnce(&Path, &Path) -> io::Result<()>,
    {
        let mut contents =
            serde_json::to_vec_pretty(self).map_err(|source| PolicyError::Serialize {
                path: path.to_owned(),
                source,
            })?;
        contents.push(b'\n');

        persist_policy_bytes_with_rename(path, &contents, rename)
    }

    fn from_json_value(value: Value, path: Option<&Path>) -> Result<Self, PolicyError> {
        warn_unknown_top_level_keys(&value);

        let policy: Self = serde_json::from_value(value).map_err(|source| PolicyError::Parse {
            path: path.map(Path::to_owned),
            source,
        })?;
        policy.validate()?;
        warn_unreachable_route_path_prefixes(&policy);

        Ok(policy)
    }

    fn validate(&self) -> Result<(), PolicyError> {
        if !self.schema_version.starts_with("0.") {
            return Err(PolicyError::Invalid(format!(
                "policy schema_version must start with \"0.\", got '{}'",
                self.schema_version
            )));
        }

        validate_rules(&self.rules)?;
        validate_rate_limits(&self.rate_limits)?;

        self.egress.validate()
    }
}

fn validate_rules(rules: &[Rule]) -> Result<(), PolicyError> {
    for (rule_index, rule) in rules.iter().enumerate() {
        if !rule.path.starts_with('/') {
            return Err(PolicyError::Invalid(format!(
                "rules[{rule_index}].path must start with '/', got '{}'",
                rule.path
            )));
        }
        if let Some(segment) = super::matcher::find_malformed_capture_segment(&rule.path) {
            return Err(PolicyError::Invalid(format!(
                "rules[{rule_index}].path segment '{segment}' looks like a capture but is not \
                 valid (capture names must start with a letter or underscore and contain only \
                 ASCII letters, digits, and underscores, e.g. '{{id}}'); as written this rule \
                 would never match any request"
            )));
        }

        validate_principal_matcher(&rule.principal, &format!("rules[{rule_index}].principal"))?;
    }

    Ok(())
}

fn validate_rate_limits(rate_limits: &[RateLimitRule]) -> Result<(), PolicyError> {
    for (rule_index, rule) in rate_limits.iter().enumerate() {
        if !rule.requests_per_second.is_finite() || rule.requests_per_second <= 0.0 {
            return Err(PolicyError::Invalid(format!(
                "rate_limits[{rule_index}].requests_per_second must be finite and positive"
            )));
        }

        if rule.burst == 0 {
            return Err(PolicyError::Invalid(format!(
                "rate_limits[{rule_index}].burst must be positive"
            )));
        }

        if let Some(path) = rule.path.as_ref() {
            if !path.starts_with('/') {
                return Err(PolicyError::Invalid(format!(
                    "rate_limits[{rule_index}].path must start with '/', got '{path}'"
                )));
            }
            if let Some(segment) = super::matcher::find_malformed_capture_segment(path) {
                return Err(PolicyError::Invalid(format!(
                    "rate_limits[{rule_index}].path segment '{segment}' looks like a capture but \
                     is not valid (capture names must start with a letter or underscore and \
                     contain only ASCII letters, digits, and underscores, e.g. '{{id}}'); as \
                     written this override would never match any request"
                )));
            }
        }

        validate_principal_matcher(
            &rule.principal,
            &format!("rate_limits[{rule_index}].principal"),
        )?;
    }

    Ok(())
}

fn validate_principal_matcher(
    principal: &PrincipalMatcher,
    field_path: &str,
) -> Result<(), PolicyError> {
    for auth_method in &principal.auth_methods {
        if !valid_auth_method_name(auth_method) {
            return Err(PolicyError::Invalid(format!(
                "{field_path}.auth_methods contains unknown auth method '{auth_method}', expected \
                 '{AUTH_METHOD_BEARER_TOKEN}' or '{AUTH_METHOD_SESSION_COOKIE}'"
            )));
        }
    }

    Ok(())
}

impl EgressPolicy {
    fn is_empty(&self) -> bool {
        self.hosts.is_empty() && self.cidrs.is_empty() && self.ports.is_empty()
    }

    fn validate(&self) -> Result<(), PolicyError> {
        for host in &self.hosts {
            if !is_valid_egress_host_pattern(host) {
                return Err(PolicyError::Invalid(format!(
                    "egress host pattern must be an ASCII hostname or wildcard prefix like \"*.example.com\", got '{host}'"
                )));
            }
        }

        for cidr in &self.cidrs {
            cidr.parse::<ipnet::IpNet>().map_err(|err| {
                PolicyError::Invalid(format!("egress CIDR '{cidr}' is invalid: {err}"))
            })?;
        }

        for port in &self.ports {
            if *port == 0 {
                return Err(PolicyError::Invalid(
                    "egress ports must be in the range 1..=65535".to_owned(),
                ));
            }
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
        }
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
        }
    }
}

#[allow(dead_code)]
fn persist_policy_bytes_with_rename<F>(
    path: &Path,
    contents: &[u8],
    rename: F,
) -> Result<(), PolicyError>
where
    F: FnOnce(&Path, &Path) -> io::Result<()>,
{
    let (temp_path, mut temp_file) = create_temp_policy_file(path)?;

    if let Err(source) = write_policy_file_contents(&mut temp_file, contents) {
        drop(temp_file);
        remove_temp_policy_file(path, &temp_path);
        return Err(policy_write_error(path, Some(&temp_path), source));
    }

    drop(temp_file);

    if let Err(source) = rename(&temp_path, path) {
        remove_temp_policy_file(path, &temp_path);
        return Err(policy_write_error(path, Some(&temp_path), source));
    }

    Ok(())
}

#[allow(dead_code)]
fn create_temp_policy_file(path: &Path) -> Result<(PathBuf, fs::File), PolicyError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let Some(file_name) = path.file_name() else {
        return Err(policy_write_error(
            path,
            None,
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "policy file path must include a file name",
            ),
        ));
    };

    for _ in 0..TEMP_FILE_CREATE_ATTEMPTS {
        let temp_path = parent.join(temp_policy_file_name(file_name));
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
        {
            Ok(file) => return Ok((temp_path, file)),
            Err(source) if source.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(source) => return Err(policy_write_error(path, Some(&temp_path), source)),
        }
    }

    Err(policy_write_error(
        path,
        None,
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not create a unique temporary policy file",
        ),
    ))
}

#[allow(dead_code)]
fn temp_policy_file_name(file_name: &std::ffi::OsStr) -> OsString {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let counter = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut temp_file_name = OsString::from(".");
    temp_file_name.push(file_name);
    temp_file_name.push(format!(".{}.{}.{}.tmp", std::process::id(), now, counter));
    temp_file_name
}

#[allow(dead_code)]
fn write_policy_file_contents(file: &mut fs::File, contents: &[u8]) -> io::Result<()> {
    file.write_all(contents)?;
    file.flush()?;
    file.sync_all()
}

#[allow(dead_code)]
fn policy_write_error(path: &Path, temp_path: Option<&Path>, source: io::Error) -> PolicyError {
    PolicyError::Write {
        path: path.to_owned(),
        temp_path: temp_path.map(Path::to_owned),
        source,
    }
}

#[allow(dead_code)]
fn remove_temp_policy_file(path: &Path, temp_path: &Path) {
    if let Err(err) = fs::remove_file(temp_path) {
        tracing::warn!(
            policy_file = %path.display(),
            temp_policy_file = %temp_path.display(),
            error = %err,
            "failed to clean up temporary policy file"
        );
    }
}

fn warn_unknown_top_level_keys(value: &Value) {
    let unknown_keys = unknown_top_level_keys(value);

    if !unknown_keys.is_empty() {
        tracing::warn!(
            unknown_keys = ?unknown_keys,
            "policy document contains unknown top-level keys"
        );
    }
}

fn unknown_top_level_keys(value: &Value) -> Vec<String> {
    let Some(object) = value.as_object() else {
        return Vec::new();
    };

    object
        .keys()
        .filter(|key| !KNOWN_TOP_LEVEL_KEYS.contains(&key.as_str()))
        .cloned()
        .collect()
}

fn warn_unreachable_route_path_prefixes(policy: &Policy) {
    let path_prefixes = unreachable_route_path_prefixes(&policy.routes);

    if !path_prefixes.is_empty() {
        tracing::warn!(
            path_prefixes = ?path_prefixes,
            "policy contains route path_prefix values that do not start with '/' and cannot match request paths"
        );
    }
}

fn unreachable_route_path_prefixes(routes: &[RouteRule]) -> Vec<String> {
    routes
        .iter()
        .filter(|route| !route.path_prefix.starts_with('/'))
        .map(|route| route.path_prefix.clone())
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

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        fs,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    use jsonschema::Validator;
    use serde_json::{json, Value};

    use super::*;
    use crate::rbac::{PrincipalMatcher, RuleAction};

    #[test]
    fn valid_policy_from_file_parses() {
        let file = TempPolicyFile::new(
            r#"{
                "schema_version": "0.1.0",
                "id": "local",
                "roles": {
                    "admin": { "permissions": ["*"] },
                    "reader": { "permissions": ["data:read"] }
                }
            }"#,
        );

        let policy = Policy::from_file(file.path()).expect("valid policy should parse");

        assert_eq!(policy.schema_version, "0.1.0");
        assert_eq!(policy.id.as_deref(), Some("local"));
        assert_eq!(policy.roles["admin"].permissions, vec!["*".to_owned()]);
        assert_eq!(
            policy.roles["reader"].permissions,
            vec!["data:read".to_owned()]
        );
        assert!(policy.routes.is_empty());
        assert!(policy.rules.is_empty());
        assert!(policy.rate_limits.is_empty());
    }

    #[test]
    fn default_action_parses_allow_and_defaults_to_deny() {
        let file = TempPolicyFile::new(
            r#"{
                "schema_version": "0.1.0",
                "default_action": "allow",
                "roles": {
                    "reader": { "permissions": ["data:read"] }
                }
            }"#,
        );

        let policy = Policy::from_file(file.path()).expect("default_action should parse");

        assert_eq!(policy.default_action, DefaultAction::Allow);

        let file = TempPolicyFile::new(
            r#"{
                "schema_version": "0.1.0",
                "roles": {
                    "reader": { "permissions": ["data:read"] }
                }
            }"#,
        );

        let policy = Policy::from_file(file.path()).expect("missing default_action should parse");

        assert_eq!(policy.default_action, DefaultAction::Deny);
    }

    #[test]
    fn enforcement_mode_parses_shadow_and_defaults_to_enforce() {
        let file = TempPolicyFile::new(
            r#"{
                "schema_version": "0.1.0",
                "enforcement_mode": "shadow",
                "roles": {
                    "reader": { "permissions": ["data:read"] }
                },
                "routes": [
                    {
                        "path_prefix": "/admin",
                        "permission": "admin:read",
                        "enforcement_mode": "enforce"
                    },
                    {
                        "path_prefix": "/data",
                        "permission": "data:read"
                    }
                ]
            }"#,
        );

        let policy = Policy::from_file(file.path()).expect("enforcement_mode should parse");

        assert_eq!(policy.enforcement_mode, EnforcementMode::Shadow);
        assert_eq!(
            policy.routes[0].enforcement_mode,
            Some(EnforcementMode::Enforce)
        );
        assert_eq!(policy.routes[1].enforcement_mode, None);

        let file = TempPolicyFile::new(
            r#"{
                "schema_version": "0.1.0",
                "roles": {
                    "reader": { "permissions": ["data:read"] }
                }
            }"#,
        );

        let policy = Policy::from_file(file.path()).expect("missing enforcement_mode should parse");

        assert_eq!(policy.enforcement_mode, EnforcementMode::Enforce);
    }

    #[test]
    fn invalid_enforcement_mode_is_rejected() {
        for document in [
            r#"{
                "schema_version": "0.1.0",
                "enforcement_mode": "maybe",
                "roles": {
                    "reader": { "permissions": ["data:read"] }
                }
            }"#,
            r#"{
                "schema_version": "0.1.0",
                "roles": {
                    "reader": { "permissions": ["data:read"] }
                },
                "routes": [
                    {
                        "path_prefix": "/data",
                        "permission": "data:read",
                        "enforcement_mode": "maybe"
                    }
                ]
            }"#,
        ] {
            let file = TempPolicyFile::new(document);

            let error =
                Policy::from_file(file.path()).expect_err("bad enforcement_mode should fail");

            assert!(matches!(error, PolicyError::Parse { .. }));
            assert!(
                error.to_string().contains("expected `enforce` or `shadow`"),
                "unexpected error: {error}"
            );
        }
    }

    #[test]
    fn bad_schema_version_is_rejected() {
        for schema_version in ["1.0.0", "nope"] {
            let file = TempPolicyFile::new(&format!(
                r#"{{
                    "schema_version": "{schema_version}",
                    "roles": {{ "reader": {{ "permissions": ["data:read"] }} }}
                }}"#
            ));

            let error = Policy::from_file(file.path()).expect_err("bad schema_version should fail");

            assert!(matches!(error, PolicyError::Invalid(_)));
            assert!(
                error.to_string().contains("schema_version must start with"),
                "unexpected error: {error}"
            );
        }
    }

    #[test]
    fn misspelled_role_entry_field_is_rejected() {
        let file = TempPolicyFile::new(
            r#"{
                "schema_version": "0.1.0",
                "roles": {
                    "reader": { "permission": ["data:read"] }
                }
            }"#,
        );

        let error = Policy::from_file(file.path()).expect_err("role entry typo should fail loudly");

        assert!(matches!(error, PolicyError::Parse { .. }));
        assert!(
            error.to_string().contains("unknown field `permission`"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn unknown_top_level_key_detection_names_offending_key() {
        let value = json!({
            "schema_version": "0.1.0",
            "default_action": "deny",
            "roles": {
                "reader": { "permissions": ["data:read"] }
            },
            "unexpected_section": { "ignored": true }
        });

        assert_eq!(
            unknown_top_level_keys(&value),
            vec!["unexpected_section".to_owned()]
        );
    }

    #[test]
    fn unknown_top_level_key_does_not_break_parsing() {
        let file = TempPolicyFile::new(
            r#"{
                "schema_version": "0.1.0",
                "roles": {
                    "reader": { "permissions": ["data:read"] }
                },
                "unexpected_section": { "ignored": true }
            }"#,
        );

        let policy = Policy::from_file(file.path()).expect("unknown keys should not reject policy");

        assert_eq!(
            policy.roles["reader"].permissions,
            vec!["data:read".to_owned()]
        );
    }

    #[test]
    fn routes_section_parses_as_ordered_rules() {
        let file = TempPolicyFile::new(
            r#"{
                "schema_version": "0.1.0",
                "roles": {
                    "reader": { "permissions": ["data:read"] }
                },
                "routes": [
                    { "methods": ["GET"], "path_prefix": "/data", "permission": "data:read" },
                    { "path_prefix": "/admin", "permission": "admin:read" }
                ]
            }"#,
        );

        let policy = Policy::from_file(file.path()).expect("routes section should parse");

        assert!(policy.roles.contains_key("reader"));
        assert_eq!(policy.routes.len(), 2);
        assert_eq!(policy.routes[0].methods, vec!["GET".to_owned()]);
        assert_eq!(policy.routes[0].path_prefix, "/data");
        assert_eq!(policy.routes[0].permission, "data:read");
        assert!(policy.routes[1].methods.is_empty());
        assert_eq!(policy.routes[1].path_prefix, "/admin");
        assert_eq!(policy.routes[1].permission, "admin:read");
    }

    #[test]
    fn rules_section_parses_and_round_trips_as_ordered_first_match_rules() {
        let file = TempPolicyFile::new(
            r#"{
                "schema_version": "0.1.0",
                "rules": [
                    {
                        "id": "support-user-read",
                        "methods": ["GET", "HEAD"],
                        "path": "/api/users/{id}",
                        "principal": {
                            "roles": ["admin", "support"],
                            "auth_methods": ["bearer_token"],
                            "principal_ids": ["user-123"]
                        },
                        "action": "allow"
                    },
                    {
                        "methods": ["POST"],
                        "path": "/api/**",
                        "principal": {
                            "roles": ["writer"],
                            "auth_methods": ["session_cookie"]
                        },
                        "action": "shadow"
                    },
                    {
                        "path": "/admin/**",
                        "principal": {},
                        "action": "deny"
                    }
                ]
            }"#,
        );

        let policy = Policy::from_file(file.path()).expect("rules section should parse");

        assert_eq!(policy.rules.len(), 3);
        assert_eq!(policy.rules[0].id.as_deref(), Some("support-user-read"));
        assert_eq!(
            policy.rules[0].methods,
            vec!["GET".to_owned(), "HEAD".to_owned()]
        );
        assert_eq!(policy.rules[0].path, "/api/users/{id}");
        assert_eq!(
            policy.rules[0].principal,
            PrincipalMatcher {
                roles: vec!["admin".to_owned(), "support".to_owned()],
                auth_methods: vec!["bearer_token".to_owned()],
                principal_ids: vec!["user-123".to_owned()],
            }
        );
        assert_eq!(policy.rules[0].action, RuleAction::Allow);
        assert_eq!(policy.rules[1].action, RuleAction::Shadow);
        assert_eq!(policy.rules[2].action, RuleAction::Deny);
        assert!(policy.rules[2].methods.is_empty());
        assert!(policy.rules[2].principal.is_unconstrained());

        let round_trip_value =
            serde_json::to_value(&policy).expect("policy with rules should serialize");
        let round_tripped: Policy =
            serde_json::from_value(round_trip_value).expect("serialized policy should parse");

        assert_eq!(round_tripped, policy);
    }

    #[test]
    fn rate_limits_section_parses_and_round_trips_as_ordered_first_match_rules() {
        let file = TempPolicyFile::new(
            r#"{
                "schema_version": "0.1.0",
                "rate_limits": [
                    {
                        "methods": ["GET", "HEAD"],
                        "path": "/api/users/{id}",
                        "principal": {
                            "roles": ["admin", "support"],
                            "auth_methods": ["bearer_token"],
                            "principal_ids": ["user-123"]
                        },
                        "requests_per_second": 25.5,
                        "burst": 50
                    },
                    {
                        "principal": {},
                        "requests_per_second": 5.0,
                        "burst": 10
                    }
                ]
            }"#,
        );

        let policy = Policy::from_file(file.path()).expect("rate_limits section should parse");

        assert_eq!(policy.rate_limits.len(), 2);
        assert_eq!(
            policy.rate_limits[0].methods,
            vec!["GET".to_owned(), "HEAD".to_owned()]
        );
        assert_eq!(
            policy.rate_limits[0].path.as_deref(),
            Some("/api/users/{id}")
        );
        assert_eq!(
            policy.rate_limits[0].principal,
            PrincipalMatcher {
                roles: vec!["admin".to_owned(), "support".to_owned()],
                auth_methods: vec!["bearer_token".to_owned()],
                principal_ids: vec!["user-123".to_owned()],
            }
        );
        assert_eq!(policy.rate_limits[0].requests_per_second, 25.5);
        assert_eq!(policy.rate_limits[0].burst, 50);
        assert!(policy.rate_limits[1].methods.is_empty());
        assert!(policy.rate_limits[1].path.is_none());
        assert!(policy.rate_limits[1].principal.is_unconstrained());

        let round_trip_value =
            serde_json::to_value(&policy).expect("policy with rate_limits should serialize");
        let round_tripped: Policy =
            serde_json::from_value(round_trip_value).expect("serialized policy should parse");

        assert_eq!(round_tripped, policy);
    }

    #[test]
    fn malformed_rate_limits_are_rejected_by_parser_and_schema() {
        let cases = [
            (
                "zero rps",
                json!({
                    "schema_version": "0.1.0",
                    "rate_limits": [
                        {
                            "requests_per_second": 0.0,
                            "burst": 1
                        }
                    ]
                }),
                "requests_per_second must be finite and positive",
            ),
            (
                "negative rps",
                json!({
                    "schema_version": "0.1.0",
                    "rate_limits": [
                        {
                            "requests_per_second": -1.0,
                            "burst": 1
                        }
                    ]
                }),
                "requests_per_second must be finite and positive",
            ),
            (
                "zero burst",
                json!({
                    "schema_version": "0.1.0",
                    "rate_limits": [
                        {
                            "requests_per_second": 1.0,
                            "burst": 0
                        }
                    ]
                }),
                "burst must be positive",
            ),
            (
                "non-absolute path",
                json!({
                    "schema_version": "0.1.0",
                    "rate_limits": [
                        {
                            "path": "api/**",
                            "requests_per_second": 1.0,
                            "burst": 1
                        }
                    ]
                }),
                "path must start with '/'",
            ),
            (
                "unknown auth method",
                json!({
                    "schema_version": "0.1.0",
                    "rate_limits": [
                        {
                            "principal": {
                                "auth_methods": ["api_key"]
                            },
                            "requests_per_second": 1.0,
                            "burst": 1
                        }
                    ]
                }),
                "unknown auth method 'api_key'",
            ),
        ];
        let validator = policy_schema_validator();

        for (name, value, expected_error) in cases {
            assert!(
                !validator.is_valid(&value),
                "published schema should reject {name}"
            );

            let error = Policy::from_json_value(value, None)
                .expect_err("malformed rate_limit should fail parser or validation");

            assert!(
                error.to_string().contains(expected_error),
                "unexpected error for {name}: {error}"
            );
        }
    }

    #[test]
    fn malformed_rules_are_rejected_by_parser_and_schema() {
        let cases = [
            (
                "unknown rule field",
                json!({
                    "schema_version": "0.1.0",
                    "rules": [
                        {
                            "path": "/admin/**",
                            "action": "deny",
                            "priority": 10
                        }
                    ]
                }),
                "unknown field `priority`",
            ),
            (
                "invalid action",
                json!({
                    "schema_version": "0.1.0",
                    "rules": [
                        {
                            "path": "/admin/**",
                            "action": "audit"
                        }
                    ]
                }),
                "unknown variant `audit`",
            ),
            (
                "malformed principal matcher field",
                json!({
                    "schema_version": "0.1.0",
                    "rules": [
                        {
                            "path": "/admin/**",
                            "principal": {
                                "roles": "admin"
                            },
                            "action": "deny"
                        }
                    ]
                }),
                "invalid type",
            ),
        ];
        let validator = policy_schema_validator();

        for (name, value, expected_error) in cases {
            assert!(
                !validator.is_valid(&value),
                "published schema should reject {name}"
            );

            let document =
                serde_json::to_string(&value).expect("malformed policy case should serialize");
            let file = TempPolicyFile::new(&document);
            let error = Policy::from_file(file.path())
                .expect_err("malformed rule should fail parser or validation");

            assert!(
                error.to_string().contains(expected_error),
                "unexpected error for {name}: {error}"
            );
        }
    }

    #[test]
    fn malformed_path_capture_segment_is_rejected() {
        let cases = [
            (
                "rule path",
                json!({
                    "schema_version": "0.1.0",
                    "rules": [
                        {
                            "path": "/api/{bad-name}",
                            "action": "deny"
                        }
                    ]
                }),
                "rules[0].path segment '{bad-name}'",
            ),
            (
                "rate limit override path",
                json!({
                    "schema_version": "0.1.0",
                    "rate_limits": [
                        {
                            "path": "/api/{bad-name}",
                            "requests_per_second": 10.0,
                            "burst": 20
                        }
                    ]
                }),
                "rate_limits[0].path segment '{bad-name}'",
            ),
        ];

        for (name, value, expected_error) in cases {
            let document =
                serde_json::to_string(&value).expect("malformed policy case should serialize");
            let file = TempPolicyFile::new(&document);
            let error = Policy::from_file(file.path())
                .expect_err("malformed path capture segment should fail validation");

            assert!(
                error.to_string().contains(expected_error),
                "unexpected error for {name}: {error}"
            );
        }
    }

    #[test]
    fn egress_section_parses_and_defaults_to_empty() {
        let file = TempPolicyFile::new(
            r#"{
                "schema_version": "0.1.0",
                "egress": {
                    "hosts": ["api.example.test", "*.svc.example.test"],
                    "cidrs": ["10.0.0.0/8", "2001:db8::/32"],
                    "ports": [443, 8443]
                }
            }"#,
        );

        let policy = Policy::from_file(file.path()).expect("egress section should parse");

        assert_eq!(
            policy.egress.hosts,
            vec![
                "api.example.test".to_owned(),
                "*.svc.example.test".to_owned()
            ]
        );
        assert_eq!(
            policy.egress.cidrs,
            vec!["10.0.0.0/8".to_owned(), "2001:db8::/32".to_owned()]
        );
        assert_eq!(policy.egress.ports, vec![443, 8443]);

        let file = TempPolicyFile::new(r#"{ "schema_version": "0.1.0" }"#);
        let policy = Policy::from_file(file.path()).expect("missing egress section should parse");

        assert!(policy.egress.is_empty());
    }

    #[test]
    fn malformed_egress_entries_are_rejected_by_rust_parser() {
        for (name, document, expected) in [
            (
                "bad host glob",
                r#"{
                    "schema_version": "0.1.0",
                    "egress": { "hosts": ["api.*.example.test"] }
                }"#,
                "egress host pattern",
            ),
            (
                "bad CIDR",
                r#"{
                    "schema_version": "0.1.0",
                    "egress": { "cidrs": ["10.0.0.0/33"] }
                }"#,
                "egress CIDR",
            ),
            (
                "zero port",
                r#"{
                    "schema_version": "0.1.0",
                    "egress": { "ports": [0] }
                }"#,
                "egress ports",
            ),
            (
                "out-of-range port",
                r#"{
                    "schema_version": "0.1.0",
                    "egress": { "ports": [70000] }
                }"#,
                "invalid value",
            ),
            (
                "unknown egress field",
                r#"{
                    "schema_version": "0.1.0",
                    "egress": { "hostz": ["api.example.test"] }
                }"#,
                "unknown field",
            ),
        ] {
            let file = TempPolicyFile::new(document);
            let error = match Policy::from_file(file.path()) {
                Ok(_) => panic!("{name} should be rejected"),
                Err(error) => error,
            };

            assert!(
                error.to_string().contains(expected),
                "{name} produced unexpected error: {error}"
            );
        }
    }

    #[test]
    fn unknown_rule_auth_method_is_rejected_by_parser_and_schema() {
        let value = json!({
            "schema_version": "0.1.0",
            "rules": [
                {
                    "path": "/admin/**",
                    "principal": {
                        "auth_methods": ["api_key"]
                    },
                    "action": "deny"
                }
            ]
        });
        let validator = policy_schema_validator();

        assert!(
            !validator.is_valid(&value),
            "published schema should reject unknown auth_methods entries"
        );

        let document =
            serde_json::to_string(&value).expect("malformed policy case should serialize");
        let file = TempPolicyFile::new(&document);
        let error =
            Policy::from_file(file.path()).expect_err("unknown auth method should fail validation");

        assert!(matches!(error, PolicyError::Invalid(_)));
        assert!(
            error.to_string().contains("unknown auth method 'api_key'"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn non_absolute_rule_path_is_rejected_by_parser_and_schema() {
        let value = json!({
            "schema_version": "0.1.0",
            "rules": [
                {
                    "path": "admin/**",
                    "action": "deny"
                }
            ]
        });
        let validator = policy_schema_validator();

        assert!(
            !validator.is_valid(&value),
            "published schema should reject non-absolute rule paths"
        );

        let document =
            serde_json::to_string(&value).expect("malformed policy case should serialize");
        let file = TempPolicyFile::new(&document);
        let error = Policy::from_file(file.path()).expect_err("non-absolute rule path should fail");

        assert!(matches!(error, PolicyError::Invalid(_)));
        assert!(
            error
                .to_string()
                .contains("rules[0].path must start with '/'"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn unreachable_route_path_prefix_detection_names_non_absolute_prefixes() {
        let routes = vec![
            route("/data", "data:read"),
            route("admin", "admin:read"),
            route("", "empty:read"),
            route("/reports", "reports:read"),
        ];

        assert_eq!(
            unreachable_route_path_prefixes(&routes),
            vec!["admin".to_owned(), String::new()]
        );
    }

    #[test]
    fn from_config_returns_none_when_policy_file_unset() {
        let config = test_config(None);

        let policy = Policy::from_config(&config).expect("missing policy file should be accepted");

        assert!(policy.is_none());
    }

    #[test]
    fn from_config_loads_policy_when_policy_file_is_set() {
        let file = TempPolicyFile::new(
            r#"{
                "schema_version": "0.1.0",
                "roles": {
                    "reader": { "permissions": ["data:read"] }
                }
            }"#,
        );
        let config = test_config(Some(file.path().to_string_lossy().into_owned()));

        let policy = Policy::from_config(&config)
            .expect("configured policy should load")
            .expect("POLICY_FILE should produce Some policy");

        assert_eq!(
            policy.roles["reader"].permissions,
            vec!["data:read".to_owned()]
        );
    }

    #[test]
    fn persist_to_file_round_trips_policy_document() {
        let file = TempPolicyFile::new(r#"{ "schema_version": "0.1.0" }"#);
        let policy = rich_policy();

        policy
            .persist_to_file(file.path())
            .expect("policy should persist atomically");

        let loaded = Policy::from_file(file.path()).expect("persisted policy should parse");
        let contents = fs::read_to_string(file.path())
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", file.path().display()));
        let value: Value = serde_json::from_str(&contents)
            .unwrap_or_else(|err| panic!("persisted policy should be JSON: {err}"));

        assert_eq!(loaded, policy);
        assert_schema_accepts(&policy_schema_validator(), &value);
    }

    #[test]
    fn persist_to_file_rename_failure_leaves_existing_policy_and_cleans_temp_file() {
        let file = TempPolicyFile::new(
            r#"{
                "schema_version": "0.1.0",
                "default_action": "deny",
                "roles": {
                    "reader": { "permissions": ["data:read"] }
                }
            }"#,
        );
        let original_contents = fs::read_to_string(file.path())
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", file.path().display()));
        let policy = rich_policy();

        let error = policy
            .persist_to_file_with_rename(file.path(), |_temp_path, _target_path| {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "simulated atomic rename failure",
                ))
            })
            .expect_err("rename failure should reject persistence");
        let temp_path = match &error {
            PolicyError::Write {
                temp_path: Some(temp_path),
                ..
            } => temp_path.clone(),
            other => panic!("unexpected persistence error: {other:?}"),
        };

        assert!(
            error.to_string().contains("failed to write policy file"),
            "unexpected error: {error}"
        );
        assert_eq!(
            fs::read_to_string(file.path())
                .unwrap_or_else(|err| panic!("failed to read {}: {err}", file.path().display())),
            original_contents
        );
        assert!(
            !temp_path.exists(),
            "temporary policy file should be removed after rename failure: {}",
            temp_path.display()
        );
    }

    #[test]
    fn published_schema_accepts_valid_policy_and_rejects_bad_schema_version() {
        let validator = policy_schema_validator();
        let valid_policy = json!({
            "schema_version": "0.1.0",
            "id": "local",
            "default_action": "allow",
            "roles": {
                "admin": { "permissions": ["*"] },
                "reader": { "permissions": ["data:read"] }
            }
        });
        let invalid_policy = json!({
            "schema_version": "1.0.0",
            "roles": {
                "reader": { "permissions": ["data:read"] }
            }
        });

        assert_schema_accepts(&validator, &valid_policy);
        assert!(
            !validator.is_valid(&invalid_policy),
            "published schema should reject a policy with a bad schema_version"
        );
    }

    #[test]
    fn starter_policy_file_parses_and_matches_published_schema() {
        let path = repo_root().join("docs/examples/policy.starter.json");
        let policy = Policy::from_file(&path)
            .unwrap_or_else(|err| panic!("starter policy should parse: {err}"));
        let contents = fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
        let value: Value = serde_json::from_str(&contents)
            .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()));

        assert_eq!(policy.schema_version, "0.1.0");
        assert_eq!(policy.id.as_deref(), Some("starter"));
        assert_eq!(policy.default_action, DefaultAction::Allow);
        assert_eq!(policy.enforcement_mode, EnforcementMode::Enforce);
        assert!(policy.roles.is_empty());
        assert!(policy.routes.is_empty());
        assert!(policy.rules.is_empty());
        assert!(policy.rate_limits.is_empty());
        assert_schema_accepts(&policy_schema_validator(), &value);
    }

    #[test]
    fn published_schema_accepts_enforcement_mode_at_top_level_and_route_level() {
        let validator = policy_schema_validator();
        let top_level_policy = json!({
            "schema_version": "0.1.0",
            "default_action": "deny",
            "enforcement_mode": "shadow",
            "roles": {
                "reader": { "permissions": ["data:read"] }
            }
        });
        let route_override_policy = json!({
            "schema_version": "0.1.0",
            "default_action": "deny",
            "roles": {
                "reader": { "permissions": ["data:read"] }
            },
            "routes": [
                {
                    "methods": ["GET", "HEAD"],
                    "path_prefix": "/data",
                    "permission": "data:read",
                    "enforcement_mode": "shadow"
                },
                {
                    "path_prefix": "/admin",
                    "permission": "admin:read",
                    "enforcement_mode": "enforce"
                }
            ]
        });

        assert_schema_accepts(&validator, &top_level_policy);
        assert_schema_accepts(&validator, &route_override_policy);
    }

    #[test]
    fn published_schema_accepts_policy_with_rules() {
        let validator = policy_schema_validator();
        let policy = json!({
            "schema_version": "0.1.0",
            "default_action": "deny",
            "rules": [
                {
                    "id": "support-user-read",
                    "enabled": false,
                    "methods": ["GET", "HEAD"],
                    "path": "/api/users/{id}",
                    "principal": {
                        "roles": ["admin", "support"],
                        "auth_methods": ["bearer_token"],
                        "principal_ids": ["user-123"]
                    },
                    "action": "allow"
                },
                {
                    "methods": ["POST"],
                    "path": "/api/**",
                    "principal": {
                        "roles": ["writer"],
                        "auth_methods": ["session_cookie"]
                    },
                    "action": "shadow"
                },
                {
                    "path": "/admin/**",
                    "principal": {},
                    "action": "deny"
                }
            ]
        });

        assert_schema_accepts(&validator, &policy);
    }

    #[test]
    fn published_schema_accepts_policy_with_rate_limits() {
        let validator = policy_schema_validator();
        let policy = json!({
            "schema_version": "0.1.0",
            "rate_limits": [
                {
                    "methods": ["GET", "HEAD"],
                    "path": "/api/users/{id}",
                    "principal": {
                        "roles": ["admin", "support"],
                        "auth_methods": ["bearer_token"],
                        "principal_ids": ["user-123"]
                    },
                    "requests_per_second": 25.5,
                    "burst": 50
                },
                {
                    "requests_per_second": 5.0,
                    "burst": 10
                }
            ]
        });

        assert_schema_accepts(&validator, &policy);
        Policy::from_json_value(policy, None)
            .expect("schema-valid rate_limits policy should parse");
    }

    #[test]
    fn published_schema_accepts_valid_egress_section() {
        let validator = policy_schema_validator();
        let policy = json!({
            "schema_version": "0.1.0",
            "egress": {
                "hosts": ["api.example.test", "*.svc.example.test"],
                "cidrs": ["10.0.0.0/8", "2001:db8::/32"],
                "ports": [443, 8443]
            }
        });

        assert_schema_accepts(&validator, &policy);
        Policy::from_json_value(policy, None).expect("schema-valid egress policy should parse");
    }

    #[test]
    fn published_schema_rejects_malformed_egress_entries() {
        let validator = policy_schema_validator();

        for (name, policy) in [
            (
                "bad host glob",
                json!({
                    "schema_version": "0.1.0",
                    "egress": { "hosts": ["api.*.example.test"] }
                }),
            ),
            (
                "bad CIDR",
                json!({
                    "schema_version": "0.1.0",
                    "egress": { "cidrs": ["10.0.0.0/33"] }
                }),
            ),
            (
                "out-of-range port",
                json!({
                    "schema_version": "0.1.0",
                    "egress": { "ports": [70000] }
                }),
            ),
            (
                "unknown egress field",
                json!({
                    "schema_version": "0.1.0",
                    "egress": { "hostz": ["api.example.test"] }
                }),
            ),
        ] {
            assert!(
                !validator.is_valid(&policy),
                "published schema should reject {name}"
            );
            assert!(
                Policy::from_json_value(policy, None).is_err(),
                "Rust parser should reject {name}"
            );
        }
    }

    #[test]
    fn published_schema_rejects_bad_enforcement_mode_values() {
        let validator = policy_schema_validator();
        let top_level_policy = json!({
            "schema_version": "0.1.0",
            "enforcement_mode": "maybe"
        });
        let route_override_policy = json!({
            "schema_version": "0.1.0",
            "routes": [
                {
                    "path_prefix": "/data",
                    "permission": "data:read",
                    "enforcement_mode": "maybe"
                }
            ]
        });

        assert!(
            !validator.is_valid(&top_level_policy),
            "published schema should reject a bad top-level enforcement_mode"
        );
        assert!(
            !validator.is_valid(&route_override_policy),
            "published schema should reject a bad route enforcement_mode"
        );
    }

    #[test]
    fn published_schema_accepts_extra_top_level_keys() {
        let validator = policy_schema_validator();
        let policy = json!({
            "schema_version": "0.1.0",
            "roles": {
                "reader": { "permissions": ["data:read"] }
            },
            "future_subsystem": { "enabled": true }
        });

        assert_schema_accepts(&validator, &policy);
    }

    #[test]
    fn published_schema_rejects_unknown_role_entry_fields() {
        let validator = policy_schema_validator();
        let policy = json!({
            "schema_version": "0.1.0",
            "roles": {
                "reader": { "permission": ["data:read"] }
            }
        });

        assert!(
            !validator.is_valid(&policy),
            "published schema should reject unknown role entry fields"
        );
    }

    fn policy_schema_validator() -> Validator {
        let repo_root = repo_root();
        let schema_path = repo_root.join("docs/schemas/policy.v0.schema.json");
        let schema = fs::read_to_string(&schema_path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", schema_path.display()));
        let schema = serde_json::from_str(&schema)
            .unwrap_or_else(|err| panic!("failed to parse {}: {err}", schema_path.display()));

        jsonschema::validator_for(&schema)
            .unwrap_or_else(|err| panic!("failed to compile {}: {err}", schema_path.display()))
    }

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("gateway crate should live directly under the repo root")
            .to_owned()
    }

    fn assert_schema_accepts(validator: &Validator, policy: &Value) {
        if let Err(error) = validator.validate(policy) {
            panic!("published schema should accept policy document: {error}");
        }
    }

    fn route(path_prefix: &str, permission: &str) -> RouteRule {
        RouteRule {
            methods: Vec::new(),
            path_prefix: path_prefix.to_owned(),
            permission: permission.to_owned(),
            enforcement_mode: None,
        }
    }

    fn rich_policy() -> Policy {
        Policy {
            schema_version: "0.1.0".to_owned(),
            id: Some("persisted-policy".to_owned()),
            default_action: DefaultAction::Allow,
            enforcement_mode: EnforcementMode::Shadow,
            roles: HashMap::from([
                (
                    "admin".to_owned(),
                    RoleEntry {
                        permissions: vec!["*".to_owned()],
                    },
                ),
                (
                    "reader".to_owned(),
                    RoleEntry {
                        permissions: vec!["data:read".to_owned(), "reports:read".to_owned()],
                    },
                ),
            ]),
            routes: vec![
                RouteRule {
                    methods: vec!["GET".to_owned(), "HEAD".to_owned()],
                    path_prefix: "/data".to_owned(),
                    permission: "data:read".to_owned(),
                    enforcement_mode: Some(EnforcementMode::Enforce),
                },
                RouteRule {
                    methods: Vec::new(),
                    path_prefix: "/reports".to_owned(),
                    permission: "reports:read".to_owned(),
                    enforcement_mode: None,
                },
            ],
            rules: Vec::new(),
            egress: EgressPolicy::default(),
            rate_limits: vec![RateLimitRule {
                principal: PrincipalMatcher {
                    roles: vec!["admin".to_owned()],
                    auth_methods: vec!["bearer_token".to_owned()],
                    principal_ids: Vec::new(),
                },
                methods: vec!["GET".to_owned()],
                path: Some("/admin/**".to_owned()),
                requests_per_second: 20.0,
                burst: 40,
            }],
        }
    }

    fn test_config(policy_file: Option<String>) -> Config {
        Config {
            listen_addr: "127.0.0.1:0"
                .parse()
                .expect("test listen address should parse"),
            admin_listen_addr: None,
            admin_prefix: "/admin".to_owned(),
            audit_log_file: None,
            audit_sqlite_path: None,
            audit_sqlite_retention_days: None,
            discovery_sqlite_path: None,
            payload_capture_enabled: false,
            payload_capture_sample_rate: crate::config::DEFAULT_PAYLOAD_CAPTURE_SAMPLE_RATE,
            schema_mismatch_signal_threshold:
                crate::discovery::signals::DEFAULT_SCHEMA_MISMATCH_SIGNAL_THRESHOLD,
            error_rate_spike_signal_threshold:
                crate::discovery::signals::DEFAULT_ERROR_RATE_SPIKE_SIGNAL_THRESHOLD,
            principal_new_to_endpoint_signal_threshold:
                crate::discovery::signals::DEFAULT_PRINCIPAL_NEW_TO_ENDPOINT_SIGNAL_THRESHOLD,
            volume_outlier_signal_threshold:
                crate::discovery::signals::DEFAULT_VOLUME_OUTLIER_SIGNAL_THRESHOLD,
            rule_suggestion_baseline_window_hours:
                crate::discovery::suggestions::DEFAULT_RULE_SUGGESTION_BASELINE_WINDOW_HOURS,
            openapi_spec_path: None,
            policy_file,
            policy_history_sqlite_path: None,
            cors_allow_origins: Vec::new(),
            max_body_size: 1_048_576,
            rate_limit_read_rps: 50.0,
            rate_limit_read_burst: 100,
            rate_limit_write_rps: 10.0,
            rate_limit_write_burst: 20,
            trust_proxy_headers: false,
            rbac_exempt_paths: vec![
                "/health".to_owned(),
                "/version".to_owned(),
                "/metrics".to_owned(),
            ],
            session_cookie_name: String::new(),
            validation_allowed_content_types: vec!["application/json".to_owned()],
            auth_enabled: true,
            auth_mode: crate::config::AuthMode::Required,
            auth_cookie_name: "session".to_owned(),
            auth_exempt_paths: vec![
                "/health".to_owned(),
                "/version".to_owned(),
                "/metrics".to_owned(),
            ],
            auth_providers: Vec::new(),
            jwt_jwks_url: None,
            jwt_issuer: None,
            jwt_audience: None,
            jwt_jwks_timeout_ms: 2000,
            jwt_require_jti: false,
            roles_claim: "roles".to_owned(),
            csrf_enabled: true,
            csrf_cookie_name: "csrf_token".to_owned(),
            csrf_header_name: "x-csrf-token".to_owned(),
            csrf_cookie_domain: None,
            csrf_exempt_paths: vec![
                "/health".to_owned(),
                "/version".to_owned(),
                "/metrics".to_owned(),
            ],
            upstream_url: None,
            upstream_routes: Vec::new(),
            upstream_timeout_ms: None,
            upstream_response_idle_timeout_ms: None,
            upstream_connect_timeout_ms: None,
            egress_allowed_hosts: Vec::new(),
            egress_timeout_ms: 30_000,
            egress_response_idle_timeout_ms: 30_000,
            egress_connect_timeout_ms: 10_000,
            egress_max_response_bytes: 5_242_880,
            egress_max_request_body_bytes: 1_048_576,
            egress_deny_private_ips: true,
        }
    }

    struct TempPolicyFile {
        path: PathBuf,
    }

    impl TempPolicyFile {
        fn new(contents: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "greengateway-policy-test-{}-{}.json",
                std::process::id(),
                unique_suffix()
            ));
            fs::write(&path, contents)
                .unwrap_or_else(|err| panic!("failed to write {}: {err}", path.display()));

            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempPolicyFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }

    fn unique_suffix() -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after Unix epoch")
            .as_nanos()
    }
}
