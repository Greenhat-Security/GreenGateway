use std::{
    collections::HashMap,
    error::Error,
    fmt, fs, io,
    path::{Path, PathBuf},
};

use serde::Deserialize;
use serde_json::Value;

use crate::config::Config;

const KNOWN_TOP_LEVEL_KEYS: &[&str] =
    &["schema_version", "id", "default_action", "roles", "routes"];

/// Action to apply when no route rule matches.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
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

/// RBAC policy document.
#[derive(Debug, Clone, Deserialize)]
pub struct Policy {
    pub schema_version: String,
    #[serde(default)]
    pub id: Option<String>,
    /// Governs routes not matched by any rule.
    ///
    /// Enforcement happens in the RBAC middleware in PR 2; the pure engine
    /// kernel only stores this value.
    #[serde(default)]
    pub default_action: DefaultAction,
    #[serde(default)]
    pub roles: HashMap<String, RoleEntry>,
    /// Ordered route-to-permission rules. First matching rule wins.
    #[serde(default)]
    pub routes: Vec<RouteRule>,
}

/// Permissions granted by one role.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleEntry {
    #[serde(default)]
    pub permissions: Vec<String>,
}

/// Permission required for requests matching a path prefix and optional method set.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteRule {
    /// HTTP methods this rule matches. Empty or ["*"] matches any method.
    #[serde(default)]
    pub methods: Vec<String>,
    /// Absolute path prefix this rule matches. Rules are evaluated in order.
    pub path_prefix: String,
    /// Permission required to access a matching route.
    pub permission: String,
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
        if self.schema_version.starts_with("0.") {
            Ok(())
        } else {
            Err(PolicyError::Invalid(format!(
                "policy schema_version must start with \"0.\", got '{}'",
                self.schema_version
            )))
        }
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
            Self::Invalid(message) => write!(formatter, "invalid policy: {message}"),
        }
    }
}

impl Error for PolicyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Parse { source, .. } => Some(source),
            Self::Invalid(_) => None,
        }
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

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    use jsonschema::Validator;
    use serde_json::{json, Value};

    use super::*;

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
    fn published_schema_accepts_policy_with_routes() {
        let validator = policy_schema_validator();
        let policy = json!({
            "schema_version": "0.1.0",
            "default_action": "deny",
            "roles": {
                "reader": { "permissions": ["data:read"] }
            },
            "routes": [
                {
                    "methods": ["GET", "HEAD"],
                    "path_prefix": "/data",
                    "permission": "data:read"
                },
                {
                    "path_prefix": "/admin",
                    "permission": "admin:read"
                }
            ]
        });

        assert_schema_accepts(&validator, &policy);
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
        let gateway_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let repo_root = gateway_root
            .parent()
            .expect("gateway crate should live directly under the repo root");
        let schema_path = repo_root.join("docs/schemas/policy.v0.schema.json");
        let schema = fs::read_to_string(&schema_path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", schema_path.display()));
        let schema = serde_json::from_str(&schema)
            .unwrap_or_else(|err| panic!("failed to parse {}: {err}", schema_path.display()));

        jsonschema::validator_for(&schema)
            .unwrap_or_else(|err| panic!("failed to compile {}: {err}", schema_path.display()))
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
        }
    }

    fn test_config(policy_file: Option<String>) -> Config {
        Config {
            listen_addr: "127.0.0.1:0"
                .parse()
                .expect("test listen address should parse"),
            audit_log_file: None,
            audit_sqlite_path: None,
            audit_sqlite_retention_days: None,
            policy_file,
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
            auth_cookie_name: "session".to_owned(),
            auth_exempt_paths: vec![
                "/health".to_owned(),
                "/version".to_owned(),
                "/metrics".to_owned(),
            ],
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
