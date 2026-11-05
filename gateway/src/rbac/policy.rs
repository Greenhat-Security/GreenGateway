//! The gateway's side of the RBAC policy document: reading a policy file,
//! persisting one atomically, and the identity check that activates a role's
//! grants.
//!
//! The document model and its validating parse are
//! `gateway_config::rbac::policy` (issue #242), shared with `ggctl` and
//! re-exported here so call sites keep their paths. What needs the gateway --
//! a file, the cluster roster, an authenticated principal -- stays here. The
//! inherent methods that needed it are now methods of [`PolicyFile`],
//! `ClusterDocumentFormat` and [`RoleIdentity`], with the same names.

use std::{
    ffi::OsString,
    fs, io,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

pub use gateway_config::rbac::policy::*;

use super::rule::principal_identity_matches;
use crate::{auth::Principal, config::Config};

#[allow(dead_code)]
const TEMP_FILE_CREATE_ATTEMPTS: u8 = 16;

#[allow(dead_code)]
static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Reading a policy from its file, and writing one back.
pub trait PolicyFile: Sized {
    /// Reads and validates the policy file at `path`, at most
    /// [`MAX_POLICY_FILE_BYTES`] long.
    fn from_file(path: impl AsRef<Path>) -> Result<Self, PolicyError>;

    /// The policy `POLICY_FILE` names, or `None` when it names none.
    fn from_config(config: &Config) -> Result<Option<Self>, PolicyError>;

    /// Writes the policy to `path` through a temporary file and a rename, so
    /// a reader sees the old document or the new one, never a part.
    fn persist_to_file(&self, path: impl AsRef<Path>) -> Result<(), PolicyError>;

    /// [`Self::persist_to_file`] with the rename supplied, so a test can make
    /// it fail.
    fn persist_to_file_with_rename<F>(&self, path: &Path, rename: F) -> Result<(), PolicyError>
    where
        F: FnOnce(&Path, &Path) -> io::Result<()>;
}

impl PolicyFile for Policy {
    fn from_file(path: impl AsRef<Path>) -> Result<Self, PolicyError> {
        let path = path.as_ref();
        let contents = read_policy_file_to_string(path)?;

        Self::from_source(contents.as_bytes(), Some(path))
    }

    fn from_config(config: &Config) -> Result<Option<Self>, PolicyError> {
        match config.policy_file.as_deref() {
            Some(path) => Self::from_file(path).map(Some),
            None => Ok(None),
        }
    }

    fn persist_to_file(&self, path: impl AsRef<Path>) -> Result<(), PolicyError> {
        self.persist_to_file_with_rename(path.as_ref(), |temp_path, target_path| {
            fs::rename(temp_path, target_path)
        })
    }

    fn persist_to_file_with_rename<F>(&self, path: &Path, rename: F) -> Result<(), PolicyError>
    where
        F: FnOnce(&Path, &Path) -> io::Result<()>,
    {
        // Measured before the temporary file exists: a document too large to
        // read back is refused with the live file untouched.
        let contents = match self.persisted_bytes() {
            Ok(contents) => contents,
            Err(PersistedPolicyError::Serialize(source)) => {
                return Err(PolicyError::Serialize {
                    path: path.to_owned(),
                    source,
                });
            }
            Err(error @ PersistedPolicyError::TooLarge { .. }) => {
                return Err(policy_write_error(
                    path,
                    None,
                    io::Error::new(io::ErrorKind::InvalidInput, error.to_string()),
                ));
            }
        };

        persist_policy_bytes_with_rename(path, &contents, rename)
    }
}

/// Whether the cluster serves a policy's document format.
#[cfg(feature = "postgres")]
pub(crate) trait ClusterDocumentFormat {
    /// Whether a cluster replica of this build reads and writes this
    /// policy's document format: `0` for a 0.x document, `1` for policy v1,
    /// which must lie in `cluster_membership::DOCUMENT_VERSION_RANGE`, the
    /// range every replica advertises on the roster. A `schema_version` that
    /// names no schema this build implements is never served.
    fn cluster_serves_document_format(&self) -> bool;
}

#[cfg(feature = "postgres")]
impl ClusterDocumentFormat for Policy {
    fn cluster_serves_document_format(&self) -> bool {
        let (minimum, maximum) = crate::cluster_membership::DOCUMENT_VERSION_RANGE;
        super::policy_document::PolicySchema::of_version(&self.schema_version)
            .is_some_and(|schema| (minimum..=maximum).contains(&schema.document_format_major()))
    }
}

/// Whether a role's grants are active for a principal.
pub(crate) trait RoleIdentity {
    /// Whether `principal` was authenticated by one of the role's issuers
    /// with one of its authentication methods, each unconstrained when the
    /// role lists none.
    fn matches_principal_identity(&self, principal: &Principal) -> bool;
}

impl RoleIdentity for RoleEntry {
    fn matches_principal_identity(&self, principal: &Principal) -> bool {
        principal_identity_matches(&self.issuers, &self.auth_methods, principal)
    }
}

fn read_policy_file_to_string(path: &Path) -> Result<String, PolicyError> {
    let file = fs::File::open(path).map_err(|source| PolicyError::Io {
        path: path.to_owned(),
        source,
    })?;
    let metadata = file.metadata().map_err(|source| PolicyError::Io {
        path: path.to_owned(),
        source,
    })?;
    if metadata.len() > MAX_POLICY_FILE_BYTES {
        return Err(policy_file_too_large(path));
    }

    let mut contents = String::new();
    let mut reader = file.take(MAX_POLICY_FILE_BYTES + 1);
    reader
        .read_to_string(&mut contents)
        .map_err(|source| PolicyError::Io {
            path: path.to_owned(),
            source,
        })?;
    if contents.len() as u64 > MAX_POLICY_FILE_BYTES {
        return Err(policy_file_too_large(path));
    }

    Ok(contents)
}

fn policy_file_too_large(path: &Path) -> PolicyError {
    PolicyError::Io {
        path: path.to_owned(),
        source: io::Error::new(
            io::ErrorKind::InvalidData,
            format!("policy file exceeds maximum size of {MAX_POLICY_FILE_BYTES} bytes"),
        ),
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

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        fs,
        path::{Path, PathBuf},
    };

    use jsonschema::Validator;
    use serde_json::{json, Value};

    use super::*;
    use crate::rbac::{PrincipalMatcher, Rule, RuleAction};

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
        assert!(policy.tools.is_empty());
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
        for schema_version in ["2.0.0", "1.0", "1.0.1", "nope"] {
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

        let value_with_tools = json!({
            "schema_version": "0.1.0",
            "tools": {
                "lookup": {}
            }
        });

        assert!(
            unknown_top_level_keys(&value_with_tools).is_empty(),
            "tools should be a known top-level policy section"
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
    fn issuer_bound_identity_constraints_parse_validate_and_round_trip() {
        let value = json!({
            "schema_version": "0.1.0",
            "roles": {
                "operator": {
                    "permissions": ["data:write"],
                    "issuers": ["https://idp-a.example/"],
                    "auth_methods": ["bearer_token"]
                }
            },
            "rules": [{
                "path": "/data/**",
                "principal": {
                    "roles": ["operator"],
                    "issuers": ["https://idp-a.example/"],
                    "auth_methods": ["bearer_token"],
                    "principal_ids": ["shared-subject"]
                },
                "action": "allow"
            }],
            "rate_limits": [{
                "principal": {
                    "issuers": ["https://idp-a.example/"],
                    "auth_methods": ["bearer_token"]
                },
                "requests_per_second": 5.0,
                "burst": 10
            }],
            "tools": {
                "reports.export": {
                    "allowed_roles": ["operator"],
                    "issuers": ["https://idp-a.example/"],
                    "auth_methods": ["bearer_token"]
                }
            }
        });
        assert_schema_accepts(&policy_schema_validator(), &value);

        let policy = Policy::from_json_value(value, None)
            .expect("issuer-bound identity constraints should parse");

        assert_eq!(
            policy.roles["operator"].issuers,
            vec!["https://idp-a.example".to_owned()]
        );
        assert_eq!(
            policy.rules[0].principal.issuers,
            vec!["https://idp-a.example".to_owned()]
        );
        assert_eq!(
            policy.rate_limits[0].principal.auth_methods,
            vec!["bearer_token".to_owned()]
        );
        assert_eq!(
            policy.tools["reports.export"].issuers,
            vec!["https://idp-a.example".to_owned()]
        );

        let round_trip = serde_json::to_value(&policy).expect("policy should serialize");
        let reparsed = Policy::from_json_value(round_trip, None)
            .expect("serialized issuer-bound policy should parse");
        assert_eq!(reparsed, policy);
    }

    #[test]
    fn invalid_role_and_tool_identity_constraints_are_rejected() {
        let cases = [
            (
                json!({
                    "schema_version": "0.1.0",
                    "roles": {
                        "operator": {
                            "permissions": ["data:write"],
                            "issuers": [""]
                        }
                    }
                }),
                "roles.operator.issuers must not contain empty values",
            ),
            (
                json!({
                    "schema_version": "0.1.0",
                    "tools": {
                        "reports.export": {
                            "auth_methods": ["api_key"]
                        }
                    }
                }),
                "tools.reports.export.auth_methods contains unknown auth method",
            ),
        ];
        let validator = policy_schema_validator();

        for (value, expected_error) in cases {
            assert!(!validator.is_valid(&value));
            let error = Policy::from_json_value(value, None)
                .expect_err("invalid identity constraint should fail");
            assert!(
                error.to_string().contains(expected_error),
                "unexpected error: {error}"
            );
        }
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
                    },
                    {
                        "tool_name": "reports.export",
                        "principal": {
                            "roles": ["operator"]
                        },
                        "action": "deny"
                    }
                ]
            }"#,
        );

        let policy = Policy::from_file(file.path()).expect("rules section should parse");

        assert_eq!(policy.rules.len(), 4);
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
                issuers: Vec::new(),
                auth_methods: vec!["bearer_token".to_owned()],
                principal_ids: vec!["user-123".to_owned()],
            }
        );
        assert_eq!(policy.rules[0].action, RuleAction::Allow);
        assert_eq!(policy.rules[1].action, RuleAction::Shadow);
        assert_eq!(policy.rules[2].action, RuleAction::Deny);
        assert!(policy.rules[2].methods.is_empty());
        assert!(policy.rules[2].principal.is_unconstrained());
        assert_eq!(policy.rules[3].tool_name.as_deref(), Some("reports.export"));
        assert_eq!(policy.rules[3].principal.roles, vec!["operator".to_owned()]);
        assert_eq!(policy.rules[3].action, RuleAction::Deny);

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
                issuers: Vec::new(),
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
    fn tools_section_parses_and_round_trips_with_defaults() {
        let file = TempPolicyFile::new(
            r#"{
                "schema_version": "0.1.0",
                "tools": {
                    "lookup": {},
                    "report": {
                        "enabled": false,
                        "allowed_roles": ["operator", "support"],
                        "timeout_ms": 1500,
                        "max_concurrent": 3
                    }
                }
            }"#,
        );

        let policy = Policy::from_file(file.path()).expect("tools section should parse");

        assert_eq!(policy.tools.len(), 2);
        assert_eq!(
            policy.tools["lookup"],
            ToolPolicyEntry {
                enabled: true,
                allowed_roles: Vec::new(),
                issuers: Vec::new(),
                auth_methods: Vec::new(),
                timeout_ms: DEFAULT_TOOL_POLICY_TIMEOUT_MS,
                max_concurrent: DEFAULT_TOOL_POLICY_MAX_CONCURRENT,
            }
        );
        assert_eq!(
            policy.tools["report"],
            ToolPolicyEntry {
                enabled: false,
                allowed_roles: vec!["operator".to_owned(), "support".to_owned()],
                issuers: Vec::new(),
                auth_methods: Vec::new(),
                timeout_ms: 1500,
                max_concurrent: 3,
            }
        );

        let round_trip_value =
            serde_json::to_value(&policy).expect("policy with tools should serialize");
        let round_tripped: Policy =
            serde_json::from_value(round_trip_value).expect("serialized policy should parse");

        assert_eq!(round_tripped, policy);
    }

    #[test]
    fn malformed_tool_entries_are_rejected_by_parser_and_schema() {
        let cases = [
            (
                "unknown field",
                json!({
                    "schema_version": "0.1.0",
                    "tools": {
                        "lookup": {
                            "timeout": 1000
                        }
                    }
                }),
                "unknown field",
            ),
            (
                "zero timeout",
                json!({
                    "schema_version": "0.1.0",
                    "tools": {
                        "lookup": {
                            "timeout_ms": 0
                        }
                    }
                }),
                "timeout_ms must be positive",
            ),
        ];
        let validator = policy_schema_validator();

        for (name, value, expected_error) in cases {
            assert!(
                !validator.is_valid(&value),
                "published schema should reject {name}"
            );

            let error =
                Policy::from_json_value(value, None).expect_err("malformed tool should fail");

            assert!(
                error.to_string().contains(expected_error),
                "unexpected error for {name}: {error}"
            );
        }
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
    fn route_hosts_parse_round_trip_and_match_published_schema() {
        let value = json!({
            "schema_version": "0.1.0",
            "routes": [
                {
                    "methods": ["GET"],
                    "hosts": ["admin.example.test"],
                    "path_prefix": "/data",
                    "permission": "admin:read"
                }
            ]
        });

        assert_schema_accepts(&policy_schema_validator(), &value);
        let policy = Policy::from_json_value(value, None)
            .expect("host-bound route policy should parse and validate");
        assert_eq!(policy.routes[0].hosts, vec!["admin.example.test"]);

        let serialized = serde_json::to_value(&policy).expect("host-bound policy should serialize");
        let round_tripped: Policy =
            serde_json::from_value(serialized).expect("serialized host-bound policy should parse");
        assert_eq!(round_tripped, policy);
    }

    #[test]
    fn route_hosts_reject_ports_and_case_insensitive_duplicates() {
        let validator = policy_schema_validator();
        let with_port = json!({
            "schema_version": "0.1.0",
            "routes": [
                {
                    "hosts": ["admin.example.test:443"],
                    "path_prefix": "/data",
                    "permission": "admin:read"
                }
            ]
        });
        assert!(!validator.is_valid(&with_port));
        let error = Policy::from_json_value(with_port, None)
            .expect_err("route hosts with ports should fail validation");
        assert!(error.to_string().contains("hostnames without ports"));

        let duplicate = json!({
            "schema_version": "0.1.0",
            "routes": [
                {
                    "hosts": ["admin.example.test", "ADMIN.EXAMPLE.TEST"],
                    "path_prefix": "/data",
                    "permission": "admin:read"
                }
            ]
        });
        let error = Policy::from_json_value(duplicate, None)
            .expect_err("route hosts should be unique ignoring case");
        assert!(error.to_string().contains("duplicate hostname"));
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
            (
                "path and tool_name both set",
                json!({
                    "schema_version": "0.1.0",
                    "rules": [
                        {
                            "path": "/admin/**",
                            "tool_name": "reports.export",
                            "action": "deny"
                        }
                    ]
                }),
                "rules[0] must set exactly one of path or tool_name",
            ),
            (
                "empty path and tool_name both set",
                json!({
                    "schema_version": "0.1.0",
                    "rules": [
                        {
                            "path": "",
                            "tool_name": "reports.export",
                            "action": "deny"
                        }
                    ]
                }),
                "rules[0] must set exactly one of path or tool_name",
            ),
            (
                "whitespace-only tool_name",
                json!({
                    "schema_version": "0.1.0",
                    "rules": [
                        {
                            "tool_name": "   ",
                            "action": "deny"
                        }
                    ]
                }),
                "rules[0].tool_name must not be empty",
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
    fn tool_name_rules_reject_non_empty_methods() {
        let error = Policy::validate_json_value(json!({
            "schema_version": "0.1.0",
            "rules": [
                {
                    "methods": ["MCP"],
                    "tool_name": "reports.export",
                    "action": "deny"
                }
            ]
        }))
        .expect_err("tool_name rules should not accept HTTP method constraints");

        assert!(matches!(error, PolicyError::Invalid(_)));
        assert!(
            error
                .to_string()
                .contains("rules[0].methods must be empty when tool_name is set"),
            "unexpected error: {error}"
        );

        Policy::validate_json_value(json!({
            "schema_version": "0.1.0",
            "rules": [
                {
                    "methods": [],
                    "tool_name": "reports.export",
                    "action": "deny"
                }
            ]
        }))
        .expect("empty methods should remain valid for tool_name rules");
    }

    #[test]
    fn dispatch_binding_requires_a_valid_kind_and_origin_only_http_url() {
        for invalid_origin in [
            "https://example.test/path",
            "https://user@example.test",
            "https://example.test?query=yes",
            "https://example.test#fragment",
            "ftp://example.test",
            "HTTPS://EXAMPLE.TEST",
        ] {
            let error = Policy::validate_json_value(json!({
                "schema_version": "0.1.0",
                "rules": [{
                    "path": "/reports/{id}",
                    "dispatch": {
                        "kind": "legacy",
                        "upstream_origin": invalid_origin
                    },
                    "action": "allow"
                }]
            }))
            .expect_err("invalid dispatch origin should be rejected");
            assert!(
                error.to_string().contains("HTTP(S) origin"),
                "unexpected error for {invalid_origin}: {error}"
            );
        }

        for invalid_dispatch in [
            json!(null),
            json!({
                "kind": "contextless",
                "upstream_origin": "https://example.test"
            }),
            json!({
                "kind": "contextless",
                "upstream_origin": null
            }),
            json!({ "kind": "legacy" }),
            json!({
                "kind": "legacy",
                "upstream_origin": null
            }),
            json!({ "kind": "route" }),
            json!({
                "kind": "route",
                "route_id": null
            }),
            json!({
                "kind": "route",
                "route_id": "payments",
                "upstream_origin": "https://example.test"
            }),
            json!({
                "kind": "legacy",
                "upstream_origin": "https://example.test",
                "route_id": "payments"
            }),
        ] {
            Policy::validate_json_value(json!({
                "schema_version": "0.1.0",
                "rules": [{
                    "path": "/reports/{id}",
                    "dispatch": invalid_dispatch,
                    "action": "allow"
                }]
            }))
            .expect_err("dispatch kind and origin must agree");
        }

        let error = Policy::validate_json_value(json!({
            "schema_version": "0.1.0",
            "rules": [{
                "tool_name": "reports.export",
                "dispatch": { "kind": "contextless" },
                "action": "deny"
            }]
        }))
        .expect_err("tool rules must not have HTTP dispatch provenance");
        assert!(error
            .to_string()
            .contains("dispatch is only valid for HTTP path rules"));

        Policy::validate_json_value(json!({
            "schema_version": "0.1.0",
            "rules": [
                {
                    "path": "/local/{id}",
                    "dispatch": { "kind": "contextless" },
                    "action": "allow"
                },
                {
                    "path": "/reports/{id}",
                    "dispatch": {
                        "kind": "legacy",
                        "upstream_origin": "https://EXAMPLE.TEST:443"
                    },
                    "action": "allow"
                },
                {
                    "path": "/payments/{id}",
                    "dispatch": {
                        "kind": "route",
                        "route_id": "payments"
                    },
                    "action": "deny"
                }
            ]
        }))
        .expect("contextless, legacy-origin, and logical-route dispatch bindings should be valid");
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
                "invalid number",
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

    /// The published schema bounds tool names where policy validation does.
    /// JSON Schema counts characters and the gateway bytes, so for an ASCII
    /// name the bound is the same byte on both sides; a multibyte name can pass
    /// the schema and still be refused by the gateway, never the reverse.
    #[test]
    fn the_published_schema_bounds_tool_names_where_policy_validation_does() {
        let validator = policy_schema_validator();
        let at_bound = "t".repeat(crate::request_bounds::MAX_TOOL_NAME_BYTES);
        let past_bound = format!("{at_bound}t");
        for (name, accepted) in [(at_bound, true), (past_bound, false)] {
            let mut tools = serde_json::Map::new();
            tools.insert(name.clone(), json!({}));
            for document in [
                json!({ "schema_version": "0.1.0", "tools": tools }),
                json!({
                    "schema_version": "0.1.0",
                    "rules": [{ "tool_name": name, "action": "deny" }]
                }),
            ] {
                assert_eq!(validator.is_valid(&document), accepted, "schema");
                assert_eq!(
                    Policy::validate_json_value(document).is_ok(),
                    accepted,
                    "policy validation"
                );
            }
        }
    }

    /// Every `auth_methods` enum in the published schema lists exactly the
    /// names the parser accepts.
    ///
    /// This is a pin on a divergence that had already happened. #324 added
    /// `client_certificate` to `valid_auth_method_name`, to the admin UI's
    /// `AuthMethodName` union, and to the rule editor's dropdown -- and not to
    /// `docs/schemas/policy.v0.schema.json`, which is what operators and CI
    /// validate policy files against. The result was a name the gateway loaded,
    /// the rule editor offered, and schema validation rejected, with nothing
    /// anywhere failing. Each schema carries the list in three separate places,
    /// and the v1 schema in a fourth, its identity mappings, so every one is
    /// checked.
    #[test]
    fn the_published_schema_lists_exactly_the_auth_methods_the_parser_accepts() {
        let repo_root = repo_root();
        for (schema_file, sites) in [("policy.v0.schema.json", 3), ("policy.v1.schema.json", 4)] {
            let schema_path = repo_root.join("docs/schemas").join(schema_file);
            let schema: serde_json::Value =
                serde_json::from_str(&fs::read_to_string(&schema_path).unwrap_or_else(|err| {
                    panic!("failed to read {}: {err}", schema_path.display())
                }))
                .unwrap_or_else(|err| panic!("failed to parse {}: {err}", schema_path.display()));

            let mut found = Vec::new();
            collect_auth_method_enums(&schema, &mut found);

            assert_eq!(
                found.len(),
                sites,
                "{schema_file} is expected to carry the auth-method list at {sites} sites (role \
                 permissions, route rules, tool rules, and in v1 identity mappings); found {}",
                found.len()
            );
            for names in &found {
                assert_eq!(
                    names.as_slice(),
                    crate::rbac::rule::ALL_AUTH_METHOD_NAMES,
                    "an auth_methods enum in {schema_file} disagrees with the names the parser \
                     accepts; a policy naming one of the differences would be accepted by one \
                     and rejected by the other"
                );
            }
        }
    }

    /// Walks the schema for every `auth_methods.items.enum`.
    ///
    /// Recursive rather than indexed by path, so a fourth site added later is
    /// checked automatically instead of being silently skipped.
    fn collect_auth_method_enums(value: &serde_json::Value, found: &mut Vec<Vec<String>>) {
        match value {
            serde_json::Value::Object(map) => {
                if let Some(names) = map
                    .get("auth_methods")
                    .and_then(|methods| methods.get("items"))
                    .and_then(|items| items.get("enum"))
                    .and_then(|names| names.as_array())
                {
                    found.push(
                        names
                            .iter()
                            .filter_map(|name| name.as_str().map(str::to_owned))
                            .collect(),
                    );
                }
                for nested in map.values() {
                    collect_auth_method_enums(nested, found);
                }
            }
            serde_json::Value::Array(items) => {
                for nested in items {
                    collect_auth_method_enums(nested, found);
                }
            }
            _ => {}
        }
    }

    /// And the same name end to end: a rule naming `client_certificate` passes
    /// the published schema and the parser.
    ///
    /// The agreement test above would still pass if both lists were wrong in
    /// the same way. This one asserts the name #324 actually introduced works.
    #[test]
    fn a_rule_naming_the_client_certificate_auth_method_is_accepted_by_parser_and_schema() {
        let value = json!({
            "schema_version": "0.1.0",
            "rules": [
                {
                    "path": "/admin/**",
                    "principal": {
                        "auth_methods": ["client_certificate"]
                    },
                    "action": "allow"
                }
            ]
        });

        assert!(
            policy_schema_validator().is_valid(&value),
            "the published schema must accept the auth method the gateway and the rule editor \
             both offer"
        );

        let document = serde_json::to_string(&value).expect("policy case should serialize");
        let file = TempPolicyFile::new(&document);
        let policy =
            Policy::from_file(file.path()).expect("a rule naming client_certificate should load");
        assert_eq!(
            policy.rules[0].principal.auth_methods,
            vec!["client_certificate".to_owned()]
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
    fn non_absolute_route_path_prefix_is_rejected_by_parser_and_schema() {
        for path_prefix in ["admin", ""] {
            let value = json!({
                "schema_version": "0.1.0",
                "routes": [
                    {
                        "path_prefix": path_prefix,
                        "permission": "admin:read"
                    }
                ]
            });
            let validator = policy_schema_validator();

            assert!(
                !validator.is_valid(&value),
                "published schema should reject route prefix {path_prefix:?}"
            );

            let error = Policy::validate_json_value(value)
                .expect_err("non-absolute route path_prefix should fail policy validation");
            assert!(matches!(error, PolicyError::Invalid(_)));
            assert!(
                error
                    .to_string()
                    .contains("routes[0].path_prefix must start with '/'"),
                "unexpected error: {error}"
            );
        }
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
    fn oversized_policy_file_is_rejected_with_clear_error() {
        let file = TempPolicyFile::new(&" ".repeat(1_048_577));

        let error =
            Policy::from_file(file.path()).expect_err("oversized policy file should reject");
        let message = error.to_string();

        assert!(
            message.contains("policy file exceeds maximum size of 1048576 bytes"),
            "unexpected error: {message}"
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

    /// `policy` with as many small rules as it takes for its policy file --
    /// pretty-printed, as [`Policy::persist_to_file`] writes it -- to exceed
    /// [`MAX_POLICY_FILE_BYTES`] while its compact JSON stays under it.
    fn with_rules_too_large_for_a_policy_file(mut policy: Policy) -> Policy {
        let mut count = 2_000;
        loop {
            policy.rules = (0..count)
                .map(|index| Rule {
                    id: Some(format!("rule-{index}")),
                    enabled: true,
                    methods: vec!["GET".to_owned()],
                    path: format!("/large/{index}"),
                    tool_name: None,
                    dispatch: None,
                    principal: PrincipalMatcher::default(),
                    action: RuleAction::Deny,
                    conditions: None,
                })
                .collect();
            let pretty = serde_json::to_vec_pretty(&policy)
                .unwrap_or_else(|err| panic!("policy should serialize: {err}"));
            if pretty.len() as u64 >= MAX_POLICY_FILE_BYTES {
                let compact = serde_json::to_vec(&policy)
                    .unwrap_or_else(|err| panic!("policy should serialize: {err}"));
                assert!(
                    (compact.len() as u64) < MAX_POLICY_FILE_BYTES,
                    "{count} rules are {} bytes compact",
                    compact.len()
                );
                return policy;
            }
            count += 500;
        }
    }

    #[test]
    fn persist_to_file_writes_exactly_the_measured_bytes() {
        let file = TempPolicyFile::new(r#"{ "schema_version": "0.1.0" }"#);
        let policy = rich_policy();
        let measured = policy
            .persisted_bytes()
            .unwrap_or_else(|err| panic!("a small policy fits a policy file: {err}"));

        policy
            .persist_to_file(file.path())
            .expect("policy should persist atomically");

        let written = fs::read(file.path())
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", file.path().display()));
        assert_eq!(written, measured);
    }

    #[test]
    fn persist_to_file_refuses_a_file_too_large_to_read_back_before_writing_it() {
        let file = TempPolicyFile::new(r#"{ "schema_version": "0.1.0" }"#);
        let original_contents = fs::read(file.path())
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", file.path().display()));
        let policy = with_rules_too_large_for_a_policy_file(rich_policy());

        assert!(matches!(
            policy.persisted_bytes(),
            Err(PersistedPolicyError::TooLarge { len }) if len as u64 > MAX_POLICY_FILE_BYTES
        ));
        let error = policy
            .persist_to_file(file.path())
            .expect_err("a policy file the gateway cannot read back is never written");

        // Refused before a temporary file was created, with the live file as
        // it was: written, it would be refused by its own reload and by the
        // next start.
        assert!(
            matches!(
                error,
                PolicyError::Write {
                    temp_path: None,
                    ..
                }
            ),
            "unexpected persistence error: {error:?}"
        );
        assert!(
            error
                .to_string()
                .contains("more than the maximum size of 1048576 bytes"),
            "unexpected error: {error}"
        );
        assert_eq!(
            fs::read(file.path())
                .unwrap_or_else(|err| panic!("failed to read {}: {err}", file.path().display())),
            original_contents
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
    fn starter_and_dev_policy_files_parse_and_match_published_schema() {
        for (relative_path, expected_id, expected_default_action) in [
            (
                "docs/examples/policy.starter.json",
                Some("starter"),
                DefaultAction::Allow,
            ),
            (
                "dev/policy.json",
                Some("dev-control-plane"),
                DefaultAction::Deny,
            ),
        ] {
            let path = repo_root().join(relative_path);
            let policy = Policy::from_file(&path)
                .unwrap_or_else(|err| panic!("{relative_path} should parse: {err}"));
            let contents = fs::read_to_string(&path)
                .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
            let value: Value = serde_json::from_str(&contents)
                .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()));

            assert_eq!(policy.schema_version, "0.1.0");
            assert_eq!(policy.id.as_deref(), expected_id);
            assert_eq!(policy.default_action, expected_default_action);
            assert_eq!(policy.enforcement_mode, EnforcementMode::Enforce);
            assert_schema_accepts(&policy_schema_validator(), &value);
        }
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
                    "dispatch": {
                        "kind": "legacy",
                        "upstream_origin": "https://api.example.test"
                    },
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
                },
                {
                    "tool_name": "reports.export",
                    "methods": [],
                    "principal": {
                        "roles": ["operator"]
                    },
                    "action": "deny"
                }
            ]
        });

        assert_schema_accepts(&validator, &policy);
    }

    #[test]
    fn published_schema_rejects_dispatch_on_tool_rule() {
        let validator = policy_schema_validator();
        let policy = json!({
            "schema_version": "0.1.0",
            "rules": [{
                "tool_name": "reports.export",
                "dispatch": { "kind": "contextless" },
                "action": "deny"
            }]
        });

        assert!(!validator.is_valid(&policy));
    }

    #[test]
    fn published_schema_enforces_dispatch_kind_and_origin_shape() {
        let validator = policy_schema_validator();
        for dispatch in [
            json!(null),
            json!({ "upstream_origin": "https://api.example.test" }),
            json!({ "kind": "legacy" }),
            json!({
                "kind": "contextless",
                "upstream_origin": "https://api.example.test"
            }),
            json!({
                "kind": "contextless",
                "upstream_origin": null
            }),
            json!({
                "kind": "legacy",
                "upstream_origin": "https://api.example.test/path"
            }),
            json!({
                "kind": "legacy",
                "upstream_origin": "https://user@api.example.test"
            }),
            json!({ "kind": "route" }),
            json!({
                "kind": "route",
                "route_id": "invalid route"
            }),
            json!({
                "kind": "route",
                "route_id": "payments",
                "upstream_origin": "https://api.example.test"
            }),
            json!({
                "kind": "legacy",
                "upstream_origin": "https://api.example.test",
                "route_id": "payments"
            }),
        ] {
            let policy = json!({
                "schema_version": "0.1.0",
                "rules": [{
                    "path": "/api/{id}",
                    "dispatch": dispatch,
                    "action": "allow"
                }]
            });
            assert!(!validator.is_valid(&policy), "schema accepted {policy}");
        }

        let policy = json!({
            "schema_version": "0.1.0",
            "rules": [{
                "path": "/api/{id}",
                "dispatch": {
                    "kind": "route",
                    "route_id": "payments"
                },
                "action": "deny"
            }]
        });
        assert_schema_accepts(&validator, &policy);
    }

    #[test]
    fn published_schema_rejects_tool_name_rule_with_non_empty_methods() {
        let validator = policy_schema_validator();
        let policy = json!({
            "schema_version": "0.1.0",
            "default_action": "deny",
            "rules": [
                {
                    "tool_name": "reports.export",
                    "methods": ["POST"],
                    "action": "deny"
                }
            ]
        });

        assert!(
            !validator.is_valid(&policy),
            "published schema should reject tool_name rules with non-empty methods"
        );
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
    fn published_schema_accepts_policy_with_tools() {
        let validator = policy_schema_validator();
        let policy = json!({
            "schema_version": "0.1.0",
            "tools": {
                "lookup": {
                    "enabled": true,
                    "allowed_roles": ["operator"],
                    "timeout_ms": 1500,
                    "max_concurrent": 3
                },
                "report": {
                    "enabled": false
                }
            }
        });

        assert_schema_accepts(&validator, &policy);
        Policy::from_json_value(policy, None).expect("schema-valid tools policy should parse");
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

    #[test]
    fn a_role_description_round_trips_and_grants_nothing() {
        let described = Policy::validate_json_value(json!({
            "schema_version": "0.1.0",
            "roles": {
                "reader": {
                    "permissions": ["data:read"],
                    "description": "Read-only access for the reporting team"
                }
            }
        }))
        .expect("a described role is valid");
        assert!(described.uses_role_descriptions());
        assert_eq!(
            described.roles["reader"].description.as_deref(),
            Some("Read-only access for the reporting team")
        );
        let serialized = serde_json::to_value(&described).expect("serialize");
        assert_eq!(
            serialized["roles"]["reader"]["description"],
            "Read-only access for the reporting team"
        );

        // The same role without one is the document an older gateway wrote,
        // and it serializes exactly as that gateway does: no `description`
        // key at all, so both builds compute the same ETag for it.
        let plain = Policy::validate_json_value(json!({
            "schema_version": "0.1.0",
            "roles": { "reader": { "permissions": ["data:read"] } }
        }))
        .expect("a plain role is valid");
        assert!(!plain.uses_role_descriptions());
        let serialized = serde_json::to_value(&plain).expect("serialize");
        assert_eq!(
            serialized["roles"]["reader"],
            json!({ "permissions": ["data:read"] })
        );
        let mut without = described.clone();
        without
            .roles
            .get_mut("reader")
            .expect("the role is present")
            .description = None;
        assert_eq!(without, plain, "a description changes nothing else");
    }

    #[test]
    fn role_descriptions_are_bounded_printable_and_never_blank() {
        let with_description = |description: Value| {
            Policy::validate_json_value(json!({
                "schema_version": "0.1.0",
                "roles": {
                    "reader": { "permissions": ["data:read"], "description": description }
                }
            }))
        };
        assert!(with_description(json!("x".repeat(MAX_ROLE_DESCRIPTION_BYTES))).is_ok());
        // Counted in bytes, not characters.
        let multibyte = "\u{e9}".repeat(MAX_ROLE_DESCRIPTION_BYTES / 2 + 1);
        for (description, expected) in [
            (json!(""), "must not be empty"),
            (json!("   "), "must not be empty"),
            (
                json!("x".repeat(MAX_ROLE_DESCRIPTION_BYTES + 1)),
                "must not exceed 512 bytes",
            ),
            (json!(multibyte), "must not exceed 512 bytes"),
            (json!("first line\nsecond line"), "control characters"),
            (json!("escape \u{1b}[31m"), "control characters"),
            (json!("next line \u{85}"), "control characters"),
        ] {
            let error = with_description(description.clone())
                .expect_err("an invalid description is refused");
            assert!(
                error.to_string().contains(expected),
                "{description} should be refused with {expected:?}: {error}"
            );
            assert!(
                error.to_string().contains("roles.reader.description"),
                "{error}"
            );
        }
        let error = with_description(json!(7)).expect_err("a description is a string");
        assert!(matches!(error, PolicyError::Parse { .. }), "{error}");
    }

    #[test]
    fn published_schema_accepts_a_bounded_role_description() {
        let validator = policy_schema_validator();
        let described = |description: &str| {
            json!({
                "schema_version": "0.1.0",
                "roles": {
                    "reader": { "permissions": ["data:read"], "description": description }
                }
            })
        };
        assert_schema_accepts(&validator, &described("Read-only reporting access"));
        for invalid in ["", "line\nbreak"] {
            assert!(
                !validator.is_valid(&described(invalid)),
                "published schema should reject the description {invalid:?}"
            );
        }
        assert!(!validator.is_valid(&described(&"x".repeat(MAX_ROLE_DESCRIPTION_BYTES + 1))));
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
                        issuers: Vec::new(),
                        auth_methods: Vec::new(),
                        description: None,
                    },
                ),
                (
                    "reader".to_owned(),
                    RoleEntry {
                        permissions: vec!["data:read".to_owned(), "reports:read".to_owned()],
                        issuers: Vec::new(),
                        auth_methods: Vec::new(),
                        description: None,
                    },
                ),
            ]),
            routes: vec![
                RouteRule {
                    id: None,
                    methods: vec!["GET".to_owned(), "HEAD".to_owned()],
                    hosts: Vec::new(),
                    path_prefix: "/data".to_owned(),
                    permission: "data:read".to_owned(),
                    enforcement_mode: Some(EnforcementMode::Enforce),
                },
                RouteRule {
                    id: None,
                    methods: Vec::new(),
                    hosts: Vec::new(),
                    path_prefix: "/reports".to_owned(),
                    permission: "reports:read".to_owned(),
                    enforcement_mode: None,
                },
            ],
            rules: Vec::new(),
            egress: EgressPolicy::default(),
            rate_limits: vec![RateLimitRule {
                id: None,
                principal: PrincipalMatcher {
                    roles: vec!["admin".to_owned()],
                    issuers: Vec::new(),
                    auth_methods: vec!["bearer_token".to_owned()],
                    principal_ids: Vec::new(),
                },
                methods: vec!["GET".to_owned()],
                path: Some("/admin/**".to_owned()),
                requests_per_second: 20.0,
                burst: 40,
            }],
            tools: HashMap::from([(
                "lookup".to_owned(),
                ToolPolicyEntry {
                    enabled: true,
                    allowed_roles: Vec::new(),
                    issuers: Vec::new(),
                    auth_methods: Vec::new(),
                    timeout_ms: DEFAULT_TOOL_POLICY_TIMEOUT_MS,
                    max_concurrent: DEFAULT_TOOL_POLICY_MAX_CONCURRENT,
                },
            )]),
            identity_mappings: None,
        }
    }

    fn test_config(policy_file: Option<String>) -> Config {
        Config {
            listen_addr: "127.0.0.1:0"
                .parse()
                .expect("test listen address should parse"),
            admin_listen_addr: None,
            grpc_listen_addr: None,
            grpc_max_concurrent_streams: crate::config::DEFAULT_GRPC_MAX_CONCURRENT_STREAMS,
            grpc_max_metadata_bytes: crate::config::DEFAULT_GRPC_MAX_METADATA_BYTES,
            tls_cert_files: None,
            tls_key_files: None,
            admin_tls_cert_files: None,
            admin_tls_key_files: None,
            tls_min_version: crate::config::DEFAULT_TLS_MIN_VERSION,
            tls_handshake_timeout_ms: crate::config::DEFAULT_TLS_HANDSHAKE_TIMEOUT_MS,
            tls_max_concurrent_handshakes: crate::config::DEFAULT_TLS_MAX_CONCURRENT_HANDSHAKES,
            client_cert_auth: None,
            admin_client_cert_auth: None,
            admin_prefix: "/admin".to_owned(),
            admin_login_provider: None,
            admin_session: None,
            admin_login_pending_ttl_secs: crate::config::DEFAULT_ADMIN_LOGIN_PENDING_TTL_SECS,
            admin_login_pending_max_entries: crate::config::DEFAULT_ADMIN_LOGIN_PENDING_MAX_ENTRIES,
            admin_login_pending_max_per_ip: crate::config::DEFAULT_ADMIN_LOGIN_PENDING_MAX_PER_IP,
            admin_login_keyring: Vec::new(),
            rate_limit_keyring: Vec::new(),
            gateway_public_url: None,
            audit_log_file: None,
            audit_sqlite_path: None,
            audit_sqlite_retention_days: None,
            audit_successful_probes_metrics_only: false,
            shutdown_drain_delay_ms: crate::config::DEFAULT_SHUTDOWN_DRAIN_DELAY_MS,
            shutdown_timeout_ms: crate::config::DEFAULT_SHUTDOWN_TIMEOUT_MS,
            audit_drain_timeout_ms: crate::config::DEFAULT_AUDIT_DRAIN_TIMEOUT_MS,
            audit_durability: crate::config::DEFAULT_AUDIT_DURABILITY,
            audit_durability_timeout_ms: crate::config::DEFAULT_AUDIT_DURABILITY_TIMEOUT_MS,
            discovery_sqlite_path: None,
            discovery_endpoint_limit: crate::config::DEFAULT_DISCOVERY_ENDPOINT_LIMIT,
            discovery_projector_lease_ttl_ms:
                crate::config::DEFAULT_DISCOVERY_PROJECTOR_LEASE_TTL_MS,
            discovery_projector_poll_ms: crate::config::DEFAULT_DISCOVERY_PROJECTOR_POLL_MS,
            discovery_projector_batch: crate::config::DEFAULT_DISCOVERY_PROJECTOR_BATCH,
            principal_sqlite_path: None,
            connections_sqlite_path: None,
            connection_local_secret_keyring: Vec::new(),
            connection_vault_provider:
                crate::connections::vault_secret::VaultProviderConfig::default(),
            connection_gcp_provider: crate::connections::gcp_secret::GcpProviderConfig::default(),
            connection_azure_provider:
                crate::connections::azure_secret::AzureProviderConfig::default(),
            connection_aws_provider: crate::connections::aws_secret::AwsProviderConfig::default(),
            connection_kubernetes_provider:
                crate::connections::kubernetes_secret::KubernetesProviderConfig::default(),
            connection_secret_aliases: Vec::new(),
            connection_secrets_root: None,
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
            tools_file: None,
            policy_history_sqlite_path: None,
            cors_allow_origins: Vec::new(),
            max_body_size: 1_048_576,
            max_request_path_bytes: crate::config::DEFAULT_MAX_REQUEST_PATH_BYTES,
            rate_limit_read_rps: 50.0,
            rate_limit_read_burst: 100,
            rate_limit_write_rps: 10.0,
            rate_limit_write_burst: 20,
            rate_limit_max_buckets: crate::config::DEFAULT_RATE_LIMIT_MAX_BUCKETS,
            rate_limit_bucket_ttl_ms: crate::config::DEFAULT_RATE_LIMIT_BUCKET_TTL_MS,
            trust_proxy_headers: false,
            trusted_proxy_cidrs: Vec::new(),
            rbac_exempt_paths: vec![
                "/health".to_owned(),
                "/version".to_owned(),
                "/metrics".to_owned(),
            ],
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
            jwt_jwks_max_key_age_secs: 300,
            jwt_require_jti: false,
            roles_claim: "roles".to_owned(),
            service_token_sqlite_path: None,
            service_token_cache_ttl_ms: crate::config::DEFAULT_SERVICE_TOKEN_CACHE_TTL_MS,
            tool_runtime_queue_depth: crate::config::DEFAULT_TOOL_RUNTIME_QUEUE_DEPTH,
            tool_runtime_global_concurrency: crate::config::DEFAULT_TOOL_RUNTIME_GLOBAL_CONCURRENCY,
            tool_runtime_queue_timeout_ms: crate::config::DEFAULT_TOOL_RUNTIME_QUEUE_TIMEOUT_MS,
            tool_lease_ttl_ms: crate::config::DEFAULT_TOOL_LEASE_TTL_MS,
            cluster_heartbeat_ms: crate::config::DEFAULT_CLUSTER_HEARTBEAT_MS,
            cluster_member_stale_ms: crate::config::DEFAULT_CLUSTER_MEMBER_STALE_MS,
            cluster_maintenance_interval_ms: crate::config::DEFAULT_CLUSTER_MAINTENANCE_INTERVAL_MS,
            cluster_maintenance_lease_ttl_ms:
                crate::config::DEFAULT_CLUSTER_MAINTENANCE_LEASE_TTL_MS,
            readiness_probe_cache_ms: crate::config::DEFAULT_READINESS_PROBE_CACHE_MS,
            cluster_status_expose_hostnames: false,
            audit_postgres_retention_days: None,
            authority_events: Default::default(),
            tool_runtime_default_timeout_ms: crate::config::DEFAULT_TOOL_RUNTIME_DEFAULT_TIMEOUT_MS,
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
            mcp_upstream_servers: Vec::new(),
            upstream_timeout_ms: None,
            upstream_response_idle_timeout_ms: None,
            upstream_connect_timeout_ms: None,
            egress_allowed_hosts: Vec::new(),
            egress_timeout_ms: 30_000,
            egress_response_idle_timeout_ms: 30_000,
            egress_connect_timeout_ms: 10_000,
            egress_max_response_bytes: 5_242_880,
            egress_max_request_body_bytes: 1_048_576,
            egress_nat64_prefixes: Vec::new(),
            egress_deny_private_ips: true,
            state_backend: crate::config::StateBackend::Sqlite,
            deployment_id: None,
            database: crate::config::DatabaseSettings::default(),
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

    fn unique_suffix() -> String {
        uuid::Uuid::new_v4().to_string()
    }
}
