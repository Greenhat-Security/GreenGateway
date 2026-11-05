//! The HashiCorp Vault KV v2 provider's configuration document
//! (`CONNECTION_VAULT_PROVIDER`) and its validator.
//!
//! Validation is a function of the document alone: it opens no file, resolves
//! no name and contacts no provider. The provider the gateway builds from a
//! validated document, and every check that needs the world, stay in the
//! gateway's `connections::vault_secret`, which re-exports these.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
};

use serde::Deserialize;
use url::Url;

use super::{
    secret::is_valid_file_key, MAX_CREDENTIALS, MAX_DISPLAY_NAME_CHARS, MAX_SECRET_ID_BYTES,
};
use crate::opaque_id::is_valid_opaque_id;

pub const MAX_VAULT_PROFILES: usize = 8;
pub const MAX_VAULT_SECRET_ALIASES: usize = MAX_CREDENTIALS;
pub const MAX_VAULT_PROVIDER_CONFIG_BYTES: usize = 256 * 1024;
const MAX_VAULT_ADDRESS_BYTES: usize = 512;
const MAX_VAULT_NAMESPACE_BYTES: usize = 128;
const MAX_VAULT_MOUNT_BYTES: usize = 128;
const MAX_VAULT_PATH_BYTES: usize = 512;
const MAX_VAULT_DATA_KEY_BYTES: usize = 128;
const MAX_VAULT_NAME_BYTES: usize = 128;
const REDACTED_LOCATOR: &str = "<redacted-locator>";

/// Trusted startup configuration for the read-only KV v2 provider.
#[derive(Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultProviderConfig {
    #[serde(default)]
    pub profiles: Vec<VaultProfileConfig>,
    #[serde(default)]
    pub aliases: Vec<VaultSecretAliasConfig>,
}

impl fmt::Debug for VaultProviderConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VaultProviderConfig")
            .field("profile_count", &self.profiles.len())
            .field("alias_count", &self.aliases.len())
            .finish()
    }
}

impl VaultProviderConfig {
    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty() && self.aliases.is_empty()
    }
}

/// One Vault endpoint plus the fixed workload identity used against it.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultProfileConfig {
    pub id: String,
    pub address: String,
    #[serde(default)]
    pub namespace: Option<String>,
    pub auth: VaultAuthConfig,
}

impl fmt::Debug for VaultProfileConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VaultProfileConfig")
            .field("id", &self.id)
            .field("address", &REDACTED_LOCATOR)
            .field(
                "namespace",
                &self.namespace.as_ref().map(|_| REDACTED_LOCATOR),
            )
            .field("auth", &self.auth)
            .finish()
    }
}

/// Authentication used to obtain a short-lived Vault token.
///
/// `workload_jwt` is the only mechanism that needs no bootstrap secret at all.
/// `token` and `app_role` exist for deployments without a workload identity
/// provider; both take their bootstrap material from an already configured
/// alias of another provider, never from an inline value.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum VaultAuthConfig {
    WorkloadJwt {
        mount: String,
        role: String,
        token_root: String,
        token_file: String,
    },
    Token {
        secret_alias: String,
    },
    AppRole {
        mount: String,
        role_id: String,
        secret_id_alias: String,
    },
}

impl fmt::Debug for VaultAuthConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WorkloadJwt { .. } => formatter
                .debug_struct("WorkloadJwt")
                .field("mount", &REDACTED_LOCATOR)
                .field("role", &REDACTED_LOCATOR)
                .field("token_root", &REDACTED_LOCATOR)
                .field("token_file", &REDACTED_LOCATOR)
                .finish(),
            Self::Token { secret_alias } => formatter
                .debug_struct("Token")
                .field("secret_alias", secret_alias)
                .finish(),
            Self::AppRole {
                secret_id_alias, ..
            } => formatter
                .debug_struct("AppRole")
                .field("mount", &REDACTED_LOCATOR)
                .field("role_id", &REDACTED_LOCATOR)
                .field("secret_id_alias", secret_id_alias)
                .finish(),
        }
    }
}

/// One opaque alias bound to exactly one KV v2 data key.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultSecretAliasConfig {
    pub id: String,
    pub label: String,
    pub profile: String,
    pub mount: String,
    pub path: String,
    pub key: String,
    #[serde(default)]
    pub version: Option<u64>,
}

impl fmt::Debug for VaultSecretAliasConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VaultSecretAliasConfig")
            .field("id", &self.id)
            .field("label", &self.label)
            .field("profile", &self.profile)
            .field("mount", &REDACTED_LOCATOR)
            .field("path", &REDACTED_LOCATOR)
            .field("key", &REDACTED_LOCATOR)
            .field("pinned", &self.version.is_some())
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VaultProviderConfigError {
    TooManyProfiles { maximum: usize },
    TooManyAliases { maximum: usize },
    InvalidProfileId { index: usize },
    DuplicateProfileId { index: usize, previous: usize },
    InvalidAddress { index: usize },
    InvalidNamespace { index: usize },
    InvalidAuthMount { index: usize },
    InvalidAuthRole { index: usize },
    InvalidWorkloadTokenRoot { index: usize },
    InvalidWorkloadTokenFile { index: usize },
    WorkloadTokenRootUnavailable { index: usize },
    WorkloadTokenRootPermissions { index: usize },
    InvalidBootstrapAlias { index: usize },
    BootstrapAliasCycle { index: usize },
    BootstrapResolverRequired { index: usize },
    UnknownBootstrapAlias { index: usize },
    InvalidAliasId { index: usize },
    InvalidLabel { index: usize },
    DuplicateAliasId { index: usize, previous: usize },
    ReservedAliasId { index: usize },
    UnknownProfile { index: usize },
    InvalidMount { index: usize },
    InvalidPath { index: usize },
    InvalidDataKey { index: usize },
    InvalidVersion { index: usize },
    AliasesWithoutProfiles,
}

impl fmt::Display for VaultProviderConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyProfiles { maximum } => write!(
                formatter,
                "vault provider profiles must contain at most {maximum} entries"
            ),
            Self::TooManyAliases { maximum } => write!(
                formatter,
                "vault provider aliases must contain at most {maximum} entries"
            ),
            Self::InvalidProfileId { index } => write!(
                formatter,
                "vault profile at index {index} has an invalid opaque ID"
            ),
            Self::DuplicateProfileId { index, previous } => write!(
                formatter,
                "vault profile at index {index} duplicates the opaque ID at index {previous}"
            ),
            Self::InvalidAddress { index } => write!(
                formatter,
                "vault profile at index {index} requires an absolute https address with no credentials, path, query, or fragment"
            ),
            Self::InvalidNamespace { index } => write!(
                formatter,
                "vault profile at index {index} has an invalid namespace"
            ),
            Self::InvalidAuthMount { index } => write!(
                formatter,
                "vault profile at index {index} has an invalid auth mount"
            ),
            Self::InvalidAuthRole { index } => write!(
                formatter,
                "vault profile at index {index} has an invalid auth role"
            ),
            Self::InvalidWorkloadTokenRoot { index } => write!(
                formatter,
                "vault profile at index {index} has an invalid workload identity token root"
            ),
            Self::InvalidWorkloadTokenFile { index } => write!(
                formatter,
                "vault profile at index {index} has an invalid workload identity token file key"
            ),
            Self::WorkloadTokenRootUnavailable { index } => write!(
                formatter,
                "vault profile at index {index} has a workload identity token root that is unavailable or cannot be canonicalized"
            ),
            Self::WorkloadTokenRootPermissions { index } => write!(
                formatter,
                "vault profile at index {index} has a workload identity token root with unsafe write permissions for this platform"
            ),
            Self::InvalidBootstrapAlias { index } => write!(
                formatter,
                "vault profile at index {index} has an invalid bootstrap alias ID"
            ),
            Self::BootstrapAliasCycle { index } => write!(
                formatter,
                "vault profile at index {index} bootstraps from an alias this provider itself serves"
            ),
            Self::BootstrapResolverRequired { index } => write!(
                formatter,
                "vault profile at index {index} bootstraps from an alias but no other provider is configured"
            ),
            Self::UnknownBootstrapAlias { index } => write!(
                formatter,
                "vault profile at index {index} bootstraps from an alias that no configured provider owns"
            ),
            Self::InvalidAliasId { index } => write!(
                formatter,
                "vault alias at index {index} has an invalid opaque ID"
            ),
            Self::InvalidLabel { index } => write!(
                formatter,
                "vault alias at index {index} has an invalid safe label"
            ),
            Self::DuplicateAliasId { index, previous } => write!(
                formatter,
                "vault alias at index {index} duplicates the opaque ID at index {previous}"
            ),
            Self::ReservedAliasId { index } => write!(
                formatter,
                "vault alias at index {index} duplicates an alias ID served by another provider"
            ),
            Self::UnknownProfile { index } => write!(
                formatter,
                "vault alias at index {index} names an unconfigured profile"
            ),
            Self::InvalidMount { index } => write!(
                formatter,
                "vault alias at index {index} has an invalid KV v2 mount"
            ),
            Self::InvalidPath { index } => write!(
                formatter,
                "vault alias at index {index} has an invalid KV v2 secret path"
            ),
            Self::InvalidDataKey { index } => write!(
                formatter,
                "vault alias at index {index} has an invalid KV v2 data key"
            ),
            Self::InvalidVersion { index } => write!(
                formatter,
                "vault alias at index {index} pins a version below 1"
            ),
            Self::AliasesWithoutProfiles => {
                formatter.write_str("vault aliases require at least one configured profile")
            }
        }
    }
}

impl Error for VaultProviderConfigError {}

/// Validates trusted startup configuration without touching the filesystem,
/// DNS, or the provider.
pub fn validate_vault_provider_config(
    config: &VaultProviderConfig,
    reserved_alias_ids: &BTreeSet<String>,
) -> Result<(), VaultProviderConfigError> {
    if config.profiles.len() > MAX_VAULT_PROFILES {
        return Err(VaultProviderConfigError::TooManyProfiles {
            maximum: MAX_VAULT_PROFILES,
        });
    }
    if config.aliases.len() > MAX_VAULT_SECRET_ALIASES {
        return Err(VaultProviderConfigError::TooManyAliases {
            maximum: MAX_VAULT_SECRET_ALIASES,
        });
    }
    if !config.aliases.is_empty() && config.profiles.is_empty() {
        return Err(VaultProviderConfigError::AliasesWithoutProfiles);
    }

    let alias_ids = config
        .aliases
        .iter()
        .map(|alias| alias.id.as_str())
        .collect::<BTreeSet<_>>();
    let mut profile_ids = BTreeMap::new();
    for (index, profile) in config.profiles.iter().enumerate() {
        if !is_valid_opaque_id(&profile.id, MAX_SECRET_ID_BYTES) {
            return Err(VaultProviderConfigError::InvalidProfileId { index });
        }
        if let Some(previous) = profile_ids.insert(profile.id.as_str(), index) {
            return Err(VaultProviderConfigError::DuplicateProfileId { index, previous });
        }
        if !is_valid_vault_address(&profile.address) {
            return Err(VaultProviderConfigError::InvalidAddress { index });
        }
        if profile
            .namespace
            .as_deref()
            .is_some_and(|namespace| !is_valid_vault_path(namespace, MAX_VAULT_NAMESPACE_BYTES))
        {
            return Err(VaultProviderConfigError::InvalidNamespace { index });
        }
        match &profile.auth {
            VaultAuthConfig::WorkloadJwt {
                mount,
                role,
                token_root,
                token_file,
            } => {
                if !is_valid_vault_path(mount, MAX_VAULT_MOUNT_BYTES) {
                    return Err(VaultProviderConfigError::InvalidAuthMount { index });
                }
                if !is_valid_vault_name(role) {
                    return Err(VaultProviderConfigError::InvalidAuthRole { index });
                }
                if token_root.is_empty() || token_root.len() > MAX_VAULT_PATH_BYTES {
                    return Err(VaultProviderConfigError::InvalidWorkloadTokenRoot { index });
                }
                if !is_valid_file_key(token_file) {
                    return Err(VaultProviderConfigError::InvalidWorkloadTokenFile { index });
                }
            }
            VaultAuthConfig::Token { secret_alias } => {
                validate_bootstrap_alias(index, secret_alias, &alias_ids)?;
            }
            VaultAuthConfig::AppRole {
                mount,
                role_id,
                secret_id_alias,
            } => {
                if !is_valid_vault_path(mount, MAX_VAULT_MOUNT_BYTES) {
                    return Err(VaultProviderConfigError::InvalidAuthMount { index });
                }
                if !is_valid_vault_name(role_id) {
                    return Err(VaultProviderConfigError::InvalidAuthRole { index });
                }
                validate_bootstrap_alias(index, secret_id_alias, &alias_ids)?;
            }
        }
    }

    let mut seen_alias_ids = BTreeMap::new();
    for (index, alias) in config.aliases.iter().enumerate() {
        if !is_valid_opaque_id(&alias.id, MAX_SECRET_ID_BYTES) {
            return Err(VaultProviderConfigError::InvalidAliasId { index });
        }
        if alias.label.is_empty()
            || alias.label.chars().count() > MAX_DISPLAY_NAME_CHARS
            || alias.label.chars().any(char::is_control)
        {
            return Err(VaultProviderConfigError::InvalidLabel { index });
        }
        if let Some(previous) = seen_alias_ids.insert(alias.id.as_str(), index) {
            return Err(VaultProviderConfigError::DuplicateAliasId { index, previous });
        }
        if reserved_alias_ids.contains(&alias.id) {
            return Err(VaultProviderConfigError::ReservedAliasId { index });
        }
        if !profile_ids.contains_key(alias.profile.as_str()) {
            return Err(VaultProviderConfigError::UnknownProfile { index });
        }
        if !is_valid_vault_path(&alias.mount, MAX_VAULT_MOUNT_BYTES) {
            return Err(VaultProviderConfigError::InvalidMount { index });
        }
        if !is_valid_vault_path(&alias.path, MAX_VAULT_PATH_BYTES) {
            return Err(VaultProviderConfigError::InvalidPath { index });
        }
        if !is_valid_vault_data_key(&alias.key) {
            return Err(VaultProviderConfigError::InvalidDataKey { index });
        }
        if alias.version == Some(0) {
            return Err(VaultProviderConfigError::InvalidVersion { index });
        }
    }
    Ok(())
}

fn validate_bootstrap_alias(
    index: usize,
    alias: &str,
    own_alias_ids: &BTreeSet<&str>,
) -> Result<(), VaultProviderConfigError> {
    if !is_valid_opaque_id(alias, MAX_SECRET_ID_BYTES) {
        return Err(VaultProviderConfigError::InvalidBootstrapAlias { index });
    }
    if own_alias_ids.contains(alias) {
        return Err(VaultProviderConfigError::BootstrapAliasCycle { index });
    }
    Ok(())
}

fn is_valid_vault_address(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_VAULT_ADDRESS_BYTES {
        return false;
    }
    if value
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte == b' ' || !byte.is_ascii())
    {
        return false;
    }
    let Ok(url) = Url::parse(value) else {
        return false;
    };
    url.scheme() == "https"
        && url.host_str().is_some_and(|host| !host.is_empty())
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && matches!(url.path(), "" | "/")
}

fn is_valid_vault_path(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && !value.starts_with('/')
        && !value.ends_with('/')
        && value.split('/').all(is_valid_vault_path_segment)
}

fn is_valid_vault_path_segment(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value.bytes().all(
            |byte| matches!(byte, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'_' | b'-'),
        )
}

fn is_valid_vault_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_VAULT_NAME_BYTES
        && value.bytes().all(
            |byte| matches!(byte, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'_' | b'-'),
        )
}

fn is_valid_vault_data_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_VAULT_DATA_KEY_BYTES
        && value.bytes().all(
            |byte| matches!(byte, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'_' | b'-'),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADDRESS_CANARY: &str = "https://vault-locator-canary.internal.example";
    const MOUNT_CANARY: &str = "mount-locator-canary";
    const PATH_CANARY: &str = "team-locator-canary/billing-locator-canary";
    const KEY_CANARY: &str = "data-key-locator-canary";

    fn alias(id: &str, version: Option<u64>) -> VaultSecretAliasConfig {
        VaultSecretAliasConfig {
            id: id.to_owned(),
            label: format!("{id} label"),
            profile: "primary".to_owned(),
            mount: MOUNT_CANARY.to_owned(),
            path: PATH_CANARY.to_owned(),
            key: KEY_CANARY.to_owned(),
            version,
        }
    }

    fn token_profile(id: &str, secret_alias: &str) -> VaultProfileConfig {
        VaultProfileConfig {
            id: id.to_owned(),
            address: ADDRESS_CANARY.to_owned(),
            namespace: Some("team-namespace-canary".to_owned()),
            auth: VaultAuthConfig::Token {
                secret_alias: secret_alias.to_owned(),
            },
        }
    }

    #[test]
    fn configuration_rejects_unsafe_or_ambiguous_entries() {
        let base = |profiles: Vec<VaultProfileConfig>, aliases: Vec<VaultSecretAliasConfig>| {
            validate_vault_provider_config(
                &VaultProviderConfig { profiles, aliases },
                &BTreeSet::new(),
            )
        };
        for address in [
            "http://vault.example",
            "https://user:pass@vault.example",
            "https://vault.example/v1",
            "https://vault.example?token=x",
            "https://vault.example#fragment",
            "vault.example",
            "",
        ] {
            let mut profile = token_profile("primary", "bootstrap");
            profile.address = address.to_owned();
            assert!(
                matches!(
                    base(vec![profile], Vec::new()),
                    Err(VaultProviderConfigError::InvalidAddress { .. })
                ),
                "{address:?} must be rejected"
            );
        }
        for path in [
            "../escape",
            "/absolute",
            "trailing/",
            "double//segment",
            "team/../escape",
            "team/secret?version=1",
            "team/secret#fragment",
            "team/secret%2f",
        ] {
            let mut entry = alias("billing", None);
            entry.path = path.to_owned();
            assert!(
                matches!(
                    base(vec![token_profile("primary", "bootstrap")], vec![entry]),
                    Err(VaultProviderConfigError::InvalidPath { .. })
                ),
                "{path:?} must be rejected"
            );
        }
        let mut duplicate = alias("billing", None);
        duplicate.id = "billing".to_owned();
        assert!(matches!(
            base(
                vec![token_profile("primary", "bootstrap")],
                vec![alias("billing", None), duplicate],
            ),
            Err(VaultProviderConfigError::DuplicateAliasId { .. })
        ));
        let mut unknown_profile = alias("billing", None);
        unknown_profile.profile = "missing".to_owned();
        assert!(matches!(
            base(
                vec![token_profile("primary", "bootstrap")],
                vec![unknown_profile]
            ),
            Err(VaultProviderConfigError::UnknownProfile { .. })
        ));
        assert!(matches!(
            base(
                vec![token_profile("primary", "billing")],
                vec![alias("billing", None)],
            ),
            Err(VaultProviderConfigError::BootstrapAliasCycle { .. })
        ));
        assert!(matches!(
            base(
                vec![token_profile("primary", "bootstrap")],
                vec![alias("billing", Some(0))],
            ),
            Err(VaultProviderConfigError::InvalidVersion { .. })
        ));
        assert!(matches!(
            base(Vec::new(), vec![alias("billing", None)]),
            Err(VaultProviderConfigError::AliasesWithoutProfiles)
        ));
        assert!(matches!(
            validate_vault_provider_config(
                &VaultProviderConfig {
                    profiles: vec![token_profile("primary", "bootstrap")],
                    aliases: vec![alias("billing", None)],
                },
                &BTreeSet::from(["billing".to_owned()]),
            ),
            Err(VaultProviderConfigError::ReservedAliasId { .. })
        ));
        let profiles = (0..=MAX_VAULT_PROFILES)
            .map(|index| token_profile(&format!("profile-{index}"), "bootstrap"))
            .collect::<Vec<_>>();
        assert!(matches!(
            base(profiles, Vec::new()),
            Err(VaultProviderConfigError::TooManyProfiles { .. })
        ));
    }
}
