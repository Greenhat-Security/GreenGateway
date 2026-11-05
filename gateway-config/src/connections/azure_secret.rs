//! The Azure Key Vault provider's configuration document
//! (`CONNECTION_AZURE_PROVIDER`) and its validator.
//!
//! Validation is a function of the document alone: it opens no file, resolves
//! no name and contacts no provider. The provider the gateway builds from a
//! validated document, and every check that needs the world, stay in the
//! gateway's `connections::azure_secret`, which re-exports these.

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

pub const MAX_AZURE_PROFILES: usize = 8;
pub const MAX_AZURE_SECRET_ALIASES: usize = MAX_CREDENTIALS;
pub const MAX_AZURE_PROVIDER_CONFIG_BYTES: usize = 256 * 1024;
const MAX_AZURE_AUTHORITY_HOST_BYTES: usize = 255;
const MAX_AZURE_SCOPE_BYTES: usize = 512;
const MAX_AZURE_VAULT_AUTHORITY_BYTES: usize = 512;
const MAX_AZURE_SECRET_NAME_BYTES: usize = 127;
const AZURE_SECRET_VERSION_BYTES: usize = 32;
const AZURE_CERTIFICATE_THUMBPRINT_HEX_BYTES: usize = 40;
const MAX_AZURE_WORKLOAD_TOKEN_ROOT_BYTES: usize = 512;
const REDACTED_LOCATOR: &str = "<redacted-locator>";

/// Trusted startup configuration for the read-only Key Vault Secrets provider.
#[derive(Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AzureProviderConfig {
    #[serde(default)]
    pub profiles: Vec<AzureProfileConfig>,
    #[serde(default)]
    pub aliases: Vec<AzureSecretAliasConfig>,
}

impl fmt::Debug for AzureProviderConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AzureProviderConfig")
            .field("profile_count", &self.profiles.len())
            .field("alias_count", &self.aliases.len())
            .finish()
    }
}

impl AzureProviderConfig {
    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty() && self.aliases.is_empty()
    }
}

/// One cloud/authority profile plus the fixed workload identity used with it.
///
/// The authority host and token scope default to the public cloud
/// (`login.microsoftonline.com` and `https://vault.azure.net/.default`).
/// Sovereign clouds are supported only by explicit configuration of both; the
/// provider never discovers or negotiates either value.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AzureProfileConfig {
    pub id: String,
    #[serde(default)]
    pub authority_host: Option<String>,
    pub tenant_id: String,
    pub client_id: String,
    #[serde(default)]
    pub scope: Option<String>,
    pub auth: AzureAuthConfig,
}

impl fmt::Debug for AzureProfileConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AzureProfileConfig")
            .field("id", &self.id)
            .field(
                "authority_host",
                &self.authority_host.as_ref().map(|_| REDACTED_LOCATOR),
            )
            .field("tenant_id", &REDACTED_LOCATOR)
            .field("client_id", &REDACTED_LOCATOR)
            .field("scope", &self.scope.as_ref().map(|_| REDACTED_LOCATOR))
            .field("auth", &self.auth)
            .finish()
    }
}

/// Authentication used to obtain a short-lived Entra access token.
///
/// `workload_jwt` is the only mechanism that needs no bootstrap secret at all:
/// a fixed projected OIDC token file is exchanged as a federated client
/// assertion. `client_secret` and `client_certificate` exist for deployments
/// without workload identity federation; both take their bootstrap material
/// from an already configured alias of another provider, never from an inline
/// value. Interactive, device-code, CLI, managed-identity probing, and
/// ambient credential chains are not representable.
///
/// Managed identity is absent by decision, and not for the reason usually
/// given. That `EgressClient` blocks the link-local IMDS address is only half
/// true: `169.254.0.0/16` is non-global, so the default
/// `EGRESS_DENY_PRIVATE_IPS=true` refuses it, but that is a default an operator
/// can lift with a scoped policy allow-CIDR — exactly how the Kubernetes
/// provider admits an in-cluster API server. The real obstacle is that IMDS is
/// a different protocol on a different kind of channel: an unauthenticated
/// plaintext `http://` request carrying a `Metadata` header, answered with a
/// bearer token, with no TLS, no certificate and no hostname to verify.
/// Representing it would put an unverified plaintext token fetch inside a
/// provider whose whole contract is TLS-verified egress to fixed locators, and
/// it would do so to reach a mechanism whose supported successor on Kubernetes
/// — Entra Workload ID, which uses the v2 token endpoint rather than the IMDS
/// `resource` flow — is already the `WorkloadJwt` variant below. Revisit only
/// if a managed-identity shape appears that is authenticated and routable.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum AzureAuthConfig {
    WorkloadJwt {
        token_root: String,
        token_file: String,
    },
    ClientSecret {
        secret_alias: String,
    },
    ClientCertificate {
        key_alias: String,
        certificate_thumbprint: String,
    },
}

impl fmt::Debug for AzureAuthConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WorkloadJwt { .. } => formatter
                .debug_struct("WorkloadJwt")
                .field("token_root", &REDACTED_LOCATOR)
                .field("token_file", &REDACTED_LOCATOR)
                .finish(),
            Self::ClientSecret { secret_alias } => formatter
                .debug_struct("ClientSecret")
                .field("secret_alias", secret_alias)
                .finish(),
            Self::ClientCertificate { key_alias, .. } => formatter
                .debug_struct("ClientCertificate")
                .field("key_alias", key_alias)
                .field("certificate_thumbprint", &REDACTED_LOCATOR)
                .finish(),
        }
    }
}

/// One opaque alias bound to exactly one Key Vault secret.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AzureSecretAliasConfig {
    pub id: String,
    pub label: String,
    pub profile: String,
    pub vault: String,
    pub name: String,
    #[serde(default)]
    pub version: Option<String>,
}

impl fmt::Debug for AzureSecretAliasConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AzureSecretAliasConfig")
            .field("id", &self.id)
            .field("label", &self.label)
            .field("profile", &self.profile)
            .field("vault", &REDACTED_LOCATOR)
            .field("name", &REDACTED_LOCATOR)
            .field("pinned", &self.version.is_some())
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AzureProviderConfigError {
    TooManyProfiles { maximum: usize },
    TooManyAliases { maximum: usize },
    InvalidProfileId { index: usize },
    DuplicateProfileId { index: usize, previous: usize },
    InvalidAuthorityHost { index: usize },
    InvalidTenantId { index: usize },
    InvalidClientId { index: usize },
    InvalidScope { index: usize },
    InvalidWorkloadTokenRoot { index: usize },
    InvalidWorkloadTokenFile { index: usize },
    WorkloadTokenRootUnavailable { index: usize },
    WorkloadTokenRootPermissions { index: usize },
    InvalidBootstrapAlias { index: usize },
    BootstrapAliasCycle { index: usize },
    BootstrapResolverRequired { index: usize },
    UnknownBootstrapAlias { index: usize },
    InvalidCertificateThumbprint { index: usize },
    InvalidAliasId { index: usize },
    InvalidLabel { index: usize },
    DuplicateAliasId { index: usize, previous: usize },
    ReservedAliasId { index: usize },
    UnknownProfile { index: usize },
    InvalidVaultAuthority { index: usize },
    InvalidSecretName { index: usize },
    InvalidVersion { index: usize },
    AliasesWithoutProfiles,
}

impl fmt::Display for AzureProviderConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyProfiles { maximum } => write!(
                formatter,
                "azure provider profiles must contain at most {maximum} entries"
            ),
            Self::TooManyAliases { maximum } => write!(
                formatter,
                "azure provider aliases must contain at most {maximum} entries"
            ),
            Self::InvalidProfileId { index } => write!(
                formatter,
                "azure profile at index {index} has an invalid opaque ID"
            ),
            Self::DuplicateProfileId { index, previous } => write!(
                formatter,
                "azure profile at index {index} duplicates the opaque ID at index {previous}"
            ),
            Self::InvalidAuthorityHost { index } => write!(
                formatter,
                "azure profile at index {index} requires a bare DNS authority host with no scheme, port, path, or credentials"
            ),
            Self::InvalidTenantId { index } => write!(
                formatter,
                "azure profile at index {index} requires a GUID tenant ID"
            ),
            Self::InvalidClientId { index } => write!(
                formatter,
                "azure profile at index {index} requires a GUID client ID"
            ),
            Self::InvalidScope { index } => write!(
                formatter,
                "azure profile at index {index} requires an absolute https scope ending in /.default with no port, credentials, query, or fragment"
            ),
            Self::InvalidWorkloadTokenRoot { index } => write!(
                formatter,
                "azure profile at index {index} has an invalid workload identity token root"
            ),
            Self::InvalidWorkloadTokenFile { index } => write!(
                formatter,
                "azure profile at index {index} has an invalid workload identity token file key"
            ),
            Self::WorkloadTokenRootUnavailable { index } => write!(
                formatter,
                "azure profile at index {index} has a workload identity token root that is unavailable or cannot be canonicalized"
            ),
            Self::WorkloadTokenRootPermissions { index } => write!(
                formatter,
                "azure profile at index {index} has a workload identity token root with unsafe write permissions for this platform"
            ),
            Self::InvalidBootstrapAlias { index } => write!(
                formatter,
                "azure profile at index {index} has an invalid bootstrap alias ID"
            ),
            Self::BootstrapAliasCycle { index } => write!(
                formatter,
                "azure profile at index {index} bootstraps from an alias this provider itself serves"
            ),
            Self::BootstrapResolverRequired { index } => write!(
                formatter,
                "azure profile at index {index} bootstraps from an alias but no other provider is configured"
            ),
            Self::UnknownBootstrapAlias { index } => write!(
                formatter,
                "azure profile at index {index} bootstraps from an alias that no configured provider owns"
            ),
            Self::InvalidCertificateThumbprint { index } => write!(
                formatter,
                "azure profile at index {index} requires a 40-character hex SHA-1 certificate thumbprint"
            ),
            Self::InvalidAliasId { index } => write!(
                formatter,
                "azure alias at index {index} has an invalid opaque ID"
            ),
            Self::InvalidLabel { index } => write!(
                formatter,
                "azure alias at index {index} has an invalid safe label"
            ),
            Self::DuplicateAliasId { index, previous } => write!(
                formatter,
                "azure alias at index {index} duplicates the opaque ID at index {previous}"
            ),
            Self::ReservedAliasId { index } => write!(
                formatter,
                "azure alias at index {index} duplicates an alias ID served by another provider"
            ),
            Self::UnknownProfile { index } => write!(
                formatter,
                "azure alias at index {index} names an unconfigured profile"
            ),
            Self::InvalidVaultAuthority { index } => write!(
                formatter,
                "azure alias at index {index} requires an absolute https vault authority with no credentials, path, query, or fragment"
            ),
            Self::InvalidSecretName { index } => write!(
                formatter,
                "azure alias at index {index} has an invalid Key Vault secret name"
            ),
            Self::InvalidVersion { index } => write!(
                formatter,
                "azure alias at index {index} pins an invalid secret version"
            ),
            Self::AliasesWithoutProfiles => {
                formatter.write_str("azure aliases require at least one configured profile")
            }
        }
    }
}

impl Error for AzureProviderConfigError {}

/// Validates trusted startup configuration without touching the filesystem,
/// DNS, or the provider.
pub fn validate_azure_provider_config(
    config: &AzureProviderConfig,
    reserved_alias_ids: &BTreeSet<String>,
) -> Result<(), AzureProviderConfigError> {
    if config.profiles.len() > MAX_AZURE_PROFILES {
        return Err(AzureProviderConfigError::TooManyProfiles {
            maximum: MAX_AZURE_PROFILES,
        });
    }
    if config.aliases.len() > MAX_AZURE_SECRET_ALIASES {
        return Err(AzureProviderConfigError::TooManyAliases {
            maximum: MAX_AZURE_SECRET_ALIASES,
        });
    }
    if !config.aliases.is_empty() && config.profiles.is_empty() {
        return Err(AzureProviderConfigError::AliasesWithoutProfiles);
    }

    let alias_ids = config
        .aliases
        .iter()
        .map(|alias| alias.id.as_str())
        .collect::<BTreeSet<_>>();
    let mut profile_ids = BTreeMap::new();
    for (index, profile) in config.profiles.iter().enumerate() {
        if !is_valid_opaque_id(&profile.id, MAX_SECRET_ID_BYTES) {
            return Err(AzureProviderConfigError::InvalidProfileId { index });
        }
        if let Some(previous) = profile_ids.insert(profile.id.as_str(), index) {
            return Err(AzureProviderConfigError::DuplicateProfileId { index, previous });
        }
        if profile
            .authority_host
            .as_deref()
            .is_some_and(|host| !is_valid_azure_authority_host(host))
        {
            return Err(AzureProviderConfigError::InvalidAuthorityHost { index });
        }
        if !is_valid_azure_guid(&profile.tenant_id) {
            return Err(AzureProviderConfigError::InvalidTenantId { index });
        }
        if !is_valid_azure_guid(&profile.client_id) {
            return Err(AzureProviderConfigError::InvalidClientId { index });
        }
        if profile
            .scope
            .as_deref()
            .is_some_and(|scope| !is_valid_azure_scope(scope))
        {
            return Err(AzureProviderConfigError::InvalidScope { index });
        }
        match &profile.auth {
            AzureAuthConfig::WorkloadJwt {
                token_root,
                token_file,
            } => {
                if token_root.is_empty() || token_root.len() > MAX_AZURE_WORKLOAD_TOKEN_ROOT_BYTES {
                    return Err(AzureProviderConfigError::InvalidWorkloadTokenRoot { index });
                }
                if !is_valid_file_key(token_file) {
                    return Err(AzureProviderConfigError::InvalidWorkloadTokenFile { index });
                }
            }
            AzureAuthConfig::ClientSecret { secret_alias } => {
                validate_bootstrap_alias(index, secret_alias, &alias_ids)?;
            }
            AzureAuthConfig::ClientCertificate {
                key_alias,
                certificate_thumbprint,
            } => {
                validate_bootstrap_alias(index, key_alias, &alias_ids)?;
                if !is_valid_azure_certificate_thumbprint(certificate_thumbprint) {
                    return Err(AzureProviderConfigError::InvalidCertificateThumbprint { index });
                }
            }
        }
    }

    let mut seen_alias_ids = BTreeMap::new();
    for (index, alias) in config.aliases.iter().enumerate() {
        if !is_valid_opaque_id(&alias.id, MAX_SECRET_ID_BYTES) {
            return Err(AzureProviderConfigError::InvalidAliasId { index });
        }
        if alias.label.is_empty()
            || alias.label.chars().count() > MAX_DISPLAY_NAME_CHARS
            || alias.label.chars().any(char::is_control)
        {
            return Err(AzureProviderConfigError::InvalidLabel { index });
        }
        if let Some(previous) = seen_alias_ids.insert(alias.id.as_str(), index) {
            return Err(AzureProviderConfigError::DuplicateAliasId { index, previous });
        }
        if reserved_alias_ids.contains(&alias.id) {
            return Err(AzureProviderConfigError::ReservedAliasId { index });
        }
        if !profile_ids.contains_key(alias.profile.as_str()) {
            return Err(AzureProviderConfigError::UnknownProfile { index });
        }
        if !is_valid_azure_vault_authority(&alias.vault) {
            return Err(AzureProviderConfigError::InvalidVaultAuthority { index });
        }
        if !is_valid_azure_secret_name(&alias.name) {
            return Err(AzureProviderConfigError::InvalidSecretName { index });
        }
        if alias
            .version
            .as_deref()
            .is_some_and(|version| !is_valid_azure_secret_version(version))
        {
            return Err(AzureProviderConfigError::InvalidVersion { index });
        }
    }
    Ok(())
}

fn validate_bootstrap_alias(
    index: usize,
    alias: &str,
    own_alias_ids: &BTreeSet<&str>,
) -> Result<(), AzureProviderConfigError> {
    if !is_valid_opaque_id(alias, MAX_SECRET_ID_BYTES) {
        return Err(AzureProviderConfigError::InvalidBootstrapAlias { index });
    }
    if own_alias_ids.contains(alias) {
        return Err(AzureProviderConfigError::BootstrapAliasCycle { index });
    }
    Ok(())
}

fn is_valid_azure_authority_host(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_AZURE_AUTHORITY_HOST_BYTES || !value.contains('.') {
        return false;
    }
    value.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-'))
    })
}

/// Accepts only the 36-character hyphenated GUID that Entra uses for tenant
/// and application (client) IDs.
///
/// Microsoft documents the client-credentials token endpoint as taking its
/// tenant "in GUID or domain-name format", and the domain-name half is refused
/// here deliberately. A GUID is the tenant's immutable identifier; a verified
/// domain is a mutable alias whose owning tenant is settled by DNS proof,
/// outside the configuration an operator fixes at startup — so a domain-shaped
/// tenant would be the one locator in this provider that can come to mean a
/// different thing without anyone editing the gateway. The failure mode if it
/// ever did is a denial rather than a disclosure (the assertion is still sent
/// to the same TLS-verified authority, and a client ID is globally unique, so
/// it cannot be redeemed elsewhere), but refusing costs the operator one portal
/// lookup and no capability at all: both forms name the same tenant. The
/// multi-tenant meta-tenants (`common`, `organizations`, `consumers`) are not a
/// documented shape for this grant in the first place. The configuration canary
/// pins all of these as rejected.
fn is_valid_azure_guid(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => *byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        })
}

fn is_valid_azure_scope(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_AZURE_SCOPE_BYTES {
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
        && url.port().is_none()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && url.path() == "/.default"
}

fn is_valid_azure_vault_authority(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_AZURE_VAULT_AUTHORITY_BYTES {
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

fn is_valid_azure_secret_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_AZURE_SECRET_NAME_BYTES
        && value
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-'))
}

pub fn is_valid_azure_secret_version(value: &str) -> bool {
    value.len() == AZURE_SECRET_VERSION_BYTES
        && value
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'f' | b'0'..=b'9'))
}

fn is_valid_azure_certificate_thumbprint(value: &str) -> bool {
    value.len() == AZURE_CERTIFICATE_THUMBPRINT_HEX_BYTES
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    const AUTHORITY_CANARY: &str = "login.authority-locator-canary.example";
    const TENANT_CANARY: &str = "11111111-2222-3333-4444-555566667777";
    const CLIENT_CANARY: &str = "88888888-9999-aaaa-bbbb-ccccddddeeee";
    const SCOPE_CANARY: &str = "https://vault.scope-locator-canary.example/.default";
    const VAULT_CANARY: &str = "https://vault-locator-canary.vault.example";
    const NAME_CANARY: &str = "secret-name-locator-canary";

    fn client_secret_profile(id: &str) -> AzureProfileConfig {
        AzureProfileConfig {
            id: id.to_owned(),
            authority_host: Some(AUTHORITY_CANARY.to_owned()),
            tenant_id: TENANT_CANARY.to_owned(),
            client_id: CLIENT_CANARY.to_owned(),
            scope: Some(SCOPE_CANARY.to_owned()),
            auth: AzureAuthConfig::ClientSecret {
                secret_alias: "bootstrap-client-secret".to_owned(),
            },
        }
    }

    fn certificate_profile(id: &str) -> AzureProfileConfig {
        AzureProfileConfig {
            id: id.to_owned(),
            authority_host: Some(AUTHORITY_CANARY.to_owned()),
            tenant_id: TENANT_CANARY.to_owned(),
            client_id: CLIENT_CANARY.to_owned(),
            scope: Some(SCOPE_CANARY.to_owned()),
            auth: AzureAuthConfig::ClientCertificate {
                key_alias: "bootstrap-client-key".to_owned(),
                certificate_thumbprint: "00112233445566778899aabbccddeeff00112233".to_owned(),
            },
        }
    }

    fn alias(id: &str, version: Option<&str>) -> AzureSecretAliasConfig {
        AzureSecretAliasConfig {
            id: id.to_owned(),
            label: format!("{id} label"),
            profile: "primary".to_owned(),
            vault: VAULT_CANARY.to_owned(),
            name: NAME_CANARY.to_owned(),
            version: version.map(str::to_owned),
        }
    }

    #[test]
    fn configuration_rejects_unsafe_or_ambiguous_entries() {
        let base = |profiles: Vec<AzureProfileConfig>, aliases: Vec<AzureSecretAliasConfig>| {
            validate_azure_provider_config(
                &AzureProviderConfig { profiles, aliases },
                &BTreeSet::new(),
            )
        };
        for host in [
            "https://login.microsoftonline.com",
            "login.microsoftonline.com/",
            "login.microsoftonline.com:443",
            "user@login.microsoftonline.com",
            "LOGIN.MICROSOFTONLINE.COM",
            "login..example",
            "-bad.example",
            "localhost",
            "",
        ] {
            let mut profile = client_secret_profile("primary");
            profile.authority_host = Some(host.to_owned());
            assert!(
                matches!(
                    base(vec![profile], Vec::new()),
                    Err(AzureProviderConfigError::InvalidAuthorityHost { .. })
                ),
                "{host:?} must be rejected"
            );
        }
        for tenant in [
            "common",
            "organizations",
            "consumers",
            "contoso.onmicrosoft.com",
            "11111111-2222-3333-4444-55556666777",
            "11111111222233334444555566667777zzzz",
            "",
        ] {
            let mut profile = client_secret_profile("primary");
            profile.tenant_id = tenant.to_owned();
            assert!(
                matches!(
                    base(vec![profile], Vec::new()),
                    Err(AzureProviderConfigError::InvalidTenantId { .. })
                ),
                "{tenant:?} must be rejected"
            );
        }
        for scope in [
            "http://vault.azure.net/.default",
            "https://vault.azure.net/",
            "https://vault.azure.net/.default?x=1",
            "https://vault.azure.net/.default#f",
            "https://vault.azure.net:8443/.default",
            "https://user:pass@vault.azure.net/.default",
            "vault.azure.net/.default",
            "",
        ] {
            let mut profile = client_secret_profile("primary");
            profile.scope = Some(scope.to_owned());
            assert!(
                matches!(
                    base(vec![profile], Vec::new()),
                    Err(AzureProviderConfigError::InvalidScope { .. })
                ),
                "{scope:?} must be rejected"
            );
        }
        for vault in [
            "http://myvault.vault.azure.net",
            "https://user:pass@myvault.vault.azure.net",
            "https://myvault.vault.azure.net/secrets",
            "https://myvault.vault.azure.net?x=1",
            "https://myvault.vault.azure.net#f",
            "myvault.vault.azure.net",
            "",
        ] {
            let mut entry = alias("billing", None);
            entry.vault = vault.to_owned();
            assert!(
                matches!(
                    base(vec![client_secret_profile("primary")], vec![entry]),
                    Err(AzureProviderConfigError::InvalidVaultAuthority { .. })
                ),
                "{vault:?} must be rejected"
            );
        }
        for name in [
            "has_underscore",
            "has.dot",
            "has/slash",
            "has space",
            &"x".repeat(MAX_AZURE_SECRET_NAME_BYTES + 1),
            "",
        ] {
            let mut entry = alias("billing", None);
            entry.name = name.to_owned();
            assert!(
                matches!(
                    base(vec![client_secret_profile("primary")], vec![entry]),
                    Err(AzureProviderConfigError::InvalidSecretName { .. })
                ),
                "{name:?} must be rejected"
            );
        }
        for version in ["short", "0123456789ABCDEF0123456789ABCDEF", ""] {
            assert!(
                matches!(
                    base(
                        vec![client_secret_profile("primary")],
                        vec![alias("billing", Some(version))],
                    ),
                    Err(AzureProviderConfigError::InvalidVersion { .. })
                ),
                "{version:?} must be rejected"
            );
        }
        for thumbprint in ["short", "zz112233445566778899aabbccddeeff00112233", ""] {
            let mut profile = certificate_profile("primary");
            profile.auth = AzureAuthConfig::ClientCertificate {
                key_alias: "bootstrap-client-key".to_owned(),
                certificate_thumbprint: thumbprint.to_owned(),
            };
            assert!(
                matches!(
                    base(vec![profile], Vec::new()),
                    Err(AzureProviderConfigError::InvalidCertificateThumbprint { .. })
                ),
                "{thumbprint:?} must be rejected"
            );
        }
        let mut duplicate = alias("billing", None);
        duplicate.id = "billing".to_owned();
        assert!(matches!(
            base(
                vec![client_secret_profile("primary")],
                vec![alias("billing", None), duplicate],
            ),
            Err(AzureProviderConfigError::DuplicateAliasId { .. })
        ));
        let mut unknown_profile = alias("billing", None);
        unknown_profile.profile = "missing".to_owned();
        assert!(matches!(
            base(
                vec![client_secret_profile("primary")],
                vec![unknown_profile]
            ),
            Err(AzureProviderConfigError::UnknownProfile { .. })
        ));
        let mut cyclic = client_secret_profile("primary");
        cyclic.auth = AzureAuthConfig::ClientSecret {
            secret_alias: "billing".to_owned(),
        };
        assert!(matches!(
            base(vec![cyclic], vec![alias("billing", None)]),
            Err(AzureProviderConfigError::BootstrapAliasCycle { .. })
        ));
        assert!(matches!(
            base(Vec::new(), vec![alias("billing", None)]),
            Err(AzureProviderConfigError::AliasesWithoutProfiles)
        ));
        assert!(matches!(
            validate_azure_provider_config(
                &AzureProviderConfig {
                    profiles: vec![client_secret_profile("primary")],
                    aliases: vec![alias("billing", None)],
                },
                &BTreeSet::from(["billing".to_owned()]),
            ),
            Err(AzureProviderConfigError::ReservedAliasId { .. })
        ));
        let profiles = (0..=MAX_AZURE_PROFILES)
            .map(|index| client_secret_profile(&format!("profile-{index}")))
            .collect::<Vec<_>>();
        assert!(matches!(
            base(profiles, Vec::new()),
            Err(AzureProviderConfigError::TooManyProfiles { .. })
        ));
    }
}
