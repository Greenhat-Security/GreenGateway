//! Read-only Azure Key Vault Secrets provider.
//!
//! The provider is one more implementation of the stable [`SecretResolver`]
//! contract. It adds no Connection authority, no secret CRUD service, and no
//! reveal or provider-proxy endpoint. Every provider locator (authority host,
//! tenant, client, scope, vault authority, secret name, optional pinned
//! version, workload token root and file, bootstrap alias) is fixed by trusted
//! startup configuration and bound to one opaque alias, so callers, tool
//! arguments, and ordinary Connection mutations can only name an alias that an
//! operator already provisioned.
//!
//! Only the Key Vault Secrets *Get Secret* operation is implemented, against a
//! single pinned `api-version`. There is no list, backup, restore, recover,
//! purge, write, delete, administration, or general Key Vault path, and no
//! request URL contains a caller-supplied byte: each alias carries a request
//! line that was assembled and validated once at startup.
//!
//! A Microsoft Entra access token for the fixed Key Vault scope is acquired
//! *before* any vault access through the client-credentials grant at the
//! configured authority. The provider never issues an unauthenticated probe
//! and never reads a `WWW-Authenticate` challenge to discover a tenant,
//! scope, authority, or vault: every identity input is fixed configuration.
//! Interactive, device-code, CLI, and ambient credential-chain flows are
//! structurally unrepresentable.
//!
//! Every provider and identity request travels through [`EgressClient`], so
//! the deployment egress policy (HTTPS, allowlisted host and port, strict CA,
//! hostname and SNI validation, all-answer DNS validation with exact address
//! pinning, and a disabled redirect policy) applies unchanged. Rotation,
//! revocation, disablement, deletion, temporal violations, malformed data,
//! provider outage, and newly denied access all fail closed: a failed
//! resolution purges any cached value for that alias and never returns a
//! previous value, retries anonymously, or switches credential sources.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    fs::{self},
    path::PathBuf,
    sync::{Arc, Mutex, MutexGuard, OnceLock},
    time::{Duration, Instant, SystemTime},
};

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_SAFE_NO_PAD, Engine as _};
use cap_std::{ambient_authority, fs::Dir};
use http::{
    header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE},
    HeaderMap, HeaderValue, Method, StatusCode,
};
use jsonwebtoken::{
    encode as encode_client_assertion, Algorithm, EncodingKey, Header as JwtHeader,
};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex as AsyncMutex, Semaphore};
use url::{Origin, Url};
use zeroize::Zeroizing;

use crate::egress::{EgressClient, EgressError};

use super::{
    model::{MAX_CREDENTIALS, MAX_DISPLAY_NAME_CHARS, MAX_SECRET_ID_BYTES},
    secret::{
        configured_secret_generation_digest, is_valid_opaque_id, read_bounded_file_secret,
        safe_error_alias_id, FileSecretPermissions, ResolvedSecret, SecretAliasMetadata,
        SecretProviderKind, SecretPurpose, SecretResolveError, SecretResolveErrorKind,
        SecretResolver, MAX_TLS_PRIVATE_KEY_BYTES,
    },
};

pub const MAX_AZURE_PROFILES: usize = 8;
pub const MAX_AZURE_SECRET_ALIASES: usize = MAX_CREDENTIALS;
pub const MAX_AZURE_PROVIDER_CONFIG_BYTES: usize = 256 * 1024;
pub const MAX_CONCURRENT_AZURE_RESOLUTIONS: usize = 8;

/// Pinned Key Vault Secrets data-plane API version, never negotiated or
/// discovered at runtime.
///
/// `7.6` and the date-based `2025-07-01` are GA as well, and the pin stays at
/// `7.5` on purpose. The published `7.6` Secrets specification is identical to
/// `7.5` apart from the version string, so bumping to it buys nothing for the
/// single operation this provider issues. `2025-07-01` does differ, and in the
/// wrong direction for us: it adds an `outContentType` parameter that converts
/// certificate-backed secrets between PFX and PEM, and a `previousVersion`
/// field naming the superseded version of a certificate-backed secret — the
/// same opaque-locator-for-superseded-material shape this provider withholds
/// everywhere else. Sovereign clouds also receive new API versions after the
/// public cloud, and Microsoft has announced no retirement of data-plane
/// versions, so the older stable version is the more widely reachable one at
/// no functional cost. Revisit when a needed field or operation actually lands
/// in a newer version, not because a newer number exists.
const AZURE_KEY_VAULT_API_VERSION: &str = "7.5";
const AZURE_PUBLIC_AUTHORITY_HOST: &str = "login.microsoftonline.com";
const AZURE_PUBLIC_KEY_VAULT_SCOPE: &str = "https://vault.azure.net/.default";
const AZURE_CLIENT_ASSERTION_LIFETIME_SECS: u64 = 10 * 60;
const MAX_AZURE_AUTHORITY_HOST_BYTES: usize = 255;
const MAX_AZURE_SCOPE_BYTES: usize = 512;
const MAX_AZURE_VAULT_AUTHORITY_BYTES: usize = 512;
const MAX_AZURE_SECRET_NAME_BYTES: usize = 127;
const AZURE_SECRET_VERSION_BYTES: usize = 32;
const AZURE_CERTIFICATE_THUMBPRINT_HEX_BYTES: usize = 40;
const MAX_AZURE_WORKLOAD_TOKEN_ROOT_BYTES: usize = 512;
const MAX_AZURE_TOKEN_RESPONSE_BYTES: usize = 32 * 1024;
const MAX_AZURE_READ_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_AZURE_ACCESS_TOKEN_BYTES: usize = 16 * 1024;
const MAX_AZURE_CLIENT_SECRET_BYTES: usize = 1024;
const MAX_AZURE_TOKEN_LIFETIME: Duration = Duration::from_secs(60 * 60);
const AZURE_TOKEN_REFRESH_SKEW: Duration = Duration::from_secs(30);
const AZURE_VALUE_CACHE_TTL: Duration = Duration::from_secs(60);
const MAX_AZURE_VALUE_CACHE_ENTRIES: usize = 256;
const MAX_AZURE_TRANSIENT_RETRIES: u32 = 1;
const AZURE_RETRY_BACKOFF: Duration = Duration::from_millis(100);
const AZURE_RESOLUTION_DEADLINE: Duration = Duration::from_secs(10);
const AZURE_PROVIDER_LABEL: &str = "azure_key_vault";
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
/// Requires that the resolver which will actually serve a profile's bootstrap
/// material both exists and owns the named alias.
///
/// Checking the alias against the live bootstrap resolver rather than against a
/// reserved-id set keeps this correct however the resolver is composed: an id
/// that no resolver owns is a permanent configuration error, and catching it here
/// turns it into a startup failure instead of an authentication failure on every
/// request for the life of the process.
fn require_bootstrap_alias(
    index: usize,
    alias: &str,
    bootstrap: Option<&Arc<dyn SecretResolver>>,
) -> Result<(), AzureProviderConfigError> {
    let Some(resolver) = bootstrap else {
        return Err(AzureProviderConfigError::BootstrapResolverRequired { index });
    };
    if !resolver.contains_alias(alias) {
        return Err(AzureProviderConfigError::UnknownBootstrapAlias { index });
    }
    Ok(())
}

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
                if !super::secret::is_valid_file_key(token_file) {
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

fn is_valid_azure_secret_version(value: &str) -> bool {
    value.len() == AZURE_SECRET_VERSION_BYTES
        && value
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'f' | b'0'..=b'9'))
}

fn is_valid_azure_certificate_thumbprint(value: &str) -> bool {
    value.len() == AZURE_CERTIFICATE_THUMBPRINT_HEX_BYTES
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// One bounded provider or identity exchange.
pub(crate) struct AzureHttpResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for AzureHttpResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AzureHttpResponse")
            .field("status", &self.status)
            .field("headers", &"<redacted>")
            .field("body", &"<redacted>")
            .finish()
    }
}

/// Egress-mediated transport for the provider.
///
/// The production implementation is [`EgressAzureTransport`]; tests substitute
/// a hermetic fake so CI never contacts Microsoft Entra or a real Key Vault.
#[async_trait]
pub(crate) trait AzureTransport: Send + Sync {
    /// Opaque generation of the egress configuration behind this transport.
    fn egress_generation(&self) -> [u8; 32];

    async fn send(
        &self,
        method: Method,
        url: &str,
        headers: HeaderMap,
        body: Option<Vec<u8>>,
    ) -> Result<AzureHttpResponse, EgressError>;
}

pub(crate) struct EgressAzureTransport {
    client: Arc<EgressClient>,
}

impl EgressAzureTransport {
    pub(crate) fn new(client: Arc<EgressClient>) -> Self {
        Self { client }
    }
}

impl fmt::Debug for EgressAzureTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EgressAzureTransport")
    }
}

#[async_trait]
impl AzureTransport for EgressAzureTransport {
    fn egress_generation(&self) -> [u8; 32] {
        self.client.configuration_generation()
    }

    async fn send(
        &self,
        method: Method,
        url: &str,
        headers: HeaderMap,
        body: Option<Vec<u8>>,
    ) -> Result<AzureHttpResponse, EgressError> {
        let destination = self.client.checked_destination(url).await?;
        let response = self
            .client
            .sensitive_request_with_headers_at_checked_destination(
                &destination,
                method,
                url,
                headers,
                body,
            )
            .await?;
        Ok(AzureHttpResponse {
            status: response.status,
            headers: response.headers,
            body: response.body,
        })
    }
}

pub(crate) trait AzureClock: Send + Sync {
    fn now(&self) -> Instant;
    fn now_unix(&self) -> u64;
}

struct SystemAzureClock;

impl AzureClock for SystemAzureClock {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn now_unix(&self) -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs())
            .unwrap_or_default()
    }
}

struct AzureProfile {
    id: String,
    token_url: String,
    client_id: String,
    scope: String,
    auth: AzureAuth,
}

enum AzureAuth {
    WorkloadJwt {
        token_root: Arc<Dir>,
        token_file: String,
    },
    ClientSecret {
        secret_alias: String,
    },
    ClientCertificate {
        key_alias: String,
        x5t: String,
        /// The parsed signing key, built exactly once from the bootstrap
        /// alias and held for the provider lifetime so the private key PEM is
        /// not re-resolved and re-decoded on every login. `EncodingKey` keeps
        /// an internal DER copy that is not zeroization-aware; that residual
        /// is accepted until a zeroize-capable RSA path is available.
        ///
        /// Holding it is the *smaller* residual, not just the faster path:
        /// every `EncodingKey::from_rsa_pem` also leaves its intermediate PEM
        /// decode — the DER buffer and the parsed ASN.1 integers of the private
        /// key — unwiped in freed heap, so building per login would scatter a
        /// fresh set of copies on each token acquisition rather than keeping
        /// one. It buys no extra staleness either: `certificate_thumbprint` is
        /// startup configuration, so rotating the certificate already means a
        /// configuration change and a restart, and a key that outlives its
        /// registration is refused by the authority instead of granting
        /// anything. Logins are serialized by `login_lock`, so the slot is
        /// initialised once and never races a second parse into existence.
        key: OnceLock<EncodingKey>,
    },
}

struct AzureAliasBinding {
    id: String,
    label: String,
    profile: String,
    read_url: String,
    vault_origin: Origin,
    name: String,
    version: Option<String>,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct AzureValueCacheKey {
    provider_generation: [u8; 32],
    egress_generation: [u8; 32],
    identity_generation: u64,
    alias_id: String,
    purpose: u8,
    pinned_version: Option<String>,
}

struct CachedAzureValue {
    value: Zeroizing<Vec<u8>>,
    expires_at: Instant,
}

struct CachedAzureToken {
    token: Zeroizing<Vec<u8>>,
    expires_at: Instant,
    generation: u64,
}

#[derive(Default)]
struct AzureIdentityState {
    tokens: BTreeMap<String, CachedAzureToken>,
    generations: BTreeMap<String, u64>,
}

/// One acquired grant credential, held only long enough to build the form
/// body for a single token request.
enum LoginCredential {
    Assertion(Zeroizing<String>),
    Secret(Zeroizing<String>),
}

/// Signed client-credential proof for the `client_certificate` mechanism.
#[derive(Serialize)]
struct ClientAssertionClaims {
    aud: String,
    iss: String,
    sub: String,
    jti: String,
    nbf: u64,
    iat: u64,
    exp: u64,
}

/// Read-only Key Vault Secrets provider.
#[derive(Clone)]
pub struct AzureKeyVaultSecretProvider {
    profiles: Arc<BTreeMap<String, AzureProfile>>,
    aliases: Arc<BTreeMap<String, AzureAliasBinding>>,
    transport: Arc<dyn AzureTransport>,
    bootstrap: Option<Arc<dyn SecretResolver>>,
    identity: Arc<Mutex<AzureIdentityState>>,
    login_lock: Arc<AsyncMutex<()>>,
    values: Arc<Mutex<BTreeMap<AzureValueCacheKey, CachedAzureValue>>>,
    concurrent_reads: Arc<Semaphore>,
    clock: Arc<dyn AzureClock>,
    generation: [u8; 32],
    deadline: Duration,
    value_cache_ttl: Duration,
}

impl fmt::Debug for AzureKeyVaultSecretProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AzureKeyVaultSecretProvider")
            .field("profile_count", &self.profiles.len())
            .field("alias_count", &self.aliases.len())
            .field("bootstrap_provider_enabled", &self.bootstrap.is_some())
            .field(
                "maximum_concurrent_reads",
                &MAX_CONCURRENT_AZURE_RESOLUTIONS,
            )
            .finish()
    }
}

impl AzureKeyVaultSecretProvider {
    /// Builds the provider from trusted startup configuration.
    ///
    /// `bootstrap` must be a resolver that does **not** include this provider,
    /// which together with the configuration cycle check keeps bootstrap
    /// material out of any Key-Vault-served alias.
    pub(crate) fn from_config(
        config: &AzureProviderConfig,
        reserved_alias_ids: &BTreeSet<String>,
        transport: Arc<dyn AzureTransport>,
        bootstrap: Option<Arc<dyn SecretResolver>>,
    ) -> Result<Self, AzureProviderConfigError> {
        validate_azure_provider_config(config, reserved_alias_ids)?;
        let mut profiles = BTreeMap::new();
        for (index, profile) in config.profiles.iter().enumerate() {
            let authority_host = profile
                .authority_host
                .as_deref()
                .unwrap_or(AZURE_PUBLIC_AUTHORITY_HOST);
            let token_url = format!(
                "https://{authority_host}/{tenant}/oauth2/v2.0/token",
                tenant = profile.tenant_id
            );
            let scope = profile
                .scope
                .clone()
                .unwrap_or_else(|| AZURE_PUBLIC_KEY_VAULT_SCOPE.to_owned());
            let auth = match &profile.auth {
                AzureAuthConfig::WorkloadJwt {
                    token_root,
                    token_file,
                } => AzureAuth::WorkloadJwt {
                    token_root: open_workload_token_root(index, token_root)?,
                    token_file: token_file.clone(),
                },
                AzureAuthConfig::ClientSecret { secret_alias } => {
                    require_bootstrap_alias(index, secret_alias, bootstrap.as_ref())?;
                    AzureAuth::ClientSecret {
                        secret_alias: secret_alias.clone(),
                    }
                }
                AzureAuthConfig::ClientCertificate {
                    key_alias,
                    certificate_thumbprint,
                } => {
                    require_bootstrap_alias(index, key_alias, bootstrap.as_ref())?;
                    let thumbprint = hex::decode(certificate_thumbprint).map_err(|_| {
                        AzureProviderConfigError::InvalidCertificateThumbprint { index }
                    })?;
                    AzureAuth::ClientCertificate {
                        key_alias: key_alias.clone(),
                        x5t: BASE64_URL_SAFE_NO_PAD.encode(thumbprint),
                        key: OnceLock::new(),
                    }
                }
            };
            profiles.insert(
                profile.id.clone(),
                AzureProfile {
                    id: profile.id.clone(),
                    token_url,
                    client_id: profile.client_id.clone(),
                    scope,
                    auth,
                },
            );
        }

        let mut aliases = BTreeMap::new();
        for (index, alias) in config.aliases.iter().enumerate() {
            let vault = alias.vault.trim_end_matches('/').to_owned();
            let vault_origin = Url::parse(&vault)
                .map_err(|_| AzureProviderConfigError::InvalidVaultAuthority { index })?
                .origin();
            let mut read_url = format!("{vault}/secrets/{name}", name = alias.name);
            if let Some(version) = alias.version.as_deref() {
                read_url.push('/');
                read_url.push_str(version);
            }
            read_url.push_str("?api-version=");
            read_url.push_str(AZURE_KEY_VAULT_API_VERSION);
            aliases.insert(
                alias.id.clone(),
                AzureAliasBinding {
                    id: alias.id.clone(),
                    label: alias.label.clone(),
                    profile: alias.profile.clone(),
                    read_url,
                    vault_origin,
                    name: alias.name.clone(),
                    version: alias.version.clone(),
                },
            );
        }

        Ok(Self {
            profiles: Arc::new(profiles),
            aliases: Arc::new(aliases),
            transport,
            bootstrap,
            identity: Arc::new(Mutex::new(AzureIdentityState::default())),
            login_lock: Arc::new(AsyncMutex::new(())),
            values: Arc::new(Mutex::new(BTreeMap::new())),
            concurrent_reads: Arc::new(Semaphore::new(MAX_CONCURRENT_AZURE_RESOLUTIONS)),
            clock: Arc::new(SystemAzureClock),
            generation: provider_generation(config),
            deadline: AZURE_RESOLUTION_DEADLINE,
            value_cache_ttl: AZURE_VALUE_CACHE_TTL,
        })
    }

    pub fn alias_ids(&self) -> BTreeSet<String> {
        self.aliases.keys().cloned().collect()
    }

    fn identity_guard(&self) -> MutexGuard<'_, AzureIdentityState> {
        match self.identity.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn value_guard(&self) -> MutexGuard<'_, BTreeMap<AzureValueCacheKey, CachedAzureValue>> {
        match self.values.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn identity_generation(&self, profile_id: &str) -> u64 {
        self.identity_guard()
            .generations
            .get(profile_id)
            .copied()
            .unwrap_or_default()
    }

    fn cache_key(
        &self,
        alias: &AzureAliasBinding,
        purpose: SecretPurpose,
        identity_generation: u64,
    ) -> AzureValueCacheKey {
        AzureValueCacheKey {
            provider_generation: self.generation,
            egress_generation: self.transport.egress_generation(),
            identity_generation,
            alias_id: alias.id.clone(),
            purpose: purpose_code(purpose),
            pinned_version: alias.version.clone(),
        }
    }

    fn cached_value(&self, key: &AzureValueCacheKey) -> Option<Zeroizing<Vec<u8>>> {
        let now = self.clock.now();
        let mut cache = self.value_guard();
        let entry = cache.get(key)?;
        if entry.expires_at <= now {
            cache.remove(key);
            return None;
        }
        Some(entry.value.clone())
    }

    fn store_value(&self, key: AzureValueCacheKey, value: &[u8], ttl: Duration) {
        if ttl.is_zero() {
            return;
        }
        let now = self.clock.now();
        let mut cache = self.value_guard();
        cache.retain(|_, entry| entry.expires_at > now);
        if cache.len() >= MAX_AZURE_VALUE_CACHE_ENTRIES {
            return;
        }
        cache.insert(
            key,
            CachedAzureValue {
                value: Zeroizing::new(value.to_vec()),
                expires_at: now + ttl,
            },
        );
    }

    fn purge_alias(&self, alias_id: &str) {
        self.value_guard().retain(|key, _| key.alias_id != alias_id);
    }

    fn cached_token(
        &self,
        profile_id: &str,
        minimum_generation: u64,
    ) -> Option<(Zeroizing<Vec<u8>>, u64)> {
        let now = self.clock.now();
        let mut identity = self.identity_guard();
        let token = identity.tokens.get(profile_id)?;
        if token.expires_at <= now {
            identity.tokens.remove(profile_id);
            return None;
        }
        if token.generation < minimum_generation {
            return None;
        }
        Some((token.token.clone(), token.generation))
    }

    fn store_token(
        &self,
        profile_id: &str,
        token: Zeroizing<Vec<u8>>,
        lifetime: Option<Duration>,
    ) -> u64 {
        let now = self.clock.now();
        let mut identity = self.identity_guard();
        let generation = identity
            .generations
            .entry(profile_id.to_owned())
            .or_default();
        *generation = generation.saturating_add(1);
        let generation = *generation;
        identity.tokens.remove(profile_id);
        if let Some(lifetime) = lifetime {
            identity.tokens.insert(
                profile_id.to_owned(),
                CachedAzureToken {
                    token,
                    expires_at: now + lifetime,
                    generation,
                },
            );
        }
        generation
    }

    fn invalidate_token(&self, profile_id: &str) {
        self.identity_guard().tokens.remove(profile_id);
    }

    async fn resolve_inner(
        &self,
        alias_id: &str,
        purpose: SecretPurpose,
    ) -> Result<ResolvedSecret, AzureFailure> {
        let alias = self
            .aliases
            .get(alias_id)
            .ok_or(AzureFailure::UnknownAlias)?;
        let profile = self
            .profiles
            .get(&alias.profile)
            .ok_or(AzureFailure::ProviderFailure)?;

        let identity_generation = self.identity_generation(&profile.id);
        let cache_key = self.cache_key(alias, purpose, identity_generation);
        if let Some(cached) = self.cached_value(&cache_key) {
            return ResolvedSecret::new(purpose, cached.to_vec())
                .map_err(|_| AzureFailure::InvalidMaterial);
        }

        let result = self.read_authenticated(alias, profile, purpose).await;
        if result.is_err() {
            self.purge_alias(&alias.id);
        }
        let (fetched, identity_generation) = result?;
        let secret = ResolvedSecret::new(purpose, fetched.value.to_vec())
            .map_err(|_| AzureFailure::InvalidMaterial)?;
        // A secret carrying a Key Vault expiry inside the cache window must
        // stop being served the moment it expires, so the cache lifetime is
        // clamped to the remaining validity instead of the flat TTL.
        let mut cache_ttl = self.value_cache_ttl;
        if let Some(expires_at) = fetched.expires_at_unix {
            let remaining = expires_at.saturating_sub(self.clock.now_unix());
            cache_ttl = cache_ttl.min(Duration::from_secs(remaining));
        }
        self.store_value(
            self.cache_key(alias, purpose, identity_generation),
            secret.expose(),
            cache_ttl,
        );
        Ok(secret)
    }

    async fn read_authenticated(
        &self,
        alias: &AzureAliasBinding,
        profile: &AzureProfile,
        purpose: SecretPurpose,
    ) -> Result<(FetchedSecretValue, u64), AzureFailure> {
        let (token, generation) = self.token(profile, 0).await?;
        match self.read_once(alias, purpose, &token).await {
            Err(AzureFailure::ProviderDenied) => {
                // A rotated, revoked, or expired token is the only condition
                // that earns a second attempt, and only after a fresh
                // client-credentials grant through the same fixed identity
                // source. Challenge headers on the denial are never read.
                let (token, generation) = self.token(profile, generation.saturating_add(1)).await?;
                self.read_once(alias, purpose, &token)
                    .await
                    .map(|value| (value, generation))
            }
            other => other.map(|value| (value, generation)),
        }
    }

    async fn token(
        &self,
        profile: &AzureProfile,
        minimum_generation: u64,
    ) -> Result<(Zeroizing<Vec<u8>>, u64), AzureFailure> {
        if let Some(hit) = self.cached_token(&profile.id, minimum_generation) {
            return Ok(hit);
        }
        let _guard = self.login_lock.lock().await;
        if let Some(hit) = self.cached_token(&profile.id, minimum_generation) {
            return Ok(hit);
        }
        self.invalidate_token(&profile.id);
        self.login(profile).await
    }

    async fn login(
        &self,
        profile: &AzureProfile,
    ) -> Result<(Zeroizing<Vec<u8>>, u64), AzureFailure> {
        // The grant credential is acquired before the form is assembled: the
        // form serializer is a purely synchronous, non-`Send` builder and must
        // never be held across an await point.
        let credential = match &profile.auth {
            AzureAuth::WorkloadJwt {
                token_root,
                token_file,
            } => {
                let jwt = self.workload_identity_token(token_root, token_file).await?;
                std::str::from_utf8(jwt.expose())
                    .map(|jwt| LoginCredential::Assertion(Zeroizing::new(jwt.to_owned())))
                    .map_err(|_| AzureFailure::IdentityInvalid)?
            }
            AzureAuth::ClientSecret { secret_alias } => {
                let secret = self
                    .bootstrap_material(
                        secret_alias,
                        SecretPurpose::StaticBearer,
                        MAX_AZURE_CLIENT_SECRET_BYTES,
                    )
                    .await?;
                std::str::from_utf8(&secret)
                    .map(|secret| LoginCredential::Secret(Zeroizing::new(secret.to_owned())))
                    .map_err(|_| AzureFailure::IdentityInvalid)?
            }
            AzureAuth::ClientCertificate {
                key_alias,
                x5t,
                key,
            } => {
                let assertion = self
                    .client_certificate_assertion(profile, key_alias, x5t, key)
                    .await?;
                LoginCredential::Assertion(Zeroizing::new(assertion))
            }
        };
        let body = {
            let mut form = url::form_urlencoded::Serializer::new(String::new());
            form.append_pair("client_id", &profile.client_id);
            form.append_pair("grant_type", "client_credentials");
            form.append_pair("scope", &profile.scope);
            match &credential {
                LoginCredential::Assertion(assertion) => {
                    form.append_pair(
                        "client_assertion_type",
                        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                    );
                    form.append_pair("client_assertion", assertion);
                }
                LoginCredential::Secret(secret) => {
                    form.append_pair("client_secret", secret);
                }
            }
            Zeroizing::new(form.finish().into_bytes())
        };

        let response = self
            .send_with_bounded_retries(
                Method::POST,
                &profile.token_url,
                Ok(identity_request_headers()),
                Some(body.to_vec()),
                true,
            )
            .await?;
        let body = bounded_json_body(&response, MAX_AZURE_TOKEN_RESPONSE_BYTES)?;
        let mut grant: AzureTokenResponse =
            serde_json::from_slice(body).map_err(|_| AzureFailure::IdentityInvalid)?;
        let lifetime = grant.lifetime_or_reject()?;
        let token = grant.take_token()?;
        let cache_lifetime = lifetime
            .checked_sub(AZURE_TOKEN_REFRESH_SKEW)
            .filter(|lifetime| !lifetime.is_zero());
        let generation = self.store_token(&profile.id, token.clone(), cache_lifetime);
        Ok((token, generation))
    }

    async fn client_certificate_assertion(
        &self,
        profile: &AzureProfile,
        key_alias: &str,
        x5t: &str,
        key_slot: &OnceLock<EncodingKey>,
    ) -> Result<String, AzureFailure> {
        // The signing key is built exactly once per provider lifetime; later
        // logins reuse it instead of re-resolving and re-decoding the PEM. A
        // rotated bootstrap key therefore takes effect on restart, matching
        // every other startup-fixed identity input.
        let key = match key_slot.get() {
            Some(key) => key,
            None => {
                let key_material = self
                    .bootstrap_material(
                        key_alias,
                        SecretPurpose::TlsPrivateKey,
                        MAX_TLS_PRIVATE_KEY_BYTES,
                    )
                    .await?;
                let key = EncodingKey::from_rsa_pem(&key_material)
                    .map_err(|_| AzureFailure::IdentityInvalid)?;
                key_slot.get_or_init(|| key)
            }
        };
        let now = self.clock.now_unix();
        let claims = ClientAssertionClaims {
            aud: profile.token_url.clone(),
            iss: profile.client_id.clone(),
            sub: profile.client_id.clone(),
            jti: uuid::Uuid::new_v4().to_string(),
            nbf: now,
            iat: now,
            exp: now.saturating_add(AZURE_CLIENT_ASSERTION_LIFETIME_SECS),
        };
        let mut header = JwtHeader::new(Algorithm::RS256);
        header.x5t = Some(x5t.to_owned());
        encode_client_assertion(&header, &claims, key).map_err(|_| AzureFailure::IdentityInvalid)
    }

    async fn bootstrap_material(
        &self,
        alias: &str,
        purpose: SecretPurpose,
        maximum: usize,
    ) -> Result<Zeroizing<Vec<u8>>, AzureFailure> {
        let bootstrap = self
            .bootstrap
            .as_ref()
            .ok_or(AzureFailure::ProviderFailure)?;
        let secret =
            bootstrap
                .resolve(alias, purpose)
                .await
                .map_err(|error| match error.kind() {
                    SecretResolveErrorKind::SourceDenied | SecretResolveErrorKind::UnsafeSource => {
                        AzureFailure::IdentityDenied
                    }
                    SecretResolveErrorKind::InvalidMaterial => AzureFailure::IdentityInvalid,
                    _ => AzureFailure::IdentityUnavailable,
                })?;
        if secret.expose().len() > maximum {
            return Err(AzureFailure::IdentityInvalid);
        }
        Ok(Zeroizing::new(secret.expose().to_vec()))
    }

    async fn workload_identity_token(
        &self,
        token_root: &Arc<Dir>,
        token_file: &str,
    ) -> Result<ResolvedSecret, AzureFailure> {
        let root = Arc::clone(token_root);
        let key = token_file.to_owned();
        tokio::task::spawn_blocking(move || {
            read_bounded_file_secret(
                "azure-workload-identity",
                &root,
                &key,
                SecretPurpose::StaticBearer,
                FileSecretPermissions::PlatformProjected,
            )
        })
        .await
        .map_err(|_| AzureFailure::ProviderFailure)?
        .map_err(|error| match error.kind() {
            SecretResolveErrorKind::SourceDenied | SecretResolveErrorKind::UnsafeSource => {
                AzureFailure::IdentityDenied
            }
            SecretResolveErrorKind::InvalidMaterial => AzureFailure::IdentityInvalid,
            _ => AzureFailure::IdentityUnavailable,
        })
    }

    async fn read_once(
        &self,
        alias: &AzureAliasBinding,
        purpose: SecretPurpose,
        token: &[u8],
    ) -> Result<FetchedSecretValue, AzureFailure> {
        let headers = data_request_headers(token);
        let response = self
            .send_with_bounded_retries(Method::GET, &alias.read_url, headers, None, false)
            .await?;
        let body = bounded_json_body(&response, MAX_AZURE_READ_RESPONSE_BYTES)?;
        let read: AzureSecretGetResponse =
            serde_json::from_slice(body).map_err(|_| AzureFailure::InvalidResponse)?;
        read.into_value(alias, purpose, self.clock.now_unix())
    }

    async fn send_with_bounded_retries(
        &self,
        method: Method,
        url: &str,
        headers: Result<HeaderMap, AzureFailure>,
        body: Option<Vec<u8>>,
        identity: bool,
    ) -> Result<AzureHttpResponse, AzureFailure> {
        let headers = headers?;
        let mut attempt = 0;
        loop {
            let response = self
                .transport
                .send(method.clone(), url, headers.clone(), body.clone())
                .await;
            let failure = match response {
                Ok(response) => match classify_status(response.status, identity) {
                    None => return Ok(response),
                    Some(failure) => failure,
                },
                Err(error) => map_egress_error(&error, identity),
            };
            if attempt >= MAX_AZURE_TRANSIENT_RETRIES || !failure.is_transient() {
                return Err(failure);
            }
            attempt = attempt.saturating_add(1);
            tokio::time::sleep(AZURE_RETRY_BACKOFF).await;
        }
    }
}

#[async_trait]
impl SecretResolver for AzureKeyVaultSecretProvider {
    async fn resolve(
        &self,
        alias_id: &str,
        purpose: SecretPurpose,
    ) -> Result<ResolvedSecret, SecretResolveError> {
        let alias_id = safe_error_alias_id(alias_id);
        let started = Instant::now();
        let permit = Arc::clone(&self.concurrent_reads)
            .try_acquire_owned()
            .map_err(|_| AzureFailure::ProviderBusy);
        let outcome = match permit {
            Ok(permit) => {
                let _permit = permit;
                match tokio::time::timeout(self.deadline, self.resolve_inner(&alias_id, purpose))
                    .await
                {
                    Ok(result) => result,
                    Err(_) => {
                        self.purge_alias(&alias_id);
                        Err(AzureFailure::DeadlineExceeded)
                    }
                }
            }
            Err(failure) => Err(failure),
        };
        record_resolution(&outcome, started.elapsed());
        outcome.map_err(|failure| SecretResolveError::new(&alias_id, failure.kind()))
    }

    fn contains_alias(&self, alias_id: &str) -> bool {
        self.aliases.contains_key(alias_id)
    }

    fn aliases(&self) -> Vec<SecretAliasMetadata> {
        self.aliases
            .values()
            .map(|alias| SecretAliasMetadata {
                id: alias.id.clone(),
                label: alias.label.clone(),
                provider: SecretProviderKind::AzureKeyVault,
                configured: true,
                purpose: None,
                pinned: alias.version.is_some(),
                // Key Vault versions are opaque fragments of the redacted read
                // URL, never surfaced through metadata; pinnedness is reported
                // as the dedicated boolean instead.
                version: None,
                rotated_at: None,
            })
            .collect()
    }

    fn generation_digest(&self, alias_id: &str) -> Option<String> {
        let version = self.aliases.get(alias_id)?.version.as_deref()?;
        Some(configured_secret_generation_digest(
            SecretProviderKind::AzureKeyVault,
            alias_id,
            &self.generation,
            version.as_bytes(),
        ))
    }
}

fn record_resolution(outcome: &Result<ResolvedSecret, AzureFailure>, elapsed: Duration) {
    let (result, reason) = match outcome {
        Ok(_) => ("success", "resolved"),
        Err(failure) => ("failure", failure.safe_reason()),
    };
    ::metrics::counter!(
        "connection_secret_provider_read_total",
        "provider" => AZURE_PROVIDER_LABEL,
        "result" => result,
        "reason" => reason
    )
    .increment(1);
    ::metrics::histogram!(
        "connection_secret_provider_read_duration_seconds",
        "provider" => AZURE_PROVIDER_LABEL,
        "result" => result
    )
    .record(elapsed.as_secs_f64());
    if let Err(failure) = outcome {
        tracing::warn!(
            provider = AZURE_PROVIDER_LABEL,
            reason = failure.safe_reason(),
            "connection secret provider read failed closed"
        );
    }
}

fn open_workload_token_root(
    index: usize,
    path: &str,
) -> Result<Arc<Dir>, AzureProviderConfigError> {
    let canonical = fs::canonicalize(PathBuf::from(path))
        .map_err(|_| AzureProviderConfigError::WorkloadTokenRootUnavailable { index })?;
    let directory = Dir::open_ambient_dir(&canonical, ambient_authority())
        .map_err(|_| AzureProviderConfigError::WorkloadTokenRootUnavailable { index })?;
    let metadata = directory
        .try_clone()
        .and_then(|directory| directory.into_std_file().metadata())
        .map_err(|_| AzureProviderConfigError::WorkloadTokenRootUnavailable { index })?;
    if !metadata.is_dir() {
        return Err(AzureProviderConfigError::WorkloadTokenRootUnavailable { index });
    }
    validate_token_root_permissions(index, &metadata)?;
    Ok(Arc::new(directory))
}

#[cfg(unix)]
fn validate_token_root_permissions(
    index: usize,
    metadata: &fs::Metadata,
) -> Result<(), AzureProviderConfigError> {
    if crate::connections::secret::projected_root_permissions_are_safe(metadata) {
        Ok(())
    } else {
        Err(AzureProviderConfigError::WorkloadTokenRootPermissions { index })
    }
}

#[cfg(not(unix))]
fn validate_token_root_permissions(
    _: usize,
    _: &fs::Metadata,
) -> Result<(), AzureProviderConfigError> {
    Ok(())
}

pub(crate) fn provider_generation(config: &AzureProviderConfig) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"azure-key-vault-provider-v1");
    for profile in &config.profiles {
        for field in [
            profile.id.as_str(),
            profile.authority_host.as_deref().unwrap_or_default(),
            profile.tenant_id.as_str(),
            profile.client_id.as_str(),
            profile.scope.as_deref().unwrap_or_default(),
        ] {
            digest.update(field.as_bytes());
            digest.update([0]);
        }
        match &profile.auth {
            AzureAuthConfig::WorkloadJwt {
                token_root,
                token_file,
            } => {
                digest.update(b"workload_jwt");
                for field in [token_root, token_file] {
                    digest.update(field.as_bytes());
                    digest.update([0]);
                }
            }
            AzureAuthConfig::ClientSecret { secret_alias } => {
                digest.update(b"client_secret");
                digest.update(secret_alias.as_bytes());
                digest.update([0]);
            }
            AzureAuthConfig::ClientCertificate {
                key_alias,
                certificate_thumbprint,
            } => {
                digest.update(b"client_certificate");
                for field in [key_alias, certificate_thumbprint] {
                    digest.update(field.as_bytes());
                    digest.update([0]);
                }
            }
        }
    }
    for alias in &config.aliases {
        for field in [
            alias.id.as_str(),
            alias.label.as_str(),
            alias.profile.as_str(),
            alias.vault.as_str(),
            alias.name.as_str(),
            alias.version.as_deref().unwrap_or_default(),
        ] {
            digest.update(field.as_bytes());
            digest.update([0]);
        }
    }
    digest.finalize().into()
}

const fn purpose_code(purpose: SecretPurpose) -> u8 {
    match purpose {
        SecretPurpose::HeaderApiKey => 1,
        SecretPurpose::StaticBearer => 2,
        SecretPurpose::OAuthClientSecret => 3,
        SecretPurpose::TlsPrivateKey => 4,
        SecretPurpose::TlsCertificate => 5,
        SecretPurpose::TlsCaBundle => 6,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AzureFailure {
    UnknownAlias,
    ProviderBusy,
    DeadlineExceeded,
    EgressDenied,
    RedirectRefused,
    IdentityUnavailable,
    IdentityDenied,
    IdentityInvalid,
    ProviderUnavailable,
    ProviderDenied,
    SecretAbsent,
    SecretDisabled,
    SecretNotYetValid,
    SecretExpired,
    InvalidResponse,
    InvalidMaterial,
    ProviderFailure,
}

impl AzureFailure {
    const fn safe_reason(self) -> &'static str {
        match self {
            Self::UnknownAlias => "unknown_alias",
            Self::ProviderBusy => "provider_busy",
            Self::DeadlineExceeded => "deadline_exceeded",
            Self::EgressDenied => "egress_denied",
            Self::RedirectRefused => "redirect_refused",
            Self::IdentityUnavailable => "identity_unavailable",
            Self::IdentityDenied => "identity_denied",
            Self::IdentityInvalid => "identity_invalid",
            Self::ProviderUnavailable => "provider_unavailable",
            Self::ProviderDenied => "provider_denied",
            Self::SecretAbsent => "secret_absent",
            Self::SecretDisabled => "secret_disabled",
            Self::SecretNotYetValid => "secret_not_yet_valid",
            Self::SecretExpired => "secret_expired",
            Self::InvalidResponse => "invalid_response",
            Self::InvalidMaterial => "invalid_material",
            Self::ProviderFailure => "provider_failure",
        }
    }

    const fn kind(self) -> SecretResolveErrorKind {
        match self {
            Self::UnknownAlias => SecretResolveErrorKind::UnknownAlias,
            Self::ProviderBusy => SecretResolveErrorKind::ProviderBusy,
            Self::DeadlineExceeded
            | Self::IdentityUnavailable
            | Self::ProviderUnavailable
            | Self::SecretAbsent => SecretResolveErrorKind::SourceUnavailable,
            Self::IdentityDenied
            | Self::ProviderDenied
            | Self::SecretDisabled
            | Self::SecretNotYetValid
            | Self::SecretExpired => SecretResolveErrorKind::SourceDenied,
            Self::EgressDenied | Self::RedirectRefused => SecretResolveErrorKind::UnsafeSource,
            Self::IdentityInvalid | Self::InvalidResponse | Self::InvalidMaterial => {
                SecretResolveErrorKind::InvalidMaterial
            }
            Self::ProviderFailure => SecretResolveErrorKind::ProviderFailure,
        }
    }

    const fn is_transient(self) -> bool {
        matches!(self, Self::ProviderUnavailable | Self::IdentityUnavailable)
    }
}

fn map_egress_error(error: &EgressError, identity: bool) -> AzureFailure {
    match error {
        EgressError::HostNotAllowed(_)
        | EgressError::PortNotAllowed(_)
        | EgressError::NonGlobalIpBlocked(_)
        | EgressError::SchemeNotAllowed(_)
        | EgressError::InvalidPolicy(_)
        | EgressError::InvalidUrl(_)
        | EgressError::InvalidTlsCaBundle { .. }
        | EgressError::InvalidTlsClientIdentity => AzureFailure::EgressDenied,
        EgressError::ResponseTooLarge { .. } => AzureFailure::InvalidResponse,
        EgressError::RequestBodyTooLarge { .. } | EgressError::RequestBodyReadFailed => {
            AzureFailure::IdentityInvalid
        }
        _ if identity => AzureFailure::IdentityUnavailable,
        _ => AzureFailure::ProviderUnavailable,
    }
}

fn classify_status(status: StatusCode, identity: bool) -> Option<AzureFailure> {
    if status == StatusCode::OK {
        return None;
    }
    if status.is_redirection() {
        return Some(AzureFailure::RedirectRefused);
    }
    Some(match status.as_u16() {
        400 | 401 | 403 if identity => AzureFailure::IdentityDenied,
        // The 401 challenge from Key Vault is only a denial here; its
        // `WWW-Authenticate` parameters are never parsed and never redirect
        // identity or data traffic anywhere.
        400 | 401 | 403 => AzureFailure::ProviderDenied,
        404 if identity => AzureFailure::IdentityUnavailable,
        404 => AzureFailure::SecretAbsent,
        408 | 429 | 500..=599 if identity => AzureFailure::IdentityUnavailable,
        408 | 429 | 500..=599 => AzureFailure::ProviderUnavailable,
        _ if identity => AzureFailure::IdentityInvalid,
        _ => AzureFailure::InvalidResponse,
    })
}

fn identity_request_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/x-www-form-urlencoded"),
    );
    headers
}

fn data_request_headers(token: &[u8]) -> Result<HeaderMap, AzureFailure> {
    let mut headers = HeaderMap::new();
    headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
    // The intermediate credential buffer is zeroized on drop; the resulting
    // header value is marked sensitive so it is excluded from debug output.
    let mut bearer = Zeroizing::new(Vec::with_capacity("Bearer ".len() + token.len()));
    bearer.extend_from_slice(b"Bearer ");
    bearer.extend_from_slice(token);
    let mut value = HeaderValue::from_bytes(&bearer).map_err(|_| AzureFailure::IdentityInvalid)?;
    value.set_sensitive(true);
    headers.insert(AUTHORIZATION, value);
    Ok(headers)
}

fn bounded_json_body(response: &AzureHttpResponse, maximum: usize) -> Result<&[u8], AzureFailure> {
    if !is_json_content_type(response.headers.get(CONTENT_TYPE)) {
        return Err(AzureFailure::InvalidResponse);
    }
    if response.body.len() > maximum || response.body.is_empty() {
        return Err(AzureFailure::InvalidResponse);
    }
    Ok(response.body.as_slice())
}

fn is_json_content_type(value: Option<&HeaderValue>) -> bool {
    value
        .and_then(|value| value.to_str().ok())
        .map(|value| value.split(';').next().unwrap_or_default().trim())
        .is_some_and(|value| value.eq_ignore_ascii_case("application/json"))
}

struct SecretText(Zeroizing<String>);

impl<'de> Deserialize<'de> for SecretText {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(|value| Self(Zeroizing::new(value)))
    }
}

impl SecretText {
    fn take_bytes(&mut self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(std::mem::take(&mut *self.0).into_bytes())
    }
}

#[derive(Deserialize)]
struct AzureTokenResponse {
    token_type: String,
    expires_in: u64,
    access_token: SecretText,
}

impl AzureTokenResponse {
    /// Rejects a non-expiring or non-bearer identity outright: this provider
    /// only accepts short-lived bearer tokens, so a `0` lifetime or an
    /// unexpected token type is invalid rather than an unbounded grant.
    fn lifetime_or_reject(&self) -> Result<Duration, AzureFailure> {
        if !self.token_type.eq_ignore_ascii_case("bearer") {
            return Err(AzureFailure::IdentityInvalid);
        }
        if self.expires_in == 0 {
            return Err(AzureFailure::IdentityInvalid);
        }
        Ok(Duration::from_secs(self.expires_in).min(MAX_AZURE_TOKEN_LIFETIME))
    }

    fn take_token(&mut self) -> Result<Zeroizing<Vec<u8>>, AzureFailure> {
        let token = self.access_token.take_bytes();
        if token.is_empty() || token.len() > MAX_AZURE_ACCESS_TOKEN_BYTES {
            return Err(AzureFailure::IdentityInvalid);
        }
        if token.iter().any(|byte| *byte < 0x21 || *byte > 0x7e) {
            return Err(AzureFailure::IdentityInvalid);
        }
        Ok(token)
    }
}

#[derive(Deserialize)]
struct AzureSecretGetResponse {
    #[serde(default)]
    value: Option<SecretText>,
    id: String,
    attributes: AzureSecretAttributes,
}

#[derive(Deserialize)]
struct AzureSecretAttributes {
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    nbf: Option<u64>,
    #[serde(default)]
    exp: Option<u64>,
}

/// One validated data-plane value plus the temporal bound that must also cap
/// how long the value may be cached.
struct FetchedSecretValue {
    value: Zeroizing<Vec<u8>>,
    expires_at_unix: Option<u64>,
}

impl AzureSecretGetResponse {
    fn into_value(
        mut self,
        alias: &AzureAliasBinding,
        purpose: SecretPurpose,
        now_unix: u64,
    ) -> Result<FetchedSecretValue, AzureFailure> {
        validate_secret_identity(&self.id, alias)?;
        // A secret without `enabled: true` is treated as disabled rather than
        // usable-by-default, and the temporal window is enforced with the
        // gateway clock instead of trusting the provider to withhold values.
        if self.attributes.enabled != Some(true) {
            return Err(AzureFailure::SecretDisabled);
        }
        if self
            .attributes
            .nbf
            .is_some_and(|not_before| now_unix < not_before)
        {
            return Err(AzureFailure::SecretNotYetValid);
        }
        if self
            .attributes
            .exp
            .is_some_and(|expires| now_unix >= expires)
        {
            return Err(AzureFailure::SecretExpired);
        }
        let mut value = self.value.take().ok_or(AzureFailure::SecretAbsent)?;
        let bytes = value.take_bytes();
        if bytes.is_empty() || bytes.len() > purpose.max_bytes() || bytes.contains(&0) {
            return Err(AzureFailure::InvalidMaterial);
        }
        Ok(FetchedSecretValue {
            value: bytes,
            expires_at_unix: self.attributes.exp,
        })
    }
}

/// Requires the response `id` to name exactly the configured vault authority,
/// secret name, and (when pinned) version. Anything else — another vault,
/// another secret, an unexpected path shape, or a different version under a
/// pin — fails closed instead of being trusted.
fn validate_secret_identity(id: &str, alias: &AzureAliasBinding) -> Result<(), AzureFailure> {
    let url = Url::parse(id).map_err(|_| AzureFailure::InvalidResponse)?;
    if url.scheme() != "https"
        || url.origin() != alias.vault_origin
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(AzureFailure::InvalidResponse);
    }
    let segments = url
        .path_segments()
        .map(|segments| segments.collect::<Vec<_>>())
        .unwrap_or_default();
    let [collection, name, version] = segments.as_slice() else {
        return Err(AzureFailure::InvalidResponse);
    };
    if *collection != "secrets" || *name != alias.name || !is_valid_azure_secret_version(version) {
        return Err(AzureFailure::InvalidResponse);
    }
    if alias
        .version
        .as_deref()
        .is_some_and(|pinned| pinned != *version)
    {
        return Err(AzureFailure::InvalidResponse);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;

    const VALUE_CANARY: &str = "greengateway-azure-value-canary";
    const TOKEN_CANARY: &str = "eyJ.greengateway-azure-token-canary";
    const AUTHORITY_CANARY: &str = "login.authority-locator-canary.example";
    const TENANT_CANARY: &str = "11111111-2222-3333-4444-555566667777";
    const CLIENT_CANARY: &str = "88888888-9999-aaaa-bbbb-ccccddddeeee";
    const SCOPE_CANARY: &str = "https://vault.scope-locator-canary.example/.default";
    const VAULT_CANARY: &str = "https://vault-locator-canary.vault.example";
    const NAME_CANARY: &str = "secret-name-locator-canary";
    const VERSION_CANARY: &str = "0123456789abcdef0123456789abcdef";
    const OTHER_VERSION: &str = "fedcba9876543210fedcba9876543210";
    const CLIENT_SECRET_CANARY: &str = "client-secret-bootstrap-canary";
    const START_UNIX: u64 = 1_700_000_000;

    fn token_url() -> String {
        format!("https://{AUTHORITY_CANARY}/{TENANT_CANARY}/oauth2/v2.0/token")
    }

    type Responder = dyn Fn() -> Result<AzureHttpResponse, EgressError> + Send + Sync;

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct RecordedRequest {
        method: String,
        url: String,
        authorization: Option<String>,
        content_type: Option<String>,
        body: Option<String>,
    }

    /// Scripted responses for one request channel.
    ///
    /// Queued responders are consumed in order; once the queue is empty the
    /// last consumed responder repeats, which keeps steady-state tests short
    /// while leaving a re-queued response unambiguous.
    #[derive(Default)]
    struct FakeChannel {
        queued: VecDeque<Arc<Responder>>,
        last: Option<Arc<Responder>>,
    }

    impl FakeChannel {
        fn next(&mut self) -> Option<Arc<Responder>> {
            if let Some(responder) = self.queued.pop_front() {
                self.last = Some(Arc::clone(&responder));
                return Some(responder);
            }
            self.last.clone()
        }
    }

    struct FakeAzure {
        requests: Mutex<Vec<RecordedRequest>>,
        logins: Mutex<FakeChannel>,
        reads: Mutex<FakeChannel>,
        generation: AtomicU64,
        delay: Mutex<Duration>,
    }

    impl FakeAzure {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                requests: Mutex::new(Vec::new()),
                logins: Mutex::new(FakeChannel::default()),
                reads: Mutex::new(FakeChannel::default()),
                generation: AtomicU64::new(0),
                delay: Mutex::new(Duration::ZERO),
            })
        }

        fn push_login(&self, responder: Arc<Responder>) {
            self.logins
                .lock()
                .expect("fake login queue should lock")
                .queued
                .push_back(responder);
        }

        fn push_read(&self, responder: Arc<Responder>) {
            self.reads
                .lock()
                .expect("fake read queue should lock")
                .queued
                .push_back(responder);
        }

        fn requests(&self) -> Vec<RecordedRequest> {
            self.requests
                .lock()
                .expect("fake request log should lock")
                .clone()
        }

        fn reads(&self) -> Vec<RecordedRequest> {
            self.requests()
                .into_iter()
                .filter(|request| !request.url.contains("/oauth2/"))
                .collect()
        }

        fn logins(&self) -> Vec<RecordedRequest> {
            self.requests()
                .into_iter()
                .filter(|request| request.url.contains("/oauth2/"))
                .collect()
        }

        fn set_delay(&self, delay: Duration) {
            *self.delay.lock().expect("fake delay should lock") = delay;
        }

        fn next(channel: &Mutex<FakeChannel>) -> Option<Arc<Responder>> {
            channel.lock().expect("fake queue should lock").next()
        }
    }

    #[async_trait]
    impl AzureTransport for FakeAzure {
        fn egress_generation(&self) -> [u8; 32] {
            let generation = self.generation.load(Ordering::SeqCst);
            let mut bytes = [0_u8; 32];
            bytes[..8].copy_from_slice(&generation.to_be_bytes());
            bytes
        }

        async fn send(
            &self,
            method: Method,
            url: &str,
            headers: HeaderMap,
            body: Option<Vec<u8>>,
        ) -> Result<AzureHttpResponse, EgressError> {
            let header_text = |name: http::HeaderName| {
                headers
                    .get(name)
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned)
            };
            self.requests
                .lock()
                .expect("fake request log should lock")
                .push(RecordedRequest {
                    method: method.to_string(),
                    url: url.to_owned(),
                    authorization: header_text(AUTHORIZATION),
                    content_type: header_text(CONTENT_TYPE),
                    body: body.map(|body| String::from_utf8_lossy(&body).into_owned()),
                });
            let delay = *self.delay.lock().expect("fake delay should lock");
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            let queue = if url.contains("/oauth2/") {
                &self.logins
            } else {
                &self.reads
            };
            match Self::next(queue) {
                Some(responder) => responder(),
                None => Err(EgressError::DnsResolutionFailed("fake".to_owned())),
            }
        }
    }

    fn response(status: u16, content_type: &'static str, body: &str) -> Arc<Responder> {
        let body = body.to_owned();
        Arc::new(move || {
            let mut headers = HeaderMap::new();
            headers.insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
            Ok(AzureHttpResponse {
                status: StatusCode::from_u16(status).expect("test status should be valid"),
                headers,
                body: Zeroizing::new(body.clone().into_bytes()),
            })
        })
    }

    fn json_response(status: u16, body: &str) -> Arc<Responder> {
        response(status, "application/json", body)
    }

    fn challenge_response(status: u16, challenge: &'static str, body: &str) -> Arc<Responder> {
        let body = body.to_owned();
        Arc::new(move || {
            let mut headers = HeaderMap::new();
            headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            headers.insert(
                http::header::WWW_AUTHENTICATE,
                HeaderValue::from_static(challenge),
            );
            Ok(AzureHttpResponse {
                status: StatusCode::from_u16(status).expect("test status should be valid"),
                headers,
                body: Zeroizing::new(body.clone().into_bytes()),
            })
        })
    }

    fn egress_failure(build: impl Fn() -> EgressError + Send + Sync + 'static) -> Arc<Responder> {
        Arc::new(move || Err(build()))
    }

    fn token_body(token: &str, expires_in: u64) -> String {
        format!(
            r#"{{"token_type":"Bearer","expires_in":{expires_in},"ext_expires_in":{expires_in},"access_token":"{token}"}}"#
        )
    }

    fn read_body(value: &str, version: &str) -> String {
        read_body_at(VAULT_CANARY, NAME_CANARY, value, version)
    }

    fn read_body_at(vault: &str, name: &str, value: &str, version: &str) -> String {
        format!(
            r#"{{"value":"{value}","id":"{vault}/secrets/{name}/{version}","attributes":{{"enabled":true,"created":1493938410,"updated":1493938410,"recoveryLevel":"Recoverable+Purgeable"}},"tags":{{}}}}"#
        )
    }

    fn read_body_with_attributes(value: &str, version: &str, attributes: &str) -> String {
        format!(
            r#"{{"value":"{value}","id":"{VAULT_CANARY}/secrets/{NAME_CANARY}/{version}","attributes":{attributes}}}"#
        )
    }

    struct TestClock {
        now: Mutex<Instant>,
        unix: AtomicU64,
    }

    impl TestClock {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                now: Mutex::new(Instant::now()),
                unix: AtomicU64::new(START_UNIX),
            })
        }

        fn advance(&self, step: Duration) {
            let mut now = self.now.lock().expect("test clock should lock");
            *now += step;
            self.unix.fetch_add(step.as_secs(), Ordering::SeqCst);
        }
    }

    impl AzureClock for TestClock {
        fn now(&self) -> Instant {
            *self.now.lock().expect("test clock should lock")
        }

        fn now_unix(&self) -> u64 {
            self.unix.load(Ordering::SeqCst)
        }
    }

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

    fn workload_profile(id: &str, token_root: &str) -> AzureProfileConfig {
        AzureProfileConfig {
            id: id.to_owned(),
            authority_host: Some(AUTHORITY_CANARY.to_owned()),
            tenant_id: TENANT_CANARY.to_owned(),
            client_id: CLIENT_CANARY.to_owned(),
            scope: Some(SCOPE_CANARY.to_owned()),
            auth: AzureAuthConfig::WorkloadJwt {
                token_root: token_root.to_owned(),
                token_file: "token".to_owned(),
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

    struct FakeBootstrap {
        value: Vec<u8>,
    }

    #[async_trait]
    impl SecretResolver for FakeBootstrap {
        async fn resolve(
            &self,
            alias_id: &str,
            purpose: SecretPurpose,
        ) -> Result<ResolvedSecret, SecretResolveError> {
            ResolvedSecret::new(purpose, self.value.clone()).map_err(|_| {
                SecretResolveError::new(alias_id, SecretResolveErrorKind::InvalidMaterial)
            })
        }

        // This fake answers for any alias, so contains_alias must say so too.
        // A resolver whose contains_alias disagrees with its resolve is not a
        // resolver the production seam can be tested against.
        fn contains_alias(&self, _: &str) -> bool {
            true
        }

        fn aliases(&self) -> Vec<SecretAliasMetadata> {
            Vec::new()
        }
    }

    struct ProviderFixture {
        provider: AzureKeyVaultSecretProvider,
        azure: Arc<FakeAzure>,
        clock: Arc<TestClock>,
    }

    fn provider(aliases: Vec<AzureSecretAliasConfig>) -> ProviderFixture {
        provider_with_bootstrap(
            AzureProviderConfig {
                profiles: vec![client_secret_profile("primary")],
                aliases,
            },
            Some(Arc::new(FakeBootstrap {
                value: CLIENT_SECRET_CANARY.as_bytes().to_vec(),
            })),
        )
    }

    fn provider_with_bootstrap(
        config: AzureProviderConfig,
        bootstrap: Option<Arc<dyn SecretResolver>>,
    ) -> ProviderFixture {
        let azure = FakeAzure::new();
        let clock = TestClock::new();
        let mut provider = AzureKeyVaultSecretProvider::from_config(
            &config,
            &BTreeSet::new(),
            Arc::clone(&azure) as Arc<dyn AzureTransport>,
            bootstrap,
        )
        .expect("test provider should build");
        provider.clock = Arc::clone(&clock) as Arc<dyn AzureClock>;
        ProviderFixture {
            provider,
            azure,
            clock,
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

    /// Both of these are decisions rather than accidents, so both should cost a
    /// deliberate edit here: the data-plane version pin (see the constant) and
    /// the absence of any ambient-credential auth shape (see `AzureAuthConfig`).
    #[test]
    fn the_api_version_pin_and_the_absent_ambient_auth_shapes_stay_deliberate() {
        assert_eq!(
            AZURE_KEY_VAULT_API_VERSION, "7.5",
            "the data-plane version pin is a decision; read the constant's comment before moving it"
        );
        for shape in [
            r#"{"type":"managed_identity"}"#,
            r#"{"type":"imds"}"#,
            r#"{"type":"default_azure_credential"}"#,
            r#"{"type":"azure_cli"}"#,
        ] {
            let error = match serde_json::from_str::<AzureAuthConfig>(shape) {
                Ok(parsed) => panic!("{shape} must not be representable, parsed as {parsed:?}"),
                Err(error) => error.to_string(),
            };
            assert!(
                error.contains("unknown variant"),
                "{shape} must be refused as an unknown auth variant, got {error}"
            );
        }
    }

    #[test]
    fn bootstrap_auth_without_a_bootstrap_resolver_is_rejected_at_startup() {
        for profile in [
            client_secret_profile("primary"),
            certificate_profile("primary"),
        ] {
            let error = AzureKeyVaultSecretProvider::from_config(
                &AzureProviderConfig {
                    profiles: vec![profile],
                    aliases: vec![alias("billing", None)],
                },
                &BTreeSet::new(),
                FakeAzure::new() as Arc<dyn AzureTransport>,
                None,
            )
            .expect_err("bootstrap auth without a resolver must fail at startup");
            assert!(matches!(
                error,
                AzureProviderConfigError::BootstrapResolverRequired { .. }
            ));
        }
    }

    #[tokio::test]
    async fn unknown_alias_denial_produces_zero_provider_work() {
        let fixture = provider(vec![alias("billing", None)]);
        fixture
            .azure
            .push_login(json_response(200, &token_body(TOKEN_CANARY, 600)));
        fixture
            .azure
            .push_read(json_response(200, &read_body(VALUE_CANARY, VERSION_CANARY)));

        let error = fixture
            .provider
            .resolve("not-configured", SecretPurpose::StaticBearer)
            .await
            .expect_err("unknown alias must fail closed");

        assert_eq!(error.kind(), SecretResolveErrorKind::UnknownAlias);
        assert!(fixture.azure.requests().is_empty());
    }

    #[tokio::test]
    async fn saturated_provider_admission_fails_before_any_provider_work() {
        let fixture = provider(vec![alias("billing", None)]);
        fixture
            .azure
            .push_login(json_response(200, &token_body(TOKEN_CANARY, 600)));
        fixture
            .azure
            .push_read(json_response(200, &read_body(VALUE_CANARY, VERSION_CANARY)));
        let mut provider = fixture.provider.clone();
        provider.concurrent_reads = Arc::new(Semaphore::new(0));

        let error = provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect_err("saturated admission must fail closed");

        assert_eq!(error.kind(), SecretResolveErrorKind::ProviderBusy);
        assert!(fixture.azure.requests().is_empty());
    }

    #[tokio::test]
    async fn reads_authenticate_first_and_target_only_the_get_secret_path() {
        let fixture = provider(vec![alias("billing", None)]);
        fixture
            .azure
            .push_login(json_response(200, &token_body(TOKEN_CANARY, 600)));
        fixture
            .azure
            .push_read(json_response(200, &read_body(VALUE_CANARY, VERSION_CANARY)));

        let secret = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("configured alias should resolve");

        assert_eq!(secret.expose(), VALUE_CANARY.as_bytes());
        let requests = fixture.azure.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].method, "POST");
        assert_eq!(requests[0].url, token_url());
        assert!(requests[0].authorization.is_none());
        assert_eq!(
            requests[0].content_type.as_deref(),
            Some("application/x-www-form-urlencoded")
        );
        let login_body = requests[0].body.as_deref().unwrap_or_default();
        assert!(login_body.contains("grant_type=client_credentials"));
        assert!(login_body.contains(&format!("client_id={CLIENT_CANARY}")));
        assert!(login_body.contains(CLIENT_SECRET_CANARY));
        assert!(login_body.contains("scope="));
        assert_eq!(requests[1].method, "GET");
        assert_eq!(
            requests[1].url,
            format!(
                "{VAULT_CANARY}/secrets/{NAME_CANARY}?api-version={AZURE_KEY_VAULT_API_VERSION}"
            )
        );
        assert_eq!(
            requests[1].authorization.as_deref(),
            Some(format!("Bearer {TOKEN_CANARY}").as_str())
        );
        for request in &requests {
            assert!(!request.url.contains("/secrets?"));
            assert!(!request.url.contains("maxresults"));
            assert!(!request.url.contains("/deletedsecrets"));
            assert!(!request.url.contains("/backup"));
            assert!(request.method == "GET" || request.method == "POST");
        }
    }

    #[tokio::test]
    async fn a_challenge_response_never_triggers_discovery() {
        let fixture = provider(vec![alias("billing", None)]);
        fixture
            .azure
            .push_login(json_response(200, &token_body(TOKEN_CANARY, 600)));
        // Both attempts answer with a challenge that names a different
        // authority, tenant, and resource; obeying any part of it would be
        // challenge-driven discovery.
        let challenge = "Bearer authorization=\"https://evil-authority.example/evil-tenant\", resource=\"https://evil-vault.example\"";
        fixture.azure.push_read(challenge_response(
            401,
            challenge,
            r#"{"error":{"code":"Unauthorized"}}"#,
        ));
        fixture
            .azure
            .push_login(json_response(200, &token_body(TOKEN_CANARY, 600)));
        fixture.azure.push_read(challenge_response(
            401,
            challenge,
            r#"{"error":{"code":"Unauthorized"}}"#,
        ));

        let error = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect_err("a persistent challenge must fail closed");

        assert_eq!(error.kind(), SecretResolveErrorKind::SourceDenied);
        for request in fixture.azure.requests() {
            assert!(!request.url.contains("evil-authority.example"));
            assert!(!request.url.contains("evil-vault.example"));
            assert!(!request.url.contains("evil-tenant"));
        }
        for login in fixture.azure.logins() {
            assert_eq!(login.url, token_url());
        }
    }

    #[tokio::test]
    async fn reads_never_proceed_without_an_authenticated_identity() {
        let fixture = provider(vec![alias("billing", None)]);
        fixture
            .azure
            .push_login(json_response(401, r#"{"error":"invalid_client"}"#));
        fixture
            .azure
            .push_read(json_response(200, &read_body(VALUE_CANARY, VERSION_CANARY)));

        let error = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect_err("a denied identity must fail closed");

        assert_eq!(error.kind(), SecretResolveErrorKind::SourceDenied);
        assert!(fixture.azure.reads().is_empty());
    }

    #[tokio::test]
    async fn egress_denials_and_refused_redirects_fail_closed() {
        for (responder, expected) in [
            (
                egress_failure(|| EgressError::HostNotAllowed("vault".to_owned())),
                SecretResolveErrorKind::UnsafeSource,
            ),
            (
                egress_failure(|| EgressError::SchemeNotAllowed("http".to_owned())),
                SecretResolveErrorKind::UnsafeSource,
            ),
            (
                egress_failure(|| EgressError::InvalidTlsClientIdentity),
                SecretResolveErrorKind::UnsafeSource,
            ),
            (
                egress_failure(|| {
                    EgressError::NonGlobalIpBlocked(
                        "127.0.0.1".parse().expect("literal IP should parse"),
                    )
                }),
                SecretResolveErrorKind::UnsafeSource,
            ),
            (
                json_response(302, r#"{"redirect":"https://elsewhere.example"}"#),
                SecretResolveErrorKind::UnsafeSource,
            ),
        ] {
            let fixture = provider(vec![alias("billing", None)]);
            fixture
                .azure
                .push_login(json_response(200, &token_body(TOKEN_CANARY, 600)));
            fixture.azure.push_read(responder);

            let error = fixture
                .provider
                .resolve("billing", SecretPurpose::StaticBearer)
                .await
                .expect_err("egress denial must fail closed");

            assert_eq!(error.kind(), expected);
            assert_eq!(fixture.azure.reads().len(), 1);
        }
    }

    #[tokio::test]
    async fn dns_failure_retries_once_and_then_fails_closed() {
        let fixture = provider(vec![alias("billing", None)]);
        fixture
            .azure
            .push_login(json_response(200, &token_body(TOKEN_CANARY, 600)));
        fixture.azure.push_read(egress_failure(|| {
            EgressError::DnsResolutionFailed("vault".to_owned())
        }));

        let error = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect_err("unreachable provider must fail closed");

        assert_eq!(error.kind(), SecretResolveErrorKind::SourceUnavailable);
        assert_eq!(
            fixture.azure.reads().len(),
            usize::try_from(MAX_AZURE_TRANSIENT_RETRIES).expect("retry bound should fit") + 1
        );
    }

    #[tokio::test]
    async fn a_denied_read_reauthenticates_exactly_once() {
        let fixture = provider(vec![alias("billing", None)]);
        fixture.azure.push_login(json_response(
            200,
            &token_body("eyJ.first-token-canary", 600),
        ));
        fixture
            .azure
            .push_login(json_response(200, &token_body(TOKEN_CANARY, 600)));
        fixture
            .azure
            .push_read(json_response(403, r#"{"error":{"code":"Forbidden"}}"#));
        fixture
            .azure
            .push_read(json_response(200, &read_body(VALUE_CANARY, VERSION_CANARY)));

        let secret = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("a rotated identity should recover once");

        assert_eq!(secret.expose(), VALUE_CANARY.as_bytes());
        assert_eq!(fixture.azure.logins().len(), 2);
        let reads = fixture.azure.reads();
        assert_eq!(reads.len(), 2);
        assert_eq!(
            reads[0].authorization.as_deref(),
            Some("Bearer eyJ.first-token-canary")
        );
        assert_eq!(
            reads[1].authorization.as_deref(),
            Some(format!("Bearer {TOKEN_CANARY}").as_str())
        );
    }

    #[tokio::test]
    async fn newly_denied_access_fails_closed_without_a_stale_value() {
        let fixture = provider(vec![alias("billing", None)]);
        fixture
            .azure
            .push_login(json_response(200, &token_body(TOKEN_CANARY, 600)));
        fixture
            .azure
            .push_read(json_response(200, &read_body(VALUE_CANARY, VERSION_CANARY)));
        let first = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("first read should resolve");
        assert_eq!(first.expose(), VALUE_CANARY.as_bytes());

        fixture
            .azure
            .push_read(json_response(403, r#"{"error":{"code":"Forbidden"}}"#));
        fixture.clock.advance(AZURE_VALUE_CACHE_TTL * 2);

        let error = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect_err("newly denied access must fail closed");

        assert_eq!(error.kind(), SecretResolveErrorKind::SourceDenied);
        assert!(fixture.provider.value_guard().is_empty());
    }

    #[tokio::test]
    async fn disabled_temporal_and_absent_secrets_fail_closed() {
        let disabled =
            read_body_with_attributes(VALUE_CANARY, VERSION_CANARY, r#"{"enabled":false}"#);
        let enabled_missing = read_body_with_attributes(VALUE_CANARY, VERSION_CANARY, r#"{}"#);
        let not_yet_valid = read_body_with_attributes(
            VALUE_CANARY,
            VERSION_CANARY,
            &format!(r#"{{"enabled":true,"nbf":{}}}"#, START_UNIX + 3600),
        );
        let expired = read_body_with_attributes(
            VALUE_CANARY,
            VERSION_CANARY,
            &format!(r#"{{"enabled":true,"exp":{}}}"#, START_UNIX - 3600),
        );
        let missing_value = format!(
            r#"{{"id":"{VAULT_CANARY}/secrets/{NAME_CANARY}/{VERSION_CANARY}","attributes":{{"enabled":true}}}}"#
        );
        for (responder, expected) in [
            (
                json_response(200, &disabled),
                SecretResolveErrorKind::SourceDenied,
            ),
            (
                json_response(200, &enabled_missing),
                SecretResolveErrorKind::SourceDenied,
            ),
            (
                json_response(200, &not_yet_valid),
                SecretResolveErrorKind::SourceDenied,
            ),
            (
                json_response(200, &expired),
                SecretResolveErrorKind::SourceDenied,
            ),
            (
                json_response(200, &missing_value),
                SecretResolveErrorKind::SourceUnavailable,
            ),
            (
                json_response(404, r#"{"error":{"code":"SecretNotFound"}}"#),
                SecretResolveErrorKind::SourceUnavailable,
            ),
        ] {
            let fixture = provider(vec![alias("billing", None)]);
            fixture
                .azure
                .push_login(json_response(200, &token_body(TOKEN_CANARY, 600)));
            fixture.azure.push_read(responder);

            let error = fixture
                .provider
                .resolve("billing", SecretPurpose::StaticBearer)
                .await
                .expect_err("unusable material must fail closed");

            assert_eq!(error.kind(), expected);
            assert!(fixture.provider.value_guard().is_empty());
        }
    }

    #[tokio::test]
    async fn values_expiring_inside_the_cache_window_stop_being_served_at_exp() {
        let expiring = read_body_with_attributes(
            VALUE_CANARY,
            VERSION_CANARY,
            &format!(r#"{{"enabled":true,"exp":{}}}"#, START_UNIX + 30),
        );
        let fixture = provider(vec![alias("billing", None)]);
        fixture
            .azure
            .push_login(json_response(200, &token_body(TOKEN_CANARY, 3600)));
        fixture.azure.push_read(json_response(200, &expiring));

        let first = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("a not-yet-expired secret should resolve");
        assert_eq!(first.expose(), VALUE_CANARY.as_bytes());
        let cached = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("a not-yet-expired secret should serve from cache");
        assert_eq!(cached.expose(), VALUE_CANARY.as_bytes());
        assert_eq!(fixture.azure.reads().len(), 1);

        // Past the secret's exp but still inside the flat value-cache TTL:
        // the clamped cache entry must be gone, and the refetched (still
        // expired) value must fail closed instead of serving stale material.
        fixture.clock.advance(Duration::from_secs(31));
        assert!(Duration::from_secs(31) < AZURE_VALUE_CACHE_TTL);

        let error = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect_err("an expired secret must fail closed even inside the cache TTL");

        assert_eq!(error.kind(), SecretResolveErrorKind::SourceDenied);
        assert_eq!(fixture.azure.reads().len(), 2);
        assert!(fixture.provider.value_guard().is_empty());
    }

    #[tokio::test]
    async fn response_identity_mismatches_fail_closed() {
        for body in [
            // Another vault.
            read_body_at(
                "https://other-vault.vault.example",
                NAME_CANARY,
                VALUE_CANARY,
                VERSION_CANARY,
            ),
            // Another secret in the right vault.
            read_body_at(VAULT_CANARY, "other-name", VALUE_CANARY, VERSION_CANARY),
            // A non-https identifier.
            read_body_at(
                &format!("http://{}", &VAULT_CANARY["https://".len()..]),
                NAME_CANARY,
                VALUE_CANARY,
                VERSION_CANARY,
            ),
            // A malformed version segment.
            read_body(VALUE_CANARY, "not-a-version"),
            // Extra path segments.
            format!(
                r#"{{"value":"{VALUE_CANARY}","id":"{VAULT_CANARY}/secrets/{NAME_CANARY}/{VERSION_CANARY}/extra","attributes":{{"enabled":true}}}}"#
            ),
            // A keys identifier instead of a secrets identifier.
            format!(
                r#"{{"value":"{VALUE_CANARY}","id":"{VAULT_CANARY}/keys/{NAME_CANARY}/{VERSION_CANARY}","attributes":{{"enabled":true}}}}"#
            ),
            // Not a URL at all.
            format!(
                r#"{{"value":"{VALUE_CANARY}","id":"not a url","attributes":{{"enabled":true}}}}"#
            ),
        ] {
            let fixture = provider(vec![alias("billing", None)]);
            fixture
                .azure
                .push_login(json_response(200, &token_body(TOKEN_CANARY, 600)));
            fixture.azure.push_read(json_response(200, &body));

            let error = fixture
                .provider
                .resolve("billing", SecretPurpose::StaticBearer)
                .await
                .expect_err("a mismatched response identity must fail closed");

            assert_eq!(error.kind(), SecretResolveErrorKind::InvalidMaterial);
            assert!(fixture.provider.value_guard().is_empty());
        }
    }

    #[tokio::test]
    async fn malformed_oversized_and_invalid_responses_fail_closed() {
        let oversized_value = read_body(
            &"x".repeat(super::super::secret::MAX_HTTP_CREDENTIAL_BYTES + 1),
            VERSION_CANARY,
        );
        let empty_value = read_body("", VERSION_CANARY);
        let oversized_body = format!(
            r#"{{"padding":"{}","value":"{VALUE_CANARY}","id":"{VAULT_CANARY}/secrets/{NAME_CANARY}/{VERSION_CANARY}","attributes":{{"enabled":true}}}}"#,
            "w".repeat(MAX_AZURE_READ_RESPONSE_BYTES)
        );
        for responder in [
            json_response(200, "{not json"),
            json_response(200, r#"{"value":"x"}"#),
            json_response(200, &oversized_body),
            response(200, "text/html", &read_body(VALUE_CANARY, VERSION_CANARY)),
            json_response(200, &oversized_value),
            json_response(200, &empty_value),
        ] {
            let fixture = provider(vec![alias("billing", None)]);
            fixture
                .azure
                .push_login(json_response(200, &token_body(TOKEN_CANARY, 600)));
            fixture.azure.push_read(responder);

            let error = fixture
                .provider
                .resolve("billing", SecretPurpose::StaticBearer)
                .await
                .expect_err("malformed provider data must fail closed");

            assert_eq!(error.kind(), SecretResolveErrorKind::InvalidMaterial);
            assert!(fixture.provider.value_guard().is_empty());
        }
    }

    #[tokio::test]
    async fn non_expiring_and_non_bearer_identities_are_rejected() {
        for body in [
            token_body(TOKEN_CANARY, 0),
            format!(r#"{{"token_type":"MAC","expires_in":600,"access_token":"{TOKEN_CANARY}"}}"#),
            r#"{"token_type":"Bearer","expires_in":600,"access_token":""}"#.to_owned(),
            "{not json".to_owned(),
        ] {
            let fixture = provider(vec![alias("billing", None)]);
            fixture.azure.push_login(json_response(200, &body));
            fixture
                .azure
                .push_read(json_response(200, &read_body(VALUE_CANARY, VERSION_CANARY)));

            let error = fixture
                .provider
                .resolve("billing", SecretPurpose::StaticBearer)
                .await
                .expect_err("an unusable identity grant must be refused");

            assert_eq!(error.kind(), SecretResolveErrorKind::InvalidMaterial);
            assert!(fixture.azure.reads().is_empty());
        }
    }

    #[tokio::test]
    async fn tokens_are_reused_until_the_refresh_margin_then_reacquired() {
        let fixture = provider(vec![alias("billing", None)]);
        fixture
            .azure
            .push_login(json_response(200, &token_body(TOKEN_CANARY, 300)));
        fixture
            .azure
            .push_read(json_response(200, &read_body(VALUE_CANARY, VERSION_CANARY)));

        fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("first read should resolve");
        fixture
            .clock
            .advance(AZURE_VALUE_CACHE_TTL + Duration::from_secs(1));
        fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("second read should resolve");
        assert_eq!(fixture.azure.logins().len(), 1, "a live token is reused");

        fixture.azure.push_login(json_response(
            200,
            &token_body("eyJ.rotated-token-canary", 300),
        ));
        fixture.clock.advance(Duration::from_secs(300));
        fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("read after token expiry should resolve");

        assert_eq!(fixture.azure.logins().len(), 2);
        let reads = fixture.azure.reads();
        assert_eq!(
            reads.last().and_then(|read| read.authorization.as_deref()),
            Some("Bearer eyJ.rotated-token-canary")
        );
    }

    #[tokio::test]
    async fn unpinned_aliases_observe_the_next_version_after_cache_expiry() {
        let fixture = provider(vec![alias("billing", None)]);
        fixture
            .azure
            .push_login(json_response(200, &token_body(TOKEN_CANARY, 3600)));
        fixture.azure.push_read(json_response(
            200,
            &read_body("first-value", VERSION_CANARY),
        ));

        let first = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("first read should resolve");
        let cached = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("cached read should resolve");
        assert_eq!(first.expose(), b"first-value");
        assert_eq!(cached.expose(), b"first-value");
        assert_eq!(fixture.azure.reads().len(), 1);

        fixture.azure.push_read(json_response(
            200,
            &read_body("second-value", OTHER_VERSION),
        ));
        fixture
            .clock
            .advance(AZURE_VALUE_CACHE_TTL + Duration::from_secs(1));

        let rotated = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("rotated read should resolve");

        assert_eq!(rotated.expose(), b"second-value");
        assert_eq!(fixture.azure.reads().len(), 2);
        assert_eq!(first.expose(), b"first-value");
    }

    #[tokio::test]
    async fn pinned_aliases_stay_pinned_and_reject_a_different_version() {
        let fixture = provider(vec![alias("billing", Some(VERSION_CANARY))]);
        fixture
            .azure
            .push_login(json_response(200, &token_body(TOKEN_CANARY, 3600)));
        fixture.azure.push_read(json_response(
            200,
            &read_body("pinned-value", VERSION_CANARY),
        ));

        let pinned = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("pinned read should resolve");
        assert_eq!(pinned.expose(), b"pinned-value");
        let reads = fixture.azure.reads();
        assert_eq!(
            reads[0].url,
            format!(
                "{VAULT_CANARY}/secrets/{NAME_CANARY}/{VERSION_CANARY}?api-version={AZURE_KEY_VAULT_API_VERSION}"
            )
        );

        fixture
            .azure
            .push_read(json_response(200, &read_body("newer-value", OTHER_VERSION)));
        fixture.clock.advance(AZURE_VALUE_CACHE_TTL * 2);

        let error = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect_err("a pinned alias must refuse a different version");

        assert_eq!(error.kind(), SecretResolveErrorKind::InvalidMaterial);
        assert!(fixture
            .azure
            .reads()
            .iter()
            .all(|request| request.url.contains(&format!("/{VERSION_CANARY}?"))));
    }

    #[tokio::test]
    async fn a_rotated_identity_invalidates_previously_cached_values() {
        let fixture = provider(vec![alias("billing", None)]);
        fixture
            .azure
            .push_login(json_response(200, &token_body(TOKEN_CANARY, 3600)));
        fixture
            .azure
            .push_read(json_response(200, &read_body(VALUE_CANARY, VERSION_CANARY)));
        fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("first read should resolve");
        assert_eq!(fixture.provider.value_guard().len(), 1);

        fixture.provider.invalidate_token("primary");
        fixture.provider.store_token(
            "primary",
            Zeroizing::new(b"eyJ.rotated-token".to_vec()),
            Some(Duration::from_secs(600)),
        );

        assert!(fixture
            .provider
            .cached_value(
                &fixture.provider.cache_key(
                    fixture
                        .provider
                        .aliases
                        .get("billing")
                        .expect("alias should exist"),
                    SecretPurpose::StaticBearer,
                    fixture.provider.identity_generation("primary"),
                )
            )
            .is_none());
    }

    #[tokio::test]
    async fn concurrent_resolutions_are_hard_bounded() {
        let fixture = provider(vec![alias("billing", None)]);
        fixture
            .azure
            .push_login(json_response(200, &token_body(TOKEN_CANARY, 3600)));
        fixture
            .azure
            .push_read(json_response(200, &read_body(VALUE_CANARY, VERSION_CANARY)));
        fixture.azure.set_delay(Duration::from_millis(250));
        let mut provider = fixture.provider.clone();
        provider.concurrent_reads = Arc::new(Semaphore::new(1));
        let first = tokio::spawn({
            let provider = provider.clone();
            async move {
                provider
                    .resolve("billing", SecretPurpose::StaticBearer)
                    .await
            }
        });
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(25)).await;

        let error = provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect_err("a second concurrent resolution must fail closed");
        assert_eq!(error.kind(), SecretResolveErrorKind::ProviderBusy);

        assert_eq!(
            first
                .await
                .expect("first resolution task should join")
                .expect("first resolution should succeed")
                .expose(),
            VALUE_CANARY.as_bytes()
        );
    }

    #[tokio::test]
    async fn a_hanging_provider_is_bounded_by_the_resolution_deadline() {
        let fixture = provider(vec![alias("billing", None)]);
        fixture
            .azure
            .push_login(json_response(200, &token_body(TOKEN_CANARY, 3600)));
        fixture
            .azure
            .push_read(json_response(200, &read_body(VALUE_CANARY, VERSION_CANARY)));
        fixture.azure.set_delay(Duration::from_secs(30));
        let mut provider = fixture.provider.clone();
        provider.deadline = Duration::from_millis(100);

        let error = provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect_err("a hanging provider must fail closed");

        assert_eq!(error.kind(), SecretResolveErrorKind::SourceUnavailable);
    }

    #[tokio::test]
    async fn the_value_cache_is_bounded() {
        let aliases = (0..MAX_AZURE_VALUE_CACHE_ENTRIES + 4)
            .map(|index| alias(&format!("billing-{index}"), None))
            .collect::<Vec<_>>();
        let fixture = provider(aliases);
        fixture
            .azure
            .push_login(json_response(200, &token_body(TOKEN_CANARY, 3600)));
        fixture
            .azure
            .push_read(json_response(200, &read_body(VALUE_CANARY, VERSION_CANARY)));

        for index in 0..MAX_AZURE_VALUE_CACHE_ENTRIES + 4 {
            fixture
                .provider
                .resolve(&format!("billing-{index}"), SecretPurpose::StaticBearer)
                .await
                .expect("each read should resolve");
        }

        assert!(fixture.provider.value_guard().len() <= MAX_AZURE_VALUE_CACHE_ENTRIES);
    }

    #[tokio::test]
    async fn oversized_bootstrap_material_is_rejected_before_any_identity_request() {
        let fixture = provider_with_bootstrap(
            AzureProviderConfig {
                profiles: vec![client_secret_profile("primary")],
                aliases: vec![alias("billing", None)],
            },
            Some(Arc::new(FakeBootstrap {
                value: vec![b'x'; MAX_AZURE_CLIENT_SECRET_BYTES + 1],
            })),
        );
        fixture
            .azure
            .push_login(json_response(200, &token_body(TOKEN_CANARY, 600)));

        let error = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect_err("oversized bootstrap material must fail closed");

        assert_eq!(error.kind(), SecretResolveErrorKind::InvalidMaterial);
        assert!(fixture.azure.requests().is_empty());
    }

    #[tokio::test]
    async fn workload_identity_tokens_are_read_from_a_pinned_root() {
        let root = std::env::temp_dir().join(format!(
            "greengateway-azure-workload-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir(&root).expect("workload root should create");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o755))
                .expect("workload root permissions should update");
        }
        fs::write(root.join("token"), b"projected.jwt.canary").expect("token should write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root.join("token"), fs::Permissions::from_mode(0o644))
                .expect("token permissions should update");
        }
        let fixture = provider_with_bootstrap(
            AzureProviderConfig {
                profiles: vec![workload_profile(
                    "primary",
                    root.to_str().expect("root path should be Unicode"),
                )],
                aliases: vec![alias("billing", None)],
            },
            None,
        );
        fixture
            .azure
            .push_login(json_response(200, &token_body(TOKEN_CANARY, 600)));
        fixture
            .azure
            .push_read(json_response(200, &read_body(VALUE_CANARY, VERSION_CANARY)));

        let secret = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("workload identity read should resolve");

        assert_eq!(secret.expose(), VALUE_CANARY.as_bytes());
        let logins = fixture.azure.logins();
        assert_eq!(logins.len(), 1);
        let body = logins[0].body.as_deref().unwrap_or_default();
        assert!(body.contains("projected.jwt.canary"));
        assert!(body.contains(
            "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer"
        ));
        assert!(!body.contains("client_secret="));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::write(root.join("token"), b"escalated").expect("token should rewrite");
            fs::set_permissions(root.join("token"), fs::Permissions::from_mode(0o666))
                .expect("token permissions should update");
            fixture.provider.invalidate_token("primary");
            fixture.provider.purge_alias("billing");
            let error = fixture
                .provider
                .resolve("billing", SecretPurpose::StaticBearer)
                .await
                .expect_err("a world-writable identity token must fail closed");
            assert_eq!(error.kind(), SecretResolveErrorKind::SourceDenied);
        }

        // The provider retains a capability handle to the token root; drop it
        // before removal so Windows releases the directory.
        drop(fixture);
        fs::remove_dir_all(&root).expect("workload root should remove");
    }

    // A PKCS#8 RSA key published solely for hermetic signing tests; it mirrors
    // the JWT test keys elsewhere in this crate and protects nothing.
    const TEST_RSA_PRIVATE_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCnhXdj9xmwS1xg
0FSkz/Czegzbs7x52/LjNeVoaKsKFiiZh2X6TfeNv9FBHlqaP4crN3ONOutajg2o
jVy2LqOlmX0oWOsu7s9x1SZoy18N5jtOw/knSsYDc4y6ir/0H/WNRf+qMZXo/ZGU
eDU0C2fONU0XXaGWD3ypaQeqClnSInMIIjpJ0gATyGPJVNuVgmdeYdkNBdmlOKrX
dsRg7UjAmt9WXgCm6w1MRAIeZJ6cTNhQ5cx0JBVZRxeNRcVDpXx+IW6QC+HWTcbr
GxGpNzC1AaY9q67VyV/nLypaLF2m4SyKrYbkf5azoyH7zkpvpb6mgJPjdYlhO5M8
dVHvbB81AgMBAAECggEAByEJ7KomYLdETiZvg7gJsUmfZHYorjLrCjpP8fqKVNqO
jcISV+2bfF/OYuwMxQWxFei9NSRtwaPL9wFVEbe4ZSK8DcyC7bNiBqEgilMlT20d
1wNGBiMLfDgdpA6ljpkRlRqGf9KuY4Tu/heDhBx8JW1lQ3pLlxw/nOIIXnckTWny
I5qOpk5XZ/QzJNC2ze0F2VsQ5RAGNdDG9vKHm5qeYHzgM1z9SOUMXsfPYOiXvdZP
BPa59BdP7cmXDVCuh12ZhpVnDErYtA9iPXqmoAah14JP4xKju5QIvavsQt9S8gB5
cxhAu4LmT9p1iOsKaDsG44gxUzmHS0bcuoIgFzDh4QKBgQDp3q9If/ZfZuu3+NPr
F/o36JvUY5SPnbYf1p5hSyBkVhTzKyGiYq7W0Lxs/RcOhw8YlfNfzqRNnhjmZhlE
FXpUCSXVSAtdC3MpCx2XimZltJ+TdIzajeWmh2Wx6SpJJek10UL2n6ht2BBALWyz
Dt2s709dVlxfYwHnZWBe4xxJTQKBgQC3X4prVHXcIKTyNyMS8cC/iMgbOu+Q58CF
VnBuRWsL96vzrHUgUcoYNTPbMOjm98Wzrk2roW+fnDMp0Y8ZusceKOVraihDifN2
yQ2H053ctC8YEvZeOE6JlDq+llAGnRv+113pmfZ51qNeVFcwdR5ujhAunnW7UC28
+IGqI3H5iQKBgQDik2iUP8zsbqTuLrb5K9iyM7xND1DNtsjMnbwBnKw8KR3Q3LeQ
QDUNT1tN6AFfhL++XQBVkLijrgiHpuDRklFaeyZZNJw1v7MJT4iS2XYNEOoNDLyt
vQ2BwelnbPMXvQ/soNlUYCfoi4xq8Nc/vqZLNepZDiMeEqi0iwXLyBIOfQKBgQCv
wF1to2TXF16gXCI8vQKNUO7h0mncS5Mk+QUHW3dO4BGpmegkkt+Mtik+czE2ddHB
9lSxJChVJSOQeC6cbXz8thu1COkQWn7Doc1bGoLaDsR4YWxKP9NeX3iyRGTtAdXc
OdTj2VH30rV/6nwqkIYbVgPCetPCNQWxccjtJc3OaQKBgHGijhVSMmlnGeAIiPmq
0hj0A9bv7QQz5M2TS+yuhQjHDJWa4Asic+AkgfOu5belhSDd13QCou1r8CcUc9uv
mu96vvRxLhwFLatFo4mL0WnOwBvMrR+5YwboH7Er4PBhmVJ2UKiQn8bNX3qdhVTp
O2gecI9QwDJNpm29J9wJB2F8
-----END PRIVATE KEY-----"#;

    #[tokio::test]
    async fn client_certificate_profiles_sign_a_bounded_rs256_assertion() {
        let fixture = provider_with_bootstrap(
            AzureProviderConfig {
                profiles: vec![certificate_profile("primary")],
                aliases: vec![alias("billing", None)],
            },
            Some(Arc::new(FakeBootstrap {
                value: TEST_RSA_PRIVATE_KEY.as_bytes().to_vec(),
            })),
        );
        fixture
            .azure
            .push_login(json_response(200, &token_body(TOKEN_CANARY, 600)));
        fixture
            .azure
            .push_read(json_response(200, &read_body(VALUE_CANARY, VERSION_CANARY)));

        let secret = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("certificate identity read should resolve");
        assert_eq!(secret.expose(), VALUE_CANARY.as_bytes());

        let logins = fixture.azure.logins();
        assert_eq!(logins.len(), 1);
        let body = logins[0].body.as_deref().unwrap_or_default();
        assert!(!body.contains("client_secret="));
        let assertion = body
            .split('&')
            .find_map(|pair| pair.strip_prefix("client_assertion="))
            .expect("login body should carry a client assertion");
        let assertion: String = url::form_urlencoded::parse(format!("a={assertion}").as_bytes())
            .next()
            .map(|(_, value)| value.into_owned())
            .expect("client assertion should decode");
        let segments = assertion.split('.').collect::<Vec<_>>();
        assert_eq!(segments.len(), 3, "assertion must be a compact JWS");
        let header = BASE64_URL_SAFE_NO_PAD
            .decode(segments[0])
            .expect("assertion header should decode");
        let header: serde_json::Value =
            serde_json::from_slice(&header).expect("assertion header should parse");
        assert_eq!(header["alg"], "RS256");
        assert_eq!(
            header["x5t"],
            BASE64_URL_SAFE_NO_PAD.encode(
                hex::decode("00112233445566778899aabbccddeeff00112233")
                    .expect("test thumbprint should decode")
            )
        );
        let claims = BASE64_URL_SAFE_NO_PAD
            .decode(segments[1])
            .expect("assertion claims should decode");
        let claims: serde_json::Value =
            serde_json::from_slice(&claims).expect("assertion claims should parse");
        assert_eq!(claims["aud"], token_url());
        assert_eq!(claims["iss"], CLIENT_CANARY);
        assert_eq!(claims["sub"], CLIENT_CANARY);
        let exp = claims["exp"].as_u64().expect("assertion should expire");
        let nbf = claims["nbf"].as_u64().expect("assertion should have nbf");
        assert!(exp > nbf);
        assert!(exp - nbf <= AZURE_CLIENT_ASSERTION_LIFETIME_SECS);
        assert!(!body.contains("BEGIN PRIVATE KEY"));
    }

    #[tokio::test]
    async fn metadata_and_debug_output_never_expose_locators_tokens_or_values() {
        let fixture = provider(vec![alias("billing", Some(VERSION_CANARY))]);
        fixture
            .azure
            .push_login(json_response(200, &token_body(TOKEN_CANARY, 3600)));
        fixture
            .azure
            .push_read(json_response(200, &read_body(VALUE_CANARY, VERSION_CANARY)));
        let secret = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("read should resolve");
        let denied = fixture
            .provider
            .resolve("unknown-alias", SecretPurpose::StaticBearer)
            .await
            .expect_err("unknown alias must fail");
        let configuration = AzureProviderConfig {
            profiles: vec![
                client_secret_profile("primary"),
                workload_profile("workload", "/var/run/secrets/token-root-canary"),
                certificate_profile("certificate"),
            ],
            aliases: vec![alias("billing", Some(VERSION_CANARY))],
        };

        let outputs = [
            format!("{:?}", fixture.provider),
            format!("{configuration:?}"),
            format!("{:?}", configuration.profiles),
            format!("{:?}", configuration.aliases),
            format!("{secret:?}"),
            format!("{denied:?} {denied}"),
            serde_json::to_string(&fixture.provider.aliases())
                .expect("alias metadata should serialize"),
            AzureFailure::ProviderDenied.safe_reason().to_owned(),
            AzureFailure::SecretDisabled.safe_reason().to_owned(),
            format!(
                "{}",
                AzureProviderConfigError::InvalidAuthorityHost { index: 0 }
            ),
            format!(
                "{}",
                AzureProviderConfigError::InvalidVaultAuthority { index: 0 }
            ),
        ];
        for output in outputs {
            for canary in [
                VALUE_CANARY,
                TOKEN_CANARY,
                AUTHORITY_CANARY,
                TENANT_CANARY,
                CLIENT_CANARY,
                SCOPE_CANARY,
                VAULT_CANARY,
                NAME_CANARY,
                VERSION_CANARY,
                CLIENT_SECRET_CANARY,
                "token-root-canary",
            ] {
                assert!(
                    !output.contains(canary),
                    "{canary} must not appear in {output}"
                );
            }
        }
        let metadata = fixture.provider.aliases();
        assert_eq!(metadata.len(), 1);
        assert_eq!(metadata[0].provider, SecretProviderKind::AzureKeyVault);
        assert_eq!(metadata[0].version, None);
        // The opaque version identifier stays redacted; only the fact that this
        // alias will not observe rotation is surfaced.
        assert!(metadata[0].pinned);
        assert!(serde_json::to_string(&metadata)
            .expect("alias metadata should serialize")
            .contains("azure_key_vault"));
    }

    #[test]
    fn every_failure_maps_to_a_bounded_safe_reason() {
        for failure in [
            AzureFailure::UnknownAlias,
            AzureFailure::ProviderBusy,
            AzureFailure::DeadlineExceeded,
            AzureFailure::EgressDenied,
            AzureFailure::RedirectRefused,
            AzureFailure::IdentityUnavailable,
            AzureFailure::IdentityDenied,
            AzureFailure::IdentityInvalid,
            AzureFailure::ProviderUnavailable,
            AzureFailure::ProviderDenied,
            AzureFailure::SecretAbsent,
            AzureFailure::SecretDisabled,
            AzureFailure::SecretNotYetValid,
            AzureFailure::SecretExpired,
            AzureFailure::InvalidResponse,
            AzureFailure::InvalidMaterial,
            AzureFailure::ProviderFailure,
        ] {
            let reason = failure.safe_reason();
            assert!(reason.len() <= 32);
            assert!(reason
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_'));
        }
    }
}
