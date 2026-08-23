//! Read-only HashiCorp Vault KV v2 secret provider.
//!
//! The provider is one more implementation of the stable [`SecretResolver`]
//! contract. It adds no Connection authority, no secret CRUD service, and no
//! reveal or provider-proxy endpoint. Every provider locator (address,
//! namespace, KV v2 mount, path, data key, optional pinned version, auth mount,
//! auth role) is fixed by trusted startup configuration and bound to one opaque
//! alias, so callers, tool arguments, and ordinary Connection mutations can only
//! name an alias that an operator already provisioned.
//!
//! Only the KV v2 *read secret version* operation is implemented. There is no
//! list, metadata, key-discovery, write, rotate, delete, administration, lease,
//! or general Vault path, and no request URL contains a caller-supplied byte:
//! each alias carries a request line that was assembled and validated once at
//! startup.
//!
//! Every provider and identity request travels through [`EgressClient`], so the
//! deployment egress policy (HTTPS, allowlisted host and port, strict CA,
//! hostname and SNI validation, all-answer DNS validation with exact address
//! pinning, and a disabled redirect policy) applies unchanged. Rotation,
//! revocation, deletion, destruction, malformed data, provider outage, and
//! newly denied access all fail closed: a failed resolution purges any cached
//! value for that alias and never returns a previous value, retries
//! anonymously, or switches credential sources.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    fs::{self},
    path::PathBuf,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use cap_std::{ambient_authority, fs::Dir};
use http::{
    header::{ACCEPT, CONTENT_TYPE},
    HeaderMap, HeaderName, HeaderValue, Method, StatusCode,
};
use serde::{
    de::{self, IgnoredAny, Visitor},
    Deserialize, Deserializer,
};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex as AsyncMutex, Semaphore};
use url::Url;
use zeroize::Zeroizing;

use crate::egress::{EgressClient, EgressError};

use super::{
    model::{MAX_CREDENTIALS, MAX_DISPLAY_NAME_CHARS, MAX_SECRET_ID_BYTES},
    secret::{
        is_valid_opaque_id, read_bounded_file_secret, safe_error_alias_id, FileSecretPermissions,
        ResolvedSecret, SecretAliasMetadata, SecretProviderKind, SecretPurpose, SecretResolveError,
        SecretResolveErrorKind, SecretResolver,
    },
};

pub const MAX_VAULT_PROFILES: usize = 8;
pub const MAX_VAULT_SECRET_ALIASES: usize = MAX_CREDENTIALS;
pub const MAX_VAULT_PROVIDER_CONFIG_BYTES: usize = 256 * 1024;
pub const MAX_CONCURRENT_VAULT_RESOLUTIONS: usize = 8;

const MAX_VAULT_ADDRESS_BYTES: usize = 512;
const MAX_VAULT_NAMESPACE_BYTES: usize = 128;
const MAX_VAULT_MOUNT_BYTES: usize = 128;
const MAX_VAULT_PATH_BYTES: usize = 512;
const MAX_VAULT_DATA_KEY_BYTES: usize = 128;
const MAX_VAULT_NAME_BYTES: usize = 128;
const MAX_VAULT_LOGIN_RESPONSE_BYTES: usize = 16 * 1024;
const MAX_VAULT_READ_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_VAULT_TOKEN_BYTES: usize = 1024;
const MAX_VAULT_TOKEN_LIFETIME: Duration = Duration::from_secs(60 * 60);
const VAULT_TOKEN_REFRESH_SKEW: Duration = Duration::from_secs(30);
const VAULT_STATIC_TOKEN_LIFETIME: Duration = Duration::from_secs(60);
const VAULT_VALUE_CACHE_TTL: Duration = Duration::from_secs(60);
const MAX_VAULT_VALUE_CACHE_ENTRIES: usize = 256;
const MAX_VAULT_TRANSIENT_RETRIES: u32 = 1;
const VAULT_RETRY_BACKOFF: Duration = Duration::from_millis(100);
const VAULT_RESOLUTION_DEADLINE: Duration = Duration::from_secs(10);
const VAULT_TOKEN_HEADER: &str = "x-vault-token";
const VAULT_NAMESPACE_HEADER: &str = "x-vault-namespace";
const VAULT_PROVIDER_LABEL: &str = "vault_kv_v2";
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
                if !super::secret::is_valid_file_key(token_file) {
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

/// One bounded provider or identity exchange.
pub(crate) struct VaultHttpResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for VaultHttpResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VaultHttpResponse")
            .field("status", &self.status)
            .field("headers", &"<redacted>")
            .field("body", &"<redacted>")
            .finish()
    }
}

/// Egress-mediated transport for the provider.
///
/// The production implementation is [`EgressVaultTransport`]; tests substitute a
/// hermetic fake so CI never contacts a real Vault.
#[async_trait]
pub(crate) trait VaultTransport: Send + Sync {
    /// Opaque generation of the egress configuration behind this transport.
    fn egress_generation(&self) -> [u8; 32];

    async fn send(
        &self,
        method: Method,
        url: &str,
        headers: HeaderMap,
        body: Option<Vec<u8>>,
    ) -> Result<VaultHttpResponse, EgressError>;
}

pub(crate) struct EgressVaultTransport {
    client: Arc<EgressClient>,
}

impl EgressVaultTransport {
    pub(crate) fn new(client: Arc<EgressClient>) -> Self {
        Self { client }
    }
}

impl fmt::Debug for EgressVaultTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EgressVaultTransport")
    }
}

#[async_trait]
impl VaultTransport for EgressVaultTransport {
    fn egress_generation(&self) -> [u8; 32] {
        self.client.configuration_generation()
    }

    async fn send(
        &self,
        method: Method,
        url: &str,
        headers: HeaderMap,
        body: Option<Vec<u8>>,
    ) -> Result<VaultHttpResponse, EgressError> {
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
        Ok(VaultHttpResponse {
            status: response.status,
            headers: response.headers,
            body: response.body,
        })
    }
}

pub(crate) trait VaultClock: Send + Sync {
    fn now(&self) -> Instant;
}

struct SystemVaultClock;

impl VaultClock for SystemVaultClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

struct VaultProfile {
    id: String,
    login_url: Option<String>,
    namespace: Option<HeaderValue>,
    auth: VaultAuth,
}

enum VaultAuth {
    WorkloadJwt {
        role: String,
        token_root: Arc<Dir>,
        token_file: String,
    },
    Token {
        secret_alias: String,
    },
    AppRole {
        role_id: String,
        secret_id_alias: String,
    },
}

struct VaultAliasBinding {
    id: String,
    label: String,
    profile: String,
    read_url: String,
    key: String,
    version: Option<u64>,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct VaultValueCacheKey {
    provider_generation: [u8; 32],
    egress_generation: [u8; 32],
    identity_generation: u64,
    alias_id: String,
    purpose: u8,
    pinned_version: Option<u64>,
}

struct CachedVaultValue {
    value: Zeroizing<Vec<u8>>,
    expires_at: Instant,
}

struct CachedVaultToken {
    token: Zeroizing<Vec<u8>>,
    expires_at: Instant,
    generation: u64,
}

#[derive(Default)]
struct VaultIdentityState {
    tokens: BTreeMap<String, CachedVaultToken>,
    generations: BTreeMap<String, u64>,
}

/// Read-only KV v2 provider.
#[derive(Clone)]
pub struct VaultKvV2SecretProvider {
    profiles: Arc<BTreeMap<String, VaultProfile>>,
    aliases: Arc<BTreeMap<String, VaultAliasBinding>>,
    transport: Arc<dyn VaultTransport>,
    bootstrap: Option<Arc<dyn SecretResolver>>,
    identity: Arc<Mutex<VaultIdentityState>>,
    login_lock: Arc<AsyncMutex<()>>,
    values: Arc<Mutex<BTreeMap<VaultValueCacheKey, CachedVaultValue>>>,
    concurrent_reads: Arc<Semaphore>,
    clock: Arc<dyn VaultClock>,
    generation: [u8; 32],
    deadline: Duration,
    value_cache_ttl: Duration,
}

impl fmt::Debug for VaultKvV2SecretProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VaultKvV2SecretProvider")
            .field("profile_count", &self.profiles.len())
            .field("alias_count", &self.aliases.len())
            .field("bootstrap_provider_enabled", &self.bootstrap.is_some())
            .field(
                "maximum_concurrent_reads",
                &MAX_CONCURRENT_VAULT_RESOLUTIONS,
            )
            .finish()
    }
}

impl VaultKvV2SecretProvider {
    /// Builds the provider from trusted startup configuration.
    ///
    /// `bootstrap` must be a resolver that does **not** include this provider,
    /// which together with the configuration cycle check keeps bootstrap
    /// material out of any Vault-served alias.
    pub(crate) fn from_config(
        config: &VaultProviderConfig,
        reserved_alias_ids: &BTreeSet<String>,
        transport: Arc<dyn VaultTransport>,
        bootstrap: Option<Arc<dyn SecretResolver>>,
    ) -> Result<Self, VaultProviderConfigError> {
        validate_vault_provider_config(config, reserved_alias_ids)?;
        let mut profiles = BTreeMap::new();
        for (index, profile) in config.profiles.iter().enumerate() {
            let address = profile.address.trim_end_matches('/').to_owned();
            let namespace = profile
                .namespace
                .as_deref()
                .map(|namespace| {
                    HeaderValue::from_str(namespace)
                        .map_err(|_| VaultProviderConfigError::InvalidNamespace { index })
                })
                .transpose()?;
            let (login_url, auth) = match &profile.auth {
                VaultAuthConfig::WorkloadJwt {
                    mount,
                    role,
                    token_root,
                    token_file,
                } => (
                    Some(format!("{address}/v1/auth/{mount}/login")),
                    VaultAuth::WorkloadJwt {
                        role: role.clone(),
                        token_root: open_workload_token_root(index, token_root)?,
                        token_file: token_file.clone(),
                    },
                ),
                VaultAuthConfig::Token { secret_alias } => {
                    if bootstrap.is_none() {
                        return Err(VaultProviderConfigError::BootstrapResolverRequired { index });
                    }
                    (
                        None,
                        VaultAuth::Token {
                            secret_alias: secret_alias.clone(),
                        },
                    )
                }
                VaultAuthConfig::AppRole {
                    mount,
                    role_id,
                    secret_id_alias,
                } => {
                    if bootstrap.is_none() {
                        return Err(VaultProviderConfigError::BootstrapResolverRequired { index });
                    }
                    (
                        Some(format!("{address}/v1/auth/{mount}/login")),
                        VaultAuth::AppRole {
                            role_id: role_id.clone(),
                            secret_id_alias: secret_id_alias.clone(),
                        },
                    )
                }
            };
            profiles.insert(
                profile.id.clone(),
                VaultProfile {
                    id: profile.id.clone(),
                    login_url,
                    namespace,
                    auth,
                },
            );
        }

        let mut aliases = BTreeMap::new();
        for alias in &config.aliases {
            let address = config
                .profiles
                .iter()
                .find(|profile| profile.id == alias.profile)
                .map(|profile| profile.address.trim_end_matches('/').to_owned())
                .unwrap_or_default();
            let mut read_url = format!(
                "{address}/v1/{mount}/data/{path}",
                mount = alias.mount,
                path = alias.path
            );
            if let Some(version) = alias.version {
                read_url.push_str(&format!("?version={version}"));
            }
            aliases.insert(
                alias.id.clone(),
                VaultAliasBinding {
                    id: alias.id.clone(),
                    label: alias.label.clone(),
                    profile: alias.profile.clone(),
                    read_url,
                    key: alias.key.clone(),
                    version: alias.version,
                },
            );
        }

        Ok(Self {
            profiles: Arc::new(profiles),
            aliases: Arc::new(aliases),
            transport,
            bootstrap,
            identity: Arc::new(Mutex::new(VaultIdentityState::default())),
            login_lock: Arc::new(AsyncMutex::new(())),
            values: Arc::new(Mutex::new(BTreeMap::new())),
            concurrent_reads: Arc::new(Semaphore::new(MAX_CONCURRENT_VAULT_RESOLUTIONS)),
            clock: Arc::new(SystemVaultClock),
            generation: provider_generation(config),
            deadline: VAULT_RESOLUTION_DEADLINE,
            value_cache_ttl: VAULT_VALUE_CACHE_TTL,
        })
    }

    pub fn contains_alias(&self, alias_id: &str) -> bool {
        self.aliases.contains_key(alias_id)
    }

    pub fn alias_ids(&self) -> BTreeSet<String> {
        self.aliases.keys().cloned().collect()
    }

    fn identity_guard(&self) -> MutexGuard<'_, VaultIdentityState> {
        match self.identity.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn value_guard(&self) -> MutexGuard<'_, BTreeMap<VaultValueCacheKey, CachedVaultValue>> {
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
        alias: &VaultAliasBinding,
        purpose: SecretPurpose,
        identity_generation: u64,
    ) -> VaultValueCacheKey {
        VaultValueCacheKey {
            provider_generation: self.generation,
            egress_generation: self.transport.egress_generation(),
            identity_generation,
            alias_id: alias.id.clone(),
            purpose: purpose_code(purpose),
            pinned_version: alias.version,
        }
    }

    fn cached_value(&self, key: &VaultValueCacheKey) -> Option<Zeroizing<Vec<u8>>> {
        let now = self.clock.now();
        let mut cache = self.value_guard();
        let entry = cache.get(key)?;
        if entry.expires_at <= now {
            cache.remove(key);
            return None;
        }
        Some(entry.value.clone())
    }

    fn store_value(&self, key: VaultValueCacheKey, value: &[u8]) {
        let now = self.clock.now();
        let mut cache = self.value_guard();
        cache.retain(|_, entry| entry.expires_at > now);
        if cache.len() >= MAX_VAULT_VALUE_CACHE_ENTRIES {
            return;
        }
        cache.insert(
            key,
            CachedVaultValue {
                value: Zeroizing::new(value.to_vec()),
                expires_at: now + self.value_cache_ttl,
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
                CachedVaultToken {
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
    ) -> Result<ResolvedSecret, VaultFailure> {
        let alias = self
            .aliases
            .get(alias_id)
            .ok_or(VaultFailure::UnknownAlias)?;
        let profile = self
            .profiles
            .get(&alias.profile)
            .ok_or(VaultFailure::ProviderFailure)?;

        let identity_generation = self.identity_generation(&profile.id);
        let cache_key = self.cache_key(alias, purpose, identity_generation);
        if let Some(cached) = self.cached_value(&cache_key) {
            return ResolvedSecret::new(purpose, cached.to_vec())
                .map_err(|_| VaultFailure::InvalidMaterial);
        }

        let result = self.read_authenticated(alias, profile, purpose).await;
        if result.is_err() {
            self.purge_alias(&alias.id);
        }
        let (value, identity_generation) = result?;
        let secret = ResolvedSecret::new(purpose, value.to_vec())
            .map_err(|_| VaultFailure::InvalidMaterial)?;
        self.store_value(
            self.cache_key(alias, purpose, identity_generation),
            secret.expose(),
        );
        Ok(secret)
    }

    async fn read_authenticated(
        &self,
        alias: &VaultAliasBinding,
        profile: &VaultProfile,
        purpose: SecretPurpose,
    ) -> Result<(Zeroizing<Vec<u8>>, u64), VaultFailure> {
        let (token, generation) = self.token(profile, 0).await?;
        match self.read_once(alias, profile, purpose, &token).await {
            Err(VaultFailure::ProviderDenied) => {
                // A rotated, revoked, or expired token is the only condition
                // that earns a second attempt, and only after a fresh login
                // through the same fixed identity source.
                let (token, generation) = self.token(profile, generation.saturating_add(1)).await?;
                self.read_once(alias, profile, purpose, &token)
                    .await
                    .map(|value| (value, generation))
            }
            other => other.map(|value| (value, generation)),
        }
    }

    async fn token(
        &self,
        profile: &VaultProfile,
        minimum_generation: u64,
    ) -> Result<(Zeroizing<Vec<u8>>, u64), VaultFailure> {
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
        profile: &VaultProfile,
    ) -> Result<(Zeroizing<Vec<u8>>, u64), VaultFailure> {
        let body = match &profile.auth {
            VaultAuth::Token { secret_alias } => {
                let token = self.bootstrap_material(secret_alias).await?;
                let generation = self.store_token(
                    &profile.id,
                    token.clone(),
                    Some(VAULT_STATIC_TOKEN_LIFETIME),
                );
                return Ok((token, generation));
            }
            VaultAuth::WorkloadJwt {
                role,
                token_root,
                token_file,
            } => {
                let jwt = self.workload_identity_token(token_root, token_file).await?;
                let jwt = std::str::from_utf8(jwt.expose())
                    .map_err(|_| VaultFailure::IdentityInvalid)?
                    .to_owned();
                serde_json::to_vec(&serde_json::json!({"role": role, "jwt": jwt}))
                    .map_err(|_| VaultFailure::IdentityInvalid)?
            }
            VaultAuth::AppRole {
                role_id,
                secret_id_alias,
            } => {
                let secret_id = self.bootstrap_material(secret_id_alias).await?;
                let secret_id = std::str::from_utf8(&secret_id)
                    .map_err(|_| VaultFailure::IdentityInvalid)?
                    .to_owned();
                serde_json::to_vec(&serde_json::json!({"role_id": role_id, "secret_id": secret_id}))
                    .map_err(|_| VaultFailure::IdentityInvalid)?
            }
        };

        let login_url = profile
            .login_url
            .as_deref()
            .ok_or(VaultFailure::ProviderFailure)?;
        let response = self
            .send_with_bounded_retries(
                Method::POST,
                login_url,
                self.request_headers(profile, None),
                Some(body),
                true,
            )
            .await?;
        let body = bounded_json_body(&response, MAX_VAULT_LOGIN_RESPONSE_BYTES)?;
        let mut login: VaultLoginResponse =
            serde_json::from_slice(body).map_err(|_| VaultFailure::IdentityInvalid)?;
        let lifetime = login.auth.lease_duration_or_reject()?;
        let token = login.auth.take_token()?;
        let cache_lifetime = lifetime
            .checked_sub(VAULT_TOKEN_REFRESH_SKEW)
            .filter(|lifetime| !lifetime.is_zero());
        let generation = self.store_token(&profile.id, token.clone(), cache_lifetime);
        Ok((token, generation))
    }

    async fn bootstrap_material(&self, alias: &str) -> Result<Zeroizing<Vec<u8>>, VaultFailure> {
        let bootstrap = self
            .bootstrap
            .as_ref()
            .ok_or(VaultFailure::ProviderFailure)?;
        let secret = bootstrap
            .resolve(alias, SecretPurpose::StaticBearer)
            .await
            .map_err(|error| match error.kind() {
                SecretResolveErrorKind::SourceDenied | SecretResolveErrorKind::UnsafeSource => {
                    VaultFailure::IdentityDenied
                }
                SecretResolveErrorKind::InvalidMaterial => VaultFailure::IdentityInvalid,
                _ => VaultFailure::IdentityUnavailable,
            })?;
        if secret.expose().len() > MAX_VAULT_TOKEN_BYTES {
            return Err(VaultFailure::IdentityInvalid);
        }
        Ok(Zeroizing::new(secret.expose().to_vec()))
    }

    async fn workload_identity_token(
        &self,
        token_root: &Arc<Dir>,
        token_file: &str,
    ) -> Result<ResolvedSecret, VaultFailure> {
        let root = Arc::clone(token_root);
        let key = token_file.to_owned();
        tokio::task::spawn_blocking(move || {
            read_bounded_file_secret(
                "vault-workload-identity",
                &root,
                &key,
                SecretPurpose::StaticBearer,
                FileSecretPermissions::PlatformProjected,
            )
        })
        .await
        .map_err(|_| VaultFailure::ProviderFailure)?
        .map_err(|error| match error.kind() {
            SecretResolveErrorKind::SourceDenied | SecretResolveErrorKind::UnsafeSource => {
                VaultFailure::IdentityDenied
            }
            SecretResolveErrorKind::InvalidMaterial => VaultFailure::IdentityInvalid,
            _ => VaultFailure::IdentityUnavailable,
        })
    }

    async fn read_once(
        &self,
        alias: &VaultAliasBinding,
        profile: &VaultProfile,
        purpose: SecretPurpose,
        token: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, VaultFailure> {
        let headers = self.request_headers(profile, Some(token))?;
        let response = self
            .send_with_bounded_retries(Method::GET, &alias.read_url, Ok(headers), None, false)
            .await?;
        let body = bounded_json_body(&response, MAX_VAULT_READ_RESPONSE_BYTES)?;
        let read: KvV2ReadResponse =
            serde_json::from_slice(body).map_err(|_| VaultFailure::InvalidResponse)?;
        read.into_value(&alias.key, alias.version, purpose)
    }

    fn request_headers(
        &self,
        profile: &VaultProfile,
        token: Option<&[u8]>,
    ) -> Result<HeaderMap, VaultFailure> {
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        if let Some(namespace) = profile.namespace.as_ref() {
            headers.insert(
                HeaderName::from_static(VAULT_NAMESPACE_HEADER),
                namespace.clone(),
            );
        }
        if let Some(token) = token {
            let mut value =
                HeaderValue::from_bytes(token).map_err(|_| VaultFailure::IdentityInvalid)?;
            value.set_sensitive(true);
            headers.insert(HeaderName::from_static(VAULT_TOKEN_HEADER), value);
        }
        Ok(headers)
    }

    async fn send_with_bounded_retries(
        &self,
        method: Method,
        url: &str,
        headers: Result<HeaderMap, VaultFailure>,
        body: Option<Vec<u8>>,
        identity: bool,
    ) -> Result<VaultHttpResponse, VaultFailure> {
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
            if attempt >= MAX_VAULT_TRANSIENT_RETRIES || !failure.is_transient() {
                return Err(failure);
            }
            attempt = attempt.saturating_add(1);
            tokio::time::sleep(VAULT_RETRY_BACKOFF).await;
        }
    }
}

#[async_trait]
impl SecretResolver for VaultKvV2SecretProvider {
    async fn resolve(
        &self,
        alias_id: &str,
        purpose: SecretPurpose,
    ) -> Result<ResolvedSecret, SecretResolveError> {
        let alias_id = safe_error_alias_id(alias_id);
        let started = Instant::now();
        let permit = Arc::clone(&self.concurrent_reads)
            .try_acquire_owned()
            .map_err(|_| VaultFailure::ProviderBusy);
        let outcome = match permit {
            Ok(permit) => {
                let _permit = permit;
                match tokio::time::timeout(self.deadline, self.resolve_inner(&alias_id, purpose))
                    .await
                {
                    Ok(result) => result,
                    Err(_) => {
                        self.purge_alias(&alias_id);
                        Err(VaultFailure::DeadlineExceeded)
                    }
                }
            }
            Err(failure) => Err(failure),
        };
        record_resolution(&outcome, started.elapsed());
        outcome.map_err(|failure| SecretResolveError::new(&alias_id, failure.kind()))
    }

    fn aliases(&self) -> Vec<SecretAliasMetadata> {
        self.aliases
            .values()
            .map(|alias| SecretAliasMetadata {
                id: alias.id.clone(),
                label: alias.label.clone(),
                provider: SecretProviderKind::VaultKvV2,
                configured: true,
                purpose: None,
                version: alias.version,
                rotated_at: None,
            })
            .collect()
    }
}

fn record_resolution(outcome: &Result<ResolvedSecret, VaultFailure>, elapsed: Duration) {
    let (result, reason) = match outcome {
        Ok(_) => ("success", "resolved"),
        Err(failure) => ("failure", failure.safe_reason()),
    };
    ::metrics::counter!(
        "connection_secret_provider_read_total",
        "provider" => VAULT_PROVIDER_LABEL,
        "result" => result,
        "reason" => reason
    )
    .increment(1);
    ::metrics::histogram!(
        "connection_secret_provider_read_duration_seconds",
        "provider" => VAULT_PROVIDER_LABEL,
        "result" => result
    )
    .record(elapsed.as_secs_f64());
    if let Err(failure) = outcome {
        tracing::warn!(
            provider = VAULT_PROVIDER_LABEL,
            reason = failure.safe_reason(),
            "connection secret provider read failed closed"
        );
    }
}

fn open_workload_token_root(
    index: usize,
    path: &str,
) -> Result<Arc<Dir>, VaultProviderConfigError> {
    let canonical = fs::canonicalize(PathBuf::from(path))
        .map_err(|_| VaultProviderConfigError::WorkloadTokenRootUnavailable { index })?;
    let directory = Dir::open_ambient_dir(&canonical, ambient_authority())
        .map_err(|_| VaultProviderConfigError::WorkloadTokenRootUnavailable { index })?;
    let metadata = directory
        .try_clone()
        .and_then(|directory| directory.into_std_file().metadata())
        .map_err(|_| VaultProviderConfigError::WorkloadTokenRootUnavailable { index })?;
    if !metadata.is_dir() {
        return Err(VaultProviderConfigError::WorkloadTokenRootUnavailable { index });
    }
    validate_token_root_permissions(index, &metadata)?;
    Ok(Arc::new(directory))
}

#[cfg(unix)]
fn validate_token_root_permissions(
    index: usize,
    metadata: &fs::Metadata,
) -> Result<(), VaultProviderConfigError> {
    use std::os::unix::fs::MetadataExt;
    if metadata.mode() & 0o022 == 0 {
        Ok(())
    } else {
        Err(VaultProviderConfigError::WorkloadTokenRootPermissions { index })
    }
}

#[cfg(not(unix))]
fn validate_token_root_permissions(
    _: usize,
    _: &fs::Metadata,
) -> Result<(), VaultProviderConfigError> {
    Ok(())
}

fn provider_generation(config: &VaultProviderConfig) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"vault-kv-v2-provider-v1");
    for profile in &config.profiles {
        digest.update(profile.id.as_bytes());
        digest.update([0]);
        digest.update(profile.address.as_bytes());
        digest.update([0]);
        digest.update(profile.namespace.as_deref().unwrap_or_default().as_bytes());
        digest.update([0]);
        match &profile.auth {
            VaultAuthConfig::WorkloadJwt {
                mount,
                role,
                token_root,
                token_file,
            } => {
                digest.update(b"workload_jwt");
                for field in [mount, role, token_root, token_file] {
                    digest.update(field.as_bytes());
                    digest.update([0]);
                }
            }
            VaultAuthConfig::Token { secret_alias } => {
                digest.update(b"token");
                digest.update(secret_alias.as_bytes());
                digest.update([0]);
            }
            VaultAuthConfig::AppRole {
                mount,
                role_id,
                secret_id_alias,
            } => {
                digest.update(b"app_role");
                for field in [mount, role_id, secret_id_alias] {
                    digest.update(field.as_bytes());
                    digest.update([0]);
                }
            }
        }
    }
    for alias in &config.aliases {
        for field in [
            &alias.id,
            &alias.label,
            &alias.profile,
            &alias.mount,
            &alias.path,
            &alias.key,
        ] {
            digest.update(field.as_bytes());
            digest.update([0]);
        }
        digest.update(alias.version.unwrap_or_default().to_be_bytes());
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
enum VaultFailure {
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
    SecretDestroyed,
    InvalidResponse,
    InvalidMaterial,
    ProviderFailure,
}

impl VaultFailure {
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
            Self::SecretDestroyed => "secret_destroyed",
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
            | Self::SecretAbsent
            | Self::SecretDestroyed => SecretResolveErrorKind::SourceUnavailable,
            Self::IdentityDenied | Self::ProviderDenied => SecretResolveErrorKind::SourceDenied,
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

fn map_egress_error(error: &EgressError, identity: bool) -> VaultFailure {
    match error {
        EgressError::HostNotAllowed(_)
        | EgressError::PortNotAllowed(_)
        | EgressError::NonGlobalIpBlocked(_)
        | EgressError::SchemeNotAllowed(_)
        | EgressError::InvalidPolicy(_)
        | EgressError::InvalidUrl(_)
        | EgressError::InvalidTlsCaBundle { .. }
        | EgressError::InvalidTlsClientIdentity => VaultFailure::EgressDenied,
        EgressError::ResponseTooLarge { .. } => VaultFailure::InvalidResponse,
        EgressError::RequestBodyTooLarge { .. } | EgressError::RequestBodyReadFailed => {
            VaultFailure::IdentityInvalid
        }
        _ if identity => VaultFailure::IdentityUnavailable,
        _ => VaultFailure::ProviderUnavailable,
    }
}

fn classify_status(status: StatusCode, identity: bool) -> Option<VaultFailure> {
    if status == StatusCode::OK {
        return None;
    }
    if status.is_redirection() {
        return Some(VaultFailure::RedirectRefused);
    }
    Some(match status.as_u16() {
        400 | 401 | 403 if identity => VaultFailure::IdentityDenied,
        400 | 401 | 403 => VaultFailure::ProviderDenied,
        404 if identity => VaultFailure::IdentityUnavailable,
        404 => VaultFailure::SecretAbsent,
        429 | 472 | 473 | 500..=599 if identity => VaultFailure::IdentityUnavailable,
        429 | 472 | 473 | 500..=599 => VaultFailure::ProviderUnavailable,
        _ if identity => VaultFailure::IdentityInvalid,
        _ => VaultFailure::InvalidResponse,
    })
}

fn bounded_json_body(response: &VaultHttpResponse, maximum: usize) -> Result<&[u8], VaultFailure> {
    if !is_json_content_type(response.headers.get(CONTENT_TYPE)) {
        return Err(VaultFailure::InvalidResponse);
    }
    if response.body.len() > maximum || response.body.is_empty() {
        return Err(VaultFailure::InvalidResponse);
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
struct VaultLoginResponse {
    auth: VaultLoginAuth,
}

#[derive(Deserialize)]
struct VaultLoginAuth {
    client_token: SecretText,
    lease_duration: u64,
}

impl VaultLoginAuth {
    /// Rejects a non-expiring identity outright: this provider only accepts
    /// short-lived tokens, so a `0` lease (a root or never-expiring token) is
    /// invalid rather than an unbounded grant.
    fn lease_duration_or_reject(&self) -> Result<Duration, VaultFailure> {
        if self.lease_duration == 0 {
            return Err(VaultFailure::IdentityInvalid);
        }
        Ok(Duration::from_secs(self.lease_duration).min(MAX_VAULT_TOKEN_LIFETIME))
    }

    fn take_token(&mut self) -> Result<Zeroizing<Vec<u8>>, VaultFailure> {
        let token = self.client_token.take_bytes();
        if token.is_empty() || token.len() > MAX_VAULT_TOKEN_BYTES {
            return Err(VaultFailure::IdentityInvalid);
        }
        if token.iter().any(|byte| *byte < 0x21 || *byte > 0x7e) {
            return Err(VaultFailure::IdentityInvalid);
        }
        Ok(token)
    }
}

/// One KV v2 data value.
///
/// String values are held in zeroizing storage; every other JSON shape is
/// discarded during deserialization so a sibling structure never lands in an
/// unmanaged allocation and never satisfies a data-key lookup.
enum VaultDataValue {
    Text(Zeroizing<String>),
    Other,
}

impl<'de> Deserialize<'de> for VaultDataValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(VaultDataValueVisitor)
    }
}

struct VaultDataValueVisitor;

impl<'de> Visitor<'de> for VaultDataValueVisitor {
    type Value = VaultDataValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a KV v2 data value")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(VaultDataValue::Text(Zeroizing::new(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(VaultDataValue::Text(Zeroizing::new(value)))
    }

    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(VaultDataValue::Other)
    }

    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(VaultDataValue::Other)
    }

    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(VaultDataValue::Other)
    }

    fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(VaultDataValue::Other)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(VaultDataValue::Other)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(VaultDataValue::Other)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(Self)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        while sequence.next_element::<IgnoredAny>()?.is_some() {}
        Ok(VaultDataValue::Other)
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: de::MapAccess<'de>,
    {
        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
        Ok(VaultDataValue::Other)
    }
}

#[derive(Deserialize)]
struct KvV2ReadResponse {
    data: KvV2ReadData,
}

#[derive(Deserialize)]
struct KvV2ReadData {
    #[serde(default)]
    data: Option<BTreeMap<String, VaultDataValue>>,
    metadata: KvV2Metadata,
}

#[derive(Deserialize)]
struct KvV2Metadata {
    version: u64,
    #[serde(default)]
    destroyed: bool,
    #[serde(default)]
    deletion_time: String,
}

impl KvV2ReadResponse {
    fn into_value(
        self,
        key: &str,
        pinned_version: Option<u64>,
        purpose: SecretPurpose,
    ) -> Result<Zeroizing<Vec<u8>>, VaultFailure> {
        if self.data.metadata.destroyed {
            return Err(VaultFailure::SecretDestroyed);
        }
        if !self.data.metadata.deletion_time.is_empty() {
            return Err(VaultFailure::SecretAbsent);
        }
        if self.data.metadata.version == 0 {
            return Err(VaultFailure::InvalidResponse);
        }
        if pinned_version.is_some_and(|version| version != self.data.metadata.version) {
            return Err(VaultFailure::InvalidResponse);
        }
        let data = self.data.data.ok_or(VaultFailure::SecretAbsent)?;
        let value = match data.get(key) {
            Some(VaultDataValue::Text(value)) => value,
            Some(VaultDataValue::Other) => return Err(VaultFailure::InvalidMaterial),
            None => return Err(VaultFailure::SecretAbsent),
        };
        let bytes = Zeroizing::new(value.as_bytes().to_vec());
        if bytes.is_empty() || bytes.len() > purpose.max_bytes() || bytes.contains(&0) {
            return Err(VaultFailure::InvalidMaterial);
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;

    const VALUE_CANARY: &str = "greengateway-vault-value-canary";
    const TOKEN_CANARY: &str = "hvs.greengateway-vault-token-canary";
    const ADDRESS_CANARY: &str = "https://vault-locator-canary.internal.example";
    const MOUNT_CANARY: &str = "mount-locator-canary";
    const PATH_CANARY: &str = "team-locator-canary/billing-locator-canary";
    const KEY_CANARY: &str = "data-key-locator-canary";

    type Responder = dyn Fn() -> Result<VaultHttpResponse, EgressError> + Send + Sync;

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct RecordedRequest {
        method: String,
        url: String,
        token: Option<String>,
        namespace: Option<String>,
        body: Option<String>,
    }

    /// Scripted responses for one request channel.
    ///
    /// Queued responders are consumed in order; once the queue is empty the last
    /// consumed responder repeats, which keeps steady-state tests short while
    /// leaving a re-queued response unambiguous.
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

    struct FakeVault {
        requests: Mutex<Vec<RecordedRequest>>,
        logins: Mutex<FakeChannel>,
        reads: Mutex<FakeChannel>,
        generation: AtomicU64,
        delay: Mutex<Duration>,
    }

    impl FakeVault {
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
                .filter(|request| !request.url.contains("/v1/auth/"))
                .collect()
        }

        fn logins(&self) -> Vec<RecordedRequest> {
            self.requests()
                .into_iter()
                .filter(|request| request.url.contains("/v1/auth/"))
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
    impl VaultTransport for FakeVault {
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
        ) -> Result<VaultHttpResponse, EgressError> {
            let header_text = |name: &'static str| {
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
                    token: header_text(VAULT_TOKEN_HEADER),
                    namespace: header_text(VAULT_NAMESPACE_HEADER),
                    body: body.map(|body| String::from_utf8_lossy(&body).into_owned()),
                });
            let delay = *self.delay.lock().expect("fake delay should lock");
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            let queue = if url.contains("/v1/auth/") {
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
            Ok(VaultHttpResponse {
                status: StatusCode::from_u16(status).expect("test status should be valid"),
                headers,
                body: Zeroizing::new(body.clone().into_bytes()),
            })
        })
    }

    fn json_response(status: u16, body: &str) -> Arc<Responder> {
        response(status, "application/json", body)
    }

    fn egress_failure(build: impl Fn() -> EgressError + Send + Sync + 'static) -> Arc<Responder> {
        Arc::new(move || Err(build()))
    }

    fn login_body(token: &str, lease: u64) -> String {
        format!(
            r#"{{"request_id":"abc","auth":{{"client_token":"{token}","lease_duration":{lease},"renewable":true,"policies":["default"]}}}}"#
        )
    }

    fn read_body(key: &str, value: &str, version: u64) -> String {
        format!(
            r#"{{"request_id":"abc","data":{{"data":{{"{key}":"{value}","sibling":{{"nested":true}}}},"metadata":{{"created_time":"2026-01-01T00:00:00Z","deletion_time":"","destroyed":false,"version":{version}}}}}}}"#
        )
    }

    struct TestClock {
        now: Mutex<Instant>,
    }

    impl TestClock {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                now: Mutex::new(Instant::now()),
            })
        }

        fn advance(&self, step: Duration) {
            let mut now = self.now.lock().expect("test clock should lock");
            *now += step;
        }
    }

    impl VaultClock for TestClock {
        fn now(&self) -> Instant {
            *self.now.lock().expect("test clock should lock")
        }
    }

    fn workload_profile(id: &str, token_root: &str) -> VaultProfileConfig {
        VaultProfileConfig {
            id: id.to_owned(),
            address: ADDRESS_CANARY.to_owned(),
            namespace: None,
            auth: VaultAuthConfig::WorkloadJwt {
                mount: "kubernetes".to_owned(),
                role: "greengateway".to_owned(),
                token_root: token_root.to_owned(),
                token_file: "token".to_owned(),
            },
        }
    }

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

        fn aliases(&self) -> Vec<SecretAliasMetadata> {
            Vec::new()
        }
    }

    struct ProviderFixture {
        provider: VaultKvV2SecretProvider,
        vault: Arc<FakeVault>,
        clock: Arc<TestClock>,
    }

    fn app_role_profile(id: &str, namespace: Option<&str>) -> VaultProfileConfig {
        VaultProfileConfig {
            id: id.to_owned(),
            address: ADDRESS_CANARY.to_owned(),
            namespace: namespace.map(str::to_owned),
            auth: VaultAuthConfig::AppRole {
                mount: "approle".to_owned(),
                role_id: "role-id-canary".to_owned(),
                secret_id_alias: "bootstrap-secret-id".to_owned(),
            },
        }
    }

    fn provider(aliases: Vec<VaultSecretAliasConfig>) -> ProviderFixture {
        provider_with_bootstrap(
            VaultProviderConfig {
                profiles: vec![app_role_profile("primary", None)],
                aliases,
            },
            Some(Arc::new(FakeBootstrap {
                value: b"secret-id-canary".to_vec(),
            })),
        )
    }

    fn provider_with_bootstrap(
        config: VaultProviderConfig,
        bootstrap: Option<Arc<dyn SecretResolver>>,
    ) -> ProviderFixture {
        let vault = FakeVault::new();
        let clock = TestClock::new();
        let mut provider = VaultKvV2SecretProvider::from_config(
            &config,
            &BTreeSet::new(),
            Arc::clone(&vault) as Arc<dyn VaultTransport>,
            bootstrap,
        )
        .expect("test provider should build");
        provider.clock = Arc::clone(&clock) as Arc<dyn VaultClock>;
        ProviderFixture {
            provider,
            vault,
            clock,
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

    #[tokio::test]
    async fn unknown_alias_denial_produces_zero_provider_work() {
        let fixture = provider(vec![alias("billing", None)]);
        fixture
            .vault
            .push_login(json_response(200, &login_body(TOKEN_CANARY, 600)));
        fixture
            .vault
            .push_read(json_response(200, &read_body(KEY_CANARY, VALUE_CANARY, 4)));

        let error = fixture
            .provider
            .resolve("not-configured", SecretPurpose::StaticBearer)
            .await
            .expect_err("unknown alias must fail closed");

        assert_eq!(error.kind(), SecretResolveErrorKind::UnknownAlias);
        assert!(fixture.vault.requests().is_empty());
    }

    #[tokio::test]
    async fn saturated_provider_admission_fails_before_any_provider_work() {
        let fixture = provider(vec![alias("billing", None)]);
        fixture
            .vault
            .push_login(json_response(200, &login_body(TOKEN_CANARY, 600)));
        fixture
            .vault
            .push_read(json_response(200, &read_body(KEY_CANARY, VALUE_CANARY, 4)));
        let mut provider = fixture.provider.clone();
        provider.concurrent_reads = Arc::new(Semaphore::new(0));

        let error = provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect_err("saturated admission must fail closed");

        assert_eq!(error.kind(), SecretResolveErrorKind::ProviderBusy);
        assert!(fixture.vault.requests().is_empty());
    }

    #[tokio::test]
    async fn reads_authenticate_first_and_target_only_the_kv_v2_data_path() {
        let fixture = provider_with_bootstrap(
            VaultProviderConfig {
                profiles: vec![app_role_profile("primary", Some("team-namespace-canary"))],
                aliases: vec![alias("billing", None)],
            },
            Some(Arc::new(FakeBootstrap {
                value: b"secret-id-canary".to_vec(),
            })),
        );
        fixture
            .vault
            .push_login(json_response(200, &login_body(TOKEN_CANARY, 600)));
        fixture
            .vault
            .push_read(json_response(200, &read_body(KEY_CANARY, VALUE_CANARY, 7)));

        let secret = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("configured alias should resolve");

        assert_eq!(secret.expose(), VALUE_CANARY.as_bytes());
        let requests = fixture.vault.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].method, "POST");
        assert_eq!(
            requests[0].url,
            format!("{ADDRESS_CANARY}/v1/auth/approle/login")
        );
        assert!(requests[0].token.is_none());
        assert_eq!(requests[1].method, "GET");
        assert_eq!(
            requests[1].url,
            format!("{ADDRESS_CANARY}/v1/{MOUNT_CANARY}/data/{PATH_CANARY}")
        );
        assert_eq!(requests[1].token.as_deref(), Some(TOKEN_CANARY));
        assert_eq!(
            requests[1].namespace.as_deref(),
            Some("team-namespace-canary")
        );
        for request in &requests {
            assert!(!request.url.contains("/metadata/"));
            assert!(!request.url.contains("?list="));
            assert!(request.method == "GET" || request.method == "POST");
        }
    }

    #[tokio::test]
    async fn reads_never_proceed_without_an_authenticated_identity() {
        let fixture = provider(vec![alias("billing", None)]);
        fixture
            .vault
            .push_login(json_response(403, r#"{"errors":["permission denied"]}"#));
        fixture
            .vault
            .push_read(json_response(200, &read_body(KEY_CANARY, VALUE_CANARY, 1)));
        let provider = VaultKvV2SecretProvider {
            bootstrap: None,
            ..fixture.provider.clone()
        };

        let error = provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect_err("a provider without an identity source must fail closed");

        assert_eq!(error.kind(), SecretResolveErrorKind::ProviderFailure);
        assert!(fixture.vault.reads().is_empty());
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
                .vault
                .push_login(json_response(200, &login_body(TOKEN_CANARY, 600)));
            fixture.vault.push_read(responder);

            let error = fixture
                .provider
                .resolve("billing", SecretPurpose::StaticBearer)
                .await
                .expect_err("egress denial must fail closed");

            assert_eq!(error.kind(), expected);
            assert_eq!(fixture.vault.reads().len(), 1);
        }
    }

    #[tokio::test]
    async fn dns_failure_retries_once_and_then_fails_closed() {
        let fixture = provider(vec![alias("billing", None)]);
        fixture
            .vault
            .push_login(json_response(200, &login_body(TOKEN_CANARY, 600)));
        fixture.vault.push_read(egress_failure(|| {
            EgressError::DnsResolutionFailed("vault".to_owned())
        }));

        let error = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect_err("unreachable provider must fail closed");

        assert_eq!(error.kind(), SecretResolveErrorKind::SourceUnavailable);
        assert_eq!(
            fixture.vault.reads().len(),
            usize::try_from(MAX_VAULT_TRANSIENT_RETRIES).expect("retry bound should fit") + 1
        );
    }

    #[tokio::test]
    async fn a_denied_read_reauthenticates_exactly_once() {
        let fixture = provider(vec![alias("billing", None)]);
        fixture.vault.push_login(json_response(
            200,
            &login_body("hvs.first-token-canary", 600),
        ));
        fixture
            .vault
            .push_login(json_response(200, &login_body(TOKEN_CANARY, 600)));
        fixture
            .vault
            .push_read(json_response(403, r#"{"errors":["permission denied"]}"#));
        fixture
            .vault
            .push_read(json_response(200, &read_body(KEY_CANARY, VALUE_CANARY, 9)));

        let secret = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("a rotated identity should recover once");

        assert_eq!(secret.expose(), VALUE_CANARY.as_bytes());
        assert_eq!(fixture.vault.logins().len(), 2);
        let reads = fixture.vault.reads();
        assert_eq!(reads.len(), 2);
        assert_eq!(reads[0].token.as_deref(), Some("hvs.first-token-canary"));
        assert_eq!(reads[1].token.as_deref(), Some(TOKEN_CANARY));
    }

    #[tokio::test]
    async fn newly_denied_access_fails_closed_without_a_stale_value() {
        let fixture = provider(vec![alias("billing", None)]);
        fixture
            .vault
            .push_login(json_response(200, &login_body(TOKEN_CANARY, 600)));
        fixture
            .vault
            .push_read(json_response(200, &read_body(KEY_CANARY, VALUE_CANARY, 3)));
        let first = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("first read should resolve");
        assert_eq!(first.expose(), VALUE_CANARY.as_bytes());

        fixture
            .vault
            .push_read(json_response(403, r#"{"errors":["permission denied"]}"#));
        fixture.clock.advance(VAULT_VALUE_CACHE_TTL * 2);

        let error = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect_err("newly denied access must fail closed");

        assert_eq!(error.kind(), SecretResolveErrorKind::SourceDenied);
        assert!(fixture.provider.value_guard().is_empty());
    }

    #[tokio::test]
    async fn deleted_destroyed_and_absent_values_fail_closed() {
        let destroyed = r#"{"data":{"data":null,"metadata":{"deletion_time":"","destroyed":true,"version":4}}}"#;
        let deleted = r#"{"data":{"data":null,"metadata":{"deletion_time":"2026-02-02T00:00:00Z","destroyed":false,"version":4}}}"#;
        let missing_key = r#"{"data":{"data":{"other":"value"},"metadata":{"deletion_time":"","destroyed":false,"version":4}}}"#;
        for (responder, expected) in [
            (
                json_response(200, destroyed),
                SecretResolveErrorKind::SourceUnavailable,
            ),
            (
                json_response(200, deleted),
                SecretResolveErrorKind::SourceUnavailable,
            ),
            (
                json_response(200, missing_key),
                SecretResolveErrorKind::SourceUnavailable,
            ),
            (
                json_response(404, r#"{"errors":[]}"#),
                SecretResolveErrorKind::SourceUnavailable,
            ),
        ] {
            let fixture = provider(vec![alias("billing", None)]);
            fixture
                .vault
                .push_login(json_response(200, &login_body(TOKEN_CANARY, 600)));
            fixture.vault.push_read(responder);

            let error = fixture
                .provider
                .resolve("billing", SecretPurpose::StaticBearer)
                .await
                .expect_err("absent material must fail closed");

            assert_eq!(error.kind(), expected);
        }
    }

    #[tokio::test]
    async fn malformed_oversized_and_non_string_responses_fail_closed() {
        let oversized_value = format!(
            r#"{{"data":{{"data":{{"{KEY_CANARY}":"{}"}},"metadata":{{"deletion_time":"","destroyed":false,"version":1}}}}}}"#,
            "x".repeat(super::super::secret::MAX_HTTP_CREDENTIAL_BYTES + 1)
        );
        let structured_value = format!(
            r#"{{"data":{{"data":{{"{KEY_CANARY}":{{"nested":"value"}}}},"metadata":{{"deletion_time":"","destroyed":false,"version":1}}}}}}"#
        );
        let empty_value = format!(
            r#"{{"data":{{"data":{{"{KEY_CANARY}":""}},"metadata":{{"deletion_time":"","destroyed":false,"version":1}}}}}}"#
        );
        let oversized_body = format!(
            r#"{{"warnings":["{}"],"data":{{"data":{{"{KEY_CANARY}":"{VALUE_CANARY}"}},"metadata":{{"deletion_time":"","destroyed":false,"version":1}}}}}}"#,
            "w".repeat(MAX_VAULT_READ_RESPONSE_BYTES)
        );
        for responder in [
            json_response(200, "{not json"),
            json_response(200, r#"{"data":{}}"#),
            json_response(200, &oversized_body),
            response(200, "text/html", &read_body(KEY_CANARY, VALUE_CANARY, 1)),
            json_response(200, &oversized_value),
            json_response(200, &structured_value),
            json_response(200, &empty_value),
            json_response(
                200,
                &format!(
                    r#"{{"data":{{"data":{{"{KEY_CANARY}":"{}"}},"metadata":{{"deletion_time":"","destroyed":false,"version":0}}}}}}"#,
                    VALUE_CANARY
                ),
            ),
        ] {
            let fixture = provider(vec![alias("billing", None)]);
            fixture
                .vault
                .push_login(json_response(200, &login_body(TOKEN_CANARY, 600)));
            fixture.vault.push_read(responder);

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
    async fn a_non_expiring_identity_is_rejected() {
        let fixture = provider(vec![alias("billing", None)]);
        fixture
            .vault
            .push_login(json_response(200, &login_body(TOKEN_CANARY, 0)));
        fixture
            .vault
            .push_read(json_response(200, &read_body(KEY_CANARY, VALUE_CANARY, 1)));

        let error = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect_err("a never-expiring token must be refused");

        assert_eq!(error.kind(), SecretResolveErrorKind::InvalidMaterial);
        assert!(fixture.vault.reads().is_empty());
    }

    #[tokio::test]
    async fn unpinned_aliases_observe_the_next_version_after_cache_expiry() {
        let fixture = provider(vec![alias("billing", None)]);
        fixture
            .vault
            .push_login(json_response(200, &login_body(TOKEN_CANARY, 3600)));
        fixture
            .vault
            .push_read(json_response(200, &read_body(KEY_CANARY, "first-value", 4)));

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
        assert_eq!(fixture.vault.reads().len(), 1);

        fixture.vault.push_read(json_response(
            200,
            &read_body(KEY_CANARY, "second-value", 5),
        ));
        fixture
            .clock
            .advance(VAULT_VALUE_CACHE_TTL + Duration::from_secs(1));

        let rotated = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("rotated read should resolve");

        assert_eq!(rotated.expose(), b"second-value");
        assert_eq!(fixture.vault.reads().len(), 2);
        assert_eq!(first.expose(), b"first-value");
    }

    #[tokio::test]
    async fn pinned_aliases_stay_pinned_and_reject_a_different_version() {
        let fixture = provider(vec![alias("billing", Some(3))]);
        fixture
            .vault
            .push_login(json_response(200, &login_body(TOKEN_CANARY, 3600)));
        fixture.vault.push_read(json_response(
            200,
            &read_body(KEY_CANARY, "pinned-value", 3),
        ));

        let pinned = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("pinned read should resolve");
        assert_eq!(pinned.expose(), b"pinned-value");
        let reads = fixture.vault.reads();
        assert_eq!(
            reads[0].url,
            format!("{ADDRESS_CANARY}/v1/{MOUNT_CANARY}/data/{PATH_CANARY}?version=3")
        );

        fixture
            .vault
            .push_read(json_response(200, &read_body(KEY_CANARY, "newer-value", 4)));
        fixture.clock.advance(VAULT_VALUE_CACHE_TTL * 2);

        let error = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect_err("a pinned alias must refuse a different version");

        assert_eq!(error.kind(), SecretResolveErrorKind::InvalidMaterial);
        assert!(fixture
            .vault
            .reads()
            .iter()
            .all(|request| request.url.ends_with("?version=3")));
    }

    #[tokio::test]
    async fn a_rotated_identity_invalidates_previously_cached_values() {
        let fixture = provider(vec![alias("billing", None)]);
        fixture
            .vault
            .push_login(json_response(200, &login_body(TOKEN_CANARY, 3600)));
        fixture
            .vault
            .push_read(json_response(200, &read_body(KEY_CANARY, VALUE_CANARY, 1)));
        fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("first read should resolve");
        assert_eq!(fixture.provider.value_guard().len(), 1);

        fixture.provider.invalidate_token("primary");
        fixture.provider.store_token(
            "primary",
            Zeroizing::new(b"hvs.rotated-token".to_vec()),
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
            .vault
            .push_login(json_response(200, &login_body(TOKEN_CANARY, 3600)));
        fixture
            .vault
            .push_read(json_response(200, &read_body(KEY_CANARY, VALUE_CANARY, 1)));
        fixture.vault.set_delay(Duration::from_millis(250));
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
            .vault
            .push_login(json_response(200, &login_body(TOKEN_CANARY, 3600)));
        fixture
            .vault
            .push_read(json_response(200, &read_body(KEY_CANARY, VALUE_CANARY, 1)));
        fixture.vault.set_delay(Duration::from_secs(30));
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
        let aliases = (0..MAX_VAULT_VALUE_CACHE_ENTRIES + 4)
            .map(|index| alias(&format!("billing-{index}"), None))
            .collect::<Vec<_>>();
        let fixture = provider(aliases);
        fixture
            .vault
            .push_login(json_response(200, &login_body(TOKEN_CANARY, 3600)));
        fixture
            .vault
            .push_read(json_response(200, &read_body(KEY_CANARY, VALUE_CANARY, 1)));

        for index in 0..MAX_VAULT_VALUE_CACHE_ENTRIES + 4 {
            fixture
                .provider
                .resolve(&format!("billing-{index}"), SecretPurpose::StaticBearer)
                .await
                .expect("each read should resolve");
        }

        assert!(fixture.provider.value_guard().len() <= MAX_VAULT_VALUE_CACHE_ENTRIES);
    }

    #[tokio::test]
    async fn metadata_and_debug_output_never_expose_locators_tokens_or_values() {
        let fixture = provider(vec![alias("billing", Some(2))]);
        fixture
            .vault
            .push_login(json_response(200, &login_body(TOKEN_CANARY, 3600)));
        fixture
            .vault
            .push_read(json_response(200, &read_body(KEY_CANARY, VALUE_CANARY, 2)));
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
        let configuration = VaultProviderConfig {
            profiles: vec![token_profile("primary", "bootstrap-token")],
            aliases: vec![alias("billing", Some(2))],
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
            VaultFailure::ProviderDenied.safe_reason().to_owned(),
            VaultFailure::SecretDestroyed.safe_reason().to_owned(),
            format!("{}", VaultProviderConfigError::InvalidAddress { index: 0 }),
        ];
        for output in outputs {
            for canary in [
                VALUE_CANARY,
                TOKEN_CANARY,
                ADDRESS_CANARY,
                MOUNT_CANARY,
                PATH_CANARY,
                KEY_CANARY,
            ] {
                assert!(
                    !output.contains(canary),
                    "{canary} must not appear in {output}"
                );
            }
        }
        let metadata = fixture.provider.aliases();
        assert_eq!(metadata.len(), 1);
        assert_eq!(metadata[0].provider, SecretProviderKind::VaultKvV2);
        assert_eq!(metadata[0].version, Some(2));
        assert!(serde_json::to_string(&metadata)
            .expect("alias metadata should serialize")
            .contains("vault_kv_v2"));
    }

    #[test]
    fn every_failure_maps_to_a_bounded_safe_reason() {
        for failure in [
            VaultFailure::UnknownAlias,
            VaultFailure::ProviderBusy,
            VaultFailure::DeadlineExceeded,
            VaultFailure::EgressDenied,
            VaultFailure::RedirectRefused,
            VaultFailure::IdentityUnavailable,
            VaultFailure::IdentityDenied,
            VaultFailure::IdentityInvalid,
            VaultFailure::ProviderUnavailable,
            VaultFailure::ProviderDenied,
            VaultFailure::SecretAbsent,
            VaultFailure::SecretDestroyed,
            VaultFailure::InvalidResponse,
            VaultFailure::InvalidMaterial,
            VaultFailure::ProviderFailure,
        ] {
            let reason = failure.safe_reason();
            assert!(reason.len() <= 32);
            assert!(reason
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_'));
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn workload_identity_tokens_are_read_from_a_pinned_root() {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!(
            "greengateway-vault-workload-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir(&root).expect("workload root should create");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755))
            .expect("workload root permissions should update");
        fs::write(root.join("token"), b"projected.jwt.canary").expect("token should write");
        fs::set_permissions(root.join("token"), fs::Permissions::from_mode(0o644))
            .expect("token permissions should update");
        let fixture = provider_with_bootstrap(
            VaultProviderConfig {
                profiles: vec![workload_profile(
                    "primary",
                    root.to_str().expect("root path should be Unicode"),
                )],
                aliases: vec![alias("billing", None)],
            },
            None,
        );
        fixture
            .vault
            .push_login(json_response(200, &login_body(TOKEN_CANARY, 600)));
        fixture
            .vault
            .push_read(json_response(200, &read_body(KEY_CANARY, VALUE_CANARY, 1)));

        let secret = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("workload identity read should resolve");

        assert_eq!(secret.expose(), VALUE_CANARY.as_bytes());
        let logins = fixture.vault.logins();
        assert_eq!(logins.len(), 1);
        let body = logins[0].body.as_deref().unwrap_or_default();
        assert!(body.contains("projected.jwt.canary"));
        assert!(body.contains("greengateway"));

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

        fs::remove_dir_all(&root).expect("workload root should remove");
    }
}
