//! Read-only Google Cloud Secret Manager provider.
//!
//! The provider is one more implementation of the stable [`SecretResolver`]
//! contract. It adds no Connection authority, no secret CRUD service, and no
//! reveal or provider-proxy endpoint. Every provider locator (workload identity
//! audience, subject-token file, optional impersonation target, project,
//! optional location, secret ID, version selector) is fixed by trusted startup
//! configuration and bound to one opaque alias, so callers, tool arguments, and
//! ordinary Connection mutations can only name an alias that an operator
//! already provisioned.
//!
//! Only the Secret Manager *AccessSecretVersion* operation is implemented.
//! There is no list, discovery, write, rotate, disable, destroy,
//! administration, replication, or KMS path, and no request URL contains a
//! caller-supplied byte: each alias carries a request line that was assembled
//! and validated once at startup.
//!
//! Identity is Workload Identity Federation only: a projected subject-token
//! file is exchanged at the fixed Google STS endpoint, optionally followed by
//! one bounded service-account impersonation exchange. There is no Application
//! Default Credentials chain, no gcloud/CLI invocation, no user credential, no
//! metadata-server fallback, and no support for service-account keys.
//!
//! Every provider and identity request travels through [`EgressClient`], so the
//! deployment egress policy (HTTPS, allowlisted host and port, strict CA,
//! hostname and SNI validation, all-answer DNS validation with exact address
//! pinning, and a disabled redirect policy) applies unchanged. Rotation,
//! revocation, disabled or destroyed versions, checksum mismatches, malformed
//! data, provider outage, and newly denied access all fail closed: a failed
//! resolution purges any cached value for that alias and never returns a
//! previous value, retries anonymously, or switches credential sources.

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
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use cap_std::{ambient_authority, fs::Dir};
use http::{
    header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE},
    HeaderMap, HeaderValue, Method, StatusCode,
};
use serde::{Deserialize, Deserializer};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex as AsyncMutex, Semaphore};
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

pub const MAX_GCP_PROFILES: usize = 8;
pub const MAX_GCP_SECRET_ALIASES: usize = MAX_CREDENTIALS;
pub const MAX_GCP_PROVIDER_CONFIG_BYTES: usize = 256 * 1024;
pub const MAX_CONCURRENT_GCP_RESOLUTIONS: usize = 8;

const MAX_GCP_AUDIENCE_BYTES: usize = 512;
const MAX_GCP_TOKEN_ROOT_BYTES: usize = 512;
const MAX_GCP_SERVICE_ACCOUNT_BYTES: usize = 256;
const MAX_GCP_PROJECT_BYTES: usize = 30;
const MIN_GCP_PROJECT_ID_BYTES: usize = 6;
const MAX_GCP_LOCATION_BYTES: usize = 32;
const MAX_GCP_SECRET_ID_BYTES: usize = 255;
const MIN_GCP_POOL_COMPONENT_BYTES: usize = 4;
const MAX_GCP_POOL_COMPONENT_BYTES: usize = 32;
const MAX_GCP_RESPONSE_NAME_BYTES: usize = 512;
const MAX_GCP_TOKEN_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_GCP_ACCESS_RESPONSE_BYTES: usize = 128 * 1024;
const MAX_GCP_TOKEN_BYTES: usize = 8 * 1024;
const MAX_GCP_TOKEN_LIFETIME: Duration = Duration::from_secs(60 * 60);
const GCP_TOKEN_REFRESH_SKEW: Duration = Duration::from_secs(30);
/// Bounded lifetime requested for every impersonated service-account token.
const GCP_IMPERSONATION_LIFETIME: Duration = Duration::from_secs(600);
const GCP_IMPERSONATION_LIFETIME_FIELD: &str = "600s";
const GCP_VALUE_CACHE_TTL: Duration = Duration::from_secs(60);
const MAX_GCP_VALUE_CACHE_ENTRIES: usize = 256;
const MAX_GCP_TRANSIENT_RETRIES: u32 = 1;
const GCP_RETRY_BACKOFF: Duration = Duration::from_millis(100);
const GCP_RESOLUTION_DEADLINE: Duration = Duration::from_secs(10);
/// Fixed Google STS token-exchange endpoint. Not operator-overridable: tests
/// substitute a hermetic transport instead of redirecting identity traffic.
const GCP_STS_TOKEN_URL: &str = "https://sts.googleapis.com/v1/token";
const GCP_AUDIENCE_PREFIX: &str = "//iam.googleapis.com/projects/";
const GCP_SERVICE_ACCOUNT_DOMAIN_SUFFIX: &str = ".iam.gserviceaccount.com";
const GCP_CLOUD_PLATFORM_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";
const GCP_TOKEN_EXCHANGE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const GCP_ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";
const GCP_JWT_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:jwt";
const GCP_PROVIDER_LABEL: &str = "gcp_secret_manager";
const REDACTED_LOCATOR: &str = "<redacted-locator>";

/// Trusted startup configuration for the read-only Secret Manager provider.
#[derive(Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcpProviderConfig {
    #[serde(default)]
    pub profiles: Vec<GcpProfileConfig>,
    #[serde(default)]
    pub aliases: Vec<GcpSecretAliasConfig>,
}

impl fmt::Debug for GcpProviderConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GcpProviderConfig")
            .field("profile_count", &self.profiles.len())
            .field("alias_count", &self.aliases.len())
            .finish()
    }
}

impl GcpProviderConfig {
    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty() && self.aliases.is_empty()
    }
}

/// One fixed Workload Identity Federation identity.
///
/// The subject token is always read from a projected file beneath `token_root`;
/// `audience` is the full workload identity pool provider resource; and
/// `service_account` optionally names one impersonation target reached through
/// the fixed iamcredentials `generateAccessToken` endpoint. There is no ADC,
/// CLI, user-credential, metadata-server, or service-account-key mechanism.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcpProfileConfig {
    pub id: String,
    pub audience: String,
    pub token_root: String,
    pub token_file: String,
    #[serde(default)]
    pub service_account: Option<String>,
}

impl fmt::Debug for GcpProfileConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GcpProfileConfig")
            .field("id", &self.id)
            .field("audience", &REDACTED_LOCATOR)
            .field("token_root", &REDACTED_LOCATOR)
            .field("token_file", &REDACTED_LOCATOR)
            .field(
                "service_account",
                &self.service_account.as_ref().map(|_| REDACTED_LOCATOR),
            )
            .finish()
    }
}

/// One opaque alias bound to exactly one secret version resource.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcpSecretAliasConfig {
    pub id: String,
    pub label: String,
    pub profile: String,
    pub project: String,
    #[serde(default)]
    pub location: Option<String>,
    pub secret: String,
    #[serde(default)]
    pub version: Option<u64>,
}

impl fmt::Debug for GcpSecretAliasConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GcpSecretAliasConfig")
            .field("id", &self.id)
            .field("label", &self.label)
            .field("profile", &self.profile)
            .field("project", &REDACTED_LOCATOR)
            .field(
                "location",
                &self.location.as_ref().map(|_| REDACTED_LOCATOR),
            )
            .field("secret", &REDACTED_LOCATOR)
            .field("pinned", &self.version.is_some())
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GcpProviderConfigError {
    TooManyProfiles { maximum: usize },
    TooManyAliases { maximum: usize },
    InvalidProfileId { index: usize },
    DuplicateProfileId { index: usize, previous: usize },
    InvalidAudience { index: usize },
    InvalidWorkloadTokenRoot { index: usize },
    InvalidWorkloadTokenFile { index: usize },
    WorkloadTokenRootUnavailable { index: usize },
    WorkloadTokenRootPermissions { index: usize },
    InvalidServiceAccount { index: usize },
    InvalidAliasId { index: usize },
    InvalidLabel { index: usize },
    DuplicateAliasId { index: usize, previous: usize },
    ReservedAliasId { index: usize },
    UnknownProfile { index: usize },
    InvalidProject { index: usize },
    InvalidLocation { index: usize },
    InvalidSecretId { index: usize },
    InvalidVersion { index: usize },
    AliasesWithoutProfiles,
}

impl fmt::Display for GcpProviderConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyProfiles { maximum } => write!(
                formatter,
                "gcp provider profiles must contain at most {maximum} entries"
            ),
            Self::TooManyAliases { maximum } => write!(
                formatter,
                "gcp provider aliases must contain at most {maximum} entries"
            ),
            Self::InvalidProfileId { index } => write!(
                formatter,
                "gcp profile at index {index} has an invalid opaque ID"
            ),
            Self::DuplicateProfileId { index, previous } => write!(
                formatter,
                "gcp profile at index {index} duplicates the opaque ID at index {previous}"
            ),
            Self::InvalidAudience { index } => write!(
                formatter,
                "gcp profile at index {index} requires a full workload identity pool provider audience"
            ),
            Self::InvalidWorkloadTokenRoot { index } => write!(
                formatter,
                "gcp profile at index {index} has an invalid workload identity token root"
            ),
            Self::InvalidWorkloadTokenFile { index } => write!(
                formatter,
                "gcp profile at index {index} has an invalid workload identity token file key"
            ),
            Self::WorkloadTokenRootUnavailable { index } => write!(
                formatter,
                "gcp profile at index {index} has a workload identity token root that is unavailable or cannot be canonicalized"
            ),
            Self::WorkloadTokenRootPermissions { index } => write!(
                formatter,
                "gcp profile at index {index} has a workload identity token root with unsafe write permissions for this platform"
            ),
            Self::InvalidServiceAccount { index } => write!(
                formatter,
                "gcp profile at index {index} has an invalid impersonation service account"
            ),
            Self::InvalidAliasId { index } => write!(
                formatter,
                "gcp alias at index {index} has an invalid opaque ID"
            ),
            Self::InvalidLabel { index } => write!(
                formatter,
                "gcp alias at index {index} has an invalid safe label"
            ),
            Self::DuplicateAliasId { index, previous } => write!(
                formatter,
                "gcp alias at index {index} duplicates the opaque ID at index {previous}"
            ),
            Self::ReservedAliasId { index } => write!(
                formatter,
                "gcp alias at index {index} duplicates an alias ID served by another provider"
            ),
            Self::UnknownProfile { index } => write!(
                formatter,
                "gcp alias at index {index} names an unconfigured profile"
            ),
            Self::InvalidProject { index } => write!(
                formatter,
                "gcp alias at index {index} has an invalid project"
            ),
            Self::InvalidLocation { index } => write!(
                formatter,
                "gcp alias at index {index} has an invalid location"
            ),
            Self::InvalidSecretId { index } => write!(
                formatter,
                "gcp alias at index {index} has an invalid secret ID"
            ),
            Self::InvalidVersion { index } => write!(
                formatter,
                "gcp alias at index {index} pins a version below 1"
            ),
            Self::AliasesWithoutProfiles => {
                formatter.write_str("gcp aliases require at least one configured profile")
            }
        }
    }
}

impl Error for GcpProviderConfigError {}

/// Validates trusted startup configuration without touching the filesystem,
/// DNS, or the provider.
pub fn validate_gcp_provider_config(
    config: &GcpProviderConfig,
    reserved_alias_ids: &BTreeSet<String>,
) -> Result<(), GcpProviderConfigError> {
    if config.profiles.len() > MAX_GCP_PROFILES {
        return Err(GcpProviderConfigError::TooManyProfiles {
            maximum: MAX_GCP_PROFILES,
        });
    }
    if config.aliases.len() > MAX_GCP_SECRET_ALIASES {
        return Err(GcpProviderConfigError::TooManyAliases {
            maximum: MAX_GCP_SECRET_ALIASES,
        });
    }
    if !config.aliases.is_empty() && config.profiles.is_empty() {
        return Err(GcpProviderConfigError::AliasesWithoutProfiles);
    }

    let mut profile_ids = BTreeMap::new();
    for (index, profile) in config.profiles.iter().enumerate() {
        if !is_valid_opaque_id(&profile.id, MAX_SECRET_ID_BYTES) {
            return Err(GcpProviderConfigError::InvalidProfileId { index });
        }
        if let Some(previous) = profile_ids.insert(profile.id.as_str(), index) {
            return Err(GcpProviderConfigError::DuplicateProfileId { index, previous });
        }
        if !is_valid_gcp_audience(&profile.audience) {
            return Err(GcpProviderConfigError::InvalidAudience { index });
        }
        if profile.token_root.is_empty() || profile.token_root.len() > MAX_GCP_TOKEN_ROOT_BYTES {
            return Err(GcpProviderConfigError::InvalidWorkloadTokenRoot { index });
        }
        if !super::secret::is_valid_file_key(&profile.token_file) {
            return Err(GcpProviderConfigError::InvalidWorkloadTokenFile { index });
        }
        if profile
            .service_account
            .as_deref()
            .is_some_and(|account| !is_valid_gcp_service_account(account))
        {
            return Err(GcpProviderConfigError::InvalidServiceAccount { index });
        }
    }

    let mut seen_alias_ids = BTreeMap::new();
    for (index, alias) in config.aliases.iter().enumerate() {
        if !is_valid_opaque_id(&alias.id, MAX_SECRET_ID_BYTES) {
            return Err(GcpProviderConfigError::InvalidAliasId { index });
        }
        if alias.label.is_empty()
            || alias.label.chars().count() > MAX_DISPLAY_NAME_CHARS
            || alias.label.chars().any(char::is_control)
        {
            return Err(GcpProviderConfigError::InvalidLabel { index });
        }
        if let Some(previous) = seen_alias_ids.insert(alias.id.as_str(), index) {
            return Err(GcpProviderConfigError::DuplicateAliasId { index, previous });
        }
        if reserved_alias_ids.contains(&alias.id) {
            return Err(GcpProviderConfigError::ReservedAliasId { index });
        }
        if !profile_ids.contains_key(alias.profile.as_str()) {
            return Err(GcpProviderConfigError::UnknownProfile { index });
        }
        if !is_valid_gcp_project(&alias.project) {
            return Err(GcpProviderConfigError::InvalidProject { index });
        }
        if alias
            .location
            .as_deref()
            .is_some_and(|location| !is_valid_gcp_location(location))
        {
            return Err(GcpProviderConfigError::InvalidLocation { index });
        }
        if !is_valid_gcp_secret_id(&alias.secret) {
            return Err(GcpProviderConfigError::InvalidSecretId { index });
        }
        if alias.version == Some(0) {
            return Err(GcpProviderConfigError::InvalidVersion { index });
        }
    }
    Ok(())
}

fn is_gcp_project_number(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_GCP_PROJECT_BYTES
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && !value.starts_with('0')
}

fn is_gcp_project_id(value: &str) -> bool {
    value.len() >= MIN_GCP_PROJECT_ID_BYTES
        && value.len() <= MAX_GCP_PROJECT_BYTES
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .as_bytes()
            .last()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && value
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-'))
}

fn is_valid_gcp_project(value: &str) -> bool {
    is_gcp_project_number(value) || is_gcp_project_id(value)
}

fn is_valid_gcp_location(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_GCP_LOCATION_BYTES
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .as_bytes()
            .last()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && value
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-'))
}

fn is_valid_gcp_secret_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_GCP_SECRET_ID_BYTES
        && value
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'-'))
}

fn is_valid_gcp_pool_component(value: &str) -> bool {
    value.len() >= MIN_GCP_POOL_COMPONENT_BYTES
        && value.len() <= MAX_GCP_POOL_COMPONENT_BYTES
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .as_bytes()
            .last()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && value
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-'))
}

/// Requires the complete workload identity pool provider resource:
/// `//iam.googleapis.com/projects/{number}/locations/{location}/workloadIdentityPools/{pool}/providers/{provider}`.
fn is_valid_gcp_audience(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_GCP_AUDIENCE_BYTES {
        return false;
    }
    if value
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte == b' ' || !byte.is_ascii())
    {
        return false;
    }
    let Some(rest) = value.strip_prefix(GCP_AUDIENCE_PREFIX) else {
        return false;
    };
    let segments = rest.split('/').collect::<Vec<_>>();
    let [project, locations, location, pools, pool, providers, provider] = segments.as_slice()
    else {
        return false;
    };
    *locations == "locations"
        && *pools == "workloadIdentityPools"
        && *providers == "providers"
        && is_gcp_project_number(project)
        && is_valid_gcp_location(location)
        && is_valid_gcp_pool_component(pool)
        && is_valid_gcp_pool_component(provider)
}

/// Accepts only dedicated service accounts (`{name}@{project}.iam.gserviceaccount.com`).
/// Default service accounts on other domains are rejected by design: the
/// impersonation target must be a dedicated, narrowly granted identity.
fn is_valid_gcp_service_account(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_GCP_SERVICE_ACCOUNT_BYTES || !value.is_ascii() {
        return false;
    }
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    let Some(project) = domain.strip_suffix(GCP_SERVICE_ACCOUNT_DOMAIN_SUFFIX) else {
        return false;
    };
    is_valid_gcp_pool_component(local) && is_gcp_project_id(project)
}

/// One bounded provider or identity exchange.
pub(crate) struct GcpHttpResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for GcpHttpResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GcpHttpResponse")
            .field("status", &self.status)
            .field("headers", &"<redacted>")
            .field("body", &"<redacted>")
            .finish()
    }
}

/// Egress-mediated transport for the provider.
///
/// The production implementation is [`EgressGcpTransport`]; tests substitute a
/// hermetic fake so CI never contacts Google.
#[async_trait]
pub(crate) trait GcpTransport: Send + Sync {
    /// Opaque generation of the egress configuration behind this transport.
    fn egress_generation(&self) -> [u8; 32];

    async fn send(
        &self,
        method: Method,
        url: &str,
        headers: HeaderMap,
        body: Option<Vec<u8>>,
    ) -> Result<GcpHttpResponse, EgressError>;
}

pub(crate) struct EgressGcpTransport {
    client: Arc<EgressClient>,
}

impl EgressGcpTransport {
    pub(crate) fn new(client: Arc<EgressClient>) -> Self {
        Self { client }
    }
}

impl fmt::Debug for EgressGcpTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EgressGcpTransport")
    }
}

#[async_trait]
impl GcpTransport for EgressGcpTransport {
    fn egress_generation(&self) -> [u8; 32] {
        self.client.configuration_generation()
    }

    async fn send(
        &self,
        method: Method,
        url: &str,
        headers: HeaderMap,
        body: Option<Vec<u8>>,
    ) -> Result<GcpHttpResponse, EgressError> {
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
        Ok(GcpHttpResponse {
            status: response.status,
            headers: response.headers,
            body: response.body,
        })
    }
}

pub(crate) trait GcpClock: Send + Sync {
    fn now(&self) -> Instant;
}

struct SystemGcpClock;

impl GcpClock for SystemGcpClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

struct GcpProfile {
    id: String,
    audience: String,
    token_root: Arc<Dir>,
    token_file: String,
    impersonation_url: Option<String>,
}

struct GcpAliasBinding {
    id: String,
    label: String,
    profile: String,
    access_url: String,
    project: String,
    location: Option<String>,
    secret: String,
    version: Option<u64>,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct GcpValueCacheKey {
    provider_generation: [u8; 32],
    egress_generation: [u8; 32],
    identity_generation: u64,
    alias_id: String,
    purpose: u8,
    pinned_version: Option<u64>,
}

struct CachedGcpValue {
    value: Zeroizing<Vec<u8>>,
    expires_at: Instant,
}

struct CachedGcpToken {
    token: Zeroizing<Vec<u8>>,
    expires_at: Instant,
    generation: u64,
}

#[derive(Default)]
struct GcpIdentityState {
    tokens: BTreeMap<String, CachedGcpToken>,
    generations: BTreeMap<String, u64>,
}

/// Read-only Secret Manager provider.
#[derive(Clone)]
pub struct GcpSecretManagerProvider {
    profiles: Arc<BTreeMap<String, GcpProfile>>,
    aliases: Arc<BTreeMap<String, GcpAliasBinding>>,
    transport: Arc<dyn GcpTransport>,
    identity: Arc<Mutex<GcpIdentityState>>,
    login_lock: Arc<AsyncMutex<()>>,
    values: Arc<Mutex<BTreeMap<GcpValueCacheKey, CachedGcpValue>>>,
    concurrent_reads: Arc<Semaphore>,
    clock: Arc<dyn GcpClock>,
    generation: [u8; 32],
    deadline: Duration,
    value_cache_ttl: Duration,
}

impl fmt::Debug for GcpSecretManagerProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GcpSecretManagerProvider")
            .field("profile_count", &self.profiles.len())
            .field("alias_count", &self.aliases.len())
            .field("maximum_concurrent_reads", &MAX_CONCURRENT_GCP_RESOLUTIONS)
            .finish()
    }
}

impl GcpSecretManagerProvider {
    /// Builds the provider from trusted startup configuration.
    pub(crate) fn from_config(
        config: &GcpProviderConfig,
        reserved_alias_ids: &BTreeSet<String>,
        transport: Arc<dyn GcpTransport>,
    ) -> Result<Self, GcpProviderConfigError> {
        validate_gcp_provider_config(config, reserved_alias_ids)?;
        let mut profiles = BTreeMap::new();
        for (index, profile) in config.profiles.iter().enumerate() {
            let impersonation_url = profile.service_account.as_deref().map(|account| {
                format!(
                    "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{account}:generateAccessToken"
                )
            });
            profiles.insert(
                profile.id.clone(),
                GcpProfile {
                    id: profile.id.clone(),
                    audience: profile.audience.clone(),
                    token_root: open_workload_token_root(index, &profile.token_root)?,
                    token_file: profile.token_file.clone(),
                    impersonation_url,
                },
            );
        }

        let mut aliases = BTreeMap::new();
        for alias in &config.aliases {
            let version_segment = alias
                .version
                .map_or_else(|| "latest".to_owned(), |version| version.to_string());
            let access_url = match alias.location.as_deref() {
                Some(location) => format!(
                    "https://secretmanager.{location}.rep.googleapis.com/v1/projects/{project}/locations/{location}/secrets/{secret}/versions/{version_segment}:access",
                    project = alias.project,
                    secret = alias.secret,
                ),
                None => format!(
                    "https://secretmanager.googleapis.com/v1/projects/{project}/secrets/{secret}/versions/{version_segment}:access",
                    project = alias.project,
                    secret = alias.secret,
                ),
            };
            aliases.insert(
                alias.id.clone(),
                GcpAliasBinding {
                    id: alias.id.clone(),
                    label: alias.label.clone(),
                    profile: alias.profile.clone(),
                    access_url,
                    project: alias.project.clone(),
                    location: alias.location.clone(),
                    secret: alias.secret.clone(),
                    version: alias.version,
                },
            );
        }

        Ok(Self {
            profiles: Arc::new(profiles),
            aliases: Arc::new(aliases),
            transport,
            identity: Arc::new(Mutex::new(GcpIdentityState::default())),
            login_lock: Arc::new(AsyncMutex::new(())),
            values: Arc::new(Mutex::new(BTreeMap::new())),
            concurrent_reads: Arc::new(Semaphore::new(MAX_CONCURRENT_GCP_RESOLUTIONS)),
            clock: Arc::new(SystemGcpClock),
            generation: provider_generation(config),
            deadline: GCP_RESOLUTION_DEADLINE,
            value_cache_ttl: GCP_VALUE_CACHE_TTL,
        })
    }

    pub fn alias_ids(&self) -> BTreeSet<String> {
        self.aliases.keys().cloned().collect()
    }

    fn identity_guard(&self) -> MutexGuard<'_, GcpIdentityState> {
        match self.identity.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn value_guard(&self) -> MutexGuard<'_, BTreeMap<GcpValueCacheKey, CachedGcpValue>> {
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
        alias: &GcpAliasBinding,
        purpose: SecretPurpose,
        identity_generation: u64,
    ) -> GcpValueCacheKey {
        GcpValueCacheKey {
            provider_generation: self.generation,
            egress_generation: self.transport.egress_generation(),
            identity_generation,
            alias_id: alias.id.clone(),
            purpose: purpose_code(purpose),
            pinned_version: alias.version,
        }
    }

    fn cached_value(&self, key: &GcpValueCacheKey) -> Option<Zeroizing<Vec<u8>>> {
        let now = self.clock.now();
        let mut cache = self.value_guard();
        let entry = cache.get(key)?;
        if entry.expires_at <= now {
            cache.remove(key);
            return None;
        }
        Some(entry.value.clone())
    }

    fn store_value(&self, key: GcpValueCacheKey, value: &[u8]) {
        let now = self.clock.now();
        let mut cache = self.value_guard();
        cache.retain(|_, entry| entry.expires_at > now);
        if cache.len() >= MAX_GCP_VALUE_CACHE_ENTRIES {
            return;
        }
        cache.insert(
            key,
            CachedGcpValue {
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
                CachedGcpToken {
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
    ) -> Result<ResolvedSecret, GcpFailure> {
        let alias = self.aliases.get(alias_id).ok_or(GcpFailure::UnknownAlias)?;
        let profile = self
            .profiles
            .get(&alias.profile)
            .ok_or(GcpFailure::ProviderFailure)?;

        let identity_generation = self.identity_generation(&profile.id);
        let cache_key = self.cache_key(alias, purpose, identity_generation);
        if let Some(cached) = self.cached_value(&cache_key) {
            return ResolvedSecret::new(purpose, cached.to_vec())
                .map_err(|_| GcpFailure::InvalidMaterial);
        }

        let result = self.read_authenticated(alias, profile, purpose).await;
        if result.is_err() {
            self.purge_alias(&alias.id);
        }
        let (value, identity_generation) = result?;
        let secret = ResolvedSecret::new(purpose, value.to_vec())
            .map_err(|_| GcpFailure::InvalidMaterial)?;
        self.store_value(
            self.cache_key(alias, purpose, identity_generation),
            secret.expose(),
        );
        Ok(secret)
    }

    async fn read_authenticated(
        &self,
        alias: &GcpAliasBinding,
        profile: &GcpProfile,
        purpose: SecretPurpose,
    ) -> Result<(Zeroizing<Vec<u8>>, u64), GcpFailure> {
        let (token, generation) = self.token(profile, 0).await?;
        match self.read_once(alias, purpose, &token).await {
            Err(GcpFailure::ProviderDenied) => {
                // A rotated, revoked, or expired token is the only condition
                // that earns a second attempt, and only after a fresh exchange
                // through the same fixed identity source.
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
        profile: &GcpProfile,
        minimum_generation: u64,
    ) -> Result<(Zeroizing<Vec<u8>>, u64), GcpFailure> {
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

    async fn login(&self, profile: &GcpProfile) -> Result<(Zeroizing<Vec<u8>>, u64), GcpFailure> {
        let subject = self
            .workload_identity_token(&profile.token_root, &profile.token_file)
            .await?;
        let subject = std::str::from_utf8(subject.expose())
            .map_err(|_| GcpFailure::IdentityInvalid)?
            .trim()
            .to_owned();
        if subject.is_empty() {
            return Err(GcpFailure::IdentityInvalid);
        }
        let body = serde_json::to_vec(&serde_json::json!({
            "grantType": GCP_TOKEN_EXCHANGE_GRANT_TYPE,
            "audience": profile.audience,
            "scope": GCP_CLOUD_PLATFORM_SCOPE,
            "requestedTokenType": GCP_ACCESS_TOKEN_TYPE,
            "subjectToken": subject,
            "subjectTokenType": GCP_JWT_TOKEN_TYPE,
        }))
        .map_err(|_| GcpFailure::IdentityInvalid)?;
        let response = self
            .send_with_bounded_retries(
                Method::POST,
                GCP_STS_TOKEN_URL,
                request_headers(None),
                Some(body),
                true,
            )
            .await?;
        let body = bounded_json_body(&response, MAX_GCP_TOKEN_RESPONSE_BYTES, true)?;
        let mut exchange: StsTokenResponse =
            serde_json::from_slice(body).map_err(|_| GcpFailure::IdentityInvalid)?;
        if !exchange.token_type.eq_ignore_ascii_case("bearer") {
            return Err(GcpFailure::IdentityInvalid);
        }
        // An already expired exchange is invalid rather than an unbounded
        // grant; the cache lifetime is always bounded above.
        if exchange.expires_in == 0 {
            return Err(GcpFailure::IdentityInvalid);
        }
        let lifetime = Duration::from_secs(exchange.expires_in).min(MAX_GCP_TOKEN_LIFETIME);
        let token = take_validated_token(&mut exchange.access_token)?;

        let (token, lifetime) = match profile.impersonation_url.as_deref() {
            None => (token, lifetime),
            Some(url) => {
                let body = serde_json::to_vec(&serde_json::json!({
                    "scope": [GCP_CLOUD_PLATFORM_SCOPE],
                    "lifetime": GCP_IMPERSONATION_LIFETIME_FIELD,
                }))
                .map_err(|_| GcpFailure::IdentityInvalid)?;
                let response = self
                    .send_with_bounded_retries(
                        Method::POST,
                        url,
                        request_headers(Some(&token)),
                        Some(body),
                        true,
                    )
                    .await?;
                let body = bounded_json_body(&response, MAX_GCP_TOKEN_RESPONSE_BYTES, true)?;
                let mut impersonation: ImpersonationResponse =
                    serde_json::from_slice(body).map_err(|_| GcpFailure::IdentityInvalid)?;
                // The cache lifetime is the requested bounded lifetime rather
                // than the response `expireTime`; a token the backend shortens
                // further is recovered by the single 401/403 re-exchange.
                (
                    take_validated_token(&mut impersonation.access_token)?,
                    GCP_IMPERSONATION_LIFETIME,
                )
            }
        };
        let cache_lifetime = lifetime
            .checked_sub(GCP_TOKEN_REFRESH_SKEW)
            .filter(|lifetime| !lifetime.is_zero());
        let generation = self.store_token(&profile.id, token.clone(), cache_lifetime);
        Ok((token, generation))
    }

    async fn workload_identity_token(
        &self,
        token_root: &Arc<Dir>,
        token_file: &str,
    ) -> Result<ResolvedSecret, GcpFailure> {
        let root = Arc::clone(token_root);
        let key = token_file.to_owned();
        tokio::task::spawn_blocking(move || {
            read_bounded_file_secret(
                "gcp-workload-identity",
                &root,
                &key,
                SecretPurpose::StaticBearer,
                FileSecretPermissions::PlatformProjected,
            )
        })
        .await
        .map_err(|_| GcpFailure::ProviderFailure)?
        .map_err(|error| match error.kind() {
            SecretResolveErrorKind::SourceDenied | SecretResolveErrorKind::UnsafeSource => {
                GcpFailure::IdentityDenied
            }
            SecretResolveErrorKind::InvalidMaterial => GcpFailure::IdentityInvalid,
            _ => GcpFailure::IdentityUnavailable,
        })
    }

    async fn read_once(
        &self,
        alias: &GcpAliasBinding,
        purpose: SecretPurpose,
        token: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, GcpFailure> {
        let response = self
            .send_with_bounded_retries(
                Method::GET,
                &alias.access_url,
                request_headers(Some(token)),
                None,
                false,
            )
            .await?;
        let body = bounded_json_body(&response, MAX_GCP_ACCESS_RESPONSE_BYTES, false)?;
        let read: AccessSecretVersionResponse =
            serde_json::from_slice(body).map_err(|_| GcpFailure::InvalidResponse)?;
        read.into_value(alias, purpose)
    }

    async fn send_with_bounded_retries(
        &self,
        method: Method,
        url: &str,
        headers: Result<HeaderMap, GcpFailure>,
        body: Option<Vec<u8>>,
        identity: bool,
    ) -> Result<GcpHttpResponse, GcpFailure> {
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
            if attempt >= MAX_GCP_TRANSIENT_RETRIES || !failure.is_transient() {
                return Err(failure);
            }
            attempt = attempt.saturating_add(1);
            tokio::time::sleep(GCP_RETRY_BACKOFF).await;
        }
    }
}

#[async_trait]
impl SecretResolver for GcpSecretManagerProvider {
    async fn resolve(
        &self,
        alias_id: &str,
        purpose: SecretPurpose,
    ) -> Result<ResolvedSecret, SecretResolveError> {
        let alias_id = safe_error_alias_id(alias_id);
        let started = Instant::now();
        let permit = Arc::clone(&self.concurrent_reads)
            .try_acquire_owned()
            .map_err(|_| GcpFailure::ProviderBusy);
        let outcome = match permit {
            Ok(permit) => {
                let _permit = permit;
                match tokio::time::timeout(self.deadline, self.resolve_inner(&alias_id, purpose))
                    .await
                {
                    Ok(result) => result,
                    Err(_) => {
                        self.purge_alias(&alias_id);
                        Err(GcpFailure::DeadlineExceeded)
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
                provider: SecretProviderKind::GcpSecretManager,
                configured: true,
                purpose: None,
                version: alias.version,
                rotated_at: None,
            })
            .collect()
    }
}

fn record_resolution(outcome: &Result<ResolvedSecret, GcpFailure>, elapsed: Duration) {
    let (result, reason) = match outcome {
        Ok(_) => ("success", "resolved"),
        Err(failure) => ("failure", failure.safe_reason()),
    };
    ::metrics::counter!(
        "connection_secret_provider_read_total",
        "provider" => GCP_PROVIDER_LABEL,
        "result" => result,
        "reason" => reason
    )
    .increment(1);
    ::metrics::histogram!(
        "connection_secret_provider_read_duration_seconds",
        "provider" => GCP_PROVIDER_LABEL,
        "result" => result
    )
    .record(elapsed.as_secs_f64());
    if let Err(failure) = outcome {
        tracing::warn!(
            provider = GCP_PROVIDER_LABEL,
            reason = failure.safe_reason(),
            "connection secret provider read failed closed"
        );
    }
}

fn open_workload_token_root(index: usize, path: &str) -> Result<Arc<Dir>, GcpProviderConfigError> {
    let canonical = fs::canonicalize(PathBuf::from(path))
        .map_err(|_| GcpProviderConfigError::WorkloadTokenRootUnavailable { index })?;
    let directory = Dir::open_ambient_dir(&canonical, ambient_authority())
        .map_err(|_| GcpProviderConfigError::WorkloadTokenRootUnavailable { index })?;
    let metadata = directory
        .try_clone()
        .and_then(|directory| directory.into_std_file().metadata())
        .map_err(|_| GcpProviderConfigError::WorkloadTokenRootUnavailable { index })?;
    if !metadata.is_dir() {
        return Err(GcpProviderConfigError::WorkloadTokenRootUnavailable { index });
    }
    validate_token_root_permissions(index, &metadata)?;
    Ok(Arc::new(directory))
}

#[cfg(unix)]
fn validate_token_root_permissions(
    index: usize,
    metadata: &fs::Metadata,
) -> Result<(), GcpProviderConfigError> {
    if crate::connections::secret::projected_root_permissions_are_safe(metadata) {
        Ok(())
    } else {
        Err(GcpProviderConfigError::WorkloadTokenRootPermissions { index })
    }
}

#[cfg(not(unix))]
fn validate_token_root_permissions(
    _: usize,
    _: &fs::Metadata,
) -> Result<(), GcpProviderConfigError> {
    Ok(())
}

fn provider_generation(config: &GcpProviderConfig) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"gcp-secret-manager-provider-v1");
    for profile in &config.profiles {
        for field in [
            profile.id.as_str(),
            profile.audience.as_str(),
            profile.token_root.as_str(),
            profile.token_file.as_str(),
            profile.service_account.as_deref().unwrap_or_default(),
        ] {
            digest.update(field.as_bytes());
            digest.update([0]);
        }
    }
    for alias in &config.aliases {
        for field in [
            alias.id.as_str(),
            alias.label.as_str(),
            alias.profile.as_str(),
            alias.project.as_str(),
            alias.location.as_deref().unwrap_or_default(),
            alias.secret.as_str(),
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
enum GcpFailure {
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
    SecretUnusable,
    ChecksumMismatch,
    InvalidResponse,
    InvalidMaterial,
    ProviderFailure,
}

impl GcpFailure {
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
            Self::SecretUnusable => "secret_unusable",
            Self::ChecksumMismatch => "checksum_mismatch",
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
            | Self::SecretUnusable => SecretResolveErrorKind::SourceUnavailable,
            Self::IdentityDenied | Self::ProviderDenied => SecretResolveErrorKind::SourceDenied,
            Self::EgressDenied | Self::RedirectRefused => SecretResolveErrorKind::UnsafeSource,
            Self::IdentityInvalid
            | Self::ChecksumMismatch
            | Self::InvalidResponse
            | Self::InvalidMaterial => SecretResolveErrorKind::InvalidMaterial,
            Self::ProviderFailure => SecretResolveErrorKind::ProviderFailure,
        }
    }

    const fn is_transient(self) -> bool {
        matches!(self, Self::ProviderUnavailable | Self::IdentityUnavailable)
    }
}

fn map_egress_error(error: &EgressError, identity: bool) -> GcpFailure {
    match error {
        EgressError::HostNotAllowed(_)
        | EgressError::PortNotAllowed(_)
        | EgressError::NonGlobalIpBlocked(_)
        | EgressError::SchemeNotAllowed(_)
        | EgressError::InvalidPolicy(_)
        | EgressError::InvalidUrl(_)
        | EgressError::InvalidTlsCaBundle { .. }
        | EgressError::InvalidTlsClientIdentity => GcpFailure::EgressDenied,
        EgressError::ResponseTooLarge { .. } => GcpFailure::InvalidResponse,
        EgressError::RequestBodyTooLarge { .. } | EgressError::RequestBodyReadFailed => {
            GcpFailure::IdentityInvalid
        }
        _ if identity => GcpFailure::IdentityUnavailable,
        _ => GcpFailure::ProviderUnavailable,
    }
}

fn classify_status(status: StatusCode, identity: bool) -> Option<GcpFailure> {
    if status == StatusCode::OK {
        return None;
    }
    if status.is_redirection() {
        return Some(GcpFailure::RedirectRefused);
    }
    Some(match status.as_u16() {
        400 | 401 | 403 if identity => GcpFailure::IdentityDenied,
        401 | 403 => GcpFailure::ProviderDenied,
        // Secret Manager reports disabled and destroyed versions as
        // FAILED_PRECONDITION on access; the error body is never parsed.
        400 => GcpFailure::SecretUnusable,
        404 if identity => GcpFailure::IdentityUnavailable,
        404 => GcpFailure::SecretAbsent,
        429 | 500..=599 if identity => GcpFailure::IdentityUnavailable,
        429 | 500..=599 => GcpFailure::ProviderUnavailable,
        _ if identity => GcpFailure::IdentityInvalid,
        _ => GcpFailure::InvalidResponse,
    })
}

fn request_headers(token: Option<&[u8]>) -> Result<HeaderMap, GcpFailure> {
    let mut headers = HeaderMap::new();
    headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    if let Some(token) = token {
        let mut bearer = Zeroizing::new(Vec::with_capacity(token.len() + 7));
        bearer.extend_from_slice(b"Bearer ");
        bearer.extend_from_slice(token);
        let mut value =
            HeaderValue::from_bytes(&bearer).map_err(|_| GcpFailure::IdentityInvalid)?;
        value.set_sensitive(true);
        headers.insert(AUTHORIZATION, value);
    }
    Ok(headers)
}

fn bounded_json_body(
    response: &GcpHttpResponse,
    maximum: usize,
    identity: bool,
) -> Result<&[u8], GcpFailure> {
    let invalid = if identity {
        GcpFailure::IdentityInvalid
    } else {
        GcpFailure::InvalidResponse
    };
    if !is_json_content_type(response.headers.get(CONTENT_TYPE)) {
        return Err(invalid);
    }
    if response.body.len() > maximum || response.body.is_empty() {
        return Err(invalid);
    }
    Ok(response.body.as_slice())
}

fn is_json_content_type(value: Option<&HeaderValue>) -> bool {
    value
        .and_then(|value| value.to_str().ok())
        .map(|value| value.split(';').next().unwrap_or_default().trim())
        .is_some_and(|value| value.eq_ignore_ascii_case("application/json"))
}

/// CRC-32C (Castagnoli), reflected polynomial `0x82F63B78`, implemented locally
/// so payload integrity verification adds no dependency.
const CRC32C_TABLE: [u32; 256] = build_crc32c_table();

const fn build_crc32c_table() -> [u32; 256] {
    let mut table = [0_u32; 256];
    let mut index = 0;
    while index < 256 {
        let mut crc = index as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0x82F6_3B78
            } else {
                crc >> 1
            };
            bit += 1;
        }
        table[index] = crc;
        index += 1;
    }
    table
}

fn crc32c(data: &[u8]) -> u32 {
    let mut crc = !0_u32;
    for byte in data {
        crc = (crc >> 8) ^ CRC32C_TABLE[((crc ^ u32::from(*byte)) & 0xFF) as usize];
    }
    !crc
}

/// Strict decimal parse with no sign, no leading zeros, and no surrounding
/// bytes; used for version numbers in returned resource names.
fn parse_strict_u64(value: &str) -> Option<u64> {
    if value.is_empty()
        || value.len() > 19
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return None;
    }
    value.parse().ok()
}

/// Strict parse of the proto3 int64-as-string checksum field.
fn parse_crc32c_field(value: &str) -> Option<u32> {
    u32::try_from(parse_strict_u64(value)?).ok()
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

fn take_validated_token(text: &mut SecretText) -> Result<Zeroizing<Vec<u8>>, GcpFailure> {
    let token = text.take_bytes();
    if token.is_empty() || token.len() > MAX_GCP_TOKEN_BYTES {
        return Err(GcpFailure::IdentityInvalid);
    }
    if token.iter().any(|byte| *byte < 0x21 || *byte > 0x7e) {
        return Err(GcpFailure::IdentityInvalid);
    }
    Ok(token)
}

#[derive(Deserialize)]
struct StsTokenResponse {
    access_token: SecretText,
    expires_in: u64,
    token_type: String,
}

#[derive(Deserialize)]
struct ImpersonationResponse {
    #[serde(rename = "accessToken")]
    access_token: SecretText,
}

#[derive(Deserialize)]
struct AccessSecretVersionResponse {
    name: String,
    payload: AccessSecretPayload,
}

#[derive(Deserialize)]
struct AccessSecretPayload {
    data: SecretText,
    #[serde(rename = "dataCrc32c")]
    data_crc32c: String,
}

impl AccessSecretVersionResponse {
    fn into_value(
        mut self,
        alias: &GcpAliasBinding,
        purpose: SecretPurpose,
    ) -> Result<Zeroizing<Vec<u8>>, GcpFailure> {
        if !response_name_matches(alias, &self.name) {
            return Err(GcpFailure::InvalidResponse);
        }
        let encoded = self.payload.data.take_bytes();
        let encoded = std::str::from_utf8(&encoded).map_err(|_| GcpFailure::InvalidMaterial)?;
        let decoded = Zeroizing::new(
            BASE64_STANDARD
                .decode(encoded)
                .map_err(|_| GcpFailure::InvalidMaterial)?,
        );
        let expected =
            parse_crc32c_field(&self.payload.data_crc32c).ok_or(GcpFailure::InvalidResponse)?;
        if crc32c(&decoded) != expected {
            return Err(GcpFailure::ChecksumMismatch);
        }
        if decoded.is_empty() || decoded.len() > purpose.max_bytes() || decoded.contains(&0) {
            return Err(GcpFailure::InvalidMaterial);
        }
        Ok(decoded)
    }
}

/// The returned resource name must match the alias binding exactly. The only
/// tolerated variation is Google's canonicalization of a configured project ID
/// to its numeric project number, which cannot be predicted from configuration.
fn response_name_matches(alias: &GcpAliasBinding, name: &str) -> bool {
    if name.len() > MAX_GCP_RESPONSE_NAME_BYTES {
        return false;
    }
    let mut segments = name.split('/');
    if segments.next() != Some("projects") {
        return false;
    }
    let Some(project) = segments.next() else {
        return false;
    };
    if let Some(location) = alias.location.as_deref() {
        if segments.next() != Some("locations") || segments.next() != Some(location) {
            return false;
        }
    }
    if segments.next() != Some("secrets")
        || segments.next() != Some(alias.secret.as_str())
        || segments.next() != Some("versions")
    {
        return false;
    }
    let Some(version) = segments.next() else {
        return false;
    };
    if segments.next().is_some() {
        return false;
    }
    let canonical_project_number =
        is_gcp_project_number(project) && !is_gcp_project_number(&alias.project);
    if project != alias.project && !canonical_project_number {
        return false;
    }
    let Some(version) = parse_strict_u64(version) else {
        return false;
    };
    if version == 0 {
        return false;
    }
    match alias.version {
        Some(pinned) => version == pinned,
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::atomic::{AtomicU64, Ordering},
    };

    use uuid::Uuid;

    use super::*;

    const VALUE_CANARY: &str = "greengateway-gcp-value-canary";
    const FEDERATED_TOKEN_CANARY: &str = "ya29.gcp-federated-token-canary";
    const IMPERSONATED_TOKEN_CANARY: &str = "ya29.gcp-impersonated-token-canary";
    const SUBJECT_JWT_CANARY: &str = "projected.gcp.jwt-canary";
    const AUDIENCE_CANARY: &str = "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/pool-locator-canary/providers/provider-locator-canary";
    const PROJECT_CANARY: &str = "project-locator-canary";
    const PROJECT_NUMBER_CANARY: &str = "987654321098";
    const SECRET_CANARY: &str = "secret-locator-canary";
    const LOCATION_CANARY: &str = "regional-canary1";
    const SERVICE_ACCOUNT_CANARY: &str =
        "impersonation-canary@project-locator-canary.iam.gserviceaccount.com";

    type Responder = dyn Fn() -> Result<GcpHttpResponse, EgressError> + Send + Sync;

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct RecordedRequest {
        method: String,
        url: String,
        authorization: Option<String>,
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

    struct FakeGcp {
        requests: Mutex<Vec<RecordedRequest>>,
        exchanges: Mutex<FakeChannel>,
        impersonations: Mutex<FakeChannel>,
        reads: Mutex<FakeChannel>,
        generation: AtomicU64,
        delay: Mutex<Duration>,
    }

    impl FakeGcp {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                requests: Mutex::new(Vec::new()),
                exchanges: Mutex::new(FakeChannel::default()),
                impersonations: Mutex::new(FakeChannel::default()),
                reads: Mutex::new(FakeChannel::default()),
                generation: AtomicU64::new(0),
                delay: Mutex::new(Duration::ZERO),
            })
        }

        fn push_exchange(&self, responder: Arc<Responder>) {
            self.exchanges
                .lock()
                .expect("fake exchange queue should lock")
                .queued
                .push_back(responder);
        }

        fn push_impersonation(&self, responder: Arc<Responder>) {
            self.impersonations
                .lock()
                .expect("fake impersonation queue should lock")
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
                .filter(|request| request.url.contains("secretmanager"))
                .collect()
        }

        fn exchanges(&self) -> Vec<RecordedRequest> {
            self.requests()
                .into_iter()
                .filter(|request| request.url.starts_with(GCP_STS_TOKEN_URL))
                .collect()
        }

        fn impersonations(&self) -> Vec<RecordedRequest> {
            self.requests()
                .into_iter()
                .filter(|request| request.url.contains(":generateAccessToken"))
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
    impl GcpTransport for FakeGcp {
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
        ) -> Result<GcpHttpResponse, EgressError> {
            self.requests
                .lock()
                .expect("fake request log should lock")
                .push(RecordedRequest {
                    method: method.to_string(),
                    url: url.to_owned(),
                    authorization: headers
                        .get(AUTHORIZATION)
                        .and_then(|value| value.to_str().ok())
                        .map(str::to_owned),
                    body: body.map(|body| String::from_utf8_lossy(&body).into_owned()),
                });
            let delay = *self.delay.lock().expect("fake delay should lock");
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            let queue = if url.starts_with(GCP_STS_TOKEN_URL) {
                &self.exchanges
            } else if url.contains(":generateAccessToken") {
                &self.impersonations
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
            Ok(GcpHttpResponse {
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

    fn exchange_body(token: &str, expires: u64) -> String {
        format!(
            r#"{{"access_token":"{token}","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":{expires}}}"#
        )
    }

    fn impersonation_body(token: &str) -> String {
        format!(r#"{{"accessToken":"{token}","expireTime":"2026-01-01T00:10:00Z"}}"#)
    }

    fn version_name(version: u64) -> String {
        format!("projects/{PROJECT_CANARY}/secrets/{SECRET_CANARY}/versions/{version}")
    }

    fn access_body_with_crc(name: &str, value: &[u8], crc: &str) -> String {
        let data = BASE64_STANDARD.encode(value);
        format!(r#"{{"name":"{name}","payload":{{"data":"{data}","dataCrc32c":"{crc}"}}}}"#)
    }

    fn access_body(name: &str, value: &[u8]) -> String {
        access_body_with_crc(name, value, &crc32c(value).to_string())
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

    impl GcpClock for TestClock {
        fn now(&self) -> Instant {
            *self.now.lock().expect("test clock should lock")
        }
    }

    struct TemporaryTokenRoot {
        root: PathBuf,
    }

    impl TemporaryTokenRoot {
        fn new() -> Self {
            let root =
                std::env::temp_dir().join(format!("greengateway-gcp-workload-{}", Uuid::new_v4()));
            fs::create_dir(&root).expect("workload token root should create");
            set_directory_permissions(&root, 0o755);
            let token_path = root.join("token");
            fs::write(&token_path, SUBJECT_JWT_CANARY.as_bytes())
                .expect("workload token should write");
            set_file_permissions(&token_path, 0o644);
            Self { root }
        }

        fn path(&self) -> String {
            self.root
                .to_str()
                .expect("workload token root should be Unicode")
                .to_owned()
        }
    }

    impl Drop for TemporaryTokenRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[cfg(unix)]
    fn set_directory_permissions(path: &std::path::Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .expect("directory permissions should update");
    }

    #[cfg(not(unix))]
    fn set_directory_permissions(_: &std::path::Path, _: u32) {}

    #[cfg(unix)]
    fn set_file_permissions(path: &std::path::Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .expect("file permissions should update");
    }

    #[cfg(not(unix))]
    fn set_file_permissions(_: &std::path::Path, _: u32) {}

    fn profile(id: &str, token_root: &str, service_account: Option<&str>) -> GcpProfileConfig {
        GcpProfileConfig {
            id: id.to_owned(),
            audience: AUDIENCE_CANARY.to_owned(),
            token_root: token_root.to_owned(),
            token_file: "token".to_owned(),
            service_account: service_account.map(str::to_owned),
        }
    }

    fn alias(id: &str, version: Option<u64>) -> GcpSecretAliasConfig {
        GcpSecretAliasConfig {
            id: id.to_owned(),
            label: format!("{id} label"),
            profile: "primary".to_owned(),
            project: PROJECT_CANARY.to_owned(),
            location: None,
            secret: SECRET_CANARY.to_owned(),
            version,
        }
    }

    struct ProviderFixture {
        provider: GcpSecretManagerProvider,
        gcp: Arc<FakeGcp>,
        clock: Arc<TestClock>,
        _token_root: TemporaryTokenRoot,
    }

    fn provider(aliases: Vec<GcpSecretAliasConfig>) -> ProviderFixture {
        let token_root = TemporaryTokenRoot::new();
        let config = GcpProviderConfig {
            profiles: vec![profile("primary", &token_root.path(), None)],
            aliases,
        };
        provider_with(config, token_root)
    }

    fn impersonating_provider(aliases: Vec<GcpSecretAliasConfig>) -> ProviderFixture {
        let token_root = TemporaryTokenRoot::new();
        let config = GcpProviderConfig {
            profiles: vec![profile(
                "primary",
                &token_root.path(),
                Some(SERVICE_ACCOUNT_CANARY),
            )],
            aliases,
        };
        provider_with(config, token_root)
    }

    fn provider_with(config: GcpProviderConfig, token_root: TemporaryTokenRoot) -> ProviderFixture {
        let gcp = FakeGcp::new();
        let clock = TestClock::new();
        let mut provider = GcpSecretManagerProvider::from_config(
            &config,
            &BTreeSet::new(),
            Arc::clone(&gcp) as Arc<dyn GcpTransport>,
        )
        .expect("test provider should build");
        provider.clock = Arc::clone(&clock) as Arc<dyn GcpClock>;
        ProviderFixture {
            provider,
            gcp,
            clock,
            _token_root: token_root,
        }
    }

    #[test]
    fn crc32c_matches_known_answer_vectors() {
        assert_eq!(crc32c(b""), 0);
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
        assert_eq!(crc32c(&[0_u8; 32]), 0x8A91_36AA);
        assert_eq!(crc32c(&[0xFF_u8; 32]), 0x62A8_AB43);
        let ascending = (0..32).collect::<Vec<u8>>();
        assert_eq!(crc32c(&ascending), 0x46DD_794E);
    }

    #[test]
    fn checksum_field_parsing_is_strict() {
        assert_eq!(parse_crc32c_field("0"), Some(0));
        assert_eq!(parse_crc32c_field("3808858755"), Some(0xE306_9283));
        assert_eq!(parse_crc32c_field("4294967295"), Some(u32::MAX));
        for invalid in [
            "",
            "+1",
            "-1",
            "01",
            "1 ",
            " 1",
            "4294967296",
            "18446744073709551616",
            "0x10",
            "1e3",
        ] {
            assert_eq!(
                parse_crc32c_field(invalid),
                None,
                "{invalid:?} must be rejected"
            );
        }
    }

    #[test]
    fn configuration_rejects_unsafe_or_ambiguous_entries() {
        let base = |profiles: Vec<GcpProfileConfig>, aliases: Vec<GcpSecretAliasConfig>| {
            validate_gcp_provider_config(&GcpProviderConfig { profiles, aliases }, &BTreeSet::new())
        };
        let root = "/var/run/secrets/tokens";
        for audience in [
            "",
            "https://iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/pool-name/providers/provider-name",
            "//iam.googleapis.com/projects/abc/locations/global/workloadIdentityPools/pool-name/providers/provider-name",
            "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/pool-name",
            "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/POOL/providers/provider-name",
            "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/pool-name/providers/provider-name/extra",
            "//iam.googleapis.com/projects/1/locations/../workloadIdentityPools/pool-name/providers/provider-name",
            "//evil.example/projects/1/locations/global/workloadIdentityPools/pool-name/providers/provider-name",
        ] {
            let mut entry = profile("primary", root, None);
            entry.audience = audience.to_owned();
            assert!(
                matches!(
                    base(vec![entry], Vec::new()),
                    Err(GcpProviderConfigError::InvalidAudience { .. })
                ),
                "{audience:?} must be rejected"
            );
        }
        for account in [
            "",
            "user@gmail.com",
            "sa@project.iam.gserviceaccount.com.evil.example",
            "123456-compute@developer.gserviceaccount.com",
            "sa name@project-locator-canary.iam.gserviceaccount.com",
            "Sa@project-locator-canary.iam.gserviceaccount.com",
            "sa@sa@project-locator-canary.iam.gserviceaccount.com",
            "impersonation-canary@ab.iam.gserviceaccount.com",
        ] {
            let mut entry = profile("primary", root, None);
            entry.service_account = Some(account.to_owned());
            assert!(
                matches!(
                    base(vec![entry], Vec::new()),
                    Err(GcpProviderConfigError::InvalidServiceAccount { .. })
                ),
                "{account:?} must be rejected"
            );
        }
        for token_file in ["../token", "nested/token", "", "NUL", "trailing."] {
            let mut entry = profile("primary", root, None);
            entry.token_file = token_file.to_owned();
            assert!(
                matches!(
                    base(vec![entry], Vec::new()),
                    Err(GcpProviderConfigError::InvalidWorkloadTokenFile { .. })
                ),
                "{token_file:?} must be rejected"
            );
        }
        let mut empty_root = profile("primary", root, None);
        empty_root.token_root = String::new();
        assert!(matches!(
            base(vec![empty_root], Vec::new()),
            Err(GcpProviderConfigError::InvalidWorkloadTokenRoot { .. })
        ));
        for project in [
            "",
            "UPPER",
            "0123456789",
            "-leading-hyphen",
            "trailing-hyphen-",
            "short",
            "a-project-id-that-is-far-too-long-for-gcp",
            "under_score",
            "1数字",
        ] {
            let mut entry = alias("billing", None);
            entry.project = project.to_owned();
            assert!(
                matches!(
                    base(vec![profile("primary", root, None)], vec![entry]),
                    Err(GcpProviderConfigError::InvalidProject { .. })
                ),
                "{project:?} must be rejected"
            );
        }
        for location in ["", "US-EAST1", "-east1", "east1-", "location/../escape"] {
            let mut entry = alias("billing", None);
            entry.location = Some(location.to_owned());
            assert!(
                matches!(
                    base(vec![profile("primary", root, None)], vec![entry]),
                    Err(GcpProviderConfigError::InvalidLocation { .. })
                ),
                "{location:?} must be rejected"
            );
        }
        for secret in ["", "spaced secret", "path/secret", "secret?x=1", "sécrete"] {
            let mut entry = alias("billing", None);
            entry.secret = secret.to_owned();
            assert!(
                matches!(
                    base(vec![profile("primary", root, None)], vec![entry]),
                    Err(GcpProviderConfigError::InvalidSecretId { .. })
                ),
                "{secret:?} must be rejected"
            );
        }
        assert!(matches!(
            base(
                vec![profile("primary", root, None)],
                vec![alias("billing", Some(0))],
            ),
            Err(GcpProviderConfigError::InvalidVersion { .. })
        ));
        let mut duplicate = alias("billing", None);
        duplicate.id = "billing".to_owned();
        assert!(matches!(
            base(
                vec![profile("primary", root, None)],
                vec![alias("billing", None), duplicate],
            ),
            Err(GcpProviderConfigError::DuplicateAliasId { .. })
        ));
        let mut unknown_profile = alias("billing", None);
        unknown_profile.profile = "missing".to_owned();
        assert!(matches!(
            base(vec![profile("primary", root, None)], vec![unknown_profile]),
            Err(GcpProviderConfigError::UnknownProfile { .. })
        ));
        assert!(matches!(
            base(
                vec![
                    profile("primary", root, None),
                    profile("primary", root, None)
                ],
                Vec::new()
            ),
            Err(GcpProviderConfigError::DuplicateProfileId { .. })
        ));
        let mut invalid_profile_id = profile("primary", root, None);
        invalid_profile_id.id = "../escape".to_owned();
        assert!(matches!(
            base(vec![invalid_profile_id], Vec::new()),
            Err(GcpProviderConfigError::InvalidProfileId { .. })
        ));
        let mut invalid_label = alias("billing", None);
        invalid_label.label = "bad\u{0000}label".to_owned();
        assert!(matches!(
            base(vec![profile("primary", root, None)], vec![invalid_label]),
            Err(GcpProviderConfigError::InvalidLabel { .. })
        ));
        assert!(matches!(
            base(Vec::new(), vec![alias("billing", None)]),
            Err(GcpProviderConfigError::AliasesWithoutProfiles)
        ));
        assert!(matches!(
            validate_gcp_provider_config(
                &GcpProviderConfig {
                    profiles: vec![profile("primary", root, None)],
                    aliases: vec![alias("billing", None)],
                },
                &BTreeSet::from(["billing".to_owned()]),
            ),
            Err(GcpProviderConfigError::ReservedAliasId { .. })
        ));
        let profiles = (0..=MAX_GCP_PROFILES)
            .map(|index| profile(&format!("profile-{index}"), root, None))
            .collect::<Vec<_>>();
        assert!(matches!(
            base(profiles, Vec::new()),
            Err(GcpProviderConfigError::TooManyProfiles { .. })
        ));
    }

    #[tokio::test]
    async fn unknown_alias_denial_produces_zero_provider_work() {
        let fixture = provider(vec![alias("billing", None)]);
        fixture.gcp.push_exchange(json_response(
            200,
            &exchange_body(FEDERATED_TOKEN_CANARY, 600),
        ));
        fixture.gcp.push_read(json_response(
            200,
            &access_body(&version_name(4), VALUE_CANARY.as_bytes()),
        ));

        let error = fixture
            .provider
            .resolve("not-configured", SecretPurpose::StaticBearer)
            .await
            .expect_err("unknown alias must fail closed");

        assert_eq!(error.kind(), SecretResolveErrorKind::UnknownAlias);
        assert!(fixture.gcp.requests().is_empty());
    }

    #[tokio::test]
    async fn saturated_provider_admission_fails_before_any_provider_work() {
        let fixture = provider(vec![alias("billing", None)]);
        fixture.gcp.push_exchange(json_response(
            200,
            &exchange_body(FEDERATED_TOKEN_CANARY, 600),
        ));
        fixture.gcp.push_read(json_response(
            200,
            &access_body(&version_name(4), VALUE_CANARY.as_bytes()),
        ));
        let mut provider = fixture.provider.clone();
        provider.concurrent_reads = Arc::new(Semaphore::new(0));

        let error = provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect_err("saturated admission must fail closed");

        assert_eq!(error.kind(), SecretResolveErrorKind::ProviderBusy);
        assert!(fixture.gcp.requests().is_empty());
    }

    #[tokio::test]
    async fn reads_authenticate_first_and_target_only_the_access_operation() {
        let fixture = provider(vec![alias("billing", None)]);
        fixture.gcp.push_exchange(json_response(
            200,
            &exchange_body(FEDERATED_TOKEN_CANARY, 600),
        ));
        fixture.gcp.push_read(json_response(
            200,
            &access_body(&version_name(7), VALUE_CANARY.as_bytes()),
        ));

        let secret = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("configured alias should resolve");

        assert_eq!(secret.expose(), VALUE_CANARY.as_bytes());
        let requests = fixture.gcp.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].method, "POST");
        assert_eq!(requests[0].url, GCP_STS_TOKEN_URL);
        assert!(requests[0].authorization.is_none());
        let exchange = requests[0].body.as_deref().unwrap_or_default();
        assert!(exchange.contains(GCP_TOKEN_EXCHANGE_GRANT_TYPE));
        assert!(exchange.contains(AUDIENCE_CANARY));
        assert!(exchange.contains(SUBJECT_JWT_CANARY));
        assert!(exchange.contains(GCP_CLOUD_PLATFORM_SCOPE));
        assert_eq!(requests[1].method, "GET");
        assert_eq!(
            requests[1].url,
            format!(
                "https://secretmanager.googleapis.com/v1/projects/{PROJECT_CANARY}/secrets/{SECRET_CANARY}/versions/latest:access"
            )
        );
        assert_eq!(
            requests[1].authorization.as_deref(),
            Some(format!("Bearer {FEDERATED_TOKEN_CANARY}").as_str())
        );
        for request in &requests {
            assert!(request.url.starts_with("https://"));
            assert!(!request.url.contains("metadata.google.internal"));
            assert!(!request.url.contains(":destroy"));
            assert!(!request.url.contains(":disable"));
            assert!(!request.url.contains(":addVersion"));
            assert!(request.method == "GET" || request.method == "POST");
        }
    }

    #[tokio::test]
    async fn impersonation_exchanges_the_federated_token_for_a_bounded_grant() {
        let fixture = impersonating_provider(vec![alias("billing", None)]);
        fixture.gcp.push_exchange(json_response(
            200,
            &exchange_body(FEDERATED_TOKEN_CANARY, 3600),
        ));
        fixture.gcp.push_impersonation(json_response(
            200,
            &impersonation_body(IMPERSONATED_TOKEN_CANARY),
        ));
        fixture.gcp.push_read(json_response(
            200,
            &access_body(&version_name(2), VALUE_CANARY.as_bytes()),
        ));

        let secret = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("impersonating profile should resolve");

        assert_eq!(secret.expose(), VALUE_CANARY.as_bytes());
        let requests = fixture.gcp.requests();
        assert_eq!(requests.len(), 3);
        assert_eq!(
            requests[1].url,
            format!(
                "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{SERVICE_ACCOUNT_CANARY}:generateAccessToken"
            )
        );
        assert_eq!(
            requests[1].authorization.as_deref(),
            Some(format!("Bearer {FEDERATED_TOKEN_CANARY}").as_str())
        );
        let impersonation = requests[1].body.as_deref().unwrap_or_default();
        assert!(impersonation.contains(GCP_IMPERSONATION_LIFETIME_FIELD));
        assert!(impersonation.contains(GCP_CLOUD_PLATFORM_SCOPE));
        assert_eq!(
            requests[2].authorization.as_deref(),
            Some(format!("Bearer {IMPERSONATED_TOKEN_CANARY}").as_str())
        );
    }

    #[tokio::test]
    async fn a_denied_identity_exchange_stops_before_any_secret_read() {
        for responder in [
            json_response(403, r#"{"error":"access_denied"}"#),
            json_response(400, r#"{"error":"invalid_grant"}"#),
        ] {
            let fixture = provider(vec![alias("billing", None)]);
            fixture.gcp.push_exchange(responder);
            fixture.gcp.push_read(json_response(
                200,
                &access_body(&version_name(1), VALUE_CANARY.as_bytes()),
            ));

            let error = fixture
                .provider
                .resolve("billing", SecretPurpose::StaticBearer)
                .await
                .expect_err("a denied identity must fail closed");

            assert_eq!(error.kind(), SecretResolveErrorKind::SourceDenied);
            assert!(fixture.gcp.reads().is_empty());
        }
    }

    #[tokio::test]
    async fn a_denied_impersonation_stops_before_any_secret_read() {
        let fixture = impersonating_provider(vec![alias("billing", None)]);
        fixture.gcp.push_exchange(json_response(
            200,
            &exchange_body(FEDERATED_TOKEN_CANARY, 600),
        ));
        fixture
            .gcp
            .push_impersonation(json_response(403, r#"{"error":{"code":403}}"#));
        fixture.gcp.push_read(json_response(
            200,
            &access_body(&version_name(1), VALUE_CANARY.as_bytes()),
        ));

        let error = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect_err("a denied impersonation must fail closed");

        assert_eq!(error.kind(), SecretResolveErrorKind::SourceDenied);
        assert!(fixture.gcp.reads().is_empty());
    }

    #[tokio::test]
    async fn egress_denials_and_refused_redirects_fail_closed() {
        for (responder, expected) in [
            (
                egress_failure(|| EgressError::HostNotAllowed("secretmanager".to_owned())),
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
            fixture.gcp.push_exchange(json_response(
                200,
                &exchange_body(FEDERATED_TOKEN_CANARY, 600),
            ));
            fixture.gcp.push_read(responder);

            let error = fixture
                .provider
                .resolve("billing", SecretPurpose::StaticBearer)
                .await
                .expect_err("egress denial must fail closed");

            assert_eq!(error.kind(), expected);
            assert_eq!(fixture.gcp.reads().len(), 1);
        }
    }

    #[tokio::test]
    async fn dns_failure_retries_once_and_then_fails_closed() {
        let fixture = provider(vec![alias("billing", None)]);
        fixture.gcp.push_exchange(json_response(
            200,
            &exchange_body(FEDERATED_TOKEN_CANARY, 600),
        ));
        fixture.gcp.push_read(egress_failure(|| {
            EgressError::DnsResolutionFailed("secretmanager".to_owned())
        }));

        let error = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect_err("unreachable provider must fail closed");

        assert_eq!(error.kind(), SecretResolveErrorKind::SourceUnavailable);
        assert_eq!(
            fixture.gcp.reads().len(),
            usize::try_from(MAX_GCP_TRANSIENT_RETRIES).expect("retry bound should fit") + 1
        );
    }

    #[tokio::test]
    async fn a_denied_read_reauthenticates_exactly_once() {
        let fixture = provider(vec![alias("billing", None)]);
        fixture.gcp.push_exchange(json_response(
            200,
            &exchange_body("ya29.first-token-canary", 600),
        ));
        fixture.gcp.push_exchange(json_response(
            200,
            &exchange_body(FEDERATED_TOKEN_CANARY, 600),
        ));
        fixture
            .gcp
            .push_read(json_response(403, r#"{"error":{"code":403}}"#));
        fixture.gcp.push_read(json_response(
            200,
            &access_body(&version_name(9), VALUE_CANARY.as_bytes()),
        ));

        let secret = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("a rotated identity should recover once");

        assert_eq!(secret.expose(), VALUE_CANARY.as_bytes());
        assert_eq!(fixture.gcp.exchanges().len(), 2);
        let reads = fixture.gcp.reads();
        assert_eq!(reads.len(), 2);
        assert_eq!(
            reads[0].authorization.as_deref(),
            Some("Bearer ya29.first-token-canary")
        );
        assert_eq!(
            reads[1].authorization.as_deref(),
            Some(format!("Bearer {FEDERATED_TOKEN_CANARY}").as_str())
        );
    }

    #[tokio::test]
    async fn newly_denied_access_fails_closed_without_a_stale_value() {
        let fixture = provider(vec![alias("billing", None)]);
        fixture.gcp.push_exchange(json_response(
            200,
            &exchange_body(FEDERATED_TOKEN_CANARY, 3600),
        ));
        fixture.gcp.push_read(json_response(
            200,
            &access_body(&version_name(3), VALUE_CANARY.as_bytes()),
        ));
        let first = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("first read should resolve");
        assert_eq!(first.expose(), VALUE_CANARY.as_bytes());

        fixture
            .gcp
            .push_read(json_response(403, r#"{"error":{"code":403}}"#));
        fixture.clock.advance(GCP_VALUE_CACHE_TTL * 2);

        let error = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect_err("newly denied access must fail closed");

        assert_eq!(error.kind(), SecretResolveErrorKind::SourceDenied);
        assert!(fixture.provider.value_guard().is_empty());
    }

    #[tokio::test]
    async fn disabled_destroyed_and_absent_versions_fail_closed_without_retry() {
        for (responder, expected) in [
            (
                // DISABLED and DESTROYED versions both surface as
                // FAILED_PRECONDITION on AccessSecretVersion.
                json_response(
                    400,
                    r#"{"error":{"code":400,"status":"FAILED_PRECONDITION"}}"#,
                ),
                SecretResolveErrorKind::SourceUnavailable,
            ),
            (
                json_response(404, r#"{"error":{"code":404,"status":"NOT_FOUND"}}"#),
                SecretResolveErrorKind::SourceUnavailable,
            ),
        ] {
            let fixture = provider(vec![alias("billing", None)]);
            fixture.gcp.push_exchange(json_response(
                200,
                &exchange_body(FEDERATED_TOKEN_CANARY, 600),
            ));
            fixture.gcp.push_read(responder);

            let error = fixture
                .provider
                .resolve("billing", SecretPurpose::StaticBearer)
                .await
                .expect_err("unusable versions must fail closed");

            assert_eq!(error.kind(), expected);
            assert_eq!(fixture.gcp.reads().len(), 1);
            assert!(fixture.provider.value_guard().is_empty());
        }
    }

    #[tokio::test]
    async fn a_corrupted_checksum_fails_closed() {
        let value = VALUE_CANARY.as_bytes();
        let wrong = crc32c(value).wrapping_add(1).to_string();
        let fixture = provider(vec![alias("billing", None)]);
        fixture.gcp.push_exchange(json_response(
            200,
            &exchange_body(FEDERATED_TOKEN_CANARY, 600),
        ));
        fixture.gcp.push_read(json_response(
            200,
            &access_body_with_crc(&version_name(4), value, &wrong),
        ));

        let error = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect_err("a corrupted checksum must fail closed");

        assert_eq!(error.kind(), SecretResolveErrorKind::InvalidMaterial);
        assert!(fixture.provider.value_guard().is_empty());
    }

    #[tokio::test]
    async fn a_response_for_a_different_resource_fails_closed() {
        for name in [
            format!("projects/{PROJECT_CANARY}/secrets/other-secret/versions/4"),
            format!("projects/other-project/secrets/{SECRET_CANARY}/versions/4"),
            format!("projects/{PROJECT_CANARY}/locations/{LOCATION_CANARY}/secrets/{SECRET_CANARY}/versions/4"),
            format!("projects/{PROJECT_CANARY}/secrets/{SECRET_CANARY}/versions/04"),
            format!("projects/{PROJECT_CANARY}/secrets/{SECRET_CANARY}/versions/latest"),
            format!("projects/{PROJECT_CANARY}/secrets/{SECRET_CANARY}/versions/4/extra"),
            "not-a-resource-name".to_owned(),
        ] {
            let fixture = provider(vec![alias("billing", None)]);
            fixture
                .gcp
                .push_exchange(json_response(200, &exchange_body(FEDERATED_TOKEN_CANARY, 600)));
            fixture
                .gcp
                .push_read(json_response(200, &access_body(&name, VALUE_CANARY.as_bytes())));

            let error = fixture
                .provider
                .resolve("billing", SecretPurpose::StaticBearer)
                .await
                .expect_err("a mismatched resource name must fail closed");

            assert_eq!(
                error.kind(),
                SecretResolveErrorKind::InvalidMaterial,
                "{name:?} must be rejected"
            );
            assert!(fixture.provider.value_guard().is_empty());
        }
    }

    #[tokio::test]
    async fn the_canonical_project_number_is_accepted_for_a_configured_project_id() {
        let fixture = provider(vec![alias("billing", None)]);
        fixture.gcp.push_exchange(json_response(
            200,
            &exchange_body(FEDERATED_TOKEN_CANARY, 600),
        ));
        let name = format!("projects/{PROJECT_NUMBER_CANARY}/secrets/{SECRET_CANARY}/versions/4");
        fixture.gcp.push_read(json_response(
            200,
            &access_body(&name, VALUE_CANARY.as_bytes()),
        ));

        let secret = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("a canonicalized project number should be accepted");

        assert_eq!(secret.expose(), VALUE_CANARY.as_bytes());
    }

    #[tokio::test]
    async fn regional_aliases_use_the_regional_endpoint_and_validate_the_location() {
        let mut regional = alias("billing", None);
        regional.location = Some(LOCATION_CANARY.to_owned());
        let fixture = provider(vec![regional]);
        fixture.gcp.push_exchange(json_response(
            200,
            &exchange_body(FEDERATED_TOKEN_CANARY, 600),
        ));
        let name = format!(
            "projects/{PROJECT_CANARY}/locations/{LOCATION_CANARY}/secrets/{SECRET_CANARY}/versions/4"
        );
        fixture.gcp.push_read(json_response(
            200,
            &access_body(&name, VALUE_CANARY.as_bytes()),
        ));

        let secret = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("regional alias should resolve");

        assert_eq!(secret.expose(), VALUE_CANARY.as_bytes());
        let reads = fixture.gcp.reads();
        assert_eq!(
            reads[0].url,
            format!(
                "https://secretmanager.{LOCATION_CANARY}.rep.googleapis.com/v1/projects/{PROJECT_CANARY}/locations/{LOCATION_CANARY}/secrets/{SECRET_CANARY}/versions/latest:access"
            )
        );

        fixture.clock.advance(GCP_VALUE_CACHE_TTL * 2);
        fixture.gcp.push_read(json_response(
            200,
            &access_body(&version_name(4), VALUE_CANARY.as_bytes()),
        ));
        let error = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect_err("a global name for a regional alias must fail closed");
        assert_eq!(error.kind(), SecretResolveErrorKind::InvalidMaterial);
    }

    #[tokio::test]
    async fn non_canonical_base64_and_malformed_payloads_fail_closed() {
        let name = version_name(1);
        let valid = BASE64_STANDARD.encode(VALUE_CANARY.as_bytes());
        let crc = crc32c(VALUE_CANARY.as_bytes()).to_string();
        let empty_crc = crc32c(b"").to_string();
        let payload = |data: &str, crc: &str| {
            format!(r#"{{"name":"{name}","payload":{{"data":"{data}","dataCrc32c":"{crc}"}}}}"#)
        };
        let oversized_body = format!(
            r#"{{"warnings":["{}"],"name":"{name}","payload":{{"data":"{valid}","dataCrc32c":"{crc}"}}}}"#,
            "w".repeat(MAX_GCP_ACCESS_RESPONSE_BYTES)
        );
        let numeric_crc =
            format!(r#"{{"name":"{name}","payload":{{"data":"{valid}","dataCrc32c":{crc}}}}}"#);
        let missing_crc = format!(r#"{{"name":"{name}","payload":{{"data":"{valid}"}}}}"#);
        let oversized_value = BASE64_STANDARD.encode(vec![
            b'x';
            super::super::secret::MAX_HTTP_CREDENTIAL_BYTES
                + 1
        ]);
        let oversized_crc = crc32c(&vec![
            b'x';
            super::super::secret::MAX_HTTP_CREDENTIAL_BYTES + 1
        ])
        .to_string();
        let nul_value = BASE64_STANDARD.encode(b"nul\0value");
        let nul_crc = crc32c(b"nul\0value").to_string();
        for responder in [
            json_response(200, "{not json"),
            json_response(200, r#"{"name":"x"}"#),
            json_response(200, &oversized_body),
            response(
                200,
                "text/html",
                &access_body(&name, VALUE_CANARY.as_bytes()),
            ),
            json_response(200, &numeric_crc),
            json_response(200, &missing_crc),
            json_response(200, &payload("&&&&", &crc)),
            json_response(200, &payload("QQ=", "1997036262")),
            json_response(200, &payload(&format!("{valid} "), &crc)),
            json_response(200, &payload(&format!("{valid}\n"), &crc)),
            json_response(200, &payload("", &empty_crc)),
            json_response(200, &payload(&oversized_value, &oversized_crc)),
            json_response(200, &payload(&nul_value, &nul_crc)),
            json_response(200, &payload(&valid, "not-a-number")),
            json_response(200, &payload(&valid, "+1")),
        ] {
            let fixture = provider(vec![alias("billing", None)]);
            fixture.gcp.push_exchange(json_response(
                200,
                &exchange_body(FEDERATED_TOKEN_CANARY, 600),
            ));
            fixture.gcp.push_read(responder);

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
    async fn an_invalid_identity_exchange_response_is_rejected() {
        let oversized_token = "x".repeat(MAX_GCP_TOKEN_BYTES + 1);
        for responder in [
            json_response(200, &exchange_body(FEDERATED_TOKEN_CANARY, 0)),
            json_response(
                200,
                r#"{"access_token":"","token_type":"Bearer","expires_in":600}"#,
            ),
            json_response(200, &exchange_body(&oversized_token, 600)),
            json_response(200, &exchange_body("bad token\u{7f}", 600)),
            json_response(
                200,
                r#"{"access_token":"ya29.token","token_type":"MAC","expires_in":600}"#,
            ),
            json_response(200, "{not json"),
            response(200, "text/plain", "raw-token"),
        ] {
            let fixture = provider(vec![alias("billing", None)]);
            fixture.gcp.push_exchange(responder);
            fixture.gcp.push_read(json_response(
                200,
                &access_body(&version_name(1), VALUE_CANARY.as_bytes()),
            ));

            let error = fixture
                .provider
                .resolve("billing", SecretPurpose::StaticBearer)
                .await
                .expect_err("an invalid identity exchange must fail closed");

            assert_eq!(error.kind(), SecretResolveErrorKind::InvalidMaterial);
            assert!(fixture.gcp.reads().is_empty());
        }
    }

    #[tokio::test]
    async fn latest_aliases_observe_the_next_version_after_cache_expiry() {
        let fixture = provider(vec![alias("billing", None)]);
        fixture.gcp.push_exchange(json_response(
            200,
            &exchange_body(FEDERATED_TOKEN_CANARY, 3600),
        ));
        fixture.gcp.push_read(json_response(
            200,
            &access_body(&version_name(4), b"first-value"),
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
        assert_eq!(fixture.gcp.reads().len(), 1);

        fixture.gcp.push_read(json_response(
            200,
            &access_body(&version_name(5), b"second-value"),
        ));
        fixture
            .clock
            .advance(GCP_VALUE_CACHE_TTL + Duration::from_secs(1));

        let rotated = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("rotated read should resolve");

        assert_eq!(rotated.expose(), b"second-value");
        let reads = fixture.gcp.reads();
        assert_eq!(reads.len(), 2);
        assert!(reads
            .iter()
            .all(|request| request.url.ends_with("/versions/latest:access")));
        assert_eq!(first.expose(), b"first-value");
    }

    #[tokio::test]
    async fn pinned_aliases_stay_pinned_and_reject_a_different_version() {
        let fixture = provider(vec![alias("billing", Some(3))]);
        fixture.gcp.push_exchange(json_response(
            200,
            &exchange_body(FEDERATED_TOKEN_CANARY, 3600),
        ));
        fixture.gcp.push_read(json_response(
            200,
            &access_body(&version_name(3), b"pinned-value"),
        ));

        let pinned = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("pinned read should resolve");
        assert_eq!(pinned.expose(), b"pinned-value");
        let reads = fixture.gcp.reads();
        assert!(reads[0].url.ends_with("/versions/3:access"));

        fixture.gcp.push_read(json_response(
            200,
            &access_body(&version_name(4), b"newer-value"),
        ));
        fixture.clock.advance(GCP_VALUE_CACHE_TTL * 2);

        let error = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect_err("a pinned alias must refuse a different version");

        assert_eq!(error.kind(), SecretResolveErrorKind::InvalidMaterial);
        assert!(fixture
            .gcp
            .reads()
            .iter()
            .all(|request| request.url.ends_with("/versions/3:access")));
    }

    #[tokio::test]
    async fn tokens_are_reused_within_and_reexchanged_after_the_expiry_margin() {
        let fixture = provider(vec![alias("billing", None)]);
        fixture.gcp.push_exchange(json_response(
            200,
            &exchange_body(FEDERATED_TOKEN_CANARY, 600),
        ));
        fixture.gcp.push_read(json_response(
            200,
            &access_body(&version_name(1), VALUE_CANARY.as_bytes()),
        ));
        fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("first read should resolve");
        assert_eq!(fixture.gcp.exchanges().len(), 1);

        // Within the token lifetime minus the refresh margin: no new exchange.
        fixture.clock.advance(Duration::from_secs(120));
        fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("second read should resolve");
        assert_eq!(fixture.gcp.exchanges().len(), 1);
        assert_eq!(fixture.gcp.reads().len(), 2);

        // Beyond 600s - 30s margin: the cached token is refused and one fresh
        // exchange happens before the next read.
        fixture.clock.advance(Duration::from_secs(460));
        fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("third read should resolve");
        assert_eq!(fixture.gcp.exchanges().len(), 2);
        assert_eq!(fixture.gcp.reads().len(), 3);
    }

    #[tokio::test]
    async fn a_rotated_identity_invalidates_previously_cached_values() {
        let fixture = provider(vec![alias("billing", None)]);
        fixture.gcp.push_exchange(json_response(
            200,
            &exchange_body(FEDERATED_TOKEN_CANARY, 3600),
        ));
        fixture.gcp.push_read(json_response(
            200,
            &access_body(&version_name(1), VALUE_CANARY.as_bytes()),
        ));
        fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("first read should resolve");
        assert_eq!(fixture.provider.value_guard().len(), 1);

        fixture.provider.invalidate_token("primary");
        fixture.provider.store_token(
            "primary",
            Zeroizing::new(b"ya29.rotated-token".to_vec()),
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
        fixture.gcp.push_exchange(json_response(
            200,
            &exchange_body(FEDERATED_TOKEN_CANARY, 3600),
        ));
        fixture.gcp.push_read(json_response(
            200,
            &access_body(&version_name(1), VALUE_CANARY.as_bytes()),
        ));
        fixture.gcp.set_delay(Duration::from_millis(250));
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
        fixture.gcp.push_exchange(json_response(
            200,
            &exchange_body(FEDERATED_TOKEN_CANARY, 3600),
        ));
        fixture.gcp.push_read(json_response(
            200,
            &access_body(&version_name(1), VALUE_CANARY.as_bytes()),
        ));
        fixture.gcp.set_delay(Duration::from_secs(30));
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
        let aliases = (0..MAX_GCP_VALUE_CACHE_ENTRIES + 4)
            .map(|index| alias(&format!("billing-{index}"), None))
            .collect::<Vec<_>>();
        let fixture = provider(aliases);
        fixture.gcp.push_exchange(json_response(
            200,
            &exchange_body(FEDERATED_TOKEN_CANARY, 3600),
        ));
        fixture.gcp.push_read(json_response(
            200,
            &access_body(&version_name(1), VALUE_CANARY.as_bytes()),
        ));

        for index in 0..MAX_GCP_VALUE_CACHE_ENTRIES + 4 {
            fixture
                .provider
                .resolve(&format!("billing-{index}"), SecretPurpose::StaticBearer)
                .await
                .expect("each read should resolve");
        }

        assert!(fixture.provider.value_guard().len() <= MAX_GCP_VALUE_CACHE_ENTRIES);
    }

    #[tokio::test]
    async fn metadata_and_debug_output_never_expose_locators_tokens_or_values() {
        let mut pinned = alias("billing", Some(2));
        pinned.location = Some(LOCATION_CANARY.to_owned());
        let fixture = impersonating_provider(vec![pinned.clone()]);
        let token_root_canary = fixture._token_root.path();
        fixture.gcp.push_exchange(json_response(
            200,
            &exchange_body(FEDERATED_TOKEN_CANARY, 3600),
        ));
        fixture.gcp.push_impersonation(json_response(
            200,
            &impersonation_body(IMPERSONATED_TOKEN_CANARY),
        ));
        let name = format!(
            "projects/{PROJECT_CANARY}/locations/{LOCATION_CANARY}/secrets/{SECRET_CANARY}/versions/2"
        );
        fixture.gcp.push_read(json_response(
            200,
            &access_body(&name, VALUE_CANARY.as_bytes()),
        ));
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
        let configuration = GcpProviderConfig {
            profiles: vec![profile(
                "primary",
                &token_root_canary,
                Some(SERVICE_ACCOUNT_CANARY),
            )],
            aliases: vec![pinned],
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
            GcpFailure::ProviderDenied.safe_reason().to_owned(),
            GcpFailure::ChecksumMismatch.safe_reason().to_owned(),
            format!("{}", GcpProviderConfigError::InvalidAudience { index: 0 }),
            format!("{}", GcpProviderConfigError::InvalidProject { index: 0 }),
        ];
        for output in outputs {
            for canary in [
                VALUE_CANARY,
                FEDERATED_TOKEN_CANARY,
                IMPERSONATED_TOKEN_CANARY,
                SUBJECT_JWT_CANARY,
                AUDIENCE_CANARY,
                PROJECT_CANARY,
                SECRET_CANARY,
                LOCATION_CANARY,
                SERVICE_ACCOUNT_CANARY,
                token_root_canary.as_str(),
            ] {
                assert!(
                    !output.contains(canary),
                    "{canary} must not appear in {output}"
                );
            }
        }
        let metadata = fixture.provider.aliases();
        assert_eq!(metadata.len(), 1);
        assert_eq!(metadata[0].provider, SecretProviderKind::GcpSecretManager);
        assert_eq!(metadata[0].version, Some(2));
        assert!(serde_json::to_string(&metadata)
            .expect("alias metadata should serialize")
            .contains("gcp_secret_manager"));
    }

    #[test]
    fn every_failure_maps_to_a_bounded_safe_reason() {
        for failure in [
            GcpFailure::UnknownAlias,
            GcpFailure::ProviderBusy,
            GcpFailure::DeadlineExceeded,
            GcpFailure::EgressDenied,
            GcpFailure::RedirectRefused,
            GcpFailure::IdentityUnavailable,
            GcpFailure::IdentityDenied,
            GcpFailure::IdentityInvalid,
            GcpFailure::ProviderUnavailable,
            GcpFailure::ProviderDenied,
            GcpFailure::SecretAbsent,
            GcpFailure::SecretUnusable,
            GcpFailure::ChecksumMismatch,
            GcpFailure::InvalidResponse,
            GcpFailure::InvalidMaterial,
            GcpFailure::ProviderFailure,
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
    async fn a_world_writable_subject_token_fails_closed() {
        use std::os::unix::fs::PermissionsExt;

        let fixture = provider(vec![alias("billing", None)]);
        fixture.gcp.push_exchange(json_response(
            200,
            &exchange_body(FEDERATED_TOKEN_CANARY, 600),
        ));
        fixture.gcp.push_read(json_response(
            200,
            &access_body(&version_name(1), VALUE_CANARY.as_bytes()),
        ));
        let token_path = fixture._token_root.root.join("token");
        fs::set_permissions(&token_path, fs::Permissions::from_mode(0o666))
            .expect("token permissions should update");

        let error = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect_err("a world-writable identity token must fail closed");

        assert_eq!(error.kind(), SecretResolveErrorKind::SourceDenied);
        assert!(fixture.gcp.requests().is_empty());
    }
}
