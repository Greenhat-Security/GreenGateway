//! Read-only AWS Secrets Manager secret provider.
//!
//! The provider is one more implementation of the stable [`SecretResolver`]
//! contract. It adds no Connection authority, no secret CRUD service, and no
//! reveal or provider-proxy endpoint. Every provider locator (secret ARN,
//! version selector, JSON member, STS endpoint, role ARN, token path) is fixed
//! by trusted startup configuration and bound to one opaque alias, so callers,
//! tool arguments, and ordinary Connection mutations can only name an alias
//! that an operator already provisioned.
//!
//! Only the Secrets Manager *GetSecretValue* operation is implemented. There is
//! no list, discovery, write, rotate, delete, or administration operation, and
//! no request contains a caller-supplied byte: each alias carries a request
//! body and a deterministic regional endpoint
//! (`secretsmanager.<region>.amazonaws.com`, with the region taken from the
//! validated secret ARN) that were assembled once at startup.
//!
//! Identity is deliberately narrow. The primary mode exchanges a projected
//! workload identity token for bounded STS session credentials through
//! `AssumeRoleWithWebIdentity` against an operator-fixed STS endpoint; the
//! explicit `static_keys` mode takes an access key pair from already configured
//! aliases of another provider. There is no SDK default credential chain, no
//! instance metadata service, no shared configuration file, and no process or
//! CLI credential source. Every data-plane request is SigV4 signed.
//!
//! Every provider and identity request travels through [`EgressClient`], so the
//! deployment egress policy (HTTPS, allowlisted host and port, strict CA,
//! hostname and SNI validation, all-answer DNS validation with exact address
//! pinning, and a disabled redirect policy) applies unchanged. Rotation,
//! revocation, deletion, malformed data, provider outage, and newly denied
//! access all fail closed: a failed resolution purges any cached value for that
//! alias and never returns a previous value, never falls back to `AWSPREVIOUS`,
//! retries anonymously, or switches credential sources.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    fs::{self},
    path::PathBuf,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use cap_std::{ambient_authority, fs::Dir};
use hmac::{Hmac, Mac};
use http::{
    header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE},
    HeaderMap, HeaderName, HeaderValue, Method, StatusCode,
};
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use serde::{
    de::{self, IgnoredAny, Visitor},
    Deserialize, Deserializer,
};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
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

pub const MAX_AWS_PROFILES: usize = 8;
pub const MAX_AWS_SECRET_ALIASES: usize = MAX_CREDENTIALS;
pub const MAX_AWS_PROVIDER_CONFIG_BYTES: usize = 256 * 1024;
pub const MAX_CONCURRENT_AWS_RESOLUTIONS: usize = 8;

const MAX_AWS_ENDPOINT_BYTES: usize = 512;
const MAX_AWS_ARN_BYTES: usize = 2048;
const MAX_AWS_ROLE_ARN_BYTES: usize = 2048;
const MAX_AWS_VERSION_STAGE_BYTES: usize = 256;
const MAX_AWS_JSON_MEMBER_BYTES: usize = 128;
const MAX_AWS_TOKEN_ROOT_BYTES: usize = 512;
const MAX_AWS_STS_RESPONSE_BYTES: usize = 16 * 1024;
const MAX_AWS_READ_RESPONSE_BYTES: usize = 128 * 1024;
const MAX_AWS_ERROR_BODY_BYTES: usize = 4 * 1024;
const MAX_AWS_CREDENTIAL_TEXT_BYTES: usize = 4 * 1024;
const MAX_AWS_SESSION_LIFETIME: Duration = Duration::from_secs(60 * 60);
const AWS_CREDENTIAL_REFRESH_SKEW: Duration = Duration::from_secs(30);
const AWS_STATIC_KEY_LIFETIME: Duration = Duration::from_secs(60);
const AWS_VALUE_CACHE_TTL: Duration = Duration::from_secs(60);
const MAX_AWS_VALUE_CACHE_ENTRIES: usize = 256;
const MAX_AWS_TRANSIENT_RETRIES: u32 = 1;
const AWS_RETRY_BACKOFF: Duration = Duration::from_millis(100);
const AWS_RESOLUTION_DEADLINE: Duration = Duration::from_secs(10);
const AWS_PROVIDER_LABEL: &str = "aws_secrets_manager";
const AWS_JSON_CONTENT_TYPE: &str = "application/x-amz-json-1.1";
const AWS_FORM_CONTENT_TYPE: &str = "application/x-www-form-urlencoded";
const AWS_GET_SECRET_VALUE_TARGET: &str = "secretsmanager.GetSecretValue";
const AWS_CURRENT_STAGE: &str = "AWSCURRENT";
const AWS_PREVIOUS_STAGE: &str = "AWSPREVIOUS";
const AWS_ROLE_SESSION_NAME: &str = "greengateway";
const AWS_SECRETS_MANAGER_SERVICE: &str = "secretsmanager";
const AMZ_DATE_HEADER: &str = "x-amz-date";
const AMZ_TARGET_HEADER: &str = "x-amz-target";
const AMZ_SECURITY_TOKEN_HEADER: &str = "x-amz-security-token";
const REDACTED_LOCATOR: &str = "<redacted-locator>";

/// `application/x-www-form-urlencoded` escaping for the unsigned STS exchange.
const STS_FORM_ENCODE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// Trusted startup configuration for the read-only Secrets Manager provider.
#[derive(Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AwsProviderConfig {
    #[serde(default)]
    pub profiles: Vec<AwsProfileConfig>,
    #[serde(default)]
    pub aliases: Vec<AwsSecretAliasConfig>,
}

impl fmt::Debug for AwsProviderConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsProviderConfig")
            .field("profile_count", &self.profiles.len())
            .field("alias_count", &self.aliases.len())
            .finish()
    }
}

impl AwsProviderConfig {
    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty() && self.aliases.is_empty()
    }
}

/// One region-independent AWS identity: an auth mode plus the explicit STS
/// endpoint that identity requests may contact. Nothing about the profile is
/// derived from a request, an SDK default chain, or an instance metadata
/// service.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AwsProfileConfig {
    pub id: String,
    pub sts_endpoint: String,
    pub auth: AwsAuthConfig,
}

impl fmt::Debug for AwsProfileConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsProfileConfig")
            .field("id", &self.id)
            .field("sts_endpoint", &REDACTED_LOCATOR)
            .field("auth", &self.auth)
            .finish()
    }
}

/// Authentication used to obtain SigV4 signing credentials.
///
/// `web_identity` exchanges a platform-projected workload identity token for
/// bounded STS session credentials and needs no bootstrap secret at all.
/// `static_keys` exists for deployments without a workload identity provider;
/// it takes the access key pair from already configured aliases of another
/// provider, never from an inline value, and signs directly with those keys.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum AwsAuthConfig {
    WebIdentity {
        role_arn: String,
        token_root: String,
        token_file: String,
    },
    StaticKeys {
        access_key_id_alias: String,
        secret_access_key_alias: String,
    },
}

impl fmt::Debug for AwsAuthConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WebIdentity { .. } => formatter
                .debug_struct("WebIdentity")
                .field("role_arn", &REDACTED_LOCATOR)
                .field("token_root", &REDACTED_LOCATOR)
                .field("token_file", &REDACTED_LOCATOR)
                .finish(),
            Self::StaticKeys {
                access_key_id_alias,
                secret_access_key_alias,
            } => formatter
                .debug_struct("StaticKeys")
                .field("access_key_id_alias", access_key_id_alias)
                .field("secret_access_key_alias", secret_access_key_alias)
                .finish(),
        }
    }
}

/// One opaque alias bound to exactly one Secrets Manager secret version.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AwsSecretAliasConfig {
    pub id: String,
    pub label: String,
    pub profile: String,
    pub arn: String,
    #[serde(default)]
    pub version_id: Option<String>,
    #[serde(default)]
    pub version_stage: Option<String>,
    #[serde(default)]
    pub json_key: Option<String>,
}

impl fmt::Debug for AwsSecretAliasConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsSecretAliasConfig")
            .field("id", &self.id)
            .field("label", &self.label)
            .field("profile", &self.profile)
            .field("arn", &REDACTED_LOCATOR)
            .field("pinned_version_id", &self.version_id.is_some())
            .field("pinned_version_stage", &self.version_stage.is_some())
            .field(
                "json_member",
                &self.json_key.as_ref().map(|_| REDACTED_LOCATOR),
            )
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AwsProviderConfigError {
    TooManyProfiles { maximum: usize },
    TooManyAliases { maximum: usize },
    InvalidProfileId { index: usize },
    DuplicateProfileId { index: usize, previous: usize },
    InvalidStsEndpoint { index: usize },
    InvalidRoleArn { index: usize },
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
    InvalidSecretArn { index: usize },
    AmbiguousVersionSelection { index: usize },
    InvalidVersionId { index: usize },
    InvalidVersionStage { index: usize },
    ForbiddenVersionStage { index: usize },
    InvalidJsonMember { index: usize },
    AliasesWithoutProfiles,
}

impl fmt::Display for AwsProviderConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyProfiles { maximum } => write!(
                formatter,
                "aws provider profiles must contain at most {maximum} entries"
            ),
            Self::TooManyAliases { maximum } => write!(
                formatter,
                "aws provider aliases must contain at most {maximum} entries"
            ),
            Self::InvalidProfileId { index } => write!(
                formatter,
                "aws profile at index {index} has an invalid opaque ID"
            ),
            Self::DuplicateProfileId { index, previous } => write!(
                formatter,
                "aws profile at index {index} duplicates the opaque ID at index {previous}"
            ),
            Self::InvalidStsEndpoint { index } => write!(
                formatter,
                "aws profile at index {index} requires an absolute https STS endpoint with no credentials, path, query, or fragment"
            ),
            Self::InvalidRoleArn { index } => write!(
                formatter,
                "aws profile at index {index} has an invalid IAM role ARN"
            ),
            Self::InvalidWorkloadTokenRoot { index } => write!(
                formatter,
                "aws profile at index {index} has an invalid workload identity token root"
            ),
            Self::InvalidWorkloadTokenFile { index } => write!(
                formatter,
                "aws profile at index {index} has an invalid workload identity token file key"
            ),
            Self::WorkloadTokenRootUnavailable { index } => write!(
                formatter,
                "aws profile at index {index} has a workload identity token root that is unavailable or cannot be canonicalized"
            ),
            Self::WorkloadTokenRootPermissions { index } => write!(
                formatter,
                "aws profile at index {index} has a workload identity token root with unsafe write permissions for this platform"
            ),
            Self::InvalidBootstrapAlias { index } => write!(
                formatter,
                "aws profile at index {index} has an invalid bootstrap alias ID"
            ),
            Self::BootstrapAliasCycle { index } => write!(
                formatter,
                "aws profile at index {index} bootstraps from an alias this provider itself serves"
            ),
            Self::BootstrapResolverRequired { index } => write!(
                formatter,
                "aws profile at index {index} bootstraps from an alias but no other provider is configured"
            ),
            Self::UnknownBootstrapAlias { index } => write!(
                formatter,
                "aws profile at index {index} bootstraps from an alias that no configured provider owns"
            ),
            Self::InvalidAliasId { index } => write!(
                formatter,
                "aws alias at index {index} has an invalid opaque ID"
            ),
            Self::InvalidLabel { index } => write!(
                formatter,
                "aws alias at index {index} has an invalid safe label"
            ),
            Self::DuplicateAliasId { index, previous } => write!(
                formatter,
                "aws alias at index {index} duplicates the opaque ID at index {previous}"
            ),
            Self::ReservedAliasId { index } => write!(
                formatter,
                "aws alias at index {index} duplicates an alias ID served by another provider"
            ),
            Self::UnknownProfile { index } => write!(
                formatter,
                "aws alias at index {index} names an unconfigured profile"
            ),
            Self::InvalidSecretArn { index } => write!(
                formatter,
                "aws alias at index {index} requires a complete, unambiguous Secrets Manager secret ARN including the random suffix"
            ),
            Self::AmbiguousVersionSelection { index } => write!(
                formatter,
                "aws alias at index {index} must pin at most one of version_id and version_stage"
            ),
            Self::InvalidVersionId { index } => write!(
                formatter,
                "aws alias at index {index} has an invalid version ID"
            ),
            Self::InvalidVersionStage { index } => write!(
                formatter,
                "aws alias at index {index} has an invalid version stage"
            ),
            Self::ForbiddenVersionStage { index } => write!(
                formatter,
                "aws alias at index {index} must not pin the AWSPREVIOUS stage"
            ),
            Self::InvalidJsonMember { index } => write!(
                formatter,
                "aws alias at index {index} has an invalid JSON member name"
            ),
            Self::AliasesWithoutProfiles => {
                formatter.write_str("aws aliases require at least one configured profile")
            }
        }
    }
}

impl Error for AwsProviderConfigError {}

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
) -> Result<(), AwsProviderConfigError> {
    let Some(resolver) = bootstrap else {
        return Err(AwsProviderConfigError::BootstrapResolverRequired { index });
    };
    if !resolver.contains_alias(alias) {
        return Err(AwsProviderConfigError::UnknownBootstrapAlias { index });
    }
    Ok(())
}

pub fn validate_aws_provider_config(
    config: &AwsProviderConfig,
    reserved_alias_ids: &BTreeSet<String>,
) -> Result<(), AwsProviderConfigError> {
    if config.profiles.len() > MAX_AWS_PROFILES {
        return Err(AwsProviderConfigError::TooManyProfiles {
            maximum: MAX_AWS_PROFILES,
        });
    }
    if config.aliases.len() > MAX_AWS_SECRET_ALIASES {
        return Err(AwsProviderConfigError::TooManyAliases {
            maximum: MAX_AWS_SECRET_ALIASES,
        });
    }
    if !config.aliases.is_empty() && config.profiles.is_empty() {
        return Err(AwsProviderConfigError::AliasesWithoutProfiles);
    }

    let alias_ids = config
        .aliases
        .iter()
        .map(|alias| alias.id.as_str())
        .collect::<BTreeSet<_>>();
    let mut profile_ids = BTreeMap::new();
    for (index, profile) in config.profiles.iter().enumerate() {
        if !is_valid_opaque_id(&profile.id, MAX_SECRET_ID_BYTES) {
            return Err(AwsProviderConfigError::InvalidProfileId { index });
        }
        if let Some(previous) = profile_ids.insert(profile.id.as_str(), index) {
            return Err(AwsProviderConfigError::DuplicateProfileId { index, previous });
        }
        if !is_valid_https_endpoint(&profile.sts_endpoint) {
            return Err(AwsProviderConfigError::InvalidStsEndpoint { index });
        }
        match &profile.auth {
            AwsAuthConfig::WebIdentity {
                role_arn,
                token_root,
                token_file,
            } => {
                if !is_valid_role_arn(role_arn) {
                    return Err(AwsProviderConfigError::InvalidRoleArn { index });
                }
                if token_root.is_empty() || token_root.len() > MAX_AWS_TOKEN_ROOT_BYTES {
                    return Err(AwsProviderConfigError::InvalidWorkloadTokenRoot { index });
                }
                if !super::secret::is_valid_file_key(token_file) {
                    return Err(AwsProviderConfigError::InvalidWorkloadTokenFile { index });
                }
            }
            AwsAuthConfig::StaticKeys {
                access_key_id_alias,
                secret_access_key_alias,
            } => {
                validate_bootstrap_alias(index, access_key_id_alias, &alias_ids)?;
                validate_bootstrap_alias(index, secret_access_key_alias, &alias_ids)?;
            }
        }
    }

    let mut seen_alias_ids = BTreeMap::new();
    for (index, alias) in config.aliases.iter().enumerate() {
        if !is_valid_opaque_id(&alias.id, MAX_SECRET_ID_BYTES) {
            return Err(AwsProviderConfigError::InvalidAliasId { index });
        }
        if alias.label.is_empty()
            || alias.label.chars().count() > MAX_DISPLAY_NAME_CHARS
            || alias.label.chars().any(char::is_control)
        {
            return Err(AwsProviderConfigError::InvalidLabel { index });
        }
        if let Some(previous) = seen_alias_ids.insert(alias.id.as_str(), index) {
            return Err(AwsProviderConfigError::DuplicateAliasId { index, previous });
        }
        if reserved_alias_ids.contains(&alias.id) {
            return Err(AwsProviderConfigError::ReservedAliasId { index });
        }
        if !profile_ids.contains_key(alias.profile.as_str()) {
            return Err(AwsProviderConfigError::UnknownProfile { index });
        }
        if parse_secret_arn(&alias.arn).is_none() {
            return Err(AwsProviderConfigError::InvalidSecretArn { index });
        }
        if alias.version_id.is_some() && alias.version_stage.is_some() {
            return Err(AwsProviderConfigError::AmbiguousVersionSelection { index });
        }
        if alias
            .version_id
            .as_deref()
            .is_some_and(|version| !is_valid_version_id(version))
        {
            return Err(AwsProviderConfigError::InvalidVersionId { index });
        }
        if let Some(stage) = alias.version_stage.as_deref() {
            if !is_valid_version_stage(stage) {
                return Err(AwsProviderConfigError::InvalidVersionStage { index });
            }
            if stage == AWS_PREVIOUS_STAGE {
                return Err(AwsProviderConfigError::ForbiddenVersionStage { index });
            }
        }
        if alias
            .json_key
            .as_deref()
            .is_some_and(|member| !is_valid_json_member(member))
        {
            return Err(AwsProviderConfigError::InvalidJsonMember { index });
        }
    }
    Ok(())
}

fn validate_bootstrap_alias(
    index: usize,
    alias: &str,
    own_alias_ids: &BTreeSet<&str>,
) -> Result<(), AwsProviderConfigError> {
    if !is_valid_opaque_id(alias, MAX_SECRET_ID_BYTES) {
        return Err(AwsProviderConfigError::InvalidBootstrapAlias { index });
    }
    if own_alias_ids.contains(alias) {
        return Err(AwsProviderConfigError::BootstrapAliasCycle { index });
    }
    Ok(())
}

fn is_valid_https_endpoint(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_AWS_ENDPOINT_BYTES {
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

fn is_valid_aws_region(value: &str) -> bool {
    if value.len() < 2 || value.len() > 32 {
        return false;
    }
    let mut segments = value.split('-');
    let Some(first) = segments.next() else {
        return false;
    };
    if first.is_empty() || !first.bytes().all(|byte| byte.is_ascii_lowercase()) {
        return false;
    }
    let mut rest = 0_usize;
    for segment in segments {
        if segment.is_empty()
            || !segment
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        {
            return false;
        }
        rest += 1;
    }
    rest >= 1
}

/// A complete, unambiguous secret ARN carries the random creation suffix
/// (`-` plus six alphanumeric characters). Without it, Secrets Manager treats
/// the trailing text as a *name* lookup that can silently match a different
/// secret, so partial ARNs are rejected outright.
fn has_full_arn_suffix(name: &str) -> bool {
    let bytes = name.as_bytes();
    bytes.len() >= 8
        && bytes[bytes.len() - 7] == b'-'
        && bytes[bytes.len() - 6..]
            .iter()
            .all(u8::is_ascii_alphanumeric)
}

/// Validates one full secret ARN and returns its region.
///
/// Accepted partitions are `aws` and `aws-us-gov`, the partitions whose
/// regional Secrets Manager endpoint is deterministically
/// `secretsmanager.<region>.amazonaws.com`.
fn parse_secret_arn(value: &str) -> Option<&str> {
    if value.is_empty() || value.len() > MAX_AWS_ARN_BYTES {
        return None;
    }
    if value
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte == b' ' || !byte.is_ascii())
    {
        return None;
    }
    let mut parts = value.splitn(7, ':');
    let prefix = parts.next()?;
    let partition = parts.next()?;
    let service = parts.next()?;
    let region = parts.next()?;
    let account = parts.next()?;
    let resource_kind = parts.next()?;
    let name = parts.next()?;
    (prefix == "arn"
        && matches!(partition, "aws" | "aws-us-gov")
        && service == "secretsmanager"
        && is_valid_aws_region(region)
        && account.len() == 12
        && account.bytes().all(|byte| byte.is_ascii_digit())
        && resource_kind == "secret"
        && !name.is_empty()
        && name.bytes().all(is_valid_secret_name_byte)
        && has_full_arn_suffix(name))
    .then_some(region)
}

fn is_valid_secret_name_byte(byte: u8) -> bool {
    matches!(byte, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'/' | b'_' | b'+' | b'=' | b'.' | b'@' | b'-')
}

fn is_valid_role_arn(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_AWS_ROLE_ARN_BYTES {
        return false;
    }
    if value
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte == b' ' || !byte.is_ascii())
    {
        return false;
    }
    let mut parts = value.splitn(6, ':');
    let Some(prefix) = parts.next() else {
        return false;
    };
    let Some(partition) = parts.next() else {
        return false;
    };
    let Some(service) = parts.next() else {
        return false;
    };
    let Some(region) = parts.next() else {
        return false;
    };
    let Some(account) = parts.next() else {
        return false;
    };
    let Some(resource) = parts.next() else {
        return false;
    };
    prefix == "arn"
        && matches!(partition, "aws" | "aws-us-gov")
        && service == "iam"
        && region.is_empty()
        && account.len() == 12
        && account.bytes().all(|byte| byte.is_ascii_digit())
        && resource
            .strip_prefix("role/")
            .is_some_and(|path| {
                !path.is_empty()
                    && !path.starts_with('/')
                    && !path.ends_with('/')
                    && path.bytes().all(|byte| {
                        matches!(byte, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'/' | b'_' | b'+' | b'=' | b',' | b'.' | b'@' | b'-')
                    })
            })
}

fn is_valid_version_id(value: &str) -> bool {
    (32..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn is_valid_version_stage(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_AWS_VERSION_STAGE_BYTES
        && value.bytes().all(is_valid_secret_name_byte)
}

fn is_valid_json_member(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_AWS_JSON_MEMBER_BYTES
        && !value.chars().any(char::is_control)
}

/// One bounded provider or identity exchange.
pub(crate) struct AwsHttpResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for AwsHttpResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsHttpResponse")
            .field("status", &self.status)
            .field("headers", &"<redacted>")
            .field("body", &"<redacted>")
            .finish()
    }
}

/// Egress-mediated transport for the provider.
///
/// The production implementation is [`EgressAwsTransport`]; tests substitute a
/// hermetic fake so CI never contacts AWS.
#[async_trait]
pub(crate) trait AwsTransport: Send + Sync {
    /// Opaque generation of the egress configuration behind this transport.
    fn egress_generation(&self) -> [u8; 32];

    async fn send(
        &self,
        method: Method,
        url: &str,
        headers: HeaderMap,
        body: Option<Vec<u8>>,
    ) -> Result<AwsHttpResponse, EgressError>;
}

pub(crate) struct EgressAwsTransport {
    client: Arc<EgressClient>,
}

impl EgressAwsTransport {
    pub(crate) fn new(client: Arc<EgressClient>) -> Self {
        Self { client }
    }
}

impl fmt::Debug for EgressAwsTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EgressAwsTransport")
    }
}

#[async_trait]
impl AwsTransport for EgressAwsTransport {
    fn egress_generation(&self) -> [u8; 32] {
        self.client.configuration_generation()
    }

    async fn send(
        &self,
        method: Method,
        url: &str,
        headers: HeaderMap,
        body: Option<Vec<u8>>,
    ) -> Result<AwsHttpResponse, EgressError> {
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
        Ok(AwsHttpResponse {
            status: response.status,
            headers: response.headers,
            body: response.body,
        })
    }
}

pub(crate) trait AwsClock: Send + Sync {
    fn now(&self) -> Instant;
    fn wall(&self) -> SystemTime;
}

struct SystemAwsClock;

impl AwsClock for SystemAwsClock {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn wall(&self) -> SystemTime {
        SystemTime::now()
    }
}

struct AwsProfile {
    id: String,
    sts_url: String,
    auth: AwsAuth,
}

enum AwsAuth {
    WebIdentity {
        role_arn: String,
        token_root: Arc<Dir>,
        token_file: String,
    },
    StaticKeys {
        access_key_id_alias: String,
        secret_access_key_alias: String,
    },
}

struct AwsAliasBinding {
    id: String,
    label: String,
    profile: String,
    arn: String,
    endpoint_url: String,
    host: String,
    region: String,
    version_id: Option<String>,
    version_stage: Option<String>,
    json_key: Option<String>,
}

impl AwsAliasBinding {
    /// The fixed GetSecretValue request body. When nothing is pinned the
    /// current stage is requested explicitly, so the wire request is
    /// deterministic and never falls back to another stage.
    fn request_body(&self) -> Result<Vec<u8>, AwsFailure> {
        let mut body = serde_json::Map::new();
        body.insert(
            "SecretId".to_owned(),
            serde_json::Value::String(self.arn.clone()),
        );
        if let Some(version_id) = &self.version_id {
            body.insert(
                "VersionId".to_owned(),
                serde_json::Value::String(version_id.clone()),
            );
        } else {
            let stage = self.version_stage.as_deref().unwrap_or(AWS_CURRENT_STAGE);
            body.insert(
                "VersionStage".to_owned(),
                serde_json::Value::String(stage.to_owned()),
            );
        }
        serde_json::to_vec(&serde_json::Value::Object(body))
            .map_err(|_| AwsFailure::ProviderFailure)
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct AwsValueCacheKey {
    provider_generation: [u8; 32],
    egress_generation: [u8; 32],
    identity_generation: u64,
    alias_id: String,
    purpose: u8,
    pinned_version_id: Option<String>,
    pinned_version_stage: Option<String>,
}

struct CachedAwsValue {
    value: Zeroizing<Vec<u8>>,
    expires_at: Instant,
}

/// SigV4 signing material for one profile. Secret components zeroize on drop.
struct AwsSessionCredentials {
    access_key_id: Zeroizing<String>,
    secret_access_key: Zeroizing<String>,
    session_token: Option<Zeroizing<String>>,
}

struct CachedAwsCredentials {
    credentials: Arc<AwsSessionCredentials>,
    expires_at: Instant,
    generation: u64,
}

#[derive(Default)]
struct AwsIdentityState {
    credentials: BTreeMap<String, CachedAwsCredentials>,
    generations: BTreeMap<String, u64>,
}

/// Read-only Secrets Manager provider.
#[derive(Clone)]
pub struct AwsSecretsManagerProvider {
    profiles: Arc<BTreeMap<String, AwsProfile>>,
    aliases: Arc<BTreeMap<String, AwsAliasBinding>>,
    transport: Arc<dyn AwsTransport>,
    bootstrap: Option<Arc<dyn SecretResolver>>,
    identity: Arc<Mutex<AwsIdentityState>>,
    login_lock: Arc<AsyncMutex<()>>,
    values: Arc<Mutex<BTreeMap<AwsValueCacheKey, CachedAwsValue>>>,
    concurrent_reads: Arc<Semaphore>,
    clock: Arc<dyn AwsClock>,
    generation: [u8; 32],
    deadline: Duration,
    value_cache_ttl: Duration,
}

impl fmt::Debug for AwsSecretsManagerProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsSecretsManagerProvider")
            .field("profile_count", &self.profiles.len())
            .field("alias_count", &self.aliases.len())
            .field("bootstrap_provider_enabled", &self.bootstrap.is_some())
            .field("maximum_concurrent_reads", &MAX_CONCURRENT_AWS_RESOLUTIONS)
            .finish()
    }
}

impl AwsSecretsManagerProvider {
    /// Builds the provider from trusted startup configuration.
    ///
    /// `bootstrap` must be a resolver that does **not** include this provider,
    /// which together with the configuration cycle check keeps bootstrap
    /// material out of any AWS-served alias.
    pub(crate) fn from_config(
        config: &AwsProviderConfig,
        reserved_alias_ids: &BTreeSet<String>,
        transport: Arc<dyn AwsTransport>,
        bootstrap: Option<Arc<dyn SecretResolver>>,
    ) -> Result<Self, AwsProviderConfigError> {
        validate_aws_provider_config(config, reserved_alias_ids)?;
        let mut profiles = BTreeMap::new();
        for (index, profile) in config.profiles.iter().enumerate() {
            let sts_url = format!("{}/", profile.sts_endpoint.trim_end_matches('/'));
            let auth = match &profile.auth {
                AwsAuthConfig::WebIdentity {
                    role_arn,
                    token_root,
                    token_file,
                } => AwsAuth::WebIdentity {
                    role_arn: role_arn.clone(),
                    token_root: open_workload_token_root(index, token_root)?,
                    token_file: token_file.clone(),
                },
                AwsAuthConfig::StaticKeys {
                    access_key_id_alias,
                    secret_access_key_alias,
                } => {
                    require_bootstrap_alias(index, access_key_id_alias, bootstrap.as_ref())?;
                    require_bootstrap_alias(index, secret_access_key_alias, bootstrap.as_ref())?;
                    AwsAuth::StaticKeys {
                        access_key_id_alias: access_key_id_alias.clone(),
                        secret_access_key_alias: secret_access_key_alias.clone(),
                    }
                }
            };
            profiles.insert(
                profile.id.clone(),
                AwsProfile {
                    id: profile.id.clone(),
                    sts_url,
                    auth,
                },
            );
        }

        let mut aliases = BTreeMap::new();
        for (index, alias) in config.aliases.iter().enumerate() {
            let region = parse_secret_arn(&alias.arn)
                .ok_or(AwsProviderConfigError::InvalidSecretArn { index })?
                .to_owned();
            let host = format!("secretsmanager.{region}.amazonaws.com");
            aliases.insert(
                alias.id.clone(),
                AwsAliasBinding {
                    id: alias.id.clone(),
                    label: alias.label.clone(),
                    profile: alias.profile.clone(),
                    arn: alias.arn.clone(),
                    endpoint_url: format!("https://{host}/"),
                    host,
                    region,
                    version_id: alias.version_id.clone(),
                    version_stage: alias.version_stage.clone(),
                    json_key: alias.json_key.clone(),
                },
            );
        }

        Ok(Self {
            profiles: Arc::new(profiles),
            aliases: Arc::new(aliases),
            transport,
            bootstrap,
            identity: Arc::new(Mutex::new(AwsIdentityState::default())),
            login_lock: Arc::new(AsyncMutex::new(())),
            values: Arc::new(Mutex::new(BTreeMap::new())),
            concurrent_reads: Arc::new(Semaphore::new(MAX_CONCURRENT_AWS_RESOLUTIONS)),
            clock: Arc::new(SystemAwsClock),
            generation: provider_generation(config),
            deadline: AWS_RESOLUTION_DEADLINE,
            value_cache_ttl: AWS_VALUE_CACHE_TTL,
        })
    }

    pub fn alias_ids(&self) -> BTreeSet<String> {
        self.aliases.keys().cloned().collect()
    }

    fn identity_guard(&self) -> MutexGuard<'_, AwsIdentityState> {
        match self.identity.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn value_guard(&self) -> MutexGuard<'_, BTreeMap<AwsValueCacheKey, CachedAwsValue>> {
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
        alias: &AwsAliasBinding,
        purpose: SecretPurpose,
        identity_generation: u64,
    ) -> AwsValueCacheKey {
        AwsValueCacheKey {
            provider_generation: self.generation,
            egress_generation: self.transport.egress_generation(),
            identity_generation,
            alias_id: alias.id.clone(),
            purpose: purpose_code(purpose),
            pinned_version_id: alias.version_id.clone(),
            pinned_version_stage: alias.version_stage.clone(),
        }
    }

    fn cached_value(&self, key: &AwsValueCacheKey) -> Option<Zeroizing<Vec<u8>>> {
        let now = self.clock.now();
        let mut cache = self.value_guard();
        let entry = cache.get(key)?;
        if entry.expires_at <= now {
            cache.remove(key);
            return None;
        }
        Some(entry.value.clone())
    }

    fn store_value(&self, key: AwsValueCacheKey, value: &[u8]) {
        let now = self.clock.now();
        let mut cache = self.value_guard();
        cache.retain(|_, entry| entry.expires_at > now);
        if cache.len() >= MAX_AWS_VALUE_CACHE_ENTRIES {
            return;
        }
        cache.insert(
            key,
            CachedAwsValue {
                value: Zeroizing::new(value.to_vec()),
                expires_at: now + self.value_cache_ttl,
            },
        );
    }

    fn purge_alias(&self, alias_id: &str) {
        self.value_guard().retain(|key, _| key.alias_id != alias_id);
    }

    fn cached_credentials(
        &self,
        profile_id: &str,
        minimum_generation: u64,
    ) -> Option<(Arc<AwsSessionCredentials>, u64)> {
        let now = self.clock.now();
        let mut identity = self.identity_guard();
        let cached = identity.credentials.get(profile_id)?;
        if cached.expires_at <= now {
            identity.credentials.remove(profile_id);
            return None;
        }
        if cached.generation < minimum_generation {
            return None;
        }
        Some((Arc::clone(&cached.credentials), cached.generation))
    }

    fn store_credentials(
        &self,
        profile_id: &str,
        credentials: Arc<AwsSessionCredentials>,
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
        identity.credentials.remove(profile_id);
        if let Some(lifetime) = lifetime {
            identity.credentials.insert(
                profile_id.to_owned(),
                CachedAwsCredentials {
                    credentials,
                    expires_at: now + lifetime,
                    generation,
                },
            );
        }
        generation
    }

    fn invalidate_credentials(&self, profile_id: &str) {
        self.identity_guard().credentials.remove(profile_id);
    }

    async fn resolve_inner(
        &self,
        alias_id: &str,
        purpose: SecretPurpose,
    ) -> Result<ResolvedSecret, AwsFailure> {
        let alias = self.aliases.get(alias_id).ok_or(AwsFailure::UnknownAlias)?;
        let profile = self
            .profiles
            .get(&alias.profile)
            .ok_or(AwsFailure::ProviderFailure)?;

        let identity_generation = self.identity_generation(&profile.id);
        let cache_key = self.cache_key(alias, purpose, identity_generation);
        if let Some(cached) = self.cached_value(&cache_key) {
            return ResolvedSecret::new(purpose, cached.to_vec())
                .map_err(|_| AwsFailure::InvalidMaterial);
        }

        let result = self.read_authenticated(alias, profile, purpose).await;
        if result.is_err() {
            self.purge_alias(&alias.id);
        }
        let (value, identity_generation) = result?;
        let secret = ResolvedSecret::new(purpose, value.to_vec())
            .map_err(|_| AwsFailure::InvalidMaterial)?;
        self.store_value(
            self.cache_key(alias, purpose, identity_generation),
            secret.expose(),
        );
        Ok(secret)
    }

    async fn read_authenticated(
        &self,
        alias: &AwsAliasBinding,
        profile: &AwsProfile,
        purpose: SecretPurpose,
    ) -> Result<(Zeroizing<Vec<u8>>, u64), AwsFailure> {
        let (credentials, generation) = self.credentials(profile, 0).await?;
        match self.read_once(alias, purpose, &credentials).await {
            Err(AwsFailure::ProviderDenied) => {
                // Expired, revoked, or rotated session credentials are the only
                // condition that earns a second attempt, and only after a fresh
                // authentication through the same fixed identity source.
                let (credentials, generation) = self
                    .credentials(profile, generation.saturating_add(1))
                    .await?;
                self.read_once(alias, purpose, &credentials)
                    .await
                    .map(|value| (value, generation))
            }
            other => other.map(|value| (value, generation)),
        }
    }

    async fn credentials(
        &self,
        profile: &AwsProfile,
        minimum_generation: u64,
    ) -> Result<(Arc<AwsSessionCredentials>, u64), AwsFailure> {
        if let Some(hit) = self.cached_credentials(&profile.id, minimum_generation) {
            return Ok(hit);
        }
        let _guard = self.login_lock.lock().await;
        if let Some(hit) = self.cached_credentials(&profile.id, minimum_generation) {
            return Ok(hit);
        }
        self.invalidate_credentials(&profile.id);
        self.login(profile).await
    }

    async fn login(
        &self,
        profile: &AwsProfile,
    ) -> Result<(Arc<AwsSessionCredentials>, u64), AwsFailure> {
        let (role_arn, token_root, token_file) = match &profile.auth {
            AwsAuth::StaticKeys {
                access_key_id_alias,
                secret_access_key_alias,
            } => {
                let access_key_id = self.bootstrap_material(access_key_id_alias).await?;
                let secret_access_key = self.bootstrap_material(secret_access_key_alias).await?;
                let credentials = Arc::new(AwsSessionCredentials {
                    access_key_id: credential_text(&access_key_id)?,
                    secret_access_key: credential_text(&secret_access_key)?,
                    session_token: None,
                });
                let generation = self.store_credentials(
                    &profile.id,
                    Arc::clone(&credentials),
                    Some(AWS_STATIC_KEY_LIFETIME),
                );
                return Ok((credentials, generation));
            }
            AwsAuth::WebIdentity {
                role_arn,
                token_root,
                token_file,
            } => (role_arn, token_root, token_file),
        };

        let token = self.workload_identity_token(token_root, token_file).await?;
        // The decoded token copy zeroizes on drop; the percent encoder streams
        // straight into the request body, which the transport contract takes
        // as a plain `Vec<u8>` exactly like the Vault login body.
        let token = Zeroizing::new(
            std::str::from_utf8(token.expose())
                .map_err(|_| AwsFailure::IdentityInvalid)?
                .to_owned(),
        );
        let body = format!(
            "Action=AssumeRoleWithWebIdentity&Version=2011-06-15&RoleArn={role}&RoleSessionName={session}&WebIdentityToken={token}",
            role = utf8_percent_encode(role_arn, STS_FORM_ENCODE),
            session = AWS_ROLE_SESSION_NAME,
            token = utf8_percent_encode(&token, STS_FORM_ENCODE),
        )
        .into_bytes();

        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static(AWS_FORM_CONTENT_TYPE),
        );
        let response = self
            .send_with_bounded_retries(
                Method::POST,
                &profile.sts_url,
                Ok(headers),
                Some(body),
                true,
            )
            .await?;
        let body = bounded_body(&response, MAX_AWS_STS_RESPONSE_BYTES, "application/json")
            .map_err(|_| AwsFailure::IdentityInvalid)?;
        let mut login: StsLoginEnvelope =
            serde_json::from_slice(body).map_err(|_| AwsFailure::IdentityInvalid)?;
        let sts = &mut login.response.result.credentials;
        let lifetime = self.credential_lifetime(sts.expiration)?;
        let credentials = Arc::new(AwsSessionCredentials {
            access_key_id: sts.access_key_id.take_text()?,
            secret_access_key: sts.secret_access_key.take_text()?,
            session_token: Some(sts.session_token.take_text()?),
        });
        let cache_lifetime = lifetime
            .checked_sub(AWS_CREDENTIAL_REFRESH_SKEW)
            .filter(|lifetime| !lifetime.is_zero());
        let generation =
            self.store_credentials(&profile.id, Arc::clone(&credentials), cache_lifetime);
        Ok((credentials, generation))
    }

    /// Rejects an already expired or non-finite STS expiration outright and
    /// bounds every accepted lifetime, so a misbehaving identity provider can
    /// never grant an unbounded session.
    fn credential_lifetime(&self, expiration_epoch: f64) -> Result<Duration, AwsFailure> {
        if !expiration_epoch.is_finite() || expiration_epoch <= 0.0 {
            return Err(AwsFailure::IdentityInvalid);
        }
        let now = self
            .clock
            .wall()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| AwsFailure::IdentityInvalid)?;
        let expiration = Duration::try_from_secs_f64(expiration_epoch)
            .map_err(|_| AwsFailure::IdentityInvalid)?;
        let lifetime = expiration
            .checked_sub(now)
            .ok_or(AwsFailure::IdentityInvalid)?;
        if lifetime.is_zero() {
            return Err(AwsFailure::IdentityInvalid);
        }
        Ok(lifetime.min(MAX_AWS_SESSION_LIFETIME))
    }

    async fn bootstrap_material(&self, alias: &str) -> Result<Zeroizing<Vec<u8>>, AwsFailure> {
        let bootstrap = self.bootstrap.as_ref().ok_or(AwsFailure::ProviderFailure)?;
        let secret = bootstrap
            .resolve(alias, SecretPurpose::StaticBearer)
            .await
            .map_err(|error| match error.kind() {
                SecretResolveErrorKind::SourceDenied | SecretResolveErrorKind::UnsafeSource => {
                    AwsFailure::IdentityDenied
                }
                SecretResolveErrorKind::InvalidMaterial => AwsFailure::IdentityInvalid,
                _ => AwsFailure::IdentityUnavailable,
            })?;
        if secret.expose().len() > MAX_AWS_CREDENTIAL_TEXT_BYTES {
            return Err(AwsFailure::IdentityInvalid);
        }
        Ok(Zeroizing::new(secret.expose().to_vec()))
    }

    async fn workload_identity_token(
        &self,
        token_root: &Arc<Dir>,
        token_file: &str,
    ) -> Result<ResolvedSecret, AwsFailure> {
        let root = Arc::clone(token_root);
        let key = token_file.to_owned();
        tokio::task::spawn_blocking(move || {
            read_bounded_file_secret(
                "aws-workload-identity",
                &root,
                &key,
                SecretPurpose::StaticBearer,
                FileSecretPermissions::PlatformProjected,
            )
        })
        .await
        .map_err(|_| AwsFailure::ProviderFailure)?
        .map_err(|error| match error.kind() {
            SecretResolveErrorKind::SourceDenied | SecretResolveErrorKind::UnsafeSource => {
                AwsFailure::IdentityDenied
            }
            SecretResolveErrorKind::InvalidMaterial => AwsFailure::IdentityInvalid,
            _ => AwsFailure::IdentityUnavailable,
        })
    }

    async fn read_once(
        &self,
        alias: &AwsAliasBinding,
        purpose: SecretPurpose,
        credentials: &AwsSessionCredentials,
    ) -> Result<Zeroizing<Vec<u8>>, AwsFailure> {
        let body = alias.request_body()?;
        let headers = self.signed_read_headers(alias, credentials, &body);
        let response = self
            .send_with_bounded_retries(
                Method::POST,
                &alias.endpoint_url,
                headers,
                Some(body),
                false,
            )
            .await?;
        let body = bounded_body(
            &response,
            MAX_AWS_READ_RESPONSE_BYTES,
            AWS_JSON_CONTENT_TYPE,
        )?;
        let read: GetSecretValueResponse =
            serde_json::from_slice(body).map_err(|_| AwsFailure::InvalidResponse)?;
        read.into_value(alias, purpose)
    }

    fn signed_read_headers(
        &self,
        alias: &AwsAliasBinding,
        credentials: &AwsSessionCredentials,
        body: &[u8],
    ) -> Result<HeaderMap, AwsFailure> {
        let now = OffsetDateTime::from(self.clock.wall());
        let (date, amz_date) = amz_timestamps(&now);
        let payload_hash = sha256_hex(body);
        // Canonical header values are kept in zeroizing storage and hashed
        // incrementally, so no concatenated plaintext copy of the session
        // token ever materializes outside the sensitive header value itself.
        let mut canonical: Vec<(String, Zeroizing<String>)> = vec![
            (
                "content-type".to_owned(),
                Zeroizing::new(AWS_JSON_CONTENT_TYPE.to_owned()),
            ),
            ("host".to_owned(), Zeroizing::new(alias.host.clone())),
            (AMZ_DATE_HEADER.to_owned(), Zeroizing::new(amz_date.clone())),
            (
                AMZ_TARGET_HEADER.to_owned(),
                Zeroizing::new(AWS_GET_SECRET_VALUE_TARGET.to_owned()),
            ),
        ];
        if let Some(token) = credentials.session_token.as_ref() {
            canonical.push((
                AMZ_SECURITY_TOKEN_HEADER.to_owned(),
                Zeroizing::new(token.as_str().to_owned()),
            ));
        }
        canonical.sort_by(|left, right| left.0.cmp(&right.0));
        let signed_headers = canonical
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>()
            .join(";");
        let canonical_hash =
            canonical_request_hash("POST", "/", "", &canonical, &signed_headers, &payload_hash);
        let scope = credential_scope(&date, &alias.region, AWS_SECRETS_MANAGER_SERVICE);
        let string_to_sign = signing_string(&amz_date, &scope, &canonical_hash);
        let signing_key = derive_signing_key(
            credentials.secret_access_key.as_bytes(),
            &date,
            &alias.region,
            AWS_SECRETS_MANAGER_SERVICE,
        );
        let signature = hex::encode(hmac_sha256(signing_key.as_ref(), string_to_sign.as_bytes()));
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
            access_key = credentials.access_key_id.as_str(),
        );

        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_static(AWS_JSON_CONTENT_TYPE));
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static(AWS_JSON_CONTENT_TYPE),
        );
        headers.insert(
            HeaderName::from_static(AMZ_DATE_HEADER),
            HeaderValue::from_str(&amz_date).map_err(|_| AwsFailure::IdentityInvalid)?,
        );
        headers.insert(
            HeaderName::from_static(AMZ_TARGET_HEADER),
            HeaderValue::from_static(AWS_GET_SECRET_VALUE_TARGET),
        );
        if let Some(token) = credentials.session_token.as_ref() {
            let mut value =
                HeaderValue::from_str(token.as_str()).map_err(|_| AwsFailure::IdentityInvalid)?;
            value.set_sensitive(true);
            headers.insert(HeaderName::from_static(AMZ_SECURITY_TOKEN_HEADER), value);
        }
        let mut value =
            HeaderValue::from_str(&authorization).map_err(|_| AwsFailure::IdentityInvalid)?;
        value.set_sensitive(true);
        headers.insert(AUTHORIZATION, value);
        Ok(headers)
    }

    async fn send_with_bounded_retries(
        &self,
        method: Method,
        url: &str,
        headers: Result<HeaderMap, AwsFailure>,
        body: Option<Vec<u8>>,
        identity: bool,
    ) -> Result<AwsHttpResponse, AwsFailure> {
        let headers = headers?;
        let mut attempt = 0;
        loop {
            let response = self
                .transport
                .send(method.clone(), url, headers.clone(), body.clone())
                .await;
            let failure = match response {
                Ok(response) => {
                    let error_type = if response.status == StatusCode::OK {
                        None
                    } else {
                        extract_error_type(&response)
                    };
                    match classify_status(response.status, error_type.as_deref(), identity) {
                        None => return Ok(response),
                        Some(failure) => failure,
                    }
                }
                Err(error) => map_egress_error(&error, identity),
            };
            if attempt >= MAX_AWS_TRANSIENT_RETRIES || !failure.is_transient() {
                return Err(failure);
            }
            attempt = attempt.saturating_add(1);
            tokio::time::sleep(AWS_RETRY_BACKOFF).await;
        }
    }
}

#[async_trait]
impl SecretResolver for AwsSecretsManagerProvider {
    async fn resolve(
        &self,
        alias_id: &str,
        purpose: SecretPurpose,
    ) -> Result<ResolvedSecret, SecretResolveError> {
        let alias_id = safe_error_alias_id(alias_id);
        let started = Instant::now();
        let permit = Arc::clone(&self.concurrent_reads)
            .try_acquire_owned()
            .map_err(|_| AwsFailure::ProviderBusy);
        let outcome = match permit {
            Ok(permit) => {
                let _permit = permit;
                match tokio::time::timeout(self.deadline, self.resolve_inner(&alias_id, purpose))
                    .await
                {
                    Ok(result) => result,
                    Err(_) => {
                        self.purge_alias(&alias_id);
                        Err(AwsFailure::DeadlineExceeded)
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
                provider: SecretProviderKind::AwsSecretsManager,
                configured: true,
                purpose: None,
                // A version stage is a movable label the provider follows, so
                // only an explicit VersionId counts as pinned. The id itself is
                // an opaque request selector and is never surfaced.
                pinned: alias.version_id.is_some(),
                version: None,
                rotated_at: None,
            })
            .collect()
    }
}

fn record_resolution(outcome: &Result<ResolvedSecret, AwsFailure>, elapsed: Duration) {
    let (result, reason) = match outcome {
        Ok(_) => ("success", "resolved"),
        Err(failure) => ("failure", failure.safe_reason()),
    };
    ::metrics::counter!(
        "connection_secret_provider_read_total",
        "provider" => AWS_PROVIDER_LABEL,
        "result" => result,
        "reason" => reason
    )
    .increment(1);
    ::metrics::histogram!(
        "connection_secret_provider_read_duration_seconds",
        "provider" => AWS_PROVIDER_LABEL,
        "result" => result
    )
    .record(elapsed.as_secs_f64());
    if let Err(failure) = outcome {
        tracing::warn!(
            provider = AWS_PROVIDER_LABEL,
            reason = failure.safe_reason(),
            "connection secret provider read failed closed"
        );
    }
}

fn open_workload_token_root(index: usize, path: &str) -> Result<Arc<Dir>, AwsProviderConfigError> {
    let canonical = fs::canonicalize(PathBuf::from(path))
        .map_err(|_| AwsProviderConfigError::WorkloadTokenRootUnavailable { index })?;
    let directory = Dir::open_ambient_dir(&canonical, ambient_authority())
        .map_err(|_| AwsProviderConfigError::WorkloadTokenRootUnavailable { index })?;
    let metadata = directory
        .try_clone()
        .and_then(|directory| directory.into_std_file().metadata())
        .map_err(|_| AwsProviderConfigError::WorkloadTokenRootUnavailable { index })?;
    if !metadata.is_dir() {
        return Err(AwsProviderConfigError::WorkloadTokenRootUnavailable { index });
    }
    validate_token_root_permissions(index, &metadata)?;
    Ok(Arc::new(directory))
}

#[cfg(unix)]
fn validate_token_root_permissions(
    index: usize,
    metadata: &fs::Metadata,
) -> Result<(), AwsProviderConfigError> {
    if crate::connections::secret::projected_root_permissions_are_safe(metadata) {
        Ok(())
    } else {
        Err(AwsProviderConfigError::WorkloadTokenRootPermissions { index })
    }
}

#[cfg(not(unix))]
fn validate_token_root_permissions(
    _: usize,
    _: &fs::Metadata,
) -> Result<(), AwsProviderConfigError> {
    Ok(())
}

fn provider_generation(config: &AwsProviderConfig) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"aws-secrets-manager-provider-v1");
    for profile in &config.profiles {
        digest.update(profile.id.as_bytes());
        digest.update([0]);
        digest.update(profile.sts_endpoint.as_bytes());
        digest.update([0]);
        match &profile.auth {
            AwsAuthConfig::WebIdentity {
                role_arn,
                token_root,
                token_file,
            } => {
                digest.update(b"web_identity");
                for field in [role_arn, token_root, token_file] {
                    digest.update(field.as_bytes());
                    digest.update([0]);
                }
            }
            AwsAuthConfig::StaticKeys {
                access_key_id_alias,
                secret_access_key_alias,
            } => {
                digest.update(b"static_keys");
                for field in [access_key_id_alias, secret_access_key_alias] {
                    digest.update(field.as_bytes());
                    digest.update([0]);
                }
            }
        }
    }
    for alias in &config.aliases {
        for field in [&alias.id, &alias.label, &alias.profile, &alias.arn] {
            digest.update(field.as_bytes());
            digest.update([0]);
        }
        for field in [&alias.version_id, &alias.version_stage, &alias.json_key] {
            digest.update(field.as_deref().unwrap_or_default().as_bytes());
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
enum AwsFailure {
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
    InvalidResponse,
    InvalidMaterial,
    ProviderFailure,
}

impl AwsFailure {
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

fn map_egress_error(error: &EgressError, identity: bool) -> AwsFailure {
    match error {
        EgressError::HostNotAllowed(_)
        | EgressError::PortNotAllowed(_)
        | EgressError::NonGlobalIpBlocked(_)
        | EgressError::SchemeNotAllowed(_)
        | EgressError::InvalidPolicy(_)
        | EgressError::InvalidUrl(_)
        | EgressError::InvalidTlsCaBundle { .. }
        | EgressError::InvalidTlsClientIdentity => AwsFailure::EgressDenied,
        EgressError::ResponseTooLarge { .. } => AwsFailure::InvalidResponse,
        EgressError::RequestBodyTooLarge { .. } | EgressError::RequestBodyReadFailed => {
            AwsFailure::IdentityInvalid
        }
        _ if identity => AwsFailure::IdentityUnavailable,
        _ => AwsFailure::ProviderUnavailable,
    }
}

/// Bounded classification of a non-OK response.
///
/// AWS JSON-protocol services return most client errors as HTTP `400` with a
/// `__type` discriminator, so absence and throttling are distinguished from
/// denial through that bounded field rather than the status alone. Anything
/// unrecognized fails closed as a denial or invalid response.
fn classify_status(
    status: StatusCode,
    error_type: Option<&str>,
    identity: bool,
) -> Option<AwsFailure> {
    if status == StatusCode::OK {
        return None;
    }
    if status.is_redirection() {
        return Some(AwsFailure::RedirectRefused);
    }
    Some(match status.as_u16() {
        400..=403 => match error_type {
            Some("ResourceNotFoundException" | "InvalidRequestException") if !identity => {
                AwsFailure::SecretAbsent
            }
            // JSON-protocol services throttle as `ThrottlingException`;
            // Query-protocol services such as STS report `Error.Code`
            // "Throttling" ("Rate exceeded") plus the older throttle spellings.
            Some(
                "ThrottlingException"
                | "TooManyRequestsException"
                | "LimitExceededException"
                | "Throttling"
                | "ThrottledException"
                | "RequestThrottled",
            ) => {
                if identity {
                    AwsFailure::IdentityUnavailable
                } else {
                    AwsFailure::ProviderUnavailable
                }
            }
            _ if identity => AwsFailure::IdentityDenied,
            _ => AwsFailure::ProviderDenied,
        },
        404 if identity => AwsFailure::IdentityUnavailable,
        404 => AwsFailure::SecretAbsent,
        429 | 500..=599 if identity => AwsFailure::IdentityUnavailable,
        429 | 500..=599 => AwsFailure::ProviderUnavailable,
        _ if identity => AwsFailure::IdentityInvalid,
        _ => AwsFailure::InvalidResponse,
    })
}

fn extract_error_type(response: &AwsHttpResponse) -> Option<String> {
    if response.body.is_empty() || response.body.len() > MAX_AWS_ERROR_BODY_BYTES {
        return None;
    }
    #[derive(Deserialize)]
    struct ErrorBody {
        #[serde(rename = "__type")]
        kind: Option<String>,
        #[serde(rename = "Error")]
        error: Option<ErrorDetail>,
    }
    #[derive(Deserialize)]
    struct ErrorDetail {
        #[serde(rename = "Code")]
        code: Option<String>,
    }
    let body: ErrorBody = serde_json::from_slice(&response.body).ok()?;
    let kind = body
        .kind
        .or_else(|| body.error.and_then(|error| error.code))?;
    let kind = kind.rsplit('#').next().unwrap_or_default();
    (!kind.is_empty() && kind.len() <= 64 && kind.bytes().all(|byte| byte.is_ascii_alphanumeric()))
        .then(|| kind.to_owned())
}

fn bounded_body<'a>(
    response: &'a AwsHttpResponse,
    maximum: usize,
    expected_content_type: &str,
) -> Result<&'a [u8], AwsFailure> {
    if !is_expected_content_type(response.headers.get(CONTENT_TYPE), expected_content_type) {
        return Err(AwsFailure::InvalidResponse);
    }
    if response.body.len() > maximum || response.body.is_empty() {
        return Err(AwsFailure::InvalidResponse);
    }
    Ok(response.body.as_slice())
}

fn is_expected_content_type(value: Option<&HeaderValue>, expected: &str) -> bool {
    value
        .and_then(|value| value.to_str().ok())
        .map(|value| value.split(';').next().unwrap_or_default().trim())
        .is_some_and(|value| value.eq_ignore_ascii_case(expected))
}

// --- SigV4 -------------------------------------------------------------------

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
        .expect("HMAC-SHA256 accepts a key of any length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn amz_timestamps(now: &OffsetDateTime) -> (String, String) {
    let date = format!(
        "{:04}{:02}{:02}",
        now.year(),
        u8::from(now.month()),
        now.day()
    );
    let stamp = format!(
        "{date}T{:02}{:02}{:02}Z",
        now.hour(),
        now.minute(),
        now.second()
    );
    (date, stamp)
}

/// Hashes the SigV4 canonical request incrementally, so the sensitive header
/// values (the session token in particular) are never concatenated into one
/// unmanaged plaintext buffer.
fn canonical_request_hash(
    method: &str,
    path: &str,
    query: &str,
    canonical_headers: &[(String, Zeroizing<String>)],
    signed_headers: &str,
    payload_hash: &str,
) -> String {
    let mut digest = Sha256::new();
    for piece in [method, "\n", path, "\n", query, "\n"] {
        digest.update(piece.as_bytes());
    }
    for (name, value) in canonical_headers {
        digest.update(name.as_bytes());
        digest.update(b":");
        digest.update(value.trim().as_bytes());
        digest.update(b"\n");
    }
    for piece in ["\n", signed_headers, "\n", payload_hash] {
        digest.update(piece.as_bytes());
    }
    hex::encode(digest.finalize())
}

fn credential_scope(date: &str, region: &str, service: &str) -> String {
    format!("{date}/{region}/{service}/aws4_request")
}

fn signing_string(amz_date: &str, scope: &str, canonical_request_hash: &str) -> String {
    format!("AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{canonical_request_hash}")
}

fn derive_signing_key(
    secret_access_key: &[u8],
    date: &str,
    region: &str,
    service: &str,
) -> Zeroizing<[u8; 32]> {
    let mut initial = Zeroizing::new(Vec::with_capacity(4 + secret_access_key.len()));
    initial.extend_from_slice(b"AWS4");
    initial.extend_from_slice(secret_access_key);
    let date_key = Zeroizing::new(hmac_sha256(&initial, date.as_bytes()));
    let region_key = Zeroizing::new(hmac_sha256(date_key.as_ref(), region.as_bytes()));
    let service_key = Zeroizing::new(hmac_sha256(region_key.as_ref(), service.as_bytes()));
    Zeroizing::new(hmac_sha256(service_key.as_ref(), b"aws4_request"))
}

// --- Response parsing --------------------------------------------------------

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

    fn take_text(&mut self) -> Result<Zeroizing<String>, AwsFailure> {
        let value = Zeroizing::new(std::mem::take(&mut *self.0));
        if value.is_empty()
            || value.len() > MAX_AWS_CREDENTIAL_TEXT_BYTES
            || value.bytes().any(|byte| !(0x21..=0x7e).contains(&byte))
        {
            return Err(AwsFailure::IdentityInvalid);
        }
        Ok(value)
    }
}

fn credential_text(bytes: &[u8]) -> Result<Zeroizing<String>, AwsFailure> {
    if bytes.is_empty()
        || bytes.len() > MAX_AWS_CREDENTIAL_TEXT_BYTES
        || bytes.iter().any(|byte| *byte < 0x21 || *byte > 0x7e)
    {
        return Err(AwsFailure::IdentityInvalid);
    }
    String::from_utf8(bytes.to_vec())
        .map(Zeroizing::new)
        .map_err(|_| AwsFailure::IdentityInvalid)
}

#[derive(Deserialize)]
struct StsLoginEnvelope {
    #[serde(rename = "AssumeRoleWithWebIdentityResponse")]
    response: StsLoginResponse,
}

#[derive(Deserialize)]
struct StsLoginResponse {
    #[serde(rename = "AssumeRoleWithWebIdentityResult")]
    result: StsLoginResult,
}

#[derive(Deserialize)]
struct StsLoginResult {
    #[serde(rename = "Credentials")]
    credentials: StsCredentials,
}

#[derive(Deserialize)]
struct StsCredentials {
    #[serde(rename = "AccessKeyId")]
    access_key_id: SecretText,
    #[serde(rename = "SecretAccessKey")]
    secret_access_key: SecretText,
    #[serde(rename = "SessionToken")]
    session_token: SecretText,
    #[serde(rename = "Expiration")]
    expiration: f64,
}

/// One top-level member of a JSON-structured `SecretString`.
///
/// String values are held in zeroizing storage; every other JSON shape is
/// discarded during deserialization so a sibling structure never lands in an
/// unmanaged allocation and never satisfies a member lookup.
enum AwsJsonValue {
    Text(Zeroizing<String>),
    Other,
}

impl<'de> Deserialize<'de> for AwsJsonValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(AwsJsonValueVisitor)
    }
}

struct AwsJsonValueVisitor;

impl<'de> Visitor<'de> for AwsJsonValueVisitor {
    type Value = AwsJsonValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a SecretString JSON member")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(AwsJsonValue::Text(Zeroizing::new(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(AwsJsonValue::Text(Zeroizing::new(value)))
    }

    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(AwsJsonValue::Other)
    }

    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(AwsJsonValue::Other)
    }

    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(AwsJsonValue::Other)
    }

    fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(AwsJsonValue::Other)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(AwsJsonValue::Other)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(AwsJsonValue::Other)
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
        Ok(AwsJsonValue::Other)
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: de::MapAccess<'de>,
    {
        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
        Ok(AwsJsonValue::Other)
    }
}

#[derive(Deserialize)]
struct GetSecretValueResponse {
    #[serde(rename = "ARN")]
    arn: Option<String>,
    #[serde(rename = "SecretString")]
    secret_string: Option<SecretText>,
    #[serde(rename = "SecretBinary")]
    secret_binary: Option<SecretText>,
    #[serde(rename = "VersionId")]
    version_id: Option<String>,
    #[serde(rename = "VersionStages")]
    #[serde(default)]
    version_stages: Option<Vec<String>>,
}

impl GetSecretValueResponse {
    fn into_value(
        self,
        alias: &AwsAliasBinding,
        purpose: SecretPurpose,
    ) -> Result<Zeroizing<Vec<u8>>, AwsFailure> {
        // The response must describe exactly the configured binding: the full
        // ARN and the pinned version or stage. Anything else is treated as an
        // invalid response, never silently accepted.
        if self.arn.as_deref() != Some(alias.arn.as_str()) {
            return Err(AwsFailure::InvalidResponse);
        }
        if let Some(pinned) = alias.version_id.as_deref() {
            if self.version_id.as_deref() != Some(pinned) {
                return Err(AwsFailure::InvalidResponse);
            }
        } else {
            let expected = alias.version_stage.as_deref().unwrap_or(AWS_CURRENT_STAGE);
            if !self
                .version_stages
                .iter()
                .flatten()
                .any(|stage| stage == expected)
            {
                return Err(AwsFailure::InvalidResponse);
            }
        }
        let value = match (self.secret_string, self.secret_binary) {
            (Some(_), Some(_)) => return Err(AwsFailure::InvalidResponse),
            (None, None) => return Err(AwsFailure::SecretAbsent),
            (Some(mut text), None) => {
                if let Some(member) = alias.json_key.as_deref() {
                    extract_json_member(&mut text, member)?
                } else {
                    text.take_bytes()
                }
            }
            (None, Some(mut binary)) => {
                if alias.json_key.is_some() {
                    return Err(AwsFailure::InvalidMaterial);
                }
                let encoded = binary.take_bytes();
                let decoded = BASE64_STANDARD
                    .decode(encoded.as_slice())
                    .map_err(|_| AwsFailure::InvalidResponse)?;
                Zeroizing::new(decoded)
            }
        };
        if value.is_empty() || value.len() > purpose.max_bytes() || value.contains(&0) {
            return Err(AwsFailure::InvalidMaterial);
        }
        Ok(value)
    }
}

fn extract_json_member(
    text: &mut SecretText,
    member: &str,
) -> Result<Zeroizing<Vec<u8>>, AwsFailure> {
    let bytes = text.take_bytes();
    let data: BTreeMap<String, AwsJsonValue> =
        serde_json::from_slice(&bytes).map_err(|_| AwsFailure::InvalidMaterial)?;
    match data.get(member) {
        Some(AwsJsonValue::Text(value)) => Ok(Zeroizing::new(value.as_bytes().to_vec())),
        Some(AwsJsonValue::Other) => Err(AwsFailure::InvalidMaterial),
        None => Err(AwsFailure::SecretAbsent),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;

    const VALUE_CANARY: &str = "greengateway-aws-value-canary";
    const ACCESS_KEY_CANARY: &str = "ASIACANARYACCESSKEY0";
    const SECRET_KEY_CANARY: &str = "aws-secret-access-key-canary/EXAMPLE";
    const SESSION_TOKEN_CANARY: &str = "IQoJsession-token-canary-material==";
    const STS_ENDPOINT_CANARY: &str = "https://sts.locator-canary.example";
    const ARN_CANARY: &str =
        "arn:aws:secretsmanager:us-east-1:123456789012:secret:team-canary/billing-canary-AbC123";
    const ROLE_ARN_CANARY: &str = "arn:aws:iam::123456789012:role/greengateway-role-canary";
    const VERSION_ID_CANARY: &str = "12345678-1234-1234-1234-123456789012";
    const MEMBER_CANARY: &str = "member-locator-canary";

    type Responder = dyn Fn() -> Result<AwsHttpResponse, EgressError> + Send + Sync;

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct RecordedRequest {
        method: String,
        url: String,
        authorization: Option<String>,
        target: Option<String>,
        security_token: Option<String>,
        amz_date: Option<String>,
        content_type: Option<String>,
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

    struct FakeAws {
        requests: Mutex<Vec<RecordedRequest>>,
        identities: Mutex<FakeChannel>,
        reads: Mutex<FakeChannel>,
        generation: AtomicU64,
        delay: Mutex<Duration>,
    }

    impl FakeAws {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                requests: Mutex::new(Vec::new()),
                identities: Mutex::new(FakeChannel::default()),
                reads: Mutex::new(FakeChannel::default()),
                generation: AtomicU64::new(0),
                delay: Mutex::new(Duration::ZERO),
            })
        }

        fn push_identity(&self, responder: Arc<Responder>) {
            self.identities
                .lock()
                .expect("fake identity queue should lock")
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
                .filter(|request| request.url.contains("secretsmanager."))
                .collect()
        }

        fn identities(&self) -> Vec<RecordedRequest> {
            self.requests()
                .into_iter()
                .filter(|request| !request.url.contains("secretsmanager."))
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
    impl AwsTransport for FakeAws {
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
        ) -> Result<AwsHttpResponse, EgressError> {
            let header_text = |name: &str| {
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
                    authorization: header_text("authorization"),
                    target: header_text(AMZ_TARGET_HEADER),
                    security_token: header_text(AMZ_SECURITY_TOKEN_HEADER),
                    amz_date: header_text(AMZ_DATE_HEADER),
                    content_type: header_text("content-type"),
                    body: body.map(|body| String::from_utf8_lossy(&body).into_owned()),
                });
            let delay = *self.delay.lock().expect("fake delay should lock");
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            let queue = if url.contains("secretsmanager.") {
                &self.reads
            } else {
                &self.identities
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
            Ok(AwsHttpResponse {
                status: StatusCode::from_u16(status).expect("test status should be valid"),
                headers,
                body: Zeroizing::new(body.clone().into_bytes()),
            })
        })
    }

    fn json_response(status: u16, body: &str) -> Arc<Responder> {
        response(status, AWS_JSON_CONTENT_TYPE, body)
    }

    fn sts_response(status: u16, body: &str) -> Arc<Responder> {
        response(status, "application/json", body)
    }

    fn egress_failure(build: impl Fn() -> EgressError + Send + Sync + 'static) -> Arc<Responder> {
        Arc::new(move || Err(build()))
    }

    fn sts_body(expiration: f64) -> String {
        format!(
            r#"{{"AssumeRoleWithWebIdentityResponse":{{"AssumeRoleWithWebIdentityResult":{{"Credentials":{{"AccessKeyId":"{ACCESS_KEY_CANARY}","SecretAccessKey":"{SECRET_KEY_CANARY}","SessionToken":"{SESSION_TOKEN_CANARY}","Expiration":{expiration}}},"SubjectFromWebIdentityToken":"sub"}},"ResponseMetadata":{{"RequestId":"abc"}}}}}}"#
        )
    }

    fn read_body(value: &str) -> String {
        read_body_with(ARN_CANARY, value, VERSION_ID_CANARY, &["AWSCURRENT"])
    }

    fn read_body_with(arn: &str, value: &str, version_id: &str, stages: &[&str]) -> String {
        let stages = stages
            .iter()
            .map(|stage| format!("\"{stage}\""))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            r#"{{"ARN":"{arn}","Name":"team-canary/billing-canary","VersionId":"{version_id}","SecretString":"{value}","VersionStages":[{stages}]}}"#
        )
    }

    fn binary_read_body(value: &[u8]) -> String {
        format!(
            r#"{{"ARN":"{ARN_CANARY}","Name":"team-canary/billing-canary","VersionId":"{VERSION_ID_CANARY}","SecretBinary":"{}","VersionStages":["AWSCURRENT"]}}"#,
            BASE64_STANDARD.encode(value)
        )
    }

    struct TestClock {
        now: Mutex<Instant>,
        wall: Mutex<SystemTime>,
    }

    impl TestClock {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                now: Mutex::new(Instant::now()),
                wall: Mutex::new(SystemTime::now()),
            })
        }

        fn advance(&self, step: Duration) {
            let mut now = self.now.lock().expect("test clock should lock");
            *now += step;
            let mut wall = self.wall.lock().expect("test clock should lock");
            *wall += step;
        }

        fn wall_epoch(&self) -> f64 {
            self.wall
                .lock()
                .expect("test clock should lock")
                .duration_since(UNIX_EPOCH)
                .expect("test wall clock should be after the epoch")
                .as_secs_f64()
        }

        fn pin_wall(&self, epoch_seconds: u64) {
            *self.wall.lock().expect("test clock should lock") =
                UNIX_EPOCH + Duration::from_secs(epoch_seconds);
        }
    }

    impl AwsClock for TestClock {
        fn now(&self) -> Instant {
            *self.now.lock().expect("test clock should lock")
        }

        fn wall(&self) -> SystemTime {
            *self.wall.lock().expect("test clock should lock")
        }
    }

    fn static_profile(id: &str) -> AwsProfileConfig {
        AwsProfileConfig {
            id: id.to_owned(),
            sts_endpoint: STS_ENDPOINT_CANARY.to_owned(),
            auth: AwsAuthConfig::StaticKeys {
                access_key_id_alias: "bootstrap-access-key-id".to_owned(),
                secret_access_key_alias: "bootstrap-secret-access-key".to_owned(),
            },
        }
    }

    fn web_identity_profile(id: &str, token_root: &str) -> AwsProfileConfig {
        AwsProfileConfig {
            id: id.to_owned(),
            sts_endpoint: STS_ENDPOINT_CANARY.to_owned(),
            auth: AwsAuthConfig::WebIdentity {
                role_arn: ROLE_ARN_CANARY.to_owned(),
                token_root: token_root.to_owned(),
                token_file: "token".to_owned(),
            },
        }
    }

    fn alias(id: &str) -> AwsSecretAliasConfig {
        AwsSecretAliasConfig {
            id: id.to_owned(),
            label: format!("{id} label"),
            profile: "primary".to_owned(),
            arn: ARN_CANARY.to_owned(),
            version_id: None,
            version_stage: None,
            json_key: None,
        }
    }

    struct FakeBootstrap {
        values: BTreeMap<String, Vec<u8>>,
    }

    impl FakeBootstrap {
        fn keys() -> Arc<Self> {
            Arc::new(Self {
                values: BTreeMap::from([
                    (
                        "bootstrap-access-key-id".to_owned(),
                        ACCESS_KEY_CANARY.as_bytes().to_vec(),
                    ),
                    (
                        "bootstrap-secret-access-key".to_owned(),
                        SECRET_KEY_CANARY.as_bytes().to_vec(),
                    ),
                ]),
            })
        }
    }

    #[async_trait]
    impl SecretResolver for FakeBootstrap {
        async fn resolve(
            &self,
            alias_id: &str,
            purpose: SecretPurpose,
        ) -> Result<ResolvedSecret, SecretResolveError> {
            let value = self.values.get(alias_id).ok_or_else(|| {
                SecretResolveError::new(alias_id, SecretResolveErrorKind::UnknownAlias)
            })?;
            ResolvedSecret::new(purpose, value.clone()).map_err(|_| {
                SecretResolveError::new(alias_id, SecretResolveErrorKind::InvalidMaterial)
            })
        }

        fn contains_alias(&self, alias_id: &str) -> bool {
            self.values.contains_key(alias_id)
        }

        fn aliases(&self) -> Vec<SecretAliasMetadata> {
            Vec::new()
        }
    }

    struct ProviderFixture {
        provider: AwsSecretsManagerProvider,
        aws: Arc<FakeAws>,
        clock: Arc<TestClock>,
    }

    fn provider(aliases: Vec<AwsSecretAliasConfig>) -> ProviderFixture {
        provider_with_bootstrap(
            AwsProviderConfig {
                profiles: vec![static_profile("primary")],
                aliases,
            },
            Some(FakeBootstrap::keys() as Arc<dyn SecretResolver>),
        )
    }

    fn provider_with_bootstrap(
        config: AwsProviderConfig,
        bootstrap: Option<Arc<dyn SecretResolver>>,
    ) -> ProviderFixture {
        let aws = FakeAws::new();
        let clock = TestClock::new();
        let mut provider = AwsSecretsManagerProvider::from_config(
            &config,
            &BTreeSet::new(),
            Arc::clone(&aws) as Arc<dyn AwsTransport>,
            bootstrap,
        )
        .expect("test provider should build");
        provider.clock = Arc::clone(&clock) as Arc<dyn AwsClock>;
        ProviderFixture {
            provider,
            aws,
            clock,
        }
    }

    #[test]
    fn configuration_rejects_unsafe_or_ambiguous_entries() {
        let base = |profiles: Vec<AwsProfileConfig>, aliases: Vec<AwsSecretAliasConfig>| {
            validate_aws_provider_config(&AwsProviderConfig { profiles, aliases }, &BTreeSet::new())
        };
        for endpoint in [
            "http://sts.amazonaws.com",
            "https://user:pass@sts.amazonaws.com",
            "https://sts.amazonaws.com/assume",
            "https://sts.amazonaws.com?token=x",
            "https://sts.amazonaws.com#fragment",
            "sts.amazonaws.com",
            "",
        ] {
            let mut profile = static_profile("primary");
            profile.sts_endpoint = endpoint.to_owned();
            assert!(
                matches!(
                    base(vec![profile], Vec::new()),
                    Err(AwsProviderConfigError::InvalidStsEndpoint { .. })
                ),
                "{endpoint:?} must be rejected"
            );
        }
        for arn in [
            // Partial ARN without the random suffix: a name lookup, not a binding.
            "arn:aws:secretsmanager:us-east-1:123456789012:secret:team/billing",
            // Bare name and empty values.
            "team/billing",
            "",
            // Wrong service, partition, malformed account, missing region.
            "arn:aws:ssm:us-east-1:123456789012:secret:team/billing-AbC123",
            "arn:aws-cn:secretsmanager:cn-north-1:123456789012:secret:team/billing-AbC123",
            "arn:aws:secretsmanager:us-east-1:1234:secret:team/billing-AbC123",
            "arn:aws:secretsmanager::123456789012:secret:team/billing-AbC123",
            "arn:aws:secretsmanager:us-east-1:123456789012:parameter:team/billing-AbC123",
            // Wildcards and unsafe bytes are never a fixed binding.
            "arn:aws:secretsmanager:us-east-1:123456789012:secret:team/*-AbC123",
            "arn:aws:secretsmanager:us-east-1:123456789012:secret:team/bil ling-AbC123",
        ] {
            let mut entry = alias("billing");
            entry.arn = arn.to_owned();
            assert!(
                matches!(
                    base(vec![static_profile("primary")], vec![entry]),
                    Err(AwsProviderConfigError::InvalidSecretArn { .. })
                ),
                "{arn:?} must be rejected"
            );
        }
        let mut ambiguous = alias("billing");
        ambiguous.version_id = Some(VERSION_ID_CANARY.to_owned());
        ambiguous.version_stage = Some("AWSCURRENT".to_owned());
        assert!(matches!(
            base(vec![static_profile("primary")], vec![ambiguous]),
            Err(AwsProviderConfigError::AmbiguousVersionSelection { .. })
        ));
        let mut previous = alias("billing");
        previous.version_stage = Some(AWS_PREVIOUS_STAGE.to_owned());
        assert!(matches!(
            base(vec![static_profile("primary")], vec![previous]),
            Err(AwsProviderConfigError::ForbiddenVersionStage { .. })
        ));
        let mut short_version = alias("billing");
        short_version.version_id = Some("short".to_owned());
        assert!(matches!(
            base(vec![static_profile("primary")], vec![short_version]),
            Err(AwsProviderConfigError::InvalidVersionId { .. })
        ));
        let mut bad_stage = alias("billing");
        bad_stage.version_stage = Some("stage with spaces".to_owned());
        assert!(matches!(
            base(vec![static_profile("primary")], vec![bad_stage]),
            Err(AwsProviderConfigError::InvalidVersionStage { .. })
        ));
        let mut bad_member = alias("billing");
        bad_member.json_key = Some("control\u{7}char".to_owned());
        assert!(matches!(
            base(vec![static_profile("primary")], vec![bad_member]),
            Err(AwsProviderConfigError::InvalidJsonMember { .. })
        ));
        let mut bad_role = static_profile("primary");
        bad_role.auth = AwsAuthConfig::WebIdentity {
            role_arn: "arn:aws:iam::123456789012:user/not-a-role".to_owned(),
            token_root: "/var/run/secrets/tokens".to_owned(),
            token_file: "token".to_owned(),
        };
        assert!(matches!(
            base(vec![bad_role], Vec::new()),
            Err(AwsProviderConfigError::InvalidRoleArn { .. })
        ));
        let mut duplicate = alias("billing");
        duplicate.id = "billing".to_owned();
        assert!(matches!(
            base(
                vec![static_profile("primary")],
                vec![alias("billing"), duplicate],
            ),
            Err(AwsProviderConfigError::DuplicateAliasId { .. })
        ));
        let mut unknown_profile = alias("billing");
        unknown_profile.profile = "missing".to_owned();
        assert!(matches!(
            base(vec![static_profile("primary")], vec![unknown_profile]),
            Err(AwsProviderConfigError::UnknownProfile { .. })
        ));
        let mut cycle = static_profile("primary");
        cycle.auth = AwsAuthConfig::StaticKeys {
            access_key_id_alias: "billing".to_owned(),
            secret_access_key_alias: "bootstrap-secret-access-key".to_owned(),
        };
        assert!(matches!(
            base(vec![cycle], vec![alias("billing")]),
            Err(AwsProviderConfigError::BootstrapAliasCycle { .. })
        ));
        assert!(matches!(
            base(Vec::new(), vec![alias("billing")]),
            Err(AwsProviderConfigError::AliasesWithoutProfiles)
        ));
        assert!(matches!(
            validate_aws_provider_config(
                &AwsProviderConfig {
                    profiles: vec![static_profile("primary")],
                    aliases: vec![alias("billing")],
                },
                &BTreeSet::from(["billing".to_owned()]),
            ),
            Err(AwsProviderConfigError::ReservedAliasId { .. })
        ));
        let profiles = (0..=MAX_AWS_PROFILES)
            .map(|index| static_profile(&format!("profile-{index}")))
            .collect::<Vec<_>>();
        assert!(matches!(
            base(profiles, Vec::new()),
            Err(AwsProviderConfigError::TooManyProfiles { .. })
        ));
    }

    #[tokio::test]
    async fn unknown_alias_denial_produces_zero_provider_work() {
        let fixture = provider(vec![alias("billing")]);
        fixture
            .aws
            .push_read(json_response(200, &read_body(VALUE_CANARY)));

        let error = fixture
            .provider
            .resolve("not-configured", SecretPurpose::StaticBearer)
            .await
            .expect_err("unknown alias must fail closed");

        assert_eq!(error.kind(), SecretResolveErrorKind::UnknownAlias);
        assert!(fixture.aws.requests().is_empty());
    }

    #[tokio::test]
    async fn saturated_provider_admission_fails_before_any_provider_work() {
        let fixture = provider(vec![alias("billing")]);
        fixture
            .aws
            .push_read(json_response(200, &read_body(VALUE_CANARY)));
        let mut provider = fixture.provider.clone();
        provider.concurrent_reads = Arc::new(Semaphore::new(0));

        let error = provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect_err("saturated admission must fail closed");

        assert_eq!(error.kind(), SecretResolveErrorKind::ProviderBusy);
        assert!(fixture.aws.requests().is_empty());
    }

    #[tokio::test]
    async fn static_key_reads_sign_only_get_secret_value_without_any_sts_call() {
        let fixture = provider(vec![alias("billing")]);
        fixture
            .aws
            .push_read(json_response(200, &read_body(VALUE_CANARY)));

        let secret = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("configured alias should resolve");

        assert_eq!(secret.expose(), VALUE_CANARY.as_bytes());
        assert!(fixture.aws.identities().is_empty());
        let reads = fixture.aws.reads();
        assert_eq!(reads.len(), 1);
        let read = &reads[0];
        assert_eq!(read.method, "POST");
        assert_eq!(read.url, "https://secretsmanager.us-east-1.amazonaws.com/");
        assert_eq!(read.target.as_deref(), Some(AWS_GET_SECRET_VALUE_TARGET));
        assert_eq!(read.content_type.as_deref(), Some(AWS_JSON_CONTENT_TYPE));
        assert!(read.security_token.is_none());
        let authorization = read.authorization.as_deref().unwrap_or_default();
        assert!(authorization.starts_with("AWS4-HMAC-SHA256 Credential="));
        assert!(authorization.contains(ACCESS_KEY_CANARY));
        assert!(authorization.contains("/us-east-1/secretsmanager/aws4_request"));
        assert!(authorization.contains("SignedHeaders=content-type;host;x-amz-date;x-amz-target"));
        assert!(!authorization.contains(SECRET_KEY_CANARY));
        let body = read.body.as_deref().unwrap_or_default();
        assert!(body.contains(&format!("\"SecretId\":\"{ARN_CANARY}\"")));
        assert!(body.contains("\"VersionStage\":\"AWSCURRENT\""));
        assert!(!body.contains("VersionId"));
    }

    #[tokio::test]
    async fn web_identity_reads_authenticate_first_through_the_fixed_sts_endpoint() {
        let root = std::env::temp_dir().join(format!(
            "greengateway-aws-workload-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir(&root).expect("workload root should create");
        set_projected_permissions(&root);
        fs::write(root.join("token"), b"projected.jwt.canary").expect("token should write");
        set_projected_file_permissions(&root.join("token"));
        let fixture = provider_with_bootstrap(
            AwsProviderConfig {
                profiles: vec![web_identity_profile(
                    "primary",
                    root.to_str().expect("root path should be Unicode"),
                )],
                aliases: vec![alias("billing")],
            },
            None,
        );
        fixture.aws.push_identity(sts_response(
            200,
            &sts_body(fixture.clock.wall_epoch() + 600.0),
        ));
        fixture
            .aws
            .push_read(json_response(200, &read_body(VALUE_CANARY)));

        let secret = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("workload identity read should resolve");

        assert_eq!(secret.expose(), VALUE_CANARY.as_bytes());
        let identities = fixture.aws.identities();
        assert_eq!(identities.len(), 1);
        let login = &identities[0];
        assert_eq!(login.method, "POST");
        assert_eq!(login.url, format!("{STS_ENDPOINT_CANARY}/"));
        assert!(
            login.authorization.is_none(),
            "the STS exchange is unsigned"
        );
        let body = login.body.as_deref().unwrap_or_default();
        assert!(body.contains("Action=AssumeRoleWithWebIdentity"));
        assert!(body.contains("projected.jwt.canary"));
        assert!(body.contains("RoleSessionName=greengateway"));
        assert!(body.contains(&utf8_percent_encode(ROLE_ARN_CANARY, STS_FORM_ENCODE).to_string()));
        let reads = fixture.aws.reads();
        assert_eq!(reads.len(), 1);
        assert_eq!(
            reads[0].security_token.as_deref(),
            Some(SESSION_TOKEN_CANARY)
        );
        let authorization = reads[0].authorization.as_deref().unwrap_or_default();
        assert!(authorization.contains(ACCESS_KEY_CANARY));
        assert!(authorization.contains(
            "SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;x-amz-target"
        ));

        // Release the pinned token-root handle before removing the fixture
        // directory; Windows refuses to remove a directory with an open handle.
        drop(fixture);
        fs::remove_dir_all(&root).expect("workload root should remove");
    }

    #[cfg(unix)]
    fn set_projected_permissions(path: &std::path::Path) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))
            .expect("workload root permissions should update");
    }

    #[cfg(not(unix))]
    fn set_projected_permissions(_: &std::path::Path) {}

    #[cfg(unix)]
    fn set_projected_file_permissions(path: &std::path::Path) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o644))
            .expect("token permissions should update");
    }

    #[cfg(not(unix))]
    fn set_projected_file_permissions(_: &std::path::Path) {}

    #[cfg(unix)]
    #[tokio::test]
    async fn a_world_writable_workload_identity_token_fails_closed() {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!(
            "greengateway-aws-workload-perm-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir(&root).expect("workload root should create");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755))
            .expect("workload root permissions should update");
        fs::write(root.join("token"), b"projected.jwt.canary").expect("token should write");
        fs::set_permissions(root.join("token"), fs::Permissions::from_mode(0o666))
            .expect("token permissions should update");
        let fixture = provider_with_bootstrap(
            AwsProviderConfig {
                profiles: vec![web_identity_profile(
                    "primary",
                    root.to_str().expect("root path should be Unicode"),
                )],
                aliases: vec![alias("billing")],
            },
            None,
        );

        let error = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect_err("a world-writable identity token must fail closed");
        assert_eq!(error.kind(), SecretResolveErrorKind::SourceDenied);
        assert!(fixture.aws.requests().is_empty());

        drop(fixture);
        fs::remove_dir_all(&root).expect("workload root should remove");
    }

    #[tokio::test]
    async fn reads_never_proceed_without_an_authenticated_identity() {
        let fixture = provider(vec![alias("billing")]);
        fixture
            .aws
            .push_read(json_response(200, &read_body(VALUE_CANARY)));
        let provider = AwsSecretsManagerProvider {
            bootstrap: None,
            ..fixture.provider.clone()
        };

        let error = provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect_err("a provider without an identity source must fail closed");

        assert_eq!(error.kind(), SecretResolveErrorKind::ProviderFailure);
        assert!(fixture.aws.reads().is_empty());
    }

    #[tokio::test]
    async fn egress_denials_and_refused_redirects_fail_closed() {
        for (responder, expected) in [
            (
                egress_failure(|| EgressError::HostNotAllowed("secretsmanager".to_owned())),
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
            let fixture = provider(vec![alias("billing")]);
            fixture.aws.push_read(responder);

            let error = fixture
                .provider
                .resolve("billing", SecretPurpose::StaticBearer)
                .await
                .expect_err("egress denial must fail closed");

            assert_eq!(error.kind(), expected);
            assert_eq!(fixture.aws.reads().len(), 1);
        }
    }

    #[tokio::test]
    async fn dns_failure_retries_once_and_then_fails_closed() {
        let fixture = provider(vec![alias("billing")]);
        fixture.aws.push_read(egress_failure(|| {
            EgressError::DnsResolutionFailed("secretsmanager".to_owned())
        }));

        let error = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect_err("unreachable provider must fail closed");

        assert_eq!(error.kind(), SecretResolveErrorKind::SourceUnavailable);
        assert_eq!(
            fixture.aws.reads().len(),
            usize::try_from(MAX_AWS_TRANSIENT_RETRIES).expect("retry bound should fit") + 1
        );
    }

    #[tokio::test]
    async fn a_denied_read_reauthenticates_exactly_once() {
        let root =
            std::env::temp_dir().join(format!("greengateway-aws-reauth-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).expect("workload root should create");
        set_projected_permissions(&root);
        fs::write(root.join("token"), b"projected.jwt.canary").expect("token should write");
        set_projected_file_permissions(&root.join("token"));
        let fixture = provider_with_bootstrap(
            AwsProviderConfig {
                profiles: vec![web_identity_profile(
                    "primary",
                    root.to_str().expect("root path should be Unicode"),
                )],
                aliases: vec![alias("billing")],
            },
            None,
        );
        let epoch = fixture.clock.wall_epoch();
        fixture
            .aws
            .push_identity(sts_response(200, &sts_body(epoch + 600.0)));
        fixture
            .aws
            .push_identity(sts_response(200, &sts_body(epoch + 1200.0)));
        fixture.aws.push_read(json_response(
            403,
            r#"{"__type":"ExpiredTokenException","message":"expired"}"#,
        ));
        fixture
            .aws
            .push_read(json_response(200, &read_body(VALUE_CANARY)));

        let secret = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("a rotated identity should recover once");

        assert_eq!(secret.expose(), VALUE_CANARY.as_bytes());
        assert_eq!(fixture.aws.identities().len(), 2);
        assert_eq!(fixture.aws.reads().len(), 2);

        drop(fixture);
        fs::remove_dir_all(&root).expect("workload root should remove");
    }

    #[tokio::test]
    async fn newly_denied_access_fails_closed_without_a_stale_value() {
        let fixture = provider(vec![alias("billing")]);
        fixture
            .aws
            .push_read(json_response(200, &read_body(VALUE_CANARY)));
        let first = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("first read should resolve");
        assert_eq!(first.expose(), VALUE_CANARY.as_bytes());

        fixture.aws.push_read(json_response(
            400,
            r#"{"__type":"AccessDeniedException","message":"denied"}"#,
        ));
        fixture.aws.push_read(json_response(
            400,
            r#"{"__type":"AccessDeniedException","message":"denied"}"#,
        ));
        fixture.clock.advance(AWS_VALUE_CACHE_TTL * 2);

        let error = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect_err("newly denied access must fail closed");

        assert_eq!(error.kind(), SecretResolveErrorKind::SourceDenied);
        assert!(fixture.provider.value_guard().is_empty());
    }

    #[tokio::test]
    async fn absent_and_deleted_secrets_fail_closed() {
        for body in [
            r#"{"__type":"ResourceNotFoundException","message":"Secrets Manager can't find the specified secret."}"#,
            r#"{"__type":"InvalidRequestException","message":"marked for deletion"}"#,
        ] {
            let fixture = provider(vec![alias("billing")]);
            fixture.aws.push_read(json_response(400, body));

            let error = fixture
                .provider
                .resolve("billing", SecretPurpose::StaticBearer)
                .await
                .expect_err("absent material must fail closed");

            assert_eq!(error.kind(), SecretResolveErrorKind::SourceUnavailable);
        }
    }

    #[tokio::test]
    async fn malformed_oversized_and_mismatched_responses_fail_closed() {
        let oversized_value =
            read_body(&"x".repeat(super::super::secret::MAX_HTTP_CREDENTIAL_BYTES + 1));
        let empty_value = read_body("");
        let both_fields = format!(
            r#"{{"ARN":"{ARN_CANARY}","VersionId":"{VERSION_ID_CANARY}","SecretString":"{VALUE_CANARY}","SecretBinary":"{}","VersionStages":["AWSCURRENT"]}}"#,
            BASE64_STANDARD.encode(VALUE_CANARY)
        );
        let neither_field = format!(
            r#"{{"ARN":"{ARN_CANARY}","VersionId":"{VERSION_ID_CANARY}","VersionStages":["AWSCURRENT"]}}"#
        );
        let invalid_base64 = format!(
            r#"{{"ARN":"{ARN_CANARY}","VersionId":"{VERSION_ID_CANARY}","SecretBinary":"%%%not-base64%%%","VersionStages":["AWSCURRENT"]}}"#
        );
        let wrong_arn = read_body_with(
            "arn:aws:secretsmanager:us-east-1:123456789012:secret:other-secret-aaa002",
            VALUE_CANARY,
            VERSION_ID_CANARY,
            &["AWSCURRENT"],
        );
        let missing_stage =
            read_body_with(ARN_CANARY, VALUE_CANARY, VERSION_ID_CANARY, &["AWSPENDING"]);
        let oversized_body = format!(
            r#"{{"padding":"{}","ARN":"{ARN_CANARY}","SecretString":"{VALUE_CANARY}","VersionStages":["AWSCURRENT"]}}"#,
            "w".repeat(MAX_AWS_READ_RESPONSE_BYTES)
        );
        for (responder, expected) in [
            (
                json_response(200, "{not json"),
                SecretResolveErrorKind::InvalidMaterial,
            ),
            (
                json_response(200, &oversized_body),
                SecretResolveErrorKind::InvalidMaterial,
            ),
            (
                response(200, "text/html", &read_body(VALUE_CANARY)),
                SecretResolveErrorKind::InvalidMaterial,
            ),
            (
                json_response(200, &oversized_value),
                SecretResolveErrorKind::InvalidMaterial,
            ),
            (
                json_response(200, &empty_value),
                SecretResolveErrorKind::InvalidMaterial,
            ),
            (
                json_response(200, &both_fields),
                SecretResolveErrorKind::InvalidMaterial,
            ),
            (
                json_response(200, &neither_field),
                SecretResolveErrorKind::SourceUnavailable,
            ),
            (
                json_response(200, &invalid_base64),
                SecretResolveErrorKind::InvalidMaterial,
            ),
            (
                json_response(200, &wrong_arn),
                SecretResolveErrorKind::InvalidMaterial,
            ),
            (
                json_response(200, &missing_stage),
                SecretResolveErrorKind::InvalidMaterial,
            ),
        ] {
            let fixture = provider(vec![alias("billing")]);
            fixture.aws.push_read(responder);

            let error = fixture
                .provider
                .resolve("billing", SecretPurpose::StaticBearer)
                .await
                .expect_err("malformed provider data must fail closed");

            assert_eq!(error.kind(), expected);
            assert!(fixture.provider.value_guard().is_empty());
        }
    }

    #[tokio::test]
    async fn an_already_expired_sts_identity_is_rejected() {
        let root =
            std::env::temp_dir().join(format!("greengateway-aws-expired-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).expect("workload root should create");
        set_projected_permissions(&root);
        fs::write(root.join("token"), b"projected.jwt.canary").expect("token should write");
        set_projected_file_permissions(&root.join("token"));
        let fixture = provider_with_bootstrap(
            AwsProviderConfig {
                profiles: vec![web_identity_profile(
                    "primary",
                    root.to_str().expect("root path should be Unicode"),
                )],
                aliases: vec![alias("billing")],
            },
            None,
        );
        fixture.aws.push_identity(sts_response(
            200,
            &sts_body(fixture.clock.wall_epoch() - 100.0),
        ));
        fixture
            .aws
            .push_read(json_response(200, &read_body(VALUE_CANARY)));

        let error = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect_err("an already expired identity must be refused");

        assert_eq!(error.kind(), SecretResolveErrorKind::InvalidMaterial);
        assert!(fixture.aws.reads().is_empty());

        drop(fixture);
        fs::remove_dir_all(&root).expect("workload root should remove");
    }

    /// STS is a Query-protocol service: it throttles with `Error.Code`
    /// "Throttling" ("Rate exceeded") rather than a JSON-protocol
    /// `ThrottlingException`. That spelling must classify as transient (one
    /// bounded retry), never as a permanent identity denial.
    #[tokio::test]
    async fn sts_query_protocol_throttling_is_transient_and_retried_once() {
        for spelling in ["Throttling", "ThrottledException", "RequestThrottled"] {
            assert_eq!(
                classify_status(StatusCode::BAD_REQUEST, Some(spelling), true),
                Some(AwsFailure::IdentityUnavailable),
                "{spelling} must classify as a transient identity failure"
            );
        }

        let root = std::env::temp_dir().join(format!(
            "greengateway-aws-throttle-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir(&root).expect("workload root should create");
        set_projected_permissions(&root);
        fs::write(root.join("token"), b"projected.jwt.canary").expect("token should write");
        set_projected_file_permissions(&root.join("token"));
        let fixture = provider_with_bootstrap(
            AwsProviderConfig {
                profiles: vec![web_identity_profile(
                    "primary",
                    root.to_str().expect("root path should be Unicode"),
                )],
                aliases: vec![alias("billing")],
            },
            None,
        );
        fixture.aws.push_identity(sts_response(
            400,
            r#"{"Error":{"Code":"Throttling","Message":"Rate exceeded","Type":"Sender"},"RequestId":"abc"}"#,
        ));

        let error = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect_err("a persistently throttled identity must fail closed");

        assert_eq!(error.kind(), SecretResolveErrorKind::SourceUnavailable);
        assert_eq!(
            fixture.aws.identities().len(),
            usize::try_from(MAX_AWS_TRANSIENT_RETRIES).expect("retry bound should fit") + 1
        );
        assert!(fixture.aws.reads().is_empty());

        drop(fixture);
        fs::remove_dir_all(&root).expect("workload root should remove");
    }

    #[tokio::test]
    async fn awscurrent_rotation_becomes_visible_after_cache_expiry() {
        let fixture = provider(vec![alias("billing")]);
        fixture
            .aws
            .push_read(json_response(200, &read_body("first-value")));

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
        assert_eq!(fixture.aws.reads().len(), 1);

        fixture.aws.push_read(json_response(
            200,
            &read_body_with(
                ARN_CANARY,
                "second-value",
                "22345678-1234-1234-1234-123456789012",
                &["AWSCURRENT"],
            ),
        ));
        fixture
            .clock
            .advance(AWS_VALUE_CACHE_TTL + Duration::from_secs(1));

        let rotated = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("rotated read should resolve");

        assert_eq!(rotated.expose(), b"second-value");
        assert_eq!(fixture.aws.reads().len(), 2);
        assert_eq!(first.expose(), b"first-value");
        for read in fixture.aws.reads() {
            assert!(read
                .body
                .as_deref()
                .unwrap_or_default()
                .contains("\"VersionStage\":\"AWSCURRENT\""));
        }
    }

    #[tokio::test]
    async fn pinned_version_ids_stay_pinned_and_reject_a_different_version() {
        let mut pinned = alias("billing");
        pinned.version_id = Some(VERSION_ID_CANARY.to_owned());
        let fixture = provider(vec![pinned]);
        fixture.aws.push_read(json_response(
            200,
            &read_body_with(
                ARN_CANARY,
                "pinned-value",
                VERSION_ID_CANARY,
                &["AWSPENDING"],
            ),
        ));

        let value = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("pinned read should resolve");
        assert_eq!(value.expose(), b"pinned-value");
        let body = fixture.aws.reads()[0].body.clone().unwrap_or_default();
        assert!(body.contains(&format!("\"VersionId\":\"{VERSION_ID_CANARY}\"")));
        assert!(!body.contains("VersionStage"));

        fixture.aws.push_read(json_response(
            200,
            &read_body_with(
                ARN_CANARY,
                "newer-value",
                "99945678-1234-1234-1234-123456789012",
                &["AWSCURRENT"],
            ),
        ));
        fixture.clock.advance(AWS_VALUE_CACHE_TTL * 2);

        let error = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect_err("a pinned alias must refuse a different version");

        assert_eq!(error.kind(), SecretResolveErrorKind::InvalidMaterial);
    }

    #[tokio::test]
    async fn pinned_stages_are_requested_and_verified_explicitly() {
        let mut pinned = alias("billing");
        pinned.version_stage = Some("blue".to_owned());
        let fixture = provider(vec![pinned]);
        fixture.aws.push_read(json_response(
            200,
            &read_body_with(
                ARN_CANARY,
                VALUE_CANARY,
                VERSION_ID_CANARY,
                &["blue", "AWSCURRENT"],
            ),
        ));

        let value = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("stage-pinned read should resolve");
        assert_eq!(value.expose(), VALUE_CANARY.as_bytes());
        let body = fixture.aws.reads()[0].body.clone().unwrap_or_default();
        assert!(body.contains("\"VersionStage\":\"blue\""));

        fixture.aws.push_read(json_response(
            200,
            &read_body_with(ARN_CANARY, VALUE_CANARY, VERSION_ID_CANARY, &["AWSCURRENT"]),
        ));
        fixture.clock.advance(AWS_VALUE_CACHE_TTL * 2);
        let error = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect_err("a response without the pinned stage must be refused");
        assert_eq!(error.kind(), SecretResolveErrorKind::InvalidMaterial);
    }

    #[tokio::test]
    async fn json_member_extraction_is_fixed_and_bounded() {
        let mut member_alias = alias("billing");
        member_alias.json_key = Some(MEMBER_CANARY.to_owned());
        let escaped = format!(
            r#"{{\"{MEMBER_CANARY}\":\"{VALUE_CANARY}\",\"sibling\":{{\"nested\":true}}}}"#
        );
        let fixture = provider(vec![member_alias.clone()]);
        fixture
            .aws
            .push_read(json_response(200, &read_body(&escaped)));

        let value = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("member extraction should resolve");
        assert_eq!(value.expose(), VALUE_CANARY.as_bytes());

        // Missing member fails as absent; a structured member fails as invalid.
        let missing = format!(r#"{{\"other\":\"{VALUE_CANARY}\"}}"#);
        let structured = format!(r#"{{\"{MEMBER_CANARY}\":{{\"nested\":\"x\"}}}}"#);
        let not_json = "not-a-json-object";
        for (body, expected) in [
            (missing, SecretResolveErrorKind::SourceUnavailable),
            (structured, SecretResolveErrorKind::InvalidMaterial),
            (not_json.to_owned(), SecretResolveErrorKind::InvalidMaterial),
        ] {
            let fixture = provider(vec![member_alias.clone()]);
            fixture.aws.push_read(json_response(200, &read_body(&body)));
            let error = fixture
                .provider
                .resolve("billing", SecretPurpose::StaticBearer)
                .await
                .expect_err("member lookup must fail closed");
            assert_eq!(error.kind(), expected);
        }

        // A binary payload can never satisfy a JSON member binding.
        let fixture = provider(vec![member_alias]);
        fixture.aws.push_read(json_response(
            200,
            &binary_read_body(VALUE_CANARY.as_bytes()),
        ));
        let error = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect_err("binary material must not satisfy a JSON member binding");
        assert_eq!(error.kind(), SecretResolveErrorKind::InvalidMaterial);
    }

    #[tokio::test]
    async fn secret_binary_values_decode_within_purpose_bounds() {
        let fixture = provider(vec![alias("billing")]);
        fixture.aws.push_read(json_response(
            200,
            &binary_read_body(VALUE_CANARY.as_bytes()),
        ));

        let value = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("binary read should resolve");
        assert_eq!(value.expose(), VALUE_CANARY.as_bytes());
    }

    #[tokio::test]
    async fn concurrent_resolutions_are_hard_bounded() {
        let fixture = provider(vec![alias("billing")]);
        fixture
            .aws
            .push_read(json_response(200, &read_body(VALUE_CANARY)));
        fixture.aws.set_delay(Duration::from_millis(250));
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
        let fixture = provider(vec![alias("billing")]);
        fixture
            .aws
            .push_read(json_response(200, &read_body(VALUE_CANARY)));
        fixture.aws.set_delay(Duration::from_secs(30));
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
        let aliases = (0..MAX_AWS_VALUE_CACHE_ENTRIES + 4)
            .map(|index| alias(&format!("billing-{index}")))
            .collect::<Vec<_>>();
        let fixture = provider(aliases);
        fixture
            .aws
            .push_read(json_response(200, &read_body(VALUE_CANARY)));

        for index in 0..MAX_AWS_VALUE_CACHE_ENTRIES + 4 {
            fixture
                .provider
                .resolve(&format!("billing-{index}"), SecretPurpose::StaticBearer)
                .await
                .expect("each read should resolve");
        }

        assert!(fixture.provider.value_guard().len() <= MAX_AWS_VALUE_CACHE_ENTRIES);
    }

    #[tokio::test]
    async fn metadata_and_debug_output_never_expose_locators_credentials_or_values() {
        let mut pinned = alias("billing");
        pinned.version_id = Some(VERSION_ID_CANARY.to_owned());
        pinned.json_key = Some(MEMBER_CANARY.to_owned());
        let fixture = provider(vec![alias("billing")]);
        fixture
            .aws
            .push_read(json_response(200, &read_body(VALUE_CANARY)));
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
        let configuration = AwsProviderConfig {
            profiles: vec![
                static_profile("primary"),
                AwsProfileConfig {
                    id: "workload".to_owned(),
                    sts_endpoint: STS_ENDPOINT_CANARY.to_owned(),
                    auth: AwsAuthConfig::WebIdentity {
                        role_arn: ROLE_ARN_CANARY.to_owned(),
                        token_root: "/var/run/secrets/tokens-root-canary".to_owned(),
                        token_file: "token-file-canary".to_owned(),
                    },
                },
            ],
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
            AwsFailure::ProviderDenied.safe_reason().to_owned(),
            AwsFailure::SecretAbsent.safe_reason().to_owned(),
            format!("{}", AwsProviderConfigError::InvalidSecretArn { index: 0 }),
            format!(
                "{}",
                AwsProviderConfigError::InvalidStsEndpoint { index: 0 }
            ),
        ];
        for output in outputs {
            for canary in [
                VALUE_CANARY,
                SECRET_KEY_CANARY,
                SESSION_TOKEN_CANARY,
                "sts.locator-canary.example",
                "team-canary/billing-canary",
                "greengateway-role-canary",
                "tokens-root-canary",
                "token-file-canary",
                MEMBER_CANARY,
                VERSION_ID_CANARY,
            ] {
                assert!(
                    !output.contains(canary),
                    "{canary} must not appear in {output}"
                );
            }
        }
        let metadata = fixture.provider.aliases();
        assert_eq!(metadata.len(), 1);
        assert_eq!(metadata[0].provider, SecretProviderKind::AwsSecretsManager);
        assert_eq!(metadata[0].version, None);
        // This provider was built from the unpinned alias; the pinned one below
        // only feeds the Debug-redaction assertions above.
        assert!(!metadata[0].pinned);
        assert!(serde_json::to_string(&metadata)
            .expect("alias metadata should serialize")
            .contains("aws_secrets_manager"));
    }

    #[tokio::test]
    async fn an_explicit_version_id_reports_pinned_without_surfacing_the_identifier() {
        let mut pinned_alias = alias("billing");
        pinned_alias.version_id = Some(VERSION_ID_CANARY.to_owned());
        let pinned_fixture = provider(vec![pinned_alias]);
        let pinned_metadata = pinned_fixture.provider.aliases();
        assert!(pinned_metadata[0].pinned);
        assert_eq!(pinned_metadata[0].version, None);

        // A version stage is a movable label the provider follows, so it is not
        // a pin: the gateway still observes rotation behind it.
        let mut staged_alias = alias("billing");
        staged_alias.version_stage = Some("AWSCURRENT".to_owned());
        let staged_fixture = provider(vec![staged_alias]);
        assert!(!staged_fixture.provider.aliases()[0].pinned);

        // The bit is surfaced; the opaque identifier behind it never is.
        let serialized =
            serde_json::to_string(&pinned_metadata).expect("alias metadata should serialize");
        assert!(serialized.contains("\"pinned\":true"));
        assert!(!serialized.contains(VERSION_ID_CANARY));
    }

    #[test]
    fn every_failure_maps_to_a_bounded_safe_reason() {
        for failure in [
            AwsFailure::UnknownAlias,
            AwsFailure::ProviderBusy,
            AwsFailure::DeadlineExceeded,
            AwsFailure::EgressDenied,
            AwsFailure::RedirectRefused,
            AwsFailure::IdentityUnavailable,
            AwsFailure::IdentityDenied,
            AwsFailure::IdentityInvalid,
            AwsFailure::ProviderUnavailable,
            AwsFailure::ProviderDenied,
            AwsFailure::SecretAbsent,
            AwsFailure::InvalidResponse,
            AwsFailure::InvalidMaterial,
            AwsFailure::ProviderFailure,
        ] {
            let reason = failure.safe_reason();
            assert!(reason.len() <= 32);
            assert!(reason
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_'));
        }
    }

    /// Known-answer test for the SigV4 signing-key derivation, from the AWS
    /// "deriving a signing key" documentation example.
    #[test]
    fn sigv4_signing_key_derivation_matches_the_documented_vector() {
        let key = derive_signing_key(
            b"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20120215",
            "us-east-1",
            "iam",
        );
        assert_eq!(
            hex::encode(key.as_ref()),
            "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d"
        );
    }

    /// Known-answer test for a complete SigV4 signature, from the AWS
    /// Signature Version 4 documentation suite (`GET /?Action=ListUsers` to
    /// IAM on 20150830T123600Z).
    #[test]
    fn sigv4_full_signature_matches_the_documented_vector() {
        let canonical_headers = vec![
            (
                "content-type".to_owned(),
                Zeroizing::new("application/x-www-form-urlencoded; charset=utf-8".to_owned()),
            ),
            (
                "host".to_owned(),
                Zeroizing::new("iam.amazonaws.com".to_owned()),
            ),
            (
                "x-amz-date".to_owned(),
                Zeroizing::new("20150830T123600Z".to_owned()),
            ),
        ];
        let signed_headers = "content-type;host;x-amz-date";
        let canonical_hash = canonical_request_hash(
            "GET",
            "/",
            "Action=ListUsers&Version=2010-05-08",
            &canonical_headers,
            signed_headers,
            &sha256_hex(b""),
        );
        assert_eq!(
            canonical_hash,
            "f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59"
        );
        let scope = credential_scope("20150830", "us-east-1", "iam");
        let string_to_sign = signing_string("20150830T123600Z", &scope, &canonical_hash);
        let key = derive_signing_key(
            b"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20150830",
            "us-east-1",
            "iam",
        );
        let signature = hex::encode(hmac_sha256(key.as_ref(), string_to_sign.as_bytes()));
        assert_eq!(
            signature,
            "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
        );
    }

    /// End-to-end known-answer test for the dynamically assembled data-plane
    /// signature: `signed_read_headers` itself is driven with a pinned wall
    /// clock and fixed credentials, in both the session-token and no-token
    /// shapes. The expected values are derived independently of the production
    /// helpers — the canonical request, string to sign, and signing key are
    /// recomputed inline with raw SHA-256/HMAC steps laid out per the SigV4
    /// specification, and the final signatures are additionally pinned to
    /// literals computed outside this codebase — so an assembly regression
    /// (header order, payload-hash binding, date/scope skew) cannot
    /// self-verify.
    #[test]
    fn signed_read_headers_produces_the_reference_signature_end_to_end() {
        const REFERENCE_SECRET_KEY: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
        for (session_token, pinned_signature) in [
            (
                Some(SESSION_TOKEN_CANARY),
                "348dac126bacb6c6d1c6b34ba73b88ddbb94b51ac22d86fd8725174b47cac24a",
            ),
            (
                None,
                "d678892ed5e0f6bae346a7271fb56ba8214998281ef5a4f4e63b3ec4b6ff94b6",
            ),
        ] {
            let fixture = provider(vec![alias("billing")]);
            fixture.clock.pin_wall(1_440_938_160); // 20150830T123600Z
            let binding = fixture
                .provider
                .aliases
                .get("billing")
                .expect("alias binding should exist");
            let credentials = AwsSessionCredentials {
                access_key_id: Zeroizing::new("AKIDEXAMPLE".to_owned()),
                secret_access_key: Zeroizing::new(REFERENCE_SECRET_KEY.to_owned()),
                session_token: session_token.map(|token| Zeroizing::new(token.to_owned())),
            };
            let body = binding.request_body().expect("request body should build");
            assert_eq!(
                String::from_utf8_lossy(&body),
                format!(r#"{{"SecretId":"{ARN_CANARY}","VersionStage":"AWSCURRENT"}}"#),
                "the signed payload must be the deterministic request body"
            );

            let headers = fixture
                .provider
                .signed_read_headers(binding, &credentials, &body)
                .expect("signing should succeed");

            // Independent reference computation, step by step per the SigV4
            // specification, without the production signing helpers.
            let reference_hmac = |key: &[u8], data: &[u8]| -> Vec<u8> {
                let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
                    .expect("reference HMAC accepts any key length");
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            };
            let payload_hash = hex::encode(Sha256::digest(&body));
            let mut canonical = String::from(
                "POST\n/\n\ncontent-type:application/x-amz-json-1.1\nhost:secretsmanager.us-east-1.amazonaws.com\nx-amz-date:20150830T123600Z\n",
            );
            let mut signed = String::from("content-type;host;x-amz-date");
            if let Some(token) = session_token {
                canonical.push_str(&format!("x-amz-security-token:{token}\n"));
                signed.push_str(";x-amz-security-token");
            }
            canonical.push_str("x-amz-target:secretsmanager.GetSecretValue\n");
            signed.push_str(";x-amz-target");
            canonical.push_str(&format!("\n{signed}\n{payload_hash}"));
            let string_to_sign = format!(
                "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/secretsmanager/aws4_request\n{}",
                hex::encode(Sha256::digest(canonical.as_bytes()))
            );
            let key = reference_hmac(
                format!("AWS4{REFERENCE_SECRET_KEY}").as_bytes(),
                b"20150830",
            );
            let key = reference_hmac(&key, b"us-east-1");
            let key = reference_hmac(&key, b"secretsmanager");
            let key = reference_hmac(&key, b"aws4_request");
            let reference_signature = hex::encode(reference_hmac(&key, string_to_sign.as_bytes()));
            assert_eq!(
                reference_signature, pinned_signature,
                "the inline reference derivation must match the externally computed literal"
            );

            let authorization = headers
                .get(AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .expect("authorization header should be set");
            assert_eq!(
                authorization,
                format!(
                    "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/secretsmanager/aws4_request, SignedHeaders={signed}, Signature={pinned_signature}"
                )
            );
            assert_eq!(
                headers
                    .get(AMZ_DATE_HEADER)
                    .and_then(|value| value.to_str().ok()),
                Some("20150830T123600Z")
            );
            assert_eq!(
                headers
                    .get(AMZ_SECURITY_TOKEN_HEADER)
                    .and_then(|value| value.to_str().ok()),
                session_token
            );
        }
    }

    #[test]
    fn amz_timestamps_render_basic_iso8601() {
        let moment = OffsetDateTime::from_unix_timestamp(1_440_938_160)
            .expect("documented SigV4 timestamp should convert");
        let (date, stamp) = amz_timestamps(&moment);
        assert_eq!(date, "20150830");
        assert_eq!(stamp, "20150830T123600Z");
    }
}
