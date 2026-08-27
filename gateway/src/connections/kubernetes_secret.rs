//! Read-only Kubernetes Secrets API provider.
//!
//! The provider is one more implementation of the stable [`SecretResolver`]
//! contract. It adds no Connection authority, no secret CRUD service, and no
//! reveal or provider-proxy endpoint. Every provider locator (API-server URL,
//! namespace, Secret name, `data` key, token root, token file, bootstrap alias)
//! is fixed by trusted startup configuration and bound to one opaque alias, so
//! callers, tool arguments, and ordinary Connection mutations can only name an
//! alias that an operator already provisioned.
//!
//! Only the single-object read `GET
//! /api/v1/namespaces/{namespace}/secrets/{name}` is implemented. There is no
//! discovery, list, watch, write, rotate, delete, or administration path, no
//! kubeconfig parsing, no exec/auth plugin, no proxy, and no in-cluster
//! endpoint inference: the API server is always the explicitly configured
//! `server` URL, never `KUBERNETES_SERVICE_HOST` or any other ambient
//! environment. No request URL contains a caller-supplied byte; each alias
//! carries a request line that was assembled from validated, percent-encoded
//! segments once at startup.
//!
//! Every provider request travels through [`EgressClient`], so the deployment
//! egress policy (HTTPS, allowlisted host and port, strict CA, hostname and SNI
//! validation, all-answer DNS validation with exact address pinning, and a
//! disabled redirect policy) applies unchanged, and the provider derives its
//! transport with this module's response cap clamped in so the read bound is
//! enforced while a response is received. A profile may add one PEM CA bundle
//! (for API servers issued by a private cluster CA) to the verification trust
//! set of a derived egress client, read either from a platform-projected file
//! such as the kubelet-projected `ca.crt` or from an operator-provisioned
//! non-reveal alias; trust is only ever added through that explicit, validated
//! bundle and hostname verification still applies, so TLS is never weakened or
//! skipped. Rotation, revocation, deletion, malformed data, provider outage,
//! unavailable or invalid trust material, and newly denied access all fail
//! closed: a failed resolution purges any cached value for that alias and
//! never returns a previous value, retries anonymously, or switches credential
//! sources.

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
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
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

pub const MAX_KUBERNETES_PROFILES: usize = 8;
pub const MAX_KUBERNETES_SECRET_ALIASES: usize = MAX_CREDENTIALS;
pub const MAX_KUBERNETES_PROVIDER_CONFIG_BYTES: usize = 256 * 1024;
pub const MAX_CONCURRENT_KUBERNETES_RESOLUTIONS: usize = 8;

const MAX_KUBERNETES_SERVER_BYTES: usize = 512;
const MAX_KUBERNETES_TOKEN_ROOT_BYTES: usize = 512;
/// RFC 1123 DNS label bound: Kubernetes namespaces.
const MAX_DNS1123_LABEL_BYTES: usize = 63;
/// RFC 1123 DNS subdomain bound: Kubernetes Secret names.
const MAX_DNS1123_SUBDOMAIN_BYTES: usize = 253;
/// Kubernetes `data` key bound (apimachinery `IsConfigMapKey`).
const MAX_KUBERNETES_DATA_KEY_BYTES: usize = 253;
/// A Secret holds at most 1 MiB of decoded `data` (apimachinery
/// `MaxSecretSize`, summed over values), which Base64 expands to 1,398,104
/// bytes on the JSON read path, and its annotations are separately capped at
/// 256 KiB (`TotalAnnotationSizeLimitB`). Both maxima at once come to 1,660,248
/// bytes, so this bound clears a worst-case Secret with roughly 427 KiB left
/// for names, labels, and `managedFields`. It is not raised beyond that: an
/// oversized envelope is refused rather than truncated and misparsed, and the
/// cap is buffered per in-flight read, so it multiplies by
/// `MAX_CONCURRENT_KUBERNETES_RESOLUTIONS` against an API server that could be
/// hostile.
const MAX_KUBERNETES_READ_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_KUBERNETES_TOKEN_BYTES: usize = 8 * 1024;
/// Bearer material is cached for at most this long, so a kubelet-rotated
/// projected token or a rotated bootstrap alias is observed on the next
/// resolution after expiry, and a `401` forces an immediate re-read.
///
/// Sized against the projected-token contract rather than picked round: the
/// kubelet replaces a projected token once it passes 80% of its TTL, and
/// Kubernetes rejects an `expirationSeconds` below 600, so even the least-fresh
/// token this provider can read still has 120s of validity left. Caching for
/// 60s keeps a cached copy inside that window with a factor of two to spare,
/// and costs at most one small file read per profile per minute.
const KUBERNETES_TOKEN_LIFETIME: Duration = Duration::from_secs(60);
const KUBERNETES_VALUE_CACHE_TTL: Duration = Duration::from_secs(60);
const MAX_KUBERNETES_VALUE_CACHE_ENTRIES: usize = 256;
const MAX_KUBERNETES_TRANSIENT_RETRIES: u32 = 1;
const KUBERNETES_RETRY_BACKOFF: Duration = Duration::from_millis(100);
const KUBERNETES_RESOLUTION_DEADLINE: Duration = Duration::from_secs(10);
const KUBERNETES_PROVIDER_LABEL: &str = "kubernetes_secrets";
const REDACTED_LOCATOR: &str = "<redacted-locator>";

/// Percent-encoding set for one URL path segment. Validation already restricts
/// every segment to unreserved characters, so encoding is a defensive no-op.
const PATH_SEGMENT_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// Trusted startup configuration for the read-only Kubernetes Secrets provider.
#[derive(Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KubernetesProviderConfig {
    #[serde(default)]
    pub profiles: Vec<KubernetesProfileConfig>,
    #[serde(default)]
    pub aliases: Vec<KubernetesSecretAliasConfig>,
}

impl fmt::Debug for KubernetesProviderConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KubernetesProviderConfig")
            .field("profile_count", &self.profiles.len())
            .field("alias_count", &self.aliases.len())
            .finish()
    }
}

impl KubernetesProviderConfig {
    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty() && self.aliases.is_empty()
    }
}

/// One API server plus the fixed workload identity used against it.
///
/// `server` is always an explicit `https` scheme-plus-authority URL. The
/// provider never derives an endpoint from `KUBERNETES_SERVICE_HOST`, a
/// kubeconfig, or any other ambient in-cluster environment.
///
/// TLS trust for an API server issued by a private cluster CA comes from at
/// most one of two sources, each adding to (never replacing or bypassing)
/// certificate verification for this profile only: `ca_bundle_root` plus
/// `ca_bundle_file` read a platform-projected PEM bundle (typically the
/// kubelet-projected `ca.crt`, which is world readable) beneath a pinned
/// directory, while `ca_bundle_alias` names an already configured non-reveal
/// alias of another provider for operators who provision the bundle
/// themselves.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KubernetesProfileConfig {
    pub id: String,
    pub server: String,
    #[serde(default)]
    pub ca_bundle_alias: Option<String>,
    #[serde(default)]
    pub ca_bundle_root: Option<String>,
    #[serde(default)]
    pub ca_bundle_file: Option<String>,
    pub auth: KubernetesAuthConfig,
}

impl fmt::Debug for KubernetesProfileConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KubernetesProfileConfig")
            .field("id", &self.id)
            .field("server", &REDACTED_LOCATOR)
            .field(
                "ca_bundle_alias",
                &self.ca_bundle_alias.as_ref().map(|_| REDACTED_LOCATOR),
            )
            .field(
                "ca_bundle_root",
                &self.ca_bundle_root.as_ref().map(|_| REDACTED_LOCATOR),
            )
            .field(
                "ca_bundle_file",
                &self.ca_bundle_file.as_ref().map(|_| REDACTED_LOCATOR),
            )
            .field("auth", &self.auth)
            .finish()
    }
}

/// Authentication presented on every Secret read.
///
/// `projected_token` reads an audience-bound short-lived ServiceAccount token
/// from a kubelet-projected file beneath a pinned root and observes kubelet
/// rotation on a bounded interval. `bearer_alias` takes a static bearer token
/// from an already configured alias of another provider, never from an inline
/// value. `client_certificate` authenticates with mutual TLS: the certificate
/// chain and private key come from already configured non-reveal aliases of
/// another provider, are combined into one client identity on the derived
/// egress transport, and no `Authorization` header is sent. Anonymous access,
/// kubeconfig discovery, exec/auth plugins, external commands, and proxies are
/// rejected by construction: no such mechanism exists in this configuration
/// surface.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum KubernetesAuthConfig {
    ProjectedToken {
        token_root: String,
        token_file: String,
    },
    BearerAlias {
        secret_alias: String,
    },
    ClientCertificate {
        certificate_alias: String,
        private_key_alias: String,
    },
}

impl fmt::Debug for KubernetesAuthConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProjectedToken { .. } => formatter
                .debug_struct("ProjectedToken")
                .field("token_root", &REDACTED_LOCATOR)
                .field("token_file", &REDACTED_LOCATOR)
                .finish(),
            Self::BearerAlias { secret_alias } => formatter
                .debug_struct("BearerAlias")
                .field("secret_alias", secret_alias)
                .finish(),
            Self::ClientCertificate {
                certificate_alias,
                private_key_alias,
            } => formatter
                .debug_struct("ClientCertificate")
                .field("certificate_alias", certificate_alias)
                .field("private_key_alias", private_key_alias)
                .finish(),
        }
    }
}

/// One opaque alias bound to exactly one Secret `data` key.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KubernetesSecretAliasConfig {
    pub id: String,
    pub label: String,
    pub profile: String,
    pub namespace: String,
    pub name: String,
    pub key: String,
}

impl fmt::Debug for KubernetesSecretAliasConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KubernetesSecretAliasConfig")
            .field("id", &self.id)
            .field("label", &self.label)
            .field("profile", &self.profile)
            .field("namespace", &REDACTED_LOCATOR)
            .field("name", &REDACTED_LOCATOR)
            .field("key", &REDACTED_LOCATOR)
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KubernetesProviderConfigError {
    TooManyProfiles { maximum: usize },
    TooManyAliases { maximum: usize },
    InvalidProfileId { index: usize },
    DuplicateProfileId { index: usize, previous: usize },
    InvalidServer { index: usize },
    InvalidCaBundleAlias { index: usize },
    CaBundleAliasCycle { index: usize },
    ConflictingCaBundleSources { index: usize },
    InvalidCaBundleRoot { index: usize },
    InvalidCaBundleFile { index: usize },
    CaBundleRootUnavailable { index: usize },
    CaBundleRootPermissions { index: usize },
    TransportBounds,
    InvalidProjectedTokenRoot { index: usize },
    InvalidProjectedTokenFile { index: usize },
    ProjectedTokenRootUnavailable { index: usize },
    ProjectedTokenRootPermissions { index: usize },
    InvalidBootstrapAlias { index: usize },
    BootstrapAliasCycle { index: usize },
    BootstrapResolverRequired { index: usize },
    UnknownBootstrapAlias { index: usize },
    InvalidAliasId { index: usize },
    InvalidLabel { index: usize },
    DuplicateAliasId { index: usize, previous: usize },
    ReservedAliasId { index: usize },
    UnknownProfile { index: usize },
    InvalidNamespace { index: usize },
    InvalidSecretName { index: usize },
    InvalidDataKey { index: usize },
    AliasesWithoutProfiles,
}

impl fmt::Display for KubernetesProviderConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyProfiles { maximum } => write!(
                formatter,
                "kubernetes provider profiles must contain at most {maximum} entries"
            ),
            Self::TooManyAliases { maximum } => write!(
                formatter,
                "kubernetes provider aliases must contain at most {maximum} entries"
            ),
            Self::InvalidProfileId { index } => write!(
                formatter,
                "kubernetes profile at index {index} has an invalid opaque ID"
            ),
            Self::DuplicateProfileId { index, previous } => write!(
                formatter,
                "kubernetes profile at index {index} duplicates the opaque ID at index {previous}"
            ),
            Self::InvalidServer { index } => write!(
                formatter,
                "kubernetes profile at index {index} requires an absolute https server URL with no credentials, path, query, or fragment"
            ),
            Self::InvalidCaBundleAlias { index } => write!(
                formatter,
                "kubernetes profile at index {index} has an invalid CA bundle alias ID"
            ),
            Self::CaBundleAliasCycle { index } => write!(
                formatter,
                "kubernetes profile at index {index} takes its CA bundle from an alias this provider itself serves"
            ),
            Self::ConflictingCaBundleSources { index } => write!(
                formatter,
                "kubernetes profile at index {index} must configure at most one CA bundle source, and a projected source requires both ca_bundle_root and ca_bundle_file"
            ),
            Self::InvalidCaBundleRoot { index } => write!(
                formatter,
                "kubernetes profile at index {index} has an invalid CA bundle root"
            ),
            Self::InvalidCaBundleFile { index } => write!(
                formatter,
                "kubernetes profile at index {index} has an invalid CA bundle file key"
            ),
            Self::CaBundleRootUnavailable { index } => write!(
                formatter,
                "kubernetes profile at index {index} has a CA bundle root that is unavailable or cannot be canonicalized"
            ),
            Self::CaBundleRootPermissions { index } => write!(
                formatter,
                "kubernetes profile at index {index} has a CA bundle root with unsafe write permissions for this platform"
            ),
            Self::TransportBounds => formatter.write_str(
                "kubernetes provider transport response bounds could not be applied",
            ),
            Self::InvalidProjectedTokenRoot { index } => write!(
                formatter,
                "kubernetes profile at index {index} has an invalid projected token root"
            ),
            Self::InvalidProjectedTokenFile { index } => write!(
                formatter,
                "kubernetes profile at index {index} has an invalid projected token file key"
            ),
            Self::ProjectedTokenRootUnavailable { index } => write!(
                formatter,
                "kubernetes profile at index {index} has a projected token root that is unavailable or cannot be canonicalized"
            ),
            Self::ProjectedTokenRootPermissions { index } => write!(
                formatter,
                "kubernetes profile at index {index} has a projected token root with unsafe write permissions for this platform"
            ),
            Self::InvalidBootstrapAlias { index } => write!(
                formatter,
                "kubernetes profile at index {index} has an invalid bootstrap alias ID"
            ),
            Self::BootstrapAliasCycle { index } => write!(
                formatter,
                "kubernetes profile at index {index} bootstraps from an alias this provider itself serves"
            ),
            Self::BootstrapResolverRequired { index } => write!(
                formatter,
                "kubernetes profile at index {index} references an alias of another provider but no other provider is configured"
            ),
            Self::UnknownBootstrapAlias { index } => write!(
                formatter,
                "kubernetes profile at index {index} bootstraps from an alias that no configured provider owns"
            ),
            Self::InvalidAliasId { index } => write!(
                formatter,
                "kubernetes alias at index {index} has an invalid opaque ID"
            ),
            Self::InvalidLabel { index } => write!(
                formatter,
                "kubernetes alias at index {index} has an invalid safe label"
            ),
            Self::DuplicateAliasId { index, previous } => write!(
                formatter,
                "kubernetes alias at index {index} duplicates the opaque ID at index {previous}"
            ),
            Self::ReservedAliasId { index } => write!(
                formatter,
                "kubernetes alias at index {index} duplicates an alias ID served by another provider"
            ),
            Self::UnknownProfile { index } => write!(
                formatter,
                "kubernetes alias at index {index} names an unconfigured profile"
            ),
            Self::InvalidNamespace { index } => write!(
                formatter,
                "kubernetes alias at index {index} has an invalid namespace (RFC 1123 DNS label required)"
            ),
            Self::InvalidSecretName { index } => write!(
                formatter,
                "kubernetes alias at index {index} has an invalid Secret name (RFC 1123 DNS subdomain required)"
            ),
            Self::InvalidDataKey { index } => write!(
                formatter,
                "kubernetes alias at index {index} has an invalid data key"
            ),
            Self::AliasesWithoutProfiles => {
                formatter.write_str("kubernetes aliases require at least one configured profile")
            }
        }
    }
}

impl Error for KubernetesProviderConfigError {}

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
) -> Result<(), KubernetesProviderConfigError> {
    let Some(resolver) = bootstrap else {
        return Err(KubernetesProviderConfigError::BootstrapResolverRequired { index });
    };
    if !resolver.contains_alias(alias) {
        return Err(KubernetesProviderConfigError::UnknownBootstrapAlias { index });
    }
    Ok(())
}

pub fn validate_kubernetes_provider_config(
    config: &KubernetesProviderConfig,
    reserved_alias_ids: &BTreeSet<String>,
) -> Result<(), KubernetesProviderConfigError> {
    if config.profiles.len() > MAX_KUBERNETES_PROFILES {
        return Err(KubernetesProviderConfigError::TooManyProfiles {
            maximum: MAX_KUBERNETES_PROFILES,
        });
    }
    if config.aliases.len() > MAX_KUBERNETES_SECRET_ALIASES {
        return Err(KubernetesProviderConfigError::TooManyAliases {
            maximum: MAX_KUBERNETES_SECRET_ALIASES,
        });
    }
    if !config.aliases.is_empty() && config.profiles.is_empty() {
        return Err(KubernetesProviderConfigError::AliasesWithoutProfiles);
    }

    let alias_ids = config
        .aliases
        .iter()
        .map(|alias| alias.id.as_str())
        .collect::<BTreeSet<_>>();
    let mut profile_ids = BTreeMap::new();
    for (index, profile) in config.profiles.iter().enumerate() {
        if !is_valid_opaque_id(&profile.id, MAX_SECRET_ID_BYTES) {
            return Err(KubernetesProviderConfigError::InvalidProfileId { index });
        }
        if let Some(previous) = profile_ids.insert(profile.id.as_str(), index) {
            return Err(KubernetesProviderConfigError::DuplicateProfileId { index, previous });
        }
        if !is_valid_kubernetes_server(&profile.server) {
            return Err(KubernetesProviderConfigError::InvalidServer { index });
        }
        let projected_ca_configured =
            profile.ca_bundle_root.is_some() || profile.ca_bundle_file.is_some();
        if profile.ca_bundle_alias.is_some() && projected_ca_configured
            || profile.ca_bundle_root.is_some() != profile.ca_bundle_file.is_some()
        {
            return Err(KubernetesProviderConfigError::ConflictingCaBundleSources { index });
        }
        if let Some(ca_alias) = profile.ca_bundle_alias.as_deref() {
            if !is_valid_opaque_id(ca_alias, MAX_SECRET_ID_BYTES) {
                return Err(KubernetesProviderConfigError::InvalidCaBundleAlias { index });
            }
            if alias_ids.contains(ca_alias) {
                return Err(KubernetesProviderConfigError::CaBundleAliasCycle { index });
            }
        }
        if let Some(ca_root) = profile.ca_bundle_root.as_deref() {
            if ca_root.is_empty() || ca_root.len() > MAX_KUBERNETES_TOKEN_ROOT_BYTES {
                return Err(KubernetesProviderConfigError::InvalidCaBundleRoot { index });
            }
        }
        if let Some(ca_file) = profile.ca_bundle_file.as_deref() {
            if !super::secret::is_valid_file_key(ca_file) {
                return Err(KubernetesProviderConfigError::InvalidCaBundleFile { index });
            }
        }
        match &profile.auth {
            KubernetesAuthConfig::ProjectedToken {
                token_root,
                token_file,
            } => {
                if token_root.is_empty() || token_root.len() > MAX_KUBERNETES_TOKEN_ROOT_BYTES {
                    return Err(KubernetesProviderConfigError::InvalidProjectedTokenRoot { index });
                }
                if !super::secret::is_valid_file_key(token_file) {
                    return Err(KubernetesProviderConfigError::InvalidProjectedTokenFile { index });
                }
            }
            KubernetesAuthConfig::BearerAlias { secret_alias } => {
                if !is_valid_opaque_id(secret_alias, MAX_SECRET_ID_BYTES) {
                    return Err(KubernetesProviderConfigError::InvalidBootstrapAlias { index });
                }
                if alias_ids.contains(secret_alias.as_str()) {
                    return Err(KubernetesProviderConfigError::BootstrapAliasCycle { index });
                }
            }
            KubernetesAuthConfig::ClientCertificate {
                certificate_alias,
                private_key_alias,
            } => {
                for bootstrap_alias in [certificate_alias, private_key_alias] {
                    if !is_valid_opaque_id(bootstrap_alias, MAX_SECRET_ID_BYTES) {
                        return Err(KubernetesProviderConfigError::InvalidBootstrapAlias { index });
                    }
                    if alias_ids.contains(bootstrap_alias.as_str()) {
                        return Err(KubernetesProviderConfigError::BootstrapAliasCycle { index });
                    }
                }
            }
        }
    }

    let mut seen_alias_ids = BTreeMap::new();
    for (index, alias) in config.aliases.iter().enumerate() {
        if !is_valid_opaque_id(&alias.id, MAX_SECRET_ID_BYTES) {
            return Err(KubernetesProviderConfigError::InvalidAliasId { index });
        }
        if alias.label.is_empty()
            || alias.label.chars().count() > MAX_DISPLAY_NAME_CHARS
            || alias.label.chars().any(char::is_control)
        {
            return Err(KubernetesProviderConfigError::InvalidLabel { index });
        }
        if let Some(previous) = seen_alias_ids.insert(alias.id.as_str(), index) {
            return Err(KubernetesProviderConfigError::DuplicateAliasId { index, previous });
        }
        if reserved_alias_ids.contains(&alias.id) {
            return Err(KubernetesProviderConfigError::ReservedAliasId { index });
        }
        if !profile_ids.contains_key(alias.profile.as_str()) {
            return Err(KubernetesProviderConfigError::UnknownProfile { index });
        }
        if !is_valid_dns1123_label(&alias.namespace) {
            return Err(KubernetesProviderConfigError::InvalidNamespace { index });
        }
        if !is_valid_dns1123_subdomain(&alias.name) {
            return Err(KubernetesProviderConfigError::InvalidSecretName { index });
        }
        if !is_valid_kubernetes_data_key(&alias.key) {
            return Err(KubernetesProviderConfigError::InvalidDataKey { index });
        }
    }
    Ok(())
}

fn is_valid_kubernetes_server(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_KUBERNETES_SERVER_BYTES {
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

/// RFC 1123 DNS label: lowercase alphanumerics and `-`, alphanumeric at both
/// ends, at most 63 bytes. Kubernetes namespaces use exactly this shape.
fn is_valid_dns1123_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_DNS1123_LABEL_BYTES
        && value
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-'))
        && !value.starts_with('-')
        && !value.ends_with('-')
}

/// RFC 1123 DNS subdomain: dot-separated DNS labels, at most 253 bytes.
/// Kubernetes Secret names use exactly this shape.
fn is_valid_dns1123_subdomain(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_DNS1123_SUBDOMAIN_BYTES
        && value.split('.').all(is_valid_dns1123_label)
}

/// Kubernetes Secret `data` key: `[-._a-zA-Z0-9]+`, at most 253 bytes, and
/// neither `.` nor `..`.
fn is_valid_kubernetes_data_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_KUBERNETES_DATA_KEY_BYTES
        && value != "."
        && value != ".."
        && value.bytes().all(
            |byte| matches!(byte, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'_' | b'-'),
        )
}

/// One bounded provider exchange.
pub(crate) struct KubernetesHttpResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for KubernetesHttpResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KubernetesHttpResponse")
            .field("status", &self.status)
            .field("headers", &"<redacted>")
            .field("body", &"<redacted>")
            .finish()
    }
}

/// Egress-mediated transport for the provider.
///
/// The production implementation is [`EgressKubernetesTransport`]; tests
/// substitute a hermetic fake so CI never contacts a real cluster.
#[async_trait]
pub(crate) trait KubernetesTransport: Send + Sync {
    /// Opaque generation of the egress configuration behind this transport.
    fn egress_generation(&self) -> [u8; 32];

    /// Derives a transport that additionally trusts the given PEM CA bundle
    /// when verifying the API server certificate and/or presents the given
    /// combined certificate-chain-plus-private-key PEM as its mutual-TLS
    /// client identity. All other egress policy is inherited unchanged;
    /// invalid material fails closed.
    fn with_tls_material(
        &self,
        ca_bundle_pem: Option<&[u8]>,
        client_identity_pem: Option<&[u8]>,
    ) -> Result<Arc<dyn KubernetesTransport>, EgressError>;

    async fn send(
        &self,
        method: Method,
        url: &str,
        headers: HeaderMap,
        body: Option<Vec<u8>>,
    ) -> Result<KubernetesHttpResponse, EgressError>;
}

pub(crate) struct EgressKubernetesTransport {
    client: Arc<EgressClient>,
}

impl EgressKubernetesTransport {
    /// Wraps the deployment egress client with this provider's response cap
    /// clamped in, so the read bound is enforced while a response is being
    /// received rather than after the egress layer has buffered it.
    pub(crate) fn bounded(client: &Arc<EgressClient>) -> Result<Self, EgressError> {
        let capped = client.with_response_cap(MAX_KUBERNETES_READ_RESPONSE_BYTES)?;
        Ok(Self {
            client: Arc::new(capped),
        })
    }

    #[cfg(test)]
    pub(crate) fn response_cap(&self) -> usize {
        self.client.max_response_bytes()
    }
}

impl fmt::Debug for EgressKubernetesTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EgressKubernetesTransport")
    }
}

#[async_trait]
impl KubernetesTransport for EgressKubernetesTransport {
    fn egress_generation(&self) -> [u8; 32] {
        self.client.configuration_generation()
    }

    fn with_tls_material(
        &self,
        ca_bundle_pem: Option<&[u8]>,
        client_identity_pem: Option<&[u8]>,
    ) -> Result<Arc<dyn KubernetesTransport>, EgressError> {
        let derived = self
            .client
            .with_tls_material(ca_bundle_pem, client_identity_pem)?;
        Ok(Arc::new(Self {
            client: Arc::new(derived),
        }))
    }

    async fn send(
        &self,
        method: Method,
        url: &str,
        headers: HeaderMap,
        body: Option<Vec<u8>>,
    ) -> Result<KubernetesHttpResponse, EgressError> {
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
        Ok(KubernetesHttpResponse {
            status: response.status,
            headers: response.headers,
            body: response.body,
        })
    }
}

pub(crate) trait KubernetesClock: Send + Sync {
    fn now(&self) -> Instant;
}

struct SystemKubernetesClock;

impl KubernetesClock for SystemKubernetesClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

struct KubernetesProfile {
    id: String,
    ca_bundle: Option<CaBundleSource>,
    auth: KubernetesAuth,
}

/// Where a profile's additional TLS trust anchors come from. Both sources are
/// re-read on every resolution, so a rotated bundle is observed promptly and a
/// missing or unusable bundle fails closed before any connection attempt.
enum CaBundleSource {
    /// A non-reveal alias of another provider, for operator-provisioned
    /// bundles (an exclusive-permission regular file or environment value).
    Alias(String),
    /// A platform-projected PEM file beneath a pinned root, matching the
    /// world-readable `ca.crt` the kubelet projects next to ServiceAccount
    /// tokens.
    Projected { root: Arc<Dir>, file: String },
}

enum KubernetesAuth {
    ProjectedToken {
        token_root: Arc<Dir>,
        token_file: String,
    },
    BearerAlias {
        secret_alias: String,
    },
    ClientCertificate {
        certificate_alias: String,
        private_key_alias: String,
    },
}

struct KubernetesAliasBinding {
    id: String,
    label: String,
    profile: String,
    read_url: String,
    namespace: String,
    name: String,
    key: String,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct KubernetesValueCacheKey {
    provider_generation: [u8; 32],
    egress_generation: [u8; 32],
    identity_generation: u64,
    alias_id: String,
    purpose: u8,
}

struct CachedKubernetesValue {
    value: Zeroizing<Vec<u8>>,
    expires_at: Instant,
}

struct CachedKubernetesToken {
    token: Zeroizing<Vec<u8>>,
    expires_at: Instant,
    generation: u64,
}

#[derive(Default)]
struct KubernetesIdentityState {
    tokens: BTreeMap<String, CachedKubernetesToken>,
    generations: BTreeMap<String, u64>,
}

struct DerivedProfileTransport {
    material_fingerprint: [u8; 32],
    transport: Arc<dyn KubernetesTransport>,
}

/// Read-only Kubernetes Secrets provider.
#[derive(Clone)]
pub struct KubernetesSecretProvider {
    profiles: Arc<BTreeMap<String, KubernetesProfile>>,
    aliases: Arc<BTreeMap<String, KubernetesAliasBinding>>,
    transport: Arc<dyn KubernetesTransport>,
    derived_transports: Arc<Mutex<BTreeMap<String, DerivedProfileTransport>>>,
    bootstrap: Option<Arc<dyn SecretResolver>>,
    identity: Arc<Mutex<KubernetesIdentityState>>,
    login_lock: Arc<AsyncMutex<()>>,
    values: Arc<Mutex<BTreeMap<KubernetesValueCacheKey, CachedKubernetesValue>>>,
    concurrent_reads: Arc<Semaphore>,
    clock: Arc<dyn KubernetesClock>,
    generation: [u8; 32],
    deadline: Duration,
    value_cache_ttl: Duration,
    token_lifetime: Duration,
}

impl fmt::Debug for KubernetesSecretProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KubernetesSecretProvider")
            .field("profile_count", &self.profiles.len())
            .field("alias_count", &self.aliases.len())
            .field("bootstrap_provider_enabled", &self.bootstrap.is_some())
            .field(
                "maximum_concurrent_reads",
                &MAX_CONCURRENT_KUBERNETES_RESOLUTIONS,
            )
            .finish()
    }
}

impl KubernetesSecretProvider {
    /// Builds the provider from trusted startup configuration.
    ///
    /// `bootstrap` must be a resolver that does **not** include this provider,
    /// which together with the configuration cycle checks keeps bearer and CA
    /// bootstrap material out of any Kubernetes-served alias.
    pub(crate) fn from_config(
        config: &KubernetesProviderConfig,
        reserved_alias_ids: &BTreeSet<String>,
        transport: Arc<dyn KubernetesTransport>,
        bootstrap: Option<Arc<dyn SecretResolver>>,
    ) -> Result<Self, KubernetesProviderConfigError> {
        validate_kubernetes_provider_config(config, reserved_alias_ids)?;
        let mut profiles = BTreeMap::new();
        for (index, profile) in config.profiles.iter().enumerate() {
            if let Some(alias) = profile.ca_bundle_alias.as_deref() {
                require_bootstrap_alias(index, alias, bootstrap.as_ref())?;
            }
            let ca_bundle = if let Some(alias) = profile.ca_bundle_alias.as_deref() {
                Some(CaBundleSource::Alias(alias.to_owned()))
            } else if let (Some(root), Some(file)) = (
                profile.ca_bundle_root.as_deref(),
                profile.ca_bundle_file.as_deref(),
            ) {
                Some(CaBundleSource::Projected {
                    root: open_projected_root(
                        index,
                        root,
                        |index| KubernetesProviderConfigError::CaBundleRootUnavailable { index },
                        |index| KubernetesProviderConfigError::CaBundleRootPermissions { index },
                    )?,
                    file: file.to_owned(),
                })
            } else {
                None
            };
            let auth = match &profile.auth {
                KubernetesAuthConfig::ProjectedToken {
                    token_root,
                    token_file,
                } => KubernetesAuth::ProjectedToken {
                    token_root: open_projected_root(
                        index,
                        token_root,
                        |index| KubernetesProviderConfigError::ProjectedTokenRootUnavailable {
                            index,
                        },
                        |index| KubernetesProviderConfigError::ProjectedTokenRootPermissions {
                            index,
                        },
                    )?,
                    token_file: token_file.clone(),
                },
                KubernetesAuthConfig::BearerAlias { secret_alias } => {
                    require_bootstrap_alias(index, secret_alias, bootstrap.as_ref())?;
                    KubernetesAuth::BearerAlias {
                        secret_alias: secret_alias.clone(),
                    }
                }
                KubernetesAuthConfig::ClientCertificate {
                    certificate_alias,
                    private_key_alias,
                } => {
                    require_bootstrap_alias(index, certificate_alias, bootstrap.as_ref())?;
                    require_bootstrap_alias(index, private_key_alias, bootstrap.as_ref())?;
                    KubernetesAuth::ClientCertificate {
                        certificate_alias: certificate_alias.clone(),
                        private_key_alias: private_key_alias.clone(),
                    }
                }
            };
            profiles.insert(
                profile.id.clone(),
                KubernetesProfile {
                    id: profile.id.clone(),
                    ca_bundle,
                    auth,
                },
            );
        }

        let mut aliases = BTreeMap::new();
        for alias in &config.aliases {
            let server = config
                .profiles
                .iter()
                .find(|profile| profile.id == alias.profile)
                .map(|profile| profile.server.trim_end_matches('/').to_owned())
                .unwrap_or_default();
            let read_url = format!(
                "{server}/api/v1/namespaces/{namespace}/secrets/{name}",
                namespace = utf8_percent_encode(&alias.namespace, PATH_SEGMENT_ENCODE_SET),
                name = utf8_percent_encode(&alias.name, PATH_SEGMENT_ENCODE_SET),
            );
            aliases.insert(
                alias.id.clone(),
                KubernetesAliasBinding {
                    id: alias.id.clone(),
                    label: alias.label.clone(),
                    profile: alias.profile.clone(),
                    read_url,
                    namespace: alias.namespace.clone(),
                    name: alias.name.clone(),
                    key: alias.key.clone(),
                },
            );
        }

        Ok(Self {
            profiles: Arc::new(profiles),
            aliases: Arc::new(aliases),
            transport,
            derived_transports: Arc::new(Mutex::new(BTreeMap::new())),
            bootstrap,
            identity: Arc::new(Mutex::new(KubernetesIdentityState::default())),
            login_lock: Arc::new(AsyncMutex::new(())),
            values: Arc::new(Mutex::new(BTreeMap::new())),
            concurrent_reads: Arc::new(Semaphore::new(MAX_CONCURRENT_KUBERNETES_RESOLUTIONS)),
            clock: Arc::new(SystemKubernetesClock),
            generation: provider_generation(config),
            deadline: KUBERNETES_RESOLUTION_DEADLINE,
            value_cache_ttl: KUBERNETES_VALUE_CACHE_TTL,
            token_lifetime: KUBERNETES_TOKEN_LIFETIME,
        })
    }

    pub fn alias_ids(&self) -> BTreeSet<String> {
        self.aliases.keys().cloned().collect()
    }

    fn identity_guard(&self) -> MutexGuard<'_, KubernetesIdentityState> {
        match self.identity.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn value_guard(
        &self,
    ) -> MutexGuard<'_, BTreeMap<KubernetesValueCacheKey, CachedKubernetesValue>> {
        match self.values.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn transport_guard(&self) -> MutexGuard<'_, BTreeMap<String, DerivedProfileTransport>> {
        match self.derived_transports.lock() {
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
        alias: &KubernetesAliasBinding,
        purpose: SecretPurpose,
        identity_generation: u64,
        egress_generation: [u8; 32],
    ) -> KubernetesValueCacheKey {
        KubernetesValueCacheKey {
            provider_generation: self.generation,
            egress_generation,
            identity_generation,
            alias_id: alias.id.clone(),
            purpose: purpose_code(purpose),
        }
    }

    fn cached_value(&self, key: &KubernetesValueCacheKey) -> Option<Zeroizing<Vec<u8>>> {
        let now = self.clock.now();
        let mut cache = self.value_guard();
        let entry = cache.get(key)?;
        if entry.expires_at <= now {
            cache.remove(key);
            return None;
        }
        Some(entry.value.clone())
    }

    fn store_value(&self, key: KubernetesValueCacheKey, value: &[u8]) {
        let now = self.clock.now();
        let mut cache = self.value_guard();
        cache.retain(|_, entry| entry.expires_at > now);
        if cache.len() >= MAX_KUBERNETES_VALUE_CACHE_ENTRIES {
            return;
        }
        cache.insert(
            key,
            CachedKubernetesValue {
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

    fn store_token(&self, profile_id: &str, token: Zeroizing<Vec<u8>>) -> u64 {
        let now = self.clock.now();
        let mut identity = self.identity_guard();
        let generation = identity
            .generations
            .entry(profile_id.to_owned())
            .or_default();
        *generation = generation.saturating_add(1);
        let generation = *generation;
        identity.tokens.remove(profile_id);
        identity.tokens.insert(
            profile_id.to_owned(),
            CachedKubernetesToken {
                token,
                expires_at: now + self.token_lifetime,
                generation,
            },
        );
        generation
    }

    fn invalidate_token(&self, profile_id: &str) {
        self.identity_guard().tokens.remove(profile_id);
    }

    async fn resolve_inner(
        &self,
        alias_id: &str,
        purpose: SecretPurpose,
    ) -> Result<ResolvedSecret, KubernetesFailure> {
        let alias = self
            .aliases
            .get(alias_id)
            .ok_or(KubernetesFailure::UnknownAlias)?;
        let profile = self
            .profiles
            .get(&alias.profile)
            .ok_or(KubernetesFailure::ProviderFailure)?;

        // A trust-material failure purges like any other failed resolution,
        // so a value cached under the previous trust state is never served
        // across an intervening trust outage.
        let transport = match self.transport_for(profile).await {
            Ok(transport) => transport,
            Err(failure) => {
                self.purge_alias(&alias.id);
                return Err(failure);
            }
        };
        let identity_generation = self.identity_generation(&profile.id);
        let cache_key = self.cache_key(
            alias,
            purpose,
            identity_generation,
            transport.egress_generation(),
        );
        if let Some(cached) = self.cached_value(&cache_key) {
            return ResolvedSecret::new(purpose, cached.to_vec())
                .map_err(|_| KubernetesFailure::InvalidMaterial);
        }

        let result = self
            .read_authenticated(alias, profile, transport.as_ref(), purpose)
            .await;
        if result.is_err() {
            self.purge_alias(&alias.id);
        }
        let (value, identity_generation) = result?;
        let secret = ResolvedSecret::new(purpose, value.to_vec())
            .map_err(|_| KubernetesFailure::InvalidMaterial)?;
        self.store_value(
            self.cache_key(
                alias,
                purpose,
                identity_generation,
                transport.egress_generation(),
            ),
            secret.expose(),
        );
        Ok(secret)
    }

    /// Returns the transport for one profile, deriving (and re-deriving on
    /// rotation) a client whose TLS trust additionally accepts the profile's
    /// CA bundle and whose mutual-TLS client identity carries the profile's
    /// certificate material. Both sources are re-resolved per resolution and
    /// fingerprinted, so rotated material re-derives the transport and, via
    /// the egress generation in the value-cache key, invalidates values
    /// cached under the previous material. Missing or invalid material fails
    /// closed before any connection is attempted.
    async fn transport_for(
        &self,
        profile: &KubernetesProfile,
    ) -> Result<Arc<dyn KubernetesTransport>, KubernetesFailure> {
        let ca_bundle = match profile.ca_bundle.as_ref() {
            Some(source) => Some(self.ca_bundle_material(source).await?),
            None => None,
        };
        let client_identity = match &profile.auth {
            KubernetesAuth::ClientCertificate {
                certificate_alias,
                private_key_alias,
            } => Some(
                self.client_identity_material(certificate_alias, private_key_alias)
                    .await?,
            ),
            KubernetesAuth::ProjectedToken { .. } | KubernetesAuth::BearerAlias { .. } => None,
        };
        if ca_bundle.is_none() && client_identity.is_none() {
            return Ok(Arc::clone(&self.transport));
        }
        let mut digest = Sha256::new();
        digest.update(b"kubernetes-profile-tls-material-v1");
        if let Some(bundle) = ca_bundle.as_ref() {
            digest.update([1]);
            digest.update(bundle.expose());
        }
        digest.update([0]);
        if let Some(identity) = client_identity.as_ref() {
            digest.update([1]);
            digest.update(identity.as_slice());
        }
        let material_fingerprint: [u8; 32] = digest.finalize().into();
        if let Some(entry) = self.transport_guard().get(&profile.id) {
            if entry.material_fingerprint == material_fingerprint {
                return Ok(Arc::clone(&entry.transport));
            }
        }
        let derived = self
            .transport
            .with_tls_material(
                ca_bundle.as_ref().map(|bundle| bundle.expose()),
                client_identity.as_deref().map(Vec::as_slice),
            )
            .map_err(|error| match error {
                EgressError::InvalidTlsClientIdentity => KubernetesFailure::IdentityInvalid,
                _ => KubernetesFailure::TrustInvalid,
            })?;
        self.transport_guard().insert(
            profile.id.clone(),
            DerivedProfileTransport {
                material_fingerprint,
                transport: Arc::clone(&derived),
            },
        );
        Ok(derived)
    }

    /// Resolves and combines the mutual-TLS certificate chain and private key
    /// from their bootstrap aliases into one PEM identity, per the egress
    /// client-identity convention (certificate chain first, then the key).
    async fn client_identity_material(
        &self,
        certificate_alias: &str,
        private_key_alias: &str,
    ) -> Result<Zeroizing<Vec<u8>>, KubernetesFailure> {
        let bootstrap = self
            .bootstrap
            .as_ref()
            .ok_or(KubernetesFailure::ProviderFailure)?;
        let map_identity_error = |error: SecretResolveError| match error.kind() {
            SecretResolveErrorKind::SourceDenied | SecretResolveErrorKind::UnsafeSource => {
                KubernetesFailure::IdentityDenied
            }
            SecretResolveErrorKind::UnknownAlias | SecretResolveErrorKind::InvalidMaterial => {
                KubernetesFailure::IdentityInvalid
            }
            SecretResolveErrorKind::ProviderBusy
            | SecretResolveErrorKind::SourceUnavailable
            | SecretResolveErrorKind::ProviderFailure => KubernetesFailure::IdentityUnavailable,
        };
        let certificate = bootstrap
            .resolve(certificate_alias, SecretPurpose::TlsCertificate)
            .await
            .map_err(map_identity_error)?;
        let private_key = bootstrap
            .resolve(private_key_alias, SecretPurpose::TlsPrivateKey)
            .await
            .map_err(map_identity_error)?;
        let separator_len = usize::from(!certificate.expose().ends_with(b"\n"));
        let identity_len = certificate
            .expose()
            .len()
            .checked_add(separator_len)
            .and_then(|length| length.checked_add(private_key.expose().len()))
            .ok_or(KubernetesFailure::IdentityInvalid)?;
        let mut identity = Zeroizing::new(Vec::with_capacity(identity_len));
        identity.extend_from_slice(certificate.expose());
        if separator_len == 1 {
            identity.push(b'\n');
        }
        identity.extend_from_slice(private_key.expose());
        Ok(identity)
    }

    async fn ca_bundle_material(
        &self,
        source: &CaBundleSource,
    ) -> Result<ResolvedSecret, KubernetesFailure> {
        match source {
            CaBundleSource::Alias(alias) => {
                let bootstrap = self
                    .bootstrap
                    .as_ref()
                    .ok_or(KubernetesFailure::ProviderFailure)?;
                bootstrap
                    .resolve(alias, SecretPurpose::TlsCaBundle)
                    .await
                    .map_err(|error| match error.kind() {
                        SecretResolveErrorKind::ProviderBusy
                        | SecretResolveErrorKind::SourceUnavailable
                        | SecretResolveErrorKind::ProviderFailure => {
                            KubernetesFailure::TrustUnavailable
                        }
                        SecretResolveErrorKind::UnknownAlias
                        | SecretResolveErrorKind::SourceDenied
                        | SecretResolveErrorKind::UnsafeSource
                        | SecretResolveErrorKind::InvalidMaterial => {
                            KubernetesFailure::TrustInvalid
                        }
                    })
            }
            CaBundleSource::Projected { root, file } => {
                let root = Arc::clone(root);
                let key = file.clone();
                tokio::task::spawn_blocking(move || {
                    read_bounded_file_secret(
                        "kubernetes-projected-ca-bundle",
                        &root,
                        &key,
                        SecretPurpose::TlsCaBundle,
                        FileSecretPermissions::PlatformProjected,
                    )
                })
                .await
                .map_err(|_| KubernetesFailure::ProviderFailure)?
                .map_err(|error| match error.kind() {
                    SecretResolveErrorKind::ProviderBusy
                    | SecretResolveErrorKind::SourceUnavailable
                    | SecretResolveErrorKind::ProviderFailure => {
                        KubernetesFailure::TrustUnavailable
                    }
                    SecretResolveErrorKind::UnknownAlias
                    | SecretResolveErrorKind::SourceDenied
                    | SecretResolveErrorKind::UnsafeSource
                    | SecretResolveErrorKind::InvalidMaterial => KubernetesFailure::TrustInvalid,
                })
            }
        }
    }

    async fn read_authenticated(
        &self,
        alias: &KubernetesAliasBinding,
        profile: &KubernetesProfile,
        transport: &dyn KubernetesTransport,
        purpose: SecretPurpose,
    ) -> Result<(Zeroizing<Vec<u8>>, u64), KubernetesFailure> {
        if matches!(profile.auth, KubernetesAuth::ClientCertificate { .. }) {
            // Mutual TLS carries the identity at the transport layer; no
            // bearer token exists and no `Authorization` header is sent. The
            // identity material was freshly resolved for this resolution when
            // the transport was derived, so a `401` means the current
            // material is rejected and fails closed with no retry.
            return match self.read_once(alias, transport, purpose, None).await {
                Err(KubernetesFailure::TokenRejected) => Err(KubernetesFailure::IdentityDenied),
                other => other.map(|value| (value, 0)),
            };
        }
        let (token, generation) = self.token(profile, 0).await?;
        match self
            .read_once(alias, transport, purpose, Some(&token))
            .await
        {
            Err(KubernetesFailure::TokenRejected) => {
                // A rotated or expired bearer token is the only condition that
                // earns a second attempt, and only after a fresh re-read of
                // the same fixed identity source. An RBAC denial (`403`) never
                // retries.
                let (token, generation) = self.token(profile, generation.saturating_add(1)).await?;
                self.read_once(alias, transport, purpose, Some(&token))
                    .await
                    .map(|value| (value, generation))
            }
            other => other.map(|value| (value, generation)),
        }
    }

    async fn token(
        &self,
        profile: &KubernetesProfile,
        minimum_generation: u64,
    ) -> Result<(Zeroizing<Vec<u8>>, u64), KubernetesFailure> {
        if let Some(hit) = self.cached_token(&profile.id, minimum_generation) {
            return Ok(hit);
        }
        let _guard = self.login_lock.lock().await;
        if let Some(hit) = self.cached_token(&profile.id, minimum_generation) {
            return Ok(hit);
        }
        self.invalidate_token(&profile.id);
        let token = match &profile.auth {
            KubernetesAuth::ProjectedToken {
                token_root,
                token_file,
            } => self.projected_token(token_root, token_file).await?,
            KubernetesAuth::BearerAlias { secret_alias } => {
                self.bootstrap_material(secret_alias).await?
            }
            // Mutual-TLS profiles never mint a bearer token; the identity
            // lives on the derived transport and the read path returns before
            // requesting one.
            KubernetesAuth::ClientCertificate { .. } => {
                return Err(KubernetesFailure::ProviderFailure)
            }
        };
        validate_token_bytes(&token)?;
        let generation = self.store_token(&profile.id, token.clone());
        Ok((token, generation))
    }

    async fn bootstrap_material(
        &self,
        alias: &str,
    ) -> Result<Zeroizing<Vec<u8>>, KubernetesFailure> {
        let bootstrap = self
            .bootstrap
            .as_ref()
            .ok_or(KubernetesFailure::ProviderFailure)?;
        let secret = bootstrap
            .resolve(alias, SecretPurpose::StaticBearer)
            .await
            .map_err(|error| match error.kind() {
                SecretResolveErrorKind::SourceDenied | SecretResolveErrorKind::UnsafeSource => {
                    KubernetesFailure::IdentityDenied
                }
                SecretResolveErrorKind::InvalidMaterial => KubernetesFailure::IdentityInvalid,
                _ => KubernetesFailure::IdentityUnavailable,
            })?;
        Ok(Zeroizing::new(secret.expose().to_vec()))
    }

    /// Re-reads the kubelet-projected ServiceAccount token from its pinned
    /// root. The read happens on every token refresh, so kubelet rotation is
    /// observed within the bounded token lifetime, and immediately after a
    /// `401` because the rejected generation forces a fresh read.
    async fn projected_token(
        &self,
        token_root: &Arc<Dir>,
        token_file: &str,
    ) -> Result<Zeroizing<Vec<u8>>, KubernetesFailure> {
        let root = Arc::clone(token_root);
        let key = token_file.to_owned();
        let secret = tokio::task::spawn_blocking(move || {
            read_bounded_file_secret(
                "kubernetes-projected-token",
                &root,
                &key,
                SecretPurpose::StaticBearer,
                FileSecretPermissions::PlatformProjected,
            )
        })
        .await
        .map_err(|_| KubernetesFailure::ProviderFailure)?
        .map_err(|error| match error.kind() {
            SecretResolveErrorKind::SourceDenied | SecretResolveErrorKind::UnsafeSource => {
                KubernetesFailure::IdentityDenied
            }
            SecretResolveErrorKind::InvalidMaterial => KubernetesFailure::IdentityInvalid,
            _ => KubernetesFailure::IdentityUnavailable,
        })?;
        Ok(Zeroizing::new(secret.expose().to_vec()))
    }

    async fn read_once(
        &self,
        alias: &KubernetesAliasBinding,
        transport: &dyn KubernetesTransport,
        purpose: SecretPurpose,
        token: Option<&[u8]>,
    ) -> Result<Zeroizing<Vec<u8>>, KubernetesFailure> {
        let headers = request_headers(token)?;
        let response = self
            .send_with_bounded_retries(transport, Method::GET, &alias.read_url, headers, None)
            .await?;
        let body = bounded_json_body(&response, MAX_KUBERNETES_READ_RESPONSE_BYTES)?;
        let read: SecretReadResponse =
            serde_json::from_slice(body).map_err(|_| KubernetesFailure::InvalidResponse)?;
        read.into_value(alias, purpose)
    }

    async fn send_with_bounded_retries(
        &self,
        transport: &dyn KubernetesTransport,
        method: Method,
        url: &str,
        headers: HeaderMap,
        body: Option<Vec<u8>>,
    ) -> Result<KubernetesHttpResponse, KubernetesFailure> {
        let mut attempt = 0;
        loop {
            let response = transport
                .send(method.clone(), url, headers.clone(), body.clone())
                .await;
            let failure = match response {
                Ok(response) => match classify_status(response.status) {
                    None => return Ok(response),
                    Some(failure) => failure,
                },
                Err(error) => map_egress_error(&error),
            };
            if attempt >= MAX_KUBERNETES_TRANSIENT_RETRIES || !failure.is_transient() {
                return Err(failure);
            }
            attempt = attempt.saturating_add(1);
            tokio::time::sleep(KUBERNETES_RETRY_BACKOFF).await;
        }
    }
}

#[async_trait]
impl SecretResolver for KubernetesSecretProvider {
    async fn resolve(
        &self,
        alias_id: &str,
        purpose: SecretPurpose,
    ) -> Result<ResolvedSecret, SecretResolveError> {
        let alias_id = safe_error_alias_id(alias_id);
        let started = Instant::now();
        let permit = Arc::clone(&self.concurrent_reads)
            .try_acquire_owned()
            .map_err(|_| KubernetesFailure::ProviderBusy);
        let outcome = match permit {
            Ok(permit) => {
                let _permit = permit;
                match tokio::time::timeout(self.deadline, self.resolve_inner(&alias_id, purpose))
                    .await
                {
                    Ok(result) => result,
                    Err(_) => {
                        self.purge_alias(&alias_id);
                        Err(KubernetesFailure::DeadlineExceeded)
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
                provider: SecretProviderKind::KubernetesSecrets,
                configured: true,
                purpose: None,
                pinned: false,
                version: None,
                rotated_at: None,
            })
            .collect()
    }
}

fn record_resolution(outcome: &Result<ResolvedSecret, KubernetesFailure>, elapsed: Duration) {
    let (result, reason) = match outcome {
        Ok(_) => ("success", "resolved"),
        Err(failure) => ("failure", failure.safe_reason()),
    };
    ::metrics::counter!(
        "connection_secret_provider_read_total",
        "provider" => KUBERNETES_PROVIDER_LABEL,
        "result" => result,
        "reason" => reason
    )
    .increment(1);
    ::metrics::histogram!(
        "connection_secret_provider_read_duration_seconds",
        "provider" => KUBERNETES_PROVIDER_LABEL,
        "result" => result
    )
    .record(elapsed.as_secs_f64());
    if let Err(failure) = outcome {
        tracing::warn!(
            provider = KUBERNETES_PROVIDER_LABEL,
            reason = failure.safe_reason(),
            "connection secret provider read failed closed"
        );
    }
}

fn request_headers(token: Option<&[u8]>) -> Result<HeaderMap, KubernetesFailure> {
    let mut headers = HeaderMap::new();
    headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
    if let Some(token) = token {
        let mut bearer = Zeroizing::new(Vec::with_capacity(b"Bearer ".len() + token.len()));
        bearer.extend_from_slice(b"Bearer ");
        bearer.extend_from_slice(token);
        let mut value = HeaderValue::from_bytes(bearer.as_slice())
            .map_err(|_| KubernetesFailure::IdentityInvalid)?;
        value.set_sensitive(true);
        headers.insert(AUTHORIZATION, value);
    }
    Ok(headers)
}

fn validate_token_bytes(token: &[u8]) -> Result<(), KubernetesFailure> {
    if token.is_empty() || token.len() > MAX_KUBERNETES_TOKEN_BYTES {
        return Err(KubernetesFailure::IdentityInvalid);
    }
    if token.iter().any(|byte| *byte < 0x21 || *byte > 0x7e) {
        return Err(KubernetesFailure::IdentityInvalid);
    }
    Ok(())
}

/// Opens one platform-projected root directory as a pinned capability handle,
/// used for both the projected ServiceAccount token root and a projected CA
/// bundle root. `unavailable` and `permissions` name the per-field
/// configuration errors so failures stay attributable without leaking the
/// path.
fn open_projected_root(
    index: usize,
    path: &str,
    unavailable: fn(usize) -> KubernetesProviderConfigError,
    permissions: fn(usize) -> KubernetesProviderConfigError,
) -> Result<Arc<Dir>, KubernetesProviderConfigError> {
    let canonical = fs::canonicalize(PathBuf::from(path)).map_err(|_| unavailable(index))?;
    let directory =
        Dir::open_ambient_dir(&canonical, ambient_authority()).map_err(|_| unavailable(index))?;
    let metadata = directory
        .try_clone()
        .and_then(|directory| directory.into_std_file().metadata())
        .map_err(|_| unavailable(index))?;
    if !metadata.is_dir() {
        return Err(unavailable(index));
    }
    validate_projected_root_permissions(index, &metadata, permissions)?;
    Ok(Arc::new(directory))
}

#[cfg(unix)]
fn validate_projected_root_permissions(
    index: usize,
    metadata: &fs::Metadata,
    permissions: fn(usize) -> KubernetesProviderConfigError,
) -> Result<(), KubernetesProviderConfigError> {
    if crate::connections::secret::projected_root_permissions_are_safe(metadata) {
        Ok(())
    } else {
        Err(permissions(index))
    }
}

#[cfg(not(unix))]
fn validate_projected_root_permissions(
    _: usize,
    _: &fs::Metadata,
    _: fn(usize) -> KubernetesProviderConfigError,
) -> Result<(), KubernetesProviderConfigError> {
    Ok(())
}

fn provider_generation(config: &KubernetesProviderConfig) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"kubernetes-secrets-provider-v1");
    for profile in &config.profiles {
        digest.update(profile.id.as_bytes());
        digest.update([0]);
        digest.update(profile.server.as_bytes());
        digest.update([0]);
        for ca_field in [
            profile.ca_bundle_alias.as_deref(),
            profile.ca_bundle_root.as_deref(),
            profile.ca_bundle_file.as_deref(),
        ] {
            digest.update(ca_field.unwrap_or_default().as_bytes());
            digest.update([0]);
        }
        match &profile.auth {
            KubernetesAuthConfig::ProjectedToken {
                token_root,
                token_file,
            } => {
                digest.update(b"projected_token");
                for field in [token_root, token_file] {
                    digest.update(field.as_bytes());
                    digest.update([0]);
                }
            }
            KubernetesAuthConfig::BearerAlias { secret_alias } => {
                digest.update(b"bearer_alias");
                digest.update(secret_alias.as_bytes());
                digest.update([0]);
            }
            KubernetesAuthConfig::ClientCertificate {
                certificate_alias,
                private_key_alias,
            } => {
                digest.update(b"client_certificate");
                for field in [certificate_alias, private_key_alias] {
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
            &alias.namespace,
            &alias.name,
            &alias.key,
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
enum KubernetesFailure {
    UnknownAlias,
    ProviderBusy,
    DeadlineExceeded,
    EgressDenied,
    RedirectRefused,
    TrustUnavailable,
    TrustInvalid,
    IdentityUnavailable,
    IdentityDenied,
    IdentityInvalid,
    TokenRejected,
    ProviderUnavailable,
    ProviderDenied,
    SecretAbsent,
    InvalidResponse,
    InvalidMaterial,
    ProviderFailure,
}

impl KubernetesFailure {
    const fn safe_reason(self) -> &'static str {
        match self {
            Self::UnknownAlias => "unknown_alias",
            Self::ProviderBusy => "provider_busy",
            Self::DeadlineExceeded => "deadline_exceeded",
            Self::EgressDenied => "egress_denied",
            Self::RedirectRefused => "redirect_refused",
            Self::TrustUnavailable => "trust_unavailable",
            Self::TrustInvalid => "trust_invalid",
            Self::IdentityUnavailable => "identity_unavailable",
            Self::IdentityDenied => "identity_denied",
            Self::IdentityInvalid => "identity_invalid",
            Self::TokenRejected => "token_rejected",
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
            | Self::TrustUnavailable
            | Self::IdentityUnavailable
            | Self::ProviderUnavailable
            | Self::SecretAbsent => SecretResolveErrorKind::SourceUnavailable,
            Self::IdentityDenied | Self::TokenRejected | Self::ProviderDenied => {
                SecretResolveErrorKind::SourceDenied
            }
            Self::EgressDenied | Self::RedirectRefused | Self::TrustInvalid => {
                SecretResolveErrorKind::UnsafeSource
            }
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

fn map_egress_error(error: &EgressError) -> KubernetesFailure {
    match error {
        EgressError::HostNotAllowed(_)
        | EgressError::PortNotAllowed(_)
        | EgressError::NonGlobalIpBlocked(_)
        | EgressError::SchemeNotAllowed(_)
        | EgressError::InvalidPolicy(_)
        | EgressError::InvalidUrl(_)
        | EgressError::InvalidTlsCaBundle { .. }
        | EgressError::InvalidTlsClientIdentity => KubernetesFailure::EgressDenied,
        EgressError::ResponseTooLarge { .. } => KubernetesFailure::InvalidResponse,
        EgressError::RequestBodyTooLarge { .. } | EgressError::RequestBodyReadFailed => {
            KubernetesFailure::InvalidResponse
        }
        _ => KubernetesFailure::ProviderUnavailable,
    }
}

fn classify_status(status: StatusCode) -> Option<KubernetesFailure> {
    if status == StatusCode::OK {
        return None;
    }
    if status.is_redirection() {
        return Some(KubernetesFailure::RedirectRefused);
    }
    Some(match status.as_u16() {
        // An expired or rotated bearer token; eligible for exactly one
        // re-read of the fixed identity source.
        401 => KubernetesFailure::TokenRejected,
        // An RBAC denial; never retried and never re-authenticated.
        403 => KubernetesFailure::ProviderDenied,
        404 => KubernetesFailure::SecretAbsent,
        429 | 500..=599 => KubernetesFailure::ProviderUnavailable,
        _ => KubernetesFailure::InvalidResponse,
    })
}

fn bounded_json_body(
    response: &KubernetesHttpResponse,
    maximum: usize,
) -> Result<&[u8], KubernetesFailure> {
    if !is_json_content_type(response.headers.get(CONTENT_TYPE)) {
        return Err(KubernetesFailure::InvalidResponse);
    }
    if response.body.len() > maximum || response.body.is_empty() {
        return Err(KubernetesFailure::InvalidResponse);
    }
    Ok(response.body.as_slice())
}

fn is_json_content_type(value: Option<&HeaderValue>) -> bool {
    value
        .and_then(|value| value.to_str().ok())
        .map(|value| value.split(';').next().unwrap_or_default().trim())
        .is_some_and(|value| value.eq_ignore_ascii_case("application/json"))
}

/// One Secret `data` value.
///
/// String values are held in zeroizing storage; every other JSON shape is
/// discarded during deserialization so a sibling structure never lands in an
/// unmanaged allocation and never satisfies a data-key lookup.
enum KubernetesDataValue {
    Text(Zeroizing<String>),
    Other,
}

impl<'de> Deserialize<'de> for KubernetesDataValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(KubernetesDataValueVisitor)
    }
}

struct KubernetesDataValueVisitor;

impl<'de> Visitor<'de> for KubernetesDataValueVisitor {
    type Value = KubernetesDataValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a Kubernetes Secret data value")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(KubernetesDataValue::Text(Zeroizing::new(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(KubernetesDataValue::Text(Zeroizing::new(value)))
    }

    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(KubernetesDataValue::Other)
    }

    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(KubernetesDataValue::Other)
    }

    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(KubernetesDataValue::Other)
    }

    fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(KubernetesDataValue::Other)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(KubernetesDataValue::Other)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(KubernetesDataValue::Other)
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
        Ok(KubernetesDataValue::Other)
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: de::MapAccess<'de>,
    {
        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
        Ok(KubernetesDataValue::Other)
    }
}

#[derive(Deserialize)]
struct SecretReadResponse {
    kind: String,
    #[serde(rename = "apiVersion")]
    api_version: String,
    metadata: SecretObjectMetadata,
    #[serde(default)]
    data: Option<BTreeMap<String, KubernetesDataValue>>,
}

#[derive(Deserialize)]
struct SecretObjectMetadata {
    name: String,
    namespace: String,
}

impl SecretReadResponse {
    fn into_value(
        self,
        alias: &KubernetesAliasBinding,
        purpose: SecretPurpose,
    ) -> Result<Zeroizing<Vec<u8>>, KubernetesFailure> {
        // The returned object must be exactly the bound Secret: a proxy,
        // aggregation layer, or misrouted response that answers with another
        // kind, group version, name, or namespace fails closed.
        if self.kind != "Secret" || self.api_version != "v1" {
            return Err(KubernetesFailure::InvalidResponse);
        }
        if self.metadata.name != alias.name || self.metadata.namespace != alias.namespace {
            return Err(KubernetesFailure::InvalidResponse);
        }
        let data = self.data.ok_or(KubernetesFailure::SecretAbsent)?;
        let value = match data.get(&alias.key) {
            Some(KubernetesDataValue::Text(value)) => value,
            Some(KubernetesDataValue::Other) => return Err(KubernetesFailure::InvalidMaterial),
            None => return Err(KubernetesFailure::SecretAbsent),
        };
        // The standard engine rejects whitespace, missing or excess padding,
        // and non-zero trailing bits, so only the canonical encoding of the
        // stored bytes is accepted.
        let bytes = Zeroizing::new(
            BASE64_STANDARD
                .decode(value.as_bytes())
                .map_err(|_| KubernetesFailure::InvalidMaterial)?,
        );
        if bytes.is_empty() || bytes.len() > purpose.max_bytes() || bytes.contains(&0) {
            return Err(KubernetesFailure::InvalidMaterial);
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

    const VALUE_CANARY: &str = "greengateway-kubernetes-value-canary";
    const TOKEN_CANARY: &str = "eyJhbGciOiJSUzI1NiJ9.kubernetes-token-canary.sig";
    const SERVER_CANARY: &str = "https://kubernetes-locator-canary.internal.example:6443";
    const NAMESPACE_CANARY: &str = "namespace-locator-canary";
    const NAME_CANARY: &str = "secret-name-locator-canary";
    const KEY_CANARY: &str = "data-key-locator-canary";
    const CA_PEM_CANARY: &str =
        "-----BEGIN CERTIFICATE-----\nca-material-canary\n-----END CERTIFICATE-----\n";
    const CERT_PEM_CANARY: &str = "-----BEGIN CERTIFICATE-----
client-cert-material-canary
-----END CERTIFICATE-----";
    const KEY_PEM_CANARY: &str = "-----BEGIN PRIVATE KEY-----
client-key-material-canary
-----END PRIVATE KEY-----
";

    type Responder = dyn Fn() -> Result<KubernetesHttpResponse, EgressError> + Send + Sync;

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct RecordedRequest {
        method: String,
        url: String,
        authorization: Option<String>,
        accept: Option<String>,
        body: Option<String>,
        derived_ca: Option<String>,
        derived_identity: Option<String>,
    }

    /// Scripted responses for the read channel.
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

    struct FakeCluster {
        requests: Mutex<Vec<RecordedRequest>>,
        reads: Mutex<FakeChannel>,
        generation: AtomicU64,
        delay: Mutex<Duration>,
        reject_ca_bundles: Mutex<bool>,
    }

    impl FakeCluster {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                requests: Mutex::new(Vec::new()),
                reads: Mutex::new(FakeChannel::default()),
                generation: AtomicU64::new(0),
                delay: Mutex::new(Duration::ZERO),
                reject_ca_bundles: Mutex::new(false),
            })
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

        fn set_delay(&self, delay: Duration) {
            *self.delay.lock().expect("fake delay should lock") = delay;
        }

        fn set_reject_ca_bundles(&self, reject: bool) {
            *self
                .reject_ca_bundles
                .lock()
                .expect("fake CA switch should lock") = reject;
        }
    }

    /// A transport view over the shared fake cluster. The base view has no
    /// TLS material; `with_tls_material` returns a derived view that records
    /// the material on every request and reports a distinct egress
    /// generation.
    struct FakeTransport {
        cluster: Arc<FakeCluster>,
        derived_ca: Option<String>,
        derived_identity: Option<String>,
    }

    impl FakeTransport {
        fn new(cluster: Arc<FakeCluster>) -> Arc<Self> {
            Arc::new(Self {
                cluster,
                derived_ca: None,
                derived_identity: None,
            })
        }
    }

    #[async_trait]
    impl KubernetesTransport for FakeTransport {
        fn egress_generation(&self) -> [u8; 32] {
            let generation = self.cluster.generation.load(Ordering::SeqCst);
            let mut bytes = [0_u8; 32];
            bytes[..8].copy_from_slice(&generation.to_be_bytes());
            if self.derived_ca.is_some() || self.derived_identity.is_some() {
                let mut digest = Sha256::new();
                digest.update(b"fake-derived");
                digest.update(self.derived_ca.as_deref().unwrap_or_default().as_bytes());
                digest.update([0]);
                digest.update(
                    self.derived_identity
                        .as_deref()
                        .unwrap_or_default()
                        .as_bytes(),
                );
                let fingerprint: [u8; 32] = digest.finalize().into();
                bytes[8..16].copy_from_slice(&fingerprint[..8]);
            }
            bytes
        }

        fn with_tls_material(
            &self,
            ca_bundle_pem: Option<&[u8]>,
            client_identity_pem: Option<&[u8]>,
        ) -> Result<Arc<dyn KubernetesTransport>, EgressError> {
            if *self
                .cluster
                .reject_ca_bundles
                .lock()
                .expect("fake CA switch should lock")
            {
                return Err(EgressError::InvalidTlsCaBundle {
                    path: "material".into(),
                    message: "rejected by fake".to_owned(),
                });
            }
            Ok(Arc::new(Self {
                cluster: Arc::clone(&self.cluster),
                derived_ca: ca_bundle_pem.map(|pem| String::from_utf8_lossy(pem).into_owned()),
                derived_identity: client_identity_pem
                    .map(|pem| String::from_utf8_lossy(pem).into_owned()),
            }))
        }

        async fn send(
            &self,
            method: Method,
            url: &str,
            headers: HeaderMap,
            body: Option<Vec<u8>>,
        ) -> Result<KubernetesHttpResponse, EgressError> {
            let header_text = |name: http::header::HeaderName| {
                headers
                    .get(name)
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned)
            };
            self.cluster
                .requests
                .lock()
                .expect("fake request log should lock")
                .push(RecordedRequest {
                    method: method.to_string(),
                    url: url.to_owned(),
                    authorization: header_text(AUTHORIZATION),
                    accept: header_text(ACCEPT),
                    body: body.map(|body| String::from_utf8_lossy(&body).into_owned()),
                    derived_ca: self.derived_ca.clone(),
                    derived_identity: self.derived_identity.clone(),
                });
            let delay = *self.cluster.delay.lock().expect("fake delay should lock");
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            match self
                .cluster
                .reads
                .lock()
                .expect("fake read queue should lock")
                .next()
            {
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
            Ok(KubernetesHttpResponse {
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

    fn secret_body_with_identity(
        namespace: &str,
        name: &str,
        key: &str,
        encoded_value: &str,
    ) -> String {
        format!(
            r#"{{"kind":"Secret","apiVersion":"v1","metadata":{{"name":"{name}","namespace":"{namespace}","uid":"e1","resourceVersion":"41"}},"type":"Opaque","data":{{"{key}":"{encoded_value}","sibling-key":"c2libGluZw=="}}}}"#
        )
    }

    fn secret_body(key: &str, value: &str) -> String {
        secret_body_with_identity(
            NAMESPACE_CANARY,
            NAME_CANARY,
            key,
            &BASE64_STANDARD.encode(value),
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

    impl KubernetesClock for TestClock {
        fn now(&self) -> Instant {
            *self.now.lock().expect("test clock should lock")
        }
    }

    #[test]
    fn a_bootstrap_alias_no_resolver_owns_is_rejected_at_construction() {
        let bootstrap = FakeBootstrap::with_token(TOKEN_CANARY.as_bytes());
        let cluster = FakeCluster::new();
        let build = |profile: KubernetesProfileConfig| {
            KubernetesSecretProvider::from_config(
                &KubernetesProviderConfig {
                    profiles: vec![profile],
                    aliases: vec![alias("billing")],
                },
                &BTreeSet::new(),
                FakeTransport::new(Arc::clone(&cluster)) as Arc<dyn KubernetesTransport>,
                Some(Arc::clone(&bootstrap) as Arc<dyn SecretResolver>),
            )
            .map(|_| ())
        };

        // A bearer alias nothing owns must fail here, not on every request for
        // the life of the process.
        assert!(matches!(
            build(bearer_profile("primary", "no-such-alias")),
            Err(KubernetesProviderConfigError::UnknownBootstrapAlias { index: 0 })
        ));

        // Same rule for trust material and for each half of a client identity.
        let mut ca = bearer_profile("primary", "bootstrap-token");
        ca.ca_bundle_alias = Some("no-such-alias".to_owned());
        assert!(matches!(
            build(ca),
            Err(KubernetesProviderConfigError::UnknownBootstrapAlias { index: 0 })
        ));

        let mut identity = client_certificate_profile("primary");
        identity.auth = KubernetesAuthConfig::ClientCertificate {
            certificate_alias: "tls-cert".to_owned(),
            private_key_alias: "no-such-alias".to_owned(),
        };
        assert!(matches!(
            build(identity),
            Err(KubernetesProviderConfigError::UnknownBootstrapAlias { index: 0 })
        ));

        // An owned alias still builds.
        assert!(build(bearer_profile("primary", "bootstrap-token")).is_ok());
    }

    fn bearer_profile(id: &str, secret_alias: &str) -> KubernetesProfileConfig {
        KubernetesProfileConfig {
            id: id.to_owned(),
            server: SERVER_CANARY.to_owned(),
            ca_bundle_alias: None,
            ca_bundle_root: None,
            ca_bundle_file: None,
            auth: KubernetesAuthConfig::BearerAlias {
                secret_alias: secret_alias.to_owned(),
            },
        }
    }

    fn projected_profile(id: &str, token_root: &str) -> KubernetesProfileConfig {
        KubernetesProfileConfig {
            id: id.to_owned(),
            server: SERVER_CANARY.to_owned(),
            ca_bundle_alias: None,
            ca_bundle_root: None,
            ca_bundle_file: None,
            auth: KubernetesAuthConfig::ProjectedToken {
                token_root: token_root.to_owned(),
                token_file: "token".to_owned(),
            },
        }
    }

    fn client_certificate_profile(id: &str) -> KubernetesProfileConfig {
        KubernetesProfileConfig {
            id: id.to_owned(),
            server: SERVER_CANARY.to_owned(),
            ca_bundle_alias: None,
            ca_bundle_root: None,
            ca_bundle_file: None,
            auth: KubernetesAuthConfig::ClientCertificate {
                certificate_alias: "tls-cert".to_owned(),
                private_key_alias: "tls-key".to_owned(),
            },
        }
    }

    fn alias(id: &str) -> KubernetesSecretAliasConfig {
        KubernetesSecretAliasConfig {
            id: id.to_owned(),
            label: format!("{id} label"),
            profile: "primary".to_owned(),
            namespace: NAMESPACE_CANARY.to_owned(),
            name: NAME_CANARY.to_owned(),
            key: KEY_CANARY.to_owned(),
        }
    }

    struct FakeBootstrap {
        values: Mutex<BTreeMap<String, Vec<u8>>>,
        resolutions: AtomicU64,
    }

    impl FakeBootstrap {
        /// Seeds every alias the test profiles reference.
        ///
        /// Production's bootstrap resolver is the operator alias resolver, whose
        /// id set is fixed from configuration before any provider is built, so a
        /// fixture that only gains its aliases after construction does not model
        /// reality — and provider construction now (correctly) rejects a profile
        /// whose bootstrap alias no resolver owns. Tests that need material to be
        /// absent at *request* time call `remove`.
        fn with_token(token: &[u8]) -> Arc<Self> {
            Arc::new(Self {
                values: Mutex::new(BTreeMap::from([
                    ("bootstrap-token".to_owned(), token.to_vec()),
                    ("cluster-ca".to_owned(), CA_PEM_CANARY.as_bytes().to_vec()),
                    ("tls-cert".to_owned(), CERT_PEM_CANARY.as_bytes().to_vec()),
                    ("tls-key".to_owned(), KEY_PEM_CANARY.as_bytes().to_vec()),
                ])),
                resolutions: AtomicU64::new(0),
            })
        }

        fn set(&self, alias_id: &str, value: &[u8]) {
            self.values
                .lock()
                .expect("bootstrap fixture should lock")
                .insert(alias_id.to_owned(), value.to_vec());
        }

        fn remove(&self, alias_id: &str) {
            self.values
                .lock()
                .expect("bootstrap fixture should lock")
                .remove(alias_id);
        }

        fn resolutions(&self) -> u64 {
            self.resolutions.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl SecretResolver for FakeBootstrap {
        async fn resolve(
            &self,
            alias_id: &str,
            purpose: SecretPurpose,
        ) -> Result<ResolvedSecret, SecretResolveError> {
            self.resolutions.fetch_add(1, Ordering::SeqCst);
            let value = self
                .values
                .lock()
                .expect("bootstrap fixture should lock")
                .get(alias_id)
                .cloned()
                .ok_or_else(|| {
                    SecretResolveError::new(alias_id, SecretResolveErrorKind::UnknownAlias)
                })?;
            ResolvedSecret::new(purpose, value).map_err(|_| {
                SecretResolveError::new(alias_id, SecretResolveErrorKind::InvalidMaterial)
            })
        }

        fn contains_alias(&self, alias_id: &str) -> bool {
            self.values
                .lock()
                .expect("bootstrap fixture should lock")
                .contains_key(alias_id)
        }

        fn aliases(&self) -> Vec<SecretAliasMetadata> {
            Vec::new()
        }
    }

    struct ProviderFixture {
        provider: KubernetesSecretProvider,
        cluster: Arc<FakeCluster>,
        clock: Arc<TestClock>,
        bootstrap: Arc<FakeBootstrap>,
    }

    fn provider(aliases: Vec<KubernetesSecretAliasConfig>) -> ProviderFixture {
        provider_with_config(KubernetesProviderConfig {
            profiles: vec![bearer_profile("primary", "bootstrap-token")],
            aliases,
        })
    }

    fn provider_with_config(config: KubernetesProviderConfig) -> ProviderFixture {
        let cluster = FakeCluster::new();
        let clock = TestClock::new();
        let bootstrap = FakeBootstrap::with_token(TOKEN_CANARY.as_bytes());
        let mut provider = KubernetesSecretProvider::from_config(
            &config,
            &BTreeSet::new(),
            FakeTransport::new(Arc::clone(&cluster)) as Arc<dyn KubernetesTransport>,
            Some(Arc::clone(&bootstrap) as Arc<dyn SecretResolver>),
        )
        .expect("test provider should build");
        provider.clock = Arc::clone(&clock) as Arc<dyn KubernetesClock>;
        ProviderFixture {
            provider,
            cluster,
            clock,
            bootstrap,
        }
    }

    #[test]
    fn configuration_rejects_unsafe_or_ambiguous_entries() {
        let base = |profiles: Vec<KubernetesProfileConfig>,
                    aliases: Vec<KubernetesSecretAliasConfig>| {
            validate_kubernetes_provider_config(
                &KubernetesProviderConfig { profiles, aliases },
                &BTreeSet::new(),
            )
        };
        for server in [
            "http://kubernetes.example",
            "https://user:pass@kubernetes.example",
            "https://kubernetes.example/api",
            "https://kubernetes.example?watch=true",
            "https://kubernetes.example#fragment",
            "kubernetes.example",
            "",
        ] {
            let mut profile = bearer_profile("primary", "bootstrap-token");
            profile.server = server.to_owned();
            assert!(
                matches!(
                    base(vec![profile], Vec::new()),
                    Err(KubernetesProviderConfigError::InvalidServer { .. })
                ),
                "{server:?} must be rejected"
            );
        }
        for namespace in [
            "",
            "Upper",
            "under_score",
            "-leading",
            "trailing-",
            "dotted.name",
            "..",
            "a/b",
            "a%2fb",
            "name space",
            &"n".repeat(MAX_DNS1123_LABEL_BYTES + 1),
        ] {
            let mut entry = alias("billing");
            entry.namespace = namespace.to_owned();
            assert!(
                matches!(
                    base(
                        vec![bearer_profile("primary", "bootstrap-token")],
                        vec![entry]
                    ),
                    Err(KubernetesProviderConfigError::InvalidNamespace { .. })
                ),
                "{namespace:?} must be rejected"
            );
        }
        for name in [
            "",
            "Upper",
            "..",
            "trailing.",
            ".leading",
            "double..dot",
            "with/slash",
            "with%2fencoded",
            "under_score",
            &"n".repeat(MAX_DNS1123_SUBDOMAIN_BYTES + 1),
        ] {
            let mut entry = alias("billing");
            entry.name = name.to_owned();
            assert!(
                matches!(
                    base(
                        vec![bearer_profile("primary", "bootstrap-token")],
                        vec![entry]
                    ),
                    Err(KubernetesProviderConfigError::InvalidSecretName { .. })
                ),
                "{name:?} must be rejected"
            );
        }
        for key in [
            "",
            ".",
            "..",
            "a b",
            "a/b",
            "a%2fb",
            "a\u{7f}b",
            &"k".repeat(MAX_KUBERNETES_DATA_KEY_BYTES + 1),
        ] {
            let mut entry = alias("billing");
            entry.key = key.to_owned();
            assert!(
                matches!(
                    base(
                        vec![bearer_profile("primary", "bootstrap-token")],
                        vec![entry]
                    ),
                    Err(KubernetesProviderConfigError::InvalidDataKey { .. })
                ),
                "{key:?} must be rejected"
            );
        }
        assert!(matches!(
            base(
                vec![bearer_profile("primary", "bootstrap-token")],
                vec![alias("billing"), alias("billing")],
            ),
            Err(KubernetesProviderConfigError::DuplicateAliasId { .. })
        ));
        let mut unknown_profile = alias("billing");
        unknown_profile.profile = "missing".to_owned();
        assert!(matches!(
            base(
                vec![bearer_profile("primary", "bootstrap-token")],
                vec![unknown_profile]
            ),
            Err(KubernetesProviderConfigError::UnknownProfile { .. })
        ));
        assert!(matches!(
            base(
                vec![bearer_profile("primary", "billing")],
                vec![alias("billing")],
            ),
            Err(KubernetesProviderConfigError::BootstrapAliasCycle { .. })
        ));
        let mut ca_cycle = bearer_profile("primary", "bootstrap-token");
        ca_cycle.ca_bundle_alias = Some("billing".to_owned());
        assert!(matches!(
            base(vec![ca_cycle], vec![alias("billing")]),
            Err(KubernetesProviderConfigError::CaBundleAliasCycle { .. })
        ));
        let mut invalid_ca = bearer_profile("primary", "bootstrap-token");
        invalid_ca.ca_bundle_alias = Some("../escape".to_owned());
        assert!(matches!(
            base(vec![invalid_ca], Vec::new()),
            Err(KubernetesProviderConfigError::InvalidCaBundleAlias { .. })
        ));
        let mut invalid_token_file = projected_profile("primary", "/var/run/secrets/tokens");
        if let KubernetesAuthConfig::ProjectedToken { token_file, .. } =
            &mut invalid_token_file.auth
        {
            *token_file = "../escape".to_owned();
        }
        assert!(matches!(
            base(vec![invalid_token_file], Vec::new()),
            Err(KubernetesProviderConfigError::InvalidProjectedTokenFile { .. })
        ));
        assert!(matches!(
            base(Vec::new(), vec![alias("billing")]),
            Err(KubernetesProviderConfigError::AliasesWithoutProfiles)
        ));
        assert!(matches!(
            validate_kubernetes_provider_config(
                &KubernetesProviderConfig {
                    profiles: vec![bearer_profile("primary", "bootstrap-token")],
                    aliases: vec![alias("billing")],
                },
                &BTreeSet::from(["billing".to_owned()]),
            ),
            Err(KubernetesProviderConfigError::ReservedAliasId { .. })
        ));
        let profiles = (0..=MAX_KUBERNETES_PROFILES)
            .map(|index| bearer_profile(&format!("profile-{index}"), "bootstrap-token"))
            .collect::<Vec<_>>();
        assert!(matches!(
            base(profiles, Vec::new()),
            Err(KubernetesProviderConfigError::TooManyProfiles { .. })
        ));
    }

    #[tokio::test]
    async fn unknown_alias_denial_produces_zero_provider_work() {
        let fixture = provider(vec![alias("billing")]);
        fixture
            .cluster
            .push_read(json_response(200, &secret_body(KEY_CANARY, VALUE_CANARY)));

        let error = fixture
            .provider
            .resolve("not-configured", SecretPurpose::StaticBearer)
            .await
            .expect_err("unknown alias must fail closed");

        assert_eq!(error.kind(), SecretResolveErrorKind::UnknownAlias);
        assert!(fixture.cluster.requests().is_empty());
        assert_eq!(fixture.bootstrap.resolutions(), 0);
    }

    #[tokio::test]
    async fn saturated_provider_admission_fails_before_any_provider_work() {
        let fixture = provider(vec![alias("billing")]);
        fixture
            .cluster
            .push_read(json_response(200, &secret_body(KEY_CANARY, VALUE_CANARY)));
        let mut provider = fixture.provider.clone();
        provider.concurrent_reads = Arc::new(Semaphore::new(0));

        let error = provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect_err("saturated admission must fail closed");

        assert_eq!(error.kind(), SecretResolveErrorKind::ProviderBusy);
        assert!(fixture.cluster.requests().is_empty());
    }

    #[tokio::test]
    async fn reads_authenticate_first_and_target_only_the_bound_secret_path() {
        let fixture = provider(vec![alias("billing")]);
        fixture
            .cluster
            .push_read(json_response(200, &secret_body(KEY_CANARY, VALUE_CANARY)));

        let secret = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("configured alias should resolve");

        assert_eq!(secret.expose(), VALUE_CANARY.as_bytes());
        let requests = fixture.cluster.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, "GET");
        assert_eq!(
            requests[0].url,
            format!("{SERVER_CANARY}/api/v1/namespaces/{NAMESPACE_CANARY}/secrets/{NAME_CANARY}")
        );
        assert_eq!(
            requests[0].authorization.as_deref(),
            Some(format!("Bearer {TOKEN_CANARY}").as_str())
        );
        assert_eq!(requests[0].accept.as_deref(), Some("application/json"));
        assert!(requests[0].body.is_none());
        for request in &requests {
            assert!(!request.url.contains('?'));
            assert!(!request.url.contains("/watch"));
            assert!(!request.url.ends_with("/secrets"));
            assert_eq!(request.method, "GET");
        }
    }

    #[tokio::test]
    async fn egress_denials_and_refused_redirects_fail_closed() {
        for (responder, expected) in [
            (
                egress_failure(|| EgressError::HostNotAllowed("kubernetes".to_owned())),
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
                        "10.96.0.1".parse().expect("literal IP should parse"),
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
            fixture.cluster.push_read(responder);

            let error = fixture
                .provider
                .resolve("billing", SecretPurpose::StaticBearer)
                .await
                .expect_err("egress denial must fail closed");

            assert_eq!(error.kind(), expected);
            assert_eq!(fixture.cluster.requests().len(), 1);
        }
    }

    #[tokio::test]
    async fn dns_failure_retries_once_and_then_fails_closed() {
        let fixture = provider(vec![alias("billing")]);
        fixture.cluster.push_read(egress_failure(|| {
            EgressError::DnsResolutionFailed("kubernetes".to_owned())
        }));

        let error = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect_err("unreachable provider must fail closed");

        assert_eq!(error.kind(), SecretResolveErrorKind::SourceUnavailable);
        assert_eq!(
            fixture.cluster.requests().len(),
            usize::try_from(MAX_KUBERNETES_TRANSIENT_RETRIES).expect("retry bound should fit") + 1
        );
    }

    #[tokio::test]
    async fn an_expired_token_re_reads_the_identity_source_exactly_once() {
        let fixture = provider(vec![alias("billing")]);
        fixture.cluster.push_read(json_response(
            401,
            r#"{"kind":"Status","apiVersion":"v1","reason":"Unauthorized","code":401}"#,
        ));
        fixture
            .cluster
            .push_read(json_response(200, &secret_body(KEY_CANARY, VALUE_CANARY)));

        let secret = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("a rotated identity should recover once");

        assert_eq!(secret.expose(), VALUE_CANARY.as_bytes());
        assert_eq!(fixture.cluster.requests().len(), 2);
        assert_eq!(fixture.bootstrap.resolutions(), 2);
    }

    #[tokio::test]
    async fn a_persistent_401_fails_closed_after_one_re_read() {
        let fixture = provider(vec![alias("billing")]);
        fixture.cluster.push_read(json_response(
            401,
            r#"{"kind":"Status","apiVersion":"v1","reason":"Unauthorized","code":401}"#,
        ));

        let error = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect_err("a persistently rejected token must fail closed");

        assert_eq!(error.kind(), SecretResolveErrorKind::SourceDenied);
        assert_eq!(fixture.cluster.requests().len(), 2);
        assert_eq!(fixture.bootstrap.resolutions(), 2);
    }

    #[tokio::test]
    async fn an_rbac_denial_never_re_authenticates_or_retries() {
        let fixture = provider(vec![alias("billing")]);
        fixture.cluster.push_read(json_response(
            403,
            r#"{"kind":"Status","apiVersion":"v1","reason":"Forbidden","code":403}"#,
        ));

        let error = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect_err("an RBAC denial must fail closed");

        assert_eq!(error.kind(), SecretResolveErrorKind::SourceDenied);
        assert_eq!(fixture.cluster.requests().len(), 1);
        assert_eq!(fixture.bootstrap.resolutions(), 1);
    }

    #[tokio::test]
    async fn newly_denied_access_fails_closed_without_a_stale_value() {
        let fixture = provider(vec![alias("billing")]);
        fixture
            .cluster
            .push_read(json_response(200, &secret_body(KEY_CANARY, VALUE_CANARY)));
        let first = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("first read should resolve");
        assert_eq!(first.expose(), VALUE_CANARY.as_bytes());

        fixture.cluster.push_read(json_response(
            403,
            r#"{"kind":"Status","apiVersion":"v1","reason":"Forbidden","code":403}"#,
        ));
        fixture.clock.advance(KUBERNETES_VALUE_CACHE_TTL * 2);

        let error = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect_err("newly denied access must fail closed");

        assert_eq!(error.kind(), SecretResolveErrorKind::SourceDenied);
        assert!(fixture.provider.value_guard().is_empty());
    }

    #[tokio::test]
    async fn object_identity_mismatches_fail_closed() {
        let encoded = BASE64_STANDARD.encode(VALUE_CANARY);
        for body in [
            secret_body_with_identity(NAMESPACE_CANARY, "other-secret", KEY_CANARY, &encoded),
            secret_body_with_identity("other-namespace", NAME_CANARY, KEY_CANARY, &encoded),
            secret_body(KEY_CANARY, VALUE_CANARY)
                .replace(r#""kind":"Secret""#, r#""kind":"ConfigMap""#),
            secret_body(KEY_CANARY, VALUE_CANARY)
                .replace(r#""apiVersion":"v1""#, r#""apiVersion":"v2""#),
        ] {
            let fixture = provider(vec![alias("billing")]);
            fixture.cluster.push_read(json_response(200, &body));

            let error = fixture
                .provider
                .resolve("billing", SecretPurpose::StaticBearer)
                .await
                .expect_err("an object identity mismatch must fail closed");

            assert_eq!(error.kind(), SecretResolveErrorKind::InvalidMaterial);
            assert!(fixture.provider.value_guard().is_empty());
        }
    }

    #[tokio::test]
    async fn missing_keys_missing_data_and_missing_secrets_fail_closed() {
        let missing_key = secret_body_with_identity(
            NAMESPACE_CANARY,
            NAME_CANARY,
            "other-key",
            &BASE64_STANDARD.encode(VALUE_CANARY),
        );
        let no_data = format!(
            r#"{{"kind":"Secret","apiVersion":"v1","metadata":{{"name":"{NAME_CANARY}","namespace":"{NAMESPACE_CANARY}"}},"type":"Opaque"}}"#
        );
        for (responder, expected) in [
            (
                json_response(200, &missing_key),
                SecretResolveErrorKind::SourceUnavailable,
            ),
            (
                json_response(200, &no_data),
                SecretResolveErrorKind::SourceUnavailable,
            ),
            (
                json_response(
                    404,
                    r#"{"kind":"Status","apiVersion":"v1","reason":"NotFound","code":404}"#,
                ),
                SecretResolveErrorKind::SourceUnavailable,
            ),
        ] {
            let fixture = provider(vec![alias("billing")]);
            fixture.cluster.push_read(responder);

            let error = fixture
                .provider
                .resolve("billing", SecretPurpose::StaticBearer)
                .await
                .expect_err("absent material must fail closed");

            assert_eq!(error.kind(), expected);
        }
    }

    #[tokio::test]
    async fn non_canonical_base64_encodings_fail_closed() {
        for encoded in [
            "QQ",
            "QQ== ",
            " QQ==",
            "QUJ\nD",
            "QR==",
            "QQ===",
            "not-base64!",
            "",
        ] {
            let body =
                secret_body_with_identity(NAMESPACE_CANARY, NAME_CANARY, KEY_CANARY, encoded);
            let fixture = provider(vec![alias("billing")]);
            fixture.cluster.push_read(json_response(200, &body));

            let error = fixture
                .provider
                .resolve("billing", SecretPurpose::StaticBearer)
                .await
                .expect_err("non-canonical Base64 must fail closed");

            assert_eq!(
                error.kind(),
                SecretResolveErrorKind::InvalidMaterial,
                "{encoded:?} must be rejected"
            );
        }
    }

    #[tokio::test]
    async fn malformed_oversized_and_non_string_responses_fail_closed() {
        let oversized_value = secret_body_with_identity(
            NAMESPACE_CANARY,
            NAME_CANARY,
            KEY_CANARY,
            &BASE64_STANDARD.encode(vec![
                b'x';
                super::super::secret::MAX_HTTP_CREDENTIAL_BYTES + 1
            ]),
        );
        let structured_value = format!(
            r#"{{"kind":"Secret","apiVersion":"v1","metadata":{{"name":"{NAME_CANARY}","namespace":"{NAMESPACE_CANARY}"}},"data":{{"{KEY_CANARY}":{{"nested":"value"}}}}}}"#
        );
        let nul_value = secret_body_with_identity(
            NAMESPACE_CANARY,
            NAME_CANARY,
            KEY_CANARY,
            &BASE64_STANDARD.encode(b"nul\0value"),
        );
        let oversized_body = format!(
            r#"{{"kind":"Secret","apiVersion":"v1","metadata":{{"name":"{NAME_CANARY}","namespace":"{NAMESPACE_CANARY}","annotations":{{"pad":"{}"}}}},"data":{{"{KEY_CANARY}":"{}"}}}}"#,
            "w".repeat(MAX_KUBERNETES_READ_RESPONSE_BYTES),
            BASE64_STANDARD.encode(VALUE_CANARY),
        );
        for responder in [
            json_response(200, "{not json"),
            json_response(200, r#"{"kind":"Secret"}"#),
            json_response(200, &oversized_body),
            response(200, "text/html", &secret_body(KEY_CANARY, VALUE_CANARY)),
            json_response(200, &oversized_value),
            json_response(200, &structured_value),
            json_response(200, &nul_value),
        ] {
            let fixture = provider(vec![alias("billing")]);
            fixture.cluster.push_read(responder);

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
    async fn bearer_material_that_cannot_form_a_header_fails_closed() {
        let fixture = provider(vec![alias("billing")]);
        fixture
            .bootstrap
            .set("bootstrap-token", b"token with spaces\x01");
        fixture
            .cluster
            .push_read(json_response(200, &secret_body(KEY_CANARY, VALUE_CANARY)));

        let error = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect_err("non-header-safe bearer material must fail closed");

        assert_eq!(error.kind(), SecretResolveErrorKind::InvalidMaterial);
        assert!(fixture.cluster.requests().is_empty());
    }

    #[tokio::test]
    async fn rotated_bearer_material_is_observed_after_the_bounded_token_lifetime() {
        let fixture = provider(vec![alias("billing")]);
        fixture
            .cluster
            .push_read(json_response(200, &secret_body(KEY_CANARY, "first-value")));

        let first = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("first read should resolve");
        assert_eq!(first.expose(), b"first-value");

        fixture
            .bootstrap
            .set("bootstrap-token", b"rotated-token-canary");
        fixture
            .cluster
            .push_read(json_response(200, &secret_body(KEY_CANARY, "second-value")));
        fixture.clock.advance(
            KUBERNETES_TOKEN_LIFETIME
                .max(KUBERNETES_VALUE_CACHE_TTL)
                .saturating_add(Duration::from_secs(1)),
        );

        let second = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("rotated read should resolve");

        assert_eq!(second.expose(), b"second-value");
        let requests = fixture.cluster.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(
            requests[0].authorization.as_deref(),
            Some(format!("Bearer {TOKEN_CANARY}").as_str())
        );
        assert_eq!(
            requests[1].authorization.as_deref(),
            Some("Bearer rotated-token-canary")
        );
    }

    #[tokio::test]
    async fn concurrent_resolutions_are_hard_bounded() {
        let fixture = provider(vec![alias("billing")]);
        fixture
            .cluster
            .push_read(json_response(200, &secret_body(KEY_CANARY, VALUE_CANARY)));
        fixture.cluster.set_delay(Duration::from_millis(250));
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
            .cluster
            .push_read(json_response(200, &secret_body(KEY_CANARY, VALUE_CANARY)));
        fixture.cluster.set_delay(Duration::from_secs(30));
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
        let aliases = (0..MAX_KUBERNETES_VALUE_CACHE_ENTRIES + 4)
            .map(|index| alias(&format!("billing-{index}")))
            .collect::<Vec<_>>();
        let fixture = provider(aliases);
        fixture
            .cluster
            .push_read(json_response(200, &secret_body(KEY_CANARY, VALUE_CANARY)));

        for index in 0..MAX_KUBERNETES_VALUE_CACHE_ENTRIES + 4 {
            fixture
                .provider
                .resolve(&format!("billing-{index}"), SecretPurpose::StaticBearer)
                .await
                .expect("each read should resolve");
        }

        assert!(fixture.provider.value_guard().len() <= MAX_KUBERNETES_VALUE_CACHE_ENTRIES);
    }

    #[tokio::test]
    async fn cached_values_expire_and_observe_rotated_secret_data() {
        let fixture = provider(vec![alias("billing")]);
        fixture
            .cluster
            .push_read(json_response(200, &secret_body(KEY_CANARY, "first-value")));

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
        assert_eq!(fixture.cluster.requests().len(), 1);

        fixture
            .cluster
            .push_read(json_response(200, &secret_body(KEY_CANARY, "second-value")));
        fixture
            .clock
            .advance(KUBERNETES_VALUE_CACHE_TTL + Duration::from_secs(1));

        let rotated = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("rotated read should resolve");

        assert_eq!(rotated.expose(), b"second-value");
        assert_eq!(fixture.cluster.requests().len(), 2);
        assert_eq!(first.expose(), b"first-value");
    }

    #[tokio::test]
    async fn a_profile_ca_bundle_derives_a_dedicated_trust_transport() {
        let mut profile = bearer_profile("primary", "bootstrap-token");
        profile.ca_bundle_alias = Some("cluster-ca".to_owned());
        let fixture = provider_with_config(KubernetesProviderConfig {
            profiles: vec![profile],
            aliases: vec![alias("billing")],
        });
        fixture
            .bootstrap
            .set("cluster-ca", CA_PEM_CANARY.as_bytes());
        fixture
            .cluster
            .push_read(json_response(200, &secret_body(KEY_CANARY, VALUE_CANARY)));

        let secret = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("a CA-pinned profile should resolve");

        assert_eq!(secret.expose(), VALUE_CANARY.as_bytes());
        let requests = fixture.cluster.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].derived_ca.as_deref(), Some(CA_PEM_CANARY));

        // A rotated CA bundle re-derives the transport and invalidates the
        // value cached under the previous trust generation.
        fixture.bootstrap.set(
            "cluster-ca",
            "-----BEGIN CERTIFICATE-----\nrotated\n-----END CERTIFICATE-----\n".as_bytes(),
        );
        fixture
            .cluster
            .push_read(json_response(200, &secret_body(KEY_CANARY, "second-value")));

        let rotated = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("a rotated CA bundle should re-derive the transport");

        assert_eq!(rotated.expose(), b"second-value");
        let requests = fixture.cluster.requests();
        assert_eq!(requests.len(), 2);
        assert!(requests[1]
            .derived_ca
            .as_deref()
            .is_some_and(|ca| ca.contains("rotated")));
    }

    #[tokio::test]
    async fn missing_or_invalid_ca_trust_material_fails_closed_before_any_request() {
        let mut profile = bearer_profile("primary", "bootstrap-token");
        profile.ca_bundle_alias = Some("cluster-ca".to_owned());

        let fixture = provider_with_config(KubernetesProviderConfig {
            profiles: vec![profile.clone()],
            aliases: vec![alias("billing")],
        });
        // Configured and resolvable at construction, gone by request time.
        fixture.bootstrap.remove("cluster-ca");
        fixture
            .cluster
            .push_read(json_response(200, &secret_body(KEY_CANARY, VALUE_CANARY)));
        let error = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect_err("a missing CA bundle alias must fail closed");
        assert_eq!(error.kind(), SecretResolveErrorKind::UnsafeSource);
        assert!(fixture.cluster.requests().is_empty());

        let fixture = provider_with_config(KubernetesProviderConfig {
            profiles: vec![profile],
            aliases: vec![alias("billing")],
        });
        fixture
            .bootstrap
            .set("cluster-ca", CA_PEM_CANARY.as_bytes());
        fixture.cluster.set_reject_ca_bundles(true);
        fixture
            .cluster
            .push_read(json_response(200, &secret_body(KEY_CANARY, VALUE_CANARY)));
        let error = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect_err("an unusable CA bundle must fail closed");
        assert_eq!(error.kind(), SecretResolveErrorKind::UnsafeSource);
        assert!(fixture.cluster.requests().is_empty());
    }

    #[test]
    fn configuration_rejects_conflicting_or_invalid_ca_bundle_sources() {
        let base = |profile: KubernetesProfileConfig| {
            validate_kubernetes_provider_config(
                &KubernetesProviderConfig {
                    profiles: vec![profile],
                    aliases: Vec::new(),
                },
                &BTreeSet::new(),
            )
        };
        let mut both_sources = bearer_profile("primary", "bootstrap-token");
        both_sources.ca_bundle_alias = Some("cluster-ca".to_owned());
        both_sources.ca_bundle_root =
            Some("/var/run/secrets/kubernetes.io/serviceaccount".to_owned());
        both_sources.ca_bundle_file = Some("ca.crt".to_owned());
        assert!(matches!(
            base(both_sources),
            Err(KubernetesProviderConfigError::ConflictingCaBundleSources { .. })
        ));
        let mut root_without_file = bearer_profile("primary", "bootstrap-token");
        root_without_file.ca_bundle_root = Some("/var/run/secrets".to_owned());
        assert!(matches!(
            base(root_without_file),
            Err(KubernetesProviderConfigError::ConflictingCaBundleSources { .. })
        ));
        let mut file_without_root = bearer_profile("primary", "bootstrap-token");
        file_without_root.ca_bundle_file = Some("ca.crt".to_owned());
        assert!(matches!(
            base(file_without_root),
            Err(KubernetesProviderConfigError::ConflictingCaBundleSources { .. })
        ));
        let mut empty_root = bearer_profile("primary", "bootstrap-token");
        empty_root.ca_bundle_root = Some(String::new());
        empty_root.ca_bundle_file = Some("ca.crt".to_owned());
        assert!(matches!(
            base(empty_root),
            Err(KubernetesProviderConfigError::InvalidCaBundleRoot { .. })
        ));
        for file in ["../escape", "nested/ca.crt", "..", "NUL"] {
            let mut invalid_file = bearer_profile("primary", "bootstrap-token");
            invalid_file.ca_bundle_root = Some("/var/run/secrets".to_owned());
            invalid_file.ca_bundle_file = Some(file.to_owned());
            assert!(
                matches!(
                    base(invalid_file),
                    Err(KubernetesProviderConfigError::InvalidCaBundleFile { .. })
                ),
                "{file:?} must be rejected"
            );
        }
    }

    #[tokio::test]
    async fn a_projected_ca_bundle_derives_trust_and_observes_rotation() {
        let root = std::env::temp_dir().join(format!(
            "greengateway-kubernetes-projected-ca-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir(&root).expect("projected CA root should create");
        set_directory_permissions(&root, 0o755);
        fs::write(root.join("ca.crt"), CA_PEM_CANARY.as_bytes()).expect("CA bundle should write");
        set_file_permissions(&root.join("ca.crt"), 0o644);

        let mut profile = bearer_profile("primary", "bootstrap-token");
        profile.ca_bundle_root = Some(
            root.to_str()
                .expect("CA root path should be Unicode")
                .to_owned(),
        );
        profile.ca_bundle_file = Some("ca.crt".to_owned());
        let fixture = provider_with_config(KubernetesProviderConfig {
            profiles: vec![profile],
            aliases: vec![alias("billing")],
        });
        fixture
            .cluster
            .push_read(json_response(200, &secret_body(KEY_CANARY, VALUE_CANARY)));

        let secret = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("a projected-CA profile should resolve");
        assert_eq!(secret.expose(), VALUE_CANARY.as_bytes());
        let requests = fixture.cluster.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].derived_ca.as_deref(), Some(CA_PEM_CANARY));

        // A rotated projected bundle re-derives the transport and invalidates
        // the value cached under the previous trust generation.
        fs::write(
            root.join("ca.crt"),
            b"-----BEGIN CERTIFICATE-----\nrotated-projected\n-----END CERTIFICATE-----\n",
        )
        .expect("CA bundle should rewrite");
        set_file_permissions(&root.join("ca.crt"), 0o644);
        fixture
            .cluster
            .push_read(json_response(200, &secret_body(KEY_CANARY, "second-value")));

        let rotated = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("a rotated projected CA bundle should re-derive the transport");
        assert_eq!(rotated.expose(), b"second-value");
        let requests = fixture.cluster.requests();
        assert_eq!(requests.len(), 2);
        assert!(requests[1]
            .derived_ca
            .as_deref()
            .is_some_and(|ca| ca.contains("rotated-projected")));

        // A missing projected bundle fails closed before any request.
        fs::remove_file(root.join("ca.crt")).expect("CA bundle should remove");
        fixture.provider.purge_alias("billing");
        let error = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect_err("a missing projected CA bundle must fail closed");
        assert_eq!(error.kind(), SecretResolveErrorKind::SourceUnavailable);
        assert_eq!(fixture.cluster.requests().len(), 2);

        drop(fixture);
        fs::remove_dir_all(&root).expect("projected CA root should remove");
    }

    #[tokio::test]
    async fn a_trust_outage_purges_previously_cached_values() {
        let mut profile = bearer_profile("primary", "bootstrap-token");
        profile.ca_bundle_alias = Some("cluster-ca".to_owned());
        let fixture = provider_with_config(KubernetesProviderConfig {
            profiles: vec![profile],
            aliases: vec![alias("billing")],
        });
        fixture
            .bootstrap
            .set("cluster-ca", CA_PEM_CANARY.as_bytes());
        fixture
            .cluster
            .push_read(json_response(200, &secret_body(KEY_CANARY, "first-value")));
        let first = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("first read should resolve");
        assert_eq!(first.expose(), b"first-value");
        assert_eq!(fixture.provider.value_guard().len(), 1);

        // Trust material becomes unresolvable: the resolution fails closed
        // and the previously cached value is purged, not preserved.
        fixture.bootstrap.remove("cluster-ca");
        let error = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect_err("a trust outage must fail closed");
        assert_eq!(error.kind(), SecretResolveErrorKind::UnsafeSource);
        assert!(fixture.provider.value_guard().is_empty());
        assert_eq!(fixture.cluster.requests().len(), 1);

        // After trust recovers, the next resolution re-reads the provider
        // instead of serving the pre-outage value, even inside the value TTL.
        fixture
            .bootstrap
            .set("cluster-ca", CA_PEM_CANARY.as_bytes());
        fixture
            .cluster
            .push_read(json_response(200, &secret_body(KEY_CANARY, "second-value")));
        let recovered = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("a recovered trust source should resolve");
        assert_eq!(recovered.expose(), b"second-value");
        assert_eq!(fixture.cluster.requests().len(), 2);
    }

    #[test]
    fn configuration_rejects_invalid_client_certificate_bootstrap() {
        let base = |profile: KubernetesProfileConfig, aliases: Vec<KubernetesSecretAliasConfig>| {
            validate_kubernetes_provider_config(
                &KubernetesProviderConfig {
                    profiles: vec![profile],
                    aliases,
                },
                &BTreeSet::new(),
            )
        };
        let mut invalid_certificate = client_certificate_profile("primary");
        if let KubernetesAuthConfig::ClientCertificate {
            certificate_alias, ..
        } = &mut invalid_certificate.auth
        {
            *certificate_alias = "../escape".to_owned();
        }
        assert!(matches!(
            base(invalid_certificate, Vec::new()),
            Err(KubernetesProviderConfigError::InvalidBootstrapAlias { .. })
        ));
        let mut key_cycle = client_certificate_profile("primary");
        if let KubernetesAuthConfig::ClientCertificate {
            private_key_alias, ..
        } = &mut key_cycle.auth
        {
            *private_key_alias = "billing".to_owned();
        }
        assert!(matches!(
            base(key_cycle, vec![alias("billing")]),
            Err(KubernetesProviderConfigError::BootstrapAliasCycle { .. })
        ));
    }

    #[tokio::test]
    async fn client_certificate_profiles_authenticate_with_mutual_tls_only() {
        let fixture = provider_with_config(KubernetesProviderConfig {
            profiles: vec![client_certificate_profile("primary")],
            aliases: vec![alias("billing")],
        });
        fixture
            .bootstrap
            .set("tls-cert", CERT_PEM_CANARY.as_bytes());
        fixture.bootstrap.set("tls-key", KEY_PEM_CANARY.as_bytes());
        fixture
            .cluster
            .push_read(json_response(200, &secret_body(KEY_CANARY, VALUE_CANARY)));

        let secret = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("a mutual-TLS profile should resolve");

        assert_eq!(secret.expose(), VALUE_CANARY.as_bytes());
        let requests = fixture.cluster.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].authorization, None,
            "mutual TLS must not send a bearer header"
        );
        let expected_identity = format!(
            "{CERT_PEM_CANARY}
{KEY_PEM_CANARY}"
        );
        assert_eq!(
            requests[0].derived_identity.as_deref(),
            Some(expected_identity.as_str()),
            "the derived transport must carry the combined identity PEM"
        );
        assert_eq!(requests[0].derived_ca, None);
    }

    #[tokio::test]
    async fn rotated_client_identity_material_re_derives_and_invalidates_cached_values() {
        let fixture = provider_with_config(KubernetesProviderConfig {
            profiles: vec![client_certificate_profile("primary")],
            aliases: vec![alias("billing")],
        });
        fixture
            .bootstrap
            .set("tls-cert", CERT_PEM_CANARY.as_bytes());
        fixture.bootstrap.set("tls-key", KEY_PEM_CANARY.as_bytes());
        fixture
            .cluster
            .push_read(json_response(200, &secret_body(KEY_CANARY, "first-value")));
        let first = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("first read should resolve");
        assert_eq!(first.expose(), b"first-value");

        fixture.bootstrap.set(
            "tls-key",
            b"-----BEGIN PRIVATE KEY-----
rotated-key
-----END PRIVATE KEY-----
",
        );
        fixture
            .cluster
            .push_read(json_response(200, &secret_body(KEY_CANARY, "second-value")));

        let rotated = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("rotated identity material should re-derive the transport");

        assert_eq!(rotated.expose(), b"second-value");
        let requests = fixture.cluster.requests();
        assert_eq!(
            requests.len(),
            2,
            "rotation must invalidate the cached value without waiting for the TTL"
        );
        assert!(requests[1]
            .derived_identity
            .as_deref()
            .is_some_and(|identity| identity.contains("rotated-key")));
    }

    #[tokio::test]
    async fn missing_client_identity_material_fails_closed_before_any_request() {
        let fixture = provider_with_config(KubernetesProviderConfig {
            profiles: vec![client_certificate_profile("primary")],
            aliases: vec![alias("billing")],
        });
        // The private key disappears after startup: the alias is configured and
        // was resolvable when the provider was built, so this exercises the
        // runtime fail-closed path rather than the construction-time check.
        fixture.bootstrap.remove("tls-key");
        fixture
            .cluster
            .push_read(json_response(200, &secret_body(KEY_CANARY, VALUE_CANARY)));

        let error = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect_err("missing client identity material must fail closed");

        assert_eq!(error.kind(), SecretResolveErrorKind::InvalidMaterial);
        assert!(fixture.cluster.requests().is_empty());
        assert!(fixture.provider.value_guard().is_empty());
    }

    #[tokio::test]
    async fn a_401_under_mutual_tls_fails_closed_without_retry() {
        let fixture = provider_with_config(KubernetesProviderConfig {
            profiles: vec![client_certificate_profile("primary")],
            aliases: vec![alias("billing")],
        });
        fixture
            .bootstrap
            .set("tls-cert", CERT_PEM_CANARY.as_bytes());
        fixture.bootstrap.set("tls-key", KEY_PEM_CANARY.as_bytes());
        fixture.cluster.push_read(json_response(
            401,
            r#"{"kind":"Status","apiVersion":"v1","reason":"Unauthorized","code":401}"#,
        ));

        let error = fixture
            .provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect_err("a rejected client identity must fail closed");

        assert_eq!(error.kind(), SecretResolveErrorKind::SourceDenied);
        assert_eq!(
            fixture.cluster.requests().len(),
            1,
            "mutual TLS has no token re-read and must not retry"
        );
    }

    // Both read bounds are derived from published Kubernetes limits rather than
    // chosen round, and every other test spends them symbolically, so nothing
    // else would notice either constant being retuned. The next two tests pin
    // the derivations so a future edit has to redo the arithmetic. They are
    // deliberately separate: in one test the first panicking assertion would
    // mask the second bound entirely.
    #[test]
    fn the_response_cap_clears_a_maximal_secret_envelope() {
        // apimachinery `MaxSecretSize`, summed over decoded `data` values, and
        // `TotalAnnotationSizeLimitB`. `data` arrives Base64-encoded in JSON.
        const MAX_SECRET_DATA_BYTES: usize = 1024 * 1024;
        const MAX_ANNOTATION_BYTES: usize = 256 * 1024;
        let encoded_data = MAX_SECRET_DATA_BYTES.div_ceil(3) * 4;
        assert!(
            MAX_KUBERNETES_READ_RESPONSE_BYTES >= encoded_data + MAX_ANNOTATION_BYTES,
            "the response cap must admit a maximal Secret payload ({encoded_data} Base64 bytes) \
             plus a maximal annotation set ({MAX_ANNOTATION_BYTES} bytes), but it is \
             {MAX_KUBERNETES_READ_RESPONSE_BYTES}"
        );
    }

    #[test]
    fn cached_bearer_material_expires_inside_a_projected_tokens_residual_validity() {
        // The kubelet replaces a projected token once it passes 80% of its TTL
        // and Kubernetes rejects an `expirationSeconds` below 600, so the
        // least-fresh token a resolution can read retains 20% of 600s.
        const MIN_PROJECTED_TOKEN_TTL: Duration = Duration::from_secs(600);
        let residual_validity = MIN_PROJECTED_TOKEN_TTL - MIN_PROJECTED_TOKEN_TTL * 4 / 5;
        assert!(
            KUBERNETES_TOKEN_LIFETIME < residual_validity,
            "cached bearer material must expire before the least-fresh projected token could \
             ({residual_validity:?} of validity), but it is cached for \
             {KUBERNETES_TOKEN_LIFETIME:?}"
        );
    }

    #[test]
    fn the_transport_response_cap_is_clamped_into_the_derived_client() {
        let client = Arc::new(
            crate::egress::EgressClient::new(crate::egress::EgressConfig::default())
                .expect("egress client should build"),
        );
        let transport =
            EgressKubernetesTransport::bounded(&client).expect("bounded transport should build");
        assert_eq!(transport.response_cap(), MAX_KUBERNETES_READ_RESPONSE_BYTES);

        let tighter_config = crate::egress::EgressConfig {
            max_response_bytes: 1024,
            ..Default::default()
        };
        let tighter = Arc::new(
            crate::egress::EgressClient::new(tighter_config).expect("egress client should build"),
        );
        let transport =
            EgressKubernetesTransport::bounded(&tighter).expect("bounded transport should build");
        assert_eq!(
            transport.response_cap(),
            1024,
            "a tighter deployment bound must never be widened"
        );
    }

    #[tokio::test]
    async fn a_provider_without_a_bootstrap_resolver_rejects_bootstrap_profiles() {
        let cluster = FakeCluster::new();
        let error = KubernetesSecretProvider::from_config(
            &KubernetesProviderConfig {
                profiles: vec![bearer_profile("primary", "bootstrap-token")],
                aliases: vec![alias("billing")],
            },
            &BTreeSet::new(),
            FakeTransport::new(Arc::clone(&cluster)) as Arc<dyn KubernetesTransport>,
            None,
        )
        .expect_err("a bearer profile without a bootstrap resolver must fail");
        assert!(matches!(
            error,
            KubernetesProviderConfigError::BootstrapResolverRequired { .. }
        ));

        let mut ca_profile = projected_profile("primary", ".");
        ca_profile.ca_bundle_alias = Some("cluster-ca".to_owned());
        let error = KubernetesSecretProvider::from_config(
            &KubernetesProviderConfig {
                profiles: vec![ca_profile],
                aliases: vec![alias("billing")],
            },
            &BTreeSet::new(),
            FakeTransport::new(cluster) as Arc<dyn KubernetesTransport>,
            None,
        )
        .expect_err("a CA-bundle profile without a bootstrap resolver must fail");
        assert!(matches!(
            error,
            KubernetesProviderConfigError::BootstrapResolverRequired { .. }
        ));

        let cluster = FakeCluster::new();
        let error = KubernetesSecretProvider::from_config(
            &KubernetesProviderConfig {
                profiles: vec![client_certificate_profile("primary")],
                aliases: vec![alias("billing")],
            },
            &BTreeSet::new(),
            FakeTransport::new(cluster) as Arc<dyn KubernetesTransport>,
            None,
        )
        .expect_err("a client-certificate profile without a bootstrap resolver must fail");
        assert!(matches!(
            error,
            KubernetesProviderConfigError::BootstrapResolverRequired { .. }
        ));
    }

    #[tokio::test]
    async fn metadata_and_debug_output_never_expose_locators_tokens_or_values() {
        let fixture = provider(vec![alias("billing")]);
        fixture
            .cluster
            .push_read(json_response(200, &secret_body(KEY_CANARY, VALUE_CANARY)));
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
        let mut ca_profile = bearer_profile("primary", "bootstrap-token");
        ca_profile.ca_bundle_alias = Some("cluster-ca".to_owned());
        let mut projected_ca_profile =
            projected_profile("secondary", "/var/run/secrets/tokens-canary");
        projected_ca_profile.ca_bundle_root = Some("/var/run/secrets/ca-root-canary".to_owned());
        projected_ca_profile.ca_bundle_file = Some("ca-file-canary.crt".to_owned());
        let configuration = KubernetesProviderConfig {
            profiles: vec![ca_profile, projected_ca_profile],
            aliases: vec![alias("billing")],
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
            KubernetesFailure::ProviderDenied.safe_reason().to_owned(),
            KubernetesFailure::TrustInvalid.safe_reason().to_owned(),
            format!(
                "{}",
                KubernetesProviderConfigError::InvalidServer { index: 0 }
            ),
        ];
        for output in outputs {
            for canary in [
                VALUE_CANARY,
                TOKEN_CANARY,
                SERVER_CANARY,
                NAMESPACE_CANARY,
                NAME_CANARY,
                KEY_CANARY,
                "tokens-canary",
                "ca-root-canary",
                "ca-file-canary",
            ] {
                assert!(
                    !output.contains(canary),
                    "{canary} must not appear in {output}"
                );
            }
        }
        let metadata = fixture.provider.aliases();
        assert_eq!(metadata.len(), 1);
        assert_eq!(metadata[0].provider, SecretProviderKind::KubernetesSecrets);
        assert_eq!(metadata[0].version, None);
        assert!(!metadata[0].pinned);
        assert!(serde_json::to_string(&metadata)
            .expect("alias metadata should serialize")
            .contains("kubernetes_secrets"));
    }

    #[test]
    fn every_failure_maps_to_a_bounded_safe_reason() {
        for failure in [
            KubernetesFailure::UnknownAlias,
            KubernetesFailure::ProviderBusy,
            KubernetesFailure::DeadlineExceeded,
            KubernetesFailure::EgressDenied,
            KubernetesFailure::RedirectRefused,
            KubernetesFailure::TrustUnavailable,
            KubernetesFailure::TrustInvalid,
            KubernetesFailure::IdentityUnavailable,
            KubernetesFailure::IdentityDenied,
            KubernetesFailure::IdentityInvalid,
            KubernetesFailure::TokenRejected,
            KubernetesFailure::ProviderUnavailable,
            KubernetesFailure::ProviderDenied,
            KubernetesFailure::SecretAbsent,
            KubernetesFailure::InvalidResponse,
            KubernetesFailure::InvalidMaterial,
            KubernetesFailure::ProviderFailure,
        ] {
            let reason = failure.safe_reason();
            assert!(reason.len() <= 32);
            assert!(reason
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_'));
        }
    }

    #[tokio::test]
    async fn projected_tokens_are_read_from_a_pinned_root_and_observe_rotation() {
        let root = std::env::temp_dir().join(format!(
            "greengateway-kubernetes-projected-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir(&root).expect("projected root should create");
        set_directory_permissions(&root, 0o755);
        fs::write(root.join("token"), b"projected.jwt.canary").expect("token should write");
        set_file_permissions(&root.join("token"), 0o644);

        let cluster = FakeCluster::new();
        let clock = TestClock::new();
        let mut provider = KubernetesSecretProvider::from_config(
            &KubernetesProviderConfig {
                profiles: vec![projected_profile(
                    "primary",
                    root.to_str().expect("root path should be Unicode"),
                )],
                aliases: vec![alias("billing")],
            },
            &BTreeSet::new(),
            FakeTransport::new(Arc::clone(&cluster)) as Arc<dyn KubernetesTransport>,
            None,
        )
        .expect("projected provider should build");
        provider.clock = Arc::clone(&clock) as Arc<dyn KubernetesClock>;
        cluster.push_read(json_response(200, &secret_body(KEY_CANARY, VALUE_CANARY)));

        let secret = provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("projected identity read should resolve");
        assert_eq!(secret.expose(), VALUE_CANARY.as_bytes());
        assert_eq!(
            cluster.requests()[0].authorization.as_deref(),
            Some("Bearer projected.jwt.canary")
        );

        // Kubelet rotation is observed after the bounded token lifetime.
        fs::write(root.join("token"), b"projected.jwt.rotated").expect("token should rewrite");
        set_file_permissions(&root.join("token"), 0o644);
        cluster.push_read(json_response(200, &secret_body(KEY_CANARY, "second-value")));
        clock.advance(
            KUBERNETES_TOKEN_LIFETIME
                .max(KUBERNETES_VALUE_CACHE_TTL)
                .saturating_add(Duration::from_secs(1)),
        );

        let rotated = provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("rotated projected identity should resolve");
        assert_eq!(rotated.expose(), b"second-value");
        let requests = cluster.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(
            requests[1].authorization.as_deref(),
            Some("Bearer projected.jwt.rotated")
        );

        // A missing projected token fails closed without an anonymous request.
        fs::remove_file(root.join("token")).expect("token should remove");
        provider.invalidate_token("primary");
        provider.purge_alias("billing");
        let error = provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect_err("a missing projected token must fail closed");
        assert_eq!(error.kind(), SecretResolveErrorKind::SourceUnavailable);
        assert_eq!(cluster.requests().len(), 2);

        drop(provider);
        fs::remove_dir_all(&root).expect("projected root should remove");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_world_writable_projected_token_fails_closed() {
        let root = std::env::temp_dir().join(format!(
            "greengateway-kubernetes-projected-perms-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir(&root).expect("projected root should create");
        set_directory_permissions(&root, 0o755);
        fs::write(root.join("token"), b"escalated.jwt").expect("token should write");
        set_file_permissions(&root.join("token"), 0o666);

        let cluster = FakeCluster::new();
        let provider = KubernetesSecretProvider::from_config(
            &KubernetesProviderConfig {
                profiles: vec![projected_profile(
                    "primary",
                    root.to_str().expect("root path should be Unicode"),
                )],
                aliases: vec![alias("billing")],
            },
            &BTreeSet::new(),
            FakeTransport::new(Arc::clone(&cluster)) as Arc<dyn KubernetesTransport>,
            None,
        )
        .expect("projected provider should build");
        cluster.push_read(json_response(200, &secret_body(KEY_CANARY, VALUE_CANARY)));

        let error = provider
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect_err("a world-writable identity token must fail closed");
        assert_eq!(error.kind(), SecretResolveErrorKind::SourceDenied);
        assert!(cluster.requests().is_empty());

        drop(provider);
        fs::remove_dir_all(&root).expect("projected root should remove");
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
}
