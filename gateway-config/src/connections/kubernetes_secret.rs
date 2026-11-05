//! The Kubernetes Secrets provider's configuration document
//! (`CONNECTION_KUBERNETES_PROVIDER`) and its validator.
//!
//! Validation is a function of the document alone: it opens no file, resolves
//! no name and contacts no provider. The provider the gateway builds from a
//! validated document, and every check that needs the world, stay in the
//! gateway's `connections::kubernetes_secret`, which re-exports these.

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

pub const MAX_KUBERNETES_PROFILES: usize = 8;
pub const MAX_KUBERNETES_SECRET_ALIASES: usize = MAX_CREDENTIALS;
pub const MAX_KUBERNETES_PROVIDER_CONFIG_BYTES: usize = 256 * 1024;
const MAX_KUBERNETES_SERVER_BYTES: usize = 512;
const MAX_KUBERNETES_TOKEN_ROOT_BYTES: usize = 512;
/// RFC 1123 DNS label bound: Kubernetes namespaces.
const MAX_DNS1123_LABEL_BYTES: usize = 63;
/// RFC 1123 DNS subdomain bound: Kubernetes Secret names.
const MAX_DNS1123_SUBDOMAIN_BYTES: usize = 253;
/// Kubernetes `data` key bound (apimachinery `IsConfigMapKey`).
const MAX_KUBERNETES_DATA_KEY_BYTES: usize = 253;
const REDACTED_LOCATOR: &str = "<redacted-locator>";

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
            if !is_valid_file_key(ca_file) {
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
                if !is_valid_file_key(token_file) {
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

#[cfg(test)]
mod tests {
    use super::*;

    const SERVER_CANARY: &str = "https://kubernetes-locator-canary.internal.example:6443";
    const NAMESPACE_CANARY: &str = "namespace-locator-canary";
    const NAME_CANARY: &str = "secret-name-locator-canary";
    const KEY_CANARY: &str = "data-key-locator-canary";

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
}
