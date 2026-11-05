//! The Google Secret Manager provider's configuration document
//! (`CONNECTION_GCP_PROVIDER`) and its validator.
//!
//! Validation is a function of the document alone: it opens no file, resolves
//! no name and contacts no provider. The provider the gateway builds from a
//! validated document, and every check that needs the world, stay in the
//! gateway's `connections::gcp_secret`, which re-exports these.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
};

use serde::Deserialize;

use super::{
    secret::is_valid_file_key, MAX_CREDENTIALS, MAX_DISPLAY_NAME_CHARS, MAX_SECRET_ID_BYTES,
};
use crate::opaque_id::is_valid_opaque_id;

pub const MAX_GCP_PROFILES: usize = 8;
pub const MAX_GCP_SECRET_ALIASES: usize = MAX_CREDENTIALS;
pub const MAX_GCP_PROVIDER_CONFIG_BYTES: usize = 256 * 1024;
const MAX_GCP_AUDIENCE_BYTES: usize = 512;
const MAX_GCP_TOKEN_ROOT_BYTES: usize = 512;
const MAX_GCP_SERVICE_ACCOUNT_BYTES: usize = 256;
const MAX_GCP_PROJECT_BYTES: usize = 30;
const MIN_GCP_PROJECT_ID_BYTES: usize = 6;
const MAX_GCP_LOCATION_BYTES: usize = 32;
const MAX_GCP_SECRET_ID_BYTES: usize = 255;
const MIN_GCP_POOL_COMPONENT_BYTES: usize = 4;
const MAX_GCP_POOL_COMPONENT_BYTES: usize = 32;
const GCP_AUDIENCE_PREFIX: &str = "//iam.googleapis.com/projects/";
const GCP_SERVICE_ACCOUNT_DOMAIN_SUFFIX: &str = ".iam.gserviceaccount.com";
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
        if !is_valid_file_key(&profile.token_file) {
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

pub fn is_gcp_project_number(value: &str) -> bool {
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

/// Google's rule for a workload identity pool or provider ID: 4-32 bytes drawn
/// from `[a-z0-9-]`, starting and ending with an *alphanumeric* character. The
/// leading byte is deliberately not narrowed to a letter, unlike the project
/// ID, location, and service-account ID rules beside it: Google admits
/// digit-leading pool and provider IDs, so refusing them would reject a valid
/// audience at startup under an error that says the audience is malformed when
/// it is not. Nothing is protected by the stricter reading — a pool component
/// never reaches a URL, only the STS request body, where `serde_json` escapes
/// it, and [`is_valid_gcp_audience`] destructures the resource by fixed
/// position, so a digit-leading pool cannot be confused with the project-number
/// segment.
fn is_valid_gcp_pool_component(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= MIN_GCP_POOL_COMPONENT_BYTES
        && bytes.len() <= MAX_GCP_POOL_COMPONENT_BYTES
        && is_gcp_lower_alphanumeric(bytes[0])
        && bytes
            .last()
            .is_some_and(|byte| is_gcp_lower_alphanumeric(*byte))
        && bytes
            .iter()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-'))
}

/// Google's rule for the local part of a service-account email is 6-30 bytes
/// matching `[a-z]([-a-z0-9]*[a-z0-9])`. The leading-letter and trailing-
/// alphanumeric constraints are kept exactly, because unlike a pool component
/// this value is interpolated into the fixed `generateAccessToken` URL path.
/// The length window stays at this provider's wider 4-32 bytes rather than
/// narrowing to Google's 6-30: an account outside that window cannot exist, so
/// the only configuration the narrower bound would newly reject is one whose
/// impersonation exchange already fails closed, and narrowing validation on a
/// field an operator may already have set buys nothing for that.
fn is_valid_gcp_service_account_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= MIN_GCP_POOL_COMPONENT_BYTES
        && bytes.len() <= MAX_GCP_POOL_COMPONENT_BYTES
        && bytes[0].is_ascii_lowercase()
        && bytes
            .last()
            .is_some_and(|byte| is_gcp_lower_alphanumeric(*byte))
        && bytes
            .iter()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-'))
}

const fn is_gcp_lower_alphanumeric(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit()
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
pub fn is_valid_gcp_service_account(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_GCP_SERVICE_ACCOUNT_BYTES || !value.is_ascii() {
        return false;
    }
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    let Some(project) = domain.strip_suffix(GCP_SERVICE_ACCOUNT_DOMAIN_SUFFIX) else {
        return false;
    };
    is_valid_gcp_service_account_id(local) && is_gcp_project_id(project)
}

#[cfg(test)]
mod tests {
    use super::*;

    const AUDIENCE_CANARY: &str = "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/pool-locator-canary/providers/provider-locator-canary";
    const PROJECT_CANARY: &str = "project-locator-canary";
    const SECRET_CANARY: &str = "secret-locator-canary";
    const SERVICE_ACCOUNT_CANARY: &str =
        "impersonation-canary@project-locator-canary.iam.gserviceaccount.com";

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

    /// Pool and provider IDs follow Google's rule (4-32 bytes of `[a-z0-9-]`
    /// starting and ending with an alphanumeric); the service-account local
    /// part keeps Google's stricter leading-letter rule because it reaches a
    /// URL path. The two are validated separately and must not drift together.
    #[test]
    fn pool_components_admit_digits_where_google_does_and_service_accounts_do_not() {
        let root = "/var/run/secrets/tokens";
        let with_audience = |audience: &str| {
            let mut entry = profile("primary", root, None);
            entry.audience = audience.to_owned();
            validate_gcp_provider_config(
                &GcpProviderConfig {
                    profiles: vec![entry],
                    aliases: Vec::new(),
                },
                &BTreeSet::new(),
            )
        };
        for audience in [
            "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/2024-prod-pool/providers/provider-name",
            "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/pool-name/providers/9-provider",
            "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/0pool/providers/0000",
        ] {
            assert_eq!(
                with_audience(audience),
                Ok(()),
                "{audience:?} is a valid Google audience and must be accepted"
            );
        }
        for audience in [
            "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/-pool-name/providers/provider-name",
            "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/pool-name-/providers/provider-name",
            "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/abc/providers/provider-name",
            "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/pool_name/providers/provider-name",
        ] {
            assert_eq!(
                with_audience(audience),
                Err(GcpProviderConfigError::InvalidAudience { index: 0 }),
                "{audience:?} must still be rejected as an invalid audience"
            );
        }

        let with_account = |account: &str| {
            let mut entry = profile("primary", root, None);
            entry.service_account = Some(account.to_owned());
            validate_gcp_provider_config(
                &GcpProviderConfig {
                    profiles: vec![entry],
                    aliases: Vec::new(),
                },
                &BTreeSet::new(),
            )
        };
        assert_eq!(
            with_account(SERVICE_ACCOUNT_CANARY),
            Ok(()),
            "a dedicated service account must still be accepted"
        );
        for account in [
            "9sa-canary@project-locator-canary.iam.gserviceaccount.com",
            "0000@project-locator-canary.iam.gserviceaccount.com",
        ] {
            assert_eq!(
                with_account(account),
                Err(GcpProviderConfigError::InvalidServiceAccount { index: 0 }),
                "{account:?} must be rejected: a service-account ID starts with a letter"
            );
        }
    }
}
