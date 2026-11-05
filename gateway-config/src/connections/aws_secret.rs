//! The AWS Secrets Manager provider's configuration document
//! (`CONNECTION_AWS_PROVIDER`) and its validator.
//!
//! Validation is a function of the document alone: it opens no file, resolves
//! no name and contacts no provider. The provider the gateway builds from a
//! validated document, and every check that needs the world, stay in the
//! gateway's `connections::aws_secret`, which re-exports these.

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

pub const MAX_AWS_PROFILES: usize = 8;
pub const MAX_AWS_SECRET_ALIASES: usize = MAX_CREDENTIALS;
pub const MAX_AWS_PROVIDER_CONFIG_BYTES: usize = 256 * 1024;
const MAX_AWS_ENDPOINT_BYTES: usize = 512;
const MAX_AWS_ARN_BYTES: usize = 2048;
const MAX_AWS_ROLE_ARN_BYTES: usize = 2048;
const MAX_AWS_VERSION_STAGE_BYTES: usize = 256;
const MAX_AWS_JSON_MEMBER_BYTES: usize = 128;
const MAX_AWS_TOKEN_ROOT_BYTES: usize = 512;
const AWS_PREVIOUS_STAGE: &str = "AWSPREVIOUS";
const AWS_COMMERCIAL_PARTITION: &str = "aws";
const AWS_GOV_PARTITION: &str = "aws-us-gov";
const AWS_ENDPOINT_SUFFIX: &str = "amazonaws.com";
const REDACTED_LOCATOR: &str = "<redacted-locator>";

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

/// One region-independent AWS identity: an auth mode plus, for `web_identity`,
/// the explicit STS endpoint that identity requests may contact. Nothing about
/// the profile is derived from a request, an SDK default chain, or an instance
/// metadata service.
///
/// `sts_endpoint` is optional because only `web_identity` ever contacts STS;
/// `static_keys` signs directly with its bootstrap key pair and issues no STS
/// request at all. Requiring it in both modes made every `static_keys` operator
/// invent a URL the gateway would never dial, which teaches that the field is
/// decorative and hides the day it starts mattering. It stays at the profile
/// level rather than moving into the `web_identity` variant because
/// `deny_unknown_fields` would turn that move into a hard startup failure for
/// every profile already deployed under either mode; a value supplied by such a
/// profile is still shape-validated, and is then ignored under `static_keys`.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AwsProfileConfig {
    pub id: String,
    #[serde(default)]
    pub sts_endpoint: Option<String>,
    pub auth: AwsAuthConfig,
}

impl fmt::Debug for AwsProfileConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsProfileConfig")
            .field("id", &self.id)
            .field(
                "sts_endpoint",
                &self.sts_endpoint.as_ref().map(|_| REDACTED_LOCATOR),
            )
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
    TooManyProfiles {
        maximum: usize,
    },
    TooManyAliases {
        maximum: usize,
    },
    InvalidProfileId {
        index: usize,
    },
    DuplicateProfileId {
        index: usize,
        previous: usize,
    },
    InvalidStsEndpoint {
        index: usize,
    },
    StsEndpointRequired {
        index: usize,
    },
    InvalidRoleArn {
        index: usize,
    },
    InvalidWorkloadTokenRoot {
        index: usize,
    },
    InvalidWorkloadTokenFile {
        index: usize,
    },
    WorkloadTokenRootUnavailable {
        index: usize,
    },
    WorkloadTokenRootPermissions {
        index: usize,
    },
    InvalidBootstrapAlias {
        index: usize,
    },
    BootstrapAliasCycle {
        index: usize,
    },
    BootstrapResolverRequired {
        index: usize,
    },
    UnknownBootstrapAlias {
        index: usize,
    },
    InvalidAliasId {
        index: usize,
    },
    InvalidLabel {
        index: usize,
    },
    DuplicateAliasId {
        index: usize,
        previous: usize,
    },
    ReservedAliasId {
        index: usize,
    },
    UnknownProfile {
        index: usize,
    },
    InvalidSecretArn {
        index: usize,
    },
    AmbiguousVersionSelection {
        index: usize,
    },
    InvalidVersionId {
        index: usize,
    },
    InvalidVersionStage {
        index: usize,
    },
    ForbiddenVersionStage {
        index: usize,
    },
    InvalidJsonMember {
        index: usize,
    },
    CrossPartitionAlias {
        index: usize,
        alias_partition: &'static str,
        profile: usize,
        profile_partition: &'static str,
    },
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
            Self::StsEndpointRequired { index } => write!(
                formatter,
                "aws profile at index {index} authenticates with web_identity and must configure an sts_endpoint"
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
            Self::CrossPartitionAlias {
                index,
                alias_partition,
                profile,
                profile_partition,
            } => write!(
                formatter,
                "aws alias at index {index} names an {alias_partition} secret but its profile at index {profile} obtains credentials from an {profile_partition} STS endpoint"
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
    // Only for profiles whose STS endpoint states a partition; see
    // `sts_endpoint_partition`.
    let mut profile_partitions: BTreeMap<&str, (usize, &'static str)> = BTreeMap::new();
    for (index, profile) in config.profiles.iter().enumerate() {
        if !is_valid_opaque_id(&profile.id, MAX_SECRET_ID_BYTES) {
            return Err(AwsProviderConfigError::InvalidProfileId { index });
        }
        if let Some(previous) = profile_ids.insert(profile.id.as_str(), index) {
            return Err(AwsProviderConfigError::DuplicateProfileId { index, previous });
        }
        // A supplied endpoint is shape-checked in both modes, so a `static_keys`
        // profile still carrying one from an earlier release neither starts with
        // a malformed URL nor fails to start at all.
        if profile
            .sts_endpoint
            .as_deref()
            .is_some_and(|endpoint| !is_valid_https_endpoint(endpoint))
        {
            return Err(AwsProviderConfigError::InvalidStsEndpoint { index });
        }
        match &profile.auth {
            AwsAuthConfig::WebIdentity {
                role_arn,
                token_root,
                token_file,
            } => {
                let Some(endpoint) = profile.sts_endpoint.as_deref() else {
                    return Err(AwsProviderConfigError::StsEndpointRequired { index });
                };
                // Recorded for `web_identity` only. It is the sole mode that
                // dials STS, so it is the sole mode where the endpoint decides
                // which partition the resulting session credentials belong to.
                // A `static_keys` profile signs with a bootstrap key pair whose
                // partition this configuration never states, and any endpoint it
                // still carries is never contacted, so there is nothing to bind.
                if let Some(partition) = sts_endpoint_partition(endpoint) {
                    profile_partitions.insert(profile.id.as_str(), (index, partition));
                }
                if !is_valid_role_arn(role_arn) {
                    return Err(AwsProviderConfigError::InvalidRoleArn { index });
                }
                if token_root.is_empty() || token_root.len() > MAX_AWS_TOKEN_ROOT_BYTES {
                    return Err(AwsProviderConfigError::InvalidWorkloadTokenRoot { index });
                }
                if !is_valid_file_key(token_file) {
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
        let Some(region) = parse_secret_arn(&alias.arn) else {
            return Err(AwsProviderConfigError::InvalidSecretArn { index });
        };
        // `partition_matches_region` stops one *locator* naming a partition its
        // host does not belong to. This stops the strictly worse thing: one
        // partition's live *credential* being sent to another partition's host.
        //
        // The alias endpoint is derived from the alias region alone, and the
        // session credentials are minted at whatever endpoint the profile names,
        // so nothing else relates the two. Left unchecked, a `web_identity`
        // profile pointed at commercial STS could serve a GovCloud alias, and
        // every read would SigV4-sign commercial session credentials -- the
        // access key and the `x-amz-security-token` bearer with it -- to
        // `secretsmanager.us-gov-west-1.amazonaws.com`.
        //
        // This is a narrowing, and it only rejects configurations that were
        // already broken. The partitions are separate trust domains with
        // separate IAM: a commercial session principal does not exist in
        // GovCloud, so GovCloud rejects the credential outright rather than
        // authorizing anything, and the reverse holds too. That failure is
        // permanent, not transient -- the profile mints another credential in
        // the same partition on every refresh -- so a rejected pairing could
        // only ever have failed on every request for the life of the process.
        // Refusing it at startup names the misconfiguration instead of burying
        // it in a per-request authentication error.
        if let Some((profile, profile_partition)) = profile_partitions.get(alias.profile.as_str()) {
            let alias_partition = partition_for_region(region);
            if alias_partition != *profile_partition {
                return Err(AwsProviderConfigError::CrossPartitionAlias {
                    index,
                    alias_partition,
                    profile: *profile,
                    profile_partition,
                });
            }
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
            // Refusing an explicit `AWSPREVIOUS` pin goes further than the rule
            // against *falling back* to it, deliberately. `AWSPREVIOUS` is a
            // label AWS moves at every rotation, so pinning it never names a
            // version: it stands for "whatever this secret was superseded by
            // last", which makes the alias a standing read of material the
            // rotation process has already retired and silently changes which
            // value it serves each time the secret rotates. The one legitimate
            // use of that stage is a dual-credential grace window during
            // rotation, and this provider serves exactly one value per alias, so
            // it has no such mode. Rolling back a bad rotation is still
            // supported by pinning that version's `version_id`, which is a fixed
            // selector rather than a moving pointer at whatever is currently
            // stale.
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
/// Accepted partitions are `aws` and `aws-us-gov`, the partitions whose regional
/// Secrets Manager endpoint is deterministically
/// `secretsmanager.<region>.amazonaws.com`. GovCloud stays in scope because it
/// satisfies that formula exactly; `aws-cn` is refused because its endpoints
/// live under `amazonaws.com.cn`, so admitting it would send a China-partition
/// locator to whatever commercial host the formula happens to spell.
///
/// The partition must also agree with the region, because the host is derived
/// from the region alone: the ARN travels on the wire as the `SecretId`, but its
/// partition constrains nothing about where the request is sent. Without that
/// check, a GovCloud ARN carrying a commercial region would egress a GovCloud
/// locator to commercial AWS. Such a pair is an ARN AWS never issues, so it can
/// only ever have failed at the provider or at the response ARN binding;
/// rejecting it here turns a permanent per-request failure into a startup
/// error.
pub fn parse_secret_arn(value: &str) -> Option<&str> {
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
        && partition_matches_region(partition, region)
        && account.len() == 12
        && account.bytes().all(|byte| byte.is_ascii_digit())
        && resource_kind == "secret"
        && !name.is_empty()
        && name.bytes().all(is_valid_secret_name_byte)
        && has_full_arn_suffix(name))
    .then_some(region)
}

/// `aws-us-gov` owns exactly the `us-gov-` regions, and `aws` owns none of
/// them, so a region names its partition outright.
fn partition_for_region(region: &str) -> &'static str {
    if region.starts_with("us-gov-") {
        AWS_GOV_PARTITION
    } else {
        AWS_COMMERCIAL_PARTITION
    }
}

/// Whether a secret ARN's stated partition agrees with the region its endpoint
/// is derived from.
///
/// This applies to secret ARNs only. A role ARN carries no region (IAM is
/// global) and its partition derives no host either, because the STS endpoint a
/// role is assumed at is configured explicitly rather than computed, so there is
/// nothing for the same check to protect there.
fn partition_matches_region(partition: &str, region: &str) -> bool {
    partition_for_region(region) == partition
}

/// The partition a configured STS endpoint issues credentials in, when its host
/// states one.
///
/// AWS owns `amazonaws.com`, and every GovCloud service endpoint carries its
/// region in the host because GovCloud publishes no regionless endpoint. So a
/// host under that suffix either names a `us-gov-` region, and is GovCloud, or
/// names none, and is commercial. Any region-shaped label is examined, not just
/// the leftmost, because an interface VPC endpoint prefixes the host with a
/// `vpce-<id>` label that is itself region-shaped.
///
/// A host outside `amazonaws.com` states nothing: it is a private endpoint, a
/// corporate CNAME, or a test double, and which partition it fronts is not
/// knowable from the name. Those are deliberately left unconstrained. The point
/// of the check below is to refuse a pairing that provably cannot work, and
/// guessing a partition for an opaque host would instead refuse deployments
/// that do.
fn sts_endpoint_partition(endpoint: &str) -> Option<&'static str> {
    let url = Url::parse(endpoint).ok()?;
    let host = url.host_str()?.trim_end_matches('.');
    if host != AWS_ENDPOINT_SUFFIX
        && !host
            .strip_suffix(AWS_ENDPOINT_SUFFIX)
            .is_some_and(|parent| parent.ends_with('.'))
    {
        return None;
    }
    if host
        .split('.')
        .any(|label| label.starts_with("us-gov-") && is_valid_aws_region(label))
    {
        return Some(AWS_GOV_PARTITION);
    }
    Some(AWS_COMMERCIAL_PARTITION)
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

#[cfg(test)]
mod tests {
    use super::*;

    const STS_ENDPOINT_CANARY: &str = "https://sts.locator-canary.example";
    const COMMERCIAL_STS_ENDPOINT: &str = "https://sts.us-east-1.amazonaws.com";
    const GOV_STS_ENDPOINT: &str = "https://sts.us-gov-west-1.amazonaws.com";
    const ARN_CANARY: &str =
        "arn:aws:secretsmanager:us-east-1:123456789012:secret:team-canary/billing-canary-AbC123";
    const GOV_ARN_CANARY: &str =
        "arn:aws-us-gov:secretsmanager:us-gov-west-1:123456789012:secret:team-canary/billing-canary-AbC123";
    const ROLE_ARN_CANARY: &str = "arn:aws:iam::123456789012:role/greengateway-role-canary";
    const VERSION_ID_CANARY: &str = "12345678-1234-1234-1234-123456789012";

    fn static_profile(id: &str) -> AwsProfileConfig {
        AwsProfileConfig {
            id: id.to_owned(),
            // static_keys never dials STS, so the default fixture omits the
            // endpoint entirely; every static-key test below therefore exercises
            // the shape an operator can now actually write.
            sts_endpoint: None,
            auth: AwsAuthConfig::StaticKeys {
                access_key_id_alias: "bootstrap-access-key-id".to_owned(),
                secret_access_key_alias: "bootstrap-secret-access-key".to_owned(),
            },
        }
    }

    fn web_identity_profile(id: &str, token_root: &str) -> AwsProfileConfig {
        AwsProfileConfig {
            id: id.to_owned(),
            sts_endpoint: Some(STS_ENDPOINT_CANARY.to_owned()),
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
            profile.sts_endpoint = Some(endpoint.to_owned());
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
            // A partition that disagrees with its region is an ARN AWS never
            // issues, and the endpoint is derived from the region alone.
            "arn:aws-us-gov:secretsmanager:us-east-1:123456789012:secret:team/billing-AbC123",
            "arn:aws:secretsmanager:us-gov-west-1:123456789012:secret:team/billing-AbC123",
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
        // Keep the endpoint set: without it the web_identity requirement below
        // would reject this profile first and the role-ARN check would never run.
        bad_role.sts_endpoint = Some(STS_ENDPOINT_CANARY.to_owned());
        bad_role.auth = AwsAuthConfig::WebIdentity {
            role_arn: "arn:aws:iam::123456789012:user/not-a-role".to_owned(),
            token_root: "/var/run/secrets/tokens".to_owned(),
            token_file: "token".to_owned(),
        };
        assert!(matches!(
            base(vec![bad_role], Vec::new()),
            Err(AwsProviderConfigError::InvalidRoleArn { .. })
        ));
        let mut missing_endpoint = web_identity_profile("primary", "/var/run/secrets/tokens");
        missing_endpoint.sts_endpoint = None;
        let outcome = base(vec![missing_endpoint], Vec::new());
        assert!(
            matches!(
                outcome,
                Err(AwsProviderConfigError::StsEndpointRequired { .. })
            ),
            "web_identity without an sts_endpoint must be refused, got {outcome:?}"
        );
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

    /// A locator that names the wrong partition is a bad address;
    /// `partition_matches_region` already refuses that. Binding an alias to a
    /// profile in the *other* partition is worse: the address is right, and what
    /// crosses the boundary is a live credential.
    #[test]
    fn a_profile_and_the_aliases_bound_to_it_must_share_a_partition() {
        let config = |endpoint: Option<&str>, arn: &str, web_identity: bool| {
            let mut profile = if web_identity {
                web_identity_profile("primary", "/var/run/secrets/tokens")
            } else {
                static_profile("primary")
            };
            profile.sts_endpoint = endpoint.map(str::to_owned);
            let mut entry = alias("billing");
            entry.arn = arn.to_owned();
            validate_aws_provider_config(
                &AwsProviderConfig {
                    profiles: vec![profile],
                    aliases: vec![entry],
                },
                &BTreeSet::new(),
            )
        };

        // Commercial STS session credentials signed to a GovCloud host, and the
        // reverse. Both name the alias index and both partitions.
        for (endpoint, arn, alias_partition, profile_partition) in [
            (COMMERCIAL_STS_ENDPOINT, GOV_ARN_CANARY, "aws-us-gov", "aws"),
            (GOV_STS_ENDPOINT, ARN_CANARY, "aws", "aws-us-gov"),
        ] {
            let outcome = config(Some(endpoint), arn, true);
            assert!(
                matches!(
                    outcome,
                    Err(AwsProviderConfigError::CrossPartitionAlias {
                        index: 0,
                        alias_partition: found_alias,
                        profile: 0,
                        profile_partition: found_profile,
                    }) if found_alias == alias_partition && found_profile == profile_partition
                ),
                "{endpoint} paired with {arn} must be refused as cross-partition, got {outcome:?}"
            );
        }

        // The same fixtures with the partitions aligned must validate, or the
        // rejections above would prove nothing about the partition pair.
        for (endpoint, arn) in [
            (COMMERCIAL_STS_ENDPOINT, ARN_CANARY),
            (GOV_STS_ENDPOINT, GOV_ARN_CANARY),
        ] {
            let outcome = config(Some(endpoint), arn, true);
            assert!(
                outcome.is_ok(),
                "{endpoint} paired with {arn} is a partition-consistent deployment, got {outcome:?}"
            );
        }

        // A GovCloud interface VPC endpoint prefixes the host with a `vpce-<id>`
        // label that is itself region-shaped. Reading the leftmost region-shaped
        // label would call this commercial and refuse a working deployment.
        let outcome = config(
            Some("https://vpce-0a1b2c3d4e5f01234.sts.us-gov-west-1.vpce.amazonaws.com"),
            GOV_ARN_CANARY,
            true,
        );
        assert!(
            outcome.is_ok(),
            "a GovCloud interface endpoint must not be read as commercial, got {outcome:?}"
        );

        // A host outside `amazonaws.com` states no partition, so it constrains
        // nothing rather than being guessed at.
        let outcome = config(Some(STS_ENDPOINT_CANARY), GOV_ARN_CANARY, true);
        assert!(
            outcome.is_ok(),
            "an opaque STS host must not be assigned a partition, got {outcome:?}"
        );

        // `static_keys` never dials STS, so an endpoint it still carries decides
        // nothing about which partition its bootstrap key pair belongs to.
        let outcome = config(Some(COMMERCIAL_STS_ENDPOINT), GOV_ARN_CANARY, false);
        assert!(
            outcome.is_ok(),
            "a legacy static_keys endpoint must not bind a partition, got {outcome:?}"
        );

        // The role ARN is deliberately left alone: IAM is global, the role ARN
        // carries no region, and the endpoint a role is assumed at is configured
        // rather than derived from it. `web_identity_profile` supplies a
        // commercial role ARN, so the GovCloud pairing above already relies on
        // this; assert it rather than leaving it to be rediscovered.
        assert!(ROLE_ARN_CANARY.starts_with("arn:aws:iam::"));
        assert_eq!(
            sts_endpoint_partition(GOV_STS_ENDPOINT),
            Some("aws-us-gov"),
            "the GovCloud pairing must pass on the endpoint, not on the role ARN"
        );
    }

    #[test]
    fn an_sts_endpoint_is_required_only_by_the_mode_that_dials_sts() {
        let base = |profiles: Vec<AwsProfileConfig>| {
            validate_aws_provider_config(
                &AwsProviderConfig {
                    profiles,
                    aliases: Vec::new(),
                },
                &BTreeSet::new(),
            )
        };

        // static_keys signs directly with its bootstrap key pair, so it must not
        // be made to invent an endpoint the gateway will never dial.
        let mut omitted = static_profile("primary");
        omitted.sts_endpoint = None;
        assert!(base(vec![omitted]).is_ok());

        // A profile written before the field became optional keeps working, and
        // the value it carries is still shape-checked rather than waved through.
        let mut legacy = static_profile("primary");
        legacy.sts_endpoint = Some(STS_ENDPOINT_CANARY.to_owned());
        assert!(base(vec![legacy]).is_ok());
        let mut legacy_malformed = static_profile("primary");
        legacy_malformed.sts_endpoint = Some("http://sts.amazonaws.com".to_owned());
        let outcome = base(vec![legacy_malformed]);
        assert!(
            matches!(
                outcome,
                Err(AwsProviderConfigError::InvalidStsEndpoint { .. })
            ),
            "a supplied endpoint stays shape-checked under static_keys, got {outcome:?}"
        );

        // web_identity is the only mode that reaches STS, so there it is
        // required rather than merely validated when present.
        let mut missing = web_identity_profile("primary", "/var/run/secrets/tokens");
        missing.sts_endpoint = None;
        let outcome = base(vec![missing]);
        assert!(
            matches!(
                outcome,
                Err(AwsProviderConfigError::StsEndpointRequired { .. })
            ),
            "web_identity without an sts_endpoint must be refused, got {outcome:?}"
        );

        // The profile shape is an operator contract under `deny_unknown_fields`:
        // both already-deployed shapes must still deserialize, which is what
        // rules out moving the field into the `web_identity` variant.
        let deployed = r#"{"profiles":[{"id":"legacy-static","sts_endpoint":"https://sts.us-east-1.amazonaws.com","auth":{"type":"static_keys","access_key_id_alias":"a","secret_access_key_alias":"b"}},{"id":"legacy-web","sts_endpoint":"https://sts.us-east-1.amazonaws.com","auth":{"type":"web_identity","role_arn":"arn:aws:iam::123456789012:role/reader","token_root":"/var/run/secrets/tokens","token_file":"token"}}],"aliases":[]}"#;
        let parsed: AwsProviderConfig = serde_json::from_str(deployed)
            .expect("both already-deployed profile shapes must still parse");
        assert_eq!(parsed.profiles.len(), 2);
        assert!(parsed
            .profiles
            .iter()
            .all(|profile| profile.sts_endpoint.is_some()));
    }
}
