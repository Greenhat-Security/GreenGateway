use std::{
    collections::BTreeMap,
    env,
    error::Error,
    fmt,
    fs::{self, File},
    io::{self, Read},
    path::{Path, PathBuf},
    sync::Arc,
};

use async_trait::async_trait;
use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt as _, OpenOptionsSyncExt as _};
use cap_std::{
    ambient_authority,
    fs::{Dir, OpenOptions as CapabilityOpenOptions},
};
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

use super::model::{MAX_CREDENTIALS, MAX_DISPLAY_NAME_CHARS, MAX_SECRET_ID_BYTES};

pub const MAX_HTTP_CREDENTIAL_BYTES: usize = 8 * 1024;
pub const MAX_TLS_PRIVATE_KEY_BYTES: usize = 256 * 1024;
pub const MAX_TLS_CERTIFICATE_BYTES: usize = 1024 * 1024;
pub const MAX_OPERATOR_SECRET_ALIASES: usize = MAX_CREDENTIALS;
pub const MAX_OPERATOR_SECRET_ALIAS_CONFIG_BYTES: usize = 256 * 1024;
pub const MAX_CONCURRENT_SECRET_RESOLUTIONS: usize = 16;
const MAX_ENVIRONMENT_KEY_BYTES: usize = 128;
const MAX_FILE_KEY_BYTES: usize = 255;
#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

/// Permission policy applied to a bounded on-disk secret read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FileSecretPermissions {
    /// Operator-provisioned material that must grant no group or other
    /// permission at all.
    Exclusive,
    /// Platform-projected workload identity material that the container runtime
    /// publishes world readable, such as a Kubernetes projected service-account
    /// token. Group and other *write* permissions remain rejected. The kubelet
    /// atomic writer publishes each projected file as a relative symlink into a
    /// timestamped `..data` directory, so the leaf may be a symlink; resolution
    /// stays confined beneath the capability root and the opened handle must
    /// still be a regular file.
    PlatformProjected,
}

#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorSecretAliasConfig {
    pub id: String,
    pub label: String,
    pub source: OperatorSecretAliasSource,
}

impl fmt::Debug for OperatorSecretAliasConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OperatorSecretAliasConfig")
            .field("id", &self.id)
            .field("label", &self.label)
            .field("source", &self.source)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum OperatorSecretAliasSource {
    Environment { key: String },
    File { key: String },
}

impl fmt::Debug for OperatorSecretAliasSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Environment { .. } => formatter
                .debug_struct("Environment")
                .field("key", &"<redacted-locator>")
                .finish(),
            Self::File { .. } => formatter
                .debug_struct("File")
                .field("key", &"<redacted-locator>")
                .finish(),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct SecretRootConfig(PathBuf);

impl SecretRootConfig {
    pub fn new(path: PathBuf) -> Self {
        Self(path)
    }

    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

impl fmt::Debug for SecretRootConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted-locator>")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretProviderKind {
    OperatorEnvironment,
    OperatorFile,
    LocalEncrypted,
    VaultKvV2,
    GcpSecretManager,
    AzureKeyVault,
    AwsSecretsManager,
    KubernetesSecrets,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SecretAliasMetadata {
    pub id: String,
    pub label: String,
    pub provider: SecretProviderKind,
    pub configured: bool,
    #[serde(skip_serializing)]
    pub purpose: Option<SecretPurpose>,
    /// Whether resolution is bound to an immutable version and will not observe
    /// upstream rotation. A movable selector — Vault/GCP `latest`, an AWS
    /// version stage — reports `false`, because the operationally load-bearing
    /// question is "will the gateway pick up a rotation?".
    pub pinned: bool,
    /// Numeric only, and deliberately so. Azure and AWS version identifiers are
    /// opaque strings and Kubernetes has no version concept, so those three
    /// providers report `None` here and answer the operationally load-bearing
    /// question through `pinned` instead. Widening this to a string was weighed
    /// and rejected in issue #286: the shipped admin UI rejects the entire
    /// metadata response unless `version` is a non-negative integer, then does
    /// arithmetic on it to confirm an encrypted-local rotation, and a type
    /// change to a published `connection-admin.v1` field is breaking where
    /// adding `pinned` beside it was not. The opaque identifiers also stay
    /// withheld on their own merit: a provider version is a path segment of a
    /// read URL whose other segments are categorically redacted, and surfacing
    /// one correlates an alias to an exact upstream object version while buying
    /// an operator nothing, since network aliases always report
    /// `can_rotate: false` / `can_delete: false`. Per-provider canary tests
    /// enforce that absence.
    pub version: Option<u64>,
    pub rotated_at: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SecretProviderConfigError {
    TooManyAliases { maximum: usize },
    InvalidAliasId { index: usize },
    InvalidLabel { index: usize },
    InvalidEnvironmentKey { index: usize },
    InvalidFileKey { index: usize },
    DuplicateAliasId { index: usize, previous: usize },
    SecretsRootRequired { index: usize },
    SecretsRootUnavailable,
    SecretsRootNotDirectory,
    SecretsRootPermissions,
}

impl fmt::Display for SecretProviderConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyAliases { maximum } => {
                write!(formatter, "operator secret aliases must contain at most {maximum} entries")
            }
            Self::InvalidAliasId { index } => write!(
                formatter,
                "operator secret alias at index {index} has an invalid opaque ID"
            ),
            Self::InvalidLabel { index } => write!(
                formatter,
                "operator secret alias at index {index} has an invalid safe label"
            ),
            Self::InvalidEnvironmentKey { index } => write!(
                formatter,
                "operator secret alias at index {index} has an invalid environment locator"
            ),
            Self::InvalidFileKey { index } => write!(
                formatter,
                "operator secret alias at index {index} has an invalid file key"
            ),
            Self::DuplicateAliasId { index, previous } => write!(
                formatter,
                "operator secret alias at index {index} duplicates the opaque ID at index {previous}"
            ),
            Self::SecretsRootRequired { index } => write!(
                formatter,
                "operator file alias at index {index} requires CONNECTION_SECRETS_ROOT"
            ),
            Self::SecretsRootUnavailable => formatter.write_str(
                "CONNECTION_SECRETS_ROOT is unavailable or cannot be canonicalized",
            ),
            Self::SecretsRootNotDirectory => {
                formatter.write_str("CONNECTION_SECRETS_ROOT must be a directory")
            }
            Self::SecretsRootPermissions => formatter.write_str(
                "CONNECTION_SECRETS_ROOT has unsafe write permissions for this platform",
            ),
        }
    }
}

impl Error for SecretProviderConfigError {}

pub fn validate_operator_secret_alias_config(
    aliases: &[OperatorSecretAliasConfig],
    secrets_root_configured: bool,
) -> Result<(), SecretProviderConfigError> {
    if aliases.len() > MAX_OPERATOR_SECRET_ALIASES {
        return Err(SecretProviderConfigError::TooManyAliases {
            maximum: MAX_OPERATOR_SECRET_ALIASES,
        });
    }
    let mut ids = BTreeMap::new();
    for (index, alias) in aliases.iter().enumerate() {
        if !is_valid_opaque_id(&alias.id, MAX_SECRET_ID_BYTES) {
            return Err(SecretProviderConfigError::InvalidAliasId { index });
        }
        if alias.label.is_empty()
            || alias.label.chars().count() > MAX_DISPLAY_NAME_CHARS
            || alias.label.chars().any(char::is_control)
        {
            return Err(SecretProviderConfigError::InvalidLabel { index });
        }
        if let Some(previous) = ids.insert(alias.id.as_str(), index) {
            return Err(SecretProviderConfigError::DuplicateAliasId { index, previous });
        }
        match &alias.source {
            OperatorSecretAliasSource::Environment { key } => {
                if !is_valid_environment_key(key) {
                    return Err(SecretProviderConfigError::InvalidEnvironmentKey { index });
                }
            }
            OperatorSecretAliasSource::File { key } => {
                if !secrets_root_configured {
                    return Err(SecretProviderConfigError::SecretsRootRequired { index });
                }
                if !is_valid_file_key(key) {
                    return Err(SecretProviderConfigError::InvalidFileKey { index });
                }
            }
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretResolveErrorKind {
    UnknownAlias,
    ProviderBusy,
    SourceUnavailable,
    SourceDenied,
    UnsafeSource,
    InvalidMaterial,
    ProviderFailure,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretResolveError {
    alias_id: String,
    kind: SecretResolveErrorKind,
}

impl SecretResolveError {
    pub(crate) fn new(alias_id: impl Into<String>, kind: SecretResolveErrorKind) -> Self {
        Self {
            alias_id: alias_id.into(),
            kind,
        }
    }

    pub fn alias_id(&self) -> &str {
        &self.alias_id
    }

    pub fn kind(&self) -> SecretResolveErrorKind {
        self.kind
    }
}

impl fmt::Display for SecretResolveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "secret alias '{}' resolution failed: {}",
            self.alias_id,
            match self.kind {
                SecretResolveErrorKind::UnknownAlias => "unknown_alias",
                SecretResolveErrorKind::ProviderBusy => "provider_busy",
                SecretResolveErrorKind::SourceUnavailable => "source_unavailable",
                SecretResolveErrorKind::SourceDenied => "source_denied",
                SecretResolveErrorKind::UnsafeSource => "unsafe_source",
                SecretResolveErrorKind::InvalidMaterial => "invalid_material",
                SecretResolveErrorKind::ProviderFailure => "provider_failure",
            }
        )
    }
}

impl Error for SecretResolveError {}

#[async_trait]
pub trait SecretResolver: Send + Sync {
    async fn resolve(
        &self,
        alias_id: &str,
        purpose: SecretPurpose,
    ) -> Result<ResolvedSecret, SecretResolveError>;

    fn aliases(&self) -> Vec<SecretAliasMetadata>;

    /// Whether this provider owns the alias. Providers with an alias index
    /// should override the metadata-scan default.
    fn contains_alias(&self, alias_id: &str) -> bool {
        self.aliases().iter().any(|alias| alias.id == alias_id)
    }
}

type EnvironmentReader = dyn Fn(&str) -> Result<String, ()> + Send + Sync;

#[derive(Clone)]
pub struct OperatorAliasResolver {
    aliases: Arc<BTreeMap<String, OperatorSecretAliasConfig>>,
    secrets_root: Option<Arc<Dir>>,
    environment: Arc<EnvironmentReader>,
    concurrent_reads: Arc<Semaphore>,
}

impl fmt::Debug for OperatorAliasResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OperatorAliasResolver")
            .field("alias_count", &self.aliases.len())
            .field(
                "secrets_root",
                &self.secrets_root.as_ref().map(|_| "<redacted-locator>"),
            )
            .field(
                "maximum_concurrent_reads",
                &MAX_CONCURRENT_SECRET_RESOLUTIONS,
            )
            .finish()
    }
}

impl OperatorAliasResolver {
    pub fn from_config(
        aliases: &[OperatorSecretAliasConfig],
        secrets_root: Option<&SecretRootConfig>,
    ) -> Result<Self, SecretProviderConfigError> {
        Self::from_config_with_environment(
            aliases,
            secrets_root,
            Arc::new(|key| env::var(key).map_err(|_| ())),
            MAX_CONCURRENT_SECRET_RESOLUTIONS,
        )
    }

    fn from_config_with_environment(
        aliases: &[OperatorSecretAliasConfig],
        secrets_root: Option<&SecretRootConfig>,
        environment: Arc<EnvironmentReader>,
        maximum_concurrent_reads: usize,
    ) -> Result<Self, SecretProviderConfigError> {
        validate_operator_secret_alias_config(aliases, secrets_root.is_some())?;
        let secrets_root = if let Some(root) = secrets_root {
            let canonical = fs::canonicalize(root.as_path())
                .map_err(|_| SecretProviderConfigError::SecretsRootUnavailable)?;
            let directory = Dir::open_ambient_dir(&canonical, ambient_authority())
                .map_err(|_| SecretProviderConfigError::SecretsRootUnavailable)?;
            let metadata = directory
                .try_clone()
                .and_then(|directory| directory.into_std_file().metadata())
                .map_err(|_| SecretProviderConfigError::SecretsRootUnavailable)?;
            if !metadata.is_dir() {
                return Err(SecretProviderConfigError::SecretsRootNotDirectory);
            }
            validate_root_permissions(&metadata)?;
            Some(Arc::new(directory))
        } else {
            None
        };
        let aliases = aliases
            .iter()
            .cloned()
            .map(|alias| (alias.id.clone(), alias))
            .collect();
        Ok(Self {
            aliases: Arc::new(aliases),
            secrets_root,
            environment,
            concurrent_reads: Arc::new(Semaphore::new(maximum_concurrent_reads)),
        })
    }

    pub fn contains_alias(&self, alias_id: &str) -> bool {
        <Self as SecretResolver>::contains_alias(self, alias_id)
    }

    pub(crate) fn resolve_blocking(
        &self,
        alias_id: &str,
        purpose: SecretPurpose,
    ) -> Result<ResolvedSecret, SecretResolveError> {
        let _permit = Arc::clone(&self.concurrent_reads)
            .try_acquire_owned()
            .map_err(|_| SecretResolveError::new(alias_id, SecretResolveErrorKind::ProviderBusy))?;
        self.resolve_blocking_inner(alias_id, purpose)
    }

    fn resolve_blocking_inner(
        &self,
        alias_id: &str,
        purpose: SecretPurpose,
    ) -> Result<ResolvedSecret, SecretResolveError> {
        let alias = self.aliases.get(alias_id).cloned().ok_or_else(|| {
            SecretResolveError::new(
                safe_error_alias_id(alias_id),
                SecretResolveErrorKind::UnknownAlias,
            )
        })?;
        match &alias.source {
            OperatorSecretAliasSource::Environment { key } => {
                let value = (self.environment)(key).map_err(|_| {
                    SecretResolveError::new(&alias.id, SecretResolveErrorKind::SourceUnavailable)
                })?;
                ResolvedSecret::new(purpose, value.into_bytes()).map_err(|_| {
                    SecretResolveError::new(&alias.id, SecretResolveErrorKind::InvalidMaterial)
                })
            }
            OperatorSecretAliasSource::File { key } => {
                let root = self.secrets_root.as_deref().ok_or_else(|| {
                    SecretResolveError::new(&alias.id, SecretResolveErrorKind::ProviderFailure)
                })?;
                read_file_secret(&alias.id, root, key, purpose)
            }
        }
    }
}

#[async_trait]
impl SecretResolver for OperatorAliasResolver {
    async fn resolve(
        &self,
        alias_id: &str,
        purpose: SecretPurpose,
    ) -> Result<ResolvedSecret, SecretResolveError> {
        let resolver = self.clone();
        let alias_id = safe_error_alias_id(alias_id);
        let join_alias_id = alias_id.clone();
        let permit = Arc::clone(&self.concurrent_reads)
            .try_acquire_owned()
            .map_err(|_| {
                SecretResolveError::new(&alias_id, SecretResolveErrorKind::ProviderBusy)
            })?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            resolver.resolve_blocking_inner(&alias_id, purpose)
        })
        .await
        .map_err(|_| {
            SecretResolveError::new(join_alias_id, SecretResolveErrorKind::ProviderFailure)
        })?
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
                provider: match alias.source {
                    OperatorSecretAliasSource::Environment { .. } => {
                        SecretProviderKind::OperatorEnvironment
                    }
                    OperatorSecretAliasSource::File { .. } => SecretProviderKind::OperatorFile,
                },
                configured: true,
                purpose: None,
                pinned: false,
                version: None,
                rotated_at: None,
            })
            .collect()
    }
}

fn read_file_secret(
    alias_id: &str,
    root: &Dir,
    key: &str,
    purpose: SecretPurpose,
) -> Result<ResolvedSecret, SecretResolveError> {
    read_bounded_file_secret(
        alias_id,
        root,
        key,
        purpose,
        FileSecretPermissions::Exclusive,
    )
}

/// Reads one bounded secret file beneath an already validated capability root.
///
/// The leaf is opened in nonblocking mode, the opened handle is revalidated as
/// a regular file, and the read is capped before any material is parsed.
/// Operator material never follows links. Platform-projected identity material
/// may be reached through the kubelet atomic writer's relative symlinks
/// (`token -> ..data/token`); the capability root confines that resolution, so
/// a link that escapes the root fails closed. Providers that consume
/// platform-projected material also relax only the group/other *read* rule
/// through `permissions`.
pub(crate) fn read_bounded_file_secret(
    alias_id: &str,
    root: &Dir,
    key: &str,
    purpose: SecretPurpose,
    permissions: FileSecretPermissions,
) -> Result<ResolvedSecret, SecretResolveError> {
    let initial_metadata = root
        .symlink_metadata(key)
        .map_err(|error| map_file_error(alias_id, error, false))?;
    let leaf_acceptable = match permissions {
        FileSecretPermissions::Exclusive => {
            initial_metadata.is_file() && !initial_metadata.is_symlink()
        }
        FileSecretPermissions::PlatformProjected => {
            initial_metadata.is_file() || initial_metadata.is_symlink()
        }
    };
    if !leaf_acceptable {
        return Err(SecretResolveError::new(
            alias_id,
            SecretResolveErrorKind::UnsafeSource,
        ));
    }
    let file = open_file_beneath(root, key, permissions)
        .map_err(|error| map_file_error(alias_id, error, true))?;
    let metadata = file
        .metadata()
        .map_err(|error| map_file_error(alias_id, error, false))?;
    if !metadata.is_file() || is_reparse_point(&metadata) {
        return Err(SecretResolveError::new(
            alias_id,
            SecretResolveErrorKind::UnsafeSource,
        ));
    }
    validate_file_permissions(alias_id, &metadata, permissions)?;

    let maximum = purpose.max_bytes();
    if u64::try_from(maximum).is_ok_and(|maximum| metadata.len() > maximum) {
        return Err(SecretResolveError::new(
            alias_id,
            SecretResolveErrorKind::InvalidMaterial,
        ));
    }
    let mut value = Zeroizing::new(Vec::with_capacity(
        usize::try_from(metadata.len())
            .unwrap_or(maximum)
            .min(maximum),
    ));
    file.take(u64::try_from(maximum).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut value)
        .map_err(|error| map_file_error(alias_id, error, false))?;
    if value.len() > maximum {
        return Err(SecretResolveError::new(
            alias_id,
            SecretResolveErrorKind::InvalidMaterial,
        ));
    }
    // A platform-projected bearer token is written by a container runtime, and
    // whether that writer terminates the file is not something an operator
    // controls — an init container using `echo` adds a newline, the kubelet does
    // not. Trailing whitespace is never significant in such a token, and every
    // provider that consumes one already trims it, so normalize here, before the
    // purpose's header-safety rule would reject it. Scoped narrowly on purpose:
    // operator-provisioned material keeps its bytes exactly because those bytes
    // are the credential, and projected TLS material is PEM whose trailing
    // newline is conventional and feeds a trust fingerprint.
    if permissions == FileSecretPermissions::PlatformProjected && purpose.is_http_header_value() {
        while value.last().is_some_and(|byte| byte.is_ascii_whitespace()) {
            value.pop();
        }
        if value.is_empty() {
            return Err(SecretResolveError::new(
                alias_id,
                SecretResolveErrorKind::InvalidMaterial,
            ));
        }
    }
    ResolvedSecret::new(purpose, std::mem::take(&mut *value))
        .map_err(|_| SecretResolveError::new(alias_id, SecretResolveErrorKind::InvalidMaterial))
}

fn map_file_error(alias_id: &str, error: io::Error, unsafe_on_other: bool) -> SecretResolveError {
    let kind = match error.kind() {
        io::ErrorKind::NotFound => SecretResolveErrorKind::SourceUnavailable,
        io::ErrorKind::PermissionDenied => SecretResolveErrorKind::SourceDenied,
        _ if unsafe_on_other => SecretResolveErrorKind::UnsafeSource,
        _ => SecretResolveErrorKind::ProviderFailure,
    };
    SecretResolveError::new(alias_id, kind)
}

fn open_file_beneath(
    root: &Dir,
    key: &str,
    permissions: FileSecretPermissions,
) -> io::Result<File> {
    let mut options = CapabilityOpenOptions::new();
    options.read(true);
    options.follow(match permissions {
        FileSecretPermissions::Exclusive => FollowSymlinks::No,
        // Symlink resolution is confined beneath the capability root; absolute
        // targets and traversal above the root fail instead of escaping.
        FileSecretPermissions::PlatformProjected => FollowSymlinks::Yes,
    });
    options.nonblock(true);
    root.open_with(key, &options).map(|file| file.into_std())
}

#[cfg(windows)]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_: &fs::Metadata) -> bool {
    false
}

#[cfg(unix)]
fn validate_root_permissions(metadata: &fs::Metadata) -> Result<(), SecretProviderConfigError> {
    use std::os::unix::fs::MetadataExt;
    if metadata.mode() & 0o022 == 0 {
        Ok(())
    } else {
        Err(SecretProviderConfigError::SecretsRootPermissions)
    }
}

#[cfg(not(unix))]
fn validate_root_permissions(_: &fs::Metadata) -> Result<(), SecretProviderConfigError> {
    Ok(())
}

/// Whether a platform-projected material root carries acceptable permissions.
///
/// Container runtimes publish projected volumes as a tmpfs whose mount root is
/// world-writable with the sticky bit set — `drwxrwxrwt`, mode `1777` — which
/// is what `ls -ld /var/run/secrets/kubernetes.io/serviceaccount` shows inside
/// any pod. The sticky bit is precisely what makes that shape safe: a process
/// that does not own an entry cannot rename or delete it, so the projected leaf
/// cannot be swapped underneath us. A group/other-writable root *without* the
/// sticky bit offers no such protection and stays rejected.
///
/// This is the projected-root counterpart to the leaf rule in
/// [`read_bounded_file_secret`]: both must tolerate the shape the kubelet
/// actually publishes, and neither may tolerate anything looser. Every network
/// secret provider shares this one predicate so the five cannot drift apart.
#[cfg(unix)]
pub(crate) fn projected_root_permissions_are_safe(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    const STICKY: u32 = 0o1000;
    const GROUP_OTHER_WRITE: u32 = 0o022;
    let mode = metadata.mode();
    mode & GROUP_OTHER_WRITE == 0 || mode & STICKY != 0
}

#[cfg(not(unix))]
pub(crate) fn projected_root_permissions_are_safe(_: &fs::Metadata) -> bool {
    true
}

#[cfg(unix)]
fn validate_file_permissions(
    alias_id: &str,
    metadata: &fs::Metadata,
    permissions: FileSecretPermissions,
) -> Result<(), SecretResolveError> {
    use std::os::unix::fs::MetadataExt;
    let forbidden = match permissions {
        FileSecretPermissions::Exclusive => 0o077,
        FileSecretPermissions::PlatformProjected => 0o022,
    };
    if metadata.mode() & forbidden == 0 {
        Ok(())
    } else {
        Err(SecretResolveError::new(
            alias_id,
            SecretResolveErrorKind::UnsafeSource,
        ))
    }
}

#[cfg(not(unix))]
fn validate_file_permissions(
    _: &str,
    _: &fs::Metadata,
    _: FileSecretPermissions,
) -> Result<(), SecretResolveError> {
    Ok(())
}

pub(crate) fn is_valid_opaque_id(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().enumerate().all(|(index, byte)| match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' => true,
            b'.' | b'_' | b'-' => index > 0,
            _ => false,
        })
}

pub(crate) fn safe_error_alias_id(value: &str) -> String {
    if is_valid_opaque_id(value, MAX_SECRET_ID_BYTES) {
        value.to_owned()
    } else {
        "<invalid-alias>".to_owned()
    }
}

fn is_valid_environment_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ENVIRONMENT_KEY_BYTES
        && value.bytes().enumerate().all(|(index, byte)| {
            byte == b'_'
                || byte.is_ascii_alphanumeric() && (index > 0 || byte.is_ascii_alphabetic())
        })
}

pub(crate) fn is_valid_file_key(value: &str) -> bool {
    is_valid_opaque_id(value, MAX_FILE_KEY_BYTES)
        && value != "."
        && value != ".."
        && !value.ends_with(['.', ' '])
        && !is_windows_reserved_file_key(value)
}

fn is_windows_reserved_file_key(value: &str) -> bool {
    let stem = value
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || stem
            .strip_prefix("COM")
            .or_else(|| stem.strip_prefix("LPT"))
            .is_some_and(|suffix| suffix.len() == 1 && matches!(suffix.as_bytes()[0], b'1'..=b'9'))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretPurpose {
    HeaderApiKey,
    StaticBearer,
    OAuthClientSecret,
    TlsPrivateKey,
    TlsCertificate,
    TlsCaBundle,
}

impl SecretPurpose {
    pub(crate) const fn max_bytes(self) -> usize {
        match self {
            Self::HeaderApiKey | Self::StaticBearer | Self::OAuthClientSecret => {
                MAX_HTTP_CREDENTIAL_BYTES
            }
            Self::TlsPrivateKey => MAX_TLS_PRIVATE_KEY_BYTES,
            Self::TlsCertificate | Self::TlsCaBundle => MAX_TLS_CERTIFICATE_BYTES,
        }
    }

    /// Whether material for this purpose is sent verbatim as an HTTP header
    /// value.
    ///
    /// The OAuth client secret is deliberately excluded: it is URL-encoded and
    /// then base64-encoded into a Basic credential, so bytes that no header may
    /// carry survive that transformation harmlessly.
    pub(crate) const fn is_http_header_value(self) -> bool {
        matches!(self, Self::HeaderApiKey | Self::StaticBearer)
    }
}

/// Mirrors the validity rule `http::HeaderValue::from_bytes` applies: visible
/// ASCII and above, plus horizontal tab, excluding DEL.
const fn is_header_safe(byte: u8) -> bool {
    byte >= 0x20 && byte != 0x7F || byte == b'\t'
}

#[derive(Debug, PartialEq, Eq)]
pub enum SecretValueError {
    Empty,
    TooLarge {
        maximum: usize,
    },
    ContainsNul,
    /// Material for a purpose that is sent as an HTTP header contains a byte no
    /// header value may carry.
    NotHeaderSafe,
}

/// Resolved secret material that cannot be serialized or accidentally logged.
///
/// The owned bytes are zeroized on replacement and drop. Callers receive only a
/// borrowed view so ordinary credential handling does not create another owned
/// copy.
pub struct ResolvedSecret {
    purpose: SecretPurpose,
    value: Zeroizing<Vec<u8>>,
}

impl ResolvedSecret {
    pub fn new(purpose: SecretPurpose, value: Vec<u8>) -> Result<Self, SecretValueError> {
        let value = Zeroizing::new(value);
        if value.is_empty() {
            return Err(SecretValueError::Empty);
        }
        if value.len() > purpose.max_bytes() {
            return Err(SecretValueError::TooLarge {
                maximum: purpose.max_bytes(),
            });
        }
        if value.contains(&0) {
            return Err(SecretValueError::ContainsNul);
        }
        // Credential purposes are sent verbatim as an HTTP header value, and
        // `HeaderValue::from_bytes` refuses control bytes. Catching that here,
        // where the material is already in hand, turns it into one clear error
        // at write or rotation time instead of a 502 on every proxied request
        // for the life of the binding. A trailing newline is the common case:
        // `echo 'token' > secret-file` produces one.
        if purpose.is_http_header_value() && !value.iter().all(|byte| is_header_safe(*byte)) {
            return Err(SecretValueError::NotHeaderSafe);
        }

        Ok(Self { purpose, value })
    }

    pub fn purpose(&self) -> SecretPurpose {
        self.purpose
    }

    pub fn expose(&self) -> &[u8] {
        self.value.as_slice()
    }

    pub fn replace(&mut self, value: Vec<u8>) -> Result<(), SecretValueError> {
        let replacement = Self::new(self.purpose, value)?;
        self.value = replacement.value;
        Ok(())
    }
}

impl fmt::Debug for ResolvedSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        fs,
        sync::{Arc, Mutex},
    };

    use uuid::Uuid;

    use super::*;

    /// Every provider kind, kept exhaustive by the match below: adding a
    /// variant breaks compilation here until this list and the published
    /// admin schema are both updated.
    const ALL_SECRET_PROVIDER_KINDS: [SecretProviderKind; 8] = [
        SecretProviderKind::OperatorEnvironment,
        SecretProviderKind::OperatorFile,
        SecretProviderKind::LocalEncrypted,
        SecretProviderKind::VaultKvV2,
        SecretProviderKind::GcpSecretManager,
        SecretProviderKind::AzureKeyVault,
        SecretProviderKind::AwsSecretsManager,
        SecretProviderKind::KubernetesSecrets,
    ];

    #[allow(dead_code)]
    fn assert_secret_provider_kinds_exhaustive(kind: SecretProviderKind) {
        match kind {
            SecretProviderKind::OperatorEnvironment
            | SecretProviderKind::OperatorFile
            | SecretProviderKind::LocalEncrypted
            | SecretProviderKind::VaultKvV2
            | SecretProviderKind::GcpSecretManager
            | SecretProviderKind::AzureKeyVault
            | SecretProviderKind::AwsSecretsManager
            | SecretProviderKind::KubernetesSecrets => {}
        }
    }

    #[test]
    fn published_admin_schema_lists_every_secret_provider_kind() {
        let schema_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("gateway crate should live inside the workspace")
            .join("docs/schemas/connection-admin.v1.schema.json");
        let schema: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(schema_path).expect("published admin schema should read"),
        )
        .expect("published admin schema should parse");
        let listed: std::collections::BTreeSet<String> = schema
            .pointer("/$defs/SecretProvider/enum")
            .and_then(serde_json::Value::as_array)
            .expect("schema should define the SecretProvider enum")
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .expect("SecretProvider enum entries should be strings")
                    .to_owned()
            })
            .collect();
        let expected: std::collections::BTreeSet<String> = ALL_SECRET_PROVIDER_KINDS
            .iter()
            .map(|kind| {
                serde_json::to_value(kind)
                    .expect("provider kind should serialize")
                    .as_str()
                    .expect("provider kind should serialize as a string")
                    .to_owned()
            })
            .collect();
        assert_eq!(
            listed, expected,
            "docs/schemas/connection-admin.v1.schema.json SecretProvider enum must list exactly the serialized SecretProviderKind variants"
        );
    }

    const CANARY: &[u8] = b"greengateway-secret-canary";

    struct TemporarySecrets {
        root: PathBuf,
    }

    impl TemporarySecrets {
        fn new(name: &str) -> Self {
            let root =
                std::env::temp_dir().join(format!("greengateway-secret-{name}-{}", Uuid::new_v4()));
            fs::create_dir(&root).expect("temporary secrets root should create");
            set_directory_permissions(&root, 0o755);
            Self { root }
        }

        fn write(&self, key: &str, value: &[u8]) {
            let path = self.root.join(key);
            fs::write(&path, value).expect("temporary secret should write");
            set_file_permissions(&path, 0o600);
        }

        fn root_config(&self) -> SecretRootConfig {
            SecretRootConfig::new(self.root.clone())
        }
    }

    impl Drop for TemporarySecrets {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[cfg(unix)]
    fn set_directory_permissions(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .expect("directory permissions should update");
    }

    #[cfg(not(unix))]
    fn set_directory_permissions(_: &Path, _: u32) {}

    #[cfg(unix)]
    fn set_file_permissions(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .expect("file permissions should update");
    }

    #[cfg(not(unix))]
    fn set_file_permissions(_: &Path, _: u32) {}

    fn environment_alias(id: &str, key: &str) -> OperatorSecretAliasConfig {
        OperatorSecretAliasConfig {
            id: id.to_owned(),
            label: format!("{id} label"),
            source: OperatorSecretAliasSource::Environment {
                key: key.to_owned(),
            },
        }
    }

    fn file_alias(id: &str, key: &str) -> OperatorSecretAliasConfig {
        OperatorSecretAliasConfig {
            id: id.to_owned(),
            label: format!("{id} label"),
            source: OperatorSecretAliasSource::File {
                key: key.to_owned(),
            },
        }
    }

    fn resolver_with_environment(
        aliases: &[OperatorSecretAliasConfig],
        values: Arc<Mutex<BTreeMap<String, String>>>,
        maximum_concurrent_reads: usize,
    ) -> OperatorAliasResolver {
        let environment = Arc::new(move |key: &str| {
            values
                .lock()
                .expect("environment fixture lock should work")
                .get(key)
                .cloned()
                .ok_or(())
        });
        OperatorAliasResolver::from_config_with_environment(
            aliases,
            None,
            environment,
            maximum_concurrent_reads,
        )
        .expect("environment resolver should build")
    }

    #[test]
    fn debug_never_exposes_secret_material() {
        let secret = ResolvedSecret::new(SecretPurpose::StaticBearer, CANARY.to_vec())
            .expect("bounded canary should be accepted");

        assert_eq!(format!("{secret:?}"), "<redacted>");
        assert!(!format!("{secret:?}").contains("canary"));
    }

    #[test]
    fn values_are_not_trimmed_or_transformed() {
        let value = b"  exact credential bytes  ".to_vec();
        let secret = ResolvedSecret::new(SecretPurpose::HeaderApiKey, value.clone())
            .expect("bounded value should be accepted");

        assert_eq!(secret.expose(), value);
    }

    #[test]
    fn header_purposes_reject_bytes_no_header_value_can_carry() {
        // The motivating case: `echo 'token' > secret-file` appends a newline,
        // which HeaderValue::from_bytes refuses, so the binding would be
        // accepted at write time and then fail every proxied request.
        for purpose in [SecretPurpose::HeaderApiKey, SecretPurpose::StaticBearer] {
            assert_eq!(
                ResolvedSecret::new(purpose, b"sk_live_abc123\n".to_vec())
                    .expect_err("a trailing newline must be rejected"),
                SecretValueError::NotHeaderSafe
            );
            assert_eq!(
                ResolvedSecret::new(purpose, b"token\rwith-cr".to_vec())
                    .expect_err("an embedded CR must be rejected"),
                SecretValueError::NotHeaderSafe
            );
            assert_eq!(
                ResolvedSecret::new(purpose, vec![b't', 0x7F]).expect_err("DEL must be rejected"),
                SecretValueError::NotHeaderSafe
            );
            // Tab and high bytes are legal in a header value.
            ResolvedSecret::new(purpose, b"token\twith-tab".to_vec())
                .expect("a tab is a valid header byte");
            ResolvedSecret::new(purpose, vec![b't', 0xC3, 0xA9])
                .expect("bytes above ASCII are valid header bytes");
        }

        // The OAuth client secret is URL- then base64-encoded into a Basic
        // credential, so a newline never reaches a header value verbatim.
        ResolvedSecret::new(SecretPurpose::OAuthClientSecret, b"secret\n".to_vec())
            .expect("the OAuth client secret is encoded before it becomes a header");
        // TLS material is PEM and legitimately full of newlines.
        ResolvedSecret::new(SecretPurpose::TlsPrivateKey, b"-----BEGIN\nkey\n".to_vec())
            .expect("PEM material must not be header-checked");
    }

    #[test]
    fn empty_oversized_and_nul_values_fail_closed() {
        assert_eq!(
            ResolvedSecret::new(SecretPurpose::StaticBearer, Vec::new())
                .expect_err("empty secret must fail"),
            SecretValueError::Empty
        );
        assert_eq!(
            ResolvedSecret::new(
                SecretPurpose::OAuthClientSecret,
                vec![b'x'; MAX_HTTP_CREDENTIAL_BYTES + 1]
            )
            .expect_err("oversized secret must fail"),
            SecretValueError::TooLarge {
                maximum: MAX_HTTP_CREDENTIAL_BYTES
            }
        );
        assert_eq!(
            ResolvedSecret::new(SecretPurpose::TlsPrivateKey, b"key\0material".to_vec())
                .expect_err("NUL-bearing secret must fail"),
            SecretValueError::ContainsNul
        );
    }

    #[test]
    fn failed_replacement_keeps_current_value() {
        let mut secret = ResolvedSecret::new(SecretPurpose::StaticBearer, CANARY.to_vec())
            .expect("bounded canary should be accepted");

        assert_eq!(
            secret
                .replace(Vec::new())
                .expect_err("invalid replacement must fail"),
            SecretValueError::Empty
        );
        assert_eq!(secret.expose(), CANARY);
    }

    #[test]
    fn static_alias_validation_rejects_unsafe_or_ambiguous_configuration() {
        assert!(matches!(
            validate_operator_secret_alias_config(
                &[
                    environment_alias("duplicate", "FIRST_KEY"),
                    environment_alias("duplicate", "SECOND_KEY"),
                ],
                false,
            ),
            Err(SecretProviderConfigError::DuplicateAliasId { .. })
        ));
        assert!(matches!(
            validate_operator_secret_alias_config(
                &[environment_alias("../host", "SAFE_KEY")],
                false,
            ),
            Err(SecretProviderConfigError::InvalidAliasId { .. })
        ));
        assert!(matches!(
            validate_operator_secret_alias_config(
                &[environment_alias("billing", "1_INVALID")],
                false,
            ),
            Err(SecretProviderConfigError::InvalidEnvironmentKey { .. })
        ));
        for file_key in [
            "../secret",
            "/absolute",
            r"nested\secret",
            "nested/secret",
            "C:secret",
            "NUL",
            "COM1.txt",
            "trailing.",
        ] {
            assert!(
                matches!(
                    validate_operator_secret_alias_config(&[file_alias("billing", file_key)], true,),
                    Err(SecretProviderConfigError::InvalidFileKey { .. })
                ),
                "{file_key:?} must be rejected"
            );
        }
        let aliases = (0..=MAX_OPERATOR_SECRET_ALIASES)
            .map(|index| environment_alias(&format!("alias-{index}"), "SAFE_KEY"))
            .collect::<Vec<_>>();
        assert!(matches!(
            validate_operator_secret_alias_config(&aliases, false),
            Err(SecretProviderConfigError::TooManyAliases {
                maximum: MAX_OPERATOR_SECRET_ALIASES,
            })
        ));
        assert!(matches!(
            validate_operator_secret_alias_config(&[file_alias("billing", "billing")], false),
            Err(SecretProviderConfigError::SecretsRootRequired { .. })
        ));
    }

    #[test]
    fn config_and_resolver_debug_never_expose_source_locators() {
        let temporary = TemporarySecrets::new("debug");
        let environment_locator = "SUPER_SECRET_ENVIRONMENT_LOCATOR";
        let file_locator = "private-key-canary.pem";
        let root_locator = temporary.root.display().to_string();
        let aliases = vec![
            environment_alias("environment", environment_locator),
            file_alias("file", file_locator),
        ];
        let resolver = OperatorAliasResolver::from_config(&aliases, Some(&temporary.root_config()))
            .expect("resolver should build");

        for output in [
            format!("{aliases:?}"),
            format!("{resolver:?}"),
            format!("{:?}", temporary.root_config()),
        ] {
            assert!(!output.contains(environment_locator));
            assert!(!output.contains(file_locator));
            assert!(!output.contains(&root_locator));
        }
        let metadata =
            serde_json::to_string(&resolver.aliases()).expect("metadata should serialize");
        assert!(!metadata.contains(environment_locator));
        assert!(!metadata.contains(file_locator));
        assert!(!metadata.contains(&root_locator));
        assert!(metadata.contains("operator_environment"));
        assert!(metadata.contains("operator_file"));
    }

    #[tokio::test]
    async fn environment_aliases_resolve_fresh_values_and_preserve_in_flight_material() {
        let values = Arc::new(Mutex::new(BTreeMap::from([(
            "BILLING_TOKEN".to_owned(),
            "first-value".to_owned(),
        )])));
        let resolver = resolver_with_environment(
            &[environment_alias("billing", "BILLING_TOKEN")],
            Arc::clone(&values),
            MAX_CONCURRENT_SECRET_RESOLUTIONS,
        );
        let first = resolver
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("first value should resolve");
        values
            .lock()
            .expect("environment fixture lock should work")
            .insert("BILLING_TOKEN".to_owned(), "second-value".to_owned());
        let second = resolver
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("rotated value should resolve");

        assert_eq!(first.expose(), b"first-value");
        assert_eq!(second.expose(), b"second-value");

        values
            .lock()
            .expect("environment fixture lock should work")
            .insert("BILLING_TOKEN".to_owned(), String::new());
        let error = resolver
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect_err("empty rotation must fail closed");
        assert_eq!(error.kind(), SecretResolveErrorKind::InvalidMaterial);
        values
            .lock()
            .expect("environment fixture lock should work")
            .insert(
                "BILLING_TOKEN".to_owned(),
                "x".repeat(MAX_HTTP_CREDENTIAL_BYTES + 1),
            );
        assert_eq!(
            resolver
                .resolve("billing", SecretPurpose::StaticBearer)
                .await
                .expect_err("oversized rotation must fail closed")
                .kind(),
            SecretResolveErrorKind::InvalidMaterial
        );
        values
            .lock()
            .expect("environment fixture lock should work")
            .insert("BILLING_TOKEN".to_owned(), "nul\0value".to_owned());
        assert_eq!(
            resolver
                .resolve("billing", SecretPurpose::StaticBearer)
                .await
                .expect_err("NUL-bearing rotation must fail closed")
                .kind(),
            SecretResolveErrorKind::InvalidMaterial
        );
        assert_eq!(first.expose(), b"first-value");
        assert_eq!(second.expose(), b"second-value");
    }

    #[tokio::test]
    async fn resolution_errors_are_bounded_and_do_not_expose_locators_or_values() {
        let values = Arc::new(Mutex::new(BTreeMap::new()));
        let locator_canary = "SECRET_LOCATOR_CANARY";
        let resolver = resolver_with_environment(
            &[environment_alias("billing", locator_canary)],
            values,
            MAX_CONCURRENT_SECRET_RESOLUTIONS,
        );
        let missing = resolver
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect_err("missing environment value must fail");
        let unknown = resolver
            .resolve("unknown", SecretPurpose::StaticBearer)
            .await
            .expect_err("unknown alias must fail");
        let invalid_alias_canary = format!("invalid\n{}", "x".repeat(1024));
        let invalid = resolver
            .resolve(&invalid_alias_canary, SecretPurpose::StaticBearer)
            .await
            .expect_err("untrusted invalid alias must fail");
        for error in [&missing, &unknown] {
            let output = format!("{error:?} {error}");
            assert!(!output.contains(locator_canary));
            assert!(output.len() < 256);
        }
        assert_eq!(missing.kind(), SecretResolveErrorKind::SourceUnavailable);
        assert_eq!(unknown.kind(), SecretResolveErrorKind::UnknownAlias);
        assert_eq!(invalid.alias_id(), "<invalid-alias>");
        assert!(!format!("{invalid:?} {invalid}").contains(&invalid_alias_canary));
    }

    #[tokio::test]
    async fn provider_read_concurrency_is_hard_bounded() {
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let release_rx = Arc::new(Mutex::new(release_rx));
        let environment = Arc::new(move |_: &str| {
            started_tx.send(()).map_err(|_| ())?;
            release_rx.lock().map_err(|_| ())?.recv().map_err(|_| ())?;
            Ok("value".to_owned())
        });
        let resolver = OperatorAliasResolver::from_config_with_environment(
            &[environment_alias("billing", "BILLING_TOKEN")],
            None,
            environment,
            1,
        )
        .expect("resolver should build");
        let first_resolver = resolver.clone();
        let first = tokio::spawn(async move {
            first_resolver
                .resolve("billing", SecretPurpose::StaticBearer)
                .await
        });
        tokio::task::yield_now().await;
        started_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("first provider read should start");

        let error = resolver
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect_err("second concurrent resolution must fail");
        assert_eq!(error.kind(), SecretResolveErrorKind::ProviderBusy);
        release_tx
            .send(())
            .expect("first provider read should release");
        assert_eq!(
            first
                .await
                .expect("first resolution task should join")
                .expect("first resolution should succeed")
                .expose(),
            b"value"
        );
    }

    #[test]
    fn saturated_provider_rejects_before_entering_the_blocking_queue() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .max_blocking_threads(1)
            .enable_all()
            .build()
            .expect("bounded test runtime should build");
        runtime.block_on(async {
            let (started_tx, started_rx) = std::sync::mpsc::channel();
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            let blocker = tokio::task::spawn_blocking(move || {
                started_tx
                    .send(())
                    .expect("blocking-pool fixture should report admission");
                release_rx
                    .recv()
                    .expect("blocking-pool fixture should be released");
            });
            started_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .expect("blocking pool should be occupied");

            let values = Arc::new(Mutex::new(BTreeMap::from([(
                "BILLING_TOKEN".to_owned(),
                "value".to_owned(),
            )])));
            let mut resolver = resolver_with_environment(
                &[environment_alias("billing", "BILLING_TOKEN")],
                values,
                1,
            );
            resolver.concurrent_reads = Arc::new(Semaphore::new(0));
            let error = tokio::time::timeout(
                std::time::Duration::from_millis(250),
                resolver.resolve("billing", SecretPurpose::StaticBearer),
            )
            .await
            .expect("saturated admission must not wait behind a blocking task")
            .expect_err("saturated admission must fail closed");
            assert_eq!(error.kind(), SecretResolveErrorKind::ProviderBusy);

            release_tx
                .send(())
                .expect("blocking-pool fixture should release");
            blocker
                .await
                .expect("blocking-pool fixture should finish cleanly");
        });
    }

    #[tokio::test]
    async fn file_aliases_resolve_fresh_bounded_regular_files() {
        let temporary = TemporarySecrets::new("file-rotation");
        temporary.write("billing-token", b"first-file-value");
        let resolver = OperatorAliasResolver::from_config(
            &[file_alias("billing", "billing-token")],
            Some(&temporary.root_config()),
        )
        .expect("file resolver should build");
        let first = resolver
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("first file value should resolve");
        temporary.write("billing-token", b"second-file-value");
        let second = resolver
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("rotated file value should resolve");

        assert_eq!(first.expose(), b"first-file-value");
        assert_eq!(second.expose(), b"second-file-value");
    }

    #[tokio::test]
    async fn missing_non_regular_and_oversized_files_fail_closed() {
        let temporary = TemporarySecrets::new("file-failures");
        fs::create_dir(temporary.root.join("directory"))
            .expect("non-regular fixture should create");
        temporary.write("oversized", &vec![b'x'; MAX_HTTP_CREDENTIAL_BYTES + 1]);
        let aliases = vec![
            file_alias("missing", "missing"),
            file_alias("directory", "directory"),
            file_alias("oversized", "oversized"),
        ];
        let resolver = OperatorAliasResolver::from_config(&aliases, Some(&temporary.root_config()))
            .expect("resolver should build");

        assert_eq!(
            resolver
                .resolve("missing", SecretPurpose::StaticBearer)
                .await
                .expect_err("missing file must fail")
                .kind(),
            SecretResolveErrorKind::SourceUnavailable
        );
        assert_eq!(
            resolver
                .resolve("directory", SecretPurpose::StaticBearer)
                .await
                .expect_err("directory must fail")
                .kind(),
            SecretResolveErrorKind::UnsafeSource
        );
        assert_eq!(
            resolver
                .resolve("oversized", SecretPurpose::StaticBearer)
                .await
                .expect_err("oversized file must fail")
                .kind(),
            SecretResolveErrorKind::InvalidMaterial
        );
    }

    #[tokio::test]
    async fn file_resolution_errors_never_expose_file_or_root_locators() {
        let temporary = TemporarySecrets::new("file-error-redaction");
        let file_locator_canary = "private-file-locator-canary";
        let root_locator_canary = temporary.root.display().to_string();
        let resolver = OperatorAliasResolver::from_config(
            &[file_alias("billing", file_locator_canary)],
            Some(&temporary.root_config()),
        )
        .expect("resolver should build");
        let error = resolver
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect_err("missing file must fail");
        let output = format!("{error:?} {error}");

        assert_eq!(error.kind(), SecretResolveErrorKind::SourceUnavailable);
        assert!(!output.contains(file_locator_canary));
        assert!(!output.contains(&root_locator_canary));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_symlink_escape_and_loose_permissions_fail_closed() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let temporary = TemporarySecrets::new("unix-safety");
        let outside = temporary.root.with_extension("outside-secret");
        fs::write(&outside, b"outside-canary").expect("outside fixture should write");
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o600))
            .expect("outside fixture permissions should update");
        symlink(&outside, temporary.root.join("linked")).expect("symlink fixture should create");
        temporary.write("loose", b"loose-permission-canary");
        set_file_permissions(&temporary.root.join("loose"), 0o644);
        let resolver = OperatorAliasResolver::from_config(
            &[file_alias("linked", "linked"), file_alias("loose", "loose")],
            Some(&temporary.root_config()),
        )
        .expect("resolver should build");

        assert_eq!(
            resolver
                .resolve("linked", SecretPurpose::StaticBearer)
                .await
                .expect_err("symlink escape must fail")
                .kind(),
            SecretResolveErrorKind::UnsafeSource
        );
        assert_eq!(
            resolver
                .resolve("loose", SecretPurpose::StaticBearer)
                .await
                .expect_err("loosely permissioned file must fail")
                .kind(),
            SecretResolveErrorKind::UnsafeSource
        );
        fs::remove_file(outside).expect("outside fixture should remove");
    }

    #[test]
    fn a_projected_token_written_with_a_trailing_newline_still_reads() {
        let temporary = TemporarySecrets::new("projected-token-newline");
        // An init container writing the token with `echo` terminates the file;
        // the kubelet does not. Whether the token is header-safe must not depend
        // on which one provisioned it.
        temporary.write("token", b"header.payload.signature\n");
        set_file_permissions(&temporary.root.join("token"), 0o644);
        let root = Dir::open_ambient_dir(&temporary.root, ambient_authority())
            .expect("capability root should open");

        let projected = read_bounded_file_secret(
            "identity",
            &root,
            "token",
            SecretPurpose::StaticBearer,
            FileSecretPermissions::PlatformProjected,
        )
        .expect("a projected token file may be newline terminated");
        assert_eq!(projected.expose(), b"header.payload.signature");

        // Operator-provisioned material keeps its bytes exactly, so the same
        // content under the strict policy is still rejected rather than trimmed.
        set_file_permissions(&temporary.root.join("token"), 0o600);
        let operator = read_bounded_file_secret(
            "identity",
            &root,
            "token",
            SecretPurpose::StaticBearer,
            FileSecretPermissions::Exclusive,
        )
        .expect_err("operator credentials are never trimmed, so this stays invalid");
        assert_eq!(operator.kind(), SecretResolveErrorKind::InvalidMaterial);
    }

    #[cfg(unix)]
    #[test]
    fn unix_projected_root_accepts_the_kubelet_tmpfs_mode_and_rejects_plain_world_writable() {
        let temporary = TemporarySecrets::new("projected-root-mode");

        // What `ls -ld /var/run/secrets/kubernetes.io/serviceaccount` shows in
        // any pod: drwxrwxrwt. The sticky bit is the protection.
        set_directory_permissions(&temporary.root, 0o1777);
        let sticky = fs::metadata(&temporary.root).expect("sticky root should stat");
        assert!(
            projected_root_permissions_are_safe(&sticky),
            "the kubelet publishes projected volume roots as 1777; rejecting that \
             makes every workload-identity configuration unstartable"
        );

        // Same write bits, no sticky bit: any process could swap the leaf.
        set_directory_permissions(&temporary.root, 0o777);
        let world_writable = fs::metadata(&temporary.root).expect("loose root should stat");
        assert!(!projected_root_permissions_are_safe(&world_writable));

        set_directory_permissions(&temporary.root, 0o755);
        let tight = fs::metadata(&temporary.root).expect("tight root should stat");
        assert!(projected_root_permissions_are_safe(&tight));

        // Group-writable without sticky is rejected just like other-writable.
        set_directory_permissions(&temporary.root, 0o775);
        let group_writable = fs::metadata(&temporary.root).expect("group root should stat");
        assert!(!projected_root_permissions_are_safe(&group_writable));

        set_directory_permissions(&temporary.root, 0o755);
    }

    #[cfg(unix)]
    #[test]
    fn unix_platform_projected_reads_kubelet_symlink_layout() {
        use std::os::unix::fs::symlink;

        let temporary = TemporarySecrets::new("projected-layout");
        let data_dir = temporary.root.join("..2026_08_24_10_00_00.0000000001");
        fs::create_dir(&data_dir).expect("timestamped data directory should create");
        set_directory_permissions(&data_dir, 0o755);
        let token_path = data_dir.join("token");
        fs::write(&token_path, b"projected-token-material").expect("projected token should write");
        set_file_permissions(&token_path, 0o644);
        symlink(
            "..2026_08_24_10_00_00.0000000001",
            temporary.root.join("..data"),
        )
        .expect("..data symlink should create");
        symlink("..data/token", temporary.root.join("token")).expect("leaf symlink should create");
        let root = Dir::open_ambient_dir(&temporary.root, ambient_authority())
            .expect("capability root should open");

        let projected = read_bounded_file_secret(
            "projected",
            &root,
            "token",
            SecretPurpose::StaticBearer,
            FileSecretPermissions::PlatformProjected,
        )
        .expect("projected read should follow the kubelet atomic-writer layout");
        assert_eq!(projected.expose(), b"projected-token-material");

        let exclusive = read_bounded_file_secret(
            "projected",
            &root,
            "token",
            SecretPurpose::StaticBearer,
            FileSecretPermissions::Exclusive,
        )
        .expect_err("operator material must still refuse symlink leaves");
        assert_eq!(exclusive.kind(), SecretResolveErrorKind::UnsafeSource);
    }

    #[cfg(unix)]
    #[test]
    fn unix_platform_projected_symlink_escaping_the_root_fails_closed() {
        use std::os::unix::fs::symlink;

        let temporary = TemporarySecrets::new("projected-escape");
        let outside = temporary.root.with_extension("outside-token");
        fs::write(&outside, b"outside-token-material").expect("outside fixture should write");
        set_file_permissions(&outside, 0o644);
        symlink(&outside, temporary.root.join("absolute")).expect("absolute symlink should create");
        let relative_target = PathBuf::from("..").join(
            outside
                .file_name()
                .expect("outside fixture should have a file name"),
        );
        symlink(&relative_target, temporary.root.join("relative"))
            .expect("relative symlink should create");
        let root = Dir::open_ambient_dir(&temporary.root, ambient_authority())
            .expect("capability root should open");

        for key in ["absolute", "relative"] {
            let error = read_bounded_file_secret(
                "projected",
                &root,
                key,
                SecretPurpose::StaticBearer,
                FileSecretPermissions::PlatformProjected,
            )
            .expect_err("a link that escapes the root must fail closed");
            assert!(
                matches!(
                    error.kind(),
                    SecretResolveErrorKind::UnsafeSource | SecretResolveErrorKind::SourceDenied
                ),
                "escaping link must map to a fail-closed kind, got {:?}",
                error.kind()
            );
        }
        fs::remove_file(outside).expect("outside fixture should remove");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_resolution_remains_anchored_when_root_path_is_replaced() {
        let temporary = TemporarySecrets::new("unix-root-replacement");
        temporary.write("billing", b"trusted-value");
        let resolver = OperatorAliasResolver::from_config(
            &[file_alias("billing", "billing")],
            Some(&temporary.root_config()),
        )
        .expect("resolver should build");
        let moved_root = temporary.root.with_extension("anchored-root");
        fs::rename(&temporary.root, &moved_root).expect("original root should move");
        fs::create_dir(&temporary.root).expect("replacement root should create");
        set_directory_permissions(&temporary.root, 0o755);
        temporary.write("billing", b"outside-canary");

        let secret = resolver
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("resolution must remain anchored to the opened root");
        assert_eq!(secret.expose(), b"trusted-value");
        assert_ne!(secret.expose(), b"outside-canary");

        drop(secret);
        drop(resolver);
        fs::remove_dir_all(moved_root).expect("moved root should remove");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_fifo_leaf_fails_closed_without_blocking_a_provider_slot() {
        use rustix::fs::{mkfifoat, Mode, CWD};

        let temporary = TemporarySecrets::new("unix-fifo");
        mkfifoat(
            CWD,
            temporary.root.join("blocking-fifo"),
            Mode::from_bits_truncate(0o600),
        )
        .expect("FIFO fixture should create");
        let resolver = OperatorAliasResolver::from_config(
            &[file_alias("fifo", "blocking-fifo")],
            Some(&temporary.root_config()),
        )
        .expect("resolver should build");

        let error = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            resolver.resolve("fifo", SecretPurpose::StaticBearer),
        )
        .await
        .expect("nonblocking leaf open must not wait for a FIFO peer")
        .expect_err("FIFO must fail closed");
        assert_eq!(error.kind(), SecretResolveErrorKind::UnsafeSource);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_resolution_remains_anchored_when_root_junction_is_retargeted() {
        let container = std::env::temp_dir().join(format!(
            "greengateway-secret-windows-root-replacement-{}",
            Uuid::new_v4()
        ));
        let trusted_root = container.join("trusted");
        let outside_root = container.join("outside");
        let configured_root = container.join("configured");
        fs::create_dir_all(&trusted_root).expect("trusted root should create");
        fs::create_dir(&outside_root).expect("outside root should create");
        fs::write(trusted_root.join("billing"), b"trusted-value")
            .expect("trusted value should write");
        fs::write(outside_root.join("billing"), b"outside-canary")
            .expect("outside canary should write");
        create_windows_junction(&trusted_root, &configured_root);
        let resolver = OperatorAliasResolver::from_config(
            &[file_alias("billing", "billing")],
            Some(&SecretRootConfig::new(configured_root.clone())),
        )
        .expect("resolver should build");
        fs::remove_dir(&configured_root).expect("initial junction should remove");
        create_windows_junction(&outside_root, &configured_root);

        let secret = resolver
            .resolve("billing", SecretPurpose::StaticBearer)
            .await
            .expect("resolution must remain anchored to the opened root");
        assert_eq!(secret.expose(), b"trusted-value");
        assert_ne!(secret.expose(), b"outside-canary");

        drop(secret);
        drop(resolver);
        fs::remove_dir(&configured_root).expect("replacement junction should remove");
        fs::remove_dir_all(container).expect("fixture should remove");
    }

    #[cfg(windows)]
    fn create_windows_junction(target: &Path, junction: &Path) {
        let output = std::process::Command::new("cmd")
            .args(["/d", "/c", "mklink", "/J"])
            .arg(junction)
            .arg(target)
            .output()
            .expect("Windows command processor should start");
        assert!(output.status.success(), "Windows junction should create");
    }

    #[cfg(windows)]
    #[tokio::test]
    #[ignore = "requires Windows Developer Mode or SeCreateSymbolicLinkPrivilege"]
    async fn windows_file_symlink_fails_closed() {
        use std::os::windows::fs::symlink_file;

        let temporary = TemporarySecrets::new("windows-safety");
        temporary.write("real", b"real-secret");
        let linked = temporary.root.join("linked");
        symlink_file(temporary.root.join("real"), &linked)
            .expect("Windows symbolic-link privilege is required for this ignored test");
        let resolver = OperatorAliasResolver::from_config(
            &[file_alias("linked", "linked")],
            Some(&temporary.root_config()),
        )
        .expect("resolver should build");
        assert_eq!(
            resolver
                .resolve("linked", SecretPurpose::StaticBearer)
                .await
                .expect_err("reparse-point file must fail")
                .kind(),
            SecretResolveErrorKind::UnsafeSource
        );
    }

    #[cfg(unix)]
    #[test]
    fn unix_writable_secrets_root_is_rejected_without_path_disclosure() {
        let temporary = TemporarySecrets::new("root-permissions");
        set_directory_permissions(&temporary.root, 0o777);
        let root_canary = temporary.root.display().to_string();
        let error = OperatorAliasResolver::from_config(
            &[file_alias("billing", "billing")],
            Some(&temporary.root_config()),
        )
        .expect_err("writable root must fail");
        let output = format!("{error:?} {error}");

        assert_eq!(error, SecretProviderConfigError::SecretsRootPermissions);
        assert!(!output.contains(&root_canary));
    }

    #[test]
    fn unavailable_root_error_does_not_disclose_the_root_locator() {
        let locator = std::env::temp_dir().join(format!(
            "greengateway-missing-root-locator-canary-{}",
            Uuid::new_v4()
        ));
        let locator_text = locator.display().to_string();
        let error = OperatorAliasResolver::from_config(
            &[file_alias("billing", "billing")],
            Some(&SecretRootConfig::new(locator)),
        )
        .expect_err("missing root must fail");
        let output = format!("{error:?} {error}");

        assert_eq!(error, SecretProviderConfigError::SecretsRootUnavailable);
        assert!(!output.contains(&locator_text));
    }

    #[test]
    fn configured_root_is_validated_even_for_environment_only_aliases() {
        let locator = std::env::temp_dir().join(format!(
            "greengateway-unused-missing-root-canary-{}",
            Uuid::new_v4()
        ));
        let locator_text = locator.display().to_string();
        let error = OperatorAliasResolver::from_config(
            &[environment_alias("billing", "GGW_BILLING_TOKEN")],
            Some(&SecretRootConfig::new(locator)),
        )
        .expect_err("a configured root must always be valid");
        let output = format!("{error:?} {error}");

        assert_eq!(error, SecretProviderConfigError::SecretsRootUnavailable);
        assert!(!output.contains(&locator_text));
    }
}
