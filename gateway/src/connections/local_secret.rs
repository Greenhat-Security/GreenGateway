use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt, fs,
    io::Read,
    path::PathBuf,
    sync::{Arc, Mutex, MutexGuard, RwLock},
    time::Duration,
};

use async_trait::async_trait;
use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt as _, OpenOptionsSyncExt as _};
use cap_std::{
    ambient_authority,
    fs::{Dir, OpenOptions as CapabilityOpenOptions},
};
use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use rusqlite::{params, Connection, OptionalExtension, Row, TransactionBehavior};
use serde::Deserialize;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tokio::sync::Semaphore;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{
    model::{MAX_CREDENTIALS, MAX_DISPLAY_NAME_CHARS, MAX_SECRET_ID_BYTES},
    secret::{
        is_valid_file_key, is_valid_opaque_id, safe_error_alias_id, ResolvedSecret,
        SecretAliasMetadata, SecretProviderKind, SecretPurpose, SecretResolveError,
        SecretResolveErrorKind, SecretResolver, SecretRootConfig,
        MAX_CONCURRENT_SECRET_RESOLUTIONS,
    },
    store::SqliteConnectionStore,
};

const LOCAL_SECRET_SCHEMA_VERSION: u32 = 1;
const LOCAL_SECRET_ALGORITHM: &str = "xchacha20poly1305";
const LOCAL_SECRET_FIELD_PURPOSE: &str = "material";
const MASTER_KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 24;
const TAG_BYTES: usize = 16;
pub const MAX_LOCAL_SECRET_KEYS: usize = 8;
pub const MAX_LOCAL_SECRET_KEYRING_CONFIG_BYTES: usize = 16 * 1024;
pub const MAX_MASTER_KEY_ROTATION_BATCH: usize = 64;
#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalSecretKeyRole {
    Primary,
    DecryptOnly,
}

#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalSecretKeyConfig {
    pub id: String,
    pub file: String,
    pub role: LocalSecretKeyRole,
}

impl fmt::Debug for LocalSecretKeyConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalSecretKeyConfig")
            .field("id", &"<redacted-key-id>")
            .field("file", &"<redacted-locator>")
            .field("role", &self.role)
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LocalSecretKeyringConfigError {
    TooManyKeys { maximum: usize },
    InvalidKeyId { index: usize },
    InvalidFileKey { index: usize },
    DuplicateKeyId { index: usize, previous: usize },
    DuplicateFileKey { index: usize, previous: usize },
    PrimaryKeyRequired,
    MultiplePrimaryKeys,
    SecretsRootRequired,
    ManagedStoreRequired,
    SecretsRootUnavailable,
    SecretsRootNotDirectory,
    SecretsRootPermissions,
    KeyFileUnavailable { index: usize },
    KeyFileUnsafe { index: usize },
    KeyFilePermissions { index: usize },
    InvalidKeyMaterial { index: usize },
}

impl fmt::Display for LocalSecretKeyringConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyKeys { maximum } => {
                write!(
                    formatter,
                    "local secret keyring must contain at most {maximum} keys"
                )
            }
            Self::InvalidKeyId { index } => {
                write!(
                    formatter,
                    "local secret key at index {index} has an invalid key ID"
                )
            }
            Self::InvalidFileKey { index } => write!(
                formatter,
                "local secret key at index {index} has an invalid file key"
            ),
            Self::DuplicateKeyId { index, previous } => write!(
                formatter,
                "local secret key at index {index} duplicates the key ID at index {previous}"
            ),
            Self::DuplicateFileKey { index, previous } => write!(
                formatter,
                "local secret key at index {index} duplicates the file key at index {previous}"
            ),
            Self::PrimaryKeyRequired => {
                formatter.write_str("local secret keyring requires exactly one primary key")
            }
            Self::MultiplePrimaryKeys => {
                formatter.write_str("local secret keyring must contain only one primary key")
            }
            Self::SecretsRootRequired => {
                formatter.write_str("local secret keyring requires CONNECTION_SECRETS_ROOT")
            }
            Self::ManagedStoreRequired => {
                formatter.write_str("local secret keyring requires CONNECTIONS_SQLITE_PATH")
            }
            Self::SecretsRootUnavailable => formatter
                .write_str("CONNECTION_SECRETS_ROOT is unavailable or cannot be canonicalized"),
            Self::SecretsRootNotDirectory => {
                formatter.write_str("CONNECTION_SECRETS_ROOT must be a directory")
            }
            Self::SecretsRootPermissions => formatter.write_str(
                "CONNECTION_SECRETS_ROOT has unsafe write permissions for this platform",
            ),
            Self::KeyFileUnavailable { index } => write!(
                formatter,
                "local secret key file at index {index} is unavailable"
            ),
            Self::KeyFileUnsafe { index } => write!(
                formatter,
                "local secret key file at index {index} is not a safe regular file"
            ),
            Self::KeyFilePermissions { index } => write!(
                formatter,
                "local secret key file at index {index} has unsafe permissions"
            ),
            Self::InvalidKeyMaterial { index } => write!(
                formatter,
                "local secret key file at index {index} must contain exactly 32 bytes"
            ),
        }
    }
}

impl Error for LocalSecretKeyringConfigError {}

pub fn validate_local_secret_keyring_config(
    keys: &[LocalSecretKeyConfig],
    secrets_root_configured: bool,
    managed_store_configured: bool,
) -> Result<(), LocalSecretKeyringConfigError> {
    if keys.len() > MAX_LOCAL_SECRET_KEYS {
        return Err(LocalSecretKeyringConfigError::TooManyKeys {
            maximum: MAX_LOCAL_SECRET_KEYS,
        });
    }
    if keys.is_empty() {
        return Ok(());
    }
    if !secrets_root_configured {
        return Err(LocalSecretKeyringConfigError::SecretsRootRequired);
    }
    if !managed_store_configured {
        return Err(LocalSecretKeyringConfigError::ManagedStoreRequired);
    }

    let mut ids = BTreeMap::new();
    let mut files = BTreeMap::new();
    let mut primary_count = 0usize;
    for (index, key) in keys.iter().enumerate() {
        if !is_valid_opaque_id(&key.id, MAX_SECRET_ID_BYTES) {
            return Err(LocalSecretKeyringConfigError::InvalidKeyId { index });
        }
        if !is_valid_file_key(&key.file) {
            return Err(LocalSecretKeyringConfigError::InvalidFileKey { index });
        }
        if let Some(previous) = ids.insert(key.id.as_str(), index) {
            return Err(LocalSecretKeyringConfigError::DuplicateKeyId { index, previous });
        }
        if let Some(previous) = files.insert(key.file.as_str(), index) {
            return Err(LocalSecretKeyringConfigError::DuplicateFileKey { index, previous });
        }
        if key.role == LocalSecretKeyRole::Primary {
            primary_count = primary_count.saturating_add(1);
        }
    }
    match primary_count {
        0 => Err(LocalSecretKeyringConfigError::PrimaryKeyRequired),
        1 => Ok(()),
        _ => Err(LocalSecretKeyringConfigError::MultiplePrimaryKeys),
    }
}

struct KeyMaterial(Zeroizing<[u8; MASTER_KEY_BYTES]>);

impl KeyMaterial {
    fn expose(&self) -> &[u8; MASTER_KEY_BYTES] {
        &self.0
    }
}

impl fmt::Debug for KeyMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

#[derive(Clone)]
pub struct LocalSecretKeyring {
    primary_id: Arc<str>,
    keys: Arc<BTreeMap<String, Arc<KeyMaterial>>>,
}

impl fmt::Debug for LocalSecretKeyring {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalSecretKeyring")
            .field("primary_id", &"<redacted-key-id>")
            .field("key_count", &self.keys.len())
            .finish()
    }
}

impl LocalSecretKeyring {
    pub fn load(
        configs: &[LocalSecretKeyConfig],
        secrets_root: &SecretRootConfig,
    ) -> Result<Self, LocalSecretKeyringConfigError> {
        validate_local_secret_keyring_config(configs, true, true)?;
        if configs.is_empty() {
            return Err(LocalSecretKeyringConfigError::PrimaryKeyRequired);
        }

        let canonical = fs::canonicalize(secrets_root.as_path())
            .map_err(|_| LocalSecretKeyringConfigError::SecretsRootUnavailable)?;
        let directory = Dir::open_ambient_dir(&canonical, ambient_authority())
            .map_err(|_| LocalSecretKeyringConfigError::SecretsRootUnavailable)?;
        let metadata = directory
            .try_clone()
            .and_then(|directory| directory.into_std_file().metadata())
            .map_err(|_| LocalSecretKeyringConfigError::SecretsRootUnavailable)?;
        if !metadata.is_dir() {
            return Err(LocalSecretKeyringConfigError::SecretsRootNotDirectory);
        }
        validate_root_permissions(&metadata)?;

        let mut primary_id = None;
        let mut keys = BTreeMap::new();
        for (index, config) in configs.iter().enumerate() {
            let material = read_master_key(&directory, &config.file, index)?;
            if config.role == LocalSecretKeyRole::Primary {
                primary_id = Some(Arc::<str>::from(config.id.as_str()));
            }
            keys.insert(config.id.clone(), Arc::new(KeyMaterial(material)));
        }

        Ok(Self {
            primary_id: primary_id.ok_or(LocalSecretKeyringConfigError::PrimaryKeyRequired)?,
            keys: Arc::new(keys),
        })
    }

    fn primary_id(&self) -> &str {
        &self.primary_id
    }

    fn key(&self, id: &str) -> Option<&[u8; MASTER_KEY_BYTES]> {
        self.keys.get(id).map(|material| material.expose())
    }
}

fn read_master_key(
    root: &Dir,
    key: &str,
    index: usize,
) -> Result<Zeroizing<[u8; MASTER_KEY_BYTES]>, LocalSecretKeyringConfigError> {
    let initial_metadata = root
        .symlink_metadata(key)
        .map_err(|_| LocalSecretKeyringConfigError::KeyFileUnavailable { index })?;
    if !initial_metadata.is_file() || initial_metadata.is_symlink() {
        return Err(LocalSecretKeyringConfigError::KeyFileUnsafe { index });
    }
    let mut options = CapabilityOpenOptions::new();
    options.read(true);
    options.follow(FollowSymlinks::No);
    options.nonblock(true);
    let file = root
        .open_with(key, &options)
        .map(|file| file.into_std())
        .map_err(|_| LocalSecretKeyringConfigError::KeyFileUnsafe { index })?;
    let metadata = file
        .metadata()
        .map_err(|_| LocalSecretKeyringConfigError::KeyFileUnavailable { index })?;
    if !metadata.is_file() || is_reparse_point(&metadata) {
        return Err(LocalSecretKeyringConfigError::KeyFileUnsafe { index });
    }
    validate_key_file_permissions(&metadata, index)?;
    if metadata.len() != u64::try_from(MASTER_KEY_BYTES).unwrap_or(u64::MAX) {
        return Err(LocalSecretKeyringConfigError::InvalidKeyMaterial { index });
    }

    let mut bytes = Zeroizing::new(Vec::with_capacity(MASTER_KEY_BYTES + 1));
    file.take(u64::try_from(MASTER_KEY_BYTES + 1).unwrap_or(u64::MAX))
        .read_to_end(&mut bytes)
        .map_err(|_| LocalSecretKeyringConfigError::KeyFileUnavailable { index })?;
    if bytes.len() != MASTER_KEY_BYTES {
        return Err(LocalSecretKeyringConfigError::InvalidKeyMaterial { index });
    }
    let mut material = Zeroizing::new([0u8; MASTER_KEY_BYTES]);
    material.copy_from_slice(bytes.as_slice());
    Ok(material)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LocalSecretError {
    InvalidLabel,
    InvalidSecret,
    NotFound,
    LimitExceeded {
        maximum: usize,
    },
    DependencyConflict {
        connection_ids: Vec<String>,
        count: usize,
    },
    StorageFailure,
    EncryptionFailure,
    CorruptRecord,
    KeyUnavailable,
    KeyStillInUse {
        count: usize,
    },
    InvalidRotationBatch {
        maximum: usize,
    },
    IdentifierCollision,
}

impl fmt::Display for LocalSecretError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLabel => formatter.write_str("local secret label is invalid"),
            Self::InvalidSecret => formatter.write_str("local secret material is invalid"),
            Self::NotFound => formatter.write_str("local secret was not found"),
            Self::LimitExceeded { maximum } => {
                write!(
                    formatter,
                    "local secret limit of {maximum} has been reached"
                )
            }
            Self::DependencyConflict { count, .. } => write!(
                formatter,
                "local secret is referenced by {count} managed connection dependencies"
            ),
            Self::StorageFailure => formatter.write_str("local secret storage failed"),
            Self::EncryptionFailure => formatter.write_str("local secret encryption failed"),
            Self::CorruptRecord => formatter.write_str("local secret record is invalid"),
            Self::KeyUnavailable => formatter.write_str("required local secret key is unavailable"),
            Self::KeyStillInUse { count } => write!(
                formatter,
                "local secret key remains in use by {count} encrypted records"
            ),
            Self::InvalidRotationBatch { maximum } => write!(
                formatter,
                "master-key rotation batch must contain between 1 and {maximum} records"
            ),
            Self::IdentifierCollision => formatter.write_str("local secret identifier collision"),
        }
    }
}

impl Error for LocalSecretError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MasterKeyRotationProgress {
    pub reencrypted: usize,
    pub remaining: usize,
}

/// Mutation-only surface for encrypted local secrets.
///
/// This contract intentionally has no method that returns stored plaintext.
/// Runtime resolution is exposed separately through [`SecretResolver`].
pub trait LocalSecretManager: Send + Sync {
    fn create(
        &self,
        label: &str,
        secret: ResolvedSecret,
    ) -> Result<SecretAliasMetadata, LocalSecretError>;
    fn rotate(
        &self,
        id: &str,
        replacement: ResolvedSecret,
    ) -> Result<SecretAliasMetadata, LocalSecretError>;
    fn delete(&self, id: &str) -> Result<(), LocalSecretError>;
    fn metadata(&self) -> Vec<SecretAliasMetadata>;
    fn reencrypt_master_key_batch(
        &self,
        maximum_records: usize,
    ) -> Result<MasterKeyRotationProgress, LocalSecretError>;
    fn ensure_key_unused(&self, key_id: &str) -> Result<(), LocalSecretError>;
}

#[derive(Clone)]
pub struct LocalSecretProvider {
    path: Arc<PathBuf>,
    connection: Arc<Mutex<Connection>>,
    keyring: LocalSecretKeyring,
    metadata: Arc<RwLock<Vec<SecretAliasMetadata>>>,
    reserved_ids: Arc<BTreeSet<String>>,
    concurrent_reads: Arc<Semaphore>,
}

impl fmt::Debug for LocalSecretProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalSecretProvider")
            .field("database", &"<redacted-locator>")
            .field("keyring", &self.keyring)
            .field("secret_count", &self.metadata_read().len())
            .field(
                "maximum_concurrent_reads",
                &MAX_CONCURRENT_SECRET_RESOLUTIONS,
            )
            .finish()
    }
}

impl LocalSecretProvider {
    pub(crate) fn open(
        store: &SqliteConnectionStore,
        keyring: LocalSecretKeyring,
        reserved_ids: BTreeSet<String>,
    ) -> Result<Self, LocalSecretError> {
        let path = store.path().to_path_buf();
        let connection = Connection::open(&path).map_err(|_| LocalSecretError::StorageFailure)?;
        configure_connection(&connection)?;
        let provider = Self {
            path: Arc::new(path),
            connection: Arc::new(Mutex::new(connection)),
            keyring,
            metadata: Arc::new(RwLock::new(Vec::new())),
            reserved_ids: Arc::new(reserved_ids),
            concurrent_reads: Arc::new(Semaphore::new(MAX_CONCURRENT_SECRET_RESOLUTIONS)),
        };
        let records = provider.load_all_records()?;
        if records.len() > MAX_CREDENTIALS {
            return Err(LocalSecretError::LimitExceeded {
                maximum: MAX_CREDENTIALS,
            });
        }
        for record in &records {
            if provider.reserved_ids.contains(&record.id) {
                return Err(LocalSecretError::IdentifierCollision);
            }
            provider.decrypt_record(record)?;
        }
        *provider.metadata_write() = records
            .iter()
            .map(EncryptedSecretRecord::metadata)
            .collect();
        Ok(provider)
    }

    pub fn create(
        &self,
        label: &str,
        secret: ResolvedSecret,
    ) -> Result<SecretAliasMetadata, LocalSecretError> {
        validate_label(label)?;
        let now = utc_timestamp()?;
        let purpose = secret.purpose();
        let mut connection = self.connection_guard();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| LocalSecretError::StorageFailure)?;
        let count: i64 = transaction
            .query_row("SELECT COUNT(*) FROM connection_local_secrets", [], |row| {
                row.get(0)
            })
            .map_err(|_| LocalSecretError::StorageFailure)?;
        if usize::try_from(count).unwrap_or(usize::MAX) >= MAX_CREDENTIALS {
            return Err(LocalSecretError::LimitExceeded {
                maximum: MAX_CREDENTIALS,
            });
        }

        let id = self.generate_available_id(&transaction)?;
        let version = 1u64;
        let (nonce, ciphertext) = self.encrypt(&id, version, purpose, secret.expose())?;
        transaction
            .execute(
                r#"
                INSERT INTO connection_local_secrets (
                    id, schema_version, label, purpose, secret_version, algorithm,
                    key_id, nonce, ciphertext, created_at, rotated_at, updated_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, NULL, ?10)
                "#,
                params![
                    id,
                    i64::from(LOCAL_SECRET_SCHEMA_VERSION),
                    label,
                    purpose_as_str(purpose),
                    i64::try_from(version).map_err(|_| LocalSecretError::CorruptRecord)?,
                    LOCAL_SECRET_ALGORITHM,
                    self.keyring.primary_id(),
                    nonce.as_slice(),
                    ciphertext,
                    now,
                ],
            )
            .map_err(|_| LocalSecretError::StorageFailure)?;
        transaction
            .commit()
            .map_err(|_| LocalSecretError::StorageFailure)?;

        let metadata = SecretAliasMetadata {
            id,
            label: label.to_owned(),
            provider: SecretProviderKind::LocalEncrypted,
            configured: true,
            version: Some(version),
            rotated_at: None,
        };
        let mut all_metadata = self.metadata_write();
        all_metadata.push(metadata.clone());
        all_metadata.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(metadata)
    }

    pub fn rotate(
        &self,
        id: &str,
        replacement: ResolvedSecret,
    ) -> Result<SecretAliasMetadata, LocalSecretError> {
        if !is_valid_local_secret_id(id) {
            return Err(LocalSecretError::NotFound);
        }
        let mut connection = self.connection_guard();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| LocalSecretError::StorageFailure)?;
        let current = query_record(&transaction, id)?.ok_or(LocalSecretError::NotFound)?;
        current.validate()?;
        if current.purpose != replacement.purpose() {
            return Err(LocalSecretError::InvalidSecret);
        }
        self.decrypt_record(&current)?;
        let next_version = current
            .version
            .checked_add(1)
            .ok_or(LocalSecretError::CorruptRecord)?;
        let (nonce, ciphertext) = self.encrypt(
            &current.id,
            next_version,
            current.purpose,
            replacement.expose(),
        )?;
        let now = utc_timestamp()?;
        let changed = transaction
            .execute(
                r#"
                UPDATE connection_local_secrets
                SET secret_version = ?1, algorithm = ?2, key_id = ?3, nonce = ?4,
                    ciphertext = ?5, rotated_at = ?6, updated_at = ?6
                WHERE id = ?7 AND secret_version = ?8
                "#,
                params![
                    i64::try_from(next_version).map_err(|_| LocalSecretError::CorruptRecord)?,
                    LOCAL_SECRET_ALGORITHM,
                    self.keyring.primary_id(),
                    nonce.as_slice(),
                    ciphertext,
                    now,
                    current.id,
                    i64::try_from(current.version).map_err(|_| LocalSecretError::CorruptRecord)?,
                ],
            )
            .map_err(|_| LocalSecretError::StorageFailure)?;
        if changed != 1 {
            return Err(LocalSecretError::StorageFailure);
        }
        transaction
            .commit()
            .map_err(|_| LocalSecretError::StorageFailure)?;

        let metadata = SecretAliasMetadata {
            id: current.id,
            label: current.label,
            provider: SecretProviderKind::LocalEncrypted,
            configured: true,
            version: Some(next_version),
            rotated_at: Some(now),
        };
        self.upsert_metadata(metadata.clone());
        Ok(metadata)
    }

    pub fn delete(&self, id: &str) -> Result<(), LocalSecretError> {
        if !is_valid_local_secret_id(id) {
            return Err(LocalSecretError::NotFound);
        }
        let mut connection = self.connection_guard();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| LocalSecretError::StorageFailure)?;
        let exists: bool = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM connection_local_secrets WHERE id = ?1)",
                params![id],
                |row| row.get(0),
            )
            .map_err(|_| LocalSecretError::StorageFailure)?;
        if !exists {
            return Err(LocalSecretError::NotFound);
        }
        let mut statement = transaction
            .prepare(
                r#"
                SELECT DISTINCT connection_id
                FROM connection_credential_bindings
                WHERE secret_id = ?1
                ORDER BY connection_id ASC
                "#,
            )
            .map_err(|_| LocalSecretError::StorageFailure)?;
        let connection_ids = statement
            .query_map(params![id], |row| row.get::<_, String>(0))
            .map_err(|_| LocalSecretError::StorageFailure)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| LocalSecretError::StorageFailure)?;
        drop(statement);
        if !connection_ids.is_empty() {
            return Err(LocalSecretError::DependencyConflict {
                count: connection_ids.len(),
                connection_ids,
            });
        }
        let changed = transaction
            .execute(
                "DELETE FROM connection_local_secrets WHERE id = ?1",
                params![id],
            )
            .map_err(|_| LocalSecretError::StorageFailure)?;
        if changed != 1 {
            return Err(LocalSecretError::StorageFailure);
        }
        transaction
            .commit()
            .map_err(|_| LocalSecretError::StorageFailure)?;
        self.metadata_write().retain(|metadata| metadata.id != id);
        Ok(())
    }

    pub fn metadata(&self) -> Vec<SecretAliasMetadata> {
        self.metadata_read().clone()
    }

    pub fn reencrypt_master_key_batch(
        &self,
        maximum_records: usize,
    ) -> Result<MasterKeyRotationProgress, LocalSecretError> {
        if maximum_records == 0 || maximum_records > MAX_MASTER_KEY_ROTATION_BATCH {
            return Err(LocalSecretError::InvalidRotationBatch {
                maximum: MAX_MASTER_KEY_ROTATION_BATCH,
            });
        }
        let mut connection = self.connection_guard();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| LocalSecretError::StorageFailure)?;
        let limit =
            i64::try_from(maximum_records).map_err(|_| LocalSecretError::InvalidRotationBatch {
                maximum: MAX_MASTER_KEY_ROTATION_BATCH,
            })?;
        let mut statement = transaction
            .prepare(
                r#"
                SELECT id, schema_version, label, purpose, secret_version, algorithm,
                       key_id, nonce, ciphertext, created_at, rotated_at, updated_at
                FROM connection_local_secrets
                WHERE key_id <> ?1
                ORDER BY id ASC
                LIMIT ?2
                "#,
            )
            .map_err(|_| LocalSecretError::StorageFailure)?;
        let records = statement
            .query_map(params![self.keyring.primary_id(), limit], record_from_row)
            .map_err(|_| LocalSecretError::StorageFailure)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| LocalSecretError::StorageFailure)?;
        drop(statement);

        for record in &records {
            record.validate()?;
            let plaintext = self.decrypt_record(record)?;
            let (nonce, ciphertext) = self.encrypt(
                &record.id,
                record.version,
                record.purpose,
                plaintext.expose(),
            )?;
            let changed = transaction
                .execute(
                    r#"
                    UPDATE connection_local_secrets
                    SET algorithm = ?1, key_id = ?2, nonce = ?3, ciphertext = ?4,
                        updated_at = ?5
                    WHERE id = ?6 AND secret_version = ?7 AND key_id = ?8
                    "#,
                    params![
                        LOCAL_SECRET_ALGORITHM,
                        self.keyring.primary_id(),
                        nonce.as_slice(),
                        ciphertext,
                        utc_timestamp()?,
                        record.id,
                        i64::try_from(record.version)
                            .map_err(|_| LocalSecretError::CorruptRecord)?,
                        record.key_id,
                    ],
                )
                .map_err(|_| LocalSecretError::StorageFailure)?;
            if changed != 1 {
                return Err(LocalSecretError::StorageFailure);
            }
        }
        let remaining: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM connection_local_secrets WHERE key_id <> ?1",
                params![self.keyring.primary_id()],
                |row| row.get(0),
            )
            .map_err(|_| LocalSecretError::StorageFailure)?;
        transaction
            .commit()
            .map_err(|_| LocalSecretError::StorageFailure)?;
        Ok(MasterKeyRotationProgress {
            reencrypted: records.len(),
            remaining: usize::try_from(remaining).map_err(|_| LocalSecretError::CorruptRecord)?,
        })
    }

    pub fn ensure_key_unused(&self, key_id: &str) -> Result<(), LocalSecretError> {
        if !is_valid_opaque_id(key_id, MAX_SECRET_ID_BYTES) {
            return Err(LocalSecretError::KeyUnavailable);
        }
        let count: i64 = self
            .connection_guard()
            .query_row(
                "SELECT COUNT(*) FROM connection_local_secrets WHERE key_id = ?1",
                params![key_id],
                |row| row.get(0),
            )
            .map_err(|_| LocalSecretError::StorageFailure)?;
        let count = usize::try_from(count).map_err(|_| LocalSecretError::CorruptRecord)?;
        if count == 0 {
            Ok(())
        } else {
            Err(LocalSecretError::KeyStillInUse { count })
        }
    }

    fn resolve_sync(
        &self,
        alias_id: &str,
        purpose: SecretPurpose,
    ) -> Result<ResolvedSecret, SecretResolveError> {
        let record = query_record(&self.connection_guard(), alias_id)
            .map_err(|_| {
                SecretResolveError::new(alias_id, SecretResolveErrorKind::ProviderFailure)
            })?
            .ok_or_else(|| {
                SecretResolveError::new(
                    safe_error_alias_id(alias_id),
                    SecretResolveErrorKind::UnknownAlias,
                )
            })?;
        record.validate().map_err(|_| {
            SecretResolveError::new(alias_id, SecretResolveErrorKind::ProviderFailure)
        })?;
        if record.purpose != purpose {
            return Err(SecretResolveError::new(
                alias_id,
                SecretResolveErrorKind::SourceDenied,
            ));
        }
        self.decrypt_record(&record).map_err(|error| {
            SecretResolveError::new(
                alias_id,
                match error {
                    LocalSecretError::KeyUnavailable => SecretResolveErrorKind::SourceUnavailable,
                    LocalSecretError::InvalidSecret => SecretResolveErrorKind::InvalidMaterial,
                    _ => SecretResolveErrorKind::ProviderFailure,
                },
            )
        })
    }

    fn load_all_records(&self) -> Result<Vec<EncryptedSecretRecord>, LocalSecretError> {
        let connection = self.connection_guard();
        let mut statement = connection
            .prepare(
                r#"
                SELECT id, schema_version, label, purpose, secret_version, algorithm,
                       key_id, nonce, ciphertext, created_at, rotated_at, updated_at
                FROM connection_local_secrets
                ORDER BY id ASC
                LIMIT 513
                "#,
            )
            .map_err(|_| LocalSecretError::StorageFailure)?;
        let records = statement
            .query_map([], record_from_row)
            .map_err(|_| LocalSecretError::StorageFailure)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| LocalSecretError::StorageFailure)?;
        Ok(records)
    }

    fn generate_available_id(
        &self,
        transaction: &rusqlite::Transaction<'_>,
    ) -> Result<String, LocalSecretError> {
        for _ in 0..4 {
            let id = Uuid::new_v4().to_string();
            if self.reserved_ids.contains(&id) {
                continue;
            }
            let exists: bool = transaction
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM connection_local_secrets WHERE id = ?1)",
                    params![id],
                    |row| row.get(0),
                )
                .map_err(|_| LocalSecretError::StorageFailure)?;
            if !exists {
                return Ok(id);
            }
        }
        Err(LocalSecretError::IdentifierCollision)
    }

    fn encrypt(
        &self,
        id: &str,
        version: u64,
        purpose: SecretPurpose,
        plaintext: &[u8],
    ) -> Result<([u8; NONCE_BYTES], Vec<u8>), LocalSecretError> {
        let key = self
            .keyring
            .key(self.keyring.primary_id())
            .ok_or(LocalSecretError::KeyUnavailable)?;
        let cipher = XChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| LocalSecretError::EncryptionFailure)?;
        let mut nonce = [0u8; NONCE_BYTES];
        getrandom::fill(&mut nonce).map_err(|_| LocalSecretError::EncryptionFailure)?;
        let aad = canonical_aad(id, version, purpose)?;
        let xnonce = XNonce::from(nonce);
        let ciphertext = cipher
            .encrypt(
                &xnonce,
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| LocalSecretError::EncryptionFailure)?;
        Ok((nonce, ciphertext))
    }

    fn decrypt_record(
        &self,
        record: &EncryptedSecretRecord,
    ) -> Result<ResolvedSecret, LocalSecretError> {
        record.validate()?;
        let key = self
            .keyring
            .key(&record.key_id)
            .ok_or(LocalSecretError::KeyUnavailable)?;
        let cipher = XChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| LocalSecretError::EncryptionFailure)?;
        let aad = canonical_aad(&record.id, record.version, record.purpose)?;
        let nonce: [u8; NONCE_BYTES] = record
            .nonce
            .as_slice()
            .try_into()
            .map_err(|_| LocalSecretError::CorruptRecord)?;
        let xnonce = XNonce::from(nonce);
        let mut plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    &xnonce,
                    Payload {
                        msg: &record.ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| LocalSecretError::EncryptionFailure)?,
        );
        ResolvedSecret::new(record.purpose, std::mem::take(&mut *plaintext))
            .map_err(|_| LocalSecretError::InvalidSecret)
    }

    fn upsert_metadata(&self, replacement: SecretAliasMetadata) {
        let mut metadata = self.metadata_write();
        if let Some(current) = metadata
            .iter_mut()
            .find(|current| current.id == replacement.id)
        {
            *current = replacement;
        } else {
            metadata.push(replacement);
            metadata.sort_by(|left, right| left.id.cmp(&right.id));
        }
    }

    fn connection_guard(&self) -> MutexGuard<'_, Connection> {
        match self.connection.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn metadata_read(&self) -> std::sync::RwLockReadGuard<'_, Vec<SecretAliasMetadata>> {
        match self.metadata.read() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn metadata_write(&self) -> std::sync::RwLockWriteGuard<'_, Vec<SecretAliasMetadata>> {
        match self.metadata.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    #[cfg(test)]
    fn path(&self) -> &std::path::Path {
        self.path.as_path()
    }
}

#[async_trait]
impl SecretResolver for LocalSecretProvider {
    async fn resolve(
        &self,
        alias_id: &str,
        purpose: SecretPurpose,
    ) -> Result<ResolvedSecret, SecretResolveError> {
        let safe_alias_id = safe_error_alias_id(alias_id);
        let permit = Arc::clone(&self.concurrent_reads)
            .try_acquire_owned()
            .map_err(|_| {
                SecretResolveError::new(&safe_alias_id, SecretResolveErrorKind::ProviderBusy)
            })?;
        let provider = self.clone();
        let join_alias_id = safe_alias_id.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            provider.resolve_sync(&safe_alias_id, purpose)
        })
        .await
        .map_err(|_| {
            SecretResolveError::new(join_alias_id, SecretResolveErrorKind::ProviderFailure)
        })?
    }

    fn aliases(&self) -> Vec<SecretAliasMetadata> {
        self.metadata()
    }
}

impl LocalSecretManager for LocalSecretProvider {
    fn create(
        &self,
        label: &str,
        secret: ResolvedSecret,
    ) -> Result<SecretAliasMetadata, LocalSecretError> {
        LocalSecretProvider::create(self, label, secret)
    }

    fn rotate(
        &self,
        id: &str,
        replacement: ResolvedSecret,
    ) -> Result<SecretAliasMetadata, LocalSecretError> {
        LocalSecretProvider::rotate(self, id, replacement)
    }

    fn delete(&self, id: &str) -> Result<(), LocalSecretError> {
        LocalSecretProvider::delete(self, id)
    }

    fn metadata(&self) -> Vec<SecretAliasMetadata> {
        LocalSecretProvider::metadata(self)
    }

    fn reencrypt_master_key_batch(
        &self,
        maximum_records: usize,
    ) -> Result<MasterKeyRotationProgress, LocalSecretError> {
        LocalSecretProvider::reencrypt_master_key_batch(self, maximum_records)
    }

    fn ensure_key_unused(&self, key_id: &str) -> Result<(), LocalSecretError> {
        LocalSecretProvider::ensure_key_unused(self, key_id)
    }
}

fn configure_connection(connection: &Connection) -> Result<(), LocalSecretError> {
    connection
        .busy_timeout(Duration::from_secs(5))
        .map_err(|_| LocalSecretError::StorageFailure)?;
    connection
        .execute_batch(
            r#"
            PRAGMA foreign_keys = ON;
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = FULL;
            "#,
        )
        .map_err(|_| LocalSecretError::StorageFailure)
}

fn query_record(
    connection: &Connection,
    id: &str,
) -> Result<Option<EncryptedSecretRecord>, LocalSecretError> {
    connection
        .query_row(
            r#"
            SELECT id, schema_version, label, purpose, secret_version, algorithm,
                   key_id, nonce, ciphertext, created_at, rotated_at, updated_at
            FROM connection_local_secrets
            WHERE id = ?1
            "#,
            params![id],
            record_from_row,
        )
        .optional()
        .map_err(|_| LocalSecretError::StorageFailure)
}

struct EncryptedSecretRecord {
    id: String,
    schema_version: u32,
    label: String,
    purpose: SecretPurpose,
    purpose_name: String,
    version: u64,
    algorithm: String,
    key_id: String,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    created_at: String,
    rotated_at: Option<String>,
    updated_at: String,
}

impl EncryptedSecretRecord {
    fn validate(&self) -> Result<(), LocalSecretError> {
        if self.schema_version != LOCAL_SECRET_SCHEMA_VERSION
            || Uuid::parse_str(&self.id).is_err()
            || !is_valid_opaque_id(&self.key_id, MAX_SECRET_ID_BYTES)
            || purpose_as_str(self.purpose) != self.purpose_name
            || self.algorithm != LOCAL_SECRET_ALGORITHM
            || self.nonce.len() != NONCE_BYTES
            || self.ciphertext.len() < TAG_BYTES + 1
            || self.ciphertext.len() > self.purpose.max_bytes().saturating_add(TAG_BYTES)
            || validate_label(&self.label).is_err()
            || !is_valid_timestamp(&self.created_at)
            || self
                .rotated_at
                .as_deref()
                .is_some_and(|value| !is_valid_timestamp(value))
            || !is_valid_timestamp(&self.updated_at)
        {
            return Err(LocalSecretError::CorruptRecord);
        }
        Ok(())
    }

    fn metadata(&self) -> SecretAliasMetadata {
        SecretAliasMetadata {
            id: self.id.clone(),
            label: self.label.clone(),
            provider: SecretProviderKind::LocalEncrypted,
            configured: true,
            version: Some(self.version),
            rotated_at: self.rotated_at.clone(),
        }
    }
}

fn record_from_row(row: &Row<'_>) -> rusqlite::Result<EncryptedSecretRecord> {
    let schema_version = row.get::<_, i64>(1)?;
    let purpose_name = row.get::<_, String>(3)?;
    let version = row.get::<_, i64>(4)?;
    Ok(EncryptedSecretRecord {
        id: row.get(0)?,
        schema_version: u32::try_from(schema_version).unwrap_or(u32::MAX),
        label: row.get(2)?,
        purpose: purpose_from_str(&purpose_name).unwrap_or(SecretPurpose::HeaderApiKey),
        purpose_name,
        version: u64::try_from(version).unwrap_or(u64::MAX),
        algorithm: row.get(5)?,
        key_id: row.get(6)?,
        nonce: row.get(7)?,
        ciphertext: row.get(8)?,
        created_at: row.get(9)?,
        rotated_at: row.get(10)?,
        updated_at: row.get(11)?,
    })
}

fn canonical_aad(
    id: &str,
    version: u64,
    purpose: SecretPurpose,
) -> Result<Vec<u8>, LocalSecretError> {
    let uuid = Uuid::parse_str(id).map_err(|_| LocalSecretError::CorruptRecord)?;
    let purpose = purpose_as_str(purpose).as_bytes();
    let mut aad = Vec::with_capacity(96);
    aad.extend_from_slice(b"greengateway.local-secret");
    aad.push(0);
    aad.extend_from_slice(&LOCAL_SECRET_SCHEMA_VERSION.to_be_bytes());
    aad.extend_from_slice(uuid.as_bytes());
    aad.extend_from_slice(&version.to_be_bytes());
    aad.push(u8::try_from(purpose.len()).map_err(|_| LocalSecretError::CorruptRecord)?);
    aad.extend_from_slice(purpose);
    aad.push(
        u8::try_from(LOCAL_SECRET_FIELD_PURPOSE.len())
            .map_err(|_| LocalSecretError::CorruptRecord)?,
    );
    aad.extend_from_slice(LOCAL_SECRET_FIELD_PURPOSE.as_bytes());
    Ok(aad)
}

fn purpose_as_str(purpose: SecretPurpose) -> &'static str {
    match purpose {
        SecretPurpose::HeaderApiKey => "header_api_key",
        SecretPurpose::StaticBearer => "static_bearer",
        SecretPurpose::OAuthClientSecret => "oauth_client_secret",
        SecretPurpose::TlsPrivateKey => "tls_private_key",
        SecretPurpose::TlsCertificate => "tls_certificate",
        SecretPurpose::TlsCaBundle => "tls_ca_bundle",
    }
}

fn purpose_from_str(value: &str) -> Option<SecretPurpose> {
    match value {
        "header_api_key" => Some(SecretPurpose::HeaderApiKey),
        "static_bearer" => Some(SecretPurpose::StaticBearer),
        "oauth_client_secret" => Some(SecretPurpose::OAuthClientSecret),
        "tls_private_key" => Some(SecretPurpose::TlsPrivateKey),
        "tls_certificate" => Some(SecretPurpose::TlsCertificate),
        "tls_ca_bundle" => Some(SecretPurpose::TlsCaBundle),
        _ => None,
    }
}

fn validate_label(label: &str) -> Result<(), LocalSecretError> {
    if label.is_empty()
        || label.chars().count() > MAX_DISPLAY_NAME_CHARS
        || label.chars().any(char::is_control)
    {
        Err(LocalSecretError::InvalidLabel)
    } else {
        Ok(())
    }
}

fn is_valid_local_secret_id(value: &str) -> bool {
    is_valid_opaque_id(value, MAX_SECRET_ID_BYTES) && Uuid::parse_str(value).is_ok()
}

fn utc_timestamp() -> Result<String, LocalSecretError> {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|_| LocalSecretError::StorageFailure)
}

fn is_valid_timestamp(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && !value.contains('\0')
        && OffsetDateTime::parse(value, &Rfc3339).is_ok()
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
fn validate_root_permissions(metadata: &fs::Metadata) -> Result<(), LocalSecretKeyringConfigError> {
    use std::os::unix::fs::MetadataExt;
    if metadata.mode() & 0o022 == 0 {
        Ok(())
    } else {
        Err(LocalSecretKeyringConfigError::SecretsRootPermissions)
    }
}

#[cfg(not(unix))]
fn validate_root_permissions(_: &fs::Metadata) -> Result<(), LocalSecretKeyringConfigError> {
    Ok(())
}

#[cfg(unix)]
fn validate_key_file_permissions(
    metadata: &fs::Metadata,
    index: usize,
) -> Result<(), LocalSecretKeyringConfigError> {
    use std::os::unix::fs::MetadataExt;
    if metadata.mode() & 0o077 == 0 {
        Ok(())
    } else {
        Err(LocalSecretKeyringConfigError::KeyFilePermissions { index })
    }
}

#[cfg(not(unix))]
fn validate_key_file_permissions(
    _: &fs::Metadata,
    _: usize,
) -> Result<(), LocalSecretKeyringConfigError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use rusqlite::{params, Connection};
    use serde_json::Value;

    use super::*;

    const CANARY: &[u8] = b"greengateway-local-secret-canary";
    const PRIMARY_ID: &str = "primary-key-id-canary";
    const PRIMARY_FILE: &str = "primary.key";

    struct TestEnvironment {
        root: PathBuf,
        database: PathBuf,
    }

    impl TestEnvironment {
        fn new(name: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "greengateway-local-secret-{name}-{}",
                Uuid::new_v4()
            ));
            fs::create_dir(&root).expect("temporary local-secret root should create");
            set_directory_permissions(&root, 0o700);
            let database = root.join("connections.sqlite");
            Self { root, database }
        }

        fn write_key(&self, file: &str, byte: u8) {
            let path = self.root.join(file);
            fs::write(&path, [byte; MASTER_KEY_BYTES]).expect("temporary master key should write");
            set_file_permissions(&path, 0o600);
        }

        fn config(id: &str, file: &str, role: LocalSecretKeyRole) -> LocalSecretKeyConfig {
            LocalSecretKeyConfig {
                id: id.to_owned(),
                file: file.to_owned(),
                role,
            }
        }

        fn load_keyring(
            &self,
            configs: &[LocalSecretKeyConfig],
        ) -> Result<LocalSecretKeyring, LocalSecretKeyringConfigError> {
            LocalSecretKeyring::load(configs, &SecretRootConfig::new(self.root.clone()))
        }

        fn store(&self) -> SqliteConnectionStore {
            SqliteConnectionStore::open(&self.database)
                .expect("temporary connection store should open")
        }

        fn provider(
            &self,
            configs: &[LocalSecretKeyConfig],
        ) -> Result<(SqliteConnectionStore, LocalSecretProvider), LocalSecretError> {
            let store = self.store();
            let keyring = self
                .load_keyring(configs)
                .expect("test keyring should load");
            let provider = LocalSecretProvider::open(&store, keyring, BTreeSet::new())?;
            Ok((store, provider))
        }

        fn primary_config(&self) -> Vec<LocalSecretKeyConfig> {
            vec![Self::config(
                PRIMARY_ID,
                PRIMARY_FILE,
                LocalSecretKeyRole::Primary,
            )]
        }
    }

    impl Drop for TestEnvironment {
        fn drop(&mut self) {
            let expected_prefix = std::env::temp_dir().join("greengateway-local-secret-");
            let root = self
                .root
                .canonicalize()
                .unwrap_or_else(|_| self.root.clone());
            let temp = std::env::temp_dir()
                .canonicalize()
                .unwrap_or_else(|_| std::env::temp_dir());
            if root.starts_with(&temp)
                && self
                    .root
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("greengateway-local-secret-"))
                && expected_prefix.parent() == Some(std::env::temp_dir().as_path())
            {
                let _ = fs::remove_dir_all(&self.root);
            }
        }
    }

    fn secret(purpose: SecretPurpose, value: &[u8]) -> ResolvedSecret {
        ResolvedSecret::new(purpose, value.to_vec()).expect("test secret should validate")
    }

    #[test]
    fn keyring_validation_is_bounded_unique_and_redacted() {
        let configs = vec![
            TestEnvironment::config("primary", "primary.key", LocalSecretKeyRole::Primary),
            TestEnvironment::config("previous", "previous.key", LocalSecretKeyRole::DecryptOnly),
        ];
        validate_local_secret_keyring_config(&configs, true, true)
            .expect("valid keyring config should pass");

        let duplicate = vec![
            configs[0].clone(),
            TestEnvironment::config("primary", "other.key", LocalSecretKeyRole::DecryptOnly),
        ];
        assert!(matches!(
            validate_local_secret_keyring_config(&duplicate, true, true),
            Err(LocalSecretKeyringConfigError::DuplicateKeyId { .. })
        ));
        let traversal = vec![TestEnvironment::config(
            "primary",
            "../primary.key",
            LocalSecretKeyRole::Primary,
        )];
        let error = validate_local_secret_keyring_config(&traversal, true, true)
            .expect_err("traversal must fail");
        assert!(!error.to_string().contains("../primary.key"));

        let debug = format!("{configs:?}");
        assert!(!debug.contains("primary.key"));
        assert!(!debug.contains("previous"));
        assert!(debug.contains("<redacted-key-id>"));
        assert!(debug.contains("<redacted-locator>"));
    }

    #[test]
    fn master_key_files_must_be_safe_regular_exact_length_files() {
        let environment = TestEnvironment::new("key-file-validation");
        environment.write_key(PRIMARY_FILE, 7);
        let config = environment.primary_config();
        environment
            .load_keyring(&config)
            .expect("exact 32-byte key should load");

        fs::write(
            environment.root.join(PRIMARY_FILE),
            [7u8; MASTER_KEY_BYTES - 1],
        )
        .expect("short key should write");
        set_file_permissions(&environment.root.join(PRIMARY_FILE), 0o600);
        assert!(matches!(
            environment.load_keyring(&config),
            Err(LocalSecretKeyringConfigError::InvalidKeyMaterial { index: 0 })
        ));

        fs::remove_file(environment.root.join(PRIMARY_FILE)).expect("short key should remove");
        fs::create_dir(environment.root.join(PRIMARY_FILE))
            .expect("directory at key path should create");
        assert!(matches!(
            environment.load_keyring(&config),
            Err(LocalSecretKeyringConfigError::KeyFileUnsafe { index: 0 })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn master_key_symlinks_and_loose_permissions_fail_closed() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let environment = TestEnvironment::new("key-file-symlink");
        environment.write_key("real.key", 9);
        symlink("real.key", environment.root.join(PRIMARY_FILE))
            .expect("test symlink should create");
        let config = environment.primary_config();
        assert!(matches!(
            environment.load_keyring(&config),
            Err(LocalSecretKeyringConfigError::KeyFileUnsafe { index: 0 })
        ));

        fs::remove_file(environment.root.join(PRIMARY_FILE)).expect("test symlink should remove");
        environment.write_key(PRIMARY_FILE, 9);
        fs::set_permissions(
            environment.root.join(PRIMARY_FILE),
            fs::Permissions::from_mode(0o640),
        )
        .expect("test permissions should change");
        assert!(matches!(
            environment.load_keyring(&config),
            Err(LocalSecretKeyringConfigError::KeyFilePermissions { index: 0 })
        ));
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "requires Windows Developer Mode or SeCreateSymbolicLinkPrivilege"]
    fn windows_master_key_file_symlink_fails_closed() {
        use std::os::windows::fs::symlink_file;

        let environment = TestEnvironment::new("windows-key-symlink");
        environment.write_key("real.key", 10);
        symlink_file(
            environment.root.join("real.key"),
            environment.root.join(PRIMARY_FILE),
        )
        .expect("Windows symbolic-link privilege is required for this ignored test");
        assert!(matches!(
            environment.load_keyring(&environment.primary_config()),
            Err(LocalSecretKeyringConfigError::KeyFileUnsafe { index: 0 })
        ));
    }

    #[tokio::test]
    async fn create_rotate_resolve_and_delete_return_metadata_only() {
        let environment = TestEnvironment::new("lifecycle");
        environment.write_key(PRIMARY_FILE, 11);
        let (_store, provider) = environment
            .provider(&environment.primary_config())
            .expect("provider should open");

        let created = provider
            .create(
                "Billing bearer",
                secret(SecretPurpose::StaticBearer, CANARY),
            )
            .expect("secret should create");
        assert_eq!(created.provider, SecretProviderKind::LocalEncrypted);
        assert_eq!(created.version, Some(1));
        assert_eq!(created.rotated_at, None);
        assert_eq!(provider.metadata(), vec![created.clone()]);
        let serialized = serde_json::to_string(&created).expect("metadata should serialize");
        assert!(!serialized.contains(std::str::from_utf8(CANARY).expect("canary is utf8")));
        assert!(!serialized.contains(PRIMARY_ID));
        assert!(!serialized.contains(PRIMARY_FILE));

        let resolved = provider
            .resolve(&created.id, SecretPurpose::StaticBearer)
            .await
            .expect("secret should resolve");
        assert_eq!(resolved.expose(), CANARY);
        assert_eq!(format!("{resolved:?}"), "<redacted>");

        let rotated_value = b"greengateway-local-secret-rotated";
        let rotated = provider
            .rotate(
                &created.id,
                secret(SecretPurpose::StaticBearer, rotated_value),
            )
            .expect("secret should rotate");
        assert_eq!(rotated.version, Some(2));
        assert!(rotated.rotated_at.is_some());
        let resolved = provider
            .resolve(&created.id, SecretPurpose::StaticBearer)
            .await
            .expect("rotated secret should resolve");
        assert_eq!(resolved.expose(), rotated_value);
        assert!(matches!(
            provider
                .resolve(&created.id, SecretPurpose::HeaderApiKey)
                .await,
            Err(error) if error.kind() == SecretResolveErrorKind::SourceDenied
        ));

        provider
            .delete(&created.id)
            .expect("unused secret should delete");
        assert!(provider.metadata().is_empty());
        assert!(matches!(
            provider
                .resolve(&created.id, SecretPurpose::StaticBearer)
                .await,
            Err(error) if error.kind() == SecretResolveErrorKind::UnknownAlias
        ));
    }

    #[tokio::test]
    async fn invalid_identifiers_and_busy_errors_are_bounded_and_redacted() {
        let environment = TestEnvironment::new("bounded-errors");
        environment.write_key(PRIMARY_FILE, 12);
        let (_store, provider) = environment
            .provider(&environment.primary_config())
            .expect("provider should open");
        let untrusted = format!(
            "{}-secret-and-locator-canary",
            "x".repeat(MAX_SECRET_ID_BYTES + 512)
        );
        assert_eq!(provider.delete(&untrusted), Err(LocalSecretError::NotFound));
        assert!(matches!(
            provider.rotate(&untrusted, secret(SecretPurpose::StaticBearer, CANARY)),
            Err(LocalSecretError::NotFound)
        ));

        let mut busy = provider.clone();
        busy.concurrent_reads = Arc::new(Semaphore::new(0));
        let error = busy
            .resolve(&untrusted, SecretPurpose::StaticBearer)
            .await
            .expect_err("saturated provider must reject immediately");
        assert_eq!(error.kind(), SecretResolveErrorKind::ProviderBusy);
        let message = error.to_string();
        assert!(message.contains("<invalid-alias>"));
        assert!(!message.contains("secret-and-locator-canary"));
        assert!(message.len() < 128);
    }

    #[test]
    fn fresh_nonces_produce_distinct_envelopes_and_plaintext_never_reaches_database_or_wal() {
        let environment = TestEnvironment::new("nonce-and-storage");
        environment.write_key(PRIMARY_FILE, 13);
        let (_store, provider) = environment
            .provider(&environment.primary_config())
            .expect("provider should open");
        let first = provider
            .create("First", secret(SecretPurpose::OAuthClientSecret, CANARY))
            .expect("first secret should create");
        let second = provider
            .create("Second", secret(SecretPurpose::OAuthClientSecret, CANARY))
            .expect("second secret should create");

        let connection = Connection::open(provider.path()).expect("database should open");
        let first_envelope: (Vec<u8>, Vec<u8>) = connection
            .query_row(
                "SELECT nonce, ciphertext FROM connection_local_secrets WHERE id = ?1",
                params![first.id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("first envelope should query");
        let second_envelope: (Vec<u8>, Vec<u8>) = connection
            .query_row(
                "SELECT nonce, ciphertext FROM connection_local_secrets WHERE id = ?1",
                params![second.id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("second envelope should query");
        assert_ne!(first_envelope.0, second_envelope.0);
        assert_ne!(first_envelope.1, second_envelope.1);
        connection
            .execute_batch("PRAGMA wal_checkpoint(FULL);")
            .expect("checkpoint should succeed");

        let canary = std::str::from_utf8(CANARY)
            .expect("canary is utf8")
            .as_bytes();
        for path in [
            environment.database.clone(),
            PathBuf::from(format!("{}-wal", environment.database.display())),
        ] {
            if let Ok(bytes) = fs::read(&path) {
                assert!(
                    !bytes.windows(canary.len()).any(|window| window == canary),
                    "plaintext canary reached {}",
                    path.display()
                );
            }
        }
        let debug = format!("{provider:?}");
        assert!(!debug.contains(PRIMARY_ID));
        assert!(!debug.contains(environment.database.to_string_lossy().as_ref()));
        assert!(!debug.contains(std::str::from_utf8(CANARY).expect("canary is utf8")));
    }

    #[test]
    fn wrong_missing_or_tampered_keys_fail_startup_closed() {
        let environment = TestEnvironment::new("wrong-key");
        environment.write_key(PRIMARY_FILE, 17);
        let configs = environment.primary_config();
        let (store, provider) = environment
            .provider(&configs)
            .expect("provider should open");
        provider
            .create("Bearer", secret(SecretPurpose::StaticBearer, CANARY))
            .expect("secret should create");
        drop(provider);

        environment.write_key(PRIMARY_FILE, 19);
        let wrong_keyring = environment
            .load_keyring(&configs)
            .expect("replacement key should load");
        assert!(matches!(
            LocalSecretProvider::open(&store, wrong_keyring, BTreeSet::new()),
            Err(LocalSecretError::EncryptionFailure)
        ));

        environment.write_key("new.key", 23);
        let missing_old = vec![TestEnvironment::config(
            "new-primary",
            "new.key",
            LocalSecretKeyRole::Primary,
        )];
        let keyring = environment
            .load_keyring(&missing_old)
            .expect("new-only keyring should load");
        assert!(matches!(
            LocalSecretProvider::open(&store, keyring, BTreeSet::new()),
            Err(LocalSecretError::KeyUnavailable)
        ));
    }

    #[test]
    fn aad_changes_ciphertext_swaps_tag_tampering_and_unknown_algorithms_fail_closed() {
        for mutation in ["aad", "swap", "tag", "algorithm"] {
            let environment = TestEnvironment::new(mutation);
            environment.write_key(PRIMARY_FILE, 29);
            let configs = environment.primary_config();
            let (store, provider) = environment
                .provider(&configs)
                .expect("provider should open");
            let first = provider
                .create("First", secret(SecretPurpose::StaticBearer, CANARY))
                .expect("first secret should create");
            let second = provider
                .create(
                    "Second",
                    secret(
                        SecretPurpose::StaticBearer,
                        b"greengateway-local-secret-second",
                    ),
                )
                .expect("second secret should create");
            drop(provider);

            let connection =
                Connection::open(&environment.database).expect("database should open for mutation");
            match mutation {
                "aad" => {
                    connection
                        .execute(
                            "UPDATE connection_local_secrets SET id = ?1 WHERE id = ?2",
                            params![Uuid::new_v4().to_string(), first.id],
                        )
                        .expect("AAD-bound ID should mutate");
                }
                "swap" => {
                    let envelope: (Vec<u8>, Vec<u8>) = connection
                        .query_row(
                            "SELECT nonce, ciphertext FROM connection_local_secrets WHERE id = ?1",
                            params![second.id],
                            |row| Ok((row.get(0)?, row.get(1)?)),
                        )
                        .expect("second envelope should query");
                    connection
                        .execute(
                            "UPDATE connection_local_secrets SET nonce = ?1, ciphertext = ?2 WHERE id = ?3",
                            params![envelope.0, envelope.1, first.id],
                        )
                        .expect("envelope should swap");
                }
                "tag" => {
                    let mut ciphertext: Vec<u8> = connection
                        .query_row(
                            "SELECT ciphertext FROM connection_local_secrets WHERE id = ?1",
                            params![first.id],
                            |row| row.get(0),
                        )
                        .expect("ciphertext should query");
                    let last = ciphertext
                        .last_mut()
                        .expect("ciphertext must include an authentication tag");
                    *last ^= 0x80;
                    connection
                        .execute(
                            "UPDATE connection_local_secrets SET ciphertext = ?1 WHERE id = ?2",
                            params![ciphertext, first.id],
                        )
                        .expect("tag should mutate");
                }
                "algorithm" => {
                    connection
                        .execute(
                            "UPDATE connection_local_secrets SET algorithm = 'unknown-aead' WHERE id = ?1",
                            params![first.id],
                        )
                        .expect("algorithm should mutate");
                }
                _ => unreachable!("test mutation is exhaustive"),
            }
            drop(connection);

            let keyring = environment
                .load_keyring(&configs)
                .expect("keyring should reload");
            let error = match LocalSecretProvider::open(&store, keyring, BTreeSet::new()) {
                Ok(_) => panic!("mutated envelope must fail startup"),
                Err(error) => error,
            };
            assert!(matches!(
                error,
                LocalSecretError::EncryptionFailure | LocalSecretError::CorruptRecord
            ));
            let message = error.to_string();
            assert!(!message.contains(PRIMARY_ID));
            assert!(!message.contains(std::str::from_utf8(CANARY).expect("canary is utf8")));
        }
    }

    #[tokio::test]
    async fn master_key_rotation_is_bounded_transactional_and_allows_verified_removal() {
        let environment = TestEnvironment::new("master-key-rotation");
        environment.write_key("old.key", 31);
        environment.write_key("new.key", 37);
        let old_primary = vec![TestEnvironment::config(
            "old-key",
            "old.key",
            LocalSecretKeyRole::Primary,
        )];
        let (store, old_provider) = environment
            .provider(&old_primary)
            .expect("old provider should open");
        let first = old_provider
            .create("First", secret(SecretPurpose::StaticBearer, CANARY))
            .expect("first secret should create");
        let second = old_provider
            .create(
                "Second",
                secret(
                    SecretPurpose::HeaderApiKey,
                    b"greengateway-local-key-rotation-second",
                ),
            )
            .expect("second secret should create");
        drop(old_provider);

        let rotating = vec![
            TestEnvironment::config("new-key", "new.key", LocalSecretKeyRole::Primary),
            TestEnvironment::config("old-key", "old.key", LocalSecretKeyRole::DecryptOnly),
        ];
        let provider = LocalSecretProvider::open(
            &store,
            environment
                .load_keyring(&rotating)
                .expect("rotating keyring should load"),
            BTreeSet::new(),
        )
        .expect("rotating provider should open");
        assert_eq!(
            provider.ensure_key_unused("old-key"),
            Err(LocalSecretError::KeyStillInUse { count: 2 })
        );
        assert_eq!(
            provider
                .reencrypt_master_key_batch(1)
                .expect("first bounded batch should rotate"),
            MasterKeyRotationProgress {
                reencrypted: 1,
                remaining: 1
            }
        );
        assert_eq!(
            provider
                .reencrypt_master_key_batch(MAX_MASTER_KEY_ROTATION_BATCH)
                .expect("second batch should finish"),
            MasterKeyRotationProgress {
                reencrypted: 1,
                remaining: 0
            }
        );
        provider
            .ensure_key_unused("old-key")
            .expect("old key should be removable only after zero rows remain");
        assert_eq!(
            provider
                .resolve(&first.id, SecretPurpose::StaticBearer)
                .await
                .expect("first secret should survive re-encryption")
                .expose(),
            CANARY
        );

        let new_only = vec![TestEnvironment::config(
            "new-key",
            "new.key",
            LocalSecretKeyRole::Primary,
        )];
        let reopened = LocalSecretProvider::open(
            &store,
            environment
                .load_keyring(&new_only)
                .expect("new-only keyring should load"),
            BTreeSet::new(),
        )
        .expect("new-only provider should open after verified rotation");
        assert_eq!(
            reopened
                .resolve(&second.id, SecretPurpose::HeaderApiKey)
                .await
                .expect("second secret should survive key removal")
                .expose(),
            b"greengateway-local-key-rotation-second"
        );
    }

    #[test]
    fn interrupted_master_key_rotation_rolls_back_the_entire_batch() {
        let environment = TestEnvironment::new("rotation-rollback");
        environment.write_key("old.key", 41);
        environment.write_key("new.key", 43);
        let old_primary = vec![TestEnvironment::config(
            "old-key",
            "old.key",
            LocalSecretKeyRole::Primary,
        )];
        let (store, old_provider) = environment
            .provider(&old_primary)
            .expect("old provider should open");
        old_provider
            .create("First", secret(SecretPurpose::StaticBearer, CANARY))
            .expect("first secret should create");
        old_provider
            .create(
                "Second",
                secret(
                    SecretPurpose::StaticBearer,
                    b"greengateway-rotation-rollback-second",
                ),
            )
            .expect("second secret should create");
        drop(old_provider);

        let rotating = vec![
            TestEnvironment::config("new-key", "new.key", LocalSecretKeyRole::Primary),
            TestEnvironment::config("old-key", "old.key", LocalSecretKeyRole::DecryptOnly),
        ];
        let provider = LocalSecretProvider::open(
            &store,
            environment
                .load_keyring(&rotating)
                .expect("rotating keyring should load"),
            BTreeSet::new(),
        )
        .expect("rotating provider should open");
        let ordered_ids = provider
            .metadata()
            .into_iter()
            .map(|metadata| metadata.id)
            .collect::<Vec<_>>();
        {
            let connection = provider.connection_guard();
            let mut ciphertext: Vec<u8> = connection
                .query_row(
                    "SELECT ciphertext FROM connection_local_secrets WHERE id = ?1",
                    params![ordered_ids[1]],
                    |row| row.get(0),
                )
                .expect("second ciphertext should query");
            ciphertext[0] ^= 0x40;
            connection
                .execute(
                    "UPDATE connection_local_secrets SET ciphertext = ?1 WHERE id = ?2",
                    params![ciphertext, ordered_ids[1]],
                )
                .expect("second ciphertext should tamper");
        }
        assert_eq!(
            provider.reencrypt_master_key_batch(MAX_MASTER_KEY_ROTATION_BATCH),
            Err(LocalSecretError::EncryptionFailure)
        );
        let connection = Connection::open(&environment.database)
            .expect("database should open after failed rotation");
        let non_old_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM connection_local_secrets WHERE key_id <> 'old-key'",
                [],
                |row| row.get(0),
            )
            .expect("key usage should query");
        assert_eq!(
            non_old_count, 0,
            "a failed batch must roll back earlier row updates"
        );
    }

    #[test]
    fn referenced_delete_returns_bounded_safe_dependency_metadata() {
        let environment = TestEnvironment::new("dependency-delete");
        environment.write_key(PRIMARY_FILE, 47);
        let (_store, provider) = environment
            .provider(&environment.primary_config())
            .expect("provider should open");
        let created = provider
            .create("Referenced", secret(SecretPurpose::StaticBearer, CANARY))
            .expect("secret should create");
        let connection =
            Connection::open(&environment.database).expect("database should open for dependency");
        let now = utc_timestamp().expect("timestamp should format");
        connection
            .execute(
                r#"
                INSERT INTO connection_records (
                    id, schema_version, source, spec_json, connection_revision,
                    credential_revision, tls_revision, discovery_revision,
                    status_revision, created_at, updated_at
                ) VALUES ('billing', 'v0.1', 'managed', '{}', 1, 1, 0, 0, 0, ?1, ?1)
                "#,
                params![now],
            )
            .expect("test connection should insert");
        connection
            .execute(
                r#"
                INSERT INTO connection_credential_bindings (
                    connection_id, purpose, secret_id, binding_version, updated_at
                ) VALUES ('billing', 'static_bearer', ?1, 1, ?2)
                "#,
                params![created.id, now],
            )
            .expect("test binding should insert");
        drop(connection);

        assert_eq!(
            provider.delete(&created.id),
            Err(LocalSecretError::DependencyConflict {
                connection_ids: vec!["billing".to_owned()],
                count: 1,
            })
        );
        assert_eq!(provider.metadata().len(), 1);
    }

    #[tokio::test]
    async fn separate_database_and_key_backups_restore_together() {
        let source = TestEnvironment::new("backup-source");
        source.write_key(PRIMARY_FILE, 53);
        let configs = source.primary_config();
        let (store, provider) = source
            .provider(&configs)
            .expect("source provider should open");
        let created = provider
            .create("Backup", secret(SecretPurpose::TlsPrivateKey, CANARY))
            .expect("secret should create");
        provider
            .connection_guard()
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .expect("source database should checkpoint");
        drop(provider);
        drop(store);

        let backup = TestEnvironment::new("backup-restore");
        fs::copy(&source.database, &backup.database)
            .expect("database backup should copy after checkpoint");
        fs::copy(
            source.root.join(PRIMARY_FILE),
            backup.root.join(PRIMARY_FILE),
        )
        .expect("separate key backup should copy");
        set_file_permissions(&backup.root.join(PRIMARY_FILE), 0o600);

        let (backup_store, restored) = backup
            .provider(&backup.primary_config())
            .expect("database plus key backup should restore");
        assert_eq!(
            restored
                .resolve(&created.id, SecretPurpose::TlsPrivateKey)
                .await
                .expect("restored secret should resolve")
                .expose(),
            CANARY
        );
        drop(restored);

        backup.write_key(PRIMARY_FILE, 59);
        let wrong_keyring = backup
            .load_keyring(&backup.primary_config())
            .expect("wrong backup key should load");
        assert!(matches!(
            LocalSecretProvider::open(&backup_store, wrong_keyring, BTreeSet::new()),
            Err(LocalSecretError::EncryptionFailure)
        ));
    }

    #[test]
    fn metadata_json_has_no_envelope_or_keyring_fields() {
        let environment = TestEnvironment::new("metadata-shape");
        environment.write_key(PRIMARY_FILE, 61);
        let (_store, provider) = environment
            .provider(&environment.primary_config())
            .expect("provider should open");
        let metadata = provider
            .create("Metadata", secret(SecretPurpose::TlsCertificate, CANARY))
            .expect("secret should create");
        let value: Value = serde_json::to_value(metadata).expect("safe metadata should serialize");
        let object = value.as_object().expect("metadata should be an object");
        for forbidden in [
            "ciphertext",
            "nonce",
            "algorithm",
            "key_id",
            "purpose",
            "value",
        ] {
            assert!(!object.contains_key(forbidden));
        }
    }

    #[cfg(unix)]
    fn set_directory_permissions(path: &std::path::Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .expect("directory permissions should set");
    }

    #[cfg(not(unix))]
    fn set_directory_permissions(_: &std::path::Path, _: u32) {}

    #[cfg(unix)]
    fn set_file_permissions(path: &std::path::Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .expect("file permissions should set");
    }

    #[cfg(not(unix))]
    fn set_file_permissions(_: &std::path::Path, _: u32) {}
}
