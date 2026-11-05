//! The local encrypted secret keyring document
//! (`CONNECTION_LOCAL_SECRET_KEYRING`) and its validator.
//!
//! Validation is a function of the document alone: it reads no key file. The
//! gateway's `connections::local_secret`, which re-exports these, opens the
//! key files beneath the secrets root and checks their permissions and length.

use std::{collections::BTreeMap, error::Error, fmt};

use serde::Deserialize;

use super::{secret::is_valid_file_key, MAX_SECRET_ID_BYTES};
use crate::opaque_id::is_valid_opaque_id;

pub const MAX_LOCAL_SECRET_KEYS: usize = 8;
pub const MAX_LOCAL_SECRET_KEYRING_CONFIG_BYTES: usize = 16 * 1024;

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

#[cfg(test)]
mod tests {
    use super::*;

    fn config(id: &str, file: &str, role: LocalSecretKeyRole) -> LocalSecretKeyConfig {
        LocalSecretKeyConfig {
            id: id.to_owned(),
            file: file.to_owned(),
            role,
        }
    }

    #[test]
    fn keyring_validation_is_bounded_unique_and_redacted() {
        let configs = vec![
            config("primary", "primary.key", LocalSecretKeyRole::Primary),
            config("previous", "previous.key", LocalSecretKeyRole::DecryptOnly),
        ];
        validate_local_secret_keyring_config(&configs, true, true)
            .expect("valid keyring config should pass");

        let duplicate = vec![
            configs[0].clone(),
            config("primary", "other.key", LocalSecretKeyRole::DecryptOnly),
        ];
        assert!(matches!(
            validate_local_secret_keyring_config(&duplicate, true, true),
            Err(LocalSecretKeyringConfigError::DuplicateKeyId { .. })
        ));
        let traversal = vec![config(
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
}
