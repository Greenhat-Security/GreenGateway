//! The operator secret alias document (`CONNECTION_SECRET_ALIASES`), the
//! secrets root (`CONNECTION_SECRETS_ROOT`), and the alias, environment-key and
//! file-key grammars every provider document shares.
//!
//! Validation is a function of the document alone. Whether the secrets root
//! exists, is a directory and is safe to read is decided where the gateway
//! opens it (`connections::secret`, which re-exports these).

use std::{
    collections::BTreeMap,
    error::Error,
    fmt,
    path::{Path, PathBuf},
};

use serde::Deserialize;

use super::{MAX_CREDENTIALS, MAX_DISPLAY_NAME_CHARS, MAX_SECRET_ID_BYTES};
use crate::opaque_id::is_valid_opaque_id;

pub const MAX_OPERATOR_SECRET_ALIASES: usize = MAX_CREDENTIALS;
pub const MAX_OPERATOR_SECRET_ALIAS_CONFIG_BYTES: usize = 256 * 1024;
const MAX_ENVIRONMENT_KEY_BYTES: usize = 128;
const MAX_FILE_KEY_BYTES: usize = 255;

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

pub fn is_valid_environment_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ENVIRONMENT_KEY_BYTES
        && value.bytes().enumerate().all(|(index, byte)| {
            byte == b'_'
                || byte.is_ascii_alphanumeric() && (index > 0 || byte.is_ascii_alphabetic())
        })
}

pub fn is_valid_file_key(value: &str) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
