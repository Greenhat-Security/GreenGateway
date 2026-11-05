//! The Connections settings the configuration compiler validates (issue
//! #242): the operator alias, local keyring and secret provider documents
//! (`CONNECTION_*`), the limits they share with the Connections model, the
//! Connection ID grammar, and the origin-relative path grammar a Connection's
//! paths and an HTTP tool definition's path template are both held to.
//!
//! Every validator here is a function of the document it is given. None opens
//! a file, resolves a name or contacts a provider; the checks that need the
//! world (a secrets root that exists, a key file of the right shape, a
//! provider that answers) happen where the gateway builds its resolvers, in its
//! `connections` modules of the same names, which re-export these.

pub mod aws_secret;
pub mod azure_secret;
pub mod gcp_secret;
pub mod kubernetes_secret;
pub mod local_secret;
pub mod secret;
pub mod vault_secret;

use std::fmt;

use percent_encoding::percent_decode_str;

use crate::opaque_id::{is_valid_opaque_id, MAX_SECRET_ALIAS_ID_BYTES};

/// The most credentials, and so the most secret aliases of any one provider, a
/// Connections deployment holds.
pub const MAX_CREDENTIALS: usize = 512;
/// The longest Connection ID, in bytes.
pub const MAX_CONNECTION_ID_BYTES: usize = 128;
/// The longest display name or alias label, in characters.
pub const MAX_DISPLAY_NAME_CHARS: usize = 128;
/// The longest secret alias, key or profile ID, in bytes.
pub const MAX_SECRET_ID_BYTES: usize = MAX_SECRET_ALIAS_ID_BYTES;

/// The longest origin-relative path a Connection or an HTTP tool mapping
/// names, in bytes.
pub const MAX_PATH_BYTES: usize = 1_024;

/// Whether `value` is a Connection ID: an opaque ID of at most
/// [`MAX_CONNECTION_ID_BYTES`] bytes (URL-safe ASCII, starting with a letter or
/// digit).
pub fn is_valid_connection_id(value: &str) -> bool {
    is_valid_opaque_id(value, MAX_CONNECTION_ID_BYTES)
}

/// One problem with a Connection field: the field, a stable code and a
/// message for the operator who wrote it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionValidationError {
    pub field: &'static str,
    pub code: &'static str,
    pub message: String,
}

impl ConnectionValidationError {
    pub fn new(field: &'static str, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            field,
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for ConnectionValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.field, self.message)
    }
}

/// Normalizes an origin-relative path: one that names no authority, query,
/// fragment or backslash form, has no dot segment or encoded separator, and
/// is at most [`MAX_PATH_BYTES`] long. A trailing `/` is dropped from any
/// path but `/`.
pub fn normalize_origin_relative_path(
    field: &'static str,
    value: &str,
) -> Result<String, ConnectionValidationError> {
    if value.is_empty()
        || value.len() > MAX_PATH_BYTES
        || !value.starts_with('/')
        || value.starts_with("//")
        || value.contains("//")
        || value.contains(['?', '#', '\\'])
        || value.bytes().any(|byte| byte <= b' ' || byte == 0x7f)
        || has_invalid_percent_escape(value)
    {
        return Err(ConnectionValidationError::new(
            field,
            "invalid_origin_relative_path",
            format!(
                "must be an origin-relative path of 1-{MAX_PATH_BYTES} bytes without authority, query, fragment, or backslash forms"
            ),
        ));
    }

    for segment in value.split('/') {
        let decoded = percent_decode_str(segment).decode_utf8().map_err(|_| {
            ConnectionValidationError::new(
                field,
                "invalid_percent_encoding",
                "must contain valid UTF-8 percent encoding",
            )
        })?;
        if matches!(decoded.as_ref(), "." | "..")
            || decoded.contains('/')
            || decoded.contains('\\')
            || decoded.contains('\0')
        {
            return Err(ConnectionValidationError::new(
                field,
                "path_confusion",
                "must not contain dot segments or encoded path separators",
            ));
        }
    }

    if value.len() > 1 {
        Ok(value.trim_end_matches('/').to_owned())
    } else {
        Ok(value.to_owned())
    }
}

fn has_invalid_percent_escape(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return true;
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_ids_are_bounded_url_safe_opaque_ids() {
        assert!(is_valid_connection_id("legacy-default-http"));
        assert!(is_valid_connection_id("a"));
        assert!(is_valid_connection_id(&"a".repeat(MAX_CONNECTION_ID_BYTES)));
        for refused in [
            "",
            "../secret",
            "mcp/server",
            ".hidden",
            "-dash",
            "_under",
            "with space",
            "caf\u{e9}",
        ] {
            assert!(!is_valid_connection_id(refused), "{refused:?}");
        }
        assert!(!is_valid_connection_id(
            &"a".repeat(MAX_CONNECTION_ID_BYTES + 1)
        ));
    }
}
