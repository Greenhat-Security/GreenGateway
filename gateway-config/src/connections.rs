//! The Connections settings the configuration compiler validates (issue
//! #242): the operator alias, local keyring and secret provider documents
//! (`CONNECTION_*`), the limits they share with the Connections model, and the
//! Connection ID grammar.
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

/// Whether `value` is a Connection ID: an opaque ID of at most
/// [`MAX_CONNECTION_ID_BYTES`] bytes (URL-safe ASCII, starting with a letter or
/// digit).
pub fn is_valid_connection_id(value: &str) -> bool {
    is_valid_opaque_id(value, MAX_CONNECTION_ID_BYTES)
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
