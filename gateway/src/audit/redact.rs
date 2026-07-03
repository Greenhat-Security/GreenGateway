use sha2::{Digest, Sha256};

pub fn sha256_hex(input: &[u8]) -> String {
    let digest = Sha256::digest(input);
    format!("sha256:{}", hex::encode(digest))
}

#[allow(dead_code)] // Credential-bearing audit events are introduced with auth in issue #5.
pub fn hash_credential(token: &str) -> String {
    sha256_hex(token.as_bytes())
}

/// Hashes JSON using serde_json's default sorted object-key serialization.
/// Enabling serde_json's `preserve_order` feature anywhere in the dependency
/// tree would change hashes for logically identical JSON objects.
#[allow(dead_code)] // Tool/policy audit payload hashing is introduced in later MCP issues.
pub fn hash_args(args: &serde_json::Value) -> String {
    let canonical = serde_json::to_string(args).expect("serde_json::Value should serialize");
    sha256_hex(canonical.as_bytes())
}

#[allow(dead_code)] // Request/auth audit payload redaction is wired when those events are added.
pub fn redact_string(s: &str, keep_start: usize, keep_end: usize) -> String {
    let char_count = s.chars().count();
    if char_count <= keep_start.saturating_add(keep_end) {
        return "[REDACTED]".to_owned();
    }

    let start: String = s.chars().take(keep_start).collect();
    let end: String = s.chars().skip(char_count - keep_end).collect();

    format!("{start}***{end}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sha256_hex_uses_known_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn hash_credential_never_returns_raw_token() {
        let token = "secret-token";
        let hashed = hash_credential(token);

        assert!(hashed.starts_with("sha256:"));
        assert_ne!(hashed, token);
        assert_eq!(hashed, sha256_hex(token.as_bytes()));
    }

    #[test]
    fn hash_args_hashes_canonical_json() {
        let args = json!({
            "path": "/admin",
            "method": "POST"
        });
        let canonical = serde_json::to_string(&args).expect("test JSON should serialize");

        assert_eq!(hash_args(&args), sha256_hex(canonical.as_bytes()));
    }

    #[test]
    fn redact_string_keeps_edges() {
        assert_eq!(redact_string("abcdef", 2, 2), "ab***ef");
        assert_eq!(redact_string("abcdef", 0, 2), "***ef");
        assert_eq!(redact_string("abcdef", 2, 0), "ab***");
    }

    #[test]
    fn redact_string_redacts_short_values() {
        assert_eq!(redact_string("abcd", 2, 2), "[REDACTED]");
        assert_eq!(redact_string("abc", 2, 2), "[REDACTED]");
    }

    #[test]
    fn redact_string_is_char_safe_for_multibyte_input() {
        assert_eq!(redact_string("åßçdé", 1, 1), "å***é");
    }
}
