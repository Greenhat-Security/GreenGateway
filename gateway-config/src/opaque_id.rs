//! ADR-0006's opaque identifier grammar, shared by the gateway's secret
//! aliases and the configuration bundle's secret references.

/// The longest secret alias ID: `MAX_SECRET_ID_BYTES` in
/// `gateway/src/connections/model.rs`, which a gateway test holds equal.
pub const MAX_SECRET_ALIAS_ID_BYTES: usize = 128;

/// Whether `value` is an opaque ID of at most `maximum` bytes: ASCII letters
/// and digits, with `.`, `_` and `-` allowed after the first byte. The
/// grammar cannot express a path, an environment-variable reference, a URL
/// or whitespace.
pub fn is_valid_opaque_id(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().enumerate().all(|(index, byte)| match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' => true,
            b'.' | b'_' | b'-' => index > 0,
            _ => false,
        })
}
