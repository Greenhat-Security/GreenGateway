//! The stable upstream route ID grammar.
//!
//! The configuration compiler holds `UPSTREAM_ROUTES` ids to it, and policy
//! validation holds the route ids a rule names to the same grammar, so the two
//! can never disagree about which routes exist. The gateway reads it through
//! its `upstream_route` re-export.

/// The longest stable route ID, in bytes.
pub const STABLE_ROUTE_ID_MAX_LEN: usize = 64;

/// Whether `value` is a stable route ID: 1 to [`STABLE_ROUTE_ID_MAX_LEN`]
/// ASCII letters and digits, with `.`, `_` and `-` allowed after the first
/// byte.
pub fn is_valid_stable_route_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= STABLE_ROUTE_ID_MAX_LEN
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'.' | b'_' | b'-'))
        })
}
