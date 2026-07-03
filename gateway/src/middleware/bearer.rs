//! Shared bearer authorization header parsing.

use http::{header::AUTHORIZATION, HeaderMap, HeaderValue};

pub(crate) fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(AUTHORIZATION).and_then(header_value_to_str)?;
    let mut parts = value.trim_start().splitn(2, char::is_whitespace);
    let scheme = parts.next().unwrap_or_default();
    let token = parts.next().unwrap_or_default().trim();

    (scheme.eq_ignore_ascii_case("Bearer") && !token.is_empty()).then_some(token)
}

fn header_value_to_str(value: &HeaderValue) -> Option<&str> {
    value.to_str().ok()
}
