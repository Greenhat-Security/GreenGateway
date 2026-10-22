//! RFC 8785 JSON Canonicalization Scheme (JCS) and the ADR-0004 digest frame,
//! for the values the admin control plane binds stale-safe decisions to.
//!
//! The encoder covers the I-JSON (RFC 7493) value domain those bindings use:
//! objects, arrays, strings, booleans, null, and integers whose magnitude is
//! at most 2^53 - 1. A number outside that domain -- a fraction, an exponent,
//! or a larger integer -- is refused rather than approximated, because JCS
//! serializes numbers the way ECMAScript does and an approximation would give
//! the same value two digests on two platforms. Within the domain the output
//! is exactly the JCS byte sequence: object members sorted by their names'
//! UTF-16 code units, strings escaped as ECMAScript `JSON.stringify` escapes
//! them, and no insignificant whitespace.
//!
//! This is deliberately separate from the key-sorted serialization the
//! policy ETag uses. That one sorts by UTF-8 bytes and is kept unchanged as a
//! compatibility mechanism (ADR-0004, "Canonical digest contract").

use serde_json::{Number, Value};
use sha2::{Digest, Sha256};

/// The largest integer magnitude I-JSON exchanges exactly.
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// Why a value has no canonical form under this encoder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CanonicalJsonError {
    /// A number that is not an integer within the I-JSON safe range.
    UnsupportedNumber,
}

impl std::fmt::Display for CanonicalJsonError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedNumber => {
                formatter.write_str("number is not an integer within the I-JSON safe range")
            }
        }
    }
}

impl std::error::Error for CanonicalJsonError {}

/// The RFC 8785 canonical byte sequence of `value`.
pub(crate) fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>, CanonicalJsonError> {
    let mut out = Vec::new();
    write_value(value, &mut out)?;
    Ok(out)
}

/// `sha256:<hex>` over the ADR-0004 frame of a semantic payload: the JCS
/// bytes of `value`, labelled with the media type and exact schema version
/// that define it.
///
/// ```text
/// "GGDIGEST" 0x00 || u64be(len) "semantic" || u64be(len) media_type
///   || u64be(len) schema_version || u64be(len) JCS(value)
/// ```
pub(crate) fn semantic_digest(
    media_type: &str,
    schema_version: &str,
    value: &Value,
) -> Result<String, CanonicalJsonError> {
    let payload = canonical_json_bytes(value)?;
    Ok(framed_digest(
        b"semantic",
        media_type,
        schema_version,
        &payload,
    ))
}

/// `sha256:<hex>` over the ADR-0004 frame of a source payload: the exact
/// accepted source-document bytes, labelled with the media type and exact
/// schema version that define them.
///
/// ```text
/// "GGDIGEST" 0x00 || u64be(len) "source" || u64be(len) media_type
///   || u64be(len) schema_version || u64be(len) payload
/// ```
pub(crate) fn source_digest(media_type: &str, schema_version: &str, payload: &[u8]) -> String {
    framed_digest(b"source", media_type, schema_version, payload)
}

fn framed_digest(kind: &[u8], media_type: &str, schema_version: &str, payload: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(b"GGDIGEST\0");
    for part in [
        kind,
        media_type.as_bytes(),
        schema_version.as_bytes(),
        payload,
    ] {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part);
    }
    format!("sha256:{}", hex::encode(digest.finalize()))
}

fn write_value(value: &Value, out: &mut Vec<u8>) -> Result<(), CanonicalJsonError> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(number) => write_number(number, out)?,
        Value::String(text) => write_string(text, out),
        Value::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_value(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(map) => {
            // RFC 8785 section 3.2.3: member names compare as arrays of UTF-16
            // code units. That differs from byte or code point order for names
            // outside the Basic Multilingual Plane, so neither `serde_json::Map`
            // iteration nor a `String` sort is used.
            let mut members = map.iter().collect::<Vec<_>>();
            members.sort_by(|(left, _), (right, _)| left.encode_utf16().cmp(right.encode_utf16()));
            out.push(b'{');
            for (index, (name, member)) in members.into_iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_string(name, out);
                out.push(b':');
                write_value(member, out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn write_number(number: &Number, out: &mut Vec<u8>) -> Result<(), CanonicalJsonError> {
    // `serde_json` is built with `arbitrary_precision` here, so a number keeps
    // the text it was parsed from. Only an exact integer is accepted, and it
    // is written from its value, not from that text: `1.0` and `1e0` are not
    // integers to `as_i64`/`as_u64` and are refused.
    if let Some(value) = number.as_u64() {
        if value > MAX_SAFE_INTEGER {
            return Err(CanonicalJsonError::UnsupportedNumber);
        }
        out.extend_from_slice(value.to_string().as_bytes());
        return Ok(());
    }
    if let Some(value) = number.as_i64() {
        if value.unsigned_abs() > MAX_SAFE_INTEGER {
            return Err(CanonicalJsonError::UnsupportedNumber);
        }
        out.extend_from_slice(value.to_string().as_bytes());
        return Ok(());
    }
    Err(CanonicalJsonError::UnsupportedNumber)
}

/// ECMAScript `JSON.stringify` string serialization (RFC 8785 section
/// 3.2.2.2). Rust strings are always well-formed UTF-16 once encoded, so the
/// lone-surrogate escape that rule also covers cannot arise.
fn write_string(text: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for character in text.chars() {
        match character {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{8}' => out.extend_from_slice(b"\\b"),
            '\t' => out.extend_from_slice(b"\\t"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\u{c}' => out.extend_from_slice(b"\\f"),
            '\r' => out.extend_from_slice(b"\\r"),
            control if u32::from(control) < 0x20 => {
                out.extend_from_slice(format!("\\u{:04x}", u32::from(control)).as_bytes());
            }
            other => {
                let mut buffer = [0_u8; 4];
                out.extend_from_slice(other.encode_utf8(&mut buffer).as_bytes());
            }
        }
    }
    out.push(b'"');
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn canonical(value: &Value) -> String {
        String::from_utf8(canonical_json_bytes(value).expect("value should canonicalize"))
            .expect("canonical JSON should be UTF-8")
    }

    #[test]
    fn sorts_member_names_by_utf16_code_units() {
        // RFC 8785 section 3.2.3's sorting example. The emoji's surrogate pair
        // sorts before U+FB33 in UTF-16 even though its code point is larger,
        // which is exactly where UTF-8 or code point order would differ.
        let value: Value = serde_json::from_str(
            r#"{
                "\u20ac": "Euro Sign",
                "\r": "Carriage Return",
                "\ufb33": "Hebrew Letter Dalet With Dagesh",
                "1": "One",
                "\ud83d\ude00": "Emoji: Grinning Face",
                "\u0080": "Control",
                "\u00f6": "Latin Small Letter O With Diaeresis"
            }"#,
        )
        .expect("fixture should parse");

        assert_eq!(
            canonical(&value),
            concat!(
                "{\"\\r\":\"Carriage Return\",",
                "\"1\":\"One\",",
                "\"\u{80}\":\"Control\",",
                "\"\u{f6}\":\"Latin Small Letter O With Diaeresis\",",
                "\"\u{20ac}\":\"Euro Sign\",",
                "\"\u{1f600}\":\"Emoji: Grinning Face\",",
                "\"\u{fb33}\":\"Hebrew Letter Dalet With Dagesh\"}"
            )
        );
    }

    #[test]
    fn writes_nested_values_without_whitespace() {
        let value = json!({
            "b": [true, false, null, {"z": 1, "a": -2}],
            "a": "",
        });

        assert_eq!(
            canonical(&value),
            r#"{"a":"","b":[true,false,null,{"a":-2,"z":1}]}"#
        );
    }

    #[test]
    fn escapes_strings_the_way_ecmascript_does() {
        let value = json!("quote\" backslash\\ \u{8}\t\n\u{c}\r \u{1} \u{1f} \u{7f} / é \u{2028}");

        assert_eq!(
            canonical(&value),
            "\"quote\\\" backslash\\\\ \\b\\t\\n\\f\\r \\u0001 \\u001f \u{7f} / é \u{2028}\""
        );
    }

    #[test]
    fn accepts_only_safe_integers() {
        assert_eq!(
            canonical(&json!(9_007_199_254_740_991_u64)),
            "9007199254740991"
        );
        assert_eq!(
            canonical(&json!(-9_007_199_254_740_991_i64)),
            "-9007199254740991"
        );
        assert_eq!(canonical(&json!(0)), "0");

        for unsupported in ["9007199254740992", "-9007199254740992", "1.5", "1.0", "1e3"] {
            let value: Value = serde_json::from_str(unsupported).expect("number should parse");
            assert_eq!(
                canonical_json_bytes(&value),
                Err(CanonicalJsonError::UnsupportedNumber),
                "{unsupported} must not canonicalize"
            );
        }
    }

    #[test]
    fn digest_frames_the_semantic_payload() {
        // Computed independently from the ADR-0004 frame definition:
        // SHA-256(b"GGDIGEST\0" + framed("semantic") + framed(media type)
        //   + framed(schema version) + framed(b'{"a":1,"b":"x"}')).
        let digest = semantic_digest("application/json", "0.1.0", &json!({"b": "x", "a": 1}))
            .expect("digest should compute");

        assert_eq!(digest, SEMANTIC_DIGEST_VECTOR);
    }

    #[test]
    fn digest_binds_media_type_and_schema_version() {
        let value = json!({"a": 1});
        let base = semantic_digest("application/json", "0.1.0", &value).expect("digest");

        assert_ne!(
            base,
            semantic_digest("application/json", "0.1.1", &value).expect("digest")
        );
        assert_ne!(
            base,
            semantic_digest("application/vnd.example+json", "0.1.0", &value).expect("digest")
        );
        assert_eq!(
            semantic_digest("application/json", "0.1.0", &json!(1.5)),
            Err(CanonicalJsonError::UnsupportedNumber)
        );
    }

    #[test]
    fn source_digest_frames_the_exact_payload_bytes() {
        // Computed independently from the ADR-0004 frame definition:
        // SHA-256(b"GGDIGEST\0" + framed("source") + framed(media type)
        //   + framed(schema version) + framed(b"a: 1\n")).
        let digest = source_digest(
            "application/vnd.greengateway.bundle+yaml",
            "greengateway.dev/v1alpha1",
            b"a: 1\n",
        );

        assert_eq!(digest, SOURCE_DIGEST_VECTOR);
        // Formatting is significant to a source digest, unlike a semantic one.
        assert_ne!(
            digest,
            source_digest(
                "application/vnd.greengateway.bundle+yaml",
                "greengateway.dev/v1alpha1",
                b"a:  1\n",
            )
        );
    }

    const SOURCE_DIGEST_VECTOR: &str =
        "sha256:f617734214f1fe485e45f01f36000685233f8e82c0c327cc1099d8cdf1d89c6f";

    const SEMANTIC_DIGEST_VECTOR: &str =
        "sha256:124516292c7c3fd03616bc36b37cb73344539155601465c400929d4ab5ca6184";
}
