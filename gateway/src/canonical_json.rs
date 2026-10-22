//! RFC 8785 JSON Canonicalization Scheme (JCS) and the ADR-0004 digest frame,
//! for the values the admin control plane binds stale-safe decisions to.
//!
//! The encoder covers the I-JSON (RFC 7493) value domain those bindings use:
//! objects, arrays, strings, booleans, null, and numbers whose magnitude is at
//! most 2^53 - 1. Within that range a number may carry a fraction or an
//! exponent: JCS writes the IEEE 754 double nearest its source text the way
//! ECMAScript's `Number.prototype.toString` does, which depends only on the
//! shortest round-tripping digits of that double -- a platform-independent
//! quantity -- so `1.0`, `1e0` and `1` are one value with one encoding. A
//! number outside the range is refused rather than approximated: integers
//! there are not all representable, so two different source values would
//! share an encoding and a digest over it would bind neither. Within the
//! domain the output is exactly the JCS byte sequence: object members sorted
//! by their names' UTF-16 code units, strings escaped as ECMAScript
//! `JSON.stringify` escapes them, and no insignificant whitespace.
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
    /// A number that is not finite, or whose magnitude exceeds the I-JSON
    /// safe range.
    UnsupportedNumber,
}

impl std::fmt::Display for CanonicalJsonError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedNumber => {
                formatter.write_str("number is not within the I-JSON safe range")
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
        "semantic",
        media_type,
        schema_version,
        &payload,
    ))
}

/// `sha256:<hex>` over the ADR-0004 frame of a source payload: the exact
/// accepted source-document bytes, neither parsed nor normalized, labelled
/// the same way a semantic payload is.
pub(crate) fn source_digest(media_type: &str, schema_version: &str, source: &[u8]) -> String {
    framed_digest("source", media_type, schema_version, source)
}

fn framed_digest(kind: &str, media_type: &str, schema_version: &str, payload: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(b"GGDIGEST\0");
    for part in [
        kind.as_bytes(),
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
    // the text it was parsed from. That text is never copied. An integer token
    // is written from its value; anything else -- a fraction, an exponent, or
    // an integer too long for 64 bits -- is read as the double nearest its
    // text and written the way ECMAScript writes that double, so `1.0`, `1e0`
    // and `1` all become `1`.
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
    // `None` for text that is not a finite double, which includes a number
    // forged through serde_json's private number tag.
    let value = number
        .as_f64()
        .ok_or(CanonicalJsonError::UnsupportedNumber)?;
    // Every double at or beyond 2^53 is an integer outside the safe range.
    if value.abs() > MAX_SAFE_INTEGER as f64 {
        return Err(CanonicalJsonError::UnsupportedNumber);
    }
    out.extend_from_slice(ecmascript_number(value)?.as_bytes());
    Ok(())
}

/// ECMAScript `Number::toString(x)` for a finite double (RFC 8785 section
/// 3.2.2.3; ECMA-262 `Number::toString`).
///
/// The specification asks for the fewest decimal digits `s`, with exponent
/// `n`, that still identify `x`; among those for the digits closest to `x`;
/// and of two equally close, for the even one. Rust's `{:e}` prints the
/// shortest round-trip digits, so it fixes how many digits there are, but it
/// breaks that last tie upward: for `0x43143ff3c1cb0959`, exactly
/// `1424953923781206.25`, it prints `...063` where ECMAScript writes `...062`.
/// `{:.p$e}` instead rounds the exact binary value to that many digits with
/// ties to even, which is the closest such decimal. When that decimal still
/// identifies `x` it is the one the specification chooses; when it does not
/// (only possible where the rounding interval is lopsided, at a power of
/// two), the closest one that does is the shortest form `{:e}` found. Only
/// the layout rules follow: plain digits up to 21 integer places, a leading
/// `0.` down to 10^-6, and exponent notation with an explicit sign
/// otherwise. RFC 8785 Appendix B's vectors pin the result.
fn ecmascript_number(value: f64) -> Result<String, CanonicalJsonError> {
    if !value.is_finite() {
        return Err(CanonicalJsonError::UnsupportedNumber);
    }
    // Both zeros: negative zero is written "0".
    if value == 0.0 {
        return Ok("0".to_owned());
    }
    let mut text = String::new();
    if value < 0.0 {
        text.push('-');
    }
    let magnitude = value.abs();
    let shortest = format!("{magnitude:e}");
    let shortest_digits = shortest
        .split_once('e')
        .map(|(mantissa, _)| mantissa.chars().filter(char::is_ascii_digit).count())
        .ok_or(CanonicalJsonError::UnsupportedNumber)?;
    let nearest = format!(
        "{magnitude:.precision$e}",
        precision = shortest_digits.saturating_sub(1)
    );
    let scientific = if nearest.parse::<f64>() == Ok(magnitude) {
        nearest
    } else {
        shortest
    };
    let (mantissa, exponent) = scientific
        .split_once('e')
        .ok_or(CanonicalJsonError::UnsupportedNumber)?;
    let exponent: i64 = exponent
        .parse()
        .map_err(|_| CanonicalJsonError::UnsupportedNumber)?;
    let digits: String = mantissa
        .chars()
        .filter(|character| *character != '.')
        .collect();
    let digits = digits.trim_end_matches('0');
    if digits.is_empty() {
        return Err(CanonicalJsonError::UnsupportedNumber);
    }
    // In the specification's terms `x = s * 10^(n - k)` for the `k` digits of
    // `s`; `{:e}` reports `d.ddd * 10^exponent`, so `n = exponent + 1`.
    let k = digits.len() as i64;
    let n = exponent + 1;
    if k <= n && n <= 21 {
        text.push_str(digits);
        text.extend(std::iter::repeat_n('0', (n - k) as usize));
    } else if 0 < n && n <= 21 {
        let (integer, fraction) = digits.split_at(n as usize);
        text.push_str(integer);
        text.push('.');
        text.push_str(fraction);
    } else if -6 < n && n <= 0 {
        text.push_str("0.");
        text.extend(std::iter::repeat_n('0', (-n) as usize));
        text.push_str(digits);
    } else {
        let (first, rest) = digits.split_at(1);
        text.push_str(first);
        if !rest.is_empty() {
            text.push('.');
            text.push_str(rest);
        }
        text.push('e');
        text.push(if n > 0 { '+' } else { '-' });
        text.push_str(&(n - 1).unsigned_abs().to_string());
    }
    Ok(text)
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
    fn accepts_numbers_within_the_safe_range_and_refuses_the_rest() {
        assert_eq!(
            canonical(&json!(9_007_199_254_740_991_u64)),
            "9007199254740991"
        );
        assert_eq!(
            canonical(&json!(-9_007_199_254_740_991_i64)),
            "-9007199254740991"
        );
        assert_eq!(canonical(&json!(0)), "0");
        assert_eq!(canonical(&json!(20.0_f64)), "20");
        assert_eq!(canonical(&json!(0.25_f64)), "0.25");

        // A fraction or an exponent is the double nearest its text, written as
        // ECMAScript writes it: the source spelling never survives.
        for (source, expected) in [
            ("1.5", "1.5"),
            ("1.0", "1"),
            ("1e3", "1000"),
            ("1E+3", "1000"),
            ("0.5", "0.5"),
            ("-0", "0"),
            ("-0.0", "0"),
            ("0.1", "0.1"),
            ("1e-7", "1e-7"),
            ("0.000001", "0.000001"),
            ("123.456e1", "1234.56"),
            ("0.30000000000000001", "0.3"),
            ("9007199254740991.0", "9007199254740991"),
            ("-9007199254740991.0", "-9007199254740991"),
            // Exact binary values halfway between the two nearest shortest
            // decimals: ECMAScript takes the even one, where Rust's shortest
            // formatting would round up. Checked against Node's
            // `Number.prototype.toString`.
            ("1424953923781206.25", "1424953923781206.2"),
            ("-1718043322977948.25", "-1718043322977948.2"),
            ("943656659140389.25", "943656659140389.2"),
            ("265906862195952.625", "265906862195952.62"),
            ("204203881532002.125", "204203881532002.12"),
            ("10833678074757.8125", "10833678074757.812"),
        ] {
            let value: Value = serde_json::from_str(source).expect("number should parse");
            assert_eq!(canonical(&value), expected, "{source}");
        }

        for unsupported in [
            "9007199254740992",
            "-9007199254740992",
            "9007199254740992.0",
            "18446744073709551616",
            "1e16",
            "1e400",
            "-1e400",
        ] {
            let value: Value = serde_json::from_str(unsupported).expect("number should parse");
            assert_eq!(
                canonical_json_bytes(&value),
                Err(CanonicalJsonError::UnsupportedNumber),
                "{unsupported} must not canonicalize"
            );
        }
    }

    #[test]
    fn a_number_spelled_through_the_private_tag_is_written_from_its_value() {
        // With `arbitrary_precision`, an object carrying serde_json's private
        // number tag deserializes into a `Number` holding the tagged text. The
        // encoder writes the value, never that text, so the tag cannot carry
        // a spelling of its own into the canonical bytes.
        let forged: Value = serde_json::from_str(r#"{"$serde_json::private::Number":"1.50"}"#)
            .expect("the tagged number should parse");

        assert!(forged.is_number());
        assert_eq!(canonical(&forged), "1.5");
    }

    #[test]
    fn serializes_doubles_as_rfc_8785_appendix_b_does() {
        // RFC 8785 Appendix B: IEEE 754 bit patterns and their JCS text. The
        // encoder reaches only the in-range rows, but the serializer must
        // produce every row, or the in-range rows are right by accident.
        for (bits, expected) in [
            (0x0000_0000_0000_0000_u64, "0"),
            (0x8000_0000_0000_0000, "0"),
            (0x0000_0000_0000_0001, "5e-324"),
            (0x8000_0000_0000_0001, "-5e-324"),
            (0x7fef_ffff_ffff_ffff, "1.7976931348623157e+308"),
            (0xffef_ffff_ffff_ffff, "-1.7976931348623157e+308"),
            (0x4340_0000_0000_0000, "9007199254740992"),
            (0xc340_0000_0000_0000, "-9007199254740992"),
            (0x4430_0000_0000_0000, "295147905179352830000"),
            (0x44b5_2d02_c7e1_4af5, "9.999999999999997e+22"),
            (0x44b5_2d02_c7e1_4af6, "1e+23"),
            (0x44b5_2d02_c7e1_4af7, "1.0000000000000001e+23"),
            (0x444b_1ae4_d6e2_ef4e, "999999999999999700000"),
            (0x444b_1ae4_d6e2_ef4f, "999999999999999900000"),
            (0x444b_1ae4_d6e2_ef50, "1e+21"),
            (0x3eb0_c6f7_a0b5_ed8c, "9.999999999999997e-7"),
            (0x3eb0_c6f7_a0b5_ed8d, "0.000001"),
            (0x41b3_de43_5555_5553, "333333333.3333332"),
            (0x41b3_de43_5555_5554, "333333333.33333325"),
            (0x41b3_de43_5555_5555, "333333333.3333333"),
            (0x41b3_de43_5555_5556, "333333333.3333334"),
            (0x41b3_de43_5555_5557, "333333333.33333343"),
            (0xbecb_f647_612f_3696, "-0.0000033333333333333333"),
            (0x4314_3ff3_c1cb_0959, "1424953923781206.2"),
        ] {
            assert_eq!(
                ecmascript_number(f64::from_bits(bits)).as_deref(),
                Ok(expected),
                "{bits:016x}"
            );
        }
        for bits in [0x7fff_ffff_ffff_ffff_u64, 0x7ff0_0000_0000_0000] {
            assert_eq!(
                ecmascript_number(f64::from_bits(bits)),
                Err(CanonicalJsonError::UnsupportedNumber)
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
        let unsupported: Value = serde_json::from_str("1e300").expect("number should parse");
        assert_eq!(
            semantic_digest("application/json", "0.1.0", &unsupported),
            Err(CanonicalJsonError::UnsupportedNumber)
        );
    }

    #[test]
    fn source_digest_frames_the_exact_bytes() {
        // Computed independently from the ADR-0004 frame definition:
        // SHA-256(b"GGDIGEST\0" + framed("source") + framed(media type)
        //   + framed(schema version) + framed(b'{"b":"x", "a":1}')).
        let digest = source_digest("application/json", "0.1.0", br#"{"b":"x", "a":1}"#);

        assert_eq!(digest, SOURCE_DIGEST_VECTOR);
        // The bytes are hashed as given: other whitespace is another digest,
        // and so is the semantic frame over the same canonical bytes.
        assert_ne!(
            source_digest("application/json", "0.1.0", br#"{"b":"x","a":1}"#),
            digest
        );
        assert_ne!(
            source_digest("application/json", "0.1.0", br#"{"a":1,"b":"x"}"#),
            SEMANTIC_DIGEST_VECTOR
        );
    }

    const SEMANTIC_DIGEST_VECTOR: &str =
        "sha256:124516292c7c3fd03616bc36b37cb73344539155601465c400929d4ab5ca6184";
    const SOURCE_DIGEST_VECTOR: &str =
        "sha256:e6c6b953a0920d9d98079cbf0a70bed945601726e770b7f4b5bf914710cee3eb";
}
