use std::str::FromStr;

use serde_json::{Number, Value};

use super::{CodecError, DecimalWireEncoding};

pub fn encode(
    value: Value,
    scale: u8,
    wire_encoding: DecimalWireEncoding,
    max_integer_digits: u8,
) -> Result<Value, CodecError> {
    validate_options(scale, max_integer_digits)?;
    let Value::Number(number) = value else {
        return Err(CodecError::new("agent value must be a JSON number"));
    };
    let integer = scaled_integer_text(&number.to_string(), scale)?;
    enforce_integer_digits(&integer, max_integer_digits)?;

    match wire_encoding {
        DecimalWireEncoding::IntegerString => Ok(Value::String(integer)),
        DecimalWireEncoding::Integer => Number::from_str(&integer)
            .map(Value::Number)
            .map_err(|_| CodecError::new("scaled value is not a valid JSON integer")),
    }
}

pub fn decode(
    value: Value,
    scale: u8,
    wire_encoding: DecimalWireEncoding,
    max_integer_digits: u8,
) -> Result<Value, CodecError> {
    validate_options(scale, max_integer_digits)?;
    let integer = match (wire_encoding, value) {
        (DecimalWireEncoding::IntegerString, Value::String(value)) => value,
        (DecimalWireEncoding::Integer, Value::Number(value)) => value.to_string(),
        (DecimalWireEncoding::IntegerString, _) => {
            return Err(CodecError::new(
                "wire value must be a canonical integer string",
            ));
        }
        (DecimalWireEncoding::Integer, _) => {
            return Err(CodecError::new("wire value must be a JSON integer"));
        }
    };

    validate_canonical_integer(&integer)?;
    enforce_integer_digits(&integer, max_integer_digits)?;
    let decimal = unscale_integer_text(&integer, scale);
    Number::from_str(&decimal)
        .map(Value::Number)
        .map_err(|_| CodecError::new("decoded value is not a valid JSON number"))
}

fn validate_options(scale: u8, max_integer_digits: u8) -> Result<(), CodecError> {
    if scale > 18 {
        return Err(CodecError::new("decimal scale must be at most 18"));
    }
    if !(1..=38).contains(&max_integer_digits) {
        return Err(CodecError::new(
            "maximum integer digits must be between 1 and 38",
        ));
    }
    Ok(())
}

fn scaled_integer_text(token: &str, scale: u8) -> Result<String, CodecError> {
    let (negative, unsigned) = token
        .strip_prefix('-')
        .map_or((false, token), |unsigned| (true, unsigned));
    let has_exponent = unsigned.contains(['e', 'E']);
    let (mantissa, exponent) = split_exponent(unsigned)?;
    let (whole, fraction) = mantissa
        .split_once('.')
        .map_or((mantissa, ""), |(whole, fraction)| (whole, fraction));

    if whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(CodecError::new("agent value is not a valid JSON decimal"));
    }
    if !has_exponent && fraction.len() > usize::from(scale) {
        return Err(CodecError::new(format!(
            "value has {} fraction digits, codec allows {scale}",
            fraction.len()
        )));
    }

    let mut coefficient = String::with_capacity(whole.len().saturating_add(fraction.len()));
    coefficient.push_str(whole);
    coefficient.push_str(fraction);
    let decimal_shift = i64::from(exponent)
        .checked_add(i64::from(scale))
        .and_then(|shift| shift.checked_sub(i64::try_from(fraction.len()).ok()?))
        .ok_or_else(|| CodecError::new("decimal exponent is outside the supported range"))?;

    if decimal_shift >= 0 {
        let zeros = usize::try_from(decimal_shift)
            .map_err(|_| CodecError::new("decimal exponent is outside the supported range"))?;
        if zeros > 38 {
            return Err(CodecError::new(
                "scaled integer exceeds the configured digit limit",
            ));
        }
        coefficient.extend(std::iter::repeat_n('0', zeros));
    } else {
        let remove = usize::try_from(-decimal_shift)
            .map_err(|_| CodecError::new("decimal exponent is outside the supported range"))?;
        if remove > coefficient.len()
            || !coefficient[coefficient.len() - remove..]
                .bytes()
                .all(|byte| byte == b'0')
        {
            return Err(CodecError::new(format!(
                "value has fractional precision beyond scale {scale}"
            )));
        }
        coefficient.truncate(coefficient.len() - remove);
    }

    let canonical = coefficient.trim_start_matches('0');
    let canonical = if canonical.is_empty() { "0" } else { canonical };
    if negative && canonical != "0" {
        Ok(format!("-{canonical}"))
    } else {
        Ok(canonical.to_owned())
    }
}

fn split_exponent(token: &str) -> Result<(&str, i32), CodecError> {
    let split = token.find(['e', 'E']);
    let Some(index) = split else {
        return Ok((token, 0));
    };
    let mantissa = &token[..index];
    let exponent = &token[index + 1..];
    if exponent.is_empty() {
        return Err(CodecError::new(
            "agent value has an invalid decimal exponent",
        ));
    }
    let exponent = exponent
        .parse::<i32>()
        .map_err(|_| CodecError::new("decimal exponent is outside the supported range"))?;
    Ok((mantissa, exponent))
}

fn validate_canonical_integer(value: &str) -> Result<(), CodecError> {
    let valid = if value == "0" {
        true
    } else if let Some(unsigned) = value.strip_prefix('-') {
        !unsigned.is_empty()
            && !unsigned.starts_with('0')
            && unsigned.bytes().all(|byte| byte.is_ascii_digit())
    } else {
        !value.starts_with('0') && value.bytes().all(|byte| byte.is_ascii_digit())
    };

    if valid {
        Ok(())
    } else {
        Err(CodecError::new(
            "wire value must match the canonical integer grammar",
        ))
    }
}

fn enforce_integer_digits(value: &str, max_integer_digits: u8) -> Result<(), CodecError> {
    let digits = value.strip_prefix('-').unwrap_or(value).len();
    if digits > usize::from(max_integer_digits) {
        Err(CodecError::new(format!(
            "scaled integer exceeds the configured {max_integer_digits}-digit limit"
        )))
    } else {
        Ok(())
    }
}

fn unscale_integer_text(integer: &str, scale: u8) -> String {
    if scale == 0 {
        return integer.to_owned();
    }

    let (negative, digits) = integer
        .strip_prefix('-')
        .map_or((false, integer), |digits| (true, digits));
    let scale = usize::from(scale);
    let mut decimal = if digits.len() <= scale {
        let mut decimal = String::from("0.");
        decimal.extend(std::iter::repeat_n('0', scale - digits.len()));
        decimal.push_str(digits);
        decimal
    } else {
        let split = digits.len() - scale;
        format!("{}.{}", &digits[..split], &digits[split..])
    };

    while decimal.ends_with('0') {
        decimal.pop();
    }
    if decimal.ends_with('.') {
        decimal.pop();
    }
    if negative {
        decimal.insert(0, '-');
    }
    decimal
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use serde_json::json;

    use super::*;

    #[test]
    fn currency_round_trips_without_floating_point() {
        let encoded = encode(json!(24000), 6, DecimalWireEncoding::IntegerString, 24)
            .expect("currency should encode");
        assert_eq!(encoded, json!("24000000000"));
        assert_eq!(
            decode(encoded, 6, DecimalWireEncoding::IntegerString, 24)
                .expect("currency should decode"),
            json!(24000)
        );
    }

    #[test]
    fn excess_fraction_digits_are_rejected_without_rounding() {
        let value: Value = serde_json::from_str("24000.1234567").expect("valid JSON number");
        assert_eq!(
            encode(value, 6, DecimalWireEncoding::IntegerString, 24)
                .expect_err("seven fractional digits must be rejected")
                .reason,
            "value has 7 fraction digits, codec allows 6"
        );
    }

    #[test]
    fn decimal_text_24000_1234567_reaches_the_codec_unchanged() {
        let value: Value = serde_json::from_str("24000.1234567").expect("valid JSON number");
        assert_eq!(
            value.as_number().expect("number").to_string(),
            "24000.1234567"
        );
        assert!(encode(value, 6, DecimalWireEncoding::IntegerString, 24).is_err());
    }

    #[test]
    fn decimal_scaling_preserves_tokens_beyond_binary_float_precision() {
        let value: Value = serde_json::from_str("9007199254740993").expect("valid JSON number");
        assert_eq!(
            encode(value, 0, DecimalWireEncoding::IntegerString, 24)
                .expect("exact integer should encode"),
            json!("9007199254740993")
        );

        let tenth: Value = serde_json::from_str("0.1").expect("valid JSON number");
        assert_eq!(
            encode(tenth, 6, DecimalWireEncoding::IntegerString, 24)
                .expect("exact decimal should encode"),
            json!("100000")
        );

        let boundary: Value =
            serde_json::from_str("0.100000000000000001").expect("valid JSON number");
        assert_eq!(
            encode(boundary, 18, DecimalWireEncoding::IntegerString, 24)
                .expect("18-digit fraction should remain exact"),
            json!("100000000000000001")
        );
    }

    #[test]
    fn maximum_integer_digits_is_enforced_at_the_boundary() {
        let allowed: Value =
            serde_json::from_str("999999999999999999999999").expect("valid JSON number");
        assert!(encode(allowed, 0, DecimalWireEncoding::IntegerString, 24).is_ok());
        let refused: Value =
            serde_json::from_str("9999999999999999999999999").expect("valid JSON number");
        assert!(encode(refused, 0, DecimalWireEncoding::IntegerString, 24).is_err());
    }

    #[test]
    fn exponent_forms_are_exact_or_rejected() {
        let exact: Value = serde_json::from_str("1.25e2").expect("valid JSON number");
        assert_eq!(
            encode(exact, 1, DecimalWireEncoding::IntegerString, 24)
                .expect("exact exponent should encode"),
            json!("1250")
        );

        let fractional: Value = serde_json::from_str("1e-7").expect("valid JSON number");
        assert!(encode(fractional, 6, DecimalWireEncoding::IntegerString, 24).is_err());
    }

    #[test]
    fn decode_rejects_noncanonical_integer_strings() {
        for value in ["007", "+5", "-0", " 5", "5.0"] {
            assert!(
                decode(
                    Value::String(value.to_owned()),
                    6,
                    DecimalWireEncoding::IntegerString,
                    24
                )
                .is_err(),
                "{value} should be rejected"
            );
        }
    }

    proptest! {
        #[test]
        fn canonical_scaled_integers_round_trip(integer in -999_999_999_999i64..=999_999_999_999i64) {
            let wire = Value::String(integer.to_string());
            let agent = decode(
                wire.clone(),
                6,
                DecimalWireEncoding::IntegerString,
                24,
            ).expect("bounded canonical integer should decode");
            prop_assert_eq!(
                encode(
                    agent,
                    6,
                    DecimalWireEncoding::IntegerString,
                    24,
                ).expect("decoded integer should encode"),
                wire,
            );
        }
    }
}
