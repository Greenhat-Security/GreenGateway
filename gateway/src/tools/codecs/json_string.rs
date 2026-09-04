use serde_json::Value;

use super::CodecError;

pub fn encode(value: Value) -> Result<Value, CodecError> {
    serde_json::to_string(&value)
        .map(Value::String)
        .map_err(|error| CodecError::new(format!("value could not be serialized as JSON: {error}")))
}

pub fn decode(value: Value) -> Result<Value, CodecError> {
    let Value::String(value) = value else {
        return Err(CodecError::new("wire value must be a JSON string"));
    };
    serde_json::from_str(&value)
        .map_err(|error| CodecError::new(format!("wire string is not valid JSON: {error}")))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn nested_json_round_trips_through_a_compact_string() {
        let value = json!({"nested":[true,{"value":1}],"text":"hello"});
        let encoded = encode(value.clone()).expect("JSON value should encode");
        assert_eq!(
            encoded,
            Value::String("{\"nested\":[true,{\"value\":1}],\"text\":\"hello\"}".to_owned())
        );
        assert_eq!(decode(encoded).expect("JSON string should decode"), value);
    }

    #[test]
    fn malformed_json_string_is_rejected_without_echoing_it() {
        let error = decode(Value::String("{secret".to_owned()))
            .expect_err("malformed JSON should be rejected");
        assert!(error.reason.contains("not valid JSON"));
        assert!(!error.reason.contains("secret"));
    }
}
