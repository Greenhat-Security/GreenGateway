pub mod decimal_scale;
pub mod json_string;
pub mod markdown_blocks;

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Codec {
    DecimalScale {
        scale: u8,
        #[serde(default)]
        wire_encoding: DecimalWireEncoding,
        #[serde(default = "default_max_integer_digits")]
        max_integer_digits: u8,
    },
    MarkdownBlocks {
        dialect: MarkdownDialect,
        #[serde(default = "default_markdown_input_bytes")]
        max_input_bytes: usize,
    },
    JsonString,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecimalWireEncoding {
    #[default]
    IntegerString,
    Integer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MarkdownDialect {
    Blocknote,
}

pub const fn default_max_integer_digits() -> u8 {
    24
}

pub const fn default_markdown_input_bytes() -> usize {
    65_536
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodecError {
    pub reason: String,
}

impl CodecError {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

impl std::fmt::Display for CodecError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.reason)
    }
}

impl std::error::Error for CodecError {}

pub fn encode(codec: &Codec, value: Value) -> Result<Value, CodecError> {
    match codec {
        Codec::DecimalScale {
            scale,
            wire_encoding,
            max_integer_digits,
        } => decimal_scale::encode(value, *scale, *wire_encoding, *max_integer_digits),
        Codec::MarkdownBlocks {
            dialect,
            max_input_bytes,
        } => markdown_blocks::encode(value, *dialect, *max_input_bytes),
        Codec::JsonString => json_string::encode(value),
    }
}

pub fn decode(codec: &Codec, value: Value) -> Result<Value, CodecError> {
    match codec {
        Codec::DecimalScale {
            scale,
            wire_encoding,
            max_integer_digits,
        } => decimal_scale::decode(value, *scale, *wire_encoding, *max_integer_digits),
        Codec::MarkdownBlocks { .. } => Err(CodecError::new(
            "markdown_blocks has no inverse; configure an explicit response binding",
        )),
        Codec::JsonString => json_string::decode(value),
    }
}

pub fn encode_chain(codecs: &[Codec], mut value: Value) -> Result<Value, CodecError> {
    for codec in codecs {
        value = encode(codec, value)?;
    }
    Ok(value)
}

pub fn decode_chain(codecs: &[Codec], mut value: Value) -> Result<Value, CodecError> {
    for codec in codecs.iter().rev() {
        value = decode(codec, value)?;
    }
    Ok(value)
}
