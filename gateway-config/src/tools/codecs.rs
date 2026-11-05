//! The wire codecs a tool transform's bindings name (issue #360): which
//! codec, and its bounded options.
//!
//! Part of the tool definition model `gateway-config` shares with `ggctl`
//! (issue #242). Encoding and decoding values is the gateway's
//! (`gateway/src/tools/codecs`), which re-exports this module.

use serde::{Deserialize, Serialize};

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
