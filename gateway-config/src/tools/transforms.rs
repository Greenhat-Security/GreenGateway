//! The declarative agent-to-wire and wire-to-agent mapping a tool
//! definition carries, compiled from a Connection OpenAPI overlay (issue
//! #360): which agent properties a wire property is built from, by which
//! codecs, and how a response is read back.
//!
//! Part of the tool definition model `gateway-config` shares with `ggctl`
//! (issue #242). Applying a transform to a request or a response is the
//! gateway's (`gateway/src/tools/transforms.rs`), which re-exports this
//! module.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{
    codecs::Codec,
    selector::{JsonPointer, Selector},
};

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ToolTransform {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parameters: Vec<ParameterShape>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub response_fields: Vec<ParameterShape>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_root: Option<Selector>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ParameterShape {
    pub wire_property: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub wire_required: bool,
    pub agent: Vec<AgentProperty>,
    pub wire: Vec<WireBinding>,
    pub response: Vec<ResponseBinding>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentProperty {
    pub name: String,
    pub schema: Value,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct WireBinding {
    pub pointer: JsonPointer,
    #[serde(flatten)]
    pub source: WireSource,
    #[serde(default, rename = "codec", skip_serializing_if = "Vec::is_empty")]
    pub codecs: Vec<Codec>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum WireSource {
    From { from: String },
    Const { r#const: Value },
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseBinding {
    pub agent_property: String,
    pub from: JsonPointer,
    #[serde(default, rename = "codec", skip_serializing_if = "Vec::is_empty")]
    pub codecs: Vec<Codec>,
}
