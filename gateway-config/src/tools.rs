//! The tool definitions document the gateway serves tools from (tools
//! 0.1.0): the [`definitions::ToolDefinition`] model and its validating
//! parse, shared by the gateway and `ggctl` (issue #242).
//!
//! - [`definitions`]: the definition model and
//!   [`definitions::definitions_from_json_value`];
//! - [`composite`], [`transforms`], [`selector`] and [`codecs`]: the
//!   composite-tool mapping, the agent-to-wire transform, the JSON selector
//!   grammar and the wire codecs a definition can carry.
//!
//! Nothing here reads a file or the network. The registry, the tools file
//! loader and watcher, and executing a tool stay in the gateway, whose
//! `tools` modules re-export these.

pub mod codecs;
pub mod composite;
pub mod definitions;
pub mod selector;
pub mod transforms;
