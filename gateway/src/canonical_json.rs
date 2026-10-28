//! RFC 8785 canonical JSON and the ADR-0004 digest frame.
//!
//! Defined in the shared `gateway-config` crate (issue #242, ADR-0008), which
//! `ggctl` also links, so the gateway and the operator CLI compute exactly the
//! same canonical bytes and digests. This module keeps the gateway's call
//! sites on their existing path.

pub(crate) use gateway_config::canonical_json::{
    canonical_json_bytes, semantic_digest, source_digest,
};
