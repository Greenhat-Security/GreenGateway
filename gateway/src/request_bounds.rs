//! Bounds on the shape of an admitted request, defined in
//! `gateway_config::request_bounds` so the configuration compiler `ggctl`
//! shares holds configuration to the same numbers (issue #242). Admission,
//! the policy kernel and the tool lane read them through this re-export.

pub(crate) use gateway_config::request_bounds::{
    MAX_DISPATCH_FACT_BYTES, MAX_REQUEST_HOST_BYTES, MAX_REQUEST_METHOD_BYTES,
    MAX_REQUEST_PATH_BYTES, MAX_TOOL_NAME_BYTES,
};
