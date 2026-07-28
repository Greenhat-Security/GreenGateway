//! First-class connection vocabulary and security boundaries.
//!
//! The control-plane store, legacy projections, and permission-separated
//! metadata CRUD are active. Static HTTP authentication is available only
//! through explicitly connection-bound proxy routes and manual tools; the
//! remaining protocol migrations stay isolated to their named issue #240
//! slices.

#![allow(dead_code)]

pub mod admin;
pub mod control_plane;
pub mod http;
pub mod local_secret;
pub mod model;
pub mod permissions;
pub mod projection;
pub mod secret;
pub mod status;
pub mod store;
