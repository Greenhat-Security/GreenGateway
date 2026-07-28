//! First-class connection vocabulary and security boundaries.
//!
//! The control-plane store, legacy projections, and permission-separated
//! metadata CRUD are active. Outbound authentication and protocol migration
//! remain isolated to their later issue #240 slices so the existing legacy
//! runtime is unchanged until each named compatibility boundary lands.

#![allow(dead_code)]

pub mod admin;
pub mod control_plane;
pub mod local_secret;
pub mod model;
pub mod permissions;
pub mod projection;
pub mod secret;
pub mod status;
pub mod store;
