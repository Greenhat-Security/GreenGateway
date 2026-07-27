//! First-class connection vocabulary and security boundaries.
//!
//! The control-plane store and legacy projections intentionally expose no
//! admin route or outbound behavior yet. Later issue #240 slices consume these
//! pieces without changing the existing legacy runtime until their named
//! compatibility tests land.

#![allow(dead_code)]

pub mod control_plane;
pub mod model;
pub mod permissions;
pub mod projection;
pub mod secret;
pub mod status;
pub mod store;
