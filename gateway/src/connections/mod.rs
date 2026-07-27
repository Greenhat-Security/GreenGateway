//! First-class connection vocabulary and security boundaries.
//!
//! PR 1 intentionally exposes no store, admin route, or outbound behavior.
//! Later issue #240 slices consume these validated models without changing the
//! existing legacy runtime until their own compatibility tests land.

#![allow(dead_code)]

pub mod model;
pub mod permissions;
pub mod secret;
