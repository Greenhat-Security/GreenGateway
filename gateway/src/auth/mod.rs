pub mod principal;
pub mod validator;

#[allow(unused_imports)] // Public auth API re-export reserved for later identity integration.
pub use principal::{actor_from_principal, AuthMethod, Principal};
#[allow(unused_imports)] // Public auth API re-export reserved for later identity integration.
pub use validator::{AuthError, SessionCredential, SessionValidator};
