pub mod jwt;
pub mod principal;
pub mod tokens;
pub mod validator;

#[allow(unused_imports)] // Public JWT API re-export reserved for PR 3 auth middleware.
pub use jwt::{JwtAuthConfig, JwtValidator, NoopRevocationStore, RevocationStore};
#[allow(unused_imports)] // Public auth API re-export reserved for later identity integration.
pub use principal::{actor_from_principal, AuthMethod, Principal};
#[allow(unused_imports)] // Public auth API re-export reserved for later identity integration.
pub use validator::{AuthError, SessionCredential, SessionValidator};
