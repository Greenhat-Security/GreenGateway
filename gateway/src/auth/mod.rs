pub mod chain;
pub mod jwt;
pub mod oidc;
pub mod principal;
pub mod principal_directory;
pub mod service_token_validator;
pub mod tokens;
pub mod validator;

#[allow(unused_imports)] // Public chain API is used by gateway startup wiring.
pub use chain::ChainValidator;
#[allow(unused_imports)] // Public JWT API re-export reserved for PR 3 auth middleware.
pub use jwt::{JwtAuthConfig, JwtValidator, NoopRevocationStore, RevocationStore};
#[allow(unused_imports)] // Public auth API re-export reserved for later identity integration.
pub use principal::{actor_from_principal, AuthMethod, Principal};
#[allow(unused_imports)] // Public principal directory handle is wired by gateway startup.
pub use principal_directory::PrincipalDirectory;
#[allow(unused_imports)] // Public service-token validator is wired by gateway startup.
pub use service_token_validator::ServiceTokenValidator;
#[allow(unused_imports)] // Public token-store API is consumed by admin endpoints and tests.
pub use tokens::{SqliteTokenStore, TokenStore};
#[allow(unused_imports)] // Public auth API re-export reserved for later identity integration.
pub use validator::{AuthError, SessionCredential, SessionValidator};
