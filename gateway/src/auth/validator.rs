use std::{error::Error, fmt};

use super::Principal;

/// Credential material extracted from an incoming request for validation.
pub enum SessionCredential {
    #[allow(dead_code)] // Cookie validators land after the bearer JWT path.
    Cookie(String),
    Bearer(String),
}

impl fmt::Debug for SessionCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cookie(_) => formatter.write_str("Cookie(<redacted>)"),
            Self::Bearer(_) => formatter.write_str("Bearer(<redacted>)"),
        }
    }
}

/// Errors returned while validating session credentials.
#[derive(Debug)]
pub enum AuthError {
    /// Credential is invalid, expired, or revoked.
    InvalidSession(String),
    /// Upstream identity service is unreachable or returned an unexpected response.
    Upstream(String),
}

impl fmt::Display for AuthError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSession(message) => write!(formatter, "invalid session: {message}"),
            Self::Upstream(message) => {
                write!(formatter, "upstream identity service error: {message}")
            }
        }
    }
}

impl Error for AuthError {}

#[async_trait::async_trait] // Keeps async validation object-safe for Arc<dyn SessionValidator>.
pub trait SessionValidator: Send + Sync {
    async fn validate_session(
        &self,
        credential: &SessionCredential,
    ) -> Result<Principal, AuthError>;

    async fn validate_session_for_resource(
        &self,
        credential: &SessionCredential,
        _resource: Option<&str>,
    ) -> Result<Principal, AuthError> {
        self.validate_session(credential).await
    }

    /// Routing hint for whether this validator should receive cookie credentials.
    /// This is not an authorization decision: every offered credential must still pass
    /// `validate_session`, so the default only opts into receiving this channel.
    fn supports_cookie(&self) -> bool {
        true
    }

    /// Routing hint for whether this validator should receive bearer credentials.
    /// This is not an authorization decision: every offered credential must still pass
    /// `validate_session`, so the default only opts into receiving this channel.
    fn supports_bearer(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::auth::AuthMethod;

    struct StaticValidator {
        response: StaticResponse,
    }

    enum StaticResponse {
        Principal(Principal),
        Error(AuthError),
    }

    #[async_trait::async_trait]
    impl SessionValidator for StaticValidator {
        async fn validate_session(
            &self,
            _credential: &SessionCredential,
        ) -> Result<Principal, AuthError> {
            match &self.response {
                StaticResponse::Principal(principal) => Ok(principal.clone()),
                StaticResponse::Error(AuthError::InvalidSession(message)) => {
                    Err(AuthError::InvalidSession(message.clone()))
                }
                StaticResponse::Error(AuthError::Upstream(message)) => {
                    Err(AuthError::Upstream(message.clone()))
                }
            }
        }
    }

    #[tokio::test]
    async fn validator_is_usable_as_dyn_trait() {
        let validator: Arc<dyn SessionValidator> = Arc::new(StaticValidator {
            response: StaticResponse::Principal(test_principal()),
        });

        let principal = validator
            .validate_session(&SessionCredential::Bearer("token-123".to_owned()))
            .await
            .expect("static validator should return a principal");

        assert_eq!(principal.user_id, "user-123");
        assert_eq!(principal.auth_method, AuthMethod::Bearer);
    }

    #[tokio::test]
    async fn dyn_validator_can_return_auth_errors() {
        let validator: Arc<dyn SessionValidator> = Arc::new(StaticValidator {
            response: StaticResponse::Error(AuthError::InvalidSession("expired".to_owned())),
        });

        let error = validator
            .validate_session(&SessionCredential::Cookie("session-123".to_owned()))
            .await
            .expect_err("static validator should return an error");

        assert!(matches!(
            error,
            AuthError::InvalidSession(message) if message == "expired"
        ));
    }

    #[test]
    fn supports_cookie_and_bearer_default_to_true() {
        let validator: Arc<dyn SessionValidator> = Arc::new(StaticValidator {
            response: StaticResponse::Principal(test_principal()),
        });

        assert!(validator.supports_cookie());
        assert!(validator.supports_bearer());
    }

    #[test]
    fn session_credential_debug_redacts_secret_values() {
        let bearer_secret = "super-secret-token-value";
        let bearer = SessionCredential::Bearer(bearer_secret.to_owned());
        let bearer_output = format!("{bearer:?}");

        assert!(!bearer_output.contains(bearer_secret));
        assert!(bearer_output.contains("<redacted>"));

        let cookie_secret = "super-secret-cookie-value";
        let cookie = SessionCredential::Cookie(cookie_secret.to_owned());
        let cookie_output = format!("{cookie:?}");

        assert!(!cookie_output.contains(cookie_secret));
        assert!(cookie_output.contains("<redacted>"));
    }

    fn test_principal() -> Principal {
        Principal {
            user_id: "user-123".to_owned(),
            issuer: None,
            email: Some("user@example.com".to_owned()),
            org_id: Some("org-456".to_owned()),
            roles: vec!["member".to_owned()],
            session_id: "session-789".to_owned(),
            auth_method: AuthMethod::Bearer,
        }
    }
}
