use std::sync::Arc;

use super::{AuthError, Principal, SessionCredential, SessionValidator};

const NO_PROVIDER_ACCEPTED: &str = "no configured auth provider accepted the credential";

/// Ordered session validator chain.
///
/// Invalid credentials fall through to later providers, while upstream identity
/// failures stop immediately so operational failures are not masked.
pub struct ChainValidator {
    validators: Vec<Arc<dyn SessionValidator>>,
}

impl ChainValidator {
    pub fn new(validators: Vec<Arc<dyn SessionValidator>>) -> Self {
        Self { validators }
    }
}

#[async_trait::async_trait]
impl SessionValidator for ChainValidator {
    async fn validate_session(
        &self,
        credential: &SessionCredential,
    ) -> Result<Principal, AuthError> {
        self.validate_session_for_resource(credential, None).await
    }

    async fn validate_session_for_resource(
        &self,
        credential: &SessionCredential,
        resource: Option<&str>,
    ) -> Result<Principal, AuthError> {
        for validator in &self.validators {
            match validator
                .validate_session_for_resource(credential, resource)
                .await
            {
                Ok(principal) => return Ok(principal),
                Err(AuthError::InvalidSession(_)) => continue,
                Err(error @ AuthError::Upstream(_)) => return Err(error),
            }
        }

        Err(AuthError::InvalidSession(NO_PROVIDER_ACCEPTED.to_owned()))
    }

    fn supports_cookie(&self) -> bool {
        self.validators
            .iter()
            .any(|validator| validator.supports_cookie())
    }

    fn supports_bearer(&self) -> bool {
        self.validators
            .iter()
            .any(|validator| validator.supports_bearer())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::auth::{AuthError, AuthMethod, Principal, SessionCredential, SessionValidator};

    #[derive(Clone)]
    struct MockValidator {
        name: &'static str,
        outcome: MockOutcome,
        supports_cookie: bool,
        supports_bearer: bool,
        calls: Arc<Mutex<Vec<&'static str>>>,
    }

    #[derive(Clone)]
    enum MockOutcome {
        Principal(Principal),
        InvalidSession(&'static str),
        Upstream(&'static str),
    }

    #[async_trait::async_trait]
    impl SessionValidator for MockValidator {
        async fn validate_session(
            &self,
            _credential: &SessionCredential,
        ) -> Result<Principal, AuthError> {
            self.calls
                .lock()
                .expect("call log should not be poisoned")
                .push(self.name);

            match &self.outcome {
                MockOutcome::Principal(principal) => Ok(principal.clone()),
                MockOutcome::InvalidSession(reason) => {
                    Err(AuthError::InvalidSession((*reason).to_owned()))
                }
                MockOutcome::Upstream(reason) => Err(AuthError::Upstream((*reason).to_owned())),
            }
        }

        fn supports_cookie(&self) -> bool {
            self.supports_cookie
        }

        fn supports_bearer(&self) -> bool {
            self.supports_bearer
        }
    }

    #[tokio::test]
    async fn returns_first_successful_principal_and_stops() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let chain = ChainValidator::new(vec![
            validator("first", MockOutcome::InvalidSession("wrong issuer"), &calls),
            validator(
                "second",
                MockOutcome::Principal(test_principal("user-second")),
                &calls,
            ),
            validator(
                "third",
                MockOutcome::Principal(test_principal("user-third")),
                &calls,
            ),
        ]);

        let principal = chain
            .validate_session(&SessionCredential::Bearer("token".to_owned()))
            .await
            .expect("second validator should accept the credential");

        assert_eq!(principal.user_id, "user-second");
        assert_eq!(logged_calls(&calls), vec!["first", "second"]);
    }

    #[tokio::test]
    async fn invalid_session_falls_through_to_later_validators() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let chain = ChainValidator::new(vec![
            validator("first", MockOutcome::InvalidSession("unknown kid"), &calls),
            validator(
                "second",
                MockOutcome::InvalidSession("bad signature"),
                &calls,
            ),
            validator(
                "third",
                MockOutcome::Principal(test_principal("user-third")),
                &calls,
            ),
        ]);

        let principal = chain
            .validate_session(&SessionCredential::Bearer("token".to_owned()))
            .await
            .expect("third validator should accept the credential");

        assert_eq!(principal.user_id, "user-third");
        assert_eq!(logged_calls(&calls), vec!["first", "second", "third"]);
    }

    #[tokio::test]
    async fn upstream_error_returns_immediately_without_trying_later_validators() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let chain = ChainValidator::new(vec![
            validator("first", MockOutcome::InvalidSession("unknown kid"), &calls),
            validator("second", MockOutcome::Upstream("JWKS fetch failed"), &calls),
            validator(
                "third",
                MockOutcome::Principal(test_principal("user-third")),
                &calls,
            ),
        ]);

        let error = chain
            .validate_session(&SessionCredential::Bearer("token".to_owned()))
            .await
            .expect_err("upstream error should stop validation");

        assert!(matches!(
            error,
            AuthError::Upstream(message) if message == "JWKS fetch failed"
        ));
        assert_eq!(logged_calls(&calls), vec!["first", "second"]);
    }

    #[tokio::test]
    async fn empty_chain_returns_final_invalid_session() {
        let chain = ChainValidator::new(Vec::new());

        let error = chain
            .validate_session(&SessionCredential::Bearer("token".to_owned()))
            .await
            .expect_err("empty chain should reject credentials");

        assert_final_invalid_session(error);
    }

    #[tokio::test]
    async fn all_invalid_sessions_return_final_invalid_session() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let chain = ChainValidator::new(vec![
            validator("first", MockOutcome::InvalidSession("unknown kid"), &calls),
            validator(
                "second",
                MockOutcome::InvalidSession("bad signature"),
                &calls,
            ),
        ]);

        let error = chain
            .validate_session(&SessionCredential::Bearer("token".to_owned()))
            .await
            .expect_err("chain should reject credentials no provider accepts");

        assert_final_invalid_session(error);
        assert_eq!(logged_calls(&calls), vec!["first", "second"]);
    }

    #[test]
    fn supports_cookie_and_bearer_are_or_across_validators() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let bearer_only = Arc::new(MockValidator {
            name: "bearer",
            outcome: MockOutcome::Principal(test_principal("bearer-user")),
            supports_cookie: false,
            supports_bearer: true,
            calls: Arc::clone(&calls),
        }) as Arc<dyn SessionValidator>;
        let cookie_only = Arc::new(MockValidator {
            name: "cookie",
            outcome: MockOutcome::Principal(test_principal("cookie-user")),
            supports_cookie: true,
            supports_bearer: false,
            calls,
        }) as Arc<dyn SessionValidator>;

        let chain = ChainValidator::new(vec![bearer_only, cookie_only]);

        assert!(chain.supports_cookie());
        assert!(chain.supports_bearer());
    }

    #[test]
    fn empty_chain_supports_no_credential_channels() {
        let chain = ChainValidator::new(Vec::new());

        assert!(!chain.supports_cookie());
        assert!(!chain.supports_bearer());
    }

    fn validator(
        name: &'static str,
        outcome: MockOutcome,
        calls: &Arc<Mutex<Vec<&'static str>>>,
    ) -> Arc<dyn SessionValidator> {
        Arc::new(MockValidator {
            name,
            outcome,
            supports_cookie: true,
            supports_bearer: true,
            calls: Arc::clone(calls),
        })
    }

    fn logged_calls(calls: &Arc<Mutex<Vec<&'static str>>>) -> Vec<&'static str> {
        calls
            .lock()
            .expect("call log should not be poisoned")
            .clone()
    }

    fn assert_final_invalid_session(error: AuthError) {
        assert!(matches!(
            error,
            AuthError::InvalidSession(message)
                if message == "no configured auth provider accepted the credential"
        ));
    }

    fn test_principal(user_id: &str) -> Principal {
        Principal {
            user_id: user_id.to_owned(),
            issuer: None,
            email: Some(format!("{user_id}@example.test")),
            org_id: None,
            roles: vec!["member".to_owned()],
            session_id: format!("{user_id}-session"),
            auth_method: AuthMethod::Bearer,
        }
    }
}
