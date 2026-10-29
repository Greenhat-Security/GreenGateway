//! Re-judging the credential an admitted request was authenticated with.
//!
//! Authentication is a decision about one request. A response that outlives
//! its request -- the admin audit event stream can stay open for as long as
//! the client reads it -- keeps acting on that decision long after the
//! session behind it may have been logged out, expired or revoked. A
//! [`Reauthentication`] lets such a response ask the same question again,
//! of the same authority, about the same credential.

use std::{fmt, sync::Arc};

use super::{
    admin_session::AdminSessions, AuthError, Principal, SessionCredential, SessionValidator,
};

const NOT_A_SESSION_COOKIE: &str = "admin session credential is not a session cookie";

/// The authority that judged a request's credential.
pub enum CredentialJudge {
    /// A gateway-issued admin session, judged by its own store and the login
    /// provider, never by the global chain.
    AdminSession(Arc<AdminSessions>),
    /// The global validator chain.
    Validator(Arc<dyn SessionValidator>),
}

/// The credential a request was admitted with and the authority that judged
/// it.
///
/// The authentication middleware inserts one beside the [`Principal`] of
/// every request it admits, so the two always travel together. The
/// credential cannot be read back out: the only thing a holder can do with
/// it is [`Reauthentication::revalidate`], and `Debug` never prints it.
#[derive(Clone)]
pub struct Reauthentication {
    inner: Arc<Inner>,
}

struct Inner {
    judge: CredentialJudge,
    credential: SessionCredential,
    /// The protected resource the credential was bound to, if any.
    resource: Option<String>,
}

impl Reauthentication {
    pub fn new(
        judge: CredentialJudge,
        credential: SessionCredential,
        resource: Option<String>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                judge,
                credential,
                resource,
            }),
        }
    }

    /// Judge the credential again, now, by the authority that admitted it.
    ///
    /// The answers are the validators' own: `InvalidSession` for a credential
    /// that is no longer accepted (logged out, expired, revoked, rejected),
    /// `Upstream` when the authority could not decide. Nothing here records
    /// an audit event or counts as activity: an admin session's idle
    /// deadline does not move (see [`AdminSessions::reauthenticate`]).
    pub async fn revalidate(&self) -> Result<Principal, AuthError> {
        match (&self.inner.judge, &self.inner.credential) {
            (CredentialJudge::AdminSession(sessions), SessionCredential::Cookie(value)) => {
                sessions.reauthenticate(value).await
            }
            // The middleware only ever pairs an admin session with its
            // cookie; anything else is not a session this store can judge.
            (CredentialJudge::AdminSession(_), _) => {
                Err(AuthError::InvalidSession(NOT_A_SESSION_COOKIE.to_owned()))
            }
            (CredentialJudge::Validator(validator), credential) => {
                validator
                    .validate_session_for_resource(credential, self.inner.resource.as_deref())
                    .await
            }
        }
    }
}

impl fmt::Debug for Reauthentication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Reauthentication(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::auth::{
        admin_session::{
            tests::{cookie_headers, front, issue_across, session_config, Authority},
            AdminSessionStorage, AdminSessionStore, MemoryAdminSessionStore,
        },
        AuthMethod,
    };

    /// Accepts exactly the bearer value it was built with, for one resource,
    /// until told to refuse; records every value it was asked about.
    struct RecordingValidator {
        accepted: String,
        resource: Option<String>,
        refuse: Mutex<bool>,
        asked: Mutex<Vec<(String, Option<String>)>>,
    }

    #[async_trait::async_trait]
    impl SessionValidator for RecordingValidator {
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
            let SessionCredential::Bearer(value) = credential else {
                return Err(AuthError::InvalidSession("not a bearer".to_owned()));
            };
            self.asked
                .lock()
                .unwrap()
                .push((value.clone(), resource.map(str::to_owned)));
            if *self.refuse.lock().unwrap()
                || *value != self.accepted
                || resource.map(str::to_owned) != self.resource
            {
                return Err(AuthError::InvalidSession("token revoked".to_owned()));
            }
            Ok(Principal {
                user_id: "streamer".to_owned(),
                issuer: Some("https://issuer.example.test".to_owned()),
                email: None,
                org_id: None,
                roles: vec!["admin".to_owned()],
                session_id: "token-id".to_owned(),
                auth_method: AuthMethod::Bearer,
            })
        }
    }

    #[tokio::test]
    async fn revalidation_asks_the_same_validator_about_the_same_credential() {
        let bearer = format!("test-{}", uuid::Uuid::new_v4());
        let validator = Arc::new(RecordingValidator {
            accepted: bearer.clone(),
            resource: Some("https://gateway.example.test/mcp".to_owned()),
            refuse: Mutex::new(false),
            asked: Mutex::new(Vec::new()),
        });
        let reauthentication = Reauthentication::new(
            CredentialJudge::Validator(Arc::clone(&validator) as Arc<dyn SessionValidator>),
            SessionCredential::Bearer(bearer.clone()),
            Some("https://gateway.example.test/mcp".to_owned()),
        );

        let principal = reauthentication.revalidate().await.unwrap();
        assert_eq!(principal.user_id, "streamer");
        // A clone shares the credential; it does not copy a second one out.
        *validator.refuse.lock().unwrap() = true;
        assert!(matches!(
            reauthentication.clone().revalidate().await,
            Err(AuthError::InvalidSession(_))
        ));
        let resource = Some("https://gateway.example.test/mcp".to_owned());
        assert_eq!(
            *validator.asked.lock().unwrap(),
            [
                (bearer.clone(), resource.clone()),
                (bearer.clone(), resource)
            ]
        );
        assert_eq!(
            format!("{reauthentication:?}"),
            "Reauthentication(<redacted>)"
        );
        assert!(!format!("{reauthentication:?}").contains(&bearer));
    }

    #[tokio::test]
    async fn an_admin_session_is_rejudged_by_its_store_and_ends_with_logout() {
        let authority = Arc::new(Authority::default());
        let config = session_config(AdminSessionStorage::StandaloneMemory, 8);
        let store = Arc::new(MemoryAdminSessionStore::new(config.clone()));
        let sessions = Arc::new(front(
            &authority,
            Arc::clone(&store) as Arc<dyn AdminSessionStore>,
            config,
        ));
        let headers = cookie_headers(
            &issue_across(&sessions, &sessions, &http::HeaderMap::new())
                .await
                .unwrap(),
        );
        let value = sessions.credential(&headers).unwrap();
        let reauthentication = Reauthentication::new(
            CredentialJudge::AdminSession(Arc::clone(&sessions)),
            SessionCredential::Cookie(value),
            None,
        );

        let principal = reauthentication.revalidate().await.unwrap();
        assert_eq!(principal.auth_method, AuthMethod::Cookie);
        assert_eq!(principal.user_id, "operator");
        sessions.revoke(&headers, None).await.unwrap();
        assert!(matches!(
            reauthentication.revalidate().await,
            Err(AuthError::InvalidSession(_))
        ));
    }

    #[tokio::test]
    async fn an_admin_session_judge_refuses_anything_but_its_cookie() {
        let authority = Arc::new(Authority::default());
        let config = session_config(AdminSessionStorage::StandaloneMemory, 8);
        let store = Arc::new(MemoryAdminSessionStore::new(config.clone()));
        let sessions = Arc::new(front(
            &authority,
            store as Arc<dyn AdminSessionStore>,
            config,
        ));
        let reauthentication = Reauthentication::new(
            CredentialJudge::AdminSession(sessions),
            SessionCredential::Bearer(format!("test-{}", uuid::Uuid::new_v4())),
            None,
        );

        assert!(matches!(
            reauthentication.revalidate().await,
            Err(AuthError::InvalidSession(_))
        ));
        assert_eq!(
            authority.calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "the provider is never asked about a credential the store cannot hold"
        );
    }
}
