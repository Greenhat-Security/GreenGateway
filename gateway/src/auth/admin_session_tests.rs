use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;

#[derive(Default)]
struct Authority {
    calls: AtomicUsize,
    outcome: AtomicUsize,
    pause: AtomicUsize,
    entered: tokio::sync::Notify,
    resume: tokio::sync::Notify,
}

#[async_trait::async_trait]
impl SessionValidator for Authority {
    async fn validate_session(
        &self,
        credential: &SessionCredential,
    ) -> Result<Principal, AuthError> {
        assert!(matches!(credential, SessionCredential::Bearer(_)));
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.pause.load(Ordering::SeqCst) != 0 {
            self.entered.notify_one();
            self.resume.notified().await;
        }
        match self.outcome.load(Ordering::SeqCst) {
            1 => Err(AuthError::InvalidSession("rejected".to_owned())),
            2 => Err(AuthError::Upstream("unavailable".to_owned())),
            outcome => Ok(Principal {
                user_id: if outcome == 3 { "other" } else { "operator" }.to_owned(),
                issuer: Some("https://issuer.example.test".to_owned()),
                email: None,
                org_id: None,
                roles: vec!["admin".to_owned()],
                session_id: "issuer-token-id".to_owned(),
                auth_method: AuthMethod::Bearer,
            }),
        }
    }
    fn supports_cookie(&self) -> bool {
        false
    }
}

fn new_sessions(authority: &Arc<Authority>) -> AdminSessions {
    AdminSessions::new(
        AdminSessionConfig {
            ttl: Duration::from_secs(60),
            max_entries: 8,
        },
        Arc::clone(authority) as Arc<dyn SessionValidator>,
        "/operations",
        "https://management.example.test".to_owned(),
    )
    .expect("valid configuration")
}

fn cookie_headers(issued: &IssuedSession) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        issued
            .cookie
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .parse()
            .unwrap(),
    );
    headers
}

async fn issue(sessions: &AdminSessions) -> IssuedSession {
    let binding = uuid::Uuid::new_v4().to_string();
    sessions
        .begin_login(&binding, Duration::from_secs(30), &HeaderMap::new())
        .unwrap();
    sessions
        .issue(
            uuid::Uuid::new_v4().to_string(),
            &HeaderMap::new(),
            &binding,
        )
        .await
        .unwrap()
}

async fn validate(sessions: &AdminSessions, headers: &HeaderMap) -> Result<Principal, AuthError> {
    sessions
        .validate_session(&SessionCredential::Cookie(
            sessions.credential(headers).unwrap(),
        ))
        .await
}

#[tokio::test]
async fn admin_session_cookie_is_independent_and_authority_is_rechecked() {
    let authority = Arc::new(Authority::default());
    let sessions = new_sessions(&authority);
    let token = uuid::Uuid::new_v4().to_string();
    sessions
        .begin_login("binding", Duration::from_secs(30), &HeaderMap::new())
        .unwrap();
    let issued = sessions
        .issue(token.clone(), &HeaderMap::new(), "binding")
        .await
        .unwrap();
    let cookie = issued.cookie.to_str().unwrap();
    for flag in [
        "__Host-",
        "Path=/",
        "HttpOnly",
        "Secure",
        "SameSite=Lax",
        "Max-Age=60",
    ] {
        assert!(cookie.contains(flag));
    }
    assert!(!cookie.contains(&token));
    assert!(!format!("{issued:?}").contains(cookie));
    let headers = cookie_headers(&issued);
    let principal = validate(&sessions, &headers).await.unwrap();
    assert_eq!(principal.auth_method, AuthMethod::Cookie);
    assert_ne!(principal.session_id, sessions.credential(&headers).unwrap());
    validate(&sessions, &headers).await.unwrap();
    assert_eq!(authority.calls.load(Ordering::SeqCst), 3);
    let stored = sessions.store.lock().unwrap();
    assert_eq!(stored.entries.len(), 1);
    assert!(stored
        .entries
        .contains_key(&digest(&sessions.credential(&headers).unwrap())));
}

#[tokio::test]
async fn admin_session_outage_preserves_session_but_rejection_revokes_it() {
    let authority = Arc::new(Authority::default());
    let sessions = new_sessions(&authority);
    let headers = cookie_headers(&issue(&sessions).await);
    authority.outcome.store(2, Ordering::SeqCst);
    assert!(matches!(
        validate(&sessions, &headers).await,
        Err(AuthError::Upstream(_))
    ));
    authority.outcome.store(0, Ordering::SeqCst);
    validate(&sessions, &headers).await.unwrap();
    authority.outcome.store(1, Ordering::SeqCst);
    assert!(matches!(
        validate(&sessions, &headers).await,
        Err(AuthError::InvalidSession(_))
    ));
    authority.outcome.store(0, Ordering::SeqCst);
    assert!(validate(&sessions, &headers).await.is_err());
}

#[tokio::test]
async fn admin_session_expiry_identity_change_and_restart_fail_closed() {
    let authority = Arc::new(Authority::default());
    let sessions = new_sessions(&authority);
    let headers = cookie_headers(&issue(&sessions).await);
    for entry in sessions.store.lock().unwrap().entries.values_mut() {
        entry.expires_at = Instant::now();
    }
    assert!(validate(&sessions, &headers).await.is_err());
    assert_eq!(
        authority.calls.load(Ordering::SeqCst),
        1,
        "expired sessions do not consult authority"
    );
    let headers = cookie_headers(&issue(&sessions).await);
    let restarted = new_sessions(&authority);
    assert!(validate(&restarted, &headers).await.is_err());
    authority.outcome.store(3, Ordering::SeqCst);
    assert!(validate(&sessions, &headers).await.is_err());
}

#[tokio::test]
async fn admin_session_logout_wins_over_validation_in_flight() {
    let authority = Arc::new(Authority::default());
    let sessions = new_sessions(&authority);
    let headers = cookie_headers(&issue(&sessions).await);
    authority.pause.store(1, Ordering::SeqCst);
    let work = tokio::spawn({
        let sessions = sessions.clone();
        let headers = headers.clone();
        async move { validate(&sessions, &headers).await }
    });
    authority.entered.notified().await;
    sessions.revoke(&headers, None).unwrap();
    authority.resume.notify_one();
    assert!(matches!(
        work.await.unwrap(),
        Err(AuthError::InvalidSession(_))
    ));
}

#[tokio::test]
async fn admin_session_logout_cancels_pending_and_undelivered_completion() {
    let authority = Arc::new(Authority::default());
    let sessions = new_sessions(&authority);
    sessions
        .begin_login("pending", Duration::from_secs(30), &HeaderMap::new())
        .unwrap();
    authority.pause.store(1, Ordering::SeqCst);
    let work = tokio::spawn({
        let sessions = sessions.clone();
        async move {
            sessions
                .issue(
                    uuid::Uuid::new_v4().to_string(),
                    &HeaderMap::new(),
                    "pending",
                )
                .await
        }
    });
    authority.entered.notified().await;
    sessions.revoke(&HeaderMap::new(), Some("pending")).unwrap();
    authority.resume.notify_one();
    assert!(matches!(
        work.await.unwrap(),
        Err(AuthError::InvalidSession(_))
    ));
    authority.pause.store(0, Ordering::SeqCst);
    sessions
        .begin_login("undelivered", Duration::from_secs(30), &HeaderMap::new())
        .unwrap();
    let issued = sessions
        .issue(
            uuid::Uuid::new_v4().to_string(),
            &HeaderMap::new(),
            "undelivered",
        )
        .await
        .unwrap();
    sessions
        .revoke(&HeaderMap::new(), Some("undelivered"))
        .unwrap();
    assert!(validate(&sessions, &cookie_headers(&issued)).await.is_err());
}

#[tokio::test]
async fn admin_session_capacity_and_duplicate_cookies_fail_closed() {
    let authority = Arc::new(Authority::default());
    let mut sessions = new_sessions(&authority);
    sessions.config.max_entries = 1;
    let issued = issue(&sessions).await;
    assert!(sessions
        .begin_login("second", Duration::from_secs(30), &HeaderMap::new())
        .is_err());
    let mut headers = cookie_headers(&issued);
    let cookie = headers[header::COOKIE].clone();
    headers.append(header::COOKIE, cookie);
    assert!(validate(&sessions, &headers).await.is_err());
    assert!(sessions
        .validate_session(&SessionCredential::Bearer(uuid::Uuid::new_v4().to_string()))
        .await
        .is_err());
    assert!(sessions
        .validate_session_for_resource(
            &SessionCredential::Cookie(sessions.credential(&headers).unwrap()),
            Some("https://gateway.example.test/mcp")
        )
        .await
        .is_err());
}

#[test]
fn admin_session_requires_https_bounded_config_and_exact_origin() {
    let authority = Arc::new(Authority::default());
    let sessions = new_sessions(&authority);
    let mut headers = HeaderMap::new();
    assert!(!sessions.origin_matches(&headers));
    headers.insert(
        header::ORIGIN,
        "https://management.example.test".parse().unwrap(),
    );
    assert!(sessions.origin_matches(&headers));
    headers.append(
        header::ORIGIN,
        "https://management.example.test".parse().unwrap(),
    );
    assert!(!sessions.origin_matches(&headers));
    assert!(AdminSessions::new(
        sessions.config,
        authority,
        "/operations",
        "http://localhost".to_owned()
    )
    .is_err());
}

#[tokio::test]
async fn admin_session_delivered_cookie_releases_login_capacity_for_logout_and_replacement() {
    let authority = Arc::new(Authority::default());
    let mut sessions = new_sessions(&authority);
    sessions.config.max_entries = 1;
    let original = cookie_headers(&issue(&sessions).await);
    sessions.revoke(&original, None).unwrap();
    let replacement = cookie_headers(&issue(&sessions).await);
    assert!(validate(&sessions, &original).await.is_err());
    sessions
        .begin_login("replace", Duration::from_secs(30), &replacement)
        .unwrap();
    let next = sessions
        .issue(uuid::Uuid::new_v4().to_string(), &replacement, "replace")
        .await
        .unwrap();
    assert!(validate(&sessions, &replacement).await.is_err());
    validate(&sessions, &cookie_headers(&next)).await.unwrap();
    assert!(sessions.store.lock().unwrap().attempts.is_empty());
}
