use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;

/// The CSRF header the test fronts are configured with.
pub(crate) const CSRF_HEADER: &str = "x-test-csrf";
/// The double-submit token every test session is issued with.
pub(crate) const CSRF: &str = "bound-csrf-token";

/// A stand-in for the login provider's bearer validator. `outcome`: 0
/// accepts as `operator`, 1 rejects, 2 is unavailable, 3 accepts as `other`.
#[derive(Default)]
pub(crate) struct Authority {
    pub(crate) calls: AtomicUsize,
    pub(crate) outcome: AtomicUsize,
    pub(crate) pause: AtomicUsize,
    pub(crate) entered: tokio::sync::Notify,
    pub(crate) resume: tokio::sync::Notify,
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

pub(crate) fn session_config(
    storage: AdminSessionStorage,
    max_entries: usize,
) -> AdminSessionConfig {
    AdminSessionConfig {
        storage,
        ttl: Duration::from_secs(60),
        idle_timeout: Duration::from_secs(60),
        max_entries,
    }
}

/// One replica's front over `store`.
pub(crate) fn front(
    authority: &Arc<Authority>,
    store: Arc<dyn AdminSessionStore>,
    config: AdminSessionConfig,
) -> AdminSessions {
    AdminSessions::new(
        config,
        Arc::clone(authority) as Arc<dyn SessionValidator>,
        store,
        "/operations",
        "https://management.example.test".to_owned(),
        CSRF_HEADER,
    )
    .expect("valid configuration")
}

fn memory_sessions(
    authority: &Arc<Authority>,
    max_entries: usize,
) -> (AdminSessions, Arc<MemoryAdminSessionStore>) {
    let config = session_config(AdminSessionStorage::StandaloneMemory, max_entries);
    let store = Arc::new(MemoryAdminSessionStore::new(config.clone()));
    let sessions = front(
        authority,
        Arc::clone(&store) as Arc<dyn AdminSessionStore>,
        config,
    );
    (sessions, store)
}

fn new_sessions(authority: &Arc<Authority>) -> (AdminSessions, Arc<MemoryAdminSessionStore>) {
    memory_sessions(authority, 8)
}

pub(crate) fn cookie_headers(issued: &IssuedSession) -> HeaderMap {
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

/// Begin a cookie login on `begin` and complete it on `complete`, bound to
/// [`CSRF`]. `headers` is what the browser presents to both.
pub(crate) async fn issue_across(
    begin: &AdminSessions,
    complete: &AdminSessions,
    headers: &HeaderMap,
) -> Result<IssuedSession, AuthError> {
    let binding = uuid::Uuid::new_v4().to_string();
    begin
        .begin_login(&binding, Duration::from_secs(30), headers)
        .await?;
    complete
        .issue(uuid::Uuid::new_v4().to_string(), headers, &binding, CSRF)
        .await
}

async fn issue(sessions: &AdminSessions) -> IssuedSession {
    issue_across(sessions, sessions, &HeaderMap::new())
        .await
        .unwrap()
}

/// A safe request authenticated by the session in `headers`.
pub(crate) async fn read(
    sessions: &AdminSessions,
    headers: &HeaderMap,
) -> Result<Principal, SessionRefusal> {
    let value = sessions.credential(headers).unwrap_or_default();
    sessions.authenticate(&value, &Method::GET, headers).await
}

/// An unsafe request authenticated by the session in `headers`, carrying
/// `csrf` in the configured header when given.
pub(crate) async fn write(
    sessions: &AdminSessions,
    headers: &HeaderMap,
    csrf: Option<&str>,
) -> Result<Principal, SessionRefusal> {
    let mut headers = headers.clone();
    if let Some(csrf) = csrf {
        headers.insert(CSRF_HEADER, csrf.parse().unwrap());
    }
    let value = sessions.credential(&headers).unwrap_or_default();
    sessions.authenticate(&value, &Method::POST, &headers).await
}

pub(crate) fn is_invalid(result: &Result<Principal, SessionRefusal>) -> bool {
    matches!(
        result,
        Err(SessionRefusal::Auth(AuthError::InvalidSession(_)))
    )
}

pub(crate) fn is_unavailable(result: &Result<Principal, SessionRefusal>) -> bool {
    matches!(result, Err(SessionRefusal::Auth(AuthError::Upstream(_))))
}

// ---------------------------------------------------------------------------
// The store contract. `a` and `b` are two replicas' fronts over one store:
// the same memory store in standalone mode, two PostgreSQL stores on one
// database in cluster mode. Both answer to `authority`, and the store has
// room for at least four sessions.
// ---------------------------------------------------------------------------

/// A login begun on one replica completes on another, the session it issues
/// authenticates everywhere with the provider consulted each time, and a
/// logout on either replica ends it on both.
pub(crate) async fn contract_sessions_are_shared_and_revalidated(
    a: &AdminSessions,
    b: &AdminSessions,
    authority: &Authority,
) {
    let before = authority.calls.load(Ordering::SeqCst);
    let issued = issue_across(a, b, &HeaderMap::new()).await.unwrap();
    let headers = cookie_headers(&issued);
    let on_a = read(a, &headers).await.unwrap();
    let on_b = read(b, &headers).await.unwrap();
    assert_eq!(on_a.auth_method, AuthMethod::Cookie);
    assert_eq!(on_a.user_id, "operator");
    assert_eq!(
        on_a.session_id, on_b.session_id,
        "one session, two replicas"
    );
    assert_ne!(on_a.session_id, a.credential(&headers).unwrap());
    assert_eq!(
        authority.calls.load(Ordering::SeqCst) - before,
        3,
        "issuance and every request consult the provider"
    );
    b.revoke(&headers, None).await.unwrap();
    assert!(is_invalid(&read(a, &headers).await));
    assert!(is_invalid(&read(b, &headers).await));
    // Logout is idempotent.
    a.revoke(&headers, None).await.unwrap();
}

/// An unavailable provider keeps the session; a rejection, or a token that
/// now names another identity, withdraws it for every replica.
pub(crate) async fn contract_outage_preserves_but_rejection_and_identity_change_withdraw(
    a: &AdminSessions,
    b: &AdminSessions,
    authority: &Authority,
) {
    for withdrawing in [1, 3] {
        let headers = cookie_headers(&issue_across(a, a, &HeaderMap::new()).await.unwrap());
        authority.outcome.store(2, Ordering::SeqCst);
        assert!(is_unavailable(&read(a, &headers).await));
        authority.outcome.store(0, Ordering::SeqCst);
        read(b, &headers).await.unwrap();
        authority.outcome.store(withdrawing, Ordering::SeqCst);
        assert!(is_invalid(&read(a, &headers).await));
        authority.outcome.store(0, Ordering::SeqCst);
        assert!(
            is_invalid(&read(b, &headers).await),
            "a withdrawal on one replica is seen by the other"
        );
    }
}

/// Unsafe requests must carry the CSRF token the session was issued with;
/// safe requests need none.
pub(crate) async fn contract_unsafe_requests_need_the_bound_csrf_token(
    a: &AdminSessions,
    b: &AdminSessions,
    authority: &Authority,
) {
    let headers = cookie_headers(&issue_across(a, b, &HeaderMap::new()).await.unwrap());
    let before = authority.calls.load(Ordering::SeqCst);
    for csrf in [None, Some("another-csrf-token"), Some("")] {
        assert!(matches!(
            write(a, &headers, csrf).await,
            Err(SessionRefusal::CsrfUnbound)
        ));
    }
    assert_eq!(
        authority.calls.load(Ordering::SeqCst),
        before,
        "an unbound token is refused before the provider is asked"
    );
    let mut duplicated = headers.clone();
    duplicated.append(CSRF_HEADER, CSRF.parse().unwrap());
    duplicated.append(CSRF_HEADER, CSRF.parse().unwrap());
    let value = a.credential(&duplicated).unwrap();
    assert!(matches!(
        a.authenticate(&value, &Method::DELETE, &duplicated).await,
        Err(SessionRefusal::CsrfUnbound)
    ));
    write(b, &headers, Some(CSRF)).await.unwrap();
    read(a, &headers).await.unwrap();
    // A refusal does not end the session.
    write(a, &headers, Some(CSRF)).await.unwrap();
    a.revoke(&headers, None).await.unwrap();
}

/// A logout during the provider check wins: the request is not admitted.
pub(crate) async fn contract_logout_wins_over_validation_in_flight(
    a: &AdminSessions,
    b: &AdminSessions,
    authority: &Authority,
) {
    let headers = cookie_headers(&issue_across(a, a, &HeaderMap::new()).await.unwrap());
    authority.pause.store(1, Ordering::SeqCst);
    let work = tokio::spawn({
        let a = a.clone();
        let headers = headers.clone();
        async move { read(&a, &headers).await }
    });
    authority.entered.notified().await;
    b.revoke(&headers, None).await.unwrap();
    authority.pause.store(0, Ordering::SeqCst);
    authority.resume.notify_one();
    assert!(is_invalid(&work.await.unwrap()));
}

/// Logout with the login's binding cancels a completion still waiting on the
/// IdP, and an issued session whose response never reached the browser,
/// whichever replica each step lands on.
pub(crate) async fn contract_logout_cancels_pending_and_undelivered_completion(
    a: &AdminSessions,
    b: &AdminSessions,
    authority: &Authority,
) {
    a.begin_login("pending", Duration::from_secs(30), &HeaderMap::new())
        .await
        .unwrap();
    authority.pause.store(1, Ordering::SeqCst);
    let work = tokio::spawn({
        let a = a.clone();
        async move {
            a.issue(
                uuid::Uuid::new_v4().to_string(),
                &HeaderMap::new(),
                "pending",
                CSRF,
            )
            .await
        }
    });
    authority.entered.notified().await;
    b.revoke(&HeaderMap::new(), Some("pending")).await.unwrap();
    authority.pause.store(0, Ordering::SeqCst);
    authority.resume.notify_one();
    assert!(matches!(
        work.await.unwrap(),
        Err(AuthError::InvalidSession(_))
    ));

    a.begin_login("undelivered", Duration::from_secs(30), &HeaderMap::new())
        .await
        .unwrap();
    let issued = a
        .issue(
            uuid::Uuid::new_v4().to_string(),
            &HeaderMap::new(),
            "undelivered",
            CSRF,
        )
        .await
        .unwrap();
    b.revoke(&HeaderMap::new(), Some("undelivered"))
        .await
        .unwrap();
    assert!(is_invalid(&read(a, &cookie_headers(&issued)).await));
    // A binding issues at most one session.
    assert!(matches!(
        a.issue(
            uuid::Uuid::new_v4().to_string(),
            &HeaderMap::new(),
            "undelivered",
            CSRF,
        )
        .await,
        Err(AuthError::InvalidSession(_))
    ));
    // Once presented, a session no longer depends on its binding: a stale
    // binding cannot end it.
    a.begin_login("delivered", Duration::from_secs(30), &HeaderMap::new())
        .await
        .unwrap();
    let issued = a
        .issue(
            uuid::Uuid::new_v4().to_string(),
            &HeaderMap::new(),
            "delivered",
            CSRF,
        )
        .await
        .unwrap();
    let headers = cookie_headers(&issued);
    read(b, &headers).await.unwrap();
    a.revoke(&HeaderMap::new(), Some("delivered"))
        .await
        .unwrap();
    read(b, &headers).await.unwrap();
    b.revoke(&headers, None).await.unwrap();
}

/// A new sign-in in a browser that presents a live session replaces it in the
/// same step, on every replica.
pub(crate) async fn contract_sign_in_replaces_the_presented_session(
    a: &AdminSessions,
    b: &AdminSessions,
    _authority: &Authority,
) {
    let original = cookie_headers(&issue_across(a, a, &HeaderMap::new()).await.unwrap());
    read(a, &original).await.unwrap();
    let replacement = cookie_headers(&issue_across(b, a, &original).await.unwrap());
    assert!(is_invalid(&read(b, &original).await));
    read(b, &replacement).await.unwrap();
    a.revoke(&replacement, None).await.unwrap();
}

/// The capacity of a store is shared by its replicas: at capacity a grant is
/// refused as unavailable without evicting anyone, unless it replaces the
/// session the browser presents. Pending logins are bounded the same way.
pub(crate) async fn contract_capacity_is_shared_and_never_evicts(
    a: &AdminSessions,
    b: &AdminSessions,
    _authority: &Authority,
) {
    let held = cookie_headers(&issue_across(a, a, &HeaderMap::new()).await.unwrap());
    // The issued session's login is still tracked until it is presented.
    assert!(matches!(
        b.begin_login("second", Duration::from_secs(30), &HeaderMap::new())
            .await,
        Err(AuthError::Upstream(_))
    ));
    read(b, &held).await.unwrap();
    b.begin_login("second", Duration::from_secs(30), &HeaderMap::new())
        .await
        .unwrap();
    assert!(matches!(
        a.issue(
            uuid::Uuid::new_v4().to_string(),
            &HeaderMap::new(),
            "second",
            CSRF
        )
        .await,
        Err(AuthError::Upstream(_))
    ));
    read(a, &held).await.unwrap();
    // Replacing the presented session fits.
    let replacement = a
        .issue(uuid::Uuid::new_v4().to_string(), &held, "second", CSRF)
        .await
        .unwrap();
    assert!(is_invalid(&read(b, &held).await));
    let replacement = cookie_headers(&replacement);
    read(b, &replacement).await.unwrap();
    // Logout frees the slot.
    b.revoke(&replacement, None).await.unwrap();
    let next = cookie_headers(&issue_across(a, b, &HeaderMap::new()).await.unwrap());
    read(a, &next).await.unwrap();
    a.revoke(&next, None).await.unwrap();
}

/// What an open audit event stream asks of its session: the same judgement
/// as a request -- live, accepted by the provider for the same identity,
/// still live afterwards -- with no CSRF token. A logout on either replica,
/// a rejection or an identity change ends it, an unavailable provider is
/// reported as unavailable without ending the session, and a logout during
/// the provider check wins.
pub(crate) async fn contract_reauthentication_follows_the_session(
    a: &AdminSessions,
    b: &AdminSessions,
    authority: &Authority,
) {
    let headers = cookie_headers(&issue_across(a, b, &HeaderMap::new()).await.unwrap());
    let admitted = read(a, &headers).await.unwrap();
    let value = a.credential(&headers).unwrap();
    let rechecked = b.reauthenticate(&value).await.unwrap();
    assert_eq!(rechecked.auth_method, AuthMethod::Cookie);
    assert_eq!(rechecked.user_id, admitted.user_id);
    assert_eq!(
        rechecked.session_id, admitted.session_id,
        "the same session, on either replica"
    );
    authority.outcome.store(2, Ordering::SeqCst);
    assert!(matches!(
        a.reauthenticate(&value).await,
        Err(AuthError::Upstream(_))
    ));
    authority.outcome.store(0, Ordering::SeqCst);
    a.reauthenticate(&value).await.unwrap();
    b.revoke(&headers, None).await.unwrap();
    assert!(matches!(
        a.reauthenticate(&value).await,
        Err(AuthError::InvalidSession(_))
    ));

    for withdrawing in [1, 3] {
        let headers = cookie_headers(&issue_across(a, a, &HeaderMap::new()).await.unwrap());
        read(a, &headers).await.unwrap();
        let value = a.credential(&headers).unwrap();
        authority.outcome.store(withdrawing, Ordering::SeqCst);
        assert!(matches!(
            a.reauthenticate(&value).await,
            Err(AuthError::InvalidSession(_))
        ));
        authority.outcome.store(0, Ordering::SeqCst);
        assert!(
            is_invalid(&read(b, &headers).await),
            "a re-check the provider refuses withdraws the session everywhere"
        );
    }

    let headers = cookie_headers(&issue_across(a, a, &HeaderMap::new()).await.unwrap());
    read(a, &headers).await.unwrap();
    let value = a.credential(&headers).unwrap();
    authority.pause.store(1, Ordering::SeqCst);
    let work = tokio::spawn({
        let a = a.clone();
        async move { a.reauthenticate(&value).await }
    });
    authority.entered.notified().await;
    b.revoke(&headers, None).await.unwrap();
    authority.pause.store(0, Ordering::SeqCst);
    authority.resume.notify_one();
    assert!(matches!(
        work.await.unwrap(),
        Err(AuthError::InvalidSession(_))
    ));
}

/// Every contract case a store with room for at least four sessions must
/// pass. Capacity is checked separately, with a store of one.
pub(crate) async fn run_session_contract(
    a: &AdminSessions,
    b: &AdminSessions,
    authority: &Authority,
) {
    contract_sessions_are_shared_and_revalidated(a, b, authority).await;
    contract_reauthentication_follows_the_session(a, b, authority).await;
    contract_outage_preserves_but_rejection_and_identity_change_withdraw(a, b, authority).await;
    contract_unsafe_requests_need_the_bound_csrf_token(a, b, authority).await;
    contract_logout_wins_over_validation_in_flight(a, b, authority).await;
    contract_logout_cancels_pending_and_undelivered_completion(a, b, authority).await;
    contract_sign_in_replaces_the_presented_session(a, b, authority).await;
}

// ---------------------------------------------------------------------------
// The memory store
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_memory_store_satisfies_the_session_contract() {
    let authority = Arc::new(Authority::default());
    let (sessions, _) = new_sessions(&authority);
    run_session_contract(&sessions, &sessions.clone(), &authority).await;
    let (single, _) = memory_sessions(&authority, 1);
    contract_capacity_is_shared_and_never_evicts(&single, &single.clone(), &authority).await;
}

#[tokio::test]
async fn admin_session_cookie_is_independent_and_authority_is_rechecked() {
    let authority = Arc::new(Authority::default());
    let (sessions, store) = new_sessions(&authority);
    let token = uuid::Uuid::new_v4().to_string();
    sessions
        .begin_login("binding", Duration::from_secs(30), &HeaderMap::new())
        .await
        .unwrap();
    let issued = sessions
        .issue(token.clone(), &HeaderMap::new(), "binding", CSRF)
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
    let principal = read(&sessions, &headers).await.unwrap();
    assert_eq!(principal.auth_method, AuthMethod::Cookie);
    assert_ne!(principal.session_id, sessions.credential(&headers).unwrap());
    read(&sessions, &headers).await.unwrap();
    assert_eq!(authority.calls.load(Ordering::SeqCst), 3);
    let value = sessions.credential(&headers).unwrap();
    let state = store.state.lock().unwrap();
    assert_eq!(state.entries.len(), 1);
    let key = sessions.session_key_for_test(&value);
    assert!(state.entries.contains_key(&key));
    // Neither the cookie, the binding nor the CSRF token is a key, and the
    // stored CSRF value is a digest.
    for secret in [value.as_str(), "binding", CSRF] {
        let plain: SessionDigest = Sha256::digest(secret).into();
        assert!(!state.entries.contains_key(&plain));
        assert!(!state.attempts.contains_key(&plain));
    }
    assert_ne!(state.entries[&key].session.csrf.as_slice(), CSRF.as_bytes());
}

#[tokio::test]
async fn admin_session_outage_preserves_session_but_rejection_revokes_it() {
    let authority = Arc::new(Authority::default());
    let (sessions, _) = new_sessions(&authority);
    contract_outage_preserves_but_rejection_and_identity_change_withdraw(
        &sessions, &sessions, &authority,
    )
    .await;
}

#[tokio::test]
async fn admin_session_expiry_identity_change_and_restart_fail_closed() {
    let authority = Arc::new(Authority::default());
    let (sessions, store) = new_sessions(&authority);
    let headers = cookie_headers(&issue(&sessions).await);
    for entry in store.state.lock().unwrap().entries.values_mut() {
        entry.expires_at = Instant::now();
    }
    assert!(is_invalid(&read(&sessions, &headers).await));
    assert_eq!(
        authority.calls.load(Ordering::SeqCst),
        1,
        "expired sessions do not consult authority"
    );
    let headers = cookie_headers(&issue(&sessions).await);
    let (restarted, _) = new_sessions(&authority);
    assert!(is_invalid(&read(&restarted, &headers).await));
    authority.outcome.store(3, Ordering::SeqCst);
    assert!(is_invalid(&read(&sessions, &headers).await));
}

#[tokio::test]
async fn admin_session_idle_deadline_moves_with_use_but_never_past_the_absolute_one() {
    let authority = Arc::new(Authority::default());
    let mut config = session_config(AdminSessionStorage::StandaloneMemory, 8);
    config.idle_timeout = Duration::from_secs(20);
    let store = Arc::new(MemoryAdminSessionStore::new(config.clone()));
    let sessions = front(
        &authority,
        Arc::clone(&store) as Arc<dyn AdminSessionStore>,
        config,
    );
    let headers = cookie_headers(&issue(&sessions).await);
    let deadlines = || {
        let state = store.state.lock().unwrap();
        let entry = state.entries.values().next().unwrap();
        (entry.idle_expires_at, entry.expires_at)
    };
    let (idle, absolute) = deadlines();
    assert!(idle < absolute, "the idle limit binds before the TTL");
    // Pull the idle deadline in: use moves it forward again, capped at the
    // absolute deadline.
    for entry in store.state.lock().unwrap().entries.values_mut() {
        entry.idle_expires_at = Instant::now() + Duration::from_secs(1);
        entry.expires_at = Instant::now() + Duration::from_secs(5);
    }
    read(&sessions, &headers).await.unwrap();
    let (idle, absolute) = deadlines();
    assert_eq!(idle, absolute, "use never extends the absolute deadline");
    // An idle session is refused even before its absolute deadline.
    for entry in store.state.lock().unwrap().entries.values_mut() {
        entry.idle_expires_at = Instant::now();
    }
    let calls = authority.calls.load(Ordering::SeqCst);
    assert!(is_invalid(&read(&sessions, &headers).await));
    assert_eq!(authority.calls.load(Ordering::SeqCst), calls);
    assert!(store.state.lock().unwrap().entries.is_empty());
}

#[tokio::test]
async fn admin_session_reauthentication_is_not_use_and_never_moves_a_deadline() {
    let authority = Arc::new(Authority::default());
    let mut config = session_config(AdminSessionStorage::StandaloneMemory, 8);
    config.idle_timeout = Duration::from_secs(20);
    let store = Arc::new(MemoryAdminSessionStore::new(config.clone()));
    let sessions = front(
        &authority,
        Arc::clone(&store) as Arc<dyn AdminSessionStore>,
        config,
    );
    let headers = cookie_headers(&issue(&sessions).await);
    read(&sessions, &headers).await.unwrap();
    let value = sessions.credential(&headers).unwrap();
    let soon = Instant::now() + Duration::from_secs(2);
    for entry in store.state.lock().unwrap().entries.values_mut() {
        entry.idle_expires_at = soon;
    }
    let deadlines = || {
        let state = store.state.lock().unwrap();
        let entry = state.entries.values().next().unwrap();
        (entry.idle_expires_at, entry.expires_at)
    };
    let before = deadlines();

    sessions.reauthenticate(&value).await.unwrap();
    sessions.reauthenticate(&value).await.unwrap();

    assert_eq!(
        deadlines(),
        before,
        "an open stream cannot keep an idle session alive"
    );
    // Once the idle deadline passes, the re-check is refused without asking
    // the provider, as a request would be.
    for entry in store.state.lock().unwrap().entries.values_mut() {
        entry.idle_expires_at = Instant::now();
    }
    let calls = authority.calls.load(Ordering::SeqCst);
    assert!(matches!(
        sessions.reauthenticate(&value).await,
        Err(AuthError::InvalidSession(_))
    ));
    assert_eq!(authority.calls.load(Ordering::SeqCst), calls);
    // A malformed cookie value is refused before the store is consulted.
    assert!(matches!(
        sessions.reauthenticate("not-a-session").await,
        Err(AuthError::InvalidSession(_))
    ));
}

#[tokio::test]
async fn admin_session_logout_wins_over_validation_in_flight() {
    let authority = Arc::new(Authority::default());
    let (sessions, _) = new_sessions(&authority);
    contract_logout_wins_over_validation_in_flight(&sessions, &sessions, &authority).await;
}

#[tokio::test]
async fn admin_session_logout_cancels_pending_and_undelivered_completion() {
    let authority = Arc::new(Authority::default());
    let (sessions, _) = new_sessions(&authority);
    contract_logout_cancels_pending_and_undelivered_completion(&sessions, &sessions, &authority)
        .await;
}

#[tokio::test]
async fn admin_session_unsafe_requests_need_the_bound_csrf_token() {
    let authority = Arc::new(Authority::default());
    let (sessions, _) = new_sessions(&authority);
    contract_unsafe_requests_need_the_bound_csrf_token(&sessions, &sessions, &authority).await;
}

#[tokio::test]
async fn admin_session_capacity_and_duplicate_cookies_fail_closed() {
    let authority = Arc::new(Authority::default());
    let (sessions, _) = memory_sessions(&authority, 1);
    let issued = issue(&sessions).await;
    assert!(sessions
        .begin_login("second", Duration::from_secs(30), &HeaderMap::new())
        .await
        .is_err());
    let mut headers = cookie_headers(&issued);
    let cookie = headers[header::COOKIE].clone();
    headers.append(header::COOKIE, cookie);
    assert_eq!(sessions.credential(&headers).as_deref(), Some(""));
    assert!(is_invalid(&read(&sessions, &headers).await));
    for malformed in ["", "not-hex", &"g".repeat(64), &"a".repeat(63)] {
        assert!(is_invalid(
            &sessions
                .authenticate(malformed, &Method::GET, &HeaderMap::new())
                .await
        ));
    }
}

#[test]
fn admin_session_requires_https_bounded_config_and_exact_origin() {
    let authority = Arc::new(Authority::default());
    let (sessions, store) = new_sessions(&authority);
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
    let store = store as Arc<dyn AdminSessionStore>;
    let build = |config: AdminSessionConfig, origin: &str, csrf_header: &str| {
        AdminSessions::new(
            config,
            Arc::clone(&authority) as Arc<dyn SessionValidator>,
            Arc::clone(&store),
            "/operations",
            origin.to_owned(),
            csrf_header,
        )
    };
    let valid = session_config(AdminSessionStorage::StandaloneMemory, 8);
    assert!(build(
        valid.clone(),
        "https://management.example.test",
        CSRF_HEADER
    )
    .is_ok());
    assert!(build(valid.clone(), "http://localhost", CSRF_HEADER).is_err());
    assert!(build(valid.clone(), "https://management.example.test", "").is_err());
    let mut longer_idle = valid.clone();
    longer_idle.idle_timeout = valid.ttl + Duration::from_secs(1);
    let mut no_idle = valid.clone();
    no_idle.idle_timeout = Duration::ZERO;
    let mut too_long = valid.clone();
    too_long.ttl = Duration::from_secs(MAX_SESSION_TTL_SECS + 1);
    too_long.idle_timeout = too_long.ttl;
    let mut too_many = valid.clone();
    too_many.max_entries = MAX_SESSION_ENTRIES + 1;
    let mut none = valid;
    none.max_entries = 0;
    for invalid in [longer_idle, no_idle, too_long, too_many, none] {
        assert!(build(invalid, "https://management.example.test", CSRF_HEADER).is_err());
    }
    assert_eq!(
        sessions.storage().as_str(),
        "standalone_memory",
        "the advertised storage names the mode"
    );
    assert_eq!(
        AdminSessionStorage::ClusterPostgres.as_str(),
        "cluster_postgres"
    );
    assert!(is_safe_method(&Method::GET));
    assert!(is_safe_method(&Method::HEAD));
    assert!(is_safe_method(&Method::OPTIONS));
    for unsafe_method in [Method::POST, Method::PUT, Method::PATCH, Method::DELETE] {
        assert!(!is_safe_method(&unsafe_method));
    }
}

#[tokio::test]
async fn admin_session_delivered_cookie_releases_login_capacity_for_logout_and_replacement() {
    let authority = Arc::new(Authority::default());
    let (sessions, store) = memory_sessions(&authority, 1);
    let original = cookie_headers(&issue(&sessions).await);
    sessions.revoke(&original, None).await.unwrap();
    let replacement = cookie_headers(&issue(&sessions).await);
    assert!(is_invalid(&read(&sessions, &original).await));
    sessions
        .begin_login("replace", Duration::from_secs(30), &replacement)
        .await
        .unwrap();
    let next = sessions
        .issue(
            uuid::Uuid::new_v4().to_string(),
            &replacement,
            "replace",
            CSRF,
        )
        .await
        .unwrap();
    assert!(is_invalid(&read(&sessions, &replacement).await));
    read(&sessions, &cookie_headers(&next)).await.unwrap();
    assert!(store.state.lock().unwrap().attempts.is_empty());
}

#[tokio::test]
async fn admin_session_refuses_an_oversized_token_or_missing_csrf_before_asking_the_provider() {
    let authority = Arc::new(Authority::default());
    let (sessions, _) = new_sessions(&authority);
    sessions
        .begin_login("binding", Duration::from_secs(30), &HeaderMap::new())
        .await
        .unwrap();
    for (token, csrf) in [
        (String::new(), CSRF),
        ("t".repeat(MAX_ACCESS_TOKEN_BYTES + 1), CSRF),
        ("token".to_owned(), ""),
    ] {
        assert!(matches!(
            sessions
                .issue(token, &HeaderMap::new(), "binding", csrf)
                .await,
            Err(AuthError::InvalidSession(_))
        ));
    }
    assert_eq!(authority.calls.load(Ordering::SeqCst), 0);
    // The login is still pending: a valid completion succeeds.
    sessions
        .issue(
            "t".repeat(MAX_ACCESS_TOKEN_BYTES),
            &HeaderMap::new(),
            "binding",
            CSRF,
        )
        .await
        .unwrap();
}
