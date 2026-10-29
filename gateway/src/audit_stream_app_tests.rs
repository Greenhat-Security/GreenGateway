//! An open audit event stream stays authorized only for as long as its
//! caller does (part of #420).
//!
//! These drive the real endpoint with shortened [`AuditStreamLimits`], so a
//! re-check and a lifetime can be watched happening. The other two halves
//! are tested where they live: that the authentication middleware hands the
//! endpoint the credential it admitted (`middleware::auth`), and that an
//! admin session re-check follows logout without counting as use (the
//! admin session contract). The durable stream's closing frame is in
//! `durable_sse_tests`.
use super::*;
use crate::audit::sink::tests::CaptureSink;
use std::sync::atomic::{AtomicUsize, Ordering};

const STREAMER: &str = "audit-streamer";
const REQUEST_ID: &str = "stream-reauthorization";

/// Re-checks often enough to watch, and a lifetime no test reaches unless
/// it shortens it.
const WATCHED: AuditStreamLimits = AuditStreamLimits {
    recheck_interval: Duration::from_millis(50),
    max_lifetime: Duration::from_secs(60),
};

/// What the stand-in authority answers when the stream asks again.
#[derive(Clone)]
enum Verdict {
    Accept(auth::Principal),
    Refuse,
    Unavailable,
    Hang,
}

/// The authority a stream's credential answers to, which a test turns
/// against the stream while it is open.
struct Authority {
    verdict: Mutex<Verdict>,
    calls: AtomicUsize,
}

impl Authority {
    fn accepting(principal: &auth::Principal) -> Arc<Self> {
        Arc::new(Self {
            verdict: Mutex::new(Verdict::Accept(principal.clone())),
            calls: AtomicUsize::new(0),
        })
    }

    fn answer(&self, verdict: Verdict) {
        *self.verdict.lock().unwrap() = verdict;
    }
}

#[async_trait::async_trait]
impl auth::SessionValidator for Authority {
    async fn validate_session(
        &self,
        _credential: &auth::SessionCredential,
    ) -> Result<auth::Principal, auth::AuthError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let verdict = self.verdict.lock().unwrap().clone();
        match verdict {
            Verdict::Accept(principal) => Ok(principal),
            Verdict::Refuse => Err(auth::AuthError::InvalidSession("token revoked".to_owned())),
            Verdict::Unavailable => Err(auth::AuthError::Upstream("issuer unreachable".to_owned())),
            Verdict::Hang => std::future::pending().await,
        }
    }
}

fn stream_policy(streamer_permissions: &[&str]) -> String {
    json!({
        "schema_version": "0.1.0",
        "default_action": "deny",
        "roles": {
            STREAMER: { "permissions": streamer_permissions },
            "reader": { "permissions": [ADMIN_AUDIT_READ_PERMISSION] }
        }
    })
    .to_string()
}

struct Harness {
    router: Router,
    events: audit::AuditEventSender,
    rbac: middleware::rbac::RbacState,
    policy: TempPolicyFile,
    capture: CaptureSink,
}

fn stream_harness(limits: AuditStreamLimits) -> Harness {
    let policy = TempPolicyFile::new(&stream_policy(&[ADMIN_AUDIT_STREAM_PERMISSION]));
    let capture = CaptureSink::new();
    let rbac = middleware::rbac::RbacState::new(
        rbac::policy::Policy::from_file(&policy.path).expect("stream policy should parse"),
        Vec::new(),
        false,
        audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>),
    );
    let (events, _) = tokio::sync::broadcast::channel(16);
    let router = Router::new()
        .route(AUDIT_EVENTS_STREAM_ROUTE, get(audit_events_stream_endpoint))
        .with_state(AuditAdminState {
            query_store: None,
            event_sender: events.clone(),
            rbac_state: Some(rbac.clone()),
            stream_limits: limits,
            #[cfg(feature = "postgres")]
            pg_audit: None,
        });
    Harness {
        router,
        events,
        rbac,
        policy,
        capture,
    }
}

/// A stream request as the authentication middleware hands it on: the
/// principal, and beside it the credential it was admitted with.
fn admitted(principal: &auth::Principal, authority: &Arc<Authority>) -> Request<Body> {
    let mut request = Request::builder()
        .uri(AUDIT_EVENTS_STREAM_ROUTE)
        .header(REQUEST_ID_HEADER, REQUEST_ID)
        .body(Body::empty())
        .expect("stream request should build");
    request.extensions_mut().insert(principal.clone());
    request.extensions_mut().insert(auth::Reauthentication::new(
        auth::CredentialJudge::Validator(Arc::clone(authority) as Arc<dyn auth::SessionValidator>),
        auth::SessionCredential::Bearer(format!("test-{}", uuid::Uuid::new_v4())),
        None,
    ));
    request
}

/// An open stream, read frame by frame.
struct OpenStream {
    body: axum::body::BodyDataStream,
    received: String,
}

impl OpenStream {
    async fn open(harness: &Harness, request: Request<Body>) -> Self {
        let response = harness
            .router
            .clone()
            .oneshot(request)
            .await
            .expect("stream request should complete");
        assert_eq!(response.status(), StatusCode::OK);
        Self {
            body: response.into_body().into_data_stream(),
            received: String::new(),
        }
    }

    /// Read until `event` has been delivered.
    async fn delivered(&mut self, event: &audit::AuditEvent) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while !contains_event_id(&self.received, &event.event_id) {
                let chunk = self
                    .body
                    .next()
                    .await
                    .expect("stream ended before the event arrived")
                    .expect("stream chunk should read");
                self.received
                    .push_str(std::str::from_utf8(&chunk).expect("SSE chunk should be UTF-8"));
            }
        })
        .await
        .expect("event should be delivered");
    }

    /// Read until the gateway ends the stream, and return everything sent.
    async fn ended(mut self) -> String {
        tokio::time::timeout(Duration::from_secs(5), async {
            while let Some(chunk) = self.body.next().await {
                let chunk = chunk.expect("stream chunk should read");
                self.received
                    .push_str(std::str::from_utf8(&chunk).expect("SSE chunk should be UTF-8"));
            }
        })
        .await
        .expect("the gateway should end the stream");
        self.received
    }
}

/// The stream's last frame, which must be its closing frame, and its
/// reason.
fn closing_reason(body: &str) -> String {
    let last = body
        .rsplit("\n\n")
        .find(|frame| !frame.trim().is_empty())
        .unwrap_or_else(|| panic!("the stream sent nothing: {body:?}"));
    assert!(
        last.lines().any(|line| line == "event: stream.closed"),
        "the last frame must be the closing frame: {body:?}"
    );
    assert!(
        !last.lines().any(|line| line.starts_with("id:")),
        "the closing frame carries no stream position: {last:?}"
    );
    let data = last
        .lines()
        .find_map(|line| line.strip_prefix("data: "))
        .unwrap_or_else(|| panic!("the closing frame has no data: {last:?}"));
    let data: Value = serde_json::from_str(data).expect("closing frame data should be JSON");
    assert_eq!(
        data.as_object().map(serde_json::Map::len),
        Some(1),
        "the closing frame says why and nothing else: {data}"
    );
    data["reason"]
        .as_str()
        .expect("closing reason should be a string")
        .to_owned()
}

/// The one audit record of the stream's end.
fn recorded_end(capture: &CaptureSink, event_type: &str) -> audit::AuditEvent {
    assert_eventually(Duration::from_secs(5), || {
        capture
            .events()
            .iter()
            .any(|event| event.event_type == event_type)
    });
    let ends: Vec<_> = capture
        .events()
        .into_iter()
        .filter(|event| event.event_type == event_type)
        .collect();
    assert_eq!(ends.len(), 1, "one record per ended stream: {ends:?}");
    let end = ends.into_iter().next().expect("one record");
    assert_eq!(end.request_id, REQUEST_ID);
    assert_eq!(
        end.actor.as_ref().map(|actor| actor.user_id.as_str()),
        Some("user-123")
    );
    assert_eq!(end.payload["path"], AUDIT_EVENTS_STREAM_ROUTE);
    assert_eq!(end.payload["authorization_layer"], "audit_event_stream");
    end
}

#[tokio::test]
async fn a_stream_ends_once_its_credential_is_refused_on_recheck() {
    let harness = stream_harness(WATCHED);
    let principal = test_principal(&[STREAMER]);
    let authority = Authority::accepting(&principal);
    let mut stream = OpenStream::open(&harness, admitted(&principal, &authority)).await;
    let before = test_stream_event("audit.stream.before", "/before");
    harness
        .events
        .send(before.clone())
        .expect("the stream should be subscribed");
    stream.delivered(&before).await;

    // Logout, expiry and revocation all look the same from here: the
    // authority that admitted the credential no longer accepts it.
    authority.answer(Verdict::Refuse);
    let body = stream.ended().await;

    assert_eq!(closing_reason(&body), "session_ended");
    let end = recorded_end(&harness.capture, "auth.failure");
    assert_eq!(end.payload["reason"], "token revoked");
    assert!(authority.calls.load(Ordering::SeqCst) >= 1);
    assert!(
        harness
            .events
            .send(test_stream_event("audit.stream.after", "/after"))
            .is_err(),
        "an ended stream no longer listens for events"
    );
}

#[tokio::test]
async fn a_stream_fails_closed_when_its_authority_cannot_answer() {
    for (verdict, recorded) in [
        (Verdict::Unavailable, "upstream_error: issuer unreachable"),
        // A re-check that never answers is cut off at the interval.
        (Verdict::Hang, "recheck_timed_out"),
    ] {
        let harness = stream_harness(WATCHED);
        let principal = test_principal(&[STREAMER]);
        let authority = Authority::accepting(&principal);
        let stream = OpenStream::open(&harness, admitted(&principal, &authority)).await;
        authority.answer(verdict);

        let body = stream.ended().await;

        assert_eq!(closing_reason(&body), "session_unverifiable");
        let end = recorded_end(&harness.capture, "auth.failure");
        assert_eq!(end.payload["reason"], recorded);
    }
}

#[tokio::test]
async fn a_stream_ends_when_its_credential_names_someone_else_or_loses_the_role() {
    let harness = stream_harness(WATCHED);
    let principal = test_principal(&[STREAMER]);
    let authority = Authority::accepting(&principal);
    let stream = OpenStream::open(&harness, admitted(&principal, &authority)).await;
    let mut someone_else = principal.clone();
    someone_else.user_id = "user-456".to_owned();
    authority.answer(Verdict::Accept(someone_else));

    assert_eq!(closing_reason(&stream.ended().await), "session_ended");
    let end = recorded_end(&harness.capture, "auth.failure");
    assert_eq!(end.payload["reason"], "identity_changed");

    // The same identity, whose authority now reports roles that no longer
    // grant the stream.
    let harness = stream_harness(WATCHED);
    let stream = OpenStream::open(&harness, admitted(&principal, &authority)).await;
    authority.answer(Verdict::Accept(test_principal(&["reader"])));

    assert_eq!(closing_reason(&stream.ended().await), "permission_revoked");
    let end = recorded_end(&harness.capture, "authz.denied");
    assert_eq!(end.payload["reason"], "missing_permission");
    assert_eq!(end.payload["permission"], ADMIN_AUDIT_STREAM_PERMISSION);
    assert_eq!(end.payload["operation"], "stream");
}

#[tokio::test]
async fn a_policy_change_stops_delivery_at_the_next_event() {
    // No re-check falls inside this test: the permission is checked against
    // the live policy before every frame, without waiting for one.
    let harness = stream_harness(AuditStreamLimits {
        recheck_interval: Duration::from_secs(60),
        max_lifetime: Duration::from_secs(60),
    });
    let principal = test_principal(&[STREAMER]);
    let authority = Authority::accepting(&principal);
    let mut stream = OpenStream::open(&harness, admitted(&principal, &authority)).await;
    let before = test_stream_event("audit.stream.before", "/before");
    harness.events.send(before.clone()).expect("subscribed");
    stream.delivered(&before).await;

    harness.policy.write(&stream_policy(&[]));
    middleware::rbac::reload_policy_from_file(&harness.rbac, &harness.policy.path)
        .await
        .expect("the narrower policy should install");
    let after = test_stream_event("audit.stream.after", "/after");
    harness.events.send(after.clone()).expect("subscribed");
    let body = stream.ended().await;

    assert!(
        !contains_event_id(&body, &after.event_id),
        "no event is delivered after the permission is gone: {body}"
    );
    assert_eq!(closing_reason(&body), "permission_revoked");
    recorded_end(&harness.capture, "authz.denied");
    assert_eq!(
        authority.calls.load(Ordering::SeqCst),
        0,
        "the policy, not a re-check, ended this stream"
    );
}

#[tokio::test]
async fn a_stream_that_stays_authorized_still_ends_at_its_lifetime() {
    let harness = stream_harness(AuditStreamLimits {
        recheck_interval: Duration::from_millis(50),
        max_lifetime: Duration::from_millis(600),
    });
    let principal = test_principal(&[STREAMER]);
    let authority = Authority::accepting(&principal);
    let stream = OpenStream::open(&harness, admitted(&principal, &authority)).await;

    let body = stream.ended().await;

    assert_eq!(closing_reason(&body), "lifetime_elapsed");
    assert!(
        authority.calls.load(Ordering::SeqCst) >= 2,
        "the credential was re-checked while the stream was open"
    );
    // Reaching the lifetime is not a security decision: nothing is
    // recorded as a failure or a denial.
    let recorded: Vec<_> = harness
        .capture
        .events()
        .into_iter()
        .map(|event| event.event_type)
        .collect();
    assert!(
        !recorded
            .iter()
            .any(|event_type| event_type == "auth.failure" || event_type == "authz.denied"),
        "{recorded:?}"
    );
}

#[tokio::test]
async fn a_principal_without_its_credential_is_not_streamed() {
    let harness = stream_harness(WATCHED);
    let mut request = Request::builder()
        .uri(AUDIT_EVENTS_STREAM_ROUTE)
        .body(Body::empty())
        .expect("stream request should build");
    request.extensions_mut().insert(test_principal(&[STREAMER]));

    let response = harness
        .router
        .clone()
        .oneshot(request)
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        body_string(response).await,
        r#"{"error":"audit event stream cannot re-check the caller"}"#
    );
    // Authentication and permission still answer first.
    let response = harness
        .router
        .clone()
        .oneshot(audit_query_request(
            AUDIT_EVENTS_STREAM_ROUTE,
            Some(test_principal(&["reader"])),
        ))
        .await
        .expect("request should complete");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[test]
fn every_stream_is_rechecked_well_within_its_lifetime() {
    let served = AuditStreamLimits::SERVED;
    assert_eq!(served.recheck_interval, Duration::from_secs(15));
    assert_eq!(served.max_lifetime, Duration::from_secs(30 * 60));
    assert!(served.recheck_interval * 4 <= served.max_lifetime);
}
