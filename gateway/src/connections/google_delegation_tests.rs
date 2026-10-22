//! Google domain-wide delegation without Google: a stub stands in for the IAM Credentials
//! `signJwt` method and the token endpoint, another for the federated identity, and every call
//! goes through the Connection runtime a manual tool call uses. Nothing reaches the network, and
//! no key exists anywhere: the stub "signs" by echoing the claims it was asked to sign.

use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Mutex,
    },
};

use serde_json::Value;

use super::*;
use crate::{
    audit::{sink::tests::CaptureSink, AuditSink},
    auth::{AuthMethod, Principal},
    config::Config,
    connections::{
        control_plane::ConnectionControlPlane,
        gcp_secret::GcpProfileConfig,
        http::{ConnectionHttpError, ConnectionHttpRuntime},
        model::{
            ConnectionAuthentication, ConnectionEndpoint, ConnectionKind, ConnectionWrite,
            GoogleSubjectClaim, TlsProfile,
        },
        token_exchange::{DelegatedTokenPurgeTrigger, ManualTokenClock},
    },
    egress::EgressConfig,
};

const PROFILE: &str = "gateway-wif";
const SERVICE_ACCOUNT: &str = "gateway-delegate@example-project.iam.gserviceaccount.com";
const TRUSTED_ISSUER: &str = "https://idp.example.test";
const GMAIL_READ: &str = "https://www.googleapis.com/auth/gmail.readonly";
const CALENDAR_READ: &str = "https://www.googleapis.com/auth/calendar.readonly";
/// What the stubs hand out or add. None of it may surface in an error, a log line or audit.
const FEDERATED_TOKEN_CANARY: &str = "federated-token-canary";
const SIGNATURE_CANARY: &str = "c2lnbmF0dXJlLWNhbmFyeQ";
const DENIAL_DESCRIPTION_CANARY: &str = "delegation-denied-description-canary";

/// What the stub `signJwt` does with the next request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Signer {
    /// Signs exactly what it was asked to.
    Sign,
    /// Answers every request with this status.
    Refuse(u16),
    /// Answers `401` once, as for an expired federated token, then signs.
    ExpireOnce,
    /// Signs, but for another user than the one it was asked about.
    SwapSubject,
}

/// What the stub token endpoint does with the next assertion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Endpoint {
    Grant { expires_in: u64 },
    Refuse { status: u16, error: &'static str },
}

#[derive(Clone, Debug)]
struct Recorded {
    url: String,
    authorization: Option<String>,
    body: String,
}

struct StubGoogle {
    requests: Mutex<Vec<Recorded>>,
    denied_hosts: Mutex<Vec<&'static str>>,
    signer: Mutex<Signer>,
    endpoint: Mutex<Endpoint>,
    issued: AtomicUsize,
}

impl StubGoogle {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            requests: Mutex::new(Vec::new()),
            denied_hosts: Mutex::new(Vec::new()),
            signer: Mutex::new(Signer::Sign),
            endpoint: Mutex::new(Endpoint::Grant { expires_in: 3_599 }),
            issued: AtomicUsize::new(0),
        })
    }

    fn set_signer(&self, signer: Signer) {
        *self.signer.lock().expect("signer lock") = signer;
    }

    fn set_endpoint(&self, endpoint: Endpoint) {
        *self.endpoint.lock().expect("endpoint lock") = endpoint;
    }

    fn deny_host(&self, host: &'static str) {
        self.denied_hosts.lock().expect("host lock").push(host);
    }

    fn requests(&self) -> Vec<Recorded> {
        self.requests.lock().expect("request lock").clone()
    }

    fn signing_requests(&self) -> Vec<Recorded> {
        self.requests()
            .into_iter()
            .filter(|request| request.url.ends_with(":signJwt"))
            .collect()
    }

    fn token_requests(&self) -> Vec<Recorded> {
        self.requests()
            .into_iter()
            .filter(|request| request.url == GOOGLE_TOKEN_URL)
            .collect()
    }

    fn sign(&self, body: &str) -> (u16, String) {
        let signer = {
            let mut signer = self.signer.lock().expect("signer lock");
            let current = *signer;
            if current == Signer::ExpireOnce {
                *signer = Signer::Sign;
            }
            current
        };
        let request: Value = serde_json::from_str(body).expect("signJwt takes a JSON object");
        let payload = request["payload"]
            .as_str()
            .expect("signJwt signs a payload string");
        match signer {
            Signer::Refuse(status) => (status, json!({"error": {"code": status}}).to_string()),
            Signer::ExpireOnce => (401, json!({"error": {"code": 401}}).to_string()),
            Signer::Sign | Signer::SwapSubject => {
                let mut claims: Value =
                    serde_json::from_str(payload).expect("the payload is a JSON claim set");
                if signer == Signer::SwapSubject {
                    claims["sub"] = json!("someone-else@example.test");
                }
                let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","kid":"stub","typ":"JWT"}"#);
                let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
                (
                    200,
                    json!({
                        "keyId": "stub-signing-key",
                        "signedJwt": format!("{header}.{payload}.{SIGNATURE_CANARY}"),
                    })
                    .to_string(),
                )
            }
        }
    }

    fn exchange(&self, body: &str) -> (u16, String) {
        let fields: BTreeMap<String, String> = form_urlencoded::parse(body.as_bytes())
            .map(|(name, value)| (name.into_owned(), value.into_owned()))
            .collect();
        assert_eq!(
            fields.get("grant_type").map(String::as_str),
            Some(GRANT_TYPE_JWT_BEARER)
        );
        assert_eq!(fields.len(), 2, "only the grant type and the assertion");
        match *self.endpoint.lock().expect("endpoint lock") {
            Endpoint::Grant { expires_in } => {
                let claims = unverified_claims(&fields["assertion"]);
                let user = claims["sub"].as_str().expect("the assertion names a user");
                let serial = self.issued.fetch_add(1, Ordering::AcqRel) + 1;
                (
                    200,
                    json!({
                        "access_token": format!("google-{user}-{serial}"),
                        "expires_in": expires_in,
                        "token_type": "Bearer",
                    })
                    .to_string(),
                )
            }
            Endpoint::Refuse { status, error } => (
                status,
                json!({"error": error, "error_description": DENIAL_DESCRIPTION_CANARY}).to_string(),
            ),
        }
    }
}

#[async_trait]
impl GcpTransport for StubGoogle {
    fn egress_generation(&self) -> [u8; 32] {
        [3; 32]
    }

    async fn preflight(&self, url: &str) -> Result<(), EgressError> {
        let host = url::Url::parse(url)
            .ok()
            .and_then(|url| url.host_str().map(str::to_owned))
            .unwrap_or_default();
        if self
            .denied_hosts
            .lock()
            .expect("host lock")
            .iter()
            .any(|denied| *denied == host)
        {
            return Err(EgressError::HostNotAllowed(host));
        }
        Ok(())
    }

    async fn send(
        &self,
        method: Method,
        url: &str,
        headers: HeaderMap,
        body: Option<Vec<u8>>,
    ) -> Result<GcpHttpResponse, EgressError> {
        assert_eq!(method, Method::POST);
        let body = String::from_utf8(body.unwrap_or_default()).expect("bodies are UTF-8");
        self.requests.lock().expect("request lock").push(Recorded {
            url: url.to_owned(),
            authorization: headers
                .get(header::AUTHORIZATION)
                .map(|value| value.to_str().expect("visible ASCII").to_owned()),
            body: body.clone(),
        });
        let (status, answer) = if url == GOOGLE_TOKEN_URL {
            self.exchange(&body)
        } else if url.ends_with(":signJwt") {
            self.sign(&body)
        } else {
            panic!("nothing else is ever asked of Google");
        };
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json; charset=utf-8"),
        );
        Ok(GcpHttpResponse {
            status: StatusCode::from_u16(status).expect("a valid status"),
            headers,
            body: Zeroizing::new(answer.into_bytes()),
        })
    }
}

/// The federated identity: a token per generation, never refused.
struct StubIdentity {
    calls: Mutex<Vec<(String, u64)>>,
    generation: AtomicU64,
}

impl StubIdentity {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            calls: Mutex::new(Vec::new()),
            generation: AtomicU64::new(1),
        })
    }

    fn calls(&self) -> Vec<(String, u64)> {
        self.calls.lock().expect("call lock").clone()
    }
}

#[async_trait]
impl GoogleWorkloadIdentity for StubIdentity {
    async fn access_token(
        &self,
        profile_id: &str,
        minimum_generation: u64,
    ) -> Result<FederatedAccessToken, FederatedIdentityError> {
        self.calls
            .lock()
            .expect("call lock")
            .push((profile_id.to_owned(), minimum_generation));
        if profile_id != PROFILE {
            return Err(FederatedIdentityError::UnknownProfile);
        }
        let generation = self
            .generation
            .fetch_max(minimum_generation, Ordering::AcqRel)
            .max(minimum_generation);
        Ok(FederatedAccessToken {
            token: Zeroizing::new(format!("{FEDERATED_TOKEN_CANARY}-{generation}").into_bytes()),
            generation,
        })
    }
}

fn unverified_claims(assertion: &str) -> Value {
    let payload = assertion.split('.').nth(1).expect("a JWT has a payload");
    serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(payload)
            .expect("the payload is base64url"),
    )
    .expect("the payload is JSON")
}

fn caller_from(subject: &str, issuer: &str, email: Option<&str>) -> AttestedCaller {
    AttestedCaller::from_principal(&Principal {
        user_id: subject.to_owned(),
        issuer: Some(issuer.to_owned()),
        email: email.map(str::to_owned),
        org_id: None,
        roles: vec!["mail:read".to_owned()],
        session_id: format!("session-{subject}"),
        auth_method: AuthMethod::Bearer,
    })
    .expect("a provider-vouched principal is attestable")
}

fn alice() -> AttestedCaller {
    caller_from("alice", TRUSTED_ISSUER, Some("alice@example.test"))
}

fn bob() -> AttestedCaller {
    caller_from("bob", TRUSTED_ISSUER, Some("bob@example.test"))
}

fn delegation_write() -> ConnectionWrite {
    ConnectionWrite {
        display_name: "Workspace mail".to_owned(),
        description: None,
        enabled: true,
        kind: ConnectionKind::HttpApi,
        endpoint: ConnectionEndpoint {
            base_url: "https://gmail.googleapis.com".to_owned(),
            base_path: "/gmail/v1".to_owned(),
        },
        authentication: ConnectionAuthentication::GoogleDomainWideDelegation {
            service_account_email: SERVICE_ACCOUNT.to_owned(),
            workload_identity_profile: PROFILE.to_owned(),
            scopes: vec![GMAIL_READ.to_owned(), CALENDAR_READ.to_owned()],
            subject_claim: GoogleSubjectClaim::Email,
            // Stored canonical: the trailing slash goes.
            subject_issuers: vec![format!("{TRUSTED_ISSUER}/")],
        },
        additional_headers: Vec::new(),
        caller_assertion: None,
        tls: TlsProfile::default(),
        timeouts: None,
        discovery: None,
        test_profile: None,
    }
}

struct Harness {
    root: PathBuf,
    runtime: ConnectionHttpRuntime,
    control_plane: ConnectionControlPlane,
    connection_id: String,
    google: Arc<StubGoogle>,
    identity: Arc<StubIdentity>,
    clock: Arc<ManualTokenClock>,
    capture: CaptureSink,
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

impl Harness {
    async fn new() -> Self {
        Self::build(8, true).await
    }

    async fn build(capacity: usize, install_identity: bool) -> Self {
        let root = std::env::temp_dir().join(format!(
            "greengateway-google-delegation-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir(&root).expect("temporary root creates");
        let mut config = Config::test_defaults();
        config.connections_sqlite_path =
            Some(root.join("connections.sqlite").display().to_string());
        config.connection_gcp_provider.profiles = vec![GcpProfileConfig {
            id: PROFILE.to_owned(),
            audience: "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/gateway-pool/providers/gateway-provider".to_owned(),
            token_root: root.display().to_string(),
            token_file: "gcp-token".to_owned(),
            service_account: None,
        }];
        let control_plane =
            ConnectionControlPlane::from_config(&config).expect("control plane builds");
        let identity = StubIdentity::new();
        if install_identity {
            control_plane.install_google_workload_identity(identity.clone());
        }
        let initial = control_plane.runtime_snapshot();
        let created = control_plane
            .create_managed(initial.collection_etag(), delegation_write(), "test-admin")
            .await
            .expect("the delegating Connection saves");

        let google = StubGoogle::new();
        let clock = Arc::new(ManualTokenClock::new());
        let capture = CaptureSink::new();
        let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
        let egress_config = EgressConfig::default();
        let egress_client =
            Arc::new(EgressClient::new(egress_config.clone()).expect("egress client builds"));
        let runtime =
            ConnectionHttpRuntime::new(control_plane.clone(), egress_config, egress_client)
                .with_audit(audit)
                .with_google_delegation_for_test(google.clone(), clock.clone(), capacity);
        Self {
            root,
            runtime,
            control_plane,
            connection_id: created.id.to_string(),
            google,
            identity,
            clock,
            capture,
        }
    }

    /// The `Authorization` a manual tool call made for `caller` sends upstream.
    async fn bearer_for(
        &self,
        caller: Option<&AttestedCaller>,
    ) -> Result<String, ConnectionHttpError> {
        let target = self
            .runtime
            .tool_call_target(&self.connection_id, "/users/me/messages")?;
        let credential = self
            .runtime
            .resolve_credential(&target, caller)
            .await?
            .expect("a delegating Connection always has a credential");
        assert!(credential.is_oauth(), "an upstream 401 must drop it");
        let mut headers = HeaderMap::new();
        credential.inject(&mut headers)?;
        let value = headers
            .get(header::AUTHORIZATION)
            .expect("the token goes in Authorization");
        assert!(value.is_sensitive());
        Ok(value.to_str().expect("visible ASCII").to_owned())
    }

    async fn mint_events(&self, count: usize) -> Vec<AuditEvent> {
        let started = Instant::now();
        loop {
            let events: Vec<AuditEvent> = self
                .capture
                .events()
                .into_iter()
                .filter(|event| {
                    event.event_type == audit::event::CONNECTION_GOOGLE_DELEGATION_TOKEN
                })
                .collect();
            if events.len() >= count || started.elapsed() > Duration::from_secs(2) {
                return events;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Everything a caller, an operator or a log could ever see of a run.
    fn rendered_audit(&self) -> String {
        serde_json::to_string(&self.capture.events()).expect("audit serializes")
    }
}

fn assert_no_token_material(rendered: &str) {
    for canary in [
        FEDERATED_TOKEN_CANARY,
        SIGNATURE_CANARY,
        DENIAL_DESCRIPTION_CANARY,
        "google-alice",
        "google-bob",
        "stub-signing-key",
        "eyJ",
    ] {
        assert!(!rendered.contains(canary), "leaked {canary:?}: {rendered}");
    }
}

#[tokio::test]
async fn two_principals_are_signed_for_as_themselves_and_get_tokens_of_their_own() {
    let harness = Harness::new().await;

    assert_eq!(
        harness.bearer_for(Some(&alice())).await,
        Ok("Bearer google-alice@example.test-1".to_owned())
    );
    assert_eq!(
        harness.bearer_for(Some(&bob())).await,
        Ok("Bearer google-bob@example.test-2".to_owned())
    );
    // Cached per caller: nothing more is asked of Google or of the identity.
    assert_eq!(
        harness.bearer_for(Some(&alice())).await,
        Ok("Bearer google-alice@example.test-1".to_owned())
    );
    assert_eq!(harness.google.signing_requests().len(), 2);
    assert_eq!(harness.google.token_requests().len(), 2);
    assert_eq!(harness.identity.calls().len(), 2);
    assert_eq!(harness.runtime.google_delegation_cache_entries(), 2);

    for (request, user) in harness
        .google
        .signing_requests()
        .iter()
        .zip(["alice@example.test", "bob@example.test"])
    {
        assert_eq!(
            request.url,
            format!(
                "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{SERVICE_ACCOUNT}:signJwt"
            )
        );
        // Signed as the federated identity, never with a key of the gateway's.
        assert_eq!(
            request.authorization.as_deref(),
            Some(format!("Bearer {FEDERATED_TOKEN_CANARY}-1").as_str())
        );
        let body: Value = serde_json::from_str(&request.body).expect("JSON body");
        let claims: Value = serde_json::from_str(body["payload"].as_str().expect("payload"))
            .expect("the payload is a claim set");
        assert_eq!(claims["iss"], json!(SERVICE_ACCOUNT));
        assert_eq!(claims["sub"], json!(user));
        assert_eq!(claims["aud"], json!(GOOGLE_TOKEN_URL));
        // Sorted, as validation stores them.
        assert_eq!(
            claims["scope"],
            json!(format!("{CALENDAR_READ} {GMAIL_READ}"))
        );
        let issued_at = claims["iat"].as_u64().expect("iat");
        assert_eq!(
            claims["exp"].as_u64(),
            Some(issued_at + ASSERTION_LIFETIME_SECONDS)
        );
        assert_eq!(body.as_object().map(|body| body.len()), Some(1));
    }
    for (request, user) in harness
        .google
        .token_requests()
        .iter()
        .zip(["alice@example.test", "bob@example.test"])
    {
        // The token endpoint authenticates the assertion, so nothing else is sent.
        assert_eq!(request.authorization, None);
        let assertion = form_urlencoded::parse(request.body.as_bytes())
            .find(|(name, _)| name == "assertion")
            .map(|(_, value)| value.into_owned())
            .expect("the assertion is sent");
        assert!(assertion.ends_with(SIGNATURE_CANARY));
        assert_eq!(unverified_claims(&assertion)["sub"], json!(user));
    }

    let events = harness.mint_events(2).await;
    assert_eq!(events.len(), 2, "every mint is audited, a cache hit is not");
    for (event, subject) in events.iter().zip(["alice", "bob"]) {
        let actor = event.actor.as_ref().expect("the caller is the actor");
        assert_eq!(actor.user_id, subject);
        assert_eq!(actor.issuer.as_deref(), Some(TRUSTED_ISSUER));
        assert_eq!(event.payload["outcome"], json!("success"));
        assert_eq!(event.payload["reason"], json!("minted"));
        assert_eq!(event.payload["auth_type"], json!(AUTH_TYPE));
        assert_eq!(event.payload["service_account"], json!(SERVICE_ACCOUNT));
        assert_eq!(event.payload["scopes"], json!([CALENDAR_READ, GMAIL_READ]));
        assert_eq!(event.payload["google_status"], json!(200));
    }
    assert_no_token_material(&harness.rendered_audit());
}

#[tokio::test]
async fn a_caller_the_connection_cannot_act_as_is_refused_before_anything_is_asked() {
    let harness = Harness::new().await;
    let untrusted = caller_from(
        "mallory",
        "https://other-idp.example.test",
        Some("alice@example.test"),
    );
    let no_email = caller_from("carol", TRUSTED_ISSUER, None);
    let not_an_address = caller_from("dave", TRUSTED_ISSUER, Some("dave"));

    assert_eq!(
        harness.bearer_for(None).await,
        Err(ConnectionHttpError::DelegatedTokenNoPrincipal)
    );
    // Another provider naming the same address names nobody here.
    assert_eq!(
        harness.bearer_for(Some(&untrusted)).await,
        Err(ConnectionHttpError::GoogleDelegation(
            GoogleDelegationError::IssuerNotTrusted
        ))
    );
    for caller in [&no_email, &not_an_address] {
        assert_eq!(
            harness.bearer_for(Some(caller)).await,
            Err(ConnectionHttpError::GoogleDelegation(
                GoogleDelegationError::NoEmail
            ))
        );
    }
    assert!(harness.google.requests().is_empty());
    assert!(harness.identity.calls().is_empty());
    assert_eq!(harness.runtime.google_delegation_cache_entries(), 0);
    assert_eq!(
        ConnectionHttpError::GoogleDelegation(GoogleDelegationError::NoEmail).safe_reason(),
        "google_delegation_no_email"
    );
}

#[tokio::test]
async fn google_refusals_fail_closed_with_reasons_of_their_own_and_are_not_cached() {
    let harness = Harness::new().await;
    let refused = |error| Err(ConnectionHttpError::GoogleDelegation(error));

    // Not a user of the domain, or a suspended one.
    harness.google.set_endpoint(Endpoint::Refuse {
        status: 400,
        error: "invalid_grant",
    });
    assert_eq!(
        harness.bearer_for(Some(&alice())).await,
        refused(GoogleDelegationError::Denied)
    );
    // A delegation the administrator never authorised for these scopes.
    harness.google.set_endpoint(Endpoint::Refuse {
        status: 401,
        error: "unauthorized_client",
    });
    assert_eq!(
        harness.bearer_for(Some(&alice())).await,
        refused(GoogleDelegationError::ExchangeFailed)
    );
    harness.google.set_endpoint(Endpoint::Refuse {
        status: 500,
        error: "backend_error",
    });
    assert_eq!(
        harness.bearer_for(Some(&alice())).await,
        refused(GoogleDelegationError::ExchangeFailed)
    );
    assert_eq!(
        harness.google.token_requests().len(),
        3,
        "a failure is never cached"
    );

    harness
        .google
        .set_endpoint(Endpoint::Grant { expires_in: 3_599 });
    let events = harness.mint_events(3).await;
    assert_eq!(events[0].payload["google_status"], json!(400));
    assert_eq!(events[0].payload["google_error"], json!("invalid_grant"));
    assert_eq!(events[0].payload["stage"], json!("exchange"));
    assert_eq!(
        events[1].payload["google_error"],
        json!("unauthorized_client")
    );
    // An unregistered code is never recorded verbatim.
    assert_eq!(events[2].payload["google_error"], json!("unregistered"));
    assert_no_token_material(&harness.rendered_audit());
}

#[tokio::test]
async fn a_refused_federated_token_is_replaced_once_and_a_wrong_assertion_is_never_exchanged() {
    let harness = Harness::new().await;

    // An expired federated token: one fresh exchange through the same profile, then success.
    harness.google.set_signer(Signer::ExpireOnce);
    assert_eq!(
        harness.bearer_for(Some(&alice())).await,
        Ok("Bearer google-alice@example.test-1".to_owned())
    );
    assert_eq!(
        harness.identity.calls(),
        vec![(PROFILE.to_owned(), 0), (PROFILE.to_owned(), 2)]
    );
    let signing = harness.google.signing_requests();
    assert_eq!(signing.len(), 2);
    assert_eq!(
        signing[1].authorization.as_deref(),
        Some(format!("Bearer {FEDERATED_TOKEN_CANARY}-2").as_str())
    );

    // A federated identity that may not sign as the account: retried once, then refused.
    harness.google.set_signer(Signer::Refuse(403));
    assert_eq!(
        harness.bearer_for(Some(&bob())).await,
        Err(ConnectionHttpError::GoogleDelegation(
            GoogleDelegationError::SigningFailed
        ))
    );
    assert_eq!(harness.google.signing_requests().len(), 4);

    // A signer that answered about somebody else: nothing is exchanged.
    harness.google.set_signer(Signer::SwapSubject);
    assert_eq!(
        harness.bearer_for(Some(&bob())).await,
        Err(ConnectionHttpError::GoogleDelegation(
            GoogleDelegationError::SigningFailed
        ))
    );
    assert_eq!(
        harness.google.token_requests().len(),
        1,
        "only alice's assertion was exchanged"
    );
    let events = harness.mint_events(3).await;
    assert_eq!(events[1].payload["stage"], json!("sign"));
    assert_eq!(events[1].payload["google_status"], json!(403));
    assert_no_token_material(&harness.rendered_audit());
}

#[tokio::test]
async fn an_endpoint_the_egress_policy_refuses_stops_the_mint_before_the_identity_is_read() {
    for host in ["oauth2.googleapis.com", "iamcredentials.googleapis.com"] {
        let harness = Harness::new().await;
        harness.google.deny_host(host);
        assert_eq!(
            harness.bearer_for(Some(&alice())).await,
            Err(ConnectionHttpError::GoogleDelegation(
                GoogleDelegationError::EgressDenied
            )),
            "{host}"
        );
        assert!(harness.google.requests().is_empty(), "{host}");
        assert!(harness.identity.calls().is_empty(), "{host}");
    }
}

#[tokio::test]
async fn without_a_federated_identity_nothing_is_signed() {
    let harness = Harness::build(8, false).await;
    assert_eq!(
        harness.bearer_for(Some(&alice())).await,
        Err(ConnectionHttpError::GoogleDelegation(
            GoogleDelegationError::IdentityFailed
        ))
    );
    assert!(harness.google.requests().is_empty());
    let events = harness.mint_events(1).await;
    assert_eq!(events[0].payload["stage"], json!("identity"));
    assert_eq!(
        events[0].payload["identity_reason"],
        json!("identity_not_configured")
    );
}

#[tokio::test]
async fn tokens_are_bounded_in_number_and_lifetime() {
    let harness = Harness::build(1, true).await;
    harness
        .bearer_for(Some(&alice()))
        .await
        .expect("alice mints");
    // A full cache evicts the idle entry: bob gets his own token, and alice mints again.
    assert_eq!(
        harness.bearer_for(Some(&bob())).await,
        Ok("Bearer google-bob@example.test-2".to_owned())
    );
    assert_eq!(
        harness.bearer_for(Some(&alice())).await,
        Ok("Bearer google-alice@example.test-3".to_owned())
    );
    assert_eq!(harness.runtime.google_delegation_cache_entries(), 1);

    // Google's hour is never trusted past the ceiling.
    harness
        .clock
        .advance(Duration::from_secs(MAX_DELEGATED_TOKEN_CACHE_SECONDS - 60));
    assert_eq!(
        harness.bearer_for(Some(&alice())).await,
        Ok("Bearer google-alice@example.test-3".to_owned())
    );
    harness.clock.advance(Duration::from_secs(60));
    assert_eq!(
        harness.bearer_for(Some(&alice())).await,
        Ok("Bearer google-alice@example.test-4".to_owned())
    );

    // A short lifetime is refreshed before it ends.
    harness
        .google
        .set_endpoint(Endpoint::Grant { expires_in: 60 });
    harness
        .clock
        .advance(Duration::from_secs(MAX_DELEGATED_TOKEN_CACHE_SECONDS));
    assert_eq!(
        harness.bearer_for(Some(&alice())).await,
        Ok("Bearer google-alice@example.test-5".to_owned())
    );
    harness.clock.advance(Duration::from_secs(55));
    assert_eq!(
        harness.bearer_for(Some(&alice())).await,
        Ok("Bearer google-alice@example.test-6".to_owned())
    );
}

#[tokio::test]
async fn a_principal_purge_drops_their_google_tokens_and_counts_them() {
    let harness = Harness::new().await;
    harness
        .bearer_for(Some(&alice()))
        .await
        .expect("alice mints");
    harness.bearer_for(Some(&bob())).await.expect("bob mints");

    let purged = harness.runtime.purge_delegated_tokens(
        &format!("{TRUSTED_ISSUER}/"),
        "alice",
        DelegatedTokenPurgeTrigger::CredentialRevoked,
    );
    assert_eq!(purged, 1);
    assert_eq!(harness.runtime.google_delegation_cache_entries(), 1);
    assert_eq!(
        harness.bearer_for(Some(&alice())).await,
        Ok("Bearer google-alice@example.test-3".to_owned()),
        "the next call asks Google again"
    );
    assert_eq!(
        harness.bearer_for(Some(&bob())).await,
        Ok("Bearer google-bob@example.test-2".to_owned())
    );
    let purge = harness
        .capture
        .events()
        .into_iter()
        .find(|event| event.event_type == audit::event::CONNECTION_DELEGATED_TOKEN_PURGE)
        .expect("the purge is audited");
    assert_eq!(purge.payload["purged_entries"], json!(1));
    assert_eq!(purge.payload["google_delegation_entries"], json!(1));
}

#[tokio::test]
async fn a_domain_wide_delegation_serves_manual_tool_calls_and_no_other_lane() {
    let harness = Harness::new().await;
    let id = harness.connection_id.as_str();
    let target = harness
        .runtime
        .tool_call_target(id, "/users/me/messages")
        .expect("a manual tool call is served");
    assert_eq!(target.authentication_kind(), AUTH_TYPE);
    assert!(target.credential_belongs_to_caller());
    assert!(!target.attests_caller(), "nothing is attested to Google");

    let unsupported = Some(ConnectionHttpError::UnsupportedAuthentication);
    assert_eq!(harness.runtime.target(id, "/").err(), unsupported);
    assert_eq!(
        harness.runtime.openapi_tool_target(id, "/").err(),
        unsupported
    );
    assert_eq!(
        harness.runtime.proxy_route_target(id, "/").err(),
        unsupported
    );
    let etag = harness
        .control_plane
        .runtime_snapshot()
        .managed()
        .values()
        .next()
        .expect("the Connection is stored")
        .etag()
        .to_string();
    assert_eq!(harness.runtime.test_target(id, &etag).err(), unsupported);
    assert!(harness.google.requests().is_empty());
}

#[tokio::test]
async fn an_enabled_save_must_name_a_configured_workload_identity_profile() {
    let harness = Harness::new().await;
    let mut write = delegation_write();
    if let ConnectionAuthentication::GoogleDomainWideDelegation {
        workload_identity_profile,
        ..
    } = &mut write.authentication
    {
        *workload_identity_profile = "unconfigured-profile".to_owned();
    }
    let snapshot = harness.control_plane.runtime_snapshot();
    let refused = match harness
        .control_plane
        .create_managed(snapshot.collection_etag(), write.clone(), "test-admin")
        .await
    {
        Ok(_) => panic!("an unconfigured profile must refuse an enabled save"),
        Err(error) => format!("{error:?}"),
    };
    assert!(
        refused.contains("authentication.workload_identity_profile"),
        "{refused}"
    );

    // A disabled draft may name a profile this replica does not know yet.
    write.enabled = false;
    harness
        .control_plane
        .create_managed(snapshot.collection_etag(), write, "test-admin")
        .await
        .expect("a disabled draft saves");
}

#[test]
fn a_signed_assertion_must_be_a_compact_jws_carrying_exactly_the_claims_sent() {
    let binding = GoogleDelegationBinding {
        connection_id: ConnectionId::parse("mail").expect("valid id"),
        connection_etag: "etag-1".to_owned(),
        service_account_email: SERVICE_ACCOUNT.to_owned(),
        workload_identity_profile: PROFILE.to_owned(),
        scopes: vec![GMAIL_READ.to_owned()],
        subject_issuers: vec![TRUSTED_ISSUER.to_owned()],
        token_client: Arc::new(
            EgressClient::new(EgressConfig::default()).expect("egress client builds"),
        ),
        identity: None,
    };
    let claims = AssertionClaims::new(&binding, "alice@example.test", 1_000);
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256"}"#);
    let jws = |claims: &AssertionClaims| {
        format!(
            "{header}.{}.{SIGNATURE_CANARY}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).expect("claims serialize"))
        )
    };
    validate_signed_assertion(&jws(&claims), &claims).expect("the claims sent are accepted");

    let mut other = claims.clone();
    other.sub = "bob@example.test".to_owned();
    let mut longer = claims.clone();
    longer.exp += 3_600;
    let mut wider = claims.clone();
    wider.scope = format!("{GMAIL_READ} https://mail.google.com/");
    for forged in [jws(&other), jws(&longer), jws(&wider)] {
        assert_eq!(
            validate_signed_assertion(&forged, &claims),
            Err(GoogleDelegationError::SigningFailed)
        );
    }
    let valid = jws(&claims);
    for malformed in [
        String::new(),
        format!("{valid}.extra"),
        valid.replace(&format!(".{SIGNATURE_CANARY}"), "."),
        format!("{valid} "),
        format!("{header}.not-base64!.sig"),
        "a".repeat(MAX_SIGNED_ASSERTION_BYTES + 1),
    ] {
        assert_eq!(
            validate_signed_assertion(&malformed, &claims),
            Err(GoogleDelegationError::SigningFailed),
            "{malformed:?}"
        );
    }
}

#[test]
fn only_a_single_plain_address_can_be_a_subject() {
    for valid in ["alice@example.test", "a.b+c@mail.example.co.uk"] {
        assert!(is_single_plain_address(valid), "{valid}");
    }
    for invalid in [
        "",
        "alice",
        "@example.test",
        "alice@",
        "alice@localhost",
        "alice@@example.test",
        "alice@example..test",
        "alice@example.test.",
        "alice @example.test",
        "alice@exämple.test",
        &format!("{}@example.test", "a".repeat(MAX_SUBJECT_EMAIL_BYTES)),
    ] {
        assert!(!is_single_plain_address(invalid), "{invalid:?}");
    }
}

#[test]
fn a_token_response_must_be_a_bounded_bearer_token() {
    let parse = |body: Value| {
        let token: TokenResponse = serde_json::from_value(body).expect("parses");
        validate_token_response(&token)
    };
    assert_eq!(
        parse(
            json!({"access_token": "ya29.token", "token_type": "Bearer", "expires_in": 3599, "id_token": "skipped"})
        ),
        Ok(3_599)
    );
    for body in [
        json!({"access_token": "ya29.token", "token_type": "Bearer"}),
        json!({"access_token": "ya29.token", "token_type": "Bearer", "expires_in": 0}),
        json!({"access_token": "ya29.token", "token_type": "Bearer", "expires_in": MAX_TOKEN_LIFETIME_SECS + 1}),
        json!({"access_token": "ya29.token", "token_type": "mac", "expires_in": 60}),
        json!({"access_token": "", "token_type": "Bearer", "expires_in": 60}),
        json!({"access_token": "line\nbreak", "token_type": "Bearer", "expires_in": 60}),
    ] {
        assert_eq!(
            parse(body.clone()),
            Err(GoogleDelegationError::ExchangeFailed),
            "{body}"
        );
    }
}

#[test]
fn a_refusal_is_a_denial_only_when_google_says_so() {
    for (status, code, expected) in [
        (
            StatusCode::BAD_REQUEST,
            Some("invalid_grant"),
            GoogleDelegationError::Denied,
        ),
        (
            StatusCode::BAD_REQUEST,
            Some("access_denied"),
            GoogleDelegationError::Denied,
        ),
        (StatusCode::FORBIDDEN, None, GoogleDelegationError::Denied),
        (
            StatusCode::UNAUTHORIZED,
            Some("unauthorized_client"),
            GoogleDelegationError::ExchangeFailed,
        ),
        (
            StatusCode::BAD_REQUEST,
            Some("invalid_scope"),
            GoogleDelegationError::ExchangeFailed,
        ),
        (
            StatusCode::BAD_REQUEST,
            Some("unregistered"),
            GoogleDelegationError::ExchangeFailed,
        ),
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Some("invalid_grant"),
            GoogleDelegationError::ExchangeFailed,
        ),
    ] {
        assert_eq!(
            classify_refusal(status, code),
            expected,
            "{status} {code:?}"
        );
    }
}

#[test]
fn every_failure_has_a_fixed_reason_of_its_own() {
    let reasons = [
        GoogleDelegationError::NoEmail,
        GoogleDelegationError::IssuerNotTrusted,
        GoogleDelegationError::EgressDenied,
        GoogleDelegationError::IdentityFailed,
        GoogleDelegationError::SigningFailed,
        GoogleDelegationError::Denied,
        GoogleDelegationError::ExchangeFailed,
        GoogleDelegationError::Unavailable,
    ]
    .map(GoogleDelegationError::safe_reason);
    let unique: std::collections::BTreeSet<_> = reasons.iter().collect();
    assert_eq!(unique.len(), reasons.len());
    assert!(reasons
        .iter()
        .all(|reason| reason.starts_with("google_delegation_")));
}

#[test]
fn the_cache_key_separates_issuers_subjects_and_addresses() {
    let base = subject_digest("https://idp.example.test", "alice", "alice@example.test");
    assert_ne!(
        base,
        subject_digest("https://idp.example.test", "alice", "alias@example.test")
    );
    assert_ne!(
        base,
        subject_digest("https://other.example.test", "alice", "alice@example.test")
    );
    // Length-prefixed, so moving bytes between parts never collides.
    assert_ne!(
        subject_digest("ab", "c", "d@e.f"),
        subject_digest("a", "bc", "d@e.f")
    );
}
