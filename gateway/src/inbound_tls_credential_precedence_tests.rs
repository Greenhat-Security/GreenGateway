//! Credential precedence over a real listener: a bearer token or session
//! cookie the caller sent decides, not the certificate its connection was
//! established with. Shared fixtures stay in `inbound_tls_tests.rs`.
use super::*;

// --- credential precedence -------------------------------------------------
//
// `crate::middleware::auth::request_credential` documents that a credential the
// caller SENT wins over the certificate their connection was established with.
// That rule shipped with no test: inverting the function to certificate-first
// left the entire suite green, while turning any `optional` or `required`
// listener into one where a valid certificate silently launders an expired,
// revoked or unknown bearer token.
//
// These tests need a chain that actually judges bearer and cookie credentials.
// With only `ClientCertificateValidator` in the chain the middleware
// short-circuits a bearer credential as `bearer_auth_unsupported` before any
// validator sees it, and a test built on that would be asserting about a
// routing hint rather than about which credential won.

const GOOD_BEARER_TOKEN: &str = "test-bearer-token-the-chain-accepts";
const GOOD_SESSION_COOKIE: &str = "test-session-cookie-the-chain-accepts";
const TOKEN_SUBJECT: &str = "token-subject";

/// A validator that judges bearer and cookie credentials and knows exactly one
/// of each.
///
/// Knowing a good credential as well as rejecting bad ones is what lets these
/// tests distinguish three outcomes rather than two: authenticated as the
/// token's subject, authenticated as the certificate's subject, or refused. A
/// chain that could only refuse would collapse the first two.
struct StaticTokenValidator;

#[async_trait::async_trait]
impl SessionValidator for StaticTokenValidator {
    async fn validate_session(
        &self,
        credential: &SessionCredential,
    ) -> Result<Principal, AuthError> {
        let accepted = match credential {
            SessionCredential::Bearer(token) => token == GOOD_BEARER_TOKEN,
            SessionCredential::Cookie(cookie) => cookie == GOOD_SESSION_COOKIE,
            SessionCredential::ClientCertificate(_) => false,
        };
        if !accepted {
            return Err(AuthError::InvalidSession(
                "the static test validator does not know this credential".to_owned(),
            ));
        }

        Ok(Principal {
            user_id: TOKEN_SUBJECT.to_owned(),
            issuer: None,
            email: None,
            org_id: None,
            roles: Vec::new(),
            session_id: "static-test-session".to_owned(),
            auth_method: AuthMethod::Bearer,
        })
    }
}

/// A validator that would happily authenticate anything, including a
/// certificate credential, while never having opted into being asked about one.
///
/// This is the shape `SessionValidator::supports_client_certificate` exists to
/// protect against and its doc comment describes: a validator that predates
/// certificates, has not been told about them, and whose `validate_session`
/// does not discriminate. Nothing else in the suite can exercise the
/// middleware's `client_certificate_auth_unsupported` branch, because every
/// real validator that declines the channel also rejects the credential -- so
/// deleting the branch would change no outcome and no test would notice.
struct PermissiveLegacyValidator;

#[async_trait::async_trait]
impl SessionValidator for PermissiveLegacyValidator {
    async fn validate_session(
        &self,
        _credential: &SessionCredential,
    ) -> Result<Principal, AuthError> {
        Ok(Principal {
            user_id: "legacy-validator-subject".to_owned(),
            issuer: None,
            email: None,
            org_id: None,
            roles: Vec::new(),
            session_id: "legacy-test-session".to_owned(),
            auth_method: AuthMethod::Bearer,
        })
    }

    // `supports_client_certificate` is deliberately left at its default of
    // `false`. That is the whole fixture.
}

/// A certificate credential is never handed to a validator that did not opt in.
///
/// The routing hint defaults to `false` so that a validator written before
/// certificates existed is not silently asked to judge one. Without the
/// middleware's guard this request is served as `legacy-validator-subject`: a
/// validator that never agreed to judge certificates deciding who a certificate
/// caller is.
#[tokio::test]
async fn a_certificate_credential_is_refused_by_a_validator_that_never_opted_in() {
    let material = MaterialDir::new();
    let ca = client_ca();
    let server = write_client_auth_material(&material, &ca);
    let bindings = InboundTlsBindings::load(&client_auth_config(
        &material,
        ClientCertRequirement::Optional,
        None,
    ))
    .expect("client-auth material should load");
    let listener = serve_router(
        &bindings,
        authenticating_router_over(vec![
            Arc::new(PermissiveLegacyValidator) as Arc<dyn SessionValidator>
        ]),
    )
    .await;

    let response = whoami(
        listener.addr,
        client_config_with_identity(
            &server.ca_der,
            Some(issue_client_identity(&ca, ClientIdentitySpec::default())),
        ),
    )
    .await
    .expect("the handshake must succeed; the refusal belongs to the router");

    assert_unauthorized(
        &response,
        "a certificate offered to a chain that never opted into certificates",
    );
    assert!(
        !response.contains("legacy-validator-subject"),
        "a validator that did not opt into the certificate channel must never be asked to judge one: {response}"
    );
    listener.stop().await;
}

/// A listener whose chain accepts tokens, cookies and certificates -- the shape
/// an `optional` deployment migrating onto certificates actually runs.
async fn serve_mixed_credentials(bindings: &InboundTlsBindings) -> RunningListener {
    serve_router(
        bindings,
        authenticating_router_over(vec![
            Arc::new(StaticTokenValidator) as Arc<dyn SessionValidator>,
            Arc::new(ClientCertificateValidator) as Arc<dyn SessionValidator>,
        ]),
    )
    .await
}

/// The control, on the same listener and the same chain as the tests below: a
/// caller who sends no credential is judged on the certificate.
///
/// Without this the three tests that follow would be satisfied by a listener
/// that had simply stopped accepting certificates.
#[tokio::test]
async fn a_connection_certificate_authenticates_when_no_credential_was_sent() {
    let material = MaterialDir::new();
    let ca = client_ca();
    let server = write_client_auth_material(&material, &ca);
    let bindings = InboundTlsBindings::load(&client_auth_config(
        &material,
        ClientCertRequirement::Optional,
        None,
    ))
    .expect("client-auth material should load");
    let listener = serve_mixed_credentials(&bindings).await;

    let response = whoami_request(
        listener.addr,
        Arc::new(client_config_with_identity(
            &server.ca_der,
            Some(issue_client_identity(&ca, ClientIdentitySpec::default())),
        )),
        "",
    )
    .await
    .expect("a well-formed client certificate must complete the handshake");

    assert!(
        response
            .body
            .contains(&format!("principal={CLIENT_SPIFFE_ID}")),
        "with nothing else sent, the certificate is the credential: {}",
        response.body
    );
    listener.stop().await;
}

/// A bearer token the chain rejects is a 401, even over a certificate the chain
/// would have accepted.
///
/// This is the rule `request_credential` documents. Under the inverted order the
/// token is never evaluated and the caller is served as the certificate's
/// subject -- an expired or revoked token silently succeeding as somebody else.
#[tokio::test]
async fn a_rejected_bearer_token_is_not_rescued_by_the_connection_certificate() {
    let material = MaterialDir::new();
    let ca = client_ca();
    let server = write_client_auth_material(&material, &ca);
    let bindings = InboundTlsBindings::load(&client_auth_config(
        &material,
        ClientCertRequirement::Optional,
        None,
    ))
    .expect("client-auth material should load");
    let listener = serve_mixed_credentials(&bindings).await;

    let response = whoami_request(
        listener.addr,
        Arc::new(client_config_with_identity(
            &server.ca_der,
            Some(issue_client_identity(&ca, ClientIdentitySpec::default())),
        )),
        "Authorization: Bearer not-a-token-this-chain-knows\r\n",
    )
    .await
    .expect("the handshake must still succeed; the refusal belongs to the router");

    assert_unauthorized(
        &response.body,
        "a rejected bearer token sent over a valid client certificate",
    );
    assert!(
        !response
            .body
            .contains(&format!("principal={CLIENT_SPIFFE_ID}")),
        "the certificate must not authenticate a caller who sent a credential that failed: {}",
        response.body
    );
    listener.stop().await;
}

/// The same rule in the direction that produces a principal: a token the chain
/// accepts wins, and the caller is the *token's* subject rather than the
/// certificate's.
///
/// This is the assertion that names the wrong value. Under the inverted order
/// this request is served as `principal=spiffe://gateway.test/ns/payments/sa/api`
/// instead of `principal=token-subject`, which is a silent identity swap rather
/// than a visible failure.
#[tokio::test]
async fn an_accepted_bearer_token_outranks_the_connection_certificate() {
    let material = MaterialDir::new();
    let ca = client_ca();
    let server = write_client_auth_material(&material, &ca);
    let bindings = InboundTlsBindings::load(&client_auth_config(
        &material,
        ClientCertRequirement::Optional,
        None,
    ))
    .expect("client-auth material should load");
    let listener = serve_mixed_credentials(&bindings).await;

    let response = whoami_request(
        listener.addr,
        Arc::new(client_config_with_identity(
            &server.ca_der,
            Some(issue_client_identity(&ca, ClientIdentitySpec::default())),
        )),
        &format!("Authorization: Bearer {GOOD_BEARER_TOKEN}\r\n"),
    )
    .await
    .expect("an accepted token over a valid certificate must be served");

    assert!(
        response
            .body
            .contains(&format!("principal={TOKEN_SUBJECT}")),
        "the caller asked to be judged as the token's subject: {}",
        response.body
    );
    assert!(
        !response.body.contains(CLIENT_SPIFFE_ID),
        "the connection's certificate must not decide the identity of a caller who sent a token: {}",
        response.body
    );
    listener.stop().await;
}

/// The cookie half of the same rule.
///
/// `request_credential` prefers a bearer token, then a session cookie, then the
/// certificate. A rejected cookie must therefore be a 401 too, not a fallthrough
/// to the connection's certificate.
#[tokio::test]
async fn a_rejected_session_cookie_is_not_rescued_by_the_connection_certificate() {
    let material = MaterialDir::new();
    let ca = client_ca();
    let server = write_client_auth_material(&material, &ca);
    let bindings = InboundTlsBindings::load(&client_auth_config(
        &material,
        ClientCertRequirement::Optional,
        None,
    ))
    .expect("client-auth material should load");
    let listener = serve_mixed_credentials(&bindings).await;

    let response = whoami_request(
        listener.addr,
        Arc::new(client_config_with_identity(
            &server.ca_der,
            Some(issue_client_identity(&ca, ClientIdentitySpec::default())),
        )),
        "Cookie: session=not-a-cookie-this-chain-knows\r\n",
    )
    .await
    .expect("the handshake must still succeed; the refusal belongs to the router");

    assert_unauthorized(
        &response.body,
        "a rejected session cookie sent over a valid client certificate",
    );
    listener.stop().await;
}

/// And the cookie in the accepting direction, so the cookie test above is not
/// passing because cookies never authenticate on this listener at all.
#[tokio::test]
async fn an_accepted_session_cookie_outranks_the_connection_certificate() {
    let material = MaterialDir::new();
    let ca = client_ca();
    let server = write_client_auth_material(&material, &ca);
    let bindings = InboundTlsBindings::load(&client_auth_config(
        &material,
        ClientCertRequirement::Optional,
        None,
    ))
    .expect("client-auth material should load");
    let listener = serve_mixed_credentials(&bindings).await;

    let response = whoami_request(
        listener.addr,
        Arc::new(client_config_with_identity(
            &server.ca_der,
            Some(issue_client_identity(&ca, ClientIdentitySpec::default())),
        )),
        &format!("Cookie: session={GOOD_SESSION_COOKIE}\r\n"),
    )
    .await
    .expect("an accepted cookie over a valid certificate must be served");

    assert!(
        response
            .body
            .contains(&format!("principal={TOKEN_SUBJECT}")),
        "the caller asked to be judged as the cookie's subject: {}",
        response.body
    );
    assert!(
        !response.body.contains(CLIENT_SPIFFE_ID),
        "the connection's certificate must not decide the identity of a caller who sent a cookie: {}",
        response.body
    );
    listener.stop().await;
}
