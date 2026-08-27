use rcgen::{CertificateParams, Ia5String, KeyPair, SanType};
use sha2::{Digest, Sha256};
use tokio_rustls::rustls::pki_types::CertificateDer;

use super::*;
use crate::auth::{chain::ChainValidator, AuthMethod};

/// A self-signed certificate carrying exactly the SANs a test asks for.
///
/// Self-signed is correct here and not a shortcut: this module makes no trust
/// decision, so the only thing that matters about the certificate is what it
/// asserts about itself. Verification is exercised end to end in
/// `gateway/src/inbound_tls_tests.rs`, against a real handshake.
fn certificate_with_sans(sans: Vec<SanType>) -> CertificateDer<'static> {
    let mut params = CertificateParams::default();
    params.subject_alt_names = sans;
    let key = KeyPair::generate().expect("test key should generate");
    params
        .self_signed(&key)
        .expect("test certificate should build")
        .der()
        .clone()
}

fn uri_san(value: &str) -> SanType {
    SanType::URI(Ia5String::try_from(value).expect("test URI SAN should be IA5"))
}

fn dns_san(value: &str) -> SanType {
    SanType::DnsName(Ia5String::try_from(value).expect("test DNS SAN should be IA5"))
}

const SPIFFE_ID: &str = "spiffe://prod.example.test/ns/payments/sa/api";

// --- the identity a certificate carries -------------------------------------

#[test]
fn one_spiffe_uri_san_is_the_identity() {
    let certificate = certificate_with_sans(vec![uri_san(SPIFFE_ID)]);

    let identity = identity_from_certificate(&certificate, ClientCertIdentitySource::Spiffe)
        .expect("a certificate with exactly one SPIFFE ID must have an identity");

    assert_eq!(identity.identity(), SPIFFE_ID);
    assert_eq!(identity.source(), ClientCertIdentitySource::Spiffe);
    assert_eq!(
        identity.fingerprint(),
        hex::encode(Sha256::digest(certificate.as_ref())),
        "the fingerprint must be the SHA-256 of the leaf DER, so an operator can tie a session \
         to one issued certificate"
    );
}

/// The rule stated explicitly, rather than "the first one wins".
///
/// Whoever assembles the certificate chooses the SAN order. If order decided
/// the principal, a caller who can persuade a CA to add one more SAN chooses
/// which principal they authenticate as.
#[test]
fn two_different_spiffe_ids_are_not_an_identity() {
    let certificate = certificate_with_sans(vec![
        uri_san("spiffe://prod.example.test/ns/payments/sa/api"),
        uri_san("spiffe://prod.example.test/ns/payments/sa/admin"),
    ]);

    let error = identity_from_certificate(&certificate, ClientCertIdentitySource::Spiffe)
        .expect_err("a certificate carrying two identities must carry none");

    assert_eq!(error, ClientCertIdentityError::Ambiguous);
    assert_eq!(error.reason(), "identity_ambiguous");
}

/// Two spellings of one name are one identity, not two.
///
/// DNS names are case-insensitive, so refusing this would be refusing a
/// certificate that names one caller unambiguously.
#[test]
fn two_spellings_of_one_dns_name_are_one_identity() {
    let certificate = certificate_with_sans(vec![
        dns_san("API.Example.Test"),
        dns_san("api.example.test"),
    ]);

    let identity = identity_from_certificate(&certificate, ClientCertIdentitySource::Dns)
        .expect("two spellings of one DNS name are one identity");

    assert_eq!(identity.identity(), "api.example.test");
}

#[test]
fn two_different_dns_names_are_not_an_identity() {
    let certificate = certificate_with_sans(vec![
        dns_san("api.example.test"),
        dns_san("db.example.test"),
    ]);

    let error = identity_from_certificate(&certificate, ClientCertIdentitySource::Dns)
        .expect_err("a certificate naming two hosts does not name one caller");

    assert_eq!(error, ClientCertIdentityError::Ambiguous);
}

#[test]
fn a_certificate_with_no_san_of_the_configured_kind_has_no_identity() {
    let certificate = certificate_with_sans(vec![dns_san("api.example.test")]);

    let error = identity_from_certificate(&certificate, ClientCertIdentitySource::Spiffe)
        .expect_err("a DNS-only certificate has no SPIFFE identity");

    assert_eq!(error, ClientCertIdentityError::Absent);
    assert_eq!(error.reason(), "identity_absent");
}

/// A wildcard names a set of hosts. It is discarded before the count, so it can
/// neither become an identity nor make a certificate ambiguous.
#[test]
fn a_wildcard_dns_san_is_never_an_identity() {
    let wildcard_only = certificate_with_sans(vec![dns_san("*.example.test")]);
    let wildcard_and_name =
        certificate_with_sans(vec![dns_san("*.example.test"), dns_san("api.example.test")]);

    assert_eq!(
        identity_from_certificate(&wildcard_only, ClientCertIdentitySource::Dns)
            .expect_err("a wildcard alone is not a caller"),
        ClientCertIdentityError::Absent
    );
    assert_eq!(
        identity_from_certificate(&wildcard_and_name, ClientCertIdentitySource::Dns)
            .expect("a wildcard must not make an otherwise unambiguous certificate ambiguous")
            .identity(),
        "api.example.test"
    );
}

/// Filtering by scheme is what lets a SPIFFE deployment carry an ordinary URI
/// SAN alongside the SVID.
#[test]
fn a_non_spiffe_uri_san_does_not_make_a_spiffe_certificate_ambiguous() {
    let certificate = certificate_with_sans(vec![
        uri_san(SPIFFE_ID),
        uri_san("https://api.example.test/metadata"),
    ]);

    assert_eq!(
        identity_from_certificate(&certificate, ClientCertIdentitySource::Spiffe)
            .expect("only one URI SAN is a SPIFFE ID")
            .identity(),
        SPIFFE_ID
    );
    assert_eq!(
        identity_from_certificate(&certificate, ClientCertIdentitySource::Uri)
            .expect_err("under the plain URI source the same certificate carries two identities"),
        ClientCertIdentityError::Ambiguous,
    );
}

// --- the bound --------------------------------------------------------------

#[test]
fn an_identity_longer_than_the_bound_is_rejected() {
    let long_path = "a".repeat(MAX_IDENTITY_BYTES);
    let certificate = certificate_with_sans(vec![uri_san(&format!(
        "spiffe://prod.example.test/{long_path}"
    ))]);

    let error = identity_from_certificate(&certificate, ClientCertIdentitySource::Spiffe)
        .expect_err("an identity past the bound must not become a principal");

    assert_eq!(error, ClientCertIdentityError::TooLong);
    assert_eq!(error.reason(), "identity_too_long");
}

/// IA5 covers the control characters, so a CA can put a newline in a SAN. The
/// identity is on its way to a log line and an audit row.
#[test]
fn an_identity_containing_a_control_character_is_rejected() {
    let certificate = certificate_with_sans(vec![uri_san(
        "spiffe://prod.example.test/ns/a\nnot-really: injected",
    )]);

    assert_eq!(
        identity_from_certificate(&certificate, ClientCertIdentitySource::Spiffe)
            .expect_err("a control character must not reach a log line as an identity"),
        ClientCertIdentityError::Malformed
    );
}

// --- canonical form ---------------------------------------------------------

/// Rejected rather than lower-cased. Accepting both spellings would mean one
/// workload has two principal ids; skipping it silently would mean a
/// certificate carrying only the odd spelling authenticates as nothing while
/// looking valid.
#[test]
fn a_spiffe_id_with_a_non_canonical_scheme_is_rejected() {
    let certificate = certificate_with_sans(vec![uri_san("SPIFFE://prod.example.test/ns/a")]);

    assert_eq!(
        identity_from_certificate(&certificate, ClientCertIdentitySource::Spiffe)
            .expect_err("a non-canonical scheme is not a SPIFFE ID"),
        ClientCertIdentityError::Malformed
    );
}

#[test]
fn a_spiffe_id_with_an_upper_case_trust_domain_is_rejected() {
    let certificate = certificate_with_sans(vec![uri_san("spiffe://PROD.example.test/ns/a")]);

    assert_eq!(
        identity_from_certificate(&certificate, ClientCertIdentitySource::Spiffe)
            .expect_err("SPIFFE trust domains are lower case"),
        ClientCertIdentityError::Malformed
    );
}

#[test]
fn a_spiffe_id_with_dot_segments_or_an_empty_segment_is_rejected() {
    for value in [
        "spiffe://prod.example.test/ns//sa/api",
        "spiffe://prod.example.test/ns/../sa/api",
        "spiffe://prod.example.test/ns/payments/",
    ] {
        let certificate = certificate_with_sans(vec![uri_san(value)]);

        assert_eq!(
            identity_from_certificate(&certificate, ClientCertIdentitySource::Spiffe)
                .expect_err("two spellings must never denote one workload"),
            ClientCertIdentityError::Malformed,
            "{value} must not be accepted"
        );
    }
}

#[test]
fn a_spiffe_id_carrying_userinfo_a_port_or_a_query_is_rejected() {
    for value in [
        "spiffe://user@prod.example.test/ns/a",
        "spiffe://prod.example.test:8443/ns/a",
        "spiffe://prod.example.test/ns/a?role=admin",
        "spiffe://prod.example.test/ns/a#admin",
    ] {
        let certificate = certificate_with_sans(vec![uri_san(value)]);

        assert_eq!(
            identity_from_certificate(&certificate, ClientCertIdentitySource::Spiffe)
                .expect_err("a SPIFFE ID has no userinfo, port, query, or fragment"),
            ClientCertIdentityError::Malformed,
            "{value} must not be accepted"
        );
    }
}

#[test]
fn a_uri_identity_must_have_a_lower_case_scheme_and_a_body() {
    for value in ["HTTPS://api.example.test/a", "https:", "not-a-uri"] {
        let certificate = certificate_with_sans(vec![uri_san(value)]);

        assert_eq!(
            identity_from_certificate(&certificate, ClientCertIdentitySource::Uri)
                .expect_err("a URI identity must be canonical"),
            ClientCertIdentityError::Malformed,
            "{value} must not be accepted"
        );
    }
}

// --- the principal a certificate becomes ------------------------------------

#[tokio::test]
async fn a_verified_certificate_becomes_a_principal_carrying_no_roles() {
    let certificate = certificate_with_sans(vec![uri_san(SPIFFE_ID)]);
    let identity = identity_from_certificate(&certificate, ClientCertIdentitySource::Spiffe)
        .expect("the test certificate carries one SPIFFE ID");

    let principal = ClientCertificateValidator
        .validate_session(&SessionCredential::ClientCertificate(identity.clone()))
        .await
        .expect("a verified certificate identity must authenticate");

    assert_eq!(principal.user_id, SPIFFE_ID);
    assert_eq!(principal.auth_method, AuthMethod::ClientCertificate);
    assert_eq!(principal.session_id, identity.fingerprint());
    assert_eq!(
        principal.issuer.as_deref(),
        Some("provider:client-certificate"),
        "the identity boundary must be nameable, so a policy can tell a certificate subject \
         from a token subject that happens to spell the same string"
    );
    assert!(
        principal.roles.is_empty(),
        "a certificate says who a caller is, not what they may do"
    );
}

/// A certificate has no audience, so it cannot satisfy a resource binding whose
/// entire purpose is that a credential issued for one resource is not valid at
/// another.
#[tokio::test]
async fn a_certificate_cannot_authenticate_a_resource_bound_session() {
    let certificate = certificate_with_sans(vec![uri_san(SPIFFE_ID)]);
    let identity = identity_from_certificate(&certificate, ClientCertIdentitySource::Spiffe)
        .expect("the test certificate carries one SPIFFE ID");

    let error = ClientCertificateValidator
        .validate_session_for_resource(
            &SessionCredential::ClientCertificate(identity),
            Some("https://gateway.example.test/mcp"),
        )
        .await
        .expect_err("a certificate carries no audience");

    assert!(matches!(error, AuthError::InvalidSession(_)));
}

// --- the chain --------------------------------------------------------------

/// The #291 rule, from the new validator's side.
///
/// `ChainValidator` offers every credential to every validator, and reports a
/// remembered `Upstream` failure when nothing accepted. If this validator
/// answered "upstream failure" to the credentials it does not own, adding
/// client-certificate auth would turn every rejected bearer token in the
/// deployment from a 401 into a 503.
#[tokio::test]
async fn foreign_credentials_are_rejected_as_invalid_sessions_not_upstream_failures() {
    for credential in [
        SessionCredential::Bearer("some-token".to_owned()),
        SessionCredential::Cookie("some-session".to_owned()),
    ] {
        let error = ClientCertificateValidator
            .validate_session(&credential)
            .await
            .expect_err("only certificate credentials authenticate here");

        assert!(
            matches!(error, AuthError::InvalidSession(_)),
            "a credential this validator does not own is a judgement, not an outage: {error:?}"
        );
    }
}

#[tokio::test]
async fn a_chain_with_certificate_auth_still_reports_an_unknown_token_as_unauthorized() {
    struct RejectingValidator;

    #[async_trait::async_trait]
    impl SessionValidator for RejectingValidator {
        async fn validate_session(
            &self,
            _credential: &SessionCredential,
        ) -> Result<Principal, AuthError> {
            Err(AuthError::InvalidSession("unknown kid".to_owned()))
        }
    }

    let chain = ChainValidator::new(vec![
        Arc::new(ClientCertificateValidator) as Arc<dyn SessionValidator>,
        Arc::new(RejectingValidator) as Arc<dyn SessionValidator>,
    ]);

    let error = chain
        .validate_session(&SessionCredential::Bearer("unknown".to_owned()))
        .await
        .expect_err("no provider owns this token");

    assert!(
        matches!(error, AuthError::InvalidSession(_)),
        "a rejected token must stay a 401 once certificate auth is in the chain: {error:?}"
    );
}

#[test]
fn the_certificate_channel_is_opt_in_and_the_others_are_not_offered() {
    let validator: Arc<dyn SessionValidator> = Arc::new(ClientCertificateValidator);

    assert!(validator.supports_client_certificate());
    assert!(!validator.supports_bearer());
    assert!(!validator.supports_cookie());

    struct OlderValidator;

    #[async_trait::async_trait]
    impl SessionValidator for OlderValidator {
        async fn validate_session(
            &self,
            _credential: &SessionCredential,
        ) -> Result<Principal, AuthError> {
            Err(AuthError::InvalidSession("no".to_owned()))
        }
    }

    assert!(
        !OlderValidator.supports_client_certificate(),
        "a validator that predates this channel must not be offered certificates by default"
    );
}

#[test]
fn debug_output_carries_the_identity_and_no_certificate_bytes() {
    let certificate = certificate_with_sans(vec![uri_san(SPIFFE_ID)]);
    let identity = identity_from_certificate(&certificate, ClientCertIdentitySource::Spiffe)
        .expect("the test certificate carries one SPIFFE ID");

    let rendered = format!(
        "{:?}",
        SessionCredential::ClientCertificate(identity.clone())
    );

    assert!(rendered.contains(SPIFFE_ID));
    assert!(!rendered.contains('\n'));
    assert!(
        !rendered.contains(&hex::encode(&certificate.as_ref()[..16])),
        "certificate bytes must not be rendered anywhere: {rendered}"
    );
}
