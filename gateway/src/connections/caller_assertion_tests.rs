//! Tests for signed caller assertions.
//!
//! The assertions here are mostly about what this gateway *refuses*. Signing is the easy half; the
//! failure modes are where an upstream ends up trusting the wrong thing, so a Connection that
//! attests its caller must never quietly fall back to acting anonymously, must never attest a value
//! a caller could have chosen, and must never emit a token an upstream will reject.
//!
//! Keys are generated per test with `rcgen` rather than committed. No private key material belongs
//! in this tree.

use jsonwebtoken::{decode, DecodingKey, Validation};
use serde_json::Value;

use super::*;

const ISSUER: &str = "https://gateway.example";
const AUDIENCE: &str = "https://internal.example/api";
const REQUEST_ID: &str = "req-01hz-example-0000";
/// The provider that authenticated the caller, which is not this gateway.
const CALLER_ISSUER: &str = "https://idp.example";

fn es256_pair() -> rcgen::KeyPair {
    rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("P-256 key generates")
}

fn es256_key(pair: &rcgen::KeyPair) -> AssertionSigningKey {
    AssertionSigningKey::from_pkcs8_pem(
        "gw-test-1",
        AssertionAlgorithm::Es256,
        pair.serialize_pem().as_bytes(),
    )
    .expect("generated key loads")
}

/// The uncompressed SEC1 point of a generated key: the trailing 65 bytes of its SPKI DER.
fn es256_public_point(pair: &rcgen::KeyPair) -> Vec<u8> {
    let der = pair.public_key_der();
    der[der.len() - 65..].to_vec()
}

fn config() -> CallerAssertionConfig<'static> {
    CallerAssertionConfig {
        issuer: ISSUER,
        audience: AUDIENCE,
        token_type: "at+jwt",
        lifetime_seconds: 60,
        claims: &[],
        bind_request: false,
        bind_approval: false,
    }
}

fn caller() -> CallerIdentity<'static> {
    CallerIdentity {
        issuer: CALLER_ISSUER,
        subject: "user-1",
        email: Some("someone@example.com"),
        roles: &[],
    }
}

/// Splits a compact JWS and decodes header and payload without verifying; the signature itself is
/// checked by the round-trip tests below.
fn decode_unverified(token: &str) -> (Value, Value) {
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let mut parts = token.split('.');
    let header = parts.next().expect("header");
    let payload = parts.next().expect("payload");
    assert!(parts.next().is_some(), "signature present");
    assert!(parts.next().is_none(), "exactly three parts");
    (
        serde_json::from_slice(&engine.decode(header).expect("header base64"))
            .expect("header json"),
        serde_json::from_slice(&engine.decode(payload).expect("payload base64"))
            .expect("payload json"),
    )
}

#[test]
fn an_assertion_carries_the_claims_an_upstream_verifies_on() {
    let pair = es256_pair();
    let token = sign_caller_assertion(
        &es256_key(&pair),
        &config(),
        Some(&caller()),
        REQUEST_ID,
        1_757_000_000,
        None,
        None,
    )
    .expect("signs");

    let (header, claims) = decode_unverified(&token);
    assert_eq!(header["alg"], "ES256");
    assert_eq!(header["typ"], "at+jwt");
    assert_eq!(header["kid"], "gw-test-1");
    assert_eq!(claims["iss"], ISSUER);
    assert_eq!(claims["aud"], AUDIENCE);
    assert_eq!(claims["sub"], "https://idp.example#user-1");
    assert_eq!(claims["jti"], REQUEST_ID);
    assert_eq!(
        claims["exp"].as_u64().unwrap() - claims["iat"].as_u64().unwrap(),
        60
    );
    // Nothing an operator did not ask for. An upstream deciding on `email` should only ever see it
    // when the operator chose to attest it.
    assert!(claims.get("email").is_none());
    assert!(claims.get("roles").is_none());
}

#[test]
fn a_call_without_a_principal_is_refused_rather_than_signed_anonymously() {
    // The whole point of the mechanism. A Connection configured to attest its caller and then
    // sending an unattributable request would be worse than one that never attested at all.
    let pair = es256_pair();
    assert_eq!(
        sign_caller_assertion(
            &es256_key(&pair),
            &config(),
            None,
            REQUEST_ID,
            1_757_000_000,
            None,
            None,
        ),
        Err(CallerAssertionError::NoPrincipal)
    );
}

#[test]
fn configured_principal_claims_are_included_and_others_are_not() {
    let pair = es256_pair();
    let roles = vec!["member".to_owned(), "admin".to_owned()];
    let caller = CallerIdentity {
        issuer: CALLER_ISSUER,
        subject: "user-1",
        email: Some("someone@example.com"),
        roles: &roles,
    };
    let mut config = config();
    config.claims = &[PrincipalClaim::Email, PrincipalClaim::Roles];

    let token = sign_caller_assertion(
        &es256_key(&pair),
        &config,
        Some(&caller),
        REQUEST_ID,
        1_757_000_000,
        None,
        None,
    )
    .expect("signs");

    let (_, claims) = decode_unverified(&token);
    assert_eq!(claims["email"], "someone@example.com");
    assert_eq!(claims["roles"], serde_json::json!(["member", "admin"]));
}

#[test]
fn request_binding_covers_the_bytes_actually_sent() {
    let pair = es256_pair();
    let mut config = config();
    config.bind_request = true;
    let body = br#"{"b":2,"a":1}"#;
    let binding = RequestBinding {
        method: "post",
        path: "/api/v2/things",
        body,
    };

    let token = sign_caller_assertion(
        &es256_key(&pair),
        &config,
        Some(&caller()),
        REQUEST_ID,
        1_757_000_000,
        Some(&binding),
        None,
    )
    .expect("signs");

    let (_, claims) = decode_unverified(&token);
    assert_eq!(claims["method"], "POST");
    assert_eq!(claims["path"], "/api/v2/things");
    assert_eq!(claims["request_sha256"], body_digest(body));
}

#[test]
fn the_digest_is_over_raw_bytes_so_key_order_is_not_canonicalized_away() {
    // The design decision this whole module rests on. Two JSON documents that are semantically
    // equal but textually different hash differently, because the upstream hashes what arrived
    // rather than reconstructing a canonical form. That is what makes verification three lines in
    // any language instead of a shared canonicalization spec every upstream must reimplement.
    assert_ne!(
        body_digest(br#"{"a":1,"b":2}"#),
        body_digest(br#"{"b":2,"a":1}"#)
    );
    // And it is a plain SHA-256, so an upstream can check it with its standard library.
    assert_eq!(
        body_digest(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn binding_without_a_request_is_refused() {
    let pair = es256_pair();
    let mut config = config();
    config.bind_request = true;
    assert_eq!(
        sign_caller_assertion(
            &es256_key(&pair),
            &config,
            Some(&caller()),
            REQUEST_ID,
            1_757_000_000,
            None,
            None,
        ),
        Err(CallerAssertionError::InvalidClaim("request_binding"))
    );
}

#[test]
fn an_approval_binding_without_an_approval_is_refused() {
    let pair = es256_pair();
    let mut config = config();
    config.bind_approval = true;
    assert_eq!(
        sign_caller_assertion(
            &es256_key(&pair),
            &config,
            Some(&caller()),
            REQUEST_ID,
            1_757_000_000,
            None,
            None,
        ),
        Err(CallerAssertionError::ApprovalRequired)
    );
}

#[test]
fn lifetimes_outside_the_issuable_window_are_refused() {
    let pair = es256_pair();
    let key = es256_key(&pair);

    let mut zero = config();
    zero.lifetime_seconds = 0;
    assert_eq!(
        sign_caller_assertion(
            &key,
            &zero,
            Some(&caller()),
            REQUEST_ID,
            1_757_000_000,
            None,
            None
        ),
        Err(CallerAssertionError::InvalidLifetime)
    );

    let mut too_long = config();
    too_long.lifetime_seconds = MAX_LIFETIME_SECONDS + 1;
    assert_eq!(
        sign_caller_assertion(
            &key,
            &too_long,
            Some(&caller()),
            REQUEST_ID,
            1_757_000_000,
            None,
            None
        ),
        Err(CallerAssertionError::InvalidLifetime)
    );

    let mut at_cap = config();
    at_cap.lifetime_seconds = MAX_LIFETIME_SECONDS;
    assert!(sign_caller_assertion(
        &key,
        &at_cap,
        Some(&caller()),
        REQUEST_ID,
        1_757_000_000,
        None,
        None
    )
    .is_ok());
}

#[test]
fn control_characters_in_a_claim_are_refused_rather_than_escaped() {
    // A header value that smuggles a newline is a request-splitting problem one hop later.
    let pair = es256_pair();
    let key = es256_key(&pair);
    let caller = CallerIdentity {
        issuer: CALLER_ISSUER,
        subject: "user\n1",
        email: None,
        roles: &[],
    };
    assert_eq!(
        sign_caller_assertion(
            &key,
            &config(),
            Some(&caller),
            REQUEST_ID,
            1_757_000_000,
            None,
            None
        ),
        Err(CallerAssertionError::InvalidClaim("sub"))
    );
}

#[test]
fn an_es256_assertion_verifies_against_the_published_key() {
    let pair = es256_pair();
    let token = sign_caller_assertion(
        &es256_key(&pair),
        &config(),
        Some(&caller()),
        REQUEST_ID,
        1_757_000_000,
        None,
        None,
    )
    .expect("signs");

    let mut validation = Validation::new(Algorithm::ES256);
    validation.set_issuer(&[ISSUER]);
    validation.set_audience(&[AUDIENCE]);
    // The fixture timestamp is fixed, so this checks the signature and the bound claims rather than
    // the wall clock.
    validation.validate_exp = false;

    let public = DecodingKey::from_ec_pem(pair.public_key_pem().as_bytes()).expect("public key");
    let decoded = decode::<Value>(&token, &public, &validation).expect("verifies");
    assert_eq!(decoded.claims["sub"], "https://idp.example#user-1");
}

#[test]
fn the_published_es256_jwk_has_the_members_a_verifier_needs() {
    let pair = es256_pair();
    let jwk = es256_public_jwk("gw-test-1", &es256_public_point(&pair)).expect("valid point");
    assert_eq!(jwk["kty"], "EC");
    assert_eq!(jwk["crv"], "P-256");
    assert_eq!(jwk["alg"], "ES256");
    assert_eq!(jwk["use"], "sig");
    assert_eq!(jwk["kid"], "gw-test-1");
    // 32 bytes base64url without padding is 43 characters.
    assert_eq!(jwk["x"].as_str().unwrap().len(), 43);
    assert_eq!(jwk["y"].as_str().unwrap().len(), 43);
    // No private component ever reaches the published document.
    assert!(jwk.get("d").is_none());
}

#[test]
fn a_malformed_public_point_is_refused() {
    assert_eq!(
        es256_public_jwk("gw-test-1", &[0x04; 64]),
        Err(CallerAssertionError::KeyUnusable)
    );
    // A compressed point carries one coordinate; a JWK needs both.
    let compressed = [vec![0x02u8], vec![0x11u8; 32]].concat();
    assert_eq!(
        es256_public_jwk("gw-test-1", &compressed),
        Err(CallerAssertionError::KeyUnusable)
    );
}

#[test]
fn a_public_point_that_is_not_on_the_curve_is_refused() {
    // Right length, right prefix, wrong point. A truncated read or a coordinate pair taken from the
    // wrong key looks exactly like this, and the JWK it produces is syntactically perfect and
    // cryptographically useless: the gateway keeps signing while every upstream rejects the key.
    let arbitrary = [vec![0x04u8], vec![0x11u8; 32], vec![0x22u8; 32]].concat();
    assert_eq!(
        es256_public_jwk("gw-test-1", &arbitrary),
        Err(CallerAssertionError::KeyUnusable)
    );

    // One flipped byte of a real key's y coordinate leaves the curve.
    let pair = es256_pair();
    let mut corrupted = es256_public_point(&pair);
    corrupted[64] ^= 0x01;
    assert_eq!(
        es256_public_jwk("gw-test-1", &corrupted),
        Err(CallerAssertionError::KeyUnusable)
    );

    // A coordinate at or above the field prime is not a field element at all.
    let too_large = [vec![0x04u8], vec![0xffu8; 32], vec![0xffu8; 32]].concat();
    assert_eq!(
        es256_public_jwk("gw-test-1", &too_large),
        Err(CallerAssertionError::KeyUnusable)
    );

    // The generated key itself still passes, so the check is not simply refusing everything.
    assert!(es256_public_jwk("gw-test-1", &es256_public_point(&pair)).is_ok());
}

#[test]
fn two_providers_issuing_the_same_subject_are_not_the_same_caller() {
    // The whole point of the mechanism: an upstream doing per-user ownership checks must never treat
    // a caller from one provider as the identically named caller from another. `iss` on the token is
    // this gateway, so `sub` has to carry the provider that actually authenticated the caller.
    let pair = es256_pair();
    let key = es256_key(&pair);
    let sign = |issuer: &str| {
        let caller = CallerIdentity {
            issuer,
            subject: "alice",
            email: None,
            roles: &[],
        };
        let token = sign_caller_assertion(
            &key,
            &config(),
            Some(&caller),
            REQUEST_ID,
            1_757_000_000,
            None,
            None,
        )
        .expect("signs");
        decode_unverified(&token).1
    };

    let first = sign("https://idp-a.example");
    let second = sign("https://idp-b.example");
    assert_ne!(first["sub"], second["sub"]);
    assert_eq!(first["sub"], "https://idp-a.example#alice");
    assert_eq!(second["sub"], "https://idp-b.example#alice");
}

#[test]
fn the_unscoped_identity_halves_travel_beside_the_scoped_subject() {
    // An upstream matching its own user records reads these rather than taking `sub` apart.
    let pair = es256_pair();
    let token = sign_caller_assertion(
        &es256_key(&pair),
        &config(),
        Some(&caller()),
        REQUEST_ID,
        1_757_000_000,
        None,
        None,
    )
    .expect("signs");
    let (_, claims) = decode_unverified(&token);
    assert_eq!(claims["caller_iss"], CALLER_ISSUER);
    assert_eq!(claims["caller_sub"], "user-1");
    assert_eq!(claims["sub"], "https://idp.example#user-1");
}

#[test]
fn an_issuer_that_would_make_the_subject_ambiguous_is_refused() {
    let pair = es256_pair();
    let key = es256_key(&pair);
    let refuse = |issuer: &str| {
        let caller = CallerIdentity {
            issuer,
            subject: "user-1",
            email: None,
            roles: &[],
        };
        sign_caller_assertion(
            &key,
            &config(),
            Some(&caller),
            REQUEST_ID,
            1_757_000_000,
            None,
            None,
        )
    };

    // OpenID Connect forbids a fragment in an issuer identifier. Honouring that is what keeps the
    // first `#` the end of the issuer, so an issuer carrying one is refused rather than encoded.
    assert_eq!(
        refuse("https://idp.example#not-an-issuer"),
        Err(CallerAssertionError::InvalidClaim("caller_iss"))
    );
    // No issuer means no identity boundary, and this gateway will not guess one.
    assert_eq!(
        refuse(""),
        Err(CallerAssertionError::InvalidClaim("caller_iss"))
    );
    assert_eq!(
        refuse("https://idp.example\n"),
        Err(CallerAssertionError::InvalidClaim("caller_iss"))
    );
}

#[test]
fn the_published_rs256_jwk_has_the_members_a_verifier_needs() {
    let jwk = rs256_public_jwk("gw-rsa-1", &[0xab; 256], &[0x01, 0x00, 0x01]).expect("valid");
    assert_eq!(jwk["kty"], "RSA");
    assert_eq!(jwk["alg"], "RS256");
    assert_eq!(jwk["use"], "sig");
    assert_eq!(jwk["kid"], "gw-rsa-1");
    assert!(jwk.get("d").is_none());
    assert_eq!(
        rs256_public_jwk("k", &[], &[1]),
        Err(CallerAssertionError::KeyUnusable)
    );
}

#[test]
fn the_signing_key_never_prints_its_material() {
    let pair = es256_pair();
    let rendered = format!("{:?}", es256_key(&pair));
    assert!(rendered.contains("gw-test-1"));
    assert!(!rendered.contains("BEGIN"));
    assert!(!rendered.to_ascii_lowercase().contains("private"));
}

#[test]
fn a_key_that_does_not_match_its_algorithm_is_refused_at_load() {
    // Configuration time is the only good moment to find this: a mismatch fails every call.
    let pair = es256_pair();
    assert_eq!(
        AssertionSigningKey::from_pkcs8_pem(
            "gw-test-1",
            AssertionAlgorithm::Rs256,
            pair.serialize_pem().as_bytes(),
        )
        .map(|_| ())
        .unwrap_err(),
        CallerAssertionError::KeyUnusable
    );
}
