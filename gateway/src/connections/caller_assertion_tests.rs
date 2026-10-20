//! Tests for signed caller assertions.
//!
//! The assertions here are mostly about what this gateway *refuses*. Signing is the easy half; the
//! failure modes are where an upstream ends up trusting the wrong thing, so a Connection that
//! attests its caller must never quietly fall back to acting anonymously, must never attest a value
//! a caller could have chosen, and must never emit a token an upstream will reject.
//!
//! Keys are generated per test rather than committed: P-256 keys with `rcgen`, RSA keys with
//! aws-lc-rs. No private key material belongs in this tree.

use aws_lc_rs::encoding::AsDer;
use jsonwebtoken::{decode, jwk::Jwk, DecodingKey, Validation};
use serde_json::Value;
use tokio_rustls::rustls::pki_types::PrivatePkcs8KeyDer;

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
    let der = rcgen::PublicKeyData::subject_public_key_info(pair);
    der[der.len() - 65..].to_vec()
}

/// A freshly generated RSA-2048 key: its PKCS#8 PEM, and the modulus and exponent a JWKS publishes.
struct Rs256Pair {
    pem: String,
    modulus: Vec<u8>,
    exponent: Vec<u8>,
}

/// `rcgen` is built on ring here, and ring cannot generate RSA keys, so the key comes from aws-lc-rs
/// -- already linked as `jsonwebtoken`'s backend -- and `rcgen` only wraps its DER as PEM.
fn rs256_pair() -> Rs256Pair {
    let generated = aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048)
        .expect("RSA-2048 key generates");
    let pkcs8 = generated
        .as_der()
        .expect("generated RSA key encodes as PKCS#8")
        .as_ref()
        .to_vec();
    let pem = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
        &PrivatePkcs8KeyDer::from(pkcs8),
        &rcgen::PKCS_RSA_SHA256,
    )
    .expect("generated RSA key loads")
    .serialize_pem();
    let public = aws_lc_rs::rsa::PublicKeyComponents::<Vec<u8>>::from(
        aws_lc_rs::signature::KeyPair::public_key(&generated),
    );
    Rs256Pair {
        pem,
        modulus: public.n,
        exponent: public.e,
    }
}

/// The public JWK this gateway would publish for `pair`, parsed by a standard JWK reader.
fn published_rs256_jwk(pair: &Rs256Pair) -> Jwk {
    let jwk = rs256_public_jwk("gw-rsa-1", &pair.modulus, &pair.exponent).expect("valid JWK");
    // No private component ever reaches the published document.
    assert!(jwk.get("d").is_none());
    serde_json::from_value(jwk).expect("the published JWK is a standard JWK")
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
fn an_rs256_assertion_verifies_against_the_published_jwk() {
    // Cloudflare Access publishes RS256, so an upstream that already verifies it must be able to
    // verify this the same way: a standard verifier, holding only the JWK this gateway publishes.
    let pair = rs256_pair();
    let key = AssertionSigningKey::from_pkcs8_pem(
        "gw-rsa-1",
        AssertionAlgorithm::Rs256,
        pair.pem.as_bytes(),
    )
    .expect("generated RSA key loads");
    let token = sign_caller_assertion(
        &key,
        &config(),
        Some(&caller()),
        REQUEST_ID,
        1_757_000_000,
        None,
        None,
    )
    .expect("signs");

    let (header, _) = decode_unverified(&token);
    assert_eq!(header["alg"], "RS256");
    assert_eq!(header["typ"], "at+jwt");
    assert_eq!(header["kid"], "gw-rsa-1");

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[ISSUER]);
    validation.set_audience(&[AUDIENCE]);
    // The fixture timestamp is fixed, so this checks the signature and the bound claims rather than
    // the wall clock.
    validation.validate_exp = false;
    let public = DecodingKey::from_jwk(&published_rs256_jwk(&pair)).expect("public key");
    let decoded = decode::<Value>(&token, &public, &validation).expect("verifies");
    assert_eq!(decoded.claims["sub"], "https://idp.example#user-1");
    assert_eq!(decoded.claims["caller_sub"], "user-1");
    assert_eq!(decoded.claims["jti"], REQUEST_ID);

    // The signature is what makes it verify: the published key of any other pair refuses it.
    let other = DecodingKey::from_jwk(&published_rs256_jwk(&rs256_pair())).expect("public key");
    assert!(decode::<Value>(&token, &other, &validation).is_err());

    // And an RSA key is not an ES256 key, the reverse of the mismatch refused below.
    assert_eq!(
        AssertionSigningKey::from_pkcs8_pem(
            "gw-rsa-1",
            AssertionAlgorithm::Es256,
            pair.pem.as_bytes()
        )
        .map(|_| ())
        .unwrap_err(),
        CallerAssertionError::KeyUnusable
    );
    // The loaded key still never prints its material.
    let rendered = format!("{key:?}");
    assert!(rendered.contains("gw-rsa-1"));
    assert!(!rendered.contains("BEGIN"));
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

/// Every member a published JWK may carry, by key type. Anything else -- `d`, `p`, `q`, `dp`, `dq`,
/// `qi`, `oth`, `k` -- would be private material or an unreviewed extension.
const EC_PUBLIC_MEMBERS: [&str; 7] = ["alg", "crv", "kid", "kty", "use", "x", "y"];
const RSA_PUBLIC_MEMBERS: [&str; 6] = ["alg", "e", "kid", "kty", "n", "use"];
const PRIVATE_MEMBERS: [&str; 8] = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

fn assert_only_public_members(jwk: &Value) {
    let mut members = jwk
        .as_object()
        .expect("a JWK is an object")
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    members.sort_unstable();
    let allowed: &[&str] = match jwk["kty"].as_str() {
        Some("EC") => &EC_PUBLIC_MEMBERS,
        Some("RSA") => &RSA_PUBLIC_MEMBERS,
        other => panic!("unexpected key type {other:?}"),
    };
    assert_eq!(
        members, allowed,
        "the published JWK carries exactly the public members"
    );
    for private in PRIVATE_MEMBERS {
        assert!(
            jwk.get(private).is_none(),
            "the published JWK carries {private}"
        );
    }
}

/// The base64 body of a PEM document, line by line: each is a fragment of private key material.
fn pem_body_lines(pem: &str) -> Vec<&str> {
    pem.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("-----"))
        .collect()
}

fn loaded(kid: &str, algorithm: AssertionAlgorithm, pem: &str) -> AssertionSigningKey {
    load_signing_key(kid, algorithm, pem.as_bytes()).expect("generated key loads")
}

fn sign_as(key: &AssertionSigningKey, subject: &str) -> String {
    let caller = CallerIdentity {
        issuer: CALLER_ISSUER,
        subject,
        email: None,
        roles: &[],
    };
    sign_caller_assertion(
        key,
        &config(),
        Some(&caller),
        REQUEST_ID,
        1_757_000_000,
        None,
        None,
    )
    .expect("signs")
}

/// A verifier holding only the published set, as an upstream does: it selects the key by the
/// token's `kid`, takes the algorithm from the published key rather than from the token, and checks
/// the signature, issuer and audience.
fn verify_against_published_set(token: &str, jwks: &str) -> Option<Value> {
    let set: jsonwebtoken::jwk::JwkSet =
        serde_json::from_str(jwks).expect("the published set is a standard JWK Set");
    let kid = jsonwebtoken::decode_header(token).ok()?.kid?;
    let jwk = set.find(&kid)?;
    let algorithm = match jwk.common.key_algorithm.as_ref()? {
        jsonwebtoken::jwk::KeyAlgorithm::ES256 => Algorithm::ES256,
        jsonwebtoken::jwk::KeyAlgorithm::RS256 => Algorithm::RS256,
        _ => return None,
    };
    let key = DecodingKey::from_jwk(jwk).ok()?;
    let mut validation = Validation::new(algorithm);
    validation.set_issuer(&[ISSUER]);
    validation.set_audience(&[AUDIENCE]);
    // The fixture timestamp is fixed, so this checks the signature and the bound claims rather than
    // the wall clock.
    validation.validate_exp = false;
    decode::<Value>(token, &key, &validation)
        .ok()
        .map(|data| data.claims)
}

fn published(keys: &[&AssertionSigningKey]) -> JwksBuild {
    JwksDocument::from_public_jwks(keys.iter().map(|key| key.public_jwk().clone()))
}

#[test]
fn a_resolved_es256_key_publishes_a_jwk_that_verifies_what_it_signs() {
    let pem = es256_pair().serialize_pem();
    let key = loaded("gw-es-1", AssertionAlgorithm::Es256, &pem);
    assert_only_public_members(key.public_jwk());
    assert_eq!(key.public_jwk()["kid"], "gw-es-1");
    assert_eq!(key.public_jwk()["alg"], "ES256");

    let build = published(&[&key]);
    assert!(build.withheld_kids.is_empty());
    let claims = verify_against_published_set(&sign_as(&key, "user-1"), build.document.body())
        .expect("the published JWK verifies the resolved key's signature");
    assert_eq!(claims["sub"], "https://idp.example#user-1");

    // A token from any other key is refused by the same set.
    let stranger = loaded(
        "gw-es-1",
        AssertionAlgorithm::Es256,
        &es256_pair().serialize_pem(),
    );
    assert!(
        verify_against_published_set(&sign_as(&stranger, "user-1"), build.document.body())
            .is_none()
    );
}

#[test]
fn a_resolved_rs256_key_publishes_a_jwk_that_verifies_what_it_signs() {
    let pair = rs256_pair();
    let key = loaded("gw-rsa-1", AssertionAlgorithm::Rs256, &pair.pem);
    assert_only_public_members(key.public_jwk());
    // Derived from the private key, it is exactly the JWK the public components would produce.
    assert_eq!(
        key.public_jwk(),
        &rs256_public_jwk("gw-rsa-1", &pair.modulus, &pair.exponent).expect("valid JWK")
    );

    let build = published(&[&key]);
    let claims = verify_against_published_set(&sign_as(&key, "user-2"), build.document.body())
        .expect("the published JWK verifies the resolved key's signature");
    assert_eq!(claims["caller_sub"], "user-2");

    let stranger = loaded("gw-rsa-1", AssertionAlgorithm::Rs256, &rs256_pair().pem);
    assert!(
        verify_against_published_set(&sign_as(&stranger, "user-2"), build.document.body())
            .is_none()
    );
}

#[test]
fn an_upstream_holding_both_published_keys_accepts_assertions_signed_by_either() {
    // The rotation model: the next key is published before it signs, and the previous one stays
    // published until everything it signed has expired. An upstream that fetched the set at any
    // point in between holds both, so it never rejects a valid assertion mid-rotation.
    let previous = loaded(
        "gw-2026-09",
        AssertionAlgorithm::Es256,
        &es256_pair().serialize_pem(),
    );
    let next = loaded("gw-2026-10", AssertionAlgorithm::Rs256, &rs256_pair().pem);
    let both = published(&[&previous, &next]);
    assert_eq!(both.document.key_count(), 2);

    for (key, subject) in [
        (&previous, "before-the-switch"),
        (&next, "after-the-switch"),
    ] {
        let claims = verify_against_published_set(&sign_as(key, subject), both.document.body())
            .expect("either published key verifies");
        assert_eq!(claims["caller_sub"], subject);
    }

    // Once the previous key is retired from the set, what it signed no longer verifies, and what
    // the next key signs still does.
    let retired = published(&[&next]);
    assert!(verify_against_published_set(
        &sign_as(&previous, "before-the-switch"),
        retired.document.body()
    )
    .is_none());
    assert!(verify_against_published_set(
        &sign_as(&next, "after-the-switch"),
        retired.document.body()
    )
    .is_some());
    // And the two sets are distinguishable by a cache validator.
    assert_ne!(both.document.etag(), retired.document.etag());
}

#[test]
fn no_private_parameter_ever_reaches_the_published_set() {
    let ec_pem = es256_pair().serialize_pem();
    let rsa = rs256_pair();
    let ec = loaded("gw-es-1", AssertionAlgorithm::Es256, &ec_pem);
    let rs = loaded("gw-rsa-1", AssertionAlgorithm::Rs256, &rsa.pem);
    let build = published(&[&ec, &rs]);

    let document: Value =
        serde_json::from_str(build.document.body()).expect("the published set is JSON");
    assert_eq!(
        document.as_object().map(|members| members.len()),
        Some(1),
        "the set carries nothing beside its keys"
    );
    let keys = document["keys"].as_array().expect("a key array");
    assert_eq!(keys.len(), 2);
    for jwk in keys {
        assert_only_public_members(jwk);
    }

    // No fragment of either private key appears in the body, the entity tag, or the debug output
    // of anything that held it.
    let rendered = [
        build.document.body().to_owned(),
        build.document.etag().to_owned(),
        format!("{build:?}"),
        format!("{ec:?}"),
        format!("{rs:?}"),
    ]
    .join("\n");
    for line in pem_body_lines(&ec_pem)
        .into_iter()
        .chain(pem_body_lines(&rsa.pem))
    {
        assert!(!rendered.contains(line), "private key material leaked");
    }
    assert!(!rendered.contains("PRIVATE KEY"));
}

#[test]
fn an_algorithm_mismatch_is_reported_as_one() {
    // The operator chose the wrong `algorithm` for a perfectly good key; saying so is the whole
    // diagnostic.
    let ec_pem = es256_pair().serialize_pem();
    let rsa = rs256_pair();
    assert_eq!(
        load_signing_key("gw-1", AssertionAlgorithm::Rs256, ec_pem.as_bytes()).map(|_| ()),
        Err(SigningKeyRejection::AlgorithmMismatch)
    );
    assert_eq!(
        load_signing_key("gw-1", AssertionAlgorithm::Es256, rsa.pem.as_bytes()).map(|_| ()),
        Err(SigningKeyRejection::AlgorithmMismatch)
    );
    assert_eq!(
        SigningKeyRejection::AlgorithmMismatch.code(),
        "algorithm_mismatch"
    );

    // A key of the right family on the wrong curve is not a mismatch with the other algorithm: it
    // cannot sign as either.
    let p384 = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384)
        .expect("P-384 key generates")
        .serialize_pem();
    assert_eq!(
        load_signing_key("gw-1", AssertionAlgorithm::Es256, p384.as_bytes()).map(|_| ()),
        Err(SigningKeyRejection::Unusable)
    );
    assert_eq!(SigningKeyRejection::Unusable.code(), "unusable_signing_key");
}

/// A well-formed PEM block under `label`, carrying bytes that are not a key.
fn foreign_block(label: &str) -> String {
    format!("-----BEGIN {label}-----\nAAAAAAAAAAAAAAAA\n-----END {label}-----\n")
}

#[test]
fn material_that_is_not_exactly_one_pkcs8_private_key_is_refused() {
    let pair = es256_pair();
    let pem = pair.serialize_pem();
    let certificate = rcgen::CertificateParams::default()
        .self_signed(&pair)
        .expect("test certificate builds")
        .pem();
    let refused = [
        // The public half alone, which the underlying parser would otherwise take as an RSA key.
        pair.public_key_pem(),
        certificate.clone(),
        // A PKCS#1 or SEC1 label is not PKCS#8, whatever it wraps.
        pem.replace("PRIVATE KEY", "RSA PRIVATE KEY"),
        pem.replace("PRIVATE KEY", "EC PRIVATE KEY"),
        // Two keys, or a key with a certificate: which one would sign is not this gateway's guess.
        format!("{pem}{}", es256_pair().serialize_pem()),
        format!("{pem}{certificate}"),
        // Blocks the PEM parser does not recognise, which it skips rather than reports, so only
        // counting every opening marker sees them beside the key.
        format!("{pem}{}", foreign_block("ENCRYPTED PRIVATE KEY")),
        format!("{}{pem}", foreign_block("OPENSSH PRIVATE KEY")),
        format!("{pem}{}", foreign_block("RSA PUBLIC KEY")),
        "not a key".to_owned(),
        String::new(),
    ];
    for material in refused {
        assert_eq!(
            load_signing_key("gw-1", AssertionAlgorithm::Es256, material.as_bytes()).map(|_| ()),
            Err(SigningKeyRejection::NotPkcs8)
        );
    }
    assert_eq!(SigningKeyRejection::NotPkcs8.code(), "invalid_signing_key");

    // Commentary around the one block is not a second block.
    let annotated = format!("assertion key for the billing upstream\n{pem}");
    assert!(load_signing_key("gw-1", AssertionAlgorithm::Es256, annotated.as_bytes()).is_ok());
}

#[test]
fn a_key_shared_by_two_connections_is_published_once() {
    // One gateway key serving many upstreams is the common deployment, and it is one key.
    let pem = es256_pair().serialize_pem();
    let first = loaded("gw-shared", AssertionAlgorithm::Es256, &pem);
    let second = loaded("gw-shared", AssertionAlgorithm::Es256, &pem);
    let build = published(&[&first, &second]);
    assert!(build.withheld_kids.is_empty());
    assert_eq!(build.document.key_count(), 1);
}

#[test]
fn a_kid_that_names_two_different_keys_is_withheld() {
    // A verifier selecting by `kid` could take either key, so neither is published under it.
    let first = loaded(
        "gw-clash",
        AssertionAlgorithm::Es256,
        &es256_pair().serialize_pem(),
    );
    let second = loaded(
        "gw-clash",
        AssertionAlgorithm::Es256,
        &es256_pair().serialize_pem(),
    );
    let unrelated = loaded(
        "gw-other",
        AssertionAlgorithm::Es256,
        &es256_pair().serialize_pem(),
    );
    let build = published(&[&first, &second, &unrelated]);
    assert_eq!(build.withheld_kids, vec!["gw-clash".to_owned()]);
    assert_eq!(build.document.key_count(), 1);
    assert!(build.document.body().contains("gw-other"));
    assert!(!build.document.body().contains("gw-clash"));
}

#[test]
fn the_entity_tag_depends_only_on_which_keys_are_published() {
    let first = loaded(
        "gw-a",
        AssertionAlgorithm::Es256,
        &es256_pair().serialize_pem(),
    );
    let second = loaded(
        "gw-b",
        AssertionAlgorithm::Es256,
        &es256_pair().serialize_pem(),
    );
    let forward = published(&[&first, &second]);
    let reverse = published(&[&second, &first]);
    assert_eq!(forward.document, reverse.document);
    assert!(forward
        .document
        .etag()
        .starts_with("\"caller-assertion-jwks:sha256:"));
    assert!(forward.document.etag().ends_with('"'));

    let empty = JwksDocument::from_public_jwks(Vec::new());
    assert_eq!(empty.document.body(), r#"{"keys":[]}"#);
    assert_eq!(empty.document.key_count(), 0);
    assert_ne!(empty.document.etag(), forward.document.etag());
}

#[test]
fn a_cached_copy_revalidates_against_the_entity_tag() {
    let key = loaded(
        "gw-a",
        AssertionAlgorithm::Es256,
        &es256_pair().serialize_pem(),
    );
    let document = published(&[&key]).document;
    let etag = document.etag().to_owned();
    assert!(document.matches_if_none_match(&etag));
    assert!(document.matches_if_none_match(&format!("W/{etag}")));
    assert!(document.matches_if_none_match(&format!("\"stale\", {etag}")));
    assert!(document.matches_if_none_match("*"));
    assert!(!document.matches_if_none_match("\"stale\""));
    assert!(!document.matches_if_none_match(""));
}

#[test]
fn the_published_set_is_cacheable_for_its_advertised_lifetime() {
    // The header is a literal so it can be a static header value; it must not drift from the
    // lifetime the rotation procedure waits out.
    assert_eq!(
        JWKS_CACHE_CONTROL,
        format!("public, max-age={JWKS_MAX_AGE_SECONDS}")
    );
    assert!(JWKS_PATH.starts_with("/.well-known/"));
}

#[test]
fn the_configured_algorithm_maps_onto_the_signing_algorithm() {
    use super::super::model::CallerAssertionAlgorithm;

    assert_eq!(
        AssertionAlgorithm::from(CallerAssertionAlgorithm::Es256),
        AssertionAlgorithm::Es256
    );
    assert_eq!(
        AssertionAlgorithm::from(CallerAssertionAlgorithm::Rs256),
        AssertionAlgorithm::Rs256
    );
}
