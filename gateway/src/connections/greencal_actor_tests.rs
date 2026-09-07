//! Tests for the GreenCal actor assertion signer.
//!
//! The canonicalization and digest cases in `greencal_actor_fixtures.json` are **generated from
//! GreenCal's own verifier**, not written by hand. Its `docs/scoped-gateway-v2.md` asks for exactly
//! that: "Gateway must add matching cross-language fixtures before activation, rather than guessing
//! how to hash JSON." The generator extracts `canonicalJson` and `requestDigest` verbatim from
//! `src/gateway/scopedGatewayActor.ts` in the GreenCal repository, strips only the TypeScript
//! annotations, runs them under Node, and records the canonical text and digest each case produces.
//! Regenerate them the same way whenever that file changes; do not edit the JSON by hand.
//!
//! The cases that matter are the ordering ones. JavaScript sorts object keys by UTF-16 code unit,
//! so U+10000 sorts *below* U+FFFF because its first surrogate is 0xD800. Rust's `str` ordering is
//! by UTF-8 byte and puts them the other way round. A naive port would agree with the fixtures on
//! every ASCII payload and silently produce a different digest -- and therefore a rejected request
//! -- the first time a calendar title contained an emoji.

use serde_json::{json, Value};

use super::*;

/// One generated case: the request as JavaScript saw it, and what it produced.
#[derive(serde::Deserialize)]
struct Fixture {
    name: String,
    operation: String,
    body: Value,
    canonical: String,
    digest: String,
}

fn fixtures() -> Vec<Fixture> {
    serde_json::from_str(include_str!("greencal_actor_fixtures.json"))
        .expect("fixtures are valid JSON")
}

#[test]
fn canonical_json_matches_the_javascript_verifier() {
    let fixtures = fixtures();
    assert!(
        fixtures.len() >= 19,
        "fixture set shrank; regenerate rather than trimming"
    );
    for fixture in fixtures {
        let produced = canonical_json(&fixture.body)
            .unwrap_or_else(|error| panic!("{}: {error}", fixture.name));
        assert_eq!(
            produced, fixture.canonical,
            "canonical form disagrees with GreenCal for case {:?}",
            fixture.name
        );
    }
}

#[test]
fn request_digest_matches_the_javascript_verifier() {
    for fixture in fixtures() {
        let produced = request_digest(&fixture.operation, &fixture.body)
            .unwrap_or_else(|error| panic!("{}: {error}", fixture.name));
        assert_eq!(
            produced, fixture.digest,
            "digest disagrees with GreenCal for case {:?}",
            fixture.name
        );
    }
}

#[test]
fn object_keys_sort_by_utf16_code_unit_not_code_point() {
    // The single case a UTF-8 ordering gets wrong, stated directly rather than only as a fixture,
    // so the reason survives even if the generated file is ever replaced.
    let body = json!({ "\u{10000}": 1, "\u{ffff}": 2 });
    let canonical = canonical_json(&body).expect("canonicalizable");
    assert!(
        canonical.starts_with("{\"\u{10000}\""),
        "supplementary key must sort first, got {canonical}"
    );
}

#[test]
fn nesting_deeper_than_the_shared_cap_is_refused() {
    let mut value = json!(1);
    for _ in 0..40 {
        value = json!({ "n": value });
    }
    assert_eq!(
        canonical_json(&value),
        Err(ActorSigningError::UncanonicalizableBody("depth"))
    );
}

#[test]
fn non_integer_numbers_are_refused_rather_than_guessed() {
    // The v2 body schemas allow only safe integers. Rather than reimplement JavaScript's
    // shortest-round-trip double formatting for values the API would reject, refuse them.
    assert!(canonical_json(&json!({ "n": 1.5 })).is_err());
    assert!(canonical_json(&json!({ "n": 9_007_199_254_740_992_i64 })).is_err());
    assert_eq!(
        canonical_json(&json!({ "n": 9_007_199_254_740_991_i64 })).unwrap(),
        "{\"n\":9007199254740991}"
    );
}

/// A fresh P-256 key pair for one test.
///
/// Generated rather than committed. This repository keeps no private key material in the tree --
/// its only historical exceptions are recorded in `.gitleaksignore` -- and a checked-in PEM would
/// trip the secret scanner for no benefit, since nothing outside the test needs this key to be
/// stable.
fn test_key_pair() -> rcgen::KeyPair {
    rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("P-256 key generates")
}

fn signing_key_from(pair: &rcgen::KeyPair) -> ActorSigningKey {
    ActorSigningKey::from_pkcs8_pem("gw-test-1", pair.serialize_pem().as_bytes())
        .expect("generated key loads")
}

fn signing_key() -> ActorSigningKey {
    signing_key_from(&test_key_pair())
}

const SUBJECT: &str = "u-anthony-001";
const ORG: &str = "greenhat";
const SERVICE_CLIENT: &str = "greengateway-greencal";
const REQUEST_KEY: &str = "test-request-key-0000000000000000";
const APPROVAL_ID: &str = "test-approval-id-0000000000000000";

fn read_request<'a>(body: &'a Value) -> ActorAssertionRequest<'a> {
    ActorAssertionRequest {
        subject: SUBJECT,
        org_id: ORG,
        service_client_id: SERVICE_CLIENT,
        operation: "greencal_get_meeting",
        body,
        request_key: REQUEST_KEY,
        approval_id: None,
        mutation: false,
        issued_at: 1_757_000_000,
        lifetime_seconds: 30,
    }
}

#[test]
fn a_read_assertion_carries_the_claims_greencal_requires() {
    let body = json!({ "meetingId": "m-1" });
    let token = sign_actor_assertion(&signing_key(), &read_request(&body)).expect("signs");

    let (header, claims) = decode_unverified(&token);
    assert_eq!(header["alg"], "ES256");
    assert_eq!(header["typ"], ACTOR_TYP);
    assert_eq!(header["kid"], "gw-test-1");
    assert_eq!(claims["iss"], ACTOR_ISSUER);
    assert_eq!(claims["aud"], ACTOR_AUDIENCE);
    assert_eq!(claims["sub"], SUBJECT);
    assert_eq!(claims["org_id"], ORG);
    assert_eq!(claims["service_client_id"], SERVICE_CLIENT);
    assert_eq!(claims["jti"], REQUEST_KEY);
    assert_eq!(claims["operation"], "greencal_get_meeting");
    assert_eq!(
        claims["request_sha256"],
        request_digest("greencal_get_meeting", &body).unwrap()
    );
    assert_eq!(
        claims["exp"].as_u64().unwrap() - claims["iat"].as_u64().unwrap(),
        30
    );
    // A read must not claim an approval; GreenCal reads `approved` only for mutations, and an
    // approval attached to a read is an approval for some other operation.
    assert!(claims.get("approved").is_none());
    assert!(claims.get("approval_id").is_none());
}

#[test]
fn a_mutation_assertion_binds_the_approval_and_the_request_key() {
    let body = json!({ "requestKey": REQUEST_KEY, "expectedVersion": 3, "title": "Review" });
    let mut request = read_request(&body);
    request.operation = "greencal_update_meeting";
    request.mutation = true;
    request.approval_id = Some(APPROVAL_ID);

    let token = sign_actor_assertion(&signing_key(), &request).expect("signs");
    let (_, claims) = decode_unverified(&token);
    assert_eq!(claims["approved"], true);
    assert_eq!(claims["approval_id"], APPROVAL_ID);
    assert_eq!(claims["jti"], REQUEST_KEY);
}

#[test]
fn a_mutation_whose_body_omits_the_request_key_is_refused() {
    // GreenCal checks `body.requestKey === jti`. Signing it anyway would spend the request key on
    // an assertion its verifier rejects, which is indistinguishable from tampering in its audit.
    let body = json!({ "expectedVersion": 3 });
    let mut request = read_request(&body);
    request.mutation = true;
    request.approval_id = Some(APPROVAL_ID);
    assert_eq!(
        sign_actor_assertion(&signing_key(), &request),
        Err(ActorSigningError::InvalidClaim("requestKey"))
    );
}

#[test]
fn a_mutation_whose_body_carries_a_different_request_key_is_refused() {
    let body = json!({ "requestKey": "test-request-key-1111111111111111" });
    let mut request = read_request(&body);
    request.mutation = true;
    request.approval_id = Some(APPROVAL_ID);
    assert_eq!(
        sign_actor_assertion(&signing_key(), &request),
        Err(ActorSigningError::InvalidClaim("requestKey"))
    );
}

#[test]
fn a_mutation_without_an_approval_is_refused() {
    let body = json!({ "requestKey": REQUEST_KEY });
    let mut request = read_request(&body);
    request.mutation = true;
    request.approval_id = None;
    assert_eq!(
        sign_actor_assertion(&signing_key(), &request),
        Err(ActorSigningError::ApprovalMismatch)
    );
}

#[test]
fn a_read_carrying_an_approval_is_refused() {
    let body = json!({ "meetingId": "m-1" });
    let mut request = read_request(&body);
    request.approval_id = Some(APPROVAL_ID);
    assert_eq!(
        sign_actor_assertion(&signing_key(), &request),
        Err(ActorSigningError::ApprovalMismatch)
    );
}

#[test]
fn claim_shapes_match_the_verifiers_regexes() {
    let body = json!({});
    let key = signing_key();

    let mut short_key = read_request(&body);
    short_key.request_key = "too-short";
    assert_eq!(
        sign_actor_assertion(&key, &short_key),
        Err(ActorSigningError::InvalidClaim("jti"))
    );

    let mut spaced_key = read_request(&body);
    let with_space = "01JQ8Z9X7YQ2W4E6R8T0YU2I4O6P8A0 ";
    spaced_key.request_key = with_space;
    assert_eq!(
        sign_actor_assertion(&key, &spaced_key),
        Err(ActorSigningError::InvalidClaim("jti"))
    );

    let mut email_subject = read_request(&body);
    email_subject.subject = "anthony@greenhatsec.com";
    assert_eq!(
        sign_actor_assertion(&key, &email_subject),
        Err(ActorSigningError::InvalidClaim("sub"))
    );

    let mut odd_operation = read_request(&body);
    odd_operation.operation = "GreenCal_Get_Meeting";
    assert_eq!(
        sign_actor_assertion(&key, &odd_operation),
        Err(ActorSigningError::InvalidClaim("operation"))
    );

    let mut path_operation = read_request(&body);
    path_operation.operation = "greencal/../admin";
    assert_eq!(
        sign_actor_assertion(&key, &path_operation),
        Err(ActorSigningError::InvalidClaim("operation"))
    );
}

#[test]
fn lifetimes_outside_the_accepted_window_are_refused() {
    let body = json!({});
    let key = signing_key();

    let mut zero = read_request(&body);
    zero.lifetime_seconds = 0;
    assert_eq!(
        sign_actor_assertion(&key, &zero),
        Err(ActorSigningError::InvalidLifetime)
    );

    let mut too_long = read_request(&body);
    too_long.lifetime_seconds = MAX_LIFETIME_SECONDS + 1;
    assert_eq!(
        sign_actor_assertion(&key, &too_long),
        Err(ActorSigningError::InvalidLifetime)
    );

    let mut at_cap = read_request(&body);
    at_cap.lifetime_seconds = MAX_LIFETIME_SECONDS;
    assert!(sign_actor_assertion(&key, &at_cap).is_ok());
}

#[test]
fn the_published_jwk_carries_exactly_the_seven_accepted_members() {
    // GreenCal rejects a key with any other member, `d` included, so this is asserted rather than
    // assumed: publishing a JWK it refuses disables the integration wholesale.
    let point = [vec![0x04u8], vec![0x11u8; 32], vec![0x22u8; 32]].concat();
    let jwk = public_jwk("gw-test-1", &point).expect("valid point");
    let object = jwk.as_object().expect("object");
    let mut members: Vec<&str> = object.keys().map(String::as_str).collect();
    members.sort_unstable();
    assert_eq!(members, ["alg", "crv", "kid", "kty", "use", "x", "y"]);
    assert_eq!(jwk["kty"], "EC");
    assert_eq!(jwk["crv"], "P-256");
    assert_eq!(jwk["alg"], "ES256");
    assert_eq!(jwk["use"], "sig");
    // 32 bytes base64url with no padding is 43 characters, which is what its regex demands.
    assert_eq!(jwk["x"].as_str().unwrap().len(), 43);
    assert_eq!(jwk["y"].as_str().unwrap().len(), 43);
}

#[test]
fn a_malformed_public_point_is_refused() {
    assert_eq!(
        public_jwk("gw-test-1", &[0x04; 64]),
        Err(ActorSigningError::KeyUnusable)
    );
    // Compressed points carry only one coordinate; GreenCal's JWKS needs both.
    let compressed = [vec![0x02u8], vec![0x11u8; 32]].concat();
    assert_eq!(
        public_jwk("gw-test-1", &compressed),
        Err(ActorSigningError::KeyUnusable)
    );
}

#[test]
fn the_signing_key_never_prints_its_material() {
    let rendered = format!("{:?}", signing_key());
    assert!(rendered.contains("gw-test-1"));
    assert!(!rendered.to_ascii_lowercase().contains("private"));
    assert!(!rendered.contains("BEGIN"));
}

/// Splits a compact JWS and decodes its header and payload, without verifying.
///
/// The signature is checked by GreenCal, and by the round-trip test below; these assertions are
/// about what this gateway puts in the token.
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
fn the_signature_verifies_against_the_matching_public_key() {
    use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};

    let pair = test_key_pair();
    let body = json!({ "meetingId": "m-1" });
    let token =
        sign_actor_assertion(&signing_key_from(&pair), &read_request(&body)).expect("signs");

    let mut validation = Validation::new(Algorithm::ES256);
    validation.set_issuer(&[ACTOR_ISSUER]);
    validation.set_audience(&[ACTOR_AUDIENCE]);
    validation.set_required_spec_claims(&["iss", "aud", "exp", "sub"]);
    // The fixture timestamp is fixed, so validate the shape rather than the wall clock.
    validation.validate_exp = false;

    let public =
        DecodingKey::from_ec_pem(pair.public_key_pem().as_bytes()).expect("public key loads");
    let decoded = decode::<Value>(&token, &public, &validation).expect("verifies");
    assert_eq!(decoded.claims["sub"], SUBJECT);
}
