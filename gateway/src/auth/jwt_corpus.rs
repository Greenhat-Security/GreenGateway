//! Test-only corpus entry point for the synchronous JWT/JWK parsers.
//!
//! This deliberately calls neither `decode` (which can refresh JWKS) nor
//! `validate_claims` (which can consult revocation). The generated signatures
//! exercise real crypto, but are never fixtures or diagnostic output.

use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde_json::{json, Value};

use crate::egress::{DnsResolver, EgressClient, EgressConfig};

use super::{
    cached_decoding_key, AuthError, CachedDecodingKey, JwksKey, JwtAuthConfig, JwtValidator,
    RevocationStore,
};

const MAX_INPUT_BYTES: usize = 16_384;
const ISSUER: &str = "https://corpus-issuer.example.test";
const AUDIENCE: &str = "corpus-audience";
// Expiry is 2100-01-01; the not-before rejection is 2200-01-01. The
// acceptance oracle is intentionally valid through 2099, not near a clock
// boundary. The expired value is one second after the Unix epoch.
const FUTURE_EXP: u64 = 4_102_444_800;
const FUTURE_NBF: u64 = 7_258_118_400;
const EXPIRED: u64 = 1;

struct NoDns(Arc<AtomicUsize>);

#[async_trait::async_trait]
impl DnsResolver for NoDns {
    async fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<SocketAddr>, std::io::Error> {
        self.0.fetch_add(1, Ordering::SeqCst);
        panic!("pure JWT corpus attempted DNS resolution");
    }
}

struct NoRevocation(Arc<AtomicUsize>);

#[async_trait::async_trait]
impl RevocationStore for NoRevocation {
    async fn is_revoked(&self, _jti: &str) -> Result<bool, AuthError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        panic!("pure JWT corpus attempted revocation lookup");
    }
}

struct SignedCase {
    token: String,
    accepted: bool,
    failure: &'static str,
}

struct Identity {
    encoding: EncodingKey,
    cached: CachedDecodingKey,
    cases: Vec<SignedCase>,
}

/// Construct once per worker so mutations reuse generated keys and oracles.
pub(crate) struct CorpusHarness {
    validator: JwtValidator,
    identities: [Identity; 2],
    dns_calls: Arc<AtomicUsize>,
    revocation_calls: Arc<AtomicUsize>,
}

impl CorpusHarness {
    pub(crate) fn new() -> Result<Self, &'static str> {
        let dns_calls = Arc::new(AtomicUsize::new(0));
        let revocation_calls = Arc::new(AtomicUsize::new(0));
        let egress = EgressClient::new_with_resolver(
            EgressConfig {
                allowed_hosts: HashSet::from(["corpus-issuer.example.test".to_owned()]),
                ..EgressConfig::default()
            },
            Arc::new(NoDns(Arc::clone(&dns_calls))),
        )
        .map_err(|_| "JWT corpus egress construction failed")?;
        let validator = JwtValidator::new_with_keys(
            JwtAuthConfig {
                jwks_url: format!("{ISSUER}/jwks"),
                issuer: Some(ISSUER.to_owned()),
                audience: Some(AUDIENCE.to_owned()),
                http_timeout: Duration::from_secs(1),
                jwks_max_key_age: Duration::from_secs(300),
                require_jti: true,
                roles_claim: "roles".to_owned(),
                roles_claim_delimiter: None,
                org_claim: None,
            },
            Arc::new(egress),
            Arc::new(NoRevocation(Arc::clone(&revocation_calls))),
            HashMap::new(),
        )
        .map_err(|_| "JWT corpus validator construction failed")?;
        let harness = Self {
            validator,
            identities: [identity(Algorithm::ES256)?, identity(Algorithm::EdDSA)?],
            dns_calls,
            revocation_calls,
        };
        harness.check(b"{}")?;
        Ok(harness)
    }

    pub(crate) fn check(&self, input: &[u8]) -> Result<(), &'static str> {
        if input.len() > MAX_INPUT_BYTES {
            return Err("JWT corpus input exceeds byte limit");
        }
        let parsed = serde_json::from_slice::<Value>(input).ok();
        for identity in &self.identities {
            // Each mutation must still reach positive verification and all
            // forced denial cases; random malformed inputs alone are vacuous.
            for case in &identity.cases {
                if self
                    .validator
                    .decode_with_key(&case.token, &identity.cached)
                    .is_ok()
                    != case.accepted
                {
                    return Err(case.failure);
                }
            }
            if let Ok(token) = std::str::from_utf8(input) {
                self.stable_decode(token, &identity.cached)?;
            }
            let (_, payload_and_signature) = identity.cases[0]
                .token
                .split_once('.')
                .ok_or("generated JWT missing header separator")?;
            // Arbitrary bytes reach the real header parser, including invalid
            // UTF-8. Retaining a signature does not imply it is still valid.
            let token = format!(
                "{}.{}",
                URL_SAFE_NO_PAD.encode(input),
                payload_and_signature
            );
            self.stable_decode(&token, &identity.cached)?;
            if let Some(value) = &parsed {
                let mut claims = value.get("claims").unwrap_or(value).clone();
                fixed_time_claims(&mut claims);
                let token = sign(&claims, identity)?;
                self.stable_decode(&token, &identity.cached)?;
                if let Some(header) = value.get("header") {
                    let bytes = serde_json::to_vec(header)
                        .map_err(|_| "JWT corpus header serialization failed")?;
                    let token = format!(
                        "{}.{}",
                        URL_SAFE_NO_PAD.encode(bytes),
                        payload_and_signature
                    );
                    self.stable_decode(&token, &identity.cached)?;
                }
            }
        }
        if let Some(value) = &parsed {
            let jwk = value.get("jwk").unwrap_or(value);
            let parse = || {
                serde_json::from_value::<JwksKey>(jwk.clone())
                    .ok()
                    .and_then(cached_decoding_key)
            };
            let first = parse();
            let second = parse();
            let shape = |key: &CachedDecodingKey| (key.kid.clone(), key.algorithm);
            if first.as_ref().map(shape) != second.as_ref().map(shape) {
                return Err("JWK corpus classification changed on replay");
            }
            if let (Some(first), Some(second)) = (first, second) {
                for identity in &self.identities {
                    let token = &identity.cases[0].token;
                    if self.validator.decode_with_key(token, &first).is_ok()
                        != self.validator.decode_with_key(token, &second).is_ok()
                    {
                        return Err("JWK corpus verification changed on replay");
                    }
                }
            }
        }
        if self.dns_calls.load(Ordering::SeqCst) != 0
            || self.revocation_calls.load(Ordering::SeqCst) != 0
        {
            return Err("JWT corpus performed an external lookup");
        }
        Ok(())
    }

    fn stable_decode(&self, token: &str, key: &CachedDecodingKey) -> Result<(), &'static str> {
        let first = self.validator.decode_with_key(token, key).is_ok();
        let second = self.validator.decode_with_key(token, key).is_ok();
        if first != second {
            return Err("JWT corpus classification changed on replay");
        }
        Ok(())
    }
}

// Preserve missing and malformed time claims. Numeric values are mapped to
// one of two fixed distant times, so corpus bytes cannot pick a leeway edge.
fn fixed_time_claims(claims: &mut Value) {
    for (name, even, odd) in [("exp", FUTURE_EXP, EXPIRED), ("nbf", EXPIRED, FUTURE_NBF)] {
        if let Some(value) = claims.get_mut(name) {
            if value.is_number() {
                let is_even = value.as_u64().is_some_and(|number| number % 2 == 0);
                *value = json!(if is_even { even } else { odd });
            }
        }
    }
}

fn base_claims() -> Value {
    json!({"sub": "corpus-subject", "iss": ISSUER, "aud": AUDIENCE,
        "exp": FUTURE_EXP, "nbf": EXPIRED, "jti": "corpus-session"})
}

fn sign(claims: &Value, identity: &Identity) -> Result<String, &'static str> {
    let mut header = Header::new(identity.cached.algorithm);
    header.kid = Some(identity.cached.kid.clone());
    encode(&header, claims, &identity.encoding).map_err(|_| "JWT corpus signing failed")
}

fn identity(algorithm: Algorithm) -> Result<Identity, &'static str> {
    let kind = match algorithm {
        Algorithm::ES256 => &rcgen::PKCS_ECDSA_P256_SHA256,
        Algorithm::EdDSA => &rcgen::PKCS_ED25519,
        _ => return Err("unsupported JWT corpus identity algorithm"),
    };
    let pair =
        rcgen::KeyPair::generate_for(kind).map_err(|_| "JWT corpus key generation failed")?;
    let raw = pair.public_key_raw();
    let der = pair.serialize_der();
    let (encoding, jwk) = match algorithm {
        Algorithm::ES256 if raw.len() == 65 && raw[0] == 4 => (
            EncodingKey::from_ec_der(&der),
            json!({"kid": "corpus-ec", "kty": "EC", "crv": "P-256",
                "x": URL_SAFE_NO_PAD.encode(&raw[1..33]),
                "y": URL_SAFE_NO_PAD.encode(&raw[33..65])}),
        ),
        Algorithm::EdDSA if raw.len() == 32 => (
            EncodingKey::from_ed_der(&der),
            json!({"kid": "corpus-ed", "kty": "OKP", "crv": "Ed25519",
                "x": URL_SAFE_NO_PAD.encode(raw)}),
        ),
        _ => return Err("generated JWT public key has unexpected shape"),
    };
    let cached = serde_json::from_value::<JwksKey>(jwk)
        .ok()
        .and_then(cached_decoding_key)
        .ok_or("generated JWK was not admitted")?;
    if cached.algorithm != algorithm {
        return Err("generated JWK has wrong algorithm");
    }
    let mut identity = Identity {
        encoding,
        cached,
        cases: Vec::new(),
    };
    identity.cases.push(SignedCase {
        token: sign(&base_claims(), &identity)?,
        accepted: true,
        failure: "valid generated JWT was rejected",
    });
    for (claim, value, failure) in [
        (
            "iss",
            json!("https://different.example.test"),
            "wrong JWT issuer was accepted",
        ),
        (
            "aud",
            json!("different-audience"),
            "wrong JWT audience was accepted",
        ),
        ("exp", json!(EXPIRED), "expired JWT was accepted"),
        ("nbf", json!(FUTURE_NBF), "future JWT was accepted"),
        ("exp", Value::Null, "null JWT expiry was accepted"),
        ("sub", json!([]), "malformed JWT subject was accepted"),
    ] {
        let mut claims = base_claims();
        claims[claim] = value;
        identity.cases.push(SignedCase {
            token: sign(&claims, &identity)?,
            accepted: false,
            failure,
        });
    }
    for claim in ["sub", "exp", "iss", "aud"] {
        let mut claims = base_claims();
        claims
            .as_object_mut()
            .ok_or("JWT baseline claims are not an object")?
            .remove(claim);
        identity.cases.push(SignedCase {
            token: sign(&claims, &identity)?,
            accepted: false,
            failure: "JWT missing a required pure-decoder claim was accepted",
        });
    }
    let token = &identity.cases[0].token;
    let (signed, signature) = token
        .rsplit_once('.')
        .ok_or("generated JWT missing signature separator")?;
    let mut signature = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| "generated JWT signature is not base64url")?;
    let first = signature
        .first_mut()
        .ok_or("generated JWT signature is empty")?;
    *first ^= 1;
    identity.cases.push(SignedCase {
        token: format!("{signed}.{}", URL_SAFE_NO_PAD.encode(signature)),
        accepted: false,
        failure: "JWT with altered signature was accepted",
    });
    identity.cases.push(SignedCase {
        token: encode(
            &Header::new(Algorithm::HS256),
            &base_claims(),
            &EncodingKey::from_secret(&der),
        )
        .map_err(|_| "JWT corpus alternate-algorithm signing failed")?,
        accepted: false,
        failure: "JWT with wrong algorithm was accepted",
    });
    Ok(identity)
}

#[test]
fn generated_jwt_corpus_checks_acceptance_rejection_and_no_lookup() {
    let harness = CorpusHarness::new().expect("runtime JWT corpus identities");
    for identity in &harness.identities {
        assert_eq!(
            identity.cases.iter().filter(|case| case.accepted).count(),
            1
        );
        assert_eq!(
            identity.cases.iter().filter(|case| !case.accepted).count(),
            12
        );
    }
    for input in [
        b"{}".as_slice(),
        br#"{"claims":{"sub":"corpus-subject","iss":"https://corpus-issuer.example.test","aud":"corpus-audience","exp":2,"nbf":2}}"#,
        br#"{"jwk":{"kty":"EC","kid":"synthetic","crv":"P-256","x":"?","y":"?"}}"#,
        br#"{"header":{"alg":"none","jku":"https://never-contact.example.test/keys"}}"#,
        b"\x00\xff\x80",
    ] {
        harness.check(input).expect("bounded pure JWT corpus check");
    }
    assert!(harness.check(&vec![0; MAX_INPUT_BYTES + 1]).is_err());
    assert_eq!(harness.dns_calls.load(Ordering::SeqCst), 0);
    assert_eq!(harness.revocation_calls.load(Ordering::SeqCst), 0);
}
