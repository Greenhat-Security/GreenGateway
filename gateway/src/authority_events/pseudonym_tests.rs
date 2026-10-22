use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Mutex,
};

use async_trait::async_trait;

use super::*;
use crate::connections::secret::{SecretAliasMetadata, SecretResolveError, SecretValueError};

/// A fresh key, hex encoded the way an operator provisions one. Generated at
/// run time so no key material is ever committed.
fn generated_key_hex() -> String {
    let mut bytes = [0_u8; PSEUDONYM_KEY_BYTES];
    getrandom::fill(&mut bytes).expect("the OS random source should be available");
    hex::encode(bytes)
}

fn resolved(purpose: SecretPurpose, material: &str) -> ResolvedSecret {
    ResolvedSecret::new(purpose, material.as_bytes().to_vec())
        .expect("bounded test material should be accepted")
}

fn key(material: &str) -> PseudonymKey {
    PseudonymKey::from_resolved(&resolved(SecretPurpose::AuthorityPseudonymKey, material))
        .expect("a generated key should parse")
}

fn keyring(authority_id: Uuid, current: &str, previous: Option<&str>) -> PseudonymKeyring {
    PseudonymKeyring::new(authority_id, key(current), previous.map(key))
        .expect("the keyring should build")
}

/// The documented construction, written out independently of the module's
/// helpers and with its labels spelled literally, so changing the derivation
/// format -- which would orphan every committed reference -- fails here.
fn documented_reference(
    material: &str,
    authority_id: Uuid,
    domain_label: &str,
    components: &[&str],
) -> String {
    fn framed(mac: &mut Hmac<Sha256>, field: &[u8]) {
        mac.update(&(field.len() as u64).to_be_bytes());
        mac.update(field);
    }
    let raw = hex::decode(material).expect("generated key is hex");
    let mut key_id = <Hmac<Sha256> as KeyInit>::new_from_slice(&raw).expect("any key length");
    framed(&mut key_id, b"greengateway.authority_pseudonym.key_id.v1");
    let key_id = key_id.finalize().into_bytes();

    let mut tag = <Hmac<Sha256> as KeyInit>::new_from_slice(&raw).expect("any key length");
    framed(&mut tag, b"greengateway.authority_pseudonym.v1");
    framed(&mut tag, authority_id.as_bytes());
    framed(&mut tag, domain_label.as_bytes());
    tag.update(&(components.len() as u64).to_be_bytes());
    for component in components {
        framed(&mut tag, component.as_bytes());
    }
    let tag = tag.finalize().into_bytes();
    format!("{}{}", hex::encode(&key_id[..4]), hex::encode(&tag[..28]))
}

/// Components that fit `domain`, distinct per call site through `value`.
fn components_for(domain: ReferenceDomain, value: &'static str) -> Vec<&'static str> {
    match domain {
        ReferenceDomain::ActorSubject => vec!["https://issuer.example.test", value],
        _ => vec![value],
    }
}

#[test]
fn references_are_deterministic_for_one_key_authority_and_input() {
    let material = generated_key_hex();
    let authority_id = Uuid::new_v4();
    // Two keyrings built from the same material stand in for a restart and
    // for a second replica holding the same key.
    let first = keyring(authority_id, &material, None);
    let second = keyring(authority_id, &material, None);
    let components = ["https://issuer.example.test", "user-123"];

    let reference = first
        .derive(ReferenceDomain::ActorSubject, &components)
        .expect("reference should derive");
    assert_eq!(
        reference,
        first
            .derive(ReferenceDomain::ActorSubject, &components)
            .expect("reference should derive")
    );
    assert_eq!(
        reference,
        second
            .derive(ReferenceDomain::ActorSubject, &components)
            .expect("reference should derive")
    );

    // The schema's safe-reference shape, led by the key ID.
    assert_eq!(reference.as_str().len(), REFERENCE_HEX_CHARS);
    assert!(reference
        .as_str()
        .bytes()
        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')));
    assert_eq!(first.current_key_id().len(), KEY_ID_HEX_CHARS);
    assert_eq!(reference.key_id(), first.current_key_id());
    assert!(reference.as_str().starts_with(first.current_key_id()));
    assert_eq!(reference.to_string(), reference.as_str());
    assert_eq!(first.authority_id(), authority_id);
    assert_eq!(first.previous_key_id(), None);
}

#[test]
fn derivation_matches_the_documented_construction() {
    let material = generated_key_hex();
    let authority_id = Uuid::new_v4();
    let keyring = keyring(authority_id, &material, None);

    for (domain, label, components) in [
        (
            ReferenceDomain::ActorSubject,
            "actor.subject",
            vec!["https://issuer.example.test", "user-123"],
        ),
        (
            ReferenceDomain::ActorIssuer,
            "actor.issuer",
            vec!["https://issuer.example.test"],
        ),
        (
            ReferenceDomain::ActorRecorded,
            "actor.recorded",
            vec!["user-123"],
        ),
        (
            ReferenceDomain::Connection,
            "resource.connection",
            vec!["billing-api"],
        ),
        (
            ReferenceDomain::CredentialBinding,
            "resource.credential_binding",
            vec!["billing-api", "authentication"],
        ),
    ] {
        assert_eq!(
            keyring
                .derive(domain, &components)
                .expect("reference should derive")
                .as_str(),
            documented_reference(&material, authority_id, label, &components),
            "{label}"
        );
    }
}

#[test]
fn every_domain_yields_an_unrelated_reference_for_the_same_identifier() {
    let keyring = keyring(Uuid::new_v4(), &generated_key_hex(), None);
    let mut references = BTreeSet::new();
    let mut labels = BTreeSet::new();
    for domain in ReferenceDomain::ALL {
        assert!(labels.insert(domain.label()), "{domain:?} label repeats");
        let reference = keyring
            .derive(domain, &components_for(domain, "shared-identifier"))
            .expect("reference should derive");
        assert!(
            references.insert(reference.as_str().to_owned()),
            "{domain:?} collides with another domain"
        );
    }
    assert_eq!(references.len(), ReferenceDomain::ALL.len());
}

#[test]
fn length_prefixes_keep_component_boundaries_apart() {
    let keyring = keyring(Uuid::new_v4(), &generated_key_hex(), None);
    let derive = |domain, components: &[&str]| {
        keyring
            .derive(domain, components)
            .expect("reference should derive")
            .as_str()
            .to_owned()
    };
    let splits = BTreeSet::from([
        derive(ReferenceDomain::CredentialBinding, &["ab", "c"]),
        derive(ReferenceDomain::CredentialBinding, &["a", "bc"]),
        derive(ReferenceDomain::CredentialBinding, &["abc"]),
        derive(ReferenceDomain::CredentialBinding, &["a", "b", "c"]),
        derive(ReferenceDomain::CredentialBinding, &["a\0b", "c"]),
    ]);
    assert_eq!(splits.len(), 5);

    // The issuer that scopes a subject cannot run into it either.
    assert_ne!(
        derive(ReferenceDomain::ActorSubject, &["issuer-a", "bc"]),
        derive(ReferenceDomain::ActorSubject, &["issuer-ab", "c"])
    );
    assert_ne!(
        derive(ReferenceDomain::ActorSubject, &["issuer-a", "user"]),
        derive(ReferenceDomain::ActorSubject, &["issuer-b", "user"])
    );
}

#[test]
fn references_are_scoped_to_their_evidence_authority() {
    let material = generated_key_hex();
    let original = keyring(Uuid::new_v4(), &material, None);
    // A clone re-namespaced under a new authority ID, still holding the key.
    let clone = keyring(Uuid::new_v4(), &material, None);
    let components = ["billing-api"];

    let original_reference = original
        .derive(ReferenceDomain::Connection, &components)
        .expect("reference should derive");
    let clone_reference = clone
        .derive(ReferenceDomain::Connection, &components)
        .expect("reference should derive");
    assert_eq!(original.current_key_id(), clone.current_key_id());
    assert_ne!(original_reference, clone_reference);
    assert_eq!(
        clone
            .verify(
                ReferenceDomain::Connection,
                &components,
                original_reference.as_str()
            )
            .expect("well-formed reference"),
        ReferenceCheck::Mismatch
    );
}

#[test]
fn different_keys_give_unrelated_references_and_key_ids() {
    let authority_id = Uuid::new_v4();
    let first = keyring(authority_id, &generated_key_hex(), None);
    let second = keyring(authority_id, &generated_key_hex(), None);
    let components = ["billing-api"];

    assert_ne!(first.current_key_id(), second.current_key_id());
    let first_reference = first
        .derive(ReferenceDomain::Connection, &components)
        .expect("reference should derive");
    let second_reference = second
        .derive(ReferenceDomain::Connection, &components)
        .expect("reference should derive");
    assert_ne!(
        first_reference.as_str()[KEY_ID_HEX_CHARS..],
        second_reference.as_str()[KEY_ID_HEX_CHARS..]
    );
}

#[test]
fn rotation_keeps_previous_references_verifiable_inside_the_window() {
    let authority_id = Uuid::new_v4();
    let old_material = generated_key_hex();
    let new_material = generated_key_hex();
    let components = ["https://issuer.example.test", "user-123"];
    let domain = ReferenceDomain::ActorSubject;

    let before = keyring(authority_id, &old_material, None);
    let old_reference = before
        .derive(domain, &components)
        .expect("reference should derive");

    // Rotation: the new key derives, the old one only verifies.
    let window = keyring(authority_id, &new_material, Some(&old_material));
    assert_eq!(window.previous_key_id(), Some(before.current_key_id()));
    let new_reference = window
        .derive(domain, &components)
        .expect("reference should derive");
    assert_ne!(new_reference, old_reference);
    assert_eq!(new_reference.key_id(), window.current_key_id());
    assert_ne!(new_reference.key_id(), old_reference.key_id());
    assert_eq!(
        window.verify(domain, &components, new_reference.as_str()),
        Ok(ReferenceCheck::Current)
    );
    assert_eq!(
        window.verify(domain, &components, old_reference.as_str()),
        Ok(ReferenceCheck::Previous)
    );
    // Another identity never matches under either key.
    let other = ["https://issuer.example.test", "user-456"];
    assert_eq!(
        window.verify(domain, &other, new_reference.as_str()),
        Ok(ReferenceCheck::Mismatch)
    );
    assert_eq!(
        window.verify(domain, &other, old_reference.as_str()),
        Ok(ReferenceCheck::Mismatch)
    );
    // Nor does the same identity in another domain.
    assert_eq!(
        window.verify(
            ReferenceDomain::ActorIssuer,
            &["https://issuer.example.test"],
            new_reference.as_str()
        ),
        Ok(ReferenceCheck::Mismatch)
    );

    // After the window the old reference is still well formed, but it can no
    // longer be recomputed or matched.
    let after = keyring(authority_id, &new_material, None);
    assert_eq!(
        after.verify(domain, &components, old_reference.as_str()),
        Ok(ReferenceCheck::UnknownKey)
    );
    assert_eq!(
        after.verify(domain, &components, new_reference.as_str()),
        Ok(ReferenceCheck::Current)
    );
    assert_eq!(
        after.derive(domain, &components).as_ref(),
        Ok(&new_reference)
    );
}

#[test]
fn verification_rejects_malformed_and_tampered_references() {
    let keyring = keyring(Uuid::new_v4(), &generated_key_hex(), None);
    let components = ["billing-api"];
    let reference = keyring
        .derive(ReferenceDomain::Connection, &components)
        .expect("reference should derive");
    let valid = reference.as_str();

    for malformed in [
        String::new(),
        valid[..REFERENCE_HEX_CHARS - 1].to_owned(),
        format!("{valid}0"),
        valid.to_ascii_uppercase(),
        format!("{}g", &valid[..REFERENCE_HEX_CHARS - 1]),
        format!("{} ", &valid[..REFERENCE_HEX_CHARS - 1]),
    ] {
        assert_eq!(
            keyring.verify(ReferenceDomain::Connection, &components, &malformed),
            Err(PseudonymError::MalformedReference),
            "{malformed:?}"
        );
    }

    // One flipped tag character under the right key ID is a mismatch, not a
    // match and not an error.
    let last = valid.chars().last().expect("non-empty");
    let flipped = if last == '0' { '1' } else { '0' };
    let tampered = format!("{}{flipped}", &valid[..REFERENCE_HEX_CHARS - 1]);
    assert_eq!(
        keyring.verify(ReferenceDomain::Connection, &components, &tampered),
        Ok(ReferenceCheck::Mismatch)
    );
}

#[test]
fn keyring_refuses_one_key_twice_and_an_unversioned_authority() {
    let material = generated_key_hex();
    assert_eq!(
        PseudonymKeyring::new(Uuid::new_v4(), key(&material), Some(key(&material))).map(|_| ()),
        Err(PseudonymError::DuplicateKey)
    );
    // The same key spelled in upper case is still the same key.
    assert_eq!(
        PseudonymKeyring::new(
            Uuid::new_v4(),
            key(&material),
            Some(key(&material.to_ascii_uppercase()))
        )
        .map(|_| ()),
        Err(PseudonymError::DuplicateKey)
    );
    for authority_id in [Uuid::nil(), Uuid::from_u128(u128::MAX)] {
        assert_eq!(
            PseudonymKeyring::new(authority_id, key(&material), None).map(|_| ()),
            Err(PseudonymError::InvalidAuthority),
            "{authority_id}"
        );
    }
}

#[test]
fn key_material_is_64_hex_characters_resolved_under_the_dedicated_purpose() {
    let material = generated_key_hex();

    // Material resolved under any other purpose is refused even when it is a
    // well-formed key.
    for purpose in [
        SecretPurpose::StaticBearer,
        SecretPurpose::HeaderApiKey,
        SecretPurpose::OAuthClientSecret,
        SecretPurpose::AssertionSigningKey,
    ] {
        assert_eq!(
            PseudonymKey::from_resolved(&resolved(purpose, &material)).map(|_| ()),
            Err(KeyRejection::WrongPurpose),
            "{purpose:?}"
        );
    }

    for malformed in [
        material[..PSEUDONYM_KEY_BYTES * 2 - 1].to_owned(),
        material[..PSEUDONYM_KEY_BYTES * 2 - 2].to_owned(),
        format!("{}g", &material[..PSEUDONYM_KEY_BYTES * 2 - 1]),
        format!("{} ", &material[..PSEUDONYM_KEY_BYTES * 2 - 1]),
        format!("{}\n", &material[..PSEUDONYM_KEY_BYTES * 2 - 1]),
    ] {
        assert_eq!(
            PseudonymKey::from_resolved(&resolved(
                SecretPurpose::AuthorityPseudonymKey,
                &malformed
            ))
            .map(|_| ()),
            Err(KeyRejection::Malformed),
            "{malformed:?}"
        );
    }

    // A trailing newline on a full key never reaches the parser: the purpose's
    // byte bound is the exact key length.
    assert_eq!(
        ResolvedSecret::new(
            SecretPurpose::AuthorityPseudonymKey,
            format!("{material}\n").into_bytes()
        )
        .map(|_| ()),
        Err(SecretValueError::TooLarge {
            maximum: MAX_AUTHORITY_PSEUDONYM_KEY_BYTES
        })
    );

    // Placeholders are refused rather than trusted.
    for placeholder in ["00", "ff", "5a"] {
        assert_eq!(
            PseudonymKey::from_resolved(&resolved(
                SecretPurpose::AuthorityPseudonymKey,
                &placeholder.repeat(PSEUDONYM_KEY_BYTES)
            ))
            .map(|_| ()),
            Err(KeyRejection::Placeholder),
            "{placeholder}"
        );
    }

    // Case does not change the key.
    assert_eq!(
        key(&material).id(),
        key(&material.to_ascii_uppercase()).id()
    );
}

#[test]
fn components_must_fit_their_domain_and_stay_bounded() {
    let keyring = keyring(Uuid::new_v4(), &generated_key_hex(), None);
    let oversized = "x".repeat(MAX_REFERENCE_COMPONENT_BYTES + 1);
    let largest = "x".repeat(MAX_REFERENCE_COMPONENT_BYTES);

    for (domain, components) in [
        (ReferenceDomain::Connection, Vec::new()),
        (ReferenceDomain::Connection, vec!["a", "b", "c", "d", "e"]),
        (ReferenceDomain::Connection, vec![""]),
        (ReferenceDomain::Connection, vec!["owner", ""]),
        (ReferenceDomain::Connection, vec![oversized.as_str()]),
        // A subject without its issuer, or with anything extra, is refused.
        (ReferenceDomain::ActorSubject, vec!["user-123"]),
        (
            ReferenceDomain::ActorSubject,
            vec!["https://issuer.example.test", "user-123", "extra"],
        ),
        (ReferenceDomain::ActorIssuer, Vec::new()),
        (ReferenceDomain::ActorIssuer, vec!["issuer-a", "issuer-b"]),
        // A recorded actor is one identifier, never an issuer and a subject.
        (ReferenceDomain::ActorRecorded, Vec::new()),
        (
            ReferenceDomain::ActorRecorded,
            vec!["https://issuer.example.test", "user-123"],
        ),
    ] {
        assert_eq!(
            keyring.derive(domain, &components),
            Err(PseudonymError::InvalidComponents),
            "{domain:?} {}",
            components.len()
        );
        // Verification refuses the same input before looking at the reference.
        assert_eq!(
            keyring.verify(domain, &components, "not-a-reference"),
            Err(PseudonymError::InvalidComponents)
        );
    }

    keyring
        .derive(ReferenceDomain::Connection, &["a", "b", "c", "d"])
        .expect("the component limit is inclusive");
    keyring
        .derive(ReferenceDomain::Connection, &[largest.as_str()])
        .expect("the size limit is inclusive");
}

#[test]
fn key_material_never_reaches_debug_or_error_output() {
    let material = generated_key_hex();
    let previous = generated_key_hex();
    let keyring = keyring(Uuid::new_v4(), &material, Some(&previous));
    let raw = hex::decode(&material).expect("generated key is hex");

    let mut rendered = vec![
        format!("{:?}", key(&material)),
        format!("{keyring:?}"),
        format!("{keyring:#?}"),
    ];
    for error in [
        PseudonymError::SameAlias,
        PseudonymError::KeyUnavailable {
            role: KeyRole::Current,
            kind: SecretResolveErrorKind::SourceDenied,
        },
        PseudonymError::KeyRejected {
            role: KeyRole::Previous,
            reason: KeyRejection::Malformed,
        },
        PseudonymError::DuplicateKey,
        PseudonymError::InvalidAuthority,
        PseudonymError::InvalidComponents,
        PseudonymError::MalformedReference,
    ] {
        rendered.push(error.to_string());
        rendered.push(format!("{error:?}"));
    }
    for rejection in [
        KeyRejection::WrongPurpose,
        KeyRejection::Malformed,
        KeyRejection::Placeholder,
        KeyRejection::Unusable,
    ] {
        rendered.push(rejection.to_string());
    }

    let raw_debug = format!("{raw:?}");
    let raw_debug_inner = raw_debug.trim_start_matches('[').trim_end_matches(']');
    for output in &rendered {
        for secret in [&material, &previous] {
            assert!(!output.contains(secret.as_str()), "{output}");
            assert!(!output.contains(&secret.to_ascii_uppercase()), "{output}");
        }
        assert!(!output.contains(raw_debug_inner), "{output}");
    }
    assert!(rendered[0].contains("<redacted>"));
    assert!(rendered[1].contains(keyring.current_key_id()));
    assert!(rendered[1].contains(keyring.previous_key_id().expect("previous key")));
}

#[test]
fn resource_domains_are_the_proposed_event_schema_resource_kinds() {
    let schema_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("gateway has a parent directory")
        .join("docs/schemas/authority_event.v1.schema.json");
    let schema: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&schema_path).expect("the event schema should be readable"),
    )
    .expect("the event schema should be JSON");
    let schema_kinds: BTreeSet<String> = schema["properties"]["resource"]["properties"]["kind"]
        ["enum"]
        .as_array()
        .expect("resource.kind is a closed enum")
        .iter()
        .map(|kind| kind.as_str().expect("kinds are strings").to_owned())
        .collect();
    let domain_kinds: BTreeSet<String> = ReferenceDomain::ALL
        .iter()
        .filter_map(|domain| domain.label().strip_prefix("resource."))
        .map(str::to_owned)
        .collect();
    assert_eq!(domain_kinds, schema_kinds);
    // Every reference field the schema constrains has the shape derived here.
    for pattern in [
        &schema["properties"]["actor"]["properties"]["subject_ref"]["pattern"],
        &schema["properties"]["actor"]["properties"]["issuer_ref"]["pattern"],
        &schema["properties"]["resource"]["properties"]["ref"]["pattern"],
    ] {
        assert_eq!(pattern, &serde_json::json!("^[0-9a-f]{64}$"));
    }
}

/// Answers with fixed material per alias and records every request.
#[derive(Default)]
struct RecordingResolver {
    material: BTreeMap<String, (SecretPurpose, String)>,
    requests: Mutex<Vec<(String, SecretPurpose)>>,
}

impl RecordingResolver {
    fn with(mut self, alias: &str, purpose: SecretPurpose, material: &str) -> Self {
        self.material
            .insert(alias.to_owned(), (purpose, material.to_owned()));
        self
    }

    fn requests(&self) -> Vec<(String, SecretPurpose)> {
        self.requests.lock().expect("lock").clone()
    }
}

#[async_trait]
impl SecretResolver for RecordingResolver {
    async fn resolve(
        &self,
        alias_id: &str,
        purpose: SecretPurpose,
    ) -> Result<ResolvedSecret, SecretResolveError> {
        self.requests
            .lock()
            .expect("lock")
            .push((alias_id.to_owned(), purpose));
        let (stored_purpose, material) = self.material.get(alias_id).ok_or_else(|| {
            SecretResolveError::new(alias_id, SecretResolveErrorKind::UnknownAlias)
        })?;
        // Like the encrypted local store: material resolves only under the
        // purpose it was provisioned for.
        if *stored_purpose != purpose {
            return Err(SecretResolveError::new(
                alias_id,
                SecretResolveErrorKind::SourceDenied,
            ));
        }
        ResolvedSecret::new(purpose, material.as_bytes().to_vec())
            .map_err(|_| SecretResolveError::new(alias_id, SecretResolveErrorKind::InvalidMaterial))
    }

    fn aliases(&self) -> Vec<SecretAliasMetadata> {
        Vec::new()
    }
}

#[tokio::test]
async fn keyring_resolves_both_keys_under_the_dedicated_purpose() {
    let current = generated_key_hex();
    let previous = generated_key_hex();
    let resolver = RecordingResolver::default()
        .with(
            "pseudonym-current",
            SecretPurpose::AuthorityPseudonymKey,
            &current,
        )
        .with(
            "pseudonym-previous",
            SecretPurpose::AuthorityPseudonymKey,
            &previous,
        );
    let authority_id = Uuid::new_v4();

    let resolved = resolve_keyring(
        &resolver,
        authority_id,
        "pseudonym-current",
        Some("pseudonym-previous"),
    )
    .await
    .expect("both keys should resolve");
    assert_eq!(resolved.current_key_id(), key(&current).id());
    assert_eq!(resolved.previous_key_id(), Some(key(&previous).id()));
    assert_eq!(
        resolver.requests(),
        vec![
            (
                "pseudonym-current".to_owned(),
                SecretPurpose::AuthorityPseudonymKey
            ),
            (
                "pseudonym-previous".to_owned(),
                SecretPurpose::AuthorityPseudonymKey
            ),
        ]
    );
    // The resolved keyring derives exactly what one built by hand does.
    assert_eq!(
        resolved.derive(ReferenceDomain::ServiceToken, &["token-1"]),
        keyring(authority_id, &current, Some(&previous))
            .derive(ReferenceDomain::ServiceToken, &["token-1"])
    );
}

#[tokio::test]
async fn keyring_resolution_fails_closed() {
    let material = generated_key_hex();
    let authority_id = Uuid::new_v4();

    // One alias named twice is refused before anything is resolved.
    let resolver = RecordingResolver::default().with(
        "pseudonym",
        SecretPurpose::AuthorityPseudonymKey,
        &material,
    );
    assert_eq!(
        resolve_keyring(&resolver, authority_id, "pseudonym", Some("pseudonym"))
            .await
            .map(|_| ()),
        Err(PseudonymError::SameAlias)
    );
    assert!(resolver.requests().is_empty());

    // A missing previous key is fatal, not a single-key fallback.
    assert_eq!(
        resolve_keyring(&resolver, authority_id, "pseudonym", Some("missing"))
            .await
            .map(|_| ()),
        Err(PseudonymError::KeyUnavailable {
            role: KeyRole::Previous,
            kind: SecretResolveErrorKind::UnknownAlias,
        })
    );

    // Material provisioned for a Connection credential never becomes a
    // pseudonym key.
    let resolver =
        RecordingResolver::default().with("bearer", SecretPurpose::StaticBearer, &material);
    assert_eq!(
        resolve_keyring(&resolver, authority_id, "bearer", None)
            .await
            .map(|_| ()),
        Err(PseudonymError::KeyUnavailable {
            role: KeyRole::Current,
            kind: SecretResolveErrorKind::SourceDenied,
        })
    );

    // Malformed and placeholder material is rejected with the key's role.
    let resolver = RecordingResolver::default()
        .with("pseudonym", SecretPurpose::AuthorityPseudonymKey, &material)
        .with(
            "short",
            SecretPurpose::AuthorityPseudonymKey,
            &material[..PSEUDONYM_KEY_BYTES],
        )
        .with(
            "placeholder",
            SecretPurpose::AuthorityPseudonymKey,
            &"00".repeat(PSEUDONYM_KEY_BYTES),
        );
    assert_eq!(
        resolve_keyring(&resolver, authority_id, "short", None)
            .await
            .map(|_| ()),
        Err(PseudonymError::KeyRejected {
            role: KeyRole::Current,
            reason: KeyRejection::Malformed,
        })
    );
    assert_eq!(
        resolve_keyring(&resolver, authority_id, "pseudonym", Some("placeholder"))
            .await
            .map(|_| ()),
        Err(PseudonymError::KeyRejected {
            role: KeyRole::Previous,
            reason: KeyRejection::Placeholder,
        })
    );
    assert_eq!(
        resolve_keyring(&resolver, Uuid::nil(), "pseudonym", None)
            .await
            .map(|_| ()),
        Err(PseudonymError::InvalidAuthority)
    );
}
