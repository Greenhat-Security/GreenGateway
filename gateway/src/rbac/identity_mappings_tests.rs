use std::collections::HashMap;

use proptest::prelude::*;
use serde_json::json;

use super::*;
use crate::rbac::conditions::UNCAPTURED_FACTS;
use crate::{
    auth::{AuthMethod, Principal},
    rbac::PrincipalMatcher,
};

const ISSUER: &str = "https://idp.example.test";

fn principal(issuer: Option<&str>, roles: &[&str], auth_method: AuthMethod) -> Principal {
    Principal {
        user_id: "alice".to_owned(),
        issuer: issuer.map(str::to_owned),
        email: None,
        org_id: None,
        roles: roles.iter().map(|role| (*role).to_owned()).collect(),
        session_id: String::new(),
        auth_method,
    }
}

fn mapping(id: &str, grant_roles: &[&str]) -> IdentityMapping {
    IdentityMapping {
        id: id.to_owned(),
        issuer: ISSUER.to_owned(),
        auth_methods: Vec::new(),
        subjects: Vec::new(),
        organizations: Vec::new(),
        claimed_roles: Vec::new(),
        grant_roles: grant_roles.iter().map(|role| (*role).to_owned()).collect(),
    }
}

fn organization(organization: Option<&str>) -> PolicyFacts {
    let mut facts = PolicyFacts::uncaptured();
    facts.organization = Fact::Captured(organization.map(str::to_owned));
    facts
}

fn roles(names: &[&str]) -> HashMap<String, RoleEntry> {
    names
        .iter()
        .map(|name| {
            (
                (*name).to_owned(),
                RoleEntry {
                    permissions: vec![format!("{name}:use")],
                    issuers: Vec::new(),
                    auth_methods: Vec::new(),
                    description: None,
                },
            )
        })
        .collect()
}

#[test]
fn internal_roles_are_the_sorted_union_of_every_applying_grant() {
    let mut admins = mapping("admins", &["admin", "reader"]);
    admins.claimed_roles = vec!["Admins".to_owned()];
    let mut everyone = mapping("everyone", &["reader"]);
    everyone.auth_methods = vec!["bearer_token".to_owned()];
    let mut bob_only = mapping("bob", &["auditor"]);
    bob_only.subjects = vec!["bob".to_owned()];
    let compiled =
        CompiledIdentityMappings::new(&[admins.clone(), everyone.clone(), bob_only.clone()]);
    let reversed = CompiledIdentityMappings::new(&[bob_only, everyone, admins]);
    let alice = principal(Some(ISSUER), &["Admins"], AuthMethod::Bearer);
    for compiled in [&compiled, &reversed] {
        assert_eq!(
            compiled.effective_roles(&alice, &UNCAPTURED_FACTS),
            Some(vec!["admin".to_owned(), "reader".to_owned()])
        );
    }
    // A claimed role is never an internal role by itself, and an unmatched
    // principal holds none.
    let cookie = principal(Some(ISSUER), &["admin"], AuthMethod::Cookie);
    assert_eq!(
        compiled.effective_roles(&cookie, &UNCAPTURED_FACTS),
        Some(Vec::new())
    );
}

#[test]
fn every_mapping_is_bound_to_its_issuer() {
    let compiled = CompiledIdentityMappings::new(&[mapping("all", &["reader"])]);
    for principal in [
        principal(
            Some("https://evil.example.test"),
            &["reader"],
            AuthMethod::Bearer,
        ),
        principal(
            Some("https://idp.example.test.evil"),
            &["reader"],
            AuthMethod::Bearer,
        ),
        // A service token carries no issuer, so no mapping applies to one.
        principal(None, &["reader"], AuthMethod::ServiceToken),
    ] {
        assert_eq!(
            compiled.effective_roles(&principal, &organization(Some("acme"))),
            Some(Vec::new()),
            "{:?}",
            principal.issuer
        );
    }
}

#[test]
fn an_organization_constraint_reads_the_captured_fact_and_is_never_guessed() {
    let mut acme = mapping("acme", &["reader"]);
    acme.organizations = vec!["acme".to_owned()];
    let compiled = CompiledIdentityMappings::new(&[acme]);
    let alice = principal(Some(ISSUER), &[], AuthMethod::Bearer);
    assert_eq!(
        compiled.effective_roles(&alice, &organization(Some("acme"))),
        Some(vec!["reader".to_owned()])
    );
    assert_eq!(
        compiled.effective_roles(&alice, &organization(Some("other"))),
        Some(Vec::new())
    );
    assert_eq!(
        compiled.effective_roles(&alice, &organization(None)),
        Some(Vec::new())
    );
    // Uncaptured: the mapping can neither apply nor be ruled out.
    assert_eq!(compiled.effective_roles(&alice, &UNCAPTURED_FACTS), None);
    // Unless something the principal itself carries already rules it out.
    let other_issuer = principal(Some("https://other.example.test"), &[], AuthMethod::Bearer);
    assert_eq!(
        compiled.effective_roles(&other_issuer, &UNCAPTURED_FACTS),
        Some(Vec::new())
    );
}

#[test]
fn validation_locates_every_problem_in_a_mapping() {
    let defined = roles(&["reader"]);
    let mut empty_issuer = mapping("m", &["reader"]);
    empty_issuer.issuer = String::new();
    let mut long_issuer = mapping("m", &["reader"]);
    long_issuer.issuer = "i".repeat(MAX_PRINCIPAL_ISSUER_BYTES + 1);
    let mut bad_method = mapping("m", &["reader"]);
    bad_method.auth_methods = vec!["bearer_token".to_owned(), "password".to_owned()];
    let mut empty_subject = mapping("m", &["reader"]);
    empty_subject.subjects = vec![String::new()];
    let mut control_role = mapping("m", &["reader"]);
    control_role.claimed_roles = vec!["ok".to_owned(), "bad\nrole".to_owned()];
    let mut long_organization = mapping("m", &["reader"]);
    long_organization.organizations = vec!["o".repeat(MAX_ORGANIZATION_BYTES + 1)];
    let mut many_subjects = mapping("m", &["reader"]);
    many_subjects.subjects = (0..=MAX_IDENTITY_MAPPING_VALUES)
        .map(|n| n.to_string())
        .collect();
    let grants_nothing = mapping("m", &[]);
    let unknown_role = mapping("m", &["reader", "admin"]);
    for (mapping, code, pointer) in [
        (empty_issuer, "issuer_empty", "/identity_mappings/0/issuer"),
        (
            long_issuer,
            "identity_mapping_value_invalid",
            "/identity_mappings/0/issuer",
        ),
        (
            bad_method,
            "auth_method_unknown",
            "/identity_mappings/0/auth_methods/1",
        ),
        (
            empty_subject,
            "identity_mapping_value_invalid",
            "/identity_mappings/0/subjects/0",
        ),
        (
            control_role,
            "identity_mapping_value_invalid",
            "/identity_mappings/0/claimed_roles/1",
        ),
        (
            long_organization,
            "identity_mapping_value_invalid",
            "/identity_mappings/0/organizations/0",
        ),
        (
            many_subjects,
            "identity_mapping_value_invalid",
            "/identity_mappings/0/subjects",
        ),
        (
            grants_nothing,
            "identity_mapping_grant_empty",
            "/identity_mappings/0/grant_roles",
        ),
        (
            unknown_role,
            "identity_mapping_role_unknown",
            "/identity_mappings/0/grant_roles/1",
        ),
    ] {
        let issue = validate_identity_mappings(&[mapping], &defined)
            .expect_err("the mapping should be refused");
        assert_eq!(
            (issue.code.as_str(), issue.pointer.as_str()),
            (code, pointer)
        );
    }
    let too_many: Vec<IdentityMapping> = (0..=MAX_IDENTITY_MAPPINGS)
        .map(|n| mapping(&format!("m{n}"), &["reader"]))
        .collect();
    let issue = validate_identity_mappings(&too_many, &defined).expect_err("too many");
    assert_eq!(issue.code, IssueCode::IdentityMappingsTooMany);
    assert!(validate_identity_mappings(&[mapping("m", &["reader"])], &defined).is_ok());
}

#[test]
fn a_mapping_round_trips_with_its_empty_lists_omitted() {
    let document = json!({
        "id": "admins",
        "issuer": ISSUER,
        "claimed_roles": ["Admins"],
        "grant_roles": ["admin"]
    });
    let parsed: IdentityMapping = serde_json::from_value(document.clone()).expect("parse");
    assert_eq!(serde_json::to_value(&parsed).expect("serialize"), document);
    let mut canonical = vec![IdentityMapping {
        issuer: " https://idp.example.test/ ".to_owned(),
        ..parsed
    }];
    canonicalize_identity_mapping_issuers(&mut canonical);
    assert_eq!(canonical[0].issuer, ISSUER);
}

fn auth_method_strategy() -> impl Strategy<Value = AuthMethod> {
    prop_oneof![
        Just(AuthMethod::Bearer),
        Just(AuthMethod::Cookie),
        Just(AuthMethod::ServiceToken),
        Just(AuthMethod::ClientCertificate),
    ]
}

fn small_set(values: &'static [&'static str]) -> impl Strategy<Value = Vec<String>> {
    proptest::sample::subsequence(values, 0..=values.len())
        .prop_map(|values| values.into_iter().map(str::to_owned).collect())
}

proptest! {
    /// Apart from its organization constraint, which reads a fact the
    /// principal does not carry, a mapping applies exactly when the existing
    /// principal matcher accepts the same constraints with its issuer as the
    /// only issuer: the same issuer, auth-method, subject and any-of-roles
    /// semantics, decided by the same principal fields.
    #[test]
    fn a_mapping_applies_exactly_when_the_principal_matcher_accepts_its_constraints(
        issuer in prop_oneof![
            Just(Some(ISSUER)),
            Just(Some("https://other.example.test")),
            Just(None),
        ],
        auth_method in auth_method_strategy(),
        user_id in prop_oneof![Just("alice"), Just("bob")],
        held in small_set(&["Admins", "Readers", "Ops"]),
        auth_methods in small_set(&["bearer_token", "session_cookie", "service_token", "client_certificate"]),
        subjects in small_set(&["alice", "carol"]),
        claimed_roles in small_set(&["Admins", "Ops", "Guests"]),
    ) {
        let mut principal = principal(issuer, &[], auth_method);
        principal.user_id = user_id.to_owned();
        principal.roles = held;
        let mapping = IdentityMapping {
            id: "m".to_owned(),
            issuer: ISSUER.to_owned(),
            auth_methods: auth_methods.clone(),
            subjects: subjects.clone(),
            organizations: Vec::new(),
            claimed_roles: claimed_roles.clone(),
            grant_roles: vec!["internal".to_owned()],
        };
        let matcher = PrincipalMatcher {
            roles: claimed_roles,
            issuers: vec![ISSUER.to_owned()],
            auth_methods,
            principal_ids: subjects,
        };
        let applies = mapping_applies(&mapping, &principal, &UNCAPTURED_FACTS);
        prop_assert_eq!(applies, Truth::of(matcher.matches(Some(&principal))));
        let compiled = CompiledIdentityMappings::new(&[mapping]);
        let expected = if matcher.matches(Some(&principal)) {
            vec!["internal".to_owned()]
        } else {
            Vec::new()
        };
        prop_assert_eq!(compiled.effective_roles(&principal, &UNCAPTURED_FACTS), Some(expected));
    }
}
