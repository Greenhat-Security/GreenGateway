use std::collections::HashMap;

use crate::auth::{AuthMethod, Principal};

use super::*;
use crate::rbac::policy::{DefaultAction, EgressPolicy, EnforcementMode, RoleEntry};

#[test]
fn admin_wildcard_grants_any_permission() {
    let engine = PolicyEngine::new(test_policy(&[("admin", &["*"])]));
    let principal = test_principal(&["admin"]);

    assert!(engine.principal_has_permission(&principal, "data:read"));
    assert!(engine.principal_has_permission(&principal, "settings:write"));
    assert!(engine.principal_has_wildcard(&principal));
}

#[test]
fn exact_permission_grants_only_matching_permission() {
    let engine = PolicyEngine::new(test_policy(&[("reader", &["data:read"])]));
    let principal = test_principal(&["reader"]);

    assert!(engine.principal_has_permission(&principal, "data:read"));
    assert!(!engine.principal_has_permission(&principal, "data:write"));
}

#[test]
fn unknown_role_grants_nothing() {
    let engine = PolicyEngine::new(test_policy(&[("reader", &["data:read"])]));
    let principal = test_principal(&["operator"]);

    assert!(!engine.principal_has_permission(&principal, "data:read"));
}

#[test]
fn principal_with_no_roles_grants_nothing() {
    let engine = PolicyEngine::new(test_policy(&[("reader", &["data:read"])]));
    let principal = test_principal(&[]);

    assert!(!engine.principal_has_permission(&principal, "data:read"));
}

#[test]
fn multiple_roles_union_their_permissions() {
    let engine = PolicyEngine::new(test_policy(&[
        ("reader", &["data:read"]),
        ("writer", &["data:write"]),
    ]));
    let principal = test_principal(&["reader", "writer"]);

    assert!(engine.principal_has_permission(&principal, "data:read"));
    assert!(engine.principal_has_permission(&principal, "data:write"));
    assert!(!engine.principal_has_permission(&principal, "settings:write"));
}

#[test]
fn role_permissions_are_bound_to_the_configured_issuer() {
    let mut policy = test_policy(&[("operator", &["data:write"])]);
    policy
        .roles
        .get_mut("operator")
        .expect("operator role should exist")
        .issuers = vec!["https://idp-a.example/".to_owned()];
    let engine = PolicyEngine::new(policy);
    let mut provider_a = test_principal(&["operator"]);
    provider_a.issuer = Some("https://idp-a.example/".to_owned());
    let mut provider_b = provider_a.clone();
    provider_b.issuer = Some("https://idp-b.example/".to_owned());

    assert!(engine.principal_has_permission(&provider_a, "data:write"));
    assert!(!engine.principal_has_permission(&provider_b, "data:write"));
}

#[test]
fn wildcard_detection_respects_the_configured_issuer() {
    let mut policy = test_policy(&[("admin", &["*"])]);
    policy
        .roles
        .get_mut("admin")
        .expect("admin role should exist")
        .issuers = vec!["https://idp-a.example/".to_owned()];
    let engine = PolicyEngine::new(policy);
    let mut provider_a = test_principal(&["admin"]);
    provider_a.issuer = Some("https://idp-a.example/".to_owned());
    let mut provider_b = provider_a.clone();
    provider_b.issuer = Some("https://idp-b.example/".to_owned());

    assert!(engine.principal_has_wildcard(&provider_a));
    assert!(!engine.principal_has_wildcard(&provider_b));
}

#[test]
fn active_role_detection_respects_the_configured_auth_method() {
    let mut policy = test_policy(&[("service-admin", &["*"])]);
    policy
        .roles
        .get_mut("service-admin")
        .expect("service-admin role should exist")
        .auth_methods = vec!["service_token".to_owned()];
    let engine = PolicyEngine::new(policy);
    let bearer = test_principal(&["service-admin"]);
    let mut service_token = bearer.clone();
    service_token.auth_method = AuthMethod::ServiceToken;

    assert!(!engine.principal_has_active_role(&bearer, "service-admin"));
    assert!(!engine.principal_has_wildcard(&bearer));
    assert!(engine.principal_has_active_role(&service_token, "service-admin"));
    assert!(engine.principal_has_wildcard(&service_token));
    assert!(!engine.principal_has_active_role(&service_token, "unknown-role"));
}

fn test_policy(entries: &[(&str, &[&str])]) -> Policy {
    let roles = entries
        .iter()
        .map(|(role, permissions)| {
            (
                (*role).to_owned(),
                RoleEntry {
                    permissions: permissions
                        .iter()
                        .map(|permission| (*permission).to_owned())
                        .collect(),
                    issuers: Vec::new(),
                    auth_methods: Vec::new(),
                },
            )
        })
        .collect::<HashMap<_, _>>();

    Policy {
        schema_version: "0.1.0".to_owned(),
        id: Some("test-policy".to_owned()),
        default_action: DefaultAction::Deny,
        enforcement_mode: EnforcementMode::Enforce,
        roles,
        routes: Vec::new(),
        rules: Vec::new(),
        egress: EgressPolicy::default(),
        rate_limits: Vec::new(),
        tools: HashMap::new(),
    }
}

fn test_principal(roles: &[&str]) -> Principal {
    Principal {
        user_id: "user-123".to_owned(),
        issuer: None,
        email: Some("user@example.test".to_owned()),
        org_id: None,
        roles: roles.iter().map(|role| (*role).to_owned()).collect(),
        session_id: "session-123".to_owned(),
        auth_method: AuthMethod::Bearer,
    }
}
