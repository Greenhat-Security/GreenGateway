use super::*;
use serde_json::json;

#[test]
fn rule_deserialization_defaults_enabled_to_true() {
    let rule: Rule = serde_json::from_value(json!({
        "path": "/legacy",
        "action": "deny"
    }))
    .expect("legacy rule without enabled should deserialize");

    assert!(rule.enabled);
}

#[test]
fn empty_principal_matcher_matches_any_principal_or_none() {
    let matcher = PrincipalMatcher::default();

    assert!(matcher.matches(None));
    assert!(matcher.matches(Some(&test_principal(
        "user-123",
        &["reader"],
        AuthMethod::Bearer
    ))));
}

#[test]
fn principal_matcher_ands_non_empty_constraints() {
    let matcher = PrincipalMatcher {
        roles: vec!["admin".to_owned(), "support".to_owned()],
        issuers: Vec::new(),
        auth_methods: vec![AUTH_METHOD_BEARER_TOKEN.to_owned()],
        principal_ids: vec!["user-123".to_owned()],
    };

    assert!(matcher.matches(Some(&test_principal(
        "user-123",
        &["support"],
        AuthMethod::Bearer
    ))));
    assert!(!matcher.matches(Some(&test_principal(
        "user-123",
        &["support"],
        AuthMethod::Cookie
    ))));
    assert!(!matcher.matches(Some(&test_principal(
        "user-999",
        &["support"],
        AuthMethod::Bearer
    ))));
    assert!(!matcher.matches(Some(&test_principal(
        "user-123",
        &["reader"],
        AuthMethod::Bearer
    ))));
    assert!(!matcher.matches(None));
}

#[test]
fn principal_matcher_can_match_service_token_auth_method() {
    let matcher = PrincipalMatcher {
        roles: Vec::new(),
        issuers: Vec::new(),
        auth_methods: vec![AUTH_METHOD_SERVICE_TOKEN.to_owned()],
        principal_ids: Vec::new(),
    };

    assert!(matcher.matches(Some(&test_principal(
        "service-token:token_123",
        &["admin:tokens:read"],
        AuthMethod::ServiceToken
    ))));
    assert!(!matcher.matches(Some(&test_principal(
        "user-123",
        &["admin:tokens:read"],
        AuthMethod::Bearer
    ))));
}

/// Both halves of the claim on `AuthMethod::ClientCertificate`: a policy
/// that means to name certificates can, and a policy that names
/// `bearer_token` does not start matching them.
///
/// The second half is the reason the variant is separate rather than a
/// reuse of `Bearer`, and it had no test: every existing rule naming
/// `bearer_token` would have widened silently to include certificate
/// callers.
#[test]
fn principal_matcher_can_match_client_certificate_auth_method() {
    let certificate_matcher = PrincipalMatcher {
        roles: Vec::new(),
        issuers: Vec::new(),
        auth_methods: vec![AUTH_METHOD_CLIENT_CERTIFICATE.to_owned()],
        principal_ids: Vec::new(),
    };
    let certificate_principal = test_principal(
        "spiffe://gateway.test/ns/payments/sa/api",
        &[],
        AuthMethod::ClientCertificate,
    );

    assert!(certificate_matcher.matches(Some(&certificate_principal)));
    assert!(!certificate_matcher.matches(Some(&test_principal(
        "user-123",
        &[],
        AuthMethod::Bearer
    ))));

    // The direction that matters for every policy already deployed.
    let bearer_matcher = PrincipalMatcher {
        roles: Vec::new(),
        issuers: Vec::new(),
        auth_methods: vec![AUTH_METHOD_BEARER_TOKEN.to_owned()],
        principal_ids: Vec::new(),
    };
    assert!(
        !bearer_matcher.matches(Some(&certificate_principal)),
        "a rule naming bearer_token must not widen to certificate principals"
    );
}

#[test]
fn principal_matcher_separates_colliding_subjects_and_roles_by_issuer() {
    let matcher = PrincipalMatcher {
        roles: vec!["operator".to_owned()],
        issuers: vec!["https://idp-a.example/".to_owned()],
        auth_methods: vec![AUTH_METHOD_BEARER_TOKEN.to_owned()],
        principal_ids: vec!["shared-subject".to_owned()],
    };
    let mut provider_a = test_principal("shared-subject", &["operator"], AuthMethod::Bearer);
    provider_a.issuer = Some("https://idp-a.example/".to_owned());
    let mut provider_b = provider_a.clone();
    provider_b.issuer = Some("https://idp-b.example/".to_owned());

    assert!(matcher.matches(Some(&provider_a)));
    assert!(!matcher.matches(Some(&provider_b)));
}

#[test]
fn rule_matcher_supports_method_wildcards() {
    let rule = Rule {
        id: None,
        enabled: true,
        methods: vec!["GET".to_owned(), "HEAD".to_owned()],
        path: "/data".to_owned(),
        tool_name: None,
        dispatch: None,
        principal: PrincipalMatcher::default(),
        action: RuleAction::Allow,
    };

    assert!(rule.matches("get", "/data", None));
    assert!(rule.matches("HEAD", "/data", None));
    assert!(!rule.matches("POST", "/data", None));

    let wildcard_rule = Rule {
        id: None,
        enabled: true,
        methods: vec!["*".to_owned()],
        path: "/data".to_owned(),
        tool_name: None,
        dispatch: None,
        principal: PrincipalMatcher::default(),
        action: RuleAction::Allow,
    };

    assert!(wildcard_rule.matches("DELETE", "/data", None));
}

#[test]
fn rule_matcher_supports_literals_globs_and_params() {
    let user_item = Rule {
        id: None,
        enabled: true,
        methods: Vec::new(),
        path: "/api/users/{id}".to_owned(),
        tool_name: None,
        dispatch: None,
        principal: PrincipalMatcher::default(),
        action: RuleAction::Allow,
    };
    let one_asset_segment = Rule {
        id: None,
        enabled: true,
        methods: Vec::new(),
        path: "/assets/*".to_owned(),
        tool_name: None,
        dispatch: None,
        principal: PrincipalMatcher::default(),
        action: RuleAction::Allow,
    };
    let any_admin_depth = Rule {
        id: None,
        enabled: true,
        methods: Vec::new(),
        path: "/admin/**".to_owned(),
        tool_name: None,
        dispatch: None,
        principal: PrincipalMatcher::default(),
        action: RuleAction::Allow,
    };

    assert!(user_item.matches("GET", "/api/users/123", None));
    assert!(!user_item.matches("GET", "/api/users/123/posts", None));
    assert!(one_asset_segment.matches("GET", "/assets/app.js", None));
    assert!(!one_asset_segment.matches("GET", "/assets/css/app.css", None));
    assert!(any_admin_depth.matches("GET", "/admin", None));
    assert!(any_admin_depth.matches("GET", "/admin/settings/audit", None));
}

#[test]
fn rule_matcher_is_anchored_to_whole_path() {
    let rule = Rule {
        id: None,
        enabled: true,
        methods: Vec::new(),
        path: "/api/users/{id}".to_owned(),
        tool_name: None,
        dispatch: None,
        principal: PrincipalMatcher::default(),
        action: RuleAction::Allow,
    };

    assert!(!rule.matches("GET", "/prefix/api/users/123", None));
    assert!(!rule.matches("GET", "/api/users/123/suffix", None));
}

fn test_principal(user_id: &str, roles: &[&str], auth_method: AuthMethod) -> Principal {
    Principal {
        user_id: user_id.to_owned(),
        issuer: None,
        email: Some("user@example.test".to_owned()),
        org_id: None,
        roles: roles.iter().map(|role| (*role).to_owned()).collect(),
        session_id: "session-123".to_owned(),
        auth_method,
    }
}
