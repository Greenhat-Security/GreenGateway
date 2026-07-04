use serde::{Deserialize, Serialize};

use crate::auth::{AuthMethod, Principal};

pub const AUTH_METHOD_BEARER_TOKEN: &str = "bearer_token";
pub const AUTH_METHOD_SESSION_COOKIE: &str = "session_cookie";

/// Action applied by a first-match-wins firewall rule.
///
/// Direct rules run before, and take precedence over, the routes/permission
/// model: once a rule matches, it is the sole authority for the request and
/// routes are never consulted. `Allow` and `Shadow` both forward the request
/// unconditionally (no downstream permission check) — `Shadow` differs only
/// in recording a would-deny observation event instead of an allowed one, for
/// policy-authoring dry runs. An overly broad rule (e.g. an unconstrained
/// principal matcher on a sensitive path) can therefore grant access the
/// routes-based permission model would have denied.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    Allow,
    Deny,
    Shadow,
}

/// Principal constraints for a firewall rule.
///
/// Non-empty fields are ANDed together: a principal must satisfy the role
/// constraint, the authentication-method constraint, and the principal-id
/// constraint when each is configured. Within one field, any listed value
/// matches. Empty fields are unconstrained, and a completely empty matcher
/// matches any caller, including unauthenticated requests.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalMatcher {
    /// Role names this rule matches. Empty means any role set.
    #[serde(default)]
    pub roles: Vec<String>,
    /// Authentication methods this rule matches: "bearer_token" or
    /// "session_cookie". Empty means any authentication method.
    #[serde(default)]
    pub auth_methods: Vec<String>,
    /// Exact principal user_id values this rule matches. Empty means any
    /// principal id.
    #[serde(default)]
    pub principal_ids: Vec<String>,
}

impl PrincipalMatcher {
    #[allow(dead_code)]
    pub fn is_unconstrained(&self) -> bool {
        self.roles.is_empty() && self.auth_methods.is_empty() && self.principal_ids.is_empty()
    }

    /// Returns true when the optional principal satisfies every configured
    /// constraint. A completely empty matcher returns true for authenticated
    /// and unauthenticated callers.
    #[allow(dead_code)]
    pub fn matches(&self, principal: Option<&Principal>) -> bool {
        if self.is_unconstrained() {
            return true;
        }

        let Some(principal) = principal else {
            return false;
        };

        constraint_matches(&self.roles, |role| {
            principal
                .roles
                .iter()
                .any(|principal_role| principal_role == role)
        }) && constraint_matches(&self.auth_methods, |auth_method| {
            auth_method == auth_method_policy_value(&principal.auth_method)
        }) && constraint_matches(&self.principal_ids, |principal_id| {
            principal.user_id == principal_id
        })
    }
}

/// Direct firewall rule model.
///
/// Rules are stored in policy order and are intended to be evaluated with
/// first-match-wins semantics.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// Optional stable identifier for audit/observation attribution and future
    /// rule-management APIs. When omitted, live evaluation falls back to the
    /// rule's array index.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// HTTP methods this rule matches. Empty or ["*"] matches any method.
    #[serde(default)]
    pub methods: Vec<String>,
    /// Absolute path pattern matched against the whole request path.
    ///
    /// Syntax is segment-based and anchored, never substring-based. Literal
    /// segments match exactly and case-sensitively. `*` matches exactly one
    /// non-empty path segment. `**` matches zero or more complete path
    /// segments. `{name}` matches exactly one non-empty path segment and names
    /// the capture for future rule-preview/discovery UI; capture names use
    /// ASCII letters, digits, and `_`, and must start with a letter or `_`.
    pub path: String,
    /// Optional principal constraints. Empty or omitted means any principal,
    /// authenticated or not.
    #[serde(default)]
    pub principal: PrincipalMatcher,
    pub action: RuleAction,
}

impl Rule {
    /// Returns true when this rule matches the request tuple.
    ///
    /// Policy-level evaluation should use `RuleMatcher` so path patterns are
    /// parsed once per loaded policy instead of once per request.
    #[allow(dead_code)]
    pub fn matches(&self, method: &str, path: &str, principal: Option<&Principal>) -> bool {
        super::matcher::rule_matches(self, method, path, principal)
    }
}

pub fn valid_auth_method_name(value: &str) -> bool {
    matches!(value, AUTH_METHOD_BEARER_TOKEN | AUTH_METHOD_SESSION_COOKIE)
}

fn auth_method_policy_value(auth_method: &AuthMethod) -> &'static str {
    match auth_method {
        AuthMethod::Bearer => AUTH_METHOD_BEARER_TOKEN,
        AuthMethod::Cookie => AUTH_METHOD_SESSION_COOKIE,
    }
}

fn constraint_matches(values: &[String], matches_value: impl Fn(&str) -> bool) -> bool {
    values.is_empty() || values.iter().any(|value| matches_value(value))
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn rule_matcher_supports_method_wildcards() {
        let rule = Rule {
            id: None,
            methods: vec!["GET".to_owned(), "HEAD".to_owned()],
            path: "/data".to_owned(),
            principal: PrincipalMatcher::default(),
            action: RuleAction::Allow,
        };

        assert!(rule.matches("get", "/data", None));
        assert!(rule.matches("HEAD", "/data", None));
        assert!(!rule.matches("POST", "/data", None));

        let wildcard_rule = Rule {
            id: None,
            methods: vec!["*".to_owned()],
            path: "/data".to_owned(),
            principal: PrincipalMatcher::default(),
            action: RuleAction::Allow,
        };

        assert!(wildcard_rule.matches("DELETE", "/data", None));
    }

    #[test]
    fn rule_matcher_supports_literals_globs_and_params() {
        let user_item = Rule {
            id: None,
            methods: Vec::new(),
            path: "/api/users/{id}".to_owned(),
            principal: PrincipalMatcher::default(),
            action: RuleAction::Allow,
        };
        let one_asset_segment = Rule {
            id: None,
            methods: Vec::new(),
            path: "/assets/*".to_owned(),
            principal: PrincipalMatcher::default(),
            action: RuleAction::Allow,
        };
        let any_admin_depth = Rule {
            id: None,
            methods: Vec::new(),
            path: "/admin/**".to_owned(),
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
            methods: Vec::new(),
            path: "/api/users/{id}".to_owned(),
            principal: PrincipalMatcher::default(),
            action: RuleAction::Allow,
        };

        assert!(!rule.matches("GET", "/prefix/api/users/123", None));
        assert!(!rule.matches("GET", "/api/users/123/suffix", None));
    }

    fn test_principal(user_id: &str, roles: &[&str], auth_method: AuthMethod) -> Principal {
        Principal {
            user_id: user_id.to_owned(),
            email: Some("user@example.test".to_owned()),
            org_id: None,
            roles: roles.iter().map(|role| (*role).to_owned()).collect(),
            session_id: "session-123".to_owned(),
            auth_method,
        }
    }
}
