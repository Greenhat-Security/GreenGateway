/// Authentication mechanism used to present a validated session credential.
#[allow(dead_code)] // Auth middleware will construct this when session validation lands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthMethod {
    Cookie,
    Bearer,
    ServiceToken,
}

impl AuthMethod {
    fn audit_mode(&self) -> &'static str {
        match self {
            Self::Cookie => "session_cookie",
            Self::Bearer => "bearer_token",
            Self::ServiceToken => "service_token",
        }
    }
}

/// Authenticated caller identity used for authorization and audit attribution.
#[derive(Debug, Clone)]
pub struct Principal {
    /// Canonical user identifier for authorization and ownership checks.
    pub user_id: String,
    /// User email address, normalized to lowercase when present.
    #[allow(dead_code)] // RBAC and upstream policy rules will consume this identity field.
    pub email: Option<String>,
    /// Optional organization/tenant claim; per ADR-0002, org and role claims are rule-matching inputs, not isolation boundaries.
    #[allow(dead_code)] // RBAC and upstream policy rules will consume this identity field.
    pub org_id: Option<String>,
    /// Role claims used by policy rules.
    pub roles: Vec<String>,
    /// Opaque session or credential identifier supplied by the validator.
    #[allow(dead_code)]
    // Request policy and audit enrichment will consume this identifier later.
    pub session_id: String,
    /// Authentication mechanism used for this principal.
    pub auth_method: AuthMethod,
}

/// Converts a validated principal into an audit actor.
///
/// Audit `auth_mode` values are neutral labels: `session_cookie` for cookie
/// credentials and `bearer_token` for bearer credentials.
pub fn actor_from_principal(principal: &Principal) -> crate::audit::Actor {
    crate::audit::Actor {
        user_id: principal.user_id.clone(),
        roles: if principal.roles.is_empty() {
            None
        } else {
            Some(principal.roles.clone())
        },
        auth_mode: principal.auth_method.audit_mode().to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actor_from_principal_maps_roles_and_cookie_auth_mode() {
        let principal = test_principal(AuthMethod::Cookie, vec!["admin", "member"]);

        let actor = actor_from_principal(&principal);

        assert_eq!(actor.user_id, "user-123");
        assert_eq!(
            actor.roles,
            Some(vec!["admin".to_owned(), "member".to_owned()])
        );
        assert_eq!(actor.auth_mode, "session_cookie");
    }

    #[test]
    fn actor_from_principal_omits_empty_roles_and_maps_bearer_auth_mode() {
        let principal = test_principal(AuthMethod::Bearer, Vec::new());

        let actor = actor_from_principal(&principal);

        assert_eq!(actor.user_id, "user-123");
        assert_eq!(actor.roles, None);
        assert_eq!(actor.auth_mode, "bearer_token");
    }

    #[test]
    fn actor_from_principal_maps_service_token_auth_mode() {
        let principal = test_principal(AuthMethod::ServiceToken, vec!["admin:tokens:read"]);

        let actor = actor_from_principal(&principal);

        assert_eq!(actor.auth_mode, "service_token");
        assert_eq!(actor.roles, Some(vec!["admin:tokens:read".to_owned()]));
    }

    fn test_principal(auth_method: AuthMethod, roles: Vec<&str>) -> Principal {
        Principal {
            user_id: "user-123".to_owned(),
            email: Some("user@example.com".to_owned()),
            org_id: Some("org-456".to_owned()),
            roles: roles.into_iter().map(str::to_owned).collect(),
            session_id: "session-789".to_owned(),
            auth_method,
        }
    }
}
