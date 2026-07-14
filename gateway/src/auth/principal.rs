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

pub(crate) const PROVIDER_ISSUER_PREFIX: &str = "provider:";

/// Canonical issuer form used by authentication, policy, audit, and discovery.
pub(crate) fn canonical_issuer(issuer: &str) -> Option<String> {
    let issuer = issuer.trim().trim_end_matches('/');
    if issuer.is_empty() {
        return None;
    }

    Some(issuer.to_owned())
}

/// Stable identity-boundary label for configured providers without an issuer.
pub(crate) fn provider_issuer(provider_name: &str) -> String {
    let mut encoded = String::with_capacity(provider_name.len());
    for byte in provider_name.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            write!(&mut encoded, "%{byte:02X}").expect("writing to a string cannot fail");
        }
    }

    format!("{PROVIDER_ISSUER_PREFIX}{encoded}")
}

/// Authenticated caller identity used for authorization and audit attribution.
#[derive(Debug, Clone)]
pub struct Principal {
    /// Canonical user identifier for authorization and ownership checks.
    pub user_id: String,
    /// Optional identity-provider issuer used to disambiguate equal subjects across providers.
    pub issuer: Option<String>,
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
        issuer: principal.issuer.as_deref().and_then(canonical_issuer),
        email: principal.email.clone(),
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
        let mut principal = test_principal(AuthMethod::Cookie, vec!["admin", "member"]);
        principal.issuer = Some("https://idp.example/".to_owned());

        let actor = actor_from_principal(&principal);

        assert_eq!(actor.user_id, "user-123");
        assert_eq!(actor.issuer, Some("https://idp.example".to_owned()));
        assert_eq!(actor.email, Some("user@example.com".to_owned()));
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
        assert_eq!(actor.email, Some("user@example.com".to_owned()));
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

    #[test]
    fn actor_from_principal_omits_absent_email() {
        let mut principal = test_principal(AuthMethod::Bearer, vec!["admin"]);
        principal.email = None;

        let actor = actor_from_principal(&principal);

        assert_eq!(actor.email, None);
    }

    #[test]
    fn canonical_issuer_trims_whitespace_and_trailing_slashes() {
        assert_eq!(
            canonical_issuer(" https://idp.example/// "),
            Some("https://idp.example".to_owned())
        );
        assert_eq!(canonical_issuer("///"), None);
    }

    #[test]
    fn provider_issuer_encodes_reserved_provider_name_bytes() {
        assert_eq!(provider_issuer("workforce"), "provider:workforce");
        assert_eq!(provider_issuer("team/red"), "provider:team%2Fred");
        assert_ne!(provider_issuer("team/red"), provider_issuer("team%2Fred"));
    }

    fn test_principal(auth_method: AuthMethod, roles: Vec<&str>) -> Principal {
        Principal {
            user_id: "user-123".to_owned(),
            issuer: None,
            email: Some("user@example.com".to_owned()),
            org_id: Some("org-456".to_owned()),
            roles: roles.into_iter().map(str::to_owned).collect(),
            session_id: "session-789".to_owned(),
            auth_method,
        }
    }
}
