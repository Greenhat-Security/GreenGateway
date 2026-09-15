/// Authentication mechanism used to present a validated session credential.
#[allow(dead_code)] // Auth middleware will construct this when session validation lands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthMethod {
    Cookie,
    Bearer,
    ServiceToken,
    /// A client certificate verified during the inbound TLS handshake.
    ///
    /// A separate variant rather than a reuse of an existing one because RBAC
    /// rules match on it: a policy that says `auth_methods: ["bearer_token"]`
    /// must not start matching certificate principals, and one that means to
    /// name certificates must be able to.
    ClientCertificate,
}

impl AuthMethod {
    fn audit_mode(&self) -> &'static str {
        match self {
            Self::Cookie => "session_cookie",
            Self::Bearer => "bearer_token",
            Self::ServiceToken => "service_token",
            Self::ClientCertificate => "client_certificate",
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

/// Most role names a principal may carry.
pub(crate) const MAX_PRINCIPAL_ROLES: usize = 256;
/// Longest role name, in bytes.
pub(crate) const MAX_PRINCIPAL_ROLE_BYTES: usize = 256;
/// Longest subject (`user_id`), in bytes.
pub(crate) const MAX_PRINCIPAL_SUBJECT_BYTES: usize = 4096;
/// Longest issuer, in bytes.
pub(crate) const MAX_PRINCIPAL_ISSUER_BYTES: usize = 4096;

/// Why a principal's identity facts are outside the shape every consumer of a
/// [`Principal`] is entitled to assume.
///
/// Authentication refuses a credential that would produce one of these, so a
/// principal that reaches authorization, audit or the policy kernel never
/// carries them. The size bounds exist so policy evaluation has a work limit no
/// token can defeat; the emptiness rules exist because an empty subject or role
/// name can never match a rule, so it is only ever noise or an attempt. The
/// kernel (`policy_eval`) applies the same predicate again, which is what makes
/// its own rejections unreachable from an authenticated principal rather than
/// merely believed to be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PrincipalShapeError {
    TooManyRoles,
    SubjectTooLong,
    IssuerTooLong,
    RoleTooLong,
    EmptySubject,
    EmptyRole,
}

impl PrincipalShapeError {
    /// Whether the fault is size rather than emptiness. The kernel reports the
    /// two as different errors, and the size checks run first so a principal
    /// with both problems is consistently reported as oversized.
    pub(crate) fn is_size(self) -> bool {
        !matches!(self, Self::EmptySubject | Self::EmptyRole)
    }
}

impl std::fmt::Display for PrincipalShapeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooManyRoles => write!(formatter, "more than {MAX_PRINCIPAL_ROLES} roles"),
            Self::SubjectTooLong => write!(
                formatter,
                "subject longer than {MAX_PRINCIPAL_SUBJECT_BYTES} bytes"
            ),
            Self::IssuerTooLong => write!(
                formatter,
                "issuer longer than {MAX_PRINCIPAL_ISSUER_BYTES} bytes"
            ),
            Self::RoleTooLong => write!(
                formatter,
                "a role longer than {MAX_PRINCIPAL_ROLE_BYTES} bytes"
            ),
            Self::EmptySubject => formatter.write_str("an empty subject"),
            Self::EmptyRole => formatter.write_str("an empty role"),
        }
    }
}

/// Judges the identity facts a validator is about to put in a [`Principal`].
///
/// Callable before the principal exists because the cookie-session validator
/// caches its verdict, and a rejection is a verdict worth caching: the
/// introspection response that produced it will produce it again.
pub(crate) fn check_principal_shape(
    user_id: &str,
    issuer: Option<&str>,
    roles: &[String],
) -> Result<(), PrincipalShapeError> {
    // Size before emptiness, deliberately; see `PrincipalShapeError::is_size`.
    if user_id.len() > MAX_PRINCIPAL_SUBJECT_BYTES {
        return Err(PrincipalShapeError::SubjectTooLong);
    }
    if issuer.is_some_and(|issuer| issuer.len() > MAX_PRINCIPAL_ISSUER_BYTES) {
        return Err(PrincipalShapeError::IssuerTooLong);
    }
    check_roles_size(roles)?;
    if user_id.is_empty() {
        return Err(PrincipalShapeError::EmptySubject);
    }
    check_roles_emptiness(roles)
}

/// Judges a role list on its own, for the one place roles are stored before
/// they become a principal: service-token scopes are authored through the admin
/// API and become roles at authentication, so the same bound applies when they
/// are written.
pub(crate) fn check_roles_shape(roles: &[String]) -> Result<(), PrincipalShapeError> {
    check_roles_size(roles)?;
    check_roles_emptiness(roles)
}

fn check_roles_size(roles: &[String]) -> Result<(), PrincipalShapeError> {
    if roles.len() > MAX_PRINCIPAL_ROLES {
        return Err(PrincipalShapeError::TooManyRoles);
    }
    if roles
        .iter()
        .any(|role| role.len() > MAX_PRINCIPAL_ROLE_BYTES)
    {
        return Err(PrincipalShapeError::RoleTooLong);
    }
    Ok(())
}

fn check_roles_emptiness(roles: &[String]) -> Result<(), PrincipalShapeError> {
    if roles.iter().any(String::is_empty) {
        return Err(PrincipalShapeError::EmptyRole);
    }
    Ok(())
}

impl Principal {
    /// Whether this principal is within the bounds [`check_principal_shape`]
    /// states. Every validator judges the facts before constructing one, so
    /// this holds for any principal authentication produced; the kernel checks
    /// it again rather than trusting that.
    pub(crate) fn check_shape(&self) -> Result<(), PrincipalShapeError> {
        check_principal_shape(&self.user_id, self.issuer.as_deref(), &self.roles)
    }
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

    #[test]
    fn principal_shape_accepts_every_bound_exactly_and_refuses_one_past_it() {
        let roles = |count: usize, len: usize| vec!["r".repeat(len); count];
        let issuer = "i".repeat(MAX_PRINCIPAL_ISSUER_BYTES);

        let mut principal = test_principal(AuthMethod::Bearer, Vec::new());
        principal.user_id = "u".repeat(MAX_PRINCIPAL_SUBJECT_BYTES);
        principal.issuer = Some(issuer.clone());
        principal.roles = roles(MAX_PRINCIPAL_ROLES, MAX_PRINCIPAL_ROLE_BYTES);
        assert_eq!(principal.check_shape(), Ok(()));

        for (user_id, issuer, roles, expected) in [
            (
                "u".repeat(MAX_PRINCIPAL_SUBJECT_BYTES + 1),
                None,
                Vec::new(),
                PrincipalShapeError::SubjectTooLong,
            ),
            (
                "user".to_owned(),
                Some(format!("{issuer}i")),
                Vec::new(),
                PrincipalShapeError::IssuerTooLong,
            ),
            (
                "user".to_owned(),
                None,
                roles(MAX_PRINCIPAL_ROLES + 1, 1),
                PrincipalShapeError::TooManyRoles,
            ),
            (
                "user".to_owned(),
                None,
                roles(1, MAX_PRINCIPAL_ROLE_BYTES + 1),
                PrincipalShapeError::RoleTooLong,
            ),
            (
                String::new(),
                None,
                Vec::new(),
                PrincipalShapeError::EmptySubject,
            ),
            (
                "user".to_owned(),
                None,
                vec!["admin".to_owned(), String::new()],
                PrincipalShapeError::EmptyRole,
            ),
        ] {
            assert_eq!(
                check_principal_shape(&user_id, issuer.as_deref(), &roles),
                Err(expected),
                "{expected:?}"
            );
        }
    }

    #[test]
    fn size_is_judged_before_emptiness_so_the_kernel_reports_it_consistently() {
        // A principal with both an oversized subject and an empty role is
        // reported as oversized: the kernel maps size to ContextTooLarge and
        // emptiness to InvalidPrincipal, and this order decides which.
        let error = check_principal_shape(
            &"u".repeat(MAX_PRINCIPAL_SUBJECT_BYTES + 1),
            None,
            &[String::new()],
        )
        .expect_err("out of bounds");
        assert_eq!(error, PrincipalShapeError::SubjectTooLong);
        assert!(error.is_size());
        assert!(!PrincipalShapeError::EmptyRole.is_size());
        assert!(!PrincipalShapeError::EmptySubject.is_size());
    }

    #[test]
    fn roles_shape_is_the_role_half_of_the_principal_predicate() {
        for roles in [
            vec!["r".repeat(MAX_PRINCIPAL_ROLE_BYTES); MAX_PRINCIPAL_ROLES],
            vec!["r".repeat(MAX_PRINCIPAL_ROLE_BYTES + 1)],
            vec!["r".to_owned(); MAX_PRINCIPAL_ROLES + 1],
            vec![String::new()],
            Vec::new(),
        ] {
            assert_eq!(
                check_roles_shape(&roles),
                check_principal_shape("user", None, &roles)
            );
        }
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
