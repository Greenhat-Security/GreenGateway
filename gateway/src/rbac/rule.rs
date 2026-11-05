//! What a direct firewall rule and a principal constraint match.
//!
//! The rule model and the authentication method names a policy may use are
//! `gateway_config::rbac::rule` (issue #242), re-exported here so call sites
//! keep their paths. Matching reads an authenticated [`Principal`], which is
//! the gateway's, so it stays here: the inherent `matches` methods the model
//! had are now [`PrincipalMatch`] and [`RuleMatch`], with the same names.

pub use gateway_config::rbac::rule::*;

use crate::auth::{AuthMethod, Principal};

/// Whether a principal satisfies a [`PrincipalMatcher`].
pub trait PrincipalMatch {
    /// Returns true when the optional principal satisfies every configured
    /// constraint. A completely empty matcher returns true for authenticated
    /// and unauthenticated callers.
    fn matches(&self, principal: Option<&Principal>) -> bool;
}

impl PrincipalMatch for PrincipalMatcher {
    fn matches(&self, principal: Option<&Principal>) -> bool {
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
        }) && principal_identity_matches(&self.issuers, &self.auth_methods, principal)
            && constraint_matches(&self.principal_ids, |principal_id| {
                principal.user_id == principal_id
            })
    }
}

/// Whether a direct [`Rule`] matches a request.
#[allow(dead_code)]
pub trait RuleMatch {
    /// Returns true when this rule matches the request tuple.
    ///
    /// Policy-level evaluation should use `RuleMatcher` so path patterns are
    /// parsed once per loaded policy instead of once per request.
    fn matches(&self, method: &str, path: &str, principal: Option<&Principal>) -> bool;
}

#[allow(dead_code)]
impl RuleMatch for Rule {
    fn matches(&self, method: &str, path: &str, principal: Option<&Principal>) -> bool {
        super::matcher::rule_matches(self, method, path, principal)
    }
}

pub(crate) fn principal_identity_matches(
    issuers: &[String],
    auth_methods: &[String],
    principal: &Principal,
) -> bool {
    constraint_matches(issuers, |issuer| {
        principal.issuer.as_deref() == Some(issuer)
    }) && constraint_matches(auth_methods, |auth_method| {
        auth_method == auth_method_policy_value(&principal.auth_method)
    })
}

pub(crate) fn auth_method_policy_value(auth_method: &AuthMethod) -> &'static str {
    match auth_method {
        AuthMethod::Bearer => AUTH_METHOD_BEARER_TOKEN,
        AuthMethod::Cookie => AUTH_METHOD_SESSION_COOKIE,
        AuthMethod::ServiceToken => AUTH_METHOD_SERVICE_TOKEN,
        AuthMethod::ClientCertificate => AUTH_METHOD_CLIENT_CERTIFICATE,
    }
}

fn constraint_matches(values: &[String], matches_value: impl Fn(&str) -> bool) -> bool {
    values.is_empty() || values.iter().any(|value| matches_value(value))
}

#[cfg(test)]
#[path = "rule_tests.rs"]
mod tests;
