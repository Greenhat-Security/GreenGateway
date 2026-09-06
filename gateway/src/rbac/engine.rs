use crate::auth;

use super::policy::Policy;

/// Stateless role-to-permission policy evaluator.
pub struct PolicyEngine {
    policy: Policy,
}

impl PolicyEngine {
    pub fn new(policy: Policy) -> Self {
        Self { policy }
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// True if any principal role grants `permission`; a role holding "*" grants everything.
    pub fn principal_has_permission(&self, principal: &auth::Principal, permission: &str) -> bool {
        principal
            .roles
            .iter()
            .filter_map(|role| self.policy.roles.get(role))
            .filter(|entry| entry.matches_principal_identity(principal))
            .flat_map(|entry| entry.permissions.iter())
            .any(|grant| grant == "*" || grant == permission)
    }

    /// True if any identity-matched principal role grants the `"*"` wildcard permission.
    pub fn principal_has_wildcard(&self, principal: &auth::Principal) -> bool {
        principal
            .roles
            .iter()
            .filter_map(|role| self.policy.roles.get(role))
            .filter(|entry| entry.matches_principal_identity(principal))
            .flat_map(|entry| entry.permissions.iter())
            .any(|grant| grant == "*")
    }

    /// True if `role` is carried by the principal, exists in policy, and is active
    /// for the principal's issuer and authentication method.
    pub fn principal_has_active_role(&self, principal: &auth::Principal, role: &str) -> bool {
        principal.roles.iter().any(|held| held == role)
            && self
                .policy
                .roles
                .get(role)
                .is_some_and(|entry| entry.matches_principal_identity(principal))
    }
}

#[cfg(test)]
#[path = "engine_tests.rs"]
mod tests;
