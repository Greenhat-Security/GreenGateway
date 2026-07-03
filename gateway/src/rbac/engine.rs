use crate::auth;

use super::policy::Policy;

/// Stateless role-to-permission policy evaluator.
#[allow(dead_code)] // Authorization middleware in PR 2 will hold and call the engine.
pub struct PolicyEngine {
    policy: Policy,
}

impl PolicyEngine {
    #[allow(dead_code)] // Authorization middleware in PR 2 will construct the engine at startup.
    pub fn new(policy: Policy) -> Self {
        Self { policy }
    }

    /// True if any principal role grants `permission`; a role holding "*" grants everything.
    #[allow(dead_code)] // Authorization middleware in PR 2 will call this for route permissions.
    pub fn principal_has_permission(&self, principal: &auth::Principal, permission: &str) -> bool {
        principal
            .roles
            .iter()
            .filter_map(|role| self.policy.roles.get(role))
            .flat_map(|entry| entry.permissions.iter())
            .any(|grant| grant == "*" || grant == permission)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::auth::{AuthMethod, Principal};

    use super::*;
    use crate::rbac::policy::RoleEntry;

    #[test]
    fn admin_wildcard_grants_any_permission() {
        let engine = PolicyEngine::new(test_policy(&[("admin", &["*"])]));
        let principal = test_principal(&["admin"]);

        assert!(engine.principal_has_permission(&principal, "data:read"));
        assert!(engine.principal_has_permission(&principal, "settings:write"));
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
                    },
                )
            })
            .collect::<HashMap<_, _>>();

        Policy {
            schema_version: "0.1.0".to_owned(),
            id: Some("test-policy".to_owned()),
            roles,
        }
    }

    fn test_principal(roles: &[&str]) -> Principal {
        Principal {
            user_id: "user-123".to_owned(),
            email: Some("user@example.test".to_owned()),
            org_id: None,
            roles: roles.iter().map(|role| (*role).to_owned()).collect(),
            session_id: "session-123".to_owned(),
            auth_method: AuthMethod::Bearer,
        }
    }
}
