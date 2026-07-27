//! Permission names reserved by the issue #240 connection control plane.

pub const ADMIN_CONNECTIONS_READ: &str = "admin:connections:read";
pub const ADMIN_CONNECTIONS_WRITE: &str = "admin:connections:write";
pub const ADMIN_CONNECTIONS_SECRETS_WRITE: &str = "admin:connections:secrets:write";
pub const ADMIN_CONNECTIONS_TEST: &str = "admin:connections:test";
pub const ADMIN_CONNECTIONS_REFRESH: &str = "admin:connections:refresh";
pub const ADMIN_TOOLS_READ: &str = "admin:tools:read";
pub const ADMIN_TOOLS_WRITE: &str = "admin:tools:write";
pub const ADMIN_TOOLS_EXECUTE: &str = "admin:tools:execute";

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn connection_permission_names_are_unique_and_bounded() {
        let permissions = [
            ADMIN_CONNECTIONS_READ,
            ADMIN_CONNECTIONS_WRITE,
            ADMIN_CONNECTIONS_SECRETS_WRITE,
            ADMIN_CONNECTIONS_TEST,
            ADMIN_CONNECTIONS_REFRESH,
            ADMIN_TOOLS_READ,
            ADMIN_TOOLS_WRITE,
            ADMIN_TOOLS_EXECUTE,
        ];

        assert_eq!(
            permissions.into_iter().collect::<BTreeSet<_>>().len(),
            permissions.len()
        );
        assert!(permissions
            .iter()
            .all(|permission| permission.len() <= 64 && permission.is_ascii()));
    }
}
