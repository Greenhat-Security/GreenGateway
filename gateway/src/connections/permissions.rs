//! Permission names reserved by the issue #240 connection control plane.

pub const ADMIN_CONNECTIONS_READ: &str = "admin:connections:read";
pub const ADMIN_CONNECTIONS_WRITE: &str = "admin:connections:write";
pub const ADMIN_CONNECTIONS_SECRETS_WRITE: &str = "admin:connections:secrets:write";
pub const ADMIN_CONNECTIONS_TEST: &str = "admin:connections:test";
pub const ADMIN_CONNECTIONS_REFRESH: &str = "admin:connections:refresh";
pub const ADMIN_TOOLS_READ: &str = "admin:tools:read";
pub const ADMIN_TOOLS_WRITE: &str = "admin:tools:write";
pub const ADMIN_TOOLS_EXECUTE: &str = "admin:tools:execute";

/// The cluster status API (issue #241, PR 14): `GET
/// /v1{ADMIN_PREFIX}/cluster` and `/cluster/replicas`.
///
/// Its own permission rather than `admin:status:read`, because the two
/// answer different questions about different blast radii. `/status`
/// describes *this process's* configuration; the cluster routes describe
/// the deployment's topology -- how many replicas exist, which are live,
/// what versions they run, and which one holds the maintenance lease. That
/// is the map an attacker wants and an on-call operator needs, so it is
/// granted separately. There is no matching write permission: the surface
/// has no mutation routes.
pub const ADMIN_CLUSTER_READ: &str = "admin:cluster:read";

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
            ADMIN_CLUSTER_READ,
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
