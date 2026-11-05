//! The revision ledger's permission codes against the gateway's own (issue
//! #242, PR 11).
//!
//! Conditional plan, apply, history and rollback, and the production
//! compiler ledger plans run (`gateway_config::revisions::ProductionCompiler`),
//! are `gateway-config`'s and are tested there. What only the gateway can
//! check is that the permissions the library requires are the ones its
//! admin routes grant.

use gateway_config::{
    bundle::ResourceValidators,
    revisions::{
        PlanCompiler, ProductionCompiler, ADMIN_CONFIG_WRITE, ADMIN_POLICY_WRITE, ADMIN_TOOLS_WRITE,
    },
};

#[test]
fn the_library_requires_the_gateway_permission_codes() {
    assert_eq!(ADMIN_POLICY_WRITE, crate::ADMIN_POLICY_WRITE_PERMISSION);
    assert_eq!(ADMIN_TOOLS_WRITE, crate::ADMIN_TOOLS_WRITE_PERMISSION);
    assert_eq!(ADMIN_CONFIG_WRITE, "admin:config:write");
    // The validators are the production ones bundle reading runs.
    let validators = ProductionCompiler;
    assert!(validators
        .validators()
        .policy(serde_json::json!({"schema_version": "0.1.0"}))
        .is_some());
}
