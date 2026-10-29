//! The policy invariants a deployment profile enforces (ADR-0008,
//! "Initialization profiles").
//!
//! `production` requires a deny-by-default policy that enforces its
//! decisions, with no role granting the `*` wildcard permission. `migration`
//! permits each of those compatibility behaviors only when the deployment
//! document acknowledges it; `v1alpha1` has no acknowledgment list yet (it
//! arrives with the field catalog), so a migration bundle is held to the
//! production invariants rather than allowed them unacknowledged.
//! `development` adds no policy invariant.
//!
//! They apply to a policy the bundle supplies, once it has passed its
//! published schema, so every member read here has its schema type. A policy
//! left to the server's store is checked where the store is. Role names are
//! policy values, so a wildcard role is reported at `/roles` and the line of
//! its `*`, never by name.

use super::{
    diagnostic::{BundleDiagnostic, Code, Pointer},
    document::Profile,
    source::FileName,
    syntax::{Node, Value},
};

/// Reports every profile invariant the policy document `node` breaks.
pub(crate) fn policy(
    profile: Profile,
    node: &Node,
    file: &FileName,
    diagnostics: &mut Vec<BundleDiagnostic>,
) {
    if profile == Profile::Development {
        return;
    }
    let report = |diagnostics: &mut Vec<BundleDiagnostic>, code, pointer, node: &Node| {
        diagnostics.push(BundleDiagnostic::at(
            code,
            file,
            pointer,
            Some(node.position),
        ));
    };
    let root = Pointer::root();
    for member in node.as_object().unwrap_or_default() {
        match member.key.as_str() {
            // An absent `default_action` is `deny`, and an absent
            // `enforcement_mode` is `enforce`.
            "default_action" if member.value.as_str() == Some("allow") => report(
                diagnostics,
                Code::PolicyDefaultAllow,
                root.member("default_action"),
                &member.value,
            ),
            "enforcement_mode" if member.value.as_str() == Some("shadow") => report(
                diagnostics,
                Code::PolicyShadowMode,
                root.member("enforcement_mode"),
                &member.value,
            ),
            "routes" => {
                for (index, route) in elements(&member.value).iter().enumerate() {
                    let shadow = route.as_object().unwrap_or_default().iter().find(|field| {
                        field.key == "enforcement_mode" && field.value.as_str() == Some("shadow")
                    });
                    if let Some(field) = shadow {
                        report(
                            diagnostics,
                            Code::PolicyShadowMode,
                            root.member("routes")
                                .index(index)
                                .member("enforcement_mode"),
                            &field.value,
                        );
                    }
                }
            }
            "roles" => {
                for role in member.value.as_object().unwrap_or_default() {
                    let wildcard = role
                        .value
                        .as_object()
                        .unwrap_or_default()
                        .iter()
                        .filter(|field| field.key == "permissions")
                        .flat_map(|field| elements(&field.value))
                        .find(|permission| permission.as_str() == Some("*"));
                    if let Some(permission) = wildcard {
                        report(
                            diagnostics,
                            Code::PolicyWildcardRole,
                            root.member("roles"),
                            permission,
                        );
                    }
                }
            }
            _ => {}
        }
    }
}

fn elements(node: &Node) -> &[Node] {
    match &node.value {
        Value::Array(items) => items,
        _ => &[],
    }
}
