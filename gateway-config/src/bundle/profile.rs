//! The policy invariants a deployment profile enforces (ADR-0008,
//! "Initialization profiles").
//!
//! `production` requires a deny-by-default policy that enforces its
//! decisions, with no role granting the `*` wildcard permission. `migration`
//! permits each of those compatibility behaviors only when the deployment
//! document lists its [`Compatibility`] code under
//! `spec.compatibility.acknowledged`; an acknowledged behavior is then
//! reported as a warning instead of an error, so every report still shows
//! it. No other profile may acknowledge one (the deployment reader refuses
//! the list there), and `development` adds no policy invariant.
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

/// A compatibility behavior a `migration` deployment document may keep by
/// acknowledging it (ADR-0008, "Initialization profiles"). The list is
/// closed: a behavior the reader does not enforce as an invariant has no
/// code to acknowledge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Compatibility {
    PolicyDefaultAllow,
    PolicyShadowMode,
    WildcardRole,
}

impl Compatibility {
    /// Every behavior, in canonical order.
    pub(crate) const ALL: &'static [Self] = &[
        Self::PolicyDefaultAllow,
        Self::PolicyShadowMode,
        Self::WildcardRole,
    ];

    /// Its code in `spec.compatibility.acknowledged`: the reason segment of
    /// the diagnostic it relaxes.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::PolicyDefaultAllow => "policy_default_allow",
            Self::PolicyShadowMode => "policy_shadow_mode",
            Self::WildcardRole => "wildcard_role",
        }
    }

    /// The profile diagnostic an acknowledgment turns into a warning.
    pub(crate) fn code(self) -> Code {
        match self {
            Self::PolicyDefaultAllow => Code::PolicyDefaultAllow,
            Self::PolicyShadowMode => Code::PolicyShadowMode,
            Self::WildcardRole => Code::PolicyWildcardRole,
        }
    }
}

/// A deployment's profile and the compatibility behaviors it acknowledges.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProfileRules {
    pub(crate) profile: Profile,
    pub(crate) acknowledged: Vec<Compatibility>,
}

impl ProfileRules {
    /// Whether a breach reported as `code` is acknowledged: only a
    /// `migration` document can acknowledge one.
    fn acknowledges(&self, code: Code) -> bool {
        self.profile == Profile::Migration
            && self
                .acknowledged
                .iter()
                .any(|behavior| behavior.code() == code)
    }
}

/// Reports every profile invariant the policy document `node` breaks: as an
/// error, or as a warning when the deployment acknowledges the behavior.
pub(crate) fn policy(
    rules: &ProfileRules,
    node: &Node,
    file: &FileName,
    diagnostics: &mut Vec<BundleDiagnostic>,
) {
    if rules.profile == Profile::Development {
        return;
    }
    let report = |diagnostics: &mut Vec<BundleDiagnostic>, code, pointer, node: &Node| {
        let diagnostic = BundleDiagnostic::at(code, file, pointer, Some(node.position));
        diagnostics.push(if rules.acknowledges(code) {
            diagnostic.warning()
        } else {
            diagnostic
        });
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
