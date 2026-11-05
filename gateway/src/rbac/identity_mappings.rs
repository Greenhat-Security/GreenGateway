//! Applying policy v1 identity mappings to a principal (issue #243, checklist
//! item 16).
//!
//! The mapping model, its validation and the rules of mapped-role mode are
//! `gateway_config::rbac::identity_mappings` (issue #242), re-exported here so
//! call sites keep their paths. This module is what reads an authenticated
//! principal: the internal roles a principal holds under a policy's mappings,
//! and whether one mapping applies to it.

use std::collections::BTreeSet;

pub use gateway_config::rbac::identity_mappings::*;

use super::{
    conditions::{Fact, PolicyFacts, Truth},
    rule::{auth_method_policy_value, ALL_AUTH_METHOD_NAMES, AUTH_METHOD_SERVICE_TOKEN},
};
use crate::auth::Principal;

/// The identity mappings of a policy in mapped-role mode, compiled once per
/// snapshot.
#[derive(Debug, Clone)]
pub(crate) struct CompiledIdentityMappings {
    mappings: Vec<IdentityMapping>,
}

impl CompiledIdentityMappings {
    pub(crate) fn new(mappings: &[IdentityMapping]) -> Self {
        Self {
            mappings: mappings.to_vec(),
        }
    }

    /// The internal roles `principal` holds, sorted and de-duplicated, or
    /// `None` when a mapping reads a fact that was not captured and so the
    /// roles cannot be told.
    pub(crate) fn effective_roles(
        &self,
        principal: &Principal,
        facts: &PolicyFacts,
    ) -> Option<Vec<String>> {
        let mut granted = BTreeSet::new();
        for mapping in &self.mappings {
            match mapping_applies(mapping, principal, facts) {
                Truth::True => granted.extend(mapping.grant_roles.iter().map(String::as_str)),
                Truth::False => {}
                Truth::Unknown => return None,
            }
        }
        Some(granted.into_iter().map(str::to_owned).collect())
    }
}

/// The authentication methods of the principals `mapping` can apply to: the
/// ones it lists, or every method when it lists none, less `service_token`.
/// A service-token principal carries no issuer and every mapping is bound to
/// one, so no mapping applies to a service token whatever it lists.
pub(crate) fn admitted_auth_methods(mapping: &IdentityMapping) -> impl Iterator<Item = &str> {
    ALL_AUTH_METHOD_NAMES.iter().copied().filter(|method| {
        *method != AUTH_METHOD_SERVICE_TOKEN
            && (mapping.auth_methods.is_empty()
                || mapping.auth_methods.iter().any(|listed| listed == method))
    })
}

/// Whether `mapping` applies to `principal`. Every constraint but the
/// organization reads the principal itself, which is always known.
pub(crate) fn mapping_applies(
    mapping: &IdentityMapping,
    principal: &Principal,
    facts: &PolicyFacts,
) -> Truth {
    let listed = |values: &[String], present: &str| {
        values.is_empty() || values.iter().any(|value| value == present)
    };
    let identity_holds = principal.issuer.as_deref() == Some(mapping.issuer.as_str())
        && listed(
            &mapping.auth_methods,
            auth_method_policy_value(&principal.auth_method),
        )
        && listed(&mapping.subjects, &principal.user_id)
        && (mapping.claimed_roles.is_empty()
            || principal
                .roles
                .iter()
                .any(|role| mapping.claimed_roles.contains(role)));
    if !identity_holds {
        return Truth::False;
    }
    if mapping.organizations.is_empty() {
        return Truth::True;
    }
    match &facts.organization {
        Fact::Uncaptured => Truth::Unknown,
        Fact::Captured(None) => Truth::False,
        Fact::Captured(Some(organization)) => {
            Truth::of(mapping.organizations.contains(organization))
        }
    }
}

#[cfg(test)]
#[path = "identity_mappings_tests.rs"]
mod tests;
