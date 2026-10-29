//! Identity mappings for policy v1 (issue #243, checklist item 16).
//!
//! By default a principal's claimed roles -- the role claim its identity
//! provider or service token carried -- are the roles policy grants
//! permissions to. A policy v1 document that sets `identity_mappings`, even
//! to an empty array, is in **mapped-role mode** instead: verified external
//! attributes stay external, and a principal holds exactly the internal roles
//! the mappings that apply to it grant. A claimed role named `admin` is then
//! only an attribute a mapping may test, never the `admin` role itself.
//!
//! A mapping applies to a principal authenticated by exactly its `issuer`,
//! after the canonicalization every policy issuer gets, whose authentication
//! method, subject, verified organization and claimed roles each satisfy the
//! mapping's list for it when that list is not empty: any listed value
//! satisfies a list, and every non-empty list must be satisfied. The
//! principal's internal roles are the union of `grant_roles` over every
//! mapping that applies, sorted and de-duplicated, so the result does not
//! depend on the order mappings are listed in; the order is for the people
//! who maintain them and for diagnostics.
//!
//! Every mapping is bound to an issuer. A service token carries no issuer, so
//! no mapping applies to one and in mapped-role mode it holds no internal
//! role: a source of service-token identity needs a reviewed model of its
//! own. An anonymous caller holds no role in either mode.
//!
//! A mapping that constrains `organizations` reads the organization fact. If
//! that fact was not captured, the mapping can neither be applied nor ruled
//! out, and the principal's roles are undetermined: the kernel answers
//! indeterminate rather than grant or withhold a role on a guess.

use std::collections::{BTreeSet, HashMap};

use serde::{Deserialize, Serialize};

use super::{
    conditions::{is_bounded_text, Fact, PolicyFacts, Truth},
    policy::RoleEntry,
    policy_document::{IssueCode, PolicyIssue},
    rule::{auth_method_policy_value, valid_auth_method_name},
};
use crate::auth::{
    principal::{
        canonical_issuer, MAX_PRINCIPAL_ISSUER_BYTES, MAX_PRINCIPAL_ROLE_BYTES,
        MAX_PRINCIPAL_SUBJECT_BYTES,
    },
    Principal,
};

/// Most identity mappings one policy may list.
pub(crate) const MAX_IDENTITY_MAPPINGS: usize = 256;
/// Most values one mapping's list may hold.
pub(crate) const MAX_IDENTITY_MAPPING_VALUES: usize = 64;
/// Longest organization a mapping may name, in bytes.
pub(crate) const MAX_ORGANIZATION_BYTES: usize = 256;

/// One ordered identity mapping.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityMapping {
    /// Stable identifier, unique across rules, routes, rate overrides and
    /// identity mappings.
    pub id: String,
    /// The one issuer whose principals this mapping can apply to.
    pub issuer: String,
    /// Authentication methods the principal must have used. Empty means any.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub auth_methods: Vec<String>,
    /// Exact principal subjects (`user_id`). Empty means any.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subjects: Vec<String>,
    /// Exact verified organizations. Empty means any, including none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub organizations: Vec<String>,
    /// Claimed roles, of which the principal must carry at least one. Empty
    /// means any.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claimed_roles: Vec<String>,
    /// The internal roles, defined in `roles`, this mapping grants.
    pub grant_roles: Vec<String>,
}

/// Canonicalizes each mapping's issuer, as role and rule issuers are.
pub(crate) fn canonicalize_identity_mapping_issuers(mappings: &mut [IdentityMapping]) {
    for mapping in mappings {
        mapping.issuer = canonical_issuer(&mapping.issuer).unwrap_or_default();
    }
}

/// Validates the identity mappings against the roles they grant, stopping at
/// the first problem as the rest of the semantic validation does.
pub(crate) fn validate_identity_mappings(
    mappings: &[IdentityMapping],
    roles: &HashMap<String, RoleEntry>,
) -> Result<(), PolicyIssue> {
    if mappings.len() > MAX_IDENTITY_MAPPINGS {
        return Err(PolicyIssue::new(
            IssueCode::IdentityMappingsTooMany,
            "/identity_mappings".to_owned(),
            format!("identity_mappings must list at most {MAX_IDENTITY_MAPPINGS} mappings"),
        ));
    }
    for (index, mapping) in mappings.iter().enumerate() {
        let pointer = format!("/identity_mappings/{index}");
        let field_path = format!("identity_mappings[{index}]");
        if mapping.issuer.trim().is_empty() {
            return Err(PolicyIssue::new(
                IssueCode::IssuerEmpty,
                format!("{pointer}/issuer"),
                format!("{field_path}.issuer must not be empty"),
            ));
        }
        if mapping.issuer.len() > MAX_PRINCIPAL_ISSUER_BYTES {
            return Err(PolicyIssue::new(
                IssueCode::IdentityMappingValueInvalid,
                format!("{pointer}/issuer"),
                format!("{field_path}.issuer must not exceed {MAX_PRINCIPAL_ISSUER_BYTES} bytes"),
            ));
        }
        if mapping.auth_methods.len() > MAX_IDENTITY_MAPPING_VALUES {
            return Err(too_many_values(&pointer, &field_path, "auth_methods"));
        }
        for (method_index, auth_method) in mapping.auth_methods.iter().enumerate() {
            if !valid_auth_method_name(auth_method) {
                return Err(PolicyIssue::new(
                    IssueCode::AuthMethodUnknown,
                    format!("{pointer}/auth_methods/{method_index}"),
                    format!(
                        "{field_path}.auth_methods contains unknown auth method '{auth_method}'"
                    ),
                ));
            }
        }
        for (member, values, max_bytes) in [
            ("subjects", &mapping.subjects, MAX_PRINCIPAL_SUBJECT_BYTES),
            (
                "organizations",
                &mapping.organizations,
                MAX_ORGANIZATION_BYTES,
            ),
            (
                "claimed_roles",
                &mapping.claimed_roles,
                MAX_PRINCIPAL_ROLE_BYTES,
            ),
        ] {
            validate_values(&pointer, &field_path, member, values, max_bytes)?;
        }
        if mapping.grant_roles.is_empty() {
            return Err(PolicyIssue::new(
                IssueCode::IdentityMappingGrantEmpty,
                format!("{pointer}/grant_roles"),
                format!("{field_path}.grant_roles must name at least one role"),
            ));
        }
        if mapping.grant_roles.len() > MAX_IDENTITY_MAPPING_VALUES {
            return Err(too_many_values(&pointer, &field_path, "grant_roles"));
        }
        for (role_index, role) in mapping.grant_roles.iter().enumerate() {
            if !roles.contains_key(role) {
                return Err(PolicyIssue::new(
                    IssueCode::IdentityMappingRoleUnknown,
                    format!("{pointer}/grant_roles/{role_index}"),
                    format!(
                        "{field_path}.grant_roles[{role_index}] names role '{role}', which the \
                         policy's roles do not define"
                    ),
                ));
            }
        }
    }
    Ok(())
}

fn validate_values(
    pointer: &str,
    field_path: &str,
    member: &str,
    values: &[String],
    max_bytes: usize,
) -> Result<(), PolicyIssue> {
    if values.len() > MAX_IDENTITY_MAPPING_VALUES {
        return Err(too_many_values(pointer, field_path, member));
    }
    for (index, value) in values.iter().enumerate() {
        if !is_bounded_text(value, max_bytes, false) {
            return Err(PolicyIssue::new(
                IssueCode::IdentityMappingValueInvalid,
                format!("{pointer}/{member}/{index}"),
                format!(
                    "{field_path}.{member}[{index}] must be 1 to {max_bytes} bytes of text \
                     without control characters"
                ),
            ));
        }
    }
    Ok(())
}

fn too_many_values(pointer: &str, field_path: &str, member: &str) -> PolicyIssue {
    PolicyIssue::new(
        IssueCode::IdentityMappingValueInvalid,
        format!("{pointer}/{member}"),
        format!("{field_path}.{member} must list at most {MAX_IDENTITY_MAPPING_VALUES} values"),
    )
}

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
