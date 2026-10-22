//! Explicit, deterministic conversion of a 0.x policy document to policy v1
//! (issue #243, checklist item 3).
//!
//! Nothing converts a document on its own: startup, reload and replacement
//! read each document under the schema it names. [`convert_v0_source`] is
//! called only when an operator asks for a conversion, returns the v1
//! document beside a list of what changed, and writes nothing.
//!
//! ## What a conversion keeps
//!
//! The v1 document is the gateway's own serialization of what the 0.x reader
//! read, with `schema_version` set to `1.0.0` and a stable id on every rule,
//! route and rate override. Every member is written the way the gateway
//! writes it -- defaults explicit or omitted, issuers canonicalized, maps
//! sorted by name, arrays in document order -- so one 0.x reading has one v1
//! document however its source was spelled. What the 0.x reader ignored is
//! not carried over and is listed: a top-level member it does not know, and
//! every copy of a repeated member name except the last, the one it read.
//!
//! ## Ids
//!
//! A rule keeps its *effective* id when that is a valid v1 id that no earlier
//! rule already claimed. The effective id is the one the gateway already
//! attributes the rule's decisions to in audit events, hit counts, shadow
//! review and the rule-management routes: its `id`, or for a rule without
//! one, its zero-based index written in decimal. Keeping it means a rule's
//! history stays its own across the conversion.
//!
//! Every other element gets a generated id: `route-N`, `rule-N` or
//! `rate-limit-N`, where `N` is its zero-based index in the 0.x document.
//! Kept rule ids are claimed first, in rule order; generated ids are then
//! assigned in section order (routes, rules, rate overrides) and, when the
//! plain form is already taken, get the smallest suffix `-2`, `-3`, ... that
//! makes them unique. Every written, replaced and assigned id is listed.
//!
//! ## Parity
//!
//! The conversion is refused unless the document it produces reads back,
//! through the same v1 reader startup and replacement use, as exactly the
//! policy the 0.x reader read apart from `schema_version` and the ids it
//! wrote. Decisions are a function of that policy alone, so the two
//! documents decide every request identically; the golden tests show it
//! through the shared evaluator. A document whose v1 form the reader would
//! refuse -- a number beyond the I-JSON safe range, or a normalized form
//! larger than 1 MiB -- is refused with the reader's own diagnostics rather
//! than converted into something that cannot be used.

use std::collections::HashSet;

use serde::{
    ser::{SerializeMap, SerializeSeq},
    Serialize, Serializer,
};
use serde_json::{Map, Value};

use super::{
    policy::KNOWN_TOP_LEVEL_KEYS,
    policy_document::{
        self, inspect_source, is_valid_element_id, IssueCode, PolicyInspection, PolicySchema,
        DISPATCH_MEMBERS, EGRESS_MEMBERS, POLICY_V1_SCHEMA_VERSION, PRINCIPAL_MEMBERS,
        RATE_LIMIT_MEMBERS, ROLE_MEMBERS, ROUTE_MEMBERS, RULE_MEMBERS, TOOL_MEMBERS,
    },
    Policy,
};

/// A stable change code. The string is part of the policy API contract; the
/// variant name is not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ChangeCode {
    SchemaVersionSet,
    UnknownMemberRemoved,
    DuplicateMemberResolved,
    MoreDuplicateMembersResolved,
    RuleIdWritten,
    RuleIdReplaced,
    ElementIdAssigned,
}

impl ChangeCode {
    /// Every code, so tests can check the vocabulary as a whole.
    #[cfg(test)]
    pub(crate) const ALL: [Self; 7] = [
        Self::SchemaVersionSet,
        Self::UnknownMemberRemoved,
        Self::DuplicateMemberResolved,
        Self::MoreDuplicateMembersResolved,
        Self::RuleIdWritten,
        Self::RuleIdReplaced,
        Self::ElementIdAssigned,
    ];

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::SchemaVersionSet => "schema_version_set",
            Self::UnknownMemberRemoved => "unknown_member_removed",
            Self::DuplicateMemberResolved => "duplicate_member_resolved",
            Self::MoreDuplicateMembersResolved => "more_duplicate_members_resolved",
            Self::RuleIdWritten => "rule_id_written",
            Self::RuleIdReplaced => "rule_id_replaced",
            Self::ElementIdAssigned => "element_id_assigned",
        }
    }

    /// What changed, in words that quote nothing from the document.
    pub(crate) const fn message(self) -> &'static str {
        match self {
            Self::SchemaVersionSet => "schema_version is set to \"1.0.0\"",
            Self::UnknownMemberRemoved => {
                "a top-level member the 0.x reader ignores is not carried into policy v1"
            }
            Self::DuplicateMemberResolved => {
                "an object repeated this member name; only the last copy, the one the 0.x \
                 reader used, is kept"
            }
            Self::MoreDuplicateMembersResolved => {
                "further repeated member names were resolved the same way and are not listed"
            }
            Self::RuleIdWritten => {
                "the rule had no id; the id the gateway already reports for it, its index, is \
                 written, so its audit attribution is unchanged"
            }
            Self::RuleIdReplaced => {
                "the rule's id is not a valid v1 id or an earlier rule already uses it; it gets \
                 a generated id, and its audit attribution changes to that id"
            }
            Self::ElementIdAssigned => "the element had no id; it gets a generated one",
        }
    }
}

impl Serialize for ChangeCode {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// One reviewable difference between a 0.x document and its conversion. None
/// of them changes what the policy authorizes; they name what the conversion
/// wrote, replaced or left out.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct ConversionChange {
    pub(crate) code: ChangeCode,
    /// RFC 6901 JSON Pointer into the 0.x document, which locates the same
    /// element in the v1 document; empty for the whole document.
    pub(crate) pointer: String,
    /// The id the element has in the v1 document.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) element_id: Option<String>,
    /// For a replaced rule id, the effective id the rule had before.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) previous_id: Option<String>,
    pub(crate) message: &'static str,
}

impl ConversionChange {
    fn new(code: ChangeCode, pointer: String) -> Self {
        Self {
            code,
            pointer,
            element_id: None,
            previous_id: None,
            message: code.message(),
        }
    }

    fn with_id(code: ChangeCode, pointer: String, element_id: String) -> Self {
        Self {
            element_id: Some(element_id),
            ..Self::new(code, pointer)
        }
    }
}

/// A completed conversion: the v1 document and what it took to get there.
#[derive(Debug)]
pub(crate) struct PolicyConversion {
    source_schema_version: String,
    source_digest: String,
    semantic_digest: String,
    changes: Vec<ConversionChange>,
    /// The gateway's serialization of the v1 policy. Its maps are sorted by
    /// name; [`Self::document`] adds the member order.
    document: Value,
}

impl PolicyConversion {
    /// The 0.x `schema_version` the source declared.
    pub(crate) fn source_schema_version(&self) -> &str {
        &self.source_schema_version
    }

    /// The ADR-0004 source digest of the 0.x bytes converted.
    pub(crate) fn source_digest(&self) -> &str {
        &self.source_digest
    }

    /// The v1 semantic digest of the converted document: the one
    /// `POST /policy/validate` reports for it however it is later spelled.
    pub(crate) fn semantic_digest(&self) -> &str {
        &self.semantic_digest
    }

    pub(crate) fn changes(&self) -> &[ConversionChange] {
        &self.changes
    }

    /// The v1 document, serializing with every object's members in the
    /// order the policy defines them.
    pub(crate) fn document(&self) -> ConvertedDocument<'_> {
        ConvertedDocument(&self.document)
    }
}

/// Why a conversion produced no document.
#[derive(Debug)]
pub(crate) enum ConversionError {
    /// The source cannot be converted. The inspection holds the diagnostics:
    /// the source's own errors, [`IssueCode::ConversionRequiresV0`] for a
    /// document that is not 0.x, or the errors the v1 reader found in the
    /// conversion, located at the same pointers.
    Refused(Box<PolicyInspection>),
    /// The converted document did not read back as the policy it came from.
    /// Never expected; refused rather than returned with a different meaning.
    ParityViolated,
    /// The converted policy could not be serialized. Never expected.
    Encoding,
}

/// Converts 0.x policy source bytes to policy v1. Pure: it reads only
/// `source`, and writes and logs nothing except the unknown-top-level-member
/// warning every 0.x reading logs.
pub(crate) fn convert_v0_source(source: &[u8]) -> Result<PolicyConversion, ConversionError> {
    let mut inspection = inspect_source(source);
    if inspection
        .schema_version()
        .and_then(PolicySchema::of_version)
        == Some(PolicySchema::V1)
    {
        inspection.refuse(
            IssueCode::ConversionRequiresV0,
            "/schema_version",
            format!(
                "/schema_version: {}",
                IssueCode::ConversionRequiresV0.message()
            ),
        );
        return Err(ConversionError::Refused(Box::new(inspection)));
    }
    let (Some(source_policy), Some(source_digest)) = (
        inspection
            .policy()
            .filter(|_| inspection.is_valid())
            .cloned(),
        inspection.source_digest().map(str::to_owned),
    ) else {
        return Err(ConversionError::Refused(Box::new(inspection)));
    };

    let mut changes = vec![ConversionChange::new(
        ChangeCode::SchemaVersionSet,
        "/schema_version".to_owned(),
    )];
    // The 0.x inspection already located every top-level member it ignores.
    let removed: Vec<String> = inspection
        .diagnostics()
        .iter()
        .filter(|diagnostic| diagnostic.code == IssueCode::UnknownTopLevelMember.as_str())
        .map(|diagnostic| diagnostic.pointer.clone())
        .collect();
    changes.extend(
        removed.iter().map(|pointer| {
            ConversionChange::new(ChangeCode::UnknownMemberRemoved, pointer.clone())
        }),
    );
    // A repeat in or of a removed member is not resolved but left out with
    // it, which its removal already lists.
    let (repeats, more_repeats) = policy_document::repeated_member_pointers(source);
    changes.extend(
        repeats
            .into_iter()
            .filter(|pointer| !is_within_any(pointer, &removed))
            .map(|pointer| ConversionChange::new(ChangeCode::DuplicateMemberResolved, pointer)),
    );
    if more_repeats {
        changes.push(ConversionChange::new(
            ChangeCode::MoreDuplicateMembersResolved,
            String::new(),
        ));
    }

    let mut policy = source_policy.clone();
    policy.schema_version = POLICY_V1_SCHEMA_VERSION.to_owned();
    assign_ids(&mut policy, &mut changes);

    let document = serde_json::to_value(&policy).map_err(|_| ConversionError::Encoding)?;
    let bytes =
        serde_json::to_vec(&ConvertedDocument(&document)).map_err(|_| ConversionError::Encoding)?;
    let readback = inspect_source(&bytes);
    if !readback.is_valid() {
        inspection.refuse_with_errors_of(&readback);
        return Err(ConversionError::Refused(Box::new(inspection)));
    }
    let (Some(read_policy), Some(semantic_digest)) =
        (readback.policy(), readback.semantic_digest())
    else {
        return Err(ConversionError::ParityViolated);
    };
    if *read_policy != policy
        || without_conversion_ids(read_policy, &source_policy) != source_policy
    {
        return Err(ConversionError::ParityViolated);
    }

    Ok(PolicyConversion {
        source_schema_version: source_policy.schema_version,
        source_digest,
        semantic_digest: semantic_digest.to_owned(),
        changes,
        document,
    })
}

/// Whether `pointer` locates one of `roots` or something inside one.
fn is_within_any(pointer: &str, roots: &[String]) -> bool {
    roots.iter().any(|root| {
        pointer
            .strip_prefix(root.as_str())
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
    })
}

/// Gives every rule, route and rate override its v1 id, by the rules in the
/// module documentation, recording each id written.
fn assign_ids(policy: &mut Policy, changes: &mut Vec<ConversionChange>) {
    let mut taken = HashSet::new();
    let mut replaced = Vec::new();
    for (index, rule) in policy.rules.iter_mut().enumerate() {
        let effective = rule.id.clone().unwrap_or_else(|| index.to_string());
        if is_valid_element_id(&effective) && taken.insert(effective.clone()) {
            if rule.id.is_none() {
                changes.push(ConversionChange::with_id(
                    ChangeCode::RuleIdWritten,
                    format!("/rules/{index}/id"),
                    effective.clone(),
                ));
                rule.id = Some(effective);
            }
        } else {
            replaced.push((index, effective));
        }
    }

    // Generated ids in section order: routes, then the rules whose id could
    // not be kept, then rate overrides.
    for (index, route) in policy.routes.iter_mut().enumerate() {
        let id = unique_id(&format!("route-{index}"), &mut taken);
        changes.push(ConversionChange::with_id(
            ChangeCode::ElementIdAssigned,
            format!("/routes/{index}/id"),
            id.clone(),
        ));
        route.id = Some(id);
    }
    for (index, previous) in replaced {
        let Some(rule) = policy.rules.get_mut(index) else {
            continue;
        };
        let id = unique_id(&format!("rule-{index}"), &mut taken);
        changes.push(ConversionChange {
            previous_id: Some(previous),
            ..ConversionChange::with_id(
                ChangeCode::RuleIdReplaced,
                format!("/rules/{index}/id"),
                id.clone(),
            )
        });
        rule.id = Some(id);
    }
    for (index, limit) in policy.rate_limits.iter_mut().enumerate() {
        let id = unique_id(&format!("rate-limit-{index}"), &mut taken);
        changes.push(ConversionChange::with_id(
            ChangeCode::ElementIdAssigned,
            format!("/rate_limits/{index}/id"),
            id.clone(),
        ));
        limit.id = Some(id);
    }
}

/// `base`, or `base-K` for the smallest `K` from 2 that no element has yet,
/// and claims it. Each element claims one id, so the search ends within one
/// more step than there are elements.
fn unique_id(base: &str, taken: &mut HashSet<String>) -> String {
    if taken.insert(base.to_owned()) {
        return base.to_owned();
    }
    let mut suffix = 2_usize;
    loop {
        let candidate = format!("{base}-{suffix}");
        if taken.insert(candidate.clone()) {
            return candidate;
        }
        suffix += 1;
    }
}

/// `converted` with the version and rule ids of `source` and no route or
/// rate override ids: what is left when everything the conversion wrote is
/// taken out again.
fn without_conversion_ids(converted: &Policy, source: &Policy) -> Policy {
    let mut projected = converted.clone();
    projected.schema_version = source.schema_version.clone();
    for (rule, original) in projected.rules.iter_mut().zip(&source.rules) {
        rule.id = original.id.clone();
    }
    for route in &mut projected.routes {
        route.id = None;
    }
    for limit in &mut projected.rate_limits {
        limit.id = None;
    }
    projected
}

/// A converted v1 document. It serializes every object's members in the
/// order the policy defines them, the order the gateway writes them in, and
/// every map by name, so a document has one byte sequence for one policy.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ConvertedDocument<'a>(&'a Value);

impl Serialize for ConvertedDocument<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        Ordered {
            value: self.0,
            at: Location::Document,
        }
        .serialize(serializer)
    }
}

/// Where a value sits in a v1 document, which fixes its members' order.
#[derive(Clone, Copy)]
enum Location {
    Document,
    Roles,
    RoleEntry,
    Routes,
    Route,
    Rules,
    Rule,
    Principal,
    Dispatch,
    Egress,
    RateLimits,
    RateLimit,
    Tools,
    ToolEntry,
    Value,
}

impl Location {
    /// The members written first, in this order. Any other member follows,
    /// by name; none exists in a document the v1 reader accepts.
    fn member_order(self) -> &'static [&'static str] {
        match self {
            Self::Document => KNOWN_TOP_LEVEL_KEYS,
            Self::RoleEntry => ROLE_MEMBERS.allowed,
            Self::Route => ROUTE_MEMBERS.allowed,
            Self::Rule => RULE_MEMBERS.allowed,
            Self::Principal => PRINCIPAL_MEMBERS.allowed,
            Self::Dispatch => DISPATCH_MEMBERS.allowed,
            Self::Egress => EGRESS_MEMBERS.allowed,
            Self::RateLimit => RATE_LIMIT_MEMBERS.allowed,
            Self::ToolEntry => TOOL_MEMBERS.allowed,
            Self::Roles
            | Self::Routes
            | Self::Rules
            | Self::RateLimits
            | Self::Tools
            | Self::Value => &[],
        }
    }

    /// Where the member `name` of an object here sits.
    fn member(self, name: &str) -> Self {
        match (self, name) {
            (Self::Document, "roles") => Self::Roles,
            (Self::Document, "routes") => Self::Routes,
            (Self::Document, "rules") => Self::Rules,
            (Self::Document, "egress") => Self::Egress,
            (Self::Document, "rate_limits") => Self::RateLimits,
            (Self::Document, "tools") => Self::Tools,
            (Self::Roles, _) => Self::RoleEntry,
            (Self::Tools, _) => Self::ToolEntry,
            (Self::Rule | Self::RateLimit, "principal") => Self::Principal,
            (Self::Rule, "dispatch") => Self::Dispatch,
            _ => Self::Value,
        }
    }

    /// Where an element of an array here sits.
    fn element(self) -> Self {
        match self {
            Self::Routes => Self::Route,
            Self::Rules => Self::Rule,
            Self::RateLimits => Self::RateLimit,
            _ => Self::Value,
        }
    }
}

struct Ordered<'a> {
    value: &'a Value,
    at: Location,
}

impl Serialize for Ordered<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.value {
            Value::Object(object) => {
                let mut map = serializer.serialize_map(Some(object.len()))?;
                for (name, member) in ordered_members(object, self.at.member_order()) {
                    map.serialize_entry(
                        name,
                        &Ordered {
                            value: member,
                            at: self.at.member(name),
                        },
                    )?;
                }
                map.end()
            }
            Value::Array(items) => {
                let mut sequence = serializer.serialize_seq(Some(items.len()))?;
                for item in items {
                    sequence.serialize_element(&Ordered {
                        value: item,
                        at: self.at.element(),
                    })?;
                }
                sequence.end()
            }
            scalar => scalar.serialize(serializer),
        }
    }
}

/// `object`'s members: those `order` names first, in that order, then the
/// rest by name.
fn ordered_members<'a>(
    object: &'a Map<String, Value>,
    order: &'static [&'static str],
) -> Vec<(&'a str, &'a Value)> {
    let mut members: Vec<(&str, &Value)> = order
        .iter()
        .filter_map(|name| object.get_key_value(*name))
        .map(|(name, value)| (name.as_str(), value))
        .collect();
    let mut rest: Vec<(&str, &Value)> = object
        .iter()
        .filter(|(name, _)| !order.contains(&name.as_str()))
        .map(|(name, value)| (name.as_str(), value))
        .collect();
    rest.sort_by(|left, right| left.0.cmp(right.0));
    members.extend(rest);
    members
}

#[cfg(test)]
#[path = "policy_conversion_tests.rs"]
mod tests;
