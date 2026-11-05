//! Typed rule conditions for policy v1 (issue #243, checklist item 16).
//!
//! A direct rule in a policy v1 document may carry `conditions`: a small
//! typed tree over facts that the request, the principal or the tool call
//! carries. It is deliberately not a language. A node is exactly one of a
//! fixed set of operators -- `all`, `any` and `not` over other nodes, or one
//! leaf -- with bounded depth, node count, list length and string size, so a
//! condition cannot grow into a script, a regular expression or a remote
//! lookup, and the work one costs is known before it runs.
//!
//! ## Three answers, not two
//!
//! A leaf reads one fact. A fact the caller captured is answered: a header the
//! request did not carry is simply not there, so a leaf that requires it does
//! not match. A fact the caller never captured is a different input -- a
//! replayed request whose headers were not retained, say -- and a leaf that
//! reads it is [`Truth::Unknown`], never a guessed no-match. The combinators
//! use Kleene logic: `all` is false as soon as one operand is, `any` true as
//! soon as one is, and otherwise an unknown operand keeps the node unknown;
//! `not` leaves unknown unknown. The kernel turns an unknown rule into an
//! indeterminate decision, never an allow.
//!
//! ## What the leaves may read
//!
//! - `organization`: the organization authentication verified for the
//!   principal, bound to the issuer that verified it.
//! - `scope`: the OAuth scopes the principal's verified `scope` or `scp`
//!   claim granted, bound to the issuer that verified them.
//! - `claim`: one claim the issuer's JWT provider allowlists in
//!   `verified_claims`, as its validation verified it, bound to that issuer.
//! - `source_network`: the canonical client address the gateway derived after
//!   trusted-proxy processing, never a forwarding header.
//! - `header` and `query`: one named request header or decoded query
//!   parameter, from an explicit name the gateway checks is not one that can
//!   carry credentials, identity or hop-by-hop routing.
//! - `tool_argument`: one scalar of a tool call's schema-validated arguments,
//!   by bounded JSON Pointer, and only one the tool's input schema makes
//!   eligible ([`tool_argument_pointer_eligible`]).
//! - `time_window`: a half-open UTC interval over an injected clock.
//!
//! An HTTP path rule may read every leaf but `tool_argument`; a tool-name rule
//! every leaf but `header` and `query`. Validation refuses the rest, so a leaf
//! never sits where its fact cannot exist.
//!
//! The identity leaves -- `organization`, `scope` and `claim` -- read what
//! authentication verified for the principal, never a request header, and
//! are issuer-bound: a principal another issuer authenticated does not match,
//! whatever it carries. A scope or claim the principal's authentication did
//! not capture -- a method that verifies none, a claim its provider does not
//! allowlist, a value past the capture bounds -- is unknown, never absent.
//!
//! ## Which tool arguments a leaf may read
//!
//! A `tool_argument` pointer is eligible for a tool only when it resolves
//! through the tool's input schema by declared `properties` alone: every
//! schema it passes through has `"type": "object"` and declares the next
//! token under `properties`, and the schema it ends at has a `type` of
//! exactly `"string"`, `"integer"`, `"number"` or `"boolean"`. No schema on
//! the way may be `writeOnly` (anything but `false`), have `format`
//! `"password"`, or compose or reference others (`$ref`, `$dynamicRef`,
//! `allOf`, `anyOf`, `oneOf`, `not`, `if`, `then`, `else`,
//! `dependentSchemas`, `patternProperties`), since a schema elsewhere could
//! then mark the field secret or widen what it accepts. Anything else -- an
//! array index, an undeclared or additional property, a `$ref` -- is
//! ineligible. Publication refuses a rule that reads an ineligible pointer of
//! a registered tool (`condition_pointer_ineligible`), and a tool lane whose
//! tool's schema has since made one ineligible captures no arguments at all,
//! so a rule that reads them is undetermined and refused rather than decided
//! without a value the schema calls secret.

use std::collections::BTreeMap;
use std::net::IpAddr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use super::policy_document::{IssueCode, PolicyIssue};
use crate::auth::{
    claims::{is_scope_token, is_verified_claim_text, verified_claim_name_problem},
    principal::{
        canonical_issuer, MAX_PRINCIPAL_ISSUER_BYTES, MAX_PRINCIPAL_SCOPE_BYTES,
        MAX_VERIFIED_CLAIM_NAME_BYTES, MAX_VERIFIED_CLAIM_VALUE_BYTES,
    },
    Principal, VerifiedClaim,
};

/// Deepest a condition tree may nest; the root node is depth 1.
pub(crate) const MAX_CONDITION_DEPTH: usize = 4;
/// Most nodes, combinators and leaves together, one rule's tree may hold.
pub(crate) const MAX_CONDITION_NODES: usize = 32;
/// Most operands one `all` or `any` may list.
pub(crate) const MAX_CONDITION_BRANCHES: usize = 16;
/// Most values one leaf may list.
pub(crate) const MAX_CONDITION_VALUES: usize = 32;
/// Longest value, in bytes, a leaf may list.
pub(crate) const MAX_CONDITION_VALUE_BYTES: usize = 256;
/// Longest header or query parameter name, in bytes.
pub(crate) const MAX_CONDITION_NAME_BYTES: usize = 128;
/// Longest tool-argument pointer, in bytes.
pub(crate) const MAX_TOOL_ARGUMENT_POINTER_BYTES: usize = 256;
/// Most reference tokens a tool-argument pointer may have.
pub(crate) const MAX_TOOL_ARGUMENT_POINTER_TOKENS: usize = 8;

/// One node of a rule's condition tree: exactly one operator.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Condition {
    /// Every operand holds.
    All(Vec<Condition>),
    /// At least one operand holds.
    Any(Vec<Condition>),
    /// The operand does not hold.
    Not(Box<Condition>),
    Organization(OrganizationCondition),
    Scope(ScopeCondition),
    Claim(ClaimCondition),
    SourceNetwork(SourceNetworkCondition),
    Header(HeaderCondition),
    Query(QueryCondition),
    ToolArgument(ToolArgumentCondition),
    TimeWindow(TimeWindowCondition),
}

/// The principal was authenticated by exactly `issuer` and its verified
/// organization is one of `values`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationCondition {
    pub issuer: String,
    #[serde(rename = "in")]
    pub values: Vec<String>,
}

/// The principal was authenticated by exactly `issuer` and one of its
/// verified OAuth scopes is one of `values`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeCondition {
    pub issuer: String,
    #[serde(rename = "in")]
    pub values: Vec<String>,
}

/// The principal was authenticated by exactly `issuer` and some value of its
/// verified claim `name` -- a claim that issuer's JWT provider allowlists --
/// equals one of `values`: strings and booleans exactly, numbers by value.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimCondition {
    pub issuer: String,
    pub name: String,
    #[serde(rename = "in")]
    pub values: Vec<Value>,
}

/// The canonical client address lies in one of `cidrs`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceNetworkCondition {
    pub cidrs: Vec<String>,
}

/// Some occurrence of the request header `name` is exactly one of `values`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderCondition {
    pub name: String,
    #[serde(rename = "in")]
    pub values: Vec<String>,
}

/// Some occurrence of the decoded query parameter `name` is exactly one of
/// `values`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QueryCondition {
    pub name: String,
    #[serde(rename = "in")]
    pub values: Vec<String>,
}

/// The validated tool argument at `pointer` is a scalar equal to one of
/// `values`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ToolArgumentCondition {
    pub pointer: String,
    #[serde(rename = "in")]
    pub values: Vec<Value>,
}

/// The evaluation time lies in `[from, until)`, both RFC 3339 UTC instants.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TimeWindowCondition {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<String>,
}

/// The kind of rule a condition belongs to, which decides the leaves it may
/// use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConditionTarget {
    HttpPath,
    ToolName,
}

/// Exact header names no condition may read: credentials, the request's
/// routing identity, and hop-by-hop or forwarding fields a client or an
/// intermediary controls.
const FORBIDDEN_HEADER_NAMES: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "host",
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "forwarded",
    "via",
    "true-client-ip",
    "cf-connecting-ip",
];

/// Header name prefixes no condition may read: forwarding and rewriting
/// fields, which only a trusted proxy may set and the gateway already folds
/// into the facts it derives.
const FORBIDDEN_HEADER_PREFIXES: &[&str] = &["x-forwarded-", "proxy-", "x-original-", "x-rewrite-"];

/// Fragments that mark a header name as one that can carry a credential or
/// an identity. Conservative on purpose: a header an authentication boundary
/// produces is a claim about identity, and identity is read from the verified
/// principal, never from an inbound header.
const FORBIDDEN_HEADER_FRAGMENTS: &[&str] = &[
    "auth",
    "token",
    "secret",
    "passw",
    "cookie",
    "session",
    "credential",
    "key",
    "signature",
    "jwt",
    "csrf",
    "xsrf",
    "user",
    "email",
    "identity",
    "principal",
    "subject",
    "account",
    "role",
    "group",
    "tenant",
    "organization",
    "org-id",
    "real-ip",
    "client-ip",
    "client-cert",
    "remote-",
    "ssl-",
    "tls-",
];

/// Query parameter names no condition may read, compared ASCII
/// case-insensitively: the OAuth parameters that carry or bind a credential.
const FORBIDDEN_QUERY_NAMES: &[&str] = &["code", "state", "sig"];

/// Fragments that mark a query parameter name as one that can carry a
/// credential.
const FORBIDDEN_QUERY_FRAGMENTS: &[&str] = &[
    "auth",
    "token",
    "secret",
    "passw",
    "cookie",
    "session",
    "credential",
    "key",
    "signature",
    "jwt",
    "csrf",
    "xsrf",
];

/// Whether a condition may read the header `name` (already lowercase).
pub(crate) fn header_name_is_readable(name: &str) -> bool {
    !FORBIDDEN_HEADER_NAMES.contains(&name)
        && !FORBIDDEN_HEADER_PREFIXES
            .iter()
            .any(|prefix| name.starts_with(prefix))
        && !FORBIDDEN_HEADER_FRAGMENTS
            .iter()
            .any(|fragment| name.contains(fragment))
}

/// Whether a condition may read the query parameter `name`.
pub(crate) fn query_name_is_readable(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    !FORBIDDEN_QUERY_NAMES.contains(&name.as_str())
        && !FORBIDDEN_QUERY_FRAGMENTS
            .iter()
            .any(|fragment| name.contains(fragment))
}

impl Condition {
    /// Every `tool_argument` leaf of the tree, in document order: the RFC
    /// 6901 location of its `pointer` member below `location`, the tree's own
    /// location (`/rules/{index}/conditions`), and the argument pointer it
    /// reads.
    pub(crate) fn tool_argument_leaves<'a>(
        &'a self,
        location: &str,
        leaves: &mut Vec<(String, &'a str)>,
    ) {
        match self {
            Self::All(operands) | Self::Any(operands) => {
                let operator = if matches!(self, Self::All(_)) {
                    "all"
                } else {
                    "any"
                };
                for (index, operand) in operands.iter().enumerate() {
                    operand.tool_argument_leaves(&format!("{location}/{operator}/{index}"), leaves);
                }
            }
            Self::Not(operand) => operand.tool_argument_leaves(&format!("{location}/not"), leaves),
            Self::ToolArgument(leaf) => leaves.push((
                format!("{location}/tool_argument/pointer"),
                leaf.pointer.as_str(),
            )),
            Self::Organization(_)
            | Self::Scope(_)
            | Self::Claim(_)
            | Self::SourceNetwork(_)
            | Self::Header(_)
            | Self::Query(_)
            | Self::TimeWindow(_) => {}
        }
    }

    /// Calls `visit` with every `claim` leaf of the tree and the JSON Pointer
    /// to it, `pointer` being the tree's own, in document order.
    pub(crate) fn for_each_claim(
        &self,
        pointer: &str,
        visit: &mut impl FnMut(&ClaimCondition, String),
    ) {
        match self {
            Self::All(operands) | Self::Any(operands) => {
                let operator = if matches!(self, Self::All(_)) {
                    "all"
                } else {
                    "any"
                };
                for (index, operand) in operands.iter().enumerate() {
                    operand.for_each_claim(&format!("{pointer}/{operator}/{index}"), visit);
                }
            }
            Self::Not(operand) => operand.for_each_claim(&format!("{pointer}/not"), visit),
            Self::Claim(leaf) => visit(leaf, format!("{pointer}/claim")),
            Self::Organization(_)
            | Self::Scope(_)
            | Self::SourceNetwork(_)
            | Self::Header(_)
            | Self::Query(_)
            | Self::ToolArgument(_)
            | Self::TimeWindow(_) => {}
        }
    }
}

/// The facts a policy's typed matchers can read, so that a serving lane
/// captures exactly those and nothing else: nothing at all for a policy with
/// neither identity mappings nor rule conditions, which therefore decides,
/// allocates and binds exactly as one did before conditions were served.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct FactNeeds {
    /// An identity mapping or an `organization` leaf reads the organization
    /// authentication verified for the principal.
    pub(crate) organization: bool,
    /// A `scope` leaf, or an identity mapping that lists `scopes`, reads the
    /// principal's verified OAuth scopes.
    pub(crate) scopes: bool,
    /// The claim names `claim` leaves read, sorted and unique. A lane copies
    /// these verified claims and no others.
    pub(crate) claims: Vec<String>,
    /// A `source_network` leaf reads the canonical client address.
    pub(crate) source_ip: bool,
    /// The header names `header` leaves read: lowercase, sorted and unique.
    /// A lane copies these headers and no others.
    pub(crate) headers: Vec<String>,
    /// The query parameter names `query` leaves read, sorted and unique.
    pub(crate) query: Vec<String>,
    /// The argument pointers `tool_argument` leaves read, by the tool their
    /// tool-name rule names, each list sorted and unique. A tool lane
    /// validates a call's arguments before it decides a rule that reads one,
    /// and captures the values at these pointers and no others.
    pub(crate) tool_arguments: BTreeMap<String, Vec<String>>,
    /// A `time_window` leaf reads the evaluation instant.
    pub(crate) now: bool,
}

impl FactNeeds {
    /// What the conditions of `rules`, and the identity mappings of a policy
    /// in mapped-role mode, read.
    pub(crate) fn of(
        rules: &[super::rule::Rule],
        identity_mappings: Option<&[super::identity_mappings::IdentityMapping]>,
    ) -> Self {
        let mut needs = Self {
            organization: identity_mappings.is_some(),
            scopes: identity_mappings
                .is_some_and(|mappings| mappings.iter().any(|mapping| !mapping.scopes.is_empty())),
            ..Self::default()
        };
        for rule in rules {
            if let Some(conditions) = &rule.conditions {
                needs.add(conditions, rule.tool_name.as_deref());
            }
        }
        for names in [&mut needs.headers, &mut needs.query, &mut needs.claims] {
            names.sort_unstable();
            names.dedup();
        }
        for pointers in needs.tool_arguments.values_mut() {
            pointers.sort_unstable();
            pointers.dedup();
        }
        needs
    }

    /// `tool_name` is the tool the condition's rule names. Validation admits
    /// a `tool_argument` leaf only in a tool-name rule, so one anywhere else
    /// -- only in a policy assembled in memory -- reads nothing a lane
    /// captures, and stays undetermined.
    fn add(&mut self, condition: &Condition, tool_name: Option<&str>) {
        match condition {
            Condition::All(operands) | Condition::Any(operands) => {
                for operand in operands {
                    self.add(operand, tool_name);
                }
            }
            Condition::Not(operand) => self.add(operand, tool_name),
            Condition::Organization(_) => self.organization = true,
            Condition::Scope(_) => self.scopes = true,
            Condition::Claim(leaf) => self.claims.push(leaf.name.clone()),
            Condition::SourceNetwork(_) => self.source_ip = true,
            Condition::Header(leaf) => self.headers.push(leaf.name.to_ascii_lowercase()),
            Condition::Query(leaf) => self.query.push(leaf.name.clone()),
            Condition::ToolArgument(leaf) => {
                if let Some(tool_name) = tool_name {
                    self.tool_arguments
                        .entry(tool_name.to_owned())
                        .or_default()
                        .push(leaf.pointer.clone());
                }
            }
            Condition::TimeWindow(_) => self.now = true,
        }
    }

    /// The argument pointers the tool-name rules for `tool_name` read, sorted
    /// and unique. Empty when none reads one, so a call to that tool is
    /// decided exactly as it was before arguments were served.
    pub(crate) fn tool_argument_pointers(&self, tool_name: &str) -> &[String] {
        self.tool_arguments
            .get(tool_name)
            .map_or(&[], Vec::as_slice)
    }

    /// Whether a request fact -- anything beyond the organization, scopes and
    /// claims, which a lane reads from the principal -- is read at all.
    pub(crate) fn reads_request_facts(&self) -> bool {
        self.source_ip
            || !self.headers.is_empty()
            || !self.query.is_empty()
            || !self.tool_arguments.is_empty()
            || self.now
    }
}

/// Canonicalizes the issuers a condition binds, as role and rule issuers are.
pub(crate) fn canonicalize_condition_issuers(condition: &mut Condition) {
    match condition {
        Condition::All(operands) | Condition::Any(operands) => {
            for operand in operands {
                canonicalize_condition_issuers(operand);
            }
        }
        Condition::Not(operand) => canonicalize_condition_issuers(operand),
        Condition::Organization(leaf) => {
            leaf.issuer = canonical_issuer(&leaf.issuer).unwrap_or_default();
        }
        Condition::Scope(leaf) => {
            leaf.issuer = canonical_issuer(&leaf.issuer).unwrap_or_default();
        }
        Condition::Claim(leaf) => {
            leaf.issuer = canonical_issuer(&leaf.issuer).unwrap_or_default();
        }
        Condition::SourceNetwork(_)
        | Condition::Header(_)
        | Condition::Query(_)
        | Condition::ToolArgument(_)
        | Condition::TimeWindow(_) => {}
    }
}

/// Validates a rule's condition tree, stopping at the first problem as the
/// rest of the semantic validation does. `pointer` locates the tree itself
/// (`/rules/{index}/conditions`); `field_path` names it in the detail.
pub(crate) fn validate_condition(
    condition: &Condition,
    target: ConditionTarget,
    pointer: &str,
    field_path: &str,
) -> Result<(), PolicyIssue> {
    let mut nodes = 0;
    validate_node(condition, target, pointer, field_path, 1, &mut nodes)
}

fn validate_node(
    condition: &Condition,
    target: ConditionTarget,
    pointer: &str,
    field_path: &str,
    depth: usize,
    nodes: &mut usize,
) -> Result<(), PolicyIssue> {
    *nodes += 1;
    if depth > MAX_CONDITION_DEPTH || *nodes > MAX_CONDITION_NODES {
        return Err(PolicyIssue::new(
            IssueCode::ConditionTooComplex,
            pointer.to_owned(),
            format!(
                "{field_path} nests deeper than {MAX_CONDITION_DEPTH} levels or holds more than \
                 {MAX_CONDITION_NODES} nodes"
            ),
        ));
    }
    match condition {
        Condition::All(operands) | Condition::Any(operands) => {
            let operator = if matches!(condition, Condition::All(_)) {
                "all"
            } else {
                "any"
            };
            let pointer = format!("{pointer}/{operator}");
            if operands.is_empty() {
                return Err(PolicyIssue::new(
                    IssueCode::ConditionValueInvalid,
                    pointer,
                    format!("{field_path}.{operator} must list at least one condition"),
                ));
            }
            if operands.len() > MAX_CONDITION_BRANCHES {
                return Err(PolicyIssue::new(
                    IssueCode::ConditionTooComplex,
                    pointer,
                    format!(
                        "{field_path}.{operator} must list at most {MAX_CONDITION_BRANCHES} \
                         conditions"
                    ),
                ));
            }
            for (index, operand) in operands.iter().enumerate() {
                validate_node(
                    operand,
                    target,
                    &format!("{pointer}/{index}"),
                    &format!("{field_path}.{operator}[{index}]"),
                    depth + 1,
                    nodes,
                )?;
            }
            Ok(())
        }
        Condition::Not(operand) => validate_node(
            operand,
            target,
            &format!("{pointer}/not"),
            &format!("{field_path}.not"),
            depth + 1,
            nodes,
        ),
        Condition::Organization(leaf) => {
            let pointer = format!("{pointer}/organization");
            let field_path = format!("{field_path}.organization");
            validate_issuer(&leaf.issuer, &pointer, &field_path)?;
            validate_text_values(&leaf.values, &pointer, &field_path, false)
        }
        Condition::Scope(leaf) => {
            let pointer = format!("{pointer}/scope");
            let field_path = format!("{field_path}.scope");
            validate_issuer(&leaf.issuer, &pointer, &field_path)?;
            validate_value_count(leaf.values.len(), &format!("{pointer}/in"), &field_path)?;
            for (index, value) in leaf.values.iter().enumerate() {
                if !is_scope_token(value) {
                    return Err(value_issue(
                        format!("{pointer}/in/{index}"),
                        format!(
                            "{field_path}.in[{index}] must be an OAuth scope token: 1 to \
                             {MAX_PRINCIPAL_SCOPE_BYTES} bytes of visible ASCII without a space, \
                             a quote or a backslash"
                        ),
                    ));
                }
            }
            Ok(())
        }
        Condition::Claim(leaf) => {
            let pointer = format!("{pointer}/claim");
            let field_path = format!("{field_path}.claim");
            validate_issuer(&leaf.issuer, &pointer, &field_path)?;
            if let Some(problem) = verified_claim_name_problem(&leaf.name) {
                // A malformed name is a value problem; a well-formed one that
                // names an identity, scope, email or credential claim is a
                // name no condition may read.
                let malformed = leaf.name.is_empty()
                    || leaf.name.len() > MAX_VERIFIED_CLAIM_NAME_BYTES
                    || leaf.name.chars().any(char::is_control)
                    || leaf.name.trim() != leaf.name;
                return Err(PolicyIssue::new(
                    if malformed {
                        IssueCode::ConditionValueInvalid
                    } else {
                        IssueCode::ConditionNameForbidden
                    },
                    format!("{pointer}/name"),
                    format!("{field_path}.name {problem}"),
                ));
            }
            validate_value_count(leaf.values.len(), &format!("{pointer}/in"), &field_path)?;
            for (index, value) in leaf.values.iter().enumerate() {
                let scalar = match value {
                    Value::String(text) => is_verified_claim_text(text),
                    Value::Bool(_) | Value::Number(_) => true,
                    Value::Null | Value::Array(_) | Value::Object(_) => false,
                };
                if !scalar {
                    return Err(value_issue(
                        format!("{pointer}/in/{index}"),
                        format!(
                            "{field_path}.in[{index}] must be a string of at most \
                             {MAX_VERIFIED_CLAIM_VALUE_BYTES} bytes without control characters, \
                             a number, or a boolean"
                        ),
                    ));
                }
            }
            Ok(())
        }
        Condition::SourceNetwork(leaf) => {
            let pointer = format!("{pointer}/source_network");
            let field_path = format!("{field_path}.source_network");
            validate_value_count(leaf.cidrs.len(), &format!("{pointer}/cidrs"), &field_path)?;
            for (index, cidr) in leaf.cidrs.iter().enumerate() {
                let canonical = cidr
                    .parse::<IpNet>()
                    .ok()
                    .filter(|network| network.trunc() == *network);
                if canonical.is_none() {
                    return Err(PolicyIssue::new(
                        IssueCode::ConditionCidrInvalid,
                        format!("{pointer}/cidrs/{index}"),
                        format!(
                            "{field_path}.cidrs[{index}] must be an IPv4 or IPv6 network address \
                             in CIDR notation, with no host bits set"
                        ),
                    ));
                }
            }
            Ok(())
        }
        Condition::Header(leaf) => {
            let pointer = format!("{pointer}/header");
            let field_path = format!("{field_path}.header");
            require_target(target, ConditionTarget::HttpPath, &pointer, &field_path)?;
            if !is_lowercase_token(&leaf.name) {
                return Err(value_issue(
                    format!("{pointer}/name"),
                    format!(
                        "{field_path}.name must be a lowercase HTTP field name of 1 to \
                         {MAX_CONDITION_NAME_BYTES} bytes"
                    ),
                ));
            }
            if !header_name_is_readable(&leaf.name) {
                return Err(PolicyIssue::new(
                    IssueCode::ConditionNameForbidden,
                    format!("{pointer}/name"),
                    format!(
                        "{field_path}.name '{}' names a header that can carry credentials, \
                         identity, or hop-by-hop routing",
                        leaf.name
                    ),
                ));
            }
            validate_value_count(leaf.values.len(), &format!("{pointer}/in"), &field_path)?;
            for (index, value) in leaf.values.iter().enumerate() {
                let printable = !value.is_empty()
                    && value.len() <= MAX_CONDITION_VALUE_BYTES
                    && value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
                    && !value.starts_with(' ')
                    && !value.ends_with(' ');
                if !printable {
                    return Err(value_issue(
                        format!("{pointer}/in/{index}"),
                        format!(
                            "{field_path}.in[{index}] must be 1 to {MAX_CONDITION_VALUE_BYTES} \
                             bytes of visible ASCII, without leading or trailing spaces"
                        ),
                    ));
                }
            }
            Ok(())
        }
        Condition::Query(leaf) => {
            let pointer = format!("{pointer}/query");
            let field_path = format!("{field_path}.query");
            require_target(target, ConditionTarget::HttpPath, &pointer, &field_path)?;
            if !is_printable_text(&leaf.name, MAX_CONDITION_NAME_BYTES) {
                return Err(value_issue(
                    format!("{pointer}/name"),
                    format!(
                        "{field_path}.name must be 1 to {MAX_CONDITION_NAME_BYTES} bytes of text \
                         without control characters"
                    ),
                ));
            }
            if !query_name_is_readable(&leaf.name) {
                return Err(PolicyIssue::new(
                    IssueCode::ConditionNameForbidden,
                    format!("{pointer}/name"),
                    format!(
                        "{field_path}.name '{}' names a query parameter that can carry a \
                         credential",
                        leaf.name
                    ),
                ));
            }
            validate_text_values(&leaf.values, &pointer, &field_path, true)
        }
        Condition::ToolArgument(leaf) => {
            let pointer = format!("{pointer}/tool_argument");
            let field_path = format!("{field_path}.tool_argument");
            require_target(target, ConditionTarget::ToolName, &pointer, &field_path)?;
            if !is_bounded_json_pointer(&leaf.pointer) {
                return Err(PolicyIssue::new(
                    IssueCode::ConditionPointerInvalid,
                    format!("{pointer}/pointer"),
                    format!(
                        "{field_path}.pointer must be a non-empty RFC 6901 JSON Pointer of at \
                         most {MAX_TOOL_ARGUMENT_POINTER_TOKENS} reference tokens and \
                         {MAX_TOOL_ARGUMENT_POINTER_BYTES} bytes"
                    ),
                ));
            }
            validate_value_count(leaf.values.len(), &format!("{pointer}/in"), &field_path)?;
            for (index, value) in leaf.values.iter().enumerate() {
                let scalar = match value {
                    Value::String(text) => is_bounded_text(text, MAX_CONDITION_VALUE_BYTES, true),
                    Value::Bool(_) | Value::Number(_) => true,
                    Value::Null | Value::Array(_) | Value::Object(_) => false,
                };
                if !scalar {
                    return Err(value_issue(
                        format!("{pointer}/in/{index}"),
                        format!(
                            "{field_path}.in[{index}] must be a string of at most \
                             {MAX_CONDITION_VALUE_BYTES} bytes without control characters, a \
                             number, or a boolean"
                        ),
                    ));
                }
            }
            Ok(())
        }
        Condition::TimeWindow(leaf) => {
            let pointer = format!("{pointer}/time_window");
            let field_path = format!("{field_path}.time_window");
            if leaf.from.is_none() && leaf.until.is_none() {
                return Err(time_issue(
                    pointer,
                    format!("{field_path} must set from, until, or both"),
                ));
            }
            let from = match leaf.from.as_deref() {
                Some(from) => Some(parse_utc_instant(from).ok_or_else(|| {
                    time_issue(
                        format!("{pointer}/from"),
                        format!("{field_path}.from must be an RFC 3339 UTC instant such as 2026-01-01T00:00:00Z"),
                    )
                })?),
                None => None,
            };
            let until = match leaf.until.as_deref() {
                Some(until) => Some(parse_utc_instant(until).ok_or_else(|| {
                    time_issue(
                        format!("{pointer}/until"),
                        format!("{field_path}.until must be an RFC 3339 UTC instant such as 2026-01-01T00:00:00Z"),
                    )
                })?),
                None => None,
            };
            if let (Some(from), Some(until)) = (from, until) {
                if from >= until {
                    return Err(time_issue(
                        format!("{pointer}/until"),
                        format!("{field_path}.until must be later than from"),
                    ));
                }
            }
            Ok(())
        }
    }
}

/// An identity leaf's issuer: present, and within the bound a principal's
/// issuer is held to.
fn validate_issuer(issuer: &str, pointer: &str, field_path: &str) -> Result<(), PolicyIssue> {
    if issuer.trim().is_empty() {
        return Err(PolicyIssue::new(
            IssueCode::IssuerEmpty,
            format!("{pointer}/issuer"),
            format!("{field_path}.issuer must not be empty"),
        ));
    }
    if issuer.len() > MAX_PRINCIPAL_ISSUER_BYTES {
        return Err(value_issue(
            format!("{pointer}/issuer"),
            format!("{field_path}.issuer must not exceed {MAX_PRINCIPAL_ISSUER_BYTES} bytes"),
        ));
    }
    Ok(())
}

fn require_target(
    target: ConditionTarget,
    required: ConditionTarget,
    pointer: &str,
    field_path: &str,
) -> Result<(), PolicyIssue> {
    if target == required {
        return Ok(());
    }
    let rule_kind = match required {
        ConditionTarget::HttpPath => "an HTTP path rule",
        ConditionTarget::ToolName => "a tool_name rule",
    };
    Err(PolicyIssue::new(
        IssueCode::ConditionNotApplicable,
        pointer.to_owned(),
        format!("{field_path} is valid only in {rule_kind}"),
    ))
}

fn validate_value_count(count: usize, pointer: &str, field_path: &str) -> Result<(), PolicyIssue> {
    if count == 0 || count > MAX_CONDITION_VALUES {
        return Err(value_issue(
            pointer.to_owned(),
            format!("{field_path} must list 1 to {MAX_CONDITION_VALUES} values"),
        ));
    }
    Ok(())
}

/// A leaf's `in` list of text values. `allow_empty` admits the empty string,
/// which a query parameter without a value decodes to.
fn validate_text_values(
    values: &[String],
    pointer: &str,
    field_path: &str,
    allow_empty: bool,
) -> Result<(), PolicyIssue> {
    validate_value_count(values.len(), &format!("{pointer}/in"), field_path)?;
    for (index, value) in values.iter().enumerate() {
        if !is_bounded_text(value, MAX_CONDITION_VALUE_BYTES, allow_empty) {
            return Err(value_issue(
                format!("{pointer}/in/{index}"),
                format!(
                    "{field_path}.in[{index}] must be at most {MAX_CONDITION_VALUE_BYTES} bytes of \
                     text without control characters{}",
                    if allow_empty { "" } else { ", and not empty" }
                ),
            ));
        }
    }
    Ok(())
}

fn value_issue(pointer: String, detail: String) -> PolicyIssue {
    PolicyIssue::new(IssueCode::ConditionValueInvalid, pointer, detail)
}

fn time_issue(pointer: String, detail: String) -> PolicyIssue {
    PolicyIssue::new(IssueCode::ConditionTimeInvalid, pointer, detail)
}

pub(crate) fn is_bounded_text(value: &str, max_bytes: usize, allow_empty: bool) -> bool {
    (allow_empty || !value.is_empty())
        && value.len() <= max_bytes
        && !value.chars().any(char::is_control)
}

fn is_printable_text(value: &str, max_bytes: usize) -> bool {
    is_bounded_text(value, max_bytes, false)
}

/// An HTTP field name (RFC 9110 `token`), lowercase, of bounded length.
fn is_lowercase_token(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_CONDITION_NAME_BYTES
        && name.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

/// A non-empty RFC 6901 pointer whose `~` escapes are all `~0` or `~1`, with
/// bounded size and token count. The empty pointer, which names the whole
/// argument object, is refused: a leaf compares one scalar.
fn is_bounded_json_pointer(pointer: &str) -> bool {
    let Some(tokens) = pointer.strip_prefix('/') else {
        return false;
    };
    if pointer.len() > MAX_TOOL_ARGUMENT_POINTER_BYTES || pointer.chars().any(char::is_control) {
        return false;
    }
    let mut count = 0;
    for token in tokens.split('/') {
        count += 1;
        let mut escapes = token.split('~');
        escapes.next();
        if escapes.any(|rest| !(rest.starts_with('0') || rest.starts_with('1'))) {
            return false;
        }
    }
    count <= MAX_TOOL_ARGUMENT_POINTER_TOKENS
}

/// Schema keywords that compose or reference other schemas. A schema on a
/// pointer's path that carries one is also judged by schemas the path does
/// not show, which could mark the field secret or widen what it accepts.
const COMPOSING_SCHEMA_KEYWORDS: &[&str] = &[
    "$ref",
    "$dynamicRef",
    "allOf",
    "anyOf",
    "oneOf",
    "not",
    "if",
    "then",
    "else",
    "dependentSchemas",
    "patternProperties",
];

/// Whether a `tool_argument` leaf may read `pointer` of a tool whose input
/// schema is `schema`: the pointer resolves through declared `properties` of
/// object schemas to a schema of one scalar `type`, and no schema on the way
/// is secret-marked or composed (see the module documentation). Every other
/// pointer is ineligible, the empty one included.
pub(crate) fn tool_argument_pointer_eligible(schema: &Value, pointer: &str) -> bool {
    let Some(tokens) = pointer.strip_prefix('/') else {
        return false;
    };
    let mut node = schema;
    for token in tokens.split('/') {
        if !plain_schema(node) || node.get("type").and_then(Value::as_str) != Some("object") {
            return false;
        }
        let token = token.replace("~1", "/").replace("~0", "~");
        match node
            .get("properties")
            .and_then(Value::as_object)
            .and_then(|properties| properties.get(&token))
        {
            Some(next) => node = next,
            None => return false,
        }
    }
    plain_schema(node)
        && matches!(
            node.get("type").and_then(Value::as_str),
            Some("string" | "integer" | "number" | "boolean")
        )
}

/// The scalars of `arguments` at `pointers`, each at the same place in a
/// fresh object, and nothing else: the argument fact a `tool_argument` leaf
/// reads. A pointer the arguments do not reach, or that reaches an array or
/// an object, contributes nothing, so a leaf over it does not match -- as a
/// leaf over an argument the call did not pass does not.
pub(crate) fn referenced_tool_arguments(arguments: &Value, pointers: &[String]) -> Value {
    let mut referenced = serde_json::Map::new();
    for pointer in pointers {
        let Some(scalar) = arguments
            .pointer(pointer)
            .filter(|value| matches!(value, Value::String(_) | Value::Number(_) | Value::Bool(_)))
        else {
            continue;
        };
        let Some(tokens) = pointer.strip_prefix('/') else {
            continue;
        };
        let tokens: Vec<String> = tokens
            .split('/')
            .map(|token| token.replace("~1", "/").replace("~0", "~"))
            .collect();
        insert_scalar(&mut referenced, &tokens, scalar);
    }
    Value::Object(referenced)
}

/// Places `scalar` at `tokens` below `object`, making the objects on the way.
/// Nothing is placed where a scalar already sits on the way, which the
/// pointer that reached `scalar` could not have walked through.
fn insert_scalar(object: &mut serde_json::Map<String, Value>, tokens: &[String], scalar: &Value) {
    match tokens {
        [] => {}
        [last] => {
            object.insert(last.clone(), scalar.clone());
        }
        [first, rest @ ..] => {
            if let Value::Object(next) = object
                .entry(first.clone())
                .or_insert_with(|| Value::Object(serde_json::Map::new()))
            {
                insert_scalar(next, rest, scalar);
            }
        }
    }
}

/// An object schema that is not secret-marked and composes no other.
fn plain_schema(node: &Value) -> bool {
    let Some(schema) = node.as_object() else {
        return false;
    };
    schema
        .get("writeOnly")
        .is_none_or(|write_only| *write_only == Value::Bool(false))
        && !schema
            .get("format")
            .and_then(Value::as_str)
            .is_some_and(|format| format.eq_ignore_ascii_case("password"))
        && !COMPOSING_SCHEMA_KEYWORDS
            .iter()
            .any(|keyword| schema.contains_key(*keyword))
}

/// Seconds since the Unix epoch of an RFC 3339 instant written in its one
/// accepted spelling: `YYYY-MM-DDTHH:MM:SSZ`, UTC, no fraction and no offset.
/// UTC has no daylight-saving transitions, so every instant has exactly one
/// spelling and every window boundary one meaning.
pub(crate) fn parse_utc_instant(value: &str) -> Option<i64> {
    let bytes = value.as_bytes();
    if bytes.len() != 20 || bytes[10] != b'T' || bytes[19] != b'Z' {
        return None;
    }
    OffsetDateTime::parse(value, &Rfc3339)
        .ok()
        .map(OffsetDateTime::unix_timestamp)
}

/// One fact a typed matcher reads, distinguishing a fact the caller never
/// captured from what it captured.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Fact<T> {
    /// Not captured: a matcher that reads it is undetermined.
    Uncaptured,
    Captured(T),
}

/// The facts a typed matcher -- a rule condition or an identity mapping --
/// may read, beside the principal and the request the evaluation context
/// already carries.
///
/// Values live here only for the duration of one evaluation. Nothing the
/// kernel returns -- no trace, reason or binding -- carries any of them.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct PolicyFacts {
    /// The organization authentication verified for the principal, if any.
    /// It is the principal's own issuer that verified it: a serving lane
    /// reads it from the authenticated principal (`Principal::org_id`), never
    /// from a request header.
    pub(crate) organization: Fact<Option<String>>,
    /// The OAuth scopes authentication verified for the principal
    /// (`Principal::scopes`), sorted and unique, and verified by the
    /// principal's own issuer like the organization. Uncaptured when the
    /// principal's authentication captured no scope fact.
    pub(crate) scopes: Fact<Vec<String>>,
    /// The verified claims (`Principal::verified_claims`) whose names a
    /// `claim` leaf reads: one entry per name authentication captured, so a
    /// name with no entry was not captured for this principal.
    pub(crate) claims: Fact<Vec<VerifiedClaim>>,
    /// The canonical client address after trusted-proxy processing.
    pub(crate) source_ip: Fact<IpAddr>,
    /// Request header field lines, one entry per occurrence, as received.
    pub(crate) headers: Fact<Vec<(String, String)>>,
    /// Decoded query parameters, one entry per occurrence, in request order.
    pub(crate) query: Fact<Vec<(String, String)>>,
    /// The tool call's schema-validated arguments, reduced to the eligible
    /// scalars the policy's `tool_argument` leaves read for that tool: every
    /// other field, a secret-marked one included, is removed before the
    /// kernel sees them (`middleware::policy_facts::tool_argument_facts`).
    pub(crate) tool_arguments: Fact<Value>,
    /// The evaluation instant, in whole seconds since the Unix epoch.
    pub(crate) now: Fact<i64>,
}

impl PolicyFacts {
    /// Facts of which none was captured.
    pub(crate) const fn uncaptured() -> Self {
        Self {
            organization: Fact::Uncaptured,
            scopes: Fact::Uncaptured,
            claims: Fact::Uncaptured,
            source_ip: Fact::Uncaptured,
            headers: Fact::Uncaptured,
            query: Fact::Uncaptured,
            tool_arguments: Fact::Uncaptured,
            now: Fact::Uncaptured,
        }
    }

    /// Whether any fact was captured.
    pub(crate) fn any_captured(&self) -> bool {
        !matches!(
            self,
            Self {
                organization: Fact::Uncaptured,
                scopes: Fact::Uncaptured,
                claims: Fact::Uncaptured,
                source_ip: Fact::Uncaptured,
                headers: Fact::Uncaptured,
                query: Fact::Uncaptured,
                tool_arguments: Fact::Uncaptured,
                now: Fact::Uncaptured,
            }
        )
    }
}

/// Facts of which none was captured, for an evaluation whose input records
/// none: historical replay, the analyzer and the rule preview, and the
/// serving lanes under a policy nothing in which reads one. A rule or mapping
/// that reads one is then undetermined, so the answer is indeterminate rather
/// than a guess.
pub(crate) static UNCAPTURED_FACTS: PolicyFacts = PolicyFacts::uncaptured();

/// A three-valued answer: whether a condition holds, does not, or cannot be
/// told from the facts captured.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Truth {
    False,
    True,
    Unknown,
}

impl Truth {
    pub(crate) fn of(value: bool) -> Self {
        if value {
            Self::True
        } else {
            Self::False
        }
    }

    fn not(self) -> Self {
        match self {
            Self::False => Self::True,
            Self::True => Self::False,
            Self::Unknown => Self::Unknown,
        }
    }

    /// Kleene conjunction of `self` with what `next` yields, which is not
    /// evaluated once the answer is false.
    pub(crate) fn and_then(self, next: impl FnOnce() -> Self) -> Self {
        match self {
            Self::False => Self::False,
            Self::True => next(),
            Self::Unknown => match next() {
                Self::False => Self::False,
                Self::True | Self::Unknown => Self::Unknown,
            },
        }
    }

    /// Kleene disjunction, the dual of [`Self::and_then`].
    pub(crate) fn or_else(self, next: impl FnOnce() -> Self) -> Self {
        match self {
            Self::True => Self::True,
            Self::False => next(),
            Self::Unknown => match next() {
                Self::True => Self::True,
                Self::False | Self::Unknown => Self::Unknown,
            },
        }
    }
}

/// A condition tree compiled once per policy snapshot.
#[derive(Debug, Clone)]
pub(crate) enum CompiledCondition {
    All(Vec<CompiledCondition>),
    Any(Vec<CompiledCondition>),
    Not(Box<CompiledCondition>),
    Organization {
        issuer: String,
        values: Vec<String>,
    },
    Scope {
        issuer: String,
        values: Vec<String>,
    },
    Claim {
        issuer: String,
        name: String,
        values: Vec<Value>,
    },
    SourceNetwork(Vec<IpNet>),
    Header {
        name: String,
        values: Vec<String>,
    },
    Query {
        name: String,
        values: Vec<String>,
    },
    ToolArgument {
        pointer: String,
        values: Vec<Value>,
    },
    TimeWindow {
        from: Option<i64>,
        until: Option<i64>,
    },
    /// A leaf whose authored value does not compile. Validation refuses
    /// every document that has one, so only a policy assembled in memory
    /// reaches it, and it is never answered: it is undetermined, which no
    /// lane acts on.
    Unusable,
}

impl CompiledCondition {
    pub(crate) fn new(condition: &Condition) -> Self {
        match condition {
            Condition::All(operands) => Self::All(operands.iter().map(Self::new).collect()),
            Condition::Any(operands) => Self::Any(operands.iter().map(Self::new).collect()),
            Condition::Not(operand) => Self::Not(Box::new(Self::new(operand))),
            Condition::Organization(leaf) => match canonical_issuer(&leaf.issuer) {
                Some(issuer) => Self::Organization {
                    issuer,
                    values: leaf.values.clone(),
                },
                None => Self::Unusable,
            },
            Condition::Scope(leaf) => match canonical_issuer(&leaf.issuer) {
                Some(issuer) => Self::Scope {
                    issuer,
                    values: leaf.values.clone(),
                },
                None => Self::Unusable,
            },
            Condition::Claim(leaf) => match canonical_issuer(&leaf.issuer) {
                Some(issuer) => Self::Claim {
                    issuer,
                    name: leaf.name.clone(),
                    values: leaf.values.clone(),
                },
                None => Self::Unusable,
            },
            Condition::SourceNetwork(leaf) => {
                let networks: Option<Vec<IpNet>> = leaf
                    .cidrs
                    .iter()
                    .map(|cidr| cidr.parse::<IpNet>().ok())
                    .collect();
                networks.map_or(Self::Unusable, Self::SourceNetwork)
            }
            Condition::Header(leaf) => Self::Header {
                name: leaf.name.to_ascii_lowercase(),
                values: leaf.values.clone(),
            },
            Condition::Query(leaf) => Self::Query {
                name: leaf.name.clone(),
                values: leaf.values.clone(),
            },
            Condition::ToolArgument(leaf) => Self::ToolArgument {
                pointer: leaf.pointer.clone(),
                values: leaf.values.clone(),
            },
            Condition::TimeWindow(leaf) => {
                let from = leaf.from.as_deref().map(parse_utc_instant);
                let until = leaf.until.as_deref().map(parse_utc_instant);
                match (from, until) {
                    (Some(None), _) | (_, Some(None)) | (None, None) => Self::Unusable,
                    (from, until) => Self::TimeWindow {
                        from: from.flatten(),
                        until: until.flatten(),
                    },
                }
            }
        }
    }

    /// Whether the condition holds for `principal` -- already the principal
    /// the lane judges -- and `facts`.
    pub(crate) fn evaluate(&self, principal: Option<&Principal>, facts: &PolicyFacts) -> Truth {
        match self {
            Self::All(operands) => operands.iter().fold(Truth::True, |truth, operand| {
                truth.and_then(|| operand.evaluate(principal, facts))
            }),
            Self::Any(operands) => operands.iter().fold(Truth::False, |truth, operand| {
                truth.or_else(|| operand.evaluate(principal, facts))
            }),
            Self::Not(operand) => operand.evaluate(principal, facts).not(),
            Self::Organization { issuer, values } => {
                // Issuer-bound: an organization another issuer verified is a
                // different organization, whatever it is called.
                if !issued_by(principal, issuer) {
                    return Truth::False;
                }
                match &facts.organization {
                    Fact::Uncaptured => Truth::Unknown,
                    Fact::Captured(None) => Truth::False,
                    Fact::Captured(Some(organization)) => Truth::of(values.contains(organization)),
                }
            }
            Self::Scope { issuer, values } => {
                // Issuer-bound as an organization is: a scope another issuer
                // granted is another issuer's scope.
                if !issued_by(principal, issuer) {
                    return Truth::False;
                }
                match &facts.scopes {
                    Fact::Uncaptured => Truth::Unknown,
                    Fact::Captured(scopes) => {
                        Truth::of(scopes.iter().any(|scope| values.contains(scope)))
                    }
                }
            }
            Self::Claim {
                issuer,
                name,
                values,
            } => {
                if !issued_by(principal, issuer) {
                    return Truth::False;
                }
                match &facts.claims {
                    Fact::Uncaptured => Truth::Unknown,
                    // A name with no entry was never captured for this
                    // principal -- its provider does not allowlist it, or its
                    // value was past the capture bounds -- so it is unknown,
                    // not absent.
                    Fact::Captured(claims) => match claims.iter().find(|claim| claim.name == *name)
                    {
                        None => Truth::Unknown,
                        Some(claim) => Truth::of(claim.values.iter().any(|actual| {
                            values.iter().any(|authored| scalar_eq(authored, actual))
                        })),
                    },
                }
            }
            Self::SourceNetwork(networks) => match facts.source_ip {
                Fact::Uncaptured => Truth::Unknown,
                Fact::Captured(address) => {
                    let address = address.to_canonical();
                    Truth::of(networks.iter().any(|network| network.contains(&address)))
                }
            },
            Self::Header { name, values } => match &facts.headers {
                Fact::Uncaptured => Truth::Unknown,
                Fact::Captured(headers) => Truth::of(headers.iter().any(|(field, value)| {
                    field.eq_ignore_ascii_case(name) && values.contains(value)
                })),
            },
            Self::Query { name, values } => match &facts.query {
                Fact::Uncaptured => Truth::Unknown,
                Fact::Captured(pairs) => Truth::of(
                    pairs
                        .iter()
                        .any(|(key, value)| key == name && values.contains(value)),
                ),
            },
            Self::ToolArgument { pointer, values } => match &facts.tool_arguments {
                Fact::Uncaptured => Truth::Unknown,
                Fact::Captured(arguments) => Truth::of(
                    arguments
                        .pointer(pointer)
                        .is_some_and(|actual| values.iter().any(|value| scalar_eq(value, actual))),
                ),
            },
            Self::TimeWindow { from, until } => match facts.now {
                Fact::Uncaptured => Truth::Unknown,
                Fact::Captured(now) => Truth::of(
                    from.is_none_or(|from| now >= from) && until.is_none_or(|until| now < until),
                ),
            },
            Self::Unusable => Truth::Unknown,
        }
    }
}

/// Whether `principal` was authenticated by exactly `issuer`, already
/// canonical on both sides. An anonymous caller was authenticated by none.
fn issued_by(principal: Option<&Principal>, issuer: &str) -> bool {
    principal.is_some_and(|principal| principal.issuer.as_deref() == Some(issuer))
}

/// Scalar equality for a tool argument or a claim: strings and booleans exactly,
/// numbers by value, so `1` and `1.0` are one number. An array or object is
/// never equal to an authored scalar.
fn scalar_eq(authored: &Value, actual: &Value) -> bool {
    match (authored, actual) {
        (Value::String(authored), Value::String(actual)) => authored == actual,
        (Value::Bool(authored), Value::Bool(actual)) => authored == actual,
        (Value::Number(authored), Value::Number(actual)) => {
            authored == actual
                || authored
                    .as_f64()
                    .zip(actual.as_f64())
                    .is_some_and(|(authored, actual)| authored == actual)
        }
        _ => false,
    }
}

#[cfg(test)]
#[path = "conditions_tests.rs"]
mod tests;
