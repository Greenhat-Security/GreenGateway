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
//!
//! ## Where each half lives
//!
//! This module is the condition model and its validation, which the policy's
//! validating parse runs and `ggctl` shares (issue #242). Evaluation -- the
//! facts, the three-valued answer (a fact the caller never captured is
//! unknown, never a guessed no-match) and the compiled tree -- reads an
//! authenticated principal, so it is the gateway's
//! (`gateway/src/rbac/conditions.rs`).

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use super::policy_document::{IssueCode, PolicyIssue};
use crate::auth::{
    canonical_issuer, is_scope_token, is_verified_claim_text, verified_claim_name_problem,
    MAX_PRINCIPAL_ISSUER_BYTES, MAX_PRINCIPAL_SCOPE_BYTES, MAX_VERIFIED_CLAIM_NAME_BYTES,
    MAX_VERIFIED_CLAIM_VALUE_BYTES,
};

/// Deepest a condition tree may nest; the root node is depth 1.
pub const MAX_CONDITION_DEPTH: usize = 4;
/// Most nodes, combinators and leaves together, one rule's tree may hold.
pub const MAX_CONDITION_NODES: usize = 32;
/// Most operands one `all` or `any` may list.
pub const MAX_CONDITION_BRANCHES: usize = 16;
/// Most values one leaf may list.
pub const MAX_CONDITION_VALUES: usize = 32;
/// Longest value, in bytes, a leaf may list.
pub const MAX_CONDITION_VALUE_BYTES: usize = 256;
/// Longest header or query parameter name, in bytes.
pub const MAX_CONDITION_NAME_BYTES: usize = 128;
/// Longest tool-argument pointer, in bytes.
pub const MAX_TOOL_ARGUMENT_POINTER_BYTES: usize = 256;
/// Most reference tokens a tool-argument pointer may have.
pub const MAX_TOOL_ARGUMENT_POINTER_TOKENS: usize = 8;

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
pub enum ConditionTarget {
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
pub fn header_name_is_readable(name: &str) -> bool {
    !FORBIDDEN_HEADER_NAMES.contains(&name)
        && !FORBIDDEN_HEADER_PREFIXES
            .iter()
            .any(|prefix| name.starts_with(prefix))
        && !FORBIDDEN_HEADER_FRAGMENTS
            .iter()
            .any(|fragment| name.contains(fragment))
}

/// Whether a condition may read the query parameter `name`.
pub fn query_name_is_readable(name: &str) -> bool {
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
    pub fn tool_argument_leaves<'a>(&'a self, location: &str, leaves: &mut Vec<(String, &'a str)>) {
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
    pub fn for_each_claim(&self, pointer: &str, visit: &mut impl FnMut(&ClaimCondition, String)) {
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

/// Canonicalizes the issuers a condition binds, as role and rule issuers are.
pub fn canonicalize_condition_issuers(condition: &mut Condition) {
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
pub fn validate_condition(
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

pub fn is_bounded_text(value: &str, max_bytes: usize, allow_empty: bool) -> bool {
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
pub fn tool_argument_pointer_eligible(schema: &Value, pointer: &str) -> bool {
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
pub fn parse_utc_instant(value: &str) -> Option<i64> {
    let bytes = value.as_bytes();
    if bytes.len() != 20 || bytes[10] != b'T' || bytes[19] != b'Z' {
        return None;
    }
    OffsetDateTime::parse(value, &Rfc3339)
        .ok()
        .map(OffsetDateTime::unix_timestamp)
}
