//! Evaluating typed rule conditions for policy v1 (issue #243, checklist
//! item 16).
//!
//! The condition model and its validation are
//! `gateway_config::rbac::conditions` (issue #242), re-exported here so call
//! sites keep their paths; that module's documentation describes what a
//! condition may read. This module is the evaluation the kernel runs: the
//! facts a lane captured, the three-valued answer and the condition tree
//! compiled once per policy snapshot.
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

use std::net::IpAddr;

use ipnet::IpNet;
use serde_json::Value;

pub use gateway_config::rbac::conditions::*;

use crate::auth::{principal::canonical_issuer, Principal};

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
    /// The canonical client address after trusted-proxy processing.
    pub(crate) source_ip: Fact<IpAddr>,
    /// Request header field lines, one entry per occurrence, as received.
    pub(crate) headers: Fact<Vec<(String, String)>>,
    /// Decoded query parameters, one entry per occurrence, in request order.
    pub(crate) query: Fact<Vec<(String, String)>>,
    /// The tool call's schema-validated arguments, secret-marked fields
    /// already removed.
    pub(crate) tool_arguments: Fact<Value>,
    /// The evaluation instant, in whole seconds since the Unix epoch.
    pub(crate) now: Fact<i64>,
}

impl PolicyFacts {
    /// Facts of which none was captured.
    pub(crate) const fn uncaptured() -> Self {
        Self {
            organization: Fact::Uncaptured,
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
                let bound = principal
                    .is_some_and(|principal| principal.issuer.as_deref() == Some(issuer.as_str()));
                if !bound {
                    return Truth::False;
                }
                match &facts.organization {
                    Fact::Uncaptured => Truth::Unknown,
                    Fact::Captured(None) => Truth::False,
                    Fact::Captured(Some(organization)) => Truth::of(values.contains(organization)),
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

/// Scalar equality for a tool argument: strings and booleans exactly,
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
