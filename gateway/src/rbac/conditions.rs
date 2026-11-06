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

use std::collections::BTreeMap;
use std::net::IpAddr;

use ipnet::IpNet;
use serde_json::Value;

pub use gateway_config::rbac::conditions::*;

use crate::auth::{principal::canonical_issuer, Principal, VerifiedClaim};

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
