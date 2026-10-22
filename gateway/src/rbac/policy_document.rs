//! Policy schema versions, structured diagnostics and canonical digests
//! (issue #243, checklist item 3).
//!
//! ## Two schemas, dispatched exactly
//!
//! A policy document's `schema_version` selects the rules it is read under,
//! and nothing else does:
//!
//! - Exactly `"1.0.0"` is **policy v1**. Every object's members come from a
//!   closed vocabulary, so an unknown member is an error rather than something
//!   silently dropped. Every direct rule, route and rate override carries a
//!   required `id`, unique across all three. Member names are unique in every
//!   object, no value is `null`, and every number lies in the I-JSON safe
//!   range, so the document has one reading and one RFC 8785 canonical form.
//!   No other `1.x` string is accepted: a later revision of v1 gets an exact
//!   string of its own.
//! - Any other version that starts with `0.` is **policy v0**, read exactly as
//!   before v1 existed. Unknown top-level members warn and are dropped and rule
//!   ids are optional. Routes and rate overrides carry no id at all, and a 0.x
//!   document that sets one is refused, so that a 0.x document means one thing
//!   to every gateway that accepts it.
//! - Anything else is refused.
//!
//! The two schemas share their semantics: a v1 document authorizes exactly as
//! the 0.x document with the same members would. v1 adds identity and
//! strictness, not behaviour.
//!
//! ## Diagnostics
//!
//! [`inspect_source`] reports the problems it finds in a document as
//! [`PolicyDiagnostic`]s: a stable code, a severity, an RFC 6901 JSON Pointer,
//! the stable id of the element concerned when it has one, a fixed message and
//! remediation, and which later uses the problem blocks. The message is static
//! text that never echoes a value from the document, so a diagnostic is safe
//! to record wherever its code is. The free-text detail the policy API has
//! always returned travels beside it, for the caller who sent the document.
//!
//! Structural v1 problems -- members, ids, numbers -- are reported together,
//! up to [`MAX_REPORTED_ISSUES`]. The semantic validation v1 shares with v0
//! stops at the first problem, as it always has.
//!
//! ## Digests
//!
//! A document that inspects clean gets an ADR-0004 source digest over the
//! exact bytes it was read from. A v1 document also gets a semantic digest:
//! the RFC 8785 canonical form of the gateway's own serialization of the
//! parsed policy. That serialization is v1's normalization: members the
//! gateway defaults are written or omitted the way it writes them, issuer
//! values are canonicalized and de-duplicated, and every array keeps its
//! document order. Two v1 documents with one semantic digest are one policy
//! to this gateway. v0 defines no normalization, so it has no semantic digest.

use std::{collections::HashSet, fmt};

use serde::{
    de::{self, DeserializeOwned, DeserializeSeed, MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer, Serialize,
};
use serde_json::{Map, Value};

use super::{
    policy::{
        DefaultAction, EgressPolicy, EnforcementMode, Policy, PolicyError, RoleEntry,
        ToolPolicyEntry, V0Rejection, KNOWN_TOP_LEVEL_KEYS, MAX_POLICY_FILE_BYTES,
    },
    RateLimitRule, RouteRule, Rule,
};
use crate::{canonical_json, request_bounds::MAX_TOOL_NAME_BYTES};

/// The exact `schema_version` of policy v1.
pub(crate) const POLICY_V1_SCHEMA_VERSION: &str = "1.0.0";

/// The media type every policy digest frames. It is the one the policy
/// kernel frames its source digests with, so one document has one source
/// digest wherever it is computed.
pub(crate) const POLICY_MEDIA_TYPE: &str = "application/json";

/// The most structural problems one inspection reports. A document past it
/// is already refused; listing every element of a 1 MiB document would only
/// make the refusal larger than the document.
pub(crate) const MAX_REPORTED_ISSUES: usize = 100;

/// The schema a policy document is read under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PolicySchema {
    /// Any `0.x` version: the original format.
    V0,
    /// Exactly [`POLICY_V1_SCHEMA_VERSION`].
    V1,
}

impl PolicySchema {
    /// The schema `schema_version` dispatches to, or `None` when this build
    /// implements none that claims it.
    pub(crate) fn of_version(schema_version: &str) -> Option<Self> {
        if schema_version == POLICY_V1_SCHEMA_VERSION {
            Some(Self::V1)
        } else if schema_version.starts_with("0.") {
            Some(Self::V0)
        } else {
            None
        }
    }

    /// The schema a parsed document declares.
    pub(crate) fn of_document(document: &Value) -> Option<Self> {
        document
            .get("schema_version")
            .and_then(Value::as_str)
            .and_then(Self::of_version)
    }

    /// The document format major the cluster roster advertises a range of
    /// (`cluster_membership::DOCUMENT_VERSION_RANGE`).
    #[cfg(any(test, feature = "postgres"))]
    pub(crate) const fn document_format_major(self) -> i32 {
        match self {
            Self::V0 => 0,
            Self::V1 => 1,
        }
    }
}

/// A stable diagnostic code. The string is part of the policy API contract;
/// the variant name is not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IssueCode {
    InvalidJson,
    DocumentTooLarge,
    DuplicateMember,
    InvalidType,
    InvalidValue,
    SchemaVersionUnsupported,
    UnknownMember,
    RequiredMemberMissing,
    NumberOutOfRange,
    ElementIdMissing,
    ElementIdInvalid,
    ElementIdDuplicate,
    MemberRequiresV1,
    TooManyProblems,
    PathNotAbsolute,
    PathCaptureMalformed,
    RuleTargetInvalid,
    ToolNameEmpty,
    ToolNameTooLong,
    ToolRuleMethodsPresent,
    ToolRuleDispatchPresent,
    DispatchMemberNotAllowed,
    DispatchMemberMissing,
    DispatchOriginInvalid,
    DispatchRouteIdInvalid,
    RouteHostInvalid,
    RouteHostDuplicate,
    RateLimitRateInvalid,
    RateLimitBurstInvalid,
    IssuerEmpty,
    AuthMethodUnknown,
    RoleDescriptionInvalid,
    ToolTimeoutInvalid,
    EgressHostInvalid,
    EgressCidrInvalid,
    EgressPortInvalid,
    UnknownTopLevelMember,
    StableIdsUnavailable,
    DispatchNotConfigured,
    DocumentFormatUnsupportedInCluster,
}

impl IssueCode {
    /// Every code, so tests can check the vocabulary as a whole.
    #[cfg(test)]
    pub(crate) const ALL: [Self; 40] = [
        Self::InvalidJson,
        Self::DocumentTooLarge,
        Self::DuplicateMember,
        Self::InvalidType,
        Self::InvalidValue,
        Self::SchemaVersionUnsupported,
        Self::UnknownMember,
        Self::RequiredMemberMissing,
        Self::NumberOutOfRange,
        Self::ElementIdMissing,
        Self::ElementIdInvalid,
        Self::ElementIdDuplicate,
        Self::MemberRequiresV1,
        Self::TooManyProblems,
        Self::PathNotAbsolute,
        Self::PathCaptureMalformed,
        Self::RuleTargetInvalid,
        Self::ToolNameEmpty,
        Self::ToolNameTooLong,
        Self::ToolRuleMethodsPresent,
        Self::ToolRuleDispatchPresent,
        Self::DispatchMemberNotAllowed,
        Self::DispatchMemberMissing,
        Self::DispatchOriginInvalid,
        Self::DispatchRouteIdInvalid,
        Self::RouteHostInvalid,
        Self::RouteHostDuplicate,
        Self::RateLimitRateInvalid,
        Self::RateLimitBurstInvalid,
        Self::IssuerEmpty,
        Self::AuthMethodUnknown,
        Self::RoleDescriptionInvalid,
        Self::ToolTimeoutInvalid,
        Self::EgressHostInvalid,
        Self::EgressCidrInvalid,
        Self::EgressPortInvalid,
        Self::UnknownTopLevelMember,
        Self::StableIdsUnavailable,
        Self::DispatchNotConfigured,
        Self::DocumentFormatUnsupportedInCluster,
    ];

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidJson => "invalid_json",
            Self::DocumentTooLarge => "document_too_large",
            Self::DuplicateMember => "duplicate_member",
            Self::InvalidType => "invalid_type",
            Self::InvalidValue => "invalid_value",
            Self::SchemaVersionUnsupported => "schema_version_unsupported",
            Self::UnknownMember => "unknown_member",
            Self::RequiredMemberMissing => "required_member_missing",
            Self::NumberOutOfRange => "number_out_of_range",
            Self::ElementIdMissing => "element_id_missing",
            Self::ElementIdInvalid => "element_id_invalid",
            Self::ElementIdDuplicate => "element_id_duplicate",
            Self::MemberRequiresV1 => "member_requires_v1",
            Self::TooManyProblems => "too_many_problems",
            Self::PathNotAbsolute => "path_not_absolute",
            Self::PathCaptureMalformed => "path_capture_malformed",
            Self::RuleTargetInvalid => "rule_target_invalid",
            Self::ToolNameEmpty => "tool_name_empty",
            Self::ToolNameTooLong => "tool_name_too_long",
            Self::ToolRuleMethodsPresent => "tool_rule_methods_present",
            Self::ToolRuleDispatchPresent => "tool_rule_dispatch_present",
            Self::DispatchMemberNotAllowed => "dispatch_member_not_allowed",
            Self::DispatchMemberMissing => "dispatch_member_missing",
            Self::DispatchOriginInvalid => "dispatch_origin_invalid",
            Self::DispatchRouteIdInvalid => "dispatch_route_id_invalid",
            Self::RouteHostInvalid => "route_host_invalid",
            Self::RouteHostDuplicate => "route_host_duplicate",
            Self::RateLimitRateInvalid => "rate_limit_rate_invalid",
            Self::RateLimitBurstInvalid => "rate_limit_burst_invalid",
            Self::IssuerEmpty => "issuer_empty",
            Self::AuthMethodUnknown => "auth_method_unknown",
            Self::RoleDescriptionInvalid => "role_description_invalid",
            Self::ToolTimeoutInvalid => "tool_timeout_invalid",
            Self::EgressHostInvalid => "egress_host_invalid",
            Self::EgressCidrInvalid => "egress_cidr_invalid",
            Self::EgressPortInvalid => "egress_port_invalid",
            Self::UnknownTopLevelMember => "unknown_top_level_member",
            Self::StableIdsUnavailable => "stable_ids_unavailable",
            Self::DispatchNotConfigured => "dispatch_not_configured",
            Self::DocumentFormatUnsupportedInCluster => "document_format_unsupported_in_cluster",
        }
    }

    /// What is wrong, in words that quote nothing from the document.
    pub(crate) const fn message(self) -> &'static str {
        match self {
            Self::InvalidJson => "the document is not well-formed JSON text",
            Self::DocumentTooLarge => "the document is larger than a policy may be",
            Self::DuplicateMember => "an object names the same member more than once",
            Self::InvalidType => "the value has the wrong JSON type for this location",
            Self::InvalidValue => "the value is not one this location accepts",
            Self::SchemaVersionUnsupported => {
                "schema_version names no policy schema this gateway implements"
            }
            Self::UnknownMember => "the member is not part of policy v1",
            Self::RequiredMemberMissing => "a member this element requires is absent",
            Self::NumberOutOfRange => "the number is outside the I-JSON safe range",
            Self::ElementIdMissing => "the element has no stable id",
            Self::ElementIdInvalid => "the id is not a valid stable id",
            Self::ElementIdDuplicate => {
                "the id is already used by an earlier rule, route, or rate override"
            }
            Self::MemberRequiresV1 => "the member exists only in policy v1",
            Self::TooManyProblems => "further problems in the document were not reported",
            Self::PathNotAbsolute => "the path does not start with '/'",
            Self::PathCaptureMalformed => {
                "a path segment looks like a capture but is not a valid one, so the pattern \
                 can never match"
            }
            Self::RuleTargetInvalid => "a rule must set exactly one of path and tool_name",
            Self::ToolNameEmpty => "the tool name is empty",
            Self::ToolNameTooLong => "a tool name is longer than 4096 bytes",
            Self::ToolRuleMethodsPresent => "a tool_name rule cannot constrain HTTP methods",
            Self::ToolRuleDispatchPresent => "dispatch applies only to HTTP path rules",
            Self::DispatchMemberNotAllowed => {
                "the dispatch binding sets a member its kind does not use"
            }
            Self::DispatchMemberMissing => {
                "the dispatch binding lacks the member its kind requires"
            }
            Self::DispatchOriginInvalid => "upstream_origin is not an HTTP(S) origin",
            Self::DispatchRouteIdInvalid => "route_id is not a valid stable route id",
            Self::RouteHostInvalid => "the route host is not a hostname without a port",
            Self::RouteHostDuplicate => {
                "the route lists the same host more than once; hosts compare case-insensitively"
            }
            Self::RateLimitRateInvalid => "requests_per_second is not finite and positive",
            Self::RateLimitBurstInvalid => "burst is not positive",
            Self::IssuerEmpty => "an issuer constraint is empty",
            Self::AuthMethodUnknown => "the authentication method is not one the gateway knows",
            Self::RoleDescriptionInvalid => {
                "a role description must be non-blank printable text of at most 512 bytes"
            }
            Self::ToolTimeoutInvalid => "timeout_ms is not positive",
            Self::EgressHostInvalid => {
                "the egress host pattern is not an ASCII hostname or a '*.' wildcard prefix"
            }
            Self::EgressCidrInvalid => "the egress CIDR does not parse",
            Self::EgressPortInvalid => "the egress port is outside 1 to 65535",
            Self::UnknownTopLevelMember => "a 0.x reader ignores this top-level member",
            Self::StableIdsUnavailable => {
                "a 0.x document gives routes and rate overrides no id, and rules only an \
                 optional one, so its elements cannot be named stably"
            }
            Self::DispatchNotConfigured => {
                "a rule's dispatch binding does not match this gateway's proxy routing \
                 configuration"
            }
            Self::DocumentFormatUnsupportedInCluster => {
                "cluster mode does not yet commit documents of this schema_version"
            }
        }
    }

    /// What to do about it.
    pub(crate) const fn remediation(self) -> &'static str {
        match self {
            Self::InvalidJson => {
                "Send one UTF-8 JSON object, without a byte-order mark or trailing content."
            }
            Self::DocumentTooLarge => "Keep the document within 1048576 bytes.",
            Self::DuplicateMember => {
                "Remove the repeated member; JSON readers disagree about which copy wins."
            }
            Self::InvalidType | Self::InvalidValue => {
                "Compare the element with the published schema for its schema_version under \
                 docs/schemas."
            }
            Self::SchemaVersionUnsupported => {
                "Set schema_version to exactly \"1.0.0\" for policy v1, or to a \"0.\" version \
                 for the original format."
            }
            Self::UnknownMember => {
                "Remove the member or correct its spelling; policy v1 refuses members it does \
                 not define instead of ignoring them."
            }
            Self::RequiredMemberMissing => "Add the member the pointer names.",
            Self::NumberOutOfRange => {
                "Use a finite number whose magnitude is at most 9007199254740991."
            }
            Self::ElementIdMissing | Self::ElementIdInvalid => {
                "Give every rule, route, and rate override an id of 1 to 64 ASCII letters, \
                 digits, '.', '_', or '-', starting with a letter or digit."
            }
            Self::ElementIdDuplicate => {
                "Give each element its own id; ids are unique across rules, routes, and \
                 rate_limits."
            }
            Self::MemberRequiresV1 => {
                "Remove the member, or set schema_version to \"1.0.0\" and give every rule, \
                 route, and rate override an id."
            }
            Self::TooManyProblems => "Fix the problems reported, then validate again.",
            Self::PathNotAbsolute => "Write the path as an absolute path beginning with '/'.",
            Self::PathCaptureMalformed => {
                "Name a capture with ASCII letters, digits, and '_', starting with a letter or \
                 '_', for example {id}."
            }
            Self::RuleTargetInvalid => {
                "Keep path for an HTTP rule or tool_name for an MCP tool rule, not both and \
                 not neither."
            }
            Self::ToolNameEmpty => "Name the tool exactly as MCP clients call it.",
            Self::ToolNameTooLong => {
                "Shorten the tool name; the tool lane never evaluates a longer one."
            }
            Self::ToolRuleMethodsPresent => "Remove methods from the tool_name rule.",
            Self::ToolRuleDispatchPresent => "Remove dispatch from the tool_name rule.",
            Self::DispatchMemberNotAllowed | Self::DispatchMemberMissing => {
                "A contextless dispatch takes no other member, a legacy dispatch takes \
                 upstream_origin, and a route dispatch takes route_id."
            }
            Self::DispatchOriginInvalid => {
                "Write the origin as http(s)://host[:port], with no credentials, path, query, \
                 or fragment."
            }
            Self::DispatchRouteIdInvalid => "Use the id of a configured UPSTREAM_ROUTES entry.",
            Self::RouteHostInvalid => {
                "List bare hostnames such as api.example.com; request ports are ignored when \
                 matching."
            }
            Self::RouteHostDuplicate => "Remove the repeated host.",
            Self::RateLimitRateInvalid => "Set requests_per_second to a positive number.",
            Self::RateLimitBurstInvalid => "Set burst to a positive integer.",
            Self::IssuerEmpty => {
                "Remove the empty value; an empty issuers list already means any issuer."
            }
            Self::AuthMethodUnknown => {
                "Use bearer_token, session_cookie, service_token, or client_certificate."
            }
            Self::RoleDescriptionInvalid => "Correct the description, or omit it.",
            Self::ToolTimeoutInvalid => "Set timeout_ms to a positive number of milliseconds.",
            Self::EgressHostInvalid => {
                "Use a hostname such as api.example.com or a wildcard prefix such as \
                 *.example.com."
            }
            Self::EgressCidrInvalid => "Write the range as an IPv4 or IPv6 CIDR.",
            Self::EgressPortInvalid => "List ports from 1 to 65535.",
            Self::UnknownTopLevelMember => {
                "Remove the member, or move to policy v1, which refuses unknown members \
                 instead of ignoring them."
            }
            Self::StableIdsUnavailable => {
                "Move to policy v1 (schema_version \"1.0.0\") and give every rule, route, and \
                 rate override an id."
            }
            Self::DispatchNotConfigured => {
                "Bind the rule to a route id this gateway configures, or update it for the \
                 current UPSTREAM_ROUTES."
            }
            Self::DocumentFormatUnsupportedInCluster => {
                "Keep a cluster deployment on a 0.x document until a release that gates v1 \
                 documents on every replica's capability."
            }
        }
    }
}

impl fmt::Display for IssueCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One reason a document is refused: a code, where it applies, and the
/// free-text detail the policy API reports to the caller who sent the
/// document. The detail may quote the document; the code and pointer never
/// carry more than its location.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PolicyIssue {
    pub(crate) code: IssueCode,
    pub(crate) pointer: String,
    pub(crate) detail: String,
}

impl PolicyIssue {
    pub(crate) fn new(code: IssueCode, pointer: String, detail: String) -> Self {
        Self {
            code,
            pointer,
            detail,
        }
    }

    /// An issue whose detail is its own fixed message and location, for a
    /// check that has no earlier wording to keep.
    pub(crate) fn located(code: IssueCode, pointer: String) -> Self {
        let detail = if pointer.is_empty() {
            code.message().to_owned()
        } else {
            format!("{pointer}: {}", code.message())
        };
        Self::new(code, pointer, detail)
    }
}

impl fmt::Display for PolicyIssue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.detail)
    }
}

/// How serious a diagnostic is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DiagnosticSeverity {
    /// The document cannot be accepted.
    Error,
    /// The document is accepted, with a limitation stated.
    Warning,
}

/// Which later uses a diagnostic stands in the way of.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct DiagnosticBlocks {
    pub(crate) simulation: bool,
    pub(crate) tests: bool,
    pub(crate) publication: bool,
    pub(crate) evidence: bool,
}

impl DiagnosticBlocks {
    fn of(code: IssueCode, severity: DiagnosticSeverity) -> Self {
        match (severity, code) {
            // The document itself is sound; only this deployment cannot
            // commit it.
            (DiagnosticSeverity::Error, IssueCode::DocumentFormatUnsupportedInCluster) => Self {
                simulation: false,
                tests: false,
                publication: true,
                evidence: false,
            },
            (DiagnosticSeverity::Error, _) => Self {
                simulation: true,
                tests: true,
                publication: true,
                evidence: true,
            },
            // A warning states a limitation of what the document can prove
            // about itself, never of what it enforces.
            (DiagnosticSeverity::Warning, _) => Self {
                simulation: false,
                tests: false,
                publication: false,
                evidence: true,
            },
        }
    }
}

/// One structured finding about a policy document.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct PolicyDiagnostic {
    pub(crate) code: &'static str,
    pub(crate) severity: DiagnosticSeverity,
    /// RFC 6901 JSON Pointer into the document; empty for the whole document.
    pub(crate) pointer: String,
    /// The stable id of the rule, route, or rate override the pointer is in,
    /// when that element has a valid one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) element_id: Option<String>,
    pub(crate) message: &'static str,
    pub(crate) remediation: &'static str,
    pub(crate) blocks: DiagnosticBlocks,
}

impl PolicyDiagnostic {
    fn new(
        code: IssueCode,
        severity: DiagnosticSeverity,
        pointer: String,
        document: Option<&Value>,
    ) -> Self {
        let element_id = document.and_then(|document| element_id_at(document, &pointer));
        Self {
            code: code.as_str(),
            severity,
            pointer,
            element_id,
            message: code.message(),
            remediation: code.remediation(),
            blocks: DiagnosticBlocks::of(code, severity),
        }
    }
}

/// Everything one inspection established about a policy document.
#[derive(Debug)]
pub(crate) struct PolicyInspection {
    schema_version: Option<String>,
    diagnostics: Vec<PolicyDiagnostic>,
    /// The detail of each error diagnostic, in the same order.
    details: Vec<String>,
    source_digest: Option<String>,
    semantic_digest: Option<String>,
    policy: Option<Policy>,
}

impl PolicyInspection {
    fn empty() -> Self {
        Self {
            schema_version: None,
            diagnostics: Vec::new(),
            details: Vec::new(),
            source_digest: None,
            semantic_digest: None,
            policy: None,
        }
    }

    /// The document's `schema_version`, when it names a schema this gateway
    /// implements.
    pub(crate) fn schema_version(&self) -> Option<&str> {
        self.schema_version.as_deref()
    }

    pub(crate) fn diagnostics(&self) -> &[PolicyDiagnostic] {
        &self.diagnostics
    }

    /// The free-text detail of every error, in diagnostic order.
    pub(crate) fn error_details(&self) -> &[String] {
        &self.details
    }

    pub(crate) fn source_digest(&self) -> Option<&str> {
        self.source_digest.as_deref()
    }

    pub(crate) fn semantic_digest(&self) -> Option<&str> {
        self.semantic_digest.as_deref()
    }

    /// The parsed policy, when the document itself is sound -- even if a
    /// deployment check later refused it.
    pub(crate) fn policy(&self) -> Option<&Policy> {
        self.policy.as_ref()
    }

    /// Whether the document may be published: it parsed, and nothing
    /// reported blocks publication.
    pub(crate) fn is_valid(&self) -> bool {
        self.policy.is_some()
            && !self
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.blocks.publication)
    }

    /// Records a refusal a deployment check made of an otherwise sound
    /// document.
    pub(crate) fn refuse(&mut self, code: IssueCode, pointer: &str, detail: String) {
        self.diagnostics.push(PolicyDiagnostic::new(
            code,
            DiagnosticSeverity::Error,
            pointer.to_owned(),
            None,
        ));
        self.details.push(detail);
    }

    /// The policy if it may be published, or every error's detail.
    pub(crate) fn into_policy(self) -> Result<Policy, Vec<String>> {
        if self.is_valid() {
            if let Some(policy) = self.policy {
                return Ok(policy);
            }
        }
        Err(self.details)
    }

    fn error(&mut self, document: Option<&Value>, issue: PolicyIssue) {
        self.diagnostics.push(PolicyDiagnostic::new(
            issue.code,
            DiagnosticSeverity::Error,
            issue.pointer,
            document,
        ));
        self.details.push(issue.detail);
    }

    fn warning(&mut self, document: &Value, code: IssueCode, pointer: String) {
        self.diagnostics.push(PolicyDiagnostic::new(
            code,
            DiagnosticSeverity::Warning,
            pointer,
            Some(document),
        ));
    }
}

/// Inspects policy source bytes: every diagnostic, the digests a clean
/// document earns, and the parsed policy. Writes and logs nothing except the
/// unknown-top-level-member warning a 0.x document has always logged.
pub(crate) fn inspect_source(source: &[u8]) -> PolicyInspection {
    let mut inspection = PolicyInspection::empty();
    let document: Value = match serde_json::from_slice(source) {
        Ok(document) => document,
        Err(error) => {
            inspection.error(
                None,
                PolicyIssue::new(
                    IssueCode::InvalidJson,
                    String::new(),
                    format!("invalid JSON: {error}"),
                ),
            );
            return inspection;
        }
    };
    let schema = PolicySchema::of_document(&document);
    if schema.is_some() {
        inspection.schema_version = document
            .get("schema_version")
            .and_then(Value::as_str)
            .map(str::to_owned);
    }
    match schema {
        Some(PolicySchema::V1) => inspect_v1(source, &document, &mut inspection),
        _ => inspect_v0(source, &document, &mut inspection),
    }
    inspection
}

fn inspect_v1(source: &[u8], document: &Value, inspection: &mut PolicyInspection) {
    let policy = match parse_v1_source(source, document) {
        Ok(policy) => policy,
        Err(issues) => {
            for issue in issues {
                inspection.error(Some(document), issue);
            }
            return;
        }
    };
    let semantic_digest = serde_json::to_value(&policy).ok().and_then(|normalized| {
        canonical_json::semantic_digest(POLICY_MEDIA_TYPE, POLICY_V1_SCHEMA_VERSION, &normalized)
            .ok()
    });
    let Some(semantic_digest) = semantic_digest else {
        // Unreachable for a document whose numbers were all checked, and
        // refused rather than accepted without its digest if it is not.
        inspection.error(
            Some(document),
            PolicyIssue::located(IssueCode::NumberOutOfRange, String::new()),
        );
        return;
    };
    inspection.source_digest = Some(canonical_json::source_digest(
        POLICY_MEDIA_TYPE,
        POLICY_V1_SCHEMA_VERSION,
        source,
    ));
    inspection.semantic_digest = Some(semantic_digest);
    inspection.policy = Some(policy);
}

fn inspect_v0(source: &[u8], document: &Value, inspection: &mut PolicyInspection) {
    // A 0.x document keeps every reading it has always had; what v1 refuses
    // is reported here only as the limitation it is. A document that names
    // no implemented schema is read this way too, so that it is refused in
    // the words it always was, but it is not described as a 0.x document.
    if PolicySchema::of_document(document) == Some(PolicySchema::V0) {
        if let Err(issue) = check_unique_members(source) {
            if issue.code == IssueCode::DuplicateMember {
                inspection.warning(document, IssueCode::DuplicateMember, issue.pointer);
            }
        }
        let mut unknown = super::policy::unknown_top_level_keys(document);
        unknown.sort();
        for key in unknown {
            inspection.warning(
                document,
                IssueCode::UnknownTopLevelMember,
                format!("/{}", pointer_token(&key)),
            );
        }
    }
    super::policy::warn_unknown_top_level_keys(document);

    let policy = match Policy::parse_v0(document) {
        Ok(policy) => policy,
        Err(V0Rejection::Parse(error)) => {
            let detail = PolicyError::Parse {
                path: None,
                source: error,
            }
            .to_string();
            inspection.error(
                Some(document),
                PolicyIssue::new(
                    IssueCode::InvalidValue,
                    locate_typed_failure(document),
                    detail,
                ),
            );
            return;
        }
        Err(V0Rejection::Invalid(issue)) => {
            inspection.error(Some(document), issue);
            return;
        }
    };
    if !policy.routes.is_empty()
        || !policy.rate_limits.is_empty()
        || policy.rules.iter().any(|rule| rule.id.is_none())
    {
        inspection.warning(document, IssueCode::StableIdsUnavailable, String::new());
    }
    inspection.source_digest = Some(canonical_json::source_digest(
        POLICY_MEDIA_TYPE,
        &policy.schema_version,
        source,
    ));
    inspection.policy = Some(policy);
}

/// Parses a v1 document from its source bytes: the parsed `document` must be
/// those bytes. Adds to [`parse_v1`] what only the bytes can show -- the size
/// bound, repeated member names, and a member spelled in a form a typed
/// reading of the bytes would not accept.
pub(crate) fn parse_v1_source(source: &[u8], document: &Value) -> Result<Policy, Vec<PolicyIssue>> {
    if source.len() as u64 > MAX_POLICY_FILE_BYTES {
        return Err(vec![PolicyIssue::located(
            IssueCode::DocumentTooLarge,
            String::new(),
        )]);
    }
    check_unique_members(source).map_err(|issue| vec![issue])?;
    let policy = parse_v1(document)?;
    // With `arbitrary_precision`, a JSON object carrying serde_json's private
    // number tag reads as a number through `Value`, but not when the bytes
    // are read straight into the typed policy. Both readings must accept the
    // document, so that every JSON reader sees the same members.
    if serde_json::from_slice::<Policy>(source).is_err() {
        return Err(vec![PolicyIssue::located(
            IssueCode::InvalidValue,
            String::new(),
        )]);
    }
    Ok(policy)
}

/// Parses and validates a v1 document that has already been read as JSON.
/// Structural problems are all reported; semantic validation stops at the
/// first, as it does for v0.
pub(crate) fn parse_v1(document: &Value) -> Result<Policy, Vec<PolicyIssue>> {
    let mut issues = IssueList::default();
    check_v1_structure(document, &mut issues);
    if !issues.is_empty() {
        return Err(issues.into_vec());
    }
    super::policy::validate_rule_target_properties(document).map_err(|issue| vec![issue])?;
    let mut policy = Policy::deserialize(document).map_err(|error| {
        vec![PolicyIssue::new(
            IssueCode::InvalidValue,
            locate_typed_failure(document),
            PolicyError::Parse {
                path: None,
                source: error,
            }
            .to_string(),
        )]
    })?;
    policy.canonicalize_issuers();
    policy.check_semantics().map_err(|issue| vec![issue])?;
    Ok(policy)
}

/// Structural problems, collected up to [`MAX_REPORTED_ISSUES`]. Past the
/// bound one [`IssueCode::TooManyProblems`] stands for the rest, so a large
/// broken document cannot make its refusal larger still.
#[derive(Default)]
struct IssueList {
    issues: Vec<PolicyIssue>,
    overflowed: bool,
}

impl IssueList {
    fn push(&mut self, issue: PolicyIssue) {
        if self.issues.len() < MAX_REPORTED_ISSUES {
            self.issues.push(issue);
        } else {
            self.overflowed = true;
        }
    }

    fn is_empty(&self) -> bool {
        self.issues.is_empty()
    }

    fn into_vec(mut self) -> Vec<PolicyIssue> {
        if self.overflowed {
            self.issues.push(PolicyIssue::located(
                IssueCode::TooManyProblems,
                String::new(),
            ));
        }
        self.issues
    }
}

/// One object's closed member vocabulary in policy v1.
struct Members {
    allowed: &'static [&'static str],
    /// Required members other than `id`, which the id checks report.
    required: &'static [&'static str],
}

const ROLE_MEMBERS: Members = Members {
    allowed: &["permissions", "issuers", "auth_methods", "description"],
    required: &[],
};
const ROUTE_MEMBERS: Members = Members {
    allowed: &[
        "id",
        "methods",
        "hosts",
        "path_prefix",
        "permission",
        "enforcement_mode",
    ],
    required: &["path_prefix", "permission"],
};
const RULE_MEMBERS: Members = Members {
    allowed: &[
        "id",
        "enabled",
        "methods",
        "path",
        "tool_name",
        "dispatch",
        "principal",
        "action",
    ],
    required: &["action"],
};
const PRINCIPAL_MEMBERS: Members = Members {
    allowed: &["roles", "issuers", "auth_methods", "principal_ids"],
    required: &[],
};
const DISPATCH_MEMBERS: Members = Members {
    allowed: &["kind", "upstream_origin", "route_id"],
    required: &["kind"],
};
const EGRESS_MEMBERS: Members = Members {
    allowed: &["hosts", "cidrs", "ports"],
    required: &[],
};
const RATE_LIMIT_MEMBERS: Members = Members {
    allowed: &[
        "id",
        "principal",
        "methods",
        "path",
        "requests_per_second",
        "burst",
    ],
    required: &["requests_per_second", "burst"],
};
const TOOL_MEMBERS: Members = Members {
    allowed: &[
        "enabled",
        "allowed_roles",
        "issuers",
        "auth_methods",
        "timeout_ms",
        "max_concurrent",
    ],
    required: &[],
};

/// The sections whose elements carry a stable id, in document order.
const IDENTIFIED_SECTIONS: [&str; 3] = ["routes", "rules", "rate_limits"];

fn check_v1_structure(document: &Value, issues: &mut IssueList) {
    let Some(object) = document.as_object() else {
        issues.push(PolicyIssue::located(IssueCode::InvalidType, String::new()));
        return;
    };
    for name in sorted_names(object) {
        if !KNOWN_TOP_LEVEL_KEYS.contains(&name.as_str()) {
            issues.push(PolicyIssue::located(
                IssueCode::UnknownMember,
                format!("/{}", pointer_token(name)),
            ));
        }
    }
    if let Some(roles) = object.get("roles") {
        check_entries(roles, "/roles", &ROLE_MEMBERS, false, issues);
    }
    let mut ids = HashSet::new();
    for section in IDENTIFIED_SECTIONS {
        let Some(elements) = object.get(section) else {
            continue;
        };
        let pointer = format!("/{section}");
        let Some(elements) = elements.as_array() else {
            issues.push(PolicyIssue::located(IssueCode::InvalidType, pointer));
            continue;
        };
        for (index, element) in elements.iter().enumerate() {
            let pointer = format!("{pointer}/{index}");
            let Some(element) = element.as_object() else {
                issues.push(PolicyIssue::located(IssueCode::InvalidType, pointer));
                continue;
            };
            let members = match section {
                "routes" => &ROUTE_MEMBERS,
                "rules" => &RULE_MEMBERS,
                _ => &RATE_LIMIT_MEMBERS,
            };
            check_members(element, &pointer, members, issues);
            check_element_id(element, &pointer, &mut ids, issues);
            if let Some(principal) = element.get("principal") {
                check_object(
                    principal,
                    &format!("{pointer}/principal"),
                    &PRINCIPAL_MEMBERS,
                    issues,
                );
            }
            if section == "rules" {
                if let Some(dispatch) = element.get("dispatch") {
                    check_object(
                        dispatch,
                        &format!("{pointer}/dispatch"),
                        &DISPATCH_MEMBERS,
                        issues,
                    );
                }
            }
        }
    }
    if let Some(egress) = object.get("egress") {
        check_object(egress, "/egress", &EGRESS_MEMBERS, issues);
    }
    if let Some(tools) = object.get("tools") {
        check_entries(tools, "/tools", &TOOL_MEMBERS, true, issues);
    }
    for name in sorted_names(object) {
        let Some(member) = object.get(name) else {
            continue;
        };
        let pointer = format!("/{}", pointer_token(name));
        match (name.as_str(), member.as_object()) {
            // An entry whose name is too long is already refused, without its
            // name; nothing inside it is located by that name either.
            ("tools", Some(tools)) => {
                for tool_name in sorted_names(tools) {
                    if let Some(entry) = tools.get(tool_name) {
                        if tool_name.len() <= MAX_TOOL_NAME_BYTES {
                            check_values(
                                entry,
                                &format!("{pointer}/{}", pointer_token(tool_name)),
                                issues,
                            );
                        }
                    }
                }
            }
            _ => check_values(member, &pointer, issues),
        }
    }
}

/// A map of named entries (`roles`, `tools`), each an object of `members`.
/// For `tools`, a name longer than the tool lane evaluates is refused as
/// [`IssueCode::ToolNameTooLong`] at the map, without echoing it, and its
/// entry is not examined further: the name alone refuses the document.
fn check_entries(
    value: &Value,
    pointer: &str,
    members: &Members,
    tool_names: bool,
    issues: &mut IssueList,
) {
    let Some(entries) = value.as_object() else {
        issues.push(PolicyIssue::located(
            IssueCode::InvalidType,
            pointer.to_owned(),
        ));
        return;
    };
    let mut reported_long_name = false;
    for name in sorted_names(entries) {
        if tool_names && name.len() > MAX_TOOL_NAME_BYTES {
            if !reported_long_name {
                issues.push(PolicyIssue::new(
                    IssueCode::ToolNameTooLong,
                    pointer.to_owned(),
                    format!("tools entry names must not exceed {MAX_TOOL_NAME_BYTES} bytes"),
                ));
                reported_long_name = true;
            }
            continue;
        }
        if let Some(entry) = entries.get(name) {
            check_object(
                entry,
                &format!("{pointer}/{}", pointer_token(name)),
                members,
                issues,
            );
        }
    }
}

fn check_object(value: &Value, pointer: &str, members: &Members, issues: &mut IssueList) {
    match value.as_object() {
        Some(object) => check_members(object, pointer, members, issues),
        None => issues.push(PolicyIssue::located(
            IssueCode::InvalidType,
            pointer.to_owned(),
        )),
    }
}

fn check_members(
    object: &Map<String, Value>,
    pointer: &str,
    members: &Members,
    issues: &mut IssueList,
) {
    for name in sorted_names(object) {
        if !members.allowed.contains(&name.as_str()) {
            issues.push(PolicyIssue::located(
                IssueCode::UnknownMember,
                format!("{pointer}/{}", pointer_token(name)),
            ));
        }
    }
    for required in members.required {
        if !object.contains_key(*required) {
            issues.push(PolicyIssue::located(
                IssueCode::RequiredMemberMissing,
                format!("{pointer}/{required}"),
            ));
        }
    }
}

fn check_element_id<'a>(
    element: &'a Map<String, Value>,
    pointer: &str,
    ids: &mut HashSet<&'a str>,
    issues: &mut IssueList,
) {
    let pointer = format!("{pointer}/id");
    match element.get("id") {
        None => issues.push(PolicyIssue::located(IssueCode::ElementIdMissing, pointer)),
        Some(Value::String(id)) if is_valid_element_id(id) => {
            if !ids.insert(id.as_str()) {
                issues.push(PolicyIssue::located(IssueCode::ElementIdDuplicate, pointer));
            }
        }
        Some(_) => issues.push(PolicyIssue::located(IssueCode::ElementIdInvalid, pointer)),
    }
}

/// Every number must have an RFC 8785 canonical form, or the document has
/// no semantic digest. And no value may be `null`: policy v1 defines no
/// member that takes one, and a 0.x reader takes `null` for "absent" in some
/// places and refuses it in others, so v1 gives it no reading at all. An
/// element's `null` id is left to the id checks, which report it as an
/// invalid id.
fn check_values(value: &Value, pointer: &str, issues: &mut IssueList) {
    match value {
        Value::Number(_) => {
            if canonical_json::canonical_json_bytes(value).is_err() {
                issues.push(PolicyIssue::located(
                    IssueCode::NumberOutOfRange,
                    pointer.to_owned(),
                ));
            }
        }
        Value::Null => {
            if !is_element_id_pointer(pointer) {
                issues.push(PolicyIssue::located(
                    IssueCode::InvalidType,
                    pointer.to_owned(),
                ));
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                check_values(item, &format!("{pointer}/{index}"), issues);
            }
        }
        Value::Object(object) => {
            for name in sorted_names(object) {
                if let Some(member) = object.get(name) {
                    check_values(
                        member,
                        &format!("{pointer}/{}", pointer_token(name)),
                        issues,
                    );
                }
            }
        }
        Value::Bool(_) | Value::String(_) => {}
    }
}

/// Whether `pointer` is `/{section}/{index}/id` for a section whose elements
/// carry a stable id.
fn is_element_id_pointer(pointer: &str) -> bool {
    let mut tokens = pointer.split('/');
    matches!(
        (tokens.next(), tokens.next(), tokens.next(), tokens.next(), tokens.next()),
        (Some(""), Some(section), Some(index), Some("id"), None)
            if IDENTIFIED_SECTIONS.contains(&section) && index.parse::<usize>().is_ok()
    )
}

fn sorted_names(object: &Map<String, Value>) -> Vec<&String> {
    let mut names: Vec<&String> = object.keys().collect();
    names.sort();
    names
}

/// The stable element id syntax: the one `UPSTREAM_ROUTES[].id` and a rule's
/// `dispatch.route_id` use -- 1 to 64 ASCII letters, digits, `.`, `_` and
/// `-`, starting with a letter or digit.
pub(crate) fn is_valid_element_id(id: &str) -> bool {
    crate::upstream_route::is_valid_stable_route_id(id)
}

/// One RFC 6901 reference token: `~` is written `~0` and `/` is written `~1`.
pub(crate) fn pointer_token(raw: &str) -> String {
    raw.replace('~', "~0").replace('/', "~1")
}

/// The valid stable id of the rule, route, or rate override `pointer` is in.
fn element_id_at(document: &Value, pointer: &str) -> Option<String> {
    let mut tokens = pointer.strip_prefix('/')?.split('/');
    let section = tokens.next()?;
    if !IDENTIFIED_SECTIONS.contains(&section) {
        return None;
    }
    let index: usize = tokens.next()?.parse().ok()?;
    let id = document.get(section)?.get(index)?.get("id")?.as_str()?;
    is_valid_element_id(id).then(|| id.to_owned())
}

/// Where a typed reading of `document` fails: the first member, or element of
/// an ordered section, that does not read on its own. The whole document
/// when none can be singled out.
fn locate_typed_failure(document: &Value) -> String {
    let Some(object) = document.as_object() else {
        return String::new();
    };
    if !matches!(object.get("schema_version"), Some(Value::String(_))) {
        return "/schema_version".to_owned();
    }
    if fails::<Option<String>>(object.get("id")) {
        return "/id".to_owned();
    }
    if fails::<DefaultAction>(object.get("default_action")) {
        return "/default_action".to_owned();
    }
    if fails::<EnforcementMode>(object.get("enforcement_mode")) {
        return "/enforcement_mode".to_owned();
    }
    if let Some(pointer) = failing_entry::<RoleEntry>(object.get("roles"), "/roles") {
        return pointer;
    }
    if let Some(pointer) = failing_element::<RouteRule>(object.get("routes"), "/routes") {
        return pointer;
    }
    if let Some(pointer) = failing_element::<Rule>(object.get("rules"), "/rules") {
        return pointer;
    }
    if fails::<EgressPolicy>(object.get("egress")) {
        return "/egress".to_owned();
    }
    if let Some(pointer) =
        failing_element::<RateLimitRule>(object.get("rate_limits"), "/rate_limits")
    {
        return pointer;
    }
    if let Some(pointer) = failing_entry::<ToolPolicyEntry>(object.get("tools"), "/tools") {
        return pointer;
    }
    String::new()
}

fn fails<T: DeserializeOwned>(value: Option<&Value>) -> bool {
    value.is_some_and(|value| T::deserialize(value).is_err())
}

fn failing_element<T: DeserializeOwned>(value: Option<&Value>, pointer: &str) -> Option<String> {
    let value = value?;
    let Some(elements) = value.as_array() else {
        return Some(pointer.to_owned());
    };
    elements
        .iter()
        .position(|element| T::deserialize(element).is_err())
        .map(|index| format!("{pointer}/{index}"))
}

fn failing_entry<T: DeserializeOwned>(value: Option<&Value>, pointer: &str) -> Option<String> {
    let value = value?;
    let Some(entries) = value.as_object() else {
        return Some(pointer.to_owned());
    };
    sorted_names(entries)
        .into_iter()
        .find(|name| {
            entries
                .get(*name)
                .is_some_and(|entry| T::deserialize(entry).is_err())
        })
        .map(|name| entry_pointer(pointer, name))
}

/// The pointer to a named entry. A tool name too long for the tool lane to
/// evaluate is refused without being echoed (`tools entry names must not
/// exceed ...`), so its location is the map, not the name; no other entry
/// name is that long in a policy the gateway accepts.
fn entry_pointer(pointer: &str, name: &str) -> String {
    if name.len() > MAX_TOOL_NAME_BYTES {
        pointer.to_owned()
    } else {
        format!("{pointer}/{}", pointer_token(name))
    }
}

/// Refuses a document in which any object names a member twice, reporting
/// the first repeat. `serde_json::Value` keeps the last copy silently, so
/// the check reads the bytes.
pub(crate) fn check_unique_members(source: &[u8]) -> Result<(), PolicyIssue> {
    let mut scan = MemberScan::default();
    let mut deserializer = serde_json::Deserializer::from_slice(source);
    let scanned = ScanSeed { scan: &mut scan }
        .deserialize(&mut deserializer)
        .and_then(|()| deserializer.end());
    match (scanned, scan.duplicate) {
        (_, Some(pointer)) => Err(PolicyIssue::located(IssueCode::DuplicateMember, pointer)),
        (Ok(()), None) => Ok(()),
        (Err(error), None) => Err(PolicyIssue::new(
            IssueCode::InvalidJson,
            String::new(),
            format!("invalid JSON: {error}"),
        )),
    }
}

#[derive(Default)]
struct MemberScan {
    /// Reference tokens from the root to the value being read.
    path: Vec<String>,
    duplicate: Option<String>,
}

impl MemberScan {
    fn pointer(&self) -> String {
        self.path
            .iter()
            .map(|token| format!("/{}", pointer_token(token)))
            .collect()
    }
}

struct ScanSeed<'a> {
    scan: &'a mut MemberScan,
}

impl<'de> DeserializeSeed<'de> for ScanSeed<'_> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_any(ScanVisitor { scan: self.scan })
    }
}

struct ScanVisitor<'a> {
    scan: &'a mut MemberScan,
}

impl<'de> Visitor<'de> for ScanVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JSON with unique object members")
    }

    fn visit_bool<E: de::Error>(self, _value: bool) -> Result<(), E> {
        Ok(())
    }

    fn visit_i64<E: de::Error>(self, _value: i64) -> Result<(), E> {
        Ok(())
    }

    fn visit_u64<E: de::Error>(self, _value: u64) -> Result<(), E> {
        Ok(())
    }

    fn visit_f64<E: de::Error>(self, _value: f64) -> Result<(), E> {
        Ok(())
    }

    fn visit_str<E: de::Error>(self, _value: &str) -> Result<(), E> {
        Ok(())
    }

    fn visit_unit<E: de::Error>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<(), A::Error> {
        let mut index = 0_usize;
        loop {
            self.scan.path.push(index.to_string());
            let element = sequence.next_element_seed(ScanSeed {
                scan: &mut *self.scan,
            })?;
            self.scan.path.pop();
            if element.is_none() {
                return Ok(());
            }
            index += 1;
        }
    }

    // With `arbitrary_precision`, serde_json presents a fraction or exponent
    // to a generic visitor as a one-member map under a private tag. That map
    // has one member, so it can never look like a repeat.
    fn visit_map<A: MapAccess<'de>>(self, mut object: A) -> Result<(), A::Error> {
        let mut names = HashSet::new();
        while let Some(name) = object.next_key::<String>()? {
            let repeated = !names.insert(name.clone());
            self.scan.path.push(name);
            if repeated {
                self.scan.duplicate = Some(self.scan.pointer());
                return Err(de::Error::custom("duplicate object member"));
            }
            object.next_value_seed(ScanSeed {
                scan: &mut *self.scan,
            })?;
            self.scan.path.pop();
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "policy_document_tests.rs"]
mod tests;
