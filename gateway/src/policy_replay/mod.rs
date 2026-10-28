//! Replay contexts (issue #243, slice 12): what a retained request record must
//! carry for the policy kernel to decide it again, and the adapters that read
//! one out of the audit records this gateway already writes.
//!
//! A [`ReplayContext`] is the `replay-context.v1` record: the facts the kernel
//! reads for one HTTP request or one tool invocation, each stated as recorded,
//! absent or not recorded, and the policy result the gateway recorded at the
//! time. [`evaluate`] turns those facts into the kernel's own contexts --
//! [`crate::policy_eval::PolicyEvaluationContext`],
//! [`crate::policy_eval::tools::ToolEvaluationContext`] and
//! [`crate::policy_eval::egress::EgressEvaluationContext`] -- and asks the
//! compiled policy, so a replayed decision is the decision production makes
//! for the same facts. [`legacy`] reads the facts out of the audit events the
//! gateway writes today. The published form is
//! `docs/schemas/replay-context.v1.schema.json`.
//!
//! ## Facts, not guesses
//!
//! A fact a record does not carry is `not_recorded`, never a default. That is
//! a different input from a fact the request genuinely lacked -- no `Host`
//! header, no principal -- and the kernel answers the two differently: an
//! uncaptured fact it needs is `indeterminate` with a stable limitation, never
//! a no-match and never an allow. Replay is where that distinction earns its
//! keep, because retained records routinely lack facts that live admission
//! always has.
//!
//! One fact the kernel cannot express as missing is the MCP alias identity:
//! an HTTP target is either contextless or an alias, and the observation a
//! request leaves does not say which. A context then names both, and
//! [`evaluate::evaluate_http`] answers only when both give the same decision.
//! Substituting the contextless reading would decide an alias request under
//! the wrong precedence order; see [`crate::policy_eval`].
//!
//! ## Redaction is by construction
//!
//! The types below have a place for each fact the kernel reads and for the
//! bounded policy result the gateway recorded, and for nothing else. Source
//! address, user agent, request id, email, organization, session, headers,
//! query values, bodies and their shapes, response status, latency, upstream
//! status, pool, endpoint and attempts, tool arguments and results, rendered
//! tool paths, connection and assertion identifiers, and free-text errors have
//! no member to land in, so an adapter cannot copy them by accident and a
//! serialized context cannot repeat them. Formatting a context names its source
//! and lane only.
//!
//! What a context does keep -- subject, issuer, roles, exact path, host and
//! routing facts -- it keeps because the kernel decides on it, exactly as
//! recorded: a projection that hashed or truncated them would change the
//! answer. Keeping them out of results, traces, audit and evidence is the
//! output projection's job, not this record's.
//!
//! ## What is not here yet
//!
//! No live path writes a `replay-context.v1` record and no job reads one: the
//! bounded replay job engine (slice 13) is the first consumer, and the
//! recorded-versus-candidate comparison (slice 14) the second. Every context
//! today comes from [`legacy`].

#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the replay job engine (#243 slice 13) is the first caller outside tests"
    )
)]

pub(crate) mod evaluate;
pub(crate) mod legacy;
#[cfg(test)]
mod live_tests;
#[cfg(test)]
mod tests;

use std::fmt;

use http::Method;
use serde_json::{json, Map, Value};
use url::Url;

use crate::{
    auth::{
        principal::{check_principal_shape, MAX_PRINCIPAL_ISSUER_BYTES},
        AuthMethod,
    },
    policy_eval::{input::has_unique_members, validate_path, DispatchFacts},
    rbac::rule::{
        AUTH_METHOD_BEARER_TOKEN, AUTH_METHOD_CLIENT_CERTIFICATE, AUTH_METHOD_SERVICE_TOKEN,
        AUTH_METHOD_SESSION_COOKIE,
    },
    request_bounds::{
        MAX_DISPATCH_FACT_BYTES, MAX_REQUEST_HOST_BYTES, MAX_REQUEST_METHOD_BYTES,
        MAX_REQUEST_PATH_BYTES, MAX_TOOL_NAME_BYTES,
    },
    upstream_route::is_bare_host,
};

/// The exact schema version this module reads and writes.
pub(crate) const REPLAY_CONTEXT_SCHEMA_VERSION: &str = "replay-context.v1";
/// Largest serialized context [`ReplayContext::parse`] reads. Every fact is
/// bounded by the limit live admission applies to it, and the largest context
/// those limits allow (roles dominate, at 256 of 256 bytes) is well inside it.
pub(crate) const MAX_REPLAY_CONTEXT_BYTES: usize = 128 * 1024;
/// Longest recorded rule id or permission a context keeps. A longer one is
/// dropped and the context says so with `attribution_omitted`.
pub(crate) const MAX_RECORDED_ELEMENT_BYTES: usize = 256;
/// Longest stable reason code a recorded result carries.
pub(crate) const MAX_REASON_CODE_BYTES: usize = 64;
/// Longest egress destination scheme a context carries.
const MAX_SCHEME_BYTES: usize = 32;
/// The prefix the classifier gives a pooled route's logical origin.
const POOL_ORIGIN_PREFIX: &str = "pool:";

/// The members each tagged fact allows, per state.
const STATE_ONLY: &[&str] = &["state"];
const AUTHENTICATED_MEMBERS: &[&str] = &["state", "subject", "issuer", "roles", "auth_method"];
const PRESENT_HOST_MEMBERS: &[&str] = &["state", "host"];
const LOCAL_ROUTING_MEMBERS: &[&str] = &["state", "mcp_identity"];
const DISPATCH_MEMBERS: &[&str] = &[
    "state",
    "route_id",
    "route_host",
    "route_path_prefix",
    "upstream_origin",
];
const ALIAS_MEMBERS: &[&str] = &["state", "canonical_path"];
const DESTINATION_MEMBERS: &[&str] = &[
    "state",
    "scheme",
    "host",
    "port",
    "userinfo",
    "fragment",
    "resolution",
];

/// Member names only a credential would be filed under. No context has such a
/// member, so they are already unknown; refusing them by name says the record
/// tried to carry what a replay context never carries.
const FORBIDDEN_MEMBERS: &[&str] = &[
    "access_token",
    "api_key",
    "authorization",
    "body",
    "client_secret",
    "cookie",
    "cookies",
    "credential",
    "credentials",
    "email",
    "headers",
    "id_token",
    "jwt",
    "password",
    "query",
    "refresh_token",
    "secret",
    "session",
    "session_id",
    "token",
];

/// One retained record, as the facts the kernel reads and the result the
/// gateway recorded. Built only by [`legacy`] or [`ReplayContext::parse`],
/// both of which bound every fact first.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ReplayContext {
    pub(crate) source: ReplaySource,
    pub(crate) facts: ReplayFacts,
    pub(crate) recorded: RecordedResult,
}

impl fmt::Debug for ReplayContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReplayContext")
            .field("source", &self.source)
            .field("lane", &self.facts.lane())
            .finish_non_exhaustive()
    }
}

/// Which kind of record a context was read from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReplaySource {
    /// `http.request_observed` for an HTTP request.
    HttpObservation,
    /// `tool.invoke_start`, or a `tool.invoke_rejected` written at admission.
    ToolAdmission,
    /// `authz.denied` written when a tool-name rule refused an invocation.
    ToolRuleDecision,
}

impl ReplaySource {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::HttpObservation => "http_observation",
            Self::ToolAdmission => "tool_admission",
            Self::ToolRuleDecision => "tool_rule_decision",
        }
    }

    fn parse(code: &str) -> Option<Self> {
        [
            Self::HttpObservation,
            Self::ToolAdmission,
            Self::ToolRuleDecision,
        ]
        .into_iter()
        .find(|source| source.as_str() == code)
    }
}

/// The facts of one request or invocation, per lane.
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum ReplayFacts {
    Http(HttpFacts),
    Tool(ToolFacts),
}

impl ReplayFacts {
    pub(crate) fn lane(&self) -> &'static str {
        match self {
            Self::Http(_) => "http",
            Self::Tool(_) => "tool",
        }
    }
}

/// What the HTTP lane, and rate-lane selection, read for one request.
///
/// Method and path are always recorded: every record an HTTP context is read
/// from carries both, so a context without them is a record that was not
/// adapted, not a context with a gap.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct HttpFacts {
    pub(crate) method: Method,
    /// Exact already-separated URI path; never a query, fragment or URL.
    pub(crate) path: String,
    pub(crate) principal: PrincipalRecord,
    pub(crate) request_host: HostRecord,
    pub(crate) routing: RoutingRecord,
    pub(crate) egress: EgressRecord,
}

/// What the tool lane reads for one invocation. v1 replays the invocation
/// operation only: no record states a visibility, inventory or composite
/// question, and a rendered tool request is not adapted (see [`legacy`]).
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ToolFacts {
    pub(crate) tool_name: String,
    pub(crate) principal: PrincipalRecord,
    pub(crate) egress: EgressRecord,
}

/// The caller, as recorded.
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum PrincipalRecord {
    /// The record has an actor whose identity it does not fully state.
    NotRecorded,
    /// No principal was authenticated for the request.
    Anonymous,
    Authenticated(RecordedPrincipal),
}

/// The policy facts of an authenticated caller: the four the kernel's principal
/// projection keeps, and nothing it drops.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct RecordedPrincipal {
    pub(crate) subject: String,
    pub(crate) issuer: Option<String>,
    pub(crate) roles: Vec<String>,
    pub(crate) auth_method: AuthMethod,
}

/// The request host, without port, as the routing lane compares it.
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum HostRecord {
    NotRecorded,
    /// The request carried no usable `Host`.
    Absent,
    Present(String),
}

/// How the request was classified for dispatch.
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum RoutingRecord {
    /// Classification was not recorded, or not fully: a dispatch-scoped rule
    /// cannot be judged.
    NotRecorded,
    /// Classified, and no proxy route was selected.
    Local(McpIdentity),
    /// Classified onto a proxy route, with the facts the classifier recorded.
    ProxyDispatch(DispatchFacts),
}

/// Whether a locally classified request's path was its own policy identity.
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum McpIdentity {
    /// The path is its own policy identity.
    Canonical,
    /// An MCP route reached by another path, decided under both identities.
    Alias { canonical_path: String },
    /// The path could have been an MCP route alias and the record does not say.
    NotRecorded,
}

/// An outbound destination, as the static egress lane reads it.
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum EgressRecord {
    NotRecorded,
    Destination(EgressFacts),
}

/// The destination facts [`crate::policy_eval::egress::EgressDestination`]
/// keeps. `userinfo` and `fragment` say whether the URL had one; their values
/// are never part of a context. v1 carries no resolution evidence, so an
/// admitted destination replays as indeterminate.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct EgressFacts {
    pub(crate) scheme: String,
    pub(crate) host: Option<String>,
    pub(crate) port: Option<u16>,
    pub(crate) userinfo: bool,
    pub(crate) fragment: bool,
}

/// What the gateway recorded for the policy stage at the time, under the
/// evaluator and resources it ran then. A comparison aid, never an input to a
/// replayed decision.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct RecordedResult {
    pub(crate) policy: RecordedPolicy,
    /// The policy stage's stable reason code.
    pub(crate) reason: Option<String>,
    pub(crate) matched_rule_id: Option<String>,
    pub(crate) permission: Option<String>,
    pub(crate) path_prefix: Option<String>,
    /// The record named a matched element too long to keep.
    pub(crate) attribution_omitted: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecordedPolicy {
    Allowed,
    Denied,
    /// A shadow decision: denied logically, forwarded.
    WouldDeny,
    /// A tool invocation passed policy admission; whether a shadow rule also
    /// observed it is recorded separately and not here.
    Admitted,
}

impl RecordedPolicy {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Denied => "denied",
            Self::WouldDeny => "would_deny",
            Self::Admitted => "admitted",
        }
    }

    fn parse(code: &str) -> Option<Self> {
        [Self::Allowed, Self::Denied, Self::WouldDeny, Self::Admitted]
            .into_iter()
            .find(|policy| policy.as_str() == code)
    }
}

/// Why a serialized context was refused. A stable code only: the refusal never
/// repeats a value, a member name or the parser's own message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReplayContextError {
    TooLarge,
    InvalidJson,
    DuplicateMember,
    UnsupportedSchemaVersion,
    UnknownMember,
    ForbiddenMember,
    MissingMember,
    InvalidType,
    InvalidValue,
    TooLong,
}

impl ReplayContextError {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::TooLarge => "replay_context_too_large",
            Self::InvalidJson => "invalid_json",
            Self::DuplicateMember => "duplicate_member",
            Self::UnsupportedSchemaVersion => "unsupported_schema_version",
            Self::UnknownMember => "unknown_member",
            Self::ForbiddenMember => "forbidden_member",
            Self::MissingMember => "missing_member",
            Self::InvalidType => "invalid_type",
            Self::InvalidValue => "invalid_value",
            Self::TooLong => "too_long",
        }
    }
}

/// Why one fact is out of bounds. The shared checks below answer with this so
/// the legacy adapter and the parser refuse exactly the same values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FactProblem {
    TooLong,
    Invalid,
}

impl From<FactProblem> for ReplayContextError {
    fn from(problem: FactProblem) -> Self {
        match problem {
            FactProblem::TooLong => Self::TooLong,
            FactProblem::Invalid => Self::InvalidValue,
        }
    }
}

/// A request method the kernel accepts: an HTTP token within the admission
/// bound.
pub(crate) fn check_method(method: &str) -> Result<Method, FactProblem> {
    if method.len() > MAX_REQUEST_METHOD_BYTES {
        return Err(FactProblem::TooLong);
    }
    Method::from_bytes(method.as_bytes()).map_err(|_| FactProblem::Invalid)
}

/// An exact request path the kernel accepts, checked by the kernel's own
/// predicate.
pub(crate) fn check_path(path: &str) -> Result<(), FactProblem> {
    if path.len() > MAX_REQUEST_PATH_BYTES {
        return Err(FactProblem::TooLong);
    }
    validate_path(path).map_err(|_| FactProblem::Invalid)
}

/// A principal authentication would have admitted: the shape check the kernel
/// applies, read from the same function.
pub(crate) fn check_principal(principal: &RecordedPrincipal) -> Result<(), FactProblem> {
    if principal.issuer.as_deref() == Some("") {
        return Err(FactProblem::Invalid);
    }
    check_principal_shape(
        &principal.subject,
        principal.issuer.as_deref(),
        &principal.roles,
    )
    .map_err(|problem| {
        if problem.is_size() {
            FactProblem::TooLong
        } else {
            FactProblem::Invalid
        }
    })
}

/// A bare host as the routing lane derives one: no port, lower-cased.
pub(crate) fn check_host(host: &str) -> Result<(), FactProblem> {
    if host.len() > MAX_REQUEST_HOST_BYTES {
        return Err(FactProblem::TooLong);
    }
    if !is_bare_host(host) {
        return Err(FactProblem::Invalid);
    }
    Ok(())
}

/// Dispatch facts as the classifier records them.
///
/// The origin is either a pooled route's logical `pool:` origin or an ASCII
/// serialized URL origin -- the only two forms the classifier writes. Anything
/// else could carry a path, a query or userinfo, none of which is a dispatch
/// fact, so it is refused rather than kept.
pub(crate) fn check_dispatch(facts: &DispatchFacts) -> Result<(), FactProblem> {
    for value in [
        facts.route_id.as_deref(),
        facts.route_host.as_deref(),
        facts.route_path_prefix.as_deref(),
        Some(facts.upstream_origin.as_str()),
    ]
    .into_iter()
    .flatten()
    {
        if value.len() > MAX_DISPATCH_FACT_BYTES {
            return Err(FactProblem::TooLong);
        }
        if value.is_empty() {
            return Err(FactProblem::Invalid);
        }
    }
    if let Some(host) = facts.route_host.as_deref() {
        check_host(host)?;
    }
    if !is_recorded_origin(&facts.upstream_origin) {
        return Err(FactProblem::Invalid);
    }
    Ok(())
}

fn is_recorded_origin(origin: &str) -> bool {
    match origin.strip_prefix(POOL_ORIGIN_PREFIX) {
        Some(route_id) => !route_id.is_empty(),
        None => Url::parse(origin).is_ok_and(|url| {
            let origin_form = url.origin();
            origin_form.is_tuple() && origin_form.ascii_serialization() == origin
        }),
    }
}

/// A tool name the tool lane accepts.
pub(crate) fn check_tool_name(name: &str) -> Result<(), FactProblem> {
    if name.len() > MAX_TOOL_NAME_BYTES {
        return Err(FactProblem::TooLong);
    }
    if name.is_empty() {
        return Err(FactProblem::Invalid);
    }
    Ok(())
}

/// A stable reason code: lower-case ASCII letters, digits, `_`, `.` and `-`.
pub(crate) fn check_reason_code(code: &str) -> Result<(), FactProblem> {
    if code.len() > MAX_REASON_CODE_BYTES {
        return Err(FactProblem::TooLong);
    }
    if code.is_empty()
        || !code.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_.-".contains(&byte)
        })
    {
        return Err(FactProblem::Invalid);
    }
    Ok(())
}

fn check_egress(facts: &EgressFacts) -> Result<(), FactProblem> {
    if facts.scheme.len() > MAX_SCHEME_BYTES {
        return Err(FactProblem::TooLong);
    }
    let mut scheme = facts.scheme.bytes();
    if !scheme.next().is_some_and(|byte| byte.is_ascii_lowercase())
        || !scheme.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"+-.".contains(&byte)
        })
    {
        return Err(FactProblem::Invalid);
    }
    if let Some(host) = facts.host.as_deref() {
        if host.len() > MAX_REQUEST_HOST_BYTES {
            return Err(FactProblem::TooLong);
        }
        if host.is_empty()
            || host
                .bytes()
                .any(|byte| byte <= b' ' || byte == 127 || b"/?#@".contains(&byte))
        {
            return Err(FactProblem::Invalid);
        }
    }
    Ok(())
}

fn check_recorded(recorded: &RecordedResult) -> Result<(), FactProblem> {
    if let Some(reason) = recorded.reason.as_deref() {
        check_reason_code(reason)?;
    }
    for element in [
        recorded.matched_rule_id.as_deref(),
        recorded.permission.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        if element.len() > MAX_RECORDED_ELEMENT_BYTES {
            return Err(FactProblem::TooLong);
        }
        if element.is_empty() {
            return Err(FactProblem::Invalid);
        }
    }
    if let Some(prefix) = recorded.path_prefix.as_deref() {
        if prefix.len() > MAX_REQUEST_PATH_BYTES {
            return Err(FactProblem::TooLong);
        }
        if prefix.is_empty() {
            return Err(FactProblem::Invalid);
        }
    }
    Ok(())
}

impl ReplayContext {
    /// Every bound the schema states, over an already-built context. The
    /// adapter and the parser both end here, so neither can produce a context
    /// the other would refuse.
    pub(crate) fn check(&self) -> Result<(), FactProblem> {
        match &self.facts {
            ReplayFacts::Http(facts) => {
                check_path(&facts.path)?;
                if facts.method.as_str().len() > MAX_REQUEST_METHOD_BYTES {
                    return Err(FactProblem::TooLong);
                }
                check_principal_record(&facts.principal)?;
                if let HostRecord::Present(host) = &facts.request_host {
                    check_host(host)?;
                }
                match &facts.routing {
                    RoutingRecord::NotRecorded | RoutingRecord::Local(McpIdentity::Canonical) => {}
                    RoutingRecord::Local(McpIdentity::NotRecorded) => {}
                    RoutingRecord::Local(McpIdentity::Alias { canonical_path }) => {
                        check_path(canonical_path)?;
                    }
                    RoutingRecord::ProxyDispatch(dispatch) => check_dispatch(dispatch)?,
                }
                check_egress_record(&facts.egress)?;
            }
            ReplayFacts::Tool(facts) => {
                check_tool_name(&facts.tool_name)?;
                check_principal_record(&facts.principal)?;
                check_egress_record(&facts.egress)?;
            }
        }
        check_recorded(&self.recorded)
    }

    /// The `replay-context.v1` JSON form. Deterministic: members are emitted in
    /// one fixed set, and a fact is either present or stated as missing.
    pub(crate) fn to_json(&self) -> Value {
        json!({
            "schema_version": REPLAY_CONTEXT_SCHEMA_VERSION,
            "source": self.source.as_str(),
            "facts": match &self.facts {
                ReplayFacts::Http(facts) => json!({
                    "lane": "http",
                    "method": facts.method.as_str(),
                    "path": facts.path,
                    "principal": principal_json(&facts.principal),
                    "request_host": match &facts.request_host {
                        HostRecord::NotRecorded => json!({ "state": "not_recorded" }),
                        HostRecord::Absent => json!({ "state": "absent" }),
                        HostRecord::Present(host) => json!({ "state": "present", "host": host }),
                    },
                    "routing": routing_json(&facts.routing),
                    "egress": egress_json(&facts.egress),
                }),
                ReplayFacts::Tool(facts) => json!({
                    "lane": "tool",
                    "operation": "invocation",
                    "tool_name": facts.tool_name,
                    "principal": principal_json(&facts.principal),
                    "egress": egress_json(&facts.egress),
                }),
            },
            "recorded": recorded_json(&self.recorded),
        })
    }

    /// Read a serialized context: exact version dispatch, unique members, no
    /// unknown member anywhere, and every bound [`Self::check`] states.
    pub(crate) fn parse(source: &[u8]) -> Result<Self, ReplayContextError> {
        if source.len() > MAX_REPLAY_CONTEXT_BYTES {
            return Err(ReplayContextError::TooLarge);
        }
        let value =
            serde_json::from_slice::<Value>(source).map_err(|_| ReplayContextError::InvalidJson)?;
        if !has_unique_members(source) {
            return Err(ReplayContextError::DuplicateMember);
        }
        Self::from_json(&value)
    }

    /// [`Self::parse`] over an already-parsed value, for a caller that holds
    /// one. A `Value` has already lost repeated member names, so a caller with
    /// the bytes should use [`Self::parse`].
    pub(crate) fn from_json(value: &Value) -> Result<Self, ReplayContextError> {
        let object = object(value)?;
        // The version decides everything else, so it is read first and alone.
        if object.get("schema_version").and_then(Value::as_str)
            != Some(REPLAY_CONTEXT_SCHEMA_VERSION)
        {
            return Err(ReplayContextError::UnsupportedSchemaVersion);
        }
        members(object, &["schema_version", "source", "facts", "recorded"])?;
        let source = ReplaySource::parse(text(required(object, "source")?)?)
            .ok_or(ReplayContextError::InvalidValue)?;
        let facts = parse_facts(required(object, "facts")?)?;
        let recorded = parse_recorded(required(object, "recorded")?)?;
        let context = Self {
            source,
            facts,
            recorded,
        };
        // Which lane a source writes is fixed; a tool source with HTTP facts
        // is not a record any adapter produces.
        let consistent = matches!(
            (context.source, &context.facts),
            (ReplaySource::HttpObservation, ReplayFacts::Http(_))
                | (
                    ReplaySource::ToolAdmission | ReplaySource::ToolRuleDecision,
                    ReplayFacts::Tool(_)
                )
        );
        if !consistent {
            return Err(ReplayContextError::InvalidValue);
        }
        context.check()?;
        Ok(context)
    }
}

fn check_principal_record(principal: &PrincipalRecord) -> Result<(), FactProblem> {
    match principal {
        PrincipalRecord::Authenticated(principal) => check_principal(principal),
        PrincipalRecord::NotRecorded | PrincipalRecord::Anonymous => Ok(()),
    }
}

fn check_egress_record(egress: &EgressRecord) -> Result<(), FactProblem> {
    match egress {
        EgressRecord::Destination(facts) => check_egress(facts),
        EgressRecord::NotRecorded => Ok(()),
    }
}

/// The audit `auth_mode` label of an authentication method, which is also the
/// policy's `auth_methods` value for it.
pub(crate) fn auth_method_code(method: &AuthMethod) -> &'static str {
    match method {
        AuthMethod::Bearer => AUTH_METHOD_BEARER_TOKEN,
        AuthMethod::Cookie => AUTH_METHOD_SESSION_COOKIE,
        AuthMethod::ServiceToken => AUTH_METHOD_SERVICE_TOKEN,
        AuthMethod::ClientCertificate => AUTH_METHOD_CLIENT_CERTIFICATE,
    }
}

/// The authentication method an audit `auth_mode` label names, if it is one
/// of the four a principal can carry.
pub(crate) fn auth_method_from_code(code: &str) -> Option<AuthMethod> {
    match code {
        AUTH_METHOD_BEARER_TOKEN => Some(AuthMethod::Bearer),
        AUTH_METHOD_SESSION_COOKIE => Some(AuthMethod::Cookie),
        AUTH_METHOD_SERVICE_TOKEN => Some(AuthMethod::ServiceToken),
        AUTH_METHOD_CLIENT_CERTIFICATE => Some(AuthMethod::ClientCertificate),
        _ => None,
    }
}

fn principal_json(principal: &PrincipalRecord) -> Value {
    match principal {
        PrincipalRecord::NotRecorded => json!({ "state": "not_recorded" }),
        PrincipalRecord::Anonymous => json!({ "state": "anonymous" }),
        PrincipalRecord::Authenticated(principal) => {
            let mut object = Map::new();
            object.insert("state".to_owned(), json!("authenticated"));
            object.insert("subject".to_owned(), json!(principal.subject));
            if let Some(issuer) = &principal.issuer {
                object.insert("issuer".to_owned(), json!(issuer));
            }
            object.insert("roles".to_owned(), json!(principal.roles));
            object.insert(
                "auth_method".to_owned(),
                json!(auth_method_code(&principal.auth_method)),
            );
            Value::Object(object)
        }
    }
}

fn routing_json(routing: &RoutingRecord) -> Value {
    match routing {
        RoutingRecord::NotRecorded => json!({ "state": "not_recorded" }),
        RoutingRecord::Local(identity) => json!({
            "state": "local",
            "mcp_identity": match identity {
                McpIdentity::Canonical => json!({ "state": "canonical" }),
                McpIdentity::Alias { canonical_path } => {
                    json!({ "state": "alias", "canonical_path": canonical_path })
                }
                McpIdentity::NotRecorded => json!({ "state": "not_recorded" }),
            },
        }),
        RoutingRecord::ProxyDispatch(facts) => {
            let mut object = Map::new();
            object.insert("state".to_owned(), json!("proxy_dispatch"));
            for (key, value) in [
                ("route_id", &facts.route_id),
                ("route_host", &facts.route_host),
                ("route_path_prefix", &facts.route_path_prefix),
            ] {
                if let Some(value) = value {
                    object.insert(key.to_owned(), json!(value));
                }
            }
            object.insert("upstream_origin".to_owned(), json!(facts.upstream_origin));
            Value::Object(object)
        }
    }
}

fn egress_json(egress: &EgressRecord) -> Value {
    match egress {
        EgressRecord::NotRecorded => json!({ "state": "not_recorded" }),
        EgressRecord::Destination(facts) => {
            let mut object = Map::new();
            object.insert("state".to_owned(), json!("destination"));
            object.insert("scheme".to_owned(), json!(facts.scheme));
            if let Some(host) = &facts.host {
                object.insert("host".to_owned(), json!(host));
            }
            if let Some(port) = facts.port {
                object.insert("port".to_owned(), json!(port));
            }
            object.insert("userinfo".to_owned(), json!(facts.userinfo));
            object.insert("fragment".to_owned(), json!(facts.fragment));
            object.insert("resolution".to_owned(), json!({ "state": "not_recorded" }));
            Value::Object(object)
        }
    }
}

fn recorded_json(recorded: &RecordedResult) -> Value {
    let mut object = Map::new();
    object.insert("policy".to_owned(), json!(recorded.policy.as_str()));
    for (key, value) in [
        ("reason", &recorded.reason),
        ("matched_rule_id", &recorded.matched_rule_id),
        ("permission", &recorded.permission),
        ("path_prefix", &recorded.path_prefix),
    ] {
        if let Some(value) = value {
            object.insert(key.to_owned(), json!(value));
        }
    }
    if recorded.attribution_omitted {
        object.insert("attribution_omitted".to_owned(), json!(true));
    }
    Value::Object(object)
}

fn object(value: &Value) -> Result<&Map<String, Value>, ReplayContextError> {
    value.as_object().ok_or(ReplayContextError::InvalidType)
}

/// Refuse every member not in `allowed`, naming a credential-shaped one
/// separately. The member's value is never read.
fn members(object: &Map<String, Value>, allowed: &[&str]) -> Result<(), ReplayContextError> {
    for key in object.keys() {
        if allowed.contains(&key.as_str()) {
            continue;
        }
        return Err(
            if FORBIDDEN_MEMBERS.contains(&key.to_ascii_lowercase().as_str()) {
                ReplayContextError::ForbiddenMember
            } else {
                ReplayContextError::UnknownMember
            },
        );
    }
    Ok(())
}

fn required<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a Value, ReplayContextError> {
    object.get(key).ok_or(ReplayContextError::MissingMember)
}

fn text(value: &Value) -> Result<&str, ReplayContextError> {
    value.as_str().ok_or(ReplayContextError::InvalidType)
}

fn optional_text<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> Result<Option<&'a str>, ReplayContextError> {
    object.get(key).map(text).transpose()
}

fn boolean(value: &Value) -> Result<bool, ReplayContextError> {
    value.as_bool().ok_or(ReplayContextError::InvalidType)
}

/// The `state` member of a tagged fact, after checking the object's members
/// against the ones that state allows.
fn state(
    object: &Map<String, Value>,
    allowed: impl Fn(&str) -> Option<&'static [&'static str]>,
) -> Result<&str, ReplayContextError> {
    let state = text(required(object, "state")?)?;
    let members_for_state = allowed(state).ok_or(ReplayContextError::InvalidValue)?;
    members(object, members_for_state)?;
    Ok(state)
}

fn parse_facts(value: &Value) -> Result<ReplayFacts, ReplayContextError> {
    let object = object(value)?;
    match text(required(object, "lane")?)? {
        "http" => {
            members(
                object,
                &[
                    "lane",
                    "method",
                    "path",
                    "principal",
                    "request_host",
                    "routing",
                    "egress",
                ],
            )?;
            let method = check_method(text(required(object, "method")?)?)?;
            let path = text(required(object, "path")?)?.to_owned();
            Ok(ReplayFacts::Http(HttpFacts {
                method,
                path,
                principal: parse_principal(required(object, "principal")?)?,
                request_host: parse_host(required(object, "request_host")?)?,
                routing: parse_routing(required(object, "routing")?)?,
                egress: parse_egress(required(object, "egress")?)?,
            }))
        }
        "tool" => {
            members(
                object,
                &["lane", "operation", "tool_name", "principal", "egress"],
            )?;
            if text(required(object, "operation")?)? != "invocation" {
                return Err(ReplayContextError::InvalidValue);
            }
            Ok(ReplayFacts::Tool(ToolFacts {
                tool_name: text(required(object, "tool_name")?)?.to_owned(),
                principal: parse_principal(required(object, "principal")?)?,
                egress: parse_egress(required(object, "egress")?)?,
            }))
        }
        _ => Err(ReplayContextError::InvalidValue),
    }
}

fn parse_principal(value: &Value) -> Result<PrincipalRecord, ReplayContextError> {
    let object = object(value)?;
    match state(object, |state| match state {
        "not_recorded" | "anonymous" => Some(STATE_ONLY),
        "authenticated" => Some(AUTHENTICATED_MEMBERS),
        _ => None,
    })? {
        "not_recorded" => Ok(PrincipalRecord::NotRecorded),
        "anonymous" => Ok(PrincipalRecord::Anonymous),
        _ => {
            let roles = required(object, "roles")?
                .as_array()
                .ok_or(ReplayContextError::InvalidType)?
                .iter()
                .map(|role| text(role).map(str::to_owned))
                .collect::<Result<Vec<_>, _>>()?;
            let issuer = optional_text(object, "issuer")?;
            if issuer.is_some_and(|issuer| issuer.len() > MAX_PRINCIPAL_ISSUER_BYTES) {
                return Err(ReplayContextError::TooLong);
            }
            Ok(PrincipalRecord::Authenticated(RecordedPrincipal {
                subject: text(required(object, "subject")?)?.to_owned(),
                issuer: issuer.map(str::to_owned),
                roles,
                auth_method: auth_method_from_code(text(required(object, "auth_method")?)?)
                    .ok_or(ReplayContextError::InvalidValue)?,
            }))
        }
    }
}

fn parse_host(value: &Value) -> Result<HostRecord, ReplayContextError> {
    let object = object(value)?;
    match state(object, |state| match state {
        "not_recorded" | "absent" => Some(STATE_ONLY),
        "present" => Some(PRESENT_HOST_MEMBERS),
        _ => None,
    })? {
        "not_recorded" => Ok(HostRecord::NotRecorded),
        "absent" => Ok(HostRecord::Absent),
        _ => Ok(HostRecord::Present(
            text(required(object, "host")?)?.to_owned(),
        )),
    }
}

fn parse_routing(value: &Value) -> Result<RoutingRecord, ReplayContextError> {
    let object = object(value)?;
    match state(object, |state| match state {
        "not_recorded" => Some(STATE_ONLY),
        "local" => Some(LOCAL_ROUTING_MEMBERS),
        "proxy_dispatch" => Some(DISPATCH_MEMBERS),
        _ => None,
    })? {
        "not_recorded" => Ok(RoutingRecord::NotRecorded),
        "local" => {
            let identity = self::object(required(object, "mcp_identity")?)?;
            Ok(RoutingRecord::Local(
                match state(identity, |state| match state {
                    "canonical" | "not_recorded" => Some(STATE_ONLY),
                    "alias" => Some(ALIAS_MEMBERS),
                    _ => None,
                })? {
                    "canonical" => McpIdentity::Canonical,
                    "not_recorded" => McpIdentity::NotRecorded,
                    _ => McpIdentity::Alias {
                        canonical_path: text(required(identity, "canonical_path")?)?.to_owned(),
                    },
                },
            ))
        }
        _ => Ok(RoutingRecord::ProxyDispatch(DispatchFacts {
            route_id: optional_text(object, "route_id")?.map(str::to_owned),
            route_host: optional_text(object, "route_host")?.map(str::to_owned),
            route_path_prefix: optional_text(object, "route_path_prefix")?.map(str::to_owned),
            upstream_origin: text(required(object, "upstream_origin")?)?.to_owned(),
        })),
    }
}

fn parse_egress(value: &Value) -> Result<EgressRecord, ReplayContextError> {
    let object = object(value)?;
    match state(object, |state| match state {
        "not_recorded" => Some(STATE_ONLY),
        "destination" => Some(DESTINATION_MEMBERS),
        _ => None,
    })? {
        "not_recorded" => Ok(EgressRecord::NotRecorded),
        _ => {
            // v1 records no resolution evidence; the member exists so that a
            // reader is told so rather than left to infer it.
            let resolution = self::object(required(object, "resolution")?)?;
            state(resolution, |state| {
                (state == "not_recorded").then_some(STATE_ONLY)
            })?;
            let port = match object.get("port") {
                None => None,
                Some(port) => Some(
                    port.as_u64()
                        .and_then(|port| u16::try_from(port).ok())
                        .ok_or(ReplayContextError::InvalidValue)?,
                ),
            };
            Ok(EgressRecord::Destination(EgressFacts {
                scheme: text(required(object, "scheme")?)?.to_owned(),
                host: optional_text(object, "host")?.map(str::to_owned),
                port,
                userinfo: boolean(required(object, "userinfo")?)?,
                fragment: boolean(required(object, "fragment")?)?,
            }))
        }
    }
}

fn parse_recorded(value: &Value) -> Result<RecordedResult, ReplayContextError> {
    let object = object(value)?;
    members(
        object,
        &[
            "policy",
            "reason",
            "matched_rule_id",
            "permission",
            "path_prefix",
            "attribution_omitted",
        ],
    )?;
    let attribution_omitted = match object.get("attribution_omitted") {
        None => false,
        // Written only when true, so that one context has one serialization.
        Some(Value::Bool(true)) => true,
        Some(_) => return Err(ReplayContextError::InvalidValue),
    };
    Ok(RecordedResult {
        policy: RecordedPolicy::parse(text(required(object, "policy")?)?)
            .ok_or(ReplayContextError::InvalidValue)?,
        reason: optional_text(object, "reason")?.map(str::to_owned),
        matched_rule_id: optional_text(object, "matched_rule_id")?.map(str::to_owned),
        permission: optional_text(object, "permission")?.map(str::to_owned),
        path_prefix: optional_text(object, "path_prefix")?.map(str::to_owned),
        attribution_omitted,
    })
}
