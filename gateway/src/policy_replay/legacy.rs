//! Replay contexts read out of the audit records the gateway writes today.
//!
//! None of these records was designed for replay, so each adapter states what
//! its record does and does not establish, and says so per fact rather than
//! per record. [`adapt_audit_event`] reads one stored event and answers with
//! exactly one [`LegacyRecord`]: the event is the one replayable record of a
//! request or invocation, or another record covers it, or it is refused with a
//! stable code. Nothing is dropped without a code, so a replay over a window
//! can always say how many records it could not use and why.
//!
//! ## One canonical record per request and per invocation
//!
//! A request or a tool invocation leaves several events, and replaying each
//! would count it several times. The adapter therefore names one of them as
//! replayable and every other one as a duplicate of it:
//!
//! | Request or invocation | Replayable record | Duplicates |
//! | --- | --- | --- |
//! | HTTP request | `http.request_observed` | its `authz.*` decision |
//! | Tool invocation admitted by policy | `tool.invoke_start`, or the `tool.invoke_rejected` a full queue, queue timeout, cancellation or lease outage wrote instead | a tool-rule `authz.allowed` / `authz.would_deny`, its outcome events, its tool observation |
//! | Tool invocation refused by its entry, or by the evaluator | `tool.invoke_rejected` (`unknown_tool`, `disabled`, `role_not_allowed`, or a policy refusal) | its tool observation |
//! | Tool invocation refused by a tool-name rule | the tool-rule `authz.denied` | the `tool.invoke_rejected` (`matched_rule`) written beside it, its tool observation |
//!
//! A `matched_rule` rejection is never the replayable one because the runtime
//! writes the same rejection when a rendered HTTP rule refuses an invocation it
//! had already admitted: the reason alone cannot tell the two apart, and the
//! tool-rule decision, or the invocation's start, always exists beside it.
//!
//! ## What the records establish
//!
//! - **Envelope.** Events at audit schema `0.1.0` predate the actor's issuer, so
//!   an actor in one is `not_recorded`: its issuer may have existed and is not
//!   known. `0.2.0` records the issuer whenever the principal had one. Any
//!   other version is unsupported.
//! - **Principal.** No actor is an anonymous request. An actor names one of the
//!   four authentication methods a principal can carry, or it is
//!   `not_recorded` rather than guessed.
//! - **Routing and host.** Observations record the routing classification
//!   (`routing_context_known`), the request host and the dispatch facts since
//!   the same change; an observation without `routing_context_known` records
//!   neither, and its host is `not_recorded`, not absent. A dispatch recorded
//!   without a route id predates route ids, which every dispatch now carries,
//!   so its routing is `not_recorded`: a route-scoped rule cannot be judged.
//! - **MCP alias identity.** Never recorded. A locally classified path that no
//!   configuration could serve as an MCP alias is its own identity; one that
//!   could ([`could_be_mcp_route_alias`]) is `not_recorded`, and replay decides
//!   it only when both readings agree.
//! - **Egress.** Never recorded: no record names the destination a request
//!   connected to or what it resolved to. Every context says `not_recorded`.
//! - **Not adapted.** A request that never reached the policy stage
//!   (`policy_decision: not_evaluated` -- refused by authentication, exempt, or
//!   a probe) is not a policy question. A rendered tool request's `authz.*`
//!   record carries the rendered path, which holds tool arguments, and is not
//!   adapted at all.

use serde_json::{Map, Value};

use crate::{
    audit::{event, Actor, AuditEvent},
    auth::protected_resource::MCP_RESOURCE_PATH,
    middleware::rbac::ToolPolicyRefusal,
    policy_eval::DispatchFacts,
    request_bounds::MAX_REQUEST_PATH_BYTES,
};

use super::{
    auth_method_from_code, check_dispatch, check_host, check_method, check_path, check_principal,
    check_reason_code, check_tool_name, EgressRecord, HostRecord, HttpFacts, McpIdentity,
    PrincipalRecord, RecordedPolicy, RecordedPrincipal, RecordedResult, ReplayContext, ReplayFacts,
    ReplaySource, RoutingRecord, ToolFacts, MAX_RECORDED_ELEMENT_BYTES,
};

const HTTP_REQUEST_OBSERVED: &str = "http.request_observed";
const AUTHZ_ALLOWED: &str = "authz.allowed";
const AUTHZ_DENIED: &str = "authz.denied";
const AUTHZ_WOULD_DENY: &str = "authz.would_deny";
const AUTHZ_REVISION_CHECK_FAILED: &str = "authz.revision_check_failed";
/// The method a tool-name rule's decision record carries in place of an HTTP
/// method; a rendered tool request's record carries the rendered one.
const TOOL_RULE_METHOD: &str = "MCP";
/// The envelope before the actor recorded an issuer.
const ENVELOPE_WITHOUT_ISSUER: &str = "0.1.0";
/// The envelope this adapter was written against. A new envelope version is
/// unsupported until the adapter is reviewed for it.
const ENVELOPE_WITH_ISSUER: &str = "0.2.0";

/// Rejections the tool lane writes when policy refuses an invocation at
/// admission: its entry, or the evaluator's refusal to answer.
const POLICY_REJECTIONS: &[&str] = &["unknown_tool", "disabled", "role_not_allowed"];
/// Rejections written after policy admitted an invocation and before it
/// started: capacity and the execution-lease authority.
const CAPACITY_REJECTIONS: &[&str] = &[
    "queue_full",
    "queue_timeout",
    "cancelled",
    "authority_unavailable",
];
/// Rejections another record of the same invocation always covers.
const COVERED_REJECTIONS: &[&str] = &["matched_rule", "precondition_failed"];

/// What one stored audit event is to replay.
#[derive(Debug)]
pub(crate) enum LegacyRecord {
    /// The one replayable record of its request or invocation, boxed: a
    /// context is far larger than every other answer, which is a code.
    Replayable(Box<ReplayContext>),
    /// Another record of the same request or invocation is the replayable one.
    Duplicate(DuplicateRecord),
    /// The request never reached the policy stage.
    NotPolicyEvaluated,
    /// A request record replay does not adapt.
    Unsupported(UnsupportedRecord),
    /// A request record this gateway would not have written.
    Malformed(MalformedRecord),
    /// Not a request or invocation record at all.
    NotRequestRecord,
}

impl LegacyRecord {
    /// The stable code a replay counts this record under.
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::Replayable(_) => "replayable",
            Self::Duplicate(duplicate) => duplicate.as_str(),
            Self::NotPolicyEvaluated => "not_policy_evaluated",
            Self::Unsupported(unsupported) => unsupported.as_str(),
            Self::Malformed(malformed) => malformed.as_str(),
            Self::NotRequestRecord => "not_request_record",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DuplicateRecord {
    /// The `http.request_observed` a tool invocation writes.
    ToolObservation,
    /// An HTTP request's `authz.*` record; its observation is replayable.
    HttpDecision,
    /// A tool-rule allow or shadow; the invocation's admission is replayable.
    ToolRuleDecision,
    /// A `tool.invoke_rejected` another record of the invocation covers.
    ToolRejection,
    /// `tool.invoke_success` or `tool.invoke_failure`, after admission.
    ToolOutcome,
}

impl DuplicateRecord {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::ToolObservation => "duplicate_tool_observation",
            Self::HttpDecision => "duplicate_http_decision",
            Self::ToolRuleDecision => "duplicate_tool_rule_decision",
            Self::ToolRejection => "duplicate_tool_rejection",
            Self::ToolOutcome => "duplicate_tool_outcome",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UnsupportedRecord {
    EnvelopeVersion,
    /// A rendered tool request's decision: its path carries tool arguments.
    RenderedToolRequest,
    /// A `tool.invoke_rejected` reason this adapter does not know, so it cannot
    /// say whether the record is its invocation's replayable one.
    ToolRejectionReason,
}

impl UnsupportedRecord {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::EnvelopeVersion => "unsupported_envelope_version",
            Self::RenderedToolRequest => "unsupported_rendered_tool_request",
            Self::ToolRejectionReason => "unsupported_tool_rejection",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MalformedRecord {
    Payload,
    Method,
    Path,
    Principal,
    RequestHost,
    Routing,
    ToolName,
    PolicyDecision,
    RecordedResult,
}

impl MalformedRecord {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Payload => "malformed_payload",
            Self::Method => "malformed_method",
            Self::Path => "malformed_path",
            Self::Principal => "malformed_principal",
            Self::RequestHost => "malformed_request_host",
            Self::Routing => "malformed_routing",
            Self::ToolName => "malformed_tool_name",
            Self::PolicyDecision => "malformed_policy_decision",
            Self::RecordedResult => "malformed_recorded_result",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Envelope {
    WithoutIssuer,
    WithIssuer,
}

/// Whether this gateway could have served `path` as an MCP route alias.
///
/// Every alias [`crate::auth::protected_resource::mcp_route_paths`] derives
/// is the public URL's path with the canonical MCP path appended, so an alias
/// always ends in it, and the canonical path itself is never an alias. Any
/// other path is its own policy identity under every configuration, which is
/// what lets a record that does not state its MCP identity still be read
/// exactly for every other path.
pub(crate) fn could_be_mcp_route_alias(path: &str) -> bool {
    path != MCP_RESOURCE_PATH && path.ends_with(MCP_RESOURCE_PATH)
}

/// Read one stored audit event.
pub(crate) fn adapt_audit_event(event: &AuditEvent) -> LegacyRecord {
    let request_record = matches!(
        event.event_type.as_str(),
        HTTP_REQUEST_OBSERVED
            | AUTHZ_ALLOWED
            | AUTHZ_DENIED
            | AUTHZ_WOULD_DENY
            | AUTHZ_REVISION_CHECK_FAILED
            | event::TOOL_INVOKE_START
            | event::TOOL_INVOKE_REJECTED
            | event::TOOL_INVOKE_SUCCESS
            | event::TOOL_INVOKE_FAILURE
    );
    if !request_record {
        return LegacyRecord::NotRequestRecord;
    }
    let envelope = match event.schema_version.as_str() {
        ENVELOPE_WITHOUT_ISSUER => Envelope::WithoutIssuer,
        ENVELOPE_WITH_ISSUER => Envelope::WithIssuer,
        _ => return LegacyRecord::Unsupported(UnsupportedRecord::EnvelopeVersion),
    };
    let Some(payload) = event.payload.as_object() else {
        return LegacyRecord::Malformed(MalformedRecord::Payload);
    };
    let adapted = match event.event_type.as_str() {
        HTTP_REQUEST_OBSERVED => observation(event.actor.as_ref(), envelope, payload),
        AUTHZ_ALLOWED | AUTHZ_DENIED | AUTHZ_WOULD_DENY | AUTHZ_REVISION_CHECK_FAILED => {
            decision(event, envelope, payload)
        }
        event::TOOL_INVOKE_START => tool_admission(
            event.actor.as_ref(),
            envelope,
            payload,
            RecordedPolicy::Admitted,
            None,
        ),
        event::TOOL_INVOKE_REJECTED => tool_rejection(event.actor.as_ref(), envelope, payload),
        _ => Ok(LegacyRecord::Duplicate(DuplicateRecord::ToolOutcome)),
    };
    adapted.unwrap_or_else(LegacyRecord::Malformed)
}

/// An `http.request_observed` event.
fn observation(
    actor: Option<&Actor>,
    envelope: Envelope,
    payload: &Map<String, Value>,
) -> Result<LegacyRecord, MalformedRecord> {
    // The tool runtime writes an observation of its own for each invocation,
    // with the tool's name; an HTTP request's observation never has one.
    if payload.contains_key("tool_name") {
        return Ok(LegacyRecord::Duplicate(DuplicateRecord::ToolObservation));
    }
    let policy = match payload.get("policy_decision").and_then(Value::as_str) {
        Some("allowed") => RecordedPolicy::Allowed,
        Some("denied") => RecordedPolicy::Denied,
        Some("would_deny") => RecordedPolicy::WouldDeny,
        Some("not_evaluated") => return Ok(LegacyRecord::NotPolicyEvaluated),
        _ => return Err(MalformedRecord::PolicyDecision),
    };
    let method = string(payload, "method")
        .and_then(|method| check_method(method).ok())
        .ok_or(MalformedRecord::Method)?;
    let path = string(payload, "path")
        .filter(|path| check_path(path).is_ok())
        .ok_or(MalformedRecord::Path)?
        .to_owned();
    let principal = principal_record(actor, envelope)?;
    let (request_host, routing) = observed_routing(payload, &path)?;
    let recorded = recorded_result(policy, payload, "policy_reason")?;
    Ok(LegacyRecord::Replayable(Box::new(ReplayContext {
        source: ReplaySource::HttpObservation,
        facts: ReplayFacts::Http(HttpFacts {
            method,
            path,
            principal,
            request_host,
            routing,
            egress: EgressRecord::NotRecorded,
        }),
        recorded,
    })))
}

/// The host and routing an observation recorded, read exactly as the
/// classifier left them on the request.
fn observed_routing(
    payload: &Map<String, Value>,
    path: &str,
) -> Result<(HostRecord, RoutingRecord), MalformedRecord> {
    let classified = match payload.get("routing_context_known") {
        // Recorded since the change that recorded the host too: before it,
        // neither was, and an unrecorded host is not an absent one.
        None => return Ok((HostRecord::NotRecorded, RoutingRecord::NotRecorded)),
        Some(Value::Bool(classified)) => *classified,
        Some(_) => return Err(MalformedRecord::Routing),
    };
    let request_host = match payload.get("request_host") {
        None => HostRecord::Absent,
        Some(Value::String(host)) if check_host(host).is_ok() => HostRecord::Present(host.clone()),
        Some(_) => return Err(MalformedRecord::RequestHost),
    };
    let route_fact = |key: &str| match payload.get(key) {
        None => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(MalformedRecord::Routing),
    };
    let route_id = route_fact("upstream_route_id")?;
    let route_host = route_fact("upstream_route_host")?;
    let route_path_prefix = route_fact("upstream_route_path_prefix")?;
    let upstream_origin = route_fact("upstream_origin")?;
    let any_route_fact = route_id.is_some() || route_host.is_some() || route_path_prefix.is_some();
    if !classified {
        // The classifier records dispatch facts only for a request it
        // classified; facts on an unclassified one did not come from it.
        if any_route_fact || upstream_origin.is_some() {
            return Err(MalformedRecord::Routing);
        }
        return Ok((request_host, RoutingRecord::NotRecorded));
    }
    let routing = match upstream_origin {
        Some(upstream_origin) => {
            let facts = DispatchFacts {
                route_id,
                route_host,
                route_path_prefix,
                upstream_origin,
            };
            check_dispatch(&facts).map_err(|_| MalformedRecord::Routing)?;
            if facts.route_id.is_some() {
                RoutingRecord::ProxyDispatch(facts)
            } else {
                RoutingRecord::NotRecorded
            }
        }
        // Route facts without an origin cannot come from the classifier.
        None if any_route_fact => return Err(MalformedRecord::Routing),
        None if could_be_mcp_route_alias(path) => RoutingRecord::Local(McpIdentity::NotRecorded),
        None => RoutingRecord::Local(McpIdentity::Canonical),
    };
    Ok((request_host, routing))
}

/// An `authz.*` event. Only a tool-name rule's denial is replayable; see the
/// module documentation.
fn decision(
    event: &AuditEvent,
    envelope: Envelope,
    payload: &Map<String, Value>,
) -> Result<LegacyRecord, MalformedRecord> {
    if !payload.contains_key("tool_name") {
        return Ok(LegacyRecord::Duplicate(DuplicateRecord::HttpDecision));
    }
    if string(payload, "method") != Some(TOOL_RULE_METHOD) {
        return Ok(LegacyRecord::Unsupported(
            UnsupportedRecord::RenderedToolRequest,
        ));
    }
    match event.event_type.as_str() {
        AUTHZ_DENIED => {}
        AUTHZ_ALLOWED | AUTHZ_WOULD_DENY => {
            return Ok(LegacyRecord::Duplicate(DuplicateRecord::ToolRuleDecision))
        }
        // The tool lane writes no revision-check record.
        _ => return Err(MalformedRecord::Payload),
    }
    let tool_name = tool_name(payload)?;
    let principal = principal_record(event.actor.as_ref(), envelope)?;
    let recorded = recorded_result(RecordedPolicy::Denied, payload, "reason")?;
    Ok(LegacyRecord::Replayable(Box::new(ReplayContext {
        source: ReplaySource::ToolRuleDecision,
        facts: ReplayFacts::Tool(ToolFacts {
            tool_name,
            principal,
            egress: EgressRecord::NotRecorded,
        }),
        recorded,
    })))
}

/// A `tool.invoke_rejected` event, by the reason it carries.
fn tool_rejection(
    actor: Option<&Actor>,
    envelope: Envelope,
    payload: &Map<String, Value>,
) -> Result<LegacyRecord, MalformedRecord> {
    let reason = string(payload, "reason").ok_or(MalformedRecord::RecordedResult)?;
    if POLICY_REJECTIONS.contains(&reason) || ToolPolicyRefusal::REASONS.contains(&reason) {
        tool_admission(
            actor,
            envelope,
            payload,
            RecordedPolicy::Denied,
            Some(reason),
        )
    } else if CAPACITY_REJECTIONS.contains(&reason) {
        // Policy admitted the call; what refused it is not a policy result.
        tool_admission(actor, envelope, payload, RecordedPolicy::Admitted, None)
    } else if COVERED_REJECTIONS.contains(&reason) {
        Ok(LegacyRecord::Duplicate(DuplicateRecord::ToolRejection))
    } else {
        Ok(LegacyRecord::Unsupported(
            UnsupportedRecord::ToolRejectionReason,
        ))
    }
}

fn tool_admission(
    actor: Option<&Actor>,
    envelope: Envelope,
    payload: &Map<String, Value>,
    policy: RecordedPolicy,
    reason: Option<&str>,
) -> Result<LegacyRecord, MalformedRecord> {
    let tool_name = tool_name(payload)?;
    let principal = principal_record(actor, envelope)?;
    if let Some(reason) = reason {
        check_reason_code(reason).map_err(|_| MalformedRecord::RecordedResult)?;
    }
    Ok(LegacyRecord::Replayable(Box::new(ReplayContext {
        source: ReplaySource::ToolAdmission,
        facts: ReplayFacts::Tool(ToolFacts {
            tool_name,
            principal,
            egress: EgressRecord::NotRecorded,
        }),
        recorded: RecordedResult {
            policy,
            reason: reason.map(str::to_owned),
            matched_rule_id: None,
            permission: None,
            path_prefix: None,
            attribution_omitted: false,
        },
    })))
}

fn tool_name(payload: &Map<String, Value>) -> Result<String, MalformedRecord> {
    string(payload, "tool_name")
        .filter(|name| check_tool_name(name).is_ok())
        .map(str::to_owned)
        .ok_or(MalformedRecord::ToolName)
}

/// The principal an audit actor records; see the module documentation.
fn principal_record(
    actor: Option<&Actor>,
    envelope: Envelope,
) -> Result<PrincipalRecord, MalformedRecord> {
    let Some(actor) = actor else {
        return Ok(PrincipalRecord::Anonymous);
    };
    if envelope == Envelope::WithoutIssuer {
        return Ok(PrincipalRecord::NotRecorded);
    }
    let Some(auth_method) = auth_method_from_code(&actor.auth_mode) else {
        return Ok(PrincipalRecord::NotRecorded);
    };
    let principal = RecordedPrincipal {
        subject: actor.user_id.clone(),
        issuer: actor.issuer.clone(),
        roles: actor.roles.clone().unwrap_or_default(),
        auth_method,
    };
    // Authentication refuses a principal outside these bounds, so an actor
    // outside them is not one a served request left.
    check_principal(&principal).map_err(|_| MalformedRecord::Principal)?;
    Ok(PrincipalRecord::Authenticated(principal))
}

/// The policy result a record states: its stable reason, and the element that
/// decided. An element too long to keep is dropped and flagged, never cut.
fn recorded_result(
    policy: RecordedPolicy,
    payload: &Map<String, Value>,
    reason_key: &str,
) -> Result<RecordedResult, MalformedRecord> {
    let reason = match payload.get(reason_key) {
        None => None,
        Some(Value::String(reason)) if check_reason_code(reason).is_ok() => Some(reason.clone()),
        Some(_) => return Err(MalformedRecord::RecordedResult),
    };
    let mut attribution_omitted = false;
    let mut element = |key: &str, max_bytes: usize| match payload.get(key) {
        None => Ok(None),
        Some(Value::String(value)) if value.is_empty() => Err(MalformedRecord::RecordedResult),
        Some(Value::String(value)) if value.len() > max_bytes => {
            attribution_omitted = true;
            Ok(None)
        }
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(MalformedRecord::RecordedResult),
    };
    let matched_rule_id = element("matched_rule_id", MAX_RECORDED_ELEMENT_BYTES)?;
    let permission = element("permission", MAX_RECORDED_ELEMENT_BYTES)?;
    let path_prefix = element("path_prefix", MAX_REQUEST_PATH_BYTES)?;
    Ok(RecordedResult {
        policy,
        reason,
        matched_rule_id,
        permission,
        path_prefix,
        attribution_omitted,
    })
}

fn string<'a>(payload: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    payload.get(key).and_then(Value::as_str)
}
