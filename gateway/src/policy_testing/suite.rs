//! The `policy-tests.v1` document: a strict, exact-version list of synthetic
//! cases, each a typed hypothetical input and an expectation.
//!
//! The parser reads a `serde_json::Value` by hand rather than through derived
//! deserializers so that every refusal is a [`Diagnostic`] with a stable code
//! and a JSON Pointer, and so that no refusal ever echoes an input value: a
//! serde error message quotes the offending value, and a fixture value is
//! exactly what must not reach a log, an error body or an audit record.
//!
//! What a case can say is deliberately narrow. Identity is a typed set of
//! policy facts -- subject, issuer, roles, authentication method -- and never a
//! token, cookie, header or credential: there is no field to put one in, and a
//! member named like one is refused with its own code rather than as an
//! ordinary typo.

use http::Method;
use serde::Serialize;
use serde_json::{Map, Value};
use url::Url;

use crate::{
    auth::{
        principal::{canonical_issuer, check_principal_shape, MAX_PRINCIPAL_ISSUER_BYTES},
        AuthMethod, Principal,
    },
    canonical_json,
    policy_eval::{
        tools::{validate_rendered_http_path, ToolOperation},
        validate_path, DispatchFacts, LogicalDecision, PolicyEffect, Reason,
    },
    rbac::rule::{
        AUTH_METHOD_BEARER_TOKEN, AUTH_METHOD_CLIENT_CERTIFICATE, AUTH_METHOD_SERVICE_TOKEN,
        AUTH_METHOD_SESSION_COOKIE,
    },
    request_bounds::{
        MAX_DISPATCH_FACT_BYTES, MAX_REQUEST_HOST_BYTES, MAX_REQUEST_METHOD_BYTES,
        MAX_TOOL_NAME_BYTES,
    },
    upstream_route::is_bare_host,
};

/// The only schema version this parser implements. Exact dispatch: a later
/// version is refused, never read as this one.
pub(crate) const SUITE_SCHEMA_VERSION: &str = "policy-tests.v1";
/// The media type the suite digest is framed with.
pub(crate) const SUITE_MEDIA_TYPE: &str = "application/vnd.greengateway.policy-tests+json";
/// Most cases one suite may declare. Each is one evaluator call, so this and
/// the request-body limit together bound the work of one run.
pub(crate) const MAX_CASES: usize = 512;
/// Longest case identifier, in bytes.
pub(crate) const MAX_CASE_ID_BYTES: usize = 128;
/// Longest suite or case description, in bytes.
pub(crate) const MAX_DESCRIPTION_BYTES: usize = 1024;
/// Most diagnostics one refusal reports; the rest are summarized as truncated.
pub(crate) const MAX_DIAGNOSTICS: usize = 64;
/// Largest route or rate-override position an expectation may name: far
/// beyond any realistic policy, and small enough that it is never a lossy
/// number on any platform or in any JSON reader.
pub(crate) const MAX_EXPECTED_INDEX: u64 = 1 << 20;
/// Longest member name a diagnostic pointer repeats; a longer one is
/// described instead of quoted.
const MAX_POINTER_MEMBER_BYTES: usize = 64;

/// Member names that only a credential would be filed under. A case has no
/// such field, so these are already unknown; naming them separately tells the
/// author that the problem is what they tried to supply, not a typo.
const FORBIDDEN_MEMBERS: &[&str] = &[
    "access_token",
    "api_key",
    "apikey",
    "authorization",
    "bearer",
    "client_secret",
    "cookie",
    "cookies",
    "credential",
    "credentials",
    "headers",
    "id_token",
    "jwt",
    "password",
    "refresh_token",
    "secret",
    "session",
    "session_id",
    "token",
];

/// One reason a suite was refused: a stable code, where, and a fixed sentence
/// that never contains an input value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct Diagnostic {
    pub(crate) code: &'static str,
    pub(crate) pointer: String,
    pub(crate) message: String,
}

/// Every diagnostic a refused suite produced, up to [`MAX_DIAGNOSTICS`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct Diagnostics {
    pub(crate) diagnostics: Vec<Diagnostic>,
    pub(crate) truncated: bool,
}

impl Diagnostics {
    pub(crate) fn new() -> Self {
        Self {
            diagnostics: Vec::new(),
            truncated: false,
        }
    }

    pub(crate) fn push(&mut self, code: &'static str, pointer: &str, message: impl Into<String>) {
        if self.diagnostics.len() < MAX_DIAGNOSTICS {
            self.diagnostics.push(Diagnostic {
                code,
                pointer: pointer.to_owned(),
                message: message.into(),
            });
        } else {
            self.truncated = true;
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.diagnostics.is_empty() && !self.truncated
    }
}

/// An accepted suite. Only [`parse_suite`] builds one, so every case in it has
/// already been checked against the bounds the evaluator enforces.
///
/// None of the suite's types derive `Debug`: a case holds fixture values, and
/// a formatted case in a log line is exactly the secondary output ADR-0004
/// keeps them out of. The suite itself formats as its digest and size.
pub(crate) struct Suite {
    pub(crate) digest: String,
    pub(crate) cases: Vec<Case>,
}

impl std::fmt::Debug for Suite {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Suite")
            .field("digest", &self.digest)
            .field("cases", &self.cases.len())
            .finish()
    }
}

pub(crate) struct Case {
    pub(crate) id: String,
    /// The JSON Pointer of the case in the submitted suite, for reports.
    pub(crate) pointer: String,
    pub(crate) input: CaseInput,
}

/// What a case asks, per lane. Each variant carries the expectation that lane
/// can answer, so an HTTP case cannot carry a rate expectation by accident.
pub(crate) enum CaseInput {
    Http {
        request: HttpRequest,
        principal: SyntheticPrincipal,
        expect: DecisionExpectation<Reason>,
    },
    Tool {
        operation: ToolOperation,
        tool_name: String,
        principal: SyntheticPrincipal,
        expect: DecisionExpectation<crate::policy_eval::tools::ToolReason>,
    },
    ToolHttp {
        tool_name: String,
        method: Method,
        path: String,
        principal: SyntheticPrincipal,
        expect: DecisionExpectation<crate::policy_eval::tools::ToolReason>,
    },
    Rate {
        method: Method,
        path: String,
        principal: SyntheticPrincipal,
        expect: RateExpectation,
    },
}

impl CaseInput {
    pub(crate) fn kind(&self) -> CaseKind {
        match self {
            Self::Http { .. } => CaseKind::Http,
            Self::Tool { .. } => CaseKind::Tool,
            Self::ToolHttp { .. } => CaseKind::ToolHttp,
            Self::Rate { .. } => CaseKind::Rate,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CaseKind {
    Http,
    Tool,
    ToolHttp,
    Rate,
}

impl CaseKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Tool => "tool",
            Self::ToolHttp => "tool_http",
            Self::Rate => "rate",
        }
    }
}

pub(crate) struct HttpRequest {
    pub(crate) method: Method,
    pub(crate) path: String,
    /// `None` is a request with no `Host` header, which is a fact, not a gap:
    /// a synthetic case states every fact it depends on.
    pub(crate) host: Option<String>,
    pub(crate) target: SyntheticTarget,
}

pub(crate) enum SyntheticTarget {
    Contextless,
    McpAlias { canonical_path: String },
    ProxyDispatch(DispatchFacts),
}

pub(crate) enum SyntheticPrincipal {
    Anonymous,
    Authenticated(Principal),
}

/// What an HTTP or tool case expects. `logical` is required; the rest are
/// asserted only when present.
#[derive(Debug)]
pub(crate) struct DecisionExpectation<R> {
    pub(crate) logical: LogicalDecision,
    pub(crate) effect: Option<PolicyEffect>,
    pub(crate) reason: Option<R>,
    pub(crate) matched: Option<MatchedExpectation>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum MatchedExpectation {
    None,
    /// A direct rule by its effective identifier: its `id`, or its position
    /// for a rule without one, as every other policy API names it.
    Rule(String),
    /// A route by position; v0 routes carry no identifier.
    Route(usize),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RateExpectation {
    NoOverride,
    Override(usize),
}

/// Parse and validate a suite, or say every reason it is refused.
///
/// The digest is the ADR-0004 semantic digest of the accepted document: its
/// RFC 8785 bytes, framed with [`SUITE_MEDIA_TYPE`] and
/// [`SUITE_SCHEMA_VERSION`]. This version defines no normalization beyond
/// JCS, so two suites have the same digest exactly when they are the same
/// JSON value.
pub(crate) fn parse_suite(value: &Value) -> Result<Suite, Diagnostics> {
    let mut diagnostics = Diagnostics::new();
    let Some(root) = object(value, "", &mut diagnostics) else {
        return Err(diagnostics);
    };
    check_members(
        root,
        "",
        &["schema_version", "description", "cases"],
        &mut diagnostics,
    );
    match root.get("schema_version") {
        None => diagnostics.push(
            "missing_field",
            "/schema_version",
            "schema_version is required",
        ),
        Some(Value::String(version)) if version == SUITE_SCHEMA_VERSION => {}
        Some(_) => {
            // Refuse before reading anything else: a different version may
            // give the same members a different meaning.
            diagnostics.push(
                "unsupported_schema_version",
                "/schema_version",
                format!("schema_version must be exactly \"{SUITE_SCHEMA_VERSION}\""),
            );
            return Err(diagnostics);
        }
    }
    if let Some(description) = root.get("description") {
        bounded_string(
            description,
            "/description",
            MAX_DESCRIPTION_BYTES,
            &mut diagnostics,
        );
    }
    let cases = parse_case_list(
        root.get("cases"),
        "/cases",
        MAX_CASES,
        (
            "empty_suite",
            "a suite needs at least one case; an empty suite proves nothing",
        ),
        parse_case,
        |case| &case.id,
        &mut diagnostics,
    );
    if !diagnostics.is_empty() {
        return Err(diagnostics);
    }
    match canonical_json::semantic_digest(SUITE_MEDIA_TYPE, SUITE_SCHEMA_VERSION, value) {
        Ok(digest) => Ok(Suite { digest, cases }),
        // Unreachable for an accepted suite, whose only numbers are bounded
        // positions; refused rather than digested some other way.
        Err(_) => {
            diagnostics.push(
                "unsupported_number",
                "",
                "every number in a suite must be an integer within the I-JSON safe range",
            );
            Err(diagnostics)
        }
    }
}

/// A synthetic input with no expectation: what a simulation evaluates
/// (issue #243, slice 10). It is parsed by exactly the functions a test case
/// is, so a simulation and a test can never disagree about what a case means.
pub(crate) struct SyntheticCase {
    pub(crate) id: String,
    /// The JSON Pointer of the case in the submitted document, for results.
    pub(crate) pointer: String,
    pub(crate) context: CaseContext,
}

/// What a case asks, per lane, without what it expects.
pub(crate) enum CaseContext {
    Http {
        request: HttpRequest,
        principal: SyntheticPrincipal,
    },
    Tool {
        operation: ToolOperation,
        tool_name: String,
        principal: SyntheticPrincipal,
    },
    ToolHttp {
        tool_name: String,
        method: Method,
        path: String,
        principal: SyntheticPrincipal,
    },
    Rate {
        method: Method,
        path: String,
        principal: SyntheticPrincipal,
    },
}

impl CaseContext {
    pub(crate) fn kind(&self) -> CaseKind {
        match self {
            Self::Http { .. } => CaseKind::Http,
            Self::Tool { .. } => CaseKind::Tool,
            Self::ToolHttp { .. } => CaseKind::ToolHttp,
            Self::Rate { .. } => CaseKind::Rate,
        }
    }
}

/// What a case expects, per lane.
enum CaseExpectation {
    Http(DecisionExpectation<Reason>),
    Tool(DecisionExpectation<crate::policy_eval::tools::ToolReason>),
    Rate(RateExpectation),
}

/// Parse a list of cases at `pointer`: present, an array, non-empty, within
/// `max_cases`, and with unique ids. Shared by a test suite and a simulation,
/// so both bound and identify their cases the same way.
pub(crate) fn parse_case_list<T>(
    value: Option<&Value>,
    pointer: &str,
    max_cases: usize,
    (empty_code, empty_message): (&'static str, &'static str),
    parse_one: fn(&Value, &str, &mut Diagnostics) -> Option<T>,
    id_of: fn(&T) -> &str,
    diagnostics: &mut Diagnostics,
) -> Vec<T> {
    let mut cases = Vec::new();
    match value {
        None => diagnostics.push(
            "missing_field",
            pointer,
            format!("{} is required", pointer.trim_start_matches('/')),
        ),
        Some(Value::Array(items)) if items.is_empty() => {
            diagnostics.push(empty_code, pointer, empty_message)
        }
        Some(Value::Array(items)) if items.len() > max_cases => diagnostics.push(
            "too_many_cases",
            pointer,
            format!("at most {max_cases} cases may be declared"),
        ),
        Some(Value::Array(items)) => {
            let mut seen = std::collections::HashSet::new();
            for (index, item) in items.iter().enumerate() {
                let case_pointer = format!("{pointer}/{index}");
                if let Some(case) = parse_one(item, &case_pointer, diagnostics) {
                    if !seen.insert(id_of(&case).to_owned()) {
                        diagnostics.push(
                            "duplicate_case_id",
                            &format!("{case_pointer}/id"),
                            "case ids must be unique",
                        );
                    }
                    cases.push(case);
                }
            }
        }
        Some(_) => diagnostics.push("invalid_type", pointer, "cases must be an array"),
    }
    cases
}

/// One simulation case: a test case's members less `expect`, which is refused
/// as an unknown member because a simulation asserts nothing.
pub(crate) fn parse_synthetic_case(
    value: &Value,
    pointer: &str,
    diagnostics: &mut Diagnostics,
) -> Option<SyntheticCase> {
    let before = diagnostics.diagnostics.len();
    let (map, id, kind) = parse_case_header(value, pointer, false, diagnostics)?;
    let context = parse_case_context(map, pointer, kind, diagnostics);
    if diagnostics.diagnostics.len() != before || diagnostics.truncated {
        return None;
    }
    Some(SyntheticCase {
        id: id?,
        pointer: pointer.to_owned(),
        context: context?,
    })
}

fn parse_case(value: &Value, pointer: &str, diagnostics: &mut Diagnostics) -> Option<Case> {
    let before = diagnostics.diagnostics.len();
    let (map, id, kind) = parse_case_header(value, pointer, true, diagnostics)?;
    let context = parse_case_context(map, pointer, kind, diagnostics);
    let expect_pointer = format!("{pointer}/expect");
    let expect = required(map, "expect", pointer, diagnostics).and_then(|value| match kind {
        CaseKind::Http => {
            parse_decision_expectation(value, &expect_pointer, parse_http_reason, true, diagnostics)
                .map(CaseExpectation::Http)
        }
        CaseKind::Tool | CaseKind::ToolHttp => parse_decision_expectation(
            value,
            &expect_pointer,
            parse_tool_reason,
            false,
            diagnostics,
        )
        .map(CaseExpectation::Tool),
        CaseKind::Rate => {
            parse_rate_expectation(value, &expect_pointer, diagnostics).map(CaseExpectation::Rate)
        }
    });
    if diagnostics.diagnostics.len() != before || diagnostics.truncated {
        return None;
    }
    let input = match (context?, expect?) {
        (CaseContext::Http { request, principal }, CaseExpectation::Http(expect)) => {
            CaseInput::Http {
                request,
                principal,
                expect,
            }
        }
        (
            CaseContext::Tool {
                operation,
                tool_name,
                principal,
            },
            CaseExpectation::Tool(expect),
        ) => CaseInput::Tool {
            operation,
            tool_name,
            principal,
            expect,
        },
        (
            CaseContext::ToolHttp {
                tool_name,
                method,
                path,
                principal,
            },
            CaseExpectation::Tool(expect),
        ) => CaseInput::ToolHttp {
            tool_name,
            method,
            path,
            principal,
            expect,
        },
        (
            CaseContext::Rate {
                method,
                path,
                principal,
            },
            CaseExpectation::Rate(expect),
        ) => CaseInput::Rate {
            method,
            path,
            principal,
            expect,
        },
        // Both halves are parsed for the one kind read above, so they always
        // pair. Refused with a diagnostic rather than dropped, because a case
        // that vanished without one would leave a suite that runs fewer cases
        // than its author wrote.
        _ => {
            diagnostics.push(
                "inconsistent_case",
                pointer,
                "the case's input and expectation are for different kinds",
            );
            return None;
        }
    };
    Some(Case {
        id: id?,
        pointer: pointer.to_owned(),
        input,
    })
}

/// A case's id, description and kind, and the member check for that kind:
/// the members both a test case and a simulation case carry, plus `expect`
/// when `expectation` is set.
fn parse_case_header<'a>(
    value: &'a Value,
    pointer: &str,
    expectation: bool,
    diagnostics: &mut Diagnostics,
) -> Option<(&'a Map<String, Value>, Option<String>, CaseKind)> {
    let map = object(value, pointer, diagnostics)?;
    let id = required(map, "id", pointer, diagnostics).and_then(|value| {
        let pointer = format!("{pointer}/id");
        let id = bounded_string(value, &pointer, MAX_CASE_ID_BYTES, diagnostics)?;
        if !valid_case_id(&id) {
            diagnostics.push(
                "invalid_case_id",
                &pointer,
                "a case id starts with an ASCII letter or digit and contains only ASCII letters, digits, '.', '_', ':' and '-'",
            );
            return None;
        }
        Some(id)
    });
    if let Some(description) = map.get("description") {
        bounded_string(
            description,
            &format!("{pointer}/description"),
            MAX_DESCRIPTION_BYTES,
            diagnostics,
        );
    }
    let kind = required(map, "kind", pointer, diagnostics).and_then(|value| {
        let kind = match value.as_str() {
            Some("http") => Some(CaseKind::Http),
            Some("tool") => Some(CaseKind::Tool),
            Some("tool_http") => Some(CaseKind::ToolHttp),
            Some("rate") => Some(CaseKind::Rate),
            _ => None,
        };
        if kind.is_none() {
            diagnostics.push(
                "invalid_value",
                &format!("{pointer}/kind"),
                "kind must be one of \"http\", \"tool\", \"tool_http\" or \"rate\"",
            );
        }
        kind
    });
    let mut members: Vec<&str> = match kind {
        // Without a kind the other members have no defined meaning; report
        // only what is wrong regardless of kind.
        None => vec!["id", "description", "kind", "principal", "request", "tool"],
        Some(CaseKind::Http | CaseKind::Rate) => {
            vec!["id", "description", "kind", "principal", "request"]
        }
        Some(CaseKind::Tool) => vec!["id", "description", "kind", "principal", "tool"],
        Some(CaseKind::ToolHttp) => {
            vec!["id", "description", "kind", "principal", "tool", "request"]
        }
    };
    if expectation {
        members.push("expect");
    }
    check_members(map, pointer, &members, diagnostics);
    Some((map, id, kind?))
}

/// The typed input of a case of `kind`.
fn parse_case_context(
    map: &Map<String, Value>,
    pointer: &str,
    kind: CaseKind,
    diagnostics: &mut Diagnostics,
) -> Option<CaseContext> {
    let principal = required(map, "principal", pointer, diagnostics)
        .and_then(|value| parse_principal(value, &format!("{pointer}/principal"), diagnostics));
    match kind {
        CaseKind::Http => {
            let request = required(map, "request", pointer, diagnostics).and_then(|value| {
                parse_http_request(value, &format!("{pointer}/request"), diagnostics)
            });
            Some(CaseContext::Http {
                request: request?,
                principal: principal?,
            })
        }
        CaseKind::Tool => {
            let tool = required(map, "tool", pointer, diagnostics)
                .and_then(|value| parse_tool(value, &format!("{pointer}/tool"), true, diagnostics));
            let (operation, tool_name) = tool?;
            let principal = principal?;
            // The inventory API that eligibility mirrors is
            // authenticated-only; the evaluator refuses the combination.
            if operation == ToolOperation::PolicyEligibility
                && matches!(principal, SyntheticPrincipal::Anonymous)
            {
                diagnostics.push(
                    "inconsistent_case",
                    &format!("{pointer}/principal"),
                    "tool eligibility is only defined for an authenticated principal",
                );
                return None;
            }
            Some(CaseContext::Tool {
                operation,
                tool_name,
                principal,
            })
        }
        CaseKind::ToolHttp => {
            let tool = required(map, "tool", pointer, diagnostics).and_then(|value| {
                parse_tool(value, &format!("{pointer}/tool"), false, diagnostics)
            });
            let request = required(map, "request", pointer, diagnostics).and_then(|value| {
                parse_method_and_path(
                    value,
                    &format!("{pointer}/request"),
                    PathKind::Rendered,
                    diagnostics,
                )
            });
            let ((_, tool_name), (method, path)) = (tool?, request?);
            Some(CaseContext::ToolHttp {
                tool_name,
                method,
                path,
                principal: principal?,
            })
        }
        CaseKind::Rate => {
            let request = required(map, "request", pointer, diagnostics).and_then(|value| {
                parse_method_and_path(
                    value,
                    &format!("{pointer}/request"),
                    PathKind::Request,
                    diagnostics,
                )
            });
            let (method, path) = request?;
            Some(CaseContext::Rate {
                method,
                path,
                principal: principal?,
            })
        }
    }
}

fn valid_case_id(id: &str) -> bool {
    let mut bytes = id.bytes();
    bytes
        .next()
        .is_some_and(|first| first.is_ascii_alphanumeric())
        && bytes
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn parse_principal(
    value: &Value,
    pointer: &str,
    diagnostics: &mut Diagnostics,
) -> Option<SyntheticPrincipal> {
    if value.as_str() == Some("anonymous") {
        return Some(SyntheticPrincipal::Anonymous);
    }
    let Value::Object(map) = value else {
        diagnostics.push(
            "invalid_type",
            pointer,
            "principal must be \"anonymous\" or an object of identity facts",
        );
        return None;
    };
    check_members(
        map,
        pointer,
        &["subject", "issuer", "roles", "auth_method"],
        diagnostics,
    );
    let subject = required(map, "subject", pointer, diagnostics).and_then(|value| {
        // The shape check below owns the bound; this only reads the string.
        string(value, &format!("{pointer}/subject"), diagnostics)
    });
    let issuer = match map.get("issuer") {
        None => Some(None),
        Some(value) => {
            let pointer = format!("{pointer}/issuer");
            string(value, &pointer, diagnostics).and_then(|issuer| {
                if issuer.len() > MAX_PRINCIPAL_ISSUER_BYTES {
                    diagnostics.push(
                        "too_long",
                        &pointer,
                        format!("issuer may be at most {MAX_PRINCIPAL_ISSUER_BYTES} bytes"),
                    );
                    return None;
                }
                // Authentication canonicalizes issuers before a principal
                // exists, and policy does the same when it loads, so a case
                // does too: an issuer written with a trailing slash matches
                // exactly what it would match on a real request.
                match canonical_issuer(&issuer) {
                    Some(issuer) => Some(Some(issuer)),
                    None => {
                        diagnostics.push(
                            "invalid_value",
                            &pointer,
                            "issuer must not be blank; omit it for a principal without one",
                        );
                        None
                    }
                }
            })
        }
    };
    let roles = match map.get("roles") {
        None => Some(Vec::new()),
        Some(Value::Array(items)) => {
            let mut roles = Vec::with_capacity(items.len());
            let mut valid = true;
            for (index, item) in items.iter().enumerate() {
                match string(item, &format!("{pointer}/roles/{index}"), diagnostics) {
                    Some(role) => roles.push(role),
                    None => valid = false,
                }
            }
            valid.then_some(roles)
        }
        Some(_) => {
            diagnostics.push(
                "invalid_type",
                &format!("{pointer}/roles"),
                "roles must be an array of strings",
            );
            None
        }
    };
    let auth_method = required(map, "auth_method", pointer, diagnostics).and_then(|value| {
        let method = match value.as_str() {
            Some(AUTH_METHOD_BEARER_TOKEN) => Some(AuthMethod::Bearer),
            Some(AUTH_METHOD_SESSION_COOKIE) => Some(AuthMethod::Cookie),
            Some(AUTH_METHOD_SERVICE_TOKEN) => Some(AuthMethod::ServiceToken),
            Some(AUTH_METHOD_CLIENT_CERTIFICATE) => Some(AuthMethod::ClientCertificate),
            _ => None,
        };
        if method.is_none() {
            diagnostics.push(
                "invalid_value",
                &format!("{pointer}/auth_method"),
                "auth_method must be one of the names a policy's auth_methods accepts",
            );
        }
        method
    });
    let (subject, issuer, roles, auth_method) = (subject?, issuer?, roles?, auth_method?);
    // The predicate authentication applies before any principal exists, so a
    // case cannot describe an identity no credential could produce.
    if let Err(problem) = check_principal_shape(&subject, issuer.as_deref(), &roles) {
        diagnostics.push(
            "invalid_principal",
            pointer,
            format!("principal is outside the shape authentication admits: {problem}"),
        );
        return None;
    }
    Some(SyntheticPrincipal::Authenticated(Principal {
        user_id: subject,
        issuer,
        // Display and session metadata are not policy facts. They stay empty
        // so nothing beyond what a case states can influence a result.
        email: None,
        org_id: None,
        roles,
        session_id: String::new(),
        auth_method,
    }))
}

fn parse_http_request(
    value: &Value,
    pointer: &str,
    diagnostics: &mut Diagnostics,
) -> Option<HttpRequest> {
    let map = object(value, pointer, diagnostics)?;
    check_members(
        map,
        pointer,
        &["method", "path", "host", "target"],
        diagnostics,
    );
    let method = required(map, "method", pointer, diagnostics)
        .and_then(|value| parse_method(value, &format!("{pointer}/method"), diagnostics));
    let path = required(map, "path", pointer, diagnostics).and_then(|value| {
        parse_path(
            value,
            &format!("{pointer}/path"),
            PathKind::Request,
            diagnostics,
        )
    });
    let host = match map.get("host") {
        None => Some(None),
        Some(value) => parse_host(value, &format!("{pointer}/host"), diagnostics).map(Some),
    };
    let target = match map.get("target") {
        None => Some(SyntheticTarget::Contextless),
        Some(value) => parse_target(value, &format!("{pointer}/target"), diagnostics),
    };
    Some(HttpRequest {
        method: method?,
        path: path?,
        host: host?,
        target: target?,
    })
}

fn parse_target(
    value: &Value,
    pointer: &str,
    diagnostics: &mut Diagnostics,
) -> Option<SyntheticTarget> {
    let map = object(value, pointer, diagnostics)?;
    let kind_pointer = format!("{pointer}/kind");
    let kind = match required(map, "kind", pointer, diagnostics)?.as_str() {
        Some(kind @ ("contextless" | "mcp_alias" | "proxy_dispatch")) => kind,
        _ => {
            diagnostics.push(
                "invalid_value",
                &kind_pointer,
                "target kind must be one of \"contextless\", \"mcp_alias\" or \"proxy_dispatch\"",
            );
            return None;
        }
    };
    match kind {
        "contextless" => {
            check_members(map, pointer, &["kind"], diagnostics);
            Some(SyntheticTarget::Contextless)
        }
        "mcp_alias" => {
            check_members(map, pointer, &["kind", "canonical_path"], diagnostics);
            let canonical_path =
                required(map, "canonical_path", pointer, diagnostics).and_then(|value| {
                    parse_path(
                        value,
                        &format!("{pointer}/canonical_path"),
                        PathKind::Request,
                        diagnostics,
                    )
                })?;
            Some(SyntheticTarget::McpAlias { canonical_path })
        }
        _ => {
            check_members(
                map,
                pointer,
                &[
                    "kind",
                    "upstream_origin",
                    "route_id",
                    "route_host",
                    "route_path_prefix",
                ],
                diagnostics,
            );
            let upstream_origin =
                required(map, "upstream_origin", pointer, diagnostics).and_then(|value| {
                    parse_upstream_origin(value, &format!("{pointer}/upstream_origin"), diagnostics)
                });
            let route_id = optional_fact(map, "route_id", pointer, diagnostics);
            let route_host = match map.get("route_host") {
                None => Some(None),
                Some(value) => {
                    parse_host(value, &format!("{pointer}/route_host"), diagnostics).map(Some)
                }
            };
            let route_path_prefix = optional_fact(map, "route_path_prefix", pointer, diagnostics)
                .and_then(|prefix| match prefix {
                    Some(prefix) if !prefix.starts_with('/') => {
                        diagnostics.push(
                            "invalid_value",
                            &format!("{pointer}/route_path_prefix"),
                            "route_path_prefix must be an absolute path prefix",
                        );
                        None
                    }
                    prefix => Some(prefix),
                });
            Some(SyntheticTarget::ProxyDispatch(DispatchFacts {
                route_id: route_id?,
                route_host: route_host?,
                route_path_prefix: route_path_prefix?,
                upstream_origin: upstream_origin?,
            }))
        }
    }
}

/// A dispatch fact that is bounded, non-empty and free of whitespace and
/// control characters; `Ok(None)` when absent.
fn optional_fact(
    map: &Map<String, Value>,
    key: &str,
    pointer: &str,
    diagnostics: &mut Diagnostics,
) -> Option<Option<String>> {
    let Some(value) = map.get(key) else {
        return Some(None);
    };
    let pointer = format!("{pointer}/{key}");
    let fact = bounded_string(value, &pointer, MAX_DISPATCH_FACT_BYTES, diagnostics)?;
    if fact.bytes().any(|byte| byte <= b' ' || byte == 127) {
        diagnostics.push(
            "invalid_value",
            &pointer,
            "a dispatch fact must not contain whitespace or control characters",
        );
        return None;
    }
    Some(Some(fact))
}

/// The selected upstream's origin, in the form production records it: the
/// ASCII serialization of an `http` or `https` origin, or a logical pool
/// origin `pool:<route id>`. It is a label the evaluator compares, never an
/// address anything connects to, so a URL with credentials, a path, a query
/// or a fragment is refused rather than reduced to its origin.
fn parse_upstream_origin(
    value: &Value,
    pointer: &str,
    diagnostics: &mut Diagnostics,
) -> Option<String> {
    let origin = bounded_string(value, pointer, MAX_DISPATCH_FACT_BYTES, diagnostics)?;
    let invalid = |diagnostics: &mut Diagnostics| {
        diagnostics.push(
            "invalid_origin",
            pointer,
            "upstream_origin must be an http or https origin without credentials, path, query or fragment, or \"pool:<route id>\"",
        );
        None
    };
    if let Some(route_id) = origin.strip_prefix("pool:") {
        if route_id.is_empty() || route_id.bytes().any(|byte| byte <= b' ' || byte == 127) {
            return invalid(diagnostics);
        }
        return Some(origin);
    }
    let Ok(url) = Url::parse(&origin) else {
        return invalid(diagnostics);
    };
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return invalid(diagnostics);
    }
    Some(url.origin().ascii_serialization())
}

fn parse_host(value: &Value, pointer: &str, diagnostics: &mut Diagnostics) -> Option<String> {
    let host = bounded_string(value, pointer, MAX_REQUEST_HOST_BYTES, diagnostics)?;
    // The routing lane compares hosts without their port, and so does the
    // evaluator, so a case states the host the way that lane sees it.
    if !is_bare_host(&host) || host.bytes().any(|byte| byte <= b' ' || byte == 127) {
        diagnostics.push(
            "invalid_host",
            pointer,
            "host must be a bare host name or address without a port",
        );
        return None;
    }
    Some(host)
}

#[derive(Clone, Copy)]
enum PathKind {
    /// An inbound request path, under the evaluator's request-path rules.
    Request,
    /// A rendered tool HTTP path, which may carry percent-escapes.
    Rendered,
}

fn parse_method_and_path(
    value: &Value,
    pointer: &str,
    kind: PathKind,
    diagnostics: &mut Diagnostics,
) -> Option<(Method, String)> {
    let map = object(value, pointer, diagnostics)?;
    check_members(map, pointer, &["method", "path"], diagnostics);
    let method = required(map, "method", pointer, diagnostics)
        .and_then(|value| parse_method(value, &format!("{pointer}/method"), diagnostics));
    let path = required(map, "path", pointer, diagnostics)
        .and_then(|value| parse_path(value, &format!("{pointer}/path"), kind, diagnostics));
    Some((method?, path?))
}

fn parse_method(value: &Value, pointer: &str, diagnostics: &mut Diagnostics) -> Option<Method> {
    let method = bounded_string(value, pointer, MAX_REQUEST_METHOD_BYTES, diagnostics)?;
    match Method::from_bytes(method.as_bytes()) {
        Ok(method) => Some(method),
        Err(_) => {
            diagnostics.push(
                "invalid_method",
                pointer,
                "method must be an HTTP method token",
            );
            None
        }
    }
}

fn parse_path(
    value: &Value,
    pointer: &str,
    kind: PathKind,
    diagnostics: &mut Diagnostics,
) -> Option<String> {
    let path = string(value, pointer, diagnostics)?;
    // The evaluator's own predicates, so a case the parser accepts is never
    // one the evaluator refuses as malformed or oversized.
    let checked = match kind {
        PathKind::Request => validate_path(&path),
        PathKind::Rendered => validate_rendered_http_path(&path),
    };
    if checked.is_err() {
        diagnostics.push(
            "invalid_path",
            pointer,
            match kind {
                PathKind::Request => "path must be an absolute, already-separated request path without query, fragment, dot segments or control characters, within the request path limit",
                PathKind::Rendered => "path must be an absolute rendered tool path with valid percent-escapes, without query, fragment, dot segments or control characters, within the request path limit",
            },
        );
        return None;
    }
    Some(path)
}

/// `(operation, tool name)`. Only a `tool` case may name an operation; a
/// `tool_http` case is always the rendered-request lane.
fn parse_tool(
    value: &Value,
    pointer: &str,
    allow_operation: bool,
    diagnostics: &mut Diagnostics,
) -> Option<(ToolOperation, String)> {
    let map = object(value, pointer, diagnostics)?;
    let members: &[&str] = if allow_operation {
        &["name", "operation"]
    } else {
        &["name"]
    };
    check_members(map, pointer, members, diagnostics);
    let name = required(map, "name", pointer, diagnostics).and_then(|value| {
        bounded_string(
            value,
            &format!("{pointer}/name"),
            MAX_TOOL_NAME_BYTES,
            diagnostics,
        )
    });
    let operation = if !allow_operation {
        Some(ToolOperation::RenderedHttp)
    } else {
        match map.get("operation") {
            None => Some(ToolOperation::Invocation),
            Some(value) => {
                let operation = match value.as_str() {
                    Some("invocation") => Some(ToolOperation::Invocation),
                    Some("visibility") => Some(ToolOperation::Visibility),
                    Some("eligibility") => Some(ToolOperation::PolicyEligibility),
                    _ => None,
                };
                if operation.is_none() {
                    diagnostics.push(
                        "invalid_value",
                        &format!("{pointer}/operation"),
                        "operation must be one of \"invocation\", \"visibility\" or \"eligibility\"",
                    );
                }
                operation
            }
        }
    };
    Some((operation?, name?))
}

fn parse_decision_expectation<R>(
    value: &Value,
    pointer: &str,
    parse_reason: fn(&str) -> Option<R>,
    routes: bool,
    diagnostics: &mut Diagnostics,
) -> Option<DecisionExpectation<R>> {
    let map = object(value, pointer, diagnostics)?;
    check_members(
        map,
        pointer,
        &["logical", "effect", "reason", "matched"],
        diagnostics,
    );
    let logical = required(map, "logical", pointer, diagnostics).and_then(|value| {
        // `indeterminate` is not an expectation: every case states every fact
        // it depends on, so an indeterminate answer means the evaluator could
        // not decide, and a run reports that as incomplete, never as a pass.
        let logical = match value.as_str() {
            Some("allow") => Some(LogicalDecision::Allow),
            Some("deny") => Some(LogicalDecision::Deny),
            _ => None,
        };
        if logical.is_none() {
            diagnostics.push(
                "invalid_value",
                &format!("{pointer}/logical"),
                "logical must be \"allow\" or \"deny\"",
            );
        }
        logical
    });
    let effect = match map.get("effect") {
        None => Some(None),
        Some(value) => {
            let effect = match value.as_str() {
                Some("allow") => Some(PolicyEffect::Allow),
                Some("block") => Some(PolicyEffect::Block),
                Some("observe") => Some(PolicyEffect::Observe),
                _ => None,
            };
            if effect.is_none() {
                diagnostics.push(
                    "invalid_value",
                    &format!("{pointer}/effect"),
                    "effect must be \"allow\", \"block\" or \"observe\"",
                );
            }
            effect.map(Some)
        }
    };
    let reason = match map.get("reason") {
        None => Some(None),
        Some(value) => {
            let reason = value.as_str().and_then(parse_reason);
            if reason.is_none() {
                diagnostics.push(
                    "invalid_value",
                    &format!("{pointer}/reason"),
                    "reason must be one of the stable reason codes this lane reports",
                );
            }
            reason.map(Some)
        }
    };
    let matched = match map.get("matched") {
        None => Some(None),
        Some(value) => {
            parse_matched(value, &format!("{pointer}/matched"), routes, diagnostics).map(Some)
        }
    };
    Some(DecisionExpectation {
        logical: logical?,
        effect: effect?,
        reason: reason?,
        matched: matched?,
    })
}

fn parse_matched(
    value: &Value,
    pointer: &str,
    routes: bool,
    diagnostics: &mut Diagnostics,
) -> Option<MatchedExpectation> {
    if value.as_str() == Some("none") {
        return Some(MatchedExpectation::None);
    }
    let shape = if routes {
        "matched must be \"none\", {\"rule\": \"<rule id>\"} or {\"route\": <position>}"
    } else {
        "matched must be \"none\" or {\"rule\": \"<rule id>\"}"
    };
    let Value::Object(map) = value else {
        diagnostics.push("invalid_type", pointer, shape);
        return None;
    };
    match (map.len(), map.get("rule"), map.get("route")) {
        (1, Some(rule), None) => {
            let id = bounded_string(
                rule,
                &format!("{pointer}/rule"),
                MAX_DISPATCH_FACT_BYTES,
                diagnostics,
            )?;
            Some(MatchedExpectation::Rule(id))
        }
        (1, None, Some(route)) if routes => {
            index(route, &format!("{pointer}/route"), diagnostics).map(MatchedExpectation::Route)
        }
        _ => {
            diagnostics.push("invalid_value", pointer, shape);
            None
        }
    }
}

fn parse_rate_expectation(
    value: &Value,
    pointer: &str,
    diagnostics: &mut Diagnostics,
) -> Option<RateExpectation> {
    let map = object(value, pointer, diagnostics)?;
    check_members(map, pointer, &["rate_override"], diagnostics);
    match required(map, "rate_override", pointer, diagnostics)? {
        Value::Null => Some(RateExpectation::NoOverride),
        value => index(value, &format!("{pointer}/rate_override"), diagnostics)
            .map(RateExpectation::Override),
    }
}

pub(crate) fn index(value: &Value, pointer: &str, diagnostics: &mut Diagnostics) -> Option<usize> {
    match value
        .as_u64()
        .filter(|index| *index <= MAX_EXPECTED_INDEX)
        .and_then(|index| usize::try_from(index).ok())
    {
        Some(index) => Some(index),
        None => {
            diagnostics.push(
                "invalid_value",
                pointer,
                format!("a position must be an integer from 0 to {MAX_EXPECTED_INDEX}"),
            );
            None
        }
    }
}

pub(crate) fn parse_http_reason(code: &str) -> Option<Reason> {
    // `incomplete` is absent on purpose; see `parse_decision_expectation`.
    match code {
        "matched_rule" => Some(Reason::MatchedRule),
        "missing_permission" => Some(Reason::MissingPermission),
        "missing_principal" => Some(Reason::MissingPrincipal),
        "default_allow" => Some(Reason::DefaultAllow),
        "default_deny" => Some(Reason::DefaultDeny),
        "host_policy_required" => Some(Reason::HostPolicyRequired),
        _ => None,
    }
}

pub(crate) fn parse_tool_reason(code: &str) -> Option<crate::policy_eval::tools::ToolReason> {
    use crate::policy_eval::tools::ToolReason;
    match code {
        "unknown_tool" => Some(ToolReason::UnknownTool),
        "disabled" => Some(ToolReason::Disabled),
        "role_not_allowed" => Some(ToolReason::RoleNotAllowed),
        "matched_rule" => Some(ToolReason::MatchedRule),
        "allowed" => Some(ToolReason::Allowed),
        "not_in_policy" => Some(ToolReason::NotInPolicy),
        "policy_disabled" => Some(ToolReason::PolicyDisabled),
        "principal_not_eligible" => Some(ToolReason::PrincipalNotEligible),
        "policy_denied" => Some(ToolReason::PolicyDenied),
        "eligible" => Some(ToolReason::Eligible),
        "no_http_rule" => Some(ToolReason::NoHttpRule),
        _ => None,
    }
}

pub(crate) fn object<'a>(
    value: &'a Value,
    pointer: &str,
    diagnostics: &mut Diagnostics,
) -> Option<&'a Map<String, Value>> {
    match value {
        Value::Object(map) => Some(map),
        _ => {
            diagnostics.push("invalid_type", pointer, "expected an object");
            None
        }
    }
}

pub(crate) fn required<'a>(
    map: &'a Map<String, Value>,
    key: &str,
    pointer: &str,
    diagnostics: &mut Diagnostics,
) -> Option<&'a Value> {
    let value = map.get(key);
    if value.is_none() {
        diagnostics.push(
            "missing_field",
            &format!("{pointer}/{key}"),
            format!("{key} is required"),
        );
    }
    value
}

/// Refuse every member not in `allowed`, naming a credential-shaped one
/// separately. The member's value is never read.
pub(crate) fn check_members(
    map: &Map<String, Value>,
    pointer: &str,
    allowed: &[&str],
    diagnostics: &mut Diagnostics,
) {
    for key in map.keys() {
        if allowed.contains(&key.as_str()) {
            continue;
        }
        let member_pointer = member_pointer(pointer, key);
        if FORBIDDEN_MEMBERS.contains(&key.to_ascii_lowercase().as_str()) {
            diagnostics.push(
                "forbidden_field",
                &member_pointer,
                "a synthetic case never carries credentials, tokens, cookies or headers; describe the identity with principal facts instead",
            );
        } else {
            diagnostics.push("unknown_field", &member_pointer, "unknown member");
        }
    }
}

/// `pointer/key` with RFC 6901 escaping, or a placeholder for a member name
/// too long to repeat.
fn member_pointer(pointer: &str, key: &str) -> String {
    if key.len() > MAX_POINTER_MEMBER_BYTES {
        return format!("{pointer}/<member name longer than {MAX_POINTER_MEMBER_BYTES} bytes>");
    }
    format!("{pointer}/{}", key.replace('~', "~0").replace('/', "~1"))
}

pub(crate) fn string(
    value: &Value,
    pointer: &str,
    diagnostics: &mut Diagnostics,
) -> Option<String> {
    match value {
        Value::String(text) if !text.is_empty() => Some(text.clone()),
        Value::String(_) => {
            diagnostics.push("invalid_value", pointer, "must not be empty");
            None
        }
        _ => {
            diagnostics.push("invalid_type", pointer, "expected a string");
            None
        }
    }
}

pub(crate) fn bounded_string(
    value: &Value,
    pointer: &str,
    max_bytes: usize,
    diagnostics: &mut Diagnostics,
) -> Option<String> {
    let text = string(value, pointer, diagnostics)?;
    if text.len() > max_bytes {
        diagnostics.push(
            "too_long",
            pointer,
            format!("may be at most {max_bytes} bytes"),
        );
        return None;
    }
    Some(text)
}
