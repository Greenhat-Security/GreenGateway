//! Allocation-counted benchmarks of the tool-admission and rate-lane decisions.
//!
//! `scripts/microbench.py` runs the ignored `tool_policy_evaluation` and
//! `rate_lane_selection` tests in the gateway test binary it builds for each
//! compared revision, under the same protocol as `http_policy`:
//!
//! - `tool_policy` measures `CompiledPolicy::evaluate_tool`, the call the live
//!   tool adapters make, across every tool operation.
//! - `rate_lane` measures `CompiledPolicy::select_rate_lane`, the call the
//!   live rate stage makes to choose an override. The token buckets and their
//!   remaining capacity are mutable state outside the kernel, so they are not
//!   measured.
//!
//! Policy validation, compilation, context construction, expected-decision
//! checks and report serialization are all outside the measured intervals.
//!
//! This is a child of the `http_policy` harness so that it counts through that
//! module's global allocator, the only one a binary can have. It keeps its own
//! file, and so its own digest: changing a lane dataset does not change the
//! enforced `http_policy` harness.

use std::{env::VarError, fs::OpenOptions, hint::black_box, io::Write, time::Instant};

use http::Method;
use serde_json::{json, Value};

use super::{count_allocations, ITERATIONS, REGRESSION_ENV, RESULT_ENV, SAMPLES, WARMUP};
use crate::{
    auth::{AuthMethod, Principal},
    policy_eval::{
        tools::{
            ToolEvaluation, ToolEvaluationContext, ToolLimitation, ToolOperation, ToolReason,
            TOOL_CONTEXT_VERSION,
        },
        CompiledPolicy, EvaluationError, HostFact, HttpTarget, Limitation, LogicalDecision,
        PolicyAuthority, PolicyEffect, PolicyEvaluationContext, PrincipalFact, PrincipalIdentity,
        RateLaneOutcome, RateLaneSelection, RuleReference, CONTEXT_VERSION,
    },
    rbac::Policy,
};

const TOOL_TARGET_ID: &str = "tool_policy";
const RATE_TARGET_ID: &str = "rate_lane";
const ISSUER: &str = "https://idp.example.test";

const LONG_ORDER_PATH: &str = concat!(
    "/orders/segment01/segment02/segment03/segment04/segment05/segment06/",
    "segment07/segment08/segment09/segment10/segment11/segment12/file.json"
);

#[derive(Clone, Copy)]
enum Caller {
    /// The principal fact was never captured.
    Uncaptured,
    Anonymous,
    /// A bearer-token reader from the synthetic issuer.
    Reader,
    /// The same reader from an issuer no rule names.
    OtherIssuer,
    /// A service-token operator, with no issuer.
    Operator,
    /// The same operator authenticated by session cookie.
    OperatorWithCookie,
    /// A subject that a rate override names by principal id.
    Batch,
}

impl Caller {
    fn fact(self) -> (PrincipalFact, usize) {
        let (user_id, issuer, role, auth_method) = match self {
            Self::Uncaptured => return (PrincipalFact::Missing, 0),
            Self::Anonymous => return (PrincipalFact::Anonymous, 0),
            Self::Reader => (
                "synthetic-reader",
                Some(ISSUER),
                "reader",
                AuthMethod::Bearer,
            ),
            Self::OtherIssuer => (
                "synthetic-reader",
                Some("https://other.example.test"),
                "reader",
                AuthMethod::Bearer,
            ),
            Self::Operator => (
                "synthetic-operator",
                None,
                "operator",
                AuthMethod::ServiceToken,
            ),
            Self::OperatorWithCookie => {
                ("synthetic-operator", None, "operator", AuthMethod::Cookie)
            }
            Self::Batch => ("synthetic-batch", Some(ISSUER), "batch", AuthMethod::Bearer),
        };
        let principal = Principal {
            user_id: user_id.to_owned(),
            issuer: issuer.map(str::to_owned),
            email: None,
            org_id: None,
            roles: vec![role.to_owned()],
            session_id: String::new(),
            auth_method,
        };
        // The bytes of policy facts the projection carries: subject, issuer
        // and roles.
        let bytes = user_id.len() + issuer.map_or(0, str::len) + role.len();
        // The live adapters project an authenticated principal this way.
        (
            PrincipalFact::Authenticated(PrincipalIdentity::from_principal(&principal)),
            bytes,
        )
    }
}

fn compile(document: Value) -> Result<CompiledPolicy, String> {
    // The live install path: an already-validated policy, as RBAC state holds.
    let policy = Policy::validate_json_value(document)
        .map_err(|error| format!("synthetic policy is invalid: {error}"))?;
    CompiledPolicy::from_validated_policy(policy, PolicyAuthority::Standalone)
        .map_err(|error| format!("synthetic policy does not compile: {error:?}"))
}

/// A public, synthetic tool policy. No value is a credential and the issuer
/// uses the reserved `.test` suffix.
fn tool_policy_document() -> Value {
    json!({
        "schema_version": "0.1.0",
        "default_action": "deny",
        "roles": {
            "reader": {"permissions": ["orders.read"]},
            "operator": {"permissions": ["*"]}
        },
        "tools": {
            "orders.lookup": {},
            "orders.refund": {"allowed_roles": ["operator"], "auth_methods": ["service_token"]},
            "reports.export": {"allowed_roles": ["reader"], "issuers": [ISSUER]},
            "reports.archive": {"enabled": false},
            "inventory.audit": {}
        },
        "rules": [
            {"id": "inactive-lookup-deny", "tool_name": "orders.lookup", "enabled": false, "action": "deny"},
            {"id": "refund-allow", "tool_name": "orders.refund", "action": "allow"},
            {"id": "export-shadow", "tool_name": "reports.export", "action": "shadow"},
            {"id": "audit-deny", "tool_name": "inventory.audit", "action": "deny"},
            {"id": "contextless-orders-deny", "path": "/orders/**", "dispatch": {"kind": "contextless"}, "action": "deny"},
            {"id": "rendered-order-read", "methods": ["GET"], "path": "/orders/{id}", "action": "allow"},
            {"id": "rendered-admin-deny", "path": "/admin/**", "action": "deny"},
            {"id": "rendered-reports-shadow", "methods": ["GET"], "path": "/reports/**", "action": "shadow"}
        ]
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ToolExpected {
    logical: LogicalDecision,
    effect: PolicyEffect,
    reason: ToolReason,
    matched: Option<RuleReference>,
    limitation: Option<ToolLimitation>,
}

impl ToolExpected {
    const fn allowed(reason: ToolReason, matched: Option<RuleReference>) -> Self {
        Self {
            logical: LogicalDecision::Allow,
            effect: PolicyEffect::Allow,
            reason,
            matched,
            limitation: None,
        }
    }

    const fn denied(
        effect: PolicyEffect,
        reason: ToolReason,
        matched: Option<RuleReference>,
    ) -> Self {
        Self {
            logical: LogicalDecision::Deny,
            effect,
            reason,
            matched,
            limitation: None,
        }
    }

    const fn incomplete(limitation: ToolLimitation) -> Self {
        Self {
            logical: LogicalDecision::Indeterminate,
            effect: PolicyEffect::Block,
            reason: ToolReason::Incomplete,
            matched: None,
            limitation: Some(limitation),
        }
    }

    fn matches(&self, result: &Result<ToolEvaluation, EvaluationError>) -> bool {
        let Ok(evaluation) = result else {
            return false;
        };
        evaluation.logical() == self.logical
            && evaluation.effect() == self.effect
            && evaluation.reason() == self.reason
            && evaluation.matched() == self.matched
            && evaluation.limitation() == self.limitation
            && evaluation.is_complete() == self.limitation.is_none()
    }
}

struct ToolCase {
    name: &'static str,
    operation: ToolOperation,
    tool_name: Option<&'static str>,
    caller: Caller,
    /// Only for `RenderedHttp`: the rendered method and path, either of which
    /// may be uncaptured.
    rendered: Option<(Option<Method>, Option<&'static str>)>,
    expected: ToolExpected,
}

/// Every tool operation, and every reason and limitation the tool lane can
/// report: rule-free, allow, deny and shadow invocations, role, issuer and
/// authentication-method constraints, unknown and disabled tools, both preview
/// operations (where a shadow rule does not hide a tool), composite enablement
/// without a principal, rendered HTTP rules under unknown dispatch, and each
/// uncaptured fact.
fn tool_cases() -> Vec<ToolCase> {
    use PolicyEffect::{Block, Observe};
    use RuleReference::Direct;
    use ToolOperation::{CompositeLeaf, Invocation, PolicyEligibility, RenderedHttp, Visibility};
    use ToolReason::{
        Allowed, Disabled, Eligible, MatchedRule, NoHttpRule, NotInPolicy, PolicyDenied,
        PolicyDisabled, PrincipalNotEligible, RoleNotAllowed, UnknownTool,
    };
    let case = |name, operation, tool_name, caller, expected| ToolCase {
        name,
        operation,
        tool_name,
        caller,
        rendered: None,
        expected,
    };
    let rendered = |name, caller, method, path, expected| ToolCase {
        name,
        operation: RenderedHttp,
        tool_name: Some("orders.lookup"),
        caller,
        rendered: Some((method, path)),
        expected,
    };
    vec![
        case(
            "invocation_without_rule",
            Invocation,
            Some("orders.lookup"),
            Caller::Reader,
            ToolExpected::allowed(Allowed, None),
        ),
        case(
            "invocation_rule_allow",
            Invocation,
            Some("orders.refund"),
            Caller::Operator,
            ToolExpected::allowed(MatchedRule, Some(Direct(1))),
        ),
        case(
            "invocation_wrong_auth_method",
            Invocation,
            Some("orders.refund"),
            Caller::Reader,
            ToolExpected::denied(Block, RoleNotAllowed, None),
        ),
        case(
            "invocation_anonymous_constrained_tool",
            Invocation,
            Some("orders.refund"),
            Caller::Anonymous,
            ToolExpected::denied(Block, RoleNotAllowed, None),
        ),
        case(
            "invocation_shadow_rule",
            Invocation,
            Some("reports.export"),
            Caller::Reader,
            ToolExpected::denied(Observe, MatchedRule, Some(Direct(2))),
        ),
        case(
            "invocation_wrong_issuer",
            Invocation,
            Some("reports.export"),
            Caller::OtherIssuer,
            ToolExpected::denied(Block, RoleNotAllowed, None),
        ),
        case(
            "invocation_rule_deny",
            Invocation,
            Some("inventory.audit"),
            Caller::Reader,
            ToolExpected::denied(Block, MatchedRule, Some(Direct(3))),
        ),
        case(
            "invocation_unknown_tool",
            Invocation,
            Some("orders.cancel"),
            Caller::Reader,
            ToolExpected::denied(Block, UnknownTool, None),
        ),
        case(
            "invocation_disabled_tool",
            Invocation,
            Some("reports.archive"),
            Caller::Reader,
            ToolExpected::denied(Block, Disabled, None),
        ),
        case(
            "invocation_uncaptured_tool_name",
            Invocation,
            None,
            Caller::Reader,
            ToolExpected::incomplete(ToolLimitation::ToolName),
        ),
        case(
            "invocation_uncaptured_principal",
            Invocation,
            Some("orders.lookup"),
            Caller::Uncaptured,
            ToolExpected::incomplete(ToolLimitation::Principal),
        ),
        case(
            "visibility_without_rule",
            Visibility,
            Some("orders.lookup"),
            Caller::Reader,
            ToolExpected::allowed(Eligible, None),
        ),
        case(
            "visibility_shadow_rule_does_not_hide",
            Visibility,
            Some("reports.export"),
            Caller::Reader,
            ToolExpected::allowed(Eligible, Some(Direct(2))),
        ),
        case(
            "visibility_rule_deny",
            Visibility,
            Some("inventory.audit"),
            Caller::Reader,
            ToolExpected::denied(Block, PolicyDenied, Some(Direct(3))),
        ),
        case(
            "visibility_not_in_policy",
            Visibility,
            Some("orders.cancel"),
            Caller::Reader,
            ToolExpected::denied(Block, NotInPolicy, None),
        ),
        case(
            "visibility_disabled_tool",
            Visibility,
            Some("reports.archive"),
            Caller::Reader,
            ToolExpected::denied(Block, PolicyDisabled, None),
        ),
        case(
            "visibility_principal_not_eligible",
            Visibility,
            Some("orders.refund"),
            Caller::Reader,
            ToolExpected::denied(Block, PrincipalNotEligible, None),
        ),
        case(
            "eligibility_rule_allow",
            PolicyEligibility,
            Some("orders.refund"),
            Caller::Operator,
            ToolExpected::allowed(Eligible, Some(Direct(1))),
        ),
        case(
            "eligibility_wrong_role",
            PolicyEligibility,
            Some("reports.export"),
            Caller::Operator,
            ToolExpected::denied(Block, PrincipalNotEligible, None),
        ),
        case(
            "composite_leaf_enabled_without_principal",
            CompositeLeaf,
            Some("orders.refund"),
            Caller::Uncaptured,
            ToolExpected::allowed(Allowed, None),
        ),
        case(
            "composite_leaf_disabled",
            CompositeLeaf,
            Some("reports.archive"),
            Caller::Uncaptured,
            ToolExpected::denied(Block, Disabled, None),
        ),
        rendered(
            "rendered_skips_dispatch_scoped_rule",
            Caller::Reader,
            Some(Method::GET),
            Some("/orders/42"),
            ToolExpected::allowed(MatchedRule, Some(Direct(5))),
        ),
        rendered(
            "rendered_percent_encoded_deny",
            Caller::Operator,
            Some(Method::DELETE),
            Some("/admin/users%2F7"),
            ToolExpected::denied(Block, MatchedRule, Some(Direct(6))),
        ),
        rendered(
            "rendered_shadow_rule",
            Caller::Reader,
            Some(Method::GET),
            Some("/reports/q3"),
            ToolExpected::denied(Observe, MatchedRule, Some(Direct(7))),
        ),
        rendered(
            "rendered_without_rule",
            Caller::Reader,
            Some(Method::POST),
            Some("/reports/q3"),
            ToolExpected::allowed(NoHttpRule, None),
        ),
        rendered(
            "rendered_uncaptured_method",
            Caller::Reader,
            None,
            Some("/orders/42"),
            ToolExpected::incomplete(ToolLimitation::Method),
        ),
        rendered(
            "rendered_uncaptured_path",
            Caller::Reader,
            Some(Method::GET),
            None,
            ToolExpected::incomplete(ToolLimitation::Path),
        ),
    ]
}

struct PreparedTool {
    name: &'static str,
    context: ToolEvaluationContext,
    expected: ToolExpected,
}

/// Builds every tool context once, before any measurement. Also returns the
/// total bytes of facts the contexts carry: tool name, rendered method and
/// path, and the principal's subject, issuer and roles.
fn prepare_tools(compiled: &CompiledPolicy) -> (Vec<PreparedTool>, usize) {
    let mut prepared = Vec::new();
    let mut input_bytes = 0;
    for case in tool_cases() {
        let (principal, principal_bytes) = case.caller.fact();
        let (method, path) = case.rendered.unwrap_or_default();
        input_bytes += case.tool_name.map_or(0, str::len)
            + method.as_ref().map_or(0, |method| method.as_str().len())
            + path.map_or(0, str::len)
            + principal_bytes;
        prepared.push(PreparedTool {
            name: case.name,
            context: ToolEvaluationContext {
                version: TOOL_CONTEXT_VERSION,
                snapshot: compiled.snapshot(),
                operation: case.operation,
                tool_name: case.tool_name.map(str::to_owned),
                principal,
                method,
                path: path.map(str::to_owned),
            },
            expected: case.expected,
        });
    }
    (prepared, input_bytes)
}

/// Checks every expected decision individually, so two opposite mistakes
/// cannot cancel out in the measured checksum.
fn preflight_tools(compiled: &CompiledPolicy, cases: &[PreparedTool]) -> Result<(), String> {
    for case in cases {
        let result = compiled.evaluate_tool(&case.context);
        if !case.expected.matches(&result) {
            let actual = result.map(|evaluation| {
                (
                    evaluation.logical(),
                    evaluation.effect(),
                    evaluation.reason(),
                    evaluation.matched(),
                    evaluation.limitation(),
                )
            });
            return Err(format!(
                "{}: expected {:?}, evaluated {actual:?}",
                case.name, case.expected
            ));
        }
    }
    Ok(())
}

/// One pass over the tool dataset; the checksum counts correct decisions.
fn tool_iteration(compiled: &CompiledPolicy, cases: &[PreparedTool], regression: bool) -> u64 {
    let mut checksum = 0;
    for case in cases {
        let result = black_box(compiled).evaluate_tool(black_box(&case.context));
        if regression {
            let allocation = vec![black_box(0_u8); black_box(64_usize)];
            black_box(allocation);
        }
        checksum += u64::from(case.expected.matches(&black_box(result)));
    }
    checksum
}

/// A public, synthetic policy with ordered rate-limit overrides. No value is
/// a credential and the issuer uses the reserved `.test` suffix.
fn rate_policy_document() -> Value {
    json!({
        "schema_version": "0.1.0",
        "default_action": "allow",
        "roles": {
            "reader": {"permissions": ["orders.read"]},
            "operator": {"permissions": ["*"]}
        },
        "rate_limits": [
            {"principal": {"roles": ["operator"], "auth_methods": ["service_token"]}, "requests_per_second": 50.0, "burst": 100},
            {"principal": {"issuers": [ISSUER]}, "methods": ["POST", "PUT"], "path": "/orders/**", "requests_per_second": 5.0, "burst": 10},
            {"methods": ["GET"], "path": "/orders/{id}/export", "requests_per_second": 1.0, "burst": 2},
            {"methods": ["GET", "HEAD"], "path": "/orders/**", "requests_per_second": 20.0, "burst": 40},
            {"principal": {"principal_ids": ["synthetic-batch"]}, "requests_per_second": 2.0, "burst": 4},
            {"path": "/reports/**", "requests_per_second": 3.0, "burst": 6}
        ]
    })
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum RateExpected {
    NoOverride,
    Override {
        index: usize,
        requests_per_second: f64,
        burst: u32,
    },
    Indeterminate(Limitation),
}

impl RateExpected {
    fn matches(&self, result: &Result<RateLaneSelection, EvaluationError>) -> bool {
        let Ok(selection) = result else {
            return false;
        };
        match (*self, selection.outcome()) {
            (Self::NoOverride, RateLaneOutcome::NoOverride) => true,
            (
                Self::Override {
                    index,
                    requests_per_second,
                    burst,
                },
                RateLaneOutcome::Override {
                    index: selected,
                    limit,
                },
            ) => {
                selected == index
                    && limit.requests_per_second() == requests_per_second
                    && limit.burst() == burst
            }
            (Self::Indeterminate(expected), RateLaneOutcome::Indeterminate(limitation)) => {
                limitation == expected
            }
            _ => false,
        }
    }
}

struct RateCase {
    name: &'static str,
    method: Option<Method>,
    path: Option<&'static str>,
    caller: Caller,
    expected: RateExpected,
}

/// First match in source order over principal, method and path constraints,
/// an override shadowed by an earlier one, capture and recursive wildcard
/// patterns, a principal-id override, no override, the anonymous bypass and
/// each uncaptured fact.
fn rate_cases() -> Vec<RateCase> {
    use RateExpected::{Indeterminate, NoOverride};
    let lane = |index, requests_per_second, burst| RateExpected::Override {
        index,
        requests_per_second,
        burst,
    };
    let case = |name, method: Method, path, caller, expected| RateCase {
        name,
        method: Some(method),
        path: Some(path),
        caller,
        expected,
    };
    vec![
        case(
            "operator_service_token_override",
            Method::DELETE,
            "/orders/42",
            Caller::Operator,
            lane(0, 50.0, 100),
        ),
        case(
            "operator_cookie_skips_auth_method_override",
            Method::GET,
            "/reports/q3",
            Caller::OperatorWithCookie,
            lane(5, 3.0, 6),
        ),
        case(
            "issuer_bound_write_override",
            Method::POST,
            "/orders/42",
            Caller::Reader,
            lane(1, 5.0, 10),
        ),
        case(
            "other_issuer_write_without_override",
            Method::PUT,
            "/orders/42",
            Caller::OtherIssuer,
            NoOverride,
        ),
        case(
            "capture_override_precedes_wildcard",
            Method::GET,
            "/orders/42/export",
            Caller::Reader,
            lane(2, 1.0, 2),
        ),
        case(
            "wildcard_read_override",
            Method::GET,
            "/orders/42",
            Caller::Reader,
            lane(3, 20.0, 40),
        ),
        case(
            "wildcard_long_path_override",
            Method::HEAD,
            LONG_ORDER_PATH,
            Caller::OtherIssuer,
            lane(3, 20.0, 40),
        ),
        case(
            "principal_id_override",
            Method::DELETE,
            "/exports/7",
            Caller::Batch,
            lane(4, 2.0, 4),
        ),
        case(
            "unconstrained_path_override",
            Method::DELETE,
            "/reports/q3",
            Caller::Reader,
            lane(5, 3.0, 6),
        ),
        case(
            "no_matching_override",
            Method::GET,
            "/status",
            Caller::Reader,
            NoOverride,
        ),
        case(
            "anonymous_bypass",
            Method::GET,
            "/reports/q3",
            Caller::Anonymous,
            NoOverride,
        ),
        case(
            "uncaptured_principal",
            Method::GET,
            "/reports/q3",
            Caller::Uncaptured,
            Indeterminate(Limitation::MissingPrincipalFact),
        ),
        RateCase {
            name: "uncaptured_method",
            method: None,
            path: Some("/reports/q3"),
            caller: Caller::Reader,
            expected: Indeterminate(Limitation::MissingMethod),
        },
        RateCase {
            name: "uncaptured_path",
            method: Some(Method::GET),
            path: None,
            caller: Caller::Reader,
            expected: Indeterminate(Limitation::MissingPath),
        },
    ]
}

struct PreparedRate {
    name: &'static str,
    context: PolicyEvaluationContext,
    expected: RateExpected,
}

/// Builds every rate context once, before any measurement, in the shape the
/// live rate stage supplies: routing, host and dispatch facts uncaptured,
/// because selection does not read them. Also returns the total bytes of
/// method, path and principal facts the contexts carry.
fn prepare_rates(compiled: &CompiledPolicy) -> (Vec<PreparedRate>, usize) {
    let mut prepared = Vec::new();
    let mut input_bytes = 0;
    for case in rate_cases() {
        let (principal, principal_bytes) = case.caller.fact();
        input_bytes += case
            .method
            .as_ref()
            .map_or(0, |method| method.as_str().len())
            + case.path.map_or(0, str::len)
            + principal_bytes;
        prepared.push(PreparedRate {
            name: case.name,
            context: PolicyEvaluationContext {
                version: CONTEXT_VERSION,
                snapshot: compiled.snapshot(),
                method: case.method,
                path: case.path.map(str::to_owned),
                principal,
                target: HttpTarget::Missing,
                request_host: HostFact::Missing,
                dispatch: None,
            },
            expected: case.expected,
        });
    }
    (prepared, input_bytes)
}

fn preflight_rates(compiled: &CompiledPolicy, cases: &[PreparedRate]) -> Result<(), String> {
    for case in cases {
        let result = compiled.select_rate_lane(&case.context);
        if !case.expected.matches(&result) {
            let actual = result.map(|selection| selection.outcome());
            return Err(format!(
                "{}: expected {:?}, selected {actual:?}",
                case.name, case.expected
            ));
        }
    }
    Ok(())
}

/// One pass over the rate dataset; the checksum counts correct selections.
fn rate_iteration(compiled: &CompiledPolicy, cases: &[PreparedRate], regression: bool) -> u64 {
    let mut checksum = 0;
    for case in cases {
        let result = black_box(compiled).select_rate_lane(black_box(&case.context));
        if regression {
            let allocation = vec![black_box(0_u8); black_box(64_usize)];
            black_box(allocation);
        }
        checksum += u64::from(case.expected.matches(&black_box(result)));
    }
    checksum
}

/// Measures one prepared dataset exactly as the parent measures `http_policy`:
/// warmup, then allocation samples, then separately timed samples with
/// counting disabled. `pass` evaluates the whole dataset once and returns how
/// many decisions matched their expectation.
fn measure(
    id: &str,
    cases: usize,
    input_bytes: usize,
    regression: bool,
    mut pass: impl FnMut(bool) -> u64,
) -> Result<Value, String> {
    let operations = u64::try_from(cases).map_err(|_| "case count".to_owned())?;
    let mut warmup_checksum = 0;
    for _ in 0..WARMUP {
        warmup_checksum += pass(regression);
    }
    if warmup_checksum != operations * WARMUP {
        return Err("warmup checksum differs from the dataset".to_owned());
    }

    let expected_checksum = operations * ITERATIONS;
    let mut allocation_samples = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let (checksum, count) = count_allocations(|| {
            let mut checksum = 0;
            for _ in 0..ITERATIONS {
                checksum += black_box(pass(regression));
            }
            checksum
        })?;
        if checksum != expected_checksum {
            return Err("allocation sample checksum differs from the dataset".to_owned());
        }
        allocation_samples.push(json!({
            "allocations": count.allocations,
            "allocated_bytes": count.allocated_bytes,
            "checksum": checksum,
        }));
    }

    // As in the parent, this is an unoptimized test build whose allocator
    // still reads its flag: the timings describe this harness only.
    let mut timing_samples_ns = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let start = Instant::now();
        let mut checksum = 0;
        for _ in 0..ITERATIONS {
            checksum += black_box(pass(regression));
        }
        let elapsed = u64::try_from(start.elapsed().as_nanos())
            .map_err(|_| "timing sample overflow".to_owned())?;
        if checksum != expected_checksum {
            return Err("timing sample checksum differs from the dataset".to_owned());
        }
        timing_samples_ns.push(elapsed);
    }

    Ok(json!({
        "schema_version": 1,
        "harness": "gateway-test-binary",
        "regression_fixture": regression,
        "warmup": WARMUP,
        "iterations": ITERATIONS,
        "samples": SAMPLES,
        "targets": [{
            "id": id,
            "input_cases": cases,
            "input_bytes": input_bytes,
            "operations_per_iteration": cases,
            "expected_checksum": expected_checksum,
            "allocation_samples": allocation_samples,
            "timing_samples_ns": timing_samples_ns,
        }],
    }))
}

fn run_tools(regression: bool) -> Result<Value, String> {
    let compiled = compile(tool_policy_document())?;
    let (cases, input_bytes) = prepare_tools(&compiled);
    preflight_tools(&compiled, &cases)?;
    measure(
        TOOL_TARGET_ID,
        cases.len(),
        input_bytes,
        regression,
        |fixture| tool_iteration(&compiled, &cases, fixture),
    )
}

fn run_rates(regression: bool) -> Result<Value, String> {
    let compiled = compile(rate_policy_document())?;
    let (cases, input_bytes) = prepare_rates(&compiled);
    preflight_rates(&compiled, &cases)?;
    measure(
        RATE_TARGET_ID,
        cases.len(),
        input_bytes,
        regression,
        |fixture| rate_iteration(&compiled, &cases, fixture),
    )
}

/// The controller's side of a run: the fresh result path, the fixture switch
/// and a report that must not overwrite an existing one, as in the parent.
fn report(run: fn(bool) -> Result<Value, String>) {
    let result_path = std::env::var_os(RESULT_ENV)
        .expect("scripts/microbench.py supplies a fresh result path for this benchmark");
    let regression = match std::env::var(REGRESSION_ENV) {
        Err(VarError::NotPresent) => false,
        Ok(value) if value == "1" => true,
        _ => panic!("{REGRESSION_ENV} must be absent or exactly 1"),
    };
    let report = run(regression).unwrap_or_else(|error| panic!("benchmark failed: {error}"));
    let encoded = serde_json::to_vec(&report).expect("benchmark report encodes");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(result_path)
        .expect("benchmark result path must not already exist");
    file.write_all(&encoded)
        .expect("benchmark report is written");
}

#[test]
#[ignore = "run through scripts/microbench.py, which builds both revisions and owns the comparison"]
fn tool_policy_evaluation() {
    report(run_tools);
}

#[test]
#[ignore = "run through scripts/microbench.py, which builds both revisions and owns the comparison"]
fn rate_lane_selection() {
    report(run_rates);
}

#[test]
fn tool_policy_dataset_matches_its_expected_decisions() {
    let compiled = compile(tool_policy_document()).unwrap();
    let (cases, input_bytes) = prepare_tools(&compiled);
    preflight_tools(&compiled, &cases).unwrap();
    assert_eq!(cases.len(), 27);
    assert!(input_bytes > 0);
    assert_eq!(
        tool_iteration(&compiled, &cases, false),
        u64::try_from(cases.len()).unwrap()
    );
}

#[test]
fn rate_lane_dataset_matches_its_expected_selections() {
    let compiled = compile(rate_policy_document()).unwrap();
    let (cases, input_bytes) = prepare_rates(&compiled);
    preflight_rates(&compiled, &cases).unwrap();
    assert_eq!(cases.len(), 14);
    assert!(input_bytes > 0);
    assert_eq!(
        rate_iteration(&compiled, &cases, false),
        u64::try_from(cases.len()).unwrap()
    );
}
