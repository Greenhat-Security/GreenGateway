//! Allocation-counted benchmark of the authoritative HTTP policy decision.
//!
//! `scripts/microbench.py` builds the gateway test binary for both compared
//! revisions and runs the ignored `http_policy_evaluation` test in each. It
//! measures `CompiledPolicy::evaluate`, the call the live RBAC adapter makes,
//! over one fixed synthetic policy and request dataset. Policy validation,
//! compilation, context construction, expected-decision checks and report
//! serialization are all outside the measured intervals.
//!
//! The counting allocator below is this test binary's global allocator. It
//! counts only on the thread that enabled counting, so ordinary parallel unit
//! tests can share the binary without contaminating a measurement. Allocated
//! bytes are requested sizes, including the full new size of each realloc;
//! this is not a live-memory or peak-memory measurement.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    env::VarError,
    fs::OpenOptions,
    hint::black_box,
    io::Write,
    time::Instant,
};

use http::Method;
use serde_json::{json, Value};

use crate::{
    auth::{AuthMethod, Principal},
    policy_eval::{
        CompiledPolicy, DispatchFacts, Evaluation, EvaluationError, HostFact, HttpTarget,
        Limitation, LogicalDecision, PolicyAuthority, PolicyEffect, PolicyEvaluationContext,
        PrincipalFact, PrincipalIdentity, Reason, RuleReference, CONTEXT_VERSION,
    },
    rbac::Policy,
};

// The tool-admission and rate-lane benchmarks. A binary has one global
// allocator, so they live in a child module that counts through this one
// without widening its visibility. Their file has a digest of its own.
#[path = "lane_benchmark.rs"]
mod lane_benchmark;

/// Where the controller expects the report. The test refuses to run without
/// it and refuses to overwrite an existing file, so a stale report cannot pass.
const RESULT_ENV: &str = "GREENGATEWAY_MICROBENCH_RESULT";
/// `1` adds one 64-byte allocation per decision. Only the controller's
/// self-test sets it, and the report records that it did.
const REGRESSION_ENV: &str = "GREENGATEWAY_MICROBENCH_REGRESSION_FIXTURE";
const TARGET_ID: &str = "http_policy";
const WARMUP: u64 = 10;
const ITERATIONS: u64 = 100;
const SAMPLES: usize = 9;

#[derive(Clone, Copy)]
struct Counters {
    enabled: bool,
    allocations: u64,
    allocated_bytes: u64,
    overflowed: bool,
}

impl Counters {
    const IDLE: Self = Self {
        enabled: false,
        allocations: 0,
        allocated_bytes: 0,
        overflowed: false,
    };
}

thread_local! {
    // Constant initialization of a type without a destructor is a plain
    // thread-local slot: reading it never allocates or registers a
    // destructor, which is what makes it usable inside the allocator.
    static COUNTERS: Cell<Counters> = const { Cell::new(Counters::IDLE) };
}

fn record_allocation(size: usize) {
    // `try_with` cannot panic inside the allocator. A slot without a
    // destructor is never torn down, so it is always available.
    let _ = COUNTERS.try_with(|slot| {
        let mut counters = slot.get();
        if !counters.enabled {
            return;
        }
        let allocations = counters.allocations.checked_add(1);
        let allocated_bytes = u64::try_from(size)
            .ok()
            .and_then(|bytes| counters.allocated_bytes.checked_add(bytes));
        match (allocations, allocated_bytes) {
            (Some(allocations), Some(allocated_bytes)) => {
                counters.allocations = allocations;
                counters.allocated_bytes = allocated_bytes;
            }
            _ => counters.overflowed = true,
        }
        slot.set(counters);
    });
}

struct CountingAllocator;

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

// SAFETY: Every allocation operation delegates unchanged to System. The
// bookkeeping touches only a destructor-free thread-local cell and cannot
// recursively invoke the allocator.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record_allocation(layout.size());
        // SAFETY: The caller provides the valid allocation layout unchanged.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record_allocation(layout.size());
        // SAFETY: The caller provides the valid allocation layout unchanged.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        record_allocation(new_size);
        // SAFETY: The caller's pointer, original layout, and new size are
        // forwarded to the allocator that originally supplied the allocation.
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: The caller's pointer and layout are forwarded unchanged to
        // the same allocator that supplied the allocation.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct AllocationCount {
    allocations: u64,
    allocated_bytes: u64,
}

/// Counts the allocator calls `work` makes on this thread.
fn count_allocations<T>(work: impl FnOnce() -> T) -> Result<(T, AllocationCount), String> {
    COUNTERS.with(|slot| {
        slot.set(Counters {
            enabled: true,
            ..Counters::IDLE
        })
    });
    let value = work();
    let counters = COUNTERS.with(|slot| slot.replace(Counters::IDLE));
    if counters.overflowed {
        return Err("allocation counter overflow".to_owned());
    }
    Ok((
        value,
        AllocationCount {
            allocations: counters.allocations,
            allocated_bytes: counters.allocated_bytes,
        },
    ))
}

/// A public, synthetic policy. Every host uses the reserved `.test` suffix and
/// no value is a credential.
fn policy_document() -> Value {
    json!({
        "schema_version": "0.1.0",
        "default_action": "deny",
        "enforcement_mode": "enforce",
        "roles": {
            "reader": {
                "permissions": ["orders.read"],
                "issuers": ["https://idp.example.test/"],
                "auth_methods": ["bearer_token"]
            },
            "writer": {"permissions": ["orders.read", "orders.write"]},
            "operator": {"permissions": ["*"], "auth_methods": ["service_token"]}
        },
        "routes": [
            {"methods": ["GET"], "hosts": ["tenant-a.example.test"], "path_prefix": "/tenant", "permission": "orders.read"},
            {"methods": ["GET", "HEAD"], "path_prefix": "/orders", "permission": "orders.read"},
            {"methods": ["POST", "PUT"], "path_prefix": "/orders", "permission": "orders.write"},
            {"path_prefix": "/reports", "permission": "reports.read", "enforcement_mode": "shadow"},
            {"path_prefix": "/mcp", "permission": "mcp.use"},
            {"hosts": ["virtual.example.test"], "path_prefix": "/", "permission": "orders.read"}
        ],
        "rules": [
            {"id": "public-health", "methods": ["GET"], "path": "/public/health", "action": "allow"},
            {"id": "deny-admin", "path": "/admin/**", "action": "deny"},
            {"id": "shadow-export", "methods": ["GET"], "path": "/orders/{id}/export", "action": "shadow"},
            {"id": "allow-docs", "path": "/docs/**", "action": "allow"},
            {"id": "contextless-status", "path": "/status", "dispatch": {"kind": "contextless"}, "action": "allow"},
            {"id": "route-delete-deny", "methods": ["DELETE"], "path": "/orders/**", "dispatch": {"kind": "route", "route_id": "orders-api"}, "action": "deny"},
            {"id": "team-writers", "path": "/team/**", "principal": {"roles": ["writer"]}, "action": "allow"},
            {"id": "mcp-cookie-deny", "path": "/mcp", "principal": {"auth_methods": ["session_cookie"]}, "action": "deny"},
            {"id": "disabled-catch-all", "enabled": false, "path": "/**", "action": "deny"},
            {"id": "tool-deny", "tool_name": "synthetic_tool", "action": "deny"}
        ]
    })
}

const LONG_ADMIN_PATH: &str = concat!(
    "/admin/segment01/segment02/segment03/segment04/segment05/segment06/",
    "segment07/segment08/segment09/segment10/segment11/segment12/segment13/",
    "segment14/segment15/segment16/segment17/segment18/segment19/segment20/file.json"
);

#[derive(Clone, Copy)]
enum Caller {
    Anonymous,
    Reader,
    ReaderWithCookie,
    Writer,
    Operator,
}

impl Caller {
    fn principal(self) -> Option<Principal> {
        let (user_id, issuer, role, auth_method) = match self {
            Self::Anonymous => return None,
            Self::Reader => (
                "synthetic-reader",
                Some("https://idp.example.test"),
                "reader",
                AuthMethod::Bearer,
            ),
            Self::ReaderWithCookie => (
                "synthetic-reader",
                Some("https://idp.example.test"),
                "reader",
                AuthMethod::Cookie,
            ),
            Self::Writer => (
                "synthetic-writer",
                Some("https://idp.example.test"),
                "writer",
                AuthMethod::Cookie,
            ),
            Self::Operator => (
                "synthetic-operator",
                None,
                "operator",
                AuthMethod::ServiceToken,
            ),
        };
        Some(Principal {
            user_id: user_id.to_owned(),
            issuer: issuer.map(str::to_owned),
            email: None,
            org_id: None,
            roles: vec![role.to_owned()],
            session_id: String::new(),
            auth_method,
        })
    }
}

#[derive(Clone, Copy)]
enum Target {
    Contextless,
    Proxy {
        route_id: Option<&'static str>,
        route_host: Option<&'static str>,
        route_path_prefix: &'static str,
        upstream_origin: &'static str,
    },
    /// An MCP endpoint reached by another path, with its canonical identity.
    McpAlias(&'static str),
}

#[derive(Clone, Copy)]
enum Host {
    Absent,
    Present(&'static str),
    Missing,
}

struct Case {
    name: &'static str,
    method: &'static str,
    path: &'static str,
    caller: Caller,
    target: Target,
    host: Host,
    expected: Expected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Expected {
    logical: LogicalDecision,
    effect: PolicyEffect,
    reason: Reason,
    matched: Option<RuleReference>,
    observation: Option<RuleReference>,
    limitation: Option<Limitation>,
}

impl Expected {
    const fn allowed(reason: Reason, matched: Option<RuleReference>) -> Self {
        Self::denied(PolicyEffect::Allow, reason, matched).with_logical(LogicalDecision::Allow)
    }

    const fn denied(effect: PolicyEffect, reason: Reason, matched: Option<RuleReference>) -> Self {
        Self {
            logical: LogicalDecision::Deny,
            effect,
            reason,
            matched,
            observation: None,
            limitation: None,
        }
    }

    const fn with_logical(mut self, logical: LogicalDecision) -> Self {
        self.logical = logical;
        self
    }

    const fn observed(mut self, observation: RuleReference) -> Self {
        self.observation = Some(observation);
        self
    }

    fn matches(&self, result: &Result<Evaluation, EvaluationError>) -> bool {
        let Ok(evaluation) = result else {
            return false;
        };
        evaluation.logical() == self.logical
            && evaluation.effect() == self.effect
            && evaluation.reason() == self.reason
            && evaluation.matched() == self.matched
            && evaluation.observation() == self.observation
            && evaluation.limitation() == self.limitation
            && evaluation.is_complete() == self.limitation.is_none()
    }
}

/// One request per lane of the HTTP decision: direct allow, deny and shadow
/// rules, a dispatch-scoped rule, routes with and without permission, shadow
/// enforcement, a host-qualified route, a selected virtual upstream with and
/// without a host-bound route, both MCP alias lanes, the policy default and an
/// unanswerable request.
fn cases() -> Vec<Case> {
    use PolicyEffect::{Block, Observe};
    use Reason::{
        DefaultDeny, HostPolicyRequired, MatchedRule, MissingPermission, MissingPrincipal,
    };
    use RuleReference::{Direct, Route};
    let api = Host::Present("api.example.test");
    vec![
        Case {
            name: "public_health_anonymous",
            method: "GET",
            path: "/public/health",
            caller: Caller::Anonymous,
            target: Target::Contextless,
            host: Host::Absent,
            expected: Expected::allowed(MatchedRule, Some(Direct(0))),
        },
        Case {
            name: "admin_long_path_deny",
            method: "DELETE",
            path: LONG_ADMIN_PATH,
            caller: Caller::Writer,
            target: Target::Contextless,
            host: api,
            expected: Expected::denied(Block, MatchedRule, Some(Direct(1))),
        },
        Case {
            name: "export_shadow_rule",
            method: "GET",
            path: "/orders/42/export",
            caller: Caller::Reader,
            target: Target::Contextless,
            host: api,
            expected: Expected::denied(Observe, MatchedRule, Some(Direct(2))),
        },
        Case {
            name: "orders_read_route",
            method: "GET",
            path: "/orders/42",
            caller: Caller::Reader,
            target: Target::Contextless,
            host: api,
            expected: Expected::allowed(MatchedRule, Some(Route(1))),
        },
        Case {
            name: "orders_write_without_permission",
            method: "POST",
            path: "/orders",
            caller: Caller::Reader,
            target: Target::Contextless,
            host: api,
            expected: Expected::denied(Block, MissingPermission, Some(Route(2))),
        },
        Case {
            name: "orders_anonymous",
            method: "GET",
            path: "/orders/7",
            caller: Caller::Anonymous,
            target: Target::Contextless,
            host: Host::Absent,
            expected: Expected::denied(Block, MissingPrincipal, Some(Route(1))),
        },
        Case {
            name: "role_inactive_for_auth_method",
            method: "GET",
            path: "/orders/7",
            caller: Caller::ReaderWithCookie,
            target: Target::Contextless,
            host: api,
            expected: Expected::denied(Block, MissingPermission, Some(Route(1))),
        },
        Case {
            name: "reports_shadow_route",
            method: "GET",
            path: "/reports/q3",
            caller: Caller::Writer,
            target: Target::Contextless,
            host: Host::Absent,
            expected: Expected::denied(Observe, MissingPermission, Some(Route(3))),
        },
        Case {
            name: "operator_wildcard_permission",
            method: "PUT",
            path: "/reports/q3",
            caller: Caller::Operator,
            target: Target::Contextless,
            host: Host::Absent,
            expected: Expected::allowed(MatchedRule, Some(Route(3))),
        },
        Case {
            name: "policy_default_deny",
            method: "GET",
            path: "/unknown/path",
            caller: Caller::Writer,
            target: Target::Contextless,
            host: api,
            expected: Expected::denied(Block, DefaultDeny, None),
        },
        Case {
            name: "tenant_host_route",
            method: "GET",
            path: "/tenant/reports",
            caller: Caller::Reader,
            target: Target::Contextless,
            host: Host::Present("tenant-a.example.test"),
            expected: Expected::allowed(MatchedRule, Some(Route(0))),
        },
        Case {
            name: "virtual_upstream_with_shadow_observation",
            method: "GET",
            path: "/orders/42/export",
            caller: Caller::Reader,
            target: Target::Proxy {
                route_id: Some("virtual-api"),
                route_host: Some("virtual.example.test"),
                route_path_prefix: "/",
                upstream_origin: "https://upstream.example.test",
            },
            host: Host::Present("virtual.example.test"),
            expected: Expected::allowed(MatchedRule, Some(Route(5))).observed(Direct(2)),
        },
        Case {
            name: "virtual_upstream_without_host_route",
            method: "GET",
            path: "/orders/42",
            caller: Caller::Reader,
            target: Target::Proxy {
                route_id: Some("orders-api"),
                route_host: Some("unlisted.example.test"),
                route_path_prefix: "/orders",
                upstream_origin: "https://orders.example.test",
            },
            host: Host::Present("unlisted.example.test"),
            expected: Expected::denied(Block, HostPolicyRequired, None),
        },
        Case {
            name: "route_bound_delete_deny",
            method: "DELETE",
            path: "/orders/42",
            caller: Caller::Operator,
            target: Target::Proxy {
                route_id: Some("orders-api"),
                route_host: None,
                route_path_prefix: "/orders",
                upstream_origin: "https://orders.example.test",
            },
            host: Host::Present("orders.example.test"),
            expected: Expected::denied(Block, MatchedRule, Some(Direct(5))),
        },
        Case {
            name: "mcp_alias_deny_outranks_allow",
            method: "POST",
            path: "/docs/mcp",
            caller: Caller::Writer,
            target: Target::McpAlias("/mcp"),
            host: api,
            expected: Expected::denied(Block, MatchedRule, Some(Direct(7))),
        },
        Case {
            name: "mcp_alias_canonical_route",
            method: "POST",
            path: "/agents/mcp",
            caller: Caller::Operator,
            target: Target::McpAlias("/mcp"),
            host: Host::Absent,
            expected: Expected::allowed(MatchedRule, Some(Route(4))),
        },
        Case {
            name: "uncaptured_host_is_indeterminate",
            method: "GET",
            path: "/orders/7",
            caller: Caller::Reader,
            target: Target::Contextless,
            host: Host::Missing,
            expected: Expected {
                logical: LogicalDecision::Indeterminate,
                effect: Block,
                reason: Reason::Incomplete,
                matched: None,
                observation: None,
                limitation: Some(Limitation::MissingHostFact),
            },
        },
    ]
}

struct Prepared {
    name: &'static str,
    context: PolicyEvaluationContext,
    expected: Expected,
}

/// Builds every context once, before any measurement. Also returns the total
/// bytes of request facts the contexts carry: method, path, canonical path,
/// request host, dispatch facts, and the principal's subject, issuer and roles.
fn prepare(compiled: &CompiledPolicy) -> Result<(Vec<Prepared>, usize), String> {
    let mut prepared = Vec::new();
    let mut input_bytes = 0;
    for case in cases() {
        let method = Method::from_bytes(case.method.as_bytes())
            .map_err(|_| format!("{}: invalid method", case.name))?;
        let (target, dispatch, target_bytes) = match case.target {
            Target::Contextless => (HttpTarget::Contextless, None, 0),
            Target::Proxy {
                route_id,
                route_host,
                route_path_prefix,
                upstream_origin,
            } => (
                HttpTarget::ProxyDispatch,
                Some(DispatchFacts {
                    route_id: route_id.map(str::to_owned),
                    route_host: route_host.map(str::to_owned),
                    route_path_prefix: Some(route_path_prefix.to_owned()),
                    upstream_origin: upstream_origin.to_owned(),
                }),
                route_id.map_or(0, str::len)
                    + route_host.map_or(0, str::len)
                    + route_path_prefix.len()
                    + upstream_origin.len(),
            ),
            Target::McpAlias(canonical_path) => (
                HttpTarget::McpAlias {
                    canonical_path: canonical_path.to_owned(),
                },
                None,
                canonical_path.len(),
            ),
        };
        let (request_host, host_bytes) = match case.host {
            Host::Absent => (HostFact::Absent, 0),
            Host::Missing => (HostFact::Missing, 0),
            Host::Present(host) => (HostFact::Present(host.to_owned()), host.len()),
        };
        let principal = case.caller.principal();
        let principal_bytes = principal.as_ref().map_or(0, |principal| {
            principal.user_id.len()
                + principal.issuer.as_ref().map_or(0, String::len)
                + principal.roles.iter().map(String::len).sum::<usize>()
        });
        input_bytes +=
            case.method.len() + case.path.len() + target_bytes + host_bytes + principal_bytes;
        prepared.push(Prepared {
            name: case.name,
            context: PolicyEvaluationContext {
                version: CONTEXT_VERSION,
                snapshot: compiled.snapshot(),
                method: Some(method),
                path: Some(case.path.to_owned()),
                // The live adapter projects an authenticated principal this way.
                principal: principal
                    .as_ref()
                    .map_or(PrincipalFact::Anonymous, |principal| {
                        PrincipalFact::Authenticated(PrincipalIdentity::from_principal(principal))
                    }),
                target,
                request_host,
                dispatch,
            },
            expected: case.expected,
        });
    }
    Ok((prepared, input_bytes))
}

fn compile_policy() -> Result<CompiledPolicy, String> {
    // The live install path: an already-validated policy, as RBAC state holds.
    let policy = Policy::validate_json_value(policy_document())
        .map_err(|error| format!("synthetic policy is invalid: {error}"))?;
    CompiledPolicy::from_validated_policy(policy, PolicyAuthority::Standalone)
        .map_err(|error| format!("synthetic policy does not compile: {error:?}"))
}

/// Checks every expected decision individually, so two opposite mistakes
/// cannot cancel out in the measured checksum.
fn preflight(compiled: &CompiledPolicy, cases: &[Prepared]) -> Result<(), String> {
    for case in cases {
        let result = compiled.evaluate(&case.context);
        if !case.expected.matches(&result) {
            let actual = result.map(|evaluation| {
                (
                    evaluation.logical(),
                    evaluation.effect(),
                    evaluation.reason(),
                    evaluation.matched(),
                    evaluation.observation(),
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

/// One pass over the dataset. The checksum counts decisions that match their
/// expectation, so an incorrect fast path cannot pass as an improvement.
fn iteration(compiled: &CompiledPolicy, cases: &[Prepared], regression: bool) -> u64 {
    let mut checksum = 0;
    for case in cases {
        let result = black_box(compiled).evaluate(black_box(&case.context));
        if regression {
            let allocation = vec![black_box(0_u8); black_box(64_usize)];
            black_box(allocation);
        }
        checksum += u64::from(case.expected.matches(&black_box(result)));
    }
    checksum
}

fn run(regression: bool) -> Result<Value, String> {
    let compiled = compile_policy()?;
    let (cases, input_bytes) = prepare(&compiled)?;
    preflight(&compiled, &cases)?;
    let operations = u64::try_from(cases.len()).map_err(|_| "case count".to_owned())?;

    let mut warmup_checksum = 0;
    for _ in 0..WARMUP {
        warmup_checksum += iteration(&compiled, &cases, regression);
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
                checksum += black_box(iteration(&compiled, &cases, regression));
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

    // Timing uses a separate pass with counting disabled. The allocator still
    // reads its thread-local flag, and this is an unoptimized test build, so
    // these figures describe this harness rather than the shipped gateway.
    let mut timing_samples_ns = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let start = Instant::now();
        let mut checksum = 0;
        for _ in 0..ITERATIONS {
            checksum += black_box(iteration(&compiled, &cases, regression));
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
            "id": TARGET_ID,
            "input_cases": cases.len(),
            "input_bytes": input_bytes,
            "operations_per_iteration": cases.len(),
            "expected_checksum": expected_checksum,
            "allocation_samples": allocation_samples,
            "timing_samples_ns": timing_samples_ns,
        }],
    }))
}

#[test]
#[ignore = "run through scripts/microbench.py, which builds both revisions and owns the comparison"]
fn http_policy_evaluation() {
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
fn counting_allocator_counts_only_enabled_work_on_this_thread() {
    use std::sync::{
        atomic::{AtomicU8, Ordering},
        Arc,
    };

    let (_, empty) = count_allocations(|| ()).unwrap();
    assert_eq!(empty, AllocationCount::default());

    let (_, counted) = count_allocations(|| {
        let mut bytes: Vec<u8> = Vec::with_capacity(black_box(64));
        bytes.extend_from_slice(black_box(&[1_u8; 64]));
        bytes.reserve_exact(black_box(64));
        black_box(bytes)
    })
    .unwrap();
    // One allocation, then a realloc counted at its full new size.
    assert_eq!(
        counted,
        AllocationCount {
            allocations: 2,
            allocated_bytes: 64 + 128,
        }
    );

    // Another thread allocating inside the interval is not counted. The
    // handshake uses only atomics, which never allocate.
    let state = Arc::new(AtomicU8::new(0));
    let worker_state = Arc::clone(&state);
    let worker = std::thread::spawn(move || {
        while worker_state.load(Ordering::Acquire) != 1 {
            std::hint::spin_loop();
        }
        let bytes = black_box(vec![0_u8; 4096]);
        worker_state.store(2, Ordering::Release);
        bytes.len()
    });
    let (_, concurrent) = count_allocations(|| {
        state.store(1, Ordering::Release);
        while state.load(Ordering::Acquire) != 2 {
            std::hint::spin_loop();
        }
    })
    .unwrap();
    assert_eq!(concurrent, AllocationCount::default());
    assert_eq!(worker.join().unwrap(), 4096);

    // Counting stops with the interval.
    black_box(Vec::<u8>::with_capacity(black_box(32)));
    let (_, idle) = count_allocations(|| ()).unwrap();
    assert_eq!(idle, AllocationCount::default());
}

#[test]
fn http_policy_dataset_matches_its_expected_decisions() {
    let compiled = compile_policy().unwrap();
    let (cases, input_bytes) = prepare(&compiled).unwrap();
    preflight(&compiled, &cases).unwrap();
    assert_eq!(cases.len(), 17);
    assert!(input_bytes > 0);
    assert_eq!(
        iteration(&compiled, &cases, false),
        u64::try_from(cases.len()).unwrap()
    );
}
