//! Tool-argument conditions on the tool-call lane (issue #243): a tool-name
//! rule that reads a call's arguments is decided only after the arguments
//! have passed the tool's input schema, before any queue permit, capacity or
//! lease is taken, from the eligible scalars its conditions read and nothing
//! else.
//!
//! Each test drives real calls through the executor, the runtime and the
//! RBAC state, and holds what they decide to the shared evaluator asked
//! directly with facts built by hand.

use std::sync::atomic::AtomicI64;

use async_trait::async_trait;

use super::*;
use crate::{
    middleware::rbac::RbacState,
    policy_eval::{
        stages::NoStages,
        tools::{ToolEvaluationContext, ToolLimitation, ToolOperation, TOOL_CONTEXT_VERSION},
        CompiledPolicy, LogicalDecision, PolicyAuthority, PolicyEffect, PrincipalFact,
        UNCAPTURED_FACTS,
    },
    policy_replay::{
        evaluate::evaluate_tool,
        legacy::{adapt_audit_event, LegacyRecord},
        ReplayFacts,
    },
    storage::RepositoryError,
    tools::lease::{ExecutionLease, ExecutionLeaseStore, LeaseAttempt},
};

const TOOL: &str = "reports.export";
/// Values a call passes that no condition matches and no record may repeat:
/// one in an eligible field, two in fields the schema marks secret.
const REGION_CANARY: &str = "regionmk1";
const PIN_CANARY: &str = "pinmark77";
const MEMO_CANARY: &str = "memomark7";

fn export_tool() -> Value {
    json!({
        "name": TOOL,
        "description": "Exports a report for one region.",
        "input_json_schema": {
            "type": "object",
            "required": ["region"],
            "properties": {
                "region": { "type": "string" },
                "limit": { "type": "integer" },
                "pin": { "type": "string", "format": "password" },
                "memo": { "type": "string", "writeOnly": true }
            },
            "additionalProperties": false
        },
        "upstream": {
            "method": "POST",
            "path_template": "/v1/exports",
            "body": { "mode": "whole_args_json" }
        }
    })
}

/// Deny exports for one region, watch large ones, allow the rest.
fn export_policy(rules: Value) -> Policy {
    Policy::validate_json_value(json!({
        "schema_version": "1.0.0",
        "tools": { TOOL: { "timeout_ms": 2000, "max_concurrent": 1 } },
        "rules": rules
    }))
    .expect("the export policy validates")
}

fn argument_rules() -> Value {
    json!([
        {
            "id": "no-eu-exports",
            "tool_name": TOOL,
            "action": "deny",
            "conditions": { "tool_argument": { "pointer": "/region", "in": ["eu"] } }
        },
        {
            "id": "watch-large-exports",
            "tool_name": TOOL,
            "action": "shadow",
            "conditions": { "tool_argument": { "pointer": "/limit", "in": [1000] } }
        }
    ])
}

/// A lease authority that grants every slot and counts what it was asked.
#[derive(Default)]
struct CountingLeases {
    acquired: AtomicUsize,
    fence: AtomicI64,
}

#[async_trait]
impl ExecutionLeaseStore for CountingLeases {
    async fn try_acquire(
        &self,
        scope: &str,
        _capacity: u32,
        _invocation: &str,
    ) -> Result<LeaseAttempt, RepositoryError> {
        self.acquired.fetch_add(1, Ordering::SeqCst);
        Ok(LeaseAttempt::Acquired(ExecutionLease {
            scope: scope.to_owned(),
            slot: 0,
            fence: self.fence.fetch_add(1, Ordering::SeqCst) + 1,
        }))
    }

    async fn renew(&self, _lease: &ExecutionLease) -> Result<bool, RepositoryError> {
        Ok(true)
    }

    async fn release(&self, _lease: &ExecutionLease) -> Result<(), RepositoryError> {
        Ok(())
    }

    async fn is_current(&self, _lease: &ExecutionLease) -> Result<bool, RepositoryError> {
        Ok(true)
    }

    fn ttl(&self) -> Duration {
        Duration::from_secs(30)
    }
}

/// An upstream that answers every request `200 {}` and counts them.
async fn counting_upstream() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("test listener should bind");
    let addr = listener
        .local_addr()
        .expect("listener local address should be available");
    let requests = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&requests);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let seen = Arc::clone(&seen);
            tokio::spawn(async move {
                let _request = read_http_request(&mut stream).await;
                seen.fetch_add(1, Ordering::SeqCst);
                write_response(&mut stream, StatusCode::OK, b"{}").await;
            });
        }
    });
    (addr, requests)
}

struct Lane {
    executor: ToolExecutor,
    capture: CaptureSink,
    leases: Arc<CountingLeases>,
    upstream: Arc<AtomicUsize>,
    compiled: CompiledPolicy,
}

async fn lane(rules: Value) -> Lane {
    let policy = export_policy(rules);
    let compiled =
        CompiledPolicy::from_validated_policy(policy.clone(), PolicyAuthority::Standalone)
            .expect("the export policy compiles");
    let (addr, upstream) = counting_upstream().await;
    let capture = CaptureSink::new();
    let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
    let leases = Arc::new(CountingLeases::default());
    let runtime = ToolRuntime::new_with_rbac_state_and_leases(
        runtime_config([(TOOL, enabled_tool(2_000, 1))], 4, 1, 1_000),
        audit.clone(),
        Some(RbacState::new(policy, Vec::new(), false, audit.clone())),
        Some(Arc::clone(&leases) as Arc<dyn ExecutionLeaseStore>),
    );
    let executor = executor_for_tools_with_runtime(addr, [export_tool()], runtime, audit);
    Lane {
        executor,
        capture,
        leases,
        upstream,
        compiled,
    }
}

fn call_context(request_id: &str) -> ToolInvocationContext {
    ToolInvocationContext {
        request_id: request_id.to_owned(),
        ..invocation_context()
    }
}

/// What a call came to, in the terms the kernel answers in.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// Admitted: the work ran and reached the upstream.
    Admitted,
    /// Refused by a rule the arguments matched.
    Denied,
    /// Refused because the rules could not be decided.
    Incomplete,
    /// Refused by the input schema before the policy read anything.
    InvalidArguments,
}

fn outcome(result: &Result<ToolExecutionResult, ToolRuntimeError>) -> Outcome {
    match result {
        Ok(_) => Outcome::Admitted,
        Err(ToolRuntimeError::Rejected { reason, .. }) if reason == "matched_rule" => {
            Outcome::Denied
        }
        Err(ToolRuntimeError::Rejected { reason, .. })
            if reason == "policy_evaluation_incomplete" =>
        {
            Outcome::Incomplete
        }
        Err(ToolRuntimeError::WorkFailed {
            reason: Some(reason),
            ..
        }) if reason == "invalid_params" => Outcome::InvalidArguments,
        Err(other) => panic!("an outcome the fixture cannot produce: {other:?}"),
    }
}

/// The kernel's own answer for an anonymous invocation with `arguments`
/// already reduced by hand to the fields its conditions may read.
fn kernel(compiled: &CompiledPolicy, arguments: Option<Value>) -> Outcome {
    let context = ToolEvaluationContext {
        version: TOOL_CONTEXT_VERSION,
        snapshot: compiled.snapshot(),
        operation: ToolOperation::Invocation,
        tool_name: Some(TOOL.to_owned()),
        principal: PrincipalFact::Anonymous,
        method: None,
        path: None,
    };
    let mut facts = UNCAPTURED_FACTS.clone();
    if let Some(arguments) = arguments {
        facts.tool_arguments = Fact::Captured(arguments);
    }
    let evaluation = compiled
        .evaluate_tool_with_facts(&context, &facts, &mut NoStages)
        .expect("the kernel answers");
    match (evaluation.logical(), evaluation.effect()) {
        (LogicalDecision::Indeterminate, _) => Outcome::Incomplete,
        (_, PolicyEffect::Block) => Outcome::Denied,
        (_, PolicyEffect::Allow | PolicyEffect::Observe) => Outcome::Admitted,
    }
}

async fn call(lane: &Lane, request_id: &str, arguments: Value) -> Outcome {
    outcome(
        &lane
            .executor
            .execute(
                TOOL,
                arguments,
                call_context(request_id),
                CancellationToken::new(),
            )
            .await,
    )
}

/// The audit events of one call once its last runtime record -- its
/// success, failure or rejection -- has arrived; audit is delivered off the
/// calling task.
async fn settled_events(capture: &CaptureSink, request_id: &str) -> Vec<AuditEvent> {
    wait_until(Duration::from_secs(2), || {
        events_of(capture, request_id).iter().any(|event| {
            [
                audit::event::TOOL_INVOKE_SUCCESS,
                audit::event::TOOL_INVOKE_FAILURE,
                audit::event::TOOL_INVOKE_REJECTED,
            ]
            .contains(&event.event_type.as_str())
        })
    })
    .await;
    events_of(capture, request_id)
}

fn events_of(capture: &CaptureSink, request_id: &str) -> Vec<AuditEvent> {
    capture
        .events()
        .into_iter()
        .filter(|event| event.request_id == request_id)
        .collect()
}

#[tokio::test]
async fn argument_rules_decide_as_the_kernel_does_from_the_eligible_fields_alone() {
    let lane = lane(argument_rules()).await;
    let mut admitted = 0;
    for (index, (arguments, reduced)) in [
        (json!({ "region": "eu" }), json!({ "region": "eu" })),
        (json!({ "region": "us" }), json!({ "region": "us" })),
        (
            json!({ "region": "us", "limit": 1000 }),
            json!({ "region": "us", "limit": 1000 }),
        ),
        (
            json!({ "region": "us", "limit": 5 }),
            json!({ "region": "us", "limit": 5 }),
        ),
        // A secret-marked field never reaches the kernel, whatever it holds.
        (
            json!({ "region": "eu", "pin": "eu", "memo": "eu" }),
            json!({ "region": "eu" }),
        ),
        (
            json!({ "region": "us", "pin": PIN_CANARY, "memo": MEMO_CANARY }),
            json!({ "region": "us" }),
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let request_id = format!("parity-{index}");
        let live = call(&lane, &request_id, arguments.clone()).await;
        assert_eq!(live, kernel(&lane.compiled, Some(reduced)), "{arguments}");
        // Without the arguments the kernel cannot tell: the live lane asked
        // for them rather than guess.
        assert_eq!(kernel(&lane.compiled, None), Outcome::Incomplete);
        let events = settled_events(&lane.capture, &request_id).await;
        let decided = events
            .iter()
            .filter(|event| event.event_type.starts_with("authz."))
            .collect::<Vec<_>>();
        if live == Outcome::Admitted {
            admitted += 1;
        } else {
            assert_eq!(decided.len(), 1, "{arguments}: one rule decided");
            assert_eq!(decided[0].payload["matched_rule_id"], "no-eu-exports");
            assert!(events
                .iter()
                .all(|event| event.event_type != audit::event::TOOL_INVOKE_START));
        }
    }
    wait_until(Duration::from_secs(2), || {
        lane.upstream.load(Ordering::SeqCst) == admitted
    })
    .await;
    // The shadow rule observed the large export it matched and nothing else.
    let observed = lane
        .capture
        .events()
        .into_iter()
        .filter(|event| event.event_type == "authz.would_deny")
        .map(|event| event.request_id)
        .collect::<Vec<_>>();
    assert_eq!(observed, vec!["parity-2".to_owned()]);
}

#[tokio::test]
async fn invalid_arguments_are_refused_before_the_policy_reads_any_of_them() {
    let lane = lane(argument_rules()).await;
    for (index, arguments) in [
        // Each would match the deny rule if it were read.
        json!({ "region": "eu", "unexpected": "eu" }),
        json!({ "region": "eu", "limit": "1000" }),
        json!({ "limit": 1000 }),
        json!({ "region": ["eu"] }),
    ]
    .into_iter()
    .enumerate()
    {
        let request_id = format!("invalid-{index}");
        let result = lane
            .executor
            .execute(
                TOOL,
                arguments.clone(),
                call_context(&request_id),
                CancellationToken::new(),
            )
            .await;
        assert_eq!(outcome(&result), Outcome::InvalidArguments, "{arguments}");
        let Err(ToolRuntimeError::WorkFailed {
            details: Some(details),
            ..
        }) = &result
        else {
            panic!("{arguments}: the caller keeps the validation details");
        };
        assert!(details["problems"]
            .as_array()
            .is_some_and(|p| !p.is_empty()));
        let events = settled_events(&lane.capture, &request_id).await;
        assert!(
            events
                .iter()
                .all(|event| !event.event_type.starts_with("authz.")),
            "{arguments}: no rule decided"
        );
        let rejected = events
            .iter()
            .find(|event| event.event_type == audit::event::TOOL_INVOKE_REJECTED)
            .unwrap_or_else(|| panic!("{arguments}: the refusal is audited"));
        assert_eq!(rejected.payload["reason"], "invalid_params");
        assert!(rejected.payload["problems"].is_array());
        assert!(events
            .iter()
            .all(|event| event.event_type != audit::event::TOOL_INVOKE_START));
    }
    assert_eq!(lane.leases.acquired.load(Ordering::SeqCst), 0);
    assert_eq!(lane.upstream.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_call_an_argument_rule_refuses_takes_no_permit_or_lease() {
    let lane = lane(argument_rules()).await;
    assert_eq!(
        call(&lane, "denied", json!({ "region": "eu" })).await,
        Outcome::Denied
    );
    assert_eq!(lane.leases.acquired.load(Ordering::SeqCst), 0);
    // The decision and the rejection, and no start: the tool observation
    // beside them is the executor's outcome record, not an admission step.
    let events: Vec<AuditEvent> = settled_events(&lane.capture, "denied")
        .await
        .into_iter()
        .filter(|event| event.event_type != "http.request_observed")
        .collect();
    assert_eq!(
        events
            .iter()
            .map(|event| event.event_type.as_str())
            .collect::<Vec<_>>(),
        vec!["authz.denied", audit::event::TOOL_INVOKE_REJECTED]
    );
    assert_eq!(events[1].payload["reason"], "matched_rule");

    // The same lane takes its leases for a call the rules admit, so the
    // count above is the authority's, not a lane that never leases.
    assert_eq!(
        call(&lane, "admitted", json!({ "region": "us" })).await,
        Outcome::Admitted
    );
    assert!(lane.leases.acquired.load(Ordering::SeqCst) >= 2);
}

#[tokio::test]
async fn a_rule_over_a_field_the_schema_makes_ineligible_refuses_every_call_it_reaches() {
    // The document is sound, and publication would refuse it against this
    // registry; loaded from a file, or kept while the tool's schema changed,
    // it still never decides on the secret field.
    let lane = lane(json!([
        {
            "id": "no-known-pin",
            "tool_name": TOOL,
            "action": "deny",
            "conditions": { "tool_argument": { "pointer": "/pin", "in": [PIN_CANARY] } }
        },
        {
            "id": "no-eu-exports",
            "tool_name": TOOL,
            "action": "deny",
            "conditions": { "tool_argument": { "pointer": "/region", "in": ["eu"] } }
        }
    ]))
    .await;
    for (index, arguments) in [
        json!({ "region": "us" }),
        json!({ "region": "eu", "pin": PIN_CANARY }),
    ]
    .into_iter()
    .enumerate()
    {
        let request_id = format!("ineligible-{index}");
        assert_eq!(
            call(&lane, &request_id, arguments.clone()).await,
            Outcome::Incomplete,
            "{arguments}"
        );
        let rejected = settled_events(&lane.capture, &request_id)
            .await
            .into_iter()
            .find(|event| event.event_type == audit::event::TOOL_INVOKE_REJECTED)
            .expect("the refusal is audited");
        assert_eq!(rejected.payload["reason"], "policy_evaluation_incomplete");
    }
    assert_eq!(lane.leases.acquired.load(Ordering::SeqCst), 0);

    // A task call brings no arguments, so the rule cannot be decided for it
    // either: it is refused as undetermined, never admitted on a guess.
    let error = lane
        .executor
        .reject_task_tool_call(call_context("task"), TOOL)
        .await
        .expect_err("a task call is refused");
    assert_eq!(
        error,
        ToolRuntimeError::Rejected {
            tool_name: TOOL.to_owned(),
            reason: "policy_evaluation_incomplete".to_owned(),
        }
    );
}

#[tokio::test]
async fn no_argument_value_reaches_audit_or_replay() {
    let lane = lane(argument_rules()).await;
    let calls = [
        (
            "canary-admitted",
            json!({ "region": REGION_CANARY, "pin": PIN_CANARY, "memo": MEMO_CANARY }),
        ),
        (
            "canary-denied",
            json!({ "region": "eu", "pin": PIN_CANARY, "memo": MEMO_CANARY }),
        ),
        (
            "canary-invalid",
            json!({ "region": REGION_CANARY, "pin": 7, "memo": MEMO_CANARY }),
        ),
    ];
    for (request_id, arguments) in &calls {
        let _ = call(&lane, request_id, arguments.clone()).await;
    }
    wait_until(Duration::from_secs(2), || {
        calls.iter().all(|(request_id, _)| {
            events_of(&lane.capture, request_id).iter().any(|event| {
                [
                    audit::event::TOOL_INVOKE_SUCCESS,
                    audit::event::TOOL_INVOKE_FAILURE,
                    audit::event::TOOL_INVOKE_REJECTED,
                ]
                .contains(&event.event_type.as_str())
            })
        })
    })
    .await;
    let events = lane.capture.events();
    let recorded = serde_json::to_string(&events).expect("audit events serialize");
    for canary in [REGION_CANARY, PIN_CANARY, MEMO_CANARY] {
        assert!(!recorded.contains(canary), "audit must omit {canary}");
    }

    // Replay reads only what was recorded, so a rule over an argument is
    // unknown there: never a guessed match, never the live answer restated.
    let mut replayed = 0;
    for event in &events {
        let LegacyRecord::Replayable(context) = adapt_audit_event(event) else {
            continue;
        };
        let ReplayFacts::Tool(facts) = &context.facts else {
            continue;
        };
        let evaluation = evaluate_tool(&lane.compiled, facts).expect("a record evaluates");
        assert_eq!(evaluation.logical(), LogicalDecision::Indeterminate);
        assert_eq!(evaluation.limitation(), Some(ToolLimitation::MatcherFact));
        let trace = evaluation
            .canonical_trace_bytes()
            .expect("the trace encodes");
        let trace = String::from_utf8(trace).expect("the trace is UTF-8");
        for canary in [REGION_CANARY, PIN_CANARY, MEMO_CANARY] {
            assert!(!trace.contains(canary), "replay must omit {canary}");
        }
        replayed += 1;
    }
    assert!(replayed >= 2, "the admitted and denied calls replay");
}

#[tokio::test]
async fn a_call_decided_before_any_argument_rule_never_has_its_arguments_read() {
    // The first rule refuses every export whatever its arguments, so the
    // argument rule after it is never reached and the call's arguments --
    // invalid here -- are neither validated nor read.
    let lane = lane(json!([
        { "id": "exports-closed", "tool_name": TOOL, "action": "deny" },
        {
            "id": "no-eu-exports",
            "tool_name": TOOL,
            "action": "deny",
            "conditions": { "tool_argument": { "pointer": "/region", "in": ["eu"] } }
        }
    ]))
    .await;
    assert_eq!(
        call(&lane, "closed", json!({ "region": 7, "unexpected": true })).await,
        Outcome::Denied
    );
    let events = settled_events(&lane.capture, "closed").await;
    let denied = events
        .iter()
        .find(|event| event.event_type == "authz.denied")
        .expect("the rule's denial is audited");
    assert_eq!(denied.payload["matched_rule_id"], "exports-closed");
    assert!(events
        .iter()
        .all(|event| event.payload["reason"] != "invalid_params"));
    assert_eq!(lane.leases.acquired.load(Ordering::SeqCst), 0);
}
