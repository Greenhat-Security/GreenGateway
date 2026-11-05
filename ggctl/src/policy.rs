//! `ggctl policy lint|test|explain|replay` (issue #243 with #242; ADR-0008
//! command tree, ADR-0004).
//!
//! Every policy command asks the gateway `--server` names and judges
//! nothing itself: `lint` is `POST /policy/validate`, `test` is
//! `POST /policy/tests/runs`, `explain` is `POST /policy/simulations` and
//! `replay` starts, reads or cancels a job under `/policy/replays`. So no
//! answer can disagree with the validator and evaluator the gateway enforces
//! with, and nothing here is a second policy implementation. A document the
//! operator names is sent as its exact bytes, which is what the gateway's
//! exact-source rules for a candidate policy need; `ggctl` only checks that
//! a document it embeds in a request is one JSON value.
//!
//! What a gateway answers is repeated only once it is read as the document
//! version this `ggctl` implements, and only when every string in it is free
//! of control and bidirectional formatting characters, so an answer cannot
//! write to the operator's terminal. A refusal is reported by its status,
//! its stable `reason` and its structured diagnostics; the free-text `error`
//! and `errors` members of a gateway's answer are never repeated, since the
//! policy validator's messages may quote the document.
//!
//! None of these commands stores, publishes or activates a policy. A replay
//! start is the one request that creates anything, a bounded job, and it is
//! never resent: when its answer is lost the job may exist, and the same
//! request under the same `--idempotency-key` is how to find it.

use std::{
    io::{self, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use serde::Serialize;
use serde_json::{json, Map, Value};

use crate::{
    cli::Invocation,
    diagnostic::{Code, Diagnostic, Exit},
    input,
    remote::{self, AdminClient, Exchange, Method, RemoteArguments, Reply, JSON_MEDIA_TYPE},
    report::{self, Format, Io, ReportDiagnostic},
    sarif,
};

const VALIDATE_PATH: &str = "/policy/validate";
const TEST_RUNS_PATH: &str = "/policy/tests/runs";
const SIMULATIONS_PATH: &str = "/policy/simulations";
const REPLAYS_PATH: &str = "/policy/replays";

/// The answer documents these commands read, by exact version.
const TEST_RESULTS_VERSION: &str = "policy-test-results.v1";
const SIMULATION_RESULTS_VERSION: &str = "policy-simulation-results.v1";
const REPLAY_JOB_VERSION: &str = "policy-replay-job.v1";
/// The replay request `ggctl policy replay` writes.
const REPLAY_REQUEST_VERSION: &str = "policy-replay.v1";

/// The JUnit rendering of a test run, and the header naming its status.
const XML_MEDIA_TYPE: &str = "application/xml";
const TESTS_STATUS_HEADER: &str = "x-greengateway-policy-tests-status";
const TEST_STATUSES: &[&str] = &["passed", "failed", "incomplete", "error"];

/// The most bytes of any answer read: a simulation result's own bound.
const MAX_ANSWER_BYTES: usize = 8 * 1024 * 1024;
/// The most diagnostics a refusal's record repeats; the gateway lists 64.
const MAX_REFUSAL_DIAGNOSTICS: usize = 64;

/// The replay job states, and those a job ends in.
const JOB_STATES: &[&str] = &[
    "queued",
    "running",
    "completed",
    "completed_incomplete",
    "failed",
    "cancelled",
    "expired",
];
const FINISHED_STATES: &[&str] = &[
    "completed",
    "completed_incomplete",
    "failed",
    "cancelled",
    "expired",
];
/// How long `--wait` polls, and how often.
const WAIT_LIMIT: Duration = Duration::from_secs(600);
const FIRST_POLL_INTERVAL: Duration = Duration::from_millis(250);
const MAX_POLL_INTERVAL: Duration = Duration::from_secs(5);
/// The replay request bounds `ggctl` checks before anything is sent, as
/// the gateway's parser states them.
const MAX_REPLAY_RECORDS: u32 = 100_000;
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 128;
const MAX_TIMESTAMP_BYTES: usize = 64;
const MAX_DRAFT_ID_BYTES: usize = 64;
const MAX_ETAG_BYTES: usize = 256;

const HINT_RERUN_WITH_KEY: &str = "rerun with the same --idempotency-key: the gateway answers with the job it started, if it started one";
const HINT_GIVE_A_KEY: &str = "a job may be running; give --idempotency-key when starting one, so that a rerun finds it instead of starting another";

// ---------------------------------------------------------------------------
// ggctl policy lint

/// One diagnostic of the gateway's policy validator, as it reported it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PolicyFinding {
    pub(crate) code: String,
    /// `error`, `warning` or `risk`.
    pub(crate) severity: String,
    /// An RFC 6901 JSON Pointer into the document; empty for all of it.
    pub(crate) pointer: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) element_id: Option<String>,
    pub(crate) message: String,
    pub(crate) remediation: String,
    pub(crate) blocks: Blocks,
}

/// Which later uses a finding stands in the way of.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct Blocks {
    pub(crate) simulation: bool,
    pub(crate) tests: bool,
    pub(crate) publication: bool,
    pub(crate) evidence: bool,
}

/// The resources the cross-resource checks read.
#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct SnapshotRecord {
    #[serde(skip_serializing_if = "Option::is_none")]
    digest: Option<String>,
    complete: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    unavailable: Vec<String>,
}

/// What `POST /policy/validate` answered about a document.
#[derive(Debug, Eq, PartialEq)]
struct Inspection {
    valid: bool,
    schema_version: Option<String>,
    source_digest: Option<String>,
    semantic_digest: Option<String>,
    findings: Vec<PolicyFinding>,
    snapshot: Option<SnapshotRecord>,
}

#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct LintResult {
    /// Present once the gateway judged the document.
    #[serde(skip_serializing_if = "Option::is_none")]
    valid: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    schema_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    semantic_digest: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    diagnostics: Vec<PolicyFinding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource_snapshot: Option<SnapshotRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    refusal: Option<Refusal>,
}

/// `ggctl policy lint FILE --server URL`.
pub(crate) fn lint(invocation: &Invocation, io: &mut Io<'_>) -> Exit {
    let remote = match RemoteArguments::required(invocation) {
        Ok(remote) => remote,
        Err(diagnostic) => return report::error(io, diagnostic),
    };
    let Some((position, file)) = invocation.positional(0) else {
        return report::error(io, Diagnostic::new(Code::MissingArgument));
    };
    let mut diagnostics = Vec::new();
    let mut result = LintResult::default();
    let outcome = input::read(
        Path::new(file),
        position,
        input::MAX_DOCUMENT_BYTES,
        Code::InputTooLarge,
    )
    .and_then(|document| {
        let client = connect(remote, io)?;
        let exchange = Exchange {
            method: Method::Post,
            path: VALIDATE_PATH,
            body: Some(document),
            accept: JSON_MEDIA_TYPE,
            headers: &[],
            maximum: MAX_ANSWER_BYTES,
        };
        send(&client, &exchange)
    });
    match outcome {
        Err(diagnostic) => diagnostics.push(diagnostic),
        // The validator answers `400` with the same document for an invalid
        // policy.
        Ok(reply) if matches!(reply.status, 200 | 400) => {
            match reply.body.as_deref().and_then(inspection) {
                Some(inspection) => {
                    if !inspection.valid {
                        diagnostics.push(Diagnostic::new(Code::PolicyInvalid));
                    }
                    if let Some(flag) = invocation.flag("--warnings-as-errors") {
                        if inspection
                            .findings
                            .iter()
                            .any(|finding| finding.severity != "error")
                        {
                            diagnostics.push(Diagnostic::at(Code::WarningsAsErrors, flag));
                        }
                    }
                    result = LintResult {
                        valid: Some(inspection.valid),
                        schema_version: inspection.schema_version,
                        source_digest: inspection.source_digest,
                        semantic_digest: inspection.semantic_digest,
                        diagnostics: inspection.findings,
                        resource_snapshot: inspection.snapshot,
                        refusal: None,
                    };
                }
                None => diagnostics.push(Diagnostic::new(Code::PolicyResponseInvalid)),
            }
        }
        Ok(reply) => {
            let (diagnostic, refusal) = refusal(&reply);
            diagnostics.push(diagnostic);
            result.refusal = Some(refusal);
        }
    }
    let format = Format::of(invocation);
    if format == Format::Sarif {
        let reported: Vec<ReportDiagnostic> = diagnostics.iter().copied().map(Into::into).collect();
        let log = lint_sarif_log(&reported, &result.diagnostics);
        return report::sarif_log(io, &reported, &log);
    }
    report::finish(
        io,
        format,
        invocation.command.name,
        &result,
        &diagnostics,
        write_lint,
    )
}

fn write_lint(result: &LintResult, out: &mut dyn Write) -> io::Result<()> {
    let Some(valid) = result.valid else {
        return writeln!(out, "policy: not judged");
    };
    write!(out, "policy: {}", if valid { "valid" } else { "invalid" })?;
    for severity in ["error", "warning", "risk"] {
        match result
            .diagnostics
            .iter()
            .filter(|finding| finding.severity == severity)
            .count()
        {
            0 => {}
            1 => write!(out, ", 1 {severity}")?,
            count => write!(out, ", {count} {severity}s")?,
        }
    }
    writeln!(out)?;
    if let Some(version) = &result.schema_version {
        writeln!(out, "  schema_version   {version}")?;
    }
    if let Some(digest) = &result.source_digest {
        writeln!(out, "  source digest    {digest}")?;
    }
    if let Some(digest) = &result.semantic_digest {
        writeln!(out, "  semantic digest  {digest}")?;
    }
    if let Some(snapshot) = &result.resource_snapshot {
        let state = if snapshot.complete {
            "complete"
        } else {
            "incomplete"
        };
        match &snapshot.digest {
            Some(digest) => writeln!(out, "  resources        {digest} ({state})")?,
            None => writeln!(out, "  resources        {state}")?,
        }
    }
    for finding in &result.diagnostics {
        let at = if finding.pointer.is_empty() {
            "the document"
        } else {
            finding.pointer.as_str()
        };
        write!(out, "{} {} at {at}", finding.severity, finding.code)?;
        if let Some(id) = &finding.element_id {
            write!(out, " (id {id})")?;
        }
        writeln!(out, ": {}", finding.message)?;
    }
    Ok(())
}

/// The validator's answer, read strictly: any member out of its grammar
/// makes the whole answer unreadable rather than partly repeated.
fn inspection(body: &[u8]) -> Option<Inspection> {
    let answer = safe_json(body)?;
    let answer = answer.as_object()?;
    let valid = answer.get("valid")?.as_bool()?;
    let schema_version = optional_text(answer.get("schema_version"), is_short_text)?;
    let source_digest = optional_text(answer.get("source_digest"), is_digest)?;
    let semantic_digest = optional_text(answer.get("semantic_digest"), is_digest)?;
    let findings = answer
        .get("diagnostics")?
        .as_array()?
        .iter()
        .map(finding)
        .collect::<Option<Vec<_>>>()?;
    let snapshot = match answer.get("resource_snapshot") {
        None | Some(Value::Null) => None,
        Some(snapshot) => Some(snapshot_record(snapshot)?),
    };
    Some(Inspection {
        valid,
        schema_version,
        source_digest,
        semantic_digest,
        findings,
        snapshot,
    })
}

fn finding(value: &Value) -> Option<PolicyFinding> {
    let value = value.as_object()?;
    let text = |name: &str, accept: fn(&str) -> bool| {
        value
            .get(name)
            .and_then(Value::as_str)
            .filter(|text| accept(text))
            .map(str::to_owned)
    };
    let blocks = value.get("blocks")?;
    let flag = |name: &str| blocks.get(name).and_then(Value::as_bool);
    Some(PolicyFinding {
        code: text("code", is_code)?,
        severity: text("severity", |severity| {
            matches!(severity, "error" | "warning" | "risk")
        })?,
        pointer: text("pointer", is_pointer)?,
        element_id: optional_text(value.get("element_id"), is_short_text)?,
        message: text("message", is_message)?,
        remediation: text("remediation", is_message)?,
        blocks: Blocks {
            simulation: flag("simulation")?,
            tests: flag("tests")?,
            publication: flag("publication")?,
            evidence: flag("evidence")?,
        },
    })
}

fn snapshot_record(value: &Value) -> Option<SnapshotRecord> {
    let value = value.as_object()?;
    Some(SnapshotRecord {
        digest: optional_text(value.get("digest"), is_digest)?,
        complete: value.get("complete")?.as_bool()?,
        unavailable: match value.get("unavailable") {
            None => Vec::new(),
            Some(list) => list
                .as_array()?
                .iter()
                .map(|code| {
                    code.as_str()
                        .filter(|code| is_code(code))
                        .map(str::to_owned)
                })
                .collect::<Option<Vec<_>>>()?,
        },
    })
}

/// The SARIF log for `policy lint`: `ggctl`'s own diagnostics, then one rule
/// per validator code, in first-seen order, and one result per finding,
/// located by its JSON Pointer. The document's path is an argument and is
/// never echoed, so a result has no file location.
pub(crate) fn lint_sarif_log(
    diagnostics: &[ReportDiagnostic],
    findings: &[PolicyFinding],
) -> Value {
    let mut log = sarif::log(diagnostics);
    let run = &mut log["runs"][0];
    if let Some(run) = run.as_object_mut() {
        // No result is located in a bundle.
        run.remove("originalUriBaseIds");
    }
    let offset = run["tool"]["driver"]["rules"]
        .as_array()
        .map_or(0, Vec::len);
    let mut codes: Vec<&PolicyFinding> = Vec::new();
    for finding in findings {
        if !codes.iter().any(|seen| seen.code == finding.code) {
            codes.push(finding);
        }
    }
    let rules = codes.iter().map(|rule| {
        json!({
            "id": rule.code,
            "shortDescription": {"text": rule.message},
            "help": {"text": rule.remediation},
            "defaultConfiguration": {"level": finding_level(&rule.severity)},
        })
    });
    let results: Vec<Value> = findings
        .iter()
        .map(|finding| {
            let index = codes
                .iter()
                .position(|rule| rule.code == finding.code)
                .unwrap_or_default();
            let mut result = json!({
                "ruleId": finding.code,
                "ruleIndex": offset + index,
                "level": finding_level(&finding.severity),
                "message": {"text": finding.message},
                "properties": {
                    "severity": finding.severity,
                    "blocks": finding.blocks,
                },
            });
            if !finding.pointer.is_empty() {
                let mut location = json!({
                    "fullyQualifiedName": finding.pointer,
                    "kind": "member",
                });
                if let Some(id) = &finding.element_id {
                    location["name"] = json!(id);
                }
                result["locations"] = json!([{"logicalLocations": [location]}]);
            }
            result
        })
        .collect();
    if let Some(listed) = run["tool"]["driver"]["rules"].as_array_mut() {
        listed.extend(rules);
    }
    if let Some(listed) = run["results"].as_array_mut() {
        listed.extend(results);
    }
    log
}

/// A risk is accepted with an exposure to review: a warning, not a note.
fn finding_level(severity: &str) -> &'static str {
    match severity {
        "error" => "error",
        _ => "warning",
    }
}

// ---------------------------------------------------------------------------
// ggctl policy test

#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct TestResult {
    /// The run's status, once it completed.
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<&'static str>,
    /// The gateway's `policy-test-results.v1` report, as it answered it.
    #[serde(skip_serializing_if = "Option::is_none")]
    results: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    refusal: Option<Refusal>,
}

/// `ggctl policy test SUITE --server URL [--candidate FILE | --draft ID
/// --draft-etag ETAG]`.
pub(crate) fn test(invocation: &Invocation, io: &mut Io<'_>) -> Exit {
    let (remote, candidate) = match RemoteArguments::required(invocation).and_then(|remote| {
        Candidate::from_invocation(invocation).map(|candidate| (remote, candidate))
    }) {
        Ok(parsed) => parsed,
        Err(diagnostic) => return report::error(io, diagnostic),
    };
    let Some((position, suite)) = invocation.positional(0) else {
        return report::error(io, Diagnostic::new(Code::MissingArgument));
    };
    let format = Format::of(invocation);
    let junit = format == Format::Junit;
    let mut diagnostics = Vec::new();
    let mut result = TestResult::default();
    let outcome = input::read_json(Path::new(suite), position).and_then(|suite| {
        let candidate = candidate.read()?;
        let mut body = b"{\"suite\":".to_vec();
        body.extend_from_slice(&suite);
        let format: &[u8] = if junit {
            b",\"format\":\"junit\""
        } else {
            b",\"format\":\"json\""
        };
        body.extend_from_slice(format);
        match &candidate {
            ReadCandidate::Active => {}
            // A run names an inline candidate `policy`, not `candidate`.
            ReadCandidate::Inline(policy) => {
                body.extend_from_slice(b",\"policy\":");
                body.extend_from_slice(policy);
            }
            ReadCandidate::Draft { .. } => {
                body.extend_from_slice(b",\"candidate\":");
                body.extend_from_slice(&candidate.member());
            }
        }
        body.push(b'}');
        let client = connect(remote, io)?;
        let exchange = Exchange {
            method: Method::Post,
            path: TEST_RUNS_PATH,
            body: Some(body),
            accept: if junit {
                XML_MEDIA_TYPE
            } else {
                JSON_MEDIA_TYPE
            },
            headers: &[TESTS_STATUS_HEADER],
            maximum: MAX_ANSWER_BYTES,
        };
        send(&client, &exchange)
    });
    let mut served = None;
    match outcome {
        Err(diagnostic) => diagnostics.push(diagnostic),
        Ok(reply) if reply.status == 200 => {
            let header = reply.header(TESTS_STATUS_HEADER).and_then(test_status);
            let read = if junit {
                reply
                    .body
                    .as_deref()
                    .filter(|xml| is_served_text(xml))
                    .zip(header)
                    .map(|(xml, status)| {
                        served = Some(xml.to_vec());
                        (status, None)
                    })
            } else {
                reply
                    .body
                    .as_deref()
                    .and_then(|body| versioned(body, TEST_RESULTS_VERSION))
                    .and_then(|results| {
                        let status = results.get("status").and_then(Value::as_str)?;
                        let status = test_status(status)?;
                        // The header repeats the status; a disagreement is
                        // not an answer to trust either way.
                        if header.is_some_and(|header| header != status) {
                            return None;
                        }
                        Some((status, Some(results)))
                    })
            };
            match read {
                Some((status, results)) => {
                    if status != "passed" {
                        diagnostics.push(Diagnostic::new(Code::PolicyTestsNotPassed));
                    }
                    result.status = Some(status);
                    result.results = results;
                }
                None => {
                    served = None;
                    diagnostics.push(Diagnostic::new(Code::PolicyResponseInvalid));
                }
            }
        }
        Ok(reply) => {
            let (diagnostic, refusal) = refusal(&reply);
            diagnostics.push(diagnostic);
            result.refusal = Some(refusal);
        }
    }
    match served {
        Some(xml) => report::served_artifact(io, &xml, &diagnostics),
        None => report::finish(
            io,
            format,
            invocation.command.name,
            &result,
            &diagnostics,
            write_test,
        ),
    }
}

fn test_status(text: &str) -> Option<&'static str> {
    TEST_STATUSES.iter().copied().find(|status| *status == text)
}

fn write_test(result: &TestResult, out: &mut dyn Write) -> io::Result<()> {
    let (Some(status), Some(results)) = (result.status, &result.results) else {
        return writeln!(out, "policy tests: not run");
    };
    write!(out, "policy tests: {status}")?;
    let summary = &results["summary"];
    if let Some(total) = summary["total"].as_u64() {
        write!(out, " ({total} cases")?;
        for (member, noun) in [
            ("passed", "passed"),
            ("failed", "failed"),
            ("incomplete", "incomplete"),
            ("errors", "errors"),
        ] {
            if let Some(count) = summary[member].as_u64() {
                write!(out, ", {count} {noun}")?;
            }
        }
        write!(out, ")")?;
    }
    writeln!(out)?;
    if let (Some(version), Some(digest)) = (
        results["suite"]["schema_version"].as_str(),
        results["suite"]["digest"].as_str(),
    ) {
        writeln!(out, "  suite   {version} {digest}")?;
    }
    if let Some(source) = results["policy"]["source"].as_str() {
        match results["policy"]["etag"].as_str() {
            Some(etag) => writeln!(out, "  policy  {source} {etag}")?,
            None => writeln!(out, "  policy  {source}")?,
        }
    }
    for case in results["cases"].as_array().into_iter().flatten() {
        let (Some(status), Some(id)) = (case["status"].as_str(), case["id"].as_str()) else {
            continue;
        };
        if status == "passed" {
            continue;
        }
        write!(out, "  {status:<10}  {id}")?;
        if let Some(kind) = case["kind"].as_str() {
            write!(out, " ({kind})")?;
        }
        let mismatches: Vec<&str> = case["mismatches"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        if !mismatches.is_empty() {
            write!(out, ": {}", mismatches.join(", "))?;
        } else if let Some(code) = case["error"].as_str() {
            write!(out, ": {code}")?;
        } else if let Some(limitation) = case["actual"]["limitation"].as_str() {
            write!(out, ": {limitation}")?;
        }
        writeln!(out)?;
    }
    write_not_evaluated(results, out)
}

fn write_not_evaluated(results: &Value, out: &mut dyn Write) -> io::Result<()> {
    let stages: Vec<&str> = results["not_evaluated"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    if stages.is_empty() {
        return Ok(());
    }
    writeln!(out, "not evaluated: {}", stages.join(", "))
}

// ---------------------------------------------------------------------------
// ggctl policy explain

#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct ExplainResult {
    /// The gateway's `policy-simulation-results.v1` document, as it
    /// answered it.
    #[serde(skip_serializing_if = "Option::is_none")]
    results: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    refusal: Option<Refusal>,
}

/// `ggctl policy explain CASES --server URL`.
pub(crate) fn explain(invocation: &Invocation, io: &mut Io<'_>) -> Exit {
    let remote = match RemoteArguments::required(invocation) {
        Ok(remote) => remote,
        Err(diagnostic) => return report::error(io, diagnostic),
    };
    let Some((position, cases)) = invocation.positional(0) else {
        return report::error(io, Diagnostic::new(Code::MissingArgument));
    };
    let mut diagnostics = Vec::new();
    let mut result = ExplainResult::default();
    // The request is sent as it was written: its inline candidate, if any,
    // is judged from its exact bytes.
    let outcome = input::read_json(Path::new(cases), position).and_then(|request| {
        let client = connect(remote, io)?;
        let exchange = Exchange {
            method: Method::Post,
            path: SIMULATIONS_PATH,
            body: Some(request),
            accept: JSON_MEDIA_TYPE,
            headers: &[],
            maximum: MAX_ANSWER_BYTES,
        };
        send(&client, &exchange)
    });
    match outcome {
        Err(diagnostic) => diagnostics.push(diagnostic),
        Ok(reply) if reply.status == 200 => {
            match reply
                .body
                .as_deref()
                .and_then(|body| versioned(body, SIMULATION_RESULTS_VERSION))
            {
                Some(results) => result.results = Some(results),
                None => diagnostics.push(Diagnostic::new(Code::PolicyResponseInvalid)),
            }
        }
        Ok(reply) => {
            let (diagnostic, refusal) = refusal(&reply);
            diagnostics.push(diagnostic);
            result.refusal = Some(refusal);
        }
    }
    report::finish(
        io,
        Format::of(invocation),
        invocation.command.name,
        &result,
        &diagnostics,
        write_explain,
    )
}

/// The decision members a result line shows, in this order, when present.
const DECISION_MEMBERS: &[&str] = &[
    "lane",
    "operation",
    "logical",
    "enforcement",
    "effective_action",
    "reason",
    "selected",
    "verdict",
    "limitation",
];

fn write_explain(result: &ExplainResult, out: &mut dyn Write) -> io::Result<()> {
    let Some(results) = &result.results else {
        return writeln!(out, "simulation: not run");
    };
    let cases = results["cases"].as_array().map_or(0, Vec::len);
    write!(out, "simulation: {cases} case{}", plural(cases))?;
    if let Some(level) = results["trace"]["level"].as_str() {
        write!(out, ", trace {level}")?;
    }
    writeln!(out)?;
    for (label, member) in [("base", "base"), ("candidate", "candidate")] {
        if let Some(source) = results[member]["source"].as_str() {
            match results[member]["etag"].as_str() {
                Some(etag) => writeln!(out, "  {label:<9}  {source} {etag}")?,
                None => writeln!(out, "  {label:<9}  {source}")?,
            }
        }
    }
    for case in results["cases"].as_array().into_iter().flatten() {
        let Some(id) = case["id"].as_str() else {
            continue;
        };
        match case["kind"].as_str() {
            Some(kind) => writeln!(out, "case {id} ({kind})")?,
            None => writeln!(out, "case {id}")?,
        }
        for entry in case["results"].as_array().into_iter().flatten() {
            let projection = entry["projection"].as_str().unwrap_or("as_authored");
            write!(out, "  {projection}: {}", decision(&entry["candidate"]))?;
            if entry["changed"].as_bool() == Some(true) {
                write!(out, " (base: {})", decision(&entry["base"]))?;
            }
            writeln!(out)?;
        }
    }
    write_not_evaluated(results, out)
}

/// A decision's stable codes, space-separated.
fn decision(view: &Value) -> String {
    let codes: Vec<&str> = DECISION_MEMBERS
        .iter()
        .filter_map(|member| view[*member].as_str())
        .collect();
    if codes.is_empty() {
        "undecided".to_owned()
    } else {
        codes.join(" ")
    }
}

fn plural(count: usize) -> &'static str {
    if count == 1 {
        ""
    } else {
        "s"
    }
}

// ---------------------------------------------------------------------------
// ggctl policy replay

/// What `policy replay` was asked to do.
#[derive(Debug)]
enum ReplayAction {
    Start(ReplayStart),
    Read { job: String },
    Cancel { job: String },
}

#[derive(Debug)]
struct ReplayStart {
    base_etag: String,
    from: String,
    to: Option<String>,
    candidate: Candidate,
    enforce_all_shadow: bool,
    max_records: Option<u32>,
    idempotency_key: Option<String>,
}

#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReplayResult {
    /// `start`, `read` or `cancel`.
    action: &'static str,
    /// The `policy-replay-job.v1` job, as the gateway last answered it.
    #[serde(skip_serializing_if = "Option::is_none")]
    job: Option<Value>,
    /// For `--cancel`: `true` when the job had finished and was discarded.
    #[serde(skip_serializing_if = "Option::is_none")]
    discarded: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    refusal: Option<Refusal>,
}

/// `ggctl policy replay --server URL (--base-etag ETAG --window FROM[/TO]
/// ... | --job ID | --cancel ID) [--wait]`.
pub(crate) fn replay(invocation: &Invocation, io: &mut Io<'_>) -> Exit {
    let (remote, action) = match RemoteArguments::required(invocation)
        .and_then(|remote| replay_action(invocation).map(|action| (remote, action)))
    {
        Ok(parsed) => parsed,
        Err(diagnostic) => return report::error(io, diagnostic),
    };
    let wait = invocation.flag("--wait").is_some();
    let mut diagnostics = Vec::new();
    let mut result = ReplayResult {
        action: match action {
            ReplayAction::Start(_) => "start",
            ReplayAction::Read { .. } => "read",
            ReplayAction::Cancel { .. } => "cancel",
        },
        ..ReplayResult::default()
    };
    let client = match &action {
        ReplayAction::Start(start) => start.candidate.read().and_then(|candidate| {
            let body = start_body(start, &candidate);
            connect(remote, io).map(|client| (client, Some(body)))
        }),
        ReplayAction::Read { .. } | ReplayAction::Cancel { .. } => {
            connect(remote, io).map(|client| (client, None))
        }
    };
    match client {
        Err(diagnostic) => diagnostics.push(diagnostic),
        Ok((client, body)) => {
            let outcome = remote::block_on(run_replay(&client, &action, body, wait));
            match outcome {
                Ok(outcome) => {
                    result.job = outcome.job;
                    result.discarded = outcome.discarded;
                    result.refusal = outcome.refusal;
                    diagnostics.extend(outcome.diagnostics);
                }
                Err(code) => diagnostics.push(Diagnostic::new(code)),
            }
        }
    }
    report::finish(
        io,
        Format::of(invocation),
        invocation.command.name,
        &result,
        &diagnostics,
        write_replay,
    )
}

/// The options of `policy replay`, checked before anything is read or sent.
fn replay_action(invocation: &Invocation) -> Result<ReplayAction, Diagnostic> {
    const START_OPTIONS: &[&str] = &[
        "--base-etag",
        "--window",
        "--candidate",
        "--draft",
        "--draft-etag",
        "--enforce-all-shadow",
        "--max-records",
        "--idempotency-key",
    ];
    let job = invocation.text("--job");
    let cancel = invocation.text("--cancel");
    let start = START_OPTIONS
        .iter()
        .filter_map(|name| invocation.flag(name))
        .max();
    let conflict =
        |first: usize, second: usize| Diagnostic::at(Code::ConflictingOptions, first.max(second));
    let target = |position: usize, id: &str| {
        if is_job_id(id) {
            Ok(id.to_owned())
        } else {
            Err(Diagnostic::at(Code::InvalidValue, position))
        }
    };
    if let (Some((first, _)), Some((second, _))) = (job, cancel) {
        return Err(conflict(first, second));
    }
    if let (Some((first, _)), Some(second)) = (job.or(cancel), start) {
        return Err(conflict(first, second));
    }
    if let Some((position, id)) = cancel {
        // A cancellation is answered at once; there is nothing to wait for.
        if let Some(wait) = invocation.flag("--wait") {
            return Err(conflict(position, wait));
        }
        return Ok(ReplayAction::Cancel {
            job: target(position, id)?,
        });
    }
    if let Some((position, id)) = job {
        return Ok(ReplayAction::Read {
            job: target(position, id)?,
        });
    }
    Ok(ReplayAction::Start(replay_start(invocation)?))
}

fn replay_start(invocation: &Invocation) -> Result<ReplayStart, Diagnostic> {
    let candidate = Candidate::from_invocation(invocation)?;
    let base_etag = match invocation.text("--base-etag") {
        Some((_, etag)) if is_entity_tag(etag) => etag.to_owned(),
        Some((position, _)) => return Err(Diagnostic::at(Code::InvalidValue, position)),
        None => return Err(Diagnostic::new(Code::MissingOption).with_hint(HINT_START)),
    };
    let (from, to) = match invocation.text("--window") {
        Some((position, window)) => {
            parse_window(window).ok_or(Diagnostic::at(Code::InvalidValue, position))?
        }
        None => return Err(Diagnostic::new(Code::MissingOption).with_hint(HINT_START)),
    };
    let max_records = match invocation.text("--max-records") {
        None => None,
        Some((position, text)) => match text.parse::<u32>() {
            Ok(count) if (1..=MAX_REPLAY_RECORDS).contains(&count) => Some(count),
            _ => return Err(Diagnostic::at(Code::InvalidValue, position)),
        },
    };
    let idempotency_key = match invocation.text("--idempotency-key") {
        None => None,
        Some((_, key)) if is_idempotency_key(key) => Some(key.to_owned()),
        Some((position, _)) => return Err(Diagnostic::at(Code::InvalidValue, position)),
    };
    Ok(ReplayStart {
        base_etag,
        from,
        to,
        candidate,
        enforce_all_shadow: invocation.flag("--enforce-all-shadow").is_some(),
        max_records,
        idempotency_key,
    })
}

const HINT_START: &str =
    "starting a replay needs --base-etag and --window; read a job with --job or cancel one with --cancel";

/// `FROM` or `FROM/TO`: each an RFC 3339 date-time with an offset, which
/// the gateway's parser checks; here each is only bounded and visible ASCII.
fn parse_window(window: &str) -> Option<(String, Option<String>)> {
    let bound = |text: &str| {
        (!text.is_empty()
            && text.len() <= MAX_TIMESTAMP_BYTES
            && text
                .bytes()
                .all(|byte| byte.is_ascii_graphic() && byte != b'/'))
        .then(|| text.to_owned())
    };
    match window.split_once('/') {
        None => Some((bound(window)?, None)),
        Some((from, to)) => Some((bound(from)?, Some(bound(to)?))),
    }
}

/// The `policy-replay.v1` request for `start`, with an inline candidate's
/// exact bytes.
fn start_body(start: &ReplayStart, candidate: &ReadCandidate) -> Vec<u8> {
    let mut window = Map::new();
    window.insert("from".to_owned(), json!(start.from));
    if let Some(to) = &start.to {
        window.insert("to".to_owned(), json!(to));
    }
    let projections: &[&str] = if start.enforce_all_shadow {
        &["as_authored", "enforce_all_shadow"]
    } else {
        &["as_authored"]
    };
    let mut rest = Map::new();
    rest.insert("window".to_owned(), Value::Object(window));
    rest.insert("projections".to_owned(), json!(projections));
    if let Some(count) = start.max_records {
        rest.insert("max_records".to_owned(), json!(count));
    }
    if let Some(key) = &start.idempotency_key {
        rest.insert("idempotency_key".to_owned(), json!(key));
    }
    let mut body = format!(
        "{{\"schema_version\":{},\"base_etag\":{},\"candidate\":",
        json!(REPLAY_REQUEST_VERSION),
        json!(start.base_etag)
    )
    .into_bytes();
    body.extend_from_slice(&candidate.member());
    for (name, value) in rest {
        body.push(b',');
        body.extend_from_slice(json!(name).to_string().as_bytes());
        body.push(b':');
        body.extend_from_slice(value.to_string().as_bytes());
    }
    body.push(b'}');
    body
}

/// What a replay request established.
#[derive(Debug, Default)]
struct ReplayOutcome {
    job: Option<Value>,
    discarded: Option<bool>,
    refusal: Option<Refusal>,
    diagnostics: Vec<Diagnostic>,
}

async fn run_replay(
    client: &AdminClient,
    action: &ReplayAction,
    body: Option<Vec<u8>>,
    wait: bool,
) -> ReplayOutcome {
    let mut outcome = ReplayOutcome::default();
    let (method, path, keyed) = match action {
        ReplayAction::Start(start) => (
            Method::Post,
            REPLAYS_PATH.to_owned(),
            Some(start.idempotency_key.is_some()),
        ),
        ReplayAction::Read { job } => (Method::Get, format!("{REPLAYS_PATH}/{job}"), None),
        ReplayAction::Cancel { job } => (Method::Delete, format!("{REPLAYS_PATH}/{job}"), None),
    };
    let exchange = Exchange {
        method,
        path: &path,
        body,
        accept: JSON_MEDIA_TYPE,
        headers: &[],
        maximum: MAX_ANSWER_BYTES,
    };
    let reply = match client.exchange(&exchange).await {
        Ok(reply) => reply,
        Err(code) => {
            outcome.diagnostics.push(Diagnostic::new(code));
            // A start that reached the gateway may have created its job.
            if let Some(keyed) = keyed {
                if !matches!(
                    code,
                    Code::ConnectFailed | Code::Unauthenticated | Code::Forbidden
                ) {
                    outcome.diagnostics.push(outcome_unknown(keyed));
                }
            }
            return outcome;
        }
    };
    match (action, reply.status) {
        (ReplayAction::Cancel { .. }, 204) => {
            outcome.discarded = Some(true);
            return outcome;
        }
        (ReplayAction::Start(_), 200 | 202)
        | (ReplayAction::Read { .. }, 200)
        | (ReplayAction::Cancel { .. }, 202) => {}
        _ => {
            let (diagnostic, refusal) = refusal(&reply);
            outcome.diagnostics.push(diagnostic);
            outcome.refusal = Some(refusal);
            return outcome;
        }
    }
    let Some((job_id, job)) = reply.body.as_deref().and_then(replay_job) else {
        outcome.diagnostics.push(match keyed {
            Some(keyed) => outcome_unknown(keyed),
            None => Diagnostic::new(Code::PolicyResponseInvalid),
        });
        return outcome;
    };
    if matches!(action, ReplayAction::Cancel { .. }) {
        outcome.discarded = Some(false);
        outcome.job = Some(job);
        return outcome;
    }
    let mut job = job;
    if wait {
        let path = format!("{REPLAYS_PATH}/{job_id}");
        let deadline = Instant::now() + WAIT_LIMIT;
        let mut interval = FIRST_POLL_INTERVAL;
        while !is_finished(&job) {
            if Instant::now() + interval > deadline {
                outcome
                    .diagnostics
                    .push(Diagnostic::new(Code::PolicyWaitTimedOut));
                break;
            }
            tokio::time::sleep(interval).await;
            interval = (interval * 2).min(MAX_POLL_INTERVAL);
            let reply = match client
                .exchange(&Exchange::get(&path, MAX_ANSWER_BYTES))
                .await
            {
                Ok(reply) => reply,
                Err(code) => {
                    outcome.diagnostics.push(Diagnostic::new(code));
                    break;
                }
            };
            if reply.status != 200 {
                let (diagnostic, refusal) = refusal(&reply);
                outcome.diagnostics.push(diagnostic);
                outcome.refusal = Some(refusal);
                break;
            }
            match reply.body.as_deref().and_then(replay_job) {
                Some((id, read)) if id == job_id => job = read,
                _ => {
                    outcome
                        .diagnostics
                        .push(Diagnostic::new(Code::PolicyResponseInvalid));
                    break;
                }
            }
        }
    }
    outcome.diagnostics.extend(job_verdict(&job));
    outcome.job = Some(job);
    outcome
}

fn outcome_unknown(keyed: bool) -> Diagnostic {
    Diagnostic::new(Code::PolicyOutcomeUnknown).with_hint(if keyed {
        HINT_RERUN_WITH_KEY
    } else {
        HINT_GIVE_A_KEY
    })
}

/// A `policy-replay-job.v1` answer and its job id.
fn replay_job(body: &[u8]) -> Option<(String, Value)> {
    let job = versioned(body, REPLAY_JOB_VERSION)?;
    let id = job.get("job_id")?.as_str().filter(|id| is_job_id(id))?;
    let state = job.get("state")?.as_str()?;
    if !JOB_STATES.contains(&state) {
        return None;
    }
    Some((id.to_owned(), job))
}

fn is_finished(job: &Value) -> bool {
    job["state"]
        .as_str()
        .is_some_and(|state| FINISHED_STATES.contains(&state))
}

/// What a finished job says to a pipeline: nothing until it has finished,
/// then that an incomplete or missing result satisfies no gate and that a
/// result about a policy no longer active is not evidence about it.
fn job_verdict(job: &Value) -> Vec<Diagnostic> {
    let mut verdict = Vec::new();
    match job["state"].as_str() {
        Some("completed") => {}
        Some("completed_incomplete") => verdict.push(Diagnostic::new(Code::PolicyReplayIncomplete)),
        Some("failed" | "cancelled" | "expired") => {
            verdict.push(Diagnostic::new(Code::PolicyReplayFailed));
        }
        _ => return verdict,
    }
    if job["freshness"]["state"].as_str() == Some("stale") {
        verdict.push(Diagnostic::new(Code::PolicyReplayStale));
    }
    verdict
}

fn write_replay(result: &ReplayResult, out: &mut dyn Write) -> io::Result<()> {
    if result.discarded == Some(true) {
        return writeln!(out, "replay job discarded");
    }
    let Some(job) = &result.job else {
        return writeln!(out, "replay: no job");
    };
    let id = job["job_id"].as_str().unwrap_or("?");
    let state = job["state"].as_str().unwrap_or("?");
    write!(out, "replay job {id}: {state}")?;
    if job["cancel_requested"].as_bool() == Some(true) && !is_finished(job) {
        write!(out, " (cancellation requested)")?;
    }
    writeln!(out)?;
    if let Some(etag) = job["base"]["etag"].as_str() {
        match job["freshness"]["state"].as_str() {
            Some(freshness) => writeln!(out, "  base         {etag} ({freshness})")?,
            None => writeln!(out, "  base         {etag}")?,
        }
    }
    if let Some(source) = job["candidate"]["source"].as_str() {
        match job["candidate"]["etag"].as_str() {
            Some(etag) => writeln!(out, "  candidate    {source} {etag}")?,
            None => writeln!(out, "  candidate    {source}")?,
        }
    }
    if let Some(from) = job["window"]["from"].as_str() {
        let to = job["window"]["to"].as_str().unwrap_or("now");
        writeln!(out, "  window       {from} to {to}")?;
    }
    if let (Some(high_water), Some(selected)) = (
        job["cutoff"]["high_water"].as_u64(),
        job["cutoff"]["selected_records"].as_u64(),
    ) {
        writeln!(
            out,
            "  cutoff       high water {high_water}, {selected} records selected"
        )?;
    }
    if let Some(reason) = job["failure"]["reason"].as_str() {
        writeln!(out, "  failure      {reason}")?;
    }
    let result = &job["result"];
    if let Some(records) = result["records"].as_object() {
        let counts: Vec<String> = ["selected", "scanned", "replayable"]
            .iter()
            .filter_map(|member| {
                records
                    .get(*member)
                    .and_then(Value::as_u64)
                    .map(|count| format!("{count} {member}"))
            })
            .collect();
        writeln!(out, "  records      {}", counts.join(", "))?;
    }
    if let Some(complete) = result["complete"].as_bool() {
        let state = if complete { "complete" } else { "incomplete" };
        match job["result_digest"].as_str() {
            Some(digest) => writeln!(out, "  result       {state}, digest {digest}")?,
            None => writeln!(out, "  result       {state}")?,
        }
        let limitations: Vec<&str> = result["limitations"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        if !limitations.is_empty() {
            writeln!(out, "  limitations  {}", limitations.join(", "))?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Candidates, connections and refusals, shared by the commands above.

/// What `policy test` or `policy replay` judges.
#[derive(Debug)]
enum Candidate {
    /// The active policy.
    Active,
    /// A complete document, by the argument naming it.
    Inline {
        path: PathBuf,
        argument: usize,
    },
    Draft {
        id: String,
        etag: String,
    },
}

/// A candidate, read.
#[derive(Debug)]
enum ReadCandidate {
    Active,
    Inline(Vec<u8>),
    Draft { id: String, etag: String },
}

impl Candidate {
    fn from_invocation(invocation: &Invocation) -> Result<Self, Diagnostic> {
        let inline = invocation.value("--candidate");
        let draft = invocation.text("--draft");
        let draft_etag = invocation.text("--draft-etag");
        match (inline, draft, draft_etag) {
            (None, None, None) => Ok(Self::Active),
            (Some((position, path)), None, None) => Ok(Self::Inline {
                path: PathBuf::from(path),
                argument: position,
            }),
            (Some((first, _)), Some((second, _)), _)
            | (Some((first, _)), None, Some((second, _))) => {
                Err(Diagnostic::at(Code::ConflictingOptions, first.max(second)))
            }
            (None, Some((position, id)), Some((etag_position, etag))) => {
                if !is_draft_id(id) {
                    return Err(Diagnostic::at(Code::InvalidValue, position));
                }
                if !is_entity_tag(etag) {
                    return Err(Diagnostic::at(Code::InvalidValue, etag_position));
                }
                Ok(Self::Draft {
                    id: id.to_owned(),
                    etag: etag.to_owned(),
                })
            }
            (None, Some((position, _)), None) | (None, None, Some((position, _))) => {
                Err(Diagnostic::at(Code::MissingOption, position)
                    .with_hint("--draft and --draft-etag are given together"))
            }
        }
    }

    fn read(&self) -> Result<ReadCandidate, Diagnostic> {
        Ok(match self {
            Self::Active => ReadCandidate::Active,
            Self::Inline { path, argument } => {
                ReadCandidate::Inline(input::read_json(path, *argument)?)
            }
            Self::Draft { id, etag } => ReadCandidate::Draft {
                id: id.clone(),
                etag: etag.clone(),
            },
        })
    }
}

impl ReadCandidate {
    /// The request's `candidate` member: an inline document is spliced in
    /// as its exact bytes.
    fn member(&self) -> Vec<u8> {
        match self {
            Self::Active => json!({ "source": "active" }).to_string().into_bytes(),
            Self::Inline(policy) => {
                let mut member = b"{\"source\":\"inline\",\"policy\":".to_vec();
                member.extend_from_slice(policy);
                member.push(b'}');
                member
            }
            Self::Draft { id, etag } => {
                json!({ "source": "draft", "draft_id": id, "draft_etag": etag })
                    .to_string()
                    .into_bytes()
            }
        }
    }
}

/// Reads the credential and trust anchors and builds the client: every
/// problem here is found before any request is sent.
fn connect(remote: RemoteArguments, io: &mut Io<'_>) -> Result<AdminClient, Diagnostic> {
    remote
        .load(io.stdin_is_terminal, io.stdin)
        .and_then(AdminClient::new)
        .map_err(Diagnostic::new)
}

/// Sends one request on its own runtime.
fn send(client: &AdminClient, exchange: &Exchange<'_>) -> Result<Reply, Diagnostic> {
    remote::block_on(client.exchange(exchange))
        .and_then(|reply| reply)
        .map_err(Diagnostic::new)
}

/// A refused request, as far as its answer is safe to repeat: the status,
/// the stable `reason` and the structured request diagnostics, never the
/// free-text `error` or `errors`.
#[derive(Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Refusal {
    pub(crate) status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) reason: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) diagnostics: Vec<RequestDiagnostic>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub(crate) diagnostics_truncated: bool,
}

/// One structured diagnostic of a refused request: a stable code, the JSON
/// Pointer into the request and the gateway's fixed message.
#[derive(Debug, Eq, PartialEq, Serialize)]
pub(crate) struct RequestDiagnostic {
    pub(crate) code: String,
    pub(crate) pointer: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) message: Option<String>,
}

/// The diagnostic and record of an answer that is not the command's result.
pub(crate) fn refusal(reply: &Reply) -> (Diagnostic, Refusal) {
    let code = match reply.status {
        400 | 422 => Code::PolicyRequestRefused,
        404 => Code::PolicyNotFound,
        408 | 429 => Code::PolicyBusy,
        409 | 410 | 412 | 428 => Code::PolicyPreconditionFailed,
        413 => Code::PolicyRequestTooLarge,
        503 => Code::ServerUnavailable,
        _ => Code::UnexpectedStatus,
    };
    let mut refusal = Refusal {
        status: reply.status,
        ..Refusal::default()
    };
    // Each member read is held to its own grammar, so a hostile member
    // elsewhere in the answer costs only itself.
    let answer: Option<Value> = reply
        .body
        .as_deref()
        .and_then(|body| serde_json::from_slice(body).ok());
    if let Some(answer) = answer.as_ref().and_then(Value::as_object) {
        refusal.reason = answer
            .get("reason")
            .and_then(Value::as_str)
            .filter(|reason| is_code(reason))
            .map(str::to_owned);
        let listed = answer
            .get("diagnostics")
            .and_then(Value::as_array)
            .map_or(&[][..], Vec::as_slice);
        refusal.diagnostics = listed
            .iter()
            .filter_map(request_diagnostic)
            .take(MAX_REFUSAL_DIAGNOSTICS)
            .collect();
        refusal.diagnostics_truncated = answer
            .get("diagnostics_truncated")
            .and_then(Value::as_bool)
            .unwrap_or(false)
            || refusal.diagnostics.len() < listed.len();
    }
    (Diagnostic::new(code), refusal)
}

fn request_diagnostic(value: &Value) -> Option<RequestDiagnostic> {
    let value = value.as_object()?;
    Some(RequestDiagnostic {
        code: value
            .get("code")?
            .as_str()
            .filter(|code| is_code(code))?
            .to_owned(),
        pointer: value
            .get("pointer")?
            .as_str()
            .filter(|pointer| is_pointer(pointer))?
            .to_owned(),
        message: optional_text(value.get("message"), is_message)?,
    })
}

// ---------------------------------------------------------------------------
// Reading answers.

/// An answer that is a JSON document whose every string is safe to show.
fn safe_json(body: &[u8]) -> Option<Value> {
    let value: Value = serde_json::from_slice(body).ok()?;
    is_safe_value(&value).then_some(value)
}

/// A safe answer that is an object of exactly `version`.
fn versioned(body: &[u8], version: &str) -> Option<Value> {
    safe_json(body)
        .filter(|value| value.get("schema_version").and_then(Value::as_str) == Some(version))
}

/// Whether every string in `value`, member names included, is free of the
/// characters that could act on a terminal.
pub(crate) fn is_safe_value(value: &Value) -> bool {
    match value {
        Value::String(text) => is_safe_text(text),
        Value::Array(items) => items.iter().all(is_safe_value),
        Value::Object(members) => members
            .iter()
            .all(|(name, member)| is_safe_text(name) && is_safe_value(member)),
        Value::Null | Value::Bool(_) | Value::Number(_) => true,
    }
}

/// No control character (C0, DEL or C1) and no bidirectional formatting
/// character, which could reorder what a terminal shows.
pub(crate) fn is_safe_text(text: &str) -> bool {
    !text.chars().any(|character| {
        character.is_control()
            || matches!(
                character,
                '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
            )
    })
}

/// A served text artifact (the JUnit report): UTF-8 whose only control
/// characters are tabs and line breaks, and whose text is otherwise safe.
fn is_served_text(bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes).is_ok_and(|text| text.split(['\t', '\n', '\r']).all(is_safe_text))
}

/// `None` when present but not accepted; `Some(None)` when absent or null.
fn optional_text(value: Option<&Value>, accept: fn(&str) -> bool) -> Option<Option<String>> {
    match value {
        None | Some(Value::Null) => Some(None),
        Some(Value::String(text)) if accept(text) => Some(Some(text.clone())),
        Some(_) => None,
    }
}

/// A stable code: lowercase snake segments, as every gateway code is.
pub(crate) fn is_code(text: &str) -> bool {
    (1..=64).contains(&text.len())
        && text
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
        && text
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

/// An RFC 6901 JSON Pointer of bounded length.
pub(crate) fn is_pointer(text: &str) -> bool {
    text.len() <= 1024
        && (text.is_empty() || text.starts_with('/'))
        && is_safe_text(text)
        && text
            .split('~')
            .skip(1)
            .all(|rest| rest.starts_with(['0', '1']))
}

/// A short safe string: a version or an element id.
fn is_short_text(text: &str) -> bool {
    !text.is_empty() && text.len() <= 256 && is_safe_text(text)
}

/// A gateway's fixed message or remediation text.
fn is_message(text: &str) -> bool {
    !text.is_empty() && text.len() <= 1024 && is_safe_text(text)
}

/// `sha256:` and 64 lowercase hexadecimal digits.
pub(crate) fn is_digest(text: &str) -> bool {
    text.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

/// An RFC 9110 entity tag, weak or strong, quotes included. ETags are opaque
/// and sent byte for byte; this only keeps one from carrying anything else.
pub(crate) fn is_entity_tag(text: &str) -> bool {
    text.len() <= MAX_ETAG_BYTES
        && text
            .strip_prefix("W/")
            .unwrap_or(text)
            .strip_prefix('"')
            .and_then(|rest| rest.strip_suffix('"'))
            .is_some_and(|opaque| {
                opaque
                    .bytes()
                    .all(|byte| byte == 0x21 || (0x23..=0x7e).contains(&byte))
            })
}

/// A server-side draft id, as the drafts API returns one.
fn is_draft_id(text: &str) -> bool {
    (1..=MAX_DRAFT_ID_BYTES).contains(&text.len())
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

/// A replay job id: `rpl_` and 32 lowercase hexadecimal digits. It becomes
/// a path segment, so nothing else is accepted.
pub(crate) fn is_job_id(text: &str) -> bool {
    text.strip_prefix("rpl_").is_some_and(|hex| {
        hex.len() == 32
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

/// A replay idempotency key, in the gateway's grammar.
fn is_idempotency_key(text: &str) -> bool {
    (1..=MAX_IDEMPOTENCY_KEY_BYTES).contains(&text.len())
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

#[cfg(test)]
mod tests;
