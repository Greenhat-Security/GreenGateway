use std::ffi::OsString;

use serde_json::json;

use super::*;
use crate::cli::{parse, Parsed};

fn invocation(words: &[&str]) -> Invocation {
    let arguments: Vec<OsString> = words.iter().map(OsString::from).collect();
    match parse(&arguments) {
        Ok(Parsed::Run(invocation)) => invocation,
        other => panic!("{words:?} should run, got {other:?}"),
    }
}

fn reply(status: u16, body: Value) -> Reply {
    Reply {
        status,
        headers: Vec::new(),
        body: Some(body.to_string().into_bytes()),
    }
}

const SERVER: &str = "http://127.0.0.1:1/v1/admin";
const ETAG: &str = "\"sha256:0123456789abcdef\"";
const JOB: &str = "rpl_0123456789abcdef0123456789abcdef";

fn finding_value() -> Value {
    json!({
        "code": "element_id_duplicate",
        "severity": "error",
        "pointer": "/rules/1/id",
        "element_id": "orders-read",
        "message": "element ids must be unique",
        "remediation": "give each element its own id",
        "blocks": {"simulation": true, "tests": true, "publication": true, "evidence": true}
    })
}

#[test]
fn an_inspection_is_read_strictly_and_never_partly() {
    let digest = format!("sha256:{}", "a".repeat(64));
    let answer = json!({
        "valid": false,
        "errors": ["rule 'secret-canary' is a duplicate"],
        "schema_version": "1.0.0",
        "diagnostics": [finding_value()],
        "source_digest": digest,
        "semantic_digest": digest,
        "resource_snapshot": {"digest": digest, "complete": false, "unavailable": ["tools"]}
    });
    let read = inspection(answer.to_string().as_bytes()).expect("readable");
    assert!(!read.valid);
    assert_eq!(read.schema_version.as_deref(), Some("1.0.0"));
    assert_eq!(read.findings.len(), 1);
    assert_eq!(read.findings[0].element_id.as_deref(), Some("orders-read"));
    assert_eq!(
        read.snapshot,
        Some(SnapshotRecord {
            digest: Some(digest.clone()),
            complete: false,
            unavailable: vec!["tools".to_owned()],
        })
    );
    // The validator's free-text messages are never read.
    let serialized = serde_json::to_string(&read.findings).expect("serializes");
    assert!(!serialized.contains("secret-canary"));

    for (member, value) in [
        ("valid", json!("yes")),
        ("source_digest", json!("md5:abc")),
        ("schema_version", json!("1.0.0\u{1b}[2J")),
        ("diagnostics", json!({})),
        ("resource_snapshot", json!({"complete": "no"})),
    ] {
        let mut changed = answer.clone();
        changed[member] = value;
        assert_eq!(inspection(changed.to_string().as_bytes()), None, "{member}");
    }
    for (member, value) in [
        ("code", json!("Not-A-Code")),
        ("severity", json!("fatal")),
        ("pointer", json!("rules/1")),
        ("pointer", json!("/rules/~2")),
        ("message", json!("line one\nline two")),
        ("element_id", json!("id\u{202e}")),
        ("blocks", json!({"simulation": true})),
    ] {
        let mut finding = finding_value();
        finding[member] = value;
        let mut changed = answer.clone();
        changed["diagnostics"] = json!([finding]);
        assert_eq!(inspection(changed.to_string().as_bytes()), None, "{member}");
    }
    assert_eq!(inspection(b"not json"), None);
    // A missing optional member and a null snapshot are fine.
    let minimal = json!({"valid": true, "diagnostics": [], "resource_snapshot": null});
    let read = inspection(minimal.to_string().as_bytes()).expect("readable");
    assert!(read.valid && read.findings.is_empty() && read.snapshot.is_none());
}

#[test]
fn a_lint_sarif_log_locates_findings_by_pointer_and_never_by_file() {
    let finding = finding(&finding_value()).expect("a finding");
    let risk = PolicyFinding {
        code: "default_action_allow".to_owned(),
        severity: "risk".to_owned(),
        pointer: String::new(),
        element_id: None,
        message: "the default action allows".to_owned(),
        remediation: "deny by default".to_owned(),
        blocks: Blocks {
            simulation: false,
            tests: false,
            publication: false,
            evidence: false,
        },
    };
    let log = lint_sarif_log(
        &[Diagnostic::new(Code::PolicyInvalid).into()],
        &[finding.clone(), risk, finding],
    );
    let run = &log["runs"][0];
    assert!(run.get("originalUriBaseIds").is_none());
    let rules = run["tool"]["driver"]["rules"].as_array().expect("rules");
    let ids: Vec<_> = rules.iter().map(|rule| rule["id"].clone()).collect();
    assert_eq!(
        ids,
        [
            json!("policy.invalid"),
            json!("element_id_duplicate"),
            json!("default_action_allow")
        ]
    );
    let results = run["results"].as_array().expect("results");
    assert_eq!(results.len(), 4);
    assert_eq!(results[1]["ruleIndex"], 1);
    assert_eq!(results[3]["ruleIndex"], 1);
    assert_eq!(results[2]["ruleIndex"], 2);
    assert_eq!(results[2]["level"], "warning");
    assert_eq!(results[2]["properties"]["severity"], "risk");
    assert!(results[2].get("locations").is_none());
    assert_eq!(
        results[1]["locations"],
        json!([{"logicalLocations": [{
            "fullyQualifiedName": "/rules/1/id",
            "kind": "member",
            "name": "orders-read",
        }]}])
    );
    assert!(!log.to_string().contains("physicalLocation"));
}

#[test]
fn a_refusal_keeps_the_reason_and_structured_diagnostics_only() {
    let (diagnostic, refused) = refusal(&reply(
        422,
        json!({
            "error": "policy simulation request is invalid near 'secret-canary'",
            "errors": ["secret-canary"],
            "reason": "policy_simulation_invalid",
            "diagnostics": [
                {"code": "invalid_path", "pointer": "/cases/0/request/path", "message": "must start with /"},
                {"code": "invalid_path", "pointer": "/cases/1\u{1b}]", "message": "hostile"},
                {"code": "too_long", "pointer": ""}
            ],
            "diagnostics_truncated": false
        }),
    ));
    assert_eq!(diagnostic.code, Code::PolicyRequestRefused);
    assert_eq!(refused.status, 422);
    assert_eq!(refused.reason.as_deref(), Some("policy_simulation_invalid"));
    assert_eq!(
        refused.diagnostics,
        [
            RequestDiagnostic {
                code: "invalid_path".to_owned(),
                pointer: "/cases/0/request/path".to_owned(),
                message: Some("must start with /".to_owned()),
            },
            RequestDiagnostic {
                code: "too_long".to_owned(),
                pointer: String::new(),
                message: None,
            }
        ]
    );
    // An entry it could not repeat is counted as left out.
    assert!(refused.diagnostics_truncated);
    let serialized = serde_json::to_string(&refused).expect("serializes");
    assert!(!serialized.contains("canary"), "{serialized}");

    for (status, code) in [
        (400, Code::PolicyRequestRefused),
        (404, Code::PolicyNotFound),
        (408, Code::PolicyBusy),
        (409, Code::PolicyPreconditionFailed),
        (410, Code::PolicyPreconditionFailed),
        (412, Code::PolicyPreconditionFailed),
        (413, Code::PolicyRequestTooLarge),
        (428, Code::PolicyPreconditionFailed),
        (429, Code::PolicyBusy),
        (500, Code::UnexpectedStatus),
        (503, Code::ServerUnavailable),
    ] {
        let (diagnostic, refused) = refusal(&reply(status, json!({"reason": "Not A Code"})));
        assert_eq!(diagnostic.code, code, "{status}");
        assert_eq!(refused.reason, None);
    }
    let without_body = Reply {
        status: 413,
        headers: Vec::new(),
        body: None,
    };
    assert_eq!(
        refusal(&without_body).1,
        Refusal {
            status: 413,
            ..Refusal::default()
        }
    );
}

#[test]
fn only_safe_text_is_repeated() {
    for text in ["plain", "pointer /a~1b", "caf\u{e9}", "tab-free"] {
        assert!(is_safe_text(text), "{text:?}");
    }
    for text in [
        "\u{1b}[31m",
        "bell\u{7}",
        "del\u{7f}",
        "csi\u{9b}",
        "line\nbreak",
        "rlo\u{202e}",
        "isolate\u{2066}",
        "mark\u{200f}",
    ] {
        assert!(!is_safe_text(text), "{text:?}");
    }
    assert!(is_safe_value(&json!({"a": [1, "b", {"c": null}]})));
    assert!(!is_safe_value(&json!({"a\u{1b}": 1})));
    assert!(!is_safe_value(&json!([["\u{0}"]])));
    assert!(is_served_text(
        b"<?xml version=\"1.0\"?>\n<testsuite>\r\n\t</testsuite>\n"
    ));
    assert!(!is_served_text(b"<testsuite>\x1b[2J</testsuite>"));
    assert!(!is_served_text(b"<testsuite>\xff</testsuite>"));
}

#[test]
fn identifiers_and_etags_follow_the_gateways_grammars() {
    for etag in [ETAG, "W/\"weak\"", "\"\"", "\"a!#~\""] {
        assert!(is_entity_tag(etag), "{etag}");
    }
    let long = format!("\"{}\"", "a".repeat(MAX_ETAG_BYTES));
    for etag in [
        "sha256:abc",
        "\"",
        "\"a\"b\"",
        "\"sp ace\"",
        "W/sha",
        "\"caf\u{e9}\"",
        long.as_str(),
    ] {
        assert!(!is_entity_tag(etag), "{etag}");
    }
    assert!(is_job_id(JOB));
    for id in [
        "rpl_0123",
        "rpl_0123456789ABCDEF0123456789abcdef",
        "job_0123456789abcdef0123456789abcdef",
        "rpl_0123456789abcdef0123456789abcdef/..",
    ] {
        assert!(!is_job_id(id), "{id}");
    }
    assert!(is_draft_id("pd_0123456789abcdef0123456789abcdef"));
    assert!(!is_draft_id("pd/../x"));
    assert!(!is_draft_id(&"a".repeat(MAX_DRAFT_ID_BYTES + 1)));
    assert!(is_idempotency_key("nightly:2026-11-04.a_b"));
    assert!(!is_idempotency_key("two words"));
    assert!(!is_idempotency_key(
        &"k".repeat(MAX_IDEMPOTENCY_KEY_BYTES + 1)
    ));
    assert!(is_digest(&format!("sha256:{}", "0".repeat(64))));
    assert!(!is_digest(&format!("sha256:{}", "A".repeat(64))));
    assert!(is_pointer("") && is_pointer("/a/0/~0~1"));
    assert!(!is_pointer("/a~") && !is_pointer("a"));
}

#[test]
fn a_window_is_one_or_two_bounded_times() {
    assert_eq!(
        parse_window("2026-10-27T00:00:00Z"),
        Some(("2026-10-27T00:00:00Z".to_owned(), None))
    );
    assert_eq!(
        parse_window("2026-10-27T00:00:00Z/2026-10-28T00:00:00+01:00"),
        Some((
            "2026-10-27T00:00:00Z".to_owned(),
            Some("2026-10-28T00:00:00+01:00".to_owned())
        ))
    );
    let long = "1".repeat(MAX_TIMESTAMP_BYTES + 1);
    for window in ["/2026", "2026/", "a/b/c", "2026 10", long.as_str()] {
        assert_eq!(parse_window(window), None, "{window}");
    }
}

#[test]
fn a_replay_start_embeds_an_inline_candidate_as_its_exact_bytes() {
    let start = ReplayStart {
        base_etag: ETAG.to_owned(),
        from: "2026-10-27T00:00:00Z".to_owned(),
        to: Some("2026-10-28T00:00:00Z".to_owned()),
        candidate: Candidate::Active,
        enforce_all_shadow: true,
        max_records: Some(500),
        idempotency_key: Some("nightly".to_owned()),
    };
    let policy = b"{ \"schema_version\": \"1.0.0\",\n  \"rules\": [ ] }\n".to_vec();
    let body = start_body(&start, &ReadCandidate::Inline(policy.clone()));
    let text = String::from_utf8(body.clone()).expect("UTF-8");
    assert!(text.contains(&format!(
        "\"candidate\":{{\"source\":\"inline\",\"policy\":{}}}",
        String::from_utf8(policy).expect("UTF-8")
    )));
    let request: Value = serde_json::from_slice(&body).expect("one JSON document");
    assert_eq!(
        request,
        json!({
            "schema_version": "policy-replay.v1",
            "base_etag": ETAG,
            "candidate": {"source": "inline", "policy": {"schema_version": "1.0.0", "rules": []}},
            "window": {"from": "2026-10-27T00:00:00Z", "to": "2026-10-28T00:00:00Z"},
            "projections": ["as_authored", "enforce_all_shadow"],
            "max_records": 500,
            "idempotency_key": "nightly"
        })
    );
    let minimal = ReplayStart {
        to: None,
        enforce_all_shadow: false,
        max_records: None,
        idempotency_key: None,
        ..start
    };
    let request: Value = serde_json::from_slice(&start_body(
        &minimal,
        &ReadCandidate::Draft {
            id: "pd_1".to_owned(),
            etag: ETAG.to_owned(),
        },
    ))
    .expect("JSON");
    assert_eq!(
        request,
        json!({
            "schema_version": "policy-replay.v1",
            "base_etag": ETAG,
            "candidate": {"source": "draft", "draft_id": "pd_1", "draft_etag": ETAG},
            "window": {"from": "2026-10-27T00:00:00Z"},
            "projections": ["as_authored"]
        })
    );
    assert_eq!(
        ReadCandidate::Active.member(),
        b"{\"source\":\"active\"}".to_vec()
    );
}

#[test]
fn replay_options_choose_one_action_before_anything_is_sent() {
    let start = invocation(&[
        "policy",
        "replay",
        "--server",
        SERVER,
        "--base-etag",
        ETAG,
        "--window",
        "2026-10-27T00:00:00Z",
        "--wait",
    ]);
    assert!(matches!(replay_action(&start), Ok(ReplayAction::Start(_))));
    let read = invocation(&["policy", "replay", "--server", SERVER, "--job", JOB]);
    assert!(matches!(
        replay_action(&read),
        Ok(ReplayAction::Read { job }) if job == JOB
    ));
    let cancel = invocation(&["policy", "replay", "--server", SERVER, "--cancel", JOB]);
    assert!(matches!(
        replay_action(&cancel),
        Ok(ReplayAction::Cancel { job }) if job == JOB
    ));
    for (words, code, position) in [
        (
            &["--job", JOB, "--cancel", JOB][..],
            Code::ConflictingOptions,
            Some(7),
        ),
        (
            &["--job", JOB, "--base-etag", ETAG],
            Code::ConflictingOptions,
            Some(7),
        ),
        (
            &["--candidate", "policy.json", "--cancel", JOB],
            Code::ConflictingOptions,
            Some(7),
        ),
        (
            &["--cancel", JOB, "--wait"],
            Code::ConflictingOptions,
            Some(7),
        ),
        (&["--job", "rpl_../../x"], Code::InvalidValue, Some(5)),
        (&["--wait"], Code::MissingOption, None),
        (&["--base-etag", ETAG], Code::MissingOption, None),
        (
            &["--base-etag", "sha256:x", "--window", "2026"],
            Code::InvalidValue,
            Some(5),
        ),
        (
            &["--base-etag", ETAG, "--window", "a/b/c"],
            Code::InvalidValue,
            Some(7),
        ),
        (
            &[
                "--base-etag",
                ETAG,
                "--window",
                "2026",
                "--max-records",
                "0",
            ],
            Code::InvalidValue,
            Some(9),
        ),
        (
            &[
                "--base-etag",
                ETAG,
                "--window",
                "2026",
                "--max-records",
                "100001",
            ],
            Code::InvalidValue,
            Some(9),
        ),
        (
            &[
                "--base-etag",
                ETAG,
                "--window",
                "2026",
                "--idempotency-key",
                "a b",
            ],
            Code::InvalidValue,
            Some(9),
        ),
        (
            &["--base-etag", ETAG, "--window", "2026", "--draft", "pd_1"],
            Code::MissingOption,
            Some(9),
        ),
    ] {
        let mut arguments = vec!["policy", "replay", "--server", SERVER];
        arguments.extend_from_slice(words);
        let refused = replay_action(&invocation(&arguments)).expect_err("refused");
        assert_eq!(refused.code, code, "{words:?}");
        assert_eq!(refused.argument, position, "{words:?}");
    }
}

#[test]
fn a_candidate_is_the_active_policy_a_document_or_a_draft() {
    let base = ["policy", "test", "suite.json", "--server", SERVER];
    let with = |extra: &[&str]| {
        let mut words = base.to_vec();
        words.extend_from_slice(extra);
        Candidate::from_invocation(&invocation(&words))
    };
    assert!(matches!(with(&[]), Ok(Candidate::Active)));
    assert!(matches!(
        with(&["--candidate", "policy.json"]),
        Ok(Candidate::Inline { argument: 6, .. })
    ));
    assert!(matches!(
        with(&["--draft", "pd_1", "--draft-etag", ETAG]),
        Ok(Candidate::Draft { id, etag }) if id == "pd_1" && etag == ETAG
    ));
    for (extra, code, position) in [
        (
            &["--candidate", "policy.json", "--draft", "pd_1"][..],
            Code::ConflictingOptions,
            8,
        ),
        (
            &["--draft-etag", ETAG, "--candidate", "policy.json"],
            Code::ConflictingOptions,
            8,
        ),
        (&["--draft", "pd_1"], Code::MissingOption, 6),
        (&["--draft-etag", ETAG], Code::MissingOption, 6),
        (
            &["--draft", "pd/1", "--draft-etag", ETAG],
            Code::InvalidValue,
            6,
        ),
        (
            &["--draft", "pd_1", "--draft-etag", "unquoted"],
            Code::InvalidValue,
            8,
        ),
    ] {
        let refused = with(extra).expect_err("refused");
        assert_eq!(refused.code, code, "{extra:?}");
        assert_eq!(refused.argument, Some(position), "{extra:?}");
    }
}

#[test]
fn a_finished_job_tells_a_pipeline_whether_it_satisfies_a_gate() {
    let job =
        |state: &str, freshness: &str| json!({"state": state, "freshness": {"state": freshness}});
    let codes = |job: &Value| -> Vec<Code> {
        job_verdict(job)
            .iter()
            .map(|diagnostic| diagnostic.code)
            .collect()
    };
    assert!(codes(&job("queued", "current")).is_empty());
    assert!(codes(&job("running", "stale")).is_empty());
    assert!(codes(&job("completed", "current")).is_empty());
    assert!(codes(&job("completed", "unknown")).is_empty());
    assert_eq!(codes(&job("completed", "stale")), [Code::PolicyReplayStale]);
    assert_eq!(
        codes(&job("completed_incomplete", "current")),
        [Code::PolicyReplayIncomplete]
    );
    for state in ["failed", "cancelled", "expired"] {
        assert_eq!(codes(&job(state, "current")), [Code::PolicyReplayFailed]);
    }
    assert!(is_finished(&job("expired", "current")));
    assert!(!is_finished(&job("queued", "current")));
}

#[test]
fn a_replay_job_answer_must_be_its_version_with_a_job_id_and_a_known_state() {
    let job = json!({"schema_version": "policy-replay-job.v1", "job_id": JOB, "state": "queued"});
    assert_eq!(
        replay_job(job.to_string().as_bytes()).map(|(id, _)| id),
        Some(JOB.to_owned())
    );
    for (member, value) in [
        ("schema_version", json!("policy-replay-job.v2")),
        ("job_id", json!("rpl_x")),
        ("state", json!("paused")),
    ] {
        let mut changed = job.clone();
        changed[member] = value;
        assert!(
            replay_job(changed.to_string().as_bytes()).is_none(),
            "{member}"
        );
    }
}

#[test]
fn human_renderings_show_codes_ids_and_digests() {
    let mut out = Vec::new();
    write_lint(
        &LintResult {
            valid: Some(false),
            diagnostics: vec![finding(&finding_value()).expect("a finding")],
            ..LintResult::default()
        },
        &mut out,
    )
    .expect("writes");
    assert_eq!(
        String::from_utf8(out).expect("UTF-8"),
        "policy: invalid, 1 error\nerror element_id_duplicate at /rules/1/id (id orders-read): element ids must be unique\n"
    );

    let mut out = Vec::new();
    write_test(
        &TestResult {
            status: Some("failed"),
            results: Some(json!({
                "summary": {"total": 2, "passed": 1, "failed": 1, "incomplete": 0, "errors": 0},
                "suite": {"schema_version": "policy-tests.v1", "digest": "sha256:d"},
                "policy": {"source": "active", "etag": ETAG},
                "cases": [
                    {"id": "ok", "kind": "http", "status": "passed"},
                    {"id": "blocked", "kind": "http", "status": "failed", "mismatches": ["effect"]}
                ],
                "not_evaluated": ["authentication", "csrf"]
            })),
            refusal: None,
        },
        &mut out,
    )
    .expect("writes");
    assert_eq!(
        String::from_utf8(out).expect("UTF-8"),
        format!(
            "policy tests: failed (2 cases, 1 passed, 1 failed, 0 incomplete, 0 errors)\n  \
             suite   policy-tests.v1 sha256:d\n  policy  active {ETAG}\n  \
             failed      blocked (http): effect\nnot evaluated: authentication, csrf\n"
        )
    );

    let mut out = Vec::new();
    write_explain(
        &ExplainResult {
            results: Some(json!({
                "trace": {"level": "terminal"},
                "base": {"source": "active", "etag": ETAG},
                "candidate": {"source": "edits", "etag": ETAG},
                "cases": [{
                    "id": "reader", "kind": "http",
                    "results": [{
                        "projection": "as_authored",
                        "base": {"lane": "http", "logical": "allow", "enforcement": "not_applicable",
                                 "effective_action": "would_forward", "reason": "matched_rule"},
                        "changed": true,
                        "candidate": {"lane": "http", "logical": "deny", "enforcement": "enforced",
                                      "effective_action": "would_block", "reason": "matched_rule"}
                    }]
                }]
            })),
            refusal: None,
        },
        &mut out,
    )
    .expect("writes");
    assert_eq!(
        String::from_utf8(out).expect("UTF-8"),
        format!(
            "simulation: 1 case, trace terminal\n  base       active {ETAG}\n  \
             candidate  edits {ETAG}\ncase reader (http)\n  as_authored: http deny enforced \
             would_block matched_rule (base: http allow not_applicable would_forward matched_rule)\n"
        )
    );

    let mut out = Vec::new();
    write_replay(
        &ReplayResult {
            action: "read",
            job: Some(json!({
                "job_id": JOB,
                "state": "completed_incomplete",
                "base": {"etag": ETAG},
                "freshness": {"state": "current"},
                "candidate": {"source": "inline", "etag": ETAG},
                "window": {"from": "2026-10-27T00:00:00Z", "to": "2026-10-28T00:00:00Z"},
                "cutoff": {"high_water": 7, "selected_records": 0},
                "result_digest": "sha256:r",
                "result": {"complete": false, "limitations": ["no_data"],
                           "records": {"selected": 0, "scanned": 0, "replayable": 0}}
            })),
            discarded: None,
            refusal: None,
        },
        &mut out,
    )
    .expect("writes");
    assert_eq!(
        String::from_utf8(out).expect("UTF-8"),
        format!(
            "replay job {JOB}: completed_incomplete\n  base         {ETAG} (current)\n  \
             candidate    inline {ETAG}\n  window       2026-10-27T00:00:00Z to \
             2026-10-28T00:00:00Z\n  cutoff       high water 7, 0 records selected\n  \
             records      0 selected, 0 scanned, 0 replayable\n  result       incomplete, \
             digest sha256:r\n  limitations  no_data\n"
        )
    );
    for (result, line) in [
        (
            ReplayResult {
                action: "cancel",
                discarded: Some(true),
                ..ReplayResult::default()
            },
            "replay job discarded\n",
        ),
        (ReplayResult::default(), "replay: no job\n"),
    ] {
        let mut out = Vec::new();
        write_replay(&result, &mut out).expect("writes");
        assert_eq!(String::from_utf8(out).expect("UTF-8"), line);
    }
}
