//! The replay job engine (issue #243, slice 13): what a run counts, its
//! bounds, its determinism, cancellation, and the audit-log reader it pages
//! through; and the `policy-replay.v1` request. The admin endpoint is covered
//! in `admin_policy_replays_tests`.

use std::{
    cell::{Cell, RefCell},
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use rusqlite::Connection;
use serde_json::{json, Value};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use super::{
    job::{
        run, ReplayControl, ReplayOutcome, ReplayScope, ReplaySource, ReplaySourceError,
        ReplayStop, MAX_REPLAY_RECORDS, MAX_REPLAY_RECORD_BYTES, REPLAY_PAGE_RECORDS,
    },
    request::{parse_request, resolve_window, ReplayRequest, MAX_REPLAY_WINDOW},
};
use crate::{
    audit::{
        event,
        query::{AuditQueryStore, ReplayCutoff, ReplayPageQuery, ReplayRow},
        sqlite_sink, Actor, AuditEvent,
    },
    canonical_json,
    policy_eval::{CompiledPolicy, PolicyAuthority},
    rbac::Policy,
};

const SUBJECT_CANARY: &str = "replay-job-subject-canary-6a1f";
const REQUEST_ID_CANARY: &str = "replay-job-request-id-canary-02be";
const SOURCE_IP_CANARY: &str = "198.51.100.23";
const USER_AGENT_CANARY: &str = "replay-job-user-agent-canary-91c4";
const PATH_CANARY: &str = "/orders/replay-path-canary-5d0e";
/// 2027-01-15T08:00:00Z, in audit epoch microseconds: the start of every
/// test window.
const WINDOW_START_US: i64 = 1_800_000_000_000_000;

fn policy_document() -> Value {
    json!({
        "schema_version": "0.1.0",
        "id": "replay-jobs",
        "default_action": "deny",
        "enforcement_mode": "enforce",
        "roles": { "reader": { "permissions": ["orders:read"] } },
        "rules": [
            { "id": "public-allow", "methods": ["GET"], "path": "/public/**", "action": "allow" },
            { "id": "orders-watch", "methods": ["GET"], "path": "/orders/watched", "action": "shadow" },
            { "id": "search-tool", "tool_name": "search", "action": "allow" }
        ],
        "routes": [
            { "methods": ["GET"], "path_prefix": "/orders", "permission": "orders:read" }
        ],
        "rate_limits": [
            { "path": "/public/**", "requests_per_second": 1, "burst": 1 }
        ],
        "tools": { "search": { "enabled": true } }
    })
}

fn compiled(document: Value) -> CompiledPolicy {
    let policy = Policy::validate_json_value(document).expect("the test policy validates");
    CompiledPolicy::from_validated_policy(policy, PolicyAuthority::Standalone)
        .expect("a standalone policy compiles")
}

fn reader() -> Actor {
    Actor {
        user_id: SUBJECT_CANARY.to_owned(),
        issuer: Some("https://issuer.example".to_owned()),
        email: None,
        roles: Some(vec!["reader".to_owned()]),
        auth_mode: "bearer_token".to_owned(),
    }
}

fn timestamp(epoch_us: i64) -> String {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(epoch_us) * 1_000)
        .expect("a test timestamp is representable")
        .format(&Rfc3339)
        .expect("a test timestamp formats")
}

fn audit_event(event_type: &str, actor: Option<Actor>, payload: Value) -> AuditEvent {
    AuditEvent::new(
        event_type,
        REQUEST_ID_CANARY,
        SOURCE_IP_CANARY,
        actor,
        payload,
    )
    .with_user_agent(USER_AGENT_CANARY)
}

fn observed(method: &str, path: &str, decision: &str, actor: Option<Actor>) -> AuditEvent {
    audit_event(
        "http.request_observed",
        actor,
        json!({
            "method": method,
            "path": path,
            "status": 200,
            "policy_decision": decision,
            "routing_context_known": true,
        }),
    )
}

/// One stored row of a test source. The event is boxed, as the reader's
/// is: it is far larger than the other rows.
enum Stored {
    Event(Box<AuditEvent>),
    Unreadable,
    Oversized,
}

impl Stored {
    fn event(event: AuditEvent) -> Self {
        Self::Event(Box::new(event))
    }

    fn row(&self) -> ReplayRow {
        match self {
            Self::Event(event) => ReplayRow::Event(event.clone()),
            Self::Unreadable => ReplayRow::Unreadable,
            Self::Oversized => ReplayRow::Oversized,
        }
    }
}

type PageHook = Box<dyn FnMut(usize, &mut Vec<(i64, i64, Stored)>)>;

/// A source over rows held in memory: `(id, epoch_us, row)`. It answers a
/// page query exactly as the SQLite reader does, and lets a test cap page
/// sizes, fail, or change its rows between pages.
struct VecSource {
    rows: RefCell<Vec<(i64, i64, Stored)>>,
    page_cap: usize,
    fail: bool,
    pages: Cell<usize>,
    after_page: RefCell<Option<PageHook>>,
}

impl VecSource {
    fn new(rows: Vec<Stored>) -> Self {
        let rows = rows
            .into_iter()
            .enumerate()
            .map(|(index, stored)| {
                let index = i64::try_from(index).expect("a test index fits");
                (index + 1, WINDOW_START_US + index, stored)
            })
            .collect();
        Self {
            rows: RefCell::new(rows),
            page_cap: usize::MAX,
            fail: false,
            pages: Cell::new(0),
            after_page: RefCell::new(None),
        }
    }

    fn events(events: Vec<AuditEvent>) -> Self {
        Self::new(events.into_iter().map(Stored::event).collect())
    }

    fn push(&self, epoch_us: i64, stored: Stored) {
        let mut rows = self.rows.borrow_mut();
        let id = rows.last().map_or(1, |(id, _, _)| id + 1);
        rows.push((id, epoch_us, stored));
    }

    /// The cutoff the SQLite reader would fix for `[from, to)` now.
    fn cutoff(&self, from_epoch_us: i64, to_epoch_us: i64) -> ReplayCutoff {
        let rows = self.rows.borrow();
        let high_water = rows.last().map_or(0, |(id, _, _)| *id);
        let selected = rows
            .iter()
            .filter(|(_, epoch, _)| (from_epoch_us..to_epoch_us).contains(epoch))
            .map(|(id, _, _)| *id)
            .collect::<Vec<_>>();
        ReplayCutoff {
            high_water,
            selected: u64::try_from(selected.len()).expect("a test count fits"),
            first_id: selected.first().copied(),
            last_id: selected.last().copied(),
        }
    }

    fn scope(&self, max_records: usize) -> ReplayScope {
        let (from, to) = (WINDOW_START_US, WINDOW_START_US + 1_000_000);
        ReplayScope {
            from: timestamp(from),
            to: timestamp(to),
            from_epoch_us: from,
            to_epoch_us: to,
            cutoff: self.cutoff(from, to),
            max_records,
        }
    }
}

impl ReplaySource for VecSource {
    fn page(&self, query: &ReplayPageQuery) -> Result<Vec<(i64, ReplayRow)>, ReplaySourceError> {
        if self.fail {
            return Err(ReplaySourceError);
        }
        let page = self
            .rows
            .borrow()
            .iter()
            .filter(|(id, epoch, _)| {
                *id > query.after_id
                    && *id <= query.through_id
                    && (query.from_epoch_us..query.to_epoch_us).contains(epoch)
            })
            .take(query.limit.min(self.page_cap))
            .map(|(id, _, stored)| (*id, stored.row()))
            .collect::<Vec<_>>();
        let number = self.pages.get() + 1;
        self.pages.set(number);
        if let Some(hook) = self.after_page.borrow_mut().as_mut() {
            hook(number, &mut self.rows.borrow_mut());
        }
        Ok(page)
    }

    fn window_count(&self, scope: &ReplayScope) -> Result<u64, ReplaySourceError> {
        if self.fail {
            return Err(ReplaySourceError);
        }
        let count = self
            .rows
            .borrow()
            .iter()
            .filter(|(id, epoch, _)| {
                *id <= scope.cutoff.high_water
                    && (scope.from_epoch_us..scope.to_epoch_us).contains(epoch)
            })
            .count();
        Ok(u64::try_from(count).expect("a test count fits"))
    }
}

fn run_to_end(source: &VecSource, scope: &ReplayScope) -> ReplayOutcome {
    run(
        source,
        &compiled(policy_document()),
        scope,
        Instant::now() + Duration::from_secs(60),
        &ReplayControl::default(),
    )
    .expect("the run completes")
}

/// A window that touches every classification and every lane.
fn mixed_window() -> Vec<Stored> {
    let mut old_envelope = observed("GET", "/orders/1", "allowed", Some(reader()));
    old_envelope.schema_version = "0.1.0".to_owned();
    let mut unknown_envelope = observed("GET", "/orders/1", "allowed", Some(reader()));
    unknown_envelope.schema_version = "0.9.0".to_owned();
    vec![
        Stored::event(observed("GET", "/public/a", "allowed", Some(reader()))),
        Stored::event(audit_event(
            "authz.allowed",
            None,
            json!({ "method": "GET", "path": "/public/a", "matched_rule_id": "public-allow" }),
        )),
        Stored::event(observed("GET", PATH_CANARY, "allowed", Some(reader()))),
        Stored::event(observed("GET", "/orders/2", "denied", None)),
        Stored::event(observed(
            "GET",
            "/orders/watched",
            "would_deny",
            Some(reader()),
        )),
        Stored::event(old_envelope),
        Stored::event(unknown_envelope),
        Stored::event(observed("GET", "/health", "not_evaluated", None)),
        Stored::event(observed("GE T", "/orders/3", "allowed", None)),
        Stored::event(audit_event(
            event::TOOL_INVOKE_START,
            Some(reader()),
            json!({ "tool_name": "search", "outcome": "started" }),
        )),
        Stored::event(audit_event(
            event::POLICY_CHANGED,
            Some(reader()),
            json!({ "action": "updated" }),
        )),
        Stored::Unreadable,
        Stored::Oversized,
    ]
}

fn outcome_count(lane: &Value, logical: &str, effective_action: &str) -> u64 {
    lane["outcomes"]
        .as_array()
        .expect("outcomes")
        .iter()
        .filter(|outcome| {
            outcome["logical"] == json!(logical)
                && outcome["effective_action"] == json!(effective_action)
        })
        .map(|outcome| outcome["count"].as_u64().expect("count"))
        .sum()
}

#[test]
fn a_window_is_decided_through_the_kernel_and_counted_by_stable_codes() {
    let source = VecSource::new(mixed_window());
    let scope = source.scope(MAX_REPLAY_RECORDS);
    let outcome = run_to_end(&source, &scope);
    assert!(outcome.complete, "{:?}", outcome.limitations);
    assert!(outcome.limitations.is_empty());
    let result = &outcome.result;
    assert_eq!(result["schema_version"], json!("policy-replay-results.v1"));
    assert_eq!(result["mode"], json!("historical_replay"));
    assert_eq!(result["complete"], json!(true));

    let records = &result["records"];
    assert_eq!(records["selected"], json!(13));
    assert_eq!(records["scanned"], json!(13));
    assert_eq!(records["replayable"], json!(6));
    assert_eq!(records["duplicate"], json!(1));
    assert_eq!(records["not_policy_evaluated"], json!(1));
    assert_eq!(records["unsupported"], json!(1));
    assert_eq!(records["malformed"], json!(1));
    assert_eq!(records["not_request_record"], json!(1));
    assert_eq!(records["unreadable"], json!(1));
    assert_eq!(records["oversized"], json!(1));
    assert_eq!(
        records["by_code"],
        json!({
            "duplicate_http_decision": 1,
            "malformed_method": 1,
            "not_policy_evaluated": 1,
            "not_request_record": 1,
            "oversized_record": 1,
            "replayable": 6,
            "unreadable_record": 1,
            "unsupported_envelope_version": 1,
        })
    );

    let http = &result["replayed"]["http"];
    assert_eq!(http["replayable"], json!(5));
    // The public allow and the reader's order are forwarded; the anonymous
    // order is blocked; the watched order is a shadowed deny, forwarded.
    assert_eq!(outcome_count(http, "allow", "would_forward"), 2);
    assert_eq!(outcome_count(http, "deny", "would_block"), 1);
    assert_eq!(outcome_count(http, "deny", "would_forward"), 1);
    assert!(http["outcomes"]
        .as_array()
        .expect("outcomes")
        .iter()
        .any(|outcome| outcome["enforcement"] == json!("shadowed")));
    // The 0.1.0 envelope cannot say whether the actor had an issuer, so the
    // route's permission check cannot be judged: indeterminate, never allow.
    assert_eq!(http["indeterminate"], json!(1));
    assert_eq!(http["limitations"], json!({ "missing_principal_fact": 1 }));
    assert_eq!(http["refused"], json!(0));

    // Only the reader's public request selects the public override; the
    // record whose principal was not recorded cannot be placed in a lane.
    let rate = &result["replayed"]["rate"];
    assert_eq!(rate["override"], json!(1));
    assert_eq!(rate["no_override"], json!(3));
    assert_eq!(rate["indeterminate"], json!(1));
    assert_eq!(rate["limitations"], json!({ "missing_principal_fact": 1 }));

    let tool = &result["replayed"]["tool"];
    assert_eq!(tool["replayable"], json!(1));
    assert_eq!(outcome_count(tool, "allow", "would_forward"), 1);
    assert_eq!(result["replayed"]["total"], json!(6));
    assert_eq!(outcome.replayed, 6);
    assert!(result["not_replayed"]
        .as_array()
        .expect("not_replayed")
        .contains(&json!("rate_capacity")));
}

#[test]
fn a_result_never_repeats_a_record_value() {
    let source = VecSource::new(mixed_window());
    let outcome = run_to_end(&source, &source.scope(MAX_REPLAY_RECORDS));
    let rendered = outcome.result.to_string();
    for canary in [
        SUBJECT_CANARY,
        REQUEST_ID_CANARY,
        SOURCE_IP_CANARY,
        USER_AGENT_CANARY,
        PATH_CANARY,
        "https://issuer.example",
        "/public/a",
        "public-allow",
        "search",
    ] {
        assert!(!rendered.contains(canary), "the result repeats {canary}");
    }
}

#[test]
fn the_same_cutoff_and_policy_give_byte_identical_results_however_the_source_pages() {
    let whole = VecSource::new(mixed_window());
    let first = run_to_end(&whole, &whole.scope(MAX_REPLAY_RECORDS));
    let again = run_to_end(&whole, &whole.scope(MAX_REPLAY_RECORDS));
    let mut short_pages = VecSource::new(mixed_window());
    short_pages.page_cap = 2;
    let paged = run_to_end(&short_pages, &short_pages.scope(MAX_REPLAY_RECORDS));
    assert!(
        short_pages.pages.get() > 2,
        "the short-page source was paged"
    );
    for other in [&again, &paged] {
        assert_eq!(other.digest, first.digest);
        assert_eq!(
            canonical_json::canonical_json_bytes(&other.result).expect("canonical"),
            canonical_json::canonical_json_bytes(&first.result).expect("canonical"),
        );
    }
    assert_eq!(
        first.digest,
        canonical_json::semantic_digest(
            "application/vnd.greengateway.policy-replay-results+json",
            "policy-replay-results.v1",
            &first.result
        )
        .expect("digest")
    );
    // A different candidate is a different result.
    let mut candidate = policy_document();
    candidate["default_action"] = json!("allow");
    candidate["routes"] = json!([]);
    let other = run(
        &whole,
        &compiled(candidate),
        &whole.scope(MAX_REPLAY_RECORDS),
        Instant::now() + Duration::from_secs(60),
        &ReplayControl::default(),
    )
    .expect("the run completes");
    assert_ne!(other.digest, first.digest);
}

#[test]
fn records_written_after_the_cutoff_never_enter_a_job() {
    let source = VecSource::events(vec![
        observed("GET", "/public/a", "allowed", None),
        observed("GET", "/public/b", "allowed", None),
    ]);
    let scope = source.scope(MAX_REPLAY_RECORDS);
    // Written after the job was created, inside its window.
    source.push(
        WINDOW_START_US + 10,
        Stored::event(observed("GET", "/orders/9", "denied", None)),
    );
    let outcome = run_to_end(&source, &scope);
    assert!(outcome.complete);
    assert_eq!(outcome.scanned, 2);
    assert_eq!(outcome.result["records"]["replayable"], json!(2));
}

#[test]
fn a_window_past_the_record_bound_is_truncated_and_never_complete() {
    let source = VecSource::events(
        (0..5)
            .map(|_| observed("GET", "/public/a", "allowed", None))
            .collect(),
    );
    let outcome = run_to_end(&source, &source.scope(3));
    assert!(!outcome.complete);
    assert_eq!(outcome.limitations, ["scan_truncated"]);
    assert_eq!(outcome.scanned, 3);
    assert_eq!(outcome.result["records"]["selected"], json!(5));
    assert_eq!(outcome.result["source"]["max_records"], json!(3));
}

#[test]
fn a_run_past_its_deadline_stops_incomplete() {
    let source = VecSource::events(vec![observed("GET", "/public/a", "allowed", None)]);
    let outcome = run(
        &source,
        &compiled(policy_document()),
        &source.scope(MAX_REPLAY_RECORDS),
        Instant::now(),
        &ReplayControl::default(),
    )
    .expect("a stopped run is a result");
    assert!(!outcome.complete);
    assert_eq!(outcome.limitations, ["deadline_exceeded", "no_data"]);
    assert_eq!(outcome.scanned, 0);
}

#[test]
fn an_empty_window_is_no_data_and_never_complete() {
    let source = VecSource::new(Vec::new());
    let outcome = run_to_end(&source, &source.scope(MAX_REPLAY_RECORDS));
    assert!(!outcome.complete);
    assert_eq!(outcome.limitations, ["no_data"]);
    assert_eq!(source.pages.get(), 0, "an empty cutoff reads no page");

    // A window of records none of which is replayable is no data either.
    let source = VecSource::events(vec![observed("GET", "/health", "not_evaluated", None)]);
    let outcome = run_to_end(&source, &source.scope(MAX_REPLAY_RECORDS));
    assert_eq!(outcome.limitations, ["no_data"]);
}

#[test]
fn rows_pruned_while_a_job_runs_make_it_incomplete_never_silently_short() {
    let mut source = VecSource::events(
        (0..6)
            .map(|_| observed("GET", "/public/a", "allowed", None))
            .collect(),
    );
    source.page_cap = 2;
    let scope = source.scope(MAX_REPLAY_RECORDS);
    // Retention prunes the oldest rows after the first page: the run reads
    // the rest, and the result says the window changed under it.
    *source.after_page.borrow_mut() = Some(Box::new(|page, rows| {
        if page == 1 {
            rows.retain(|(id, _, _)| *id > 4);
        }
    }));
    let outcome = run_to_end(&source, &scope);
    assert!(!outcome.complete);
    assert_eq!(outcome.limitations, ["source_changed"]);
    assert_eq!(outcome.scanned, 4);
}

#[test]
fn a_cancelled_run_returns_no_result() {
    let source = VecSource::events(vec![observed("GET", "/public/a", "allowed", None)]);
    let control = ReplayControl::default();
    control.cancel();
    let stopped = run(
        &source,
        &compiled(policy_document()),
        &source.scope(MAX_REPLAY_RECORDS),
        Instant::now() + Duration::from_secs(60),
        &control,
    );
    assert_eq!(stopped.err(), Some(ReplayStop::Cancelled));

    // Cancelled between pages: the run stops before the next record.
    let mut source = VecSource::events(
        (0..6)
            .map(|_| observed("GET", "/public/a", "allowed", None))
            .collect(),
    );
    source.page_cap = 2;
    let control = Arc::new(ReplayControl::default());
    let cancel = Arc::clone(&control);
    *source.after_page.borrow_mut() = Some(Box::new(move |page, _| {
        if page == 1 {
            cancel.cancel();
        }
    }));
    let stopped = run(
        &source,
        &compiled(policy_document()),
        &source.scope(MAX_REPLAY_RECORDS),
        Instant::now() + Duration::from_secs(60),
        &control,
    );
    assert_eq!(stopped.err(), Some(ReplayStop::Cancelled));
    assert_eq!(control.scanned(), 0);
    assert_eq!(source.pages.get(), 1);
}

#[test]
fn a_source_that_fails_fails_the_run() {
    let mut source = VecSource::events(vec![observed("GET", "/public/a", "allowed", None)]);
    source.fail = true;
    let scope = source.scope(MAX_REPLAY_RECORDS);
    let stopped = run(
        &source,
        &compiled(policy_document()),
        &scope,
        Instant::now() + Duration::from_secs(60),
        &ReplayControl::default(),
    );
    assert_eq!(
        stopped.err(),
        Some(ReplayStop::Failed("source_unavailable"))
    );
}

/// The run records no metric. The endpoint runs it on a blocking thread,
/// outside the recorder its side-effect test installs, so this is where that
/// part of the claim is proved.
#[test]
fn the_run_records_no_metric() {
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let outcome = ::metrics::with_local_recorder(&recorder, || {
        let source = VecSource::new(mixed_window());
        run_to_end(&source, &source.scope(MAX_REPLAY_RECORDS))
    });
    assert!(outcome.complete);
    let rendered = handle.render();
    assert!(
        rendered
            .lines()
            .all(|line| line.trim().is_empty() || line.starts_with('#')),
        "a replay run recorded a metric: {rendered}"
    );
}

/// A SQLite audit log at a fresh temporary path, removed with its WAL files.
struct TempAuditLog {
    path: PathBuf,
}

impl TempAuditLog {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "greengateway-replay-{name}-{}.sqlite",
            uuid::Uuid::new_v4()
        ));
        let connection = Connection::open(&path).expect("audit log opens");
        sqlite_sink::configure_connection(&connection).expect("audit schema is created");
        Self { path }
    }

    fn write(&self, events: &[AuditEvent]) {
        let mut connection = Connection::open(&self.path).expect("audit log opens");
        sqlite_sink::write_events(&mut connection, events).expect("events are written");
    }

    fn execute(&self, sql: &str) {
        Connection::open(&self.path)
            .expect("audit log opens")
            .execute_batch(sql)
            .expect("statement runs");
    }
}

impl Drop for TempAuditLog {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", self.path.display()));
        }
    }
}

fn at(mut event: AuditEvent, epoch_us: i64) -> AuditEvent {
    event.timestamp = timestamp(epoch_us);
    event
}

fn sqlite_scope(store: &AuditQueryStore, max_records: usize) -> ReplayScope {
    let (from, to) = (WINDOW_START_US, WINDOW_START_US + 1_000_000);
    ReplayScope {
        from: timestamp(from),
        to: timestamp(to),
        from_epoch_us: from,
        to_epoch_us: to,
        cutoff: store.replay_cutoff(from, to).expect("cutoff reads"),
        max_records,
    }
}

#[test]
fn the_audit_log_reader_pins_a_cutoff_and_reads_only_below_it() {
    let log = TempAuditLog::new("cutoff");
    log.write(&[
        at(
            observed("GET", "/public/early", "allowed", None),
            WINDOW_START_US - 1,
        ),
        at(
            observed("GET", "/public/a", "allowed", None),
            WINDOW_START_US,
        ),
        at(
            observed("GET", "/public/b", "allowed", None),
            WINDOW_START_US + 5,
        ),
        at(
            observed("GET", "/public/late", "allowed", None),
            WINDOW_START_US + 1_000_000,
        ),
    ]);
    let store = AuditQueryStore::open_read_only(&log.path).expect("read-only store opens");
    let scope = sqlite_scope(&store, MAX_REPLAY_RECORDS);
    assert_eq!(scope.cutoff.high_water, 4);
    assert_eq!(scope.cutoff.selected, 2);
    assert_eq!(scope.cutoff.first_id, Some(2));
    assert_eq!(scope.cutoff.last_id, Some(3));

    // Written after the cutoff, inside the window: never read.
    log.write(&[at(
        observed("GET", "/orders/late", "denied", None),
        WINDOW_START_US + 1,
    )]);
    let outcome = run(
        &store,
        &compiled(policy_document()),
        &scope,
        Instant::now() + Duration::from_secs(60),
        &ReplayControl::default(),
    )
    .expect("the run completes");
    assert!(outcome.complete, "{:?}", outcome.limitations);
    assert_eq!(outcome.scanned, 2);
    assert_eq!(
        store
            .replay_window_count(
                scope.from_epoch_us,
                scope.to_epoch_us,
                scope.cutoff.high_water
            )
            .expect("count reads"),
        2
    );
}

#[test]
fn the_audit_log_reader_never_loads_an_oversized_or_unreadable_row() {
    let log = TempAuditLog::new("rows");
    let mut huge = observed("GET", "/public/a", "allowed", None);
    huge.payload["padding"] = json!("x".repeat(MAX_REPLAY_RECORD_BYTES));
    log.write(&[
        at(
            observed("GET", "/public/a", "allowed", None),
            WINDOW_START_US,
        ),
        at(huge, WINDOW_START_US + 1),
        at(
            observed("GET", "/public/b", "allowed", None),
            WINDOW_START_US + 2,
        ),
    ]);
    log.execute("UPDATE audit_events SET payload_json = '{not json' WHERE id = 3");
    let store = AuditQueryStore::open_read_only(&log.path).expect("read-only store opens");
    let page = store
        .replay_page(&ReplayPageQuery {
            from_epoch_us: WINDOW_START_US,
            to_epoch_us: WINDOW_START_US + 1_000_000,
            after_id: 0,
            through_id: 3,
            limit: REPLAY_PAGE_RECORDS,
            max_record_bytes: MAX_REPLAY_RECORD_BYTES,
            max_page_bytes: 1024 * 1024,
        })
        .expect("page reads");
    let kinds = page
        .iter()
        .map(|(id, row)| {
            let kind = match row {
                ReplayRow::Event(_) => "event",
                ReplayRow::Unreadable => "unreadable",
                ReplayRow::Oversized => "oversized",
            };
            (*id, kind)
        })
        .collect::<Vec<_>>();
    assert_eq!(kinds, [(1, "event"), (2, "oversized"), (3, "unreadable")]);

    // The page's byte budget ends a page after its first row, never before.
    // An oversized row costs the budget nothing, since none of it is read:
    // the next row that would be read ends the page.
    let page = store
        .replay_page(&ReplayPageQuery {
            from_epoch_us: WINDOW_START_US,
            to_epoch_us: WINDOW_START_US + 1_000_000,
            after_id: 0,
            through_id: 3,
            limit: REPLAY_PAGE_RECORDS,
            max_record_bytes: MAX_REPLAY_RECORD_BYTES,
            max_page_bytes: 1,
        })
        .expect("page reads");
    let ids = page.iter().map(|(id, _)| *id).collect::<Vec<_>>();
    assert_eq!(ids, [1, 2]);
}

#[test]
fn rows_pruned_from_the_audit_log_after_the_cutoff_make_a_job_incomplete() {
    let log = TempAuditLog::new("pruned");
    log.write(&[
        at(
            observed("GET", "/public/a", "allowed", None),
            WINDOW_START_US,
        ),
        at(
            observed("GET", "/public/b", "allowed", None),
            WINDOW_START_US + 1,
        ),
        at(
            observed("GET", "/public/c", "allowed", None),
            WINDOW_START_US + 2,
        ),
    ]);
    let store = AuditQueryStore::open_read_only(&log.path).expect("read-only store opens");
    let scope = sqlite_scope(&store, MAX_REPLAY_RECORDS);
    assert_eq!(scope.cutoff.selected, 3);
    // What retention pruning does, between the job's creation and its run.
    log.execute(&format!(
        "DELETE FROM audit_events WHERE timestamp_epoch_us < {}",
        WINDOW_START_US + 1
    ));
    let outcome = run(
        &store,
        &compiled(policy_document()),
        &scope,
        Instant::now() + Duration::from_secs(60),
        &ReplayControl::default(),
    )
    .expect("the run completes");
    assert!(!outcome.complete);
    assert_eq!(outcome.limitations, ["source_changed"]);
    assert_eq!(outcome.scanned, 2);
}

fn request_document() -> Value {
    json!({
        "schema_version": "policy-replay.v1",
        "base_etag": "\"sha256:base\"",
        "candidate": { "source": "active" },
        "window": { "from": "2027-01-15T08:00:00Z", "to": "2027-01-16T08:00:00Z" }
    })
}

fn parse(document: &Value) -> Result<ReplayRequest, Vec<(String, String)>> {
    let bytes = serde_json::to_vec(document).expect("serializes");
    parse_request(&bytes, document).map_err(|diagnostics| {
        diagnostics
            .diagnostics
            .into_iter()
            .map(|diagnostic| (diagnostic.code.to_owned(), diagnostic.pointer))
            .collect()
    })
}

fn time(text: &str) -> OffsetDateTime {
    OffsetDateTime::parse(text, &Rfc3339).expect("a test time parses")
}

#[test]
fn a_replay_request_is_strict_and_exactly_versioned() {
    let request = parse(&request_document()).expect("a minimal request parses");
    assert_eq!(request.max_records, MAX_REPLAY_RECORDS);
    assert!(request.idempotency_key.is_none());
    assert!(request.digest.starts_with("sha256:"));

    let mut full = request_document();
    full["description"] = json!("nightly");
    full["max_records"] = json!(50);
    full["idempotency_key"] = json!("nightly-2027-01-15");
    full["candidate"] = json!({ "source": "edits", "edits": [
        { "op": "set", "field": "default_action", "value": "allow" }
    ] });
    let request = parse(&full).expect("a full request parses");
    assert_eq!(request.max_records, 50);
    assert_eq!(
        request.idempotency_key.as_deref(),
        Some("nightly-2027-01-15")
    );

    let refused = |mutate: &dyn Fn(&mut Value)| {
        let mut document = request_document();
        mutate(&mut document);
        parse(&document).err().expect("refused")
    };
    assert_eq!(
        refused(&|document| document["schema_version"] = json!("policy-replay.v2")),
        [(
            "unsupported_schema_version".to_owned(),
            "/schema_version".to_owned()
        )]
    );
    assert_eq!(
        refused(&|document| document["token"] = json!("x")),
        [("forbidden_field".to_owned(), "/token".to_owned())]
    );
    assert_eq!(
        refused(&|document| document["window"]["until"] = json!("x")),
        [("unknown_field".to_owned(), "/window/until".to_owned())]
    );
    assert_eq!(
        refused(&|document| document["window"]["from"] = json!("yesterday")),
        [("invalid_value".to_owned(), "/window/from".to_owned())]
    );
    assert_eq!(
        refused(&|document| {
            document.as_object_mut().expect("object").remove("window");
        }),
        [("missing_field".to_owned(), "/window".to_owned())]
    );
    for bound in [
        json!(0),
        json!(MAX_REPLAY_RECORDS + 1),
        json!(1.5),
        json!("10"),
    ] {
        let mut document = request_document();
        document["max_records"] = bound;
        assert_eq!(
            parse(&document).err().expect("refused"),
            [("invalid_value".to_owned(), "/max_records".to_owned())]
        );
    }
    for key in [json!(""), json!("has space"), json!("k".repeat(129))] {
        let mut document = request_document();
        document["idempotency_key"] = key;
        assert!(parse(&document).is_err());
    }
}

#[test]
fn a_window_is_closed_against_the_moment_the_job_is_created() {
    let now = time("2027-01-20T00:00:00Z");
    let window = |from: &str, to: Option<&str>| {
        let mut document = request_document();
        document["window"] = match to {
            Some(to) => json!({ "from": from, "to": to }),
            None => json!({ "from": from }),
        };
        resolve_window(&parse(&document).expect("parses"), now).map_err(|diagnostics| {
            diagnostics
                .diagnostics
                .into_iter()
                .map(|diagnostic| diagnostic.code)
                .collect::<Vec<_>>()
        })
    };
    let open = window("2027-01-19T00:00:00+02:00", None).expect("an open window resolves");
    assert_eq!(open.from, "2027-01-18T22:00:00Z");
    assert_eq!(open.to, "2027-01-20T00:00:00Z");
    assert_eq!(
        open.to_epoch_us - open.from_epoch_us,
        26 * 3_600 * 1_000_000
    );
    assert_eq!(
        window("2027-01-19T00:00:00Z", Some("2027-01-21T00:00:00Z")),
        Err(vec!["window_in_future"])
    );
    assert_eq!(
        window("2027-01-19T00:00:00Z", Some("2027-01-19T00:00:00Z")),
        Err(vec!["empty_window"])
    );
    let too_early = now - MAX_REPLAY_WINDOW - time::Duration::seconds(1);
    assert_eq!(
        window(&too_early.format(&Rfc3339).expect("formats"), None),
        Err(vec!["window_too_long"])
    );
    let longest = now - MAX_REPLAY_WINDOW;
    assert!(window(&longest.format(&Rfc3339).expect("formats"), None).is_ok());
}

fn request_schema() -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../docs/schemas/policy-replay.v1.schema.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()))
}

/// The published schema and the parser agree on the requests both can judge.
#[test]
fn the_published_schema_agrees_with_the_parser() {
    let schema = request_schema();
    let validator = jsonschema::validator_for(&schema).expect("the schema compiles");
    let mut accepted = vec![request_document()];
    let mut full = request_document();
    full["description"] = json!("nightly");
    full["max_records"] = json!(MAX_REPLAY_RECORDS);
    full["idempotency_key"] = json!("nightly.2027-01-15:a_b");
    full["window"] = json!({ "from": "2027-01-15T08:00:00+01:00" });
    full["candidate"] = json!({ "source": "edits", "edits": [
        { "op": "insert", "section": "rules", "position": 0, "value": { "id": "n", "path": "/n", "action": "deny" } },
        { "op": "set", "field": "default_action", "value": "allow" }
    ] });
    accepted.push(full);
    let mut inline = request_document();
    inline["candidate"] = json!({ "source": "inline", "policy": policy_document() });
    accepted.push(inline);
    for request in &accepted {
        assert!(parse(request).is_ok(), "parser: {request}");
        if let Err(error) = validator.validate(request) {
            panic!("the schema refuses a request the parser accepts: {error}");
        }
    }

    let mut refusals = Vec::new();
    for mutate in [
        (|document: &mut Value| document["schema_version"] = json!("policy-replay.v2"))
            as fn(&mut Value),
        |document| {
            document
                .as_object_mut()
                .expect("object")
                .remove("base_etag");
        },
        |document| {
            document.as_object_mut().expect("object").remove("window");
        },
        |document| {
            document["window"]
                .as_object_mut()
                .expect("object")
                .remove("from");
        },
        |document| document["window"]["until"] = json!("2027-01-15T08:00:00Z"),
        |document| document["token"] = json!("x"),
        |document| document["max_records"] = json!(0),
        |document| document["max_records"] = json!(MAX_REPLAY_RECORDS + 1),
        |document| document["idempotency_key"] = json!("has space"),
        |document| document["idempotency_key"] = json!(""),
        |document| document["candidate"] = json!({ "source": "draft" }),
        |document| document["candidate"] = json!({ "source": "edits", "edits": [] }),
        |document| document["projections"] = json!(["as_authored"]),
    ] {
        let mut document = request_document();
        mutate(&mut document);
        refusals.push(document);
    }
    for request in refusals {
        assert!(parse(&request).is_err(), "parser: {request}");
        assert!(!validator.is_valid(&request), "schema: {request}");
    }
}
