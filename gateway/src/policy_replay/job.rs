//! The bounded replay job engine (issue #243, slice 13): decide one window of
//! retained audit records again, under a candidate policy, through the shared
//! policy kernel.
//!
//! [`run`] is the whole engine. It reads the pages of the source window a job
//! was pinned to, oldest first; reads each stored event through
//! [`legacy::adapt_audit_event`]; decides every replayable context with the
//! functions in [`evaluate`], which build the kernel's own contexts and call
//! [`CompiledPolicy`]; and folds every answer into counts keyed by stable
//! codes. Nothing in it matches a rule, a route or a tool entry itself.
//!
//! ## Bounds
//!
//! - **Records.** At most [`MAX_REPLAY_RECORDS`] rows per job, and fewer when
//!   the job asks. A window holding more stops at the bound and says
//!   `scan_truncated`.
//! - **Time.** A deadline, checked before every record. A run that reaches it
//!   stops and says `deadline_exceeded`.
//! - **Memory.** One page at a time: at most [`REPLAY_PAGE_RECORDS`] rows and
//!   [`MAX_REPLAY_PAGE_BYTES`] of their JSON past the first row. A row larger
//!   than [`MAX_REPLAY_RECORD_BYTES`] is counted as `oversized_record` without
//!   its JSON ever being read. The result is counts keyed by codes from closed
//!   sets, so it does not grow with the window.
//!
//! A stopped run is still a result -- an incomplete one, whose counts cover the
//! records it read -- never a failure and never a complete answer.
//!
//! ## Determinism
//!
//! The window, the cutoff and the record bound fix which rows a run reads and
//! in which order; every count is keyed by a stable code and rendered sorted;
//! and the result digest is the ADR-0004 semantic digest of the rendered
//! result. Two complete runs over the same cutoff and policy therefore produce
//! byte-identical results, whatever the machine or its load. A run stopped by
//! its deadline is the one exception, and says so.
//!
//! ## No side effects
//!
//! Apart from reading its source, a run is pure: it writes nothing, emits no
//! audit event or metric, reads or charges no rate bucket, acquires no tool
//! permit, resolves no name and contacts no upstream. The admin endpoint runs
//! it on a blocking thread and records the job's own lifecycle events around
//! it; those are the only records a job leaves.

use std::{
    collections::BTreeMap,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    time::{Duration, Instant},
};

use serde_json::{json, Map, Value};

use super::{
    evaluate::{evaluate_http, evaluate_tool, select_rate_lane, HttpReplayOutcome},
    legacy::{adapt_audit_event, LegacyRecord},
    EgressRecord, ReplayFacts,
};
use crate::{
    audit::query::{AuditQueryStore, ReplayCutoff, ReplayPageQuery, ReplayRow},
    canonical_json,
    policy_eval::{CompiledPolicy, EvaluationError, LogicalDecision, RateLaneOutcome},
    policy_simulation::run::enforcement_and_effect,
    policy_testing::runner::{evaluation_error_code, logical_code, tool_limitation_code},
};

/// The schema of a job's result document.
pub(crate) const RESULT_SCHEMA_VERSION: &str = "policy-replay-results.v1";
/// The media type the result digest is framed with.
pub(crate) const RESULT_MEDIA_TYPE: &str =
    "application/vnd.greengateway.policy-replay-results+json";
/// The compile-time ceiling on the rows one job reads: the 100,000-row audit
/// scan ceiling every other audit-derived policy view keeps. A job may ask
/// for fewer, never more.
pub(crate) const MAX_REPLAY_RECORDS: usize = 100_000;
/// Most rows one page holds.
pub(crate) const REPLAY_PAGE_RECORDS: usize = 500;
/// Most actor and payload JSON bytes one page holds past its first row.
pub(crate) const MAX_REPLAY_PAGE_BYTES: usize = 4 * 1024 * 1024;
/// Largest actor-plus-payload JSON read for one row. Twice the largest
/// replay context: an audit record the gateway writes is far smaller, so a
/// larger one is not a record it wrote.
pub(crate) const MAX_REPLAY_RECORD_BYTES: usize = 256 * 1024;
/// The wall-clock bound on one run.
pub(crate) const REPLAY_RUN_DEADLINE: Duration = Duration::from_secs(60);
/// Stages a replayed decision does not include: the ones outside the policy
/// verdict, which retained records cannot reconstruct.
pub(crate) const NOT_REPLAYED: &[&str] = &[
    "authentication",
    "request_admission",
    "rate_capacity",
    "tool_leases",
    "egress",
    "transport",
    "upstream",
];

/// What one job reads: the window, the cutoff fixed when it was created, and
/// its record bound.
#[derive(Clone, Debug)]
pub(crate) struct ReplayScope {
    /// The window's bounds as the job states them (RFC 3339, UTC).
    pub(crate) from: String,
    pub(crate) to: String,
    /// The same bounds as audit epoch microseconds: `[from, to)`.
    pub(crate) from_epoch_us: i64,
    pub(crate) to_epoch_us: i64,
    pub(crate) cutoff: ReplayCutoff,
    pub(crate) max_records: usize,
}

/// The source refused a read. Opaque: the cause is logged where it happened
/// and never reaches a result.
#[derive(Debug)]
pub(crate) struct ReplaySourceError;

/// Where a run reads its records from: the standalone audit log, or a test's
/// rows.
pub(crate) trait ReplaySource {
    /// One page; see [`AuditQueryStore::replay_page`].
    fn page(&self, query: &ReplayPageQuery) -> Result<Vec<(i64, ReplayRow)>, ReplaySourceError>;
    /// How many rows of the scope's window at or below its cutoff are stored
    /// now.
    fn window_count(&self, scope: &ReplayScope) -> Result<u64, ReplaySourceError>;
}

impl ReplaySource for AuditQueryStore {
    fn page(&self, query: &ReplayPageQuery) -> Result<Vec<(i64, ReplayRow)>, ReplaySourceError> {
        self.replay_page(query).map_err(|error| {
            tracing::error!(error = %error, "policy replay could not read an audit page");
            ReplaySourceError
        })
    }

    fn window_count(&self, scope: &ReplayScope) -> Result<u64, ReplaySourceError> {
        self.replay_window_count(
            scope.from_epoch_us,
            scope.to_epoch_us,
            scope.cutoff.high_water,
        )
        .map_err(|error| {
            tracing::error!(error = %error, "policy replay could not count its audit window");
            ReplaySourceError
        })
    }
}

/// What a run and its job share: the cancellation request and the progress
/// counter. Both are plain atomics, so reading progress never waits on the
/// run and cancelling never blocks.
#[derive(Debug, Default)]
pub(crate) struct ReplayControl {
    cancelled: AtomicBool,
    scanned: AtomicU64,
}

impl ReplayControl {
    /// Ask the run to stop. It stops before its next record.
    pub(crate) fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    /// Records read so far.
    pub(crate) fn scanned(&self) -> u64 {
        self.scanned.load(Ordering::Relaxed)
    }
}

/// Why a run produced no result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReplayStop {
    /// The job was cancelled.
    Cancelled,
    /// The run could not be completed honestly, with a stable code. No part
    /// of it is an answer.
    Failed(&'static str),
}

/// A run that read its window, or as much of it as its bounds allowed.
#[derive(Debug)]
pub(crate) struct ReplayOutcome {
    /// Every row the cutoff selected was read, the window was unchanged
    /// when the run ended, and at least one record was replayed.
    pub(crate) complete: bool,
    pub(crate) limitations: Vec<&'static str>,
    pub(crate) scanned: u64,
    pub(crate) replayed: u64,
    /// The `policy-replay-results.v1` document.
    pub(crate) result: Value,
    /// Its ADR-0004 semantic digest.
    pub(crate) digest: String,
}

/// Counts for one lane: how its replayable records were answered.
#[derive(Default)]
struct LaneTally {
    replayable: u64,
    /// `(logical, enforcement, effective_action, reason)`.
    decided: BTreeMap<(&'static str, &'static str, &'static str, &'static str), u64>,
    indeterminate: BTreeMap<&'static str, u64>,
    /// Records whose facts the kernel refused: not records a served request
    /// could have left.
    refused: BTreeMap<&'static str, u64>,
    /// Contexts that state an egress destination, which a job does not
    /// replay. The legacy adapters never record one.
    egress_not_replayed: u64,
}

impl LaneTally {
    fn decided_count(&self) -> u64 {
        self.decided.values().sum()
    }

    fn indeterminate_count(&self) -> u64 {
        self.indeterminate.values().sum()
    }

    fn render(&self) -> Value {
        let outcomes = self
            .decided
            .iter()
            .map(
                |((logical, enforcement, effective_action, reason), count)| {
                    json!({
                        "logical": logical,
                        "enforcement": enforcement,
                        "effective_action": effective_action,
                        "reason": reason,
                        "count": count,
                    })
                },
            )
            .collect::<Vec<_>>();
        json!({
            "replayable": self.replayable,
            "decided": self.decided_count(),
            "indeterminate": self.indeterminate_count(),
            "refused": self.refused.values().sum::<u64>(),
            "outcomes": outcomes,
            "limitations": self.indeterminate,
            "refusals": self.refused,
            "egress_not_replayed": self.egress_not_replayed,
        })
    }
}

/// Rate-lane selection for the HTTP records: which override the candidate
/// would select. Selection only; capacity is never reconstructed.
#[derive(Default)]
struct RateTally {
    no_override: u64,
    overrides: u64,
    indeterminate: BTreeMap<&'static str, u64>,
    refused: BTreeMap<&'static str, u64>,
}

impl RateTally {
    fn render(&self) -> Value {
        json!({
            "no_override": self.no_override,
            "override": self.overrides,
            "indeterminate": self.indeterminate.values().sum::<u64>(),
            "refused": self.refused.values().sum::<u64>(),
            "limitations": self.indeterminate,
            "refusals": self.refused,
        })
    }
}

/// Every count a run keeps. Keys come from closed sets of stable codes, so
/// the tally's size is bounded by the codes, not by the window.
#[derive(Default)]
struct Tally {
    scanned: u64,
    by_code: BTreeMap<&'static str, u64>,
    replayable: u64,
    duplicate: u64,
    not_policy_evaluated: u64,
    unsupported: u64,
    malformed: u64,
    not_request_record: u64,
    unreadable: u64,
    oversized: u64,
    http: LaneTally,
    rate: RateTally,
    tool: LaneTally,
}

/// An evaluator error, sorted into the two answers a run gives one: the
/// record's facts were refused (a stable code, counted), or the run itself
/// is broken (`None`: the job fails, and nothing it counted is an answer).
///
/// Exhaustive on purpose: a new error is a decision this function must make.
fn refusal_code(error: EvaluationError) -> Option<&'static str> {
    match error {
        EvaluationError::MalformedPath
        | EvaluationError::ContextTooLarge
        | EvaluationError::InvalidPrincipal
        | EvaluationError::InvalidHost
        | EvaluationError::InconsistentContext => Some(evaluation_error_code(error)),
        EvaluationError::UnsupportedContextVersion
        | EvaluationError::SnapshotMismatch
        | EvaluationError::InternalInvariant
        | EvaluationError::TraceEncoding
        | EvaluationError::TraceTooLarge => None,
    }
}

const EVALUATOR_FAILED: ReplayStop = ReplayStop::Failed("evaluator_failed");

impl Tally {
    fn count(&mut self, code: &'static str) {
        *self.by_code.entry(code).or_default() += 1;
    }

    fn observe(&mut self, policy: &CompiledPolicy, row: &ReplayRow) -> Result<(), ReplayStop> {
        self.scanned += 1;
        let event = match row {
            ReplayRow::Event(event) => event,
            ReplayRow::Unreadable => {
                self.unreadable += 1;
                self.count("unreadable_record");
                return Ok(());
            }
            ReplayRow::Oversized => {
                self.oversized += 1;
                self.count("oversized_record");
                return Ok(());
            }
        };
        let record = adapt_audit_event(event);
        self.count(record.code());
        match record {
            LegacyRecord::Replayable(context) => {
                self.replayable += 1;
                match &context.facts {
                    ReplayFacts::Http(facts) => {
                        self.http.replayable += 1;
                        if matches!(facts.egress, EgressRecord::Destination(_)) {
                            self.http.egress_not_replayed += 1;
                        }
                        self.decide_http(policy, facts)?;
                        self.select_rate(policy, facts)?;
                    }
                    ReplayFacts::Tool(facts) => {
                        self.tool.replayable += 1;
                        if matches!(facts.egress, EgressRecord::Destination(_)) {
                            self.tool.egress_not_replayed += 1;
                        }
                        self.decide_tool(policy, facts)?;
                    }
                }
            }
            LegacyRecord::Duplicate(_) => self.duplicate += 1,
            LegacyRecord::NotPolicyEvaluated => self.not_policy_evaluated += 1,
            LegacyRecord::Unsupported(_) => self.unsupported += 1,
            LegacyRecord::Malformed(_) => self.malformed += 1,
            LegacyRecord::NotRequestRecord => self.not_request_record += 1,
        }
        Ok(())
    }

    fn decide_http(
        &mut self,
        policy: &CompiledPolicy,
        facts: &super::HttpFacts,
    ) -> Result<(), ReplayStop> {
        match evaluate_http(policy, facts) {
            Ok(HttpReplayOutcome::Decided(decision)) => {
                let (enforcement, effective_action) =
                    enforcement_and_effect(decision.logical, decision.effect);
                *self
                    .http
                    .decided
                    .entry((
                        logical_code(decision.logical),
                        enforcement,
                        effective_action,
                        decision.reason.as_str(),
                    ))
                    .or_default() += 1;
            }
            Ok(HttpReplayOutcome::Indeterminate(limitation)) => {
                *self
                    .http
                    .indeterminate
                    .entry(limitation.as_str())
                    .or_default() += 1;
            }
            Err(error) => {
                let code = refusal_code(error).ok_or(EVALUATOR_FAILED)?;
                *self.http.refused.entry(code).or_default() += 1;
            }
        }
        Ok(())
    }

    fn select_rate(
        &mut self,
        policy: &CompiledPolicy,
        facts: &super::HttpFacts,
    ) -> Result<(), ReplayStop> {
        match select_rate_lane(policy, facts) {
            Ok(selection) => match selection.outcome() {
                RateLaneOutcome::NoOverride => self.rate.no_override += 1,
                RateLaneOutcome::Override { .. } => self.rate.overrides += 1,
                RateLaneOutcome::Indeterminate(limitation) => {
                    *self
                        .rate
                        .indeterminate
                        .entry(limitation.as_str())
                        .or_default() += 1;
                }
            },
            Err(error) => {
                let code = refusal_code(error).ok_or(EVALUATOR_FAILED)?;
                *self.rate.refused.entry(code).or_default() += 1;
            }
        }
        Ok(())
    }

    fn decide_tool(
        &mut self,
        policy: &CompiledPolicy,
        facts: &super::ToolFacts,
    ) -> Result<(), ReplayStop> {
        let evaluation = match evaluate_tool(policy, facts) {
            Ok(evaluation) => evaluation,
            Err(error) => {
                let code = refusal_code(error).ok_or(EVALUATOR_FAILED)?;
                *self.tool.refused.entry(code).or_default() += 1;
                return Ok(());
            }
        };
        if !evaluation.is_complete() || evaluation.logical() == LogicalDecision::Indeterminate {
            // An unanswered evaluation always names what it lacked; one that
            // does not is the kernel breaking its own contract.
            let limitation = evaluation.limitation().ok_or(EVALUATOR_FAILED)?;
            *self
                .tool
                .indeterminate
                .entry(tool_limitation_code(limitation))
                .or_default() += 1;
            return Ok(());
        }
        let (enforcement, effective_action) =
            enforcement_and_effect(evaluation.logical(), evaluation.effect());
        *self
            .tool
            .decided
            .entry((
                logical_code(evaluation.logical()),
                enforcement,
                effective_action,
                evaluation.reason().as_str(),
            ))
            .or_default() += 1;
        Ok(())
    }

    /// Records the candidate answered, decided or indeterminate.
    fn replayed(&self) -> u64 {
        self.http.decided_count()
            + self.http.indeterminate_count()
            + self.tool.decided_count()
            + self.tool.indeterminate_count()
    }

    fn render(&self, scope: &ReplayScope, complete: bool, limitations: &[&'static str]) -> Value {
        let mut records = Map::new();
        records.insert("selected".to_owned(), json!(scope.cutoff.selected));
        records.insert("scanned".to_owned(), json!(self.scanned));
        records.insert("replayable".to_owned(), json!(self.replayable));
        records.insert("duplicate".to_owned(), json!(self.duplicate));
        records.insert(
            "not_policy_evaluated".to_owned(),
            json!(self.not_policy_evaluated),
        );
        records.insert("unsupported".to_owned(), json!(self.unsupported));
        records.insert("malformed".to_owned(), json!(self.malformed));
        records.insert(
            "not_request_record".to_owned(),
            json!(self.not_request_record),
        );
        records.insert("unreadable".to_owned(), json!(self.unreadable));
        records.insert("oversized".to_owned(), json!(self.oversized));
        records.insert("by_code".to_owned(), json!(self.by_code));
        json!({
            "schema_version": RESULT_SCHEMA_VERSION,
            "mode": "historical_replay",
            "complete": complete,
            "limitations": limitations,
            "source": {
                "kind": "standalone_audit_log",
                "window": { "from": scope.from, "to": scope.to },
                "high_water": scope.cutoff.high_water,
                "max_records": scope.max_records,
            },
            "records": Value::Object(records),
            "replayed": {
                "total": self.replayed(),
                "http": self.http.render(),
                "rate": self.rate.render(),
                "tool": self.tool.render(),
            },
            "not_replayed": NOT_REPLAYED,
        })
    }
}

/// Run one job: read `scope` from `source`, oldest first, and decide every
/// replayable record under `policy`.
///
/// Stops before the next record when `control` is cancelled
/// ([`ReplayStop::Cancelled`]), and fails on a source read or an evaluator
/// invariant failure ([`ReplayStop::Failed`]); neither returns any count as
/// an answer. Reaching the record bound or `deadline` ends the scan with an
/// incomplete result. A window whose stored rows no longer match the cutoff's
/// count when the run ends -- rows pruned by retention while it ran -- is
/// incomplete with `source_changed`, never a silent omission.
pub(crate) fn run(
    source: &dyn ReplaySource,
    policy: &CompiledPolicy,
    scope: &ReplayScope,
    deadline: Instant,
    control: &ReplayControl,
) -> Result<ReplayOutcome, ReplayStop> {
    let mut tally = Tally::default();
    let max_records = scope.max_records.min(MAX_REPLAY_RECORDS);
    let mut deadline_exceeded = false;
    if let (Some(first_id), Some(last_id)) = (scope.cutoff.first_id, scope.cutoff.last_id) {
        let mut query = ReplayPageQuery {
            from_epoch_us: scope.from_epoch_us,
            to_epoch_us: scope.to_epoch_us,
            after_id: first_id.saturating_sub(1),
            through_id: last_id.min(scope.cutoff.high_water),
            limit: REPLAY_PAGE_RECORDS,
            max_record_bytes: MAX_REPLAY_RECORD_BYTES,
            max_page_bytes: MAX_REPLAY_PAGE_BYTES,
        };
        'pages: loop {
            let remaining =
                max_records.saturating_sub(usize::try_from(tally.scanned).unwrap_or(usize::MAX));
            if remaining == 0 {
                break;
            }
            if control.is_cancelled() {
                return Err(ReplayStop::Cancelled);
            }
            query.limit = remaining.min(REPLAY_PAGE_RECORDS);
            let page = source
                .page(&query)
                .map_err(|_| ReplayStop::Failed("source_unavailable"))?;
            if page.is_empty() {
                break;
            }
            for (id, row) in &page {
                if control.is_cancelled() {
                    return Err(ReplayStop::Cancelled);
                }
                if Instant::now() >= deadline {
                    deadline_exceeded = true;
                    break 'pages;
                }
                // Rows come back in id order inside the page's bounds; one
                // that does not is not the page that was asked for.
                if *id <= query.after_id || *id > query.through_id {
                    return Err(ReplayStop::Failed("source_unavailable"));
                }
                tally.observe(policy, row)?;
                query.after_id = *id;
                control.scanned.store(tally.scanned, Ordering::Relaxed);
            }
        }
    }
    if control.is_cancelled() {
        return Err(ReplayStop::Cancelled);
    }
    let mut limitations = Vec::new();
    if deadline_exceeded {
        limitations.push("deadline_exceeded");
    } else if tally.scanned < scope.cutoff.selected
        && usize::try_from(tally.scanned).unwrap_or(usize::MAX) >= max_records
    {
        limitations.push("scan_truncated");
    }
    // Rows that vanished from the window, or a scan that read a different
    // number of rows than the cutoff selected, mean the source changed under
    // the job: the result cannot claim to cover the snapshot it was pinned to.
    let stored = source
        .window_count(scope)
        .map_err(|_| ReplayStop::Failed("source_unavailable"))?;
    let scan_ended_naturally = limitations.is_empty();
    if stored != scope.cutoff.selected
        || (scan_ended_naturally && tally.scanned != scope.cutoff.selected)
    {
        limitations.push("source_changed");
    }
    let replayed = tally.replayed();
    if replayed == 0 {
        limitations.push("no_data");
    }
    limitations.sort_unstable();
    let complete = limitations.is_empty();
    let result = tally.render(scope, complete, &limitations);
    let digest = canonical_json::semantic_digest(RESULT_MEDIA_TYPE, RESULT_SCHEMA_VERSION, &result)
        .map_err(|_| ReplayStop::Failed("result_digest_failed"))?;
    Ok(ReplayOutcome {
        complete,
        limitations,
        scanned: tally.scanned,
        replayed,
        result,
        digest,
    })
}
