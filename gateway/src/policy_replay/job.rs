//! The bounded replay job engine (issue #243, slice 13): decide one window of
//! retained audit records again, under a candidate policy, through the shared
//! policy kernel.
//!
//! [`run`] is the whole engine. It reads the pages of the source window a job
//! was pinned to, oldest first; reads each stored event through
//! [`legacy::adapt_audit_event`]; decides every replayable context with the
//! functions in [`super::evaluate`], which build the kernel's own contexts and
//! call [`crate::policy_eval::CompiledPolicy`], under the candidate and the
//! base it was written against ([`super::impact`]); and folds every answer
//! into counts keyed by stable codes. Nothing in it matches a rule, a route or
//! a tool entry itself.
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
//! ## Checkpoints
//!
//! A cluster job ([`run_resumable`]) is handed a [`ReplayCheckpoints`] sink.
//! After every whole page the run gives it the stream position it has read
//! through and its partial aggregate, the lossless
//! [`super::checkpoint`] dump of every count it keeps; the sink stores both
//! in one fenced statement or stops the run. A run started from a checkpoint
//! restores that aggregate and reads on from the position after it, so a job
//! taken over by another replica counts every record exactly once: the page
//! a lost lease interrupted was never checkpointed, and is read again whole.
//! The deadline is the job's, not the run's: a resumed run gets what is left
//! of it.
//!
//! ## Determinism
//!
//! The window, the cutoff and the record bound fix which rows a run reads and
//! in which order; every count is keyed by a stable code and rendered sorted;
//! and the result digest is the ADR-0004 semantic digest of the rendered
//! result. Two complete runs over the same cutoff and policies therefore
//! produce byte-identical results, whatever the machine or its load. A run
//! stopped by its deadline is the one exception, and says so.
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
    checkpoint::{self, CheckpointError, Restored, CHECKPOINT_SCHEMA_VERSION},
    impact::{Answer, ImpactTally, RateAnswer, ReplayPolicies},
    legacy::{adapt_audit_event, LegacyRecord},
    EgressRecord, ReplayFacts,
};
use crate::{
    audit::query::{AuditQueryStore, ReplayCutoff, ReplayPageQuery, ReplayRow},
    canonical_json,
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
/// Largest serialized checkpoint a run hands its sink. A checkpoint holds
/// every count the run keeps, without a result's row caps, so it can be
/// larger than any result; one past this bound fails the job
/// (`checkpoint_too_large`) rather than storing an unbounded document.
pub(crate) const MAX_REPLAY_CHECKPOINT_BYTES: usize = 4 * 1024 * 1024;
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

/// What a source holds of a job's window when the run ends
/// ([`ReplaySource::check`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ReplaySourceCheck {
    /// Rows of the window at or below the cutoff stored now.
    pub(crate) stored: u64,
    /// Rows at or below the cutoff that the window may have held are gone:
    /// retention reached past the window's start, or the source has a gap
    /// inside it. A source that cannot tell says `false`, and its result
    /// relies on [`Self::stored`] alone.
    pub(crate) pruned: bool,
}

/// Where a run reads its records from: the standalone audit log, the
/// cluster's audit stream (`storage::postgres_audit_replay`), or a test's
/// rows.
pub(crate) trait ReplaySource {
    /// How a result names this source: its `source.kind`.
    fn kind(&self) -> &'static str;
    /// One page; see [`AuditQueryStore::replay_page`].
    fn page(&self, query: &ReplayPageQuery) -> Result<Vec<(i64, ReplayRow)>, ReplaySourceError>;
    /// What the source holds of the scope's window now.
    fn check(&self, scope: &ReplayScope) -> Result<ReplaySourceCheck, ReplaySourceError>;
}

impl ReplaySource for AuditQueryStore {
    fn kind(&self) -> &'static str {
        "standalone_audit_log"
    }

    fn page(&self, query: &ReplayPageQuery) -> Result<Vec<(i64, ReplayRow)>, ReplaySourceError> {
        self.replay_page(query).map_err(|error| {
            tracing::error!(error = %error, "policy replay could not read an audit page");
            ReplaySourceError
        })
    }

    /// The standalone log keeps no record of what retention removed, so it
    /// reports only how many of the window's rows are still stored; rows
    /// pruned before the job was created are simply not in its cutoff.
    fn check(&self, scope: &ReplayScope) -> Result<ReplaySourceCheck, ReplaySourceError> {
        let stored = self
            .replay_window_count(
                scope.from_epoch_us,
                scope.to_epoch_us,
                scope.cutoff.high_water,
            )
            .map_err(|error| {
                tracing::error!(error = %error, "policy replay could not count its audit window");
                ReplaySourceError
            })?;
        Ok(ReplaySourceCheck {
            stored,
            pruned: false,
        })
    }
}

/// What a run and its job share: the cancellation request, the release
/// request and the progress counter. All are plain atomics, so reading
/// progress never waits on the run and stopping it never blocks.
#[derive(Debug, Default)]
pub(crate) struct ReplayControl {
    cancelled: AtomicBool,
    released: AtomicBool,
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

    /// Ask the run to give its job up without an answer: its replica is
    /// shutting down, or no longer holds the job's lease. It stops before its
    /// next record with [`ReplayStop::Released`], and the job's last
    /// checkpoint stands for whoever resumes it.
    pub(crate) fn release(&self) {
        self.released.store(true, Ordering::Release);
    }

    /// Why the run must stop before its next record, if it must. A release
    /// wins over a cancellation: a run that no longer holds its job does not
    /// decide how the job ends.
    fn stop_requested(&self) -> Option<ReplayStop> {
        if self.released.load(Ordering::Acquire) {
            Some(ReplayStop::Released)
        } else if self.is_cancelled() {
            Some(ReplayStop::Cancelled)
        } else {
            None
        }
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
    /// The run gave its job up without ending it: its lease was lost or its
    /// replica is shutting down ([`ReplayControl::release`]). It records
    /// nothing; the job's last checkpoint stands, and the replica that holds
    /// the job next resumes from it. Only cluster jobs are released.
    Released,
}

/// Where a cluster job stores its progress, page by page.
pub(crate) trait ReplayCheckpoints {
    /// Every row through stream position `after_id` is folded into
    /// `checkpoint`, the run's whole partial aggregate (`scanned` rows so
    /// far). Store both atomically, or stop the run: [`ReplayStop::Cancelled`]
    /// when the job's cancellation was requested, [`ReplayStop::Released`]
    /// when this run no longer holds the job, [`ReplayStop::Failed`] when the
    /// checkpoint cannot be stored.
    fn page_done(&self, after_id: i64, scanned: u64, checkpoint: &Value) -> Result<(), ReplayStop>;
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
    /// The impact comparison's counts per projection, for the job's
    /// completion record: codes and counts only.
    pub(crate) impact: Value,
}

/// `(logical, enforcement, effective_action, reason)`.
type DecidedKey<'a> = (&'a str, &'a str, &'a str, &'a str);

/// Counts for one lane: how its replayable records were answered.
#[derive(Default)]
struct LaneTally<'a> {
    replayable: u64,
    decided: BTreeMap<DecidedKey<'a>, u64>,
    indeterminate: BTreeMap<&'a str, u64>,
    /// Records whose facts the kernel refused: not records a served request
    /// could have left.
    refused: BTreeMap<&'a str, u64>,
    /// Contexts that state an egress destination, which a job does not
    /// replay. The legacy adapters never record one.
    egress_not_replayed: u64,
}

impl<'a> LaneTally<'a> {
    /// Count the candidate's answer for one replayable record.
    fn add(&mut self, answer: Answer) {
        match answer {
            Answer::Decided(decided) => {
                let state = decided.state();
                *self
                    .decided
                    .entry((
                        state.logical,
                        state.enforcement,
                        state.effective_action,
                        state.reason,
                    ))
                    .or_default() += 1;
            }
            Answer::Indeterminate(limitation) => {
                *self.indeterminate.entry(limitation).or_default() += 1;
            }
            Answer::Refused(code) => *self.refused.entry(code).or_default() += 1,
        }
    }

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

    fn dump(&self) -> Value {
        let decided = self
            .decided
            .iter()
            .map(
                |((logical, enforcement, effective_action, reason), count)| {
                    json!([logical, enforcement, effective_action, reason, count])
                },
            )
            .collect::<Vec<_>>();
        json!({
            "replayable": self.replayable,
            "decided": decided,
            "indeterminate": self.indeterminate,
            "refused": self.refused,
            "egress_not_replayed": self.egress_not_replayed,
        })
    }

    fn restore(value: &'a Value) -> Restored<Self> {
        let object = checkpoint::exact_object(
            value,
            &[
                "replayable",
                "decided",
                "indeterminate",
                "refused",
                "egress_not_replayed",
            ],
        )?;
        let mut decided = BTreeMap::new();
        for row in checkpoint::array(checkpoint::member(object, "decided")?)? {
            let [logical, enforcement, effective_action, reason, count] = checkpoint::tuple(row)?;
            checkpoint::insert(
                &mut decided,
                (
                    checkpoint::code(logical)?,
                    checkpoint::code(enforcement)?,
                    checkpoint::code(effective_action)?,
                    checkpoint::code(reason)?,
                ),
                count,
            )?;
        }
        Ok(Self {
            replayable: checkpoint::total(checkpoint::member(object, "replayable")?)?,
            decided,
            indeterminate: checkpoint::restore_codes(checkpoint::member(object, "indeterminate")?)?,
            refused: checkpoint::restore_codes(checkpoint::member(object, "refused")?)?,
            egress_not_replayed: checkpoint::total(checkpoint::member(
                object,
                "egress_not_replayed",
            )?)?,
        })
    }
}

/// Rate-lane selection for the HTTP records: which override the candidate
/// would select. Selection only; capacity is never reconstructed.
#[derive(Default)]
struct RateTally<'a> {
    no_override: u64,
    overrides: u64,
    indeterminate: BTreeMap<&'a str, u64>,
    refused: BTreeMap<&'a str, u64>,
}

impl<'a> RateTally<'a> {
    /// Count the candidate's selection for one replayable HTTP record.
    fn add(&mut self, answer: RateAnswer) {
        match answer {
            RateAnswer::NoOverride => self.no_override += 1,
            RateAnswer::Override { .. } => self.overrides += 1,
            RateAnswer::Indeterminate(limitation) => {
                *self.indeterminate.entry(limitation).or_default() += 1;
            }
            RateAnswer::Refused(code) => *self.refused.entry(code).or_default() += 1,
        }
    }

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

    fn dump(&self) -> Value {
        json!({
            "no_override": self.no_override,
            "override": self.overrides,
            "indeterminate": self.indeterminate,
            "refused": self.refused,
        })
    }

    fn restore(value: &'a Value) -> Restored<Self> {
        let object = checkpoint::exact_object(
            value,
            &["no_override", "override", "indeterminate", "refused"],
        )?;
        Ok(Self {
            no_override: checkpoint::total(checkpoint::member(object, "no_override")?)?,
            overrides: checkpoint::total(checkpoint::member(object, "override")?)?,
            indeterminate: checkpoint::restore_codes(checkpoint::member(object, "indeterminate")?)?,
            refused: checkpoint::restore_codes(checkpoint::member(object, "refused")?)?,
        })
    }
}

/// Every count a run keeps. Keys come from closed sets of stable codes, and
/// the impact comparison's from element pairs of the policies, so the tally's
/// size is bounded by the codes and the policies, not by the window.
struct Tally<'a> {
    scanned: u64,
    by_code: BTreeMap<&'a str, u64>,
    replayable: u64,
    duplicate: u64,
    not_policy_evaluated: u64,
    unsupported: u64,
    malformed: u64,
    not_request_record: u64,
    unreadable: u64,
    oversized: u64,
    http: LaneTally<'a>,
    rate: RateTally<'a>,
    tool: LaneTally<'a>,
    impact: ImpactTally<'a>,
}

/// The record counters of a [`Tally`], as a checkpoint names them.
const RECORD_COUNTERS: [&str; 9] = [
    "scanned",
    "replayable",
    "duplicate",
    "not_policy_evaluated",
    "unsupported",
    "malformed",
    "not_request_record",
    "unreadable",
    "oversized",
];

impl<'a> Tally<'a> {
    fn new(policies: &ReplayPolicies) -> Self {
        Self {
            scanned: 0,
            by_code: BTreeMap::new(),
            replayable: 0,
            duplicate: 0,
            not_policy_evaluated: 0,
            unsupported: 0,
            malformed: 0,
            not_request_record: 0,
            unreadable: 0,
            oversized: 0,
            http: LaneTally::default(),
            rate: RateTally::default(),
            tool: LaneTally::default(),
            impact: ImpactTally::new(policies),
        }
    }

    fn count(&mut self, code: &'static str) {
        *self.by_code.entry(code).or_default() += 1;
    }

    fn record_counters(&self) -> [u64; 9] {
        [
            self.scanned,
            self.replayable,
            self.duplicate,
            self.not_policy_evaluated,
            self.unsupported,
            self.malformed,
            self.not_request_record,
            self.unreadable,
            self.oversized,
        ]
    }

    /// The `policy-replay-checkpoint.v1` document for this tally, read
    /// through stream position `after_id`.
    fn checkpoint(&self, after_id: i64) -> Value {
        let mut records = Map::new();
        for (name, value) in RECORD_COUNTERS.iter().zip(self.record_counters()) {
            records.insert((*name).to_owned(), json!(value));
        }
        records.insert("by_code".to_owned(), json!(self.by_code));
        json!({
            "schema_version": CHECKPOINT_SCHEMA_VERSION,
            "after_id": after_id,
            "records": Value::Object(records),
            "http": self.http.dump(),
            "rate": self.rate.dump(),
            "tool": self.tool.dump(),
            "impact": self.impact.dump(),
        })
    }

    /// The tally a checkpoint of a run over `policies` describes, and the
    /// stream position it was read through. Refused whole when it is not
    /// exactly such a checkpoint ([`super::checkpoint`]).
    fn restore(policies: &ReplayPolicies, value: &'a Value) -> Restored<(Self, i64)> {
        let object = checkpoint::exact_object(
            value,
            &[
                "schema_version",
                "after_id",
                "records",
                "http",
                "rate",
                "tool",
                "impact",
            ],
        )?;
        if checkpoint::member(object, "schema_version")?.as_str() != Some(CHECKPOINT_SCHEMA_VERSION)
        {
            return Err(CheckpointError);
        }
        let after_id = checkpoint::member(object, "after_id")?
            .as_i64()
            .ok_or(CheckpointError)?;
        let mut record_members = RECORD_COUNTERS.to_vec();
        record_members.push("by_code");
        let records =
            checkpoint::exact_object(checkpoint::member(object, "records")?, &record_members)?;
        let mut counters = [0_u64; 9];
        for (slot, name) in counters.iter_mut().zip(RECORD_COUNTERS) {
            *slot = checkpoint::total(checkpoint::member(records, name)?)?;
        }
        let [scanned, replayable, duplicate, not_policy_evaluated, unsupported, malformed, not_request_record, unreadable, oversized] =
            counters;
        let tally = Self {
            scanned,
            by_code: checkpoint::restore_codes(checkpoint::member(records, "by_code")?)?,
            replayable,
            duplicate,
            not_policy_evaluated,
            unsupported,
            malformed,
            not_request_record,
            unreadable,
            oversized,
            http: LaneTally::restore(checkpoint::member(object, "http")?)?,
            rate: RateTally::restore(checkpoint::member(object, "rate")?)?,
            tool: LaneTally::restore(checkpoint::member(object, "tool")?)?,
            impact: ImpactTally::restore(policies, checkpoint::member(object, "impact")?)?,
        };
        // Every record read is counted under exactly one adapter code.
        if tally.by_code.values().sum::<u64>() != tally.scanned {
            return Err(CheckpointError);
        }
        Ok((tally, after_id))
    }

    fn observe(&mut self, policies: &ReplayPolicies, row: &ReplayRow) -> Result<(), ReplayStop> {
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
                        let answer =
                            self.impact
                                .observe_http(policies, facts, &context.recorded)?;
                        self.http.add(answer);
                        let selection = self.impact.observe_rate(policies, facts)?;
                        self.rate.add(selection);
                    }
                    ReplayFacts::Tool(facts) => {
                        self.tool.replayable += 1;
                        if matches!(facts.egress, EgressRecord::Destination(_)) {
                            self.tool.egress_not_replayed += 1;
                        }
                        let answer = self.impact.observe_tool(
                            policies,
                            facts,
                            &context.recorded,
                            context.source,
                        )?;
                        self.tool.add(answer);
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

    /// Records the candidate answered, decided or indeterminate.
    fn replayed(&self) -> u64 {
        self.http.decided_count()
            + self.http.indeterminate_count()
            + self.tool.decided_count()
            + self.tool.indeterminate_count()
    }

    fn render(
        &self,
        policies: &ReplayPolicies,
        source_kind: &'static str,
        scope: &ReplayScope,
        complete: bool,
        limitations: &[&'static str],
    ) -> Value {
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
                "kind": source_kind,
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
            "impact": self.impact.render(policies, complete),
            "not_replayed": NOT_REPLAYED,
        })
    }
}

/// Run one job: read `scope` from `source`, oldest first, and decide every
/// replayable record under each of `policies`.
///
/// Stops before the next record when `control` is cancelled
/// ([`ReplayStop::Cancelled`]), and fails on a source read or an evaluator
/// invariant failure ([`ReplayStop::Failed`]); neither returns any count as
/// an answer. Reaching the record bound or `deadline` ends the scan with an
/// incomplete result. A window whose stored rows no longer match the cutoff's
/// count when the run ends -- rows pruned by retention while it ran -- is
/// incomplete with `source_changed`, and one whose source shows rows the
/// window may have held are gone, whenever they went, is incomplete with
/// `source_pruned`: never a silent omission.
pub(crate) fn run(
    source: &dyn ReplaySource,
    policies: &ReplayPolicies,
    scope: &ReplayScope,
    deadline: Instant,
    control: &ReplayControl,
) -> Result<ReplayOutcome, ReplayStop> {
    run_resumable(source, policies, scope, deadline, control, None, None)
}

/// [`run`], for a job that keeps checkpoints: start from `resume`, the last
/// checkpoint the job stored (`None` for a fresh start), and hand
/// `checkpoints` the aggregate after every whole page.
///
/// A checkpoint that is not one this build wrote for these policies and this
/// scope fails the run with `checkpoint_unreadable`, and one past
/// [`MAX_REPLAY_CHECKPOINT_BYTES`] with `checkpoint_too_large`; whatever the
/// sink answers stops the run as it says.
pub(crate) fn run_resumable(
    source: &dyn ReplaySource,
    policies: &ReplayPolicies,
    scope: &ReplayScope,
    deadline: Instant,
    control: &ReplayControl,
    resume: Option<&Value>,
    checkpoints: Option<&dyn ReplayCheckpoints>,
) -> Result<ReplayOutcome, ReplayStop> {
    let max_records = scope.max_records.min(MAX_REPLAY_RECORDS);
    let (mut tally, resumed_after) = match resume {
        None => (Tally::new(policies), None),
        Some(document) => {
            let (tally, after_id) = Tally::restore(policies, document)
                .map_err(|_| ReplayStop::Failed("checkpoint_unreadable"))?;
            (tally, Some(after_id))
        }
    };
    control.scanned.store(tally.scanned, Ordering::Relaxed);
    let mut deadline_exceeded = false;
    if let (Some(first_id), Some(last_id)) = (scope.cutoff.first_id, scope.cutoff.last_id) {
        let start = first_id.saturating_sub(1);
        let through_id = last_id.min(scope.cutoff.high_water);
        let after_id = match resumed_after {
            None => start,
            // A checkpoint names a position inside the window it read, and
            // never more rows than the job may read.
            Some(after_id)
                if (start..=through_id).contains(&after_id)
                    && usize::try_from(tally.scanned).unwrap_or(usize::MAX) <= max_records =>
            {
                after_id
            }
            Some(_) => return Err(ReplayStop::Failed("checkpoint_unreadable")),
        };
        let mut query = ReplayPageQuery {
            from_epoch_us: scope.from_epoch_us,
            to_epoch_us: scope.to_epoch_us,
            after_id,
            through_id,
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
            if let Some(stop) = control.stop_requested() {
                return Err(stop);
            }
            query.limit = remaining.min(REPLAY_PAGE_RECORDS);
            let page = source
                .page(&query)
                .map_err(|_| ReplayStop::Failed("source_unavailable"))?;
            if page.is_empty() {
                break;
            }
            for (id, row) in &page {
                if let Some(stop) = control.stop_requested() {
                    return Err(stop);
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
                tally.observe(policies, row)?;
                query.after_id = *id;
                control.scanned.store(tally.scanned, Ordering::Relaxed);
            }
            if let Some(sink) = checkpoints {
                let document = tally.checkpoint(query.after_id);
                let size = serde_json::to_vec(&document).map_or(usize::MAX, |bytes| bytes.len());
                if size > MAX_REPLAY_CHECKPOINT_BYTES {
                    return Err(ReplayStop::Failed("checkpoint_too_large"));
                }
                sink.page_done(query.after_id, tally.scanned, &document)?;
            }
        }
    }
    if let Some(stop) = control.stop_requested() {
        return Err(stop);
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
    // Rows the window may have held that were gone before the job was
    // created never reached the cutoff's count; a source that can see where
    // they were says so, and the result says `source_pruned`.
    let check = source
        .check(scope)
        .map_err(|_| ReplayStop::Failed("source_unavailable"))?;
    let scan_ended_naturally = limitations.is_empty();
    if check.stored != scope.cutoff.selected
        || (scan_ended_naturally && tally.scanned != scope.cutoff.selected)
    {
        limitations.push("source_changed");
    }
    if check.pruned {
        limitations.push("source_pruned");
    }
    let replayed = tally.replayed();
    if replayed == 0 {
        limitations.push("no_data");
    }
    limitations.sort_unstable();
    let complete = limitations.is_empty();
    let result = tally.render(policies, source.kind(), scope, complete, &limitations);
    let digest = canonical_json::semantic_digest(RESULT_MEDIA_TYPE, RESULT_SCHEMA_VERSION, &result)
        .map_err(|_| ReplayStop::Failed("result_digest_failed"))?;
    Ok(ReplayOutcome {
        complete,
        limitations,
        scanned: tally.scanned,
        replayed,
        result,
        digest,
        impact: tally.impact.summary(),
    })
}
