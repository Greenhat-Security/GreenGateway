//! `ggctl ledger seed BUNDLE --state-dir DIR`, `ggctl ledger verify
//! --state-dir DIR` and `ggctl ledger rollback REVISION --state-dir DIR
//! [--acknowledge RISK_CODE]...` (issue #242; ADR-0008, "Seeding a ledger",
//! "Recovery and lockout" and "Ledger mode").
//!
//! The offline commands over a standalone configuration revision ledger. All
//! of the work is `gateway-config`'s, the code a gateway uses, so `ggctl`
//! cannot approximate it:
//!
//! - every command first takes the state directory's exclusive lock
//!   ([`StateDirectory::acquire`]) without waiting, so a gateway or another
//!   `ggctl` holding it is `state_dir.locked` (exit `5`) before anything is
//!   read;
//! - `seed` reads the bundle strictly with the shared reader and the
//!   production validators, as `ggctl validate --strict` does, then calls
//!   [`RevisionLedger::seed`], which refuses a state directory that holds a
//!   ledger or a ledger's journal files;
//! - `verify` runs [`RevisionLedger::inspect`]: the full verification a
//!   gateway runs at start, through a read-only connection;
//! - `rollback` plans the rollback through [`RevisionService`] with the
//!   production compiler under the fixed system actor
//!   [`ACTOR_LABEL`], and applies it with
//!   [`RevisionService::apply_offline_rollback`] only when every risk code is
//!   named with `--acknowledge`; it appends a forward revision that records
//!   no request.
//!
//! Reports never echo a positional argument or a path: the bundle is named
//! by its manifest, revisions by the opaque IDs the ledger holds, arguments
//! by their position, and an actor only by its kind. A revision is held to
//! the production policy and tools validators the gateway compiles with, and
//! the reports about one say that a gateway compiles it again at start. No
//! network request is made, no environment
//! variable is read, and no gateway audit event is written: a revision's
//! record is its own evidence.

use std::{
    io::{self, Write},
    path::Path,
    time::SystemTime,
};

use gateway_config::{
    bundle::{self, ProductionBundle, ProductionValidators, ReadOptions},
    ledger::{
        LedgerActor, LedgerError, LedgerState, Operation, PlanId, RevisionId, RevisionLedger,
        RevisionSummary,
    },
    revisions::{
        OfflineRollback, Plan, PlanSubject, ProductionCompiler, RevisionError, RevisionService,
    },
    semantic_diff::SemanticDiff,
    state_dir::{StateDirError, StateDirectory},
};
use serde::Serialize;

use crate::{
    cli::Invocation,
    diagnostic::{Code, Diagnostic, Exit},
    diff,
    report::{self, Format, Io, ReportDiagnostic},
    validate::{self, BundleRecord},
};

/// The system actor every offline ledger command records: an operator
/// acting on the deployment's own authority, which nobody authenticated.
pub(crate) const ACTOR_LABEL: &str = "ggctl-ledger";

const HINT_STATE_DIR: &str = "name the standalone state directory with --state-dir";

/// A revision as a report shows it: its opaque ID, place in the chain,
/// operation, actor kind and codes, and its bundle's identity. Never the
/// actor's subject or issuer, and never document content.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RevisionRecord {
    revision: String,
    sequence: u64,
    record_hash: String,
    operation: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    rollback_of: Option<String>,
    actor_kind: &'static str,
    activation: &'static str,
    recorded_at_ms: u64,
    /// The revision was applied online, under a request it records.
    applied_online: bool,
    changed_sections: Vec<String>,
    risk_codes: Vec<String>,
    bundle: RecordedBundleRecord,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RecordedBundleRecord {
    api_version: &'static str,
    name: String,
    profile: &'static str,
    source_digest: String,
}

impl RevisionRecord {
    fn of(summary: &RevisionSummary) -> Self {
        Self {
            revision: summary.revision.as_str().to_owned(),
            sequence: summary.sequence,
            record_hash: summary.record_hash.clone(),
            operation: summary.operation.as_str(),
            rollback_of: match &summary.operation {
                Operation::Rollback { target } => Some(target.as_str().to_owned()),
                Operation::Seed | Operation::Apply => None,
            },
            actor_kind: summary.actor.kind().as_str(),
            activation: summary.activation.as_str(),
            recorded_at_ms: summary.recorded_at_ms,
            applied_online: summary.request.is_some(),
            changed_sections: summary.codes.changed_sections().to_vec(),
            risk_codes: summary.codes.risk_codes().to_vec(),
            bundle: RecordedBundleRecord {
                api_version: summary.bundle.api_version.as_str(),
                name: summary.bundle.name.clone(),
                profile: summary.bundle.profile.as_str(),
                source_digest: summary.bundle.source_digest.clone(),
            },
        }
    }

    fn write(&self, out: &mut dyn Write, label: &str) -> io::Result<()> {
        write!(
            out,
            "  {label:<15}{} (sequence {}, {}",
            self.revision, self.sequence, self.operation
        )?;
        if let Some(target) = &self.rollback_of {
            write!(out, " of {target}")?;
        }
        writeln!(out, ", bundle {})", self.bundle.name)
    }
}

/// The pointer as a report shows it.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PointerRecord {
    /// How many revisions the ledger holds.
    revisions: u64,
    desired: RevisionRecord,
    /// `null` until a gateway has activated a revision.
    active: Option<String>,
    /// The desired revision is not the active one: the next start activates
    /// it.
    restart_pending: bool,
}

impl PointerRecord {
    fn of(state: &LedgerState) -> Self {
        Self {
            revisions: state.revisions,
            desired: RevisionRecord::of(&state.desired),
            active: state.active.as_ref().map(|id| id.as_str().to_owned()),
            restart_pending: state.restart_pending(),
        }
    }

    fn write(&self, out: &mut dyn Write) -> io::Result<()> {
        self.desired.write(out, "desired")?;
        writeln!(
            out,
            "  {:<15}{}",
            "active",
            self.active.as_deref().unwrap_or("none")
        )?;
        if self.restart_pending {
            writeln!(
                out,
                "  the desired revision is not active: a gateway starting from this ledger activates it"
            )?;
        }
        Ok(())
    }
}

/// The `ledger seed` result.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SeedResult {
    /// The bundle reader accepted `BUNDLE`, strictly.
    valid: bool,
    /// The ledger was created with the bundle as its first revision.
    seeded: bool,
    /// Present once the manifest was read.
    #[serde(skip_serializing_if = "Option::is_none")]
    bundle: Option<BundleRecord>,
    /// Present when an existing ledger was found to be corrupt.
    #[serde(skip_serializing_if = "Option::is_none")]
    corruption: Option<&'static str>,
    /// The new ledger's pointer, once seeded.
    #[serde(skip_serializing_if = "Option::is_none")]
    ledger: Option<PointerRecord>,
}

/// The `ledger verify` result.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct VerifyResult {
    /// Every check of the ledger passed.
    verified: bool,
    /// The class of corruption found, when the ledger is corrupt.
    #[serde(skip_serializing_if = "Option::is_none")]
    corruption: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ledger: Option<PointerRecord>,
}

/// The `ledger rollback` result.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RollbackResult {
    /// A new forward revision restores the target's content.
    rolled_back: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    corruption: Option<&'static str>,
    /// Present once the rollback was planned.
    #[serde(skip_serializing_if = "Option::is_none")]
    plan: Option<PlanRecord>,
    /// The revision appended, once rolled back.
    #[serde(skip_serializing_if = "Option::is_none")]
    revision: Option<RevisionRecord>,
    /// The ledger's pointer, once rolled back.
    #[serde(skip_serializing_if = "Option::is_none")]
    ledger: Option<PointerRecord>,
}

/// A rollback plan as a report shows it.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PlanRecord {
    /// The desired revision the rollback was planned against.
    base: String,
    /// `REVISION`, as this ledger holds it.
    target: String,
    /// The sorted risk codes of the change, each of which needs
    /// `--acknowledge`.
    risk_codes: Vec<String>,
    /// The risk codes `--acknowledge` did not name.
    unacknowledged: Vec<String>,
    changed_sections: Vec<&'static str>,
    /// The union of permissions the change would need online; an offline
    /// command checks none.
    required_permissions: Vec<&'static str>,
    /// How the change would take effect online (`live` or `restart`), or
    /// `null` when it changes nothing. The revision itself is recorded
    /// `restart`-class: no gateway is running to activate it.
    activation: Option<&'static str>,
    diff: SemanticDiff,
}

impl PlanRecord {
    fn of(plan: &Plan, target: &RevisionId, acknowledged: &[String]) -> Self {
        Self {
            base: plan.base.as_str().to_owned(),
            target: target.as_str().to_owned(),
            risk_codes: plan.risk_codes.clone(),
            unacknowledged: plan
                .risk_codes
                .iter()
                .filter(|code| !acknowledged.contains(code))
                .cloned()
                .collect(),
            changed_sections: plan.changed_sections.clone(),
            required_permissions: plan.required_permissions.clone(),
            activation: plan.activation.map(|class| class.as_str()),
            diff: plan.diff.clone(),
        }
    }
}

/// `ggctl ledger seed BUNDLE --state-dir DIR`.
pub(crate) fn seed(invocation: &Invocation, io: &mut Io<'_>) -> Exit {
    let Some((_, path)) = invocation.positional(0) else {
        return report::error(io, Diagnostic::new(Code::MissingArgument));
    };
    let Some((state_position, state_dir)) = invocation.value("--state-dir") else {
        return report::error(
            io,
            Diagnostic::new(Code::MissingArgument).with_hint(HINT_STATE_DIR),
        );
    };
    let read = bundle::read_bundle(
        Path::new(path),
        ReadOptions { strict: true },
        &ProductionValidators,
    );
    let mut diagnostics = validate::diagnostics(&read);
    let mut result = SeedResult {
        valid: read.bundle.is_some(),
        seeded: false,
        bundle: BundleRecord::of(&read),
        corruption: None,
        ledger: None,
    };
    if let Some(bundle) = &read.bundle {
        diagnostics.extend(seed_ledger(
            Path::new(state_dir),
            state_position,
            bundle,
            &mut result,
        ));
    }
    report::finish_report(
        io,
        Format::of(invocation),
        "ledger seed",
        &result,
        &diagnostics,
        human_seed,
    )
}

fn seed_ledger(
    state_dir: &Path,
    state_position: usize,
    bundle: &ProductionBundle,
    result: &mut SeedResult,
) -> Vec<ReportDiagnostic> {
    let held = match StateDirectory::acquire(state_dir) {
        Ok(held) => held,
        Err(error) => return vec![state_dir_diagnostic(&error, state_position)],
    };
    let seeded = LedgerActor::system(ACTOR_LABEL).and_then(|actor| {
        let (mut ledger, _) = RevisionLedger::seed(&held, bundle, actor, SystemTime::now())?;
        ledger.state()
    });
    match seeded {
        Ok(state) => {
            result.seeded = true;
            result.ledger = Some(PointerRecord::of(&state));
            vec![Diagnostic::new(Code::GatewayRecompilesAtStart).into()]
        }
        Err(error) => {
            result.corruption = corruption(&error);
            vec![ledger_diagnostic(&error)]
        }
    }
}

fn human_seed(result: &SeedResult, out: &mut dyn Write) -> io::Result<()> {
    let title = result
        .bundle
        .as_ref()
        .map_or_else(|| "bundle".to_owned(), BundleRecord::title);
    match (&result.ledger, &result.bundle) {
        (Some(ledger), Some(bundle)) if result.seeded => {
            writeln!(out, "{title}: seeded a new configuration ledger")?;
            bundle.write_details(out)?;
            ledger.write(out)
        }
        _ if result.valid => writeln!(out, "{title}: valid, no ledger was seeded"),
        _ => writeln!(out, "{title}: invalid, no ledger was seeded"),
    }
}

/// `ggctl ledger verify --state-dir DIR`.
pub(crate) fn verify(invocation: &Invocation, io: &mut Io<'_>) -> Exit {
    let Some((state_position, state_dir)) = invocation.value("--state-dir") else {
        return report::error(
            io,
            Diagnostic::new(Code::MissingArgument).with_hint(HINT_STATE_DIR),
        );
    };
    let mut result = VerifyResult {
        verified: false,
        corruption: None,
        ledger: None,
    };
    let diagnostics = match StateDirectory::acquire(Path::new(state_dir)) {
        Err(error) => vec![state_dir_diagnostic(&error, state_position)],
        Ok(held) => match RevisionLedger::inspect(&held) {
            Ok(state) => {
                result.verified = true;
                result.ledger = Some(PointerRecord::of(&state));
                vec![Diagnostic::new(Code::GatewayRecompilesAtStart).into()]
            }
            Err(error) => {
                result.corruption = corruption(&error);
                vec![ledger_diagnostic(&error)]
            }
        },
    };
    report::finish_report(
        io,
        Format::of(invocation),
        "ledger verify",
        &result,
        &diagnostics,
        |result, out| match &result.ledger {
            Some(ledger) => {
                writeln!(
                    out,
                    "configuration ledger verified: {} revision{}",
                    ledger.revisions,
                    if ledger.revisions == 1 { "" } else { "s" }
                )?;
                ledger.write(out)
            }
            None => match result.corruption {
                Some(class) => writeln!(out, "configuration ledger corrupt ({class})"),
                None => writeln!(out, "configuration ledger not verified"),
            },
        },
    )
}

/// `ggctl ledger rollback REVISION --state-dir DIR [--acknowledge
/// RISK_CODE]...`.
pub(crate) fn rollback(invocation: &Invocation, io: &mut Io<'_>) -> Exit {
    let Some((revision_position, revision)) = invocation.positional(0) else {
        return report::error(io, Diagnostic::new(Code::MissingArgument));
    };
    let Some((state_position, state_dir)) = invocation.value("--state-dir") else {
        return report::error(
            io,
            Diagnostic::new(Code::MissingArgument).with_hint(HINT_STATE_DIR),
        );
    };
    // Checked against the grammar only; never echoed.
    let Some(target) = RevisionId::parse(revision) else {
        return report::error(io, Diagnostic::at(Code::InvalidValue, revision_position));
    };
    let acknowledged: Vec<String> = invocation
        .texts("--acknowledge")
        .into_iter()
        .map(|(_, code)| code.to_owned())
        .collect();
    let mut result = RollbackResult {
        rolled_back: false,
        corruption: None,
        plan: None,
        revision: None,
        ledger: None,
    };
    let diagnostics = roll_back(
        Path::new(state_dir),
        state_position,
        target,
        revision_position,
        acknowledged,
        &mut result,
    );
    report::finish_report(
        io,
        Format::of(invocation),
        "ledger rollback",
        &result,
        &diagnostics,
        human_rollback,
    )
}

fn roll_back(
    state_dir: &Path,
    state_position: usize,
    target: RevisionId,
    revision_position: usize,
    acknowledged: Vec<String>,
    result: &mut RollbackResult,
) -> Vec<ReportDiagnostic> {
    let held = match StateDirectory::acquire(state_dir) {
        Ok(held) => held,
        Err(error) => return vec![state_dir_diagnostic(&error, state_position)],
    };
    let opened = RevisionLedger::open(&held)
        .and_then(|ledger| LedgerActor::system(ACTOR_LABEL).map(|actor| (ledger, actor)));
    let (ledger, actor) = match opened {
        Ok(opened) => opened,
        Err(error) => {
            result.corruption = corruption(&error);
            return vec![ledger_diagnostic(&error)];
        }
    };
    let mut service = RevisionService::new(ledger, ProductionCompiler);
    let now = SystemTime::now();
    // The rollback the gateway's revision service would plan: the target's
    // stored content, compiled again and diffed against the desired
    // revision.
    let plan = match service.create_plan(
        PlanId::offline(),
        actor.clone(),
        PlanSubject::Rollback(target.clone()),
        now,
    ) {
        Ok(plan) => plan,
        Err(error) => return revision_diagnostics(&error, revision_position, result),
    };
    result.plan = Some(PlanRecord::of(&plan, &target, &acknowledged));
    let mut diagnostics: Vec<ReportDiagnostic> = Vec::new();
    let applied = service.apply_offline_rollback(
        OfflineRollback {
            plan: plan.id,
            actor,
            target,
            acknowledged,
        },
        now,
    );
    let applied = applied.and_then(|applied| Ok((applied, service.state()?)));
    match applied {
        Ok((applied, state)) => {
            result.rolled_back = true;
            result.revision = Some(RevisionRecord::of(&applied.revision));
            result.ledger = Some(PointerRecord::of(&state));
            diagnostics.push(Diagnostic::new(Code::GatewayRecompilesAtStart).into());
        }
        Err(error) => diagnostics.extend(revision_diagnostics(&error, revision_position, result)),
    }
    diagnostics
}

fn human_rollback(result: &RollbackResult, out: &mut dyn Write) -> io::Result<()> {
    let Some(plan) = &result.plan else {
        return match result.corruption {
            Some(class) => writeln!(
                out,
                "configuration ledger corrupt ({class}); nothing was rolled back"
            ),
            None => writeln!(out, "nothing was rolled back"),
        };
    };
    writeln!(
        out,
        "rollback of {} to the content of {}:",
        plan.base, plan.target
    )?;
    out.write_all(diff::human(&plan.diff).as_bytes())?;
    match (&result.revision, &result.ledger) {
        (Some(revision), Some(ledger)) if result.rolled_back => {
            writeln!(
                out,
                "rolled back: a new forward revision restores that content"
            )?;
            revision.write(out, "revision")?;
            ledger.write(out)
        }
        _ if !plan.unacknowledged.is_empty() => writeln!(
            out,
            "not rolled back: acknowledge each risk code with --acknowledge: {}",
            plan.unacknowledged.join(", ")
        ),
        _ => writeln!(out, "not rolled back"),
    }
}

/// The class of corruption `error` reports, if it is corruption.
fn corruption(error: &LedgerError) -> Option<&'static str> {
    match error {
        LedgerError::Corrupt(kind) => Some(kind.as_str()),
        _ => None,
    }
}

fn state_dir_diagnostic(error: &StateDirError, state_position: usize) -> ReportDiagnostic {
    Diagnostic::at(state_dir_code(error), state_position).into()
}

/// The code for a state directory refusal: the one `gateway-config` gives
/// it, with the exit ADR-0008 gives it. `ggctl backup` shares it.
pub(crate) fn state_dir_code(error: &StateDirError) -> Code {
    match error {
        StateDirError::Missing => Code::StateDirMissing,
        StateDirError::NotDirectory => Code::StateDirNotDirectory,
        StateDirError::Link => Code::StateDirLink,
        StateDirError::UnsafePermissions => Code::StateDirUnsafePermissions,
        StateDirError::UnsafeLockFile => Code::StateDirUnsafeLockFile,
        StateDirError::Locked => Code::StateDirLocked,
        StateDirError::LockUnsupported => Code::StateDirLockUnsupported,
        StateDirError::Unavailable { .. } => Code::StateDirUnavailable,
    }
}

fn ledger_diagnostic(error: &LedgerError) -> ReportDiagnostic {
    Diagnostic::new(ledger_code(error)).into()
}

/// The code for a ledger refusal or failure: the one `gateway-config` gives
/// it, except an idempotency key already used, which no offline command
/// sends.
fn ledger_code(error: &LedgerError) -> Code {
    match error {
        LedgerError::UnsafeLocation => Code::LedgerUnsafeLocation,
        LedgerError::Missing => Code::LedgerMissing,
        LedgerError::Exists => Code::LedgerExists,
        LedgerError::Unsupported => Code::LedgerUnsupported,
        LedgerError::Corrupt(_) => Code::LedgerCorrupt,
        LedgerError::Stale { .. } => Code::LedgerStale,
        LedgerError::IdempotencyKeyUsed { .. } => Code::UnexpectedRefusal,
        LedgerError::Refused(_) => Code::LedgerRefused,
        LedgerError::Full => Code::LedgerFull,
        LedgerError::Unavailable { .. } => Code::LedgerUnavailable,
    }
}

/// The diagnostics for a refused rollback. A target the ledger does not
/// hold, or whose stored content no longer reads, is located by `REVISION`'s
/// position; the reader's own diagnostics about that content follow.
fn revision_diagnostics(
    error: &RevisionError,
    revision_position: usize,
    result: &mut RollbackResult,
) -> Vec<ReportDiagnostic> {
    let code = match error {
        RevisionError::RollbackTargetUnknown => {
            return vec![Diagnostic::at(Code::RollbackTargetUnknown, revision_position).into()]
        }
        RevisionError::RollbackTargetIsHead => {
            return vec![Diagnostic::at(Code::RollbackTargetIsHead, revision_position).into()]
        }
        RevisionError::Invalid(found) => {
            let mut diagnostics: Vec<ReportDiagnostic> =
                vec![Diagnostic::at(Code::RollbackTargetInvalid, revision_position).into()];
            diagnostics.extend(found.iter().cloned().map(ReportDiagnostic::from));
            return diagnostics;
        }
        RevisionError::Ledger(error) => {
            result.corruption = corruption(error);
            ledger_code(error)
        }
        RevisionError::BaseInvalid => Code::HeadInvalid,
        RevisionError::NotNormalizable => Code::NotNormalizable,
        RevisionError::NotApplicable(_) => Code::ChangeNotApplicable,
        RevisionError::Unclassified => Code::ChangeUnclassified,
        RevisionError::NoChange => Code::NoChange,
        RevisionError::AcknowledgementRequired => Code::AcknowledgementRequired,
        RevisionError::AcknowledgementMismatch => Code::AcknowledgementMismatch,
        RevisionError::NothingToAcknowledge => Code::NothingToAcknowledge,
        RevisionError::PreconditionFailed { .. } => Code::LedgerStale,
        // What the offline path never answers as this command drives it:
        // one fresh plan, by its own actor, with no online request.
        RevisionError::PreconditionRequired(_)
        | RevisionError::IdempotencyKeyInvalid
        | RevisionError::QuotaExceeded
        | RevisionError::PlanIdInUse
        | RevisionError::PlanUnknown
        | RevisionError::PlanStale
        | RevisionError::NotAcknowledgeable(_)
        | RevisionError::IdempotencyConflict
        | RevisionError::Forbidden(_)
        | RevisionError::RestartRequired
        | RevisionError::RestartPending
        | RevisionError::OfflineActorRequired => Code::UnexpectedRefusal,
    };
    vec![Diagnostic::new(code).into()]
}

#[cfg(test)]
mod tests;
