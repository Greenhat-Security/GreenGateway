//! `ggctl doctor --state-dir DIR`: the offline checks on a standalone state
//! directory (ADR-0008, "Doctor").
//!
//! The doctor takes the directory's exclusive lock without waiting, as the
//! `ledger` and `backup` commands do, so it runs only while no gateway or
//! other `ggctl` holds the directory, and keeps it until every check ran:
//!
//! - `state_dir.lock`: the directory was admitted and locked. Otherwise its
//!   reason is the `state_dir` code, and every other check is `skipped`.
//! - `state_dir.filesystem`: advice, `warning` with
//!   `state_dir.network_filesystem` on a filesystem the best-effort check
//!   recognises as a network one, and `skipped` where it cannot tell.
//! - `store.<id>` for each store of the layout ([`StateFile`]): the checks
//!   `backup create` and `backup verify` apply to a store, run on the store
//!   where it is (`gateway_config::backup::check_store`): admission, a
//!   read-only open, SQLite's integrity check, the description a backup
//!   records and the application ID its file name calls for; for the ledger,
//!   then the full verification `ledger verify` runs. A store the directory
//!   does not hold, or one beside a pending rollback journal, which a
//!   read-only connection cannot roll back, is `skipped`; one whose
//!   write-ahead log holds transactions not yet checkpointed passes with a
//!   `warning`.
//!
//! Nothing in a store is written and nothing is copied; the lock file is
//! created if it is missing, and SQLite may create a write-ahead store's
//! `-wal` and `-shm` files to read it, as any reader does. No check makes a
//! network request or reads an environment variable, and no path is echoed.

use std::{
    path::Path,
    time::{Duration, Instant},
};

use gateway_config::{
    backup::{self, StoreCheck},
    ledger::RevisionLedger,
    state_dir::{FilesystemKind, StateDirectory, StateFile},
};

use super::{CheckRecord, Reason, Status};
use crate::{
    diagnostic::{Code, Diagnostic},
    ledger::{ledger_code, state_dir_code},
    report::ReportDiagnostic,
};

/// The checks of a state directory, in the order they are reported: the
/// directory's two, then one per store in [`StateFile::ALL`] order.
pub(crate) const CHECKS: &[&str] = &[
    "state_dir.lock",
    "state_dir.filesystem",
    "store.audit",
    "store.discovery",
    "store.principals",
    "store.connections",
    "store.service_tokens",
    "store.policy_history",
    "store.config_ledger",
];

/// The check of `store`: `store.` and the store's stable identifier.
fn store_check_id(store: StateFile) -> &'static str {
    match store {
        StateFile::Audit => "store.audit",
        StateFile::Discovery => "store.discovery",
        StateFile::Principals => "store.principals",
        StateFile::Connections => "store.connections",
        StateFile::ServiceTokens => "store.service_tokens",
        StateFile::PolicyHistory => "store.policy_history",
        StateFile::ConfigLedger => "store.config_ledger",
    }
}

/// Every check of the state directory at `path`, in [`CHECKS`] order, and
/// the diagnostics they found. `argument` is the position of `--state-dir`,
/// which locates a diagnostic about the directory or one of its stores.
pub(crate) fn checks(path: &Path, argument: usize) -> (Vec<CheckRecord>, Vec<ReportDiagnostic>) {
    let started = Instant::now();
    let held = match StateDirectory::acquire(path) {
        Ok(held) => held,
        Err(error) => {
            let refused: ReportDiagnostic = Diagnostic::at(state_dir_code(&error), argument).into();
            let mut checks = vec![CheckRecord::from_diagnostic(
                CHECKS[0],
                true,
                Status::Fail,
                &refused,
                started.elapsed(),
            )];
            checks.extend(CHECKS[1..].iter().map(|&id| {
                CheckRecord::new(
                    id,
                    id != CHECKS[1],
                    Status::Skipped,
                    Reason::Incomplete,
                    Duration::ZERO,
                )
            }));
            return (checks, vec![refused]);
        }
    };
    let mut diagnostics = Vec::new();
    let mut checks = Vec::with_capacity(CHECKS.len());
    checks.push(CheckRecord::new(
        CHECKS[0],
        true,
        Status::Pass,
        Reason::Passed,
        started.elapsed(),
    ));

    let started = Instant::now();
    let filesystem = held.filesystem();
    checks.push(match filesystem {
        FilesystemKind::Local => CheckRecord::new(
            CHECKS[1],
            false,
            Status::Pass,
            Reason::Passed,
            started.elapsed(),
        ),
        FilesystemKind::Network => {
            let warned: ReportDiagnostic =
                Diagnostic::at(Code::StateDirNetworkFilesystem, argument).into();
            let check = CheckRecord::from_diagnostic(
                CHECKS[1],
                false,
                Status::Warning,
                &warned,
                started.elapsed(),
            );
            diagnostics.push(warned);
            check
        }
        FilesystemKind::Unchecked => CheckRecord::new(
            CHECKS[1],
            false,
            Status::Skipped,
            Reason::FilesystemUnchecked,
            started.elapsed(),
        ),
    });

    for store in StateFile::ALL {
        checks.push(store_check(&held, store, argument, &mut diagnostics));
    }
    (checks, diagnostics)
}

/// The check of one store, adding the diagnostic of a failure.
fn store_check(
    held: &StateDirectory,
    store: StateFile,
    argument: usize,
    diagnostics: &mut Vec<ReportDiagnostic>,
) -> CheckRecord {
    let started = Instant::now();
    let id = store_check_id(store);
    let found = |status, reason| CheckRecord::new(id, true, status, reason, started.elapsed());
    let mut failed = |diagnostic: ReportDiagnostic| {
        let check =
            CheckRecord::from_diagnostic(id, true, Status::Fail, &diagnostic, started.elapsed());
        diagnostics.push(diagnostic);
        check
    };
    let wal_pending = match backup::check_store(held, store) {
        Ok(StoreCheck::Absent) => return found(Status::Skipped, Reason::NotPresent),
        Ok(StoreCheck::JournalPending) => return found(Status::Skipped, Reason::JournalPending),
        Ok(StoreCheck::ForeignIdentity) => {
            return found(Status::Fail, Reason::StoreIdentityMismatch)
        }
        Ok(StoreCheck::Passed { wal_pending }) => wal_pending,
        Err(error) => return failed(crate::backup::diagnostic(&error, Some(argument))),
    };
    if store == StateFile::ConfigLedger {
        if let Err(error) = RevisionLedger::inspect(held) {
            return failed(Diagnostic::at(ledger_code(&error), argument).into());
        }
    }
    if wal_pending {
        found(Status::Warning, Reason::WalPending)
    } else {
        found(Status::Pass, Reason::Passed)
    }
}

#[cfg(test)]
mod tests;
