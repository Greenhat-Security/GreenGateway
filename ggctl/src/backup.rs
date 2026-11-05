//! `ggctl backup create --state-dir DIR --output FILE [--format human|json]`
//! and `ggctl backup verify FILE [--format human|json]` (issue #242;
//! ADR-0008, "Backup and restore").
//!
//! Both are `gateway_config::backup`, which the restore that follows will
//! share: `ggctl` takes the state directory's lock, stamps the time and
//! reports. A backup is written only to the new file `--output` names, never
//! to standard output, and holds no plaintext token, secret value or key;
//! the Connections store keeps its secrets as #240 ciphertext, whose key
//! files are a separate artifact, and a create that includes that store
//! says so. Neither command makes a network request, reads an environment
//! variable or writes gateway audit events, and no path is ever echoed.

use std::{
    io::{self, Write},
    path::Path,
    time::SystemTime,
};

use gateway_config::{
    backup::{
        self, BackupError, BackupSummary, CreateRequest, EntryProblem, Producer, StoreProblem,
    },
    state_dir::{StateDirectory, StateFile},
};
use serde::Serialize;

use crate::{
    cli::Invocation,
    diagnostic::{Code, Diagnostic, Exit},
    ledger::state_dir_code,
    report::{self, Format, Io, ReportDiagnostic},
};

/// What a backup records as the program that wrote it.
const PRODUCER: Producer = Producer {
    program: "ggctl",
    version: env!("CARGO_PKG_VERSION"),
};

/// The `backup create` result.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateResult {
    /// The archive is at `--output` and verified.
    created: bool,
    /// The store a refusal concerns.
    #[serde(skip_serializing_if = "Option::is_none")]
    store: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    backup: Option<BackupRecord>,
}

/// The `backup verify` result.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct VerifyResult {
    /// Every check passed.
    verified: bool,
    /// The store a refusal concerns.
    #[serde(skip_serializing_if = "Option::is_none")]
    store: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    backup: Option<BackupRecord>,
}

/// A backup as its manifest describes it: fixed names, versions, counts and
/// opaque revision IDs, never a path or a store's content.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct BackupRecord {
    api_version: &'static str,
    archive_version: u16,
    created_at_ms: u64,
    created_by: ProducerRecord,
    sqlite_version: String,
    stores: Vec<StoreRecord>,
    entries: u64,
    bytes: u64,
    tables: u64,
    rows: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    ledger: Option<LedgerRecord>,
}

#[derive(Debug, Serialize)]
struct ProducerRecord {
    program: String,
    version: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct StoreRecord {
    store: &'static str,
    included: bool,
    /// The entry that holds it: its own file, or another name's.
    #[serde(skip_serializing_if = "Option::is_none")]
    entry: Option<&'static str>,
    tables: u64,
    rows: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct LedgerRecord {
    revisions: u64,
    desired: String,
    active: Option<String>,
    restart_pending: bool,
    bundle_api_version: String,
}

impl BackupRecord {
    fn of(summary: &BackupSummary) -> Self {
        Self {
            api_version: summary.api_version,
            archive_version: summary.archive_version,
            created_at_ms: summary.created_at_ms,
            created_by: ProducerRecord {
                program: summary.producer_program.clone(),
                version: summary.producer_version.clone(),
            },
            sqlite_version: summary.sqlite_version.clone(),
            stores: summary
                .stores
                .iter()
                .map(|store| StoreRecord {
                    store: store.store.id(),
                    included: store.included,
                    entry: store.entry.map(StateFile::file_name),
                    tables: store.tables,
                    rows: store.rows,
                })
                .collect(),
            entries: summary.entries,
            bytes: summary.bytes,
            tables: summary.tables,
            rows: summary.rows,
            ledger: summary.ledger.as_ref().map(|ledger| LedgerRecord {
                revisions: ledger.revisions,
                desired: ledger.desired.as_str().to_owned(),
                active: ledger
                    .active
                    .as_ref()
                    .map(|active| active.as_str().to_owned()),
                restart_pending: ledger.active.as_ref() != Some(&ledger.desired),
                bundle_api_version: ledger.bundle_api_version.clone(),
            }),
        }
    }

    fn connections_included(&self) -> bool {
        self.stores
            .iter()
            .any(|store| store.store == StateFile::Connections.id() && store.included)
    }

    fn write_details(&self, out: &mut dyn Write) -> io::Result<()> {
        writeln!(
            out,
            "  {} entries, {} bytes, {} tables, {} rows; written by {} {} with SQLite {}",
            self.entries,
            self.bytes,
            self.tables,
            self.rows,
            self.created_by.program,
            self.created_by.version,
            self.sqlite_version
        )?;
        for store in &self.stores {
            match (store.included, store.entry) {
                (false, _) => writeln!(out, "  {:<16} not in the state directory", store.store)?,
                (true, Some(entry)) => writeln!(
                    out,
                    "  {:<16} {entry}: {} tables, {} rows",
                    store.store, store.tables, store.rows
                )?,
                (true, None) => writeln!(out, "  {:<16} included", store.store)?,
            }
        }
        if let Some(ledger) = &self.ledger {
            writeln!(
                out,
                "  ledger: {} revisions, desired {}, active {}{}",
                ledger.revisions,
                ledger.desired,
                ledger.active.as_deref().unwrap_or("none"),
                if ledger.restart_pending {
                    " (restart pending)"
                } else {
                    ""
                }
            )?;
        }
        Ok(())
    }
}

/// `backup create`.
pub(crate) fn create(invocation: &Invocation, io: &mut Io<'_>) -> Exit {
    let (Some((state_dir_position, state_dir)), Some((output_position, output))) = (
        invocation.value("--state-dir"),
        invocation.value("--output"),
    ) else {
        return report::error(io, Diagnostic::new(Code::MissingArgument));
    };
    if output == "-" {
        return report::error(
            io,
            Diagnostic::at(Code::BackupStdoutRefused, output_position),
        );
    }
    let mut result = CreateResult {
        created: false,
        store: None,
        backup: None,
    };
    let mut diagnostics: Vec<ReportDiagnostic> = Vec::new();
    match StateDirectory::acquire(Path::new(state_dir)) {
        Err(error) => {
            diagnostics.push(Diagnostic::at(state_dir_code(&error), state_dir_position).into());
        }
        Ok(held) => {
            let request = CreateRequest {
                output: Path::new(output),
                producer: PRODUCER,
                created_at: SystemTime::now(),
            };
            match backup::create(&held, &request) {
                Ok(summary) => {
                    let record = BackupRecord::of(&summary);
                    if record.connections_included() {
                        diagnostics.push(Diagnostic::new(Code::BackupSecretKeysNotIncluded).into());
                    }
                    result.created = true;
                    result.backup = Some(record);
                }
                Err(error) => {
                    result.store = error.store().map(StateFile::id);
                    let position = match &error {
                        BackupError::OutputExists
                        | BackupError::OutputUnusable
                        | BackupError::PermissionsUnavailable => Some(output_position),
                        BackupError::StateDirUnavailable
                        | BackupError::Store { .. }
                        | BackupError::NothingToBackUp => Some(state_dir_position),
                        _ => None,
                    };
                    diagnostics.push(diagnostic(&error, position));
                }
            }
        }
    }
    report::finish_report(
        io,
        Format::of(invocation),
        "backup create",
        &result,
        &diagnostics,
        |result, out| match &result.backup {
            Some(backup) if result.created => {
                writeln!(out, "created a backup of {} stores", count_included(backup))?;
                backup.write_details(out)
            }
            _ => writeln!(out, "backup create: no backup was written"),
        },
    )
}

/// `backup verify`.
pub(crate) fn verify(invocation: &Invocation, io: &mut Io<'_>) -> Exit {
    let Some((position, archive)) = invocation.positional(0) else {
        // The parser requires FILE, so it was not UTF-8.
        return report::error(io, Diagnostic::new(Code::ArgumentNotUtf8));
    };
    let mut result = VerifyResult {
        verified: false,
        store: None,
        backup: None,
    };
    let mut diagnostics: Vec<ReportDiagnostic> = Vec::new();
    match backup::verify(Path::new(archive)) {
        Ok(summary) => {
            result.verified = true;
            result.backup = Some(BackupRecord::of(&summary));
        }
        Err(error) => {
            result.store = error.store().map(StateFile::id);
            diagnostics.push(diagnostic(&error, Some(position)));
        }
    }
    report::finish_report(
        io,
        Format::of(invocation),
        "backup verify",
        &result,
        &diagnostics,
        |result, out| match &result.backup {
            Some(backup) if result.verified => {
                writeln!(
                    out,
                    "verified a backup of {} stores, created at Unix time {}.{:03}",
                    count_included(backup),
                    backup.created_at_ms / 1000,
                    backup.created_at_ms % 1000
                )?;
                backup.write_details(out)
            }
            _ => writeln!(out, "backup verify: the backup did not verify"),
        },
    )
}

fn count_included(backup: &BackupRecord) -> usize {
    backup.stores.iter().filter(|store| store.included).count()
}

/// The report diagnostic for a backup error: the shared admission rules'
/// own code for a refused archive, located at its entry, and otherwise
/// ggctl's code for the one `gateway-config` gives it, located at the
/// argument `position` when given.
fn diagnostic(error: &BackupError, position: Option<usize>) -> ReportDiagnostic {
    let code = match error {
        BackupError::Refused(refusal) => return ReportDiagnostic::Archive(refusal.clone()),
        BackupError::StateDirUnavailable => Code::StateDirUnavailable,
        BackupError::Store { problem, .. } => match problem {
            StoreProblem::Link => Code::BackupStoreLink,
            StoreProblem::NotRegularFile => Code::BackupStoreNotRegularFile,
            StoreProblem::UnsafePermissions => Code::BackupStoreUnsafePermissions,
            StoreProblem::Unavailable => Code::BackupStoreUnavailable,
            StoreProblem::Corrupt => Code::BackupStoreCorrupt,
            StoreProblem::LedgerInvalid => Code::BackupLedgerInvalid,
            StoreProblem::LedgerShared => Code::BackupLedgerShared,
        },
        BackupError::NothingToBackUp => Code::BackupNothingToBackUp,
        BackupError::OutputExists => Code::BackupOutputExists,
        BackupError::OutputUnusable => Code::BackupOutputUnusable,
        BackupError::PermissionsUnavailable => Code::BackupPermissionsUnavailable,
        BackupError::ArchiveUnreadable => Code::BackupArchiveUnreadable,
        BackupError::ArchiveNotRegularFile => Code::BackupArchiveNotRegularFile,
        BackupError::ArchiveTooLarge => Code::BackupArchiveTooLarge,
        BackupError::StagingUnavailable => Code::BackupStagingUnavailable,
        BackupError::NotABackup => Code::BackupNotABackup,
        BackupError::UnsupportedArchiveVersion => Code::BackupUnsupportedArchiveVersion,
        BackupError::ManifestMissing => Code::BackupManifestMissing,
        BackupError::ManifestInvalid => Code::BackupManifestInvalid,
        BackupError::UnsupportedManifestVersion => Code::BackupUnsupportedManifestVersion,
        BackupError::UnexpectedEntry { .. } => Code::BackupUnexpectedEntry,
        BackupError::EntryMissing => Code::BackupEntryMissing,
        BackupError::ArchiveDigestMismatch => Code::BackupArchiveDigestMismatch,
        BackupError::Entry { problem, .. } => match problem {
            EntryProblem::ChecksumMismatch => Code::BackupChecksumMismatch,
            EntryProblem::IntegrityFailed => Code::BackupStoreIntegrityFailed,
            EntryProblem::DescriptionMismatch => Code::BackupStoreMismatch,
            EntryProblem::LedgerInvalid => Code::BackupLedgerVerificationFailed,
            EntryProblem::LedgerMismatch => Code::BackupLedgerMismatch,
        },
    };
    match position {
        Some(position) => Diagnostic::at(code, position),
        None => Diagnostic::new(code),
    }
    .into()
}

#[cfg(test)]
mod tests;
