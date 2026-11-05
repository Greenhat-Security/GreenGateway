//! Restoring a standalone backup (issue #242; ADR-0008, "Export, backup,
//! and restore"): [`restore`] replaces an empty or explicitly prepared state
//! directory with the stores one archive holds, or leaves it as it was.
//!
//! 1. **Hold.** The target is admitted and locked as any state directory is
//!    ([`StateDirectory::acquire`]), so no gateway or other `ggctl` runs on
//!    it. It must be empty or, when the caller names that intent with
//!    [`RestoreRequest::replace_existing`], hold only the layout's entries:
//!    the stores' files with their `-wal`, `-shm` and `-journal` files, the
//!    lock file and a restore marker, each a regular file. Anything else is
//!    refused, so no file the layout does not name is ever replaced. The
//!    target must not be a mount point, because the switch renames it
//!    within its parent.
//! 2. **Stage.** A new directory beside the target, named from 16 bytes the
//!    caller drew at random so that another account cannot predict it
//!    (`.NAME.ggrestore-staging-HEX`, `0700` on Unix), receives the archive
//!    through the reader [`super::verify`] uses: every check of a verify
//!    runs on the staged entries, which are bounded regular files of the
//!    layout's names admitted by the shared archive rules.
//! 3. **Check.** Each staged database must carry its store's application ID
//!    ([`StateFile::application_id`]); a store that was a second name of an
//!    earlier store's file is linked to that file again; every staged file
//!    must be owner-only on Unix and is flushed; the restore marker
//!    ([`super::marker`]) is written; the staging directory must hold exactly
//!    those entries, and is flushed.
//! 4. **Switch.** The target is renamed to `.NAME.ggrestore-previous-HEX`,
//!    the staging directory to the target's name, and their parent is
//!    flushed. If the second rename fails, the first is undone. Only then is
//!    the previous directory removed.
//!
//! Any failure before the switch completes removes the staging directory and
//! leaves the target as it was. For a target without a lock file that
//! includes removing the one this restore created, while it still holds it,
//! so a failed restore leaves an empty directory empty.
//!
//! **Locks across the renames.** Unix renames a directory whatever is open
//! beneath it, so there the target's lock stays held throughout and moves
//! with the previous directory. Windows refuses to rename a directory while
//! any file beneath it is open, the lock file included, so there the lock is
//! released just before the first rename, and that refusal is what keeps a
//! gateway that takes the lock meanwhile from having its directory moved.
//! Either way the target's entries are compared again once it is moved
//! aside, and a target that changed is moved back.

use std::{
    ffi::OsString,
    fs::{self, OpenOptions},
    io,
    path::{Path, PathBuf},
    time::SystemTime,
};

use crate::ledger::RevisionId;
use crate::state_dir::{
    is_reparse_point, StateDirError, StateDirectory, StateFile, LOCK_FILE_NAME,
    RESTORE_MARKER_FILE_NAME,
};

use super::manifest::Manifest;
use super::marker::{self, RestoreMarker};
use super::{
    create_private_directory, is_owner_only, milliseconds, open_archive, read_archive, summary,
    sync_directory, BackupError, BackupSummary, Place, Private, Producer,
};

/// SQLite's companions of a store's file, which belong to the store.
const JOURNAL_SUFFIXES: [&str; 3] = ["-wal", "-shm", "-journal"];
/// Whether the target's lock can stay held while its directory is renamed:
/// see the module documentation.
const RENAMES_KEEP_LOCKS: bool = cfg!(unix);
/// Windows also refuses a rename for a moment while a scanner or indexer
/// reads a newly written file, so a refusal there is retried this often,
/// this far apart. A directory a gateway holds stays refused.
#[cfg(windows)]
const RENAME_ATTEMPTS: u32 = 20;
#[cfg(windows)]
const RENAME_RETRY: std::time::Duration = std::time::Duration::from_millis(50);

/// What [`restore`] restores, where, and how it names what it creates.
#[derive(Clone, Copy, Debug)]
pub struct RestoreRequest<'a> {
    /// The backup archive.
    pub archive: &'a Path,
    /// The state directory to restore into: an existing, empty directory,
    /// or with `replace_existing` a state directory to replace.
    pub target: &'a Path,
    /// The caller's explicit intent to replace the stores a target holds.
    /// Without it a target that holds anything but its lock file is
    /// refused.
    pub replace_existing: bool,
    pub producer: Producer,
    /// The time the restore marker records; this crate reads no clock.
    pub restored_at: SystemTime,
    /// 16 bytes the caller drew at random: they name the staging and
    /// previous directories, so that another account cannot predict them,
    /// and make the restore ID. Not a secret.
    pub nonce: [u8; 16],
}

/// A completed restore.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestoreSummary {
    /// The restore ID its marker records: `rst-` and 32 lowercase
    /// hexadecimal digits.
    pub restore_id: String,
    /// The target held stores, which were replaced.
    pub replaced: bool,
    /// The backup restored, as its manifest describes it.
    pub backup: BackupSummary,
    /// What did not go as it should after the restore was in place.
    pub warnings: Vec<RestoreWarning>,
}

/// Something that went wrong after the restored directory was in place.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestoreWarning {
    /// The directory holding the target could not be flushed after the
    /// switch: the restore is in place, but a crash before the filesystem
    /// writes it back could undo the rename.
    DirectoryNotFlushed,
    /// The replaced directory could not be removed completely: what is left
    /// of it is beside the target, under a hidden name starting with
    /// `.NAME.ggrestore-previous-`.
    PreviousNotRemoved,
}

impl RestoreWarning {
    /// The stable code for reports.
    pub fn code(self) -> &'static str {
        match self {
            Self::DirectoryNotFlushed => "restore.directory_not_flushed",
            Self::PreviousNotRemoved => "restore.previous_not_removed",
        }
    }
}

/// Why a restore did not happen. Value-free, like [`BackupError`]. Every
/// error but [`Self::RollbackFailed`] leaves the target as it was.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RestoreError {
    /// The target is not an admissible state directory, or another process
    /// holds its lock.
    StateDir(StateDirError),
    /// The archive did not verify, or could not be read or staged.
    Backup(BackupError),
    /// The target holds stores, and the caller did not ask to replace them.
    TargetNotEmpty,
    /// The target holds an entry the state-directory layout does not name,
    /// or a layout name that is not a regular file.
    TargetNotStateDirectory,
    /// The target is a mount point, which cannot be renamed within its
    /// parent.
    TargetMountPoint,
    /// The target's entries, or the directory holding it, could not be read.
    TargetUnavailable,
    /// The staging directory beside the target could not be created,
    /// written or flushed, or holds what this restore did not put there.
    StagingUnavailable,
    /// On Unix, the filesystem did not keep the staging directory or a
    /// staged file owner-only.
    PermissionsUnavailable,
    /// A staged database does not carry the application ID of the store it
    /// would restore.
    StoreIdentity { store: StateFile },
    /// The target's entries changed between the check and the switch.
    TargetChanged,
    /// The target could not be moved aside, or the staging directory could
    /// not take its name; the target was put back.
    SwitchFailed,
    /// The staging directory could not take the target's name, and the
    /// target could not be moved back either: it is beside its name, under
    /// a hidden name starting with `.NAME.ggrestore-previous-`.
    RollbackFailed,
}

impl RestoreError {
    /// The stable code for reports.
    pub fn code(&self) -> &'static str {
        match self {
            Self::StateDir(error) => error.code(),
            Self::Backup(error) => error.code(),
            Self::TargetNotEmpty => "restore.target_not_empty",
            Self::TargetNotStateDirectory => "restore.target_not_state_dir",
            Self::TargetMountPoint => "restore.target_mount_point",
            Self::TargetUnavailable => "restore.target_unavailable",
            Self::StagingUnavailable => "restore.staging_unavailable",
            Self::PermissionsUnavailable => "restore.permissions_unavailable",
            Self::StoreIdentity { .. } => "restore.store_identity_mismatch",
            Self::TargetChanged => "restore.target_changed",
            Self::SwitchFailed => "restore.switch_failed",
            Self::RollbackFailed => "restore.rollback_failed",
        }
    }

    /// The store the error concerns, when it concerns one.
    pub fn store(&self) -> Option<StateFile> {
        match self {
            Self::Backup(error) => error.store(),
            Self::StoreIdentity { store } => Some(*store),
            _ => None,
        }
    }
}

impl std::fmt::Display for RestoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StateDir(error) => write!(formatter, "error[{}]", error.code()),
            Self::Backup(error) => error.fmt(formatter),
            _ => match self.store() {
                Some(store) => write!(formatter, "store {}: error[{}]", store.id(), self.code()),
                None => write!(formatter, "error[{}]", self.code()),
            },
        }
    }
}

impl std::error::Error for RestoreError {}

/// Restores the archive `request.archive` into the state directory
/// `request.target`, as the module documentation describes.
pub fn restore(request: &RestoreRequest<'_>) -> Result<RestoreSummary, RestoreError> {
    restore_with(request, &mut |_| Ok(()))
}

/// The points at which the tests make a restore fail, to show that the
/// target is left as it was whichever step fails.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Step {
    /// The archive is extracted and verified in the staging directory.
    Verified,
    /// The staged stores passed the restore's own checks and are flushed.
    Checked,
    /// The marker is written and the staging directory flushed.
    Staged,
    /// The target is moved aside and the staging directory is about to take
    /// its name.
    MovedAside,
}

/// [`restore`], calling `fault` at each [`Step`]: an error it returns is
/// the restore's error at that point.
pub(super) fn restore_with(
    request: &RestoreRequest<'_>,
    fault: &mut dyn FnMut(Step) -> Result<(), RestoreError>,
) -> Result<RestoreSummary, RestoreError> {
    // The archive is admitted before anything about the target is touched.
    drop(open_archive(request.archive).map_err(RestoreError::Backup)?);
    let had_lock_file = fs::symlink_metadata(request.target.join(LOCK_FILE_NAME)).is_ok();
    let lock = StateDirectory::acquire(request.target).map_err(RestoreError::StateDir)?;
    let mut hold = Hold {
        path: lock.path().to_path_buf(),
        lock: Some(lock),
        created_lock_file: !had_lock_file,
    };
    let before = layout_entries(&hold.path)?;
    let replaced = !before.is_empty();
    if replaced && !request.replace_existing {
        return Err(RestoreError::TargetNotEmpty);
    }
    refuse_mount_point(&hold.path)?;
    let place = Place::of(&hold.path).ok_or(RestoreError::TargetUnavailable)?;
    let token = hex::encode(request.nonce);

    let staging = staging_directory(&place, &token)?;
    let manifest = read_archive(request.archive, staging.path()).map_err(RestoreError::Backup)?;
    fault(Step::Verified)?;
    check_staged(&manifest, staging.path())?;
    fault(Step::Checked)?;
    let marker = marker_of(request, &manifest, replaced);
    marker::write(staging.path(), &marker).map_err(|_| RestoreError::StagingUnavailable)?;
    expect_staged_entries(&manifest, staging.path())?;
    sync_directory(staging.path()).map_err(|_| RestoreError::StagingUnavailable)?;
    fault(Step::Staged)?;

    let warnings = switch(&mut hold, staging, &place, &token, &before, fault)?;
    Ok(RestoreSummary {
        restore_id: marker.restore_id,
        replaced,
        backup: summary(&manifest),
        warnings,
    })
}

/// The target's lock, and whether this restore created its lock file.
struct Hold {
    /// The target, absolute.
    path: PathBuf,
    lock: Option<StateDirectory>,
    /// Whether the lock file beneath `path` is this restore's to remove
    /// when it lets go, so a target without one is left without one.
    created_lock_file: bool,
}

impl Hold {
    /// Lets go of the lock, first removing a lock file this restore created
    /// while still holding it: no other process can have taken it since.
    fn release(&mut self) {
        if let Some(lock) = self.lock.take() {
            if self.created_lock_file {
                let _ = fs::remove_file(self.path.join(LOCK_FILE_NAME));
            }
            drop(lock);
        }
    }
}

impl Drop for Hold {
    fn drop(&mut self) {
        self.release();
    }
}

/// One entry of the target other than its lock file, as the check saw it.
#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Present {
    name: OsString,
    length: u64,
    modified: Option<SystemTime>,
}

/// Whether `name` belongs to the state-directory layout: a store's file or
/// one of its SQLite companions, or a restore marker. The lock file is not
/// counted, since every held state directory has one.
fn is_layout_name(name: &str) -> bool {
    name == RESTORE_MARKER_FILE_NAME
        || StateFile::ALL.into_iter().any(|store| {
            name.strip_prefix(store.file_name())
                .is_some_and(|suffix| suffix.is_empty() || JOURNAL_SUFFIXES.contains(&suffix))
        })
}

/// The entries of `directory` other than its lock file, sorted. Each must
/// be a regular file the layout names.
fn layout_entries(directory: &Path) -> Result<Vec<Present>, RestoreError> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(directory).map_err(|_| RestoreError::TargetUnavailable)? {
        let entry = entry.map_err(|_| RestoreError::TargetUnavailable)?;
        let name = entry.file_name();
        if name == LOCK_FILE_NAME {
            continue;
        }
        if !name.to_str().is_some_and(is_layout_name) {
            return Err(RestoreError::TargetNotStateDirectory);
        }
        let metadata =
            fs::symlink_metadata(entry.path()).map_err(|_| RestoreError::TargetUnavailable)?;
        if metadata.file_type().is_symlink() || is_reparse_point(&metadata) || !metadata.is_file() {
            return Err(RestoreError::TargetNotStateDirectory);
        }
        entries.push(Present {
            name,
            length: metadata.len(),
            modified: metadata.modified().ok(),
        });
    }
    entries.sort();
    Ok(entries)
}

/// Refuses a target on another device than the directory holding it: a
/// mount point, which no rename within its parent can move.
#[cfg(unix)]
fn refuse_mount_point(target: &Path) -> Result<(), RestoreError> {
    use std::os::unix::fs::MetadataExt;
    let parent = target.parent().ok_or(RestoreError::TargetUnavailable)?;
    let target = fs::symlink_metadata(target).map_err(|_| RestoreError::TargetUnavailable)?;
    let parent = fs::metadata(parent).map_err(|_| RestoreError::TargetUnavailable)?;
    if target.dev() == parent.dev() {
        Ok(())
    } else {
        Err(RestoreError::TargetMountPoint)
    }
}

/// On Windows a folder a volume is mounted on is a reparse point, which the
/// state-directory admission refuses as a link, and a drive's root has no
/// parent to stage beside it in.
#[cfg(not(unix))]
fn refuse_mount_point(_: &Path) -> Result<(), RestoreError> {
    Ok(())
}

impl Place {
    /// `.NAME.ggrestore-PURPOSE-TOKEN`: hidden, beside the target, and named
    /// from the caller's random token.
    fn restore_name(&self, purpose: &str, token: &str) -> PathBuf {
        let mut name = OsString::from(".");
        name.push(&self.name);
        name.push(".ggrestore-");
        name.push(purpose);
        name.push("-");
        name.push(token);
        self.directory.join(name)
    }
}

/// Creates the staging directory, never one that exists.
fn staging_directory(place: &Place, token: &str) -> Result<Private, RestoreError> {
    let path = place.restore_name("staging", token);
    create_private_directory(&path).map_err(|_| RestoreError::StagingUnavailable)?;
    let staging = Private {
        path,
        directory: true,
        published: false,
    };
    if !is_owner_only(staging.path()) {
        return Err(RestoreError::PermissionsUnavailable);
    }
    Ok(staging)
}

/// The restore's own checks of the staged stores, beyond a verify's, and
/// the second names a backup recorded as one file.
fn check_staged(manifest: &Manifest, staging: &Path) -> Result<(), RestoreError> {
    let invalid = || RestoreError::Backup(BackupError::ManifestInvalid);
    for (record, store) in manifest.stores.iter().zip(StateFile::ALL) {
        let Some(name) = record.entry.as_deref() else {
            continue;
        };
        let entry = manifest
            .entries
            .iter()
            .find(|entry| entry.name == name)
            .ok_or_else(invalid)?;
        if entry.database.application_id != store.application_id() {
            return Err(RestoreError::StoreIdentity { store });
        }
        if store.file_name() != name {
            // A second name of an earlier store's file is that file again.
            fs::hard_link(staging.join(name), staging.join(store.file_name()))
                .map_err(|_| RestoreError::StagingUnavailable)?;
        }
    }
    for entry in &manifest.entries {
        let path = staging.join(&entry.name);
        if !is_owner_only(&path) {
            return Err(RestoreError::PermissionsUnavailable);
        }
        // Flushed before the switch, so no restored store is a file the
        // filesystem has not written yet.
        OpenOptions::new()
            .write(true)
            .open(&path)
            .and_then(|file| file.sync_all())
            .map_err(|_| RestoreError::StagingUnavailable)?;
    }
    Ok(())
}

/// The marker of this restore.
fn marker_of(request: &RestoreRequest<'_>, manifest: &Manifest, replaced: bool) -> RestoreMarker {
    let stores = manifest
        .stores
        .iter()
        .zip(StateFile::ALL)
        .filter(|(record, _)| record.included)
        .map(|(_, store)| store)
        .collect();
    let ledger = manifest.ledger.as_ref().and_then(|ledger| {
        Some((
            RevisionId::parse(&ledger.desired)?,
            match &ledger.active {
                Some(active) => Some(RevisionId::parse(active)?),
                None => None,
            },
        ))
    });
    RestoreMarker {
        restore_id: RestoreMarker::restore_id(&request.nonce),
        restored_at_ms: milliseconds(request.restored_at),
        restored_by_program: request.producer.program.to_owned(),
        restored_by_version: request.producer.version.to_owned(),
        replaced,
        backup_api_version: manifest.api_version.clone(),
        backup_created_at_ms: manifest.created_at_ms,
        backup_created_by_program: manifest.created_by.program.clone(),
        backup_created_by_version: manifest.created_by.version.clone(),
        stores,
        ledger,
    }
}

/// The staging directory must hold exactly the restored stores' files and
/// the marker, and at most the lock file the ledger's verification took:
/// the switch moves all of it into place.
fn expect_staged_entries(manifest: &Manifest, staging: &Path) -> Result<(), RestoreError> {
    let unavailable = || RestoreError::StagingUnavailable;
    let mut expected: Vec<OsString> = manifest
        .stores
        .iter()
        .zip(StateFile::ALL)
        .filter(|(record, _)| record.included)
        .map(|(_, store)| OsString::from(store.file_name()))
        .collect();
    expected.push(OsString::from(RESTORE_MARKER_FILE_NAME));
    let mut found = 0_usize;
    for entry in fs::read_dir(staging).map_err(|_| unavailable())? {
        let name = entry.map_err(|_| unavailable())?.file_name();
        if name == LOCK_FILE_NAME {
            continue;
        }
        if !expected.contains(&name) {
            return Err(unavailable());
        }
        found += 1;
    }
    if found != expected.len() {
        return Err(unavailable());
    }
    Ok(())
}

/// Moves the target aside and the staging directory into its place, or
/// puts the target back; then removes what was moved aside.
fn switch(
    hold: &mut Hold,
    mut staging: Private,
    place: &Place,
    token: &str,
    before: &[Present],
    fault: &mut dyn FnMut(Step) -> Result<(), RestoreError>,
) -> Result<Vec<RestoreWarning>, RestoreError> {
    let target = hold.path.clone();
    let previous = place.restore_name("previous", token);
    if !RENAMES_KEEP_LOCKS {
        hold.release();
    }
    rename_directory(&target, &previous).map_err(|_| RestoreError::SwitchFailed)?;
    // A lock file this restore created moved aside with the target and goes
    // with it, unless the target is put back.
    let created_lock_file = std::mem::replace(&mut hold.created_lock_file, false);
    let switched = if layout_entries(&previous).ok().as_deref() != Some(before) {
        Err(RestoreError::TargetChanged)
    } else {
        fault(Step::MovedAside).and_then(|()| {
            rename_directory(staging.path(), &target).map_err(|_| RestoreError::SwitchFailed)
        })
    };
    if let Err(error) = switched {
        return Err(match rename_directory(&previous, &target) {
            Ok(()) => {
                hold.created_lock_file = created_lock_file;
                let _ = sync_directory(&place.directory);
                error
            }
            Err(_) => RestoreError::RollbackFailed,
        });
    }
    staging.published = true;

    let mut warnings = Vec::new();
    if sync_directory(&place.directory).is_err() {
        warnings.push(RestoreWarning::DirectoryNotFlushed);
    }
    // Released before the previous directory goes: Windows will not remove
    // a directory with an open file in it.
    hold.release();
    if fs::remove_dir_all(&previous).is_err() {
        warnings.push(RestoreWarning::PreviousNotRemoved);
    } else {
        let _ = sync_directory(&place.directory);
    }
    Ok(warnings)
}

/// Renames the directory `from` to `to`.
fn rename_directory(from: &Path, to: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        for _ in 1..RENAME_ATTEMPTS {
            match fs::rename(from, to) {
                Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                    std::thread::sleep(RENAME_RETRY)
                }
                outcome => return outcome,
            }
        }
    }
    fs::rename(from, to)
}
