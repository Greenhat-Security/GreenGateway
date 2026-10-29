//! Where the ledger lives: the checks on the state directory and the ledger
//! file, and how a seed publishes a new ledger under its name.
//!
//! A seed builds the ledger in a temporary file beside it, commits and
//! flushes it, then hard-links it to [`LEDGER_FILE_NAME`]. Linking never
//! replaces an existing name, so two seeds cannot both win and a ledger is
//! never overwritten, and the ledger's name only ever names a complete
//! ledger. The temporary name is then removed and the directory flushed
//! where the platform allows it.

use std::{
    ffi::OsString,
    fs, io,
    path::{Path, PathBuf},
};

use super::{LedgerError, LEDGER_FILE_NAME};

/// What SQLite appends to a database's name for its write-ahead log, shared
/// memory index and rollback journal. A leftover one could be replayed into
/// a new database of the same name.
const JOURNAL_SUFFIXES: &[&str] = &["-wal", "-shm", "-journal"];
/// The temporary name a seed builds the ledger under.
const SEED_SUFFIX: &str = ".seed";

/// The names one seed uses.
pub(super) struct SeedPaths {
    directory: PathBuf,
    ledger: PathBuf,
    pub(super) temporary: PathBuf,
}

/// The ledger file in `state_dir`, once both are safe to use.
pub(super) fn existing_ledger(state_dir: &Path) -> Result<PathBuf, LedgerError> {
    check_directory(state_dir)?;
    let path = state_dir.join(LEDGER_FILE_NAME);
    match fs::symlink_metadata(&path) {
        Ok(metadata) if is_plain_file(&metadata) => Ok(path),
        Ok(_) => Err(LedgerError::UnsafeLocation),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Err(LedgerError::Missing),
        Err(_) => Err(LedgerError::Unavailable {
            operation: "ledger inspection",
        }),
    }
}

/// The names a seed into `state_dir` uses, once the directory is safe and
/// holds neither a ledger nor a ledger's journal files. A temporary file a
/// previous, interrupted seed left behind is removed: it was never published,
/// so nothing reads it.
pub(super) fn prepare_seed(state_dir: &Path) -> Result<SeedPaths, LedgerError> {
    check_directory(state_dir)?;
    let ledger = state_dir.join(LEDGER_FILE_NAME);
    let occupied = std::iter::once(ledger.clone()).chain(
        JOURNAL_SUFFIXES
            .iter()
            .map(|suffix| suffixed(&ledger, suffix)),
    );
    for path in occupied {
        match fs::symlink_metadata(&path) {
            Ok(_) => return Err(LedgerError::Exists),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => {
                return Err(LedgerError::Unavailable {
                    operation: "ledger inspection",
                })
            }
        }
    }
    let paths = SeedPaths {
        directory: state_dir.to_path_buf(),
        temporary: suffixed(&ledger, SEED_SUFFIX),
        ledger,
    };
    for path in temporary_files(&paths) {
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                fs::remove_file(&path).map_err(|_| LedgerError::Unavailable {
                    operation: "leftover seed removal",
                })?;
            }
            Ok(_) => return Err(LedgerError::UnsafeLocation),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => {
                return Err(LedgerError::Unavailable {
                    operation: "ledger inspection",
                })
            }
        }
    }
    Ok(paths)
}

/// Creates the empty temporary database file, owner-only where the platform
/// has modes, refusing one that exists.
pub(super) fn create_temporary(paths: &SeedPaths) -> Result<(), LedgerError> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(&paths.temporary) {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Err(LedgerError::Exists),
        Err(_) => Err(LedgerError::Unavailable {
            operation: "ledger creation",
        }),
    }
}

/// Removes whatever a failed seed left under the temporary name.
pub(super) fn discard_temporary(paths: &SeedPaths) {
    for path in temporary_files(paths) {
        // Best effort: an unremoved temporary file is never read, and the
        // next seed removes it before it starts.
        let _ = fs::remove_file(path);
    }
}

/// Flushes the committed temporary ledger and links it to the ledger's name,
/// without replacing anything there.
pub(super) fn publish(paths: &SeedPaths) -> Result<(), LedgerError> {
    let linked =
        sync_file(&paths.temporary).and_then(|()| fs::hard_link(&paths.temporary, &paths.ledger));
    if let Err(error) = linked {
        discard_temporary(paths);
        return Err(if error.kind() == io::ErrorKind::AlreadyExists {
            LedgerError::Exists
        } else {
            LedgerError::Unavailable {
                operation: "ledger publication",
            }
        });
    }
    // The ledger is published; a second name left behind for the same file is
    // removed by the next seed and is never opened as a ledger.
    let _ = fs::remove_file(&paths.temporary);
    sync_directory(&paths.directory).map_err(|_| LedgerError::Unavailable {
        operation: "ledger publication",
    })
}

fn temporary_files(paths: &SeedPaths) -> impl Iterator<Item = PathBuf> + '_ {
    std::iter::once(paths.temporary.clone()).chain(
        JOURNAL_SUFFIXES
            .iter()
            .map(|suffix| suffixed(&paths.temporary, suffix)),
    )
}

fn suffixed(path: &Path, suffix: &str) -> PathBuf {
    let mut name = OsString::from(path.as_os_str());
    name.push(suffix);
    PathBuf::from(name)
}

/// The state directory must be a directory, not a link or reparse point,
/// and not writable by group or other, who could otherwise swap the ledger.
fn check_directory(state_dir: &Path) -> Result<(), LedgerError> {
    let metadata = fs::symlink_metadata(state_dir).map_err(|_| LedgerError::UnsafeLocation)?;
    if metadata.is_dir()
        && !metadata.file_type().is_symlink()
        && !is_reparse_point(&metadata)
        && owner_alone_can_write(&metadata)
    {
        Ok(())
    } else {
        Err(LedgerError::UnsafeLocation)
    }
}

/// A regular file, not a link or reparse point, that only its owner can
/// write.
fn is_plain_file(metadata: &fs::Metadata) -> bool {
    metadata.is_file()
        && !metadata.file_type().is_symlink()
        && !is_reparse_point(metadata)
        && owner_alone_can_write(metadata)
}

fn sync_file(path: &Path) -> io::Result<()> {
    // Windows flushes only through a handle opened for writing.
    fs::OpenOptions::new().write(true).open(path)?.sync_all()
}

#[cfg(unix)]
fn sync_directory(directory: &Path) -> io::Result<()> {
    fs::File::open(directory)?.sync_all()
}

/// Windows cannot open a directory for flushing through the standard
/// library; NTFS journals the link itself.
#[cfg(not(unix))]
fn sync_directory(_: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn owner_alone_can_write(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    metadata.mode() & 0o022 == 0
}

/// Windows ACLs remain an operator and platform responsibility, as they are
/// for bundle directories.
#[cfg(not(unix))]
fn owner_alone_can_write(_: &fs::Metadata) -> bool {
    true
}

#[cfg(windows)]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & 0x0000_0400 != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_: &fs::Metadata) -> bool {
    false
}
