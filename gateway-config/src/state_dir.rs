//! The standalone state directory (issue #242; ADR-0008, "Bundle mode" and
//! "Ledger mode").
//!
//! In bundle and ledger modes a standalone deployment keeps every local store
//! beneath one directory, `GATEWAY_STATE_DIR`, under fixed file names instead
//! of the `*_SQLITE_PATH` variables environment mode reads. This module is
//! that directory's contract, shared by the gateway and `ggctl` so neither
//! can approximate the other:
//!
//! - **Layout.** [`StateFile`] names the file of every standalone store the
//!   field catalog maps to a fixed file (`BundleMapping::Resource`), plus the
//!   configuration revision ledger, [`LOCK_FILE_NAME`] names the lock file
//!   and [`RESTORE_MARKER_FILE_NAME`] the marker `ggctl backup restore`
//!   leaves for the next gateway start ([`crate::backup`]). The names never
//!   change meaning; a store that moves gets a new one.
//! - **Admission.** The directory must be a real directory: not a symbolic
//!   link, junction or other reparse point, and on Unix not writable by
//!   group or other, who could otherwise replace a store. It is checked by
//!   path, then opened without following a link at its last component and
//!   checked again on the open handle, and the lock file is opened beneath
//!   that handle, so the lock is taken on the directory that was admitted.
//! - **Lock.** [`StateDirectory::acquire`] takes an exclusive operating
//!   system advisory lock on [`LOCK_FILE_NAME`] without waiting (`flock` on
//!   Unix, `LockFileEx` on Windows, through `std::fs::File::try_lock`) and
//!   holds it for as long as the handle or any clone of it lives. A second
//!   acquisition, by another handle in the same process or by another
//!   process, is refused with [`StateDirError::Locked`] rather than queued.
//!   The lock file is created owner-only on Unix, holds no content, and is
//!   never removed: removing it while it is held would let a second process
//!   lock a new file of the same name.
//! - **Network filesystems.** Locks and SQLite are unsupported on network
//!   filesystems (ADR-0002). [`filesystem_kind`] recognises the common ones
//!   on a best-effort basis so `ggctl doctor` can warn
//!   ([`NETWORK_FILESYSTEM_CODE`]); it is never a reason to refuse, because a
//!   recognised local filesystem is no proof either.
//!
//! The lock is advisory: it keeps apart the processes that take it, the
//! gateway and `ggctl`, and nothing else. Whoever can write the state
//! directory controls a standalone deployment, as ADR-0008 states, and a
//! writer of a directory above it can always redirect the path itself; the
//! checks here refuse a directory others can write, not its owner.
//!
//! Gateway startup checks the `GATEWAY_STATE_DIR` selector. Activating
//! stores beneath that directory remains a later #242 slice.
//! Today only the revision ledger opens through a held [`StateDirectory`],
//! so nothing can open a ledger without holding its directory's lock.

mod filesystem;

#[cfg(test)]
mod tests;

use std::{
    fmt,
    fs::{self, TryLockError},
    io,
    path::{Path, PathBuf},
    sync::Arc,
};

use cap_fs_ext::{DirExt as _, FollowSymlinks, OpenOptionsFollowExt as _, OpenOptionsSyncExt as _};
use cap_std::{
    ambient_authority,
    fs::{Dir, OpenOptions as CapabilityOpenOptions},
};

pub use filesystem::{filesystem_kind, FilesystemKind, NETWORK_FILESYSTEM_CODE};

/// The lock file's name beneath the state directory.
pub const LOCK_FILE_NAME: &str = "state.lock";
/// The restore marker's name beneath the state directory: present from a
/// completed `ggctl backup restore` until the next gateway start records it.
pub const RESTORE_MARKER_FILE_NAME: &str = "restore-marker.json";
/// The `PRAGMA application_id` of the configuration revision ledger, "GGLG".
const LEDGER_APPLICATION_ID: i32 = 0x4747_4C47;

/// A standalone store's fixed file beneath the state directory.
///
/// Every store the field catalog maps to a fixed file has one, and so does
/// the configuration revision ledger. Admin sessions have none: the one
/// standalone admin session store (`ADMIN_SESSION_MODE=standalone_memory`)
/// lives in process memory, so a restart ends every session (ADR-0009).
/// SQLite keeps `-wal`, `-shm` and `-journal` files beside each, which are
/// part of the store.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum StateFile {
    /// The audit store of record (`AUDIT_SQLITE_PATH` in environment mode).
    Audit,
    /// Discovered endpoints and sampled request shapes
    /// (`DISCOVERY_SQLITE_PATH`).
    Discovery,
    /// The principal directory (`PRINCIPAL_SQLITE_PATH`).
    Principals,
    /// Connections and their credential bindings (`CONNECTIONS_SQLITE_PATH`).
    /// The key files under `CONNECTION_SECRETS_ROOT` stay outside the state
    /// directory, as ADR-0006 keeps them.
    Connections,
    /// Service tokens (`SERVICE_TOKEN_SQLITE_PATH`).
    ServiceTokens,
    /// Policy publication history (`POLICY_HISTORY_SQLITE_PATH`). The name is
    /// fixed now so no later store can take it; whether bundle mode keeps a
    /// policy history beside a bundle-owned policy is decided with bundle
    /// mode itself. In ledger mode the ledger is the history.
    PolicyHistory,
    /// The configuration revision ledger ([`crate::ledger`]), which
    /// environment mode does not have.
    ConfigLedger,
}

impl StateFile {
    /// Every state file, in a fixed order.
    pub const ALL: [Self; 7] = [
        Self::Audit,
        Self::Discovery,
        Self::Principals,
        Self::Connections,
        Self::ServiceTokens,
        Self::PolicyHistory,
        Self::ConfigLedger,
    ];

    /// The store's stable identifier, as a backup manifest names it
    /// ([`crate::backup`]). Like the file name, it never changes meaning.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Audit => "audit",
            Self::Discovery => "discovery",
            Self::Principals => "principals",
            Self::Connections => "connections",
            Self::ServiceTokens => "service_tokens",
            Self::PolicyHistory => "policy_history",
            Self::ConfigLedger => "config_ledger",
        }
    }

    /// The file's name beneath the state directory.
    pub const fn file_name(self) -> &'static str {
        match self {
            Self::Audit => "audit.sqlite3",
            Self::Discovery => "discovery.sqlite3",
            Self::Principals => "principals.sqlite3",
            Self::Connections => "connections.sqlite3",
            Self::ServiceTokens => "service-tokens.sqlite3",
            Self::PolicyHistory => "policy-history.sqlite3",
            Self::ConfigLedger => "config-ledger.sqlite3",
        }
    }

    /// The `PRAGMA application_id` a database under this name carries: the
    /// ledger's "GGLG", and `0` for the gateway's stores, which set none. A
    /// restore refuses an entry that claims another store's identity.
    pub const fn application_id(self) -> i32 {
        match self {
            Self::ConfigLedger => LEDGER_APPLICATION_ID,
            _ => 0,
        }
    }

    /// The field catalog identifier of the setting that locates this store
    /// in environment mode, or `None` for the ledger.
    pub const fn catalog_field(self) -> Option<&'static str> {
        match self {
            Self::Audit => Some("audit_sqlite_path"),
            Self::Discovery => Some("discovery_sqlite_path"),
            Self::Principals => Some("principal_sqlite_path"),
            Self::Connections => Some("connections_sqlite_path"),
            Self::ServiceTokens => Some("service_token_sqlite_path"),
            Self::PolicyHistory => Some("policy_history_sqlite_path"),
            Self::ConfigLedger => None,
        }
    }
}

/// Why a state directory was not admitted or locked. Value-free: no path
/// and no operating-system message, only stable codes. The comment on each
/// variant is the `ggctl` exit code ADR-0008 gives it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StateDirError {
    /// `3`: nothing is at the path.
    Missing,
    /// `3`: the path names something other than a directory.
    NotDirectory,
    /// `3`: the path is a symbolic link, junction or other reparse point.
    Link,
    /// `3`: on Unix, the directory is writable by group or other.
    UnsafePermissions,
    /// `3`: the lock file is a link, a reparse point or not a regular file,
    /// or on Unix is writable by group or other.
    UnsafeLockFile,
    /// `5`: another handle, in this process or another, holds the lock.
    Locked,
    /// `3`: the platform or filesystem cannot take the lock, so exclusive
    /// use cannot be promised.
    LockUnsupported,
    /// `1`: the directory or the lock file could not be inspected, opened or
    /// locked, during `operation`.
    Unavailable { operation: &'static str },
}

impl StateDirError {
    /// The stable code for reports.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Missing => "state_dir.missing",
            Self::NotDirectory => "state_dir.not_directory",
            Self::Link => "state_dir.link",
            Self::UnsafePermissions => "state_dir.unsafe_permissions",
            Self::UnsafeLockFile => "state_dir.unsafe_lock_file",
            Self::Locked => "state_dir.locked",
            Self::LockUnsupported => "state_dir.lock_unsupported",
            Self::Unavailable { .. } => "state_dir.unavailable",
        }
    }
}

impl fmt::Display for StateDirError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing => formatter.write_str("the state directory does not exist"),
            Self::NotDirectory => formatter.write_str("the state directory is not a directory"),
            Self::Link => formatter.write_str(
                "the state directory is a symbolic link, junction or reparse point",
            ),
            Self::UnsafePermissions => {
                formatter.write_str("the state directory is writable by group or other")
            }
            Self::UnsafeLockFile => formatter.write_str(
                "the state directory's lock file is a link, not a regular file, or writable by group or other",
            ),
            Self::Locked => formatter.write_str(
                "another process, or another handle in this one, holds the state directory's lock",
            ),
            Self::LockUnsupported => formatter.write_str(
                "the state directory's filesystem cannot take an exclusive lock",
            ),
            Self::Unavailable { operation } => {
                write!(formatter, "the state directory {operation} failed")
            }
        }
    }
}

impl std::error::Error for StateDirError {}

/// A state directory held under its exclusive lock.
///
/// Clones share the one lock, which is released when the last of them
/// drops. Opening a store beneath the directory takes a reference to a
/// held handle and keeps a clone for as long as the store is open, so no
/// store outlives the lock it was opened under.
#[derive(Clone)]
pub struct StateDirectory {
    held: Arc<Held>,
}

/// The lock and the directory it was taken on.
struct Held {
    /// The directory, absolute, as the caller named it.
    path: PathBuf,
    /// The open, locked lock file. Closing it releases the lock.
    lock: fs::File,
}

impl Drop for Held {
    fn drop(&mut self) {
        // Closing the handle releases the lock as well, but Windows releases
        // a lock left at close only when it gets to it; unlocking first
        // releases it now. A failure leaves the close to release it.
        let _ = self.lock.unlock();
    }
}

impl fmt::Debug for StateDirectory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StateDirectory")
            .finish_non_exhaustive()
    }
}

impl StateDirectory {
    /// Admits the directory at `path` and takes its exclusive lock, creating
    /// the lock file if it does not exist. Never waits: a lock someone else
    /// holds is [`StateDirError::Locked`].
    pub fn acquire(path: &Path) -> Result<Self, StateDirError> {
        let path = std::path::absolute(path).map_err(|_| StateDirError::Missing)?;
        check_directory(&path)?;
        let directory = open_directory(&path)?;
        let lock = open_lock_file(&directory)?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => return Err(StateDirError::Locked),
            Err(TryLockError::Error(error)) if error.kind() == io::ErrorKind::Unsupported => {
                return Err(StateDirError::LockUnsupported)
            }
            Err(TryLockError::Error(_)) => {
                return Err(StateDirError::Unavailable {
                    operation: "lock acquisition",
                })
            }
        }
        Ok(Self {
            held: Arc::new(Held { path, lock }),
        })
    }

    /// The directory, absolute.
    pub fn path(&self) -> &Path {
        &self.held.path
    }

    /// Where `file` lives beneath the directory.
    pub fn file(&self, file: StateFile) -> PathBuf {
        self.held.path.join(file.file_name())
    }

    /// What kind of filesystem the directory is on, for `ggctl doctor`'s
    /// warning. Best effort; see [`filesystem_kind`].
    pub fn filesystem(&self) -> FilesystemKind {
        filesystem_kind(&self.held.path)
    }
}

/// Checks the entry at `path`, without following a link at it, against the
/// state directory's admission rules.
pub(crate) fn check_directory(path: &Path) -> Result<(), StateDirError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| match error.kind() {
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory => StateDirError::Missing,
        _ => StateDirError::Unavailable {
            operation: "directory inspection",
        },
    })?;
    admit_directory(&metadata)
}

/// The admission rules, on metadata that was not read through a link.
fn admit_directory(metadata: &fs::Metadata) -> Result<(), StateDirError> {
    if metadata.file_type().is_symlink() || is_reparse_point(metadata) {
        return Err(StateDirError::Link);
    }
    if !metadata.is_dir() {
        return Err(StateDirError::NotDirectory);
    }
    if !owner_alone_can_write(metadata) {
        return Err(StateDirError::UnsafePermissions);
    }
    Ok(())
}

/// Opens the admitted directory without following a link at its last
/// component, and checks the open handle again: an entry swapped in since
/// the check by path is refused rather than locked.
fn open_directory(path: &Path) -> Result<Dir, StateDirError> {
    let unavailable = || StateDirError::Unavailable {
        operation: "directory open",
    };
    // Resolves `.`, `..` and links above the directory, which are the
    // caller's to trust, so the last component is the directory itself.
    let canonical = fs::canonicalize(path).map_err(|_| unavailable())?;
    let directory = match (canonical.parent(), canonical.file_name()) {
        (Some(parent), Some(name)) => Dir::open_ambient_dir(parent, ambient_authority())
            .and_then(|parent| parent.open_dir_nofollow(name))
            .map_err(|_| unavailable())?,
        // A filesystem root, which cannot be a link.
        _ => Dir::open_ambient_dir(&canonical, ambient_authority()).map_err(|_| unavailable())?,
    };
    let metadata = directory
        .try_clone()
        .and_then(|directory| directory.into_std_file().metadata())
        .map_err(|_| unavailable())?;
    admit_directory(&metadata)?;
    Ok(directory)
}

/// Opens or creates the lock file beneath `directory`, without following a
/// link, and checks the open handle.
fn open_lock_file(directory: &Dir) -> Result<fs::File, StateDirError> {
    let mut options = CapabilityOpenOptions::new();
    // Never truncated: the file's content is never read or written.
    options.read(true).write(true).truncate(false);
    options.follow(FollowSymlinks::No);
    // A FIFO planted under the lock's name must not block the open; the
    // handle check below then refuses it.
    options.nonblock(true);
    owner_only(&mut options);
    // Arbitrate first creation atomically. If another opener created the
    // file, open that same name without attempting to create it again.
    let file = match directory.open_with(LOCK_FILE_NAME, options.create_new(true)) {
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            directory.open_with(LOCK_FILE_NAME, options.create_new(false))
        }
        result => result,
    }
    .map_err(|_| classify_unopenable_lock_file(directory))?
    .into_std();
    let metadata = file.metadata().map_err(|_| StateDirError::Unavailable {
        operation: "lock file inspection",
    })?;
    if metadata.file_type().is_symlink()
        || is_reparse_point(&metadata)
        || !metadata.is_file()
        || !owner_alone_can_write(&metadata)
    {
        return Err(StateDirError::UnsafeLockFile);
    }
    Ok(file)
}

/// Why the lock file could not be opened: a link or something other than
/// a regular file is in its place, or the open failed for another reason.
fn classify_unopenable_lock_file(directory: &Dir) -> StateDirError {
    match directory.symlink_metadata(LOCK_FILE_NAME) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            StateDirError::UnsafeLockFile
        }
        _ => StateDirError::Unavailable {
            operation: "lock file open",
        },
    }
}

/// A new lock file is created readable and writable by its owner alone.
#[cfg(unix)]
fn owner_only(options: &mut CapabilityOpenOptions) {
    // Named rather than imported as `_`: its name is already a reviewed
    // capability alias, and the transport guard would carry that onto `_`.
    use cap_std::fs::OpenOptionsExt;
    OpenOptionsExt::mode(options, 0o600);
}

/// Windows ACLs remain an operator and platform responsibility, as they are
/// for bundle directories.
#[cfg(not(unix))]
fn owner_only(_: &mut CapabilityOpenOptions) {}

/// Whether group and other are denied write: for a file, the right to
/// change it; for a directory, the right to add, rename or remove its
/// entries.
#[cfg(unix)]
pub(crate) fn owner_alone_can_write(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    metadata.mode() & 0o022 == 0
}

/// Windows ACLs remain an operator and platform responsibility, as they are
/// for bundle directories.
#[cfg(not(unix))]
pub(crate) fn owner_alone_can_write(_: &fs::Metadata) -> bool {
    true
}

#[cfg(windows)]
pub(crate) fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & 0x0000_0400 != 0
}

#[cfg(not(windows))]
pub(crate) fn is_reparse_point(_: &fs::Metadata) -> bool {
    false
}
