//! Standalone backups (issue #242; ADR-0008, "Backup and restore"):
//! [`create`] writes one archive of a standalone state directory's stores,
//! [`verify`] reads one back completely, and [`restore`] puts one in place
//! of an empty or prepared state directory, or leaves it as it was.
//!
//! A backup is sensitive recovery material, not configuration: it holds the
//! audit trail, the principal directory, discovery data, service token
//! hashes, the Connections store with its #240 ciphertext, policy history
//! and the configuration revision ledger, whichever of them the state
//! directory holds ([`StateFile`]). It holds nothing else:
//!
//! - **Only the layout's stores.** Each [`StateFile`] that exists is
//!   included; the lock file, SQLite's `-wal`, `-shm` and `-journal` files and
//!   every other entry in the directory are not. Pending OIDC logins and
//!   admin sessions live in the standalone gateway's memory, not in a store,
//!   and caches are rebuilt on start, so none is ever in a backup.
//! - **No secret values or keys.** The token store holds hashes, never
//!   plaintext tokens, and the Connections store holds secrets only as #240
//!   ciphertext. The key files that decrypt it stay under
//!   `CONNECTION_SECRETS_ROOT`, outside the state directory, and are never
//!   read: they are a separate recovery artifact to back up separately.
//!
//! **Create.** The caller holds the state directory's lock, so no gateway
//! runs on it. Each store is admitted (a regular file, not a link or
//! reparse point, and on Unix not writable by group or other) and
//! identified by its device and file number, so two names for one file are
//! snapshotted once and the second store refers to the first one's entry.
//! The ledger shares its file with no store. Each file is snapshotted with
//! `VACUUM INTO` from a read-only connection (`store`), never copied, into a
//! private working directory beside the output; the ledger snapshot is
//! verified in full, as a gateway verifies it at start; every snapshot must
//! pass SQLite's integrity check. The `GatewayBackup` manifest
//! (`docs/schemas/gateway-backup.v1alpha1.schema.json`) records the binary,
//! document and store versions, the logical inventory, counts and each
//! entry's SHA-256. The archive is written to a new hidden file beside the
//! output, owner-only on Unix, flushed, read back with [`verify`]'s every
//! check, and only then linked to the output name, which must not exist and
//! is never replaced. Any failure leaves nothing at the output.
//!
//! **Verify.** The archive must be a regular file within the size bound.
//! Its container (`container`) is read through the shared
//! [`crate::archive::ArchiveGuard`], extracting every entry into a fresh
//! private staging directory beside it: the manifest first, read as a closed
//! document (`manifest`), then exactly its entries in its order, each
//! checked against its SHA-256 as it is copied, then the end record and the
//! digest of the whole archive. Each extracted database must be a SQLite
//! database in rollback-journal mode that passes `PRAGMA integrity_check`
//! and describes exactly as the manifest says; the ledger must pass the
//! ledger's full verification and hold the revisions the manifest names.
//! The staging directory is removed whatever the outcome.
//!
//! **Restore** (`restore`) extracts and verifies the archive exactly as
//! verify does, but into a staging directory beside the target state
//! directory, checks what it staged further, writes the restore marker
//! (`marker`) the next gateway start records and removes, and only then
//! switches the staging directory into the target's place by renames, or
//! leaves the target as it was.
//!
//! Every error is value-free: a stable code and, at most, the store it
//! concerns or an archive entry's position. A digest is integrity evidence,
//! not authenticity: whoever can write an archive can write a consistent
//! one, so a backup must be kept where only its owner can change it.

mod container;
mod manifest;
mod marker;
mod restore;
mod store;

#[cfg(test)]
mod tests;

use std::{
    ffi::OsString,
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use cap_fs_ext::{
    FollowSymlinks, MetadataExt as CapabilityMetadataExt, OpenOptionsFollowExt as _,
    OpenOptionsSyncExt as _,
};
use cap_std::{
    ambient_authority,
    fs::{Dir, OpenOptions as CapabilityOpenOptions},
};
use sha2::{Digest, Sha256};

use crate::archive::{AdmittedEntry, ArchiveLimits, ArchiveRefusal};
use crate::documents::{API_VERSION_V1ALPHA1, BACKUP_KIND};
use crate::ledger::{LedgerError, RevisionId, RevisionLedger};
use crate::state_dir::{is_reparse_point, owner_alone_can_write, StateDirectory, StateFile};

use container::{ContainerError, ContainerReader, ContainerWriter};
use manifest::{
    ArchiveFormatRecord, CountsRecord, DatabaseRecord, EntryRecord, LedgerRecord, Manifest,
    ProducerRecord, StoreRecord,
};
pub use manifest::{ARCHIVE_FORMAT, MANIFEST_ENTRY, MAX_MANIFEST_BYTES, SOURCE_STANDALONE};
pub use marker::{acknowledge_restore_marker, read_restore_marker, MarkerError, RestoreMarker};
pub use restore::{restore, RestoreError, RestoreRequest, RestoreSummary, RestoreWarning};
use store::SqliteFailure;

/// The most bytes one entry may hold.
pub const MAX_ENTRY_BYTES: u64 = 64 * 1024 * 1024 * 1024;
/// The most bytes every entry together may hold.
pub const MAX_DATA_BYTES: u64 = 256 * 1024 * 1024 * 1024;
/// The longest entry name.
const MAX_ENTRY_NAME_BYTES: usize = 64;
/// Hidden names tried before giving up: each is created exclusively, so a
/// name that exists is skipped, never reused.
const ATTEMPTS: usize = 16;
/// Bytes read per call while hashing.
const CHUNK_BYTES: usize = 64 * 1024;
/// The bytes of a database header [`store::is_rollback_database`] reads.
const DATABASE_HEADER_BYTES: usize = 100;

/// The bounds a backup archive is read under: the manifest and one entry per
/// store, each a single-segment name of at most 64 bytes, within the size
/// bounds. Nothing is compressed, so an archive never extracts to more than
/// its own length, which [`MAX_ARCHIVE_BYTES`] bounds before it is read.
pub fn archive_limits() -> ArchiveLimits {
    ArchiveLimits {
        max_entries: StateFile::ALL.len() + 1,
        max_path_bytes: MAX_ENTRY_NAME_BYTES,
        max_segment_bytes: MAX_ENTRY_NAME_BYTES - 1,
        max_depth: 1,
        max_entry_bytes: MAX_ENTRY_BYTES,
        max_total_bytes: MAX_DATA_BYTES,
        ..ArchiveLimits::default()
    }
}

/// The longest archive read: every entry at its longest name, the data
/// bound, and the preamble and end record.
pub const MAX_ARCHIVE_BYTES: u64 = MAX_DATA_BYTES
    + container::minimum_length()
    + (StateFile::ALL.len() as u64 + 1)
        * (container::RECORD_FIXED_BYTES + MAX_ENTRY_NAME_BYTES as u64);

/// The program writing a backup, recorded in its manifest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Producer {
    /// `^[a-z][a-z0-9-]{0,31}$`, such as `ggctl`.
    pub program: &'static str,
    /// Its version, such as `0.1.0`.
    pub version: &'static str,
}

/// What [`create`] writes and where.
#[derive(Clone, Copy, Debug)]
pub struct CreateRequest<'a> {
    /// The archive to create. It must not exist.
    pub output: &'a Path,
    pub producer: Producer,
    /// The time the manifest records; this crate reads no clock.
    pub created_at: SystemTime,
}

/// A backup as its manifest describes it, value-free: fixed names, counts,
/// versions and opaque revision IDs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupSummary {
    /// The manifest's exact document version.
    pub api_version: &'static str,
    /// The container version.
    pub archive_version: u16,
    /// Milliseconds since the Unix epoch, as the producer stamped it.
    pub created_at_ms: u64,
    pub producer_program: String,
    pub producer_version: String,
    /// The SQLite library version that took the snapshots.
    pub sqlite_version: String,
    /// Every store of the layout, in [`StateFile::ALL`] order.
    pub stores: Vec<StoreSummary>,
    /// Database entries, the manifest not counted.
    pub entries: u64,
    /// Bytes of the database entries.
    pub bytes: u64,
    pub tables: u64,
    pub rows: u64,
    pub ledger: Option<LedgerSummary>,
}

/// One store of a backup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoreSummary {
    pub store: StateFile,
    pub included: bool,
    /// The store whose file the entry holding this one is named after:
    /// itself, or for a second name of one file, the first.
    pub entry: Option<StateFile>,
    /// Tables and rows of the entry holding it.
    pub tables: u64,
    pub rows: u64,
}

/// The configuration revision ledger a backup holds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LedgerSummary {
    pub revisions: u64,
    pub desired: RevisionId,
    pub active: Option<RevisionId>,
    /// The document version of the desired revision's bundle.
    pub bundle_api_version: String,
}

/// What made a store unusable for a backup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreProblem {
    /// The store's file is a symbolic link, junction or reparse point.
    Link,
    /// The store's name is something other than a regular file.
    NotRegularFile,
    /// On Unix, the store's file is writable by group or other.
    UnsafePermissions,
    /// The store could not be opened, read or snapshotted.
    Unavailable,
    /// The snapshot is not a database or fails SQLite's integrity check.
    Corrupt,
    /// The ledger snapshot does not pass the ledger's verification.
    LedgerInvalid,
    /// The ledger is the same file as another store.
    LedgerShared,
}

/// What an archive entry did not match.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryProblem {
    /// The entry's bytes do not match the SHA-256 the manifest records.
    ChecksumMismatch,
    /// The entry is not a rollback-journal SQLite database that passes the
    /// integrity check.
    IntegrityFailed,
    /// The entry passes but is not the database the manifest describes.
    DescriptionMismatch,
    /// The ledger entry does not pass the ledger's verification.
    LedgerInvalid,
    /// The ledger verifies but does not hold the revisions the manifest
    /// names.
    LedgerMismatch,
}

/// Why a backup was not created or did not verify. Value-free: no path, no
/// value from a store or the archive, no library message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BackupError {
    /// The state directory could not be opened to read its stores.
    StateDirUnavailable,
    /// A store cannot be backed up.
    Store {
        store: StateFile,
        problem: StoreProblem,
    },
    /// The state directory holds none of the layout's stores.
    NothingToBackUp,
    /// Something exists at the output path.
    OutputExists,
    /// The archive or its working files could not be created, written,
    /// flushed or linked into place beside the output.
    OutputUnusable,
    /// On Unix, the filesystem did not keep the archive owner-only.
    PermissionsUnavailable,
    /// The archive could not be opened or read.
    ArchiveUnreadable,
    /// The archive is a link, or not a regular file.
    ArchiveNotRegularFile,
    /// The archive is longer than any backup can be.
    ArchiveTooLarge,
    /// The staging directory could not be created or written.
    StagingUnavailable,
    /// The shared admission rules refused the archive.
    Refused(ArchiveRefusal),
    /// The file is not a backup archive.
    NotABackup,
    /// The file is a PostgreSQL dump: cluster state is restored with #241's
    /// runbooks, never through a standalone backup.
    PostgresDump,
    /// A backup archive of a container version this build does not read.
    UnsupportedArchiveVersion,
    /// The first entry is not the manifest.
    ManifestMissing,
    /// The manifest is not a valid `GatewayBackup` document.
    ManifestInvalid,
    /// The manifest is not a document version this build reads.
    UnsupportedManifestVersion,
    /// The entry at `position` is not the next one the manifest lists.
    UnexpectedEntry { position: usize },
    /// The archive ends before an entry the manifest lists.
    EntryMissing,
    /// The end record's digest is not the archive's.
    ArchiveDigestMismatch,
    /// The entry holding `store` does not match the manifest.
    Entry {
        store: StateFile,
        problem: EntryProblem,
    },
}

impl BackupError {
    /// The stable code for reports.
    pub fn code(&self) -> &'static str {
        match self {
            Self::StateDirUnavailable => "state_dir.unavailable",
            Self::Store { problem, .. } => match problem {
                StoreProblem::Link => "backup.store_link",
                StoreProblem::NotRegularFile => "backup.store_not_regular_file",
                StoreProblem::UnsafePermissions => "backup.store_unsafe_permissions",
                StoreProblem::Unavailable => "backup.store_unavailable",
                StoreProblem::Corrupt => "backup.store_corrupt",
                StoreProblem::LedgerInvalid => "backup.ledger_invalid",
                StoreProblem::LedgerShared => "backup.ledger_shared",
            },
            Self::NothingToBackUp => "backup.nothing_to_back_up",
            Self::OutputExists => "backup.output_exists",
            Self::OutputUnusable => "backup.output_unusable",
            Self::PermissionsUnavailable => "backup.permissions_unavailable",
            Self::ArchiveUnreadable => "backup.archive_unreadable",
            Self::ArchiveNotRegularFile => "backup.archive_not_regular_file",
            Self::ArchiveTooLarge => "backup.archive_too_large",
            Self::StagingUnavailable => "backup.staging_unavailable",
            Self::Refused(refusal) => refusal.code.as_str(),
            Self::NotABackup => "backup.not_a_backup",
            Self::PostgresDump => "backup.postgres_unsupported",
            Self::UnsupportedArchiveVersion => "backup.unsupported_archive_version",
            Self::ManifestMissing => "backup.manifest_missing",
            Self::ManifestInvalid => "backup.manifest_invalid",
            Self::UnsupportedManifestVersion => "backup.unsupported_manifest_version",
            Self::UnexpectedEntry { .. } => "backup.unexpected_entry",
            Self::EntryMissing => "backup.entry_missing",
            Self::ArchiveDigestMismatch => "backup.archive_digest_mismatch",
            Self::Entry { problem, .. } => match problem {
                EntryProblem::ChecksumMismatch => "backup.checksum_mismatch",
                EntryProblem::IntegrityFailed => "backup.store_integrity_failed",
                EntryProblem::DescriptionMismatch => "backup.store_mismatch",
                EntryProblem::LedgerInvalid => "backup.ledger_verification_failed",
                EntryProblem::LedgerMismatch => "backup.ledger_mismatch",
            },
        }
    }

    /// The store the error concerns, when it concerns one.
    pub fn store(&self) -> Option<StateFile> {
        match self {
            Self::Store { store, .. } | Self::Entry { store, .. } => Some(*store),
            _ => None,
        }
    }
}

impl fmt::Display for BackupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(refusal) => refusal.fmt(formatter),
            Self::UnexpectedEntry { position } => {
                write!(formatter, "entry {position}: error[{}]", self.code())
            }
            _ => match self.store() {
                Some(store) => write!(formatter, "store {}: error[{}]", store.id(), self.code()),
                None => write!(formatter, "error[{}]", self.code()),
            },
        }
    }
}

impl std::error::Error for BackupError {}

/// Backs up the stores of the held `state_dir` into a new archive at
/// `request.output`, verifies it, and returns what it holds.
pub fn create(
    state_dir: &StateDirectory,
    request: &CreateRequest<'_>,
) -> Result<BackupSummary, BackupError> {
    let output = request.output;
    let place = Place::of(output).ok_or(BackupError::OutputUnusable)?;
    match fs::symlink_metadata(output) {
        Ok(_) => return Err(BackupError::OutputExists),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err(BackupError::OutputUnusable),
    }
    let groups = group(&inventory(state_dir)?)?;
    if groups.is_empty() {
        return Err(BackupError::NothingToBackUp);
    }

    let work = Private::directory(&place, "work").ok_or(BackupError::OutputUnusable)?;
    let mut snapshots = Vec::with_capacity(groups.len());
    let mut ledger = None;
    for (named, _) in &groups {
        let snapshot = snapshot(state_dir, work.path(), *named)?;
        if *named == StateFile::ConfigLedger {
            ledger = Some(
                ledger_record(work.path()).map_err(|problem| BackupError::Store {
                    store: StateFile::ConfigLedger,
                    problem: match problem {
                        LedgerCheck::Invalid => StoreProblem::LedgerInvalid,
                        LedgerCheck::Unavailable => StoreProblem::Unavailable,
                    },
                })?,
            );
        }
        snapshots.push(snapshot);
    }
    let mut entries = Vec::with_capacity(snapshots.len());
    for (path, named) in &snapshots {
        let store_error = |problem| BackupError::Store {
            store: *named,
            problem,
        };
        store::normalize(path).map_err(|failure| store_error(store_problem(failure)))?;
        let database =
            store::describe(path).map_err(|failure| store_error(store_problem(failure)))?;
        let (bytes, sha256) = hash_file(path).map_err(|_| BackupError::OutputUnusable)?;
        entries.push(EntryRecord {
            name: named.file_name().to_owned(),
            bytes,
            sha256,
            database,
        });
    }

    let stores: Vec<StoreRecord> = StateFile::ALL
        .into_iter()
        .map(|store| {
            let entry = groups
                .iter()
                .find(|(_, members)| members.contains(&store))
                .map(|(named, _)| named.file_name().to_owned());
            StoreRecord {
                store: store.id().to_owned(),
                file: store.file_name().to_owned(),
                included: entry.is_some(),
                entry,
            }
        })
        .collect();
    let manifest = Manifest {
        api_version: API_VERSION_V1ALPHA1.to_owned(),
        kind: BACKUP_KIND.to_owned(),
        archive: ArchiveFormatRecord {
            format: ARCHIVE_FORMAT.to_owned(),
            version: container::FORMAT_VERSION,
        },
        source: SOURCE_STANDALONE.to_owned(),
        created_by: ProducerRecord {
            program: request.producer.program.to_owned(),
            version: request.producer.version.to_owned(),
        },
        created_at_ms: milliseconds(request.created_at),
        sqlite_version: rusqlite::version().to_owned(),
        counts: CountsRecord::of(&stores, &entries),
        stores,
        entries,
        ledger,
    };
    // A manifest this build would refuse to read is never written.
    manifest.check()?;
    let encoded = manifest.to_bytes()?;
    if u64::try_from(encoded.len()).unwrap_or(u64::MAX) > MAX_MANIFEST_BYTES {
        return Err(BackupError::ManifestInvalid);
    }

    let partial = Private::file(&place, "partial").ok_or(BackupError::OutputUnusable)?;
    write_archive(partial.path(), &encoded, &manifest.entries, work.path())
        .map_err(|_| BackupError::OutputUnusable)?;
    // The snapshots are in the archive; they go before it is read back, so
    // the two never take space together with the staging copy.
    drop(work);
    if !is_owner_only(partial.path()) {
        return Err(BackupError::PermissionsUnavailable);
    }
    let staging = Private::directory(&place, "verify").ok_or(BackupError::StagingUnavailable)?;
    let read = read_archive(partial.path(), staging.path())?;
    drop(staging);
    if read != manifest {
        return Err(BackupError::ManifestInvalid);
    }
    partial.publish(output)?;
    Ok(summary(&manifest))
}

/// Reads the archive at `archive` completely, extracting it into a new
/// staging directory beside it, and returns what it holds. The staging
/// directory is removed whatever the outcome.
pub fn verify(archive: &Path) -> Result<BackupSummary, BackupError> {
    let place = Place::of(archive).ok_or(BackupError::ArchiveUnreadable)?;
    // Refused before anything is created beside it.
    drop(open_archive(archive)?);
    let staging = Private::directory(&place, "verify").ok_or(BackupError::StagingUnavailable)?;
    let manifest = read_archive(archive, staging.path())?;
    drop(staging);
    Ok(summary(&manifest))
}

/// The archive's directory and file name, which hidden names beside it are
/// built from.
struct Place {
    directory: PathBuf,
    name: OsString,
}

impl Place {
    fn of(path: &Path) -> Option<Self> {
        let name = path.file_name()?.to_owned();
        let directory = match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
            _ => PathBuf::from("."),
        };
        Some(Self { directory, name })
    }

    /// `.NAME.ggbk-PURPOSE-PID-N`: hidden, and never taken for the archive.
    fn hidden(&self, purpose: &str, attempt: usize) -> PathBuf {
        let mut name = OsString::from(".");
        name.push(&self.name);
        name.push(format!(".ggbk-{purpose}-{}-{attempt}", std::process::id()));
        self.directory.join(name)
    }
}

/// A file or directory this process created under a hidden name beside the
/// archive, removed when dropped unless it was published.
struct Private {
    path: PathBuf,
    directory: bool,
    published: bool,
}

impl Private {
    /// A new directory, `0700` on Unix.
    fn directory(place: &Place, purpose: &str) -> Option<Self> {
        Self::create(place, purpose, true, create_private_directory)
    }

    /// A new empty file, `0600` on Unix.
    fn file(place: &Place, purpose: &str) -> Option<Self> {
        Self::create(place, purpose, false, |path| {
            create_private_file(path).map(drop)
        })
    }

    fn create(
        place: &Place,
        purpose: &str,
        directory: bool,
        create: impl Fn(&Path) -> io::Result<()>,
    ) -> Option<Self> {
        for attempt in 0..ATTEMPTS {
            let path = place.hidden(purpose, attempt);
            match create(&path) {
                Ok(()) => {
                    return Some(Self {
                        path,
                        directory,
                        published: false,
                    })
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(_) => return None,
            }
        }
        None
    }

    fn path(&self) -> &Path {
        &self.path
    }

    /// Links the file to `output` without replacing anything there, then
    /// removes its hidden name.
    fn publish(mut self, output: &Path) -> Result<(), BackupError> {
        fs::hard_link(&self.path, output).map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                BackupError::OutputExists
            } else {
                BackupError::OutputUnusable
            }
        })?;
        self.published = true;
        // The archive is in place under its name; a hidden second name left
        // behind is never read as a backup, and flushing the directory is
        // best effort once the archive exists.
        let _ = fs::remove_file(&self.path);
        if let Some(parent) = Place::of(output) {
            let _ = sync_directory(&parent.directory);
        }
        Ok(())
    }
}

impl Drop for Private {
    fn drop(&mut self) {
        if self.published {
            return;
        }
        // Does not follow links: only what this process created goes.
        let _ = if self.directory {
            fs::remove_dir_all(&self.path)
        } else {
            fs::remove_file(&self.path)
        };
    }
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(0o700).create(path)
}

/// Windows has no mode bits: the new directory inherits the ACL of the one
/// it is created in, which is the operator's.
#[cfg(not(unix))]
fn create_private_directory(path: &Path) -> io::Result<()> {
    fs::create_dir(path)
}

/// Creates a new file, never opening an existing one: `0600` on Unix.
fn create_private_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

/// Whether group and other have no access to the file at `path`.
#[cfg(unix)]
fn is_owner_only(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    fs::symlink_metadata(path).is_ok_and(|metadata| metadata.permissions().mode() & 0o077 == 0)
}

/// Windows has no mode bits; the file's ACL is the operator's.
#[cfg(not(unix))]
fn is_owner_only(_: &Path) -> bool {
    true
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

/// Windows cannot open a directory for flushing through the standard
/// library; NTFS journals the link itself.
#[cfg(not(unix))]
fn sync_directory(_: &Path) -> io::Result<()> {
    Ok(())
}

fn milliseconds(time: SystemTime) -> u64 {
    // Before the epoch is recorded as the epoch; the manifest bounds the
    // value to what I-JSON represents exactly.
    let milliseconds = time
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis());
    u64::try_from(milliseconds)
        .unwrap_or(u64::MAX)
        .min((1 << 53) - 1)
}

/// A store present in the state directory, with its file's identity.
struct Present {
    store: StateFile,
    /// The device and file number, from an open handle.
    identity: (u64, u64),
}

/// Admits every store the state directory holds, in [`StateFile::ALL`]
/// order. Absent stores are skipped.
fn inventory(state_dir: &StateDirectory) -> Result<Vec<Present>, BackupError> {
    let directory = Dir::open_ambient_dir(state_dir.path(), ambient_authority())
        .map_err(|_| BackupError::StateDirUnavailable)?;
    let mut present = Vec::new();
    for store in StateFile::ALL {
        if let Some(identity) = admit_store(state_dir, &directory, store)? {
            present.push(Present { store, identity });
        }
    }
    Ok(present)
}

/// The identity of `store`'s file, once it is admitted; `None` when the
/// state directory does not hold it.
fn admit_store(
    state_dir: &StateDirectory,
    directory: &Dir,
    store: StateFile,
) -> Result<Option<(u64, u64)>, BackupError> {
    let refuse = |problem| BackupError::Store { store, problem };
    // Checked by path first, without following a link: a link, junction or
    // anything but a regular file is refused before it is opened.
    match fs::symlink_metadata(state_dir.file(store)) {
        Ok(metadata) if metadata.file_type().is_symlink() || is_reparse_point(&metadata) => {
            return Err(refuse(StoreProblem::Link))
        }
        Ok(metadata) if !metadata.is_file() => return Err(refuse(StoreProblem::NotRegularFile)),
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(refuse(StoreProblem::Unavailable)),
    }
    let mut options = CapabilityOpenOptions::new();
    options.read(true);
    options.follow(FollowSymlinks::No);
    // A FIFO swapped in since the check must not block the open; the handle
    // check below then refuses it.
    options.nonblock(true);
    let file = directory
        .open_with(store.file_name(), &options)
        .map_err(|_| refuse(StoreProblem::Unavailable))?;
    // `CapabilityMetadataExt`, read from the open handle as Windows needs.
    let handle = file
        .metadata()
        .map_err(|_| refuse(StoreProblem::Unavailable))?;
    let identity = (handle.dev(), handle.ino());
    let metadata = file
        .into_std()
        .metadata()
        .map_err(|_| refuse(StoreProblem::Unavailable))?;
    if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
        return Err(refuse(StoreProblem::Link));
    }
    if !metadata.is_file() {
        return Err(refuse(StoreProblem::NotRegularFile));
    }
    if !owner_alone_can_write(&metadata) {
        return Err(refuse(StoreProblem::UnsafePermissions));
    }
    Ok(Some(identity))
}

/// Groups the present stores by file: each group is named after its first
/// store, in [`StateFile::ALL`] order, and lists every store it holds.
fn group(present: &[Present]) -> Result<Vec<(StateFile, Vec<StateFile>)>, BackupError> {
    let mut groups: Vec<(StateFile, (u64, u64), Vec<StateFile>)> = Vec::new();
    for found in present {
        match groups
            .iter_mut()
            .find(|(_, identity, _)| *identity == found.identity)
        {
            Some((named, _, members)) => {
                if found.store == StateFile::ConfigLedger || *named == StateFile::ConfigLedger {
                    return Err(BackupError::Store {
                        store: StateFile::ConfigLedger,
                        problem: StoreProblem::LedgerShared,
                    });
                }
                members.push(found.store);
            }
            None => groups.push((found.store, found.identity, vec![found.store])),
        }
    }
    Ok(groups
        .into_iter()
        .map(|(named, _, members)| (named, members))
        .collect())
}

fn store_problem(failure: SqliteFailure) -> StoreProblem {
    match failure {
        SqliteFailure::Corrupt => StoreProblem::Corrupt,
        SqliteFailure::Unavailable => StoreProblem::Unavailable,
    }
}

/// Snapshots `store` into the working directory under its own file name.
fn snapshot(
    state_dir: &StateDirectory,
    work: &Path,
    store: StateFile,
) -> Result<(PathBuf, StateFile), BackupError> {
    let path = work.join(store.file_name());
    // Created empty and owner-only first: `VACUUM INTO` fills an empty file
    // and keeps its mode.
    create_private_file(&path).map_err(|_| BackupError::OutputUnusable)?;
    store::snapshot(&state_dir.file(store), &path).map_err(|failure| BackupError::Store {
        store,
        problem: store_problem(failure),
    })?;
    Ok((path, store))
}

/// Why a ledger copy did not yield a record.
enum LedgerCheck {
    Invalid,
    Unavailable,
}

/// Verifies the ledger copy in `directory`, which this process owns, as a
/// gateway does at start, and records its state.
///
/// The copy is verified through a read-only connection, so its bytes stay
/// exactly the ones the archive's checksum covers: a restore moves them into
/// place unchanged.
fn ledger_record(directory: &Path) -> Result<LedgerRecord, LedgerCheck> {
    let held = StateDirectory::acquire(directory).map_err(|_| LedgerCheck::Unavailable)?;
    let state = RevisionLedger::inspect(&held).map_err(ledger_check)?;
    Ok(LedgerRecord {
        revisions: state.revisions,
        desired: state.desired.revision.as_str().to_owned(),
        active: state.active.map(|active| active.as_str().to_owned()),
        bundle_api_version: state.desired.bundle.api_version.as_str().to_owned(),
    })
}

fn ledger_check(error: LedgerError) -> LedgerCheck {
    match error {
        LedgerError::Unavailable { .. } => LedgerCheck::Unavailable,
        _ => LedgerCheck::Invalid,
    }
}

/// The SHA-256 and length of the file at `path`.
fn hash_file(path: &Path) -> io::Result<(u64, String)> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; CHUNK_BYTES];
    let mut length: u64 = 0;
    loop {
        let read = match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        hasher.update(&buffer[..read]);
        length = length.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
    }
    Ok((length, hex::encode(hasher.finalize())))
}

/// Writes the archive into the empty file at `path`: the manifest, then
/// each snapshot in `work` in the manifest's order, each checked against
/// the digest the manifest records, then flushes it to storage.
fn write_archive(
    path: &Path,
    manifest: &[u8],
    entries: &[EntryRecord],
    work: &Path,
) -> io::Result<()> {
    let file = OpenOptions::new().write(true).open(path)?;
    let mut writer = ContainerWriter::new(BufWriter::new(file))?;
    let length = u64::try_from(manifest.len()).unwrap_or(u64::MAX);
    writer.file(MANIFEST_ENTRY, length, manifest)?;
    for entry in entries {
        let source = File::open(work.join(&entry.name))?;
        let digest = writer.file(&entry.name, entry.bytes, BufReader::new(source))?;
        if hex::encode(digest) != entry.sha256 {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
    }
    let file = writer
        .finish()?
        .into_inner()
        .map_err(|error| error.into_error())?;
    file.sync_all()
}

/// Opens the archive at `path`, refusing anything but a regular file within
/// the size bound, and returns it with its length.
fn open_archive(path: &Path) -> Result<(File, u64), BackupError> {
    let place = Place::of(path).ok_or(BackupError::ArchiveUnreadable)?;
    let directory = Dir::open_ambient_dir(&place.directory, ambient_authority())
        .map_err(|_| BackupError::ArchiveUnreadable)?;
    match directory.symlink_metadata(&place.name) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err(BackupError::ArchiveNotRegularFile)
        }
        Ok(_) => {}
        Err(_) => return Err(BackupError::ArchiveUnreadable),
    }
    let mut options = CapabilityOpenOptions::new();
    options.read(true);
    options.follow(FollowSymlinks::No);
    options.nonblock(true);
    let file = directory
        .open_with(&place.name, &options)
        .map_err(|_| BackupError::ArchiveUnreadable)?
        .into_std();
    let metadata = file
        .metadata()
        .map_err(|_| BackupError::ArchiveUnreadable)?;
    if metadata.file_type().is_symlink() || is_reparse_point(&metadata) || !metadata.is_file() {
        return Err(BackupError::ArchiveNotRegularFile);
    }
    if metadata.len() > MAX_ARCHIVE_BYTES {
        return Err(BackupError::ArchiveTooLarge);
    }
    Ok((file, metadata.len()))
}

fn container_error(error: ContainerError) -> BackupError {
    match error {
        ContainerError::Refused(refusal) => BackupError::Refused(refusal),
        ContainerError::NotABackup => BackupError::NotABackup,
        ContainerError::PostgresDump => BackupError::PostgresDump,
        ContainerError::UnsupportedVersion => BackupError::UnsupportedArchiveVersion,
        ContainerError::DigestMismatch => BackupError::ArchiveDigestMismatch,
    }
}

/// A staging file that hashes what it is written.
struct HashingFile {
    file: BufWriter<File>,
    hasher: Sha256,
}

impl Write for HashingFile {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let written = self.file.write(buffer)?;
        self.hasher.update(&buffer[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

/// Reads the archive at `archive` completely into the empty directory
/// `staging` and verifies it, returning its manifest.
fn read_archive(archive: &Path, staging: &Path) -> Result<Manifest, BackupError> {
    let (file, length) = open_archive(archive)?;
    let mut reader = ContainerReader::open(BufReader::new(file), length, archive_limits())
        .map_err(container_error)?;
    let manifest = match reader.next().map_err(container_error)? {
        Some(AdmittedEntry::File(entry)) if entry.path().as_str() == MANIFEST_ENTRY => {
            if entry.size() > MAX_MANIFEST_BYTES {
                return Err(BackupError::ManifestInvalid);
            }
            let mut bytes = Vec::new();
            reader.copy(&entry, &mut bytes).map_err(container_error)?;
            Manifest::parse(&bytes)?
        }
        _ => return Err(BackupError::ManifestMissing),
    };
    for expected in &manifest.entries {
        let entry = match reader.next().map_err(container_error)? {
            Some(AdmittedEntry::File(entry)) => entry,
            Some(AdmittedEntry::Directory(directory)) => {
                return Err(BackupError::UnexpectedEntry {
                    position: directory.position(),
                })
            }
            None => return Err(BackupError::EntryMissing),
        };
        if entry.path().as_str() != expected.name || entry.size() != expected.bytes {
            return Err(BackupError::UnexpectedEntry {
                position: entry.position(),
            });
        }
        let store = manifest
            .store_of(&expected.name)
            .ok_or(BackupError::ManifestInvalid)?;
        let file = create_private_file(&staging.join(&expected.name))
            .map_err(|_| BackupError::StagingUnavailable)?;
        let mut sink = HashingFile {
            file: BufWriter::new(file),
            hasher: Sha256::new(),
        };
        reader.copy(&entry, &mut sink).map_err(container_error)?;
        sink.flush().map_err(|_| BackupError::StagingUnavailable)?;
        if hex::encode(sink.hasher.finalize()) != expected.sha256 {
            return Err(BackupError::Entry {
                store,
                problem: EntryProblem::ChecksumMismatch,
            });
        }
    }
    match reader.next().map_err(container_error)? {
        None => {}
        Some(AdmittedEntry::File(entry)) => {
            return Err(BackupError::UnexpectedEntry {
                position: entry.position(),
            })
        }
        Some(AdmittedEntry::Directory(directory)) => {
            return Err(BackupError::UnexpectedEntry {
                position: directory.position(),
            })
        }
    }
    reader.finish().map_err(container_error)?;

    for expected in &manifest.entries {
        let store = manifest
            .store_of(&expected.name)
            .ok_or(BackupError::ManifestInvalid)?;
        let entry_error = |problem| BackupError::Entry { store, problem };
        let path = staging.join(&expected.name);
        if !store::is_rollback_database(&read_header(&path)?) {
            return Err(entry_error(EntryProblem::IntegrityFailed));
        }
        let database: DatabaseRecord = store::describe(&path).map_err(|failure| match failure {
            SqliteFailure::Corrupt => entry_error(EntryProblem::IntegrityFailed),
            SqliteFailure::Unavailable => BackupError::StagingUnavailable,
        })?;
        if database != expected.database {
            return Err(entry_error(EntryProblem::DescriptionMismatch));
        }
    }
    if let Some(expected) = &manifest.ledger {
        let entry_error = |problem| BackupError::Entry {
            store: StateFile::ConfigLedger,
            problem,
        };
        let found = ledger_record(staging).map_err(|problem| match problem {
            LedgerCheck::Invalid => entry_error(EntryProblem::LedgerInvalid),
            LedgerCheck::Unavailable => BackupError::StagingUnavailable,
        })?;
        if &found != expected {
            return Err(entry_error(EntryProblem::LedgerMismatch));
        }
    }
    Ok(manifest)
}

/// The first bytes of a staged database, as many as there are.
fn read_header(path: &Path) -> Result<Vec<u8>, BackupError> {
    let mut header = Vec::with_capacity(DATABASE_HEADER_BYTES);
    File::open(path)
        .and_then(|file| {
            file.take(DATABASE_HEADER_BYTES as u64)
                .read_to_end(&mut header)
        })
        .map_err(|_| BackupError::StagingUnavailable)?;
    Ok(header)
}

fn summary(manifest: &Manifest) -> BackupSummary {
    let stores = StateFile::ALL
        .into_iter()
        .map(|store| {
            let entry = manifest
                .store(store)
                .and_then(|record| record.entry.as_deref());
            let database = entry.and_then(|name| {
                manifest
                    .entries
                    .iter()
                    .find(|entry| entry.name == name)
                    .map(|entry| &entry.database)
            });
            StoreSummary {
                store,
                included: entry.is_some(),
                entry: entry.and_then(|name| manifest.store_of(name)),
                tables: database.map_or(0, |database| {
                    u64::try_from(database.tables.len()).unwrap_or(u64::MAX)
                }),
                rows: database.map_or(0, |database| {
                    database
                        .tables
                        .iter()
                        .map(|table| table.rows)
                        .fold(0_u64, u64::saturating_add)
                }),
            }
        })
        .collect();
    BackupSummary {
        api_version: API_VERSION_V1ALPHA1,
        archive_version: manifest.archive.version,
        created_at_ms: manifest.created_at_ms,
        producer_program: manifest.created_by.program.clone(),
        producer_version: manifest.created_by.version.clone(),
        sqlite_version: manifest.sqlite_version.clone(),
        stores,
        entries: manifest.counts.entries,
        bytes: manifest.counts.bytes,
        tables: manifest.counts.tables,
        rows: manifest.counts.rows,
        ledger: manifest.ledger.as_ref().and_then(|ledger| {
            Some(LedgerSummary {
                revisions: ledger.revisions,
                desired: RevisionId::parse(&ledger.desired)?,
                active: match &ledger.active {
                    Some(active) => Some(RevisionId::parse(active)?),
                    None => None,
                },
                bundle_api_version: ledger.bundle_api_version.clone(),
            })
        }),
    }
}
