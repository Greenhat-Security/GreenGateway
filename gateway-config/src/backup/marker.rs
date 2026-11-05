//! The restore marker: [`RESTORE_MARKER_FILE_NAME`] beneath a state
//! directory `ggctl backup restore` produced, which the next gateway start
//! reads to record `config.restore_detected` and then removes.
//!
//! The marker is written into the staging directory with the restored
//! stores, flushed, and moved into place with them, so a restored directory
//! always carries one and a directory that was never restored never does. It
//! is a closed JSON document of one version, owner-only on Unix, and holds
//! only what that audit event may carry: an opaque restore ID, times, the
//! programs and document versions involved, the restored stores' fixed
//! names and the ledger's opaque revision IDs. Never a path, an archive
//! name or a store's content.
//!
//! A marker that is a link, not a regular file, writable by group or other,
//! too large, or not exactly this document is refused rather than ignored:
//! the state directory was changed by something other than a restore, and a
//! gateway refuses to start from it until an operator looks.

use std::{
    fs::{self, File},
    io::{self, Read, Write},
    path::Path,
};

use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt as _, OpenOptionsSyncExt as _};
use cap_std::{
    ambient_authority,
    fs::{Dir, OpenOptions as CapabilityOpenOptions},
};
use serde::{Deserialize, Serialize};

use crate::documents::{api_versions_of, BACKUP_KIND};
use crate::ledger::RevisionId;
use crate::state_dir::{
    is_reparse_point, owner_alone_can_write, StateDirectory, StateFile, RESTORE_MARKER_FILE_NAME,
};

use super::{create_private_file, sync_directory};

/// The marker document's `kind`.
const MARKER_KIND: &str = "GatewayRestoreMarker";
/// The one marker version this build writes and reads.
const MARKER_VERSION: u16 = 1;
/// The largest marker read: a marker naming every store is far smaller.
const MAX_MARKER_BYTES: u64 = 16 * 1024;
/// `rst-` and 32 lowercase hexadecimal digits.
const RESTORE_ID_PREFIX: &str = "rst-";

/// A completed restore, as its marker records it. Value-free: an opaque ID,
/// times, program and document versions, fixed store names and opaque
/// revision IDs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestoreMarker {
    /// `rst-` and 32 lowercase hexadecimal digits, unique to the restore.
    pub restore_id: String,
    /// Milliseconds since the Unix epoch, as the restoring program stamped
    /// it.
    pub restored_at_ms: u64,
    pub restored_by_program: String,
    pub restored_by_version: String,
    /// The target held stores, which the restore replaced.
    pub replaced: bool,
    /// The backup manifest's exact document version.
    pub backup_api_version: String,
    pub backup_created_at_ms: u64,
    pub backup_created_by_program: String,
    pub backup_created_by_version: String,
    /// The restored stores, in [`StateFile::ALL`] order.
    pub stores: Vec<StateFile>,
    /// The restored ledger's desired and active revisions, when it holds a
    /// ledger.
    pub ledger: Option<(RevisionId, Option<RevisionId>)>,
}

impl RestoreMarker {
    /// The restore ID for a restore's 16 random bytes.
    pub(super) fn restore_id(nonce: &[u8; 16]) -> String {
        format!("{RESTORE_ID_PREFIX}{}", hex::encode(nonce))
    }
}

/// Why a restore marker could not be read or removed. Value-free.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MarkerError {
    /// The marker is a link, not a regular file, or on Unix writable by
    /// group or other.
    Unsafe,
    /// The marker is too large, or not exactly a marker document of the
    /// version this build reads.
    Invalid,
    /// The marker could not be opened, read or removed.
    Unavailable,
}

impl MarkerError {
    /// The stable code for reports and startup errors.
    pub fn code(self) -> &'static str {
        match self {
            Self::Unsafe => "restore.marker_unsafe",
            Self::Invalid => "restore.marker_invalid",
            Self::Unavailable => "restore.marker_unavailable",
        }
    }
}

impl std::fmt::Display for MarkerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "error[{}]", self.code())
    }
}

impl std::error::Error for MarkerError {}

/// The marker exactly as it is serialized.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct MarkerDocument {
    kind: String,
    version: u16,
    restore_id: String,
    restored_at_ms: u64,
    restored_by: ProgramRecord,
    replaced: bool,
    backup: BackupRecord,
    stores: Vec<String>,
    ledger: Option<LedgerRecord>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProgramRecord {
    program: String,
    version: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct BackupRecord {
    api_version: String,
    created_at_ms: u64,
    created_by: ProgramRecord,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LedgerRecord {
    desired: String,
    active: Option<String>,
}

impl MarkerDocument {
    fn of(marker: &RestoreMarker) -> Self {
        Self {
            kind: MARKER_KIND.to_owned(),
            version: MARKER_VERSION,
            restore_id: marker.restore_id.clone(),
            restored_at_ms: marker.restored_at_ms,
            restored_by: ProgramRecord {
                program: marker.restored_by_program.clone(),
                version: marker.restored_by_version.clone(),
            },
            replaced: marker.replaced,
            backup: BackupRecord {
                api_version: marker.backup_api_version.clone(),
                created_at_ms: marker.backup_created_at_ms,
                created_by: ProgramRecord {
                    program: marker.backup_created_by_program.clone(),
                    version: marker.backup_created_by_version.clone(),
                },
            },
            stores: marker
                .stores
                .iter()
                .map(|store| store.id().to_owned())
                .collect(),
            ledger: marker
                .ledger
                .as_ref()
                .map(|(desired, active)| LedgerRecord {
                    desired: desired.as_str().to_owned(),
                    active: active.as_ref().map(|active| active.as_str().to_owned()),
                }),
        }
    }

    /// The marker this document records, when it is exactly a marker of this
    /// version: the grammar of every member is checked, and the stores must
    /// be distinct names of the layout in its order.
    fn marker(self) -> Option<RestoreMarker> {
        if self.kind != MARKER_KIND
            || self.version != MARKER_VERSION
            || !is_restore_id(&self.restore_id)
            || !is_program_record(&self.restored_by)
            || !is_program_record(&self.backup.created_by)
            || !api_versions_of(BACKUP_KIND).any(|version| version == self.backup.api_version)
            || self.stores.is_empty()
        {
            return None;
        }
        let mut stores = Vec::with_capacity(self.stores.len());
        let mut layout = StateFile::ALL.into_iter();
        for id in &self.stores {
            // `find` consumes the layout up to the match, so the stores must
            // come in layout order, each once.
            stores.push(layout.find(|store| store.id() == id)?);
        }
        let ledger = match self.ledger {
            None => None,
            Some(record) => Some((
                RevisionId::parse(&record.desired)?,
                match record.active {
                    None => None,
                    Some(active) => Some(RevisionId::parse(&active)?),
                },
            )),
        };
        if ledger.is_some() != stores.contains(&StateFile::ConfigLedger) {
            return None;
        }
        Some(RestoreMarker {
            restore_id: self.restore_id,
            restored_at_ms: self.restored_at_ms,
            restored_by_program: self.restored_by.program,
            restored_by_version: self.restored_by.version,
            replaced: self.replaced,
            backup_api_version: self.backup.api_version,
            backup_created_at_ms: self.backup.created_at_ms,
            backup_created_by_program: self.backup.created_by.program,
            backup_created_by_version: self.backup.created_by.version,
            stores,
            ledger,
        })
    }
}

fn is_restore_id(text: &str) -> bool {
    text.strip_prefix(RESTORE_ID_PREFIX).is_some_and(|digits| {
        digits.len() == 32
            && digits
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

/// A program name and version of the manifest's grammar.
fn is_program_record(record: &ProgramRecord) -> bool {
    let program = record.program.as_bytes();
    let version = record.version.as_bytes();
    (1..=32).contains(&program.len())
        && program[0].is_ascii_lowercase()
        && program
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        && (1..=64).contains(&version.len())
        && version[0].is_ascii_digit()
        && version
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'+' | b'-'))
}

/// Writes `marker` into the directory at `directory`, which this process
/// created, as a new owner-only file, and flushes it.
pub(super) fn write(directory: &Path, marker: &RestoreMarker) -> io::Result<()> {
    let document = MarkerDocument::of(marker);
    let encoded =
        serde_json::to_vec(&document).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
    if document.marker().as_ref() != Some(marker)
        || u64::try_from(encoded.len()).unwrap_or(u64::MAX) > MAX_MARKER_BYTES
    {
        // A marker the gateway would refuse is never written.
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    let mut file = create_private_file(&directory.join(RESTORE_MARKER_FILE_NAME))?;
    file.write_all(&encoded)?;
    file.sync_all()
}

/// Reads the restore marker beneath the held `state_dir`: `None` when there
/// is none, which is every start but the first after a restore.
pub fn read_restore_marker(
    state_dir: &StateDirectory,
) -> Result<Option<RestoreMarker>, MarkerError> {
    let directory = Dir::open_ambient_dir(state_dir.path(), ambient_authority())
        .map_err(|_| MarkerError::Unavailable)?;
    // Checked by name first, without following a link.
    match directory.symlink_metadata(RESTORE_MARKER_FILE_NAME) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err(MarkerError::Unsafe)
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(MarkerError::Unavailable),
    }
    let mut options = CapabilityOpenOptions::new();
    options.read(true);
    options.follow(FollowSymlinks::No);
    // A FIFO swapped in since the check must not block the open.
    options.nonblock(true);
    let file: File = directory
        .open_with(RESTORE_MARKER_FILE_NAME, &options)
        .map_err(|_| MarkerError::Unavailable)?
        .into_std();
    let metadata = file.metadata().map_err(|_| MarkerError::Unavailable)?;
    if metadata.file_type().is_symlink()
        || is_reparse_point(&metadata)
        || !metadata.is_file()
        || !owner_alone_can_write(&metadata)
    {
        return Err(MarkerError::Unsafe);
    }
    if metadata.len() > MAX_MARKER_BYTES {
        return Err(MarkerError::Invalid);
    }
    let mut bytes = Vec::new();
    file.take(MAX_MARKER_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| MarkerError::Unavailable)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_MARKER_BYTES {
        return Err(MarkerError::Invalid);
    }
    serde_json::from_slice::<MarkerDocument>(&bytes)
        .ok()
        .and_then(MarkerDocument::marker)
        .map(Some)
        .ok_or(MarkerError::Invalid)
}

/// Removes the restore marker beneath the held `state_dir`, once its restore
/// is recorded, and flushes the directory so the removal lasts.
pub fn acknowledge_restore_marker(state_dir: &StateDirectory) -> Result<(), MarkerError> {
    fs::remove_file(state_dir.path().join(RESTORE_MARKER_FILE_NAME))
        .map_err(|_| MarkerError::Unavailable)?;
    sync_directory(state_dir.path()).map_err(|_| MarkerError::Unavailable)
}
