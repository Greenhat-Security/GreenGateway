//! Contained, bounded reading of one bundle directory.
//!
//! A `v1alpha1` bundle is a flat directory. The root is canonicalized once and
//! opened as a capability; every file is then opened beneath it by one name
//! that has already passed the portable file-name grammar, without following
//! links, checked on the opened handle, and read once into memory under its
//! byte bound. Nothing is reopened, so a later read of the buffer cannot see a
//! substituted file.
//!
//! The Kubernetes atomic-writer layout (`..data` pointing at one timestamped
//! sibling generation) is resolved once: every file is read from that one
//! generation directory, and the kubelet's per-key symlinks at the root are
//! never followed. Any other symbolic link, junction, reparse point,
//! subdirectory, special file or hard-linked file is refused. Entries whose
//! names begin with `.` are ignored, and never opened.
//!
//! On Unix only root and the account that owns the directory files are read
//! from may supply them: that directory must not be writable by group or
//! other, and each file must be owned by root or by the directory's owner,
//! since any other owner could change the file whatever its mode says. The
//! one exception is the atomic-writer volume root, which may be
//! world-writable with the sticky bit because that is how the kubelet
//! publishes it: nothing is read from it but `..data` and the generation
//! directory it names, and that generation must belong to the volume's
//! owner.
//!
//! A bundle can also be read from memory ([`MemoryFiles`]): the files of one
//! flat bundle directory, by name, as the revision ledger stores them or as a
//! caller received them. The same names, byte bounds and unreferenced-entry
//! rules apply; there is no filesystem to check.

use std::{
    collections::BTreeMap,
    ffi::OsStr,
    fs,
    io::{self, Read as _},
    path::{Component, Path},
};

// The link count is read through cap-fs-ext because it is the portable way to
// get it from an open Windows handle. The trait is named rather than imported
// as `_`: its name is already a reviewed capability alias, and the transport
// guard would carry that onto `_`.
use cap_fs_ext::{
    DirExt as _, FollowSymlinks, MetadataExt as CapabilityMetadataExt, OpenOptionsFollowExt as _,
    OpenOptionsSyncExt as _,
};
use cap_std::{
    ambient_authority,
    fs::{Dir, OpenOptions as CapabilityOpenOptions},
};

use super::diagnostic::{BundleDiagnostic, Code};

/// The manifest's fixed name.
pub const MANIFEST_FILE_NAME: &str = "bundle.yaml";
/// The longest bundle file name.
pub const MAX_FILE_NAME_BYTES: usize = 63;
/// Directory entries examined in a bundle, counting the root and, for the
/// atomic-writer layout, the generation directory.
pub const MAX_DIRECTORY_ENTRIES: usize = 256;
/// Bytes of every file read from one bundle, together.
pub const MAX_BUNDLE_BYTES: usize = 4 * 1024 * 1024;

const ATOMIC_WRITER_DATA: &str = "..data";

/// A bundle file name that passed the portable grammar.
///
/// `^[a-z0-9][a-z0-9._-]{0,62}$`, not ending in `.` and not a Windows device
/// name. Lowercase only, so two valid names never collide under case
/// folding, and no `/`, `\`, `:` or `..` component can be expressed, so a
/// valid name can neither leave the bundle root nor name an alternate data
/// stream.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FileName(String);

impl FileName {
    pub fn parse(name: &str) -> Option<Self> {
        is_portable_file_name(name).then(|| Self(name.to_owned()))
    }

    pub(crate) fn manifest() -> Self {
        Self(MANIFEST_FILE_NAME.to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn has_extension(&self, extension: &str) -> bool {
        self.0
            .rsplit_once('.')
            .is_some_and(|(stem, found)| !stem.is_empty() && found == extension)
    }
}

pub(crate) fn is_portable_file_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    let Some(&first) = bytes.first() else {
        return false;
    };
    bytes.len() <= MAX_FILE_NAME_BYTES
        && (first.is_ascii_lowercase() || first.is_ascii_digit())
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
        && !name.ends_with('.')
        && !is_windows_device_name(name)
}

/// Windows resolves these names to devices with any extension (`nul.json`).
fn is_windows_device_name(name: &str) -> bool {
    let stem = name.split_once('.').map_or(name, |(stem, _)| stem);
    match stem.as_bytes() {
        b"con" | b"prn" | b"aux" | b"nul" => true,
        [b'c', b'o', b'm', digit] | [b'l', b'p', b't', digit] => digit.is_ascii_digit(),
        _ => false,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EntryKind {
    File,
    Symlink,
    Directory,
    Special,
}

/// Where the reader takes a bundle's files from.
pub(crate) trait FileSource {
    /// Reads one referenced file under `maximum` bytes, charging it against
    /// [`MAX_BUNDLE_BYTES`].
    fn read(&mut self, name: &FileName, maximum: usize) -> Result<Vec<u8>, BundleDiagnostic>;

    /// One diagnostic per entry outside `referenced`.
    fn unreferenced(&self, referenced: &[FileName], strict: bool) -> Vec<BundleDiagnostic>;
}

/// The diagnostic for an unreferenced regular file: a warning, or an error
/// when reading strictly.
fn unreferenced_file(file: &FileName, strict: bool) -> BundleDiagnostic {
    let diagnostic = BundleDiagnostic::file(Code::UnreferencedEntry, file);
    if strict {
        diagnostic
    } else {
        diagnostic.warning()
    }
}

/// A bundle held in memory: the files of one flat bundle directory, by name.
///
/// Names are [`FileName`]s, so every one passed the portable grammar, and a
/// map holds each name once. The entry bound and the byte bounds are the
/// directory reader's.
pub(crate) struct MemoryFiles {
    files: BTreeMap<FileName, Vec<u8>>,
    bytes_read: usize,
}

impl MemoryFiles {
    pub(crate) fn new(files: BTreeMap<FileName, Vec<u8>>) -> Result<Self, BundleDiagnostic> {
        if files.len() > MAX_DIRECTORY_ENTRIES {
            return Err(BundleDiagnostic::bundle(Code::TooManyEntries));
        }
        Ok(Self {
            files,
            bytes_read: 0,
        })
    }
}

impl FileSource for MemoryFiles {
    fn read(&mut self, name: &FileName, maximum: usize) -> Result<Vec<u8>, BundleDiagnostic> {
        let refuse = |code| BundleDiagnostic::file(code, name);
        let bytes = self.files.get(name).ok_or(refuse(Code::FileMissing))?;
        if bytes.len() > maximum {
            return Err(refuse(Code::FileTooLarge));
        }
        if self.bytes_read.saturating_add(bytes.len()) > MAX_BUNDLE_BYTES {
            return Err(refuse(Code::BundleTooLarge));
        }
        self.bytes_read += bytes.len();
        Ok(bytes.clone())
    }

    fn unreferenced(&self, referenced: &[FileName], strict: bool) -> Vec<BundleDiagnostic> {
        self.files
            .keys()
            .filter(|name| !referenced.contains(name))
            .map(|name| unreferenced_file(name, strict))
            .collect()
    }
}

/// An opened bundle directory.
pub(crate) struct BundleDirectory {
    /// The directory files are read from: the root, or the resolved
    /// atomic-writer generation.
    files: Dir,
    /// The account that owns `files`, where the platform records one.
    owner: Option<u32>,
    /// Every entry of `files` whose name does not begin with `.`. Names that
    /// are not UTF-8 are kept lossily: they can never pass the file-name
    /// grammar, so they are never opened and never reported by name.
    entries: Vec<(String, EntryKind)>,
    bytes_read: usize,
}

impl BundleDirectory {
    pub(crate) fn open(root: &Path) -> Result<Self, BundleDiagnostic> {
        let canonical =
            fs::canonicalize(root).map_err(|_| BundleDiagnostic::bundle(Code::RootUnavailable))?;
        if !fs::symlink_metadata(&canonical).is_ok_and(|metadata| metadata.is_dir()) {
            return Err(BundleDiagnostic::bundle(Code::RootNotDirectory));
        }
        let directory = Dir::open_ambient_dir(&canonical, ambient_authority())
            .map_err(|_| BundleDiagnostic::bundle(Code::RootUnavailable))?;
        let root_metadata = check_directory(&directory, Code::RootNotDirectory)?;

        let mut examined = 0;
        let root_entries = list_entries(&directory, &mut examined)?;
        let Some(data_kind) = root_entries
            .iter()
            .find(|(name, _)| name == ATOMIC_WRITER_DATA)
            .map(|(_, kind)| *kind)
        else {
            // A flat bundle is read from its root. The sticky bit stops
            // another account replacing an entry, not adding one, and a
            // `bundle.yaml` or referenced file it added before the operator
            // did would be read; so here the root is its owner's alone.
            if !owner_alone_can_write(&root_metadata) {
                return Err(BundleDiagnostic::bundle(Code::UnsafePermissions));
            }
            let entries = root_entries
                .into_iter()
                .filter(|(name, _)| !name.starts_with('.'))
                .collect();
            return Ok(Self {
                files: directory,
                owner: owner(&root_metadata),
                entries,
                bytes_read: 0,
            });
        };

        // The atomic-writer layout. Every top-level entry that is not a dot
        // entry must be one of the kubelet's per-key links; a regular file
        // beside `..data` would be a second, unpinned generation.
        let invalid = || BundleDiagnostic::bundle(Code::AtomicWriterInvalid);
        if data_kind != EntryKind::Symlink
            || root_entries
                .iter()
                .any(|(name, kind)| !name.starts_with('.') && *kind != EntryKind::Symlink)
        {
            return Err(invalid());
        }
        // `read_link` refuses an absolute target; the target must also be one
        // dot-prefixed sibling name exactly as the kubelet writes it, never a
        // path, so no separator of either platform may appear in it.
        let target = directory
            .read_link(ATOMIC_WRITER_DATA)
            .map_err(|_| invalid())?;
        let Some(generation) = target.to_str() else {
            return Err(invalid());
        };
        if generation.contains(['/', '\\'])
            || !matches!(target.components().next(), Some(Component::Normal(_)))
            || !generation.starts_with("..")
            || generation == ATOMIC_WRITER_DATA
            || generation.len() <= 2
            || !root_entries
                .iter()
                .any(|(name, kind)| name == generation && *kind == EntryKind::Directory)
        {
            return Err(invalid());
        }
        let generation_directory = directory
            .open_dir_nofollow(generation)
            .map_err(|_| invalid())?;
        let generation_metadata =
            check_directory(&generation_directory, Code::AtomicWriterInvalid)?;
        // The kubelet creates every generation `0755`, as the volume's owner.
        // One another account can add to, or owns, is not one it wrote, even
        // though that account could have created it under a sticky root.
        if !owner_alone_can_write(&generation_metadata) {
            return Err(BundleDiagnostic::bundle(Code::UnsafePermissions));
        }
        if !owner_is_trusted(owner(&generation_metadata), owner(&root_metadata)) {
            return Err(BundleDiagnostic::bundle(Code::UntrustedOwner));
        }
        let entries = list_entries(&generation_directory, &mut examined)?
            .into_iter()
            .filter(|(name, _)| !name.starts_with('.'))
            .collect();
        Ok(Self {
            files: generation_directory,
            owner: owner(&generation_metadata),
            entries,
            bytes_read: 0,
        })
    }

    /// Reads one referenced file under `maximum` bytes.
    fn read_file(&mut self, name: &FileName, maximum: usize) -> Result<Vec<u8>, BundleDiagnostic> {
        let refuse = |code| BundleDiagnostic::file(code, name);
        // Exact-name lookup in the listing: on a case-insensitive filesystem
        // `policy.json` must not open an entry listed as `POLICY.JSON`.
        match self.kind(name.as_str()) {
            Some(EntryKind::File) => {}
            Some(EntryKind::Symlink) => return Err(refuse(Code::SymlinkForbidden)),
            Some(EntryKind::Directory | EntryKind::Special) => {
                return Err(refuse(Code::NotRegularFile))
            }
            None => return Err(refuse(Code::FileMissing)),
        }

        let mut options = CapabilityOpenOptions::new();
        options.read(true);
        options.follow(FollowSymlinks::No);
        // A FIFO swapped in after the listing must not block the reader; the
        // handle check below then refuses it.
        options.nonblock(true);
        let file = self
            .files
            .open_with(name.as_str(), &options)
            .map_err(|error| match error.kind() {
                io::ErrorKind::NotFound => refuse(Code::FileMissing),
                _ => refuse(Code::ReadFailed),
            })?;
        // `CapabilityMetadataExt::nlink`, read from the open handle.
        let links = file
            .metadata()
            .map_err(|_| refuse(Code::ReadFailed))?
            .nlink();
        let file = file.into_std();
        let metadata = file.metadata().map_err(|_| refuse(Code::ReadFailed))?;
        if is_reparse_point(&metadata) || metadata.file_type().is_symlink() {
            return Err(refuse(Code::SymlinkForbidden));
        }
        if !metadata.is_file() {
            return Err(refuse(Code::NotRegularFile));
        }
        if links != 1 {
            return Err(refuse(Code::HardLinkForbidden));
        }
        if !owner_alone_can_write(&metadata) {
            return Err(refuse(Code::UnsafePermissions));
        }
        if !owner_is_trusted(owner(&metadata), self.owner) {
            return Err(refuse(Code::UntrustedOwner));
        }
        let declared = usize::try_from(metadata.len()).unwrap_or(usize::MAX);
        if declared > maximum {
            return Err(refuse(Code::FileTooLarge));
        }
        if self.bytes_read.saturating_add(declared) > MAX_BUNDLE_BYTES {
            return Err(refuse(Code::BundleTooLarge));
        }

        let mut contents = Vec::with_capacity(declared);
        file.take(u64::try_from(maximum).unwrap_or(u64::MAX).saturating_add(1))
            .read_to_end(&mut contents)
            .map_err(|_| refuse(Code::ReadFailed))?;
        if contents.len() > maximum {
            return Err(refuse(Code::FileTooLarge));
        }
        if contents.len() != declared {
            return Err(refuse(Code::ChangedDuringRead));
        }
        self.bytes_read += contents.len();
        Ok(contents)
    }

    /// One diagnostic per entry outside `referenced`.
    ///
    /// An unreferenced regular file is a warning, or an error when `strict`.
    /// An unreferenced link, subdirectory or special file is always an error:
    /// a flat bundle has none. Only names that pass the file-name grammar are
    /// reported by name.
    fn unreferenced_entries(&self, referenced: &[FileName], strict: bool) -> Vec<BundleDiagnostic> {
        self.entries
            .iter()
            .filter(|(name, _)| !referenced.iter().any(|file| file.as_str() == name))
            .map(|(name, kind)| {
                let code = match kind {
                    EntryKind::File => Code::UnreferencedEntry,
                    EntryKind::Symlink => Code::SymlinkForbidden,
                    EntryKind::Directory | EntryKind::Special => Code::NotRegularFile,
                };
                match FileName::parse(name) {
                    Some(file) if code == Code::UnreferencedEntry => {
                        unreferenced_file(&file, strict)
                    }
                    Some(file) => BundleDiagnostic::file(code, &file),
                    None if code == Code::UnreferencedEntry && !strict => {
                        BundleDiagnostic::bundle(code).warning()
                    }
                    None => BundleDiagnostic::bundle(code),
                }
            })
            .collect()
    }

    fn kind(&self, name: &str) -> Option<EntryKind> {
        self.entries
            .iter()
            .find(|(entry, _)| entry == name)
            .map(|(_, kind)| *kind)
    }
}

/// Lists a directory without following links, refusing a listing larger
/// than the bundle bound before it is collected.
impl FileSource for BundleDirectory {
    fn read(&mut self, name: &FileName, maximum: usize) -> Result<Vec<u8>, BundleDiagnostic> {
        self.read_file(name, maximum)
    }

    fn unreferenced(&self, referenced: &[FileName], strict: bool) -> Vec<BundleDiagnostic> {
        self.unreferenced_entries(referenced, strict)
    }
}

fn list_entries(
    directory: &Dir,
    examined: &mut usize,
) -> Result<Vec<(String, EntryKind)>, BundleDiagnostic> {
    let unreadable = || BundleDiagnostic::bundle(Code::RootUnavailable);
    let mut entries = Vec::new();
    for entry in directory.entries().map_err(|_| unreadable())? {
        let entry = entry.map_err(|_| unreadable())?;
        *examined += 1;
        if *examined > MAX_DIRECTORY_ENTRIES {
            return Err(BundleDiagnostic::bundle(Code::TooManyEntries));
        }
        let file_type = entry.file_type().map_err(|_| unreadable())?;
        let kind = if file_type.is_symlink() {
            EntryKind::Symlink
        } else if file_type.is_dir() {
            EntryKind::Directory
        } else if file_type.is_file() {
            EntryKind::File
        } else {
            EntryKind::Special
        };
        let name = entry.file_name();
        entries.push((lossy_name(&name), kind));
    }
    Ok(entries)
}

fn lossy_name(name: &OsStr) -> String {
    name.to_string_lossy().into_owned()
}

/// Checks an opened directory and returns its metadata. Every directory is
/// held at least to the projected-volume rule; the caller tightens it for
/// the directory files are read from.
fn check_directory(directory: &Dir, not_directory: Code) -> Result<fs::Metadata, BundleDiagnostic> {
    let metadata = directory
        .try_clone()
        .and_then(|directory| directory.into_std_file().metadata())
        .map_err(|_| BundleDiagnostic::bundle(Code::RootUnavailable))?;
    if !metadata.is_dir() || is_reparse_point(&metadata) {
        return Err(BundleDiagnostic::bundle(not_directory));
    }
    // The kubelet publishes volume roots as `drwxrwxrwt`; the sticky bit is
    // what stops another account renaming entries, so the same predicate the
    // secret providers use applies here.
    if !crate::permissions::projected_root_permissions_are_safe(&metadata) {
        return Err(BundleDiagnostic::bundle(Code::UnsafePermissions));
    }
    Ok(metadata)
}

/// Whether group and other are denied write: for a file, the right to change
/// it; for a directory, the right to add, rename or remove its entries.
#[cfg(unix)]
fn owner_alone_can_write(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    metadata.mode() & 0o022 == 0
}

/// Windows ACLs remain an operator and platform responsibility, as they are
/// for `CONNECTION_SECRETS_ROOT`.
#[cfg(not(unix))]
fn owner_alone_can_write(_: &fs::Metadata) -> bool {
    true
}

/// The account that owns an entry, where the platform records one in its
/// metadata.
#[cfg(unix)]
fn owner(metadata: &fs::Metadata) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    Some(metadata.uid())
}

/// Windows records no owner ID in metadata; its ACLs remain an operator and
/// platform responsibility.
#[cfg(not(unix))]
fn owner(_: &fs::Metadata) -> Option<u32> {
    None
}

/// Whether an entry's owner may supply what is read from a directory: root,
/// or the directory's own owner, who could replace the entry anyway. Any
/// other owner could rewrite the file whatever its mode says, because an
/// owner may always change the mode of what it owns.
pub(crate) fn owner_is_trusted(entry: Option<u32>, directory: Option<u32>) -> bool {
    const ROOT: u32 = 0;
    match (entry, directory) {
        (Some(entry), Some(directory)) => entry == ROOT || entry == directory,
        (None, None) => true,
        _ => false,
    }
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
