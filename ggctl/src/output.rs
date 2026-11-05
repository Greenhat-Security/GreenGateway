//! Writing bundles (issue #242; ADR-0008, "Bootstrap model" and "Digests"):
//! a new bundle directory, which `ggctl init` and `ggctl convert --output`
//! share, and a new manifest for an existing bundle, which `ggctl pin`
//! writes ([`replace_manifest`], below).
//!
//! A new bundle appears at its destination whole or not at all:
//!
//! 1. The destination must not exist, or must be an empty directory that is
//!    not a link. Anything else is refused and never overwritten.
//! 2. The files are written into a new staging directory beside the
//!    destination, created exclusively under a hidden name
//!    (`.NAME.ggctl-staging-PID-N`) so it is never reused and never taken
//!    for the bundle. On Unix the directory is created `0700` and each file
//!    `0600`, and both are checked to have no group or other access
//!    afterwards; a filesystem that cannot keep those modes is refused.
//!    Windows has no mode bits: the new entries inherit the ACL of the
//!    directory they are created in, which is left to the operator, as the
//!    bundle reader leaves it.
//! 3. Each file is created new and flushed to storage, the manifest last, so
//!    even the staging directory never holds a manifest before every file it
//!    pins.
//! 4. The staging directory is read back with the bundle reader, strictly,
//!    and must yield exactly the files written. It is flushed on Unix.
//! 5. It is renamed onto the destination (an empty destination directory is
//!    removed first), and on Unix the parent directory is flushed.
//!
//! Any failure removes the staging directory, so an interrupted or refused
//! write leaves nothing at the destination. A process killed between steps
//! 2 and 5 can leave the hidden staging directory behind, never the
//! destination.
//!
//! A manifest is replaced the same way, one file instead of a directory: the
//! new bytes go into a new hidden file beside `bundle.yaml`
//! (`.bundle.yaml.ggctl-pin-PID-N`, created exclusively, `0600` and checked
//! on Unix), which is flushed and then renamed over `bundle.yaml`, and on
//! Unix the directory is flushed. `bundle.yaml` must be a regular file, not
//! a link, and must still hold the bytes the caller read, checked before the
//! hidden file is created and again just before the rename. Any failure
//! removes the hidden file and leaves `bundle.yaml` as it was; a process
//! killed before the rename can leave the hidden file, which the bundle
//! reader never opens, and never a partial manifest.

use std::{
    ffi::OsString,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};

use gateway_config::bundle::{
    self, init::GITATTRIBUTES, PublishedSchemasOnly, ReadOptions, SourceFile, MANIFEST_FILE_NAME,
    MAX_MANIFEST_BYTES,
};

use crate::{
    credential::{self, FilePermissions, FileProblem},
    diagnostic::Code,
    validate::BundleRead,
};

/// Staging names tried before giving up: each is created exclusively, so a
/// name that exists is skipped, never reused.
const STAGING_ATTEMPTS: usize = 16;
/// The name the bundle's line-ending attributes are written under.
const GITATTRIBUTES_FILE: &str = ".gitattributes";

/// Why a bundle was not written. Nothing is at the destination in any case.
#[derive(Debug)]
pub(crate) enum WriteError {
    /// The destination exists and is not an empty directory, or is a link.
    Exists,
    /// The destination's directory could not be used, or a write, flush or
    /// rename failed.
    Unusable,
    /// Owner-only permissions could not be established (Unix).
    Permissions,
    /// The written files did not read back as the same valid bundle.
    Invalid(Box<BundleRead>),
}

impl WriteError {
    /// The diagnostic code reporting it.
    pub(crate) fn code(&self) -> Code {
        match self {
            Self::Exists => Code::DestinationExists,
            Self::Unusable => Code::DestinationUnusable,
            Self::Permissions => Code::PermissionsUnavailable,
            Self::Invalid(_) => Code::WrittenBundleInvalid,
        }
    }
}

/// What is at the destination before anything is written.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Destination {
    Absent,
    EmptyDirectory,
}

/// Writes `files` as a new bundle at `destination` and returns how the
/// reader read it.
pub(crate) fn write_new_bundle(
    destination: &Path,
    files: &[SourceFile],
) -> Result<BundleRead, WriteError> {
    let found = destination_state(destination)?;
    let staging = Staging::create(destination)?;
    let ordered = files
        .iter()
        .filter(|file| file.name.as_str() != MANIFEST_FILE_NAME)
        .map(|file| (OsString::from(file.name.as_str()), file.bytes.as_slice()))
        .chain([(OsString::from(GITATTRIBUTES_FILE), GITATTRIBUTES.as_bytes())])
        .chain(
            files
                .iter()
                .filter(|file| file.name.as_str() == MANIFEST_FILE_NAME)
                .map(|file| (OsString::from(file.name.as_str()), file.bytes.as_slice())),
        );
    for (name, bytes) in ordered {
        write_file(&staging.path.join(name), bytes)?;
    }
    check_owner_only(&staging.path)?;
    let read = bundle::read_bundle(
        &staging.path,
        ReadOptions { strict: true },
        &PublishedSchemasOnly,
    );
    if read
        .bundle
        .as_ref()
        .is_none_or(|bundle| bundle.source_files() != files)
    {
        return Err(WriteError::Invalid(Box::new(read)));
    }
    sync_directory(&staging.path)?;
    if found == Destination::EmptyDirectory {
        fs::remove_dir(destination).map_err(placement_error)?;
    }
    rename_into_place(&staging.path, destination)?;
    staging.placed();
    // The bundle is in place; flushing the rename is best effort, and a
    // failure here must not report a bundle that exists as unwritten.
    let _ = sync_directory(parent_of(destination));
    Ok(read)
}

/// Refuses a destination that holds anything.
fn destination_state(destination: &Path) -> Result<Destination, WriteError> {
    let metadata = match fs::symlink_metadata(destination) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Destination::Absent),
        Err(_) => return Err(WriteError::Unusable),
    };
    // A link (on Windows, a junction too) is refused whatever it points at.
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(WriteError::Exists);
    }
    let mut entries = fs::read_dir(destination).map_err(|_| WriteError::Unusable)?;
    match entries.next() {
        None => Ok(Destination::EmptyDirectory),
        Some(_) => Err(WriteError::Exists),
    }
}

/// The directory a relative destination with no parent component is in.
fn parent_of(destination: &Path) -> &Path {
    match destination.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

/// The staging directory, removed on drop unless it was placed.
struct Staging {
    path: PathBuf,
    placed: bool,
}

impl Staging {
    fn create(destination: &Path) -> Result<Self, WriteError> {
        let Some(name) = destination.file_name() else {
            return Err(WriteError::Unusable);
        };
        let parent = parent_of(destination);
        for attempt in 0..STAGING_ATTEMPTS {
            let mut staging = OsString::from(".");
            staging.push(name);
            staging.push(format!(".ggctl-staging-{}-{attempt}", std::process::id()));
            let path = parent.join(staging);
            match create_private_directory(&path) {
                Ok(()) => {
                    return Ok(Self {
                        path,
                        placed: false,
                    })
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(_) => return Err(WriteError::Unusable),
            }
        }
        Err(WriteError::Unusable)
    }

    fn placed(mut self) {
        self.placed = true;
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        if !self.placed {
            // Does not follow links: only what this process created goes.
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(0o700).create(path)
}

#[cfg(not(unix))]
fn create_private_directory(path: &Path) -> io::Result<()> {
    fs::create_dir(path)
}

/// Creates a new file, never opening an existing one, writes it whole and
/// flushes it to storage.
fn write_file(path: &Path, bytes: &[u8]) -> Result<(), WriteError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    owner_only(&mut options);
    let mut file = options.open(path).map_err(|_| WriteError::Unusable)?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| WriteError::Unusable)
}

#[cfg(unix)]
fn owner_only(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(0o600);
}

#[cfg(not(unix))]
fn owner_only(_options: &mut OpenOptions) {}

/// Renames one path onto another, replacing a file there. Tests substitute a
/// failing one to interrupt a write at its last step.
pub(crate) type Rename = fn(&Path, &Path) -> io::Result<()>;

/// [`Rename`] as the filesystem does it.
pub(crate) fn rename(from: &Path, to: &Path) -> io::Result<()> {
    fs::rename(from, to)
}

/// Why a manifest was not replaced. `bundle.yaml` is as it was in every
/// case.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReplaceError {
    /// `bundle.yaml` is a link (on Windows, any reparse point) or not a
    /// regular file.
    NotRegularFile,
    /// `bundle.yaml` no longer holds the bytes the caller read.
    Changed,
    /// The new file could not be created, written, flushed or renamed.
    Unusable,
    /// Owner-only permissions could not be established (Unix).
    Permissions,
}

impl ReplaceError {
    /// The diagnostic code reporting it.
    pub(crate) fn code(self) -> Code {
        match self {
            Self::NotRegularFile => Code::ManifestLink,
            Self::Changed => Code::ManifestChanged,
            Self::Unusable => Code::PinWriteFailed,
            Self::Permissions => Code::PinPermissionsUnavailable,
        }
    }
}

/// Refuses a `bundle.yaml` in `root` that is a link or not a regular file.
/// One that is absent, or cannot be examined, passes: the bundle reader then
/// reports why it cannot read the manifest.
pub(crate) fn check_manifest_entry(root: &Path) -> Result<(), ReplaceError> {
    match fs::symlink_metadata(root.join(MANIFEST_FILE_NAME)) {
        Ok(metadata) if is_link(&metadata) || !metadata.is_file() => {
            Err(ReplaceError::NotRegularFile)
        }
        _ => Ok(()),
    }
}

/// Replaces `bundle.yaml` in the bundle directory `root`, which must still
/// hold `expected`, with `manifest`, atomically.
pub(crate) fn replace_manifest(
    root: &Path,
    expected: &[u8],
    manifest: &[u8],
    rename: Rename,
) -> Result<(), ReplaceError> {
    let target = root.join(MANIFEST_FILE_NAME);
    check_manifest(&target, expected)?;
    let replacement = Replacement::create(root, manifest)?;
    // Checked again just before the rename: another writer may have changed
    // the manifest meanwhile. A rename cannot compare and swap, so this
    // narrows that window; it cannot close it.
    check_manifest(&target, expected)?;
    rename_retrying(rename, &replacement.path, &target).map_err(|_| ReplaceError::Unusable)?;
    replacement.placed();
    // The manifest is replaced; flushing the rename is best effort, and a
    // failure here must not report a manifest that changed as unchanged.
    let _ = sync_directory(root);
    Ok(())
}

/// Refuses a manifest that is a link or not a regular file, or that no
/// longer holds `expected`.
fn check_manifest(path: &Path, expected: &[u8]) -> Result<(), ReplaceError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Err(ReplaceError::Changed),
        Err(_) => return Err(ReplaceError::Unusable),
    };
    if is_link(&metadata) || !metadata.is_file() {
        return Err(ReplaceError::NotRegularFile);
    }
    // Read as any local file ggctl reads: bounded, and opened without
    // blocking so a FIFO swapped in cannot stall the comparison.
    match credential::read_regular_file(
        path,
        MAX_MANIFEST_BYTES,
        FilePermissions::NotWritableByOthers,
    ) {
        Ok(current) if current.as_slice() == expected => Ok(()),
        Ok(_) | Err(FileProblem::TooLarge | FileProblem::UnsafePermissions) => {
            Err(ReplaceError::Changed)
        }
        Err(FileProblem::NotRegularFile) => Err(ReplaceError::NotRegularFile),
        Err(FileProblem::Unreadable) => Err(ReplaceError::Unusable),
    }
}

/// Whether an entry, not followed, is a link: on Windows any reparse point,
/// as the bundle reader treats one.
fn is_link(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink() || is_reparse_point(metadata)
}

#[cfg(windows)]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

/// The new manifest's hidden file, removed on drop unless it was renamed
/// into place.
struct Replacement {
    path: PathBuf,
    placed: bool,
}

impl Replacement {
    /// Creates the file exclusively under a fresh hidden name, writes
    /// `manifest` whole, flushes it, and checks it is owner-only.
    fn create(root: &Path, manifest: &[u8]) -> Result<Self, ReplaceError> {
        for attempt in 0..STAGING_ATTEMPTS {
            let name = format!(
                ".{MANIFEST_FILE_NAME}.ggctl-pin-{}-{attempt}",
                std::process::id()
            );
            let path = root.join(name);
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            owner_only(&mut options);
            let mut file = match options.open(&path) {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(_) => return Err(ReplaceError::Unusable),
            };
            // From here on the file is this process's own, removed on drop.
            let replacement = Self {
                path,
                placed: false,
            };
            file.write_all(manifest)
                .and_then(|()| file.sync_all())
                .map_err(|_| ReplaceError::Unusable)?;
            drop(file);
            if !is_owner_only(&replacement.path) {
                return Err(ReplaceError::Permissions);
            }
            return Ok(replacement);
        }
        Err(ReplaceError::Unusable)
    }

    fn placed(mut self) {
        self.placed = true;
    }
}

impl Drop for Replacement {
    fn drop(&mut self) {
        if !self.placed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// Refuses a staging directory, or a file in it, that group or other can
/// access: the modes it was created with, unless the filesystem ignored them.
fn check_owner_only(staging: &Path) -> Result<(), WriteError> {
    let entries = fs::read_dir(staging).map_err(|_| WriteError::Unusable)?;
    let mut private = is_owner_only(staging);
    for entry in entries {
        let entry = entry.map_err(|_| WriteError::Unusable)?;
        private &= is_owner_only(&entry.path());
    }
    if private {
        Ok(())
    } else {
        Err(WriteError::Permissions)
    }
}

/// Whether group and other have no access to the entry, which is not
/// followed if it is a link.
#[cfg(unix)]
fn is_owner_only(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    fs::symlink_metadata(path).is_ok_and(|metadata| metadata.permissions().mode() & 0o077 == 0)
}

/// Windows has no mode bits; the entry's ACL is the operator's.
#[cfg(not(unix))]
fn is_owner_only(_path: &Path) -> bool {
    true
}

/// Flushes a directory's entries to storage. Windows cannot open a directory
/// for that through the standard library, and a rename there is already
/// durable once it returns on the local filesystems ggctl supports.
#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), WriteError> {
    fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| WriteError::Unusable)
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), WriteError> {
    Ok(())
}

/// Something now at the destination is a conflict; anything else is a
/// failure to write.
fn placement_error(error: io::Error) -> WriteError {
    match error.kind() {
        io::ErrorKind::AlreadyExists | io::ErrorKind::DirectoryNotEmpty => WriteError::Exists,
        _ => WriteError::Unusable,
    }
}

fn rename_into_place(staging: &Path, destination: &Path) -> Result<(), WriteError> {
    rename_retrying(rename, staging, destination).map_err(placement_error)
}

#[cfg(not(windows))]
fn rename_retrying(rename: Rename, from: &Path, to: &Path) -> io::Result<()> {
    rename(from, to)
}

/// Windows refuses to rename a directory, or to replace a file, while
/// another process, such as a virus scanner or the search indexer, holds a
/// file in it or the file open; that is retried briefly. Nothing else is
/// retried.
#[cfg(windows)]
fn rename_retrying(rename: Rename, from: &Path, to: &Path) -> io::Result<()> {
    const ATTEMPTS: u64 = 5;
    let mut attempt = 1;
    loop {
        match rename(from, to) {
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied && attempt < ATTEMPTS => {
                std::thread::sleep(std::time::Duration::from_millis(50 * attempt));
                attempt += 1;
            }
            result => return result,
        }
    }
}

#[cfg(test)]
mod tests;
