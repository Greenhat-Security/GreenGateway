//! Writing a new bundle directory (issue #242 PR 6; ADR-0008, "Bootstrap
//! model"): what `ggctl init` and `ggctl convert --output` share.
//!
//! A bundle appears at its destination whole or not at all:
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

use std::{
    ffi::OsString,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};

use gateway_config::bundle::{
    self, init::GITATTRIBUTES, PublishedSchemasOnly, ReadOptions, SourceFile, MANIFEST_FILE_NAME,
};

use crate::{diagnostic::Code, validate::BundleRead};

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

#[cfg(not(windows))]
fn rename_into_place(staging: &Path, destination: &Path) -> Result<(), WriteError> {
    fs::rename(staging, destination).map_err(placement_error)
}

/// Windows refuses to rename a directory while another process, such as a
/// virus scanner or the search indexer, holds a file in it open; that is
/// retried briefly. Nothing else is retried.
#[cfg(windows)]
fn rename_into_place(staging: &Path, destination: &Path) -> Result<(), WriteError> {
    const ATTEMPTS: u64 = 5;
    for attempt in 1..=ATTEMPTS {
        match fs::rename(staging, destination) {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied && attempt < ATTEMPTS => {
                std::thread::sleep(std::time::Duration::from_millis(50 * attempt));
            }
            Err(error) => return Err(placement_error(error)),
        }
    }
    Err(WriteError::Unusable)
}

#[cfg(test)]
mod tests;
