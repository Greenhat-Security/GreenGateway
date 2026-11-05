//! Bearer-token input and bounded local file reads.
//!
//! A token never arrives on the command line (the parser refuses any option
//! that would carry one). It comes from a piped standard input
//! (`--token-stdin`) or from a regular, bounded, owner-only file
//! (`--token-file`), is held in memory that is zeroed on drop, has a redacted
//! `Debug`, and is checked against the RFC 6750 bearer-token grammar so a
//! stray newline, space or control character can never reach a header.

use std::{
    fmt,
    fs::File,
    io::{self, Read},
    path::Path,
};

use zeroize::Zeroizing;

use crate::diagnostic::Code;

/// The largest token accepted (ADR-0008, "Remote client").
pub(crate) const MAX_TOKEN_BYTES: usize = 8 * 1024;

/// A bearer token. Its value is reachable only through [`Token::expose`].
pub(crate) struct Token(Zeroizing<String>);

impl Token {
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Token {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Token(<redacted>)")
    }
}

/// Reads a token from standard input, which must not be a terminal: a token
/// typed there is echoed to the screen and kept in scrollback, and `ggctl`
/// cannot read one hidden without a platform terminal dependency.
pub(crate) fn from_stdin(stdin_is_terminal: bool, stdin: &mut dyn Read) -> Result<Token, Code> {
    if stdin_is_terminal {
        return Err(Code::StdinIsTerminal);
    }
    let bytes = read_bounded(stdin, MAX_TOKEN_BYTES).map_err(|problem| match problem {
        Bounded::TooLarge => Code::CredentialTooLarge,
        Bounded::Failed => Code::CredentialUnreadable,
    })?;
    token(bytes)
}

/// Reads a token from a file: a regular file (a symbolic link to one is
/// followed, as mounted secrets use them), at most [`MAX_TOKEN_BYTES`] and,
/// on Unix, neither readable nor writable by group or other.
pub(crate) fn from_file(path: &Path) -> Result<Token, Code> {
    let bytes = read_regular_file(path, MAX_TOKEN_BYTES, FilePermissions::OwnerOnly).map_err(
        |problem| match problem {
            FileProblem::Unreadable => Code::CredentialUnreadable,
            FileProblem::NotRegularFile => Code::CredentialNotRegularFile,
            FileProblem::TooLarge => Code::CredentialTooLarge,
            FileProblem::UnsafePermissions => Code::CredentialUnsafePermissions,
        },
    )?;
    token(bytes)
}

/// Accepts exactly one bearer token, optionally followed by one line ending.
fn token(mut bytes: Zeroizing<Vec<u8>>) -> Result<Token, Code> {
    let ending = if bytes.ends_with(b"\r\n") {
        2
    } else {
        usize::from(bytes.ends_with(b"\n"))
    };
    let length = bytes.len() - ending;
    bytes.truncate(length);
    if bytes.is_empty() {
        return Err(Code::CredentialEmpty);
    }
    if !is_bearer_token(&bytes) {
        return Err(Code::CredentialInvalid);
    }
    // Validated ASCII, so the conversion takes the buffer without copying it.
    match String::from_utf8(std::mem::take(&mut *bytes)) {
        Ok(text) => Ok(Token(Zeroizing::new(text))),
        Err(error) => {
            drop(Zeroizing::new(error.into_bytes()));
            Err(Code::CredentialInvalid)
        }
    }
}

/// RFC 6750 `b64token`: `1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="`.
fn is_bearer_token(bytes: &[u8]) -> bool {
    let body = bytes
        .iter()
        .position(|&byte| byte == b'=')
        .unwrap_or(bytes.len());
    body > 0
        && bytes[..body].iter().all(|&byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
        })
        && bytes[body..].iter().all(|&byte| byte == b'=')
}

/// Why a local file was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FileProblem {
    Unreadable,
    NotRegularFile,
    TooLarge,
    UnsafePermissions,
}

/// What another account may do to a local file `ggctl` reads, on Unix.
/// Windows has no mode bits, and the file's ACL is left to the operator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FilePermissions {
    /// Group and other have no access at all (mode `0600` or `0400`): a
    /// credential, which reading discloses.
    OwnerOnly,
    /// Group and other may read the file but not write it (mode `0644` is
    /// fine, `0664` and `0666` are not): a file whose directory another
    /// check already vouches for, such as the bundle manifest `pin` reads
    /// again after the bundle reader read it.
    NotWritableByOthers,
    /// As [`FilePermissions::NotWritableByOthers`], and no other account
    /// may change what the path resolves to: the file, every directory
    /// above it and every link on its path must be owned by root or by the
    /// account running `ggctl`, and group and other may write one of those
    /// directories only when it has the sticky bit. A trust anchor
    /// (`--ca-file`, `--answers`) is public but decides where a credential
    /// may be sent or whom a role trusts, so whoever can change or replace
    /// it gets that decision.
    TrustAnchor,
    /// Any mode: a document a command only sends for a judgement or checks
    /// itself (`ggctl policy`, `ggctl evidence verify`), which grants
    /// nothing and decides where nothing is sent, so what another account
    /// could do to it changes only what is reported about it.
    Unrestricted,
}

/// Reads a whole regular file of at most `maximum` bytes into memory that is
/// zeroed on drop.
///
/// The path is checked before it is opened, so a FIFO or device is refused
/// without being opened, and it is opened without blocking, so one swapped
/// in after that check cannot stall the read either. The opened handle is
/// then checked again and, on Unix, must be the very file the path check
/// examined, so what is read is the file the checks passed: a path swapped
/// between the two is refused rather than read. [`FilePermissions`] says
/// what the Unix mode bits, and for a trust anchor the owners and the
/// entries its path resolves through, may allow.
pub(crate) fn read_regular_file(
    path: &Path,
    maximum: usize,
    permissions: FilePermissions,
) -> Result<Zeroizing<Vec<u8>>, FileProblem> {
    let before = std::fs::metadata(path).map_err(|_| FileProblem::Unreadable)?;
    check_metadata(&before, maximum, permissions)?;
    check_directories(path, &before, permissions)?;
    let mut file = open_without_blocking(path).map_err(|_| FileProblem::Unreadable)?;
    let opened = file.metadata().map_err(|_| FileProblem::Unreadable)?;
    check_metadata(&opened, maximum, permissions)?;
    check_same_file(&before, &opened)?;
    read_bounded(&mut file, maximum).map_err(|problem| match problem {
        Bounded::TooLarge => FileProblem::TooLarge,
        Bounded::Failed => FileProblem::Unreadable,
    })
}

fn check_metadata(
    metadata: &std::fs::Metadata,
    maximum: usize,
    permissions: FilePermissions,
) -> Result<(), FileProblem> {
    if !metadata.is_file() {
        return Err(FileProblem::NotRegularFile);
    }
    if !usize::try_from(metadata.len()).is_ok_and(|length| length <= maximum) {
        return Err(FileProblem::TooLarge);
    }
    if !permissions_are_safe(metadata, permissions) {
        return Err(FileProblem::UnsafePermissions);
    }
    Ok(())
}

#[cfg(unix)]
fn permissions_are_safe(metadata: &std::fs::Metadata, permissions: FilePermissions) -> bool {
    use std::os::unix::fs::PermissionsExt;
    let forbidden = match permissions {
        FilePermissions::OwnerOnly => 0o077,
        FilePermissions::NotWritableByOthers | FilePermissions::TrustAnchor => 0o022,
        FilePermissions::Unrestricted => 0,
    };
    metadata.permissions().mode() & forbidden == 0
}

#[cfg(not(unix))]
fn permissions_are_safe(_metadata: &std::fs::Metadata, _permissions: FilePermissions) -> bool {
    true
}

/// For a trust anchor, refuses a path another account could make resolve to
/// a file of its choosing; see [`check_resolution`].
#[cfg(unix)]
fn check_directories(
    path: &Path,
    checked: &std::fs::Metadata,
    permissions: FilePermissions,
) -> Result<(), FileProblem> {
    if permissions != FilePermissions::TrustAnchor {
        return Ok(());
    }
    check_resolution(path, checked, running_account())
}

#[cfg(not(unix))]
fn check_directories(
    _path: &Path,
    _checked: &std::fs::Metadata,
    _permissions: FilePermissions,
) -> Result<(), FileProblem> {
    Ok(())
}

/// The account `ggctl` runs as: its effective user ID, the one the kernel
/// checks every file access against.
#[cfg(unix)]
fn running_account() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// The most symbolic links one path may resolve through, as on Linux.
#[cfg(unix)]
const MAX_LINKS: usize = 40;

/// Resolves `path` one entry at a time from `/` (a relative path from the
/// working directory), following each symbolic link as the kernel does, and
/// refuses it unless only root and `account` could change what it resolves
/// to.
///
/// Every entry the path resolves through, each directory, each link and the
/// file itself, must be owned by root or by `account`: an owner can always
/// change what it owns, whatever the mode says, and a link's owner chose
/// where it points. Every directory a name is looked up in must also be
/// unwritable by group and other unless it has the sticky bit, which stops
/// an account renaming or removing an entry it does not own. So a sticky
/// directory such as `/tmp` is accepted for an entry of `account`'s or
/// root's, never for one another account created there first, and a
/// directory anywhere above the file counts, not only the one holding it.
/// The walk must end at the file `checked` describes; a path that changed
/// in between is refused.
#[cfg(unix)]
fn check_resolution(
    path: &Path,
    checked: &std::fs::Metadata,
    account: u32,
) -> Result<(), FileProblem> {
    use std::{ffi::OsString, os::unix::fs::MetadataExt, path::PathBuf};
    const ROOT: u32 = 0;
    const STICKY: u32 = 0o1000;
    const GROUP_OTHER_WRITE: u32 = 0o022;
    let trusted =
        |metadata: &std::fs::Metadata| metadata.uid() == ROOT || metadata.uid() == account;
    let safe_directory = |metadata: &std::fs::Metadata| {
        trusted(metadata)
            && (metadata.mode() & GROUP_OTHER_WRITE == 0 || metadata.mode() & STICKY != 0)
    };
    let examine =
        |entry: &Path| std::fs::symlink_metadata(entry).map_err(|_| FileProblem::Unreadable);

    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        // The working directory is reported with no link in it.
        std::env::current_dir()
            .map_err(|_| FileProblem::Unreadable)?
            .join(path)
    };
    // The names still to resolve, the next one last.
    let mut pending: Vec<OsString> = Vec::new();
    push_names(&absolute, &mut pending);
    // `resolved` names the entry reached so far with no link in it, and
    // `current` is that entry's metadata.
    let mut resolved = PathBuf::from("/");
    let mut current = examine(&resolved)?;
    let mut links = 0;
    while let Some(name) = pending.pop() {
        // Only a directory holds names; anything else here means the path
        // changed after the path check resolved it.
        if !current.is_dir() {
            return Err(FileProblem::Unreadable);
        }
        if name == ".." {
            // `resolved` holds no link, so its parent is the lexical one,
            // and no write to `current` can change which directory that is.
            resolved.pop();
            current = examine(&resolved)?;
            continue;
        }
        // Whoever can write the directory a name is looked up in can
        // replace the entry it names.
        if !safe_directory(&current) {
            return Err(FileProblem::UnsafePermissions);
        }
        let entry = resolved.join(&name);
        let metadata = examine(&entry)?;
        if !trusted(&metadata) {
            return Err(FileProblem::UnsafePermissions);
        }
        if metadata.file_type().is_symlink() {
            links += 1;
            if links > MAX_LINKS {
                return Err(FileProblem::Unreadable);
            }
            let target = std::fs::read_link(&entry).map_err(|_| FileProblem::Unreadable)?;
            // A relative target resolves in the directory holding the link.
            if target.is_absolute() {
                resolved = PathBuf::from("/");
                current = examine(&resolved)?;
            }
            push_names(&target, &mut pending);
            continue;
        }
        resolved = entry;
        current = metadata;
    }
    check_same_file(checked, &current)
}

/// Pushes the names in `path` so that popping yields them in order. A root
/// or `.` component names no entry and is left out; `..` is kept as itself.
#[cfg(unix)]
fn push_names(path: &Path, pending: &mut Vec<std::ffi::OsString>) {
    use std::path::Component;
    pending.extend(
        path.components()
            .rev()
            .filter_map(|component| match component {
                Component::Normal(_) | Component::ParentDir => {
                    Some(component.as_os_str().to_owned())
                }
                Component::RootDir | Component::CurDir | Component::Prefix(_) => None,
            }),
    );
}

/// Opens for reading with `O_NONBLOCK`, so opening a FIFO that replaced the
/// checked path returns at once instead of waiting for a writer; the handle
/// check then refuses it. A regular file reads the same either way.
#[cfg(unix)]
fn open_without_blocking(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
}

/// Opening a Windows named pipe or device does not wait for a peer, so a
/// plain open cannot block on one; the handle check then refuses it.
#[cfg(not(unix))]
fn open_without_blocking(path: &Path) -> io::Result<File> {
    File::open(path)
}

/// Refuses an opened handle that is not the file the path check examined
/// (another device or inode): the path was swapped in between.
#[cfg(unix)]
fn check_same_file(
    checked: &std::fs::Metadata,
    opened: &std::fs::Metadata,
) -> Result<(), FileProblem> {
    use std::os::unix::fs::MetadataExt;
    if checked.dev() == opened.dev() && checked.ino() == opened.ino() {
        Ok(())
    } else {
        Err(FileProblem::Unreadable)
    }
}

/// Windows exposes a file's identity only through an unstable API; the
/// handle is still checked for everything the path was.
#[cfg(not(unix))]
fn check_same_file(
    _checked: &std::fs::Metadata,
    _opened: &std::fs::Metadata,
) -> Result<(), FileProblem> {
    Ok(())
}

enum Bounded {
    TooLarge,
    Failed,
}

/// Reads at most `maximum` bytes, refusing more. The buffer is allocated
/// once at its final capacity so no partial copy of a secret is left behind
/// in a freed allocation.
fn read_bounded(reader: &mut dyn Read, maximum: usize) -> Result<Zeroizing<Vec<u8>>, Bounded> {
    let limit = u64::try_from(maximum).map_or(u64::MAX, |maximum| maximum.saturating_add(1));
    let mut bytes = Zeroizing::new(Vec::with_capacity(maximum.saturating_add(1)));
    match io::Read::take(reader, limit).read_to_end(&mut bytes) {
        Ok(_) if bytes.len() > maximum => Err(Bounded::TooLarge),
        Ok(_) => Ok(bytes),
        Err(_) => Err(Bounded::Failed),
    }
}

#[cfg(test)]
mod tests;
