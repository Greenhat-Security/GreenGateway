//! Best-effort detection of a state directory on a network filesystem.
//!
//! Locks and SQLite are unsupported on network filesystems (ADR-0002): a
//! lock another host does not see, or a write-ahead log whose shared memory
//! index is not shared, breaks the guarantees the stores rely on. Where the
//! platform says what a filesystem is, the common network filesystems are
//! recognised:
//!
//! - **Linux:** `statfs` and its `f_type` magic number: NFS, SMB, CIFS and
//!   SMB2, NCP, Coda, AFS (OpenAFS and kAFS), Ceph, 9P, Lustre and GPFS.
//!   FUSE is not reported: `sshfs` and `ntfs-3g` share one magic number.
//! - **macOS:** `statfs` and its `f_fstypename`: `nfs`, `smbfs`, `afpfs`,
//!   `webdav` and `ftp`.
//! - **Windows:** a directory whose canonical path is a UNC path, which is
//!   what Windows resolves a mapped network drive to. No `GetDriveType`
//!   call: it would be this crate's first foreign function call, and a
//!   canonical drive-letter path is a local volume.
//!
//! Anything else is [`FilesystemKind::Local`], and a directory that cannot be
//! examined, or a platform with no check, is [`FilesystemKind::Unchecked`].
//! The answer is a warning for `ggctl doctor`, never a reason to refuse.

use std::path::Path;

/// The warning code `ggctl doctor` reports for a state directory on a
/// recognised network filesystem.
pub const NETWORK_FILESYSTEM_CODE: &str = "state_dir.network_filesystem";

/// What the best-effort check found.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FilesystemKind {
    /// A filesystem not recognised as a network filesystem.
    Local,
    /// A recognised network filesystem.
    Network,
    /// The directory could not be examined, or this platform has no check.
    Unchecked,
}

impl FilesystemKind {
    /// The warning code `ggctl doctor` reports, if any.
    pub fn warning_code(self) -> Option<&'static str> {
        match self {
            Self::Network => Some(NETWORK_FILESYSTEM_CODE),
            Self::Local | Self::Unchecked => None,
        }
    }
}

/// What kind of filesystem the directory at `path` is on. Reads metadata
/// only, opens nothing for writing and never fails.
pub fn filesystem_kind(path: &Path) -> FilesystemKind {
    platform_kind(path)
}

#[cfg(target_os = "linux")]
fn platform_kind(path: &Path) -> FilesystemKind {
    match rustix::fs::statfs(path) {
        // `f_type`'s width and signedness differ between architectures, and
        // some kernels sign-extend it; every magic number fits in 32 bits.
        Ok(stat) => linux_kind(stat.f_type as u32),
        Err(_) => FilesystemKind::Unchecked,
    }
}

#[cfg(target_os = "macos")]
fn platform_kind(path: &Path) -> FilesystemKind {
    match rustix::fs::statfs(path) {
        Ok(stat) => {
            // A NUL-terminated `c_char` array, whose signedness differs
            // between architectures.
            let name: Vec<u8> = stat
                .f_fstypename
                .iter()
                .take_while(|&&byte| byte != 0)
                .map(|&byte| byte as u8)
                .collect();
            macos_kind(&name)
        }
        Err(_) => FilesystemKind::Unchecked,
    }
}

#[cfg(windows)]
fn platform_kind(path: &Path) -> FilesystemKind {
    match std::fs::canonicalize(path) {
        Ok(canonical) => windows_kind(&canonical),
        Err(_) => FilesystemKind::Unchecked,
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn platform_kind(_: &Path) -> FilesystemKind {
    FilesystemKind::Unchecked
}

/// Linux `statfs` magic numbers of network filesystems, from
/// `include/uapi/linux/magic.h` and statfs(2).
#[cfg(any(test, target_os = "linux"))]
const LINUX_NETWORK_MAGIC: [u32; 12] = [
    0x0000_6969, // NFS_SUPER_MAGIC
    0x0000_517B, // SMB_SUPER_MAGIC
    0xFF53_4D42, // CIFS_SUPER_MAGIC
    0xFE53_4D42, // SMB2_SUPER_MAGIC
    0x0000_564C, // NCP_SUPER_MAGIC
    0x7375_7245, // CODA_SUPER_MAGIC
    0x5346_414F, // AFS_SUPER_MAGIC (OpenAFS)
    0x6B41_4653, // AFS_FS_MAGIC (kAFS)
    0x00C3_6400, // CEPH_SUPER_MAGIC
    0x0102_1997, // V9FS_MAGIC
    0x0BD0_0BD0, // LL_SUPER_MAGIC (Lustre)
    0x4750_4653, // GPFS_SUPER_MAGIC
];

#[cfg(any(test, target_os = "linux"))]
pub(super) fn linux_kind(magic: u32) -> FilesystemKind {
    if LINUX_NETWORK_MAGIC.contains(&magic) {
        FilesystemKind::Network
    } else {
        FilesystemKind::Local
    }
}

/// macOS `f_fstypename` values of network filesystems.
#[cfg(any(test, target_os = "macos"))]
const MACOS_NETWORK_TYPES: [&[u8]; 5] = [b"nfs", b"smbfs", b"afpfs", b"webdav", b"ftp"];

#[cfg(any(test, target_os = "macos"))]
pub(super) fn macos_kind(name: &[u8]) -> FilesystemKind {
    if MACOS_NETWORK_TYPES.contains(&name) {
        FilesystemKind::Network
    } else {
        FilesystemKind::Local
    }
}

/// A canonical path on another host: `\\server\share`, or its verbatim
/// `\\?\UNC\server\share` form.
#[cfg(windows)]
pub(super) fn windows_kind(canonical: &Path) -> FilesystemKind {
    use std::path::{Component, Prefix};

    match canonical.components().next() {
        Some(Component::Prefix(prefix))
            if matches!(prefix.kind(), Prefix::UNC(..) | Prefix::VerbatimUNC(..)) =>
        {
            FilesystemKind::Network
        }
        _ => FilesystemKind::Local,
    }
}
