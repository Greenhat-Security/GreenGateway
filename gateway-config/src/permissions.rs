//! File-permission predicates shared by the gateway's secret providers and
//! the configuration bundle reader.

use std::fs;

/// Whether a platform-projected directory root carries acceptable
/// permissions: not writable by group or other, or, when it is, with the
/// sticky bit set.
///
/// Container runtimes publish projected volumes (Kubernetes Secret, ConfigMap
/// and projected volumes) as a tmpfs whose mount root is world-writable with
/// the sticky bit set -- `drwxrwxrwt`, mode `1777`. The sticky bit is what
/// makes that shape safe: a process that does not own an entry cannot rename
/// or delete it, so an entry cannot be swapped underneath a reader. A
/// group- or other-writable root without the sticky bit offers no such
/// protection and is refused.
///
/// Windows has no mode bits; its ACLs remain an operator and platform
/// responsibility.
#[cfg(unix)]
pub fn projected_root_permissions_are_safe(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    const STICKY: u32 = 0o1000;
    const GROUP_OTHER_WRITE: u32 = 0o022;
    let mode = metadata.mode();
    mode & GROUP_OTHER_WRITE == 0 || mode & STICKY != 0
}

#[cfg(not(unix))]
pub fn projected_root_permissions_are_safe(_: &fs::Metadata) -> bool {
    true
}
