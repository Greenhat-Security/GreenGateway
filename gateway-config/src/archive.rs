//! Admission of archive entries: the rules every archive GreenGateway reads
//! must enforce, whatever its container (issue #242, ADR-0008).
//!
//! Configuration bundles are directories only and have no archive form. The
//! archive ADR-0008 does define, the backup archive `ggctl backup verify` and
//! `restore` will read, is a later slice, and so is the choice of its
//! container format under the dependency policy. What the ADR fixes now is
//! the list that reader must refuse: absolute paths, `..`, duplicate and
//! case-colliding names, alternate data streams, links, reparse points,
//! devices, sockets, excessive entry counts, truncation and decompression
//! past its bound. This module is that list, written once, so a container
//! adapter only translates its headers and streams and cannot approximate it.
//!
//! An adapter hands every entry header to [`ArchiveGuard::admit`] before it
//! reads that entry's data, and copies each admitted file's data through
//! [`ArchiveGuard::copy`]:
//!
//! - **Names.** An entry name is a relative path of `/`-separated segments,
//!   each `^[A-Za-z0-9][A-Za-z0-9._-]*$`, not ending in `.` and not a Windows
//!   device name in any case and with any extension. So no name can be
//!   absolute, climb out of the extraction root, name an NTFS alternate data
//!   stream, mean a different path on Windows (where `\` separates and a
//!   trailing dot is dropped), or alias another name by Unicode
//!   normalization: the grammar is ASCII, which also makes ASCII folding the
//!   complete case fold.
//! - **Uniqueness.** Two entries may not name the same path, paths that
//!   differ only in letter case (directory segments included), or one path
//!   as both a file and a directory: on a case-insensitive filesystem the
//!   second would overwrite or enter the first.
//! - **Kinds.** Only regular files and directories are admitted.
//! - **Sizes.** Declared sizes are charged against per-entry and total
//!   bounds before any data is read; data is then copied in fixed chunks and
//!   must be exactly its declared length, so a lying header can neither
//!   overrun nor end short. Over a compressed container, the decompressed
//!   bytes copied may not exceed a fixed multiple of the compressed bytes
//!   read, checked before every chunk is written, so a decompression bomb is
//!   refused within one chunk of its bound.
//!
//! The first refusal is final: every later call returns it again. A refusal
//! is value-free by construction (a stable code, fixed text and entry
//! positions), so no entry name, size or library error text reaches a
//! diagnostic.
//!
//! Everything here is side-effect free: the guard reads only the readers and
//! writes only the writers it is handed. Creating files beneath a fresh
//! staging root is the reader's job, with the admitted segments.

use std::{
    collections::BTreeMap,
    error::Error,
    fmt,
    io::{self, Read, Write},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

/// Bytes copied per read; a ratio or size overrun is caught within one.
pub const COPY_CHUNK_BYTES: usize = 16 * 1024;

/// The bounds one archive is read under.
///
/// [`ArchiveLimits::default`] holds the bounds a reader gets unless it
/// states tighter ones.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArchiveLimits {
    /// Entries of every kind, directories included.
    pub max_entries: usize,
    /// Bytes of one entry name, before a directory's trailing `/` is removed.
    pub max_path_bytes: usize,
    /// Bytes of one path segment.
    pub max_segment_bytes: usize,
    /// Segments of one entry name.
    pub max_depth: usize,
    /// Decompressed bytes one entry may declare.
    pub max_entry_bytes: u64,
    /// Decompressed bytes every entry together may declare.
    pub max_total_bytes: u64,
    /// The most decompressed bytes allowed per compressed byte.
    pub max_expansion_ratio: u64,
    /// Decompressed bytes always allowed, whatever the ratio, so a small,
    /// highly compressible entry is not refused.
    pub ratio_floor_bytes: u64,
}

impl Default for ArchiveLimits {
    fn default() -> Self {
        Self {
            max_entries: 1024,
            max_path_bytes: 255,
            max_segment_bytes: 63,
            max_depth: 8,
            max_entry_bytes: 1024 * 1024 * 1024,
            max_total_bytes: 4 * 1024 * 1024 * 1024,
            max_expansion_ratio: 100,
            ratio_floor_bytes: 1024 * 1024,
        }
    }
}

/// What an archive header says an entry is.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryKind {
    File,
    Directory,
    /// A symbolic link, or a junction or other reparse point.
    Symlink,
    HardLink,
    CharacterDevice,
    BlockDevice,
    Fifo,
    Socket,
    /// Any other header type: sparse files, volume labels, unknown types.
    Other,
}

/// One entry header, as the container records it.
pub struct EntryHeader<'a> {
    /// The name's exact bytes.
    pub name: &'a [u8],
    pub kind: EntryKind,
    /// The decompressed size the header declares.
    pub size: u64,
    /// The compressed size, when the container records one per entry.
    pub stored_size: Option<u64>,
}

/// Never prints the name.
impl fmt::Debug for EntryHeader<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EntryHeader")
            .field("name_bytes", &self.name.len())
            .field("kind", &self.kind)
            .field("size", &self.size)
            .field("stored_size", &self.stored_size)
            .finish()
    }
}

/// Whether, and how, the container's data is compressed.
#[derive(Clone, Debug)]
pub enum Compression {
    /// Entry data is stored as is; only declared stored sizes are checked
    /// against the expansion ratio.
    None,
    /// Entry data is decompressed from a source read through
    /// [`CompressedCounter::reader`]; every chunk is checked against the
    /// compressed bytes that counter has seen.
    Metered(CompressedCounter),
}

/// Counts the compressed bytes a decompressor has read, archive-wide.
///
/// The decompressor owns the reader; the guard keeps a clone of the counter.
/// The ratio is measured against bytes read, not bytes the decompressor has
/// used yet, so one that buffers reads ahead is credited with its buffer
/// early: that never refuses honest data, and delays a refusal by at most
/// the ratio times the buffer size.
#[derive(Clone, Debug, Default)]
pub struct CompressedCounter(Arc<AtomicU64>);

impl CompressedCounter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Wraps the compressed source.
    pub fn reader<R: Read>(&self, inner: R) -> CountingReader<R> {
        CountingReader {
            inner,
            counter: self.clone(),
        }
    }

    /// Compressed bytes read so far.
    pub fn bytes(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }

    fn add(&self, bytes: usize) {
        // 2^64 bytes cannot be read; were the counter ever to wrap, the
        // ratio would refuse sooner, not later.
        self.0
            .fetch_add(u64::try_from(bytes).unwrap_or(u64::MAX), Ordering::Relaxed);
    }
}

/// A compressed source that charges every byte read to its counter.
#[derive(Debug)]
pub struct CountingReader<R> {
    inner: R,
    counter: CompressedCounter,
}

impl<R> CountingReader<R> {
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> Read for CountingReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(buffer)?;
        self.counter.add(read);
        Ok(read)
    }
}

/// An admitted entry name: a relative path of portable segments joined by
/// `/`, without a trailing `/`.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EntryPath(String);

impl EntryPath {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The segments, outermost first, for creating each beneath the root.
    pub fn segments(&self) -> impl Iterator<Item = &str> {
        self.0.split('/')
    }
}

/// An admitted regular file, whose data must pass [`ArchiveGuard::copy`].
#[derive(Debug, Eq, PartialEq)]
pub struct FileEntry {
    position: usize,
    path: EntryPath,
    size: u64,
}

impl FileEntry {
    /// The entry's 1-based position in the archive.
    pub fn position(&self) -> usize {
        self.position
    }

    pub fn path(&self) -> &EntryPath {
        &self.path
    }

    /// The declared decompressed size.
    pub fn size(&self) -> u64 {
        self.size
    }
}

/// An admitted directory.
#[derive(Debug, Eq, PartialEq)]
pub struct DirectoryEntry {
    position: usize,
    path: EntryPath,
}

impl DirectoryEntry {
    /// The entry's 1-based position in the archive.
    pub fn position(&self) -> usize {
        self.position
    }

    pub fn path(&self) -> &EntryPath {
        &self.path
    }
}

/// An entry [`ArchiveGuard::admit`] accepted.
#[derive(Debug, Eq, PartialEq)]
pub enum AdmittedEntry {
    File(FileEntry),
    Directory(DirectoryEntry),
}

/// What an archive held, once every entry passed.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ArchiveSummary {
    pub entries: usize,
    pub files: usize,
    pub directories: usize,
    /// Decompressed bytes the file entries declared.
    pub declared_bytes: u64,
    /// Decompressed bytes copied; less than `declared_bytes` when a reader
    /// did not copy every file.
    pub copied_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClaimKind {
    File,
    Directory,
    /// A directory only named as the parent of another entry.
    Parent,
}

/// A path some entry already uses, keyed by its ASCII case fold.
#[derive(Debug)]
struct Claim {
    exact: String,
    kind: ClaimKind,
    position: usize,
}

/// Reads one archive's entries under [`ArchiveLimits`].
#[derive(Debug)]
pub struct ArchiveGuard {
    limits: ArchiveLimits,
    compression: Compression,
    claims: BTreeMap<String, Claim>,
    summary: ArchiveSummary,
    refused: Option<ArchiveRefusal>,
}

impl ArchiveGuard {
    pub fn new(limits: ArchiveLimits, compression: Compression) -> Self {
        Self {
            limits,
            compression,
            claims: BTreeMap::new(),
            summary: ArchiveSummary::default(),
            refused: None,
        }
    }

    /// Admits the next entry, before any of its data is read.
    pub fn admit(&mut self, header: &EntryHeader<'_>) -> Result<AdmittedEntry, ArchiveRefusal> {
        if let Some(refusal) = &self.refused {
            return Err(refusal.clone());
        }
        let result = self.admit_entry(header);
        self.record(result)
    }

    /// Copies an admitted file's data from `data` to `sink`, refusing it
    /// unless it is exactly the declared length and, over a compressed
    /// container, within the expansion ratio. Returns the bytes copied.
    ///
    /// No byte past either bound is written; a refused entry may have been
    /// partly written, so the destination must be discarded with the
    /// staging root.
    pub fn copy<R: Read, W: Write>(
        &mut self,
        entry: &FileEntry,
        data: R,
        sink: W,
    ) -> Result<u64, ArchiveRefusal> {
        if let Some(refusal) = &self.refused {
            return Err(refusal.clone());
        }
        let result = self
            .copy_data(entry, data, sink)
            .map_err(|code| ArchiveRefusal::entry(code, entry.position));
        self.record(result)
    }

    /// Ends the archive; the summary, or the refusal that ended it early.
    pub fn finish(self) -> Result<ArchiveSummary, ArchiveRefusal> {
        match self.refused {
            Some(refusal) => Err(refusal),
            None => Ok(self.summary),
        }
    }

    fn record<T>(&mut self, result: Result<T, ArchiveRefusal>) -> Result<T, ArchiveRefusal> {
        if let Err(refusal) = &result {
            self.refused = Some(refusal.clone());
        }
        result
    }

    fn admit_entry(&mut self, header: &EntryHeader<'_>) -> Result<AdmittedEntry, ArchiveRefusal> {
        let position = self.summary.entries.saturating_add(1);
        let refuse = |code| ArchiveRefusal::entry(code, position);
        if position > self.limits.max_entries {
            return Err(refuse(ArchiveCode::TooManyEntries));
        }
        self.summary.entries = position;

        let directory = header.kind == EntryKind::Directory;
        let path = admit_name(header.name, directory, &self.limits).map_err(refuse)?;
        let claim = match header.kind {
            EntryKind::File => ClaimKind::File,
            EntryKind::Directory => ClaimKind::Directory,
            EntryKind::Symlink => return Err(refuse(ArchiveCode::SymlinkEntry)),
            EntryKind::HardLink => return Err(refuse(ArchiveCode::HardLinkEntry)),
            EntryKind::CharacterDevice
            | EntryKind::BlockDevice
            | EntryKind::Fifo
            | EntryKind::Socket => return Err(refuse(ArchiveCode::SpecialEntry)),
            EntryKind::Other => return Err(refuse(ArchiveCode::UnsupportedEntry)),
        };
        if directory {
            if header.size != 0 || header.stored_size.is_some_and(|stored| stored != 0) {
                return Err(refuse(ArchiveCode::DirectoryHasData));
            }
        } else {
            self.charge_declared(header).map_err(refuse)?;
        }
        self.claim(&path, claim, position)?;

        if directory {
            self.summary.directories += 1;
            Ok(AdmittedEntry::Directory(DirectoryEntry { position, path }))
        } else {
            self.summary.files += 1;
            Ok(AdmittedEntry::File(FileEntry {
                position,
                path,
                size: header.size,
            }))
        }
    }

    fn charge_declared(&mut self, header: &EntryHeader<'_>) -> Result<(), ArchiveCode> {
        if header.size > self.limits.max_entry_bytes {
            return Err(ArchiveCode::EntryTooLarge);
        }
        if let Some(stored) = header.stored_size {
            if exceeds_ratio(header.size, stored, &self.limits) {
                return Err(ArchiveCode::ExpansionRatioExceeded);
            }
        }
        let total = self.summary.declared_bytes.saturating_add(header.size);
        if total > self.limits.max_total_bytes {
            return Err(ArchiveCode::TotalTooLarge);
        }
        self.summary.declared_bytes = total;
        Ok(())
    }

    /// Claims `path` and its parents, refusing any path an earlier entry
    /// already uses differently. Nothing is claimed unless all of it can be.
    fn claim(
        &mut self,
        path: &EntryPath,
        kind: ClaimKind,
        position: usize,
    ) -> Result<(), ArchiveRefusal> {
        let conflict =
            |code, earlier: &Claim| ArchiveRefusal::conflict(code, position, earlier.position);
        let mut parents = Vec::new();
        let mut end = 0;
        for segment in path.segments() {
            if end > 0 {
                let parent = &path.as_str()[..end];
                let key = parent.to_ascii_lowercase();
                match self.claims.get(&key) {
                    None => parents.push((key, parent.to_owned())),
                    Some(earlier) if earlier.exact != parent => {
                        return Err(conflict(ArchiveCode::CaseFoldCollision, earlier));
                    }
                    Some(earlier) if earlier.kind == ClaimKind::File => {
                        return Err(conflict(ArchiveCode::PathConflict, earlier));
                    }
                    Some(_) => {}
                }
                end += 1;
            }
            end += segment.len();
        }

        let key = path.as_str().to_ascii_lowercase();
        match self.claims.get_mut(&key) {
            None => {
                self.claims.insert(
                    key,
                    Claim {
                        exact: path.as_str().to_owned(),
                        kind,
                        position,
                    },
                );
            }
            Some(earlier) if earlier.exact != path.as_str() => {
                return Err(conflict(ArchiveCode::CaseFoldCollision, earlier));
            }
            // A directory listed after the entries inside it.
            Some(earlier) if earlier.kind == ClaimKind::Parent && kind == ClaimKind::Directory => {
                earlier.kind = ClaimKind::Directory;
                earlier.position = position;
            }
            Some(earlier) if earlier.kind == kind => {
                return Err(conflict(ArchiveCode::DuplicateEntry, earlier));
            }
            Some(earlier) => return Err(conflict(ArchiveCode::PathConflict, earlier)),
        }
        for (key, exact) in parents {
            self.claims.insert(
                key,
                Claim {
                    exact,
                    kind: ClaimKind::Parent,
                    position,
                },
            );
        }
        Ok(())
    }

    fn copy_data<R: Read, W: Write>(
        &mut self,
        entry: &FileEntry,
        mut data: R,
        mut sink: W,
    ) -> Result<u64, ArchiveCode> {
        let mut buffer = [0_u8; COPY_CHUNK_BYTES];
        let mut copied: u64 = 0;
        loop {
            // At most one byte past the declared size, which is enough to
            // see an overrun without reading any further.
            let remaining = entry.size.saturating_sub(copied);
            let wanted = usize::try_from(remaining.saturating_add(1))
                .map_or(buffer.len(), |wanted| wanted.min(buffer.len()));
            let read = match data.read(&mut buffer[..wanted]) {
                Ok(0) => break,
                Ok(read) => read,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                    return Err(ArchiveCode::Truncated);
                }
                Err(_) => return Err(ArchiveCode::ReadFailed),
            };
            let read_bytes = u64::try_from(read).unwrap_or(u64::MAX);
            copied = copied.saturating_add(read_bytes);
            if copied > entry.size {
                return Err(ArchiveCode::DeclaredSizeExceeded);
            }
            let total = self.summary.copied_bytes.saturating_add(read_bytes);
            if let Compression::Metered(counter) = &self.compression {
                if exceeds_ratio(total, counter.bytes(), &self.limits) {
                    return Err(ArchiveCode::ExpansionRatioExceeded);
                }
            }
            sink.write_all(&buffer[..read])
                .map_err(|_| ArchiveCode::WriteFailed)?;
            self.summary.copied_bytes = total;
        }
        if copied < entry.size {
            return Err(ArchiveCode::Truncated);
        }
        sink.flush().map_err(|_| ArchiveCode::WriteFailed)?;
        Ok(copied)
    }
}

fn exceeds_ratio(decompressed: u64, compressed: u64, limits: &ArchiveLimits) -> bool {
    decompressed > limits.ratio_floor_bytes
        && decompressed > compressed.saturating_mul(limits.max_expansion_ratio)
}

/// Checks an entry name against the portable grammar, the most specific
/// reason first.
fn admit_name(
    name: &[u8],
    directory: bool,
    limits: &ArchiveLimits,
) -> Result<EntryPath, ArchiveCode> {
    if name.len() > limits.max_path_bytes {
        return Err(ArchiveCode::NameTooLong);
    }
    let Ok(name) = std::str::from_utf8(name) else {
        return Err(ArchiveCode::InvalidName);
    };
    // tar and zip both write a directory's name with one trailing `/`.
    let name = if directory {
        name.strip_suffix('/').unwrap_or(name)
    } else {
        name
    };
    if name.is_empty() {
        return Err(ArchiveCode::InvalidName);
    }
    if name.starts_with(['/', '\\']) || has_drive_prefix(name) {
        return Err(ArchiveCode::AbsolutePath);
    }
    // Both separators, because Windows honours both.
    if name.split(['/', '\\']).any(|segment| segment == "..") {
        return Err(ArchiveCode::EntryOutsideRoot);
    }
    if name.contains(':') {
        return Err(ArchiveCode::AlternateDataStream);
    }
    if name.split('/').count() > limits.max_depth {
        return Err(ArchiveCode::PathTooDeep);
    }
    for segment in name.split('/') {
        if segment.len() > limits.max_segment_bytes {
            return Err(ArchiveCode::NameTooLong);
        }
        if is_windows_device_name(segment) {
            return Err(ArchiveCode::ReservedName);
        }
        if !is_portable_segment(segment) {
            return Err(ArchiveCode::InvalidName);
        }
    }
    Ok(EntryPath(name.to_owned()))
}

/// `C:`, `c:x`, `C:\x`: a drive-absolute or drive-relative Windows path.
fn has_drive_prefix(name: &str) -> bool {
    let bytes = name.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

/// `^[A-Za-z0-9][A-Za-z0-9._-]*$`, not ending in `.`.
fn is_portable_segment(segment: &str) -> bool {
    let bytes = segment.as_bytes();
    bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        && !segment.ends_with('.')
}

/// Windows resolves these names to devices in any case and with any
/// extension (`NUL.json`, `com1.tar.gz`).
fn is_windows_device_name(segment: &str) -> bool {
    let stem = segment.split_once('.').map_or(segment, |(stem, _)| stem);
    match stem.to_ascii_lowercase().as_bytes() {
        b"con" | b"prn" | b"aux" | b"nul" => true,
        [b'c', b'o', b'm', digit] | [b'l', b'p', b't', digit] => digit.is_ascii_digit(),
        _ => false,
    }
}

/// Every reason an archive can be refused.
///
/// The string form (`archive.reason`) is the stable contract. A published
/// code never changes meaning; renaming or removing one needs a new report
/// schema.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArchiveCode {
    TooManyEntries,
    NameTooLong,
    PathTooDeep,
    InvalidName,
    AbsolutePath,
    EntryOutsideRoot,
    AlternateDataStream,
    ReservedName,
    DuplicateEntry,
    CaseFoldCollision,
    PathConflict,
    SymlinkEntry,
    HardLinkEntry,
    SpecialEntry,
    UnsupportedEntry,
    DirectoryHasData,
    EntryTooLarge,
    TotalTooLarge,
    ExpansionRatioExceeded,
    DeclaredSizeExceeded,
    Truncated,
    Malformed,
    ReadFailed,
    WriteFailed,
}

impl ArchiveCode {
    /// Every code, in declaration order, for the uniqueness and
    /// documentation tests.
    #[cfg(test)]
    pub(crate) const ALL: &'static [ArchiveCode] = &[
        Self::TooManyEntries,
        Self::NameTooLong,
        Self::PathTooDeep,
        Self::InvalidName,
        Self::AbsolutePath,
        Self::EntryOutsideRoot,
        Self::AlternateDataStream,
        Self::ReservedName,
        Self::DuplicateEntry,
        Self::CaseFoldCollision,
        Self::PathConflict,
        Self::SymlinkEntry,
        Self::HardLinkEntry,
        Self::SpecialEntry,
        Self::UnsupportedEntry,
        Self::DirectoryHasData,
        Self::EntryTooLarge,
        Self::TotalTooLarge,
        Self::ExpansionRatioExceeded,
        Self::DeclaredSizeExceeded,
        Self::Truncated,
        Self::Malformed,
        Self::ReadFailed,
        Self::WriteFailed,
    ];

    /// The stable code.
    pub fn as_str(self) -> &'static str {
        self.entry().0
    }

    /// Fixed text describing the code. Never a value.
    pub fn message(self) -> &'static str {
        self.entry().1
    }

    fn entry(self) -> (&'static str, &'static str) {
        match self {
            Self::TooManyEntries => (
                "archive.too_many_entries",
                "the archive holds more entries than allowed",
            ),
            Self::NameTooLong => (
                "archive.name_too_long",
                "an entry name or one of its path segments is longer than allowed",
            ),
            Self::PathTooDeep => (
                "archive.path_too_deep",
                "an entry name has more path segments than allowed",
            ),
            Self::InvalidName => (
                "archive.invalid_name",
                "an entry name is not a relative path of portable ASCII segments",
            ),
            Self::AbsolutePath => (
                "archive.absolute_path",
                "an entry name is an absolute, drive or UNC path",
            ),
            Self::EntryOutsideRoot => (
                "archive.entry_outside_root",
                "an entry name has a .. segment that would leave the extraction root",
            ),
            Self::AlternateDataStream => (
                "archive.alternate_data_stream",
                "an entry name contains a colon, which names an NTFS alternate data stream",
            ),
            Self::ReservedName => (
                "archive.reserved_name",
                "an entry name has a segment Windows reserves for a device",
            ),
            Self::DuplicateEntry => ("archive.duplicate_entry", "two entries name the same path"),
            Self::CaseFoldCollision => (
                "archive.case_fold_collision",
                "two entries name paths that differ only in letter case",
            ),
            Self::PathConflict => (
                "archive.path_conflict",
                "a path is used both as a file and as a directory",
            ),
            Self::SymlinkEntry => (
                "archive.symlink_entry",
                "an entry is a symbolic link, junction or reparse point",
            ),
            Self::HardLinkEntry => ("archive.hard_link_entry", "an entry is a hard link"),
            Self::SpecialEntry => (
                "archive.special_entry",
                "an entry is a device, FIFO or socket",
            ),
            Self::UnsupportedEntry => (
                "archive.unsupported_entry",
                "an entry is of a type the reader does not accept",
            ),
            Self::DirectoryHasData => (
                "archive.directory_has_data",
                "a directory entry declares data",
            ),
            Self::EntryTooLarge => (
                "archive.entry_too_large",
                "an entry declares more decompressed bytes than one entry may hold",
            ),
            Self::TotalTooLarge => (
                "archive.total_too_large",
                "the entries declare more decompressed bytes in total than allowed",
            ),
            Self::ExpansionRatioExceeded => (
                "archive.expansion_ratio_exceeded",
                "decompressed data exceeds the allowed multiple of the compressed bytes read",
            ),
            Self::DeclaredSizeExceeded => (
                "archive.declared_size_exceeded",
                "an entry's data is longer than its declared size",
            ),
            Self::Truncated => (
                "archive.truncated",
                "the archive or an entry's data ends before its declared size",
            ),
            Self::Malformed => (
                "archive.malformed",
                "the archive's container structure is invalid",
            ),
            Self::ReadFailed => ("archive.read_failed", "the archive could not be read"),
            Self::WriteFailed => (
                "archive.write_failed",
                "an entry's data could not be written to its destination",
            ),
        }
    }
}

/// Why an archive was refused, without any value from it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveRefusal {
    pub code: ArchiveCode,
    /// The 1-based position of the refused entry, when there is one.
    pub entry: Option<usize>,
    /// The position of the earlier entry a duplicate, collision or conflict
    /// clashes with.
    pub conflicts_with: Option<usize>,
}

impl ArchiveRefusal {
    /// A refusal of the archive as a whole, for a container adapter: a
    /// malformed or truncated container, or a failed read.
    pub fn archive(code: ArchiveCode) -> Self {
        Self {
            code,
            entry: None,
            conflicts_with: None,
        }
    }

    /// A refusal of the entry at `position`.
    pub fn entry(code: ArchiveCode, position: usize) -> Self {
        Self {
            entry: Some(position),
            ..Self::archive(code)
        }
    }

    fn conflict(code: ArchiveCode, position: usize, earlier: usize) -> Self {
        Self {
            conflicts_with: Some(earlier),
            ..Self::entry(code, position)
        }
    }
}

impl fmt::Display for ArchiveRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.entry {
            Some(position) => write!(formatter, "entry {position}: ")?,
            None => formatter.write_str("archive: ")?,
        }
        write!(
            formatter,
            "error[{}]: {}",
            self.code.as_str(),
            self.code.message()
        )?;
        if let Some(earlier) = self.conflicts_with {
            write!(formatter, " (conflicts with entry {earlier})")?;
        }
        Ok(())
    }
}

impl Error for ArchiveRefusal {}

#[cfg(test)]
mod property_tests;
#[cfg(test)]
mod tests;
