//! The backup archive's container: a small framed format, written and read
//! here, whose every entry header and every byte of entry data passes the
//! shared [`ArchiveGuard`].
//!
//! The format is GreenGateway's own rather than tar or zip, so the build
//! takes no archive library (docs/deployment/cargo-dependency-policy.md):
//! everything tar can express beyond a regular file (long-name and PAX
//! extensions, links, sparse files, devices) is what the guard refuses, and a
//! fixed record grammar is simpler to bound. Nothing is compressed, so what
//! an archive can extract is never more than its own length.
//!
//! ```text
//! archive  = preamble record* end
//! preamble = "GGBACKUP" version:u16 flags:u16       version 1, flags 0
//! record   = kind:u8 name_length:u16 name size:u64 data
//! end      = 0x00 records:u32 digest:32 bytes
//! ```
//!
//! Integers are big-endian. `kind` is 1 for a regular file, 2 for a
//! directory, 3 for a symbolic link, 4 for a hard link, 5 and 6 for character
//! and block devices, 7 for a FIFO and 8 for a socket; any other non-zero
//! byte is an unknown kind. The writer writes regular files only, and the
//! reader hands every kind to the guard, which admits files and directories
//! alone. `data` is exactly `size` bytes. `records` counts the records, and
//! `digest` is the SHA-256 of every byte before it. Nothing may follow it.
//!
//! The digest detects an archive that was damaged or cut short; it is not a
//! signature, and whoever can write the archive can write a consistent one.

use std::io::{self, Read, Write};

use sha2::{Digest, Sha256};

use crate::archive::{
    AdmittedEntry, ArchiveCode, ArchiveGuard, ArchiveLimits, ArchiveRefusal, ArchiveSummary,
    Compression, EntryHeader, EntryKind, FileEntry,
};

/// The first bytes of every backup archive.
pub(super) const MAGIC: [u8; 8] = *b"GGBACKUP";
/// The one container version this build writes and reads.
pub(super) const FORMAT_VERSION: u16 = 1;
const FLAGS: u16 = 0;
const END: u8 = 0;
const FILE: u8 = 1;
/// The preamble's length.
const PREAMBLE_BYTES: u64 = 12;
/// The end record's length.
pub(super) const END_BYTES: u64 = 1 + 4 + 32;
/// A record's length before its name and data.
pub(super) const RECORD_FIXED_BYTES: u64 = 1 + 2 + 8;
/// Bytes copied per read while writing.
const CHUNK_BYTES: usize = 64 * 1024;

/// The guard's entry kind for a record's kind byte.
fn entry_kind(byte: u8) -> EntryKind {
    match byte {
        FILE => EntryKind::File,
        2 => EntryKind::Directory,
        3 => EntryKind::Symlink,
        4 => EntryKind::HardLink,
        5 => EntryKind::CharacterDevice,
        6 => EntryKind::BlockDevice,
        7 => EntryKind::Fifo,
        8 => EntryKind::Socket,
        _ => EntryKind::Other,
    }
}

/// The smallest archive: a preamble and an end record.
pub(super) const fn minimum_length() -> u64 {
    PREAMBLE_BYTES + END_BYTES
}

/// Writes a sink while hashing every byte written to it.
struct HashingWriter<W> {
    inner: W,
    hasher: Sha256,
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(buffer)?;
        self.hasher.update(&buffer[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Writes one archive.
pub(super) struct ContainerWriter<W: Write> {
    sink: HashingWriter<W>,
    records: u32,
}

impl<W: Write> ContainerWriter<W> {
    /// Starts an archive by writing its preamble.
    pub(super) fn new(sink: W) -> io::Result<Self> {
        let mut writer = Self {
            sink: HashingWriter {
                inner: sink,
                hasher: Sha256::new(),
            },
            records: 0,
        };
        writer.sink.write_all(&MAGIC)?;
        writer.sink.write_all(&FORMAT_VERSION.to_be_bytes())?;
        writer.sink.write_all(&FLAGS.to_be_bytes())?;
        Ok(writer)
    }

    /// Appends a regular file of exactly `size` bytes read from `data`, and
    /// returns the SHA-256 of those bytes. Data that ends early, or goes on
    /// past `size`, is an error and leaves the archive unfinished.
    pub(super) fn file(
        &mut self,
        name: &str,
        size: u64,
        mut data: impl Read,
    ) -> io::Result<[u8; 32]> {
        let name_length =
            u16::try_from(name.len()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        self.records = self
            .records
            .checked_add(1)
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
        self.sink.write_all(&[FILE])?;
        self.sink.write_all(&name_length.to_be_bytes())?;
        self.sink.write_all(name.as_bytes())?;
        self.sink.write_all(&size.to_be_bytes())?;
        let mut hasher = Sha256::new();
        let mut buffer = vec![0_u8; CHUNK_BYTES];
        let mut remaining = size;
        while remaining > 0 {
            let wanted =
                usize::try_from(remaining).map_or(buffer.len(), |left| left.min(buffer.len()));
            let read = match data.read(&mut buffer[..wanted]) {
                Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
                Ok(read) => read,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            };
            hasher.update(&buffer[..read]);
            self.sink.write_all(&buffer[..read])?;
            remaining -= u64::try_from(read).unwrap_or(u64::MAX).min(remaining);
        }
        // The source must end where its size said it would.
        loop {
            match data.read(&mut buffer[..1]) {
                Ok(0) => break,
                Ok(_) => return Err(io::Error::from(io::ErrorKind::InvalidData)),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        Ok(hasher.finalize().into())
    }

    /// Ends the archive with its end record and returns the sink, flushed.
    pub(super) fn finish(mut self) -> io::Result<W> {
        self.sink.write_all(&[END])?;
        self.sink.write_all(&self.records.to_be_bytes())?;
        let HashingWriter { mut inner, hasher } = self.sink;
        inner.write_all(&hasher.finalize())?;
        inner.flush()?;
        Ok(inner)
    }
}

/// Why an archive's container was refused, beyond the guard's own codes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum ContainerError {
    /// The guard refused an entry, or the container is malformed, truncated
    /// or unreadable.
    Refused(ArchiveRefusal),
    /// The file does not start like a backup archive.
    NotABackup,
    /// A backup archive of a container version this build does not read.
    UnsupportedVersion,
    /// The end record's digest is not the digest of the archive before it.
    DigestMismatch,
}

impl From<ArchiveRefusal> for ContainerError {
    fn from(refusal: ArchiveRefusal) -> Self {
        Self::Refused(refusal)
    }
}

/// Reads a source while hashing and counting every byte read from it.
struct HashingReader<R> {
    inner: R,
    hasher: Sha256,
    consumed: u64,
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(buffer)?;
        self.hasher.update(&buffer[..read]);
        self.consumed = self
            .consumed
            .saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
        Ok(read)
    }
}

/// Reads one archive, entry by entry, through the guard.
///
/// [`Self::next`] returns each entry the guard admitted, before any of its
/// data is read; the data of a file must then be read with [`Self::copy`]
/// before the next entry. The end record is checked when [`Self::next`]
/// reaches it.
pub(super) struct ContainerReader<R: Read> {
    source: HashingReader<R>,
    guard: ArchiveGuard,
    /// The archive's length as the caller found it on disk.
    length: u64,
    records: u32,
    /// A file whose data has not been read yet.
    unread: bool,
    ended: bool,
}

impl<R: Read> ContainerReader<R> {
    /// Reads and checks the preamble of the `length`-byte archive in
    /// `source`.
    pub(super) fn open(
        source: R,
        length: u64,
        limits: ArchiveLimits,
    ) -> Result<Self, ContainerError> {
        let mut reader = Self {
            source: HashingReader {
                inner: source,
                hasher: Sha256::new(),
                consumed: 0,
            },
            guard: ArchiveGuard::new(limits, Compression::None),
            length,
            records: 0,
            unread: false,
            ended: false,
        };
        let mut magic = [0_u8; MAGIC.len()];
        let read = read_up_to(&mut reader.source, &mut magic)?;
        if magic[..read] != MAGIC[..read] {
            return Err(ContainerError::NotABackup);
        }
        if read < magic.len() {
            return Err(truncated().into());
        }
        let version = reader.read_u16()?;
        if version != FORMAT_VERSION {
            return Err(ContainerError::UnsupportedVersion);
        }
        if reader.read_u16()? != FLAGS {
            return Err(ArchiveRefusal::archive(ArchiveCode::Malformed).into());
        }
        Ok(reader)
    }

    /// The next entry the guard admitted, or `None` once the end record is
    /// read and checked.
    pub(super) fn next(&mut self) -> Result<Option<AdmittedEntry>, ContainerError> {
        if self.unread || self.ended {
            // A caller that skipped a file's data, or read past the end.
            return Err(ArchiveRefusal::archive(ArchiveCode::Malformed).into());
        }
        let kind = self.read_u8()?;
        if kind == END {
            self.end()?;
            return Ok(None);
        }
        let name_length = usize::from(self.read_u16()?);
        let mut name = vec![0_u8; name_length];
        self.read_exact(&mut name)?;
        let size = self.read_u64()?;
        self.records = self
            .records
            .checked_add(1)
            .ok_or_else(|| ArchiveRefusal::archive(ArchiveCode::TooManyEntries))?;
        let admitted = self.guard.admit(&EntryHeader {
            name: &name,
            kind: entry_kind(kind),
            size,
            stored_size: None,
        })?;
        if let AdmittedEntry::File(file) = &admitted {
            // Data that could not fit before the end record is refused
            // before any of it is read or written.
            let room = self
                .length
                .saturating_sub(self.source.consumed)
                .saturating_sub(END_BYTES);
            if file.size() > room {
                return Err(ArchiveRefusal::entry(ArchiveCode::Truncated, file.position()).into());
            }
            self.unread = true;
        }
        Ok(Some(admitted))
    }

    /// Copies an admitted file's data to `sink` through the guard.
    pub(super) fn copy<W: Write>(
        &mut self,
        entry: &FileEntry,
        sink: W,
    ) -> Result<u64, ContainerError> {
        let copied = self
            .guard
            .copy(entry, (&mut self.source).take(entry.size()), sink)?;
        self.unread = false;
        Ok(copied)
    }

    /// The guard's summary, once the end record was read.
    pub(super) fn finish(self) -> Result<ArchiveSummary, ContainerError> {
        if !self.ended {
            return Err(ArchiveRefusal::archive(ArchiveCode::Malformed).into());
        }
        Ok(self.guard.finish()?)
    }

    fn end(&mut self) -> Result<(), ContainerError> {
        let records = self.read_u32()?;
        if records != self.records {
            return Err(ArchiveRefusal::archive(ArchiveCode::Malformed).into());
        }
        let expected: [u8; 32] = self.source.hasher.clone().finalize().into();
        let mut digest = [0_u8; 32];
        self.read_exact(&mut digest)?;
        if digest != expected {
            return Err(ContainerError::DigestMismatch);
        }
        let mut extra = [0_u8; 1];
        if read_up_to(&mut self.source, &mut extra)? != 0 {
            return Err(ArchiveRefusal::archive(ArchiveCode::Malformed).into());
        }
        self.ended = true;
        Ok(())
    }

    fn read_exact(&mut self, buffer: &mut [u8]) -> Result<(), ArchiveRefusal> {
        if read_up_to(&mut self.source, buffer)? < buffer.len() {
            return Err(truncated());
        }
        Ok(())
    }

    fn read_u8(&mut self) -> Result<u8, ArchiveRefusal> {
        let mut bytes = [0_u8; 1];
        self.read_exact(&mut bytes)?;
        Ok(bytes[0])
    }

    fn read_u16(&mut self) -> Result<u16, ArchiveRefusal> {
        let mut bytes = [0_u8; 2];
        self.read_exact(&mut bytes)?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn read_u32(&mut self) -> Result<u32, ArchiveRefusal> {
        let mut bytes = [0_u8; 4];
        self.read_exact(&mut bytes)?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn read_u64(&mut self) -> Result<u64, ArchiveRefusal> {
        let mut bytes = [0_u8; 8];
        self.read_exact(&mut bytes)?;
        Ok(u64::from_be_bytes(bytes))
    }
}

fn truncated() -> ArchiveRefusal {
    ArchiveRefusal::archive(ArchiveCode::Truncated)
}

/// Fills as much of `buffer` as the source holds; fewer bytes than its
/// length means the source ended.
fn read_up_to(source: &mut impl Read, buffer: &mut [u8]) -> Result<usize, ArchiveRefusal> {
    let mut filled = 0;
    while filled < buffer.len() {
        match source.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err(ArchiveRefusal::archive(ArchiveCode::ReadFailed)),
        }
    }
    Ok(filled)
}
