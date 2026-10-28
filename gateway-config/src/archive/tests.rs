//! Fixture tests for archive entry admission: one table per rejection class.

use std::{
    collections::BTreeSet,
    io::{self, Cursor, Read, Write},
};

use super::*;

fn header(name: &str, kind: EntryKind, size: u64) -> EntryHeader<'_> {
    EntryHeader {
        name: name.as_bytes(),
        kind,
        size,
        stored_size: None,
    }
}

fn file(name: &str) -> EntryHeader<'_> {
    header(name, EntryKind::File, 0)
}

fn directory(name: &str) -> EntryHeader<'_> {
    header(name, EntryKind::Directory, 0)
}

fn new_guard() -> ArchiveGuard {
    ArchiveGuard::new(ArchiveLimits::default(), Compression::None)
}

fn limited(limits: ArchiveLimits) -> ArchiveGuard {
    ArchiveGuard::new(limits, Compression::None)
}

/// Admits `headers` in order into one guard; the last result.
fn admit_all(headers: &[EntryHeader<'_>]) -> Result<AdmittedEntry, ArchiveRefusal> {
    let mut guard = new_guard();
    let (last, earlier) = headers.split_last().expect("at least one header");
    for (index, header) in earlier.iter().enumerate() {
        if let Err(refusal) = guard.admit(header) {
            panic!("entry {} should be admitted: {refusal}", index + 1);
        }
    }
    guard.admit(last)
}

fn refusal_code(header: &EntryHeader<'_>) -> ArchiveCode {
    match new_guard().admit(header) {
        Ok(entry) => panic!("{header:?} should be refused, got {entry:?}"),
        Err(refusal) => {
            assert_eq!(refusal.entry, Some(1), "{refusal}");
            assert_eq!(refusal.conflicts_with, None, "{refusal}");
            refusal.code
        }
    }
}

fn admitted_path(entry: AdmittedEntry) -> String {
    match entry {
        AdmittedEntry::File(file) => file.path().as_str().to_owned(),
        AdmittedEntry::Directory(directory) => directory.path().as_str().to_owned(),
    }
}

fn file_entry(entry: AdmittedEntry) -> FileEntry {
    match entry {
        AdmittedEntry::File(file) => file,
        AdmittedEntry::Directory(directory) => panic!("{directory:?} is not a file"),
    }
}

// --- names --------------------------------------------------------------------

#[test]
fn portable_relative_names_are_admitted_unchanged() {
    let segment = "a".repeat(63);
    let deepest = "a/b/c/d/e/f/g/h";
    let longest = [segment.as_str(); 4].join("/");
    for name in [
        "backup.yaml",
        "stores/policy-history.sqlite",
        "Stores/Policy.JSON",
        "a",
        "0",
        "a.b.c",
        "a_b-c",
        "9lives",
        // Not device names: the stem before the first dot differs.
        "con1",
        "comx",
        "console.txt",
        "nul-file",
        "lpt10",
        "auxiliary.json",
        segment.as_str(),
        deepest,
        longest.as_str(),
    ] {
        let entry = new_guard()
            .admit(&file(name))
            .unwrap_or_else(|refusal| panic!("{name}: {refusal}"));
        assert_eq!(admitted_path(entry), name);
    }
    assert_eq!(longest.len(), 255);
}

#[test]
fn a_directory_name_may_end_in_one_slash() {
    for (name, path) in [("stores/", "stores"), ("stores", "stores"), ("a/b/", "a/b")] {
        let entry = new_guard()
            .admit(&directory(name))
            .unwrap_or_else(|refusal| panic!("{name}: {refusal}"));
        assert_eq!(admitted_path(entry), path);
    }
    assert_eq!(
        refusal_code(&directory("stores//")),
        ArchiveCode::InvalidName
    );
    assert_eq!(refusal_code(&directory("/")), ArchiveCode::InvalidName);
    assert_eq!(refusal_code(&file("stores/")), ArchiveCode::InvalidName);
}

#[test]
fn absolute_drive_and_unc_paths_are_refused() {
    for name in [
        "/etc/passwd",
        "/",
        "\\windows\\system32\\config",
        "\\\\server\\share\\file",
        "//server/share/file",
        "\\\\?\\C:\\file",
        "C:\\file",
        "C:/file",
        "c:file",
        "Z:",
    ] {
        assert_eq!(
            refusal_code(&file(name)),
            ArchiveCode::AbsolutePath,
            "{name}"
        );
    }
}

#[test]
fn a_dot_dot_segment_with_either_separator_is_refused() {
    for name in [
        "..",
        "../x",
        "a/../../x",
        "a/..",
        "..\\x",
        "a\\..\\x",
        "a/..\\..\\x",
        "stores/../../../etc/cron.d/x",
    ] {
        assert_eq!(
            refusal_code(&file(name)),
            ArchiveCode::EntryOutsideRoot,
            "{name}"
        );
    }
    assert_eq!(
        refusal_code(&directory("../")),
        ArchiveCode::EntryOutsideRoot
    );
}

#[test]
fn alternate_data_streams_are_refused() {
    for name in [
        "file.txt:stream",
        "file.txt::$DATA",
        "stores/history.sqlite:Zone.Identifier",
        "a/b:c",
        "ab:",
    ] {
        assert_eq!(
            refusal_code(&file(name)),
            ArchiveCode::AlternateDataStream,
            "{name}"
        );
    }
}

#[test]
fn windows_device_names_are_refused_in_any_case_and_with_any_extension() {
    for name in [
        "CON",
        "con",
        "Con",
        "con.",
        "PRN",
        "aux",
        "NUL",
        "nul.json",
        "NUL.tar.gz",
        "Com1",
        "com9.txt",
        "COM0",
        "LPT1",
        "lpt0.log",
        "a/CON/b",
        "stores/nul",
        "aux.d/x",
    ] {
        assert_eq!(
            refusal_code(&file(name)),
            ArchiveCode::ReservedName,
            "{name}"
        );
    }
    assert_eq!(refusal_code(&directory("nul/")), ArchiveCode::ReservedName);
}

#[test]
fn names_outside_the_portable_grammar_are_refused() {
    for name in [
        "",
        "a//b",
        "./a",
        "a/./b",
        ".",
        ".hidden",
        "-rf",
        "_x",
        "a.",
        "a/b.",
        "a..",
        "a b",
        "trailing ",
        "a\\b",
        "a~1",
        "a*b",
        "a?b",
        "a|b",
        "a<b",
        "a\"b",
        "CONIN$",
        "a\u{0}b",
        "policy.json\u{0}.exe",
        "a\tb",
        "a\nb",
        "\u{e9}t\u{e9}.json",
        "\u{212a}elvin",
        "\u{202e}nosj.exe",
    ] {
        assert_eq!(
            refusal_code(&file(name)),
            ArchiveCode::InvalidName,
            "{name:?}"
        );
    }
    let not_utf8 = EntryHeader {
        name: &[0xff, b'a'],
        kind: EntryKind::File,
        size: 0,
        stored_size: None,
    };
    assert_eq!(refusal_code(&not_utf8), ArchiveCode::InvalidName);
}

#[test]
fn long_and_deep_names_are_refused() {
    let segment = "a".repeat(64);
    assert_eq!(refusal_code(&file(&segment)), ArchiveCode::NameTooLong);
    let path = ["abcdefgh"; 29].join("/");
    assert!(path.len() > 255);
    assert_eq!(refusal_code(&file(&path)), ArchiveCode::NameTooLong);
    // The byte bound applies before anything else is examined.
    let traversal = format!("{}/..", "a".repeat(254));
    assert_eq!(refusal_code(&file(&traversal)), ArchiveCode::NameTooLong);
    assert_eq!(
        refusal_code(&file("a/b/c/d/e/f/g/h/i")),
        ArchiveCode::PathTooDeep
    );
}

// --- kinds --------------------------------------------------------------------

#[test]
fn only_files_and_directories_are_admitted() {
    for (kind, code) in [
        (EntryKind::Symlink, ArchiveCode::SymlinkEntry),
        (EntryKind::HardLink, ArchiveCode::HardLinkEntry),
        (EntryKind::CharacterDevice, ArchiveCode::SpecialEntry),
        (EntryKind::BlockDevice, ArchiveCode::SpecialEntry),
        (EntryKind::Fifo, ArchiveCode::SpecialEntry),
        (EntryKind::Socket, ArchiveCode::SpecialEntry),
        (EntryKind::Other, ArchiveCode::UnsupportedEntry),
    ] {
        assert_eq!(
            refusal_code(&header("stores/history.sqlite", kind, 0)),
            code,
            "{kind:?}"
        );
    }
}

// --- uniqueness ---------------------------------------------------------------

#[test]
fn duplicate_case_folded_and_conflicting_paths_are_refused() {
    use ArchiveCode::{CaseFoldCollision, DuplicateEntry, PathConflict};
    for (headers, code) in [
        ([file("policy.json"), file("policy.json")], DuplicateEntry),
        ([directory("stores/"), directory("stores")], DuplicateEntry),
        (
            [file("policy.json"), file("Policy.json")],
            CaseFoldCollision,
        ),
        (
            [file("POLICY.JSON"), file("policy.json")],
            CaseFoldCollision,
        ),
        (
            [file("stores/a.sqlite"), file("Stores/b.sqlite")],
            CaseFoldCollision,
        ),
        ([directory("stores/"), file("STORES/a")], CaseFoldCollision),
        (
            [directory("stores/"), directory("Stores/")],
            CaseFoldCollision,
        ),
        ([file("a/b/c"), file("a/B/d")], CaseFoldCollision),
        ([file("a/b/c"), directory("A/")], CaseFoldCollision),
        ([file("a"), file("a/b")], PathConflict),
        ([file("a/b"), file("a")], PathConflict),
        ([file("a"), directory("a/")], PathConflict),
        ([directory("a/"), file("a")], PathConflict),
        ([file("a/b/c"), file("a/b")], PathConflict),
    ] {
        let refusal = admit_all(&headers).expect_err("the last entry should be refused");
        assert_eq!(refusal.code, code, "{headers:?}");
        assert_eq!(refusal.entry, Some(2), "{headers:?}");
        assert_eq!(refusal.conflicts_with, Some(1), "{headers:?}");
    }
}

#[test]
fn distinct_paths_and_repeated_parents_are_admitted() {
    let mut guard = new_guard();
    for header in [
        directory("stores/"),
        file("stores/a.sqlite"),
        file("stores/b.sqlite"),
        // A directory listed after the entries inside it.
        file("keys/one.key"),
        directory("keys/"),
        file("policy.json"),
        file("policy.json.bak"),
        file("A1"),
        file("a2"),
    ] {
        guard
            .admit(&header)
            .unwrap_or_else(|refusal| panic!("{header:?}: {refusal}"));
    }
    let refusal = guard.admit(&directory("keys")).expect_err("listed twice");
    assert_eq!(
        refusal,
        ArchiveRefusal {
            code: ArchiveCode::DuplicateEntry,
            entry: Some(10),
            conflicts_with: Some(5),
        }
    );
}

// --- declared sizes -----------------------------------------------------------

#[test]
fn declared_sizes_are_charged_before_any_data_is_read() {
    let limits = ArchiveLimits {
        max_entry_bytes: 64,
        max_total_bytes: 100,
        ..ArchiveLimits::default()
    };
    let mut guard = limited(limits);
    assert_eq!(
        guard
            .admit(&header("big", EntryKind::File, 65))
            .expect_err("too large")
            .code,
        ArchiveCode::EntryTooLarge
    );

    let mut guard = limited(limits);
    for (name, size) in [("one", 60), ("two", 40), ("empty", 0)] {
        guard
            .admit(&header(name, EntryKind::File, size))
            .unwrap_or_else(|refusal| panic!("{name}: {refusal}"));
    }
    let refusal = guard
        .admit(&header("three", EntryKind::File, 1))
        .expect_err("over the total");
    assert_eq!(refusal.code, ArchiveCode::TotalTooLarge);
    assert_eq!(refusal.entry, Some(4));

    for header in [
        header("stores/", EntryKind::Directory, 1),
        EntryHeader {
            stored_size: Some(5),
            ..directory("stores/")
        },
    ] {
        assert_eq!(refusal_code(&header), ArchiveCode::DirectoryHasData);
    }
}

#[test]
fn a_declared_compressed_size_is_held_to_the_expansion_ratio() {
    let limits = ArchiveLimits {
        max_expansion_ratio: 10,
        ratio_floor_bytes: 1000,
        ..ArchiveLimits::default()
    };
    let entry = |size, stored| EntryHeader {
        stored_size: Some(stored),
        ..header("x", EntryKind::File, size)
    };
    for (size, stored, admitted) in [
        // Under the floor whatever the ratio.
        (1000, 0, true),
        (1000, 1, true),
        // At the ratio.
        (1500, 150, true),
        (2000, 200, true),
        // Past it.
        (1001, 0, false),
        (1501, 150, false),
        (2000, 100, false),
        // Within the entry bound, far past the ratio.
        (1 << 30, 1, false),
    ] {
        let result = limited(limits).admit(&entry(size, stored));
        if admitted {
            result.unwrap_or_else(|refusal| panic!("{size}/{stored}: {refusal}"));
        } else {
            assert_eq!(
                result.expect_err("over the ratio").code,
                ArchiveCode::ExpansionRatioExceeded,
                "{size}/{stored}"
            );
        }
    }
}

#[test]
fn entries_past_the_count_bound_are_refused() {
    let mut guard = limited(ArchiveLimits {
        max_entries: 3,
        ..ArchiveLimits::default()
    });
    for name in ["a", "b", "c"] {
        guard.admit(&file(name)).expect("within the bound");
    }
    assert_eq!(
        guard.admit(&file("d")).expect_err("past the bound"),
        ArchiveRefusal::entry(ArchiveCode::TooManyEntries, 4)
    );
}

// --- data ---------------------------------------------------------------------

/// Returns at most `step` bytes per read.
struct Trickle<R> {
    inner: R,
    step: usize,
}

impl<R: Read> Read for Trickle<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let wanted = buffer.len().min(self.step);
        self.inner.read(&mut buffer[..wanted])
    }
}

/// Fails every read with `kind`, after `before` successful bytes.
struct Failing {
    before: usize,
    kind: io::ErrorKind,
    interrupted_once: bool,
}

impl Read for Failing {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.kind == io::ErrorKind::Interrupted && !self.interrupted_once {
            self.interrupted_once = true;
            return Err(io::Error::from(io::ErrorKind::Interrupted));
        }
        if self.before > 0 {
            let read = self.before.min(buffer.len());
            buffer[..read].fill(b'x');
            self.before -= read;
            return Ok(read);
        }
        if self.kind == io::ErrorKind::Interrupted {
            return Ok(0);
        }
        Err(io::Error::from(self.kind))
    }
}

/// Counts the bytes written; refuses every write when `broken`.
#[derive(Default)]
pub(super) struct CountingSink {
    pub(super) written: u64,
    broken: bool,
}

impl Write for CountingSink {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if self.broken {
            return Err(io::Error::other("refused"));
        }
        self.written += u64::try_from(buffer.len()).expect("fits");
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A run-length decoder: each 5-byte record (a little-endian `u32` count
/// and a byte) expands to that many copies of the byte. Up to 858 million
/// to one, it reads a record only when the previous run is spent, so the
/// compressed bytes it has read are exactly those it has used.
pub(super) struct RunLengthDecoder<R> {
    source: R,
    run: u32,
    byte: u8,
}

impl<R: Read> RunLengthDecoder<R> {
    pub(super) fn new(source: R) -> Self {
        Self {
            source,
            run: 0,
            byte: 0,
        }
    }
}

pub(super) fn run_length(runs: &[(u32, u8)]) -> Vec<u8> {
    let mut encoded = Vec::new();
    for (count, byte) in runs {
        encoded.extend_from_slice(&count.to_le_bytes());
        encoded.push(*byte);
    }
    encoded
}

impl<R: Read> Read for RunLengthDecoder<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        while self.run == 0 {
            let mut record = [0_u8; 5];
            match self.source.read_exact(&mut record) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(0),
                Err(error) => return Err(error),
            }
            self.run = u32::from_le_bytes([record[0], record[1], record[2], record[3]]);
            self.byte = record[4];
        }
        let wanted = buffer
            .len()
            .min(usize::try_from(self.run).unwrap_or(usize::MAX));
        buffer[..wanted].fill(self.byte);
        self.run -= u32::try_from(wanted).expect("at most the run");
        Ok(wanted)
    }
}

fn admitted_file(guard: &mut ArchiveGuard, name: &str, size: u64) -> FileEntry {
    file_entry(
        guard
            .admit(&header(name, EntryKind::File, size))
            .unwrap_or_else(|refusal| panic!("{name}: {refusal}")),
    )
}

#[test]
fn data_of_exactly_the_declared_length_is_copied() {
    let data: Vec<u8> = (0..=255).cycle().take(3 * COPY_CHUNK_BYTES + 7).collect();
    for step in [1, 7, COPY_CHUNK_BYTES, usize::MAX] {
        let mut guard = new_guard();
        let entry = admitted_file(&mut guard, "stores/a.sqlite", data.len() as u64);
        let mut sink = Vec::new();
        let source = Trickle {
            inner: Cursor::new(&data),
            step,
        };
        assert_eq!(guard.copy(&entry, source, &mut sink), Ok(data.len() as u64));
        assert_eq!(sink, data);
        let summary = guard.finish().expect("no refusal");
        assert_eq!(summary.copied_bytes, data.len() as u64);
        assert_eq!(summary.declared_bytes, data.len() as u64);
    }

    let mut guard = new_guard();
    let empty = admitted_file(&mut guard, "empty", 0);
    assert_eq!(guard.copy(&empty, io::empty(), io::sink()), Ok(0));
}

#[test]
fn short_data_is_truncated_and_long_data_is_refused_unwritten() {
    for (declared, actual) in [(10, 9), (10, 0), (COPY_CHUNK_BYTES as u64 * 2, 5)] {
        let mut guard = new_guard();
        let entry = admitted_file(&mut guard, "a", declared);
        let data = vec![7_u8; actual];
        let mut sink = Vec::new();
        let refusal = guard
            .copy(&entry, Cursor::new(&data), &mut sink)
            .expect_err("short");
        assert_eq!(refusal, ArchiveRefusal::entry(ArchiveCode::Truncated, 1));
        assert_eq!(sink, data);
    }

    for (declared, actual, step) in [
        (0, 1, usize::MAX),
        (10, 11, usize::MAX),
        (10, 11, 1),
        (10, 4 * COPY_CHUNK_BYTES, usize::MAX),
        (COPY_CHUNK_BYTES as u64, COPY_CHUNK_BYTES + 1, 100),
    ] {
        let mut guard = new_guard();
        let entry = admitted_file(&mut guard, "a", declared);
        let data = vec![7_u8; actual];
        let mut sink = Vec::new();
        let source = Trickle {
            inner: Cursor::new(&data),
            step,
        };
        let refusal = guard.copy(&entry, source, &mut sink).expect_err("long");
        assert_eq!(
            refusal,
            ArchiveRefusal::entry(ArchiveCode::DeclaredSizeExceeded, 1)
        );
        assert!(sink.len() as u64 <= declared, "{declared} {}", sink.len());
    }
}

#[test]
fn read_and_write_failures_are_refusals_without_library_text() {
    for (kind, code) in [
        (io::ErrorKind::UnexpectedEof, ArchiveCode::Truncated),
        (io::ErrorKind::InvalidData, ArchiveCode::ReadFailed),
        (io::ErrorKind::PermissionDenied, ArchiveCode::ReadFailed),
    ] {
        let mut guard = new_guard();
        let entry = admitted_file(&mut guard, "a", 100);
        let source = Failing {
            before: 10,
            kind,
            interrupted_once: true,
        };
        let refusal = guard.copy(&entry, source, io::sink()).expect_err("fails");
        assert_eq!(refusal, ArchiveRefusal::entry(code, 1), "{kind:?}");
    }

    // An interrupted read is retried.
    let mut guard = new_guard();
    let entry = admitted_file(&mut guard, "a", 10);
    let source = Failing {
        before: 10,
        kind: io::ErrorKind::Interrupted,
        interrupted_once: false,
    };
    assert_eq!(guard.copy(&entry, source, io::sink()), Ok(10));

    let mut guard = new_guard();
    let entry = admitted_file(&mut guard, "a", 3);
    let sink = CountingSink {
        broken: true,
        ..CountingSink::default()
    };
    assert_eq!(
        guard.copy(&entry, Cursor::new(b"abc"), sink),
        Err(ArchiveRefusal::entry(ArchiveCode::WriteFailed, 1))
    );
}

// --- decompression bombs ------------------------------------------------------

fn metered(limits: ArchiveLimits) -> (ArchiveGuard, CompressedCounter) {
    let counter = CompressedCounter::new();
    (
        ArchiveGuard::new(limits, Compression::Metered(counter.clone())),
        counter,
    )
}

#[test]
fn a_decompression_bomb_is_refused_at_the_ratio_bound() {
    let limits = ArchiveLimits::default();
    let (mut guard, counter) = metered(limits);
    // Five compressed bytes claiming a GiB of zeros, honestly declared.
    let gibibyte = 1024 * 1024 * 1024;
    let encoded = run_length(&[(gibibyte, 0)]);
    let entry = admitted_file(&mut guard, "stores/bomb.sqlite", u64::from(gibibyte));
    let mut sink = CountingSink::default();
    let decoder = RunLengthDecoder::new(counter.reader(Cursor::new(encoded)));
    let refusal = guard.copy(&entry, decoder, &mut sink).expect_err("a bomb");
    assert_eq!(
        refusal,
        ArchiveRefusal::entry(ArchiveCode::ExpansionRatioExceeded, 1)
    );
    assert_eq!(counter.bytes(), 5);
    // Nothing past the floor was written: the ratio allows 500 bytes here.
    assert!(sink.written <= limits.ratio_floor_bytes, "{}", sink.written);
    assert!(sink.written + COPY_CHUNK_BYTES as u64 > limits.ratio_floor_bytes);
}

#[test]
fn a_bomb_behind_a_small_declared_size_is_refused_at_that_size() {
    let (mut guard, counter) = metered(ArchiveLimits::default());
    let encoded = run_length(&[(u32::MAX, b'a')]);
    let entry = admitted_file(&mut guard, "policy.json", 100);
    let mut sink = CountingSink::default();
    let decoder = RunLengthDecoder::new(counter.reader(Cursor::new(encoded)));
    assert_eq!(
        guard.copy(&entry, decoder, &mut sink),
        Err(ArchiveRefusal::entry(ArchiveCode::DeclaredSizeExceeded, 1))
    );
    assert_eq!(sink.written, 0);
}

#[test]
fn the_ratio_is_measured_across_the_whole_archive() {
    let limits = ArchiveLimits {
        max_expansion_ratio: 4,
        ratio_floor_bytes: 64 * 1024,
        ..ArchiveLimits::default()
    };
    let (mut guard, counter) = metered(limits);
    // Two entries of 48 KiB from one compressed stream of 10 bytes: each
    // alone is under the floor, together they are not.
    let encoded = run_length(&[(48 * 1024, b'a'), (48 * 1024, b'b')]);
    let mut decoder = RunLengthDecoder::new(counter.reader(Cursor::new(encoded)));
    let first = admitted_file(&mut guard, "one", 48 * 1024);
    let second = admitted_file(&mut guard, "two", 48 * 1024);
    assert_eq!(
        guard.copy(&first, (&mut decoder).take(48 * 1024), io::sink()),
        Ok(48 * 1024)
    );
    assert_eq!(
        guard.copy(&second, (&mut decoder).take(48 * 1024), io::sink()),
        Err(ArchiveRefusal::entry(
            ArchiveCode::ExpansionRatioExceeded,
            2
        ))
    );
}

#[test]
fn honest_compressed_data_within_the_ratio_is_copied() {
    let limits = ArchiveLimits {
        max_expansion_ratio: 2,
        ratio_floor_bytes: 0,
        ..ArchiveLimits::default()
    };
    let (mut guard, counter) = metered(limits);
    // Ten bytes per five compressed: a ratio of two, exactly the bound.
    let runs: Vec<(u32, u8)> = (0..10_000).map(|index| (10, index as u8)).collect();
    let encoded = run_length(&runs);
    let entry = admitted_file(&mut guard, "a", 100_000);
    let decoder = RunLengthDecoder::new(counter.reader(Cursor::new(encoded)));
    assert_eq!(guard.copy(&entry, decoder, io::sink()), Ok(100_000));
    assert_eq!(counter.bytes(), 50_000);
}

#[test]
fn an_uncompressed_container_checks_only_declared_stored_sizes() {
    let mut guard = new_guard();
    let encoded = run_length(&[(4 * 1024 * 1024, 0)]);
    let entry = admitted_file(&mut guard, "a", 4 * 1024 * 1024);
    let decoder = RunLengthDecoder::new(Cursor::new(encoded));
    assert_eq!(guard.copy(&entry, decoder, io::sink()), Ok(4 * 1024 * 1024));
}

// --- the guard ----------------------------------------------------------------

#[test]
fn the_first_refusal_is_final() {
    let mut guard = new_guard();
    guard.admit(&file("a")).expect("valid");
    let refusal = guard.admit(&file("../b")).expect_err("traversal");
    assert_eq!(
        refusal,
        ArchiveRefusal::entry(ArchiveCode::EntryOutsideRoot, 2)
    );
    assert_eq!(guard.admit(&file("c")), Err(refusal.clone()));
    let entry = FileEntry {
        position: 1,
        path: EntryPath("a".to_owned()),
        size: 0,
    };
    assert_eq!(
        guard.copy(&entry, io::empty(), io::sink()),
        Err(refusal.clone())
    );
    assert_eq!(guard.finish(), Err(refusal));

    // A refused copy is just as final.
    let mut guard = new_guard();
    let entry = admitted_file(&mut guard, "a", 5);
    let refusal = guard
        .copy(&entry, Cursor::new(b"abc"), io::sink())
        .expect_err("short");
    assert_eq!(guard.admit(&file("b")), Err(refusal.clone()));
    assert_eq!(guard.finish(), Err(refusal));
}

#[test]
fn the_summary_counts_what_the_archive_held() {
    let mut guard = new_guard();
    guard.admit(&directory("stores/")).expect("valid");
    let one = admitted_file(&mut guard, "stores/one", 3);
    admitted_file(&mut guard, "stores/two", 4);
    guard
        .copy(&one, Cursor::new(b"abc"), io::sink())
        .expect("copied");
    assert_eq!(
        guard.finish(),
        Ok(ArchiveSummary {
            entries: 3,
            files: 2,
            directories: 1,
            declared_bytes: 7,
            copied_bytes: 3,
        })
    );
}

#[test]
fn the_default_bounds_are_the_documented_ones() {
    assert_eq!(
        ArchiveLimits::default(),
        ArchiveLimits {
            max_entries: 1024,
            max_path_bytes: 255,
            max_segment_bytes: 63,
            max_depth: 8,
            max_entry_bytes: 1 << 30,
            max_total_bytes: 4 << 30,
            max_expansion_ratio: 100,
            ratio_floor_bytes: 1 << 20,
        }
    );
    assert_eq!(COPY_CHUNK_BYTES, 16 * 1024);
}

// --- diagnostics --------------------------------------------------------------

const CANARY: &str = "zq9canary";

#[test]
fn refusals_never_carry_an_entry_name() {
    let upper = CANARY.to_ascii_uppercase();
    let long = format!("{CANARY}/{}", "a".repeat(300));
    let deep = format!("{CANARY}/a/b/c/d/e/f/g/h");
    let names = [
        format!("../{CANARY}"),
        format!("/{CANARY}"),
        format!("{CANARY}:stream"),
        format!("nul/{CANARY}"),
        format!("{CANARY} x"),
        long,
        deep,
    ];
    let mut refusals = Vec::new();
    for name in &names {
        refusals.push(new_guard().admit(&file(name)).expect_err("refused"));
    }
    refusals.push(
        new_guard()
            .admit(&header(CANARY, EntryKind::Symlink, 0))
            .expect_err("refused"),
    );
    refusals.push(admit_all(&[file(CANARY), file(&upper)]).expect_err("refused"));
    refusals.push(admit_all(&[file(CANARY), file(CANARY)]).expect_err("refused"));

    let codes: BTreeSet<&str> = refusals.iter().map(|r| r.code.as_str()).collect();
    assert_eq!(codes.len(), refusals.len(), "one refusal per class");
    for refusal in &refusals {
        let rendered = format!("{refusal} {refusal:?}").to_ascii_lowercase();
        assert!(!rendered.contains(CANARY), "{rendered}");
    }
    let rendered = format!("{:?}", file(CANARY)).to_ascii_lowercase();
    assert!(!rendered.contains(CANARY), "{rendered}");
}

#[test]
fn refusals_render_their_code_message_and_positions() {
    let duplicate = admit_all(&[file("a"), file("a")]).expect_err("duplicate");
    assert_eq!(
        duplicate.to_string(),
        "entry 2: error[archive.duplicate_entry]: two entries name the same path \
         (conflicts with entry 1)"
    );
    assert_eq!(
        ArchiveRefusal::archive(ArchiveCode::Malformed).to_string(),
        "archive: error[archive.malformed]: the archive's container structure is invalid"
    );
    assert_eq!(
        ArchiveRefusal::entry(ArchiveCode::Truncated, 7).to_string(),
        "entry 7: error[archive.truncated]: the archive or an entry's data ends before \
         its declared size"
    );
}

#[test]
fn every_code_is_stable_unique_and_documented() {
    let reference = include_str!("../../../docs/archive-admission.md").replace("\r\n", "\n");
    let mut seen = BTreeSet::new();
    for code in ArchiveCode::ALL {
        let text = code.as_str();
        let (family, reason) = text.split_once('.').expect("family.reason");
        assert_eq!(family, "archive", "{text}");
        assert!(
            !reason.is_empty()
                && reason.split('_').all(|word| {
                    word.as_bytes()
                        .first()
                        .is_some_and(|first| first.is_ascii_lowercase())
                        && word
                            .bytes()
                            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
                }),
            "{text}"
        );
        assert!(seen.insert(text), "{text} is used twice");
        assert!(
            !code.message().is_empty() && !code.message().ends_with('.'),
            "{text}"
        );
        assert!(
            reference.contains(&format!("| `{text}` |")),
            "{text} is not documented"
        );
    }
}
