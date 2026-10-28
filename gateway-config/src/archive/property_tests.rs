//! Bounded, seeded properties of archive entry admission.
//!
//! Each property runs a fixed number of cases from a fixed seed, so a failure
//! reproduces exactly and the suite's cost is bounded. They cover what the
//! fixture tables cannot enumerate: no hostile name is admitted unless it is
//! a portable path that stays beneath the extraction root on this platform,
//! the uniqueness rules agree with an independent model of a
//! case-insensitive filesystem, and copied data never passes its declared
//! size or the expansion ratio.

use std::{
    io::{self, Cursor, Read},
    path::{Component, Path},
};

use super::tests::{run_length, CountingSink, RunLengthDecoder};
use super::*;

/// SplitMix64.
struct Cases(u64);

impl Cases {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut mixed = self.0;
        mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        mixed ^ (mixed >> 31)
    }

    /// A value in `0..bound`.
    fn below(&mut self, bound: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(bound).expect("fits")).expect("fits")
    }

    /// A value in `low..=high`.
    fn between(&mut self, low: u64, high: u64) -> u64 {
        low + self.next() % (high - low + 1)
    }

    fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[self.below(items.len())]
    }

    fn coin(&mut self) -> bool {
        self.next() & 1 == 1
    }
}

/// Pieces of ordinary names.
const ORDINARY: &[&str] = &[
    "a", "b", "Z", "q", "0", "9", "stores", "x.json", "policy", "-", "_", ".", "/",
];

/// Pieces that mean something to a filesystem.
const HOSTILE: &[&str] = &[
    "..", "/", "\\", ":", " ", "\0", "\t", "~", "$", "*", "?", "\u{e9}", "\u{212a}", "\u{202e}",
    "con", "NUL", "com1", "lpt9", "C:", "//", "./", "../",
];

/// An independent statement of the segment grammar.
fn is_reference_segment(segment: &str) -> bool {
    let mut characters = segment.chars();
    let Some(first) = characters.next() else {
        return false;
    };
    let stem = segment.split('.').next().unwrap_or_default().to_lowercase();
    let device = ["con", "prn", "aux", "nul"].contains(&stem.as_str())
        || (stem.len() == 4
            && (stem.starts_with("com") || stem.starts_with("lpt"))
            && stem.ends_with(|last: char| last.is_ascii_digit()));
    first.is_ascii_alphanumeric()
        && characters.all(|character| {
            character.is_ascii_alphanumeric() || ['.', '_', '-'].contains(&character)
        })
        && !segment.ends_with('.')
        && !device
}

#[test]
fn no_hostile_name_is_admitted_outside_the_portable_grammar() {
    let mut cases = Cases::new(242_401);
    let limits = ArchiveLimits::default();
    let (mut admitted, mut refused) = (0, 0);
    for _ in 0..8192 {
        let pieces = cases.below(10);
        let name: String = (0..pieces)
            .map(|_| {
                if cases.below(4) == 0 {
                    cases.pick(HOSTILE)
                } else {
                    cases.pick(ORDINARY)
                }
            })
            .collect();
        let kind = if cases.coin() {
            EntryKind::File
        } else {
            EntryKind::Directory
        };
        let header = EntryHeader {
            name: name.as_bytes(),
            kind,
            size: 0,
            stored_size: None,
        };
        let mut guard = ArchiveGuard::new(limits, Compression::None);
        let path = match guard.admit(&header) {
            Ok(AdmittedEntry::File(entry)) => {
                assert_eq!(kind, EntryKind::File, "{name:?}");
                entry.path().clone()
            }
            Ok(AdmittedEntry::Directory(entry)) => {
                assert_eq!(kind, EntryKind::Directory, "{name:?}");
                entry.path().clone()
            }
            Err(refusal) => {
                refused += 1;
                assert_eq!(refusal.entry, Some(1));
                assert!(
                    matches!(
                        refusal.code,
                        ArchiveCode::NameTooLong
                            | ArchiveCode::PathTooDeep
                            | ArchiveCode::InvalidName
                            | ArchiveCode::AbsolutePath
                            | ArchiveCode::EntryOutsideRoot
                            | ArchiveCode::AlternateDataStream
                            | ArchiveCode::ReservedName
                    ),
                    "{name:?}: {refusal}"
                );
                continue;
            }
        };
        admitted += 1;

        // Admission never rewrites a name, beyond a directory's one
        // trailing slash.
        let text = path.as_str();
        assert!(
            name == text || (kind == EntryKind::Directory && name == format!("{text}/")),
            "{name:?} became {text:?}"
        );
        assert!(!text.is_empty() && text.len() <= limits.max_path_bytes);
        let segments: Vec<&str> = path.segments().collect();
        assert!(segments.len() <= limits.max_depth, "{text:?}");
        for segment in &segments {
            assert!(segment.len() <= limits.max_segment_bytes, "{text:?}");
            assert!(is_reference_segment(segment), "{text:?}");
        }

        // Joined beneath a root, this platform's own parser sees only
        // ordinary components, one per segment.
        let root = Path::new("staging");
        let joined = root.join(text);
        assert!(joined.starts_with(root), "{text:?}");
        let components: Vec<Component<'_>> = joined.components().collect();
        assert_eq!(components.len(), segments.len() + 1, "{text:?}");
        assert!(
            components
                .iter()
                .all(|component| matches!(component, Component::Normal(_))),
            "{text:?}"
        );
    }
    // The generator reaches both outcomes often enough to mean something.
    assert!(admitted > 500 && refused > 2000, "{admitted} {refused}");
}

/// One node of an entry: its full path or one of its parent directories.
struct Node {
    exact: String,
    folded: String,
    file: bool,
    /// Named by a directory entry itself, rather than implied as a parent.
    explicit: bool,
}

fn nodes(path: &str, file: bool) -> Vec<Node> {
    let segments: Vec<&str> = path.split('/').collect();
    (1..=segments.len())
        .map(|length| {
            let exact = segments[..length].join("/");
            let last = length == segments.len();
            Node {
                folded: exact.to_ascii_lowercase(),
                exact,
                file: last && file,
                explicit: last && !file,
            }
        })
        .collect()
}

/// A case-insensitive filesystem's view of two entries: they clash when any
/// two of their nodes fold together, unless both are directories spelled
/// alike that at most one entry names explicitly.
fn clash(earlier: &[Node], later: &[Node]) -> bool {
    earlier.iter().any(|a| {
        later.iter().any(|b| {
            a.folded == b.folded
                && (a.exact != b.exact || a.file || b.file || (a.explicit && b.explicit))
        })
    })
}

#[test]
fn uniqueness_agrees_with_a_case_insensitive_filesystem() {
    const SEGMENTS: &[&str] = &["a", "A", "b", "B", "ab", "aB", "Ab"];
    let mut cases = Cases::new(242_402);
    let (mut clean, mut clashing) = (0, 0);
    for _ in 0..4096 {
        let count = 2 + cases.below(5);
        let entries: Vec<(String, bool)> = (0..count)
            .map(|_| {
                let depth = 1 + cases.below(3);
                let path: Vec<&str> = (0..depth).map(|_| cases.pick(SEGMENTS)).collect();
                (path.join("/"), cases.coin())
            })
            .collect();
        let expected = (1..entries.len()).find(|&later| {
            let later_nodes = nodes(&entries[later].0, entries[later].1);
            entries[..later]
                .iter()
                .any(|(path, file)| clash(&nodes(path, *file), &later_nodes))
        });

        let mut guard = ArchiveGuard::new(ArchiveLimits::default(), Compression::None);
        let mut refused = None;
        for (index, (path, file)) in entries.iter().enumerate() {
            let name = if *file {
                path.clone()
            } else {
                format!("{path}/")
            };
            let header = EntryHeader {
                name: name.as_bytes(),
                kind: if *file {
                    EntryKind::File
                } else {
                    EntryKind::Directory
                },
                size: 0,
                stored_size: None,
            };
            if let Err(refusal) = guard.admit(&header) {
                assert!(
                    matches!(
                        refusal.code,
                        ArchiveCode::DuplicateEntry
                            | ArchiveCode::CaseFoldCollision
                            | ArchiveCode::PathConflict
                    ),
                    "{entries:?}: {refusal}"
                );
                assert_eq!(refusal.entry, Some(index + 1), "{entries:?}");
                let earlier = refusal.conflicts_with.expect("names the earlier entry");
                assert!(earlier <= index, "{entries:?}: {refusal}");
                refused = Some(index);
                break;
            }
        }
        assert_eq!(refused, expected, "{entries:?}");
        if expected.is_some() {
            clashing += 1;
        } else {
            clean += 1;
        }
    }
    assert!(clean > 300 && clashing > 300, "{clean} {clashing}");
}

#[test]
fn every_case_variant_of_an_admitted_path_is_refused() {
    const LETTERS: &[u8] = b"abcdefgxyzABCDEFGXYZ0123456789._-";
    let mut cases = Cases::new(242_403);
    for _ in 0..2048 {
        let depth = 1 + cases.below(4);
        let segments: Vec<String> = (0..depth)
            .map(|_| loop {
                let length = 1 + cases.below(8);
                let segment: String = (0..length)
                    .map(|_| char::from(cases.pick(LETTERS)))
                    .collect();
                if is_reference_segment(&segment) {
                    break segment;
                }
            })
            .collect();
        let path = segments.join("/");
        let variant: String = path
            .chars()
            .map(|character| {
                if cases.coin() {
                    character.to_ascii_uppercase()
                } else {
                    character.to_ascii_lowercase()
                }
            })
            .collect();

        let mut guard = ArchiveGuard::new(ArchiveLimits::default(), Compression::None);
        let first = EntryHeader {
            name: path.as_bytes(),
            kind: EntryKind::File,
            size: 0,
            stored_size: None,
        };
        guard.admit(&first).expect("a portable path");
        let second = EntryHeader {
            name: variant.as_bytes(),
            ..first
        };
        let expected = if variant == path {
            ArchiveCode::DuplicateEntry
        } else {
            ArchiveCode::CaseFoldCollision
        };
        assert_eq!(
            guard.admit(&second),
            Err(ArchiveRefusal {
                code: expected,
                entry: Some(2),
                conflicts_with: Some(1),
            }),
            "{path} {variant}"
        );

        // A new file beside the path, under a case variant of its parent,
        // clashes exactly when the parent is spelled differently.
        if let Some((parent, _)) = variant.rsplit_once('/') {
            let mut guard = ArchiveGuard::new(ArchiveLimits::default(), Compression::None);
            guard.admit(&first).expect("a portable path");
            let sibling = format!("{parent}/sibling-file-9");
            let header = EntryHeader {
                name: sibling.as_bytes(),
                ..first
            };
            let result = guard.admit(&header);
            if path.starts_with(&format!("{parent}/")) {
                assert!(result.is_ok(), "{path} {sibling}");
            } else {
                assert_eq!(
                    result.map(|_| ()).map_err(|refusal| refusal.code),
                    Err(ArchiveCode::CaseFoldCollision),
                    "{path} {sibling}"
                );
            }
        }
    }
}

/// Returns between one byte and `step` bytes per read.
struct Uneven<R> {
    inner: R,
    cases: Cases,
    step: usize,
}

impl<R: Read> Read for Uneven<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let wanted = buffer.len().min(1 + self.cases.below(self.step));
        self.inner.read(&mut buffer[..wanted])
    }
}

#[test]
fn copied_data_is_exactly_the_declared_length_or_refused() {
    let mut cases = Cases::new(242_404);
    let chunk = u64::try_from(COPY_CHUNK_BYTES).expect("fits");
    for _ in 0..512 {
        let declared = cases.between(0, 3 * chunk);
        let actual = match cases.below(3) {
            0 => declared,
            1 => cases.between(0, declared.saturating_sub(1)),
            _ => declared + cases.between(1, chunk + 1),
        };
        let data: Vec<u8> = (0..actual).map(|index| index as u8).collect();
        let mut guard = ArchiveGuard::new(ArchiveLimits::default(), Compression::None);
        let header = EntryHeader {
            name: b"stores/data.sqlite",
            kind: EntryKind::File,
            size: declared,
            stored_size: None,
        };
        let Ok(AdmittedEntry::File(entry)) = guard.admit(&header) else {
            panic!("{declared} should be admitted");
        };
        let source = Uneven {
            inner: Cursor::new(&data),
            cases: Cases::new(cases.next()),
            step: 1 + cases.below(2 * COPY_CHUNK_BYTES),
        };
        let mut sink = Vec::new();
        let result = guard.copy(&entry, source, &mut sink);
        assert!(sink.len() as u64 <= declared, "{declared} {actual}");
        assert_eq!(sink, data[..sink.len()], "{declared} {actual}");
        let expected = match actual.cmp(&declared) {
            std::cmp::Ordering::Equal => Ok(declared),
            std::cmp::Ordering::Less => Err(ArchiveCode::Truncated),
            std::cmp::Ordering::Greater => Err(ArchiveCode::DeclaredSizeExceeded),
        };
        assert_eq!(
            result.map_err(|refusal| refusal.code),
            expected,
            "{declared} {actual}"
        );
        if actual <= declared {
            assert_eq!(sink.len() as u64, actual);
        }
    }
}

#[test]
fn decompressed_bytes_never_pass_the_ratio_bound() {
    const RECORD: u64 = 5;
    let mut cases = Cases::new(242_405);
    let (mut copied, mut bombs) = (0, 0);
    for _ in 0..256 {
        let limits = ArchiveLimits {
            max_expansion_ratio: cases.between(1, 64),
            ratio_floor_bytes: cases.between(0, 128 * 1024),
            ..ArchiveLimits::default()
        };
        let longest = cases.pick(&[16_u64, 512, 4096, 65_536]);
        let mut runs = Vec::new();
        let mut total = 0;
        while total < 512 * 1024 && runs.len() < 64 {
            let count = cases.between(1, longest);
            runs.push((u32::try_from(count).expect("fits"), cases.pick(b"az09")));
            total += count;
        }

        // The decoder reads a record only when its run is spent, so while
        // run `k` is being copied exactly `k + 1` records have been read.
        // The worst moment of each run is its end.
        let mut through = 0;
        let refused_in = runs.iter().enumerate().position(|(index, (count, _))| {
            through += u64::from(*count);
            let compressed = (u64::try_from(index).expect("fits") + 1) * RECORD;
            through > limits.ratio_floor_bytes && through > compressed * limits.max_expansion_ratio
        });

        let counter = CompressedCounter::new();
        let mut guard = ArchiveGuard::new(limits, Compression::Metered(counter.clone()));
        let header = EntryHeader {
            name: b"stores/audit.sqlite",
            kind: EntryKind::File,
            size: total,
            stored_size: None,
        };
        let Ok(AdmittedEntry::File(entry)) = guard.admit(&header) else {
            panic!("{total} should be admitted");
        };
        let decoder = RunLengthDecoder::new(counter.reader(Cursor::new(run_length(&runs))));
        let mut sink = CountingSink::default();
        let result = guard.copy(&entry, decoder, &mut sink);

        let bound = limits
            .ratio_floor_bytes
            .max(counter.bytes() * limits.max_expansion_ratio);
        assert!(sink.written <= bound, "{limits:?} {runs:?}");
        match refused_in {
            None => {
                copied += 1;
                assert_eq!(result, Ok(total), "{limits:?} {runs:?}");
            }
            Some(run) => {
                bombs += 1;
                assert_eq!(
                    result.map_err(|refusal| refusal.code),
                    Err(ArchiveCode::ExpansionRatioExceeded),
                    "{limits:?} {runs:?}"
                );
                assert_eq!(
                    counter.bytes(),
                    (u64::try_from(run).expect("fits") + 1) * RECORD,
                    "refused in the first run that passes the bound"
                );
            }
        }
    }
    assert!(copied > 20 && bombs > 20, "{copied} {bombs}");
}
