# Archive entry admission

**Status: rules only; nothing reads an archive yet.** This page is the
reference for the entry admission rules in `gateway-config`
(`gateway-config/src/archive.rs`, issue #242). They are what
[ADR-0008](adr/0008-setup-cli-and-configuration-bundles.md) requires of every
archive GreenGateway reads. No released command reads one: the only archive
the ADR defines is the backup archive, and `ggctl backup verify` and
`ggctl backup restore` are a later #242 slice, which also chooses the
container format under the
[dependency policy](deployment/cargo-dependency-policy.md). No archive or
compression library is part of the build.

Configuration bundles are **directories only**
([configuration-bundles.md](configuration-bundles.md)). There is no archive
form of a bundle, and these rules do not add one.

A digest or a passing admission check is integrity information, not
authenticity: an archive that passes every rule below is well-formed, not
trusted.

## How a reader uses the rules

A container adapter (the code that parses tar, zip, or whatever the backup
slice chooses) translates each entry header into a name, a kind, a declared
decompressed size and, when the container records one, a compressed size. It
hands that header to the guard **before** it reads any of the entry's data,
then copies each admitted file's data through the guard into a file it
creates beneath a fresh staging root. The guard never opens, creates or
writes a file itself.

- The first refusal is final. Every later call returns the same refusal, so a
  reader cannot carry on past a hostile entry by mistake. A refused archive
  leaves only the staging root, which the reader discards.
- A refusal is value-free: a stable code, fixed text and the 1-based
  positions of the refused entry and, for a clash, the earlier entry it clashes
  with. No entry name, size, link target or library error text appears in
  one, so a refusal can be logged or reported as it is.

```text
entry 7: error[archive.case_fold_collision]: two entries name paths that differ only in letter case (conflicts with entry 3)
```

## Names

An entry name is a relative path of segments separated by `/`. A directory's
name may end with one `/`, as tar and zip both write it. Every segment:

- matches `^[A-Za-z0-9][A-Za-z0-9._-]*$`, so it starts with an ASCII letter or
  digit and holds only ASCII letters, digits, `.`, `_` and `-`;
- does not end in `.`, because Windows drops a trailing dot and `a.` would open
  `a`;
- is not a Windows device name (`CON`, `PRN`, `AUX`, `NUL`, `COM0` to `COM9`,
  `LPT0` to `LPT9`) in any letter case and with any extension (`nul.json`,
  `Com1.tar.gz`).

The grammar is ASCII on purpose. It leaves no Unicode normalization or
case-mapping difference between filesystems (NFC and NFD forms, the Kelvin
sign, ignorable code points) through which two names could open one file, and
it makes ASCII case folding the complete fold.

A refused name gets the most specific of these codes that applies:

| Shape | Examples | Code |
| --- | --- | --- |
| Longer than 255 bytes, or a segment over 63 | | `archive.name_too_long` |
| Absolute, drive or UNC path | `/etc/passwd`, `\windows`, `C:\x`, `c:x`, `\\server\share`, `\\?\C:\x` | `archive.absolute_path` |
| A `..` segment, with either separator | `../x`, `a/../../x`, `a\..\x` | `archive.entry_outside_root` |
| A colon: an NTFS alternate data stream | `policy.json:stream`, `x::$DATA` | `archive.alternate_data_stream` |
| More than 8 segments | | `archive.path_too_deep` |
| A Windows device name | `CON`, `nul.json`, `a/LPT1/b` | `archive.reserved_name` |
| Anything else outside the grammar | an empty name or segment, `.` and `./a`, a leading `.`, `_` or `-`, a trailing dot, `\`, spaces, control characters and NUL, non-ASCII or non-UTF-8 bytes | `archive.invalid_name` |

A name may not start with `./`, so an archive made with `tar -C dir .` is
refused.

## Uniqueness

Paths are compared after ASCII case folding, segment by segment, including the
parent directories an entry implies. An entry is refused when it:

- names exactly the path an earlier entry named (`archive.duplicate_entry`);
- names a path, or has a parent directory, that differs from an earlier one
  only in letter case, such as `policy.json` after `Policy.json` or
  `Stores/b` after `stores/a` (`archive.case_fold_collision`): on a
  case-insensitive filesystem the second would overwrite or enter the first,
  on a case-sensitive one it would not, so the archive means different things
  on different hosts;
- uses as a file a path an earlier entry used as a directory, or the reverse,
  such as `a` and `a/b` in either order (`archive.path_conflict`).

A directory entry may come before or after the entries inside it, and a parent
directory may be implied by any number of entries.

## Kinds

Only regular files and directories are admitted. A symbolic link, junction or
other reparse point is `archive.symlink_entry`; a hard link is
`archive.hard_link_entry`; a character or block device, FIFO or socket is
`archive.special_entry`; any other header type (sparse files, volume labels,
types a container defines that the adapter does not map) is
`archive.unsupported_entry`.

## Sizes and decompression bombs

Every bound is checked before the data it protects is read or written.

- **Declared sizes.** A file may declare at most 1 GiB, and the files together
  at most 4 GiB, decompressed (`archive.entry_too_large`,
  `archive.total_too_large`). A directory declares no data
  (`archive.directory_has_data`). These are charged when the header is
  admitted, before any data is read.
- **Exact length.** A file's data is copied in 16 KiB chunks and must be
  exactly its declared length. At most one byte past the declared size is
  read, and nothing past it is written (`archive.declared_size_exceeded`);
  data that ends early is `archive.truncated`. So a header cannot under-declare
  an entry to slip past the size bounds.
- **Expansion ratio.** Over a compressed container, the decompressed bytes
  copied from the whole archive may not exceed 100 times the compressed bytes
  the decompressor has read, checked before every chunk is written
  (`archive.expansion_ratio_exceeded`). The first 1 MiB is always allowed, so a
  small, highly compressible entry is not refused. A container that records a
  compressed size per entry has that declared ratio checked when the header is
  admitted, too. The ratio is measured against bytes read, so a decompressor
  that buffers input ahead can delay a refusal by at most 100 times its buffer.
- **Entries.** At most 1,024 entries of every kind (`archive.too_many_entries`).

The bounds above are the defaults (`ArchiveLimits::default()`); a reader may
state tighter ones.

Not covered by these rules, and left to the container adapter: the archive
file's own size; container structure, checksums and end markers
(`archive.malformed`, `archive.truncated`); and container-specific overlaps,
such as zip entries that share compressed data. The total-size bound still
caps what any such overlap can produce. The backup manifest's versions and
per-entry checksums are the backup slice's to verify.

## Codes

| Code | Meaning |
| --- | --- |
| `archive.too_many_entries` | The archive holds more entries than allowed. |
| `archive.name_too_long` | An entry name, or one of its segments, is too long. |
| `archive.path_too_deep` | An entry name has too many segments. |
| `archive.invalid_name` | An entry name is outside the portable grammar. |
| `archive.absolute_path` | An absolute, drive or UNC path. |
| `archive.entry_outside_root` | A `..` segment that would leave the extraction root. |
| `archive.alternate_data_stream` | A colon, which names an NTFS alternate data stream. |
| `archive.reserved_name` | A Windows device name. |
| `archive.duplicate_entry` | Two entries name the same path. |
| `archive.case_fold_collision` | Two paths differ only in letter case. |
| `archive.path_conflict` | One path is used as both a file and a directory. |
| `archive.symlink_entry` | A symbolic link, junction or reparse point. |
| `archive.hard_link_entry` | A hard link. |
| `archive.special_entry` | A device, FIFO or socket. |
| `archive.unsupported_entry` | Any other entry type. |
| `archive.directory_has_data` | A directory entry declares data. |
| `archive.entry_too_large` | One entry declares more than the entry bound. |
| `archive.total_too_large` | The entries together declare more than the total bound. |
| `archive.expansion_ratio_exceeded` | Decompressed data passes the expansion ratio. |
| `archive.declared_size_exceeded` | An entry's data is longer than declared. |
| `archive.truncated` | The archive, or an entry's data, ends early. |
| `archive.malformed` | The container's structure is invalid. |
| `archive.read_failed` | The archive could not be read. |
| `archive.write_failed` | An entry's data could not be written to its destination. |

A published code never changes meaning. ADR-0008 maps an archive integrity
failure to `ggctl` exit code `7`; no command reports these codes yet.
