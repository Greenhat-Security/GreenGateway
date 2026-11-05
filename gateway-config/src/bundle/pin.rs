//! Recomputing a bundle's pins for `ggctl pin` (issue #242; ADR-0008,
//! "Digests").
//!
//! `ggctl pin` is the only command that rewrites manifest digests, and it
//! pins only files that validate. [`pin_bundle`] reads the bundle with the
//! one reader and every check it runs -- the directory and file rules,
//! syntax, document versions, closed documents, references, the published
//! resource schemas, the caller's validators and the deployment profile --
//! except one: each referenced file's digest is recorded instead of compared
//! with its pin. A new manifest is planned only when none of those checks
//! found an error:
//!
//! - each pin that differs from its file's digest is replaced where the
//!   reader found it, digit for digit, so every other byte of the manifest
//!   (comments, member order, quoting and spacing) is kept;
//! - a pin is replaced only when it is written as exactly its 64 digits
//!   between two double or two single quotes, as `ggctl init` writes it. Any
//!   other spelling is refused with `reference.pin_not_rewritable`: a plain
//!   scalar that begins with a digit is outside the YAML subset, and an
//!   escaped digit has no replacement of the same length;
//! - the new manifest and every other file, exactly as read, are read again
//!   from memory with every check, the pins included, and must come back as
//!   the same files. So a plan only ever pins a bundle that reads as valid.
//!
//! Nothing here writes. The caller replaces the manifest, reads the bundle
//! back with [`super::read_bundle`] and holds what it read to
//! [`PinPlan::is_read_back_by`].

use std::{collections::BTreeMap, path::Path};

use super::{
    diagnostic::{BundleDiagnostic, Code, Pointer, Position},
    read_bundle_files, report,
    source::{BundleDirectory, FileName},
    Bundle, FileRole, ManifestSummary, Pins, ReadOptions, RecordedPin, ResourceValidators,
    SourceFile,
};

/// The digits of one pin.
const PIN_DIGITS: usize = 64;

/// What [`pin_bundle`] found.
#[derive(Debug)]
pub struct PinReport {
    /// What the manifest declares, once it was read and is valid.
    pub manifest: Option<ManifestSummary>,
    /// Every problem found. Never `bundle.digest_mismatch`: the pins are what
    /// is being replaced.
    pub diagnostics: Vec<BundleDiagnostic>,
    /// The new manifest, when no check found an error.
    pub plan: Option<PinPlan>,
}

/// One referenced file's pin.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilePin {
    pub role: FileRole,
    pub file: FileName,
    /// The pin the manifest holds.
    pub previous: String,
    /// The SHA-256 of the file's exact bytes as read: the pin the new
    /// manifest holds.
    pub sha256: String,
}

impl FilePin {
    pub fn changed(&self) -> bool {
        self.previous != self.sha256
    }
}

/// A bundle's new manifest, and the bundle it pins.
#[derive(Debug)]
pub struct PinPlan {
    /// The deployment document's pin, then the bundled policy's and tools'.
    pub pins: Vec<FilePin>,
    /// The source digest of the bundle the new manifest makes.
    pub source_digest: String,
    /// The manifest exactly as read.
    original: Vec<u8>,
    /// The new manifest, then every other file exactly as read: the files
    /// the bundle is made of once the manifest is replaced.
    files: Vec<SourceFile>,
}

impl PinPlan {
    /// The manifest's bytes as read, which a caller replacing it expects to
    /// find still in place.
    pub fn original_manifest(&self) -> &[u8] {
        &self.original
    }

    /// The new manifest's bytes: the original with each changed pin's
    /// digits replaced and nothing else.
    pub fn manifest(&self) -> &[u8] {
        self.files
            .iter()
            .find(|file| file.role == FileRole::Manifest)
            .map_or(&[], |file| file.bytes.as_slice())
    }

    /// Whether any pin changes, and so the manifest.
    pub fn changed(&self) -> bool {
        self.manifest() != self.original
    }

    /// Whether `bundle`, read back once the manifest was replaced, is
    /// exactly the bundle this plan pinned: the same files, byte for byte,
    /// and so the same source digest.
    pub fn is_read_back_by<P, T>(&self, bundle: &Bundle<P, T>) -> bool {
        bundle.source_files() == self.files && bundle.source_digest == self.source_digest
    }
}

/// Reads the bundle in the directory `root` as [`super::read_bundle`] does,
/// recording each referenced file's digest instead of comparing it with its
/// pin, and plans the manifest that pins those digests.
pub fn pin_bundle<V: ResourceValidators>(
    root: &Path,
    options: ReadOptions,
    validators: &V,
) -> PinReport {
    let mut pins = Pins::Record(Vec::new());
    let read = report(BundleDirectory::open(root), options, validators, &mut pins);
    let recorded = match pins {
        Pins::Record(recorded) => recorded,
        Pins::Compare => Vec::new(),
    };
    let mut diagnostics = read.diagnostics;
    let plan = read.bundle.and_then(|bundle| {
        plan(
            bundle.files,
            &recorded,
            options,
            validators,
            &mut diagnostics,
        )
    });
    PinReport {
        manifest: read.manifest,
        diagnostics,
        plan,
    }
}

/// The plan for a bundle that passed every check: `files` as the reader
/// read them, the manifest first.
fn plan<V: ResourceValidators>(
    mut files: Vec<SourceFile>,
    recorded: &[RecordedPin],
    options: ReadOptions,
    validators: &V,
    diagnostics: &mut Vec<BundleDiagnostic>,
) -> Option<PinPlan> {
    let manifest = files
        .iter_mut()
        .find(|file| file.role == FileRole::Manifest)?;
    let original = manifest.bytes.clone();
    manifest.bytes = rewrite(&original, recorded, diagnostics)?;

    let in_memory: BTreeMap<FileName, Vec<u8>> = files
        .iter()
        .map(|file| (file.name.clone(), file.bytes.clone()))
        .collect();
    let pinned = read_bundle_files(in_memory, options, validators);
    match pinned.bundle {
        Some(bundle) if bundle.files == files => Some(PinPlan {
            pins: recorded
                .iter()
                .map(|pin| FilePin {
                    role: pin.role,
                    file: pin.reference.file.clone(),
                    previous: pin.reference.sha256.clone(),
                    sha256: pin.sha256.clone(),
                })
                .collect(),
            source_digest: bundle.source_digest,
            original,
            files,
        }),
        _ => {
            // Unreachable while every replaced pin is a quoted run of digits;
            // if it were reached, the bundle is refused with a reason.
            let errors: Vec<_> = pinned
                .diagnostics
                .into_iter()
                .filter(BundleDiagnostic::is_error)
                .collect();
            if errors.is_empty() {
                diagnostics.push(BundleDiagnostic::file(
                    Code::PinNotRewritable,
                    &FileName::manifest(),
                ));
            }
            diagnostics.extend(errors);
            None
        }
    }
}

/// The manifest with every pin that differs from its file's digest replaced
/// in place, or `None` when one cannot be.
fn rewrite(
    manifest: &[u8],
    recorded: &[RecordedPin],
    diagnostics: &mut Vec<BundleDiagnostic>,
) -> Option<Vec<u8>> {
    let mut rewritten = manifest.to_vec();
    let mut refused = false;
    for pin in recorded
        .iter()
        .filter(|pin| pin.reference.sha256 != pin.sha256)
    {
        let position = pin.reference.sha256_position;
        let slot = quoted_digits(manifest, position, &pin.reference.sha256)
            .and_then(|start| rewritten.get_mut(start..start + PIN_DIGITS))
            .filter(|slot| slot.len() == pin.sha256.len());
        match slot {
            Some(slot) => slot.copy_from_slice(pin.sha256.as_bytes()),
            None => {
                refused = true;
                diagnostics.push(BundleDiagnostic::at(
                    Code::PinNotRewritable,
                    &FileName::manifest(),
                    pin_pointer(pin.role),
                    Some(position),
                ));
            }
        }
    }
    (!refused).then_some(rewritten)
}

/// Where the manifest pins a file of `role`.
fn pin_pointer(role: FileRole) -> Pointer {
    let spec = Pointer::root().member("spec");
    let reference = match role {
        FileRole::Deployment => spec.member("deployment"),
        FileRole::Policy => spec.member("resources").member("policy"),
        FileRole::Tools => spec.member("resources").member("tools"),
        // The manifest is never pinned; the pointer is never built for it.
        FileRole::Manifest => spec,
    };
    reference.member("sha256")
}

/// The byte offset of the digits of the scalar that starts at `position`
/// (1-based line, and column in characters, as the YAML reader counts them),
/// when that scalar is written as exactly `digits` between two double or two
/// single quotes. Inside quotes with no escape, the written digits are the
/// value the reader decoded, so replacing them changes that value and
/// nothing else.
fn quoted_digits(manifest: &[u8], position: Position, digits: &str) -> Option<usize> {
    let line_index = usize::try_from(position.line).ok()?.checked_sub(1)?;
    let column = usize::try_from(position.column).ok()?.checked_sub(1)?;
    let mut line_start = 0;
    for _ in 0..line_index {
        let rest = manifest.get(line_start..)?;
        line_start += rest.iter().position(|byte| *byte == b'\n')? + 1;
    }
    let rest = manifest.get(line_start..)?;
    let line = rest.split(|byte| *byte == b'\n').next()?;
    let line = std::str::from_utf8(line).ok()?;
    let (offset, _) = line.char_indices().nth(column)?;
    let scalar = line.as_bytes().get(offset..)?;
    let quote = *scalar.first()?;
    let written = scalar.get(1..=digits.len())?;
    let closing = *scalar.get(digits.len() + 1)?;
    (matches!(quote, b'"' | b'\'') && closing == quote && written == digits.as_bytes())
        .then_some(line_start + offset + 1)
}

#[cfg(test)]
mod tests;
