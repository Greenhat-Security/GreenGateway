//! `ggctl pin BUNDLE [--strict] [--format human|json]` (issue #242;
//! ADR-0008, "Digests").
//!
//! The only command that rewrites manifest digests, and it pins only files
//! that validate. The bundle is read by the shared reader in its pin mode
//! (`gateway_config::bundle::pin`): every check `ggctl validate` runs, except
//! that each referenced file's digest is recorded instead of compared with
//! its pin. Nothing is written unless every check passed. Then only the
//! digits of each pin that changed are replaced, so every other byte of
//! `bundle.yaml` is kept, and the new manifest replaces the old one
//! atomically ([`output::replace_manifest`]). Finally the bundle is read
//! back with every check, its pins included, and must be exactly the bundle
//! that was pinned; the report gives its new source digest. Nothing else is
//! written, no network request is made and no environment variable is read.
//!
//! As for `validate`, the bundled policy and tools documents are held to the
//! production validators, both before pinning and on the read back.

use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

use gateway_config::bundle::{self, pin::FilePin, ProductionValidators, ReadOptions};
use serde::Serialize;

use crate::{
    cli::Invocation,
    diagnostic::{Code, Diagnostic, Exit},
    output::{self, Rename},
    report::{self, Format, Io, ReportDiagnostic},
    validate::BundleRecord,
};

/// The `pin` result.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PinResult {
    /// Every check but the pin comparison passed, so the bundle could be
    /// pinned.
    valid: bool,
    /// `BUNDLE` as its manifest declares it, once the manifest was read: no
    /// digest or profile, since its pins are what is being replaced.
    #[serde(skip_serializing_if = "Option::is_none")]
    bundle: Option<BundleRecord>,
    /// Each referenced file's pin, once the bundle could be pinned.
    files: Vec<PinRecord>,
    /// A pin changed, so `bundle.yaml` had to be rewritten.
    changed: bool,
    /// The new `bundle.yaml` is in place.
    written: bool,
    /// The bundle as the reader read it back, once it was exactly the bundle
    /// pinned: with its new source digest.
    #[serde(skip_serializing_if = "Option::is_none")]
    pinned: Option<BundleRecord>,
}

/// One referenced file's pin. File names and digests only.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PinRecord {
    /// `deployment`, `policy` or `tools`.
    role: &'static str,
    file: String,
    /// The pin the manifest held.
    previous: String,
    /// The SHA-256 of the file's exact bytes, which the manifest now pins.
    sha256: String,
    changed: bool,
}

impl PinRecord {
    fn of(pin: &FilePin) -> Self {
        Self {
            role: pin.role.as_str(),
            file: pin.file.as_str().to_owned(),
            previous: pin.previous.clone(),
            sha256: pin.sha256.clone(),
            changed: pin.changed(),
        }
    }
}

pub(crate) fn run(invocation: &Invocation, io: &mut Io<'_>) -> Exit {
    execute(invocation, io, output::rename)
}

/// [`run`] with the rename that puts the new manifest in place, which tests
/// replace to interrupt the write.
fn execute(invocation: &Invocation, io: &mut Io<'_>, rename: Rename) -> Exit {
    let Some((_, path)) = invocation.positional(0) else {
        return report::error(io, Diagnostic::new(Code::MissingArgument));
    };
    let options = ReadOptions {
        strict: invocation.flag("--strict").is_some(),
    };
    // One resolution of the root for the read, the write and the read back.
    // A root that does not resolve is left to the reader to report.
    let root = fs::canonicalize(path).unwrap_or_else(|_| PathBuf::from(path));
    let (result, diagnostics) = pin(&root, options, rename);
    report::finish_report(
        io,
        Format::of(invocation),
        "pin",
        &result,
        &diagnostics,
        human,
    )
}

fn pin(root: &Path, options: ReadOptions, rename: Rename) -> (PinResult, Vec<ReportDiagnostic>) {
    let mut result = PinResult {
        valid: false,
        bundle: None,
        files: Vec::new(),
        changed: false,
        written: false,
        pinned: None,
    };
    let mut diagnostics: Vec<ReportDiagnostic> = Vec::new();
    // A linked manifest, such as a Kubernetes atomic-writer volume's, is
    // refused before anything is read: pin never replaces one.
    if let Err(error) = output::check_manifest_entry(root) {
        diagnostics.push(Diagnostic::new(error.code()).into());
        return (result, diagnostics);
    }

    let planned = bundle::pin::pin_bundle(root, options, &ProductionValidators);
    diagnostics.extend(planned.diagnostics.into_iter().map(ReportDiagnostic::from));
    if let Some(manifest) = &planned.manifest {
        result.bundle = Some(BundleRecord::declared(manifest));
    }
    let Some(plan) = planned.plan else {
        return (result, diagnostics);
    };
    result.valid = true;
    result.files = plan.pins.iter().map(PinRecord::of).collect();
    result.changed = plan.changed();

    if plan.changed() {
        match output::replace_manifest(root, plan.original_manifest(), plan.manifest(), rename) {
            Ok(()) => result.written = true,
            Err(error) => {
                diagnostics.push(Diagnostic::new(error.code()).into());
                return (result, diagnostics);
            }
        }
    }

    // Read back with every check, the pins included, as the gateway would
    // read it: it must be exactly the bundle that was pinned.
    let read = bundle::read_bundle(root, options, &ProductionValidators);
    match &read.bundle {
        Some(read_back) if plan.is_read_back_by(read_back) => {
            result.pinned = BundleRecord::of(&read);
        }
        _ => {
            diagnostics.extend(
                read.diagnostics
                    .iter()
                    .filter(|diagnostic| diagnostic.is_error())
                    .cloned()
                    .map(ReportDiagnostic::from),
            );
            diagnostics.push(Diagnostic::new(Code::ReadBackFailed).into());
        }
    }
    (result, diagnostics)
}

fn human(result: &PinResult, out: &mut dyn Write) -> io::Result<()> {
    let title = result
        .bundle
        .as_ref()
        .map_or_else(|| "bundle".to_owned(), BundleRecord::title);
    let changed = result.files.iter().filter(|file| file.changed).count();
    let pins = if changed == 1 { "pin" } else { "pins" };
    match (&result.pinned, result.written) {
        (Some(_), true) => writeln!(
            out,
            "{title}: pinned, {changed} {pins} changed and bundle.yaml rewritten"
        )?,
        (Some(_), false) => writeln!(
            out,
            "{title}: pinned, every pin already matched and nothing was written"
        )?,
        (None, true) => writeln!(
            out,
            "{title}: bundle.yaml rewritten, but the bundle did not read back as pinned"
        )?,
        (None, false) => writeln!(out, "{title}: not pinned, nothing was written")?,
    }
    if let Some(digest) = result.pinned.as_ref().and_then(BundleRecord::source_digest) {
        writeln!(out, "  source digest  {digest}")?;
    }
    for file in &result.files {
        let state = if file.changed {
            "pin changed"
        } else {
            "pin unchanged"
        };
        writeln!(out, "  {:<13}  {} ({state})", file.role, file.file)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
