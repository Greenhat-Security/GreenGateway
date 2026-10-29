//! `ggctl convert BUNDLE --to VERSION (--output DIR | --in-place) [--strict]
//! [--format human|json]` (issue #242 PR 6; ADR-0008, "Compatibility and
//! versions").
//!
//! The bundle is read as `ggctl validate` reads it, and only a bundle the
//! reader accepts is converted, by `gateway_config::bundle::convert`: step
//! by step from its own document version up to `--to`, never down, and not
//! at all when it is already there. `--output` writes the result as a new
//! bundle the way `ggctl init` does, read back before it is placed.
//! `--in-place` leaves `BUNDLE` where it is; it never needs to write today,
//! because `v1alpha1` is the only version, and a conversion that would
//! change the bundle is refused in place until an atomic in-place writer
//! exists. `--to` is never echoed unless it names a version this `ggctl`
//! implements.

use std::{
    io::{self, Write},
    path::Path,
};

use gateway_config::bundle::convert::{self, Refusal};
use serde::Serialize;

use crate::{
    cli::Invocation,
    diagnostic::{Code, Diagnostic, Exit},
    output::{self, WriteError},
    report::{self, Format, Io},
    validate::{self, BundleRecord},
};

/// The `convert` result.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ConvertResult {
    /// The reader accepted `BUNDLE`, so it could be converted.
    valid: bool,
    /// `BUNDLE`, once its manifest was read.
    #[serde(skip_serializing_if = "Option::is_none")]
    bundle: Option<BundleRecord>,
    /// The bundle's document version, once it was read.
    #[serde(skip_serializing_if = "Option::is_none")]
    from: Option<&'static str>,
    /// The version converted to, once the conversion was planned.
    #[serde(skip_serializing_if = "Option::is_none")]
    to: Option<&'static str>,
    /// A conversion step ran, so the files differ from `BUNDLE`'s.
    changed: bool,
    /// The converted bundle is at the `--output` directory.
    written: bool,
    /// The written bundle as the reader read it back.
    #[serde(skip_serializing_if = "Option::is_none")]
    converted: Option<BundleRecord>,
    /// `--in-place` was given. Only the human result uses it; a report says
    /// so through `written`.
    #[serde(skip)]
    in_place: bool,
}

pub(crate) fn run(invocation: &Invocation, io: &mut Io<'_>) -> Exit {
    let output = invocation.value("--output");
    let in_place = invocation.flag("--in-place");
    if let (Some(_), Some(position)) = (output, in_place) {
        return report::error(io, Diagnostic::at(Code::ConflictingOptions, position));
    }
    let (Some((to_position, target)), true) = (
        invocation.text("--to"),
        output.is_some() || in_place.is_some(),
    ) else {
        return report::error(io, Diagnostic::new(Code::MissingArgument));
    };
    let Some(read) = validate::read(invocation, invocation.flag("--strict").is_some()) else {
        return report::error(io, Diagnostic::new(Code::MissingArgument));
    };
    let mut diagnostics = validate::diagnostics(&read);
    if validate::supplies_a_resource(&read) {
        diagnostics.push(Diagnostic::new(Code::ProductionValidatorsNotRun).into());
    }
    let mut result = ConvertResult {
        valid: read.bundle.is_some(),
        bundle: BundleRecord::of(&read),
        from: read
            .bundle
            .as_ref()
            .map(|bundle| bundle.api_version.as_str()),
        to: None,
        changed: false,
        written: false,
        converted: None,
        in_place: in_place.is_some(),
    };
    if let Some(bundle) = &read.bundle {
        match convert::convert(bundle, target) {
            Err(Refusal::UnsupportedVersion) => {
                diagnostics
                    .push(Diagnostic::at(Code::UnsupportedTargetVersion, to_position).into());
            }
            Err(Refusal::Downgrade) => {
                diagnostics.push(Diagnostic::at(Code::DowngradeRefused, to_position).into());
            }
            Ok(conversion) => {
                result.to = Some(conversion.to.as_str());
                result.changed = conversion.changed();
                match (output, in_place) {
                    (Some((position, directory)), _) => {
                        match output::write_new_bundle(Path::new(directory), &conversion.files) {
                            Ok(written) => {
                                result.written = true;
                                result.converted = BundleRecord::of(&written);
                            }
                            Err(error) => {
                                if let WriteError::Invalid(read) = &error {
                                    diagnostics.extend(validate::diagnostics(read));
                                }
                                diagnostics.push(Diagnostic::at(error.code(), position).into());
                            }
                        }
                    }
                    (None, Some(position)) if conversion.changed() => {
                        diagnostics.push(Diagnostic::at(Code::InPlaceUnavailable, position).into());
                    }
                    (None, _) => {}
                }
            }
        }
    }
    report::finish_report(
        io,
        Format::of(invocation),
        "convert",
        &result,
        &diagnostics,
        human,
    )
}

fn human(result: &ConvertResult, out: &mut dyn Write) -> io::Result<()> {
    let title = result
        .bundle
        .as_ref()
        .map_or_else(|| "bundle".to_owned(), BundleRecord::title);
    match (result.from, result.to) {
        (Some(from), Some(to)) if result.written => {
            write!(
                out,
                "{title}: converted from {from} to {to}, written to the --output directory"
            )?;
            if result.changed {
                writeln!(out)
            } else {
                writeln!(out, " with its files unchanged (it was already at {to})")
            }
        }
        (Some(_), Some(to)) if result.in_place && !result.changed => {
            writeln!(out, "{title}: already at {to}; nothing to convert")
        }
        _ => writeln!(out, "{title}: not converted"),
    }
}

#[cfg(test)]
mod tests;
