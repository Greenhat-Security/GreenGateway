//! `ggctl init --profile PROFILE --output DIR [--answers FILE]
//! [--format human|json]` (issue #242 PR 6; ADR-0008, "Initialization
//! profiles" and "Bootstrap model").
//!
//! The bundle comes from `gateway_config::bundle::init`, the generator the
//! gateway's own tests hold to its production validators, and is written by
//! [`output::write_new_bundle`]: into a new staging directory, read back with
//! the bundle reader, and only then renamed into place. Without `--answers`
//! the defaults are used; `ggctl` never prompts. The answers file is read
//! like a trust anchor (a regular file of at most 64 KiB that no other
//! account can change on Unix), because it decides which issuer the operator
//! role trusts. Nothing written holds a secret, nothing is started or
//! deployed, and no network request is made. The browser wizard
//! (`init --web`) is a later #242 slice.

use std::{
    io::{self, Write},
    path::Path,
};

use gateway_config::bundle::{
    init::{self, Answers, AnswersSyntax},
    Profile,
};
use serde::Serialize;

use crate::{
    cli::Invocation,
    credential::{self, FilePermissions, FileProblem},
    diagnostic::{Code, Diagnostic, Exit},
    output::{self, WriteError},
    report::{self, Format, Io, ReportDiagnostic},
    validate::{self, BundleRecord},
};

/// The `init` result.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct InitResult {
    /// The bundle is at the `--output` directory.
    created: bool,
    profile: &'static str,
    /// Present once the answers were read.
    #[serde(skip_serializing_if = "Option::is_none")]
    topology: Option<&'static str>,
    /// Whether the policy holds the generated operator role.
    #[serde(skip_serializing_if = "Option::is_none")]
    operator: Option<bool>,
    /// The bundle as the reader read it back, once it was written.
    #[serde(skip_serializing_if = "Option::is_none")]
    bundle: Option<BundleRecord>,
}

pub(crate) fn run(invocation: &Invocation, io: &mut Io<'_>) -> Exit {
    let (Some((_, profile)), Some((output_position, output))) =
        (invocation.text("--profile"), invocation.value("--output"))
    else {
        return report::error(io, Diagnostic::new(Code::MissingArgument));
    };
    // The parser accepted only a profile name.
    let Some(profile) = Profile::ALL
        .iter()
        .copied()
        .find(|candidate| candidate.as_str() == profile)
    else {
        return report::error(io, Diagnostic::new(Code::InvalidValue));
    };
    let mut diagnostics = Vec::new();
    let answers = match invocation.value("--answers") {
        None => Some(Answers::default()),
        Some((position, path)) => read_answers(Path::new(path), position, &mut diagnostics),
    };
    let mut result = InitResult {
        created: false,
        profile: profile.as_str(),
        topology: answers.as_ref().map(|answers| answers.topology().as_str()),
        operator: answers.as_ref().map(|answers| answers.operator().is_some()),
        bundle: None,
    };
    if let Some(answers) = &answers {
        let files = init::scaffold(profile, answers);
        match output::write_new_bundle(Path::new(output), &files) {
            Ok(read) => {
                result.created = true;
                result.bundle = BundleRecord::of(&read);
                if validate::supplies_a_resource(&read) {
                    diagnostics.push(Diagnostic::new(Code::ProductionValidatorsNotRun).into());
                }
            }
            Err(error) => {
                if let WriteError::Invalid(read) = &error {
                    diagnostics.extend(validate::diagnostics(read));
                }
                diagnostics.push(Diagnostic::at(error.code(), output_position).into());
            }
        }
    }
    report::finish_report(
        io,
        Format::of(invocation),
        "init",
        &result,
        &diagnostics,
        human,
    )
}

fn human(result: &InitResult, out: &mut dyn Write) -> io::Result<()> {
    let Some(bundle) = result.bundle.as_ref().filter(|_| result.created) else {
        return writeln!(out, "init: no bundle was written");
    };
    writeln!(
        out,
        "created {}, {} topology",
        bundle.title(),
        result.topology.unwrap_or_default()
    )?;
    bundle.write_details(out)?;
    if result.operator == Some(true) {
        writeln!(
            out,
            "  operator role  bound to the answers' issuer: admin:config:read, admin:status:read"
        )?;
    }
    writeln!(
        out,
        "next: review the files, then run `ggctl validate --strict` on the --output directory"
    )
}

/// Reads the answers file the argument at `argument` names; diagnostics are
/// located by that argument, because a path is never echoed.
fn read_answers(
    path: &Path,
    argument: usize,
    diagnostics: &mut Vec<ReportDiagnostic>,
) -> Option<Answers> {
    let bytes = match credential::read_regular_file(
        path,
        init::MAX_ANSWERS_BYTES,
        FilePermissions::NotWritableByOthers,
    ) {
        Ok(bytes) => bytes,
        Err(problem) => {
            let code = match problem {
                FileProblem::Unreadable => Code::AnswersUnreadable,
                FileProblem::NotRegularFile => Code::AnswersNotRegularFile,
                FileProblem::TooLarge => Code::AnswersTooLarge,
                FileProblem::UnsafePermissions => Code::AnswersUnsafePermissions,
            };
            diagnostics.push(Diagnostic::at(code, argument).into());
            return None;
        }
    };
    let syntax = if path
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("json"))
    {
        AnswersSyntax::Json
    } else {
        AnswersSyntax::Yaml
    };
    match init::read_answers(&bytes, syntax) {
        Ok(answers) => Some(answers),
        Err(found) => {
            diagnostics.extend(
                found
                    .into_iter()
                    .map(|diagnostic| ReportDiagnostic::Document {
                        argument,
                        diagnostic,
                    }),
            );
            None
        }
    }
}

#[cfg(test)]
mod tests;
