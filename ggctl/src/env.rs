//! `--env FILE` and `--against-env FILE`: an environment file read as data
//! (ADR-0008, "`ggctl`").
//!
//! A deployment that stays in environment mode gets the same offline
//! validation, doctor and diff as a bundle. The file is read like the other
//! local files `ggctl` reads (`credential::read_regular_file`): a regular
//! file, a symbolic link to one followed, of at most
//! [`MAX_ENV_FILE_BYTES`], opened without blocking and, on Unix, not
//! writable by group or other, as the bundle reader requires of a bundle
//! file. It must be UTF-8. It is
//! then parsed with the grammar `gateway import-standalone` reads
//! (`gateway_config::env_file`) and compiled by the gateway's own compiler
//! through a reader that answers from the file alone: `ggctl` never reads
//! the process environment for it, and never runs or sources the file.
//!
//! Every finding is an [`EnvDiagnostic`]: a code, the position of the option
//! naming the file, the line where there is one, and at most an inventoried
//! setting and a compiler rule. A value, a key outside the compiler's
//! inventory and the file's path are never reported, so a secret in the
//! file cannot reach a report.

use std::{
    ffi::OsStr,
    io::{self, Write},
    path::Path,
};

use gateway_config::{
    compiler::{
        diagnostic::{ConfigDiagnostic, ConfigDiagnosticCode},
        ConfigError, ConfigPlan,
    },
    env_file::{EnvFile, MAX_ENV_FILE_BYTES},
};
use serde::Serialize;

use crate::{
    cli::Invocation,
    credential::{self, FilePermissions, FileProblem},
    diagnostic::{Code, Diagnostic, Exit},
    report::{EnvDiagnostic, ReportDiagnostic},
};

const HINT_DUPLICATE: &str = "keep one assignment of each key";
const HINT_ONE_SOURCE: &str = "give a bundle directory or an environment file, not both";
const HINT_SOURCE: &str = "give a bundle directory, or an environment file with --env";
const HINT_BASE: &str =
    "name the bundle directory to compare with in --against, or an environment file in --against-env";

/// What a command reads: a bundle directory, or an environment file named
/// by an option at a position.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Source<'a> {
    Bundle(&'a OsStr),
    Env { argument: usize, path: &'a OsStr },
}

/// The one source a command was given: a bundle directory (the `BUNDLE`
/// argument, or `--against`) or `option`'s environment file (`--env` or
/// `--against-env`), never both and never neither.
pub(crate) fn source<'a>(
    invocation: &'a Invocation,
    bundle: Option<&'a OsStr>,
    option: &str,
) -> Result<Source<'a>, Diagnostic> {
    match (bundle, invocation.value(option)) {
        (Some(_), Some((argument, _))) => {
            Err(Diagnostic::at(Code::ConflictingOptions, argument).with_hint(HINT_ONE_SOURCE))
        }
        (Some(bundle), None) => Ok(Source::Bundle(bundle)),
        (None, Some((argument, path))) => Ok(Source::Env { argument, path }),
        (None, None) => Err(
            Diagnostic::new(Code::MissingArgument).with_hint(if option == "--env" {
                HINT_SOURCE
            } else {
                HINT_BASE
            }),
        ),
    }
}

/// An environment file as far as `ggctl` could read, parse and compile it.
///
/// Deliberately not `Debug`: a `ConfigError`'s problems may quote a value.
pub(crate) struct EnvRead {
    /// The parsed file, once it was read and decoded.
    pub(crate) file: Option<EnvFile>,
    /// What the compiler made of it, once parsed.
    pub(crate) compiled: Option<Result<ConfigPlan, ConfigError>>,
    /// Every finding, in file order: the file and its lines, then the
    /// compiler's, in the order the compiler reports them.
    pub(crate) diagnostics: Vec<ReportDiagnostic>,
}

impl EnvRead {
    /// Whether the file is a valid environment configuration: it was read,
    /// every line is blank, a comment or an assignment, no key is assigned
    /// twice under `--strict`, and the compiler accepted what it sets.
    pub(crate) fn valid(&self) -> bool {
        self.plan().is_some()
    }

    /// The compiled plan, when the file is valid.
    pub(crate) fn plan(&self) -> Option<&ConfigPlan> {
        let clean = self
            .diagnostics
            .iter()
            .all(|diagnostic| diagnostic.exit() == Exit::Success);
        match &self.compiled {
            Some(Ok(plan)) if clean => Some(plan),
            _ => None,
        }
    }

    /// What a report says about the file, once it was parsed.
    pub(crate) fn record(&self) -> Option<EnvRecord> {
        let file = self.file.as_ref()?;
        let settings = file.settings();
        Some(EnvRecord {
            other_variables: file.len() - settings.len(),
            settings,
            duplicate_keys: file.duplicate_keys().len(),
        })
    }
}

/// Reads, parses and compiles the environment file at `path`, which the
/// option at position `argument` names. Under `strict` a repeated key is an
/// error; otherwise it is a warning.
pub(crate) fn read(argument: usize, path: &OsStr, strict: bool) -> EnvRead {
    let mut diagnostics: Vec<ReportDiagnostic> = Vec::new();
    let bytes = match credential::read_regular_file(
        Path::new(path),
        MAX_ENV_FILE_BYTES,
        FilePermissions::NotWritableByOthers,
    ) {
        Ok(bytes) => bytes,
        Err(problem) => {
            let code = match problem {
                FileProblem::Unreadable => Code::EnvUnreadable,
                FileProblem::NotRegularFile => Code::EnvNotRegularFile,
                FileProblem::TooLarge => Code::EnvTooLarge,
                FileProblem::UnsafePermissions => Code::EnvUnsafePermissions,
            };
            diagnostics.push(EnvDiagnostic::new(code, argument, None).into());
            return EnvRead {
                file: None,
                compiled: None,
                diagnostics,
            };
        }
    };
    let Ok(text) = std::str::from_utf8(&bytes) else {
        diagnostics.push(EnvDiagnostic::new(Code::EnvNotUtf8, argument, None).into());
        return EnvRead {
            file: None,
            compiled: None,
            diagnostics,
        };
    };
    let file = EnvFile::parse(text);
    for line in file.malformed_lines() {
        diagnostics.push(EnvDiagnostic::new(Code::EnvMalformedLine, argument, Some(*line)).into());
    }
    for duplicate in file.duplicate_keys() {
        diagnostics.push(
            EnvDiagnostic {
                field: duplicate.setting,
                warning: !strict,
                hint: Some(HINT_DUPLICATE),
                ..EnvDiagnostic::new(Code::EnvDuplicateKey, argument, Some(duplicate.line))
            }
            .into(),
        );
    }
    let compiled = file.compile();
    if let Err(error) = &compiled {
        diagnostics.extend(
            error
                .diagnostics()
                .iter()
                .map(|diagnostic| compiler_diagnostic(diagnostic, &file, argument).into()),
        );
    }
    EnvRead {
        file: Some(file),
        compiled: Some(compiled),
        diagnostics,
    }
}

/// One compiler finding, located at the line that sets its setting. Only the
/// setting's inventory name, the code and the rule are carried over: the
/// problem's own text, which may quote a value, is never read.
fn compiler_diagnostic(
    diagnostic: &ConfigDiagnostic,
    file: &EnvFile,
    argument: usize,
) -> EnvDiagnostic {
    let code = match diagnostic.code {
        ConfigDiagnosticCode::Unset => Code::ConfigUnset,
        ConfigDiagnosticCode::Empty => Code::ConfigEmpty,
        ConfigDiagnosticCode::NotUnicode => Code::ConfigNotUnicode,
        ConfigDiagnosticCode::Refused => Code::ConfigRefused,
        ConfigDiagnosticCode::Unattributed => Code::ConfigUnattributed,
    };
    EnvDiagnostic {
        field: diagnostic.variable,
        rule: Some(diagnostic.rule),
        ..EnvDiagnostic::new(
            code,
            argument,
            diagnostic.variable.and_then(|variable| file.line(variable)),
        )
    }
}

/// What a report says about an environment file: the names of the
/// inventoried settings it sets and how many other keys it sets, which are
/// never named because such a key could be anything.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EnvRecord {
    /// The gateway settings the file assigns, in the order the compiler
    /// reads them.
    settings: Vec<&'static str>,
    /// How many other keys it assigns.
    other_variables: usize,
    /// How many assignments repeat a key an earlier line assigned.
    duplicate_keys: usize,
}

impl EnvRecord {
    /// The indented detail lines of the human form.
    pub(crate) fn write_details(&self, out: &mut dyn Write) -> io::Result<()> {
        writeln!(out, "  settings       {} set", self.settings.len())?;
        if self.other_variables > 0 {
            writeln!(
                out,
                "  other keys     {} (not gateway settings, never named)",
                self.other_variables
            )?;
        }
        if self.duplicate_keys > 0 {
            writeln!(out, "  repeated keys  {}", self.duplicate_keys)?;
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests;
