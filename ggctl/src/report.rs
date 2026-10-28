//! The output contract (ADR-0008, "Output contract").
//!
//! - Standard output carries only what was asked for: an artifact (a schema,
//!   a completion script, help), the human result, with `--format json`
//!   exactly one `GgctlReport` document, or with `validate --format sarif`
//!   exactly one SARIF 2.1.0 log.
//! - Diagnostics go to standard error in human form. With `--format json` or
//!   `--format sarif` they are in the document instead, and standard error
//!   stays empty.
//! - An argument error found before a command runs is reported on standard
//!   error only, with exit code 2, and no report is written: the requested
//!   format is not known to be trustworthy yet.
//! - No color, no prompt, no progress output.

use std::{
    fmt,
    io::{self, Read, Write},
};

use gateway_config::{
    bundle::{self, BundleDiagnostic},
    documents::{API_VERSION_V1ALPHA1, REPORT_KIND},
};
use serde::Serialize;

use crate::{
    cli::{Invocation, FORMAT_JSON, FORMAT_SARIF},
    diagnostic::{Code, Diagnostic, Exit},
    sarif,
};

/// Where `docs/configuration-bundles.md` explains every bundle reader code.
pub(crate) const BUNDLE_REMEDIATION: &str = "docs/configuration-bundles.md#diagnostics";

/// The process's standard streams.
pub(crate) struct Io<'a> {
    pub(crate) stdout: &'a mut dyn Write,
    pub(crate) stderr: &'a mut dyn Write,
    pub(crate) stdin: &'a mut dyn Read,
    pub(crate) stdin_is_terminal: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Format {
    Human,
    Json,
    /// SARIF 2.1.0: `validate` is the only command whose `--format` offers it.
    Sarif,
}

impl Format {
    pub(crate) fn of(invocation: &Invocation) -> Self {
        match invocation.text("--format") {
            Some((_, FORMAT_JSON)) => Self::Json,
            Some((_, FORMAT_SARIF)) => Self::Sarif,
            _ => Self::Human,
        }
    }
}

/// One diagnostic of a report: `ggctl`'s own, or one the shared bundle
/// reader found. Both are value-free by construction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ReportDiagnostic {
    Ggctl(Diagnostic),
    Bundle(BundleDiagnostic),
}

impl ReportDiagnostic {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::Ggctl(diagnostic) => diagnostic.code.as_str(),
            Self::Bundle(diagnostic) => diagnostic.code.as_str(),
        }
    }

    pub(crate) fn severity(&self) -> &'static str {
        match self {
            Self::Ggctl(diagnostic) => diagnostic.severity(),
            Self::Bundle(diagnostic) => diagnostic.severity.as_str(),
        }
    }

    pub(crate) fn message(&self) -> &'static str {
        match self {
            Self::Ggctl(diagnostic) => diagnostic.code.message(),
            Self::Bundle(diagnostic) => diagnostic.code.message(),
        }
    }

    pub(crate) fn hint(&self) -> Option<&'static str> {
        match self {
            Self::Ggctl(diagnostic) => diagnostic.hint,
            Self::Bundle(_) => None,
        }
    }

    pub(crate) fn remediation(&self) -> &'static str {
        match self {
            Self::Ggctl(diagnostic) => diagnostic.code.remediation(),
            Self::Bundle(_) => BUNDLE_REMEDIATION,
        }
    }

    /// The exit code this diagnostic produces on its own.
    pub(crate) fn exit(&self) -> Exit {
        match self {
            Self::Ggctl(diagnostic) => diagnostic.code.exit(),
            Self::Bundle(diagnostic) => bundle_exit(diagnostic),
        }
    }

    pub(crate) fn location(&self) -> Option<LocationRecord> {
        match self {
            Self::Ggctl(diagnostic) => diagnostic
                .argument
                .map(|argument| LocationRecord::Argument { argument }),
            Self::Bundle(diagnostic) => diagnostic.file.as_ref().map(|file| LocationRecord::File {
                file: file.as_str().to_owned(),
                pointer: diagnostic.pointer.to_string(),
                line: diagnostic.position.map(|position| position.line),
                column: diagnostic.position.map(|position| position.column),
            }),
        }
    }
}

/// The exit code a bundle reader diagnostic produces on its own.
fn bundle_exit(diagnostic: &BundleDiagnostic) -> Exit {
    if !diagnostic.is_error() {
        return Exit::Success;
    }
    match diagnostic.code {
        // The bundle could not be examined: an I/O failure, not a verdict on
        // its content.
        bundle::Code::RootUnavailable
        | bundle::Code::ReadFailed
        | bundle::Code::ChangedDuringRead => Exit::Failure,
        _ => Exit::Invalid,
    }
}

impl From<Diagnostic> for ReportDiagnostic {
    fn from(diagnostic: Diagnostic) -> Self {
        Self::Ggctl(diagnostic)
    }
}

impl From<BundleDiagnostic> for ReportDiagnostic {
    fn from(diagnostic: BundleDiagnostic) -> Self {
        Self::Bundle(diagnostic)
    }
}

/// The human form written to standard error.
impl fmt::Display for ReportDiagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let diagnostic = match self {
            Self::Ggctl(diagnostic) => return diagnostic.fmt(formatter),
            Self::Bundle(diagnostic) => diagnostic,
        };
        write!(
            formatter,
            "ggctl: {}: {}: {}",
            self.severity(),
            self.code(),
            self.message()
        )?;
        if let Some(file) = &diagnostic.file {
            write!(formatter, "\n  at: {}", file.as_str())?;
            if let Some(position) = diagnostic.position {
                write!(formatter, ":{}:{}", position.line, position.column)?;
            }
            if !diagnostic.pointer.is_root() {
                write!(formatter, " {}", diagnostic.pointer)?;
            }
        }
        write!(formatter, "\n  see: {}", self.remediation())
    }
}

/// The `GgctlReport` document.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Report<'a, T: Serialize> {
    api_version: &'static str,
    kind: &'static str,
    command: &'static str,
    exit_code: u8,
    outcome: &'static str,
    diagnostics: Vec<DiagnosticRecord>,
    result: &'a T,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DiagnosticRecord {
    code: &'static str,
    severity: &'static str,
    message: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    hint: Option<&'static str>,
    remediation: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    location: Option<LocationRecord>,
}

/// What a diagnostic is about.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub(crate) enum LocationRecord {
    /// The 1-based position of the command-line argument.
    Argument { argument: usize },
    /// A place in one bundle file: its bundle-relative name, a JSON Pointer
    /// built from member names the reader defines, and the 1-based line and
    /// column where the reader has them.
    File {
        file: String,
        pointer: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        line: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        column: Option<u32>,
    },
}

impl From<&ReportDiagnostic> for DiagnosticRecord {
    fn from(diagnostic: &ReportDiagnostic) -> Self {
        Self {
            code: diagnostic.code(),
            severity: diagnostic.severity(),
            message: diagnostic.message(),
            hint: diagnostic.hint(),
            remediation: diagnostic.remediation(),
            location: diagnostic.location(),
        }
    }
}

/// Writes a command's result and diagnostics in the requested format and
/// returns the exit code they determine.
pub(crate) fn finish<T: Serialize>(
    io: &mut Io<'_>,
    format: Format,
    command: &'static str,
    result: &T,
    diagnostics: &[Diagnostic],
    human: impl FnOnce(&T, &mut dyn Write) -> io::Result<()>,
) -> Exit {
    let diagnostics: Vec<_> = diagnostics
        .iter()
        .copied()
        .map(ReportDiagnostic::Ggctl)
        .collect();
    finish_report(io, format, command, result, &diagnostics, human)
}

/// [`finish`] for a command whose diagnostics include the bundle reader's.
/// With `--format sarif` the log carries the diagnostics only.
pub(crate) fn finish_report<T: Serialize>(
    io: &mut Io<'_>,
    format: Format,
    command: &'static str,
    result: &T,
    diagnostics: &[ReportDiagnostic],
    human: impl FnOnce(&T, &mut dyn Write) -> io::Result<()>,
) -> Exit {
    let exit = Exit::worst(diagnostics.iter().map(ReportDiagnostic::exit));
    let written = match format {
        Format::Json => {
            let report = Report {
                api_version: API_VERSION_V1ALPHA1,
                kind: REPORT_KIND,
                command,
                exit_code: exit.code(),
                outcome: exit.name(),
                diagnostics: diagnostics.iter().map(DiagnosticRecord::from).collect(),
                result,
            };
            serde_json::to_writer_pretty(&mut *io.stdout, &report)
                .map_err(io::Error::from)
                .and_then(|()| writeln!(io.stdout))
                .and_then(|()| io.stdout.flush())
        }
        Format::Sarif => serde_json::to_writer_pretty(&mut *io.stdout, &sarif::log(diagnostics))
            .map_err(io::Error::from)
            .and_then(|()| writeln!(io.stdout))
            .and_then(|()| io.stdout.flush()),
        Format::Human => human(result, io.stdout)
            .and_then(|()| io.stdout.flush())
            .and_then(|()| write_diagnostics(io.stderr, diagnostics)),
    };
    match written {
        Ok(()) => exit,
        Err(_) => write_failed(io),
    }
}

/// Writes an artifact to standard output.
pub(crate) fn artifact(io: &mut Io<'_>, text: &str) -> Exit {
    match io
        .stdout
        .write_all(text.as_bytes())
        .and_then(|()| io.stdout.flush())
    {
        Ok(()) => Exit::Success,
        Err(_) => write_failed(io),
    }
}

/// Reports an error that stops a command before it produces any output.
pub(crate) fn error(io: &mut Io<'_>, diagnostic: Diagnostic) -> Exit {
    match write_diagnostics(io.stderr, &[diagnostic]) {
        Ok(()) => diagnostic.code.exit(),
        Err(_) => Exit::Failure,
    }
}

fn write_diagnostics(stderr: &mut dyn Write, diagnostics: &[impl fmt::Display]) -> io::Result<()> {
    for diagnostic in diagnostics {
        writeln!(stderr, "{diagnostic}")?;
    }
    stderr.flush()
}

fn write_failed(io: &mut Io<'_>) -> Exit {
    let _ = writeln!(io.stderr, "{}", Diagnostic::new(Code::WriteFailed));
    Exit::Failure
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Buffers for one command run.
    #[derive(Default)]
    pub(crate) struct Captured {
        pub(crate) stdout: Vec<u8>,
        pub(crate) stderr: Vec<u8>,
    }

    impl Captured {
        pub(crate) fn run(
            &mut self,
            stdin: &[u8],
            stdin_is_terminal: bool,
            command: impl FnOnce(&mut Io<'_>) -> Exit,
        ) -> Exit {
            let mut stdin = stdin;
            let mut io = Io {
                stdout: &mut self.stdout,
                stderr: &mut self.stderr,
                stdin: &mut stdin,
                stdin_is_terminal,
            };
            command(&mut io)
        }

        pub(crate) fn stdout(&self) -> &str {
            std::str::from_utf8(&self.stdout).expect("UTF-8 output")
        }

        pub(crate) fn stderr(&self) -> &str {
            std::str::from_utf8(&self.stderr).expect("UTF-8 output")
        }
    }

    /// Fails every write, like a closed pipe.
    struct Closed;

    impl Write for Closed {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        }
    }

    #[test]
    fn a_json_report_holds_the_diagnostics_and_standard_error_stays_empty() {
        let mut captured = Captured::default();
        let diagnostics = [Diagnostic::at(Code::Unauthenticated, 2).with_hint("a hint")];
        let exit = captured.run(b"", false, |io| {
            finish(
                io,
                Format::Json,
                "version",
                &serde_json::json!({"a": 1}),
                &diagnostics,
                |_, _| panic!("the human renderer must not run"),
            )
        });
        assert_eq!(exit, Exit::Denied);
        assert!(captured.stderr().is_empty());
        let report: serde_json::Value =
            serde_json::from_str(captured.stdout()).expect("one JSON document");
        assert_eq!(
            report,
            serde_json::json!({
                "apiVersion": "greengateway.dev/v1alpha1",
                "kind": "GgctlReport",
                "command": "version",
                "exitCode": 8,
                "outcome": "denied",
                "diagnostics": [{
                    "code": "remote.unauthenticated",
                    "severity": "error",
                    "message": "the server refused the request as unauthenticated (HTTP 401)",
                    "hint": "a hint",
                    "remediation": "docs/ggctl.md#remote-diagnostics",
                    "location": {"argument": 2}
                }],
                "result": {"a": 1}
            })
        );
    }

    #[test]
    fn every_code_and_exit_fits_the_published_report_schema() {
        let schema = gateway_config::documents::published_schema(API_VERSION_V1ALPHA1, REPORT_KIND)
            .expect("the report schema is published");
        let schema: serde_json::Value = serde_json::from_str(schema.json).expect("JSON");
        let validator = jsonschema::validator_for(&schema).expect("schema compiles");
        let diagnostics: Vec<_> = Code::ALL
            .iter()
            .enumerate()
            .map(|(index, code)| Diagnostic::at(*code, index + 1).with_hint("a fixed hint"))
            .collect();
        for exit in Exit::ALL {
            let mut captured = Captured::default();
            captured.run(b"", false, |io| {
                finish(
                    io,
                    Format::Json,
                    "schema",
                    &serde_json::json!({"schemas": []}),
                    &diagnostics,
                    |_, _| Ok(()),
                )
            });
            let mut report: serde_json::Value =
                serde_json::from_str(captured.stdout()).expect("JSON");
            report["exitCode"] = exit.code().into();
            report["outcome"] = exit.name().into();
            let errors: Vec<_> = validator
                .iter_errors(&report)
                .map(|error| error.to_string())
                .collect();
            assert!(errors.is_empty(), "{errors:?}");
        }
    }

    #[test]
    fn human_output_splits_the_result_and_the_diagnostics() {
        let mut captured = Captured::default();
        let exit = captured.run(b"", false, |io| {
            finish(
                io,
                Format::Human,
                "version",
                &(),
                &[Diagnostic::new(Code::ConnectFailed)],
                |_, out| writeln!(out, "result line"),
            )
        });
        assert_eq!(exit, Exit::Unavailable);
        assert_eq!(captured.stdout(), "result line\n");
        assert!(captured
            .stderr()
            .starts_with("ggctl: error: remote.connect_failed: "));
    }

    #[test]
    fn a_failed_write_is_a_failure_whatever_the_result() {
        let mut stderr = Vec::new();
        let mut stdin: &[u8] = b"";
        let mut io = Io {
            stdout: &mut Closed,
            stderr: &mut stderr,
            stdin: &mut stdin,
            stdin_is_terminal: false,
        };
        assert_eq!(artifact(&mut io, "text"), Exit::Failure);
        assert_eq!(
            finish(&mut io, Format::Json, "schema", &(), &[], |_, _| Ok(())),
            Exit::Failure
        );
        assert!(String::from_utf8(stderr)
            .expect("UTF-8")
            .contains("output.write_failed"));
    }
}
