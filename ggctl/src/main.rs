//! `ggctl`, the GreenGateway operator CLI (issue #242, ADR-0008).
//!
//! A separate binary: the `gateway` server keeps its name, its no-argument
//! startup and its one-shot commands. It provides the command table, the
//! output contract (human, `--format json` reports, SARIF for `validate` and
//! `diff`), the stable exit codes, shell completion, secure bearer-token
//! input, the version handshake with a running gateway, and offline bundle
//! validation, diagnosis and semantic diff with the gateway's own bundle
//! reader and diff engine (`gateway-config`).
//!
//! `ggctl` reads no configuration file and no environment variable, never
//! accepts a secret as an argument, and makes no network request unless a
//! command is given `--server`. The command reference is `docs/ggctl.md`.

mod cli;
mod completion;
mod convert;
mod credential;
mod diagnostic;
mod diff;
mod doctor;
mod help;
mod init;
mod output;
mod remote;
mod report;
mod sarif;
mod schema;
mod validate;
mod version;

use std::{ffi::OsString, io::IsTerminal, process::ExitCode};

use cli::Parsed;
use diagnostic::Exit;
use report::Io;

fn main() -> ExitCode {
    let arguments: Vec<OsString> = std::env::args_os().skip(1).collect();
    let stdin = std::io::stdin();
    let stdin_is_terminal = stdin.is_terminal();
    let mut stdin = stdin.lock();
    let mut stdout = std::io::stdout().lock();
    let mut stderr = std::io::stderr().lock();
    let mut io = Io {
        stdout: &mut stdout,
        stderr: &mut stderr,
        stdin: &mut stdin,
        stdin_is_terminal,
    };
    let exit = run(&arguments, &mut io);
    let _ = io.stdout.flush();
    ExitCode::from(exit.code())
}

/// Parses and runs one command line.
fn run(arguments: &[OsString], io: &mut Io<'_>) -> Exit {
    match cli::parse(arguments) {
        Err(diagnostic) => report::error(io, diagnostic),
        Ok(Parsed::Help(topic)) => report::artifact(io, &help::text(topic)),
        Ok(Parsed::Version) => {
            report::artifact(io, concat!("ggctl ", env!("CARGO_PKG_VERSION"), "\n"))
        }
        Ok(Parsed::Run(invocation)) => (invocation.command.run)(&invocation, io),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::tests::Captured;

    fn run_words(words: &[&str]) -> (Exit, Captured) {
        let arguments: Vec<OsString> = words.iter().map(OsString::from).collect();
        let mut captured = Captured::default();
        let exit = captured.run(b"", false, |io| run(&arguments, io));
        (exit, captured)
    }

    #[test]
    fn usage_errors_exit_2_on_standard_error_with_no_report() {
        for words in [
            &[][..],
            &["frobnicate"],
            &["version", "--format", "json", "--bogus"],
            &["db"],
        ] {
            let (exit, captured) = run_words(words);
            assert_eq!(exit, Exit::Usage, "{words:?}");
            assert!(captured.stdout().is_empty(), "{words:?}");
            assert!(
                captured.stderr().starts_with("ggctl: error: usage."),
                "{words:?}"
            );
        }
    }

    #[test]
    fn help_and_the_version_flag_write_to_standard_output() {
        let (exit, captured) = run_words(&["--version"]);
        assert_eq!(exit, Exit::Success);
        assert_eq!(
            captured.stdout(),
            format!("ggctl {}\n", env!("CARGO_PKG_VERSION"))
        );
        for words in [
            &["help"][..],
            &["--help"],
            &["help", "schema"],
            &["schema", "-h"],
        ] {
            let (exit, captured) = run_words(words);
            assert_eq!(exit, Exit::Success, "{words:?}");
            assert!(captured.stdout().contains("Usage: ggctl"), "{words:?}");
            assert!(captured.stderr().is_empty());
        }
    }

    #[test]
    fn schema_prints_the_published_document_or_lists_them() {
        let (exit, captured) = run_words(&["schema", "GatewayCapabilities"]);
        assert_eq!(exit, Exit::Success);
        let schema: serde_json::Value = serde_json::from_str(captured.stdout()).expect("JSON");
        assert_eq!(
            schema["$id"],
            "https://greengateway.dev/schemas/gateway-capabilities.v1alpha1.schema.json"
        );
        assert!(!captured.stdout().contains('\r'));

        let (exit, captured) = run_words(&["schema"]);
        assert_eq!(exit, Exit::Success);
        assert_eq!(
            captured.stdout(),
            "greengateway.dev/v1alpha1  GatewayBundle\n\
             greengateway.dev/v1alpha1  GatewayDeployment\n\
             greengateway.dev/v1alpha1  GatewayInitAnswers\n\
             greengateway.dev/v1alpha1  GatewayCapabilities\n\
             greengateway.dev/v1alpha1  GgctlReport\n"
        );

        let (exit, captured) = run_words(&[
            "schema",
            "GatewayBundle",
            "--api-version",
            "greengateway.dev/v1",
        ]);
        assert_eq!(exit, Exit::Invalid);
        assert!(captured.stdout().is_empty());
        assert!(captured.stderr().contains("schema.unsupported_api_version"));

        let (exit, captured) = run_words(&["schema", "GatewayBundle", "--format", "json"]);
        assert_eq!(exit, Exit::Usage);
        assert!(captured.stderr().contains("usage.format_unsupported"));

        let (exit, captured) = run_words(&[
            "schema",
            "--api-version",
            "greengateway.dev/v9",
            "--format",
            "json",
        ]);
        assert_eq!(exit, Exit::Invalid);
        let report: serde_json::Value = serde_json::from_str(captured.stdout()).expect("JSON");
        assert_eq!(report["result"]["schemas"], serde_json::json!([]));
        assert_eq!(
            report["diagnostics"][0]["code"],
            "schema.unsupported_api_version"
        );
    }

    #[test]
    fn completion_writes_the_requested_script() {
        for (shell, marker) in [
            ("bash", "complete -F _ggctl ggctl"),
            ("zsh", "#compdef ggctl"),
            ("fish", "complete -c ggctl"),
            ("powershell", "Register-ArgumentCompleter"),
        ] {
            let (exit, captured) = run_words(&["completion", shell]);
            assert_eq!(exit, Exit::Success);
            assert!(captured.stdout().contains(marker), "{shell}");
        }
    }
}
