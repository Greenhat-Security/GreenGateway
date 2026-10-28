//! `ggctl version [--server URL ...]`: this binary's version, and the
//! version handshake with a gateway.

use std::io::{self, Write};

use gateway_config::capabilities::GatewayCapabilities;
use serde::Serialize;

use crate::{
    cli::Invocation,
    diagnostic::{Diagnostic, Exit},
    remote::{self, AdminClient, Handshake, RemoteArguments},
    report::{self, Format, Io},
    schema::{self, DocumentRecord},
};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VersionResult {
    /// This binary, reported as `client`.
    client: Binary,
    /// The document versions this ggctl publishes schemas for.
    schemas: Vec<DocumentRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    server: Option<ServerRecord>,
}

#[derive(Serialize)]
struct Binary {
    name: &'static str,
    version: &'static str,
}

#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
struct ServerRecord {
    /// `true` only when the capability document was read and is one this
    /// ggctl implements.
    compatible: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    gateway_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    capabilities: Option<GatewayCapabilities>,
}

pub(crate) fn run(invocation: &Invocation, io: &mut Io<'_>) -> Exit {
    let remote = match RemoteArguments::from_invocation(invocation) {
        Ok(remote) => remote,
        Err(diagnostic) => return report::error(io, diagnostic),
    };
    let mut diagnostics = Vec::new();
    let server = remote.map(|remote| check(remote, io, &mut diagnostics));
    let result = VersionResult {
        client: Binary {
            name: "ggctl",
            version: env!("CARGO_PKG_VERSION"),
        },
        schemas: schema::published(),
        server,
    };
    report::finish(
        io,
        Format::of(invocation),
        "version",
        &result,
        &diagnostics,
        human,
    )
}

/// The handshake: every failure becomes a diagnostic and an unverified
/// server, never a guess.
fn check(
    remote: RemoteArguments,
    io: &mut Io<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) -> ServerRecord {
    let outcome = remote
        .load(io.stdin_is_terminal, io.stdin)
        .and_then(AdminClient::new)
        .and_then(|client| remote::block_on(async move { remote::handshake(&client).await }))
        .and_then(|outcome| outcome);
    match outcome {
        Ok(Handshake::Compatible(capabilities)) => ServerRecord {
            compatible: true,
            gateway_version: Some(capabilities.gateway_version.clone()),
            capabilities: Some(capabilities),
        },
        Ok(Handshake::Incompatible {
            gateway_version,
            reason,
        }) => {
            diagnostics.push(Diagnostic::new(reason));
            ServerRecord {
                gateway_version,
                ..ServerRecord::default()
            }
        }
        Err(code) => {
            diagnostics.push(Diagnostic::new(code));
            ServerRecord::default()
        }
    }
}

fn human(result: &VersionResult, out: &mut dyn Write) -> io::Result<()> {
    writeln!(out, "ggctl {}", result.client.version)?;
    let mut kinds = String::new();
    for (index, schema) in result.schemas.iter().enumerate() {
        if index > 0 {
            kinds.push_str(", ");
        }
        if index == 0 || result.schemas[index - 1].api_version != schema.api_version {
            kinds.push_str(schema.api_version);
            kinds.push(' ');
        }
        kinds.push_str(schema.kind);
    }
    writeln!(out, "schemas: {kinds}")?;
    let Some(server) = &result.server else {
        return Ok(());
    };
    match (&server.capabilities, &server.gateway_version) {
        (Some(capabilities), _) => {
            writeln!(out, "server: compatible")?;
            writeln!(out, "gateway: {}", capabilities.gateway_version)?;
            writeln!(out, "source mode: {}", capabilities.source_mode.as_str())?;
            let documents: Vec<_> = capabilities
                .documents
                .iter()
                .map(|document| format!("{} {}", document.api_version, document.kind))
                .collect();
            writeln!(out, "configuration documents: {}", list_or_none(&documents))?;
            writeln!(
                out,
                "configuration operations: {}",
                list_or_none(&capabilities.operations)
            )
        }
        (None, Some(gateway_version)) => {
            writeln!(out, "server: incompatible")?;
            writeln!(out, "gateway: {gateway_version}")
        }
        (None, None) => writeln!(out, "server: not verified"),
    }
}

/// Names the handshake already validated against a closed grammar, so they
/// are safe to print.
fn list_or_none(items: &[String]) -> String {
    if items.is_empty() {
        "none".to_owned()
    } else {
        items.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::*;
    use crate::{
        cli::{parse, Parsed},
        report::tests::Captured,
    };

    fn run_words(words: &[&str], stdin: &[u8], stdin_is_terminal: bool) -> (Exit, Captured) {
        let arguments: Vec<OsString> = words.iter().map(OsString::from).collect();
        let Ok(Parsed::Run(invocation)) = parse(&arguments) else {
            panic!("{words:?} should parse");
        };
        let mut captured = Captured::default();
        let exit = captured.run(stdin, stdin_is_terminal, |io| run(&invocation, io));
        (exit, captured)
    }

    #[test]
    fn without_a_server_it_reports_this_binary_only() {
        let (exit, captured) = run_words(&["version"], b"", true);
        assert_eq!(exit, Exit::Success);
        assert_eq!(
            captured.stdout(),
            format!(
                "ggctl {}\nschemas: greengateway.dev/v1alpha1 GatewayBundle, GatewayDeployment, \
                 GatewayCapabilities, GgctlReport\n",
                env!("CARGO_PKG_VERSION")
            )
        );
        assert!(captured.stderr().is_empty());

        let (exit, captured) = run_words(&["version", "--format", "json"], b"", true);
        assert_eq!(exit, Exit::Success);
        let report: serde_json::Value = serde_json::from_str(captured.stdout()).expect("JSON");
        assert_eq!(report["result"]["client"]["name"], "ggctl");
        assert_eq!(report["result"]["schemas"][0]["kind"], "GatewayBundle");
        assert!(report["result"].get("server").is_none());
    }

    #[test]
    fn argument_errors_are_reported_before_anything_is_read_or_sent() {
        for (words, code) in [
            (
                &["version", "--token-stdin"][..],
                "usage.option_requires_server",
            ),
            (
                &["version", "--timeout", "5"],
                "usage.option_requires_server",
            ),
            (
                &[
                    "version",
                    "--server",
                    "http://gateway.example.test/v1/admin",
                ],
                "remote.plaintext_refused",
            ),
            (
                &[
                    "version",
                    "--server",
                    "http://127.0.0.1:1/v1/admin",
                    "--ca-file",
                    "ca.pem",
                ],
                "usage.ca_file_requires_https",
            ),
            (
                &[
                    "version",
                    "--server",
                    "https://gateway.example.test/v1/admin",
                    "--token-stdin",
                    "--token-file",
                    "token",
                ],
                "usage.conflicting_options",
            ),
            (
                &[
                    "version",
                    "--server",
                    "https://gateway.example.test/v1/admin",
                    "--timeout",
                    "0",
                ],
                "usage.invalid_value",
            ),
            (
                &[
                    "version",
                    "--server",
                    "https://gateway.example.test/v1/admin",
                    "--timeout",
                    "301",
                ],
                "usage.invalid_value",
            ),
        ] {
            let (exit, captured) = run_words(words, b"", false);
            assert_eq!(exit, Exit::Usage, "{words:?}");
            assert!(captured.stdout().is_empty(), "{words:?}");
            assert!(
                captured.stderr().contains(code),
                "{words:?}: {}",
                captured.stderr()
            );
        }
    }

    #[test]
    fn a_token_from_a_terminal_is_refused_and_reported_in_the_requested_format() {
        let (exit, captured) = run_words(
            &[
                "version",
                "--server",
                "http://127.0.0.1:1/v1/admin",
                "--token-stdin",
                "--format",
                "json",
            ],
            b"",
            true,
        );
        assert_eq!(exit, Exit::Usage);
        assert!(captured.stderr().is_empty());
        let report: serde_json::Value = serde_json::from_str(captured.stdout()).expect("JSON");
        assert_eq!(
            report["diagnostics"][0]["code"],
            "credential.stdin_is_terminal"
        );
        assert_eq!(
            report["result"]["server"],
            serde_json::json!({"compatible": false})
        );
        assert_eq!(report["exitCode"], 2);
    }
}
