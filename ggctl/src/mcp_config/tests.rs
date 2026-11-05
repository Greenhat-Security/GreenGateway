use std::ffi::OsString;

use gateway_config::mcp_client_configs::{Auth, ClientKind};

use super::*;
use crate::{
    cli::{parse, Parsed, MCP_AUTHS, MCP_CLIENTS},
    report::tests::Captured,
};

const CANARY: &str = "gg-canary-mcp-config-4b1a77";

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
fn the_choices_are_the_shared_library_names() {
    let clients: Vec<_> = ClientKind::ALL
        .iter()
        .map(|client| client.as_str())
        .collect();
    assert_eq!(clients, MCP_CLIENTS);
    let auths: Vec<_> = Auth::ALL.iter().map(|auth| auth.as_str()).collect();
    assert_eq!(auths, MCP_AUTHS);
}

#[test]
fn argument_errors_are_reported_before_anything_is_read_or_sent() {
    // Every --server below is a closed loopback port: reaching it would be
    // `remote.connect_failed`, so each refusal proves nothing was sent.
    let server = "http://127.0.0.1:9/v1/admin";
    for (words, code, exit) in [
        (
            &["mcp-config", "--client", "cursor"][..],
            "usage.missing_argument",
            Exit::Usage,
        ),
        (
            &["mcp-config", "--server", server],
            "usage.missing_argument",
            Exit::Usage,
        ),
        (
            &["mcp-config", "--client", "cursor", "--token-stdin"],
            "usage.option_requires_server",
            Exit::Usage,
        ),
        (
            &[
                "mcp-config",
                "--server",
                server,
                "--client",
                "claude-desktop",
                "--auth",
                "token",
            ],
            "mcp.no_token_template",
            Exit::Usage,
        ),
        (
            &[
                "mcp-config",
                "--server",
                "http://gateway.example.test/v1/admin",
                "--client",
                "vscode",
            ],
            "remote.plaintext_refused",
            Exit::Usage,
        ),
        (
            &[
                "mcp-config",
                "--server",
                server,
                "--client",
                "cursor",
                "--name",
                "a\"b",
            ],
            "usage.invalid_value",
            Exit::Usage,
        ),
        (
            &[
                "mcp-config",
                "--server",
                server,
                "--client",
                "cursor",
                "--name",
                "${env:HOME}",
            ],
            "usage.invalid_value",
            Exit::Usage,
        ),
    ] {
        let (exit_code, captured) = run_words(words, b"", false);
        assert_eq!(exit_code, exit, "{words:?}");
        assert!(captured.stdout().is_empty(), "{words:?}");
        let stderr = captured.stderr();
        assert!(stderr.contains(code), "{words:?}: {stderr}");
        assert!(!stderr.contains("env:HOME"), "{stderr}");
        assert!(!stderr.contains("a\"b"), "{stderr}");
    }
}

#[test]
fn the_admin_token_is_read_only_from_a_pipe_and_never_echoed() {
    let (exit, captured) = run_words(
        &[
            "mcp-config",
            "--server",
            "http://127.0.0.1:9/v1/admin",
            "--client",
            "generic",
            "--auth",
            "token",
            "--token-stdin",
        ],
        CANARY.as_bytes(),
        true,
    );
    assert_eq!(exit, Exit::Usage);
    assert!(captured.stdout().is_empty());
    assert!(captured.stderr().contains("credential.stdin_is_terminal"));
    assert!(!captured.stderr().contains(CANARY));
}

#[test]
fn an_unreachable_server_writes_no_template() {
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).expect("bind");
    let address = listener.local_addr().expect("address");
    drop(listener);
    let server = format!("http://{address}/v1/admin");
    let (exit, captured) = run_words(
        &["mcp-config", "--server", &server, "--client", "cursor"],
        b"",
        false,
    );
    assert_eq!(exit, Exit::Unavailable);
    assert!(captured.stdout().is_empty());
    let stderr = captured.stderr();
    assert!(stderr.contains("remote.connect_failed"));
    assert!(!stderr.contains(&address.port().to_string()), "{stderr}");
}
