//! `ggctl mcp-config --server URL --client CLIENT [--auth oauth|token]
//! [--name NAME] ...` (issue #242, ADR-0008 "MCP client templates").
//!
//! Reads the gateway's MCP client configuration templates from
//! `GET <server>/mcp/client-configs` and writes the one template `--client`
//! and `--auth` select to standard output, byte for byte. The template is an
//! artifact, so there is no `--format`, and nothing else is written there.
//! `ggctl` never opens, edits or creates a client's configuration file: where
//! the output goes is the operator's redirect.
//!
//! The URL in every template comes from the server, which computes it from
//! its `GATEWAY_PUBLIC_URL`; `ggctl` has no option to supply or change it.
//! No template holds a credential: an OAuth template names only the URL, and
//! a token template names the environment variable `GREENGATEWAY_MCP_TOKEN`,
//! never a token. The admin token `--token-stdin` or `--token-file` supplies
//! authenticates the read and appears nowhere in the output.

use gateway_config::mcp_client_configs::{Auth, ClientKind, ServerName};

use crate::{
    cli::Invocation,
    diagnostic::{Code, Diagnostic, Exit},
    remote::{self, AdminClient, RemoteArguments},
    report::{self, Io},
};

pub(crate) fn run(invocation: &Invocation, io: &mut Io<'_>) -> Exit {
    let Some((_, client)) = invocation.text("--client") else {
        return report::error(io, Diagnostic::new(Code::MissingArgument));
    };
    // The parser accepted only a client name.
    let Some(client) = ClientKind::parse(client) else {
        return report::error(io, Diagnostic::new(Code::InvalidValue));
    };
    let auth = match invocation.text("--auth") {
        None => Auth::Oauth,
        Some((position, auth)) => match Auth::parse(auth) {
            Some(auth) => auth,
            None => return report::error(io, Diagnostic::at(Code::InvalidValue, position)),
        },
    };
    let name = match invocation.text("--name") {
        None => None,
        Some((position, name)) => match ServerName::new(name) {
            Some(name) => Some(name),
            None => return report::error(io, Diagnostic::at(Code::InvalidValue, position)),
        },
    };
    if !client.supports(auth) {
        let position = invocation.flag("--auth");
        let diagnostic = match position {
            Some(position) => Diagnostic::at(Code::McpNoTokenTemplate, position),
            None => Diagnostic::new(Code::McpNoTokenTemplate),
        };
        return report::error(io, diagnostic.with_hint(HINT_DESKTOP));
    }
    let remote = match RemoteArguments::from_invocation(invocation) {
        Ok(Some(remote)) => remote,
        Ok(None) => return report::error(io, Diagnostic::new(Code::MissingArgument)),
        Err(diagnostic) => return report::error(io, diagnostic),
    };
    let expected_name = name.clone().unwrap_or_default();
    let fetched = remote
        .load(io.stdin_is_terminal, io.stdin)
        .and_then(AdminClient::new)
        .and_then(|client| {
            remote::block_on(
                async move { remote::mcp_client_configs(&client, name.as_ref()).await },
            )
        })
        .and_then(|outcome| outcome);
    let document = match fetched {
        Ok(document) => document,
        Err(code) => return report::error(io, Diagnostic::new(code)),
    };
    if document.server_name != expected_name.as_str() {
        return report::error(io, Diagnostic::new(Code::McpConfigsInvalid));
    }
    match document.template(client, auth) {
        Some(template) => report::artifact(io, &template.content),
        None if auth == Auth::Oauth && !document.oauth => report::error(
            io,
            Diagnostic::new(Code::McpOauthUnavailable).with_hint(HINT_TOKEN),
        ),
        None => report::error(io, Diagnostic::new(Code::McpConfigsInvalid)),
    }
}

const HINT_DESKTOP: &str = "add the URL `ggctl mcp-config --client claude-desktop` writes as a custom connector, or use another client with --auth token";
const HINT_TOKEN: &str = "configure an OIDC/JWT provider with an issuer on the gateway, or use --auth token with a service token";

#[cfg(test)]
mod tests;
