//! The `McpClientConfigs` document: credential-free configuration templates
//! for MCP clients (issue #242, ADR-0008 "MCP client templates").
//!
//! A gateway serves this document at
//! `GET /v1{ADMIN_PREFIX}/mcp/client-configs` (`admin:mcp:clients:read`), the
//! admin UI shows its templates as text, and `ggctl mcp-config` writes one of
//! them to standard output. Every template is rendered here, from three
//! inputs only:
//!
//! - the gateway's MCP endpoint, which the gateway computes from
//!   `GATEWAY_PUBLIC_URL` exactly as its protected-resource metadata
//!   computes the resource identifier, and never from `Host`, forwarding
//!   headers, the browser's location or anything the caller sends;
//! - whether that metadata advertises an authorization server, which decides
//!   whether OAuth templates are offered at all;
//! - the server entry name, a short identifier the caller may choose
//!   ([`ServerName`]), `greengateway` by default.
//!
//! No template holds a credential, and none can: an OAuth template holds the
//! MCP URL and nothing that authenticates (the client discovers the
//! authorization server from the gateway's protected-resource metadata), and
//! a token template names the fixed environment variable [`TOKEN_VARIABLE`]
//! in the client's own interpolation syntax, so the client reads the token
//! from its environment when it connects.
//!
//! The document is closed and exact. A reader accepts only this
//! `(apiVersion, kind)`, refuses an unknown or duplicate member, and refuses
//! a document whose templates are not exactly what this version renders for
//! the URL, name and OAuth flag the document states, so a reader never
//! passes on a template it would not have produced itself.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

use crate::documents::{API_VERSION_V1ALPHA1, MCP_CLIENT_CONFIGS_KIND};

/// The largest document a reader accepts.
pub const MAX_MCP_CLIENT_CONFIGS_BYTES: usize = 256 * 1024;
/// The longest MCP URL a template is rendered for.
pub const MAX_MCP_URL_BYTES: usize = 16 * 1024;
/// The longest server entry name.
pub const MAX_SERVER_NAME_BYTES: usize = 64;
/// The server entry name when the caller names none.
pub const DEFAULT_SERVER_NAME: &str = "greengateway";
/// The environment variable a token template reads the bearer token from.
/// Fixed, so a template never depends on anything but the URL and the name.
pub const TOKEN_VARIABLE: &str = "GREENGATEWAY_MCP_TOKEN";
/// Every MCP URL ends at the gateway's MCP endpoint.
const MCP_PATH_SUFFIX: &str = "/mcp";
/// Characters a client configuration file interpolates (`${...}`) or
/// escapes. An endpoint holding one is never written into a template.
const UNTEMPLATABLE: [char; 4] = ['$', '{', '}', '\\'];

/// Where Cursor reads `mcp.json`: in a project, or for every project from
/// the user's home directory (shown for Windows too).
const CURSOR_LOCATIONS: &[&str] = &[
    ".cursor/mcp.json",
    "~/.cursor/mcp.json",
    "%USERPROFILE%\\.cursor\\mcp.json",
];
/// Where VS Code reads a workspace's MCP servers.
const VSCODE_LOCATIONS: &[&str] = &[".vscode/mcp.json"];

/// A client a template is rendered for.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClientKind {
    /// Any Streamable HTTP client: the transport, the URL and, for a token,
    /// the header to send.
    Generic,
    /// Claude Desktop, which adds a remote server as a custom connector by
    /// its URL and authorizes it with OAuth.
    ClaudeDesktop,
    /// Cursor's `mcp.json`.
    Cursor,
    /// VS Code's `mcp.json`.
    Vscode,
}

impl ClientKind {
    /// Every client, in rendering order.
    pub const ALL: [Self; 4] = [
        Self::Generic,
        Self::ClaudeDesktop,
        Self::Cursor,
        Self::Vscode,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Generic => "generic",
            Self::ClaudeDesktop => "claude-desktop",
            Self::Cursor => "cursor",
            Self::Vscode => "vscode",
        }
    }

    /// The client with exactly this name.
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|client| client.as_str() == text)
    }

    /// Whether this client has a template for `auth`. Claude Desktop takes a
    /// remote server's URL in its own interface and authorizes it with
    /// OAuth; GreenGateway renders no bridge that would put a token in its
    /// configuration file.
    pub fn supports(self, auth: Auth) -> bool {
        !matches!((self, auth), (Self::ClaudeDesktop, Auth::Token))
    }
}

/// How a template's client authenticates to the gateway.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Auth {
    /// The client discovers the authorization server from the gateway's
    /// protected-resource metadata and obtains its own token.
    Oauth,
    /// The client sends a bearer token it reads from [`TOKEN_VARIABLE`].
    Token,
}

impl Auth {
    /// Every mode, in rendering order.
    pub const ALL: [Self; 2] = [Self::Oauth, Self::Token];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Oauth => "oauth",
            Self::Token => "token",
        }
    }

    /// The mode with exactly this name.
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|auth| auth.as_str() == text)
    }
}

/// What a template's content is.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    /// A JSON document: the client's configuration file.
    Json,
    /// One line holding the MCP URL, for a client that takes it in its own
    /// interface.
    Url,
}

/// One template.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Template {
    pub client: ClientKind,
    pub auth: Auth,
    pub format: Format,
    /// Where the client reads a file holding this template, relative to a
    /// project or the user's home directory; empty for a client that takes
    /// it in its own interface.
    pub locations: Vec<String>,
    /// The template, ending in a line feed.
    pub content: String,
}

/// The document.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct McpClientConfigs {
    pub api_version: String,
    pub kind: String,
    /// The gateway's MCP endpoint, the URL every template names.
    pub mcp_url: String,
    /// The server entry name the JSON templates use.
    pub server_name: String,
    /// Whether the gateway's protected-resource metadata advertises an
    /// authorization server. OAuth templates are present only when it does.
    pub oauth: bool,
    /// The environment variable token templates read: [`TOKEN_VARIABLE`].
    pub token_variable: String,
    pub templates: Vec<Template>,
}

/// The gateway's MCP endpoint, checked to be one a template may name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct McpUrl(String);

/// Why an MCP endpoint cannot be written into a template.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum McpUrlError {
    /// Not an absolute URL in canonical form whose path ends at `/mcp`, with
    /// a host and without user information or a fragment, using `https`, or
    /// `http` only for a loopback host.
    Invalid,
    /// A URL a client would not read literally: longer than
    /// [`MAX_MCP_URL_BYTES`], or holding `$`, `{`, `}` or `\`, which client
    /// configuration files interpolate or escape.
    NotTemplatable,
}

impl McpUrl {
    pub fn new(text: &str) -> Result<Self, McpUrlError> {
        if text.len() > MAX_MCP_URL_BYTES {
            return Err(McpUrlError::NotTemplatable);
        }
        let url = Url::parse(text).map_err(|_| McpUrlError::Invalid)?;
        let well_formed = url.as_str() == text
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
            && url.path().ends_with(MCP_PATH_SUFFIX)
            && match url.scheme() {
                "https" => url.host_str().is_some(),
                "http" => host_is_loopback(&url),
                _ => false,
            };
        if !well_formed {
            return Err(McpUrlError::Invalid);
        }
        if text.contains(UNTEMPLATABLE) {
            return Err(McpUrlError::NotTemplatable);
        }
        Ok(Self(text.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Whether `url` names a loopback host, the only hosts `GATEWAY_PUBLIC_URL`
/// may name over plain `http`. It classifies the parsed host and resolves
/// and connects to nothing.
fn host_is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(name)) => name.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => {
            address.is_loopback()
                || address
                    .to_ipv4_mapped()
                    .is_some_and(|mapped| mapped.is_loopback())
        }
        None => false,
    }
}

/// A server entry name: 1 to 64 ASCII letters, digits, `-` and `_`, starting
/// with a letter or digit. Nothing outside that grammar is escaped into a
/// template; it is refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerName(String);

impl ServerName {
    pub fn new(text: &str) -> Option<Self> {
        let bytes = text.as_bytes();
        let valid = bytes.len() <= MAX_SERVER_NAME_BYTES
            && bytes
                .first()
                .is_some_and(|byte| byte.is_ascii_alphanumeric())
            && bytes
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
        valid.then(|| Self(text.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for ServerName {
    fn default() -> Self {
        Self(DEFAULT_SERVER_NAME.to_owned())
    }
}

impl McpClientConfigs {
    /// Every template for `mcp_url`: for each client in [`ClientKind::ALL`]
    /// order, its OAuth template when `oauth` holds, then its token template
    /// when it has one.
    pub fn render(
        mcp_url: &McpUrl,
        server_name: &ServerName,
        oauth: bool,
    ) -> Result<Self, serde_json::Error> {
        let mut templates = Vec::new();
        for client in ClientKind::ALL {
            for auth in Auth::ALL {
                if client.supports(auth) && (oauth || auth != Auth::Oauth) {
                    templates.push(template(client, auth, mcp_url, server_name)?);
                }
            }
        }
        Ok(Self {
            api_version: API_VERSION_V1ALPHA1.to_owned(),
            kind: MCP_CLIENT_CONFIGS_KIND.to_owned(),
            mcp_url: mcp_url.as_str().to_owned(),
            server_name: server_name.as_str().to_owned(),
            oauth,
            token_variable: TOKEN_VARIABLE.to_owned(),
            templates,
        })
    }

    /// The template for exactly this client and mode.
    pub fn template(&self, client: ClientKind, auth: Auth) -> Option<&Template> {
        self.templates
            .iter()
            .find(|template| template.client == client && template.auth == auth)
    }
}

/// The header a token template sends, in one client's interpolation syntax.
#[derive(Serialize)]
struct Headers {
    #[serde(rename = "Authorization")]
    authorization: String,
}

impl Headers {
    /// `None` for an OAuth template, which sends no header at all.
    fn for_auth(auth: Auth, placeholder: String) -> Option<Self> {
        match auth {
            Auth::Oauth => None,
            Auth::Token => Some(Self {
                authorization: format!("Bearer {placeholder}"),
            }),
        }
    }
}

/// The generic template: a transport description rather than any one
/// client's file. Its placeholder is shell syntax.
#[derive(Serialize)]
struct GenericServer<'a> {
    transport: &'static str,
    url: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    headers: Option<Headers>,
}

/// One entry of Cursor's `mcpServers`.
#[derive(Serialize)]
struct CursorServer<'a> {
    url: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    headers: Option<Headers>,
}

#[derive(Serialize)]
struct CursorFile<'a> {
    #[serde(rename = "mcpServers")]
    mcp_servers: BTreeMap<&'a str, CursorServer<'a>>,
}

/// One entry of VS Code's `servers`.
#[derive(Serialize)]
struct VscodeServer<'a> {
    #[serde(rename = "type")]
    transport: &'static str,
    url: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    headers: Option<Headers>,
}

#[derive(Serialize)]
struct VscodeFile<'a> {
    servers: BTreeMap<&'a str, VscodeServer<'a>>,
}

fn template(
    client: ClientKind,
    auth: Auth,
    mcp_url: &McpUrl,
    server_name: &ServerName,
) -> Result<Template, serde_json::Error> {
    let url = mcp_url.as_str();
    let name = server_name.as_str();
    // Cursor and VS Code both resolve `${env:NAME}` in a server's headers.
    let client_placeholder = format!("${{env:{TOKEN_VARIABLE}}}");
    let (format, locations, content) = match client {
        ClientKind::Generic => (
            Format::Json,
            &[][..],
            json_document(&GenericServer {
                transport: "streamable-http",
                url,
                headers: Headers::for_auth(auth, format!("${{{TOKEN_VARIABLE}}}")),
            })?,
        ),
        ClientKind::ClaudeDesktop => (Format::Url, &[][..], format!("{url}\n")),
        ClientKind::Cursor => (
            Format::Json,
            CURSOR_LOCATIONS,
            json_document(&CursorFile {
                mcp_servers: BTreeMap::from([(
                    name,
                    CursorServer {
                        url,
                        headers: Headers::for_auth(auth, client_placeholder),
                    },
                )]),
            })?,
        ),
        ClientKind::Vscode => (
            Format::Json,
            VSCODE_LOCATIONS,
            json_document(&VscodeFile {
                servers: BTreeMap::from([(
                    name,
                    VscodeServer {
                        transport: "http",
                        url,
                        headers: Headers::for_auth(auth, client_placeholder),
                    },
                )]),
            })?,
        ),
    };
    Ok(Template {
        client,
        auth,
        format,
        locations: locations
            .iter()
            .map(|location| (*location).to_owned())
            .collect(),
        content,
    })
}

/// Two-space indented JSON ending in a line feed.
fn json_document(value: &impl Serialize) -> Result<String, serde_json::Error> {
    let mut text = serde_json::to_string_pretty(value)?;
    text.push('\n');
    Ok(text)
}

/// Why a document could not be read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadError {
    /// Larger than [`MAX_MCP_CLIENT_CONFIGS_BYTES`]; nothing was parsed.
    TooLarge,
    /// Not a JSON object with readable `apiVersion` and `kind` members.
    NotADocument,
    /// A document version this reader does not implement.
    UnsupportedVersion,
    /// The supported version, but not exactly a document this version
    /// renders.
    Invalid,
}

/// The members every document version keeps, read without interpreting
/// anything else.
#[derive(Deserialize)]
struct Envelope {
    #[serde(rename = "apiVersion")]
    api_version: Option<Value>,
    kind: Option<Value>,
}

/// Reads a document strictly: it must be exactly what
/// [`McpClientConfigs::render`] produces for the URL, name and OAuth flag it
/// states.
pub fn read(bytes: &[u8]) -> Result<McpClientConfigs, ReadError> {
    if bytes.len() > MAX_MCP_CLIENT_CONFIGS_BYTES {
        return Err(ReadError::TooLarge);
    }
    let envelope: Envelope = serde_json::from_slice(bytes).map_err(|_| ReadError::NotADocument)?;
    let (Some(Value::String(api_version)), Some(Value::String(kind))) =
        (&envelope.api_version, &envelope.kind)
    else {
        return Err(ReadError::NotADocument);
    };
    if api_version != API_VERSION_V1ALPHA1 || kind != MCP_CLIENT_CONFIGS_KIND {
        return Err(ReadError::UnsupportedVersion);
    }
    let document: McpClientConfigs =
        serde_json::from_slice(bytes).map_err(|_| ReadError::Invalid)?;
    let (Ok(mcp_url), Some(server_name)) = (
        McpUrl::new(&document.mcp_url),
        ServerName::new(&document.server_name),
    ) else {
        return Err(ReadError::Invalid);
    };
    match McpClientConfigs::render(&mcp_url, &server_name, document.oauth) {
        Ok(expected) if expected == document => Ok(document),
        _ => Err(ReadError::Invalid),
    }
}

#[cfg(test)]
mod tests;
