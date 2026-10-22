//! Value-free diagnostics and the stable exit codes.
//!
//! A diagnostic is a stable code plus, at most, the 1-based position of the
//! command-line argument it is about and a fixed hint. Its message, hint and
//! remediation anchor are static text chosen by the code, so no argument,
//! token, URL, path, server response or library error text can reach one:
//! an unknown option is reported by its position, never by its spelling,
//! because the spelling may be a mistyped secret.

use std::fmt;

/// The process exit codes (ADR-0008, "Exit codes"). The numbers and names
/// are a published contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Exit {
    Success,
    Failure,
    Usage,
    Invalid,
    Drift,
    Conflict,
    Unavailable,
    Integrity,
    Denied,
}

impl Exit {
    pub(crate) const ALL: [Self; 9] = [
        Self::Success,
        Self::Failure,
        Self::Usage,
        Self::Invalid,
        Self::Drift,
        Self::Conflict,
        Self::Unavailable,
        Self::Integrity,
        Self::Denied,
    ];

    pub(crate) fn code(self) -> u8 {
        match self {
            Self::Success => 0,
            Self::Failure => 1,
            Self::Usage => 2,
            Self::Invalid => 3,
            Self::Drift => 4,
            Self::Conflict => 5,
            Self::Unavailable => 6,
            Self::Integrity => 7,
            Self::Denied => 8,
        }
    }

    /// The stable name a report carries as its `outcome`.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Usage => "usage",
            Self::Invalid => "invalid",
            Self::Drift => "drift",
            Self::Conflict => "conflict",
            Self::Unavailable => "unavailable",
            Self::Integrity => "integrity",
            Self::Denied => "denied",
        }
    }

    pub(crate) fn meaning(self) -> &'static str {
        match self {
            Self::Success => "success; for diff --check, no drift; for doctor, no required check failed",
            Self::Failure => {
                "unexpected internal, I/O or transport failure, including a mutation whose outcome could not be determined"
            }
            Self::Usage => "usage error, including a reserved command or a refused insecure option",
            Self::Invalid => {
                "invalid, incompatible or unsupported configuration, server or document version"
            }
            Self::Drift => "drift found by diff --check",
            Self::Conflict => "precondition conflict: missing or stale ETag, plan, acknowledgment or lock",
            Self::Unavailable => "a dependency was unavailable and nothing was sent or committed; safe to retry",
            Self::Integrity => "backup or archive integrity or restore verification failure",
            Self::Denied => "authentication or authorization refused",
        }
    }

    /// When several errors apply, the outcome that must not be hidden wins.
    /// An outcome that may have committed (`Failure`) outranks everything,
    /// and "safe to retry" (`Unavailable`) is never reported while any other
    /// error stands, so a pipeline that retries on 6 cannot resend work
    /// another error left in doubt.
    fn precedence(self) -> u8 {
        match self {
            Self::Failure => 8,
            Self::Integrity => 7,
            Self::Denied => 6,
            Self::Conflict => 5,
            Self::Usage => 4,
            Self::Invalid => 3,
            Self::Drift => 2,
            Self::Unavailable => 1,
            Self::Success => 0,
        }
    }

    /// The exit code for a set of diagnostics: success when there is none.
    pub(crate) fn of(diagnostics: &[Diagnostic]) -> Self {
        diagnostics
            .iter()
            .map(|diagnostic| diagnostic.code.exit())
            .max_by_key(|exit| exit.precedence())
            .unwrap_or(Self::Success)
    }
}

/// Every reason `ggctl` can refuse or fail. The string form (`family.reason`)
/// is the stable contract: a published code never changes meaning, and
/// renaming or removing one needs a new report schema version.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Code {
    // Arguments.
    MissingCommand,
    UnknownCommand,
    ReservedCommand,
    UnknownOption,
    MissingValue,
    DuplicateOption,
    UnexpectedValue,
    UnexpectedArgument,
    MissingArgument,
    InvalidValue,
    ArgumentNotUtf8,
    ConflictingOptions,
    OptionRequiresServer,
    FormatUnsupported,
    SecretOnCommandLine,
    InsecureOptionRefused,
    CaFileRequiresHttps,
    // Bearer-token input.
    StdinIsTerminal,
    CredentialUnreadable,
    CredentialNotRegularFile,
    CredentialUnsafePermissions,
    CredentialTooLarge,
    CredentialEmpty,
    CredentialInvalid,
    // Additional trust anchors.
    CaFileUnreadable,
    CaFileNotRegularFile,
    CaFileTooLarge,
    CaFileInvalid,
    // The server address and the admin API transport.
    InvalidServerUrl,
    PlaintextRefused,
    UserinfoRefused,
    QueryOrFragmentRefused,
    ConnectFailed,
    Timeout,
    TransportFailed,
    RedirectRefused,
    Unauthenticated,
    Forbidden,
    ServerUnavailable,
    UnexpectedStatus,
    ResponseTooLarge,
    UnexpectedContentType,
    // The version handshake.
    CapabilitiesUnavailable,
    UnsupportedCapabilitiesVersion,
    CapabilitiesInvalid,
    // Published schemas.
    UnsupportedSchemaVersion,
    // This process.
    WriteFailed,
    RuntimeUnavailable,
    ClientUnavailable,
}

/// The documentation families, each a section of `docs/ggctl.md`.
#[cfg(test)]
pub(crate) const FAMILIES: &[&str] = &[
    "usage",
    "credential",
    "trust",
    "remote",
    "compat",
    "schema",
    "output",
    "internal",
];

impl Code {
    /// Every code, in declaration order, for the uniqueness and
    /// documentation tests.
    #[cfg(test)]
    pub(crate) const ALL: &'static [Self] = &[
        Self::MissingCommand,
        Self::UnknownCommand,
        Self::ReservedCommand,
        Self::UnknownOption,
        Self::MissingValue,
        Self::DuplicateOption,
        Self::UnexpectedValue,
        Self::UnexpectedArgument,
        Self::MissingArgument,
        Self::InvalidValue,
        Self::ArgumentNotUtf8,
        Self::ConflictingOptions,
        Self::OptionRequiresServer,
        Self::FormatUnsupported,
        Self::SecretOnCommandLine,
        Self::InsecureOptionRefused,
        Self::CaFileRequiresHttps,
        Self::StdinIsTerminal,
        Self::CredentialUnreadable,
        Self::CredentialNotRegularFile,
        Self::CredentialUnsafePermissions,
        Self::CredentialTooLarge,
        Self::CredentialEmpty,
        Self::CredentialInvalid,
        Self::CaFileUnreadable,
        Self::CaFileNotRegularFile,
        Self::CaFileTooLarge,
        Self::CaFileInvalid,
        Self::InvalidServerUrl,
        Self::PlaintextRefused,
        Self::UserinfoRefused,
        Self::QueryOrFragmentRefused,
        Self::ConnectFailed,
        Self::Timeout,
        Self::TransportFailed,
        Self::RedirectRefused,
        Self::Unauthenticated,
        Self::Forbidden,
        Self::ServerUnavailable,
        Self::UnexpectedStatus,
        Self::ResponseTooLarge,
        Self::UnexpectedContentType,
        Self::CapabilitiesUnavailable,
        Self::UnsupportedCapabilitiesVersion,
        Self::CapabilitiesInvalid,
        Self::UnsupportedSchemaVersion,
        Self::WriteFailed,
        Self::RuntimeUnavailable,
        Self::ClientUnavailable,
    ];

    /// The stable code.
    pub(crate) fn as_str(self) -> &'static str {
        self.entry().0
    }

    /// Fixed text describing the code. Never a value.
    pub(crate) fn message(self) -> &'static str {
        self.entry().1
    }

    pub(crate) fn exit(self) -> Exit {
        self.entry().2
    }

    /// The family, which is also the `docs/ggctl.md` section that explains
    /// the code and how to fix it.
    pub(crate) fn family(self) -> &'static str {
        let code = self.as_str();
        code.split_once('.').map_or(code, |(family, _)| family)
    }

    /// The remediation reference: a repository documentation anchor.
    pub(crate) fn remediation(self) -> &'static str {
        match self.family() {
            "usage" => "docs/ggctl.md#usage-diagnostics",
            "credential" => "docs/ggctl.md#credential-diagnostics",
            "trust" => "docs/ggctl.md#trust-diagnostics",
            "remote" => "docs/ggctl.md#remote-diagnostics",
            "compat" => "docs/ggctl.md#compat-diagnostics",
            "schema" => "docs/ggctl.md#schema-diagnostics",
            "output" => "docs/ggctl.md#output-diagnostics",
            _ => "docs/ggctl.md#internal-diagnostics",
        }
    }

    fn entry(self) -> (&'static str, &'static str, Exit) {
        use Exit::{Denied, Failure, Invalid, Unavailable, Usage};
        match self {
            Self::MissingCommand => ("usage.missing_command", "no command was given", Usage),
            Self::UnknownCommand => ("usage.unknown_command", "the command is not one this ggctl implements", Usage),
            Self::ReservedCommand => (
                "usage.reserved_command",
                "the command name is reserved for operations that stay on the gateway binary",
                Usage,
            ),
            Self::UnknownOption => ("usage.unknown_option", "an argument is not an option this command accepts", Usage),
            Self::MissingValue => ("usage.missing_value", "an option that takes a value was given none", Usage),
            Self::DuplicateOption => ("usage.duplicate_option", "an option was given more than once", Usage),
            Self::UnexpectedValue => ("usage.unexpected_value", "an option that takes no value was given one", Usage),
            Self::UnexpectedArgument => (
                "usage.unexpected_argument",
                "the command takes no further positional argument",
                Usage,
            ),
            Self::MissingArgument => ("usage.missing_argument", "a required argument is missing", Usage),
            Self::InvalidValue => ("usage.invalid_value", "an argument's value is not one the command accepts", Usage),
            Self::ArgumentNotUtf8 => ("usage.argument_not_utf8", "an argument is not valid UTF-8", Usage),
            Self::ConflictingOptions => ("usage.conflicting_options", "two options that exclude each other were both given", Usage),
            Self::OptionRequiresServer => (
                "usage.option_requires_server",
                "a remote option was given without --server",
                Usage,
            ),
            Self::FormatUnsupported => (
                "usage.format_unsupported",
                "this form of the command writes an artifact and takes no --format",
                Usage,
            ),
            Self::SecretOnCommandLine => (
                "usage.secret_on_command_line",
                "ggctl never accepts a secret as a command-line argument",
                Usage,
            ),
            Self::InsecureOptionRefused => (
                "usage.insecure_option_refused",
                "ggctl has no option that disables certificate or hostname verification",
                Usage,
            ),
            Self::CaFileRequiresHttps => (
                "usage.ca_file_requires_https",
                "--ca-file applies only to an https server",
                Usage,
            ),
            Self::StdinIsTerminal => (
                "credential.stdin_is_terminal",
                "--token-stdin reads a piped token and refuses a terminal, where the token would be echoed",
                Usage,
            ),
            Self::CredentialUnreadable => ("credential.unreadable", "the token file could not be opened or read", Failure),
            Self::CredentialNotRegularFile => ("credential.not_regular_file", "the token file is not a regular file", Usage),
            Self::CredentialUnsafePermissions => (
                "credential.unsafe_permissions",
                "the token file is readable or writable by group or other",
                Usage,
            ),
            Self::CredentialTooLarge => ("credential.too_large", "the token is larger than 8 KiB", Usage),
            Self::CredentialEmpty => ("credential.empty", "the token is empty", Usage),
            Self::CredentialInvalid => (
                "credential.invalid",
                "the token is not a single RFC 6750 bearer token",
                Usage,
            ),
            Self::CaFileUnreadable => ("trust.ca_file_unreadable", "the CA file could not be opened or read", Failure),
            Self::CaFileNotRegularFile => ("trust.ca_file_not_regular_file", "the CA file is not a regular file", Usage),
            Self::CaFileTooLarge => ("trust.ca_file_too_large", "the CA file is larger than 1 MiB", Usage),
            Self::CaFileInvalid => (
                "trust.ca_file_invalid",
                "the CA file holds no PEM certificate that can be used as a trust anchor",
                Usage,
            ),
            Self::InvalidServerUrl => (
                "remote.invalid_server_url",
                "--server is not an admin API base of the form https://HOST[:PORT]/v1<ADMIN_PREFIX>",
                Usage,
            ),
            Self::PlaintextRefused => (
                "remote.plaintext_refused",
                "plain http is accepted only for a loopback IP literal; use https",
                Usage,
            ),
            Self::UserinfoRefused => (
                "remote.userinfo_refused",
                "--server must not carry a user name or password",
                Usage,
            ),
            Self::QueryOrFragmentRefused => (
                "remote.query_or_fragment_refused",
                "--server must not carry a query or fragment",
                Usage,
            ),
            Self::ConnectFailed => (
                "remote.connect_failed",
                "the connection or TLS handshake to the server failed before any request was sent",
                Unavailable,
            ),
            Self::Timeout => ("remote.timeout", "the request did not complete within the timeout", Failure),
            Self::TransportFailed => ("remote.transport_failed", "the request failed after the connection was established", Failure),
            Self::RedirectRefused => ("remote.redirect_refused", "the server answered with a redirect, which ggctl never follows", Failure),
            Self::Unauthenticated => ("remote.unauthenticated", "the server refused the request as unauthenticated (HTTP 401)", Denied),
            Self::Forbidden => ("remote.forbidden", "the server refused the request as unauthorized (HTTP 403)", Denied),
            Self::ServerUnavailable => (
                "remote.server_unavailable",
                "the server reported that a dependency is unavailable (HTTP 503)",
                Unavailable,
            ),
            Self::UnexpectedStatus => ("remote.unexpected_status", "the server answered with an unexpected HTTP status", Failure),
            Self::ResponseTooLarge => ("remote.response_too_large", "the server's response is larger than ggctl accepts", Failure),
            Self::UnexpectedContentType => (
                "remote.unexpected_content_type",
                "the server's response is not application/json",
                Failure,
            ),
            Self::CapabilitiesUnavailable => (
                "compat.capabilities_unavailable",
                "the server does not serve the configuration capability document (HTTP 404)",
                Invalid,
            ),
            Self::UnsupportedCapabilitiesVersion => (
                "compat.unsupported_capabilities_version",
                "the server's capability document is a version this ggctl does not read",
                Invalid,
            ),
            Self::CapabilitiesInvalid => (
                "compat.capabilities_invalid",
                "the server's capability document is not a valid document of its version",
                Invalid,
            ),
            Self::UnsupportedSchemaVersion => (
                "schema.unsupported_api_version",
                "this ggctl publishes no schema for that kind at that document version",
                Invalid,
            ),
            Self::WriteFailed => ("output.write_failed", "the output could not be written", Failure),
            Self::RuntimeUnavailable => ("internal.runtime_unavailable", "the asynchronous runtime could not be started", Failure),
            Self::ClientUnavailable => ("internal.client_unavailable", "the HTTP client could not be built", Failure),
        }
    }
}

/// One diagnostic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Diagnostic {
    pub(crate) code: Code,
    /// The 1-based position of the argument after `ggctl` it is about.
    pub(crate) argument: Option<usize>,
    /// Fixed guidance chosen by the caller from static text.
    pub(crate) hint: Option<&'static str>,
}

impl Diagnostic {
    pub(crate) fn new(code: Code) -> Self {
        Self {
            code,
            argument: None,
            hint: None,
        }
    }

    pub(crate) fn at(code: Code, argument: usize) -> Self {
        Self {
            argument: Some(argument),
            ..Self::new(code)
        }
    }

    pub(crate) fn with_hint(mut self, hint: &'static str) -> Self {
        self.hint = Some(hint);
        self
    }

    /// Every `ggctl` diagnostic is an error today; warnings arrive with
    /// `validate` (#242 PR 8).
    pub(crate) fn severity(&self) -> &'static str {
        "error"
    }
}

impl From<Code> for Diagnostic {
    fn from(code: Code) -> Self {
        Self::new(code)
    }
}

/// The human form written to standard error.
impl fmt::Display for Diagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "ggctl: {}: {}: {}",
            self.severity(),
            self.code.as_str(),
            self.code.message()
        )?;
        if let Some(argument) = self.argument {
            write!(formatter, " (argument {argument})")?;
        }
        if let Some(hint) = self.hint {
            write!(formatter, "\n  hint: {hint}")?;
        }
        write!(formatter, "\n  see: {}", self.code.remediation())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn exit_codes_are_the_published_table() {
        let codes: Vec<_> = Exit::ALL.iter().map(|exit| exit.code()).collect();
        assert_eq!(codes, [0, 1, 2, 3, 4, 5, 6, 7, 8]);
        let names: BTreeSet<_> = Exit::ALL.iter().map(|exit| exit.name()).collect();
        assert_eq!(names.len(), Exit::ALL.len());
    }

    #[test]
    fn codes_are_unique_lowercase_family_reason_pairs_in_documented_families() {
        let mut seen = BTreeSet::new();
        for code in Code::ALL {
            let text = code.as_str();
            assert!(seen.insert(text), "{text} is not unique");
            let (family, reason) = text.split_once('.').expect("family.reason");
            assert!(FAMILIES.contains(&family), "{text}");
            assert!(code
                .remediation()
                .ends_with(&format!("#{family}-diagnostics")));
            for segment in [family, reason] {
                assert!(
                    segment
                        .bytes()
                        .next()
                        .is_some_and(|byte| byte.is_ascii_lowercase())
                        && segment.bytes().all(|byte| {
                            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'
                        }),
                    "{text}"
                );
            }
            assert!(!code.message().is_empty());
        }
    }

    fn reference() -> String {
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../docs/ggctl.md"))
            .expect("docs/ggctl.md should be readable")
            .replace("\r\n", "\n")
    }

    /// The text of one `### Heading` section, up to the next heading.
    fn section<'a>(document: &'a str, heading: &str) -> &'a str {
        let start = document
            .find(&format!("\n### {heading}\n"))
            .unwrap_or_else(|| panic!("docs/ggctl.md has no `### {heading}` section"));
        let body = &document[start + heading.len() + 6..];
        body.find("\n#").map_or(body, |end| &body[..end])
    }

    #[test]
    fn the_reference_documents_every_code_in_its_family_with_its_exit() {
        let document = reference();
        for family in FAMILIES {
            let mut heading = family.to_owned();
            heading[..1].make_ascii_uppercase();
            let section = section(&document, &format!("{heading} diagnostics"));
            let documented: Vec<_> = section
                .lines()
                .filter_map(|line| line.strip_prefix("| `"))
                .filter_map(|line| line.split_once('`'))
                .map(|(code, rest)| (code.to_owned(), rest.to_owned()))
                .collect();
            let codes: Vec<_> = Code::ALL
                .iter()
                .filter(|code| code.family() == *family)
                .collect();
            assert_eq!(
                documented
                    .iter()
                    .map(|(code, _)| code.as_str())
                    .collect::<Vec<_>>(),
                codes.iter().map(|code| code.as_str()).collect::<Vec<_>>(),
                "the {family} section must list exactly its codes, in order"
            );
            for ((_, row), code) in documented.iter().zip(codes) {
                assert!(
                    row.starts_with(&format!(" | {} | ", code.exit().code())),
                    "{}: documented exit differs",
                    code.as_str()
                );
            }
        }
    }

    #[test]
    fn the_reference_documents_every_exit_code() {
        let document = reference();
        for exit in Exit::ALL {
            assert!(
                document.contains(&format!("\n| `{}` | `{}` | ", exit.code(), exit.name())),
                "{}",
                exit.name()
            );
        }
    }

    #[test]
    fn the_outcome_that_may_have_committed_is_never_hidden_and_retryable_never_masks() {
        let diagnostics = [
            Diagnostic::new(Code::ConnectFailed),
            Diagnostic::new(Code::Unauthenticated),
            Diagnostic::new(Code::Timeout),
        ];
        assert_eq!(Exit::of(&diagnostics), Exit::Failure);
        assert_eq!(Exit::of(&diagnostics[..2]), Exit::Denied);
        assert_eq!(Exit::of(&diagnostics[..1]), Exit::Unavailable);
        assert_eq!(
            Exit::of(&[
                Diagnostic::new(Code::ServerUnavailable),
                Diagnostic::new(Code::CapabilitiesInvalid)
            ]),
            Exit::Invalid
        );
        assert_eq!(Exit::of(&[]), Exit::Success);
    }

    #[test]
    fn the_human_form_names_the_position_and_never_a_value() {
        let text = Diagnostic::at(Code::UnknownOption, 3)
            .with_hint("run `ggctl help`")
            .to_string();
        assert_eq!(
            text,
            "ggctl: error: usage.unknown_option: an argument is not an option this command accepts (argument 3)\n  hint: run `ggctl help`\n  see: docs/ggctl.md#usage-diagnostics"
        );
    }
}
