//! The command table and the argument parser.
//!
//! One static table defines every command, argument and option. Help text
//! (`help.rs`) and shell completion (`completion.rs`) are generated from it,
//! and the parser accepts exactly what it lists, so the three cannot drift.
//!
//! Before anything else the parser refuses any argument that looks like a
//! secret-carrying or verification-disabling option, wherever it appears, so
//! a token typed as `--token=...` is refused rather than parsed, echoed or
//! reported back. Diagnostics name argument positions, never spellings.

use std::ffi::{OsStr, OsString};

use crate::{
    diagnostic::{Code, Diagnostic, Exit},
    report::Io,
};

/// What an argument or option value holds; completion uses it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ValueKind {
    /// A local file path.
    Path,
    /// A URL.
    Url,
    /// A whole number of seconds.
    Seconds,
    /// A document version string.
    Text,
    /// One of a fixed set of words.
    Choice(&'static [&'static str]),
}

#[derive(Debug)]
pub(crate) struct OptionSpec {
    pub(crate) name: &'static str,
    /// The placeholder and kind of the option's value; `None` for a flag.
    pub(crate) value: Option<(&'static str, ValueKind)>,
    pub(crate) help: &'static str,
}

#[derive(Debug)]
pub(crate) struct ArgumentSpec {
    pub(crate) name: &'static str,
    pub(crate) kind: ValueKind,
    pub(crate) required: bool,
    pub(crate) help: &'static str,
}

pub(crate) struct CommandSpec {
    pub(crate) name: &'static str,
    pub(crate) summary: &'static str,
    pub(crate) description: &'static [&'static str],
    pub(crate) arguments: &'static [ArgumentSpec],
    pub(crate) options: &'static [OptionSpec],
    pub(crate) run: fn(&Invocation, &mut Io<'_>) -> Exit,
}

impl std::fmt::Debug for CommandSpec {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CommandSpec")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

pub(crate) const FORMAT_HUMAN: &str = "human";
pub(crate) const FORMAT_JSON: &str = "json";

pub(crate) const SHELLS: &[&str] = &["bash", "zsh", "fish", "powershell"];
pub(crate) const SCHEMA_KINDS: &[&str] = &[
    gateway_config::documents::BUNDLE_KIND,
    gateway_config::documents::DEPLOYMENT_KIND,
    gateway_config::documents::CAPABILITIES_KIND,
    gateway_config::documents::REPORT_KIND,
];
const COMMAND_NAMES: &[&str] = &["version", "schema", "completion", "help"];

const FORMAT: OptionSpec = OptionSpec {
    name: "--format",
    value: Some(("FORMAT", ValueKind::Choice(&[FORMAT_HUMAN, FORMAT_JSON]))),
    help: "human (default) or json: one GgctlReport document on standard output",
};
const SERVER: OptionSpec = OptionSpec {
    name: "--server",
    value: Some(("URL", ValueKind::Url)),
    help: "the admin API base, https://HOST[:PORT]/v1<ADMIN_PREFIX>; plain http only for a loopback IP literal",
};
const CA_FILE: OptionSpec = OptionSpec {
    name: "--ca-file",
    value: Some(("PATH", ValueKind::Path)),
    help: "a PEM file of trust anchors added to the platform's for an https --server",
};
const TOKEN_STDIN: OptionSpec = OptionSpec {
    name: "--token-stdin",
    value: None,
    help: "read the admin bearer token from standard input, which must be a pipe or file",
};
const TOKEN_FILE: OptionSpec = OptionSpec {
    name: "--token-file",
    value: Some(("PATH", ValueKind::Path)),
    help: "read the admin bearer token from a regular file of at most 8 KiB, owner-only on Unix",
};
const TIMEOUT: OptionSpec = OptionSpec {
    name: "--timeout",
    value: Some(("SECONDS", ValueKind::Seconds)),
    help: "the time allowed for each request, 1 to 300 seconds (default 30)",
};
const API_VERSION: OptionSpec = OptionSpec {
    name: "--api-version",
    value: Some(("VERSION", ValueKind::Text)),
    help: "the document version to print (default: the newest this ggctl publishes)",
};

pub(crate) const COMMANDS: &[CommandSpec] = &[
    CommandSpec {
        name: "version",
        summary: "Print this ggctl's version and, with --server, check a gateway is compatible",
        description: &[
            "Prints the ggctl version and the document versions whose schemas it publishes.",
            "With --server it reads the gateway's configuration capability document \
             (GET <server>/config/capabilities, permission admin:config:read) and reports the \
             gateway version and whether this ggctl can work with it. It exits 3 when it \
             cannot. A configuration command refuses a server this check rejects; this \
             command still reports what it found.",
        ],
        arguments: &[],
        options: &[SERVER, CA_FILE, TOKEN_STDIN, TOKEN_FILE, TIMEOUT, FORMAT],
        run: crate::version::run,
    },
    CommandSpec {
        name: "schema",
        summary: "List the published document schemas or print one",
        description: &[
            "Without KIND, lists every document kind and version this ggctl publishes a \
             JSON Schema (Draft 2020-12) for. With KIND, writes that schema to standard \
             output exactly as published under docs/schemas.",
            "A schema is necessary but not sufficient: the gateway's reader is authoritative.",
        ],
        arguments: &[ArgumentSpec {
            name: "KIND",
            kind: ValueKind::Choice(SCHEMA_KINDS),
            required: false,
            help: "the document kind to print",
        }],
        options: &[API_VERSION, FORMAT],
        run: crate::schema::run,
    },
    CommandSpec {
        name: "completion",
        summary: "Write a shell completion script",
        description: &[
            "Writes a completion script for SHELL to standard output, generated from the \
             same command table as ggctl help. For example: \
             ggctl completion bash > /etc/bash_completion.d/ggctl",
        ],
        arguments: &[ArgumentSpec {
            name: "SHELL",
            kind: ValueKind::Choice(SHELLS),
            required: true,
            help: "bash, zsh, fish or powershell",
        }],
        options: &[],
        run: crate::completion::run,
    },
    CommandSpec {
        name: "help",
        summary: "Print help for ggctl or one command",
        description: &["Prints the help for COMMAND, or the overview without one."],
        arguments: &[ArgumentSpec {
            name: "COMMAND",
            kind: ValueKind::Choice(COMMAND_NAMES),
            required: false,
            help: "the command to describe",
        }],
        options: &[],
        run: crate::help::run,
    },
];

/// Names `ggctl` keeps for operations that stay on the `gateway` binary,
/// with the fixed hint naming what to run instead (ADR-0008).
const RESERVED: &[(&str, &str)] = &[
    (
        "db",
        "database migration stays on the gateway binary: run `gateway migrate check` or \
         `gateway migrate up` where the database role and network are",
    ),
    (
        "cluster",
        "cluster operations stay on the gateway binary: run `gateway cluster-members`, \
         `gateway maintenance-run` or `gateway import-standalone`",
    ),
];

/// Option names that would carry a secret. Matched exactly, case-insensitive,
/// after the leading dashes and before any `=`.
const SECRET_OPTIONS: &[&str] = &[
    "token",
    "bearer",
    "bearer-token",
    "access-token",
    "auth-token",
    "id-token",
    "authorization",
    "password",
    "passwd",
    "secret",
    "client-secret",
    "api-key",
    "apikey",
    "credential",
    "credentials",
];

/// Option names that would disable certificate or hostname verification.
const INSECURE_OPTIONS: &[&str] = &[
    "insecure",
    "insecure-skip-tls-verify",
    "skip-tls-verify",
    "tls-skip-verify",
    "no-verify",
    "no-tls-verify",
    "k",
];

const HINT_HELP: &str =
    "run `ggctl help` for the commands and `ggctl help COMMAND` for its options";
const HINT_TOKEN: &str =
    "pipe the token to --token-stdin or name an owner-only file with --token-file";
const HINT_INSECURE: &str = "add the server's CA with --ca-file instead";

/// A parsed command line.
#[derive(Debug)]
pub(crate) enum Parsed {
    Run(Invocation),
    /// `--help`, `-h` or `help`: the overview or one command's help.
    Help(Option<&'static CommandSpec>),
    /// `--version`.
    Version,
}

/// A command and its arguments, each with its 1-based position.
#[derive(Debug)]
pub(crate) struct Invocation {
    pub(crate) command: &'static CommandSpec,
    positionals: Vec<(usize, OsString)>,
    options: Vec<(&'static str, usize, Option<OsString>)>,
}

impl Invocation {
    pub(crate) fn flag(&self, name: &str) -> Option<usize> {
        self.options
            .iter()
            .find(|(option, _, _)| *option == name)
            .map(|(_, position, _)| *position)
    }

    pub(crate) fn value(&self, name: &str) -> Option<(usize, &OsStr)> {
        self.options
            .iter()
            .find(|(option, _, _)| *option == name)
            .and_then(|(_, position, value)| value.as_deref().map(|value| (*position, value)))
    }

    /// A value the parser already checked is UTF-8 (every non-path kind).
    pub(crate) fn text(&self, name: &str) -> Option<(usize, &str)> {
        self.value(name)
            .and_then(|(position, value)| value.to_str().map(|value| (position, value)))
    }

    pub(crate) fn positional(&self, index: usize) -> Option<(usize, &str)> {
        self.positionals
            .get(index)
            .and_then(|(position, value)| value.to_str().map(|value| (*position, value)))
    }
}

/// Parses the arguments after the program name.
pub(crate) fn parse(arguments: &[OsString]) -> Result<Parsed, Diagnostic> {
    refuse_dangerous_options(arguments)?;
    let Some(first) = arguments.first() else {
        return Err(Diagnostic::new(Code::MissingCommand).with_hint(HINT_HELP));
    };
    match first.to_str() {
        Some("--help" | "-h") => return Ok(Parsed::Help(None)),
        Some("--version") => return Ok(Parsed::Version),
        Some(word) if word.starts_with('-') => {
            return Err(Diagnostic::at(Code::UnknownOption, 1).with_hint(HINT_HELP))
        }
        Some(word) => {
            if let Some((_, hint)) = RESERVED.iter().find(|(name, _)| *name == word) {
                return Err(Diagnostic::at(Code::ReservedCommand, 1).with_hint(hint));
            }
        }
        None => return Err(Diagnostic::at(Code::ArgumentNotUtf8, 1)),
    }
    let Some(command) = COMMANDS
        .iter()
        .find(|command| Some(command.name) == first.to_str())
    else {
        return Err(Diagnostic::at(Code::UnknownCommand, 1).with_hint(HINT_HELP));
    };
    let invocation = parse_command(command, arguments)?;
    if invocation.flag("--help").is_some() {
        return Ok(Parsed::Help(Some(command)));
    }
    if command.name == "help" {
        let topic = invocation
            .positional(0)
            .and_then(|(_, name)| COMMANDS.iter().find(|command| command.name == name));
        return Ok(Parsed::Help(topic));
    }
    Ok(Parsed::Run(invocation))
}

fn parse_command(
    command: &'static CommandSpec,
    arguments: &[OsString],
) -> Result<Invocation, Diagnostic> {
    let mut invocation = Invocation {
        command,
        positionals: Vec::new(),
        options: Vec::new(),
    };
    let mut only_positionals = false;
    let mut index = 1;
    while index < arguments.len() {
        let position = index + 1;
        let argument = &arguments[index];
        index += 1;
        let Some(text) = argument.to_str() else {
            // A non-UTF-8 argument can only be a path option's value, which
            // is consumed below with its option; anywhere else it is refused.
            return Err(Diagnostic::at(Code::ArgumentNotUtf8, position));
        };
        if only_positionals || text == "-" || !text.starts_with('-') {
            if invocation.positionals.len() == command.arguments.len() {
                return Err(Diagnostic::at(Code::UnexpectedArgument, position).with_hint(HINT_HELP));
            }
            invocation.positionals.push((position, argument.clone()));
            continue;
        }
        if text == "--" {
            only_positionals = true;
            continue;
        }
        if text == "--help" || text == "-h" {
            invocation.options.push(("--help", position, None));
            return Ok(invocation);
        }
        let (name, inline) = match text.split_once('=') {
            Some((name, value)) => (name, Some(value)),
            None => (text, None),
        };
        let Some(option) = command.options.iter().find(|option| option.name == name) else {
            return Err(Diagnostic::at(Code::UnknownOption, position).with_hint(HINT_HELP));
        };
        if invocation.flag(option.name).is_some() {
            return Err(Diagnostic::at(Code::DuplicateOption, position));
        }
        let value = match (option.value, inline) {
            (None, None) => None,
            (None, Some(_)) => return Err(Diagnostic::at(Code::UnexpectedValue, position)),
            (Some((_, kind)), Some(value)) => {
                Some(checked_value(kind, OsStr::new(value), position)?)
            }
            (Some((_, kind)), None) => {
                let Some(value) = arguments.get(index) else {
                    return Err(Diagnostic::at(Code::MissingValue, position));
                };
                index += 1;
                Some(checked_value(kind, value, position + 1)?)
            }
        };
        invocation.options.push((option.name, position, value));
    }
    for (spec, index) in command.arguments.iter().zip(0..) {
        match invocation.positionals.get(index) {
            Some((position, value)) => {
                checked_value(spec.kind, value, *position)?;
            }
            None if spec.required => {
                return Err(Diagnostic::new(Code::MissingArgument).with_hint(HINT_HELP))
            }
            None => {}
        }
    }
    Ok(invocation)
}

/// Checks a value against its kind. Only a path may be non-UTF-8.
fn checked_value(kind: ValueKind, value: &OsStr, position: usize) -> Result<OsString, Diagnostic> {
    if value.is_empty() {
        return Err(Diagnostic::at(Code::InvalidValue, position));
    }
    if kind == ValueKind::Path {
        return Ok(value.to_owned());
    }
    let Some(text) = value.to_str() else {
        return Err(Diagnostic::at(Code::ArgumentNotUtf8, position));
    };
    if let ValueKind::Choice(choices) = kind {
        if !choices.contains(&text) {
            return Err(Diagnostic::at(Code::InvalidValue, position));
        }
    }
    Ok(value.to_owned())
}

/// Refuses a secret-carrying or verification-disabling option anywhere on
/// the command line, before any other parsing.
fn refuse_dangerous_options(arguments: &[OsString]) -> Result<(), Diagnostic> {
    for (index, argument) in arguments.iter().enumerate() {
        let text = argument.to_string_lossy();
        if text == "--" {
            break;
        }
        let Some(name) = text.strip_prefix('-') else {
            continue;
        };
        let name = name.strip_prefix('-').unwrap_or(name);
        let name = name
            .split_once('=')
            .map_or(name, |(name, _)| name)
            .to_ascii_lowercase();
        if SECRET_OPTIONS.contains(&name.as_str()) {
            return Err(Diagnostic::at(Code::SecretOnCommandLine, index + 1).with_hint(HINT_TOKEN));
        }
        if INSECURE_OPTIONS.contains(&name.as_str()) {
            return Err(
                Diagnostic::at(Code::InsecureOptionRefused, index + 1).with_hint(HINT_INSECURE)
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
