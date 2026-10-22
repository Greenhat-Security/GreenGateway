//! Help text, generated from the command table.

use std::fmt::Write as _;

use crate::{
    cli::{CommandSpec, Invocation, COMMANDS},
    diagnostic::Exit,
    report::{self, Io},
};

const WIDTH: usize = 80;

/// `ggctl help [COMMAND]`. The parser answers it as a help request; this is
/// the same answer for a caller that runs the invocation directly.
pub(crate) fn run(invocation: &Invocation, io: &mut Io<'_>) -> Exit {
    let topic = invocation
        .positional(0)
        .and_then(|(_, name)| COMMANDS.iter().find(|command| command.name == name));
    report::artifact(io, &text(topic))
}

/// The overview, or one command's help.
pub(crate) fn text(command: Option<&CommandSpec>) -> String {
    match command {
        Some(command) => command_help(command),
        None => overview(),
    }
}

fn overview() -> String {
    let mut text = format!(
        "ggctl {} - the GreenGateway operator CLI\n\n\
         Usage: ggctl <COMMAND> [OPTIONS]\n       ggctl help [COMMAND]\n\nCommands:\n",
        env!("CARGO_PKG_VERSION")
    );
    let width = COMMANDS
        .iter()
        .map(|command| command.name.len())
        .max()
        .unwrap_or(0);
    for command in COMMANDS {
        push_entry(&mut text, command.name, width, command.summary);
    }
    text.push_str("\nExit codes:\n");
    for exit in Exit::ALL {
        push_entry(&mut text, &exit.code().to_string(), 1, exit.meaning());
    }
    text.push('\n');
    push_paragraph(
        &mut text,
        "",
        "ggctl reads no configuration file and no environment variable, and makes no network \
         request unless a command is given --server. It never accepts a secret as an argument: \
         pass an admin bearer token with --token-stdin or --token-file.",
    );
    text.push('\n');
    push_paragraph(&mut text, "", "Reference: docs/ggctl.md");
    text
}

fn command_help(command: &CommandSpec) -> String {
    let mut text = format!("Usage: {}\n\n", usage(command));
    for paragraph in command.description {
        push_paragraph(&mut text, "", paragraph);
        text.push('\n');
    }
    if !command.arguments.is_empty() {
        text.push_str("Arguments:\n");
        let width = command
            .arguments
            .iter()
            .map(|argument| argument.name.len())
            .max()
            .unwrap_or(0);
        for argument in command.arguments {
            push_entry(&mut text, argument.name, width, argument.help);
        }
        text.push('\n');
    }
    text.push_str("Options:\n");
    let labels: Vec<String> = command
        .options
        .iter()
        .map(|option| match option.value {
            Some((placeholder, _)) => format!("{} {placeholder}", option.name),
            None => option.name.to_owned(),
        })
        .chain(std::iter::once("-h, --help".to_owned()))
        .collect();
    let width = labels.iter().map(String::len).max().unwrap_or(0);
    let helps = command
        .options
        .iter()
        .map(|option| option.help)
        .chain(std::iter::once("print this help"));
    for (label, help) in labels.iter().zip(helps) {
        push_entry(&mut text, label, width, help);
    }
    text
}

/// `ggctl NAME [ARGUMENT] REQUIRED [OPTIONS]`.
pub(crate) fn usage(command: &CommandSpec) -> String {
    let mut usage = format!("ggctl {}", command.name);
    for argument in command.arguments {
        if argument.required {
            let _ = write!(usage, " {}", argument.name);
        } else {
            let _ = write!(usage, " [{}]", argument.name);
        }
    }
    if !command.options.is_empty() {
        usage.push_str(" [OPTIONS]");
    }
    usage
}

/// Two-column entry, the description wrapped under itself.
fn push_entry(text: &mut String, label: &str, width: usize, description: &str) {
    let indent = " ".repeat(2 + width + 2);
    let first = format!("  {label:<width$}  ");
    push_wrapped(text, &first, &indent, description);
}

fn push_paragraph(text: &mut String, indent: &str, paragraph: &str) {
    push_wrapped(text, indent, indent, paragraph);
}

fn push_wrapped(text: &mut String, first: &str, indent: &str, words: &str) {
    let mut line = first.to_owned();
    let mut empty = true;
    for word in words.split_whitespace() {
        if !empty && line.len() + 1 + word.len() > WIDTH {
            text.push_str(line.trim_end());
            text.push('\n');
            line = indent.to_owned();
            empty = true;
        }
        if !empty {
            line.push(' ');
        }
        line.push_str(word);
        empty = false;
    }
    text.push_str(line.trim_end());
    text.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_overview_lists_every_command_and_exit_code() {
        let overview = text(None);
        for command in COMMANDS {
            assert!(
                overview.contains(&format!("\n  {}", command.name)),
                "{}",
                command.name
            );
        }
        for exit in Exit::ALL {
            assert!(overview.contains(&format!("\n  {}  ", exit.code())));
        }
        assert!(
            overview.lines().all(|line| line.len() <= WIDTH),
            "{overview}"
        );
    }

    #[test]
    fn command_help_lists_every_argument_and_option() {
        for command in COMMANDS {
            let help = text(Some(command));
            assert!(help.starts_with(&format!("Usage: ggctl {}", command.name)));
            for argument in command.arguments {
                assert!(help.contains(argument.name), "{}", argument.name);
            }
            for option in command.options {
                assert!(help.contains(option.name), "{}", option.name);
            }
            assert!(help.contains("-h, --help"));
            assert!(help.lines().all(|line| line.len() <= WIDTH), "{help}");
        }
    }

    #[test]
    fn usage_marks_optional_arguments() {
        let schema = COMMANDS
            .iter()
            .find(|command| command.name == "schema")
            .expect("schema");
        assert_eq!(usage(schema), "ggctl schema [KIND] [OPTIONS]");
        let completion = COMMANDS
            .iter()
            .find(|command| command.name == "completion")
            .expect("completion");
        assert_eq!(usage(completion), "ggctl completion SHELL");
    }
}
