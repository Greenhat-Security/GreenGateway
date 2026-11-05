//! The environment file grammar (issues #241 and #242; ADR-0008, "`ggctl`").
//!
//! `gateway import-standalone --from FILE` reads its source deployment's
//! environment from a `KEY=VALUE` file, and `ggctl validate`, `ggctl doctor`
//! and `ggctl diff` read one with `--env FILE` (and `--against-env FILE`), so a
//! deployment that stays in environment mode gets the same offline checks.
//! Both read it with [`EnvFile::parse`], so the two cannot disagree about
//! what a file sets. The grammar is the plain shape `.env.example` ships and
//! `docker compose env_file` and systemd `EnvironmentFile` read:
//!
//! - the text is split into lines as [`str::lines`] splits it: at each `\n`,
//!   dropping a `\r` before it;
//! - each line loses its leading and trailing whitespace, and is ignored when
//!   nothing is left or it starts with `#`;
//! - otherwise one leading `export ` (with exactly one space) is dropped, and
//!   the line must contain `=`: the key is what comes before the first `=`,
//!   without surrounding whitespace, and must not be empty; the value is
//!   everything after that `=`, verbatim. A value keeps its quotes, its
//!   leading spaces, every further `=` and every `#`: nothing is unquoted,
//!   unescaped, expanded or interpolated, and no line continues another;
//! - a key assigned more than once keeps its last value, as every reader of
//!   such a file applies it.
//!
//! The file is data. Nothing here runs or sources it or reads the process
//! environment, and nothing in it is echoed: a malformed line and a repeated
//! key are reported by line number, and a key by name only when it is one of
//! the configuration compiler's inventoried settings, as the inventory spells
//! it ([`compiler::inventory::config_input`]). Reading the file is the
//! caller's: the import reads its `--from` file as it always has, and `ggctl`
//! reads a regular file of at most [`MAX_ENV_FILE_BYTES`].
//!
//! [`EnvFile::compile`] runs the configuration compiler over the variables a
//! file sets, through the same kind of reader the gateway's
//! `Config::from_env_vars` takes, so a file's verdict is the verdict the
//! gateway would reach with exactly those variables in its environment.

use std::{collections::BTreeMap, env::VarError, fmt};

use crate::compiler::{self, ConfigError, ConfigPlan};

/// The largest environment file `ggctl` reads: 1 MiB.
///
/// The gateway's own configuration fits in a small fraction of it: about 150
/// settings, the largest of them JSON documents (`AUTH_PROVIDERS`,
/// `UPSTREAM_ROUTES`, the secret alias and provider documents) that the
/// compiler bounds far below this. The bound is applied before the file is
/// read into memory.
pub const MAX_ENV_FILE_BYTES: usize = 1024 * 1024;

/// One key's effective assignment: its last.
#[derive(Clone, Eq, PartialEq)]
struct Assignment {
    value: String,
    /// The 1-based line it is on.
    line: usize,
}

/// A key assigned again after an earlier assignment, which the later one
/// overrides.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DuplicateKey {
    /// The 1-based line of the repeated assignment.
    pub line: usize,
    /// The key, when it is an inventoried setting, as the inventory spells
    /// it; `None` for any other key, which is never echoed.
    pub setting: Option<&'static str>,
}

/// An environment file, parsed by the grammar above.
///
/// `Debug` shows counts only: a value may be a key or a client secret.
#[derive(Clone, Eq, PartialEq)]
pub struct EnvFile {
    variables: BTreeMap<String, Assignment>,
    malformed: Vec<usize>,
    duplicates: Vec<DuplicateKey>,
}

impl EnvFile {
    /// Parses `text`. Every line is examined: each malformed one is
    /// recorded by number and skipped, and each repeated key by the line
    /// that repeats it, so one pass reports every problem.
    pub fn parse(text: &str) -> Self {
        let mut variables: BTreeMap<String, Assignment> = BTreeMap::new();
        let mut malformed = Vec::new();
        let mut duplicates = Vec::new();
        for (index, line) in text.lines().enumerate() {
            let number = index + 1;
            let trimmed = line.trim_end().trim_start();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            // `export KEY=VALUE` is the other shape operators write.
            let assignment = trimmed.strip_prefix("export ").unwrap_or(trimmed);
            let Some((key, value)) = assignment.split_once('=') else {
                malformed.push(number);
                continue;
            };
            let key = key.trim();
            if key.is_empty() {
                malformed.push(number);
                continue;
            }
            let previous = variables.insert(
                key.to_owned(),
                Assignment {
                    value: value.to_owned(),
                    line: number,
                },
            );
            if previous.is_some() {
                duplicates.push(DuplicateKey {
                    line: number,
                    setting: compiler::inventory::config_input(key),
                });
            }
        }
        Self {
            variables,
            malformed,
            duplicates,
        }
    }

    /// The value the file sets for `name`, or `NotPresent`: the reader the
    /// configuration compiler takes. A file is text, so a value is never
    /// `NotUnicode`.
    pub fn var(&self, name: &str) -> Result<String, VarError> {
        self.variables
            .get(name)
            .map(|assignment| assignment.value.clone())
            .ok_or(VarError::NotPresent)
    }

    /// The 1-based line of `name`'s effective (last) assignment.
    pub fn line(&self, name: &str) -> Option<usize> {
        self.variables.get(name).map(|assignment| assignment.line)
    }

    /// The 1-based numbers of the lines that are neither blank, a comment
    /// nor an assignment, in order.
    pub fn malformed_lines(&self) -> &[usize] {
        &self.malformed
    }

    /// Every assignment of a key that an earlier line already assigned, in
    /// order.
    pub fn duplicate_keys(&self) -> &[DuplicateKey] {
        &self.duplicates
    }

    /// How many distinct keys the file assigns.
    pub fn len(&self) -> usize {
        self.variables.len()
    }

    /// Whether the file assigns no key at all.
    pub fn is_empty(&self) -> bool {
        self.variables.is_empty()
    }

    /// The inventoried settings the file assigns, in the order the compiler
    /// reads them, as the inventory spells them.
    pub fn settings(&self) -> Vec<&'static str> {
        compiler::inventory::CONFIG_INPUTS
            .iter()
            .copied()
            .filter(|setting| self.variables.contains_key(*setting))
            .collect()
    }

    /// Compiles the variables the file sets, and nothing else: every other
    /// input is unset, as it would be in a process environment holding only
    /// these. A malformed line sets nothing, so a file with one still
    /// compiles from its other lines; the caller decides what the malformed
    /// line means for its verdict.
    pub fn compile(&self) -> Result<ConfigPlan, ConfigError> {
        compiler::compile(|name| self.var(name))
    }

    /// Every key and its effective value, for a caller that keeps a map.
    pub fn into_variables(self) -> BTreeMap<String, String> {
        self.variables
            .into_iter()
            .map(|(key, assignment)| (key, assignment.value))
            .collect()
    }
}

impl fmt::Debug for EnvFile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnvFile")
            .field("variables", &self.variables.len())
            .field("malformed_lines", &self.malformed)
            .field("duplicate_keys", &self.duplicates)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CANARY: &str = "zqcanaryenvfile";

    fn value(file: &EnvFile, name: &str) -> Option<String> {
        file.var(name).ok()
    }

    #[test]
    fn the_shipped_shape_parses_with_the_last_assignment_winning() {
        let file = EnvFile::parse(
            "# a comment\n\
             \n\
             POLICY_FILE=/srv/policy.json\n\
             export TOOLS_FILE=/srv/tools.json\n\
             BLANK=\n\
             WITH_EQUALS=a=b=c\n\
             POLICY_FILE=/srv/policy-2.json\n",
        );
        assert!(file.malformed_lines().is_empty());
        assert_eq!(
            value(&file, "POLICY_FILE").as_deref(),
            Some("/srv/policy-2.json")
        );
        assert_eq!(file.line("POLICY_FILE"), Some(7));
        assert_eq!(
            value(&file, "TOOLS_FILE").as_deref(),
            Some("/srv/tools.json")
        );
        assert_eq!(value(&file, "BLANK").as_deref(), Some(""));
        assert_eq!(value(&file, "WITH_EQUALS").as_deref(), Some("a=b=c"));
        assert_eq!(file.var("UNSET"), Err(VarError::NotPresent));
        assert_eq!(
            file.duplicate_keys(),
            &[DuplicateKey {
                line: 7,
                setting: Some("POLICY_FILE")
            }]
        );
        assert_eq!(file.len(), 4);
        assert_eq!(file.settings(), ["POLICY_FILE", "TOOLS_FILE"]);
    }

    #[test]
    fn a_value_is_taken_verbatim_after_the_first_equals_sign() {
        let file = EnvFile::parse(
            "  QUOTED=\"required\"  \r\n\
             SINGLE='a b'\n\
             LEADING=  kept\n\
             HASH=a # not a comment\n\
             \t# an indented comment\n\
             export\tTABBED=1\n\
             export  TWO_SPACES=1\n\
             SPACED KEY = x\n",
        );
        assert!(file.malformed_lines().is_empty());
        assert_eq!(value(&file, "QUOTED").as_deref(), Some("\"required\""));
        assert_eq!(value(&file, "SINGLE").as_deref(), Some("'a b'"));
        assert_eq!(value(&file, "LEADING").as_deref(), Some("  kept"));
        assert_eq!(value(&file, "HASH").as_deref(), Some("a # not a comment"));
        // Only `export ` with exactly one space is the export shape; the key
        // is whatever precedes the first `=`, trimmed.
        assert_eq!(value(&file, "export\tTABBED").as_deref(), Some("1"));
        assert_eq!(value(&file, "TWO_SPACES").as_deref(), Some("1"));
        assert_eq!(value(&file, "SPACED KEY").as_deref(), Some(" x"));
        assert!(file.settings().is_empty());
    }

    #[test]
    fn every_malformed_line_and_repeated_key_is_reported_by_number_only() {
        let text = format!(
            "AUTH_MODE=required\n\
             {CANARY}-a-line-without-an-equals-sign\n\
             ={CANARY}\n\
             export {CANARY}\n\
             AUTH_MODE={CANARY}\n\
             {CANARY}=1\n\
             {CANARY}=2\n"
        );
        let file = EnvFile::parse(&text);
        assert_eq!(file.malformed_lines(), &[2, 3, 4]);
        assert_eq!(
            file.duplicate_keys(),
            &[
                DuplicateKey {
                    line: 5,
                    setting: Some("AUTH_MODE")
                },
                DuplicateKey {
                    line: 7,
                    setting: None
                },
            ]
        );
        let debug = format!("{file:?}");
        assert!(!debug.contains(CANARY), "{debug}");
        assert!(!debug.contains("required"), "{debug}");
    }

    #[test]
    fn compiling_reads_only_what_the_file_sets() {
        let file = EnvFile::parse("LISTEN_ADDR=127.0.0.1:9090\nNOT_A_SETTING=x\n");
        let plan = file.compile().expect("the file compiles");
        assert_eq!(
            plan.listeners.listen_addr,
            "127.0.0.1:9090".parse().expect("valid address")
        );

        let file = EnvFile::parse(&format!("AUTH_MODE={CANARY}\n"));
        let error = file.compile().expect_err("an unknown mode is refused");
        let diagnostic = &error.diagnostics()[0];
        assert_eq!(diagnostic.variable, Some("AUTH_MODE"));
        assert_eq!(file.line("AUTH_MODE"), Some(1));
    }

    #[test]
    fn an_empty_file_compiles_to_the_defaults() {
        for text in ["", "\n\n", "# only a comment\n"] {
            let file = EnvFile::parse(text);
            assert!(file.is_empty());
            assert_eq!(
                file.compile().expect("the defaults compile"),
                compiler::compile(|_| Err(VarError::NotPresent)).expect("the defaults compile")
            );
        }
    }
}
