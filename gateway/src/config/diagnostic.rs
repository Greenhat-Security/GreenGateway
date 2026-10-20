//! Value-free configuration diagnostics (issue #433, PR 1).
//!
//! A `ConfigError`'s problems are the operator-facing report. They name the
//! setting and, where it helps, quote the value that was refused, which is
//! right for a gateway describing its own environment and wrong for anything
//! that must not echo one: an import reading another deployment's settings,
//! or the validation and doctor flows of issue #242.
//!
//! A [`ConfigDiagnostic`] is the same report without the values. There is one
//! per problem, in the same order. Each names the inventoried variable its
//! problem begins with, carries a code read from how that variable was looked
//! up, and has a message built from those two and fixed text alone. Nothing
//! in it is copied from a value or from the problem's wording, so it is
//! value-free by construction rather than by redaction: there is no pattern
//! to miss.
//!
//! The code describes the input, not the rule that refused it. Rule-specific
//! codes belong to the stages the configuration compiler extracts, which can
//! assign them where each rule is checked; this module only reports what the
//! existing parser already says, without changing a word of it.

use std::{collections::BTreeMap, env::VarError};

use super::inventory;

/// How one variable came back when `Config::from_env_vars` looked it up.
/// Never its value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LookupState {
    Unset,
    Empty,
    NotUnicode,
    Set,
}

/// How every inventoried variable `Config::from_env_vars` requested came
/// back.
#[derive(Default)]
pub(super) struct Lookups {
    states: BTreeMap<&'static str, LookupState>,
}

impl Lookups {
    /// Remembers how `name` came back.
    ///
    /// A name outside the inventory is not recorded. No problem can be
    /// attributed to one, and the inventory tests fail before a read the
    /// inventory does not list can ship.
    pub(super) fn record(&mut self, name: &str, value: &Result<String, VarError>) {
        let Some(name) = inventory::config_input(name) else {
            return;
        };
        let state = match value {
            Ok(value) if value.trim().is_empty() => LookupState::Empty,
            Ok(_) => LookupState::Set,
            Err(VarError::NotPresent) => LookupState::Unset,
            Err(VarError::NotUnicode(_)) => LookupState::NotUnicode,
        };
        self.states.insert(name, state);
    }

    /// A variable `from_env_vars` never requested had no effect on the
    /// parse, which is also what an unset one has.
    fn state(&self, name: &str) -> LookupState {
        self.states.get(name).copied().unwrap_or(LookupState::Unset)
    }
}

/// What a diagnostic records about the input its problem names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ConfigDiagnosticCode {
    /// The variable is not set.
    Unset,
    /// The variable is set to an empty or whitespace-only value.
    Empty,
    /// The variable's value is not valid Unicode.
    NotUnicode,
    /// The variable is set to a value that was refused, on its own or in
    /// combination with another setting.
    Refused,
    /// The problem does not begin with an inventoried variable. No problem
    /// the parser records today has that shape; the code exists so such a
    /// problem would still be reported, rather than dropped or echoed.
    Unattributed,
}

/// One configuration problem, without the value that caused it.
#[allow(dead_code)] // Fields are read by the parity tests until the #433 compiler reads them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ConfigDiagnostic {
    /// The inventoried variable the problem begins with, or `None` when it
    /// begins with none.
    pub(crate) variable: Option<&'static str>,
    pub(crate) code: ConfigDiagnosticCode,
    /// Built from `variable`, `code` and fixed text only.
    pub(crate) message: String,
}

/// One diagnostic per problem, in the same order.
pub(super) fn diagnose(problems: &[String], lookups: &Lookups) -> Vec<ConfigDiagnostic> {
    problems
        .iter()
        .map(|problem| diagnostic(problem, lookups))
        .collect()
}

fn diagnostic(problem: &str, lookups: &Lookups) -> ConfigDiagnostic {
    let Some(variable) = attributed_variable(problem) else {
        return ConfigDiagnostic {
            variable: None,
            code: ConfigDiagnosticCode::Unattributed,
            message: "a configuration problem names no inventoried setting".to_owned(),
        };
    };
    let (code, message) = match lookups.state(variable) {
        LookupState::Unset => (
            ConfigDiagnosticCode::Unset,
            format!("{variable} is not set"),
        ),
        LookupState::Empty => (
            ConfigDiagnosticCode::Empty,
            format!("{variable} is set but empty"),
        ),
        LookupState::NotUnicode => (
            ConfigDiagnosticCode::NotUnicode,
            format!("{variable} is not valid Unicode"),
        ),
        LookupState::Set => (
            ConfigDiagnosticCode::Refused,
            format!("{variable} is set to a value that was refused"),
        ),
    };
    ConfigDiagnostic {
        variable: Some(variable),
        code,
        message,
    }
}

/// The inventoried variable a problem begins with.
///
/// Every problem the parser records starts with the name of the setting it is
/// about, followed by a space, `=`, `:`, `[` or `.` -- `FOO must be ...`,
/// `FOO=true requires ...`, `FOO[0].field ...`. The leading run of name
/// characters is looked up in the inventory, so the result is always one of
/// the inventory's own names and never text taken from the problem.
fn attributed_variable(problem: &str) -> Option<&'static str> {
    let end = problem
        .find(|character: char| {
            !(character.is_ascii_uppercase() || character.is_ascii_digit() || character == '_')
        })
        .unwrap_or(problem.len());
    inventory::config_input(&problem[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_problem_that_names_no_inventoried_setting_is_reported_without_its_text() {
        let problems = [
            "lowercase lead quoting 'zqcanary-value'".to_owned(),
            "NOT_A_GATEWAY_SETTING must be 'zqcanary-value'".to_owned(),
        ];
        let diagnostics = diagnose(&problems, &Lookups::default());

        assert_eq!(diagnostics.len(), 2);
        for diagnostic in &diagnostics {
            assert_eq!(diagnostic.variable, None);
            assert_eq!(diagnostic.code, ConfigDiagnosticCode::Unattributed);
            assert_eq!(
                diagnostic.message,
                "a configuration problem names no inventoried setting"
            );
        }
    }

    #[test]
    fn attribution_takes_the_whole_leading_name_and_nothing_after_it() {
        for (problem, expected) in [
            ("LISTEN_ADDR must be a valid socket address", "LISTEN_ADDR"),
            (
                "ADMIN_SESSION_MODE=standalone_memory requires ADMIN_LOGIN_PROVIDER",
                "ADMIN_SESSION_MODE",
            ),
            ("UPSTREAM_ROUTES[0].id is required", "UPSTREAM_ROUTES"),
            (
                "CONNECTION_SECRET_ALIASES: invalid file key",
                "CONNECTION_SECRET_ALIASES",
            ),
            ("AUTH_PROVIDERS", "AUTH_PROVIDERS"),
        ] {
            assert_eq!(attributed_variable(problem), Some(expected), "{problem}");
        }
        // A prefix of a name is not the name.
        assert_eq!(attributed_variable("ADMIN_LISTEN must be set"), None);
        assert_eq!(attributed_variable(""), None);
    }

    #[test]
    fn a_requested_variable_is_reported_by_how_it_came_back() {
        let mut lookups = Lookups::default();
        lookups.record("LISTEN_ADDR", &Err(VarError::NotPresent));
        lookups.record("AUTH_MODE", &Ok(" \t ".to_owned()));
        lookups.record("AUTH_ENABLED", &Ok("maybe".to_owned()));
        // Not an inventoried name, so never recorded.
        lookups.record("NOT_A_GATEWAY_SETTING", &Ok("value".to_owned()));

        assert_eq!(lookups.state("LISTEN_ADDR"), LookupState::Unset);
        assert_eq!(lookups.state("AUTH_MODE"), LookupState::Empty);
        assert_eq!(lookups.state("AUTH_ENABLED"), LookupState::Set);
        assert_eq!(lookups.state("ADMIN_PREFIX"), LookupState::Unset);
        assert_eq!(lookups.states.len(), 3);
    }
}
