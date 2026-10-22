//! What the configuration compiler's pure stages share (issue #433, PR 2).
//!
//! `Config::from_env_vars` still asks for its inputs in the inventory's order
//! and still reports every problem in one pass, in the order it always has.
//! What changes is where the work happens. Each block of inputs is read once
//! into [`RawInput`]s. Functions that take only those values then parse each
//! input on its own and validate the rules that relate them, and return a
//! value and its [`Findings`]. They are given no reader, and they open no
//! file, resolve no name and call no store, provider or network, so they can
//! run where no environment exists, which is what the bundle and doctor
//! callers of issue #242 need. `plan` runs every block, in order, into one
//! validated plan.
//!
//! A stage parses every input of its block before it checks any rule, while
//! the legacy parser checked some rules between two reads. Each finding
//! therefore records the inventoried input after which the legacy parser
//! reports it, and [`Checked::report`] sorts on that, stably, which puts every
//! problem back where operators have always seen it.

use std::{env::VarError, fmt};

use super::{
    diagnostic::{ConfigRule, Report},
    inventory, is_var_set,
};

/// One inventoried input exactly as the reader returned it, before anything
/// is parsed from it.
///
/// The value may be a secret, so this type implements neither `Debug` nor
/// `Display`: the only things a stage can learn about an input without
/// parsing it are whether it was set and where its value came from.
pub(super) struct RawInput {
    setting: &'static str,
    value: Result<String, VarError>,
    blank_is_a_value: bool,
}

impl RawInput {
    /// An input whose blank value means "unset", or is refused.
    pub(super) fn new(setting: &'static str, value: Result<String, VarError>) -> Self {
        Self {
            setting,
            value,
            blank_is_a_value: false,
        }
    }

    /// A list input whose blank value is an empty list that replaces the
    /// default, as `AUTH_EXEMPT_PATHS` and its siblings are.
    pub(super) fn list_replacing_its_default(
        setting: &'static str,
        value: Result<String, VarError>,
    ) -> Self {
        Self {
            setting,
            value,
            blank_is_a_value: true,
        }
    }

    /// The value as the reader returned it, for the parse helpers, which take
    /// it by value.
    pub(super) fn value(&self) -> Result<String, VarError> {
        self.value.clone()
    }

    /// Whether the input was set to anything but whitespace. A value that is
    /// not Unicode was still set.
    pub(super) fn is_set(&self) -> bool {
        is_var_set(self.value())
    }

    /// Where the setting's effective value comes from, without the value.
    ///
    /// A blank value is the default where blank means unset. Where blank is
    /// refused the configuration is refused too, so no plan is built for it
    /// to describe.
    pub(super) fn provenance(&self) -> Provenance {
        let source = match &self.value {
            Err(VarError::NotPresent) => Source::Default,
            Ok(value) if value.trim().is_empty() && !self.blank_is_a_value => Source::Default,
            Ok(_) | Err(VarError::NotUnicode(_)) => Source::Environment,
        };
        Provenance {
            setting: self.setting,
            source,
        }
    }
}

/// Where a setting's effective value came from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Source {
    /// The setting is unset, or blank where blank means unset, so its
    /// documented default applies. A default can itself depend on other
    /// settings, as the exempt-path defaults depend on `ADMIN_PREFIX`.
    Default,
    /// The process environment set it.
    Environment,
}

/// The provenance of one setting: its name and its source, never its value.
///
/// Both fields are fixed text chosen by the gateway, so a provenance record
/// cannot carry a value or a secret locator however it is printed.
#[allow(dead_code)] // Read by the stage tests until startup consumes the plan (#433 PR 3).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Provenance {
    pub(crate) setting: &'static str,
    pub(crate) source: Source,
}

/// Where secret material lives -- a file the activation stage opens -- and
/// never the material itself.
///
/// The pure stages carry a locator and never resolve it. A locator still
/// says where a deployment keeps its keys, so `Debug` shows only that one is
/// present.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct SecretLocator(String);

impl SecretLocator {
    pub(crate) fn new(locator: String) -> Self {
        Self(locator)
    }

    /// The locator, for the activation stage that opens it.
    pub(crate) fn into_locator(self) -> String {
        self.0
    }
}

impl fmt::Debug for SecretLocator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretLocator(<redacted>)")
    }
}

/// The problems a stage found, each placed where the legacy parser reports
/// it.
#[derive(Default)]
pub(super) struct Findings {
    found: Vec<Finding>,
}

struct Finding {
    /// The inventoried input after whose read the legacy parser reports this
    /// problem.
    after: &'static str,
    rule: ConfigRule,
    problem: String,
}

impl Findings {
    /// Parses or normalizes one input on its own. Whatever `parse` refuses
    /// is a refusal of `setting`'s value.
    pub(super) fn input<T>(
        &mut self,
        setting: &'static str,
        parse: impl FnOnce(&mut Vec<String>) -> T,
    ) -> T {
        self.rule(setting, ConfigRule::Value, parse)
    }

    /// Checks a rule that relates inputs. Whatever `check` refuses is
    /// reported under `rule`, after `after` is read.
    pub(super) fn rule<T>(
        &mut self,
        after: &'static str,
        rule: ConfigRule,
        check: impl FnOnce(&mut Vec<String>) -> T,
    ) -> T {
        let mut problems = Vec::new();
        let value = check(&mut problems);
        for problem in problems {
            self.refuse(after, rule, problem);
        }
        value
    }

    /// Records one problem under `rule`, reported after `after` is read.
    pub(super) fn refuse(&mut self, after: &'static str, rule: ConfigRule, problem: String) {
        self.found.push(Finding {
            after,
            rule,
            problem,
        });
    }

    /// Whether parsing `setting` refused its value.
    pub(super) fn refused(&self, setting: &'static str) -> bool {
        self.found
            .iter()
            .any(|finding| finding.rule == ConfigRule::Value && finding.after == setting)
    }
}

/// A stage's result and the problems it found on the way.
///
/// The result is always built, with defaults where an input was refused, so
/// that later stages can still check their own inputs and one pass reports
/// every problem. It is a validated plan only when no stage found anything,
/// and `Config::from_env_vars` builds nothing from it otherwise.
pub(super) struct Checked<T> {
    value: T,
    findings: Findings,
}

impl<T> Checked<T> {
    pub(super) fn new(value: T, findings: Findings) -> Self {
        Self { value, findings }
    }

    /// Appends the findings, each with the rule behind it, to the report in
    /// the order the legacy parser reports them, and returns the result.
    pub(super) fn report(self, report: &mut Report) -> T {
        let Checked {
            value,
            findings: Findings { mut found },
        } = self;
        // `sort_by_key` is stable: findings placed after the same input keep
        // the order they were found in, so an input's own refusal still comes
        // before the rules checked once it was read.
        found.sort_by_key(|finding| inventory::position(finding.after));
        for finding in found {
            report.push(finding.rule, finding.problem);
        }
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn findings_are_reported_where_the_legacy_parser_reports_them() {
        let mut findings = Findings::default();
        // Parsed in block order, then the rules: a rule placed after the
        // second input is reported before the third input's own refusal.
        findings.input("LISTEN_ADDR", |problems| {
            problems.push("LISTEN_ADDR first".to_owned())
        });
        findings.input("GRPC_LISTEN_ADDR", |problems| {
            problems.push("GRPC_LISTEN_ADDR third".to_owned())
        });
        findings.refuse(
            "ADMIN_LISTEN_ADDR",
            ConfigRule::AdminListenerCollision,
            "ADMIN_LISTEN_ADDR second".to_owned(),
        );
        findings.refuse(
            "GRPC_LISTEN_ADDR",
            ConfigRule::GrpcListenerCollision,
            "GRPC_LISTEN_ADDR fourth".to_owned(),
        );
        assert!(findings.refused("LISTEN_ADDR"));
        assert!(!findings.refused("ADMIN_LISTEN_ADDR"));

        let mut report = Report::default();
        report.push(
            ConfigRule::TrustedProxyNetworksRequired,
            "an earlier problem".to_owned(),
        );
        let value = Checked::new(7, findings).report(&mut report);

        assert_eq!(value, 7);
        assert_eq!(
            report.problems(),
            [
                "an earlier problem",
                "LISTEN_ADDR first",
                "ADMIN_LISTEN_ADDR second",
                "GRPC_LISTEN_ADDR third",
                "GRPC_LISTEN_ADDR fourth",
            ]
        );
        assert_eq!(
            report.rules(),
            [
                ConfigRule::TrustedProxyNetworksRequired,
                ConfigRule::Value,
                ConfigRule::AdminListenerCollision,
                ConfigRule::Value,
                ConfigRule::GrpcListenerCollision,
            ]
        );
    }

    #[test]
    fn provenance_names_the_source_and_never_the_value() {
        let set = RawInput::new("LISTEN_ADDR", Ok("zqcanary".to_owned()));
        let unset = RawInput::new("LISTEN_ADDR", Err(VarError::NotPresent));
        let blank = RawInput::new("ADMIN_LISTEN_ADDR", Ok(" \t ".to_owned()));
        let cleared = RawInput::list_replacing_its_default("AUTH_EXEMPT_PATHS", Ok(String::new()));

        assert_eq!(set.provenance().source, Source::Environment);
        assert_eq!(unset.provenance().source, Source::Default);
        assert_eq!(blank.provenance().source, Source::Default);
        assert_eq!(cleared.provenance().source, Source::Environment);
        assert_eq!(set.provenance().setting, "LISTEN_ADDR");
        assert!(!format!("{:?}", set.provenance()).contains("zqcanary"));

        assert!(set.is_set());
        assert!(!unset.is_set());
        assert!(!blank.is_set());
    }

    #[test]
    fn a_secret_locator_is_never_printed() {
        let locator = SecretLocator::new("/run/secrets/zqcanary.key".to_owned());
        assert_eq!(format!("{locator:?}"), "SecretLocator(<redacted>)");
        assert_eq!(locator.into_locator(), "/run/secrets/zqcanary.key");
    }
}
