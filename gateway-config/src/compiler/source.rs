//! Selects the configuration authority before compiling any of its inputs
//! (ADR-0008). Bundle and ledger activation are still unavailable.

use std::env::VarError;

use super::{
    diagnostic::{ConfigDiagnostic, ConfigDiagnosticCode, ConfigRule},
    plan::{compile, ConfigPlan},
    ConfigError,
};
use crate::catalog::{BundleMapping, FIELDS};

pub const GATEWAY_CONFIG_SOURCE: &str = "GATEWAY_CONFIG_SOURCE";
pub const GATEWAY_CONFIG_BUNDLE: &str = "GATEWAY_CONFIG_BUNDLE";
pub const GATEWAY_STATE_DIR: &str = "GATEWAY_STATE_DIR";

/// Source selectors are read before the environment compiler's inventory.
pub const SELECTORS: [&str; 3] = [
    GATEWAY_CONFIG_SOURCE,
    GATEWAY_CONFIG_BUNDLE,
    GATEWAY_STATE_DIR,
];

/// Stable, value-free reasons a configuration source cannot be used.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceRefusal {
    InvalidSelector,
    SelectorWithoutMode,
    MissingSelector,
    ConflictingEnvironment,
    ModeUnavailable,
}

impl SourceRefusal {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidSelector => "source.invalid_selector",
            Self::SelectorWithoutMode => "source.selector_without_mode",
            Self::MissingSelector => "source.missing_selector",
            Self::ConflictingEnvironment => "source.conflicting_environment",
            Self::ModeUnavailable => "source.mode_unavailable",
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            Self::InvalidSelector => "the configuration source selector has an invalid value",
            Self::SelectorWithoutMode => {
                "the selected configuration mode does not use this selector"
            }
            Self::MissingSelector => "the selected configuration mode requires this selector",
            Self::ConflictingEnvironment => {
                "this environment setting conflicts with the selected configuration source"
            }
            Self::ModeUnavailable => {
                "this build cannot start from the selected configuration source"
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Environment,
    Bundle,
    Ledger,
}

/// Compiles the selected authority. With no selectors this calls the
/// existing environment compiler. Source refusals contain setting names and
/// fixed reasons only, including in the gateway's operator-facing errors.
pub fn compile_selected(
    mut get_var: impl FnMut(&str) -> Result<String, VarError>,
) -> Result<ConfigPlan, ConfigError> {
    let mode = match get_var(GATEWAY_CONFIG_SOURCE).as_deref() {
        Err(VarError::NotPresent) | Ok("environment") => Mode::Environment,
        Ok("bundle") => Mode::Bundle,
        Ok("ledger") => Mode::Ledger,
        _ => {
            return Err(source_error(&[(
                GATEWAY_CONFIG_SOURCE,
                SourceRefusal::InvalidSelector,
            )]))
        }
    };
    let mut refused = Vec::new();
    for (name, value, allowed, required) in [
        (
            GATEWAY_CONFIG_BUNDLE,
            get_var(GATEWAY_CONFIG_BUNDLE),
            mode == Mode::Bundle,
            mode == Mode::Bundle,
        ),
        (
            GATEWAY_STATE_DIR,
            get_var(GATEWAY_STATE_DIR),
            mode != Mode::Environment,
            mode == Mode::Ledger,
        ),
    ] {
        let reason = match value {
            Err(VarError::NotPresent) if required => SourceRefusal::MissingSelector,
            Err(VarError::NotPresent) => continue,
            _ if !allowed => SourceRefusal::SelectorWithoutMode,
            Ok(value) if !value.trim().is_empty() => continue,
            _ => SourceRefusal::InvalidSelector,
        };
        refused.push((name, reason));
    }
    if mode == Mode::Environment {
        return if refused.is_empty() {
            compile(get_var)
        } else {
            Err(source_error(&refused))
        };
    }

    for field in FIELDS {
        if !matches!(field.bundle, BundleMapping::Bootstrap(_))
            && !matches!(get_var(field.environment), Err(VarError::NotPresent))
        {
            refused.push((field.environment, SourceRefusal::ConflictingEnvironment));
        }
    }
    if refused.is_empty() {
        refused.push((GATEWAY_CONFIG_SOURCE, SourceRefusal::ModeUnavailable));
    }
    Err(source_error(&refused))
}

fn source_error(refused: &[(&'static str, SourceRefusal)]) -> ConfigError {
    let mut problems = Vec::with_capacity(refused.len());
    let mut diagnostics = Vec::with_capacity(refused.len());
    for &(setting, reason) in refused {
        let message = format!("{setting}: {}: {}", reason.as_str(), reason.message());
        problems.push(message.clone());
        diagnostics.push(ConfigDiagnostic {
            variable: Some(setting),
            code: ConfigDiagnosticCode::Source(reason),
            rule: ConfigRule::SourceSelection,
            message,
        });
    }
    ConfigError {
        problems,
        diagnostics,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn from(settings: &[(&str, &str)]) -> Result<ConfigPlan, ConfigError> {
        compile_selected(|name| {
            settings
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| value.to_string())
                .ok_or(VarError::NotPresent)
        })
    }

    fn refusals(settings: &[(&str, &str)]) -> Vec<(Option<&'static str>, ConfigDiagnosticCode)> {
        let error = from(settings).expect_err("the source must be refused");
        assert!(!format!("{error:?} {error}").contains("source-canary"));
        error
            .diagnostics()
            .iter()
            .map(|item| (item.variable, item.code))
            .collect()
    }

    #[test]
    fn environment_preserves_the_compiled_plan_and_requires_no_locator() {
        let ordinary = [("ADMIN_PREFIX", "/operations")];
        let explicit = [(GATEWAY_CONFIG_SOURCE, "environment"), ordinary[0]];
        assert_eq!(from(&ordinary).unwrap(), from(&explicit).unwrap());
        for mode in [None, Some("environment")] {
            let mut settings = vec![
                (GATEWAY_CONFIG_BUNDLE, ""),
                (GATEWAY_STATE_DIR, "source-canary"),
            ];
            settings.extend(mode.map(|source| (GATEWAY_CONFIG_SOURCE, source)));
            assert_eq!(
                refusals(&settings),
                [GATEWAY_CONFIG_BUNDLE, GATEWAY_STATE_DIR].map(|name| (
                    Some(name),
                    ConfigDiagnosticCode::Source(SourceRefusal::SelectorWithoutMode)
                ))
            );
        }
    }

    #[test]
    fn the_source_and_its_locators_must_be_unambiguous() {
        for mode in ["", " ", "BUNDLE", "environment ", "source-canary"] {
            assert_eq!(
                refusals(&[(GATEWAY_CONFIG_SOURCE, mode)]),
                [(
                    Some(GATEWAY_CONFIG_SOURCE),
                    ConfigDiagnosticCode::Source(SourceRefusal::InvalidSelector)
                )]
            );
        }
        for (mode, locator) in [
            ("bundle", GATEWAY_CONFIG_BUNDLE),
            ("ledger", GATEWAY_STATE_DIR),
        ] {
            let selected = (GATEWAY_CONFIG_SOURCE, mode);
            for (value, reason) in [
                (None, SourceRefusal::MissingSelector),
                (Some("   "), SourceRefusal::InvalidSelector),
            ] {
                let mut settings = vec![selected];
                settings.extend(value.map(|value| (locator, value)));
                assert_eq!(
                    refusals(&settings),
                    [(Some(locator), ConfigDiagnosticCode::Source(reason))]
                );
            }
            assert_eq!(
                refusals(&[selected, (locator, "source-canary")]),
                [(
                    Some(GATEWAY_CONFIG_SOURCE),
                    ConfigDiagnosticCode::Source(SourceRefusal::ModeUnavailable)
                )]
            );
        }
        assert_eq!(
            refusals(&[
                (GATEWAY_CONFIG_SOURCE, "ledger"),
                (GATEWAY_STATE_DIR, "source-canary"),
                (GATEWAY_CONFIG_BUNDLE, "")
            ]),
            [(
                Some(GATEWAY_CONFIG_BUNDLE),
                ConfigDiagnosticCode::Source(SourceRefusal::SelectorWithoutMode)
            )]
        );
    }

    #[test]
    fn both_file_modes_report_every_ordinary_setting_and_ignore_bootstrap_values() {
        for (mode, locator) in [
            ("bundle", GATEWAY_CONFIG_BUNDLE),
            ("ledger", GATEWAY_STATE_DIR),
        ] {
            let mut settings = vec![(GATEWAY_CONFIG_SOURCE, mode), (locator, "source-canary")];
            settings.extend(FIELDS.iter().map(|field| {
                (
                    field.environment,
                    if matches!(field.bundle, BundleMapping::Bootstrap(_)) {
                        "source-canary"
                    } else {
                        ""
                    },
                )
            }));
            let expected: Vec<_> = FIELDS
                .iter()
                .filter(|field| !matches!(field.bundle, BundleMapping::Bootstrap(_)))
                .map(|field| {
                    (
                        Some(field.environment),
                        ConfigDiagnosticCode::Source(SourceRefusal::ConflictingEnvironment),
                    )
                })
                .collect();
            assert_eq!(refusals(&settings), expected);
        }
    }

    #[test]
    fn a_non_unicode_setting_is_present_and_its_bytes_are_never_reported() {
        let value = VarError::NotUnicode(std::ffi::OsString::from("source-canary"));
        let failure = compile_selected(|name| match name {
            GATEWAY_CONFIG_SOURCE => Ok("bundle".to_owned()),
            GATEWAY_CONFIG_BUNDLE => Ok("source-canary".to_owned()),
            "LISTEN_ADDR" => Err(value.clone()),
            _ => Err(VarError::NotPresent),
        })
        .unwrap_err();
        assert_eq!(
            failure.diagnostics()[0].code,
            ConfigDiagnosticCode::Source(SourceRefusal::ConflictingEnvironment)
        );
        assert!(!format!("{failure:?} {failure}").contains("source-canary"));
    }
}
