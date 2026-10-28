//! SARIF 2.1.0 output for validation results.
//!
//! ADR-0008 gives `--format sarif` to `ggctl validate`, so CI systems that
//! ingest SARIF can annotate a bundle review, and `ggctl diff` uses the same
//! run for its risk codes (`diff.rs`). `validate` arrives with
//! the bundle reader's move into the shared library (#242 PR 8); until then
//! no command offers this format and the writer is exercised by its tests.
//! It is built from the same value-free diagnostics as the JSON report, so
//! it can carry nothing a report could not.
// `ggctl validate` (#242 PR 8) is the caller; until then only the tests are.
#![cfg_attr(not(test), expect(dead_code))]

use serde_json::{json, Value};

use crate::diagnostic::Diagnostic;

/// The SARIF log for one run's diagnostics: one rule per distinct code, in
/// first-seen order, and one result per diagnostic.
pub(crate) fn log(diagnostics: &[Diagnostic]) -> Value {
    let mut rules: Vec<&Diagnostic> = Vec::new();
    for diagnostic in diagnostics {
        if !rules.iter().any(|rule| rule.code == diagnostic.code) {
            rules.push(diagnostic);
        }
    }
    let rule_values: Vec<Value> = rules
        .iter()
        .map(|rule| {
            json!({
                "id": rule.code.as_str(),
                "shortDescription": {"text": rule.code.message()},
                "help": {"text": format!("See {}", rule.code.remediation())},
                "defaultConfiguration": {"level": level(rule)},
            })
        })
        .collect();
    let results: Vec<Value> = diagnostics
        .iter()
        .map(|diagnostic| {
            let index = rules
                .iter()
                .position(|rule| rule.code == diagnostic.code)
                .unwrap_or_default();
            let text = match diagnostic.hint {
                Some(hint) => format!("{} ({hint})", diagnostic.code.message()),
                None => diagnostic.code.message().to_owned(),
            };
            json!({
                "ruleId": diagnostic.code.as_str(),
                "ruleIndex": index,
                "level": level(diagnostic),
                "message": {"text": text},
            })
        })
        .collect();
    envelope(rule_values, results)
}

/// One SARIF 2.1.0 run by ggctl with these rules and results; the semantic
/// diff's SARIF form (`diff.rs`) shares it.
pub(crate) fn envelope(rules: Vec<Value>, results: Vec<Value>) -> Value {
    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "ggctl",
                    "version": env!("CARGO_PKG_VERSION"),
                    "rules": rules,
                }
            },
            "results": results,
        }]
    })
}

fn level(diagnostic: &Diagnostic) -> &'static str {
    match diagnostic.severity() {
        "error" => "error",
        "warning" => "warning",
        _ => "note",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnostic::Code;

    #[test]
    fn one_rule_per_code_and_one_result_per_diagnostic() {
        let log = log(&[
            Diagnostic::new(Code::CapabilitiesInvalid),
            Diagnostic::at(Code::InvalidValue, 2).with_hint("a fixed hint"),
            Diagnostic::new(Code::CapabilitiesInvalid),
        ]);
        assert_eq!(log["version"], "2.1.0");
        let run = &log["runs"][0];
        assert_eq!(run["tool"]["driver"]["name"], "ggctl");
        let rules = run["tool"]["driver"]["rules"].as_array().expect("rules");
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0]["id"], "compat.capabilities_invalid");
        assert_eq!(rules[1]["id"], "usage.invalid_value");
        assert_eq!(
            rules[1]["help"]["text"],
            "See docs/ggctl.md#usage-diagnostics"
        );
        let results = run["results"].as_array().expect("results");
        assert_eq!(results.len(), 3);
        assert_eq!(results[2]["ruleIndex"], 0);
        assert_eq!(results[1]["ruleIndex"], 1);
        assert_eq!(results[1]["level"], "error");
        assert_eq!(
            results[1]["message"]["text"],
            "an argument's value is not one the command accepts (a fixed hint)"
        );
    }

    #[test]
    fn an_empty_run_has_no_results() {
        let log = log(&[]);
        assert_eq!(log["runs"][0]["results"], json!([]));
        assert_eq!(log["runs"][0]["tool"]["driver"]["rules"], json!([]));
    }
}
