//! SARIF 2.1.0 output for validation results.
//!
//! ADR-0008 gives `--format sarif` to `ggctl validate` only, so CI systems
//! that ingest SARIF can annotate a bundle review. The log is built from the
//! same value-free diagnostics as the JSON report, so it can carry nothing a
//! report could not: one rule per code, and per result the bundle-relative
//! file, line and column the reader reported. File locations are relative to
//! the `BUNDLE_ROOT` base, which the log describes but never resolves: the
//! bundle's own path is an argument, and no argument is echoed.

use serde_json::{json, Value};

use crate::report::{LocationRecord, ReportDiagnostic};

/// The URI base every result location is relative to.
pub(crate) const BUNDLE_ROOT: &str = "BUNDLE_ROOT";

/// The SARIF log for one run's diagnostics: one rule per distinct code, in
/// first-seen order, and one result per diagnostic.
pub(crate) fn log(diagnostics: &[ReportDiagnostic]) -> Value {
    let mut rules: Vec<&ReportDiagnostic> = Vec::new();
    for diagnostic in diagnostics {
        if !rules.iter().any(|rule| rule.code() == diagnostic.code()) {
            rules.push(diagnostic);
        }
    }
    let rule_values: Vec<Value> = rules
        .iter()
        .map(|rule| {
            json!({
                "id": rule.code(),
                "shortDescription": {"text": rule.message()},
                "help": {"text": format!("See {}", rule.remediation())},
                "defaultConfiguration": {"level": level(rule)},
            })
        })
        .collect();
    let results: Vec<Value> = diagnostics
        .iter()
        .map(|diagnostic| {
            let index = rules
                .iter()
                .position(|rule| rule.code() == diagnostic.code())
                .unwrap_or_default();
            let mut text = diagnostic.message().to_owned();
            if let Some(hint) = diagnostic.hint() {
                text = format!("{text} ({hint})");
            }
            let mut result = json!({
                "ruleId": diagnostic.code(),
                "ruleIndex": index,
                "level": level(diagnostic),
                "message": {"text": text},
            });
            if let Some(LocationRecord::File {
                file,
                pointer,
                line,
                column,
            }) = diagnostic.location()
            {
                let mut physical = json!({
                    "artifactLocation": {"uri": file, "uriBaseId": BUNDLE_ROOT},
                });
                if let (Some(line), Some(column)) = (line, column) {
                    physical["region"] = json!({"startLine": line, "startColumn": column});
                }
                let mut location = json!({"physicalLocation": physical});
                if !pointer.is_empty() {
                    location["logicalLocations"] =
                        json!([{"fullyQualifiedName": pointer, "kind": "member"}]);
                }
                result["locations"] = json!([location]);
            }
            result
        })
        .collect();
    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "ggctl",
                    "version": env!("CARGO_PKG_VERSION"),
                    "rules": rule_values,
                }
            },
            "originalUriBaseIds": {
                BUNDLE_ROOT: {"description": {"text": "The bundle directory given to ggctl validate."}}
            },
            "columnKind": "unicodeCodePoints",
            "results": results,
        }]
    })
}

fn level(diagnostic: &ReportDiagnostic) -> &'static str {
    match diagnostic.severity() {
        "error" => "error",
        "warning" => "warning",
        _ => "note",
    }
}

#[cfg(test)]
mod tests {
    use gateway_config::bundle::{self, BundleDiagnostic, FileName, Pointer, Position};

    use super::*;
    use crate::diagnostic::{Code, Diagnostic};

    #[test]
    fn one_rule_per_code_and_one_result_per_diagnostic() {
        let log = log(&[
            Diagnostic::new(Code::CapabilitiesInvalid).into(),
            Diagnostic::at(Code::InvalidValue, 2)
                .with_hint("a fixed hint")
                .into(),
            Diagnostic::new(Code::CapabilitiesInvalid).into(),
            Diagnostic::new(Code::ProductionValidatorsNotRun).into(),
        ]);
        assert_eq!(log["version"], "2.1.0");
        let run = &log["runs"][0];
        assert_eq!(run["tool"]["driver"]["name"], "ggctl");
        let rules = run["tool"]["driver"]["rules"].as_array().expect("rules");
        assert_eq!(rules.len(), 3);
        assert_eq!(rules[0]["id"], "compat.capabilities_invalid");
        assert_eq!(rules[1]["id"], "usage.invalid_value");
        assert_eq!(
            rules[1]["help"]["text"],
            "See docs/ggctl.md#usage-diagnostics"
        );
        assert_eq!(rules[2]["defaultConfiguration"]["level"], "note");
        let results = run["results"].as_array().expect("results");
        assert_eq!(results.len(), 4);
        assert_eq!(results[2]["ruleIndex"], 0);
        assert_eq!(results[1]["ruleIndex"], 1);
        assert_eq!(results[1]["level"], "error");
        assert_eq!(results[3]["level"], "note");
        assert_eq!(
            results[1]["message"]["text"],
            "an argument's value is not one the command accepts (a fixed hint)"
        );
        // An argument position is not a file location.
        assert!(results[1].get("locations").is_none());
    }

    #[test]
    fn a_bundle_diagnostic_is_located_relative_to_the_bundle_root() {
        let file = FileName::parse("bundle.yaml").expect("valid name");
        let log = log(&[
            BundleDiagnostic::at(
                bundle::Code::InvalidDigest,
                &file,
                Pointer::root().member("spec").member("deployment"),
                Some(Position::new(8, 13)),
            )
            .into(),
            BundleDiagnostic::file(bundle::Code::UnreferencedEntry, &file)
                .warning()
                .into(),
            BundleDiagnostic::bundle(bundle::Code::RootUnavailable).into(),
        ]);
        let run = &log["runs"][0];
        assert_eq!(
            run["originalUriBaseIds"][BUNDLE_ROOT]["description"]["text"],
            "The bundle directory given to ggctl validate."
        );
        let results = run["results"].as_array().expect("results");
        assert_eq!(
            results[0]["locations"],
            json!([{
                "physicalLocation": {
                    "artifactLocation": {"uri": "bundle.yaml", "uriBaseId": BUNDLE_ROOT},
                    "region": {"startLine": 8, "startColumn": 13},
                },
                "logicalLocations": [{"fullyQualifiedName": "/spec/deployment", "kind": "member"}],
            }])
        );
        assert_eq!(results[0]["ruleId"], "reference.invalid_digest");
        assert_eq!(
            run["tool"]["driver"]["rules"][0]["help"]["text"],
            "See docs/configuration-bundles.md#diagnostics"
        );
        assert_eq!(results[1]["level"], "warning");
        assert_eq!(
            results[1]["locations"][0]["physicalLocation"],
            json!({"artifactLocation": {"uri": "bundle.yaml", "uriBaseId": BUNDLE_ROOT}})
        );
        assert!(results[1]["locations"][0].get("logicalLocations").is_none());
        assert!(results[2].get("locations").is_none());
    }

    #[test]
    fn an_empty_run_has_no_results() {
        let log = log(&[]);
        assert_eq!(log["runs"][0]["results"], json!([]));
        assert_eq!(log["runs"][0]["tool"]["driver"]["rules"], json!([]));
    }
}
