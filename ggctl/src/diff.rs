//! `ggctl diff BUNDLE --against BUNDLE [--check] [--strict]
//! [--format human|json|sarif]` (issue #242, PR 9; ADR-0008, "Plan, risk
//! acknowledgment, and conditional apply").
//!
//! Both bundles are read by the shared reader, exactly as `ggctl validate`
//! reads them, and compared by `gateway_config::semantic_diff`, the engine
//! the gateway's plans will use, so the CLI cannot approximate either. The
//! change is from the `--against` bundle to `BUNDLE`. Everything written is
//! value-free because the diff is:
//!
//! - human: one line per change, then the sorted risk codes;
//! - `--format json`: one `GgctlReport` whose `result` carries the
//!   `diffResult`;
//! - `--format sarif`: the reader's diagnostics as `ggctl validate` reports
//!   them, then one result per risk code of each change, with the change's
//!   field as a logical location, so CI can annotate a review. A change that
//!   carries no risk code is not a finding and is not a result.
//!
//! `--check` adds `diff.drift_found` (exit `4`) when anything differs. A
//! bundle that is invalid is not compared: the command reports the reader's
//! diagnostics and exits as `ggctl validate` would.

use std::path::Path;

use gateway_config::{
    bundle::{self, PublishedSchemasOnly, ReadOptions},
    semantic_diff::{compare_read_bundles, Change, Display, SemanticDiff, Severity, Shown},
};
use serde::Serialize;
use serde_json::{json, Value};

use crate::{
    cli::Invocation,
    diagnostic::{Code, Diagnostic, Exit},
    report::{self, Format, Io, ReportDiagnostic},
    sarif,
    validate::{self, BundleRecord},
};

/// Where every risk code is described.
const RISK_CODES_ANCHOR: &str = "docs/semantic-diff.md#risk-codes";

/// The `diff` result.
#[derive(Debug, Serialize)]
struct DiffCommandResult<'a> {
    /// Both bundles were read with no error, so they were compared.
    valid: bool,
    /// `BUNDLE`, the candidate. Present once its manifest was read.
    #[serde(skip_serializing_if = "Option::is_none")]
    bundle: Option<BundleRecord>,
    /// The `--against` bundle, the base. Present once its manifest was read.
    #[serde(skip_serializing_if = "Option::is_none")]
    against: Option<BundleRecord>,
    /// The changes from `--against` to `BUNDLE`, when both were read.
    #[serde(skip_serializing_if = "Option::is_none")]
    diff: Option<&'a SemanticDiff>,
}

pub(crate) fn run(invocation: &Invocation, io: &mut Io<'_>) -> Exit {
    let strict = invocation.flag("--strict").is_some();
    let (Some(candidate), Some((_, against))) = (
        validate::read(invocation, strict),
        invocation.value("--against"),
    ) else {
        return report::error(io, Diagnostic::new(Code::MissingArgument));
    };
    let base = bundle::read_bundle(
        Path::new(against),
        ReadOptions { strict },
        &PublishedSchemasOnly,
    );
    let mut diagnostics = validate::diagnostics(&candidate);
    diagnostics.extend(validate::diagnostics(&base));
    if validate::supplies_a_resource(&candidate) || validate::supplies_a_resource(&base) {
        diagnostics.push(Diagnostic::new(Code::ProductionValidatorsNotRun).into());
    }
    let diff = match (&base.bundle, &candidate.bundle) {
        (Some(base), Some(candidate)) => Some(compare_read_bundles(base, candidate)),
        _ => None,
    };
    if let (Some(diff), Some(position)) = (&diff, invocation.flag("--check")) {
        if exit(diff, true) == Exit::Drift {
            diagnostics.push(Diagnostic::at(Code::DriftFound, position).into());
        }
    }
    let result = DiffCommandResult {
        valid: diff.is_some(),
        bundle: BundleRecord::of(&candidate),
        against: BundleRecord::of(&base),
        diff: diff.as_ref(),
    };
    match Format::of(invocation) {
        Format::Sarif => {
            let empty = SemanticDiff::default();
            report::sarif_log(
                io,
                &diagnostics,
                &sarif_log(diff.as_ref().unwrap_or(&empty), &diagnostics),
            )
        }
        format => {
            report::finish_report(io, format, "diff", &result, &diagnostics, |result, out| {
                match result.diff {
                    Some(diff) => out.write_all(human(diff).as_bytes()),
                    None => writeln!(out, "not compared: a bundle is invalid"),
                }
            })
        }
    }
}

/// The exit status a diff alone determines: `4` (`drift`) under `--check`
/// when anything differs, otherwise `0`.
pub(crate) fn exit(diff: &SemanticDiff, check: bool) -> Exit {
    if check && !diff.is_empty() {
        Exit::Drift
    } else {
        Exit::Success
    }
}

/// The human form: one line per change, ordered by section and field, then
/// the risk codes.
pub(crate) fn human(diff: &SemanticDiff) -> String {
    if diff.is_empty() {
        return "no changes\n".to_owned();
    }
    let mut text = String::new();
    for change in diff.changes() {
        let codes: Vec<&str> = change.risks().iter().map(|code| code.as_str()).collect();
        let mut line = format!(
            "{:<6}  {}  {} {}, {}, {}",
            severity_name(change.severity()),
            change.field(),
            change.kind().as_str(),
            value(change),
            change.class().as_str(),
            change.effect().as_str(),
        );
        if !codes.is_empty() {
            line.push_str(&format!("  [{}]", codes.join(", ")));
        }
        text.push_str(line.trim_end());
        text.push('\n');
    }
    let codes: Vec<&str> = diff.risks().into_iter().map(|code| code.as_str()).collect();
    text.push_str(&format!(
        "{} changed, highest risk {}: {}\n",
        diff.changes().len(),
        severity_name(diff.severity()),
        if codes.is_empty() {
            "no risk codes".to_owned()
        } else {
            codes.join(", ")
        }
    ));
    text
}

fn value(change: &Change) -> String {
    let entries = change.entries().map(|entries| {
        format!(
            " ({} added, {} removed, {} changed)",
            entries.added, entries.removed, entries.changed
        )
    });
    match change.display() {
        Display::Shown { before, after } => format!("{} -> {}", shown(before), shown(after)),
        Display::Withheld => format!("(value withheld){}", entries.unwrap_or_default()),
        Display::Reference => format!("(reference changed){}", entries.unwrap_or_default()),
    }
}

fn shown(value: Shown) -> String {
    match value {
        Shown::Flag(flag) => flag.to_string(),
        Shown::Word(word) => word.to_owned(),
        Shown::Count(count) => count.to_string(),
        Shown::Rate(rate) => rate.to_string(),
        Shown::Unbounded => "unbounded".to_owned(),
    }
}

fn severity_name(severity: Option<Severity>) -> &'static str {
    severity.map_or("none", Severity::as_str)
}

/// The SARIF log: the reader's diagnostics as `ggctl validate` writes them,
/// then one rule per risk code the diff carries, in code order, and one
/// result per risk code of each change.
pub(crate) fn sarif_log(diff: &SemanticDiff, diagnostics: &[ReportDiagnostic]) -> Value {
    let mut log = sarif::log(diagnostics);
    let run = &mut log["runs"][0];
    if let Some(base) = run["originalUriBaseIds"][sarif::BUNDLE_ROOT].as_object_mut() {
        base.insert(
            "description".to_owned(),
            json!({"text": "The bundle directory a diagnostic concerns: BUNDLE or --against."}),
        );
    }
    let offset = run["tool"]["driver"]["rules"]
        .as_array()
        .map_or(0, Vec::len);
    let codes: Vec<_> = diff.risks().into_iter().collect();
    let rules = codes.iter().map(|code| {
        json!({
            "id": code.as_str(),
            "shortDescription": {"text": code.description()},
            "help": {"text": format!("See {RISK_CODES_ANCHOR}")},
            "defaultConfiguration": {"level": level(code.severity())},
        })
    });
    let mut results = Vec::new();
    for change in diff.changes() {
        for code in change.risks() {
            let index = codes
                .iter()
                .position(|listed| listed == code)
                .unwrap_or_default();
            results.push(json!({
                "ruleId": code.as_str(),
                "ruleIndex": offset + index,
                "level": level(code.severity()),
                "message": {
                    "text": format!("{}: {}", change.field(), code.description()),
                },
                "locations": [{
                    "logicalLocations": [{
                        "fullyQualifiedName": change.field(),
                        "kind": "member",
                    }],
                }],
                "properties": {
                    "section": change.section().as_str(),
                    "kind": change.kind().as_str(),
                    "class": change.class().as_str(),
                    "effect": change.effect().as_str(),
                },
            }));
        }
    }
    if let Some(listed) = run["tool"]["driver"]["rules"].as_array_mut() {
        listed.extend(rules);
    }
    if let Some(listed) = run["results"].as_array_mut() {
        listed.extend(results);
    }
    log
}

fn level(severity: Severity) -> &'static str {
    match severity {
        Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}

#[cfg(test)]
mod tests;
