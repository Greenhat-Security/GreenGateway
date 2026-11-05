//! `ggctl diff (BUNDLE | --env FILE) (--against BUNDLE | --against-env FILE)
//! [--check] [--strict] [--format human|json|sarif]` (issue #242, PR 9;
//! ADR-0008, "Plan, risk acknowledgment, and conditional apply").
//!
//! Both bundles are read by the shared reader with the production
//! validators, exactly as `ggctl validate` reads them, and compared by
//! `gateway_config::semantic_diff::compare_production_bundles`, the diff the
//! revision ledger's plans make, by the documents those validators built:
//! the CLI cannot approximate either. Two environment files are each
//! compiled by the gateway's own configuration compiler, exactly as
//! `ggctl validate --env` compiles one, and their plans compared by
//! `compiler::semantic_diff::plans`, setting by setting. An environment file
//! and a bundle are read and reported but never compared: no front end maps
//! a bundle onto the compiler's settings yet, and an environment plan holds
//! no policy or tools document, so there is no common ground to compare
//! (`diff.not_comparable`). The change is from the `--against` side to the
//! other. Everything written is value-free because the diff is:
//!
//! - human: one line per change, then the sorted risk codes;
//! - `--format json`: one `GgctlReport` whose `result` carries the
//!   `diffResult`;
//! - `--format sarif`: the reader's diagnostics as `ggctl validate` reports
//!   them, then one result per risk code of each change, with the change's
//!   field as a logical location, so CI can annotate a review. A change that
//!   carries no risk code is not a finding and is not a result.
//!
//! `--check` adds `diff.drift_found` (exit `4`) when anything differs. An
//! input that is invalid is not compared: the command reports its
//! diagnostics and exits as `ggctl validate` would.

use gateway_config::{
    compiler,
    semantic_diff::{compare_production_bundles, Change, Display, SemanticDiff, Severity, Shown},
};
use serde::Serialize;
use serde_json::{json, Value};

use crate::{
    cli::Invocation,
    diagnostic::{Code, Diagnostic, Exit},
    env::{self, EnvRead, EnvRecord, Source},
    report::{self, Format, Io, ReportDiagnostic},
    sarif,
    validate::{self, BundleRead, BundleRecord},
};

/// Where every risk code is described.
const RISK_CODES_ANCHOR: &str = "docs/semantic-diff.md#risk-codes";

/// The `diff` result.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DiffCommandResult<'a> {
    /// Both inputs were read with no error and could be compared, so they
    /// were.
    valid: bool,
    /// `BUNDLE`, the candidate. Present once its manifest was read.
    #[serde(skip_serializing_if = "Option::is_none")]
    bundle: Option<BundleRecord>,
    /// The `--against` bundle, the base. Present once its manifest was read.
    #[serde(skip_serializing_if = "Option::is_none")]
    against: Option<BundleRecord>,
    /// The `--env` file, the candidate. Present once it was parsed.
    #[serde(skip_serializing_if = "Option::is_none")]
    environment: Option<EnvRecord>,
    /// The `--against-env` file, the base. Present once it was parsed.
    #[serde(skip_serializing_if = "Option::is_none")]
    against_environment: Option<EnvRecord>,
    /// The changes from the base to the candidate, when both were compared.
    #[serde(skip_serializing_if = "Option::is_none")]
    diff: Option<&'a SemanticDiff>,
}

/// One side of a diff, as far as it was read. Both reads are large, a
/// compiled plan especially, so each is boxed.
enum Side {
    Bundle(Box<BundleRead>),
    Env(Box<EnvRead>),
}

impl Side {
    fn read(source: Source<'_>, strict: bool) -> Self {
        match source {
            Source::Bundle(path) => Self::Bundle(Box::new(validate::read_path(path, strict))),
            Source::Env { argument, path } => {
                Self::Env(Box::new(env::read(argument, path, strict)))
            }
        }
    }

    fn diagnostics(&self) -> Vec<ReportDiagnostic> {
        match self {
            Self::Bundle(read) => validate::diagnostics(read),
            Self::Env(read) => read.diagnostics.clone(),
        }
    }

    fn bundle(&self) -> Option<BundleRecord> {
        match self {
            Self::Bundle(read) => BundleRecord::of(read),
            Self::Env(_) => None,
        }
    }

    fn environment(&self) -> Option<EnvRecord> {
        match self {
            Self::Bundle(_) => None,
            Self::Env(read) => read.record(),
        }
    }
}

pub(crate) fn run(invocation: &Invocation, io: &mut Io<'_>) -> Exit {
    let strict = invocation.flag("--strict").is_some();
    let sources = validate::source(invocation).and_then(|candidate| {
        let base = env::source(
            invocation,
            invocation.value("--against").map(|(_, path)| path),
            "--against-env",
        )?;
        Ok((candidate, base))
    });
    let (candidate, base) = match sources {
        Ok((candidate, base)) => (Side::read(candidate, strict), Side::read(base, strict)),
        Err(diagnostic) => return report::error(io, diagnostic),
    };
    let mut diagnostics = candidate.diagnostics();
    diagnostics.extend(base.diagnostics());
    let diff = match (&base, &candidate) {
        (Side::Bundle(base), Side::Bundle(candidate)) => match (&base.bundle, &candidate.bundle) {
            (Some(base), Some(candidate)) => Some(compare_production_bundles(base, candidate)),
            _ => None,
        },
        (Side::Env(base), Side::Env(candidate)) => match (base.plan(), candidate.plan()) {
            (Some(base), Some(candidate)) => Some(compiler::semantic_diff::plans(base, candidate)),
            _ => None,
        },
        (Side::Bundle(_), Side::Env(_)) | (Side::Env(_), Side::Bundle(_)) => {
            // Located at the option that names the environment file.
            let argument = ["--env", "--against-env"]
                .into_iter()
                .find_map(|option| invocation.value(option))
                .map(|(position, _)| position);
            diagnostics.push(
                Diagnostic {
                    argument,
                    ..Diagnostic::new(Code::NotComparable)
                }
                .into(),
            );
            None
        }
    };
    if let (Some(diff), Some(position)) = (&diff, invocation.flag("--check")) {
        if exit(diff, true) == Exit::Drift {
            diagnostics.push(Diagnostic::at(Code::DriftFound, position).into());
        }
    }
    let result = DiffCommandResult {
        valid: diff.is_some(),
        bundle: candidate.bundle(),
        against: base.bundle(),
        environment: candidate.environment(),
        against_environment: base.environment(),
        diff: diff.as_ref(),
    };
    let comparable = !matches!(
        (&base, &candidate),
        (Side::Bundle(_), Side::Env(_)) | (Side::Env(_), Side::Bundle(_))
    );
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
                    None if !comparable => writeln!(
                        out,
                        "not compared: an environment file and a bundle cannot be compared"
                    ),
                    None => writeln!(out, "not compared: an input is invalid"),
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
    // Read without indexing, which would insert the base into a log that
    // has no bundle-relative location.
    if let Some(base) = run
        .get_mut("originalUriBaseIds")
        .and_then(|bases| bases.get_mut(sarif::BUNDLE_ROOT))
        .and_then(Value::as_object_mut)
    {
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
