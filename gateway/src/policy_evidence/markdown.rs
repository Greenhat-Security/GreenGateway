//! The Markdown rendering of a `policy-evidence-report.v1` report.
//!
//! [`render`] reads the report's RFC 8785 bytes and nothing else, and writes
//! them through one fixed template: headings, labels and sentences that are
//! part of this module, with the report's values in between. Every value is a
//! scalar the report holds at a member the template names, written as an
//! inline code span -- or `none` for `null` and `(empty)` for an empty
//! string -- so no value ever becomes Markdown structure, a link or HTML.
//! Inside a span every character that is not printable ASCII, the backtick,
//! the pipe, the backslash and a space at either end are written as
//! `\u{XXXX}`, so a span can neither end early, split a table cell, lose a
//! space, nor carry a control, bidirectional or invisible character. A member
//! the template does not name is never rendered, so the rendering carries no
//! more than the report, and it leaves much of the report out: per-case
//! results, the replay result, and the analyzer's rationales, lanes and
//! patches.
//!
//! The trust statement is checked, not copied: a report whose statement is
//! not exactly the fixed one for its candidate kind is refused, and the
//! rendering then writes that fixed statement verbatim.
//!
//! Rendering is pure and deterministic: the same report bytes always give
//! the same Markdown bytes.

use serde_json::Value;

use super::{DRAFT_TRUST_STATEMENT, TRUST_STATEMENT};

/// How `null` is written.
const NONE: &str = "none";
/// How an empty string is written: an empty code span is not Markdown.
const EMPTY: &str = "(empty)";

const INTRODUCTION: &str = "This file is derived from the canonical JSON report this package's \
manifest names, through a fixed template. The JSON report is authoritative. This file repeats \
only values the report holds, and leaves many of them out.";

const NO_DIAGNOSTICS: &str = "Revalidation reported no diagnostics.";

const NO_FINDINGS: &str = "The analyzer reported no findings. That does not show that the \
policy has none of the problems the analyzer looks for: it reports only what it can prove, \
and its blind spots are documented.";

/// Why a report was not rendered. Nothing partial is ever returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MarkdownError {
    /// The bytes are not a report the assembler produces: not JSON, a
    /// member the template reads is missing or of another type, or the trust
    /// statement is not the fixed one for the report's candidate kind.
    Unrecognized,
}

/// The Markdown for the report whose RFC 8785 bytes are `report_bytes`.
pub(crate) fn render(report_bytes: &[u8]) -> Result<String, MarkdownError> {
    let report: Value =
        serde_json::from_slice(report_bytes).map_err(|_| MarkdownError::Unrecognized)?;
    let kind = at(&report, "/candidate_kind")?
        .as_str()
        .ok_or(MarkdownError::Unrecognized)?;
    let statement = match kind {
        "publication" => TRUST_STATEMENT,
        "draft" => DRAFT_TRUST_STATEMENT,
        _ => return Err(MarkdownError::Unrecognized),
    };
    if at(&report, "/trust/statement")?.as_str() != Some(statement) {
        return Err(MarkdownError::Unrecognized);
    }

    let mut page = Page::default();
    page.line("# Policy evidence report");
    page.blank();
    page.paragraph(INTRODUCTION);
    page.line(&format!("> {statement}"));

    page.heading("Summary");
    page.fields(vec![
        ("Candidate kind", value(&report, "/candidate_kind")?),
        ("Completeness", value(&report, "/completeness")?),
        ("Limitations", list(&report, "/limitations")?),
        ("Report schema version", value(&report, "/schema_version")?),
        ("Redaction profile", value(&report, "/redaction_profile")?),
        ("Gateway version", value(&report, "/gateway_version")?),
        ("Request digest", value(&report, "/request_digest")?),
        ("Signed", value(&report, "/trust/signed")?),
    ]);

    page.heading("Evaluator");
    page.fields(vec![
        (
            "HTTP semantics version",
            value(&report, "/evaluator/http_semantics_version")?,
        ),
        (
            "HTTP context version",
            value(&report, "/evaluator/http_context_version")?,
        ),
        (
            "Tool semantics version",
            value(&report, "/evaluator/tool_semantics_version")?,
        ),
        (
            "Tool context version",
            value(&report, "/evaluator/tool_context_version")?,
        ),
        (
            "Replay context version",
            value(&report, "/evaluator/replay_context_version")?,
        ),
    ]);

    if kind == "publication" {
        publication(&mut page, &report)?;
    } else {
        draft(&mut page, &report)?;
    }
    validation(&mut page, &report)?;
    tests(&mut page, &report)?;
    simulation(&mut page, &report)?;
    replay(&mut page, &report)?;
    analysis(&mut page, &report)?;
    Ok(page.text)
}

fn publication(page: &mut Page, report: &Value) -> Result<(), MarkdownError> {
    page.heading("Publication");
    let mut rows = vec![
        ("History version", value(report, "/publication/version")?),
        (
            "Policy schema version",
            value(report, "/publication/policy/schema_version")?,
        ),
        ("Policy ETag", value(report, "/publication/policy/etag")?),
        (
            "Policy semantic digest",
            value(report, "/publication/policy/semantic_digest")?,
        ),
    ];
    if at(report, "/publication/predecessor")?.is_null() {
        rows.push(("Predecessor", NONE.to_owned()));
    } else {
        rows.push((
            "Predecessor version",
            value(report, "/publication/predecessor/version")?,
        ));
        rows.push((
            "Predecessor policy ETag",
            value(report, "/publication/predecessor/policy/etag")?,
        ));
        rows.push((
            "Predecessor semantic digest",
            value(report, "/publication/predecessor/policy/semantic_digest")?,
        ));
    }
    rows.push((
        "Predecessor check",
        value(report, "/publication/predecessor_check")?,
    ));
    page.fields(rows);

    page.heading("Approval as recorded");
    let mut rows = vec![
        ("Basis", value(report, "/approval/basis")?),
        ("Operation", value(report, "/approval/operation")?),
        ("Recorded at", value(report, "/approval/recorded_at")?),
        ("Actor", value(report, "/approval/actor")?),
    ];
    for (label, pointer) in [
        ("Draft revision", "/approval/draft/revision"),
        ("Draft base ETag", "/approval/draft/base_etag"),
        (
            "Shadow review transition",
            "/approval/shadow_review/transition",
        ),
        (
            "Shadow review policy ETag",
            "/approval/shadow_review/policy_etag",
        ),
        (
            "Shadow review evidence digest",
            "/approval/shadow_review/evidence_digest",
        ),
        (
            "Rollback target version",
            "/approval/rollback_target_version",
        ),
        ("Rule id", "/approval/rule_id"),
    ] {
        if let Some(present) = report.pointer(pointer) {
            rows.push((label, scalar(present)?));
        }
    }
    page.fields(rows);
    Ok(())
}

fn draft(page: &mut Page, report: &Value) -> Result<(), MarkdownError> {
    page.heading("Draft");
    page.fields(vec![
        ("Draft id", value(report, "/draft/draft_id")?),
        ("Draft revision", value(report, "/draft/revision")?),
        ("Draft ETag", value(report, "/draft/draft_etag")?),
        (
            "Policy schema version",
            value(report, "/draft/policy/schema_version")?,
        ),
        ("Policy ETag", value(report, "/draft/policy/etag")?),
        (
            "Policy semantic digest",
            value(report, "/draft/policy/semantic_digest")?,
        ),
        ("Base source", value(report, "/draft/base/source")?),
        (
            "Base policy schema version",
            value(report, "/draft/base/policy/schema_version")?,
        ),
        (
            "Base policy ETag",
            value(report, "/draft/base/policy/etag")?,
        ),
        (
            "Base policy semantic digest",
            value(report, "/draft/base/policy/semantic_digest")?,
        ),
    ]);
    Ok(())
}

fn validation(page: &mut Page, report: &Value) -> Result<(), MarkdownError> {
    page.heading("Validation");
    let mut rows = vec![
        ("Basis", value(report, "/validation/basis")?),
        ("Valid", value(report, "/validation/valid")?),
        (
            "Diagnostics truncated",
            value(report, "/validation/diagnostics_truncated")?,
        ),
    ];
    if at(report, "/validation/resource_snapshot")?.is_null() {
        rows.push(("Resource snapshot", NONE.to_owned()));
    } else {
        if let Some(digest) = report.pointer("/validation/resource_snapshot/digest") {
            rows.push(("Resource snapshot digest", scalar(digest)?));
        }
        rows.push((
            "Resource snapshot complete",
            value(report, "/validation/resource_snapshot/complete")?,
        ));
    }
    page.fields(rows);
    let diagnostics = array(report, "/validation/diagnostics")?;
    if diagnostics.is_empty() {
        page.blank();
        page.paragraph(NO_DIAGNOSTICS);
        return Ok(());
    }
    let mut rows = Vec::with_capacity(diagnostics.len());
    for diagnostic in diagnostics {
        rows.push(vec![
            value(diagnostic, "/severity")?,
            value(diagnostic, "/code")?,
            value(diagnostic, "/pointer")?,
            optional(diagnostic, "/element_id")?,
            value(diagnostic, "/blocks/evidence")?,
        ]);
    }
    page.blank();
    page.table(
        &[
            "Severity",
            "Code",
            "Pointer",
            "Element id",
            "Blocks evidence",
        ],
        &rows,
    );
    Ok(())
}

fn tests(page: &mut Page, report: &Value) -> Result<(), MarkdownError> {
    page.heading("Tests");
    if !included(report, "/tests/included")? {
        page.fields(vec![("Included", value(report, "/tests/included")?)]);
        return Ok(());
    }
    page.fields(vec![
        ("Included", value(report, "/tests/included")?),
        ("Status", value(report, "/tests/results/status")?),
        (
            "Suite digest",
            value(report, "/tests/results/suite/digest")?,
        ),
        (
            "Policy source",
            value(report, "/tests/results/policy/source")?,
        ),
        ("Policy ETag", value(report, "/tests/results/policy/etag")?),
        ("Cases", value(report, "/tests/results/summary/total")?),
        ("Passed", value(report, "/tests/results/summary/passed")?),
        ("Failed", value(report, "/tests/results/summary/failed")?),
        (
            "Incomplete",
            value(report, "/tests/results/summary/incomplete")?,
        ),
        ("Errors", value(report, "/tests/results/summary/errors")?),
    ]);
    Ok(())
}

fn simulation(page: &mut Page, report: &Value) -> Result<(), MarkdownError> {
    page.heading("Simulation");
    if !included(report, "/simulation/included")? {
        page.fields(vec![("Included", value(report, "/simulation/included")?)]);
        return Ok(());
    }
    let mut rows = vec![
        ("Included", value(report, "/simulation/included")?),
        ("Mode", value(report, "/simulation/mode")?),
        ("Trace", value(report, "/simulation/trace")?),
        ("Projections", list(report, "/simulation/projections")?),
    ];
    if at(report, "/simulation/base")?.is_null() {
        rows.push(("Base", NONE.to_owned()));
    } else {
        if let Some(version) = report.pointer("/simulation/base/version") {
            rows.push(("Base version", scalar(version)?));
        }
        rows.push(("Base ETag", value(report, "/simulation/base/etag")?));
    }
    for (label, pointer) in [
        ("Candidate version", "/simulation/candidate/version"),
        (
            "Candidate draft revision",
            "/simulation/candidate/draft_revision",
        ),
    ] {
        if let Some(present) = report.pointer(pointer) {
            rows.push((label, scalar(present)?));
        }
    }
    rows.push((
        "Candidate ETag",
        value(report, "/simulation/candidate/etag")?,
    ));
    rows.push(("Cases", value(report, "/simulation/summary/cases")?));
    page.fields(rows);

    let summaries = at(report, "/simulation/summary/projections")?;
    let mut rows = Vec::new();
    for projection in array(report, "/simulation/projections")? {
        let name = projection.as_str().ok_or(MarkdownError::Unrecognized)?;
        let counts = summaries.get(name).ok_or(MarkdownError::Unrecognized)?;
        rows.push(vec![
            scalar(projection)?,
            value(counts, "/would_forward")?,
            value(counts, "/would_block")?,
            value(counts, "/unknown")?,
            value(counts, "/shadowed")?,
            optional(counts, "/changed_from_base")?,
        ]);
    }
    page.blank();
    page.table(
        &[
            "Projection",
            "Would forward",
            "Would block",
            "Unknown",
            "Shadowed",
            "Changed from base",
        ],
        &rows,
    );
    Ok(())
}

fn replay(page: &mut Page, report: &Value) -> Result<(), MarkdownError> {
    page.heading("Historical impact");
    if !included(report, "/replay/included")? {
        page.fields(vec![("Included", value(report, "/replay/included")?)]);
        return Ok(());
    }
    page.fields(vec![
        ("Included", value(report, "/replay/included")?),
        ("Mode", value(report, "/replay/mode")?),
        ("State", value(report, "/replay/state")?),
        ("Base ETag", value(report, "/replay/base/etag")?),
        ("Candidate ETag", value(report, "/replay/candidate/etag")?),
        ("Window from", value(report, "/replay/window/from")?),
        ("Window to", value(report, "/replay/window/to")?),
        (
            "Predecessor check",
            value(report, "/replay/predecessor_check")?,
        ),
        ("Result digest", value(report, "/replay/result_digest")?),
    ]);
    Ok(())
}

fn analysis(page: &mut Page, report: &Value) -> Result<(), MarkdownError> {
    page.heading("Analysis");
    if !included(report, "/analysis/included")? {
        page.fields(vec![("Included", value(report, "/analysis/included")?)]);
        return Ok(());
    }
    page.fields(vec![
        ("Included", value(report, "/analysis/included")?),
        (
            "Artifact digest",
            value(report, "/analysis/artifact/digest")?,
        ),
        ("Artifact size", value(report, "/analysis/artifact/size")?),
        (
            "Analyzer version",
            value(report, "/analysis/analyzer/version")?,
        ),
        (
            "Analyzed source",
            value(report, "/analysis/analyzed/source")?,
        ),
        ("Analyzed ETag", value(report, "/analysis/analyzed/etag")?),
        ("Complete", value(report, "/analysis/complete")?),
        ("Limitations", list(report, "/analysis/limitations")?),
        (
            "Suppression records read",
            value(report, "/analysis/suppressions/available")?,
        ),
        (
            "Suppression records",
            value(report, "/analysis/suppressions/records")?,
        ),
        ("Findings", value(report, "/analysis/summary/findings")?),
        (
            "Candidate patches",
            value(report, "/analysis/summary/patches")?,
        ),
    ]);

    let mut rows = Vec::new();
    for (label, pointer) in [
        ("Severity high", "/analysis/summary/by_severity/high"),
        ("Severity medium", "/analysis/summary/by_severity/medium"),
        ("Severity low", "/analysis/summary/by_severity/low"),
        (
            "Proof basis proven",
            "/analysis/summary/by_proof_basis/proven",
        ),
        (
            "Proof basis heuristic",
            "/analysis/summary/by_proof_basis/heuristic",
        ),
        (
            "Proof basis inconclusive",
            "/analysis/summary/by_proof_basis/inconclusive",
        ),
        (
            "Suppressed",
            "/analysis/summary/by_suppression_state/suppressed",
        ),
        (
            "Suppression expired",
            "/analysis/summary/by_suppression_state/suppression_expired",
        ),
        (
            "Suppression mismatched",
            "/analysis/summary/by_suppression_state/suppression_mismatched",
        ),
    ] {
        rows.push(vec![label.to_owned(), value(report, pointer)?]);
    }
    page.blank();
    page.table(&["Count", "Findings"], &rows);

    let findings = array(report, "/analysis/findings")?;
    page.blank();
    if findings.is_empty() {
        page.paragraph(NO_FINDINGS);
        return Ok(());
    }
    let mut rows = Vec::with_capacity(findings.len());
    for finding in findings {
        let suppression = at(finding, "/suppression")?;
        let (state, id) = if suppression.is_null() {
            (NONE.to_owned(), NONE.to_owned())
        } else {
            (
                value(suppression, "/state")?,
                value(suppression, "/suppression_id")?,
            )
        };
        rows.push(vec![
            value(finding, "/severity")?,
            value(finding, "/code")?,
            value(finding, "/proof_basis")?,
            value(finding, "/element/pointer")?,
            optional(finding, "/element/id")?,
            state,
            id,
        ]);
    }
    page.table(
        &[
            "Severity",
            "Code",
            "Proof basis",
            "Pointer",
            "Element id",
            "Suppression",
            "Suppression id",
        ],
        &rows,
    );
    Ok(())
}

/// The page being written: lines joined by `\n`, ending in one.
#[derive(Default)]
struct Page {
    text: String,
}

impl Page {
    fn line(&mut self, line: &str) {
        self.text.push_str(line);
        self.text.push('\n');
    }

    fn blank(&mut self) {
        self.text.push('\n');
    }

    fn paragraph(&mut self, text: &str) {
        self.line(text);
        self.blank();
    }

    fn heading(&mut self, title: &str) {
        self.blank();
        self.line(&format!("## {title}"));
        self.blank();
    }

    fn table(&mut self, header: &[&str], rows: &[Vec<String>]) {
        self.line(&format!("| {} |", header.join(" | ")));
        self.line(&format!("|{}", " --- |".repeat(header.len())));
        for row in rows {
            self.line(&format!("| {} |", row.join(" | ")));
        }
    }

    fn fields(&mut self, rows: Vec<(&str, String)>) {
        let rows = rows
            .into_iter()
            .map(|(label, value)| vec![label.to_owned(), value])
            .collect::<Vec<_>>();
        self.table(&["Field", "Value"], &rows);
    }
}

fn at<'a>(report: &'a Value, pointer: &str) -> Result<&'a Value, MarkdownError> {
    report.pointer(pointer).ok_or(MarkdownError::Unrecognized)
}

fn array<'a>(report: &'a Value, pointer: &str) -> Result<&'a [Value], MarkdownError> {
    at(report, pointer)?
        .as_array()
        .map(Vec::as_slice)
        .ok_or(MarkdownError::Unrecognized)
}

fn included(report: &Value, pointer: &str) -> Result<bool, MarkdownError> {
    at(report, pointer)?
        .as_bool()
        .ok_or(MarkdownError::Unrecognized)
}

/// The scalar at `pointer`, which must be present.
fn value(report: &Value, pointer: &str) -> Result<String, MarkdownError> {
    scalar(at(report, pointer)?)
}

/// The scalar at `pointer`, or `none` when the member is absent.
fn optional(report: &Value, pointer: &str) -> Result<String, MarkdownError> {
    match report.pointer(pointer) {
        None => Ok(NONE.to_owned()),
        Some(present) => scalar(present),
    }
}

/// The scalars of the array at `pointer`, comma-separated, or `none`.
fn list(report: &Value, pointer: &str) -> Result<String, MarkdownError> {
    let items = array(report, pointer)?;
    if items.is_empty() {
        return Ok(NONE.to_owned());
    }
    Ok(items
        .iter()
        .map(scalar)
        .collect::<Result<Vec<_>, _>>()?
        .join(", "))
}

/// One value as the template writes it. Only scalars are values: a member
/// the template expects to hold one but holding an array or object is a
/// report this template does not know.
fn scalar(value: &Value) -> Result<String, MarkdownError> {
    Ok(match value {
        Value::Null => NONE.to_owned(),
        Value::Bool(flag) => code_span(if *flag { "true" } else { "false" }),
        Value::Number(number) => code_span(&number.to_string()),
        Value::String(text) if text.is_empty() => EMPTY.to_owned(),
        Value::String(text) => code_span(text),
        Value::Array(_) | Value::Object(_) => return Err(MarkdownError::Unrecognized),
    })
}

/// `text` as an inline code span whose content is printable ASCII without
/// the backtick, the pipe or the backslash: every other character, and a
/// space at either end (which a code span would strip), is written as
/// `\u{XXXX}`. A raw backslash never appears in the content, so the notation
/// is unambiguous.
pub(crate) fn code_span(text: &str) -> String {
    let last = text.chars().count().saturating_sub(1);
    let mut span = String::with_capacity(text.len() + 2);
    span.push('`');
    for (index, character) in text.chars().enumerate() {
        let edge_space = character == ' ' && (index == 0 || index == last);
        if (' '..='~').contains(&character) && !matches!(character, '`' | '|' | '\\') && !edge_space
        {
            span.push(character);
        } else {
            span.push_str(&format!("\\u{{{:04X}}}", u32::from(character)));
        }
    }
    span.push('`');
    span
}
