//! `ggctl schema [KIND] [--api-version VERSION]`.

use gateway_config::documents::{
    api_versions_of, published_schema, PublishedSchema, PUBLISHED_SCHEMAS,
};
use serde::Serialize;

use crate::{
    cli::Invocation,
    diagnostic::{Code, Diagnostic, Exit},
    report::{self, Format, Io},
};

/// One `(apiVersion, kind)` document version in a report.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DocumentRecord {
    pub(crate) api_version: &'static str,
    pub(crate) kind: &'static str,
}

impl From<&PublishedSchema> for DocumentRecord {
    fn from(schema: &PublishedSchema) -> Self {
        Self {
            api_version: schema.api_version,
            kind: schema.kind,
        }
    }
}

/// Every published document version, in the published order.
pub(crate) fn published() -> Vec<DocumentRecord> {
    PUBLISHED_SCHEMAS.iter().map(DocumentRecord::from).collect()
}

#[derive(Serialize)]
struct SchemaList {
    schemas: Vec<DocumentRecord>,
}

pub(crate) fn run(invocation: &Invocation, io: &mut Io<'_>) -> Exit {
    match invocation.positional(0) {
        None => list(invocation, io),
        Some((_, kind)) => print(invocation, io, kind),
    }
}

fn list(invocation: &Invocation, io: &mut Io<'_>) -> Exit {
    let api_version = invocation.text("--api-version").map(|(_, version)| version);
    let schemas: Vec<_> = PUBLISHED_SCHEMAS
        .iter()
        .filter(|schema| api_version.is_none_or(|version| schema.api_version == version))
        .map(DocumentRecord::from)
        .collect();
    let diagnostics = if schemas.is_empty() {
        vec![Diagnostic::new(Code::UnsupportedSchemaVersion)]
    } else {
        Vec::new()
    };
    report::finish(
        io,
        Format::of(invocation),
        "schema",
        &SchemaList { schemas },
        &diagnostics,
        |list, out| {
            for schema in &list.schemas {
                writeln!(out, "{}  {}", schema.api_version, schema.kind)?;
            }
            Ok(())
        },
    )
}

/// Writes the schema itself: an artifact, so `--format` does not apply.
fn print(invocation: &Invocation, io: &mut Io<'_>, kind: &str) -> Exit {
    if let Some((position, _)) = invocation.text("--format") {
        return report::error(io, Diagnostic::at(Code::FormatUnsupported, position));
    }
    let api_version = match invocation.text("--api-version") {
        Some((_, version)) => Some(version),
        None => api_versions_of(kind).last(),
    };
    match api_version.and_then(|version| published_schema(version, kind)) {
        // The same bytes on every platform, whatever line endings the
        // checkout that built this binary used.
        Some(schema) => report::artifact(io, &schema.json.replace("\r\n", "\n")),
        None => report::error(io, Diagnostic::new(Code::UnsupportedSchemaVersion)),
    }
}
