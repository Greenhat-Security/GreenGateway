//! `ggctl validate BUNDLE [--strict] [--warnings-as-errors]
//! [--format human|json|sarif]`.
//!
//! The bundle is read by the shared reader in `gateway-config`, the code the
//! gateway reads bundles with (ADR-0008, "One compiler"), so the two cannot
//! disagree about anything the reader decides. `ggctl` cannot link the
//! gateway's production policy and tools validators, so it reads with
//! [`PublishedSchemasOnly`], and every report about a bundled policy or tools
//! document says those validators did not run. Nothing is written, no
//! network request is made and no environment variable is read.

use std::{
    io::{self, Write},
    path::Path,
};

use gateway_config::bundle::{
    self, BundleReport, BundledResource, Profile, PublishedSchemasOnly, ReadOptions,
    ResourceDeclaration,
};
use serde::Serialize;
use serde_json::Value;

use crate::{
    cli::Invocation,
    diagnostic::{Code, Diagnostic, Exit},
    report::{self, Format, Io, ReportDiagnostic},
};

/// What the schema-only reader returns.
pub(crate) type BundleRead = BundleReport<Value, Value>;

/// Reads the bundle the command's `BUNDLE` argument names, or `None` when
/// there is no such argument (the parser requires one).
pub(crate) fn read(invocation: &Invocation, strict: bool) -> Option<BundleRead> {
    let (_, path) = invocation.positional(0)?;
    Some(bundle::read_bundle(
        Path::new(path),
        ReadOptions { strict },
        &PublishedSchemasOnly,
    ))
}

/// The bundle reader's diagnostics as a report carries them.
pub(crate) fn diagnostics(read: &BundleRead) -> Vec<ReportDiagnostic> {
    read.diagnostics
        .iter()
        .cloned()
        .map(ReportDiagnostic::from)
        .collect()
}

/// What a report says about a bundle: what its manifest declares and, once
/// every stage passed, its digests and profile. File names, versions and
/// digests only; never document content.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BundleRecord {
    api_version: &'static str,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_digest: Option<String>,
    deployment: DeploymentRecord,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy: Option<ResourceRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tools: Option<ResourceRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    connections: Option<&'static str>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DeploymentRecord {
    file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    profile: Option<&'static str>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ResourceRecord {
    /// `bundle` or `server`.
    source: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    schema_version: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sha256: Option<String>,
    /// For a document the bundle supplies, always `not_run`: the production
    /// validators are not part of `ggctl`.
    #[serde(skip_serializing_if = "Option::is_none")]
    production_validator: Option<&'static str>,
}

impl BundleRecord {
    /// `None` when the manifest itself could not be read.
    pub(crate) fn of(read: &BundleRead) -> Option<Self> {
        let manifest = read.manifest.as_ref()?;
        let bundle = read.bundle.as_ref();
        Some(Self {
            api_version: manifest.api_version.as_str(),
            name: manifest.name.clone(),
            source_digest: bundle.map(|bundle| bundle.source_digest.clone()),
            deployment: DeploymentRecord {
                file: manifest.deployment.as_str().to_owned(),
                sha256: bundle.map(|bundle| bundle.deployment.sha256.clone()),
                profile: bundle.map(|bundle| bundle.deployment.profile.as_str()),
            },
            policy: manifest.policy.as_ref().map(|declaration| {
                ResourceRecord::of(
                    declaration,
                    bundle.and_then(|bundle| bundle.policy.as_ref()),
                )
            }),
            tools: manifest.tools.as_ref().map(|declaration| {
                ResourceRecord::of(declaration, bundle.and_then(|bundle| bundle.tools.as_ref()))
            }),
            connections: manifest.connections_from_server.then_some("server"),
        })
    }

    /// The headline: the bundle's name and document version.
    pub(crate) fn title(&self) -> String {
        format!("bundle {} ({})", self.name, self.api_version)
    }

    /// The indented detail lines of the human form.
    pub(crate) fn write_details(&self, out: &mut dyn Write) -> io::Result<()> {
        if let Some(digest) = &self.source_digest {
            writeln!(out, "  source digest  {digest}")?;
        }
        write!(out, "  deployment     {}", self.deployment.file)?;
        // ADR-0008: every report labels a development deployment
        // non-production.
        match self.deployment.profile {
            Some(profile) if profile == Profile::Development.as_str() => {
                writeln!(out, " (profile {profile}, non-production)")?;
            }
            Some(profile) => writeln!(out, " (profile {profile})")?,
            None => writeln!(out)?,
        }
        for (label, resource) in [("policy", &self.policy), ("tools", &self.tools)] {
            let Some(resource) = resource else {
                continue;
            };
            match (&resource.file, resource.schema_version) {
                (Some(file), Some(version)) => {
                    writeln!(out, "  {label:<13}  {file} (schema_version {version})")?;
                }
                _ => writeln!(out, "  {label:<13}  {}", resource.source)?,
            }
        }
        if let Some(connections) = self.connections {
            writeln!(out, "  connections    {connections}")?;
        }
        Ok(())
    }
}

impl ResourceRecord {
    fn of(declaration: &ResourceDeclaration, read: Option<&BundledResource<Value>>) -> Self {
        match declaration {
            ResourceDeclaration::Server => Self {
                source: "server",
                file: None,
                schema_version: None,
                sha256: None,
                production_validator: None,
            },
            ResourceDeclaration::Bundle {
                file,
                schema_version,
            } => Self {
                source: "bundle",
                file: Some(file.as_str().to_owned()),
                schema_version: Some(schema_version),
                sha256: match read {
                    Some(BundledResource::Bundle { sha256, .. }) => Some(sha256.clone()),
                    _ => None,
                },
                production_validator: Some("not_run"),
            },
        }
    }
}

/// Whether the manifest has the bundle supply a policy or tools document.
pub(crate) fn supplies_a_resource(read: &BundleRead) -> bool {
    read.manifest.as_ref().is_some_and(|manifest| {
        [&manifest.policy, &manifest.tools]
            .into_iter()
            .flatten()
            .any(|declaration| matches!(declaration, ResourceDeclaration::Bundle { .. }))
    })
}

/// The `validate` result.
#[derive(Debug, Serialize)]
struct ValidateResult {
    /// No stage of the reader found an error.
    valid: bool,
    /// Present once the manifest was read.
    #[serde(skip_serializing_if = "Option::is_none")]
    bundle: Option<BundleRecord>,
}

pub(crate) fn run(invocation: &Invocation, io: &mut Io<'_>) -> Exit {
    let Some(read) = read(invocation, invocation.flag("--strict").is_some()) else {
        return report::error(io, Diagnostic::new(Code::MissingArgument));
    };
    let mut diagnostics = diagnostics(&read);
    if supplies_a_resource(&read) {
        diagnostics.push(Diagnostic::new(Code::ProductionValidatorsNotRun).into());
    }
    let errors = read
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.is_error())
        .count();
    let warnings = read.diagnostics.len() - errors;
    if let Some(position) = invocation.flag("--warnings-as-errors") {
        if warnings > 0 {
            diagnostics.push(Diagnostic::at(Code::WarningsAsErrors, position).into());
        }
    }
    let result = ValidateResult {
        valid: read.bundle.is_some(),
        bundle: BundleRecord::of(&read),
    };
    report::finish_report(
        io,
        Format::of(invocation),
        "validate",
        &result,
        &diagnostics,
        |result, out| {
            let title = result
                .bundle
                .as_ref()
                .map_or_else(|| "bundle".to_owned(), BundleRecord::title);
            let verdict = if result.valid { "valid" } else { "invalid" };
            write!(out, "{title}: {verdict}")?;
            for (count, noun) in [(errors, "error"), (warnings, "warning")] {
                match count {
                    0 => {}
                    1 => write!(out, ", 1 {noun}")?,
                    _ => write!(out, ", {count} {noun}s")?,
                }
            }
            writeln!(out)?;
            match &result.bundle {
                Some(bundle) => bundle.write_details(out),
                None => Ok(()),
            }
        },
    )
}

#[cfg(test)]
pub(crate) mod tests;
