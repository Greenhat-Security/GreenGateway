//! `ggctl evidence verify PACKAGE [--format human|json]` (issue #243 with
//! #242; ADR-0004, `docs/policy-evidence.md`): offline integrity verification
//! of a policy evidence package.
//!
//! The command reads one file and nothing else: no network request, no
//! environment variable, no other file. It holds the package to the form a
//! gateway serves, with the digest code the gateway computes the manifest
//! with (`gateway_config::canonical_json`), so a verifier cannot accept a
//! digest the producer would not have written:
//!
//! - the file is at most 4 MiB, UTF-8 JSON without a byte-order mark, and
//!   exactly its own RFC 8785 bytes, which also refuses a repeated member
//!   name, since the canonical form of a parsed document never repeats one;
//! - the envelope is a `policy-evidence.v1` object of `schema_version`,
//!   `generated_at`, `manifest` and the artifacts its manifest names, and
//!   nothing else;
//! - the manifest names each artifact this `ggctl` knows at most once and in
//!   order, with exactly the media type and schema version its name defines,
//!   and the report always;
//! - each artifact has the size its entry states and the ADR-0004 digest:
//!   a JSON artifact's semantic digest over its RFC 8785 bytes, the Markdown
//!   rendering's source digest over its UTF-8 bytes;
//! - where the report repeats an artifact's manifest entry (the analysis),
//!   the two agree, so the report digest binds that artifact too.
//!
//! A package is unsigned (signing is a later slice), so a package that
//! passes is `integrity_valid` and `unsigned`: unchanged since its manifest
//! was computed, with nothing to show who computed it. `ggctl` never reports
//! a package as trusted, and refuses one whose report claims a signature.

use std::{
    io::{self, Write},
    path::Path,
};

use gateway_config::canonical_json;
use serde::Serialize;
use serde_json::{Map, Value};

use crate::{
    cli::Invocation,
    diagnostic::{Code, Diagnostic, Exit},
    input,
    report::{self, Format, Io},
};

/// The only package schema this `ggctl` verifies.
const PACKAGE_SCHEMA_VERSION: &str = "policy-evidence.v1";
/// The media type a package is served as; its source digest identifies the
/// whole file.
const PACKAGE_MEDIA_TYPE: &str = "application/vnd.greengateway.policy-evidence+json";
/// The largest package a gateway serves, every artifact included.
pub(crate) const MAX_PACKAGE_BYTES: usize = 4 * 1024 * 1024;
/// The envelope members that are not artifacts.
const ENVELOPE_MEMBERS: &[&str] = &["schema_version", "generated_at", "manifest"];
/// The members of every manifest entry.
const ENTRY_MEMBERS: &[&str] = &["name", "media_type", "schema_version", "digest", "size"];
/// More entries than artifacts are never valid; this bounds the work before
/// that is known.
const MAX_MANIFEST_ENTRIES: usize = 16;

/// How an artifact's payload is digested.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Payload {
    /// A JSON value: its semantic digest over its RFC 8785 bytes.
    Json,
    /// A string: its source digest over its UTF-8 bytes.
    Text,
}

/// An artifact a package may carry.
#[derive(Debug)]
struct Artifact {
    /// Its manifest name, which is also its envelope member.
    name: &'static str,
    media_type: &'static str,
    schema_version: &'static str,
    payload: Payload,
    required: bool,
    /// Where the report repeats this artifact's manifest entry, if it does.
    bound_by_report: Option<&'static [&'static str]>,
}

/// Every artifact this `ggctl` verifies, in the order a manifest lists them
/// (`docs/policy-evidence.md`, "Envelope and manifest").
const ARTIFACTS: &[Artifact] = &[
    Artifact {
        name: "report",
        media_type: "application/vnd.greengateway.policy-evidence-report+json",
        schema_version: "policy-evidence-report.v1",
        payload: Payload::Json,
        required: true,
        bound_by_report: None,
    },
    Artifact {
        name: "analysis",
        media_type: "application/vnd.greengateway.policy-analysis-results+json",
        schema_version: "policy-analysis-results.v1",
        payload: Payload::Json,
        required: false,
        bound_by_report: Some(&["analysis", "artifact"]),
    },
    Artifact {
        name: "report_markdown",
        media_type: "text/markdown; charset=utf-8; variant=GFM",
        schema_version: "policy-evidence-report-markdown.v1",
        payload: Payload::Text,
        required: false,
        bound_by_report: None,
    },
];

/// The verdicts a verification reaches.
const INTEGRITY_VALID: &str = "integrity_valid";
const INTEGRITY_INVALID: &str = "integrity_invalid";
const NOT_VERIFIED: &str = "not_verified";

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VerifyResult {
    /// `integrity_valid`, `integrity_invalid`, or `not_verified` for a
    /// version, artifact or signature claim this `ggctl` does not verify.
    pub(crate) verdict: &'static str,
    /// Always `unsigned`: no signature is verified.
    pub(crate) signature: &'static str,
    /// Always `false`.
    pub(crate) trusted: bool,
    /// The envelope, once it was read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) package: Option<PackageRecord>,
    /// Every manifest entry this `ggctl` knows, as the manifest states it.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) artifacts: Vec<ArtifactRecord>,
    /// What the report says of its own completeness, once it verified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) report: Option<ReportSummary>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PackageRecord {
    pub(crate) schema_version: String,
    pub(crate) generated_at: String,
    /// The file's size in bytes.
    pub(crate) size: usize,
    /// The ADR-0004 source digest of the file's bytes.
    pub(crate) source_digest: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ArtifactRecord {
    pub(crate) name: &'static str,
    pub(crate) media_type: &'static str,
    pub(crate) schema_version: &'static str,
    /// The digest and size the manifest states.
    pub(crate) digest: String,
    pub(crate) size: u64,
    /// The artifact is present and its size and digest are the stated ones.
    pub(crate) verified: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct ReportSummary {
    /// `complete` or `incomplete`.
    pub(crate) completeness: String,
    pub(crate) limitations: Vec<String>,
}

/// `ggctl evidence verify PACKAGE`.
pub(crate) fn verify(invocation: &Invocation, io: &mut Io<'_>) -> Exit {
    let Some((position, package)) = invocation.positional(0) else {
        return report::error(io, Diagnostic::new(Code::MissingArgument));
    };
    let (result, diagnostics) = match input::read(
        Path::new(package),
        position,
        MAX_PACKAGE_BYTES,
        Code::EvidencePackageTooLarge,
    ) {
        Ok(bytes) => verify_bytes(&bytes),
        // A package larger than any gateway serves is not one; a file that
        // could not be read was not verified at all.
        Err(diagnostic) if diagnostic.code == Code::EvidencePackageTooLarge => {
            (unverified(INTEGRITY_INVALID), vec![diagnostic])
        }
        Err(diagnostic) => (unverified(NOT_VERIFIED), vec![diagnostic]),
    };
    report::finish(
        io,
        Format::of(invocation),
        invocation.command.name,
        &result,
        &diagnostics,
        write_human,
    )
}

fn unverified(verdict: &'static str) -> VerifyResult {
    VerifyResult {
        verdict,
        signature: "unsigned",
        trusted: false,
        package: None,
        artifacts: Vec::new(),
        report: None,
    }
}

/// Verifies a package's bytes: the result and every problem found.
pub(crate) fn verify_bytes(bytes: &[u8]) -> (VerifyResult, Vec<Diagnostic>) {
    let mut diagnostics = Vec::new();
    let mut result = unverified(INTEGRITY_INVALID);
    let Some(envelope) = parse(bytes) else {
        return (result, vec![Diagnostic::new(Code::EvidenceMalformed)]);
    };
    // Checked before anything else is read from it, and reported with
    // whatever else is found: a package that is not its canonical bytes is
    // not the one a gateway served, whatever its digests say.
    if canonical_json::canonical_json_bytes(&envelope)
        .ok()
        .as_deref()
        != Some(bytes)
    {
        diagnostics.push(Diagnostic::new(Code::EvidenceNotCanonical));
    }
    let Some(envelope) = envelope.as_object() else {
        return (result, vec![Diagnostic::new(Code::EvidenceMalformed)]);
    };
    match envelope.get("schema_version").and_then(Value::as_str) {
        Some(PACKAGE_SCHEMA_VERSION) => {}
        Some(_) => {
            result.verdict = NOT_VERIFIED;
            diagnostics.push(Diagnostic::new(Code::EvidenceUnsupportedVersion));
            return (result, diagnostics);
        }
        None => {
            diagnostics.push(Diagnostic::new(Code::EvidenceMalformed));
            return (result, diagnostics);
        }
    }
    let (Some(generated_at), Some(entries)) = (
        envelope
            .get("generated_at")
            .and_then(Value::as_str)
            .filter(|text| is_timestamp(text)),
        manifest(envelope.get("manifest")),
    ) else {
        diagnostics.push(Diagnostic::new(Code::EvidenceMalformed));
        return (result, diagnostics);
    };
    result.package = Some(PackageRecord {
        schema_version: PACKAGE_SCHEMA_VERSION.to_owned(),
        generated_at: generated_at.to_owned(),
        size: bytes.len(),
        source_digest: canonical_json::source_digest(
            PACKAGE_MEDIA_TYPE,
            PACKAGE_SCHEMA_VERSION,
            bytes,
        ),
    });

    // Each listed artifact with its place in `ARTIFACTS`.
    let mut listed: Vec<(usize, &Artifact)> = Vec::new();
    for entry in &entries {
        let Some((index, artifact)) = ARTIFACTS
            .iter()
            .enumerate()
            .find(|(_, artifact)| artifact.name == entry.name)
        else {
            diagnostics.push(Diagnostic::new(Code::EvidenceUnsupportedArtifact));
            continue;
        };
        if listed.iter().any(|(seen, _)| *seen == index) {
            diagnostics.push(Diagnostic::new(Code::EvidenceDuplicateEntry));
            continue;
        }
        listed.push((index, artifact));
        let verified = verify_artifact(artifact, entry, envelope.get(artifact.name));
        let ok = verified.is_ok();
        if let Err(code) = verified {
            diagnostics.push(Diagnostic::new(code));
        }
        result.artifacts.push(ArtifactRecord {
            name: artifact.name,
            media_type: artifact.media_type,
            schema_version: artifact.schema_version,
            digest: entry.digest.clone(),
            size: entry.size,
            verified: ok,
        });
    }
    // Each artifact in its place: the manifest lists them in table order.
    if listed.windows(2).any(|pair| pair[0].0 > pair[1].0) {
        diagnostics.push(Diagnostic::new(Code::EvidenceMalformed));
    }
    if ARTIFACTS.iter().any(|artifact| {
        artifact.required && !listed.iter().any(|(_, seen)| seen.name == artifact.name)
    }) {
        diagnostics.push(Diagnostic::new(Code::EvidenceMissingArtifact));
    }
    if envelope.keys().any(|member| {
        !ENVELOPE_MEMBERS.contains(&member.as_str())
            && !entries.iter().any(|entry| entry.name == *member)
    }) {
        diagnostics.push(Diagnostic::new(Code::EvidenceUnlistedMember));
    }
    if let Some(report) = envelope.get("report").and_then(Value::as_object) {
        check_report(report, &entries, &mut diagnostics);
        result.report = report_summary(report);
    }

    let exits: Vec<Exit> = diagnostics
        .iter()
        .map(|diagnostic| diagnostic.code.exit())
        .collect();
    result.verdict = if exits.contains(&Exit::Integrity) {
        INTEGRITY_INVALID
    } else if exits.is_empty() {
        diagnostics.push(Diagnostic::new(Code::EvidenceUnsigned));
        INTEGRITY_VALID
    } else {
        NOT_VERIFIED
    };
    if result.verdict != INTEGRITY_VALID {
        result.report = None;
    }
    (result, diagnostics)
}

/// The package as JSON: UTF-8 without a byte-order mark, which the parser
/// refuses as it refuses anything that is not one JSON value.
fn parse(bytes: &[u8]) -> Option<Value> {
    serde_json::from_slice(bytes).ok()
}

/// One manifest entry, read.
#[derive(Debug)]
struct Entry {
    name: String,
    media_type: String,
    schema_version: String,
    digest: String,
    size: u64,
    /// The entry exactly as the manifest holds it, for the report's binding.
    value: Value,
}

/// The manifest's entries, each with exactly the members an entry has, or
/// `None` when it is not such a list.
fn manifest(value: Option<&Value>) -> Option<Vec<Entry>> {
    let items = value?.as_array()?;
    if items.is_empty() || items.len() > MAX_MANIFEST_ENTRIES {
        return None;
    }
    items
        .iter()
        .map(|item| {
            let members = item.as_object()?;
            if members.len() != ENTRY_MEMBERS.len()
                || !ENTRY_MEMBERS.iter().all(|name| members.contains_key(*name))
            {
                return None;
            }
            let text = |name: &str| members.get(name).and_then(Value::as_str).map(str::to_owned);
            Some(Entry {
                name: text("name")?,
                media_type: text("media_type")?,
                schema_version: text("schema_version")?,
                digest: text("digest").filter(|digest| is_digest(digest))?,
                size: members.get("size")?.as_u64()?,
                value: item.clone(),
            })
        })
        .collect()
}

/// Checks one listed artifact against its entry.
fn verify_artifact(artifact: &Artifact, entry: &Entry, member: Option<&Value>) -> Result<(), Code> {
    if entry.media_type != artifact.media_type || entry.schema_version != artifact.schema_version {
        return Err(Code::EvidenceArtifactTypeMismatch);
    }
    let Some(member) = member else {
        return Err(Code::EvidenceMissingArtifact);
    };
    let (size, digest) = match artifact.payload {
        Payload::Json => {
            // A JSON artifact states its own version, which must be the one
            // its entry frames its digest with.
            if member.get("schema_version").and_then(Value::as_str) != Some(artifact.schema_version)
            {
                return Err(Code::EvidenceArtifactTypeMismatch);
            }
            let bytes = canonical_json::canonical_json_bytes(member)
                .map_err(|_| Code::EvidenceNotCanonical)?;
            let digest = canonical_json::semantic_digest(
                artifact.media_type,
                artifact.schema_version,
                member,
            )
            .map_err(|_| Code::EvidenceNotCanonical)?;
            (bytes.len(), digest)
        }
        Payload::Text => {
            let Some(text) = member.as_str() else {
                return Err(Code::EvidenceArtifactTypeMismatch);
            };
            (
                text.len(),
                canonical_json::source_digest(
                    artifact.media_type,
                    artifact.schema_version,
                    text.as_bytes(),
                ),
            )
        }
    };
    // The digest first: changed content is a digest mismatch whatever its
    // size, and a size mismatch alone means the entry's size was changed.
    if digest != entry.digest {
        return Err(Code::EvidenceDigestMismatch);
    }
    if u64::try_from(size).ok() != Some(entry.size) {
        return Err(Code::EvidenceSizeMismatch);
    }
    Ok(())
}

/// What the verified report must say about itself: that it is unsigned,
/// and, for every artifact it repeats the manifest entry of, the same entry
/// the manifest holds, or none when the manifest lists no such artifact.
fn check_report(report: &Map<String, Value>, entries: &[Entry], diagnostics: &mut Vec<Diagnostic>) {
    match report
        .get("trust")
        .and_then(|trust| trust.get("signed"))
        .and_then(Value::as_bool)
    {
        Some(false) => {}
        Some(true) => diagnostics.push(Diagnostic::new(Code::EvidenceSignatureUnsupported)),
        None => diagnostics.push(Diagnostic::new(Code::EvidenceMalformed)),
    }
    for artifact in ARTIFACTS {
        let Some((first, rest)) = artifact.bound_by_report.and_then(<[_]>::split_first) else {
            continue;
        };
        let repeated = rest.iter().fold(report.get(*first), |value, member| {
            value.and_then(|value| value.get(*member))
        });
        let entry = entries.iter().find(|entry| entry.name == artifact.name);
        let agrees = match (repeated, entry) {
            (None, None) => true,
            (Some(repeated), Some(entry)) => *repeated == entry.value,
            _ => false,
        };
        if !agrees {
            diagnostics.push(Diagnostic::new(Code::EvidenceBindingMismatch));
        }
    }
}

/// The report's own completeness statement, when it is well formed.
fn report_summary(report: &Map<String, Value>) -> Option<ReportSummary> {
    let completeness = report
        .get("completeness")
        .and_then(Value::as_str)
        .filter(|completeness| matches!(*completeness, "complete" | "incomplete"))?;
    let limitations = report
        .get("limitations")?
        .as_array()?
        .iter()
        .map(|code| {
            code.as_str()
                .filter(|code| is_code(code))
                .map(str::to_owned)
        })
        .collect::<Option<Vec<_>>>()?;
    Some(ReportSummary {
        completeness: completeness.to_owned(),
        limitations,
    })
}

fn write_human(result: &VerifyResult, out: &mut dyn Write) -> io::Result<()> {
    writeln!(
        out,
        "evidence package: {}, {} (not trusted)",
        result.verdict, result.signature
    )?;
    if let Some(package) = &result.package {
        writeln!(
            out,
            "  package       {}, generated {}, {} bytes",
            package.schema_version, package.generated_at, package.size
        )?;
        writeln!(out, "  source digest {}", package.source_digest)?;
    }
    for artifact in &result.artifacts {
        let state = if artifact.verified {
            "verified"
        } else {
            "not verified"
        };
        writeln!(
            out,
            "  {:<13} {} {} bytes, {state}",
            artifact.name, artifact.digest, artifact.size
        )?;
    }
    if let Some(report) = &result.report {
        if report.limitations.is_empty() {
            writeln!(out, "  completeness  {}", report.completeness)?;
        } else {
            writeln!(
                out,
                "  completeness  {}: {}",
                report.completeness,
                report.limitations.join(", ")
            )?;
        }
    }
    if result.verdict == INTEGRITY_VALID {
        writeln!(
            out,
            "The digests show that the artifacts are the ones the manifest names. Without a \
             signature nothing shows who produced the package."
        )?;
    }
    Ok(())
}

/// `generated_at`: an RFC 3339 time as a gateway writes one, bounded and
/// visible ASCII; it is outside every digest, so nothing more is checked.
fn is_timestamp(text: &str) -> bool {
    (1..=64).contains(&text.len()) && text.bytes().all(|byte| byte.is_ascii_graphic())
}

fn is_digest(text: &str) -> bool {
    text.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

/// A limitation code: lowercase snake segments.
fn is_code(text: &str) -> bool {
    (1..=64).contains(&text.len())
        && text
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
        && text
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

#[cfg(test)]
mod tests;
