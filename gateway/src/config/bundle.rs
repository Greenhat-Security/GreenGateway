//! Versioned configuration bundles: the reader, its safe syntax subset, and
//! the `v1alpha1` documents (issue #242, PR 4).
//!
//! A bundle is a flat directory holding a `bundle.yaml` manifest
//! (`GatewayBundle`), one deployment document (`GatewayDeployment`, YAML or
//! JSON), and the policy and tools documents the manifest pins by SHA-256.
//! [`read_bundle`] reads one, side-effect free: it opens files beneath the
//! bundle root and nothing else -- no store, no network, no environment, no
//! write.
//!
//! The pipeline fails closed at every stage and reports value-free
//! diagnostics (see [`diagnostic`]):
//!
//! 1. [`source`]: contained, bounded file reads -- portable names only, no
//!    links, no special or hard-linked files, per-file and total byte bounds,
//!    and the Kubernetes `..data` layout resolved to one generation.
//! 2. [`syntax`], [`yaml`] and [`json`]: UTF-8 without a byte-order mark, LF
//!    line endings, no control, bidirectional formatting or line separator
//!    characters, then a strict JSON or safe-subset YAML parse into one tree,
//!    with duplicate keys refused and every structural bound charged while
//!    parsing.
//! 3. [`document`]: exact `apiVersion`/`kind` dispatch and closed objects.
//! 4. Digests: each referenced file's exact bytes must match the manifest's
//!    pin before it is parsed, and the bundle's source digest frames the
//!    manifest bytes with ADR-0004's `GGDIGEST` frame.
//! 5. [`resource`]: referenced policy and tools documents pass their own
//!    published schemas and production validators.
//!
//! Nothing selects a bundle yet. Bundle mode, the field catalog that fills
//! the deployment document, and `ggctl validate` are later #242 slices; until
//! they land this module is exercised by its tests only.
#![allow(dead_code)] // Bundle mode and `ggctl` (later #242 slices) are the readers.

mod diagnostic;
mod document;
mod json;
mod resource;
mod source;
mod syntax;
mod value;
mod yaml;

#[cfg(test)]
mod property_tests;
#[cfg(test)]
mod tests;

use std::path::Path;

use sha2::{Digest, Sha256};

use crate::{canonical_json, rbac::policy::Policy, tools::definitions::ToolDefinition};

use diagnostic::{BundleDiagnostic, Code, Pointer};
use document::{ApiVersion, Deployment, FileReference, Manifest, Profile, ResourceSource};
use source::{BundleDirectory, FileName};
use syntax::{decode_text, Node, SyntaxError, TextRules, DOCUMENT_LIMITS};

/// The manifest's byte bound.
pub(crate) const MAX_MANIFEST_BYTES: usize = 64 * 1024;
/// The deployment document's byte bound.
pub(crate) const MAX_DEPLOYMENT_BYTES: usize = 1024 * 1024;
/// The media type the source digest frames the manifest bytes under.
pub(crate) const MANIFEST_MEDIA_TYPE: &str = "application/vnd.greengateway.bundle+yaml";

/// How strictly to read a bundle.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ReadOptions {
    /// Turns warnings (an unreferenced entry) into errors.
    pub(crate) strict: bool,
}

/// What reading a bundle found.
#[derive(Debug)]
pub(crate) struct BundleReport {
    /// The bundle, when no diagnostic is an error.
    pub(crate) bundle: Option<Bundle>,
    pub(crate) diagnostics: Vec<BundleDiagnostic>,
}

/// A bundle that passed every stage.
#[derive(Debug)]
pub(crate) struct Bundle {
    pub(crate) api_version: ApiVersion,
    pub(crate) name: String,
    /// `sha256:` and 64 lowercase hex digits over the framed manifest bytes:
    /// the whole source bundle's identity, transitively through the pins. An
    /// integrity value only; a digest is not a signature.
    pub(crate) source_digest: String,
    pub(crate) deployment: DeploymentDocument,
    pub(crate) policy: Option<BundledResource<Policy>>,
    pub(crate) tools: Option<BundledResource<Vec<ToolDefinition>>>,
    /// Connections are server-managed in `v1alpha1`; `true` when the
    /// manifest says so.
    pub(crate) connections_from_server: bool,
}

/// The deployment document.
#[derive(Debug)]
pub(crate) struct DeploymentDocument {
    pub(crate) file: FileName,
    pub(crate) sha256: String,
    pub(crate) profile: Profile,
    /// RFC 8785 bytes of the document, the same whether it was written as
    /// YAML or JSON.
    pub(crate) canonical_json: Vec<u8>,
}

/// A policy or tools resource.
#[derive(Debug)]
pub(crate) enum BundledResource<T> {
    /// Supplied by the bundle and validated by its production validator.
    Bundle {
        file: FileName,
        schema_version: &'static str,
        sha256: String,
        document: T,
    },
    /// Left to the existing store.
    Server,
}

/// Reads and validates the bundle in the directory `root`.
pub(crate) fn read_bundle(root: &Path, options: ReadOptions) -> BundleReport {
    let mut diagnostics = Vec::new();
    let bundle = read(root, options, &mut diagnostics);
    let bundle = bundle.filter(|_| !diagnostics.iter().any(BundleDiagnostic::is_error));
    BundleReport {
        bundle,
        diagnostics,
    }
}

fn read(
    root: &Path,
    options: ReadOptions,
    diagnostics: &mut Vec<BundleDiagnostic>,
) -> Option<Bundle> {
    let mut directory = match BundleDirectory::open(root) {
        Ok(directory) => directory,
        Err(diagnostic) => {
            diagnostics.push(diagnostic);
            return None;
        }
    };
    let manifest_file = FileName::manifest();
    let manifest_bytes = match directory.read(&manifest_file, MAX_MANIFEST_BYTES) {
        Ok(bytes) => bytes,
        Err(mut diagnostic) => {
            if diagnostic.code == Code::FileMissing {
                diagnostic.code = Code::ManifestMissing;
            }
            diagnostics.push(diagnostic);
            return None;
        }
    };
    let manifest = parse_document(&manifest_bytes, &manifest_file, diagnostics)
        .and_then(|node| document::manifest(&node, diagnostics))?;
    let source_digest = canonical_json::source_digest(
        MANIFEST_MEDIA_TYPE,
        manifest.api_version.as_str(),
        &manifest_bytes,
    );

    let deployment = read_deployment(&mut directory, &manifest.deployment, diagnostics);
    let policy = manifest
        .policy
        .as_ref()
        .map(|source| read_resource(&mut directory, source, diagnostics, resource::policy));
    let tools = manifest
        .tools
        .as_ref()
        .map(|source| read_resource(&mut directory, source, diagnostics, resource::tools));
    diagnostics.extend(directory.unreferenced(&manifest.files(), options.strict));

    let Manifest {
        api_version,
        name,
        connections_from_server,
        ..
    } = manifest;
    Some(Bundle {
        api_version,
        name,
        source_digest,
        deployment: deployment?,
        policy: declared(policy)?,
        tools: declared(tools)?,
        connections_from_server,
    })
}

/// A resource the manifest may declare: `Some(None)` when it declares none,
/// `None` when the declared resource was refused.
fn declared<T>(resource: Option<Option<T>>) -> Option<Option<T>> {
    match resource {
        None => Some(None),
        Some(Some(resource)) => Some(Some(resource)),
        Some(None) => None,
    }
}

/// Reads a pinned file: the bound, then the pin over the exact bytes, before
/// anything parses them.
fn read_pinned(
    directory: &mut BundleDirectory,
    reference: &FileReference,
    maximum: usize,
    diagnostics: &mut Vec<BundleDiagnostic>,
) -> Option<Vec<u8>> {
    let bytes = match directory.read(&reference.file, maximum) {
        Ok(bytes) => bytes,
        Err(diagnostic) => {
            diagnostics.push(diagnostic);
            return None;
        }
    };
    if hex::encode(Sha256::digest(&bytes)) != reference.sha256 {
        diagnostics.push(BundleDiagnostic::file(
            Code::DigestMismatch,
            &reference.file,
        ));
        return None;
    }
    Some(bytes)
}

fn read_deployment(
    directory: &mut BundleDirectory,
    reference: &FileReference,
    diagnostics: &mut Vec<BundleDiagnostic>,
) -> Option<DeploymentDocument> {
    let bytes = read_pinned(directory, reference, MAX_DEPLOYMENT_BYTES, diagnostics)?;
    let node = parse_document(&bytes, &reference.file, diagnostics)?;
    let Deployment { profile, .. } = document::deployment(&node, &reference.file, diagnostics)?;
    // Bundle documents hold safe integers only, so this cannot fail; if it
    // ever did, the document is refused rather than given no canonical form.
    let Ok(canonical_json) = canonical_json::canonical_json_bytes(&node.to_json()) else {
        diagnostics.push(BundleDiagnostic::file(
            Code::NumberNotInteger,
            &reference.file,
        ));
        return None;
    };
    Some(DeploymentDocument {
        file: reference.file.clone(),
        sha256: reference.sha256.clone(),
        profile,
        canonical_json,
    })
}

type ResourceValidator<T> = fn(&str, &str, &FileName, &mut Vec<BundleDiagnostic>) -> Option<T>;

/// `None` when the resource was refused.
fn read_resource<T>(
    directory: &mut BundleDirectory,
    source: &ResourceSource,
    diagnostics: &mut Vec<BundleDiagnostic>,
    validate: ResourceValidator<T>,
) -> Option<BundledResource<T>> {
    let (reference, schema_version) = match source {
        ResourceSource::Server => return Some(BundledResource::Server),
        ResourceSource::Bundle {
            reference,
            schema_version,
        } => (reference, *schema_version),
    };
    let bytes = read_pinned(
        directory,
        reference,
        resource::MAX_RESOURCE_BYTES,
        diagnostics,
    )?;
    let text = decode(&bytes, TextRules::Resource, &reference.file, diagnostics)?;
    let document = validate(text, schema_version, &reference.file, diagnostics)?;
    Some(BundledResource::Bundle {
        file: reference.file.clone(),
        schema_version,
        sha256: reference.sha256.clone(),
        document,
    })
}

/// Decodes and parses a bundle document: YAML for the manifest and a
/// `.yaml` deployment document, strict JSON for a `.json` one.
fn parse_document(
    bytes: &[u8],
    file: &FileName,
    diagnostics: &mut Vec<BundleDiagnostic>,
) -> Option<Node> {
    let text = decode(bytes, TextRules::Document, file, diagnostics)?;
    let parsed = if file.has_extension("json") {
        json::parse(text, DOCUMENT_LIMITS)
    } else {
        yaml::parse(text, DOCUMENT_LIMITS)
    };
    match parsed {
        Ok(node) => Some(node),
        Err(error) => {
            diagnostics.push(syntax_diagnostic(error, file));
            None
        }
    }
}

fn decode<'b>(
    bytes: &'b [u8],
    rules: TextRules,
    file: &FileName,
    diagnostics: &mut Vec<BundleDiagnostic>,
) -> Option<&'b str> {
    match decode_text(bytes, rules) {
        Ok(text) => Some(text),
        Err(error) => {
            diagnostics.push(syntax_diagnostic(error, file));
            None
        }
    }
}

fn syntax_diagnostic(error: SyntaxError, file: &FileName) -> BundleDiagnostic {
    BundleDiagnostic::at(error.code, file, Pointer::root(), Some(error.position))
}
