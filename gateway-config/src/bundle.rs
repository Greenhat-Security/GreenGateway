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
//! This is the one reader. The gateway and `ggctl validate`/`ggctl doctor`
//! both call it (ADR-0008, "One compiler"), so neither approximates the
//! other. The pipeline fails closed at every stage and reports value-free
//! diagnostics (see [`BundleDiagnostic`]):
//!
//! 1. `source`: contained, bounded file reads -- portable names only, no
//!    links, no special or hard-linked files, per-file and total byte bounds,
//!    and the Kubernetes `..data` layout resolved to one generation.
//! 2. `syntax`, `yaml` and `json`: UTF-8 without a byte-order mark, LF line
//!    endings, no control, bidirectional formatting or line separator
//!    characters, then a strict JSON or safe-subset YAML parse into one tree,
//!    with duplicate keys refused and every structural bound charged while
//!    parsing.
//! 3. `document`: exact `apiVersion`/`kind` dispatch and closed objects,
//!    and `settings`: the deployment settings, typed and bounded by their
//!    catalog entries.
//! 4. Digests: each referenced file's exact bytes must match the manifest's
//!    pin before it is parsed, and the bundle's source digest frames the
//!    manifest bytes with ADR-0004's `GGDIGEST` frame.
//! 5. `resource`: referenced policy and tools documents are read as strict
//!    JSON at their exact declared `schema_version` and must pass their
//!    published schemas; then the caller's [`ResourceValidators`] run. The
//!    gateway and `ggctl` both pass [`ProductionValidators`], the policy and
//!    tools loaders' own validating parses, which live in this crate
//!    ([`crate::rbac`] and [`crate::tools`]).
//! 6. `profile`: a bundled policy is held to the deployment profile's
//!    invariants -- deny by default, enforce mode, no wildcard role for
//!    `production` and, until acknowledgments exist, `migration`.
//!
//! An accepted bundle keeps the exact bytes of every file it is made of
//! ([`Bundle::source_files`]); the standalone revision ledger
//! ([`crate::ledger`]) records those bytes. [`read_bundle_files`] reads a
//! bundle from such bytes in memory by the same pipeline, so a revision's
//! stored content is held to the current validators before a rollback uses
//! it, and a bundle a caller submitted is read exactly as a directory would
//! be.
//!
//! Three modules build on the reader: [`init`] generates the bundle `ggctl
//! init` writes, [`convert`] converts a bundle between document versions for
//! `ggctl convert`, and [`pin`] recomputes a bundle's pins for `ggctl pin`,
//! reading it with every check but the pin comparison. Each hands its output
//! to this reader before anything treats it as a bundle.
//!
//! The deployment document's settings come from the field catalog
//! ([`settings`]): the reader checks their shape and their own bounds, then
//! validates egress through the shared compiler stage. Gateway bundle startup
//! and compiler integration for the other domains are later #242 slices.

pub mod convert;
mod diagnostic;
mod document;
pub mod init;
mod json;
pub mod pin;
mod profile;
mod resource;
pub(crate) mod settings;
mod source;
mod syntax;
mod value;
mod yaml;

#[cfg(test)]
mod production_tests;
#[cfg(test)]
mod property_tests;
#[cfg(test)]
mod tests;

use std::{collections::BTreeMap, path::Path};

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    canonical_json,
    rbac::Policy,
    tools::definitions::{definitions_from_json_value, ToolDefinition},
};

pub use diagnostic::{BundleDiagnostic, Code, Pointer, Position, Severity};
pub use document::{ApiVersion, Profile, POLICY_SCHEMA_VERSIONS, TOOLS_SCHEMA_VERSIONS};
pub use resource::{MAX_RESOURCE_BYTES, POLICY_TOP_LEVEL_MEMBERS};
pub use settings::{
    render_deployment_reference, render_deployment_schema, Section, StandaloneStore,
    DEPLOYMENT_SCHEMA_DOCUMENT, SECTIONS, STANDALONE_STORES, STORES_PATH,
};
pub use source::{FileName, MANIFEST_FILE_NAME, MAX_BUNDLE_BYTES, MAX_DIRECTORY_ENTRIES};

pub(crate) use document::is_dns_label;
use document::{Deployment, FileReference, Manifest, ResourceSource};
use profile::ProfileRules;
use source::{BundleDirectory, FileSource, MemoryFiles};
use syntax::{decode_text, Node, SyntaxError, TextRules, DOCUMENT_LIMITS};

/// The manifest's byte bound.
pub const MAX_MANIFEST_BYTES: usize = 64 * 1024;
/// The deployment document's byte bound.
pub const MAX_DEPLOYMENT_BYTES: usize = 1024 * 1024;
/// The media type the source digest frames the manifest bytes under.
pub const MANIFEST_MEDIA_TYPE: &str = "application/vnd.greengateway.bundle+yaml";

/// How strictly to read a bundle.
#[derive(Clone, Copy, Debug, Default)]
pub struct ReadOptions {
    /// Turns warnings (an unreferenced entry) into errors.
    pub strict: bool,
}

/// The validators a caller runs on a referenced policy or tools document
/// once it has passed the bundle's own checks: strict JSON, the exact
/// declared `schema_version`, a closed policy top level, and the published
/// schema.
///
/// A validator gets the document's JSON value and returns what it built, or
/// `None` to refuse it; the reader then reports `resource.invalid` on its own
/// behalf. A validator never reports anything itself, because validator
/// messages can quote document values.
pub trait ResourceValidators {
    /// What a validated policy document becomes.
    type Policy;
    /// What a validated tools document becomes.
    type Tools;

    fn policy(&self, document: Value) -> Option<Self::Policy>;

    /// Validate the document with access to the exact pinned source bytes.
    fn policy_source(&self, _source: &[u8], document: Value) -> Option<Self::Policy> {
        self.policy(document)
    }

    fn tools(&self, document: Value) -> Option<Self::Tools>;
}

/// The gateway and `ggctl` use the environment-mode policy and tools
/// validators for bundled resources. Policy v1 validation also checks the
/// exact bytes pinned by the manifest.
///
/// A validator's error can quote document values, so it is dropped here and
/// the reader reports `resource.invalid` by code alone.
#[derive(Clone, Copy, Debug, Default)]
pub struct ProductionValidators;

impl ResourceValidators for ProductionValidators {
    type Policy = Policy;
    type Tools = Vec<ToolDefinition>;

    fn policy(&self, document: Value) -> Option<Policy> {
        Policy::validate_json_value(document).ok()
    }

    fn policy_source(&self, source: &[u8], document: Value) -> Option<Policy> {
        use crate::rbac::policy_document::{parse_v1_source, PolicySchema};

        if PolicySchema::of_document(&document) == Some(PolicySchema::V1) {
            parse_v1_source(source, &document).ok()
        } else {
            self.policy(document)
        }
    }

    fn tools(&self, document: Value) -> Option<Vec<ToolDefinition>> {
        definitions_from_json_value(document, None).ok()
    }
}

/// A bundle the reader accepted with the [`ProductionValidators`]: its
/// policy and tools documents as those validators built them.
pub type ProductionBundle = Bundle<Policy, Vec<ToolDefinition>>;

/// Runs no production validator: a referenced document that passed the
/// bundle's own checks and its published schema is accepted as its JSON
/// value, as it was written.
///
/// For the tests of the reader's own stages, which must not depend on what
/// the production validators decide. Every command reads bundles with the
/// [`ProductionValidators`].
#[derive(Clone, Copy, Debug, Default)]
pub struct PublishedSchemasOnly;

impl ResourceValidators for PublishedSchemasOnly {
    type Policy = Value;
    type Tools = Value;

    fn policy(&self, document: Value) -> Option<Value> {
        Some(document)
    }

    fn tools(&self, document: Value) -> Option<Value> {
        Some(document)
    }
}

/// What reading a bundle found.
#[derive(Debug)]
pub struct BundleReport<P, T> {
    /// The bundle, when no diagnostic is an error.
    pub bundle: Option<Bundle<P, T>>,
    /// The manifest, when it was read and is valid, even if another file of
    /// the bundle was refused: what the bundle declares, for a caller that
    /// reports per file.
    pub manifest: Option<ManifestSummary>,
    pub diagnostics: Vec<BundleDiagnostic>,
}

/// What a valid manifest declares, without any file content.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestSummary {
    pub api_version: ApiVersion,
    pub name: String,
    pub deployment: FileName,
    pub policy: Option<ResourceDeclaration>,
    pub tools: Option<ResourceDeclaration>,
    pub connections_from_server: bool,
}

/// Where the manifest says a policy or tools resource comes from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResourceDeclaration {
    /// A file of the bundle, at an exact document version.
    Bundle {
        file: FileName,
        schema_version: &'static str,
    },
    /// The existing store.
    Server,
}

impl ManifestSummary {
    fn of(manifest: &Manifest) -> Self {
        let declaration = |source: &ResourceSource| match source {
            ResourceSource::Bundle {
                reference,
                schema_version,
            } => ResourceDeclaration::Bundle {
                file: reference.file.clone(),
                schema_version,
            },
            ResourceSource::Server => ResourceDeclaration::Server,
        };
        Self {
            api_version: manifest.api_version,
            name: manifest.name.clone(),
            deployment: manifest.deployment.file.clone(),
            policy: manifest.policy.as_ref().map(declaration),
            tools: manifest.tools.as_ref().map(declaration),
            connections_from_server: manifest.connections_from_server,
        }
    }
}

/// A bundle that passed every stage.
#[derive(Debug)]
pub struct Bundle<P, T> {
    pub api_version: ApiVersion,
    pub name: String,
    /// `sha256:` and 64 lowercase hex digits over the framed manifest bytes:
    /// the whole source bundle's identity, transitively through the pins. An
    /// integrity value only; a digest is not a signature.
    pub source_digest: String,
    pub deployment: DeploymentDocument,
    pub policy: Option<BundledResource<P>>,
    pub tools: Option<BundledResource<T>>,
    /// Connections are server-managed in `v1alpha1`; `true` when the
    /// manifest says so.
    pub connections_from_server: bool,
    /// Every file the bundle is made of, exactly as read. Private, so a
    /// `Bundle` exists only as [`read_bundle`] accepted it: the revision
    /// ledger records these bytes and nothing a caller assembled.
    files: Vec<SourceFile>,
}

impl<P, T> Bundle<P, T> {
    /// The manifest, then the deployment document, then the bundled policy
    /// and tools documents, each exactly as read and already checked against
    /// its pin.
    pub fn source_files(&self) -> &[SourceFile] {
        &self.files
    }
}

/// What a file is to its bundle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileRole {
    Manifest,
    Deployment,
    Policy,
    Tools,
}

impl FileRole {
    pub const ALL: &'static [Self] = &[Self::Manifest, Self::Deployment, Self::Policy, Self::Tools];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Manifest => "manifest",
            Self::Deployment => "deployment",
            Self::Policy => "policy",
            Self::Tools => "tools",
        }
    }
}

/// One file of a bundle: its role, its name and its exact bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceFile {
    pub role: FileRole,
    pub name: FileName,
    pub bytes: Vec<u8>,
}

/// The deployment document.
#[derive(Debug)]
pub struct DeploymentDocument {
    pub file: FileName,
    pub sha256: String,
    pub profile: Profile,
    /// RFC 8785 bytes of the document, the same whether it was written as
    /// YAML or JSON, with each decimal setting in its shortest exact
    /// spelling and the store list and acknowledged behaviors in canonical
    /// order.
    pub canonical_json: Vec<u8>,
}

/// A policy or tools resource.
#[derive(Debug)]
pub enum BundledResource<T> {
    /// Supplied by the bundle and validated by the caller's validator.
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
pub fn read_bundle<V: ResourceValidators>(
    root: &Path,
    options: ReadOptions,
    validators: &V,
) -> BundleReport<V::Policy, V::Tools> {
    report(
        BundleDirectory::open(root),
        options,
        validators,
        &mut Pins::Compare,
    )
}

/// Reads and validates a bundle held in memory: the files of one flat bundle
/// directory, by name, exactly as a directory would hold them.
///
/// Every stage after the directory checks is the one [`read_bundle`] runs,
/// with the same byte bounds, and an entry the manifest does not reference
/// is reported the same way.
pub fn read_bundle_files<V: ResourceValidators>(
    files: BTreeMap<FileName, Vec<u8>>,
    options: ReadOptions,
    validators: &V,
) -> BundleReport<V::Policy, V::Tools> {
    report(
        MemoryFiles::new(files),
        options,
        validators,
        &mut Pins::Compare,
    )
}

/// What the reader does with each referenced file's pin.
pub(crate) enum Pins {
    /// Refuses a file whose bytes differ from its pin: every reader but
    /// [`pin`]'s.
    Compare,
    /// Records each file's digest instead of comparing it, for [`pin`].
    /// Every other check still runs.
    Record(Vec<RecordedPin>),
}

/// A referenced file's pin as the manifest wrote it, and the digest of the
/// file's exact bytes as read.
#[derive(Clone, Debug)]
pub(crate) struct RecordedPin {
    pub(crate) role: FileRole,
    pub(crate) reference: FileReference,
    pub(crate) sha256: String,
}

fn report<S: FileSource, V: ResourceValidators>(
    source: Result<S, BundleDiagnostic>,
    options: ReadOptions,
    validators: &V,
    pins: &mut Pins,
) -> BundleReport<V::Policy, V::Tools> {
    let mut diagnostics = Vec::new();
    let mut manifest = None;
    let bundle = match source {
        Ok(mut source) => read(
            &mut source,
            options,
            validators,
            pins,
            &mut manifest,
            &mut diagnostics,
        ),
        Err(diagnostic) => {
            diagnostics.push(diagnostic);
            None
        }
    };
    let bundle = bundle.filter(|_| !diagnostics.iter().any(BundleDiagnostic::is_error));
    BundleReport {
        bundle,
        manifest,
        diagnostics,
    }
}

fn read<S: FileSource, V: ResourceValidators>(
    directory: &mut S,
    options: ReadOptions,
    validators: &V,
    pins: &mut Pins,
    summary: &mut Option<ManifestSummary>,
    diagnostics: &mut Vec<BundleDiagnostic>,
) -> Option<Bundle<V::Policy, V::Tools>> {
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
    *summary = Some(ManifestSummary::of(&manifest));
    let source_digest = canonical_json::source_digest(
        MANIFEST_MEDIA_TYPE,
        manifest.api_version.as_str(),
        &manifest_bytes,
    );
    let mut files = vec![SourceFile {
        role: FileRole::Manifest,
        name: manifest_file,
        bytes: manifest_bytes,
    }];

    let deployment = read_deployment(
        directory,
        &manifest.deployment,
        (&mut files, pins),
        diagnostics,
    );
    // The profile's policy invariants apply once the deployment document says
    // which profile it is and what it acknowledges; without one the bundle is
    // refused anyway.
    let (deployment, rules) = match deployment {
        Some((deployment, rules)) => (Some(deployment), Some(rules)),
        None => (None, None),
    };
    let policy = manifest.policy.as_ref().map(|source| {
        read_resource(
            directory,
            source,
            (FileRole::Policy, &mut files, &mut *pins),
            diagnostics,
            |text, version, file, found| {
                resource::policy(text, version, rules.as_ref(), file, found).and_then(|document| {
                    refused_unless(
                        validators.policy_source(text.as_bytes(), document),
                        file,
                        found,
                    )
                })
            },
        )
    });
    let tools = manifest.tools.as_ref().map(|source| {
        read_resource(
            directory,
            source,
            (FileRole::Tools, &mut files, &mut *pins),
            diagnostics,
            |text, version, file, found| {
                resource::tools(text, version, file, found)
                    .and_then(|document| refused_unless(validators.tools(document), file, found))
            },
        )
    });
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
        files,
    })
}

/// A caller's validator verdict: a refusal is reported by code alone.
fn refused_unless<T>(
    validated: Option<T>,
    file: &FileName,
    diagnostics: &mut Vec<BundleDiagnostic>,
) -> Option<T> {
    if validated.is_none() {
        diagnostics.push(BundleDiagnostic::file(Code::ResourceInvalid, file));
    }
    validated
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

/// The pin a manifest gives a file: 64 lowercase hexadecimal digits of the
/// SHA-256 digest of its exact bytes.
pub fn sha256_pin(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Reads a pinned file: the bound, then the pin over the exact bytes, before
/// anything parses them. When recording, the file's digest is recorded
/// instead of compared, and the file is parsed and checked as usual.
fn read_pinned(
    directory: &mut impl FileSource,
    (role, reference): (FileRole, &FileReference),
    maximum: usize,
    pins: &mut Pins,
    diagnostics: &mut Vec<BundleDiagnostic>,
) -> Option<Vec<u8>> {
    let bytes = match directory.read(&reference.file, maximum) {
        Ok(bytes) => bytes,
        Err(diagnostic) => {
            diagnostics.push(diagnostic);
            return None;
        }
    };
    let sha256 = sha256_pin(&bytes);
    match pins {
        Pins::Compare if sha256 != reference.sha256 => {
            diagnostics.push(BundleDiagnostic::file(
                Code::DigestMismatch,
                &reference.file,
            ));
            return None;
        }
        Pins::Compare => {}
        Pins::Record(recorded) => recorded.push(RecordedPin {
            role,
            reference: reference.clone(),
            sha256,
        }),
    }
    Some(bytes)
}

fn read_deployment(
    directory: &mut impl FileSource,
    reference: &FileReference,
    (files, pins): (&mut Vec<SourceFile>, &mut Pins),
    diagnostics: &mut Vec<BundleDiagnostic>,
) -> Option<(DeploymentDocument, ProfileRules)> {
    let bytes = read_pinned(
        directory,
        (FileRole::Deployment, reference),
        MAX_DEPLOYMENT_BYTES,
        pins,
        diagnostics,
    )?;
    let node = parse_document(&bytes, &reference.file, diagnostics)?;
    let Deployment {
        profile, settings, ..
    } = document::deployment(&node, &reference.file, diagnostics)?;
    diagnostics.extend(settings.listener_diagnostics(profile, &node, &reference.file));
    diagnostics.extend(settings.egress_diagnostics(&node, &reference.file));
    diagnostics.extend(settings.provider_diagnostics(&node, &reference.file));
    // Decimals take their shortest exact spelling and the word sets their
    // canonical order, so neither changes the canonical bytes.
    let mut document = node.to_json();
    settings.canonicalize(&mut document);
    let rules = ProfileRules {
        profile,
        acknowledged: settings.acknowledged(),
    };
    // Bundle documents hold safe integers only, so this cannot fail; if it
    // ever did, the document is refused rather than given no canonical form.
    let Ok(canonical_json) = canonical_json::canonical_json_bytes(&document) else {
        diagnostics.push(BundleDiagnostic::file(
            Code::NumberNotInteger,
            &reference.file,
        ));
        return None;
    };
    files.push(SourceFile {
        role: FileRole::Deployment,
        name: reference.file.clone(),
        bytes,
    });
    Some((
        DeploymentDocument {
            file: reference.file.clone(),
            sha256: reference.sha256.clone(),
            profile,
            canonical_json,
        },
        rules,
    ))
}

/// `None` when the resource was refused. A resource the bundle supplies is
/// added to `files` under its role.
fn read_resource<T>(
    directory: &mut impl FileSource,
    source: &ResourceSource,
    (role, files, pins): (FileRole, &mut Vec<SourceFile>, &mut Pins),
    diagnostics: &mut Vec<BundleDiagnostic>,
    validate: impl FnOnce(&str, &str, &FileName, &mut Vec<BundleDiagnostic>) -> Option<T>,
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
        (role, reference),
        MAX_RESOURCE_BYTES,
        pins,
        diagnostics,
    )?;
    let text = decode(&bytes, TextRules::Resource, &reference.file, diagnostics)?;
    let document = validate(text, schema_version, &reference.file, diagnostics)?;
    files.push(SourceFile {
        role,
        name: reference.file.clone(),
        bytes,
    });
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
