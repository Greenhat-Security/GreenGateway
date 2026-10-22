//! The `v1alpha1` bundle documents: exact version dispatch and strict
//! structure.
//!
//! A reader accepts only the exact `(apiVersion, kind)` pairs it implements.
//! There is no prefix match and no downgrade: an unknown `apiVersion` stops
//! validation before any member is interpreted, because its members could
//! mean anything. Within a known version every object is closed -- a member
//! the version does not define is refused, never ignored -- and every problem
//! in the document is reported, not just the first.

use super::{
    diagnostic::{BundleDiagnostic, Code, Pointer},
    source::{FileName, MANIFEST_FILE_NAME},
    syntax::{Member, Node},
};

/// The one document version this reader implements.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ApiVersion {
    V1Alpha1,
}

impl ApiVersion {
    pub(crate) const ALL: &'static [Self] = &[Self::V1Alpha1];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::V1Alpha1 => "greengateway.dev/v1alpha1",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|version| version.as_str() == text)
    }
}

pub(crate) const BUNDLE_KIND: &str = "GatewayBundle";
pub(crate) const DEPLOYMENT_KIND: &str = "GatewayDeployment";

/// The resource document versions a `v1alpha1` bundle may declare. The
/// environment-mode validators accept any `0.` version; the bundle boundary
/// pins the exact versions that exist.
pub(crate) const POLICY_SCHEMA_VERSIONS: &[&str] = &["0.1.0"];
pub(crate) const TOOLS_SCHEMA_VERSIONS: &[&str] = &["0.1.0"];

/// A deployment profile. The compiler enforces each profile's invariants;
/// the reader only fixes the names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Profile {
    Production,
    Migration,
    Development,
}

impl Profile {
    pub(crate) const ALL: &'static [Self] = &[Self::Production, Self::Migration, Self::Development];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Production => "production",
            Self::Migration => "migration",
            Self::Development => "development",
        }
    }
}

/// A file the manifest pins.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FileReference {
    pub(crate) file: FileName,
    /// 64 lowercase hexadecimal digits over the file's exact bytes.
    pub(crate) sha256: String,
}

/// Where a policy or tools resource comes from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ResourceSource {
    /// The bundle is the resource's only writer.
    Bundle {
        reference: FileReference,
        schema_version: &'static str,
    },
    /// The existing store is the writer.
    Server,
}

/// A valid `GatewayBundle` manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Manifest {
    pub(crate) api_version: ApiVersion,
    pub(crate) name: String,
    pub(crate) deployment: FileReference,
    pub(crate) policy: Option<ResourceSource>,
    pub(crate) tools: Option<ResourceSource>,
    /// Connections accept only the server in `v1alpha1`.
    pub(crate) connections_from_server: bool,
}

impl Manifest {
    /// Every file the manifest references, the manifest included.
    pub(crate) fn files(&self) -> Vec<FileName> {
        let mut files = vec![FileName::manifest(), self.deployment.file.clone()];
        for resource in [&self.policy, &self.tools].into_iter().flatten() {
            if let ResourceSource::Bundle { reference, .. } = resource {
                files.push(reference.file.clone());
            }
        }
        files
    }
}

/// A valid `GatewayDeployment` document.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Deployment {
    pub(crate) api_version: ApiVersion,
    pub(crate) profile: Profile,
}

/// Collects one document's diagnostics.
struct Checker<'a> {
    file: &'a FileName,
    diagnostics: &'a mut Vec<BundleDiagnostic>,
    failed: bool,
}

impl Checker<'_> {
    fn report(&mut self, code: Code, pointer: Pointer, node: &Node) {
        self.failed = true;
        self.diagnostics.push(BundleDiagnostic::at(
            code,
            self.file,
            pointer,
            Some(node.position),
        ));
    }

    /// The members of an object, after refusing the ones `allowed` does not
    /// name and reporting the `required` ones that are missing.
    fn object<'n>(
        &mut self,
        node: &'n Node,
        pointer: &Pointer,
        allowed: &[&'static str],
        required: &[&'static str],
    ) -> Option<&'n [Member]> {
        let Some(members) = node.as_object() else {
            self.report(Code::WrongType, pointer.clone(), node);
            return None;
        };
        for member in members {
            if !allowed.contains(&member.key.as_str()) {
                // Reported at the parent and the key's own position: the
                // unknown name itself is document content and never echoed.
                self.failed = true;
                self.diagnostics.push(BundleDiagnostic::at(
                    Code::UnknownMember,
                    self.file,
                    pointer.clone(),
                    Some(member.key_position),
                ));
            }
        }
        for name in required {
            if !members.iter().any(|member| member.key == *name) {
                self.report(Code::MissingMember, pointer.member(name), node);
            }
        }
        Some(members)
    }

    fn string<'n>(&mut self, node: &'n Node, pointer: &Pointer) -> Option<&'n str> {
        let text = node.as_str();
        if text.is_none() {
            self.report(Code::WrongType, pointer.clone(), node);
        }
        text
    }
}

fn member<'n>(members: &'n [Member], name: &str) -> Option<&'n Node> {
    members
        .iter()
        .find(|member| member.key == name)
        .map(|member| &member.value)
}

/// The envelope check every document starts with: exact `apiVersion` and
/// `kind`, before any other member is interpreted. Returns the root's
/// members and the version, or `None` when the rest of the document cannot
/// be interpreted.
fn envelope<'n>(
    checker: &mut Checker<'_>,
    node: &'n Node,
    kind: &str,
) -> Option<(&'n [Member], ApiVersion)> {
    let root = Pointer::root();
    let Some(members) = node.as_object() else {
        checker.report(Code::WrongType, root, node);
        return None;
    };
    let version_pointer = root.member("apiVersion");
    let Some(version_node) = member(members, "apiVersion") else {
        checker.report(Code::MissingMember, version_pointer, node);
        return None;
    };
    let text = checker.string(version_node, &version_pointer)?;
    let Some(version) = ApiVersion::parse(text) else {
        checker.report(Code::UnsupportedApiVersion, version_pointer, version_node);
        return None;
    };
    let kind_pointer = root.member("kind");
    let Some(kind_node) = member(members, "kind") else {
        checker.report(Code::MissingMember, kind_pointer, node);
        return None;
    };
    if checker.string(kind_node, &kind_pointer)? != kind {
        checker.report(Code::UnsupportedKind, kind_pointer, kind_node);
        return None;
    }
    Some((members, version))
}

/// Validates a `GatewayBundle` manifest.
pub(crate) fn manifest(node: &Node, diagnostics: &mut Vec<BundleDiagnostic>) -> Option<Manifest> {
    let file = FileName::manifest();
    let mut checker = Checker {
        file: &file,
        diagnostics,
        failed: false,
    };
    let root = Pointer::root();
    let (members, api_version) = envelope(&mut checker, node, BUNDLE_KIND)?;
    checker.object(
        node,
        &root,
        &["apiVersion", "kind", "metadata", "spec"],
        &["apiVersion", "kind", "metadata", "spec"],
    )?;

    let name = member(members, "metadata").and_then(|node| {
        let pointer = root.member("metadata");
        let metadata = checker.object(node, &pointer, &["name"], &["name"])?;
        let node = member(metadata, "name")?;
        let pointer = pointer.member("name");
        let name = checker.string(node, &pointer)?;
        if is_dns_label(name) {
            Some(name.to_owned())
        } else {
            checker.report(Code::InvalidName, pointer, node);
            None
        }
    });

    let spec_pointer = root.member("spec");
    let spec = member(members, "spec").and_then(|node| {
        checker.object(
            node,
            &spec_pointer,
            &["deployment", "resources"],
            &["deployment"],
        )
    });
    let deployment = spec
        .and_then(|spec| member(spec, "deployment"))
        .and_then(|node| {
            file_reference(
                &mut checker,
                node,
                &spec_pointer.member("deployment"),
                &["yaml", "json"],
            )
        });

    let resources_pointer = spec_pointer.member("resources");
    let resources = spec
        .and_then(|spec| member(spec, "resources"))
        .and_then(|node| {
            checker.object(
                node,
                &resources_pointer,
                &["policy", "tools", "connections"],
                &[],
            )
        });
    let policy = resources
        .and_then(|resources| member(resources, "policy"))
        .map(|node| {
            json_resource(
                &mut checker,
                node,
                &resources_pointer.member("policy"),
                POLICY_SCHEMA_VERSIONS,
            )
        });
    let tools = resources
        .and_then(|resources| member(resources, "tools"))
        .map(|node| {
            json_resource(
                &mut checker,
                node,
                &resources_pointer.member("tools"),
                TOOLS_SCHEMA_VERSIONS,
            )
        });
    let connections_from_server = resources
        .and_then(|resources| member(resources, "connections"))
        .is_some_and(|node| {
            connections(&mut checker, node, &resources_pointer.member("connections"))
        });

    // Two references to one file would let one set of bytes be read as two
    // kinds of document.
    let mut seen: Vec<&FileName> = Vec::new();
    let references = [
        deployment
            .as_ref()
            .map(|reference| (reference, spec_pointer.member("deployment"))),
        bundle_reference(&policy).map(|reference| (reference, resources_pointer.member("policy"))),
        bundle_reference(&tools).map(|reference| (reference, resources_pointer.member("tools"))),
    ];
    for (reference, pointer) in references.into_iter().flatten() {
        if seen.contains(&&reference.file) {
            checker.failed = true;
            checker.diagnostics.push(BundleDiagnostic::at(
                Code::DuplicatePath,
                &file,
                pointer.member("path"),
                None,
            ));
        }
        seen.push(&reference.file);
    }

    if checker.failed {
        return None;
    }
    Some(Manifest {
        api_version,
        name: name?,
        deployment: deployment?,
        policy: policy.flatten(),
        tools: tools.flatten(),
        connections_from_server,
    })
}

fn bundle_reference(source: &Option<Option<ResourceSource>>) -> Option<&FileReference> {
    match source {
        Some(Some(ResourceSource::Bundle { reference, .. })) => Some(reference),
        _ => None,
    }
}

/// `{ path, sha256 }`, with the file name held to the portable grammar and to
/// one of `extensions`.
fn file_reference(
    checker: &mut Checker<'_>,
    node: &Node,
    pointer: &Pointer,
    extensions: &[&str],
) -> Option<FileReference> {
    let members = checker.object(node, pointer, &["path", "sha256"], &["path", "sha256"])?;
    let file = member(members, "path")
        .and_then(|node| path(checker, node, &pointer.member("path"), extensions));
    let sha256 =
        member(members, "sha256").and_then(|node| digest(checker, node, &pointer.member("sha256")));
    Some(FileReference {
        file: file?,
        sha256: sha256?,
    })
}

fn path(
    checker: &mut Checker<'_>,
    node: &Node,
    pointer: &Pointer,
    extensions: &[&str],
) -> Option<FileName> {
    let text = checker.string(node, pointer)?;
    if text == MANIFEST_FILE_NAME {
        checker.report(Code::ReservedPath, pointer.clone(), node);
        return None;
    }
    match FileName::parse(text) {
        Some(file)
            if extensions
                .iter()
                .any(|extension| file.has_extension(extension)) =>
        {
            Some(file)
        }
        _ => {
            checker.report(Code::InvalidPath, pointer.clone(), node);
            None
        }
    }
}

fn digest(checker: &mut Checker<'_>, node: &Node, pointer: &Pointer) -> Option<String> {
    let text = checker.string(node, pointer)?;
    if text.len() == 64
        && text
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        Some(text.to_owned())
    } else {
        checker.report(Code::InvalidDigest, pointer.clone(), node);
        None
    }
}

/// A policy or tools resource. `None` inside means the resource was refused.
fn json_resource(
    checker: &mut Checker<'_>,
    node: &Node,
    pointer: &Pointer,
    versions: &'static [&'static str],
) -> Option<ResourceSource> {
    let Some(members) = node.as_object() else {
        checker.report(Code::WrongType, pointer.clone(), node);
        return None;
    };
    let source_pointer = pointer.member("source");
    let Some(source_node) = member(members, "source") else {
        checker.report(Code::MissingMember, source_pointer, node);
        return None;
    };
    match checker.string(source_node, &source_pointer)? {
        "server" => {
            checker.object(node, pointer, &["source"], &["source"])?;
            Some(ResourceSource::Server)
        }
        "bundle" => {
            let members = checker.object(
                node,
                pointer,
                &["source", "path", "schema_version", "sha256"],
                &["source", "path", "schema_version", "sha256"],
            )?;
            let file = member(members, "path")
                .and_then(|node| path(checker, node, &pointer.member("path"), &["json"]));
            let schema_version = member(members, "schema_version").and_then(|node| {
                let pointer = pointer.member("schema_version");
                let text = checker.string(node, &pointer)?;
                let version = versions.iter().copied().find(|version| *version == text);
                if version.is_none() {
                    checker.report(Code::UnsupportedSchemaVersion, pointer, node);
                }
                version
            });
            let sha256 = member(members, "sha256")
                .and_then(|node| digest(checker, node, &pointer.member("sha256")));
            Some(ResourceSource::Bundle {
                reference: FileReference {
                    file: file?,
                    sha256: sha256?,
                },
                schema_version: schema_version?,
            })
        }
        _ => {
            checker.report(Code::InvalidValue, source_pointer, source_node);
            None
        }
    }
}

/// Connections are server-managed in `v1alpha1`; `true` when stated so.
fn connections(checker: &mut Checker<'_>, node: &Node, pointer: &Pointer) -> bool {
    let Some(members) = checker.object(node, pointer, &["source"], &["source"]) else {
        return false;
    };
    let Some(source) = member(members, "source") else {
        return false;
    };
    let source_pointer = pointer.member("source");
    match checker.string(source, &source_pointer) {
        Some("server") => true,
        Some("bundle") => {
            checker.report(Code::SourceUnsupported, source_pointer, source);
            false
        }
        Some(_) => {
            checker.report(Code::InvalidValue, source_pointer, source);
            false
        }
        None => false,
    }
}

/// Validates a `GatewayDeployment` document.
///
/// In this alpha the specification carries only the profile. The deployment
/// settings join it from the field catalog (issue #242, PR 3) before bundle
/// mode can be selected; until then every other member is refused as
/// unknown, so nothing is silently dropped.
pub(crate) fn deployment(
    node: &Node,
    file: &FileName,
    diagnostics: &mut Vec<BundleDiagnostic>,
) -> Option<Deployment> {
    let mut checker = Checker {
        file,
        diagnostics,
        failed: false,
    };
    let root = Pointer::root();
    let (members, api_version) = envelope(&mut checker, node, DEPLOYMENT_KIND)?;
    checker.object(
        node,
        &root,
        &["apiVersion", "kind", "spec"],
        &["apiVersion", "kind", "spec"],
    )?;
    let spec_pointer = root.member("spec");
    let profile = member(members, "spec")
        .and_then(|node| checker.object(node, &spec_pointer, &["profile"], &["profile"]))
        .and_then(|spec| member(spec, "profile"))
        .and_then(|node| {
            let pointer = spec_pointer.member("profile");
            let text = checker.string(node, &pointer)?;
            let profile = Profile::ALL
                .iter()
                .copied()
                .find(|profile| profile.as_str() == text);
            if profile.is_none() {
                checker.report(Code::InvalidValue, pointer, node);
            }
            profile
        });
    if checker.failed {
        return None;
    }
    Some(Deployment {
        api_version,
        profile: profile?,
    })
}

/// `^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`, the Kubernetes object-name label.
fn is_dns_label(name: &str) -> bool {
    let bytes = name.as_bytes();
    let alphanumeric = |byte: &u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    match bytes {
        [] => false,
        [only] => alphanumeric(only),
        [first, middle @ .., last] => {
            bytes.len() <= 63
                && alphanumeric(first)
                && alphanumeric(last)
                && middle
                    .iter()
                    .all(|byte| alphanumeric(byte) || *byte == b'-')
        }
    }
}
