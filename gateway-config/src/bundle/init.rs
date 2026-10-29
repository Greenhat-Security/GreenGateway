//! The bundle `ggctl init` writes (issue #242 PR 6; ADR-0008,
//! "Initialization profiles" and "Bootstrap model").
//!
//! [`scaffold`] turns a deployment profile and the operator's [`Answers`]
//! into the files of a `v1alpha1` bundle. It is a pure function: the same
//! profile and answers always give the same bytes, and it writes nothing.
//! `ggctl init` writes the files into a new staging directory, reads them
//! back with [`read_bundle`](super::read_bundle), and only then renames them
//! into place.
//!
//! A `v1alpha1` deployment document carries the profile and nothing else, so
//! the profiles' other invariants (authentication, egress, CSRF, audit
//! durability, loopback listeners) cannot be written down yet; they arrive
//! with the deployment settings. What can be written is the same safe
//! starting point for every profile:
//!
//! - **standalone** topology: a policy that denies by default and enforces
//!   its decisions, with no role at all unless the answers bind an operator,
//!   and a tools document with no tools. Connections stay with the server.
//! - **cluster** topology: policy, tools and Connections all stay with the
//!   server, because the PostgreSQL control planes are their writers in
//!   cluster mode (ADR-0008, "Resource ownership").
//!
//! The operator role, when the answers ask for one, is bound to exactly one
//! issuer and explicit authentication methods and grants two read
//! permissions with routes for them; it is never a wildcard and never
//! provider-agnostic. The permissive starter policy is never written.
//!
//! Nothing here can hold or make a secret: the answers document has no
//! member that can carry a secret value, `v1alpha1` has no sensitive setting
//! for a reference to fill, and no credential is generated.

use super::{
    diagnostic::{BundleDiagnostic, Code, Pointer, Position},
    document::{envelope, is_dns_label, member, Checker, Profile},
    json,
    source::{FileName, MANIFEST_FILE_NAME},
    syntax::{decode_text, Node, SyntaxError, TextRules, Value, DOCUMENT_LIMITS},
    yaml, FileRole, SourceFile, POLICY_SCHEMA_VERSIONS, TOOLS_SCHEMA_VERSIONS,
};
use crate::documents::{API_VERSION_V1ALPHA1, BUNDLE_KIND, DEPLOYMENT_KIND, INIT_ANSWERS_KIND};

/// The answers document's byte bound.
pub const MAX_ANSWERS_BYTES: usize = 64 * 1024;
/// The bundle name, and policy `id`, when the answers give none.
pub const DEFAULT_NAME: &str = "greengateway";
/// The `.gitattributes` written beside the bundle's files, so a checkout with
/// `core.autocrlf` cannot change a pinned file's bytes (ADR-0008, "Layout and
/// delivery"). The reader ignores dot entries.
pub const GITATTRIBUTES: &str = "* text eol=lf\n";
/// The name of the role the answers' `operator` generates.
pub const OPERATOR_ROLE: &str = "operator";
/// The permissions the operator role grants, each with the route prefix,
/// under the default admin prefix, that its `GET` route covers.
pub const OPERATOR_PERMISSIONS: &[(&str, &str)] = &[
    ("admin:config:read", "/v1/admin/config"),
    ("admin:status:read", "/v1/admin/status"),
];

/// The deployment document's file name.
pub const DEPLOYMENT_FILE: &str = "deployment.yaml";
/// The policy document's file name, in the standalone topology.
pub const POLICY_FILE: &str = "policy.json";
/// The tools document's file name, in the standalone topology.
pub const TOOLS_FILE: &str = "tools.json";

/// The longest issuer the answers accept.
const MAX_ISSUER_BYTES: usize = 1024;
/// The most characters, or `%XX` escapes, of a `provider:` boundary's name.
const MAX_PROVIDER_NAME_UNITS: usize = 128;
const PROVIDER_PREFIX: &str = "provider:";
const HTTPS_PREFIX: &str = "https://";

/// Which store writes the policy and tools.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Topology {
    /// One gateway: the bundle supplies its policy and tools documents.
    Standalone,
    /// The PostgreSQL state backend (ADR-0007): its control planes write the
    /// policy and tools, so the bundle leaves both to the server.
    Cluster,
}

impl Topology {
    pub const ALL: &'static [Self] = &[Self::Standalone, Self::Cluster];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Standalone => "standalone",
            Self::Cluster => "cluster",
        }
    }
}

/// An authentication method a generated role may be activated by, in the
/// policy's spelling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthMethod {
    BearerToken,
    SessionCookie,
    ServiceToken,
    ClientCertificate,
}

impl AuthMethod {
    pub const ALL: &'static [Self] = &[
        Self::BearerToken,
        Self::SessionCookie,
        Self::ServiceToken,
        Self::ClientCertificate,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::BearerToken => "bearer_token",
            Self::SessionCookie => "session_cookie",
            Self::ServiceToken => "service_token",
            Self::ClientCertificate => "client_certificate",
        }
    }
}

/// The operator role the answers bind.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Operator {
    issuer: String,
    auth_methods: Vec<AuthMethod>,
}

impl Operator {
    /// The issuer, in the canonical form the gateway compares: an exact
    /// `https` issuer without trailing slashes, or a `provider:` boundary.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn auth_methods(&self) -> &[AuthMethod] {
        &self.auth_methods
    }
}

/// What `ggctl init` builds a bundle from, beside the profile. Built only by
/// [`Answers::default`] and [`read_answers`], so every value has passed its
/// rule.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Answers {
    name: String,
    topology: Topology,
    operator: Option<Operator>,
}

impl Default for Answers {
    fn default() -> Self {
        Self {
            name: DEFAULT_NAME.to_owned(),
            topology: Topology::Standalone,
            operator: None,
        }
    }
}

impl Answers {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn topology(&self) -> Topology {
        self.topology
    }

    pub fn operator(&self) -> Option<&Operator> {
        self.operator.as_ref()
    }
}

/// How an answers document is written.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnswersSyntax {
    /// The bundle's YAML subset.
    Yaml,
    /// Strict JSON.
    Json,
}

/// Reads a `GatewayInitAnswers` document under the same text rules, syntax
/// subset, bounds and closed-object rules as a bundle document. Diagnostics
/// carry a pointer and a position, and no file: the document is not part of
/// a bundle, and its path is the caller's to locate.
pub fn read_answers(bytes: &[u8], syntax: AnswersSyntax) -> Result<Answers, Vec<BundleDiagnostic>> {
    if bytes.len() > MAX_ANSWERS_BYTES {
        return Err(vec![BundleDiagnostic::bundle(Code::FileTooLarge)]);
    }
    let parsed = decode_text(bytes, TextRules::Document).and_then(|text| match syntax {
        AnswersSyntax::Yaml => yaml::parse(text, DOCUMENT_LIMITS),
        AnswersSyntax::Json => json::parse(text, DOCUMENT_LIMITS),
    });
    let node = parsed
        .map_err(|SyntaxError { code, position }| vec![located(code, Pointer::root(), position)])?;
    let mut diagnostics = Vec::new();
    match answers(&node, &mut diagnostics) {
        Some(answers) if diagnostics.is_empty() => Ok(answers),
        _ => Err(diagnostics),
    }
}

fn located(code: Code, pointer: Pointer, position: Position) -> BundleDiagnostic {
    BundleDiagnostic {
        pointer,
        position: Some(position),
        ..BundleDiagnostic::bundle(code)
    }
}

fn answers(node: &Node, diagnostics: &mut Vec<BundleDiagnostic>) -> Option<Answers> {
    let mut checker = Checker {
        file: None,
        diagnostics,
        failed: false,
    };
    let root = Pointer::root();
    let (members, _) = envelope(&mut checker, node, INIT_ANSWERS_KIND)?;
    checker.object(
        node,
        &root,
        &["apiVersion", "kind", "spec"],
        &["apiVersion", "kind", "spec"],
    )?;
    let spec_pointer = root.member("spec");
    let spec = member(members, "spec").and_then(|node| {
        checker.object(node, &spec_pointer, &["name", "topology", "operator"], &[])
    })?;

    let mut answers = Answers::default();
    if let Some(node) = member(spec, "name") {
        let pointer = spec_pointer.member("name");
        if let Some(name) = checker.string(node, &pointer) {
            if is_dns_label(name) {
                answers.name = name.to_owned();
            } else {
                checker.report(Code::InvalidName, pointer, node);
            }
        }
    }
    if let Some(node) = member(spec, "topology") {
        let pointer = spec_pointer.member("topology");
        if let Some(text) = checker.string(node, &pointer) {
            match Topology::ALL
                .iter()
                .copied()
                .find(|topology| topology.as_str() == text)
            {
                Some(topology) => answers.topology = topology,
                None => checker.report(Code::InvalidValue, pointer, node),
            }
        }
    }
    if let Some(node) = member(spec, "operator") {
        let pointer = spec_pointer.member("operator");
        answers.operator = operator(&mut checker, node, &pointer);
        // A cluster's policy is the server's, so there is no policy here to
        // hold the role.
        if answers.topology == Topology::Cluster {
            checker.report(Code::NotApplicable, pointer, node);
        }
    }
    if checker.failed {
        return None;
    }
    Some(answers)
}

fn operator(checker: &mut Checker<'_>, node: &Node, pointer: &Pointer) -> Option<Operator> {
    let members = checker.object(
        node,
        pointer,
        &["issuer", "auth_methods"],
        &["issuer", "auth_methods"],
    )?;
    let issuer = member(members, "issuer").and_then(|node| {
        let pointer = pointer.member("issuer");
        let text = checker.string(node, &pointer)?;
        let issuer = canonical_issuer(text);
        if issuer.is_none() {
            checker.report(Code::InvalidValue, pointer, node);
        }
        issuer
    });
    let auth_methods = member(members, "auth_methods")
        .and_then(|node| auth_methods(checker, node, &pointer.member("auth_methods")));
    Some(Operator {
        issuer: issuer?,
        auth_methods: auth_methods?,
    })
}

/// At least one method, each known and named once: an empty list would mean
/// any method.
fn auth_methods(
    checker: &mut Checker<'_>,
    node: &Node,
    pointer: &Pointer,
) -> Option<Vec<AuthMethod>> {
    let Value::Array(items) = &node.value else {
        checker.report(Code::WrongType, pointer.clone(), node);
        return None;
    };
    if items.is_empty() {
        checker.report(Code::InvalidValue, pointer.clone(), node);
        return None;
    }
    let mut methods = Vec::with_capacity(items.len());
    let mut valid = true;
    for (index, item) in items.iter().enumerate() {
        let pointer = pointer.index(index);
        let Some(text) = checker.string(item, &pointer) else {
            valid = false;
            continue;
        };
        match AuthMethod::ALL
            .iter()
            .copied()
            .find(|method| method.as_str() == text)
        {
            Some(method) if !methods.contains(&method) => methods.push(method),
            _ => {
                checker.report(Code::InvalidValue, pointer, item);
                valid = false;
            }
        }
    }
    valid.then_some(methods)
}

/// An exact `https` issuer with a host and no user name, password, query or
/// fragment, without its trailing slashes (the form the gateway compares
/// issuers in), or a `provider:` boundary whose name is percent-encoded as
/// the gateway encodes it. `None` for anything else, so nothing that could
/// carry a credential or break out of a JSON string is written.
fn canonical_issuer(text: &str) -> Option<String> {
    if text.len() > MAX_ISSUER_BYTES {
        return None;
    }
    if let Some(name) = text.strip_prefix(PROVIDER_PREFIX) {
        return is_encoded_provider_name(name).then(|| text.to_owned());
    }
    let rest = text.strip_prefix(HTTPS_PREFIX)?.trim_end_matches('/');
    let host = rest.split('/').next().unwrap_or_default();
    let allowed = |character: char| {
        !(character.is_whitespace()
            || character.is_control()
            || matches!(character, '?' | '#' | '@' | '\\' | '"'))
    };
    (!host.is_empty() && rest.chars().all(allowed)).then(|| format!("{HTTPS_PREFIX}{rest}"))
}

/// `([A-Za-z0-9._~-] | %XX)+`, with uppercase hexadecimal escapes, at most
/// [`MAX_PROVIDER_NAME_UNITS`] units: what `provider_issuer` in the gateway
/// produces from a provider name.
fn is_encoded_provider_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    let mut index = 0;
    let mut units = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'~' | b'-') {
            index += 1;
        } else if byte == b'%'
            && bytes.get(index + 1..index + 3).is_some_and(|escape| {
                escape
                    .iter()
                    .all(|digit| digit.is_ascii_digit() || (b'A'..=b'F').contains(digit))
            })
        {
            index += 3;
        } else {
            return false;
        }
        units += 1;
    }
    (1..=MAX_PROVIDER_NAME_UNITS).contains(&units)
}

/// The files of the bundle for `profile` and `answers`, the manifest first
/// and then each file in the order the manifest references it. The
/// `.gitattributes` beside them is [`GITATTRIBUTES`].
pub fn scaffold(profile: Profile, answers: &Answers) -> Vec<SourceFile> {
    let deployment = deployment_document(profile).into_bytes();
    let deployment_pin = super::sha256_pin(&deployment);
    let mut files = vec![SourceFile {
        role: FileRole::Deployment,
        name: FileName::fixed(DEPLOYMENT_FILE),
        bytes: deployment,
    }];
    let resources = match answers.topology {
        Topology::Standalone => {
            let policy = policy_document(answers).into_bytes();
            let tools = tools_document().into_bytes();
            let resources = format!(
                concat!(
                    "    policy:\n",
                    "      source: bundle\n",
                    "      path: {policy_file}\n",
                    "      schema_version: \"{policy_version}\"\n",
                    "      sha256: \"{policy_pin}\"\n",
                    "    tools:\n",
                    "      source: bundle\n",
                    "      path: {tools_file}\n",
                    "      schema_version: \"{tools_version}\"\n",
                    "      sha256: \"{tools_pin}\"\n",
                ),
                policy_file = POLICY_FILE,
                policy_version = policy_schema_version(),
                policy_pin = super::sha256_pin(&policy),
                tools_file = TOOLS_FILE,
                tools_version = tools_schema_version(),
                tools_pin = super::sha256_pin(&tools),
            );
            files.push(SourceFile {
                role: FileRole::Policy,
                name: FileName::fixed(POLICY_FILE),
                bytes: policy,
            });
            files.push(SourceFile {
                role: FileRole::Tools,
                name: FileName::fixed(TOOLS_FILE),
                bytes: tools,
            });
            resources
        }
        Topology::Cluster => concat!(
            "    policy:\n",
            "      source: server\n",
            "    tools:\n",
            "      source: server\n",
        )
        .to_owned(),
    };
    let manifest = format!(
        concat!(
            "# Generated by ggctl init. Each sha256 pins the exact bytes of its file:\n",
            "# change a file and its pin together, then run ggctl validate.\n",
            "apiVersion: {api_version}\n",
            "kind: {kind}\n",
            "metadata:\n",
            "  name: \"{name}\"\n",
            "spec:\n",
            "  deployment:\n",
            "    path: {deployment_file}\n",
            "    sha256: \"{deployment_pin}\"\n",
            "  resources:\n",
            "{resources}",
            "    connections:\n",
            "      source: server\n",
        ),
        api_version = API_VERSION_V1ALPHA1,
        kind = BUNDLE_KIND,
        name = answers.name,
        deployment_file = DEPLOYMENT_FILE,
        deployment_pin = deployment_pin,
        resources = resources,
    );
    files.insert(
        0,
        SourceFile {
            role: FileRole::Manifest,
            name: FileName::fixed(MANIFEST_FILE_NAME),
            bytes: manifest.into_bytes(),
        },
    );
    files
}

fn deployment_document(profile: Profile) -> String {
    let notice = match profile {
        Profile::Development => {
            "# The development profile is for local evaluation, not for production.\n"
        }
        Profile::Migration => {
            "# The migration profile is for moving an existing deployment over, not a final state.\n"
        }
        Profile::Production => "",
    };
    format!(
        "# Generated by ggctl init.\n{notice}apiVersion: {API_VERSION_V1ALPHA1}\nkind: {DEPLOYMENT_KIND}\nspec:\n  profile: {}\n",
        profile.as_str()
    )
}

/// Deny by default and enforce, whatever the profile; the operator role and
/// its routes only when the answers bind one.
fn policy_document(answers: &Answers) -> String {
    let (roles, routes) = match &answers.operator {
        None => ("{}".to_owned(), "[]".to_owned()),
        Some(operator) => {
            let permissions: Vec<_> = OPERATOR_PERMISSIONS
                .iter()
                .map(|(permission, _)| format!("\"{permission}\""))
                .collect();
            let methods: Vec<_> = operator
                .auth_methods
                .iter()
                .map(|method| format!("\"{}\"", method.as_str()))
                .collect();
            let roles = format!(
                concat!(
                    "{{\n",
                    "    \"{role}\": {{\n",
                    "      \"description\": \"Reads the gateway's status and configuration capabilities. Generated by ggctl init.\",\n",
                    "      \"permissions\": [{permissions}],\n",
                    "      \"issuers\": [\"{issuer}\"],\n",
                    "      \"auth_methods\": [{methods}]\n",
                    "    }}\n",
                    "  }}",
                ),
                role = OPERATOR_ROLE,
                permissions = permissions.join(", "),
                issuer = operator.issuer,
                methods = methods.join(", "),
            );
            let routes: Vec<_> = OPERATOR_PERMISSIONS
                .iter()
                .map(|(permission, prefix)| {
                    format!(
                        "    {{\"methods\": [\"GET\"], \"path_prefix\": \"{prefix}\", \"permission\": \"{permission}\"}}"
                    )
                })
                .collect();
            (roles, format!("[\n{}\n  ]", routes.join(",\n")))
        }
    };
    format!(
        concat!(
            "{{\n",
            "  \"schema_version\": \"{version}\",\n",
            "  \"id\": \"{id}\",\n",
            "  \"default_action\": \"deny\",\n",
            "  \"enforcement_mode\": \"enforce\",\n",
            "  \"roles\": {roles},\n",
            "  \"routes\": {routes}\n",
            "}}\n",
        ),
        version = policy_schema_version(),
        id = answers.name,
        roles = roles,
        routes = routes,
    )
}

fn tools_document() -> String {
    format!(
        "{{\n  \"schema_version\": \"{}\",\n  \"tools\": []\n}}\n",
        tools_schema_version()
    )
}

/// The newest policy document version the bundle boundary implements.
fn policy_schema_version() -> &'static str {
    POLICY_SCHEMA_VERSIONS.last().copied().unwrap_or("0.1.0")
}

/// The newest tools document version the bundle boundary implements.
fn tools_schema_version() -> &'static str {
    TOOLS_SCHEMA_VERSIONS.last().copied().unwrap_or("0.1.0")
}

#[cfg(test)]
mod tests;
