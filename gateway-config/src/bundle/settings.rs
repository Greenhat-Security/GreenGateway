//! The deployment settings a `GatewayDeployment` document's `spec` carries
//! (issue #242), read from the field catalog.
//!
//! Every catalog field with a document path ([`Field::document_path`]) is one
//! member of `spec` or of a section beneath it, and the document's shape is
//! derived from those paths alone: the members an object may have are
//! exactly the next segments of the paths beneath it. So every section is
//! closed, a member no path names is refused rather than ignored, and the
//! reader, the published schema ([`render_deployment_schema`]) and the
//! reference in `docs/configuration-bundles.md`
//! ([`render_deployment_reference`]) cannot describe different documents.
//!
//! Each setting is held to its catalog entry and nothing else:
//!
//! - a boolean is `true` or `false`, and a choice exactly one of its words;
//! - an integer is a JSON integer within the field's own range, which the
//!   I-JSON safe range bounds further (the syntax reader refuses anything
//!   beyond it before a value is built);
//! - a fractional field is a decimal string (ADR-0008's grammar) within the
//!   field's own range. Its value is exactly the `f64` the same text gives in
//!   the environment, and its canonical form the shortest exact spelling;
//! - a socket address, URL or other string is non-empty, with no whitespace
//!   at either end, and a list is an array of such strings with no comma, so
//!   each maps one to one onto an entry of the environment's comma-separated
//!   form, which trims entries and drops empty ones;
//! - a field whose value may carry a secret accepts only a secret reference;
//! - a field that holds a JSON document (`AUTH_PROVIDERS`, `UPSTREAM_ROUTES`,
//!   `MCP_UPSTREAM_SERVERS`) takes the closed structured form
//!   [`structured`] defines from the compiler's own types, in which every
//!   member that may carry a secret accepts only a secret reference;
//! - no field accepts an unresolved placeholder.
//!
//! The reader checks shape and per-field bounds here. It runs the compiler's
//! listener, egress, authentication provider and admin login rules after reading these
//! settings. The other compiler rules still need their document mappings.
//!
//! Some members are the document's own rather than one field's
//! ([`OWN_MEMBERS`]): the standalone stores a deployment keeps beneath its
//! state directory, whether each listener terminates TLS and checks client
//! certificates against a revocation list, the admin login client, and the
//! compatibility behaviors a `migration` document acknowledges. In
//! environment mode the first two are which host locators are set
//! (ADR-0008, "Bootstrap inputs"): the document states the intent, and the
//! locators stay in the environment.

mod listeners;
mod render;
pub(crate) mod structured;
#[cfg(test)]
mod structured_tests;
#[cfg(test)]
mod tests;

use std::{collections::BTreeMap, env::VarError};

use crate::{
    catalog::{self, DecimalBound, DecimalRange, Domain, Field, FieldType, Sensitivity, FIELDS},
    compiler::{self, egress, AdminClientPresence, AdminLoginRefusal},
    state_dir::StateFile,
};

pub use render::{render_deployment_reference, render_deployment_schema};

use super::{
    diagnostic::{BundleDiagnostic, Code, Pointer},
    document::{member, Checker},
    profile::Compatibility,
    source::FileName,
    syntax::{Member, Node, Value, MAX_SAFE_INTEGER},
    value::{Decimal, SecretReference, Unresolved},
};
use structured::{Document, Structured};

/// Where the published deployment schema is committed, relative to the
/// repository root.
pub const DEPLOYMENT_SCHEMA_DOCUMENT: &str = "docs/schemas/gateway-deployment.v1alpha1.schema.json";

/// The document path of the standalone store list.
pub const STORES_PATH: &str = "/spec/state/stores";

/// The document path of the acknowledged compatibility behaviors.
pub(crate) const ACKNOWLEDGED_PATH: &str = "/spec/compatibility/acknowledged";

/// What a member of the document's own holds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OwnValue {
    /// Exactly one of these words.
    Word(&'static [&'static str]),
    /// A non-empty string with no whitespace at either end.
    Text,
    /// A secret reference.
    Secret,
    /// Distinct names from [`STANDALONE_STORES`], kept in its order.
    Stores,
    /// Distinct codes from [`Compatibility::ALL`], kept in its order.
    Compatibility,
}

impl OwnValue {
    /// The words a set member may name, in canonical order.
    pub(crate) fn set_words(self) -> Option<Vec<&'static str>> {
        match self {
            Self::Stores => Some(STANDALONE_STORES.iter().map(|store| store.name).collect()),
            Self::Compatibility => Some(
                Compatibility::ALL
                    .iter()
                    .map(|behavior| behavior.as_str())
                    .collect(),
            ),
            Self::Word(_) | Self::Text | Self::Secret => None,
        }
    }
}

/// A member of `spec` that is the document's own rather than one catalog
/// field's.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OwnMember {
    pub(crate) path: &'static str,
    pub(crate) value: OwnValue,
    /// What it means, for the schema.
    pub(crate) description: &'static str,
    /// What it is in environment mode, for the reference.
    pub(crate) environment: &'static str,
    /// Its default, spelled for the reference.
    pub(crate) default: &'static str,
}

/// The words of a listener's TLS and revocation-list intent.
const INTENT: &[&str] = &["required", "off"];

/// Every member of the document's own, in the order the reference lists
/// them within their sections.
pub(crate) const OWN_MEMBERS: &[OwnMember] = &[
    OwnMember {
        path: "/spec/listeners/public/tls",
        value: OwnValue::Word(INTENT),
        description: "Whether the data listener terminates TLS. The certificate and key are host locators that stay in the environment; the compiler will hold this intent and them to each other.",
        environment: "`required` when [`TLS_CERT_FILE`](configuration.md#tls_cert_file) and [`TLS_KEY_FILE`](configuration.md#tls_key_file) are set",
        default: "`\"off\"`",
    },
    OwnMember {
        path: "/spec/listeners/public/client_certificate_crl",
        value: OwnValue::Word(INTENT),
        description: "Whether the data listener checks client certificates against a certificate revocation list. The list is a host locator that stays in the environment; the compiler will hold this intent and it to each other.",
        environment: "`required` when [`CLIENT_CERT_CRL_FILE`](configuration.md#client_cert_crl_file) is set",
        default: "`\"off\"`",
    },
    OwnMember {
        path: "/spec/listeners/admin/tls",
        value: OwnValue::Word(INTENT),
        description: "Whether the admin listener terminates TLS. The certificate and key are host locators that stay in the environment; the compiler will hold this intent and them to each other.",
        environment: "`required` when [`ADMIN_TLS_CERT_FILE`](configuration.md#admin_tls_cert_file) and [`ADMIN_TLS_KEY_FILE`](configuration.md#admin_tls_key_file) are set",
        default: "`\"off\"`",
    },
    OwnMember {
        path: "/spec/listeners/admin/client_certificate_crl",
        value: OwnValue::Word(INTENT),
        description: "Whether the admin listener checks client certificates against a certificate revocation list. The list is a host locator that stays in the environment; the compiler will hold this intent and it to each other.",
        environment: "`required` when [`ADMIN_CLIENT_CERT_CRL_FILE`](configuration.md#admin_client_cert_crl_file) is set",
        default: "`\"off\"`",
    },
    OwnMember {
        path: "/spec/admin_login/client_id",
        value: OwnValue::Text,
        description: "The OAuth client ID admin sign-in uses with the admin login provider.",
        environment: "`client_id` of the [`AUTH_PROVIDERS`](configuration.md#auth_providers) entry [`ADMIN_LOGIN_PROVIDER`](configuration.md#admin_login_provider) names",
        default: "unset",
    },
    OwnMember {
        path: "/spec/admin_login/client_secret",
        value: OwnValue::Secret,
        description: "The OAuth client secret admin sign-in uses with the admin login provider. It is a secret, so it is a secret reference.",
        environment: "`client_secret` of the [`AUTH_PROVIDERS`](configuration.md#auth_providers) entry [`ADMIN_LOGIN_PROVIDER`](configuration.md#admin_login_provider) names",
        default: "unset",
    },
    OwnMember {
        path: "/spec/admin_login/redirect_uri",
        value: OwnValue::Text,
        description: "The callback URL the admin login provider redirects to after sign-in.",
        environment: "`redirect_uri` of the [`AUTH_PROVIDERS`](configuration.md#auth_providers) entry [`ADMIN_LOGIN_PROVIDER`](configuration.md#admin_login_provider) names",
        default: "unset",
    },
    OwnMember {
        path: STORES_PATH,
        value: OwnValue::Stores,
        description: "The standalone stores kept beneath the state directory, each named once; in environment mode, which of their *_SQLITE_PATH variables are set.",
        environment: "",
        default: "unset",
    },
    OwnMember {
        path: ACKNOWLEDGED_PATH,
        value: OwnValue::Compatibility,
        description: "The compatibility behaviors a migration document keeps, each named once. Only the migration profile may acknowledge one, and each is then a warning instead of an error.",
        environment: "none: environment mode has no profile",
        default: "unset",
    },
];

/// A standalone store a deployment document can enable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StandaloneStore {
    /// Its word in `spec.state.stores`.
    pub name: &'static str,
    /// Its fixed file beneath the state directory.
    pub file: StateFile,
}

impl StandaloneStore {
    /// The environment variable that locates the store in environment mode.
    pub fn environment(&self) -> Option<&'static str> {
        let id = self.file.catalog_field()?;
        FIELDS
            .iter()
            .find(|field| field.id == id)
            .map(|field| field.environment)
    }
}

/// The stores `spec.state.stores` can name, in canonical order.
///
/// Policy publication history is not one of them: whether bundle mode keeps
/// a history beside a bundle-owned policy is still undecided (ADR-0008), so
/// `v1alpha1` cannot enable it. Nor is the configuration ledger, which only
/// ledger mode keeps.
pub const STANDALONE_STORES: &[StandaloneStore] = &[
    StandaloneStore {
        name: "audit",
        file: StateFile::Audit,
    },
    StandaloneStore {
        name: "discovery",
        file: StateFile::Discovery,
    },
    StandaloneStore {
        name: "principals",
        file: StateFile::Principals,
    },
    StandaloneStore {
        name: "connections",
        file: StateFile::Connections,
    },
    StandaloneStore {
        name: "service_tokens",
        file: StateFile::ServiceTokens,
    },
];

/// A closed object beneath `spec` that groups settings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Section {
    pub path: &'static str,
    pub description: &'static str,
}

/// Every section, each described once. `bundle::settings::tests` holds this
/// list to the sections the document paths imply.
pub const SECTIONS: &[Section] = &[
    Section {
        path: "/spec/listeners",
        description: "The listeners the gateway binds. Certificate, key, CA and CRL files are host locators and stay in the environment; the document states whether each listener terminates TLS and checks a revocation list.",
    },
    Section {
        path: "/spec/listeners/public",
        description: "The data listener.",
    },
    Section {
        path: "/spec/listeners/admin",
        description: "The admin surface: its own listener, when it has one, and its path prefix.",
    },
    Section {
        path: "/spec/listeners/grpc",
        description: "The gRPC listener.",
    },
    Section {
        path: "/spec/listeners/tls",
        description: "Inbound TLS on the listeners that terminate it.",
    },
    Section {
        path: "/spec/admin_login",
        description: "Admin sign-in through an authentication provider, and the OAuth client it signs in with.",
    },
    Section {
        path: "/spec/admin_sessions",
        description: "Admin sessions.",
    },
    Section {
        path: "/spec/audit",
        description: "The audit trail: durability, the shutdown drain, probe observations and retention.",
    },
    Section {
        path: "/spec/shutdown",
        description: "Graceful shutdown.",
    },
    Section {
        path: "/spec/discovery",
        description: "API discovery, payload capture and the discovery signals.",
    },
    Section {
        path: "/spec/discovery/projector",
        description: "The cluster-mode discovery projector.",
    },
    Section {
        path: "/spec/discovery/payload_capture",
        description: "Sampled request payload capture.",
    },
    Section {
        path: "/spec/discovery/signals",
        description: "The thresholds of the discovery signals.",
    },
    Section {
        path: "/spec/policy_tests",
        description: "The stored policy test suite as a gate on policy changes.",
    },
    Section {
        path: "/spec/cors",
        description: "Cross-origin resource sharing.",
    },
    Section {
        path: "/spec/limits",
        description: "Request bounds, and the media types mutating requests may carry.",
    },
    Section {
        path: "/spec/rate_limits",
        description: "The global rate limits applied before authentication, in two lanes.",
    },
    Section {
        path: "/spec/rate_limits/read",
        description: "The read lane: `GET` and `HEAD` requests.",
    },
    Section {
        path: "/spec/rate_limits/write",
        description: "The write lane: every other method.",
    },
    Section {
        path: "/spec/trusted_proxies",
        description: "Which proxies' forwarded client addresses are believed.",
    },
    Section {
        path: "/spec/authorization",
        description: "Authorization outside the policy document.",
    },
    Section {
        path: "/spec/authentication",
        description: "Request authentication and the authentication providers.",
    },
    Section {
        path: "/spec/tool_runtime",
        description: "Tool execution.",
    },
    Section {
        path: "/spec/cluster",
        description: "Cluster identity, membership, readiness and status, in cluster mode.",
    },
    Section {
        path: "/spec/csrf",
        description: "Cross-site request forgery protection for cookie-authenticated requests.",
    },
    Section {
        path: "/spec/upstream",
        description: "The single upstream or the upstream routes, the MCP upstream servers, and the timeouts of proxied requests.",
    },
    Section {
        path: "/spec/egress",
        description: "Requests the gateway itself sends.",
    },
    Section {
        path: "/spec/state",
        description: "The state backend and, in standalone mode, the stores kept beneath the state directory.",
    },
    Section {
        path: "/spec/state/postgres",
        description: "The PostgreSQL pool, its timeouts and migrations, in cluster mode. The connection string file and its CA bundle are host locators and stay in the environment.",
    },
    Section {
        path: "/spec/authority_evidence",
        description: "Authority evidence and its event delivery.",
    },
    Section {
        path: "/spec/compatibility",
        description: "The compatibility behaviors a migration document acknowledges.",
    },
];

/// A setting's value as the document wrote it, typed by its catalog entry.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum SettingValue {
    Boolean(bool),
    Integer(u64),
    Decimal(Decimal),
    /// One of a choice field's words.
    Word(&'static str),
    /// A socket address, URL or other string, held to the shape above.
    Text(String),
    List(Vec<String>),
    Secret(SecretReference),
    /// A JSON-valued field, in its environment form.
    Structured(Structured),
    /// A set of words, in canonical order.
    Words(Vec<&'static str>),
}

/// One setting a document gave.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Setting {
    pub(crate) field: &'static Field,
    pub(crate) value: SettingValue,
}

/// One member of the document's own that a document gave.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct OwnSetting {
    pub(crate) member: &'static OwnMember,
    pub(crate) value: SettingValue,
}

/// The settings of a valid deployment document, in the order it gave them.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct Settings {
    pub(crate) values: Vec<Setting>,
    pub(crate) own: Vec<OwnSetting>,
}

impl Settings {
    /// Compile the document's public egress settings independently of the
    /// process environment. A list entry cannot contain a comma, so joining
    /// it preserves exactly the entries the egress stage will read.
    pub(super) fn egress_diagnostics(
        &self,
        document: &Node,
        file: &FileName,
    ) -> Vec<BundleDiagnostic> {
        let mut inputs = BTreeMap::new();
        let mut unsupported = Vec::new();
        for setting in self
            .values
            .iter()
            .filter(|setting| setting.field.domain == Domain::Egress)
        {
            let input = match &setting.value {
                SettingValue::Boolean(value) => value.to_string(),
                SettingValue::Integer(value) => value.to_string(),
                SettingValue::List(entries) => entries.join(","),
                _ => {
                    unsupported.push(setting.field.environment);
                    continue;
                }
            };
            inputs.insert(setting.field.environment, input);
        }
        if inputs.is_empty() && unsupported.is_empty() {
            return Vec::new();
        }
        let mut refused =
            egress::refused_settings(|name| inputs.remove(name).ok_or(VarError::NotPresent));
        // The stage requests each input once. A new catalog field that it
        // never requested must not silently pass validation.
        refused.extend(inputs.into_keys());
        refused.extend(unsupported);
        refused
            .into_iter()
            .map(|name| {
                let path = catalog::field(name)
                    .and_then(Field::document_path)
                    .unwrap_or("");
                at_setting(
                    Code::InvalidEgressSetting,
                    file,
                    document,
                    path.split('/').skip(1),
                )
            })
            .collect()
    }

    /// Checks explicit providers and the client of the one selected for
    /// admin login. Only presence crosses the compiler boundary for client
    /// fields, and an alias is never read, serialized, or resolved here.
    pub(super) fn provider_diagnostics(
        &self,
        document: &Node,
        file: &FileName,
    ) -> Vec<BundleDiagnostic> {
        let setting = |name| {
            self.values
                .iter()
                .find(|setting| setting.field.environment == name)
                .map(|setting| &setting.value)
        };
        let invalid_providers = || {
            at_setting(
                Code::InvalidAuthProvider,
                file,
                document,
                ["spec", "authentication", "providers"],
            )
        };
        let invalid_login = |field| {
            at_setting(
                Code::InvalidAdminLogin,
                file,
                document,
                ["spec", "admin_login", field],
            )
        };
        let providers = match setting(compiler::AUTH_PROVIDERS) {
            None => Some(Vec::new()),
            Some(SettingValue::Structured(structured)) if structured.secrets.is_empty() => {
                serde_json::from_value(structured.environment.clone()).ok()
            }
            // A future secret-bearing provider member needs an explicit mapping.
            Some(_) => None,
        };
        let Some(providers) = providers else {
            return vec![invalid_providers()];
        };
        let login = match setting(compiler::ADMIN_LOGIN_PROVIDER) {
            Some(SettingValue::Text(name)) => Some(name.as_str()),
            None => None,
            _ => return vec![invalid_login("provider")],
        };
        let client = AdminClientPresence {
            client_id: matches!(
                self.own_value("/spec/admin_login/client_id"),
                Some(SettingValue::Text(_))
            ),
            client_secret: matches!(
                self.own_value("/spec/admin_login/client_secret"),
                Some(SettingValue::Secret(_))
            ),
            redirect_uri: matches!(
                self.own_value("/spec/admin_login/redirect_uri"),
                Some(SettingValue::Text(_))
            ),
        };
        let (valid, login_refusals) = compiler::check_document_providers(providers, login, client);
        let mut diagnostics = Vec::new();
        if !valid {
            diagnostics.push(invalid_providers());
        }
        for refusal in login_refusals {
            let field = match refusal {
                AdminLoginRefusal::Client(field) => field,
                AdminLoginRefusal::Unknown
                | AdminLoginRefusal::Type
                | AdminLoginRefusal::Issuer => "provider",
            };
            let diagnostic = invalid_login(field);
            if !diagnostics.contains(&diagnostic) {
                diagnostics.push(diagnostic);
            }
        }
        diagnostics
    }

    /// The value the document gave the member of its own at `path`.
    pub(crate) fn own_value(&self, path: &str) -> Option<&SettingValue> {
        self.own
            .iter()
            .find(|setting| setting.member.path == path)
            .map(|setting| &setting.value)
    }

    /// The compatibility behaviors the document acknowledges.
    pub(crate) fn acknowledged(&self) -> Vec<Compatibility> {
        match self.own_value(ACKNOWLEDGED_PATH) {
            Some(SettingValue::Words(words)) => Compatibility::ALL
                .iter()
                .copied()
                .filter(|behavior| words.contains(&behavior.as_str()))
                .collect(),
            _ => Vec::new(),
        }
    }

    /// Rewrites the document's JSON value into its canonical form: each
    /// decimal as its shortest exact spelling and each set of words (the
    /// store list, the acknowledged behaviors) in its canonical order, so
    /// neither changes the canonical bytes or the digests made from them.
    pub(crate) fn canonicalize(&self, document: &mut serde_json::Value) {
        for setting in &self.values {
            let SettingValue::Decimal(decimal) = &setting.value else {
                continue;
            };
            let slot = setting
                .field
                .document_path()
                .and_then(|path| document.pointer_mut(path));
            if let Some(slot) = slot {
                *slot = serde_json::Value::String(decimal.canonical().to_owned());
            }
        }
        for setting in &self.own {
            let SettingValue::Words(words) = &setting.value else {
                continue;
            };
            if let Some(slot) = document.pointer_mut(setting.member.path) {
                *slot = serde_json::Value::Array(
                    words
                        .iter()
                        .map(|word| serde_json::Value::String((*word).to_owned()))
                        .collect(),
                );
            }
        }
    }
}

/// A missing required member is located at the closest enclosing node.
/// Pointer segments come only from the schema or the compiler's fixed fields.
fn at_setting(
    code: Code,
    file: &FileName,
    document: &Node,
    path: impl IntoIterator<Item = &'static str>,
) -> BundleDiagnostic {
    let mut pointer = Pointer::root();
    let mut node = Some(document);
    let mut position = document.position;
    for segment in path {
        pointer = pointer.member(segment);
        node = node
            .and_then(|node| node.as_object())
            .and_then(|members| member(members, segment));
        if let Some(node) = node {
            position = node.position;
        }
    }
    BundleDiagnostic::at(code, file, pointer, Some(position))
}

/// What one member of a `spec` object is.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Child {
    Setting(&'static Field),
    /// A section, by its document path.
    Section(&'static str),
    Own(&'static OwnMember),
}

/// Every document path below `spec`, in catalog order, the document's own
/// members last.
pub(crate) fn document_paths() -> impl Iterator<Item = (&'static str, Child)> {
    FIELDS
        .iter()
        .filter_map(|field| {
            field
                .document_path()
                .map(|path| (path, Child::Setting(field)))
        })
        .chain(
            OWN_MEMBERS
                .iter()
                .map(|member| (member.path, Child::Own(member))),
        )
}

/// The members the object at `path` may have, by name, in the order the
/// paths beneath it first name them.
pub(crate) fn children(path: &str) -> Vec<(&'static str, Child)> {
    let mut children: Vec<(&'static str, Child)> = Vec::new();
    for (full, leaf) in document_paths() {
        let Some(rest) = full
            .strip_prefix(path)
            .and_then(|rest| rest.strip_prefix('/'))
        else {
            continue;
        };
        let child = match rest.split_once('/') {
            None => (rest, leaf),
            Some((name, _)) => {
                let end = full.len() - rest.len() + name.len();
                (name, Child::Section(&full[..end]))
            }
        };
        if !children.iter().any(|(name, _)| *name == child.0) {
            children.push(child);
        }
    }
    children
}

/// The member names of the object at `path`.
pub(crate) fn member_names(path: &str) -> Vec<&'static str> {
    children(path).into_iter().map(|(name, _)| name).collect()
}

/// Reads the settings among `members`, the members of the object at `path`
/// (`/spec` or a section), whose unknown members the caller has already
/// refused.
pub(super) fn read_members(
    checker: &mut Checker<'_>,
    members: &[Member],
    path: &'static str,
    pointer: &Pointer,
    settings: &mut Settings,
) {
    let children = children(path);
    for member in members {
        let Some((name, child)) = children
            .iter()
            .find(|(name, _)| *name == member.key.as_str())
        else {
            continue;
        };
        let pointer = pointer.member(name);
        match *child {
            Child::Setting(field) => match Document::of(field) {
                Some(document) => {
                    let read = structured::read(checker, document, &member.value, &pointer);
                    if let Some(value) = read {
                        settings.values.push(Setting {
                            field,
                            value: SettingValue::Structured(value),
                        });
                    }
                }
                None => match check(field, &member.value) {
                    Ok(value) => settings.values.push(Setting { field, value }),
                    Err(refused) => {
                        let pointer = match refused.index {
                            Some(index) => pointer.index(index),
                            None => pointer,
                        };
                        checker.report(refused.code, pointer, refused.node);
                    }
                },
            },
            Child::Section(section) => {
                if Unresolved::from_node(&member.value).is_some() {
                    checker.report(Code::Unresolved, pointer, &member.value);
                    continue;
                }
                if let Some(members) =
                    checker.object(&member.value, &pointer, &member_names(section), &[])
                {
                    read_members(checker, members, section, &pointer, settings);
                }
            }
            Child::Own(own) => {
                if let Some(value) = read_own(checker, own, &member.value, &pointer) {
                    settings.own.push(OwnSetting { member: own, value });
                }
            }
        }
    }
}

/// Reads a member of the document's own.
fn read_own(
    checker: &mut Checker<'_>,
    own: &'static OwnMember,
    node: &Node,
    pointer: &Pointer,
) -> Option<SettingValue> {
    let mut refuse = |code| {
        checker.report(code, pointer.clone(), node);
        None
    };
    if own.value == OwnValue::Secret {
        return match SecretReference::from_node(node) {
            Ok(reference) => Some(SettingValue::Secret(reference)),
            Err(code) => refuse(code),
        };
    }
    if Unresolved::from_node(node).is_some() {
        return refuse(Code::Unresolved);
    }
    match own.value {
        OwnValue::Word(words) => match node.as_str() {
            Some(text) => match words.iter().copied().find(|word| *word == text) {
                Some(word) => Some(SettingValue::Word(word)),
                None => refuse(Code::InvalidValue),
            },
            None => refuse(Code::WrongType),
        },
        OwnValue::Text => match node.as_str() {
            Some(text) if is_trimmed(text) => Some(SettingValue::Text(text.to_owned())),
            Some(_) => refuse(Code::InvalidValue),
            None => refuse(Code::WrongType),
        },
        OwnValue::Stores | OwnValue::Compatibility => {
            let words = own.value.set_words().unwrap_or_default();
            word_set(checker, &words, node, pointer).map(SettingValue::Words)
        }
        // Read above, before the placeholder check.
        OwnValue::Secret => None,
    }
}

/// Why a value was refused, and where: `index` is the list entry at fault.
#[derive(Debug)]
pub(crate) struct Refused<'n> {
    pub(crate) code: Code,
    pub(crate) index: Option<usize>,
    pub(crate) node: &'n Node,
}

/// Types one setting's value by its catalog entry.
pub(crate) fn check<'n>(
    field: &'static Field,
    node: &'n Node,
) -> Result<SettingValue, Refused<'n>> {
    let refused = |code| Refused {
        code,
        index: None,
        node,
    };
    if Unresolved::from_node(node).is_some() {
        return Err(refused(Code::Unresolved));
    }
    if field.sensitivity != Sensitivity::Public {
        return SecretReference::from_node(node)
            .map(SettingValue::Secret)
            .map_err(refused);
    }
    match field.field_type {
        FieldType::Boolean => match node.value {
            Value::Bool(value) => Ok(SettingValue::Boolean(value)),
            _ => Err(refused(Code::WrongType)),
        },
        FieldType::Integer(range) => match node.value {
            Value::Integer(value) => u64::try_from(value)
                .ok()
                .filter(|value| (range.minimum..=range.maximum).contains(value))
                .map(SettingValue::Integer)
                .ok_or_else(|| refused(Code::InvalidValue)),
            _ => Err(refused(Code::WrongType)),
        },
        FieldType::Decimal(range) => {
            let decimal = Decimal::from_node(node).map_err(refused)?;
            if within(range, decimal.as_f64()) {
                Ok(SettingValue::Decimal(decimal))
            } else {
                Err(refused(Code::InvalidValue))
            }
        }
        FieldType::Choice(words) => {
            let text = node.as_str().ok_or_else(|| refused(Code::WrongType))?;
            words
                .iter()
                .copied()
                .find(|word| *word == text)
                .map(SettingValue::Word)
                .ok_or_else(|| refused(Code::InvalidValue))
        }
        FieldType::SocketAddress | FieldType::Url | FieldType::Text => {
            let text = node.as_str().ok_or_else(|| refused(Code::WrongType))?;
            if is_trimmed(text) {
                Ok(SettingValue::Text(text.to_owned()))
            } else {
                Err(refused(Code::InvalidValue))
            }
        }
        FieldType::List => {
            let Value::Array(items) = &node.value else {
                return Err(refused(Code::WrongType));
            };
            let mut entries = Vec::with_capacity(items.len());
            for (index, item) in items.iter().enumerate() {
                let entry = |code| Refused {
                    code,
                    index: Some(index),
                    node: item,
                };
                if Unresolved::from_node(item).is_some() {
                    return Err(entry(Code::Unresolved));
                }
                let text = item.as_str().ok_or_else(|| entry(Code::WrongType))?;
                if !is_list_entry(text) {
                    return Err(entry(Code::InvalidValue));
                }
                entries.push(text.to_owned());
            }
            Ok(SettingValue::List(entries))
        }
        // No host path has a document path in `v1alpha1` (the catalog's
        // tests hold that), and a JSON document is read by `structured`,
        // never here; refusing keeps both so.
        FieldType::Path | FieldType::PathList | FieldType::Json => Err(refused(Code::WrongType)),
    }
}

/// Whether `value` lies within a decimal range, compared as the compiler
/// compares the environment's `f64`.
fn within(range: DecimalRange, value: f64) -> bool {
    let above = |bound: DecimalBound| {
        bound.value.parse::<f64>().is_ok_and(|bound_value| {
            value > bound_value || (bound.inclusive && value == bound_value)
        })
    };
    let below = |bound: DecimalBound| {
        bound.value.parse::<f64>().is_ok_and(|bound_value| {
            value < bound_value || (bound.inclusive && value == bound_value)
        })
    };
    above(range.minimum) && range.maximum.is_none_or(below)
}

/// Non-empty, with no whitespace at either end.
pub(crate) fn is_trimmed(text: &str) -> bool {
    !text.is_empty()
        && !text.starts_with(char::is_whitespace)
        && !text.ends_with(char::is_whitespace)
}

/// One entry of a comma-separated environment list.
fn is_list_entry(text: &str) -> bool {
    is_trimmed(text) && !text.contains(',')
}

/// The largest integer a document can hold for `maximum`.
pub(crate) fn document_maximum(maximum: u64) -> u64 {
    maximum.min(MAX_SAFE_INTEGER.unsigned_abs())
}

/// A set of distinct `words`, returned in the order `words` lists them: the
/// store list and the acknowledged behaviors.
fn word_set(
    checker: &mut Checker<'_>,
    words: &[&'static str],
    node: &Node,
    pointer: &Pointer,
) -> Option<Vec<&'static str>> {
    let Value::Array(items) = &node.value else {
        checker.report(Code::WrongType, pointer.clone(), node);
        return None;
    };
    let mut named: Vec<&'static str> = Vec::new();
    let mut valid = true;
    for (index, item) in items.iter().enumerate() {
        let pointer = pointer.index(index);
        if Unresolved::from_node(item).is_some() {
            checker.report(Code::Unresolved, pointer, item);
            valid = false;
            continue;
        }
        let Some(text) = item.as_str() else {
            checker.report(Code::WrongType, pointer, item);
            valid = false;
            continue;
        };
        match words.iter().copied().find(|word| *word == text) {
            Some(word) if !named.contains(&word) => named.push(word),
            // An unknown word, or one named twice.
            _ => {
                checker.report(Code::InvalidValue, pointer, item);
                valid = false;
            }
        }
    }
    valid.then(|| {
        words
            .iter()
            .copied()
            .filter(|word| named.contains(word))
            .collect()
    })
}

/// Whether the document accepts the JSON text `value` for `field`.
#[cfg(test)]
pub(crate) fn accepts(field: &'static Field, value: &str) -> bool {
    super::json::parse(value, super::syntax::DOCUMENT_LIMITS)
        .is_ok_and(|node| check(field, &node).is_ok())
}

/// The canonical spelling of a decimal the document accepts for `field`.
#[cfg(test)]
pub(crate) fn canonical_decimal(field: &'static Field, text: &str) -> Option<String> {
    let node = Node::new(Value::String(text.to_owned()), Default::default());
    match check(field, &node) {
        Ok(SettingValue::Decimal(decimal)) => Some(decimal.canonical().to_owned()),
        _ => None,
    }
}
