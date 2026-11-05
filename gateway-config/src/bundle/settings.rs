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
//! - no field accepts an unresolved placeholder.
//!
//! Rules relating one setting to another, and each string's own grammar, stay
//! the compiler's. The compiler does not consume a deployment document yet,
//! so in this alpha the reader checks the settings' shape and their own
//! bounds only: a document can still set a combination the compiler would
//! refuse, and nothing starts from it.
//!
//! One member is the document's own rather than a field's:
//! `spec.state.stores`, the standalone stores a deployment keeps beneath its
//! state directory, which in environment mode is which of their
//! `*_SQLITE_PATH` variables are set (ADR-0008, "Bootstrap inputs").

mod render;
#[cfg(test)]
mod tests;

use serde_json::Value as JsonValue;

use crate::catalog::{DecimalBound, DecimalRange, Field, FieldType, Sensitivity, FIELDS};

pub use render::{render_deployment_reference, render_deployment_schema};

use super::{
    diagnostic::{Code, Pointer},
    document::Checker,
    syntax::{Member, Node, Value, MAX_SAFE_INTEGER},
    value::{Decimal, SecretReference, Unresolved},
};

/// Where the published deployment schema is committed, relative to the
/// repository root.
pub const DEPLOYMENT_SCHEMA_DOCUMENT: &str = "docs/schemas/gateway-deployment.v1alpha1.schema.json";

/// The document path of the standalone store list.
pub const STORES_PATH: &str = "/spec/state/stores";

/// A standalone store a deployment document can enable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StandaloneStore {
    /// Its word in `spec.state.stores`.
    pub name: &'static str,
    /// The environment variable that locates it in environment mode.
    pub environment: &'static str,
}

/// The stores `spec.state.stores` can name, in canonical order.
///
/// Policy publication history is not one of them: whether bundle mode keeps
/// a history beside a bundle-owned policy is still undecided (ADR-0008), so
/// `v1alpha1` cannot enable it.
pub const STANDALONE_STORES: &[StandaloneStore] = &[
    StandaloneStore {
        name: "audit",
        environment: "AUDIT_SQLITE_PATH",
    },
    StandaloneStore {
        name: "discovery",
        environment: "DISCOVERY_SQLITE_PATH",
    },
    StandaloneStore {
        name: "principals",
        environment: "PRINCIPAL_SQLITE_PATH",
    },
    StandaloneStore {
        name: "connections",
        environment: "CONNECTIONS_SQLITE_PATH",
    },
    StandaloneStore {
        name: "service_tokens",
        environment: "SERVICE_TOKEN_SQLITE_PATH",
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
        description: "The listeners the gateway binds. Certificate, key, CA and CRL files are host locators and stay in the environment.",
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
        description: "Admin sign-in through an authentication provider.",
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
        description: "Request authentication.",
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
        description: "The single upstream and the timeouts of proxied requests.",
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
}

/// One setting a document gave.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Setting {
    pub(crate) field: &'static Field,
    pub(crate) value: SettingValue,
}

/// The settings of a valid deployment document, in the order it gave them.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct Settings {
    pub(crate) values: Vec<Setting>,
    /// The enabled standalone stores in canonical order, when the document
    /// names them.
    pub(crate) stores: Option<Vec<&'static str>>,
}

impl Settings {
    /// Rewrites the document's JSON value into its canonical form: each
    /// decimal as its shortest exact spelling and the store list in
    /// [`STANDALONE_STORES`] order, so neither changes the canonical bytes
    /// or the digests made from them.
    pub(crate) fn canonicalize(&self, document: &mut JsonValue) {
        for setting in &self.values {
            let SettingValue::Decimal(decimal) = &setting.value else {
                continue;
            };
            let slot = setting
                .field
                .document_path()
                .and_then(|path| document.pointer_mut(path));
            if let Some(slot) = slot {
                *slot = JsonValue::String(decimal.canonical().to_owned());
            }
        }
        if let (Some(stores), Some(slot)) = (&self.stores, document.pointer_mut(STORES_PATH)) {
            *slot = JsonValue::Array(
                stores
                    .iter()
                    .map(|store| JsonValue::String((*store).to_owned()))
                    .collect(),
            );
        }
    }
}

/// What one member of a `spec` object is.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Child {
    Setting(&'static Field),
    /// A section, by its document path.
    Section(&'static str),
    Stores,
}

/// Every document path below `spec`, in catalog order, the store list last.
pub(crate) fn document_paths() -> impl Iterator<Item = (&'static str, Child)> {
    FIELDS
        .iter()
        .filter_map(|field| {
            field
                .document_path()
                .map(|path| (path, Child::Setting(field)))
        })
        .chain(std::iter::once((STORES_PATH, Child::Stores)))
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
            Child::Setting(field) => match check(field, &member.value) {
                Ok(value) => settings.values.push(Setting { field, value }),
                Err(refused) => {
                    let pointer = match refused.index {
                        Some(index) => pointer.index(index),
                        None => pointer,
                    };
                    checker.report(refused.code, pointer, refused.node);
                }
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
            Child::Stores => settings.stores = stores(checker, &member.value, &pointer),
        }
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
        // No host path or JSON document has a document path in `v1alpha1`
        // (the catalog's tests hold that); refusing keeps it so if one did.
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
fn is_trimmed(text: &str) -> bool {
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

/// `spec.state.stores`: distinct store names, returned in canonical order.
fn stores(checker: &mut Checker<'_>, node: &Node, pointer: &Pointer) -> Option<Vec<&'static str>> {
    if Unresolved::from_node(node).is_some() {
        checker.report(Code::Unresolved, pointer.clone(), node);
        return None;
    }
    let Value::Array(items) = &node.value else {
        checker.report(Code::WrongType, pointer.clone(), node);
        return None;
    };
    let mut named: Vec<&'static str> = Vec::new();
    let mut valid = true;
    for (index, item) in items.iter().enumerate() {
        let pointer = pointer.index(index);
        let Some(text) = item.as_str() else {
            checker.report(Code::WrongType, pointer, item);
            valid = false;
            continue;
        };
        match STANDALONE_STORES.iter().find(|store| store.name == text) {
            Some(store) if !named.contains(&store.name) => named.push(store.name),
            // An unknown store, or one named twice.
            _ => {
                checker.report(Code::InvalidValue, pointer, item);
                valid = false;
            }
        }
    }
    valid.then(|| {
        STANDALONE_STORES
            .iter()
            .map(|store| store.name)
            .filter(|name| named.contains(name))
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
