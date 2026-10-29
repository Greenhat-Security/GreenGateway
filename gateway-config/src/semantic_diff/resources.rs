//! The bundle-level settings and the referenced policy and tools documents.
//!
//! A bundle pins its policy and tools documents and the bundle reader runs
//! their production validators, so the documents compared here are already
//! valid. They are compared member by member as the policy loader reads
//! them. A modelled member the document omits takes the default the
//! published schema and the loader give it, so spelling a default out is
//! not a change. Ordered lists stay ordered, because first match wins, and
//! their entries (routes, rules, rate-limit overrides, tool definitions) are
//! compared as given: a caller passes both sides in one form, and the
//! gateway passes its validators' normalized form. Sets are compared as
//! sets.
//!
//! Every top-level member is compared, either by its own detector or, for
//! one this module does not model, as an opaque value whose change is
//! `unknown`. Entry names (roles, tools) never reach a report: a collection
//! is reported as counts.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

use super::{
    unmatched, ChangeClass, ChangeKind, Comparison, Display, EntryCounts, Field, Impact, Redaction,
    RiskCode, Rule, Section, SemanticDiff, SetCounts,
};
use crate::bundle::{Bundle, BundledResource, POLICY_TOP_LEVEL_MEMBERS};

/// Where a bundle's policy or tools document comes from.
#[derive(Clone, Copy, Debug)]
pub enum ResourceView<'a> {
    /// The manifest does not declare the resource.
    Undeclared,
    /// The existing store is the resource's writer.
    Server,
    /// The bundle supplies it.
    Bundle {
        /// The manifest's pin over the file's exact bytes.
        sha256: &'a str,
        /// The validated document, or `None` when the caller has no form of
        /// it to compare; a changed pin is then `unknown`.
        document: Option<&'a Value>,
    },
}

impl ResourceView<'_> {
    fn source(&self) -> &'static str {
        match self {
            Self::Undeclared => "undeclared",
            Self::Server => "server",
            Self::Bundle { .. } => "bundle",
        }
    }
}

/// What a diff compares of one compiled bundle.
#[derive(Clone, Copy, Debug)]
pub struct BundleView<'a> {
    pub api_version: &'static str,
    /// `metadata.name`.
    pub name: &'a str,
    pub profile: &'static str,
    /// The manifest's pin over the deployment document's exact bytes.
    pub deployment_sha256: &'a str,
    /// The deployment document's canonical JSON bytes.
    pub deployment_canonical_json: &'a [u8],
    pub policy: ResourceView<'a>,
    pub tools: ResourceView<'a>,
    /// `spec.resources.connections.source: server` is declared.
    pub connections_from_server: bool,
}

impl<'a> BundleView<'a> {
    /// What a diff compares of a bundle the reader accepted. `policy` and
    /// `tools` are its documents in the JSON form to compare: the document
    /// the reader validated, or the caller's validators' normalized form.
    pub fn of<P, T>(
        bundle: &'a Bundle<P, T>,
        policy: Option<&'a Value>,
        tools: Option<&'a Value>,
    ) -> Self {
        Self {
            api_version: bundle.api_version.as_str(),
            name: &bundle.name,
            profile: bundle.deployment.profile.as_str(),
            deployment_sha256: &bundle.deployment.sha256,
            deployment_canonical_json: &bundle.deployment.canonical_json,
            policy: ResourceView::of(bundle.policy.as_ref(), policy),
            tools: ResourceView::of(bundle.tools.as_ref(), tools),
            connections_from_server: bundle.connections_from_server,
        }
    }
}

impl<'a> ResourceView<'a> {
    fn of<T>(resource: Option<&'a BundledResource<T>>, document: Option<&'a Value>) -> Self {
        match resource {
            None => Self::Undeclared,
            Some(BundledResource::Server) => Self::Server,
            Some(BundledResource::Bundle { sha256, .. }) => Self::Bundle {
                sha256: sha256.as_str(),
                document,
            },
        }
    }
}

/// Compares two bundles read with `PublishedSchemasOnly`, whose policy and
/// tools documents are the JSON values the reader checked.
pub fn compare_read_bundles(
    base: &Bundle<Value, Value>,
    candidate: &Bundle<Value, Value>,
) -> SemanticDiff {
    let mut comparison = Comparison::new();
    compare_bundles(
        &mut comparison,
        &BundleView::of(base, document(&base.policy), document(&base.tools)),
        &BundleView::of(
            candidate,
            document(&candidate.policy),
            document(&candidate.tools),
        ),
    );
    comparison.finish()
}

fn document(resource: &Option<BundledResource<Value>>) -> Option<&Value> {
    match resource {
        Some(BundledResource::Bundle { document, .. }) => Some(document),
        _ => None,
    }
}

/// The profiles from the most guarantees to the fewest.
const PROFILES: &[&str] = &["production", "migration", "development"];

const fn field(
    id: &'static str,
    section: Section,
    class: ChangeClass,
    risk: RiskCode,
    rule: Rule,
) -> Field {
    Field {
        id,
        section,
        class,
        risk,
        rule,
    }
}

static API_VERSION: Field = field(
    "bundle.api_version",
    Section::Bundle,
    ChangeClass::Restart,
    RiskCode::UnknownImpact,
    Rule::Unclassified,
);
static NAME: Field = field(
    "bundle.name",
    Section::Bundle,
    ChangeClass::Restart,
    RiskCode::UnknownImpact,
    Rule::Neutral,
);
static PROFILE: Field = field(
    "deployment.profile",
    Section::Bundle,
    ChangeClass::Restart,
    RiskCode::ProfileChanged,
    Rule::Ranked(PROFILES),
);
static DEPLOYMENT_PIN: Field = field(
    "deployment.sha256",
    Section::Bundle,
    ChangeClass::Restart,
    RiskCode::UnknownImpact,
    Rule::Neutral,
);
static DEPLOYMENT_DOCUMENT: Field = field(
    "deployment.document",
    Section::Bundle,
    ChangeClass::Restart,
    RiskCode::UnknownImpact,
    Rule::Unclassified,
);
static CONNECTIONS_SOURCE: Field = field(
    "resources.connections.source",
    Section::Connections,
    ChangeClass::ConnectionOrSecret,
    RiskCode::UnknownImpact,
    Rule::Neutral,
);

/// The fields of one bundle resource.
struct ResourceFields {
    source: Field,
    pin: Field,
    document: Field,
}

static POLICY_RESOURCE: ResourceFields = ResourceFields {
    source: field(
        "resources.policy.source",
        Section::Policy,
        ChangeClass::Restart,
        RiskCode::UnknownImpact,
        Rule::Unclassified,
    ),
    pin: field(
        "resources.policy.sha256",
        Section::Policy,
        ChangeClass::Live,
        RiskCode::UnknownImpact,
        Rule::Neutral,
    ),
    document: field(
        "policy.document",
        Section::Policy,
        ChangeClass::Live,
        RiskCode::UnknownImpact,
        Rule::Unclassified,
    ),
};

static TOOLS_RESOURCE: ResourceFields = ResourceFields {
    source: field(
        "resources.tools.source",
        Section::Tools,
        ChangeClass::Restart,
        RiskCode::UnknownImpact,
        Rule::Unclassified,
    ),
    pin: field(
        "resources.tools.sha256",
        Section::Tools,
        ChangeClass::Live,
        RiskCode::UnknownImpact,
        Rule::Neutral,
    ),
    document: field(
        "tools.document",
        Section::Tools,
        ChangeClass::Live,
        RiskCode::UnknownImpact,
        Rule::Unclassified,
    ),
};

/// Compares two compiled bundles: the manifest and deployment settings, and
/// each resource's source, pin and content.
pub fn compare_bundles(
    comparison: &mut Comparison,
    base: &BundleView<'_>,
    candidate: &BundleView<'_>,
) {
    comparison.word(&API_VERSION, base.api_version, candidate.api_version);
    comparison.value(&NAME, Some(base.name), Some(candidate.name));
    comparison.word(&PROFILE, base.profile, candidate.profile);
    comparison.value(
        &DEPLOYMENT_PIN,
        Some(base.deployment_sha256),
        Some(candidate.deployment_sha256),
    );
    // The deployment document holds only the profile in this alpha. A
    // member the field catalog adds later is still compared: until a
    // detector exists for it, its change is `unknown`.
    let rest = |canonical: &[u8]| -> Option<Value> {
        let mut document: Value = serde_json::from_slice(canonical).ok()?;
        document.get_mut("spec")?.as_object_mut()?.remove("profile");
        Some(document)
    };
    let rest_differs = match (
        rest(base.deployment_canonical_json),
        rest(candidate.deployment_canonical_json),
    ) {
        (Some(base), Some(candidate)) => base != candidate,
        _ => base.deployment_canonical_json != candidate.deployment_canonical_json,
    };
    if rest_differs {
        comparison.record(
            &DEPLOYMENT_DOCUMENT,
            ChangeKind::Modified,
            &[Impact::Unknown],
            Display::Withheld,
            None,
        );
    }
    compare_resource(
        comparison,
        &POLICY_RESOURCE,
        &base.policy,
        &candidate.policy,
        compare_policy,
    );
    compare_resource(
        comparison,
        &TOOLS_RESOURCE,
        &base.tools,
        &candidate.tools,
        compare_tools,
    );
    let connections = |view: &BundleView<'_>| {
        if view.connections_from_server {
            "server"
        } else {
            "undeclared"
        }
    };
    comparison.word(
        &CONNECTIONS_SOURCE,
        connections(base),
        connections(candidate),
    );
}

fn compare_resource(
    comparison: &mut Comparison,
    fields: &'static ResourceFields,
    base: &ResourceView<'_>,
    candidate: &ResourceView<'_>,
    compare: fn(&mut Comparison, &Value, &Value),
) {
    // A resource that moves between the bundle and the server changes its
    // writer, and the server's content is not known here.
    comparison.word(&fields.source, base.source(), candidate.source());
    let (
        ResourceView::Bundle {
            sha256: base_pin,
            document: base_document,
        },
        ResourceView::Bundle {
            sha256: candidate_pin,
            document: candidate_document,
        },
    ) = (base, candidate)
    else {
        return;
    };
    comparison.value(&fields.pin, Some(*base_pin), Some(*candidate_pin));
    match (base_document, candidate_document) {
        (Some(base), Some(candidate)) => compare(comparison, base, candidate),
        _ if base_pin != candidate_pin => comparison.record(
            &fields.document,
            ChangeKind::Modified,
            &[Impact::Unknown],
            Display::Withheld,
            None,
        ),
        _ => {}
    }
}

// --- Policy -----------------------------------------------------------------

const DEFAULT_ACTIONS: &[&str] = &["deny", "allow"];
const ENFORCEMENT_MODES: &[&str] = &["enforce", "shadow"];
/// The policy loader's tool entry defaults (`DEFAULT_TOOL_POLICY_TIMEOUT_MS`
/// and `DEFAULT_TOOL_POLICY_MAX_CONCURRENT` in `gateway/src/rbac/policy.rs`,
/// which a gateway test holds equal to these).
pub const DEFAULT_TOOL_TIMEOUT_MS: u64 = 30_000;
pub const DEFAULT_TOOL_MAX_CONCURRENT: u64 = 8;

const fn policy_field(id: &'static str, risk: RiskCode, rule: Rule) -> Field {
    field(id, Section::Policy, ChangeClass::Live, risk, rule)
}

static POLICY_SCHEMA_VERSION: Field = policy_field(
    "policy.schema_version",
    RiskCode::UnknownImpact,
    Rule::Unclassified,
);
static POLICY_ID: Field = policy_field("policy.id", RiskCode::UnknownImpact, Rule::Neutral);
static DEFAULT_ACTION: Field = policy_field(
    "policy.default_action",
    RiskCode::PolicyDefaultAllow,
    Rule::Ranked(DEFAULT_ACTIONS),
);
static ENFORCEMENT_MODE: Field = policy_field(
    "policy.enforcement_mode",
    RiskCode::ShadowEnabled,
    Rule::Ranked(ENFORCEMENT_MODES),
);
static ROLES: Field = policy_field(
    "policy.roles",
    RiskCode::PolicyBroadened,
    Rule::GrowthIsLooser,
);
static ROUTES: Field = policy_field("policy.routes", RiskCode::UnknownImpact, Rule::Unclassified);
static ROUTE_SHADOW_OVERRIDES: Field = policy_field(
    "policy.routes.shadow_overrides",
    RiskCode::ShadowEnabled,
    Rule::HigherIsLooser,
);
static RULES: Field = policy_field("policy.rules", RiskCode::UnknownImpact, Rule::Unclassified);
static EGRESS_HOSTS: Field = field(
    "policy.egress.hosts",
    Section::Egress,
    ChangeClass::Restart,
    RiskCode::EgressBroadened,
    Rule::GrowthIsLooser,
);
static EGRESS_CIDRS: Field = field(
    "policy.egress.cidrs",
    Section::Egress,
    ChangeClass::Restart,
    RiskCode::PrivateEgressAllowed,
    Rule::GrowthIsLooser,
);
static EGRESS_PORTS: Field = field(
    "policy.egress.ports",
    Section::Egress,
    ChangeClass::Restart,
    RiskCode::EgressBroadened,
    Rule::Restriction,
);
static EGRESS_OTHER: Field = field(
    "policy.egress.document",
    Section::Egress,
    ChangeClass::Restart,
    RiskCode::UnknownImpact,
    Rule::Unclassified,
);
static RATE_LIMITS: Field = policy_field(
    "policy.rate_limits",
    RiskCode::LimitsLoosened,
    Rule::HigherIsLooser,
);
static TOOL_POLICIES: Field = policy_field(
    "policy.tools",
    RiskCode::PolicyBroadened,
    Rule::GrowthIsLooser,
);
static POLICY_OTHER: Field = policy_field(
    "policy.unmodelled_members",
    RiskCode::UnknownImpact,
    Rule::Unclassified,
);

/// Compares two validated policy documents. A document that is not a JSON
/// object compares as one opaque value.
pub fn compare_policy(comparison: &mut Comparison, base: &Value, candidate: &Value) {
    let (Some(base), Some(candidate)) = (base.as_object(), candidate.as_object()) else {
        opaque(comparison, &POLICY_RESOURCE.document, base, candidate);
        return;
    };
    let member = |document: &Map<String, Value>, name: &str| document.get(name).cloned();

    comparison.value(
        &POLICY_SCHEMA_VERSION,
        base.get("schema_version"),
        candidate.get("schema_version"),
    );
    comparison.value(&POLICY_ID, base.get("id"), candidate.get("id"));
    word_member(
        comparison,
        &DEFAULT_ACTION,
        base.get("default_action"),
        candidate.get("default_action"),
        "deny",
    );
    word_member(
        comparison,
        &ENFORCEMENT_MODE,
        base.get("enforcement_mode"),
        candidate.get("enforcement_mode"),
        "enforce",
    );

    let roles = |document: &Map<String, Value>| entries(document.get("roles"), normalized_role);
    comparison.entries(
        &ROLES,
        Redaction::Withheld,
        &roles(base),
        &roles(candidate),
        role_impacts,
    );

    let routes = |document: &Map<String, Value>| list(document.get("routes"));
    let (base_routes, candidate_routes) = (routes(base), routes(candidate));
    comparison.sequence(&ROUTES, &base_routes, &candidate_routes);
    let shadow_overrides = |routes: &[Value]| {
        routes
            .iter()
            .filter(|route| route.get("enforcement_mode").and_then(Value::as_str) == Some("shadow"))
            .count() as u64
    };
    comparison.count(
        &ROUTE_SHADOW_OVERRIDES,
        Some(shadow_overrides(&base_routes)),
        Some(shadow_overrides(&candidate_routes)),
    );
    comparison.sequence(
        &RULES,
        &list(base.get("rules")),
        &list(candidate.get("rules")),
    );

    compare_egress(
        comparison,
        member(base, "egress"),
        member(candidate, "egress"),
    );
    compare_rate_limits(
        comparison,
        &list(base.get("rate_limits")),
        &list(candidate.get("rate_limits")),
    );

    let tools =
        |document: &Map<String, Value>| entries(document.get("tools"), normalized_tool_policy);
    comparison.entries(
        &TOOL_POLICIES,
        Redaction::Withheld,
        &tools(base),
        &tools(candidate),
        tool_policy_impacts,
    );

    let other = |document: &Map<String, Value>| -> BTreeMap<String, Value> {
        document
            .iter()
            .filter(|(name, _)| !POLICY_TOP_LEVEL_MEMBERS.contains(&name.as_str()))
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect()
    };
    comparison.entries(
        &POLICY_OTHER,
        Redaction::Withheld,
        &other(base),
        &other(candidate),
        |_, _| vec![Impact::Unknown],
    );
}

/// A member whose value is one of `rule`'s words, `default` when absent. A
/// value outside the vocabulary is compared opaquely, as `unknown`.
fn word_member(
    comparison: &mut Comparison,
    field: &'static Field,
    base: Option<&Value>,
    candidate: Option<&Value>,
    default: &'static str,
) {
    // A field without a vocabulary compares every value opaquely.
    let vocabulary: &[&'static str] = match field.rule {
        Rule::Ranked(vocabulary) => vocabulary,
        _ => &[],
    };
    let word = |value: Option<&Value>| -> Option<&'static str> {
        match value {
            None => Some(default),
            Some(value) => {
                let text = value.as_str()?;
                vocabulary.iter().copied().find(|word| *word == text)
            }
        }
    };
    match (word(base), word(candidate)) {
        (Some(base), Some(candidate)) => comparison.word(field, base, candidate),
        _ => {
            let effective =
                |value: Option<&Value>| value.cloned().unwrap_or_else(|| Value::from(default));
            opaque(comparison, field, &effective(base), &effective(candidate));
        }
    }
}

fn opaque(comparison: &mut Comparison, field: &'static Field, base: &Value, candidate: &Value) {
    if base != candidate {
        comparison.record(
            field,
            ChangeKind::Modified,
            &[Impact::Unknown],
            Display::Withheld,
            None,
        );
    }
}

/// An object member as entries by name, each in its normalized form;
/// absent or not an object is empty (the validator refuses the latter).
/// Entries that mean the same compare equal, so only an entry that means
/// something else reaches its assessor.
fn entries(value: Option<&Value>, normalize: fn(&Value) -> Value) -> BTreeMap<String, Value> {
    value
        .and_then(Value::as_object)
        .map(|members| {
            members
                .iter()
                .map(|(name, value)| (name.clone(), normalize(value)))
                .collect()
        })
        .unwrap_or_default()
}

/// A role as the loader reads it: its permission, issuer and auth method
/// lists as sorted sets, an absent one empty. A member that is not a list of
/// strings is left as given, and its assessor reports it as `unknown`.
fn normalized_role(role: &Value) -> Value {
    normalized(role, &["permissions", "issuers", "auth_methods"], &[])
}

/// A tool policy entry as the loader reads it: its role, issuer and auth
/// method lists as sorted sets, and its defaults filled in. The runtime
/// treats a concurrency of 0 as 1.
fn normalized_tool_policy(entry: &Value) -> Value {
    let mut entry = normalized(
        entry,
        &["allowed_roles", "issuers", "auth_methods"],
        &[
            ("timeout_ms", DEFAULT_TOOL_TIMEOUT_MS, 0),
            ("max_concurrent", DEFAULT_TOOL_MAX_CONCURRENT, 1),
        ],
    );
    if let Some(members) = entry.as_object_mut() {
        members
            .entry("enabled".to_owned())
            .or_insert(Value::Bool(true));
    }
    entry
}

/// `entry` with each of `sets` as a sorted set of strings and each of
/// `numbers` as its default when absent, raised to its floor.
fn normalized(entry: &Value, sets: &[&str], numbers: &[(&str, u64, u64)]) -> Value {
    let Some(members) = entry.as_object() else {
        return entry.clone();
    };
    let mut members = members.clone();
    for name in sets {
        if let Some(set) = string_set(members.get(*name), false) {
            members.insert((*name).to_owned(), Value::from(Vec::from_iter(set)));
        }
    }
    for (name, default, floor) in numbers {
        if let Some(number) = whole_number(members.get(*name), *default) {
            members.insert((*name).to_owned(), Value::from(number.max(*floor)));
        }
    }
    Value::Object(members)
}

/// An array member; absent is empty, and anything else is one opaque entry
/// so that a change to it still registers.
fn list(value: Option<&Value>) -> Vec<Value> {
    match value {
        None => Vec::new(),
        Some(Value::Array(items)) => items.clone(),
        Some(other) => vec![other.clone()],
    }
}

/// An array of strings as a set, `None` when the member is not one.
fn string_set(value: Option<&Value>, lowercase: bool) -> Option<BTreeSet<String>> {
    match value {
        None => Some(BTreeSet::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| {
                item.as_str().map(|text| {
                    if lowercase {
                        text.to_ascii_lowercase()
                    } else {
                        text.to_owned()
                    }
                })
            })
            .collect(),
        Some(_) => None,
    }
}

/// A non-negative integer member, `default` when absent, `None` when it is
/// not one.
fn whole_number(value: Option<&Value>, default: u64) -> Option<u64> {
    match value {
        None => Some(default),
        Some(value) => value.as_u64(),
    }
}

/// The impacts of one role entry that differs. A role grants its
/// permissions to every principal carrying it, limited by `issuers` and
/// `auth_methods` when they are not empty.
fn role_impacts(base: Option<&Value>, candidate: Option<&Value>) -> Vec<Impact> {
    const MEMBERS: &[&str] = &["permissions", "issuers", "auth_methods", "description"];
    let broadened = Impact::Loosened(RiskCode::PolicyBroadened);
    match (base, candidate) {
        (Some(_), None) => vec![Impact::Tightened],
        (None, Some(added)) => match string_set(added.get("permissions"), false) {
            Some(permissions) if permissions.is_empty() => vec![Impact::Neutral],
            Some(_) => vec![broadened],
            None => vec![Impact::Unknown],
        },
        (Some(base), Some(candidate)) => {
            let mut impacts = Vec::new();
            for (name, rule) in [
                ("permissions", Rule::GrowthIsLooser),
                ("issuers", Rule::Restriction),
                ("auth_methods", Rule::Restriction),
            ] {
                match (
                    string_set(base.get(name), false),
                    string_set(candidate.get(name), false),
                ) {
                    (Some(before), Some(after)) if before != after => impacts
                        .push(rule.set(RiskCode::PolicyBroadened, SetCounts::of(&before, &after))),
                    (Some(_), Some(_)) => {}
                    _ => impacts.push(Impact::Unknown),
                }
            }
            if base.get("description") != candidate.get("description") {
                impacts.push(Impact::Neutral);
            }
            impacts.extend(unmodelled_members(base, candidate, MEMBERS));
            impacts
        }
        (None, None) => Vec::new(),
    }
}

/// The impacts of one tool policy entry that differs. A tool with no entry
/// is refused, so adding an enabled entry grants and removing one revokes.
fn tool_policy_impacts(base: Option<&Value>, candidate: Option<&Value>) -> Vec<Impact> {
    const MEMBERS: &[&str] = &[
        "enabled",
        "allowed_roles",
        "issuers",
        "auth_methods",
        "timeout_ms",
        "max_concurrent",
    ];
    let enabled = |entry: &Value| match entry.get("enabled") {
        None => Some(true),
        Some(value) => value.as_bool(),
    };
    match (base, candidate) {
        (Some(_), None) => vec![Impact::Tightened],
        (None, Some(added)) => match enabled(added) {
            Some(true) => vec![Impact::Loosened(RiskCode::PolicyBroadened)],
            Some(false) => vec![Impact::Neutral],
            None => vec![Impact::Unknown],
        },
        (Some(base), Some(candidate)) => {
            let mut impacts = Vec::new();
            match (enabled(base), enabled(candidate)) {
                (Some(before), Some(after)) if before != after => {
                    impacts.push(Rule::LooserWhen(true).flag(RiskCode::PolicyBroadened, after));
                }
                (Some(_), Some(_)) => {}
                _ => impacts.push(Impact::Unknown),
            }
            for name in ["allowed_roles", "issuers", "auth_methods"] {
                match (
                    string_set(base.get(name), false),
                    string_set(candidate.get(name), false),
                ) {
                    (Some(before), Some(after)) if before != after => impacts.push(
                        Rule::Restriction
                            .set(RiskCode::PolicyBroadened, SetCounts::of(&before, &after)),
                    ),
                    (Some(_), Some(_)) => {}
                    _ => impacts.push(Impact::Unknown),
                }
            }
            // The runtime treats a concurrency of 0 as 1.
            for (name, default, floor) in [
                ("timeout_ms", DEFAULT_TOOL_TIMEOUT_MS, 0),
                ("max_concurrent", DEFAULT_TOOL_MAX_CONCURRENT, 1),
            ] {
                match (
                    whole_number(base.get(name), default),
                    whole_number(candidate.get(name), default),
                ) {
                    (Some(before), Some(after)) => {
                        let (before, after) = (before.max(floor), after.max(floor));
                        if before != after {
                            impacts.push(
                                Rule::HigherIsLooser
                                    .order(RiskCode::LimitsLoosened, after.cmp(&before)),
                            );
                        }
                    }
                    _ => impacts.push(Impact::Unknown),
                }
            }
            impacts.extend(unmodelled_members(base, candidate, MEMBERS));
            impacts
        }
        (None, None) => Vec::new(),
    }
}

/// `unknown` when an entry's members outside `modelled` differ.
fn unmodelled_members(base: &Value, candidate: &Value, modelled: &[&str]) -> Option<Impact> {
    let other = |entry: &Value| -> Option<BTreeMap<String, Value>> {
        entry.as_object().map(|members| {
            members
                .iter()
                .filter(|(name, _)| !modelled.contains(&name.as_str()))
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect()
        })
    };
    match (other(base), other(candidate)) {
        (Some(before), Some(after)) if before == after => None,
        _ => Some(Impact::Unknown),
    }
}

/// Rate-limit overrides are ordered, first match wins, and each replaces the
/// global lane's rate for the requests it matches, so an override that is
/// added, removed or moved can raise a limit as easily as lower one. Only the
/// same overrides in the same order, with their rates changed, can be
/// ordered: a raised rate or burst loosens, a lowered one tightens.
fn compare_rate_limits(comparison: &mut Comparison, base: &[Value], candidate: &[Value]) {
    if base == candidate {
        return;
    }
    if base.len() != candidate.len() {
        comparison.record(
            &RATE_LIMITS,
            ChangeKind::Modified,
            &[Impact::Unknown],
            Display::Withheld,
            Some(EntryCounts {
                added: unmatched(candidate, base),
                removed: unmatched(base, candidate),
                changed: 0,
            }),
        );
        return;
    }
    let mut impacts = Vec::new();
    let mut changed = 0;
    for (before, after) in base.iter().zip(candidate) {
        let entry = rate_limit_impacts(before, after);
        if !entry.is_empty() {
            changed += 1;
        }
        impacts.extend(entry);
    }
    // Overrides that differ only in how a number is spelled are the same.
    if changed > 0 {
        comparison.record(
            &RATE_LIMITS,
            ChangeKind::Modified,
            &impacts,
            Display::Withheld,
            Some(EntryCounts {
                added: 0,
                removed: 0,
                changed,
            }),
        );
    }
}

/// The impacts of one override against the one in its place.
fn rate_limit_impacts(base: &Value, candidate: &Value) -> Vec<Impact> {
    const RATES: &[&str] = &["requests_per_second", "burst"];
    if base == candidate {
        return Vec::new();
    }
    if let Some(impact) = unmodelled_members(base, candidate, RATES) {
        return vec![impact];
    }
    let rate = |entry: &Value| entry.get("requests_per_second").and_then(Value::as_f64);
    let burst = |entry: &Value| entry.get("burst").and_then(Value::as_u64);
    let mut impacts = Vec::new();
    match (rate(base), rate(candidate)) {
        (Some(before), Some(after)) if before != after => impacts
            .push(Rule::HigherIsLooser.order(RiskCode::LimitsLoosened, after.total_cmp(&before))),
        (Some(_), Some(_)) => {}
        _ => impacts.push(Impact::Unknown),
    }
    match (burst(base), burst(candidate)) {
        (Some(before), Some(after)) if before != after => {
            impacts.push(Rule::HigherIsLooser.order(RiskCode::LimitsLoosened, after.cmp(&before)))
        }
        (Some(_), Some(_)) => {}
        _ => impacts.push(Impact::Unknown),
    }
    impacts
}

fn compare_egress(comparison: &mut Comparison, base: Option<Value>, candidate: Option<Value>) {
    const MEMBERS: &[&str] = &["hosts", "cidrs", "ports"];
    let empty = || Value::Object(Map::new());
    let (base, candidate) = (base.unwrap_or_else(empty), candidate.unwrap_or_else(empty));
    let (Some(before), Some(after)) = (base.as_object(), candidate.as_object()) else {
        opaque(comparison, &EGRESS_OTHER, &base, &candidate);
        return;
    };
    // Host patterns match case-insensitively.
    for (field, name, lowercase) in [
        (&EGRESS_HOSTS, "hosts", true),
        (&EGRESS_CIDRS, "cidrs", true),
    ] {
        match (
            string_set(before.get(name), lowercase),
            string_set(after.get(name), lowercase),
        ) {
            (Some(before), Some(after)) => comparison.set(field, before, after),
            _ => opaque_member(comparison, field, before.get(name), after.get(name)),
        }
    }
    let ports = |value: Option<&Value>| -> Option<BTreeSet<u64>> {
        match value {
            None => Some(BTreeSet::new()),
            Some(Value::Array(items)) => items.iter().map(Value::as_u64).collect(),
            Some(_) => None,
        }
    };
    match (ports(before.get("ports")), ports(after.get("ports"))) {
        (Some(before), Some(after)) => comparison.set(&EGRESS_PORTS, before, after),
        _ => opaque_member(
            comparison,
            &EGRESS_PORTS,
            before.get("ports"),
            after.get("ports"),
        ),
    }
    if let Some(impact) = unmodelled_members(&base, &candidate, MEMBERS) {
        comparison.record(
            &EGRESS_OTHER,
            ChangeKind::Modified,
            &[impact],
            Display::Withheld,
            None,
        );
    }
}

fn opaque_member(
    comparison: &mut Comparison,
    field: &'static Field,
    base: Option<&Value>,
    candidate: Option<&Value>,
) {
    if base != candidate {
        comparison.record(
            field,
            ChangeKind::Modified,
            &[Impact::Unknown],
            Display::Withheld,
            None,
        );
    }
}

// --- Tools ------------------------------------------------------------------

static TOOLS_SCHEMA_VERSION: Field = field(
    "tools.schema_version",
    Section::Tools,
    ChangeClass::Live,
    RiskCode::UnknownImpact,
    Rule::Unclassified,
);
static TOOL_DEFINITIONS: Field = field(
    "tools.definitions",
    Section::Tools,
    ChangeClass::Live,
    RiskCode::ToolSurfaceBroadened,
    Rule::GrowthIsLooser,
);
static TOOLS_OTHER: Field = field(
    "tools.unmodelled_members",
    Section::Tools,
    ChangeClass::Live,
    RiskCode::UnknownImpact,
    Rule::Unclassified,
);

/// Compares two validated tools documents: definitions by tool name. A new
/// tool is a broader surface, a removed one a narrower one, and a changed
/// definition (its upstream mapping, schema or source) is `unknown`.
pub fn compare_tools(comparison: &mut Comparison, base: &Value, candidate: &Value) {
    let (Some(base), Some(candidate)) = (base.as_object(), candidate.as_object()) else {
        opaque(comparison, &TOOLS_RESOURCE.document, base, candidate);
        return;
    };
    comparison.value(
        &TOOLS_SCHEMA_VERSION,
        base.get("schema_version"),
        candidate.get("schema_version"),
    );
    match (
        definitions(base.get("tools")),
        definitions(candidate.get("tools")),
    ) {
        (Some(before), Some(after)) => comparison.entries(
            &TOOL_DEFINITIONS,
            Redaction::Withheld,
            &before,
            &after,
            |before, after| match (before, after) {
                (None, Some(_)) => vec![Impact::Loosened(RiskCode::ToolSurfaceBroadened)],
                (Some(_), None) => vec![Impact::Tightened],
                _ => vec![Impact::Unknown],
            },
        ),
        _ => opaque_member(
            comparison,
            &TOOL_DEFINITIONS,
            base.get("tools"),
            candidate.get("tools"),
        ),
    }
    let other = |document: &Map<String, Value>| -> BTreeMap<String, Value> {
        document
            .iter()
            .filter(|(name, _)| !matches!(name.as_str(), "schema_version" | "tools"))
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect()
    };
    comparison.entries(
        &TOOLS_OTHER,
        Redaction::Withheld,
        &other(base),
        &other(candidate),
        |_, _| vec![Impact::Unknown],
    );
}

/// Tool definitions by name, `None` when a definition has no string name or
/// a name repeats (the validator refuses both).
fn definitions(value: Option<&Value>) -> Option<BTreeMap<String, Value>> {
    let items = match value {
        None => return Some(BTreeMap::new()),
        Some(Value::Array(items)) => items,
        Some(_) => return None,
    };
    let mut definitions = BTreeMap::new();
    for item in items {
        let name = item.get("name").and_then(Value::as_str)?;
        if definitions.insert(name.to_owned(), item.clone()).is_some() {
            return None;
        }
    }
    Some(definitions)
}
