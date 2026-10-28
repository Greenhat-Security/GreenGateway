//! The semantic configuration diff and its risk classification (issue #242,
//! PR 9; ADR-0008, "Change classes" and "Plan, risk acknowledgment, and
//! conditional apply").
//!
//! A reviewer, `ggctl diff` and, later, a server plan all need one answer to
//! "what does this candidate change, and what does it weaken?". This module
//! computes it from configuration a caller has already compiled and
//! validated, never from YAML or environment text, so formatting, member
//! order and the order of an unordered list never register, and every value
//! is compared as the compiler normalized it.
//!
//! The caller describes each setting once, as a static [`Field`]: a stable
//! identifier, a [`Section`], a [`ChangeClass`], the [`Rule`] that says
//! which direction loosens it, and the [`RiskCode`] a loosening carries. A
//! [`Comparison`] is then given the base and candidate value of every field
//! and records one [`Change`] for each field that differs, with an
//! [`Effect`]:
//!
//! - `loosened`: the change weakens a control and carries a risk code;
//! - `tightened` or `neutral`: it carries none;
//! - `unknown`: no detector can tell, so it carries `risk.unknown_impact`.
//!   A change is never left without a code because a detector is missing.
//!
//! The result is redacted by construction. Only closed-vocabulary values can
//! be shown: booleans, words the caller fixes as `&'static str`, and
//! numbers. Every other value (a path, URL, host, CIDR, name or document
//! member) is reported only as changed, with entry counts for a collection,
//! and a secret, secret reference or secret locator only as a changed
//! reference. No old or new value of those, and nothing derived from one,
//! reaches a [`SemanticDiff`]: values are compared for equality in memory
//! and then dropped.
//!
//! Like the rest of this crate it is side-effect free: no file, environment,
//! clock or network access.

use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
};

use serde::{ser::SerializeStruct, Serialize, Serializer};

mod resources;
#[cfg(test)]
mod tests;

pub use resources::{
    compare_bundles, compare_policy, compare_tools, BundleView, ResourceView,
    DEFAULT_TOOL_MAX_CONCURRENT, DEFAULT_TOOL_TIMEOUT_MS, POLICY_TOP_LEVEL_MEMBERS,
};

/// How serious a risk is. `Low < Medium < High`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Severity {
    Low,
    Medium,
    High,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

/// A stable risk code (ADR-0008, "Plan, risk acknowledgment, and conditional
/// apply"). A published code never changes meaning; renaming or removing one
/// requires a new report version.
///
/// Codes sort by their text, so a sorted set of codes is the same set in
/// every language that sorts strings.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum RiskCode {
    AdminAccessPathRemoved,
    AuditDurabilityReduced,
    AuthDisabled,
    AuthObserveOnly,
    AuthTrustChanged,
    CookieOrCsrfWeakened,
    CorsBroadened,
    CredentialBindingChanged,
    DataExposureIncreased,
    EgressBroadened,
    ExemptionsBroadened,
    LimitsLoosened,
    ListenerExposed,
    PlaintextTransport,
    PolicyBroadened,
    PolicyDefaultAllow,
    PrivateEgressAllowed,
    ProfileChanged,
    PublicOriginChanged,
    RoutingChanged,
    ShadowEnabled,
    StorageChanged,
    TlsWeakened,
    ToolSurfaceBroadened,
    TrustedProxiesChanged,
    UnknownImpact,
}

impl RiskCode {
    /// Every code, sorted by its text.
    pub const ALL: &'static [Self] = &[
        Self::AdminAccessPathRemoved,
        Self::AuditDurabilityReduced,
        Self::AuthDisabled,
        Self::AuthObserveOnly,
        Self::AuthTrustChanged,
        Self::CookieOrCsrfWeakened,
        Self::CorsBroadened,
        Self::CredentialBindingChanged,
        Self::DataExposureIncreased,
        Self::EgressBroadened,
        Self::ExemptionsBroadened,
        Self::LimitsLoosened,
        Self::ListenerExposed,
        Self::PlaintextTransport,
        Self::PolicyBroadened,
        Self::PolicyDefaultAllow,
        Self::PrivateEgressAllowed,
        Self::ProfileChanged,
        Self::PublicOriginChanged,
        Self::RoutingChanged,
        Self::ShadowEnabled,
        Self::StorageChanged,
        Self::TlsWeakened,
        Self::ToolSurfaceBroadened,
        Self::TrustedProxiesChanged,
        Self::UnknownImpact,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::AdminAccessPathRemoved => "risk.admin_access_path_removed",
            Self::AuditDurabilityReduced => "risk.audit_durability_reduced",
            Self::AuthDisabled => "risk.auth_disabled",
            Self::AuthObserveOnly => "risk.auth_observe_only",
            Self::AuthTrustChanged => "risk.auth_trust_changed",
            Self::CookieOrCsrfWeakened => "risk.cookie_or_csrf_weakened",
            Self::CorsBroadened => "risk.cors_broadened",
            Self::CredentialBindingChanged => "risk.credential_binding_changed",
            Self::DataExposureIncreased => "risk.data_exposure_increased",
            Self::EgressBroadened => "risk.egress_broadened",
            Self::ExemptionsBroadened => "risk.exemptions_broadened",
            Self::LimitsLoosened => "risk.limits_loosened",
            Self::ListenerExposed => "risk.listener_exposed",
            Self::PlaintextTransport => "risk.plaintext_transport",
            Self::PolicyBroadened => "risk.policy_broadened",
            Self::PolicyDefaultAllow => "risk.policy_default_allow",
            Self::PrivateEgressAllowed => "risk.private_egress_allowed",
            Self::ProfileChanged => "risk.profile_changed",
            Self::PublicOriginChanged => "risk.public_origin_changed",
            Self::RoutingChanged => "risk.routing_changed",
            Self::ShadowEnabled => "risk.shadow_enabled",
            Self::StorageChanged => "risk.storage_changed",
            Self::TlsWeakened => "risk.tls_weakened",
            Self::ToolSurfaceBroadened => "risk.tool_surface_broadened",
            Self::TrustedProxiesChanged => "risk.trusted_proxies_changed",
            Self::UnknownImpact => "risk.unknown_impact",
        }
    }

    /// Authentication, egress and policy weakening, and anything no
    /// detector can classify, are high.
    pub fn severity(self) -> Severity {
        match self {
            Self::AdminAccessPathRemoved
            | Self::AuthDisabled
            | Self::AuthObserveOnly
            | Self::AuthTrustChanged
            | Self::CookieOrCsrfWeakened
            | Self::CredentialBindingChanged
            | Self::EgressBroadened
            | Self::ExemptionsBroadened
            | Self::ListenerExposed
            | Self::PlaintextTransport
            | Self::PolicyBroadened
            | Self::PolicyDefaultAllow
            | Self::PrivateEgressAllowed
            | Self::ProfileChanged
            | Self::ShadowEnabled
            | Self::UnknownImpact => Severity::High,
            Self::AuditDurabilityReduced
            | Self::CorsBroadened
            | Self::DataExposureIncreased
            | Self::PublicOriginChanged
            | Self::RoutingChanged
            | Self::StorageChanged
            | Self::TlsWeakened
            | Self::ToolSurfaceBroadened
            | Self::TrustedProxiesChanged => Severity::Medium,
            Self::LimitsLoosened => Severity::Low,
        }
    }

    /// Fixed text describing what a change carrying the code does.
    pub fn description(self) -> &'static str {
        match self {
            Self::AdminAccessPathRemoved => {
                "an admin authentication path was removed, which can lock administrators out"
            }
            Self::AuditDurabilityReduced => {
                "fewer events are recorded, they are recorded less durably, or they are kept for less time"
            }
            Self::AuthDisabled => "authentication is turned off",
            Self::AuthObserveOnly => "failed authentication is observed instead of refused",
            Self::AuthTrustChanged => {
                "an identity provider, issuer, key source, audience, claim or client-certificate rule was added or changed, or a check on it was relaxed"
            }
            Self::CookieOrCsrfWeakened => {
                "CSRF protection or cookie scope was relaxed, or admin sessions last longer"
            }
            Self::CorsBroadened => "more origins may make cross-origin requests",
            Self::CredentialBindingChanged => {
                "a secret reference, key, secret provider or credential binding was added or changed"
            }
            Self::DataExposureIncreased => {
                "more request data is captured, or more deployment topology is disclosed"
            }
            Self::EgressBroadened => "more outbound destinations or ports are allowed",
            Self::ExemptionsBroadened => {
                "more paths are exempt from authentication, authorization or CSRF checks"
            }
            Self::LimitsLoosened => {
                "a size, rate, time, concurrency or validation bound was raised, removed or relaxed"
            }
            Self::ListenerExposed => {
                "a listener is reachable beyond loopback, or another listener was opened"
            }
            Self::PlaintextTransport => "a connection that used TLS no longer does",
            Self::PolicyBroadened => "a policy role or tool entry grants more or restricts less",
            Self::PolicyDefaultAllow => {
                "requests no policy rule matches are allowed, or no policy is enforced at all"
            }
            Self::PrivateEgressAllowed => {
                "outbound requests may reach private or other non-global addresses"
            }
            Self::ProfileChanged => "the deployment profile moved to one with fewer guarantees",
            Self::PublicOriginChanged => "the public URL the gateway advertises changed",
            Self::RoutingChanged => "requests are routed to a new or different upstream",
            Self::ShadowEnabled => "policy denials are observed instead of enforced",
            Self::StorageChanged => "a state store, its backend or its migration behavior changed",
            Self::TlsWeakened => "the minimum TLS version was lowered",
            Self::ToolSurfaceBroadened => "more tools or tool sources are exposed",
            Self::TrustedProxiesChanged => {
                "more peers are trusted to report the client address, or proxy headers are trusted"
            }
            Self::UnknownImpact => {
                "no detector can classify this change, so it is treated as a weakening"
            }
        }
    }
}

impl Ord for RiskCode {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_str().cmp(other.as_str())
    }
}

impl PartialOrd for RiskCode {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Serialize for RiskCode {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// The part of the configuration a field belongs to. Reports name changed
/// sections; a section name is fixed text.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Section {
    Bundle,
    Listeners,
    Tls,
    Authentication,
    Admin,
    BrowserSecurity,
    ProxyTrust,
    Routing,
    Egress,
    Limits,
    Audit,
    Observability,
    Storage,
    Cluster,
    Connections,
    Lifecycle,
    Policy,
    Tools,
}

impl Section {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bundle => "bundle",
            Self::Listeners => "listeners",
            Self::Tls => "tls",
            Self::Authentication => "authentication",
            Self::Admin => "admin",
            Self::BrowserSecurity => "browser_security",
            Self::ProxyTrust => "proxy_trust",
            Self::Routing => "routing",
            Self::Egress => "egress",
            Self::Limits => "limits",
            Self::Audit => "audit",
            Self::Observability => "observability",
            Self::Storage => "storage",
            Self::Cluster => "cluster",
            Self::Connections => "connections",
            Self::Lifecycle => "lifecycle",
            Self::Policy => "policy",
            Self::Tools => "tools",
        }
    }
}

/// How a change can take effect (ADR-0008, "Change classes"). Every change
/// carries exactly one.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ChangeClass {
    /// Activates in the running process in ledger mode.
    Live,
    /// Durable once staged; active only after a new process proves it
    /// compiled the revision.
    Restart,
    /// A fingerprinted change in cluster mode (ADR-0007's procedure).
    CoordinatedCutover,
    /// Owned by a bootstrap input; a bundle cannot change it.
    Bootstrap,
    /// A #240 Connection or secret operation, never performed by a bundle.
    ConnectionOrSecret,
    /// A #241 migration, import or cluster operation, performed by its
    /// `gateway` command.
    ClusterOperation,
    /// Not possible in this mode.
    Unsupported,
}

impl ChangeClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Restart => "restart",
            Self::CoordinatedCutover => "coordinated_cutover",
            Self::Bootstrap => "bootstrap",
            Self::ConnectionOrSecret => "connection_or_secret",
            Self::ClusterOperation => "cluster_operation",
            Self::Unsupported => "unsupported",
        }
    }
}

/// Which direction of change loosens a field.
#[derive(Clone, Copy, Debug)]
pub enum Rule {
    /// No change has a security effect (a label, a cookie name).
    Neutral,
    /// Every change loosens (a public origin, a credential binding).
    AnyChange,
    /// No detector exists: every change is `unknown`.
    Unclassified,
    /// A flag: changing to this value loosens, away from it tightens.
    LooserWhen(bool),
    /// Words from the strictest to the loosest. A word not listed is
    /// `unknown`.
    Ranked(&'static [&'static str]),
    /// A quantity, where unbounded is the highest: raising it loosens.
    HigherIsLooser,
    /// A quantity, where unbounded is the highest: lowering it loosens.
    LowerIsLooser,
    /// A set of allowed things: any added member loosens; only removals
    /// tighten.
    GrowthIsLooser,
    /// A set that restricts, where empty means unrestricted: emptying it or
    /// adding a member loosens; restricting an empty set or only removing
    /// members tightens.
    Restriction,
    /// An optional value: removing it loosens, adding it tightens, and
    /// replacing it is neutral (an audit sink, a revocation list).
    AbsenceIsLooser,
    /// An optional value: adding or replacing it loosens, removing it
    /// tightens (a tools source).
    PresenceIsLooser,
}

impl Rule {
    /// The impact of a change the rule cannot order: what `Neutral`,
    /// `AnyChange` and `Unclassified` say, and `unknown` for a rule that
    /// does not apply to the value compared.
    fn unordered(self, risk: RiskCode) -> Impact {
        match self {
            Self::Neutral => Impact::Neutral,
            Self::AnyChange => Impact::Loosened(risk),
            _ => Impact::Unknown,
        }
    }

    /// Two different flags.
    pub fn flag(self, risk: RiskCode, candidate: bool) -> Impact {
        match self {
            Self::LooserWhen(looser) if candidate == looser => Impact::Loosened(risk),
            Self::LooserWhen(_) => Impact::Tightened,
            other => other.unordered(risk),
        }
    }

    /// Two different words.
    pub fn word(self, risk: RiskCode, base: &str, candidate: &str) -> Impact {
        match self {
            Self::Ranked(order) => {
                let position = |word: &str| order.iter().position(|listed| *listed == word);
                match (position(base), position(candidate)) {
                    (Some(base), Some(candidate)) if candidate > base => Impact::Loosened(risk),
                    (Some(_), Some(_)) => Impact::Tightened,
                    _ => Impact::Unknown,
                }
            }
            other => other.unordered(risk),
        }
    }

    /// Two different quantities, given how the candidate orders against
    /// the base.
    pub fn order(self, risk: RiskCode, candidate: Ordering) -> Impact {
        match (self, candidate) {
            (_, Ordering::Equal) => Impact::Neutral,
            (Self::HigherIsLooser, Ordering::Greater) | (Self::LowerIsLooser, Ordering::Less) => {
                Impact::Loosened(risk)
            }
            (Self::HigherIsLooser | Self::LowerIsLooser, _) => Impact::Tightened,
            (other, _) => other.unordered(risk),
        }
    }

    /// Two different sets, by what was added and removed.
    pub fn set(self, risk: RiskCode, counts: SetCounts) -> Impact {
        match self {
            Self::GrowthIsLooser if counts.added > 0 => Impact::Loosened(risk),
            Self::GrowthIsLooser => Impact::Tightened,
            Self::Restriction if counts.after == 0 || (counts.before > 0 && counts.added > 0) => {
                Impact::Loosened(risk)
            }
            Self::Restriction => Impact::Tightened,
            other => other.unordered(risk),
        }
    }

    /// An optional value that was added, removed or replaced.
    pub fn presence(self, risk: RiskCode, kind: ChangeKind) -> Impact {
        match (self, kind) {
            (Self::AbsenceIsLooser, ChangeKind::Removed) => Impact::Loosened(risk),
            (Self::AbsenceIsLooser, ChangeKind::Added) => Impact::Tightened,
            (Self::AbsenceIsLooser, ChangeKind::Modified) => Impact::Neutral,
            (Self::PresenceIsLooser, ChangeKind::Removed) => Impact::Tightened,
            (Self::PresenceIsLooser, _) => Impact::Loosened(risk),
            (other, _) => other.unordered(risk),
        }
    }

    /// Two different ordered lists. Where order is meaning no rule can
    /// order two lists, so only `Neutral` and `AnyChange` say more than
    /// `unknown`.
    pub fn sequence(self, risk: RiskCode) -> Impact {
        self.unordered(risk)
    }
}

/// The sizes a set comparison is judged by.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SetCounts {
    pub before: usize,
    pub after: usize,
    pub added: usize,
    pub removed: usize,
}

impl SetCounts {
    pub fn of<T: Ord>(base: &BTreeSet<T>, candidate: &BTreeSet<T>) -> Self {
        Self {
            before: base.len(),
            after: candidate.len(),
            added: candidate.difference(base).count(),
            removed: base.difference(candidate).count(),
        }
    }
}

/// One setting a diff can report.
#[derive(Debug)]
pub struct Field {
    /// The stable identifier: the environment setting name for a deployment
    /// setting, or a dotted document path for a bundle or resource member.
    pub id: &'static str,
    pub section: Section,
    pub class: ChangeClass,
    /// The code a loosening change carries, unless the comparison names a
    /// more specific one.
    pub risk: RiskCode,
    pub rule: Rule,
}

/// What one facet of a change does to security.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Impact {
    Neutral,
    Tightened,
    Loosened(RiskCode),
    Unknown,
}

/// What a change does, over all its facets: `loosened` when any loosens,
/// otherwise `unknown` when any is unknown, otherwise `tightened` when any
/// tightens, otherwise `neutral`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Effect {
    Neutral,
    Tightened,
    Unknown,
    Loosened,
}

impl Effect {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Neutral => "neutral",
            Self::Tightened => "tightened",
            Self::Unknown => "unknown",
            Self::Loosened => "loosened",
        }
    }
}

/// Whether a field gained, lost or changed its value.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ChangeKind {
    Added,
    Removed,
    Modified,
}

impl ChangeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Added => "added",
            Self::Removed => "removed",
            Self::Modified => "modified",
        }
    }

    /// The kind of change between two optional values that differ.
    pub fn of<T>(base: Option<T>, candidate: Option<T>) -> Self {
        match (base, candidate) {
            (None, Some(_)) => Self::Added,
            (Some(_), None) => Self::Removed,
            _ => Self::Modified,
        }
    }
}

/// A value a report may show: closed-vocabulary by type.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Shown {
    Flag(bool),
    /// A word the caller fixed in its source.
    Word(&'static str),
    Count(u64),
    Rate(f64),
    /// A quantity with no bound.
    Unbounded,
}

/// What a report shows of a change's values.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Display {
    /// Both values, which are closed-vocabulary.
    Shown { before: Shown, after: Shown },
    /// That the value changed, never what it was or became.
    Withheld,
    /// A secret, secret reference or secret locator changed; never which.
    Reference,
}

/// How a collection's entries are redacted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Redaction {
    Withheld,
    Reference,
}

impl Redaction {
    fn display(self) -> Display {
        match self {
            Self::Withheld => Display::Withheld,
            Self::Reference => Display::Reference,
        }
    }
}

/// How many entries of a collection were added, removed or changed.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EntryCounts {
    pub added: usize,
    pub removed: usize,
    pub changed: usize,
}

/// One field that differs.
#[derive(Clone, Debug)]
pub struct Change {
    field: &'static Field,
    kind: ChangeKind,
    effect: Effect,
    risks: BTreeSet<RiskCode>,
    display: Display,
    entries: Option<EntryCounts>,
}

impl Change {
    pub fn field(&self) -> &'static str {
        self.field.id
    }

    pub fn section(&self) -> Section {
        self.field.section
    }

    pub fn class(&self) -> ChangeClass {
        self.field.class
    }

    pub fn kind(&self) -> ChangeKind {
        self.kind
    }

    pub fn effect(&self) -> Effect {
        self.effect
    }

    /// The sorted risk codes; empty only for a `tightened` or `neutral`
    /// change.
    pub fn risks(&self) -> &BTreeSet<RiskCode> {
        &self.risks
    }

    /// The highest severity of the change's risk codes.
    pub fn severity(&self) -> Option<Severity> {
        self.risks.iter().map(|risk| risk.severity()).max()
    }

    pub fn display(&self) -> Display {
        self.display
    }

    pub fn entries(&self) -> Option<EntryCounts> {
        self.entries
    }
}

/// Compares the base and candidate value of each field and collects the
/// changes.
///
/// Each field is compared once; a caller that compiled both sides walks
/// every field of both, which is what makes the diff complete.
#[derive(Debug, Default)]
pub struct Comparison {
    changes: Vec<Change>,
}

impl Comparison {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records one change from its facets. `impacts` empty is `neutral`.
    pub fn record(
        &mut self,
        field: &'static Field,
        kind: ChangeKind,
        impacts: &[Impact],
        display: Display,
        entries: Option<EntryCounts>,
    ) {
        let mut risks = BTreeSet::new();
        let mut effect = Effect::Neutral;
        for impact in impacts {
            let facet = match impact {
                Impact::Neutral => Effect::Neutral,
                Impact::Tightened => Effect::Tightened,
                Impact::Loosened(risk) => {
                    risks.insert(*risk);
                    Effect::Loosened
                }
                Impact::Unknown => {
                    risks.insert(RiskCode::UnknownImpact);
                    Effect::Unknown
                }
            };
            effect = effect.max(facet);
        }
        self.changes.push(Change {
            field,
            kind,
            effect,
            risks,
            display,
            entries,
        });
    }

    /// A flag, shown.
    pub fn flag(&mut self, field: &'static Field, base: bool, candidate: bool) {
        if base != candidate {
            let impact = field.rule.flag(field.risk, candidate);
            self.record(
                field,
                ChangeKind::Modified,
                &[impact],
                Display::Shown {
                    before: Shown::Flag(base),
                    after: Shown::Flag(candidate),
                },
                None,
            );
        }
    }

    /// A word from a closed vocabulary, shown.
    pub fn word(&mut self, field: &'static Field, base: &'static str, candidate: &'static str) {
        if base != candidate {
            let impact = field.rule.word(field.risk, base, candidate);
            self.record(
                field,
                ChangeKind::Modified,
                &[impact],
                Display::Shown {
                    before: Shown::Word(base),
                    after: Shown::Word(candidate),
                },
                None,
            );
        }
    }

    /// A whole-number quantity, shown; `None` is unbounded.
    pub fn count(&mut self, field: &'static Field, base: Option<u64>, candidate: Option<u64>) {
        if base != candidate {
            let impact = field.rule.order(field.risk, bounded_cmp(candidate, base));
            let shown = |value: Option<u64>| value.map_or(Shown::Unbounded, Shown::Count);
            self.record(
                field,
                ChangeKind::Modified,
                &[impact],
                Display::Shown {
                    before: shown(base),
                    after: shown(candidate),
                },
                None,
            );
        }
    }

    /// A rate, shown. The gateway validates rates finite; positive and
    /// negative zero are the same rate.
    pub fn rate(&mut self, field: &'static Field, base: f64, candidate: f64) {
        if base != candidate {
            let impact = field.rule.order(field.risk, candidate.total_cmp(&base));
            self.record(
                field,
                ChangeKind::Modified,
                &[impact],
                Display::Shown {
                    before: Shown::Rate(base),
                    after: Shown::Rate(candidate),
                },
                None,
            );
        }
    }

    /// An unordered set, by member counts only. Duplicates collapse.
    pub fn set<T: Ord>(
        &mut self,
        field: &'static Field,
        base: impl IntoIterator<Item = T>,
        candidate: impl IntoIterator<Item = T>,
    ) {
        let base: BTreeSet<T> = base.into_iter().collect();
        let candidate: BTreeSet<T> = candidate.into_iter().collect();
        if base != candidate {
            let counts = SetCounts::of(&base, &candidate);
            let impact = field.rule.set(field.risk, counts);
            self.record(
                field,
                ChangeKind::Modified,
                &[impact],
                Display::Withheld,
                Some(EntryCounts {
                    added: counts.added,
                    removed: counts.removed,
                    changed: 0,
                }),
            );
        }
    }

    /// An ordered list, where order is meaning (first match wins). Counts
    /// are of entries without an equal partner on the other side.
    pub fn sequence<T: PartialEq>(&mut self, field: &'static Field, base: &[T], candidate: &[T]) {
        let impact = field.rule.sequence(field.risk);
        self.assessed_sequence(field, base, candidate, &[impact]);
    }

    /// An ordered list whose impacts the caller assessed from what the two
    /// lists hold, counted as [`Comparison::sequence`] counts them.
    pub fn assessed_sequence<T: PartialEq>(
        &mut self,
        field: &'static Field,
        base: &[T],
        candidate: &[T],
        impacts: &[Impact],
    ) {
        if base != candidate {
            self.record(
                field,
                ChangeKind::Modified,
                impacts,
                Display::Withheld,
                Some(EntryCounts {
                    added: unmatched(candidate, base),
                    removed: unmatched(base, candidate),
                    changed: 0,
                }),
            );
        }
    }

    /// An optional value that is never shown.
    pub fn value<T: PartialEq + ?Sized>(
        &mut self,
        field: &'static Field,
        base: Option<&T>,
        candidate: Option<&T>,
    ) {
        self.opaque(field, base, candidate, Display::Withheld);
    }

    /// An optional secret, secret reference or secret locator: reported
    /// only as a changed reference.
    pub fn secret<T: PartialEq + ?Sized>(
        &mut self,
        field: &'static Field,
        base: Option<&T>,
        candidate: Option<&T>,
    ) {
        self.opaque(field, base, candidate, Display::Reference);
    }

    fn opaque<T: PartialEq + ?Sized>(
        &mut self,
        field: &'static Field,
        base: Option<&T>,
        candidate: Option<&T>,
        display: Display,
    ) {
        if base != candidate {
            let kind = ChangeKind::of(base, candidate);
            let impact = field.rule.presence(field.risk, kind);
            self.record(field, kind, &[impact], display, None);
        }
    }

    /// A keyed collection. `assess` is given the base and candidate entry of
    /// every key whose entries differ, `None` for a side that lacks it, and
    /// returns that entry's impacts; an entry that differs with no impact
    /// reported is `unknown`.
    pub fn entries<K: Ord, V: PartialEq>(
        &mut self,
        field: &'static Field,
        redaction: Redaction,
        base: &BTreeMap<K, V>,
        candidate: &BTreeMap<K, V>,
        mut assess: impl FnMut(Option<&V>, Option<&V>) -> Vec<Impact>,
    ) {
        let mut counts = EntryCounts::default();
        let mut impacts = Vec::new();
        let keys: BTreeSet<&K> = base.keys().chain(candidate.keys()).collect();
        for key in keys {
            let (before, after) = (base.get(key), candidate.get(key));
            if before == after {
                continue;
            }
            match (before, after) {
                (None, Some(_)) => counts.added += 1,
                (Some(_), None) => counts.removed += 1,
                _ => counts.changed += 1,
            }
            let entry = assess(before, after);
            if entry.is_empty() {
                impacts.push(Impact::Unknown);
            }
            impacts.extend(entry);
        }
        if counts != EntryCounts::default() {
            self.record(
                field,
                ChangeKind::Modified,
                &impacts,
                redaction.display(),
                Some(counts),
            );
        }
    }

    /// The changes, ordered by section and field identifier.
    pub fn finish(mut self) -> SemanticDiff {
        self.changes
            .sort_by(|a, b| (a.field.section, a.field.id).cmp(&(b.field.section, b.field.id)));
        SemanticDiff {
            changes: self.changes,
        }
    }
}

/// How `candidate` orders against `base`, where `None` is unbounded.
fn bounded_cmp(candidate: Option<u64>, base: Option<u64>) -> Ordering {
    match (candidate, base) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater,
        (Some(_), None) => Ordering::Less,
        (Some(candidate), Some(base)) => candidate.cmp(&base),
    }
}

/// How many entries of `side` have no equal partner left in `other`.
fn unmatched<T: PartialEq>(side: &[T], other: &[T]) -> usize {
    let mut used = vec![false; other.len()];
    side.iter()
        .filter(|item| {
            match other
                .iter()
                .enumerate()
                .position(|(index, candidate)| !used[index] && candidate == *item)
            {
                Some(index) => {
                    used[index] = true;
                    false
                }
                None => true,
            }
        })
        .count()
}

/// The changes between two compiled configurations.
#[derive(Clone, Debug, Default)]
pub struct SemanticDiff {
    changes: Vec<Change>,
}

impl SemanticDiff {
    /// No field differs: the two describe the same configuration.
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }

    pub fn changes(&self) -> &[Change] {
        &self.changes
    }

    /// The sorted set of every change's risk codes.
    pub fn risks(&self) -> BTreeSet<RiskCode> {
        self.changes
            .iter()
            .flat_map(|change| change.risks.iter().copied())
            .collect()
    }

    /// The highest severity of any risk code, `None` when no change
    /// carries one.
    pub fn severity(&self) -> Option<Severity> {
        self.changes.iter().filter_map(Change::severity).max()
    }

    /// The sections with a change.
    pub fn sections(&self) -> BTreeSet<Section> {
        self.changes.iter().map(Change::section).collect()
    }
}

fn severity_name(severity: Option<Severity>) -> &'static str {
    severity.map_or("none", Severity::as_str)
}

/// The report form: `{changed, severity, riskCodes, sections, changes}`,
/// published as `diffResult` in `ggctl-report.v1alpha1.schema.json`.
impl Serialize for SemanticDiff {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let sections: Vec<&'static str> =
            self.sections().into_iter().map(Section::as_str).collect();
        let mut report = serializer.serialize_struct("SemanticDiff", 5)?;
        report.serialize_field("changed", &!self.is_empty())?;
        report.serialize_field("severity", severity_name(self.severity()))?;
        report.serialize_field("riskCodes", &self.risks())?;
        report.serialize_field("sections", &sections)?;
        report.serialize_field("changes", &self.changes)?;
        report.end()
    }
}

impl Serialize for Change {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut record = serializer.serialize_struct("Change", 9)?;
        record.serialize_field("field", self.field.id)?;
        record.serialize_field("section", self.field.section.as_str())?;
        record.serialize_field("kind", self.kind.as_str())?;
        record.serialize_field("class", self.field.class.as_str())?;
        record.serialize_field("effect", self.effect.as_str())?;
        record.serialize_field("severity", severity_name(self.severity()))?;
        record.serialize_field("riskCodes", &self.risks)?;
        record.serialize_field("value", &self.display)?;
        match &self.entries {
            Some(entries) => record.serialize_field("entries", entries)?,
            None => record.skip_field("entries")?,
        }
        record.end()
    }
}

impl Serialize for Display {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Shown { before, after } => {
                let mut value = serializer.serialize_struct("Shown", 3)?;
                value.serialize_field("display", "shown")?;
                value.serialize_field("before", before)?;
                value.serialize_field("after", after)?;
                value.end()
            }
            Self::Withheld => {
                let mut value = serializer.serialize_struct("Withheld", 1)?;
                value.serialize_field("display", "withheld")?;
                value.end()
            }
            Self::Reference => {
                let mut value = serializer.serialize_struct("Reference", 1)?;
                value.serialize_field("display", "reference")?;
                value.end()
            }
        }
    }
}

impl Serialize for Shown {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Flag(flag) => serializer.serialize_bool(*flag),
            Self::Word(word) => serializer.serialize_str(word),
            Self::Count(count) => serializer.serialize_u64(*count),
            Self::Rate(rate) => serializer.serialize_f64(*rate),
            Self::Unbounded => serializer.serialize_str("unbounded"),
        }
    }
}

impl Serialize for EntryCounts {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut counts = serializer.serialize_struct("EntryCounts", 3)?;
        counts.serialize_field("added", &self.added)?;
        counts.serialize_field("removed", &self.removed)?;
        counts.serialize_field("changed", &self.changed)?;
        counts.end()
    }
}
