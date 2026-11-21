//! What a discovery suggestion was generated against, and whether that still
//! holds (issue #243, checklist item 19).
//!
//! A generation run records, with every suggestion it writes or rebinds, the
//! inputs it judged the suggestion against: the authoritative policy (its
//! ETag and, for a v1 document, its semantic digest), the policy resources
//! (the snapshot's digest, whether it was complete, and its components
//! without the cluster security revision), the generator and evidence schema
//! versions, the evidence cutoff and the ADR-0004 semantic digest of the
//! evidence. That is the [`SuggestionGenerationBinding`].
//!
//! Freshness is computed from that binding and the live state on every read,
//! never stored ([`suggestion_freshness`]). It fails closed: a suggestion is
//! `current` only when the live policy ETag, the generator and evidence
//! schema versions and every resource component equal the recorded ones and
//! the resource snapshot was complete both then and now. A row without a
//! binding is `unbound`, an unreadable authority gives `unknown`, and a rule
//! the live policy already holds gives `superseded`.
//!
//! The cluster security revision is never compared (owner ruling 3 of
//! 2026-11-20): it advances on every security change, token revocations
//! included, and a policy change is already caught by the policy ETag. The
//! stored snapshot digest covers that revision, so it is kept for display
//! and audit and is never compared either.

use serde::{Serialize, Serializer};
use serde_json::Value;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::canonical_json;

/// The version of the suggestion generator this build runs. Moves whenever
/// the planner would propose something different from the same inputs.
pub const RULE_SUGGESTION_GENERATOR_VERSION: &str = "rule-suggestions.v1";
/// The version of the per-suggestion `evidence` object's schema.
pub const RULE_SUGGESTION_EVIDENCE_SCHEMA_VERSION: &str = "rule-suggestion-evidence.v1";
/// The media type the evidence digest frames.
const RULE_SUGGESTION_EVIDENCE_MEDIA_TYPE: &str =
    "application/vnd.greengateway.rule-suggestion-evidence+json";

/// The largest stored version string or timestamp, in bytes; the PostgreSQL
/// columns carry the same bound.
const MAX_BINDING_TEXT_BYTES: usize = 64;
/// The largest stored resource-components document, in bytes.
pub(crate) const MAX_BINDING_COMPONENTS_BYTES: usize = 4096;

/// The resource components a binding compares, in the order their reason
/// codes are reported. The cluster security revision is not one of them.
const COMPARED_COMPONENTS: [(&str, &str); 6] = [
    ("gateway_build", "gateway_build_changed"),
    ("evaluator", "evaluator_changed"),
    ("configuration", "configuration_changed"),
    ("egress", "egress_changed"),
    ("tools", "tools_changed"),
    ("connections", "connections_changed"),
];

/// What one generation run judged a suggestion against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SuggestionGenerationBinding {
    pub generator_version: String,
    pub evidence_schema_version: String,
    /// RFC 3339 UTC: when the run started, before it read any evidence.
    pub evidence_cutoff: String,
    /// The ADR-0004 semantic digest of the suggestion's `evidence`.
    pub evidence_digest: String,
    /// The authoritative policy ETag the run filtered candidates against.
    /// Stored, never serialized: a suggestions reader without policy read
    /// permission must not learn the live ETag from it.
    pub policy_etag: String,
    /// The semantic digest of that policy (v1 documents only). Stored, never
    /// serialized, for the same reason.
    pub policy_semantic_digest: Option<String>,
    /// The resource snapshot digest, for display and audit only.
    pub resource_snapshot_digest: Option<String>,
    pub resource_snapshot_complete: bool,
    /// The RFC 8785 form of the snapshot components without the security
    /// revision. Stored, never serialized.
    pub resource_components: String,
}

impl Serialize for SuggestionGenerationBinding {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(Serialize)]
        struct View<'a> {
            generator_version: &'a str,
            evidence_schema_version: &'a str,
            evidence_cutoff: &'a str,
            evidence_digest: &'a str,
            resource_snapshot_digest: Option<&'a str>,
            resource_snapshot_complete: bool,
        }
        View {
            generator_version: &self.generator_version,
            evidence_schema_version: &self.evidence_schema_version,
            evidence_cutoff: &self.evidence_cutoff,
            evidence_digest: &self.evidence_digest,
            resource_snapshot_digest: self.resource_snapshot_digest.as_deref(),
            resource_snapshot_complete: self.resource_snapshot_complete,
        }
        .serialize(serializer)
    }
}

/// The run-wide inputs every suggestion of one generation run is bound to;
/// [`Self::binding_for`] adds the per-suggestion evidence digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SuggestionGenerationContext {
    pub policy_etag: String,
    pub policy_semantic_digest: Option<String>,
    pub resource_snapshot_digest: Option<String>,
    pub resource_snapshot_complete: bool,
    pub resource_components: String,
}

impl SuggestionGenerationContext {
    /// The context of a run against the policy whose ETag is `policy_etag`
    /// and the resources `components` (the snapshot's components without the
    /// security revision). `None` when the components have no canonical form
    /// or exceed the stored bound, so nothing is bound to them.
    pub fn new(
        policy_etag: String,
        policy_semantic_digest: Option<String>,
        resource_snapshot_digest: Option<String>,
        resource_snapshot_complete: bool,
        components: &Value,
    ) -> Option<Self> {
        let resource_components = canonical_components(components)?;
        Some(Self {
            policy_etag,
            policy_semantic_digest,
            resource_snapshot_digest,
            resource_snapshot_complete,
            resource_components,
        })
    }

    /// The binding of one suggestion whose evidence is `evidence`, generated
    /// by a run that started at `evidence_cutoff`. `None` when the evidence
    /// has no canonical form: such a row is written unbound, which reads as
    /// never current.
    pub fn binding_for(
        &self,
        evidence_cutoff: &str,
        evidence: &Value,
    ) -> Option<SuggestionGenerationBinding> {
        let binding = SuggestionGenerationBinding {
            generator_version: RULE_SUGGESTION_GENERATOR_VERSION.to_owned(),
            evidence_schema_version: RULE_SUGGESTION_EVIDENCE_SCHEMA_VERSION.to_owned(),
            evidence_cutoff: evidence_cutoff.to_owned(),
            evidence_digest: evidence_digest(evidence)?,
            policy_etag: self.policy_etag.clone(),
            policy_semantic_digest: self.policy_semantic_digest.clone(),
            resource_snapshot_digest: self.resource_snapshot_digest.clone(),
            resource_snapshot_complete: self.resource_snapshot_complete,
            resource_components: self.resource_components.clone(),
        };
        binding.is_well_formed().then_some(binding)
    }

    /// A fixed context for tests that exercise generation without caring
    /// what it is bound to.
    #[cfg(test)]
    pub(crate) fn for_tests() -> Self {
        Self::new(
            format!("\"sha256:{}\"", "0".repeat(64)),
            None,
            Some(format!("sha256:{}", "1".repeat(64))),
            true,
            &serde_json::json!({
                "gateway_build": "test",
                "evaluator": {},
                "configuration": "sha256:test",
                "egress": "sha256:test",
                "tools": "sha256:test",
                "connections": "\"connections:test\"",
            }),
        )
        .expect("the test generation context is canonical")
    }
}

/// The live state a binding is compared with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveGenerationState {
    pub policy_etag: String,
    pub resource_snapshot_complete: bool,
    /// The RFC 8785 form of the live snapshot components without the
    /// security revision; `None` when they have no canonical form.
    pub resource_components: Option<String>,
}

impl LiveGenerationState {
    pub fn new(policy_etag: String, resource_snapshot_complete: bool, components: &Value) -> Self {
        Self {
            policy_etag,
            resource_snapshot_complete,
            resource_components: canonical_components(components),
        }
    }
}

/// Whether an open suggestion is still bound to the live state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FreshnessStatus {
    Current,
    Stale,
    Superseded,
    Unbound,
    Unknown,
}

/// A suggestion's freshness: the status and the stable reason codes behind
/// it. A suggestion that is not open has no status; its state already says
/// what it is.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SuggestionFreshness {
    pub status: Option<FreshnessStatus>,
    pub reasons: Vec<&'static str>,
}

impl SuggestionFreshness {
    /// The freshness of a suggestion that is not open.
    pub fn not_open() -> Self {
        Self {
            status: None,
            reasons: Vec::new(),
        }
    }

    pub fn is_current(&self) -> bool {
        self.status == Some(FreshnessStatus::Current)
    }

    fn of(status: FreshnessStatus, reasons: Vec<&'static str>) -> Self {
        Self {
            status: Some(status),
            reasons,
        }
    }
}

/// The freshness of an open suggestion bound by `binding` (`None`: no binding
/// was recorded), against `live` (`None`: the policy authority could not be
/// read). `rule_live` says the live policy already holds the proposed rule.
/// Pure; see the module documentation for the rules.
pub fn suggestion_freshness(
    binding: Option<&SuggestionGenerationBinding>,
    live: Option<&LiveGenerationState>,
    rule_live: bool,
) -> SuggestionFreshness {
    if rule_live {
        return SuggestionFreshness::of(FreshnessStatus::Superseded, vec!["rule_already_live"]);
    }
    let Some(binding) = binding else {
        return SuggestionFreshness::of(FreshnessStatus::Unbound, vec!["binding_not_recorded"]);
    };
    let Some(live) = live else {
        return SuggestionFreshness::of(FreshnessStatus::Unknown, vec!["policy_unavailable"]);
    };

    let mut reasons = Vec::new();
    if binding.policy_etag != live.policy_etag {
        reasons.push("policy_changed");
    }
    if binding.generator_version != RULE_SUGGESTION_GENERATOR_VERSION {
        reasons.push("generator_changed");
    }
    if binding.evidence_schema_version != RULE_SUGGESTION_EVIDENCE_SCHEMA_VERSION {
        reasons.push("evidence_schema_changed");
    }
    let recorded = parse_components(&binding.resource_components);
    let current = live
        .resource_components
        .as_deref()
        .and_then(parse_components);
    match (recorded, current) {
        (Some(recorded), Some(current)) => {
            for (component, reason) in COMPARED_COMPONENTS {
                if recorded.get(component) != current.get(component) {
                    reasons.push(reason);
                }
            }
            if !binding.resource_snapshot_complete || !live.resource_snapshot_complete {
                reasons.push("resource_snapshot_incomplete");
            }
        }
        // Components that cannot be read cannot be shown to match.
        _ => reasons.push("resource_snapshot_incomplete"),
    }

    if reasons.is_empty() {
        SuggestionFreshness::of(FreshnessStatus::Current, reasons)
    } else {
        SuggestionFreshness::of(FreshnessStatus::Stale, reasons)
    }
}

/// `sha256:<hex>` over the ADR-0004 `semantic` frame of the RFC 8785 form
/// of `evidence`; `None` when the evidence has no canonical form (a number
/// outside the I-JSON range).
pub fn evidence_digest(evidence: &Value) -> Option<String> {
    canonical_json::semantic_digest(
        RULE_SUGGESTION_EVIDENCE_MEDIA_TYPE,
        RULE_SUGGESTION_EVIDENCE_SCHEMA_VERSION,
        evidence,
    )
    .ok()
}

/// The binding columns of one stored row, as both stores read them.
#[derive(Clone, Debug, Default)]
pub(crate) struct StoredGenerationBinding {
    pub(crate) generator_version: Option<String>,
    pub(crate) evidence_schema_version: Option<String>,
    pub(crate) evidence_cutoff: Option<String>,
    pub(crate) evidence_digest: Option<String>,
    pub(crate) policy_etag: Option<String>,
    pub(crate) policy_semantic_digest: Option<String>,
    pub(crate) resource_snapshot_digest: Option<String>,
    pub(crate) resource_snapshot_complete: Option<bool>,
    pub(crate) resource_components: Option<String>,
}

impl StoredGenerationBinding {
    /// The columns a binding is written as; all `None` for no binding.
    pub(crate) fn of(binding: Option<&SuggestionGenerationBinding>) -> Self {
        let Some(binding) = binding else {
            return Self::default();
        };
        Self {
            generator_version: Some(binding.generator_version.clone()),
            evidence_schema_version: Some(binding.evidence_schema_version.clone()),
            evidence_cutoff: Some(binding.evidence_cutoff.clone()),
            evidence_digest: Some(binding.evidence_digest.clone()),
            policy_etag: Some(binding.policy_etag.clone()),
            policy_semantic_digest: binding.policy_semantic_digest.clone(),
            resource_snapshot_digest: binding.resource_snapshot_digest.clone(),
            resource_snapshot_complete: Some(binding.resource_snapshot_complete),
            resource_components: Some(binding.resource_components.clone()),
        }
    }

    /// The binding these columns hold. Any column missing or malformed --
    /// a row an older binary wrote, a half-written or edited file -- reads
    /// as no binding: never an error, so one bad row cannot fail a listing
    /// or an acceptance, and never current.
    pub(crate) fn decode(self) -> Option<SuggestionGenerationBinding> {
        let binding = SuggestionGenerationBinding {
            generator_version: self.generator_version?,
            evidence_schema_version: self.evidence_schema_version?,
            evidence_cutoff: self.evidence_cutoff?,
            evidence_digest: self.evidence_digest?,
            policy_etag: self.policy_etag?,
            policy_semantic_digest: self.policy_semantic_digest,
            resource_snapshot_digest: self.resource_snapshot_digest,
            resource_snapshot_complete: self.resource_snapshot_complete?,
            resource_components: self.resource_components?,
        };
        binding.is_well_formed().then_some(binding)
    }
}

impl SuggestionGenerationBinding {
    /// Every field within its stored shape and bound.
    fn is_well_formed(&self) -> bool {
        bounded_text(&self.generator_version)
            && bounded_text(&self.evidence_schema_version)
            && bounded_text(&self.evidence_cutoff)
            && OffsetDateTime::parse(&self.evidence_cutoff, &Rfc3339).is_ok()
            && is_digest(&self.evidence_digest)
            && is_policy_etag(&self.policy_etag)
            && self.policy_semantic_digest.as_deref().is_none_or(is_digest)
            && self
                .resource_snapshot_digest
                .as_deref()
                .is_none_or(is_digest)
            && self.resource_components.len() <= MAX_BINDING_COMPONENTS_BYTES
            && parse_components(&self.resource_components).is_some()
    }
}

fn bounded_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_BINDING_TEXT_BYTES
        && value.bytes().all(|byte| byte.is_ascii_graphic())
}

/// `sha256:` and 64 lowercase hex digits.
fn is_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(is_lower_hex_64)
}

/// A strong policy ETag: `"sha256:<64 hex>"`, quotes included.
fn is_policy_etag(value: &str) -> bool {
    value
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .is_some_and(is_digest)
}

fn is_lower_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn canonical_components(components: &Value) -> Option<String> {
    if !components.is_object() {
        return None;
    }
    let bytes = canonical_json::canonical_json_bytes(components).ok()?;
    let text = String::from_utf8(bytes).ok()?;
    (text.len() <= MAX_BINDING_COMPONENTS_BYTES).then_some(text)
}

fn parse_components(text: &str) -> Option<serde_json::Map<String, Value>> {
    match serde_json::from_str::<Value>(text).ok()? {
        Value::Object(map) => Some(map),
        _ => None,
    }
}

#[cfg(test)]
#[path = "suggestion_binding_tests.rs"]
mod tests;
