//! The `v1` revision record: how a proposal becomes canonical record bytes
//! and a record hash, and how stored bytes are read back -- by the same
//! rules, so the ledger never writes a record it would refuse to read.

use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::bundle::{
    is_dns_label, sha256_pin, ApiVersion, Bundle, BundledResource, FileName, FileRole, Profile,
    SourceFile, MANIFEST_FILE_NAME, MANIFEST_MEDIA_TYPE, POLICY_SCHEMA_VERSIONS,
    TOOLS_SCHEMA_VERSIONS,
};
use crate::canonical_json;

use super::{
    is_lowercase_hex, ActivationClass, ActorKind, AuthMode, Corruption, LedgerActor, LedgerError,
    Operation, ParentLink, RecordedBundle, RecordedFile, Refusal, ResourceOrigin, RevisionCodes,
    RevisionId, RevisionSummary,
};

/// The media type a record hash frames the canonical record bytes under.
pub(super) const RECORD_MEDIA_TYPE: &str = "application/vnd.greengateway.config-revision+json";
/// The record format this binary writes and reads.
pub(super) const RECORD_SCHEMA_VERSION: &str = "v1";
/// A record's byte bound. The largest legitimate record -- two maximal actor
/// fields and three full code lists -- is about a third of it.
pub(super) const MAX_RECORD_BYTES: usize = 64 * 1024;
/// The largest integer I-JSON exchanges exactly.
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// What a revision records, before the ledger gives it a place in the chain.
pub(super) struct Pending {
    recorded_at_ms: u64,
    operation: Operation,
    actor: LedgerActor,
    activation: ActivationClass,
    codes: RevisionCodes,
    bundle: RecordedBundle,
}

impl Pending {
    pub(super) fn new<P, T>(
        bundle: &Bundle<P, T>,
        actor: LedgerActor,
        operation: Operation,
        activation: ActivationClass,
        codes: RevisionCodes,
        recorded_at: SystemTime,
    ) -> Result<Self, LedgerError> {
        Ok(Self {
            recorded_at_ms: unix_millis(recorded_at)?,
            operation,
            actor,
            activation,
            codes,
            bundle: recorded_bundle(bundle)?,
        })
    }

    pub(super) fn operation(&self) -> &Operation {
        &self.operation
    }

    pub(super) fn activation(&self) -> ActivationClass {
        self.activation
    }

    pub(super) fn bundle(&self) -> &RecordedBundle {
        &self.bundle
    }
}

/// A record ready to insert.
pub(super) struct Encoded {
    pub(super) bytes: Vec<u8>,
    pub(super) summary: RevisionSummary,
}

/// The record of `pending` at `sequence` on top of `parent`.
pub(super) fn encode(
    pending: &Pending,
    sequence: u64,
    parent: Option<ParentLink>,
) -> Result<Encoded, LedgerError> {
    const ENCODING: LedgerError = LedgerError::Unavailable {
        operation: "record encoding",
    };
    let record = RecordV1 {
        sequence,
        parent: parent.map(|parent| ParentV1 {
            revision: parent.revision.as_str().to_owned(),
            record_hash: parent.record_hash,
        }),
        recorded_at_ms: pending.recorded_at_ms,
        operation: pending.operation.as_str().to_owned(),
        rollback_of: match &pending.operation {
            Operation::Rollback { target } => Some(target.as_str().to_owned()),
            Operation::Seed | Operation::Apply => None,
        },
        actor: ActorV1 {
            kind: pending.actor.kind().as_str().to_owned(),
            subject: pending.actor.subject().to_owned(),
            issuer: pending.actor.issuer().map(str::to_owned),
            auth_mode: pending.actor.auth_mode().as_str().to_owned(),
        },
        activation: pending.activation.as_str().to_owned(),
        changed_sections: pending.codes.changed_sections().to_vec(),
        risk_codes: pending.codes.risk_codes().to_vec(),
        required_permissions: pending.codes.required_permissions().to_vec(),
        bundle: BundleV1 {
            api_version: pending.bundle.api_version.as_str().to_owned(),
            name: pending.bundle.name.clone(),
            profile: pending.bundle.profile.as_str().to_owned(),
            source_digest: pending.bundle.source_digest.clone(),
            policy: pending.bundle.policy.as_str().to_owned(),
            tools: pending.bundle.tools.as_str().to_owned(),
            files: pending
                .bundle
                .files
                .iter()
                .map(|file| FileV1 {
                    role: file.role.as_str().to_owned(),
                    name: file.name.as_str().to_owned(),
                    sha256: file.sha256.clone(),
                    schema_version: file.schema_version.map(str::to_owned),
                })
                .collect(),
        },
    };
    let value = serde_json::to_value(&record).map_err(|_| ENCODING)?;
    let bytes = canonical_json::canonical_json_bytes(&value).map_err(|_| ENCODING)?;
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(LedgerError::Refused(Refusal::RecordTooLarge));
    }
    let record_hash = record_hash(&value).ok_or(ENCODING)?;
    let revision = RevisionId::of_record_hash(&record_hash).ok_or(ENCODING)?;
    // Read back by the rules every later read applies.
    let summary = decode(&bytes, &record_hash, revision.as_str()).map_err(|_| ENCODING)?;
    Ok(Encoded { bytes, summary })
}

/// Reads stored record bytes, which must be canonical, hash to
/// `stored_hash`, yield the ID `stored_id`, and hold a valid record.
pub(super) fn decode(
    bytes: &[u8],
    stored_hash: &str,
    stored_id: &str,
) -> Result<RevisionSummary, LedgerError> {
    const RECORD: LedgerError = LedgerError::Corrupt(Corruption::Record);
    const HASH: LedgerError = LedgerError::Corrupt(Corruption::RecordHash);
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(RECORD);
    }
    let value: Value = serde_json::from_slice(bytes).map_err(|_| RECORD)?;
    let record_hash = record_hash(&value).ok_or(RECORD)?;
    let revision = RevisionId::of_record_hash(&record_hash).ok_or(RECORD)?;
    if record_hash != stored_hash || revision.as_str() != stored_id {
        return Err(HASH);
    }
    // The hash covers the parsed value; the bytes must also be exactly its
    // canonical form, so one record has one stored spelling.
    let canonical = canonical_json::canonical_json_bytes(&value).map_err(|_| RECORD)?;
    if canonical != bytes {
        return Err(RECORD);
    }
    let record: RecordV1 = serde_json::from_value(value).map_err(|_| RECORD)?;
    read_record(record, revision, record_hash)
}

/// The `GGDIGEST` frame of a record's canonical bytes.
fn record_hash(value: &Value) -> Option<String> {
    canonical_json::semantic_digest(RECORD_MEDIA_TYPE, RECORD_SCHEMA_VERSION, value).ok()
}

/// Checks `files`, the stored bytes in recorded order, against the record:
/// each file's pin, and the manifest's bytes against the source digest.
pub(super) fn check_documents(
    bundle: &RecordedBundle,
    files: &[SourceFile],
) -> Result<(), LedgerError> {
    const DOCUMENT: LedgerError = LedgerError::Corrupt(Corruption::Document);
    if files.len() != bundle.files.len() {
        return Err(DOCUMENT);
    }
    for (recorded, stored) in bundle.files.iter().zip(files) {
        if recorded.role != stored.role
            || recorded.name != stored.name
            || sha256_pin(&stored.bytes) != recorded.sha256
        {
            return Err(DOCUMENT);
        }
    }
    let manifest = files.first().ok_or(DOCUMENT)?;
    let digest = canonical_json::source_digest(
        MANIFEST_MEDIA_TYPE,
        bundle.api_version.as_str(),
        &manifest.bytes,
    );
    if digest != bundle.source_digest {
        return Err(DOCUMENT);
    }
    Ok(())
}

fn unix_millis(time: SystemTime) -> Result<u64, LedgerError> {
    time.duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok())
        .filter(|millis| *millis <= MAX_SAFE_INTEGER)
        .ok_or(LedgerError::Refused(Refusal::TimeNotRecordable))
}

/// What the ledger records about an accepted bundle, after checking that the
/// bundle's files reproduce its own pins and source digest.
fn recorded_bundle<P, T>(bundle: &Bundle<P, T>) -> Result<RecordedBundle, LedgerError> {
    const INCONSISTENT: LedgerError = LedgerError::Refused(Refusal::BundleInconsistent);
    let absent = (ResourceOrigin::Absent, None);
    let (policy, policy_pin) = bundle.policy.as_ref().map_or(absent, resource_origin);
    let (tools, tools_pin) = bundle.tools.as_ref().map_or(absent, resource_origin);
    let mut files = Vec::new();
    for file in bundle.source_files() {
        let sha256 = sha256_pin(&file.bytes);
        let (expected, schema_version) = match file.role {
            FileRole::Manifest => (None, None),
            FileRole::Deployment => (Some(bundle.deployment.sha256.as_str()), None),
            FileRole::Policy => (policy_pin.map(|(pin, _)| pin), policy_pin.map(|(_, v)| v)),
            FileRole::Tools => (tools_pin.map(|(pin, _)| pin), tools_pin.map(|(_, v)| v)),
        };
        if file.role != FileRole::Manifest && expected != Some(sha256.as_str()) {
            return Err(INCONSISTENT);
        }
        files.push(RecordedFile {
            role: file.role,
            name: file.name.clone(),
            sha256,
            schema_version,
        });
    }
    let recorded = RecordedBundle {
        api_version: bundle.api_version,
        name: bundle.name.clone(),
        profile: bundle.deployment.profile,
        source_digest: bundle.source_digest.clone(),
        policy,
        tools,
        files,
    };
    if !is_well_formed(&recorded) {
        return Err(INCONSISTENT);
    }
    check_documents(&recorded, bundle.source_files()).map_err(|_| INCONSISTENT)?;
    Ok(recorded)
}

/// A resource's origin and, for a bundled one, its pin and document version.
fn resource_origin<R>(
    resource: &BundledResource<R>,
) -> (ResourceOrigin, Option<(&str, &'static str)>) {
    match resource {
        BundledResource::Bundle {
            sha256,
            schema_version,
            ..
        } => (
            ResourceOrigin::Bundle,
            Some((sha256.as_str(), *schema_version)),
        ),
        BundledResource::Server => (ResourceOrigin::Server, None),
    }
}

/// The shape every recorded bundle has: a DNS-label name, a framed source
/// digest, then exactly the manifest under its fixed name, the deployment
/// document, and a policy and a tools file only where the bundle supplies
/// them, each with a pin and, for policy and tools, a document version.
fn is_well_formed(bundle: &RecordedBundle) -> bool {
    let mut roles = vec![FileRole::Manifest, FileRole::Deployment];
    if bundle.policy == ResourceOrigin::Bundle {
        roles.push(FileRole::Policy);
    }
    if bundle.tools == ResourceOrigin::Bundle {
        roles.push(FileRole::Tools);
    }
    is_dns_label(&bundle.name)
        && is_framed_digest(&bundle.source_digest)
        && bundle.files.len() == roles.len()
        && bundle.files.iter().zip(&roles).all(|(file, role)| {
            let versioned = matches!(role, FileRole::Policy | FileRole::Tools);
            file.role == *role
                && (file.role != FileRole::Manifest || file.name.as_str() == MANIFEST_FILE_NAME)
                && file.sha256.len() == 64
                && is_lowercase_hex(&file.sha256)
                && file.schema_version.is_some() == versioned
        })
}

fn is_framed_digest(digest: &str) -> bool {
    digest
        .strip_prefix("sha256:")
        .is_some_and(|digits| digits.len() == 64 && is_lowercase_hex(digits))
}

/// The typed record, or why it is not one. A well-formed record that names a
/// document version this binary does not know is unsupported, not corrupt.
fn read_record(
    record: RecordV1,
    revision: RevisionId,
    record_hash: String,
) -> Result<RevisionSummary, LedgerError> {
    const RECORD: LedgerError = LedgerError::Corrupt(Corruption::Record);
    let RecordV1 {
        sequence,
        parent,
        recorded_at_ms,
        operation,
        rollback_of,
        actor,
        activation,
        changed_sections,
        risk_codes,
        required_permissions,
        bundle,
    } = record;

    if sequence == 0 || recorded_at_ms > MAX_SAFE_INTEGER {
        return Err(RECORD);
    }
    let parent = match parent {
        None => None,
        Some(ParentV1 {
            revision,
            record_hash,
        }) => {
            let revision = RevisionId::parse(&revision).ok_or(RECORD)?;
            if RevisionId::of_record_hash(&record_hash).as_ref() != Some(&revision) {
                return Err(RECORD);
            }
            Some(ParentLink {
                revision,
                record_hash,
            })
        }
    };
    let operation = match (operation.as_str(), rollback_of) {
        ("seed", None) => Operation::Seed,
        ("apply", None) => Operation::Apply,
        ("rollback", Some(target)) => Operation::Rollback {
            target: RevisionId::parse(&target).ok_or(RECORD)?,
        },
        _ => return Err(RECORD),
    };
    let actor = LedgerActor::checked(
        named(ActorKind::ALL, &actor.kind, |kind| kind.as_str()).ok_or(RECORD)?,
        actor.subject,
        actor.issuer,
        named(AuthMode::ALL, &actor.auth_mode, |mode| mode.as_str()).ok_or(RECORD)?,
    )
    .ok_or(RECORD)?;
    let activation =
        named(ActivationClass::ALL, &activation, |class| class.as_str()).ok_or(RECORD)?;
    let codes = RevisionCodes::new(
        &changed_sections[..],
        &risk_codes[..],
        &required_permissions[..],
    )
    .map_err(|_| RECORD)?;
    // Sorted and unique already: one set of codes has one spelling.
    if codes.changed_sections != changed_sections
        || codes.risk_codes != risk_codes
        || codes.required_permissions != required_permissions
    {
        return Err(RECORD);
    }
    let bundle = read_bundle_record(bundle)?;
    Ok(RevisionSummary {
        sequence,
        revision,
        record_hash,
        parent,
        recorded_at_ms,
        operation,
        actor,
        activation,
        codes,
        bundle,
    })
}

fn read_bundle_record(bundle: BundleV1) -> Result<RecordedBundle, LedgerError> {
    const RECORD: LedgerError = LedgerError::Corrupt(Corruption::Record);
    let BundleV1 {
        api_version,
        name,
        profile,
        source_digest,
        policy,
        tools,
        files,
    } = bundle;
    let api_version = named(ApiVersion::ALL, &api_version, |version| version.as_str())
        .ok_or(LedgerError::Unsupported)?;
    let profile = named(Profile::ALL, &profile, |profile| profile.as_str())
        .ok_or(LedgerError::Unsupported)?;
    let origin = |text: &str| named(ResourceOrigin::ALL, text, |origin| origin.as_str());
    let files = files
        .into_iter()
        .map(|file| {
            let role = named(FileRole::ALL, &file.role, |role| role.as_str()).ok_or(RECORD)?;
            let versions = match role {
                FileRole::Policy => POLICY_SCHEMA_VERSIONS,
                FileRole::Tools => TOOLS_SCHEMA_VERSIONS,
                FileRole::Manifest | FileRole::Deployment => &[],
            };
            let schema_version = match file.schema_version {
                None => None,
                Some(version) => Some(
                    versions
                        .iter()
                        .copied()
                        .find(|known| *known == version)
                        .ok_or(LedgerError::Unsupported)?,
                ),
            };
            Ok(RecordedFile {
                role,
                name: FileName::parse(&file.name).ok_or(RECORD)?,
                sha256: file.sha256,
                schema_version,
            })
        })
        .collect::<Result<Vec<_>, LedgerError>>()?;
    let bundle = RecordedBundle {
        api_version,
        name,
        profile,
        source_digest,
        policy: origin(&policy).ok_or(RECORD)?,
        tools: origin(&tools).ok_or(RECORD)?,
        files,
    };
    if !is_well_formed(&bundle) {
        return Err(RECORD);
    }
    Ok(bundle)
}

/// The member of `all` whose name is `text`.
fn named<T: Copy>(all: &[T], text: &str, name: impl Fn(T) -> &'static str) -> Option<T> {
    all.iter().copied().find(|member| name(*member) == text)
}

// The serialized record. Members are snake_case and every one is always
// present (an absent optional member is `null`), so a record has exactly one
// canonical spelling; unknown members are refused.

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RecordV1 {
    sequence: u64,
    parent: Option<ParentV1>,
    recorded_at_ms: u64,
    operation: String,
    rollback_of: Option<String>,
    actor: ActorV1,
    activation: String,
    changed_sections: Vec<String>,
    risk_codes: Vec<String>,
    required_permissions: Vec<String>,
    bundle: BundleV1,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ParentV1 {
    revision: String,
    record_hash: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ActorV1 {
    kind: String,
    subject: String,
    issuer: Option<String>,
    auth_mode: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BundleV1 {
    api_version: String,
    name: String,
    profile: String,
    source_digest: String,
    policy: String,
    tools: String,
    files: Vec<FileV1>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FileV1 {
    role: String,
    name: String,
    sha256: String,
    schema_version: Option<String>,
}
