//! The standalone configuration revision ledger (issue #242, PR 10;
//! ADR-0008, "Ledger mode").
//!
//! One SQLite database, [`LEDGER_FILE_NAME`], beneath the state directory,
//! holding the configuration bundles a standalone deployment applied as an
//! append-only chain of immutable revisions:
//!
//! - **Records.** Each revision is one canonical JSON record (RFC 8785): its
//!   sequence number, its parent revision and that parent's record hash, the
//!   time the caller stamped it with, the operation (`seed`, `apply` or
//!   `rollback` with its target), the actor in the closed vocabulary the
//!   authority-evidence tables use, the activation class, the changed
//!   section names, risk codes and required permissions (codes only, never
//!   values), and the bundle: its document version, name, profile, source
//!   digest, where its policy and tools come from, and every file's role,
//!   name, pin and document version.
//! - **Chain.** A record's hash is the ADR-0004 `GGDIGEST` frame of its
//!   canonical bytes under its own media type, and a revision's opaque ID is
//!   derived from that hash. Because each record carries its parent's hash,
//!   an edit, removal, insertion or reorder anywhere in the history changes
//!   every later hash and is detected.
//! - **Documents.** The exact bytes of every bundle file are stored once,
//!   keyed by their SHA-256 pin, and checked against the pin whenever they
//!   are read. The manifest's bytes must reproduce the recorded source digest.
//! - **Pointer.** One row names the desired revision, which is always the
//!   newest, and the active revision, the one a running gateway compiled.
//!   Both only move forward: a rollback is a new revision with prior content.
//!
//! The ledger fails closed. Opening it checks the file's location and
//! permissions, the SQLite page structure, the exact schema (including the
//! triggers that refuse updates and deletes), every record, the whole chain,
//! every document and the pointer; any discrepancy is [`LedgerError::Corrupt`]
//! with a value-free [`Corruption`] class, and a handle that has seen
//! corruption refuses every later call. Appends take SQLite's write lock with
//! an immediate transaction, compare the caller's expected head with the head
//! inside that transaction, and commit the revision, its documents and the
//! pointer move together, so a crash leaves either the old head or the new
//! one. A ledger is created only whole, with its first revision: [`seed`]
//! builds it under a temporary name and links it into place after commit.
//!
//! A hash chain is integrity evidence, not authentication: whoever can write
//! the state directory can replace the whole ledger with a consistent one,
//! which is why ADR-0008 treats filesystem access to the state directory as
//! full control of a standalone deployment.
//!
//! Not here yet: selecting ledger mode at startup, the state-directory lock
//! that keeps offline `ggctl ledger` commands and a running gateway apart,
//! evidence and outbox rows, `ggctl ledger seed|verify|rollback`, plans and
//! online apply, and pruning. Until pruning lands an append beyond
//! [`MAX_RETAINED_REVISIONS`] is refused rather than history dropped.
//!
//! Like the rest of this crate the ledger reads no clock and no environment:
//! callers stamp each revision with its time.
//!
//! [`seed`]: RevisionLedger::seed

mod location;
mod record;
mod store;

#[cfg(test)]
mod tests;

use std::{fmt, path::Path, time::SystemTime};

use rusqlite::Connection;

use crate::bundle::{ApiVersion, Bundle, FileName, FileRole, Profile, SourceFile};
use crate::opaque_id::is_valid_opaque_id;

/// The ledger's file name beneath the state directory.
pub const LEDGER_FILE_NAME: &str = "config-ledger.sqlite3";
/// The most revisions a ledger holds (ADR-0008's retention bound).
pub const MAX_RETAINED_REVISIONS: usize = 1024;
/// The most revisions one [`RevisionLedger::revisions`] page returns.
pub const MAX_REVISION_PAGE: usize = 100;
/// The most entries in each code list a revision records.
pub const MAX_RECORDED_CODES: usize = 64;
/// The longest code a revision records.
pub const MAX_CODE_BYTES: usize = 128;
/// The longest actor subject: the bound authentication enforces.
pub const MAX_ACTOR_SUBJECT_BYTES: usize = 4096;
/// The longest actor issuer: the bound authentication enforces.
pub const MAX_ACTOR_ISSUER_BYTES: usize = 4096;
/// The longest system actor label.
pub const MAX_SYSTEM_LABEL_BYTES: usize = 128;

/// An opaque revision identifier: `rev-` and 32 lowercase hexadecimal digits
/// taken from the revision's record hash.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RevisionId(String);

impl RevisionId {
    const PREFIX: &'static str = "rev-";
    const DIGITS: usize = 32;

    pub fn parse(text: &str) -> Option<Self> {
        let digits = text.strip_prefix(Self::PREFIX)?;
        (digits.len() == Self::DIGITS && is_lowercase_hex(digits)).then(|| Self(text.to_owned()))
    }

    /// The ID of the revision whose record hash is `record_hash`.
    fn of_record_hash(record_hash: &str) -> Option<Self> {
        let digits = record_hash.strip_prefix("sha256:")?;
        if digits.len() != 64 || !is_lowercase_hex(digits) {
            return None;
        }
        Some(Self(format!("{}{}", Self::PREFIX, &digits[..Self::DIGITS])))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RevisionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

fn is_lowercase_hex(text: &str) -> bool {
    text.bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// What kind of actor recorded a revision: the closed `actor_kind`
/// vocabulary of the authority-evidence tables.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActorKind {
    /// A principal an identity provider or the inbound TLS handshake vouched
    /// for.
    Principal,
    /// A gateway-issued service token.
    ServiceToken,
    /// An operator command acting on the deployment's own authority under a
    /// fixed label, such as an offline `ggctl ledger` command. Nobody
    /// authenticated it, so it has no issuer.
    System,
}

impl ActorKind {
    pub const ALL: &'static [Self] = &[Self::Principal, Self::ServiceToken, Self::System];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Principal => "principal",
            Self::ServiceToken => "service_token",
            Self::System => "system",
        }
    }
}

/// How an actor authenticated, in the audit vocabulary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthMode {
    SessionCookie,
    BearerToken,
    ClientCertificate,
    ServiceToken,
    System,
}

impl AuthMode {
    pub const ALL: &'static [Self] = &[
        Self::SessionCookie,
        Self::BearerToken,
        Self::ClientCertificate,
        Self::ServiceToken,
        Self::System,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::SessionCookie => "session_cookie",
            Self::BearerToken => "bearer_token",
            Self::ClientCertificate => "client_certificate",
            Self::ServiceToken => "service_token",
            Self::System => "system",
        }
    }

    /// Whether an actor of `kind` can have authenticated this way: the pairs
    /// the authority-evidence tables' CHECK constraints admit.
    fn agrees_with(self, kind: ActorKind) -> bool {
        match kind {
            ActorKind::Principal => matches!(
                self,
                Self::SessionCookie | Self::BearerToken | Self::ClientCertificate
            ),
            ActorKind::ServiceToken => self == Self::ServiceToken,
            ActorKind::System => self == Self::System,
        }
    }
}

/// Who recorded a revision: the subject, the canonical issuer for a
/// principal, the actor kind and the auth mode, and nothing else -- never a
/// credential, a session identifier, roles or an email address. Kind and
/// auth mode always agree, because only the constructors set them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LedgerActor {
    kind: ActorKind,
    subject: String,
    issuer: Option<String>,
    auth_mode: AuthMode,
}

impl LedgerActor {
    /// An authenticated principal, with its issuer already in canonical form.
    pub fn principal(
        subject: &str,
        issuer: Option<&str>,
        auth_mode: AuthMode,
    ) -> Result<Self, LedgerError> {
        Self::checked(
            ActorKind::Principal,
            subject.to_owned(),
            issuer.map(str::to_owned),
            auth_mode,
        )
        .ok_or(LedgerError::Refused(Refusal::ActorNotRecordable))
    }

    /// A gateway-issued service token, by its `service-token:<id>` subject.
    pub fn service_token(subject: &str) -> Result<Self, LedgerError> {
        Self::checked(
            ActorKind::ServiceToken,
            subject.to_owned(),
            None,
            AuthMode::ServiceToken,
        )
        .ok_or(LedgerError::Refused(Refusal::ActorNotRecordable))
    }

    /// An operator command's fixed label: an opaque ID of at most
    /// [`MAX_SYSTEM_LABEL_BYTES`] bytes.
    pub fn system(label: &str) -> Result<Self, LedgerError> {
        Self::checked(ActorKind::System, label.to_owned(), None, AuthMode::System)
            .ok_or(LedgerError::Refused(Refusal::ActorNotRecordable))
    }

    /// The one rule every recorded actor satisfies, on append and on read: a
    /// subject of 1 to [`MAX_ACTOR_SUBJECT_BYTES`] bytes (an opaque label for
    /// a system actor), an issuer of 1 to [`MAX_ACTOR_ISSUER_BYTES`] bytes
    /// only for a principal, and an auth mode that agrees with the kind.
    fn checked(
        kind: ActorKind,
        subject: String,
        issuer: Option<String>,
        auth_mode: AuthMode,
    ) -> Option<Self> {
        let subject_ok = match kind {
            ActorKind::System => is_valid_opaque_id(&subject, MAX_SYSTEM_LABEL_BYTES),
            ActorKind::Principal | ActorKind::ServiceToken => {
                !subject.is_empty() && subject.len() <= MAX_ACTOR_SUBJECT_BYTES
            }
        };
        let issuer_ok = match issuer.as_deref() {
            None => true,
            Some(issuer) => {
                kind == ActorKind::Principal
                    && !issuer.is_empty()
                    && issuer.len() <= MAX_ACTOR_ISSUER_BYTES
            }
        };
        (subject_ok && issuer_ok && auth_mode.agrees_with(kind)).then_some(Self {
            kind,
            subject,
            issuer,
            auth_mode,
        })
    }

    pub fn kind(&self) -> ActorKind {
        self.kind
    }

    /// The principal's subject, or the system label.
    pub fn subject(&self) -> &str {
        &self.subject
    }

    pub fn issuer(&self) -> Option<&str> {
        self.issuer.as_deref()
    }

    pub fn auth_mode(&self) -> AuthMode {
        self.auth_mode
    }
}

/// When a revision takes effect (ADR-0008's change classes a ledger records).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivationClass {
    /// Activates in the running process. The active pointer moves with the
    /// revision unless a restart is already pending.
    Live,
    /// Durable once recorded; active only after a new process compiles it.
    /// Only the desired pointer moves.
    Restart,
}

impl ActivationClass {
    pub const ALL: &'static [Self] = &[Self::Live, Self::Restart];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Restart => "restart",
        }
    }
}

/// What a revision did.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Operation {
    /// The first revision, written by [`RevisionLedger::seed`] and only
    /// there.
    Seed,
    /// A new bundle.
    Apply,
    /// A prior revision's content again, as a new forward revision.
    Rollback { target: RevisionId },
}

impl Operation {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Seed => "seed",
            Self::Apply => "apply",
            Self::Rollback { .. } => "rollback",
        }
    }
}

/// The codes a revision records about its change: changed section names,
/// risk codes and required permissions. Each list is sorted, free of
/// duplicates, at most [`MAX_RECORDED_CODES`] long, and holds codes of 1 to
/// [`MAX_CODE_BYTES`] bytes: a lowercase ASCII letter, then lowercase
/// letters, digits, `_`, `.`, `:` or `-`. The grammar cannot express a
/// value, a path or whitespace.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RevisionCodes {
    changed_sections: Vec<String>,
    risk_codes: Vec<String>,
    required_permissions: Vec<String>,
}

impl RevisionCodes {
    /// No codes: what a seed records.
    pub fn none() -> Self {
        Self::default()
    }

    /// Sorts and deduplicates each list, and refuses any code outside the
    /// grammar or a list beyond the bound.
    pub fn new<S: AsRef<str>>(
        changed_sections: &[S],
        risk_codes: &[S],
        required_permissions: &[S],
    ) -> Result<Self, LedgerError> {
        let list = |codes: &[S]| {
            let mut list: Vec<String> = codes.iter().map(|code| code.as_ref().to_owned()).collect();
            list.sort();
            list.dedup();
            let valid = list.len() <= MAX_RECORDED_CODES && list.iter().all(|code| is_code(code));
            valid
                .then_some(list)
                .ok_or(LedgerError::Refused(Refusal::CodeNotRecordable))
        };
        Ok(Self {
            changed_sections: list(changed_sections)?,
            risk_codes: list(risk_codes)?,
            required_permissions: list(required_permissions)?,
        })
    }

    pub fn changed_sections(&self) -> &[String] {
        &self.changed_sections
    }

    pub fn risk_codes(&self) -> &[String] {
        &self.risk_codes
    }

    pub fn required_permissions(&self) -> &[String] {
        &self.required_permissions
    }
}

fn is_code(code: &str) -> bool {
    let bytes = code.as_bytes();
    bytes.len() <= MAX_CODE_BYTES
        && bytes.first().is_some_and(u8::is_ascii_lowercase)
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'_' | b'.' | b':' | b'-')
        })
}

/// A revision to append: a bundle [`crate::bundle::read_bundle`] accepted,
/// who is recording it, and what it does.
pub struct Proposal<'a, P, T> {
    pub bundle: &'a Bundle<P, T>,
    pub actor: LedgerActor,
    /// [`Operation::Apply`] or [`Operation::Rollback`]; a seed is refused.
    pub operation: Operation,
    pub activation: ActivationClass,
    pub codes: RevisionCodes,
    /// The time to record, at millisecond precision. The ledger reads no
    /// clock and does not require times to increase.
    pub recorded_at: SystemTime,
}

/// Where a bundle's policy or tools come from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceOrigin {
    /// A file of the bundle.
    Bundle,
    /// The existing store.
    Server,
    /// The manifest does not declare it.
    Absent,
}

impl ResourceOrigin {
    pub const ALL: &'static [Self] = &[Self::Bundle, Self::Server, Self::Absent];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bundle => "bundle",
            Self::Server => "server",
            Self::Absent => "absent",
        }
    }
}

/// One file a revision recorded, without its content.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordedFile {
    pub role: FileRole,
    pub name: FileName,
    /// 64 lowercase hexadecimal digits over the exact bytes: the manifest's
    /// pin.
    pub sha256: String,
    /// The exact document version of a policy or tools file.
    pub schema_version: Option<&'static str>,
}

/// The bundle a revision recorded, without file content.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordedBundle {
    pub api_version: ApiVersion,
    pub name: String,
    pub profile: Profile,
    /// The bundle's source digest: `sha256:` and 64 lowercase hex digits
    /// over the framed manifest bytes.
    pub source_digest: String,
    pub policy: ResourceOrigin,
    pub tools: ResourceOrigin,
    /// The manifest, the deployment document, then the policy and tools
    /// files the bundle supplies, in that order.
    pub files: Vec<RecordedFile>,
}

/// A revision's parent, as its record names it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParentLink {
    pub revision: RevisionId,
    pub record_hash: String,
}

/// One revision's record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevisionSummary {
    /// 1 for the seed, then one more for each revision.
    pub sequence: u64,
    pub revision: RevisionId,
    /// `sha256:` and 64 lowercase hex digits: the `GGDIGEST` frame of the
    /// canonical record under its media type. A strong validator for the
    /// revision.
    pub record_hash: String,
    /// `None` only for the seed.
    pub parent: Option<ParentLink>,
    /// Milliseconds since the Unix epoch, as the caller stamped it.
    pub recorded_at_ms: u64,
    pub operation: Operation,
    pub actor: LedgerActor,
    pub activation: ActivationClass,
    pub codes: RevisionCodes,
    pub bundle: RecordedBundle,
}

/// One revision with the exact bytes of its files, each checked against its
/// pin as it was read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredRevision {
    pub summary: RevisionSummary,
    /// In [`RecordedBundle::files`] order.
    pub files: Vec<SourceFile>,
}

/// The ledger's pointer and head.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LedgerState {
    /// How many revisions the ledger holds.
    pub revisions: u64,
    /// The newest revision, which is always the desired one.
    pub desired: RevisionSummary,
    /// The revision a gateway last compiled and activated, if any.
    pub active: Option<RevisionId>,
}

impl LedgerState {
    /// Whether the desired revision is not yet active.
    pub fn restart_pending(&self) -> bool {
        self.active.as_ref() != Some(&self.desired.revision)
    }
}

/// What the ledger found when it refused to trust its contents.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Corruption {
    /// SQLite reports a malformed database or page structure.
    Integrity,
    /// The file is not a GreenGateway configuration ledger.
    Format,
    /// The tables or triggers are not exactly the ledger's.
    Schema,
    /// A record is not canonical JSON, or not a valid record.
    Record,
    /// A record's bytes do not hash to its stored hash and ID.
    RecordHash,
    /// The sequence, a parent link or a rollback target is broken.
    Chain,
    /// A stored document does not match its pin or the source digest, or a
    /// document no revision records is present.
    Document,
    /// The pointer is missing, is not at the head, or names a revision the
    /// chain does not hold.
    Pointer,
}

impl Corruption {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Integrity => "integrity",
            Self::Format => "format",
            Self::Schema => "schema",
            Self::Record => "record",
            Self::RecordHash => "record_hash",
            Self::Chain => "chain",
            Self::Document => "document",
            Self::Pointer => "pointer",
        }
    }
}

/// Why the ledger refused to record something. Nothing was written.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Refusal {
    /// The actor is outside the recordable bounds or vocabulary.
    ActorNotRecordable,
    /// A code is outside the grammar, or a list is beyond its bound.
    CodeNotRecordable,
    /// The time is before the Unix epoch or beyond the I-JSON safe range.
    TimeNotRecordable,
    /// A seed is written only by [`RevisionLedger::seed`].
    SeedNotAppendable,
    /// The rollback target is not a revision of this ledger.
    RollbackTargetUnknown,
    /// The rollback target is the head itself.
    RollbackTargetIsHead,
    /// The bundle's source digest is not the rollback target's.
    RollbackContentDiffers,
    /// The bundle's files do not reproduce its own digests.
    BundleInconsistent,
    /// The record would exceed its byte bound.
    RecordTooLarge,
}

impl Refusal {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ActorNotRecordable => "actor_not_recordable",
            Self::CodeNotRecordable => "code_not_recordable",
            Self::TimeNotRecordable => "time_not_recordable",
            Self::SeedNotAppendable => "seed_not_appendable",
            Self::RollbackTargetUnknown => "rollback_target_unknown",
            Self::RollbackTargetIsHead => "rollback_target_is_head",
            Self::RollbackContentDiffers => "rollback_content_differs",
            Self::BundleInconsistent => "bundle_inconsistent",
            Self::RecordTooLarge => "record_too_large",
        }
    }
}

/// Why a ledger operation did not happen. Value-free: no path, document
/// value, actor or raw SQLite message, only stable codes and, for a stale
/// head, the opaque ID of the head that won.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LedgerError {
    /// The state directory is missing, is not a directory, is a link, or is
    /// writable by group or other; or the ledger path is a link, not a
    /// regular file, or writable by group or other.
    UnsafeLocation,
    /// The state directory holds no ledger.
    Missing,
    /// The state directory already holds a ledger, or a previous ledger's
    /// journal files, which a new ledger could replay.
    Exists,
    /// The ledger is in a format newer than this binary, or records a
    /// document version this binary does not know.
    Unsupported,
    /// The ledger failed verification. Nothing was read or written, and a
    /// handle that has reported this refuses every later call.
    Corrupt(Corruption),
    /// The head is no longer the one the caller expected.
    Stale { head: RevisionId },
    /// The ledger refused to record the proposal.
    Refused(Refusal),
    /// The ledger already holds [`MAX_RETAINED_REVISIONS`] revisions.
    Full,
    /// The ledger could not be read or written: busy, read-only, out of
    /// space or another I/O failure, during `operation`.
    Unavailable { operation: &'static str },
}

impl LedgerError {
    /// The stable code for reports.
    pub fn code(&self) -> &'static str {
        match self {
            Self::UnsafeLocation => "ledger.unsafe_location",
            Self::Missing => "ledger.missing",
            Self::Exists => "ledger.exists",
            Self::Unsupported => "ledger.unsupported",
            Self::Corrupt(_) => "ledger.corrupt",
            Self::Stale { .. } => "ledger.stale",
            Self::Refused(_) => "ledger.refused",
            Self::Full => "ledger.full",
            Self::Unavailable { .. } => "ledger.unavailable",
        }
    }
}

impl fmt::Display for LedgerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsafeLocation => formatter.write_str(
                "the state directory or ledger file is a link, not the expected kind of entry, or writable by group or other",
            ),
            Self::Missing => formatter.write_str("the state directory holds no configuration ledger"),
            Self::Exists => formatter.write_str(
                "the state directory already holds a configuration ledger or its journal files",
            ),
            Self::Unsupported => formatter.write_str(
                "the configuration ledger uses a format or document version this binary does not support",
            ),
            Self::Corrupt(kind) => write!(
                formatter,
                "the configuration ledger failed verification ({})",
                kind.as_str()
            ),
            Self::Stale { head } => write!(formatter, "the configuration ledger head is now {head}"),
            Self::Refused(reason) => write!(
                formatter,
                "the configuration ledger refused the revision ({})",
                reason.as_str()
            ),
            Self::Full => write!(
                formatter,
                "the configuration ledger already holds {MAX_RETAINED_REVISIONS} revisions"
            ),
            Self::Unavailable { operation } => {
                write!(formatter, "the configuration ledger {operation} failed")
            }
        }
    }
}

impl std::error::Error for LedgerError {}

/// An open, verified revision ledger.
///
/// Every call takes `&mut self`; a caller that shares one wraps it in a
/// mutex. Two handles on one ledger, in one process or two, serialize their
/// writes through SQLite's write lock, and compare-and-set on the head means
/// exactly one of two appends against the same head wins.
pub struct RevisionLedger {
    connection: Connection,
    /// Set by the first corruption any call reports; every later call
    /// reports it again.
    corruption: Option<Corruption>,
    max_revisions: usize,
}

impl fmt::Debug for RevisionLedger {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RevisionLedger")
            .field("corruption", &self.corruption)
            .finish_non_exhaustive()
    }
}

impl RevisionLedger {
    /// Creates the ledger in `state_dir` with `bundle` as its first, desired
    /// and not yet active revision, and opens it.
    ///
    /// Refuses a state directory that already holds a ledger or a previous
    /// ledger's journal files. The ledger is built and committed under a
    /// temporary name, flushed, then linked to [`LEDGER_FILE_NAME`] without
    /// replacing anything, so an interrupted seed never leaves a file under
    /// the ledger's name; a leftover temporary file is discarded by the next
    /// seed.
    pub fn seed<P, T>(
        state_dir: &Path,
        bundle: &Bundle<P, T>,
        actor: LedgerActor,
        recorded_at: SystemTime,
    ) -> Result<(Self, RevisionSummary), LedgerError> {
        let pending = record::Pending::new(
            bundle,
            actor,
            Operation::Seed,
            ActivationClass::Restart,
            RevisionCodes::none(),
            recorded_at,
        )?;
        let paths = location::prepare_seed(state_dir)?;
        let initialized = location::create_temporary(&paths)
            .and_then(|()| store::initialize(&paths.temporary, pending, bundle.source_files()));
        if let Err(error) = initialized {
            location::discard_temporary(&paths);
            return Err(error);
        }
        location::publish(&paths)?;
        let mut ledger = Self::open(state_dir)?;
        let state = ledger.state()?;
        Ok((ledger, state.desired))
    }

    /// Opens and fully verifies the ledger in `state_dir`.
    pub fn open(state_dir: &Path) -> Result<Self, LedgerError> {
        let path = location::existing_ledger(state_dir)?;
        let connection = store::open(&path)?;
        store::verify(&connection, MAX_RETAINED_REVISIONS)?;
        Ok(Self {
            connection,
            corruption: None,
            max_revisions: MAX_RETAINED_REVISIONS,
        })
    }

    /// Verifies the whole ledger again, as [`Self::open`] did.
    pub fn verify(&mut self) -> Result<LedgerState, LedgerError> {
        self.usable()?;
        let verified = store::verify(&self.connection, self.max_revisions);
        self.observe(verified)
    }

    /// The pointer, with the desired revision's record.
    pub fn state(&mut self) -> Result<LedgerState, LedgerError> {
        self.usable()?;
        let state = store::state(&self.connection);
        self.observe(state)
    }

    /// Appends a revision on top of `expected_head`, in one immediate
    /// transaction with its documents and the pointer move.
    ///
    /// The desired pointer always moves to the new revision. The active
    /// pointer moves with it only for an [`ActivationClass::Live`] revision
    /// and only when no restart is pending, that is when the head being
    /// replaced is the active revision.
    pub fn append<P, T>(
        &mut self,
        expected_head: &RevisionId,
        proposal: Proposal<'_, P, T>,
    ) -> Result<RevisionSummary, LedgerError> {
        self.usable()?;
        if proposal.operation == Operation::Seed {
            return Err(LedgerError::Refused(Refusal::SeedNotAppendable));
        }
        let pending = record::Pending::new(
            proposal.bundle,
            proposal.actor,
            proposal.operation,
            proposal.activation,
            proposal.codes,
            proposal.recorded_at,
        )?;
        let appended = store::append(
            &mut self.connection,
            self.max_revisions,
            expected_head,
            pending,
            proposal.bundle.source_files(),
        );
        self.observe(appended)
    }

    /// Records that a gateway compiled and activated `desired`, which must
    /// be the desired revision. Idempotent.
    pub fn activate(&mut self, desired: &RevisionId) -> Result<LedgerState, LedgerError> {
        self.usable()?;
        let activated = store::activate(&mut self.connection, desired);
        self.observe(activated)?;
        self.state()
    }

    /// Up to `limit` revisions (at most [`MAX_REVISION_PAGE`]), newest first,
    /// starting below sequence `before` when given.
    pub fn revisions(
        &mut self,
        before: Option<u64>,
        limit: usize,
    ) -> Result<Vec<RevisionSummary>, LedgerError> {
        self.usable()?;
        let page = store::revisions(&self.connection, before, limit.min(MAX_REVISION_PAGE));
        self.observe(page)
    }

    /// One revision with its files, or `None` when this ledger has no such
    /// revision.
    pub fn revision(&mut self, id: &RevisionId) -> Result<Option<StoredRevision>, LedgerError> {
        self.usable()?;
        let stored = store::revision(&self.connection, id);
        self.observe(stored)
    }

    fn usable(&self) -> Result<(), LedgerError> {
        match self.corruption {
            Some(kind) => Err(LedgerError::Corrupt(kind)),
            None => Ok(()),
        }
    }

    fn observe<V>(&mut self, result: Result<V, LedgerError>) -> Result<V, LedgerError> {
        if let Err(LedgerError::Corrupt(kind)) = &result {
            self.corruption.get_or_insert(*kind);
        }
        result
    }

    /// A lower retention bound, so a test can reach it.
    #[cfg(test)]
    fn with_revision_limit(mut self, max_revisions: usize) -> Self {
        self.max_revisions = max_revisions;
        self
    }
}
