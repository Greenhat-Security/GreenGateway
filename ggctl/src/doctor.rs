//! `ggctl doctor BUNDLE [--format human|json]`: the offline doctor
//! (ADR-0008, "Doctor").
//!
//! The doctor runs the same shared bundle reader as `validate`, once, and
//! reports each of its stages as a check of its own, then the checks that
//! need more than the reader: whether the production validators ran (they
//! cannot, here) and whether the deployment profile is one for production.
//! It makes no network request, reads no environment variable and writes
//! nothing; the network checks ADR-0008 describes run only inside a gateway.
//!
//! Every check has a stable ID, a severity (`error` for a required check,
//! whose failure fails the doctor, `warning` for advice), a status of `pass`,
//! `warning`, `fail` or `skipped`, a reason code and a duration. `skipped`
//! never counts as `pass`: when the reader stopped before it could show a
//! stage clean on every file, that stage is `skipped` with
//! `doctor.incomplete` rather than `pass`. A reason is either a bundle
//! reader code or one of [`Reason`]; neither carries a value.

use std::{
    io::{self, Write},
    time::{Duration, Instant},
};

use gateway_config::bundle::{BundleDiagnostic, Code, Profile, ResourceDeclaration};
use serde::Serialize;

use crate::{
    cli::Invocation,
    diagnostic::{self, Diagnostic, Exit},
    report::{self, Format, Io, BUNDLE_REMEDIATION},
    validate::{self, BundleRead, BundleRecord},
};

/// Where `docs/ggctl.md` explains every check and reason.
const DOCTOR_REMEDIATION: &str = "docs/ggctl.md#doctor-checks";

/// A stage of the bundle reader, reported as one check.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Stage {
    Files,
    Syntax,
    Compatibility,
    Structure,
    References,
    Resources,
    Profile,
    UnreferencedEntries,
}

impl Stage {
    pub(crate) const ALL: [Self; 8] = [
        Self::Files,
        Self::Syntax,
        Self::Compatibility,
        Self::Structure,
        Self::References,
        Self::Resources,
        Self::Profile,
        Self::UnreferencedEntries,
    ];

    pub(crate) fn id(self) -> &'static str {
        match self {
            Self::Files => "bundle.files",
            Self::Syntax => "bundle.syntax",
            Self::Compatibility => "bundle.compatibility",
            Self::Structure => "bundle.structure",
            Self::References => "bundle.references",
            Self::Resources => "bundle.resources",
            Self::Profile => "bundle.profile",
            Self::UnreferencedEntries => "bundle.unreferenced_entries",
        }
    }

    fn required(self) -> bool {
        self != Self::UnreferencedEntries
    }

    /// The stage a reader code belongs to. Exhaustive on purpose: a new
    /// reader code cannot reach a report without being given a stage.
    pub(crate) fn of(code: Code) -> Self {
        match code {
            Code::RootUnavailable
            | Code::RootNotDirectory
            | Code::UnsafePermissions
            | Code::UntrustedOwner
            | Code::TooManyEntries
            | Code::ManifestMissing
            | Code::SymlinkForbidden
            | Code::NotRegularFile
            | Code::HardLinkForbidden
            | Code::FileTooLarge
            | Code::BundleTooLarge
            | Code::ReadFailed
            | Code::ChangedDuringRead
            | Code::AtomicWriterInvalid
            | Code::ByteOrderMark
            | Code::CarriageReturn
            | Code::NotUtf8 => Self::Files,
            Code::EmptyDocument
            | Code::TooDeep
            | Code::TooManyMembers
            | Code::TooManyElements
            | Code::TooManyNodes
            | Code::StringTooLong
            | Code::KeyTooLong
            | Code::NumberNotInteger
            | Code::IntegerOutOfRange
            | Code::ForbiddenCharacter
            | Code::JsonSyntax
            | Code::JsonDuplicateKey
            | Code::YamlSyntax
            | Code::YamlDuplicateKey
            | Code::AliasForbidden
            | Code::AnchorForbidden
            | Code::TagForbidden
            | Code::MergeKeyForbidden
            | Code::DirectiveForbidden
            | Code::MultipleDocuments
            | Code::ComplexKeyForbidden
            | Code::NonStringKey
            | Code::KeyMustBeQuoted
            | Code::AmbiguousScalar
            | Code::BlockScalarForbidden
            | Code::MultilineValueForbidden
            | Code::UnsupportedEscape
            | Code::TabForbidden
            | Code::BadIndentation
            | Code::EmptyValue => Self::Syntax,
            Code::UnsupportedApiVersion
            | Code::UnsupportedKind
            | Code::UnsupportedSchemaVersion
            | Code::SchemaVersionMismatch => Self::Compatibility,
            Code::UnknownMember
            | Code::MissingMember
            | Code::WrongType
            | Code::InvalidValue
            | Code::InvalidName
            | Code::InvalidDecimal
            | Code::InlineSecretValue
            | Code::InvalidSecretReference => Self::Structure,
            Code::FileMissing
            | Code::DigestMismatch
            | Code::InvalidPath
            | Code::ReservedPath
            | Code::DuplicatePath
            | Code::InvalidDigest
            | Code::SourceUnsupported
            | Code::Unresolved => Self::References,
            Code::ResourceUnknownMember | Code::ResourceInvalid => Self::Resources,
            Code::PolicyDefaultAllow | Code::PolicyShadowMode | Code::PolicyWildcardRole => {
                Self::Profile
            }
            Code::UnreferencedEntry => Self::UnreferencedEntries,
        }
    }
}

/// The checks that are not one stage of the reader.
pub(crate) const OTHER_CHECKS: &[&str] = &["resources.production_validators", "deployment.profile"];

/// A doctor reason that is not a bundle reader code. The string form is a
/// published contract, like a diagnostic code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Reason {
    Passed,
    Incomplete,
    ServerManaged,
    NotDeclared,
    ValidatorUnavailable,
    MigrationProfile,
    DevelopmentProfile,
}

impl Reason {
    #[cfg(test)]
    pub(crate) const ALL: &'static [Self] = &[
        Self::Passed,
        Self::Incomplete,
        Self::ServerManaged,
        Self::NotDeclared,
        Self::ValidatorUnavailable,
        Self::MigrationProfile,
        Self::DevelopmentProfile,
    ];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "doctor.passed",
            Self::Incomplete => "doctor.incomplete",
            Self::ServerManaged => "doctor.server_managed",
            Self::NotDeclared => "doctor.not_declared",
            Self::ValidatorUnavailable => "doctor.validator_unavailable",
            Self::MigrationProfile => "doctor.migration_profile",
            Self::DevelopmentProfile => "doctor.development_profile",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Status {
    Pass,
    Warning,
    Fail,
    Skipped,
}

impl Status {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Warning => "warning",
            Self::Fail => "fail",
            Self::Skipped => "skipped",
        }
    }
}

/// One check's result.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CheckRecord {
    pub(crate) id: &'static str,
    /// `error` for a required check, `warning` for advice.
    pub(crate) severity: &'static str,
    pub(crate) status: Status,
    /// A bundle reader code or a [`Reason`].
    pub(crate) reason: &'static str,
    pub(crate) remediation: &'static str,
    /// Checks drawn from the one reader run all report that run's duration.
    pub(crate) duration_ms: u64,
}

impl CheckRecord {
    fn new(
        id: &'static str,
        required: bool,
        status: Status,
        reason: Reason,
        took: Duration,
    ) -> Self {
        Self {
            id,
            severity: severity(required),
            status,
            reason: reason.as_str(),
            remediation: DOCTOR_REMEDIATION,
            duration_ms: milliseconds(took),
        }
    }

    /// A stage whose reason is the first reader diagnostic it found.
    fn found(stage: Stage, status: Status, diagnostic: &BundleDiagnostic, took: Duration) -> Self {
        Self {
            id: stage.id(),
            severity: severity(stage.required()),
            status,
            reason: diagnostic.code.as_str(),
            remediation: BUNDLE_REMEDIATION,
            duration_ms: milliseconds(took),
        }
    }

    fn failed_required(&self) -> bool {
        self.severity == "error" && self.status == Status::Fail
    }
}

fn severity(required: bool) -> &'static str {
    if required {
        "error"
    } else {
        "warning"
    }
}

fn milliseconds(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// Every check, in a fixed order: the reader's stages, then the others.
pub(crate) fn checks(read: &BundleRead, took: Duration) -> Vec<CheckRecord> {
    let mut checks: Vec<_> = Stage::ALL
        .iter()
        .map(|stage| stage_check(*stage, read, took))
        .collect();
    let started = Instant::now();
    let (status, reason) = match &read.manifest {
        None => (Status::Skipped, Reason::Incomplete),
        Some(_) if validate::supplies_a_resource(read) => {
            (Status::Skipped, Reason::ValidatorUnavailable)
        }
        Some(_) => (Status::Skipped, Reason::NotDeclared),
    };
    checks.push(CheckRecord::new(
        OTHER_CHECKS[0],
        true,
        status,
        reason,
        started.elapsed(),
    ));
    let started = Instant::now();
    let (status, reason) = match read.bundle.as_ref().map(|bundle| bundle.deployment.profile) {
        None => (Status::Skipped, Reason::Incomplete),
        Some(Profile::Production) => (Status::Pass, Reason::Passed),
        Some(Profile::Migration) => (Status::Warning, Reason::MigrationProfile),
        Some(Profile::Development) => (Status::Warning, Reason::DevelopmentProfile),
    };
    checks.push(CheckRecord::new(
        OTHER_CHECKS[1],
        false,
        status,
        reason,
        started.elapsed(),
    ));
    checks
}

fn stage_check(stage: Stage, read: &BundleRead, took: Duration) -> CheckRecord {
    let found: Vec<_> = read
        .diagnostics
        .iter()
        .filter(|diagnostic| Stage::of(diagnostic.code) == stage)
        .collect();
    if let Some(diagnostic) = found.iter().find(|diagnostic| diagnostic.is_error()) {
        return CheckRecord::found(stage, Status::Fail, diagnostic, took);
    }
    if let Some(diagnostic) = found.first() {
        return CheckRecord::found(stage, Status::Warning, diagnostic, took);
    }
    let declared_policy = read.manifest.as_ref().map(|manifest| &manifest.policy);
    let (status, reason) = match (stage, declared_policy) {
        // The profile's invariants are checked on a policy the bundle
        // supplies; one in the server's store is checked where it is.
        (Stage::Profile, Some(Some(ResourceDeclaration::Server))) => {
            (Status::Skipped, Reason::ServerManaged)
        }
        (Stage::Profile, Some(None)) => (Status::Skipped, Reason::NotDeclared),
        _ if read.bundle.is_some() => (Status::Pass, Reason::Passed),
        _ => (Status::Skipped, Reason::Incomplete),
    };
    CheckRecord::new(stage.id(), stage.required(), status, reason, took)
}

/// The `doctor` result.
#[derive(Debug, Serialize)]
struct DoctorResult {
    /// Present once the manifest was read.
    #[serde(skip_serializing_if = "Option::is_none")]
    bundle: Option<BundleRecord>,
    checks: Vec<CheckRecord>,
}

pub(crate) fn run(invocation: &Invocation, io: &mut Io<'_>) -> Exit {
    let started = Instant::now();
    let Some(read) = validate::read(invocation, false) else {
        return report::error(io, Diagnostic::new(diagnostic::Code::MissingArgument));
    };
    let checks = checks(&read, started.elapsed());
    let mut diagnostics = validate::diagnostics(&read);
    let failed = checks.iter().any(CheckRecord::failed_required);
    if failed {
        diagnostics.push(Diagnostic::new(diagnostic::Code::RequiredCheckFailed).into());
    }
    let result = DoctorResult {
        bundle: BundleRecord::of(&read),
        checks,
    };
    report::finish_report(
        io,
        Format::of(invocation),
        "doctor",
        &result,
        &diagnostics,
        |result, out| human(result, failed, out),
    )
}

fn human(result: &DoctorResult, failed: bool, out: &mut dyn Write) -> io::Result<()> {
    let title = result
        .bundle
        .as_ref()
        .map_or_else(|| "bundle".to_owned(), BundleRecord::title);
    writeln!(out, "{title}: offline checks")?;
    let width = result
        .checks
        .iter()
        .map(|check| check.id.len())
        .max()
        .unwrap_or(0);
    for check in &result.checks {
        writeln!(
            out,
            "  {:<7}  {:<width$}  {}",
            check.status.as_str(),
            check.id,
            check.reason
        )?;
    }
    if failed {
        writeln!(out, "a required check failed")
    } else {
        writeln!(out, "no required check failed")
    }
}

#[cfg(test)]
mod tests;
