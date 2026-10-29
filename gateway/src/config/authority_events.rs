//! Authority-event delivery settings (issue #425, PR 3), compiled in a pure
//! stage (issue #433, PR 2), and the required-evidence mode (issue #425, PR 4).
//!
//! Cluster mode journals every committed evidence row in its own transaction
//! whatever these say; they choose where the dispatcher delivers the journal,
//! the key its safe references are derived under, how much the journal may
//! hold, and how long delivered rows stay. Standalone mode has no journal and
//! no dispatcher, so every delivery setting here is refused there rather than
//! ignored.
//!
//! `AUTHORITY_EVIDENCE_DURABILITY` is read in both modes. Under `required` a
//! cluster replica must deliver what it journals, so a sink is mandatory; the
//! storage stage adds the rule that needs the admin session store, and the
//! changes refused at runtime are `authority_events::required`'s.
//!
//! One block, [`AuthorityEventInputs`], read right after PostgreSQL's. Which
//! rules apply depends on the state backend, so the storage stage compiles
//! the block once the backend is parsed, into the same findings as its own
//! rules: everything found here is reported before them, which is where the
//! legacy parser reported it. Nothing here opens the event file or resolves
//! a pseudonym key alias; the cluster wiring does both at startup.

use std::{env::VarError, fmt, str::FromStr, time::Duration};

use super::{
    blank_as_unset,
    diagnostic::ConfigRule,
    parse_optional_string, parse_var,
    stage::{Findings, Provenance, RawInput},
    validate_maximum_u64, validate_positive_bounded_u64, StateBackend, STATE_BACKEND,
};
use crate::connections::{model::MAX_SECRET_ID_BYTES, secret::is_valid_opaque_id};

pub(super) const AUTHORITY_EVIDENCE_DURABILITY: &str = "AUTHORITY_EVIDENCE_DURABILITY";
pub(super) const AUTHORITY_EVENT_SINK: &str = "AUTHORITY_EVENT_SINK";
pub(super) const AUTHORITY_EVENT_FILE: &str = "AUTHORITY_EVENT_FILE";
pub(super) const AUTHORITY_PSEUDONYM_KEY_ALIAS: &str = "AUTHORITY_PSEUDONYM_KEY_ALIAS";
pub(super) const AUTHORITY_PSEUDONYM_PREVIOUS_KEY_ALIAS: &str =
    "AUTHORITY_PSEUDONYM_PREVIOUS_KEY_ALIAS";
pub(super) const AUTHORITY_EVENT_JOURNAL_CAPACITY: &str = "AUTHORITY_EVENT_JOURNAL_CAPACITY";
pub(super) const AUTHORITY_EVENT_RETENTION_HOURS: &str = "AUTHORITY_EVENT_RETENTION_HOURS";

/// Retained journal rows, delivered or not, before authority mutations are
/// refused.
pub const DEFAULT_AUTHORITY_EVENT_JOURNAL_CAPACITY: u64 = 1_000_000;
pub const MAX_AUTHORITY_EVENT_JOURNAL_CAPACITY: u64 = 1_000_000_000;
/// How long a delivered row stays in the journal: a week, so a downstream
/// consumer that lost data can be replayed from the journal for that long.
pub const DEFAULT_AUTHORITY_EVENT_RETENTION_HOURS: u64 = 168;
/// Ten years.
pub const MAX_AUTHORITY_EVENT_RETENTION_HOURS: u64 = 87_600;

/// What the gateway requires of the evidence of an authority change
/// (`AUTHORITY_EVIDENCE_DURABILITY`, issue #425, PR 4).
///
/// `BestEffort`, the default, performs every change the configuration
/// enables and keeps whatever evidence its store records, which for some
/// changes is nothing durable. `Required` refuses every change the evidence
/// inventory says this deployment mode cannot record in the change's own
/// transaction -- at startup when the configuration itself enables it, and
/// otherwise when it is asked for -- and refuses a cluster replica that would
/// journal evidence without delivering it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AuthorityEvidenceDurability {
    #[default]
    BestEffort,
    Required,
}

impl AuthorityEvidenceDurability {
    /// The value as `AUTHORITY_EVIDENCE_DURABILITY` spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BestEffort => "best_effort",
            Self::Required => "required",
        }
    }
}

impl FromStr for AuthorityEvidenceDurability {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "required" => Ok(Self::Required),
            "best_effort" => Ok(Self::BestEffort),
            _ => Err("expected `required` or `best_effort`"),
        }
    }
}

/// Where delivered authority events go.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum AuthorityEventSinkSetting {
    /// No dispatcher runs. Events are still journaled and retained.
    #[default]
    None,
    /// One structured log line per event.
    Log,
    /// JSON lines appended to this file and synced per batch.
    File(String),
}

impl AuthorityEventSinkSetting {
    /// The sink's name, as `AUTHORITY_EVENT_SINK` spells it.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Log => "log",
            Self::File(_) => "file",
        }
    }
}

/// The validated settings. Defaults are standalone mode's: nothing to
/// deliver, and no change refused for its evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityEventSettings {
    /// Whether a change this deployment cannot evidence is refused.
    pub durability: AuthorityEvidenceDurability,
    pub sink: AuthorityEventSinkSetting,
    /// The secret alias of the current pseudonym key; required when a sink
    /// is configured.
    pub pseudonym_key_alias: Option<String>,
    /// The alias of the previous key during a rotation window.
    pub previous_pseudonym_key_alias: Option<String>,
    pub journal_capacity: u64,
    pub retention_hours: u64,
}

impl Default for AuthorityEventSettings {
    fn default() -> Self {
        Self {
            durability: AuthorityEvidenceDurability::BestEffort,
            sink: AuthorityEventSinkSetting::None,
            pseudonym_key_alias: None,
            previous_pseudonym_key_alias: None,
            journal_capacity: DEFAULT_AUTHORITY_EVENT_JOURNAL_CAPACITY,
            retention_hours: DEFAULT_AUTHORITY_EVENT_RETENTION_HOURS,
        }
    }
}

impl AuthorityEventSettings {
    /// How long a delivered row stays in the journal.
    #[cfg_attr(not(feature = "postgres"), allow(dead_code))] // read by the cluster wiring only
    pub fn retention(&self) -> Duration {
        Duration::from_secs(self.retention_hours.saturating_mul(3_600))
    }

    /// The configured pseudonym key aliases: the current one, then the
    /// previous one. No Connection may bind either.
    pub fn pseudonym_key_aliases(&self) -> impl Iterator<Item = &str> {
        self.pseudonym_key_alias
            .iter()
            .chain(self.previous_pseudonym_key_alias.iter())
            .map(String::as_str)
    }
}

/// The value vocabulary of `AUTHORITY_EVENT_SINK`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SinkKind {
    None,
    Log,
    File,
}

impl FromStr for SinkKind {
    type Err = UnknownSink;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim() {
            "none" => Ok(Self::None),
            "log" => Ok(Self::Log),
            "file" => Ok(Self::File),
            _ => Err(UnknownSink),
        }
    }
}

#[derive(Debug)]
struct UnknownSink;

impl fmt::Display for UnknownSink {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("expected one of none, log, file")
    }
}

/// The authority-event block's inputs, as the reader returned them.
pub(super) struct AuthorityEventInputs {
    durability: RawInput,
    sink: RawInput,
    file: RawInput,
    pseudonym_key_alias: RawInput,
    previous_pseudonym_key_alias: RawInput,
    journal_capacity: RawInput,
    retention_hours: RawInput,
}

impl AuthorityEventInputs {
    /// Requests every input of the block once, in the inventory's order.
    pub(super) fn read(mut get_var: impl FnMut(&str) -> Result<String, VarError>) -> Self {
        Self {
            durability: RawInput::new(
                AUTHORITY_EVIDENCE_DURABILITY,
                get_var(AUTHORITY_EVIDENCE_DURABILITY),
            ),
            sink: RawInput::new(AUTHORITY_EVENT_SINK, get_var(AUTHORITY_EVENT_SINK)),
            file: RawInput::new(AUTHORITY_EVENT_FILE, get_var(AUTHORITY_EVENT_FILE)),
            pseudonym_key_alias: RawInput::new(
                AUTHORITY_PSEUDONYM_KEY_ALIAS,
                get_var(AUTHORITY_PSEUDONYM_KEY_ALIAS),
            ),
            previous_pseudonym_key_alias: RawInput::new(
                AUTHORITY_PSEUDONYM_PREVIOUS_KEY_ALIAS,
                get_var(AUTHORITY_PSEUDONYM_PREVIOUS_KEY_ALIAS),
            ),
            journal_capacity: RawInput::new(
                AUTHORITY_EVENT_JOURNAL_CAPACITY,
                get_var(AUTHORITY_EVENT_JOURNAL_CAPACITY),
            ),
            retention_hours: RawInput::new(
                AUTHORITY_EVENT_RETENTION_HOURS,
                get_var(AUTHORITY_EVENT_RETENTION_HOURS),
            ),
        }
    }

    pub(super) fn provenance(&self) -> Vec<Provenance> {
        [
            &self.durability,
            &self.sink,
            &self.file,
            &self.pseudonym_key_alias,
            &self.previous_pseudonym_key_alias,
            &self.journal_capacity,
            &self.retention_hours,
        ]
        .into_iter()
        .map(RawInput::provenance)
        .collect()
    }
}

/// Parses every input of the block, then checks the rules between them and
/// the state backend, recording each problem in `findings`.
///
/// Each value is refused on its own once it is read. The alias shapes and
/// every rule are reported once the block's last input is read, in the order
/// below; the storage stage records its own rules after them.
pub(super) fn compile(
    inputs: &AuthorityEventInputs,
    state_backend: StateBackend,
    findings: &mut Findings,
) -> AuthorityEventSettings {
    // Like `AUDIT_DURABILITY`, a blank value is refused rather than read as
    // the weaker default.
    let durability = findings.input(AUTHORITY_EVIDENCE_DURABILITY, |problems| {
        parse_var(
            AUTHORITY_EVIDENCE_DURABILITY,
            inputs.durability.value(),
            AuthorityEvidenceDurability::BestEffort,
            "authority evidence durability mode",
            problems,
        )
    });
    // Set means set to anything but whitespace. A value that is not Unicode
    // is refused as a value, and is not also reported as material the
    // backend never reads.
    let sink_raw = blank_as_unset(inputs.sink.value());
    let sink_set = sink_raw.is_ok();
    let sink_kind = findings.input(AUTHORITY_EVENT_SINK, |problems| {
        parse_var(
            AUTHORITY_EVENT_SINK,
            sink_raw,
            SinkKind::None,
            "authority event sink",
            problems,
        )
    });
    let file = findings.input(AUTHORITY_EVENT_FILE, |problems| {
        parse_optional_string(AUTHORITY_EVENT_FILE, inputs.file.value(), problems)
    });
    let key = findings.input(AUTHORITY_PSEUDONYM_KEY_ALIAS, |problems| {
        parse_optional_string(
            AUTHORITY_PSEUDONYM_KEY_ALIAS,
            inputs.pseudonym_key_alias.value(),
            problems,
        )
    });
    let previous = findings.input(AUTHORITY_PSEUDONYM_PREVIOUS_KEY_ALIAS, |problems| {
        parse_optional_string(
            AUTHORITY_PSEUDONYM_PREVIOUS_KEY_ALIAS,
            inputs.previous_pseudonym_key_alias.value(),
            problems,
        )
    });
    let capacity_raw = blank_as_unset(inputs.journal_capacity.value());
    let capacity_set = capacity_raw.is_ok();
    let journal_capacity = findings.input(AUTHORITY_EVENT_JOURNAL_CAPACITY, |problems| {
        validate_positive_bounded_u64(
            AUTHORITY_EVENT_JOURNAL_CAPACITY,
            parse_var(
                AUTHORITY_EVENT_JOURNAL_CAPACITY,
                capacity_raw,
                DEFAULT_AUTHORITY_EVENT_JOURNAL_CAPACITY,
                "event count",
                problems,
            ),
            MAX_AUTHORITY_EVENT_JOURNAL_CAPACITY,
            DEFAULT_AUTHORITY_EVENT_JOURNAL_CAPACITY,
            problems,
        )
    });
    let retention_raw = blank_as_unset(inputs.retention_hours.value());
    let retention_set = retention_raw.is_ok();
    let retention_hours = findings.input(AUTHORITY_EVENT_RETENTION_HOURS, |problems| {
        validate_maximum_u64(
            AUTHORITY_EVENT_RETENTION_HOURS,
            parse_var(
                AUTHORITY_EVENT_RETENTION_HOURS,
                retention_raw,
                DEFAULT_AUTHORITY_EVENT_RETENTION_HOURS,
                "hour count",
                problems,
            ),
            MAX_AUTHORITY_EVENT_RETENTION_HOURS,
            DEFAULT_AUTHORITY_EVENT_RETENTION_HOURS,
            problems,
        )
    });

    // Every check below is reported once the block's last input is read.
    let after = AUTHORITY_EVENT_RETENTION_HOURS;

    // An alias's shape is a property of its own value, but the legacy parser
    // checks it once the whole block is read, so it is reported there.
    for (name, alias) in [
        (AUTHORITY_PSEUDONYM_KEY_ALIAS, key.as_deref()),
        (AUTHORITY_PSEUDONYM_PREVIOUS_KEY_ALIAS, previous.as_deref()),
    ] {
        if alias.is_some_and(|alias| !is_valid_opaque_id(alias, MAX_SECRET_ID_BYTES)) {
            findings.refuse(
                after,
                ConfigRule::Value,
                format!(
                    "{name} must be a secret alias ID of 1 to {MAX_SECRET_ID_BYTES} letters, digits, '.', '_' or '-', starting with a letter or digit; it names the key, never its material"
                ),
            );
        }
    }

    match state_backend {
        StateBackend::Sqlite => {
            for (name, set) in [
                (AUTHORITY_EVENT_SINK, sink_set),
                (AUTHORITY_EVENT_FILE, file.is_some()),
                (AUTHORITY_PSEUDONYM_KEY_ALIAS, key.is_some()),
                (AUTHORITY_PSEUDONYM_PREVIOUS_KEY_ALIAS, previous.is_some()),
                (AUTHORITY_EVENT_JOURNAL_CAPACITY, capacity_set),
                (AUTHORITY_EVENT_RETENTION_HOURS, retention_set),
            ] {
                if set {
                    findings.refuse(
                        after,
                        ConfigRule::ClusterSettingInStandaloneMode,
                        format!(
                            "{name} is set while {STATE_BACKEND} is sqlite; standalone mode has no authority-event journal or dispatcher and never reads it"
                        ),
                    );
                }
            }
        }
        StateBackend::Postgres => {
            match sink_kind {
                SinkKind::None => {
                    for (name, set) in [
                        (AUTHORITY_EVENT_FILE, file.is_some()),
                        (AUTHORITY_PSEUDONYM_KEY_ALIAS, key.is_some()),
                        (AUTHORITY_PSEUDONYM_PREVIOUS_KEY_ALIAS, previous.is_some()),
                    ] {
                        if set {
                            findings.refuse(
                                after,
                                ConfigRule::AuthorityEventMaterialUnused,
                                format!(
                                    "{name} is set while {AUTHORITY_EVENT_SINK} is none; no dispatcher runs and nothing reads it"
                                ),
                            );
                        }
                    }
                }
                SinkKind::Log | SinkKind::File => {
                    if key.is_none() {
                        findings.refuse(
                            after,
                            ConfigRule::AuthorityEventSinkRequirements,
                            format!(
                                "{AUTHORITY_PSEUDONYM_KEY_ALIAS} is required when {AUTHORITY_EVENT_SINK} is set; delivered events name every actor and resource by a reference keyed under it, and there is no unkeyed mode"
                            ),
                        );
                    }
                }
            }
            if sink_kind == SinkKind::File && file.is_none() {
                findings.refuse(
                    after,
                    ConfigRule::AuthorityEventSinkRequirements,
                    format!("{AUTHORITY_EVENT_FILE} is required when {AUTHORITY_EVENT_SINK}=file"),
                );
            }
            if sink_kind == SinkKind::Log && file.is_some() {
                findings.refuse(
                    after,
                    ConfigRule::AuthorityEventMaterialUnused,
                    format!(
                        "{AUTHORITY_EVENT_FILE} is set while {AUTHORITY_EVENT_SINK}=log; only the file sink writes a file"
                    ),
                );
            }
            if key.is_some() && key == previous {
                findings.refuse(
                    after,
                    ConfigRule::AuthorityPseudonymKeysDistinct,
                    format!(
                        "{AUTHORITY_PSEUDONYM_KEY_ALIAS} and {AUTHORITY_PSEUDONYM_PREVIOUS_KEY_ALIAS} must name different aliases"
                    ),
                );
            }
            // Every change this replica journals is evidence the deployment
            // undertook to deliver. With no sink no dispatcher runs and the
            // journal only retains it. A configured sink's own requirements
            // are the rules above.
            if durability == AuthorityEvidenceDurability::Required && sink_kind == SinkKind::None {
                findings.refuse(
                    after,
                    ConfigRule::AuthorityEvidenceDeliveryRequired,
                    format!(
                        "{AUTHORITY_EVIDENCE_DURABILITY}=required needs {AUTHORITY_EVENT_SINK}=log or file when {STATE_BACKEND}=postgres; with none, the authority evidence this replica journals is retained but never delivered"
                    ),
                );
            }
        }
    }

    let sink = match sink_kind {
        SinkKind::None => AuthorityEventSinkSetting::None,
        SinkKind::Log => AuthorityEventSinkSetting::Log,
        SinkKind::File => AuthorityEventSinkSetting::File(file.unwrap_or_default()),
    };
    AuthorityEventSettings {
        durability,
        sink,
        pseudonym_key_alias: key,
        previous_pseudonym_key_alias: previous,
        journal_capacity,
        retention_hours,
    }
}
