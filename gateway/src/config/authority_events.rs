//! Authority-event delivery settings (issue #425, PR 3).
//!
//! Cluster mode journals every committed evidence row in its own transaction
//! whatever these say; they choose where the dispatcher delivers the journal,
//! the key its safe references are derived under, how much the journal may
//! hold, and how long delivered rows stay. Standalone mode has no journal and
//! no dispatcher, so every setting here is refused there rather than ignored.

use std::{env::VarError, fmt, str::FromStr, time::Duration};

use super::{
    blank_as_unset,
    diagnostic::ConfigRule,
    parse_optional_string, parse_var,
    stage::{Findings, Provenance, RawInput},
    validate_maximum_u64, validate_positive_bounded_u64, StateBackend, STATE_BACKEND,
};
use crate::connections::{model::MAX_SECRET_ID_BYTES, secret::is_valid_opaque_id};

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
/// deliver.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityEventSettings {
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

/// The block's inputs, each read once. They are the last inputs the
/// configuration reads, right after the PostgreSQL settings.
pub(super) struct AuthorityEventInputs {
    sink: RawInput,
    file: RawInput,
    key: RawInput,
    previous: RawInput,
    capacity: RawInput,
    retention: RawInput,
}

impl AuthorityEventInputs {
    /// Requests every input of the block once, in the order `CONFIG_INPUTS`
    /// lists them.
    pub(super) fn read(get_var: &mut impl FnMut(&str) -> Result<String, VarError>) -> Self {
        Self {
            sink: RawInput::new(AUTHORITY_EVENT_SINK, get_var(AUTHORITY_EVENT_SINK)),
            file: RawInput::new(AUTHORITY_EVENT_FILE, get_var(AUTHORITY_EVENT_FILE)),
            key: RawInput::new(
                AUTHORITY_PSEUDONYM_KEY_ALIAS,
                get_var(AUTHORITY_PSEUDONYM_KEY_ALIAS),
            ),
            previous: RawInput::new(
                AUTHORITY_PSEUDONYM_PREVIOUS_KEY_ALIAS,
                get_var(AUTHORITY_PSEUDONYM_PREVIOUS_KEY_ALIAS),
            ),
            capacity: RawInput::new(
                AUTHORITY_EVENT_JOURNAL_CAPACITY,
                get_var(AUTHORITY_EVENT_JOURNAL_CAPACITY),
            ),
            retention: RawInput::new(
                AUTHORITY_EVENT_RETENTION_HOURS,
                get_var(AUTHORITY_EVENT_RETENTION_HOURS),
            ),
        }
    }

    pub(super) fn provenance(&self) -> Vec<Provenance> {
        [
            &self.sink,
            &self.file,
            &self.key,
            &self.previous,
            &self.capacity,
            &self.retention,
        ]
        .into_iter()
        .map(RawInput::provenance)
        .collect()
    }
}

/// Parses the block's inputs and checks its rules against the state
/// backend.
///
/// Each input's own refusal is placed after that input, and every check
/// that follows after the block's last input, in the order they are found.
/// That is where, and in which order, the legacy parser reported them:
/// ahead of the cluster-mode rules the storage stage checks once every
/// input is read.
pub(super) fn compile(
    inputs: &AuthorityEventInputs,
    state_backend: StateBackend,
    findings: &mut Findings,
) -> AuthorityEventSettings {
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
        parse_optional_string(AUTHORITY_PSEUDONYM_KEY_ALIAS, inputs.key.value(), problems)
    });
    let previous = findings.input(AUTHORITY_PSEUDONYM_PREVIOUS_KEY_ALIAS, |problems| {
        parse_optional_string(
            AUTHORITY_PSEUDONYM_PREVIOUS_KEY_ALIAS,
            inputs.previous.value(),
            problems,
        )
    });
    let capacity_raw = blank_as_unset(inputs.capacity.value());
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
    let retention_raw = blank_as_unset(inputs.retention.value());
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
                                ConfigRule::AuthorityEventDelivery,
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
                            ConfigRule::AuthorityEventDelivery,
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
                    ConfigRule::AuthorityEventDelivery,
                    format!("{AUTHORITY_EVENT_FILE} is required when {AUTHORITY_EVENT_SINK}=file"),
                );
            }
            if sink_kind == SinkKind::Log && file.is_some() {
                findings.refuse(
                    after,
                    ConfigRule::AuthorityEventDelivery,
                    format!(
                        "{AUTHORITY_EVENT_FILE} is set while {AUTHORITY_EVENT_SINK}=log; only the file sink writes a file"
                    ),
                );
            }
            if key.is_some() && key == previous {
                findings.refuse(
                    after,
                    ConfigRule::AuthorityEventDelivery,
                    format!(
                        "{AUTHORITY_PSEUDONYM_KEY_ALIAS} and {AUTHORITY_PSEUDONYM_PREVIOUS_KEY_ALIAS} must name different aliases"
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
        sink,
        pseudonym_key_alias: key,
        previous_pseudonym_key_alias: previous,
        journal_capacity,
        retention_hours,
    }
}
