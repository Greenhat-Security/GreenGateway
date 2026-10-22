//! Authority-event delivery settings (issue #425, PR 3).
//!
//! Cluster mode journals every committed evidence row in its own transaction
//! whatever these say; they choose where the dispatcher delivers the journal,
//! the key its safe references are derived under, how much the journal may
//! hold, and how long delivered rows stay. Standalone mode has no journal and
//! no dispatcher, so every setting here is refused there rather than ignored.

use std::{env::VarError, fmt, str::FromStr, time::Duration};

use super::{
    blank_as_unset, parse_optional_string, parse_var, validate_maximum_u64,
    validate_positive_bounded_u64, StateBackend, STATE_BACKEND,
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

/// Read and validate the settings, in the order `CONFIG_INPUTS` lists them.
pub(super) fn parse(
    get_var: &mut impl FnMut(&str) -> Result<String, VarError>,
    state_backend: StateBackend,
    problems: &mut Vec<String>,
) -> AuthorityEventSettings {
    let sink_raw = blank_as_unset(get_var(AUTHORITY_EVENT_SINK));
    let sink_set = sink_raw.is_ok();
    let sink_kind = parse_var(
        AUTHORITY_EVENT_SINK,
        sink_raw,
        SinkKind::None,
        "authority event sink",
        problems,
    );
    let file = parse_optional_string(
        AUTHORITY_EVENT_FILE,
        get_var(AUTHORITY_EVENT_FILE),
        problems,
    );
    let key = parse_optional_string(
        AUTHORITY_PSEUDONYM_KEY_ALIAS,
        get_var(AUTHORITY_PSEUDONYM_KEY_ALIAS),
        problems,
    );
    let previous = parse_optional_string(
        AUTHORITY_PSEUDONYM_PREVIOUS_KEY_ALIAS,
        get_var(AUTHORITY_PSEUDONYM_PREVIOUS_KEY_ALIAS),
        problems,
    );
    let capacity_raw = blank_as_unset(get_var(AUTHORITY_EVENT_JOURNAL_CAPACITY));
    let capacity_set = capacity_raw.is_ok();
    let journal_capacity = validate_positive_bounded_u64(
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
    );
    let retention_raw = blank_as_unset(get_var(AUTHORITY_EVENT_RETENTION_HOURS));
    let retention_set = retention_raw.is_ok();
    let retention_hours = validate_maximum_u64(
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
    );

    for (name, alias) in [
        (AUTHORITY_PSEUDONYM_KEY_ALIAS, key.as_deref()),
        (AUTHORITY_PSEUDONYM_PREVIOUS_KEY_ALIAS, previous.as_deref()),
    ] {
        if alias.is_some_and(|alias| !is_valid_opaque_id(alias, MAX_SECRET_ID_BYTES)) {
            problems.push(format!(
                "{name} must be a secret alias ID of 1 to {MAX_SECRET_ID_BYTES} letters, digits, '.', '_' or '-', starting with a letter or digit; it names the key, never its material"
            ));
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
                    problems.push(format!(
                        "{name} is set while {STATE_BACKEND} is sqlite; standalone mode has no authority-event journal or dispatcher and never reads it"
                    ));
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
                            problems.push(format!(
                                "{name} is set while {AUTHORITY_EVENT_SINK} is none; no dispatcher runs and nothing reads it"
                            ));
                        }
                    }
                }
                SinkKind::Log | SinkKind::File => {
                    if key.is_none() {
                        problems.push(format!(
                            "{AUTHORITY_PSEUDONYM_KEY_ALIAS} is required when {AUTHORITY_EVENT_SINK} is set; delivered events name every actor and resource by a reference keyed under it, and there is no unkeyed mode"
                        ));
                    }
                }
            }
            if sink_kind == SinkKind::File && file.is_none() {
                problems.push(format!(
                    "{AUTHORITY_EVENT_FILE} is required when {AUTHORITY_EVENT_SINK}=file"
                ));
            }
            if sink_kind == SinkKind::Log && file.is_some() {
                problems.push(format!(
                    "{AUTHORITY_EVENT_FILE} is set while {AUTHORITY_EVENT_SINK}=log; only the file sink writes a file"
                ));
            }
            if key.is_some() && key == previous {
                problems.push(format!(
                    "{AUTHORITY_PSEUDONYM_KEY_ALIAS} and {AUTHORITY_PSEUDONYM_PREVIOUS_KEY_ALIAS} must name different aliases"
                ));
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
