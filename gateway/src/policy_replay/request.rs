//! The `policy-replay.v1` request that starts a replay job: strict members,
//! exact version dispatch, and structured, value-free diagnostics.
//!
//! ```json
//! {
//!   "schema_version": "policy-replay.v1",
//!   "base_etag": "\"sha256:...\"",
//!   "candidate": { "source": "edits", "edits": [ ... ] },
//!   "window": { "from": "2026-10-27T00:00:00Z", "to": "2026-10-28T00:00:00Z" },
//!   "max_records": 50000,
//!   "idempotency_key": "nightly"
//! }
//! ```
//!
//! `base_etag` pins the active policy the request was written against, as a
//! simulation's does, and `candidate` takes the simulation's three sources
//! with the same members ([`parse_candidate`]). The window is a half-open
//! `[from, to)` interval of audit timestamps; `to` defaults to the moment the
//! job is created. Its bounds against the clock are checked when the job is
//! created ([`resolve_window`]), since only then is "now" known.

use serde_json::Value;
use time::{format_description::well_known::Rfc3339, Duration, OffsetDateTime, UtcOffset};

use super::job::MAX_REPLAY_RECORDS;
use crate::{
    canonical_json,
    policy_simulation::request::{parse_candidate, CandidateSource, MAX_BASE_ETAG_BYTES},
    policy_testing::suite::{
        bounded_string, check_members, object, required, Diagnostics, MAX_DESCRIPTION_BYTES,
    },
};

/// The only request schema this module implements.
pub(crate) const REPLAY_SCHEMA_VERSION: &str = "policy-replay.v1";
/// The media type the request digest is framed with.
pub(crate) const REPLAY_MEDIA_TYPE: &str = "application/vnd.greengateway.policy-replay+json";
/// The longest window one job may cover.
pub(crate) const MAX_REPLAY_WINDOW: Duration = Duration::days(31);
/// Longest idempotency key, in bytes.
pub(crate) const MAX_IDEMPOTENCY_KEY_BYTES: usize = 128;
/// Longest window bound accepted, in bytes: well beyond any RFC 3339 time.
const MAX_TIMESTAMP_BYTES: usize = 64;

/// An accepted request. Only [`parse_request`] builds one.
///
/// It does not derive `Debug`: an inline candidate holds a policy, which
/// does not belong in a log line.
pub(crate) struct ReplayRequest {
    /// The ADR-0004 source digest of the exact request bytes.
    pub(crate) digest: String,
    pub(crate) base_etag: String,
    pub(crate) candidate: CandidateSource,
    pub(crate) from: OffsetDateTime,
    /// `None` when the window ends when the job is created.
    pub(crate) to: Option<OffsetDateTime>,
    pub(crate) max_records: usize,
    pub(crate) idempotency_key: Option<String>,
}

/// A window resolved against the job's creation time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ResolvedWindow {
    /// RFC 3339 in UTC, as the job states it.
    pub(crate) from: String,
    pub(crate) to: String,
    /// Audit epoch microseconds, `[from, to)`.
    pub(crate) from_epoch_us: i64,
    pub(crate) to_epoch_us: i64,
}

/// Parse and validate a request body already read as `value` from `bytes`,
/// or say every reason it is refused.
pub(crate) fn parse_request(bytes: &[u8], value: &Value) -> Result<ReplayRequest, Diagnostics> {
    let mut diagnostics = Diagnostics::new();
    let Some(root) = object(value, "", &mut diagnostics) else {
        return Err(diagnostics);
    };
    check_members(
        root,
        "",
        &[
            "schema_version",
            "description",
            "base_etag",
            "candidate",
            "window",
            "max_records",
            "idempotency_key",
        ],
        &mut diagnostics,
    );
    match root.get("schema_version") {
        None => diagnostics.push(
            "missing_field",
            "/schema_version",
            "schema_version is required",
        ),
        Some(Value::String(version)) if version == REPLAY_SCHEMA_VERSION => {}
        Some(_) => {
            // Refuse before reading anything else: a different version may
            // give the same members a different meaning.
            diagnostics.push(
                "unsupported_schema_version",
                "/schema_version",
                format!("schema_version must be exactly \"{REPLAY_SCHEMA_VERSION}\""),
            );
            return Err(diagnostics);
        }
    }
    if let Some(description) = root.get("description") {
        bounded_string(
            description,
            "/description",
            MAX_DESCRIPTION_BYTES,
            &mut diagnostics,
        );
    }
    let base_etag = required(root, "base_etag", "", &mut diagnostics).and_then(|value| {
        bounded_string(value, "/base_etag", MAX_BASE_ETAG_BYTES, &mut diagnostics)
    });
    let candidate = required(root, "candidate", "", &mut diagnostics)
        .and_then(|value| parse_candidate(bytes, value, &mut diagnostics));
    let window = required(root, "window", "", &mut diagnostics)
        .and_then(|value| parse_window(value, &mut diagnostics));
    let max_records = match root.get("max_records") {
        None => Some(MAX_REPLAY_RECORDS),
        Some(value) => {
            let bound = value
                .as_u64()
                .and_then(|records| usize::try_from(records).ok())
                .filter(|records| (1..=MAX_REPLAY_RECORDS).contains(records));
            if bound.is_none() {
                diagnostics.push(
                    "invalid_value",
                    "/max_records",
                    format!("max_records must be an integer from 1 to {MAX_REPLAY_RECORDS}"),
                );
            }
            bound
        }
    };
    let idempotency_key = match root.get("idempotency_key") {
        None => Some(None),
        Some(value) => parse_idempotency_key(value, &mut diagnostics).map(Some),
    };
    if !diagnostics.is_empty() {
        return Err(diagnostics);
    }
    match (base_etag, candidate, window, max_records, idempotency_key) {
        (
            Some(base_etag),
            Some(candidate),
            Some((from, to)),
            Some(max_records),
            Some(idempotency_key),
        ) => Ok(ReplayRequest {
            digest: canonical_json::source_digest(REPLAY_MEDIA_TYPE, REPLAY_SCHEMA_VERSION, bytes),
            base_etag,
            candidate,
            from,
            to,
            max_records,
            idempotency_key,
        }),
        // Every arm that yields `None` above records why; refused rather
        // than defaulted if one ever does not.
        _ => {
            diagnostics.push("invalid_request", "", "the replay request is incomplete");
            Err(diagnostics)
        }
    }
}

fn parse_timestamp(
    value: &Value,
    pointer: &str,
    diagnostics: &mut Diagnostics,
) -> Option<OffsetDateTime> {
    let text = bounded_string(value, pointer, MAX_TIMESTAMP_BYTES, diagnostics)?;
    match OffsetDateTime::parse(&text, &Rfc3339) {
        Ok(time) => Some(time),
        Err(_) => {
            diagnostics.push(
                "invalid_value",
                pointer,
                "must be an RFC 3339 date-time with an offset",
            );
            None
        }
    }
}

fn parse_window(
    value: &Value,
    diagnostics: &mut Diagnostics,
) -> Option<(OffsetDateTime, Option<OffsetDateTime>)> {
    let map = object(value, "/window", diagnostics)?;
    check_members(map, "/window", &["from", "to"], diagnostics);
    let from = required(map, "from", "/window", diagnostics)
        .and_then(|value| parse_timestamp(value, "/window/from", diagnostics));
    let to = match map.get("to") {
        None => Some(None),
        Some(value) => parse_timestamp(value, "/window/to", diagnostics).map(Some),
    };
    Some((from?, to?))
}

/// An idempotency key: 1 to [`MAX_IDEMPOTENCY_KEY_BYTES`] bytes of ASCII
/// letters, digits, `.`, `_`, `:` and `-`. A key is an identifier the caller
/// chose, never a value from traffic, so it has no room for anything else.
fn parse_idempotency_key(value: &Value, diagnostics: &mut Diagnostics) -> Option<String> {
    let key = bounded_string(
        value,
        "/idempotency_key",
        MAX_IDEMPOTENCY_KEY_BYTES,
        diagnostics,
    )?;
    if !key
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        diagnostics.push(
            "invalid_value",
            "/idempotency_key",
            "an idempotency key is ASCII letters, digits, '.', '_', ':' and '-'",
        );
        return None;
    }
    Some(key)
}

fn epoch_micros(time: OffsetDateTime) -> Option<i64> {
    i64::try_from(time.unix_timestamp_nanos() / 1_000).ok()
}

/// The request's window, closed against `now`, the job's creation time: `to`
/// defaults to `now`, may not be later, must follow `from`, and the window
/// may cover at most [`MAX_REPLAY_WINDOW`].
pub(crate) fn resolve_window(
    request: &ReplayRequest,
    now: OffsetDateTime,
) -> Result<ResolvedWindow, Diagnostics> {
    let mut diagnostics = Diagnostics::new();
    let from = request.from.to_offset(UtcOffset::UTC);
    let to = request.to.unwrap_or(now).to_offset(UtcOffset::UTC);
    if to > now {
        diagnostics.push(
            "window_in_future",
            "/window/to",
            "a replay reads records already stored; the window may not end after the job is created",
        );
    }
    if from >= to {
        diagnostics.push(
            "empty_window",
            "/window/from",
            "the window must begin before it ends",
        );
    } else if to - from > MAX_REPLAY_WINDOW {
        diagnostics.push(
            "window_too_long",
            "/window",
            format!(
                "a replay window may cover at most {} days",
                MAX_REPLAY_WINDOW.whole_days()
            ),
        );
    }
    if !diagnostics.is_empty() {
        return Err(diagnostics);
    }
    match (
        from.format(&Rfc3339),
        to.format(&Rfc3339),
        epoch_micros(from),
        epoch_micros(to),
    ) {
        (Ok(from_text), Ok(to_text), Some(from_epoch_us), Some(to_epoch_us)) => {
            Ok(ResolvedWindow {
                from: from_text,
                to: to_text,
                from_epoch_us,
                to_epoch_us,
            })
        }
        _ => {
            diagnostics.push(
                "invalid_value",
                "/window",
                "the window cannot be represented as audit timestamps",
            );
            Err(diagnostics)
        }
    }
}
