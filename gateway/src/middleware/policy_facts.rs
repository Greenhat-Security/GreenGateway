//! The typed-matcher facts a serving lane captures (issue #243).
//!
//! A policy v1 rule may carry conditions over the principal's verified
//! organization, the canonical client address, named request headers and
//! query parameters, and the evaluation instant. The shared evaluator reads
//! them from [`PolicyFacts`]; this module is the one place a live lane builds
//! that value, so the HTTP stage and the tool lanes cannot capture the same
//! fact two ways.
//!
//! What it captures is exactly what the compiled policy reads
//! ([`CompiledPolicy::fact_needs`]) and nothing else. A policy with neither
//! identity mappings nor conditions gets no fact at all, without an
//! allocation, so it decides and binds exactly as one did before conditions
//! were served. For the rest:
//!
//! - **Organization**: from the authenticated principal only
//!   ([`CompiledPolicy::serving_facts`]), never from a header.
//! - **Source address**: the canonical client address under the gateway's
//!   [`ClientIpPolicy`], the address audit records. A forwarding header counts
//!   only when the connection peer is a configured trusted proxy; raw
//!   `X-Forwarded-For` is never read. A request with no connection peer has
//!   no address, so a `source_network` leaf is undetermined rather than
//!   guessed.
//! - **Headers**: only the names a `header` leaf reads, every occurrence of
//!   each in the order received, each field line whole (a comma-separated
//!   line is one value). A value that is not UTF-8 is carried lossily: it
//!   still counts as an occurrence and can never equal an authored value,
//!   which is visible ASCII.
//! - **Query**: the whole query is decoded strictly (see [`decode_component`]),
//!   and only the parameters a `query` leaf reads are kept, every occurrence
//!   in request order. A query that does not decode strictly is refused
//!   ([`FactsRefusal::QueryUndecodable`]): a parameter the gateway cannot
//!   read the way an upstream would is not one it may decide on.
//! - **Instant**: whole seconds since the Unix epoch from the [`PolicyClock`]
//!   the state carries -- the system clock in production, a fixed one in
//!   tests.
//! - **Tool arguments**: only on tool invocation admission, only once the
//!   call's arguments have passed the tool's input schema, and only the
//!   scalars at the pointers the tool's rules read, each of which the schema
//!   must make eligible ([`tool_argument_facts`]). No other lane, and no
//!   listing or inventory preview, ever has a call's arguments.
//!
//! Headers and query parameters are bounded by the evaluator's own fact
//! bounds before they are copied; past them the request is refused
//! ([`FactsRefusal::TooLarge`]), never truncated, since a dropped occurrence
//! could turn a `not` into a match. No value captured here is logged, audited
//! or returned: the facts live for one evaluation.

#[cfg(test)]
use std::sync::{
    atomic::{AtomicI64, Ordering},
    Arc,
};
use std::{
    borrow::Cow,
    net::IpAddr,
    time::{SystemTime, UNIX_EPOCH},
};

use http::{Extensions, HeaderMap, Uri};
use serde_json::Value;

use crate::{
    auth::Principal,
    client_ip::{canonical_client_addr, ClientIpPolicy},
    policy_eval::{
        CompiledPolicy, Fact, PolicyFacts, MAX_FACT_ENTRIES, MAX_FACT_NAME_BYTES,
        MAX_FACT_VALUE_BYTES,
    },
    rbac::conditions::{referenced_tool_arguments, tool_argument_pointer_eligible},
};

/// The clock a `time_window` condition is judged by on the serving lanes.
///
/// Injected into the RBAC state rather than read wherever a decision is made,
/// so a test can stand at either side of a window's boundary. Simulations and
/// test runs never read it: a synthetic case states its instant.
#[derive(Clone, Debug, Default)]
pub(crate) enum PolicyClock {
    /// The system clock.
    #[default]
    System,
    /// A clock that reads what the test last set.
    #[cfg(test)]
    Fixed(Arc<AtomicI64>),
}

impl PolicyClock {
    /// A test clock reading `now`, in whole seconds since the Unix epoch.
    #[cfg(test)]
    pub(crate) fn fixed(now: i64) -> Self {
        Self::Fixed(Arc::new(AtomicI64::new(now)))
    }

    /// Move a test clock, and every state sharing it, to `now`.
    #[cfg(test)]
    pub(crate) fn set(&self, now: i64) {
        if let Self::Fixed(clock) = self {
            clock.store(now, Ordering::SeqCst);
        }
    }

    /// Whole seconds since the Unix epoch, rounded down. Window boundaries
    /// are whole seconds, so rounding down decides `[from, until)` exactly.
    /// `None` when the system clock reads before the epoch or beyond what the
    /// evaluator's instant holds: a window is then undetermined, never
    /// guessed open or shut.
    pub(crate) fn now(&self) -> Option<i64> {
        match self {
            Self::System => SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()
                .and_then(|elapsed| i64::try_from(elapsed.as_secs()).ok()),
            #[cfg(test)]
            Self::Fixed(clock) => Some(clock.load(Ordering::SeqCst)),
        }
    }
}

/// Why a request's facts were not captured. Each is a refusal on the lane
/// that asked, never a default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FactsRefusal {
    /// The query does not decode strictly: a malformed percent-escape, a
    /// decoded byte sequence that is not UTF-8, or a decoded control
    /// character.
    QueryUndecodable,
    /// The referenced headers or query parameters exceed the evaluator's fact
    /// bounds: more than [`MAX_FACT_ENTRIES`] occurrences, or one longer than
    /// [`MAX_FACT_VALUE_BYTES`].
    TooLarge,
}

/// The facts the HTTP stage evaluates a request with: the principal's, and
/// the request facts the compiled policy reads.
pub(crate) fn http_request_facts(
    compiled: &CompiledPolicy,
    principal: Option<&Principal>,
    headers: &HeaderMap,
    uri: &Uri,
    extensions: &Extensions,
    client_ip_policy: &ClientIpPolicy,
    clock: &PolicyClock,
) -> Result<PolicyFacts, FactsRefusal> {
    let mut facts = compiled.serving_facts(principal);
    let needs = compiled.fact_needs();
    if !needs.reads_request_facts() {
        return Ok(facts);
    }
    if needs.source_ip {
        facts.source_ip = captured(canonical_client_addr(headers, extensions, client_ip_policy));
    }
    if !needs.headers.is_empty() {
        facts.headers = Fact::Captured(referenced_headers(headers, &needs.headers)?);
    }
    if !needs.query.is_empty() {
        facts.query = Fact::Captured(referenced_query(uri.query(), &needs.query)?);
    }
    if needs.now {
        facts.now = captured(clock.now());
    }
    Ok(facts)
}

/// What a tool lane knows of a call beyond the principal it judges: the
/// canonical client address the call entered the gateway from, when its
/// entry point had a connection peer, and the clock it is judged by.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ToolCallFacts<'a> {
    pub(crate) source_address: Option<IpAddr>,
    pub(crate) clock: &'a PolicyClock,
}

/// The facts a tool lane evaluates a call with: the principal's, the source
/// address and the instant. A tool call has no request headers or query of
/// its own, so a rule a rendered tool request reaches whose conditions read
/// one is undetermined there, and refused.
pub(crate) fn tool_call_facts(
    compiled: &CompiledPolicy,
    principal: Option<&Principal>,
    call: ToolCallFacts<'_>,
) -> PolicyFacts {
    let mut facts = compiled.serving_facts(principal);
    let needs = compiled.fact_needs();
    if needs.source_ip {
        facts.source_ip = captured(call.source_address);
    }
    if needs.now {
        facts.now = captured(call.clock.now());
    }
    facts
}

/// The argument fact tool invocation admission decides a call's tool-name
/// rules by, from `arguments` that have already passed the input schema
/// `schema` they were validated against: the scalars at `pointers` -- the
/// pointers those rules read ([`CompiledPolicy::fact_needs`]) -- and nothing
/// else, so a field no condition reads, a secret-marked one included, never
/// reaches the kernel.
///
/// Uncaptured when any of `pointers` is not one the schema makes eligible
/// (`rbac::conditions::tool_argument_pointer_eligible`): a rule that reads
/// the arguments is then undetermined and the call refused, rather than
/// decided as though a field the schema does not let a condition read were
/// absent. Publication refuses such a pointer; this holds when the tool's
/// schema changed after the policy was published.
pub(crate) fn tool_argument_facts(
    schema: &Value,
    arguments: &Value,
    pointers: &[String],
) -> Fact<Value> {
    if pointers
        .iter()
        .all(|pointer| tool_argument_pointer_eligible(schema, pointer))
    {
        Fact::Captured(referenced_tool_arguments(arguments, pointers))
    } else {
        Fact::Uncaptured
    }
}

fn captured<T>(value: Option<T>) -> Fact<T> {
    value.map_or(Fact::Uncaptured, Fact::Captured)
}

/// Every occurrence of each header in `names`, in the order received.
fn referenced_headers(
    headers: &HeaderMap,
    names: &[String],
) -> Result<Vec<(String, String)>, FactsRefusal> {
    let mut copied = Vec::new();
    for name in names {
        for value in headers.get_all(name.as_str()) {
            if copied.len() == MAX_FACT_ENTRIES {
                return Err(FactsRefusal::TooLarge);
            }
            let value = String::from_utf8_lossy(value.as_bytes());
            if value.len() > MAX_FACT_VALUE_BYTES {
                return Err(FactsRefusal::TooLarge);
            }
            copied.push((name.clone(), value.into_owned()));
        }
    }
    Ok(copied)
}

/// Every occurrence of each query parameter in `names`, decoded, in request
/// order. Every parameter is decoded, read or not, so one malformed anywhere
/// refuses the query.
fn referenced_query(
    query: Option<&str>,
    names: &[String],
) -> Result<Vec<(String, String)>, FactsRefusal> {
    let mut pairs = Vec::new();
    let Some(query) = query else {
        return Ok(pairs);
    };
    // Empty pieces (`a=1&&b=2`, a trailing `&`) carry no parameter, and every
    // form decoder skips them alike.
    for piece in query.split('&').filter(|piece| !piece.is_empty()) {
        let (name, value) = piece.split_once('=').unwrap_or((piece, ""));
        let name = decode_component(name)?;
        let value = decode_component(value)?;
        if !names.iter().any(|wanted| wanted.as_str() == name.as_ref()) {
            continue;
        }
        if pairs.len() == MAX_FACT_ENTRIES
            || name.len() > MAX_FACT_NAME_BYTES
            || value.len() > MAX_FACT_VALUE_BYTES
        {
            return Err(FactsRefusal::TooLarge);
        }
        pairs.push((name.into_owned(), value.into_owned()));
    }
    Ok(pairs)
}

/// One query name or value, decoded as `application/x-www-form-urlencoded`
/// decodes it -- `+` is a space, `%XX` the byte `XX`, and only the first `=`
/// of a parameter separates its name from its value -- but strictly: a `%`
/// not followed by two hexadecimal digits, a decoded byte sequence that is not
/// UTF-8, or a decoded control character refuses the query. Lenient decoders
/// disagree about exactly those inputs (keep the escape, drop it, replace the
/// bytes, stop at a NUL), so deciding on one would decide on a parameter the
/// upstream may read differently.
fn decode_component(raw: &str) -> Result<Cow<'_, str>, FactsRefusal> {
    let bytes = raw.as_bytes();
    if !bytes.iter().any(|&byte| matches!(byte, b'%' | b'+')) {
        if raw.chars().any(char::is_control) {
            return Err(FactsRefusal::QueryUndecodable);
        }
        return Ok(Cow::Borrowed(raw));
    }
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut rest = bytes;
    while let Some((&byte, tail)) = rest.split_first() {
        rest = tail;
        match byte {
            b'+' => decoded.push(b' '),
            b'%' => {
                let escape = match rest {
                    [high, low, tail @ ..] => {
                        rest = tail;
                        hex_digit(*high).zip(hex_digit(*low))
                    }
                    _ => None,
                };
                let Some((high, low)) = escape else {
                    return Err(FactsRefusal::QueryUndecodable);
                };
                decoded.push((high << 4) | low);
            }
            byte => decoded.push(byte),
        }
    }
    let text = String::from_utf8(decoded).map_err(|_| FactsRefusal::QueryUndecodable)?;
    if text.chars().any(char::is_control) {
        return Err(FactsRefusal::QueryUndecodable);
    }
    Ok(Cow::Owned(text))
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
#[path = "policy_facts_tests.rs"]
mod tests;
