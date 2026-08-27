//! gRPC wire-protocol rules, as pure functions.
//!
//! Everything here is decidable from the request alone, needs no state, and
//! reaches no network. That is deliberate: these are the checks that must all
//! pass before the call is allowed to exist, so keeping them free of I/O makes
//! "nothing here can reach an upstream" a property of the module rather than a
//! claim about the call order.
//!
//! Every rule fails closed. Where the gRPC specification is permissive and the
//! permissiveness buys a proxy nothing, this is stricter -- a method path is
//! held to the protobuf identifier grammar rather than to "any two segments",
//! because the whole authorization story depends on the path having exactly one
//! spelling.

use std::time::Duration;

use http::{header::CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue, StatusCode};

/// Media types this gateway accepts on a gRPC call.
///
/// Read by two places that must agree: the gRPC listener's request-validation
/// middleware, which is handed this list as its allow-list, and
/// [`validate_content_type`] below. One constant, so a media type cannot be
/// accepted by one and refused by the other.
pub(crate) const GRPC_CONTENT_TYPES: &[&str] = &[
    "application/grpc",
    "application/grpc+proto",
    "application/grpc+json",
];

/// The content type the gateway states on every response it generates itself.
pub(crate) const GRPC_CONTENT_TYPE: HeaderValue = HeaderValue::from_static("application/grpc");

pub(crate) const GRPC_STATUS: HeaderName = HeaderName::from_static("grpc-status");
pub(crate) const GRPC_MESSAGE: HeaderName = HeaderName::from_static("grpc-message");
pub(crate) const GRPC_TIMEOUT: HeaderName = HeaderName::from_static("grpc-timeout");

/// Longest method path the gateway will even look at.
///
/// A bound before parsing, so a pathological path costs a length check rather
/// than a scan. Comfortably above any real protobuf fully-qualified name.
pub(crate) const MAX_METHOD_PATH_BYTES: usize = 512;

/// Longest `grpc-timeout` value, per the gRPC specification: at most eight
/// digits and a one-character unit.
const MAX_TIMEOUT_VALUE_BYTES: usize = 9;

/// gRPC status codes, as defined by the canonical error model.
///
/// Only the codes this gateway can itself produce, plus the ones it maps from
/// HTTP, are named. A code the gateway never emits would be a name with no
/// call site.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GrpcStatus {
    Ok,
    Cancelled,
    Unknown,
    InvalidArgument,
    DeadlineExceeded,
    PermissionDenied,
    ResourceExhausted,
    Unimplemented,
    Internal,
    Unavailable,
    Unauthenticated,
}

impl GrpcStatus {
    /// A bounded, low-cardinality label. Safe as a metric label and an audit
    /// field, unlike the numeric code paired with a caller-supplied message.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Cancelled => "cancelled",
            Self::Unknown => "unknown",
            Self::InvalidArgument => "invalid_argument",
            Self::DeadlineExceeded => "deadline_exceeded",
            Self::PermissionDenied => "permission_denied",
            Self::ResourceExhausted => "resource_exhausted",
            Self::Unimplemented => "unimplemented",
            Self::Internal => "internal",
            Self::Unavailable => "unavailable",
            Self::Unauthenticated => "unauthenticated",
        }
    }

    pub(crate) fn header_value(self) -> HeaderValue {
        match self {
            Self::Ok => HeaderValue::from_static("0"),
            Self::Cancelled => HeaderValue::from_static("1"),
            Self::Unknown => HeaderValue::from_static("2"),
            Self::InvalidArgument => HeaderValue::from_static("3"),
            Self::DeadlineExceeded => HeaderValue::from_static("4"),
            Self::PermissionDenied => HeaderValue::from_static("7"),
            Self::ResourceExhausted => HeaderValue::from_static("8"),
            Self::Unimplemented => HeaderValue::from_static("12"),
            Self::Internal => HeaderValue::from_static("13"),
            Self::Unavailable => HeaderValue::from_static("14"),
            Self::Unauthenticated => HeaderValue::from_static("16"),
        }
    }
}

/// Maps an HTTP status the gateway's own middleware produced onto a gRPC status.
///
/// This exists because the gRPC listener runs the identical middleware stack as
/// the HTTP data listener -- the same `apply_middleware` call with the same
/// value -- and that stack answers in HTTP. Rather than teach every middleware
/// about gRPC, the listener's outermost layer rewrites whatever comes back.
///
/// The mapping follows the gRPC-over-HTTP2 specification's table, with one
/// deliberate deviation: **429 becomes `RESOURCE_EXHAUSTED`, not `UNAVAILABLE`**.
/// The specification's table is written for an intermediary that cannot know
/// why a 429 was produced. Here it is always this gateway's own rate limiter,
/// and `RESOURCE_EXHAUSTED` is the canonical code for a quota decision -- it
/// tells a client the call was refused rather than that the server was down,
/// which changes whether retrying is sensible.
pub(crate) fn grpc_status_for_http_status(status: StatusCode) -> GrpcStatus {
    match status.as_u16() {
        200 => GrpcStatus::Ok,
        400 | 431 => GrpcStatus::Internal,
        401 => GrpcStatus::Unauthenticated,
        403 => GrpcStatus::PermissionDenied,
        404 => GrpcStatus::Unimplemented,
        408 => GrpcStatus::DeadlineExceeded,
        413 | 429 => GrpcStatus::ResourceExhausted,
        // 415 is what request validation answers for a media type this
        // listener does not serve, and 501 is what it answers for CONNECT.
        // Both are "this server does not implement what you asked for".
        415 | 501 => GrpcStatus::Unimplemented,
        502..=504 => GrpcStatus::Unavailable,
        _ => GrpcStatus::Unknown,
    }
}

/// Maps an HTTP status the UPSTREAM produced onto a gRPC status.
///
/// Separate from [`grpc_status_for_http_status`] because the inputs are
/// different populations with different meanings. A gRPC server answers every
/// application outcome with HTTP 200 and a `grpc-status` trailer, so any other
/// status from the upstream means the peer is not speaking gRPC properly, and
/// the gateway must not let the client mistake it for an application answer.
pub(crate) fn grpc_status_for_upstream_status(status: StatusCode) -> GrpcStatus {
    match status.as_u16() {
        400 => GrpcStatus::Internal,
        401 => GrpcStatus::Unauthenticated,
        403 => GrpcStatus::PermissionDenied,
        404 => GrpcStatus::Unimplemented,
        429 | 502 | 503 | 504 => GrpcStatus::Unavailable,
        _ => GrpcStatus::Unknown,
    }
}

/// Why a request was refused before it became a call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProtocolRejection {
    pub(crate) status: GrpcStatus,
    /// Bounded category. Every value is a literal in this file, so it is safe
    /// as a metric label, an audit field, and a `grpc-message`.
    pub(crate) reason: &'static str,
}

impl ProtocolRejection {
    const fn invalid(reason: &'static str) -> Self {
        Self {
            status: GrpcStatus::InvalidArgument,
            reason,
        }
    }
}

/// A validated `/package.Service/Method` path.
///
/// Holds offsets into the caller's path rather than copies, because the whole
/// point is that the authorized identity and the forwarded `:path` are the same
/// bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CanonicalMethod<'a> {
    pub(crate) service: &'a str,
    pub(crate) method: &'a str,
}

/// Validates a gRPC method path.
///
/// The grammar is protobuf's, not HTTP's: `/` then a dot-separated sequence of
/// identifiers, then `/`, then one identifier. Nothing else. That is stricter
/// than the gRPC specification, which allows an opaque service name, and the
/// strictness is the point -- **a path that matches this grammar has exactly
/// one spelling**, so the string RBAC evaluates, the string audit records, and
/// the string sent upstream as `:path` cannot differ.
///
/// Note what this does NOT have to re-check. `is_unsafe_request_path`
/// (gateway/src/path_match.rs) already rejected `%`, `\`, `//`, and `.`/`..`
/// segments before RBAC ran, so no percent-encoding or dot-segment can reach
/// here. A legitimate gRPC path is unaffected by that check: dots inside a
/// segment are ordinary, and only a segment that IS `.` or `..` is refused.
pub(crate) fn validate_method_path(path: &str) -> Result<CanonicalMethod<'_>, ProtocolRejection> {
    if path.len() > MAX_METHOD_PATH_BYTES {
        return Err(ProtocolRejection::invalid("method_path_too_long"));
    }
    let Some(rest) = path.strip_prefix('/') else {
        return Err(ProtocolRejection::invalid("method_path_not_absolute"));
    };
    let Some((service, method)) = rest.split_once('/') else {
        return Err(ProtocolRejection::invalid("method_path_shape"));
    };
    if method.contains('/') {
        return Err(ProtocolRejection::invalid("method_path_shape"));
    }
    if service.is_empty() || method.is_empty() {
        return Err(ProtocolRejection::invalid("method_path_shape"));
    }
    if !service.split('.').all(is_protobuf_identifier) {
        return Err(ProtocolRejection::invalid("service_name_grammar"));
    }
    if !is_protobuf_identifier(method) {
        return Err(ProtocolRejection::invalid("method_name_grammar"));
    }

    Ok(CanonicalMethod { service, method })
}

/// The protobuf identifier grammar: a letter or underscore, then letters,
/// digits, or underscores.
fn is_protobuf_identifier(value: &str) -> bool {
    let mut characters = value.chars();
    let Some(first) = characters.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }

    characters.all(|character| character.is_ascii_alphanumeric() || character == '_')
}

/// Validates the request's `Content-Type` and returns the value to send
/// upstream.
///
/// The returned value is one of [`GRPC_CONTENT_TYPES`], not the caller's bytes.
/// A caller who wrote `Application/GRPC+PROTO; charset=utf-8` gets the
/// canonical spelling forwarded, so what crosses the boundary is a constant
/// from this file rather than a string an attacker chose.
pub(crate) fn validate_content_type(headers: &HeaderMap) -> Result<HeaderValue, ProtocolRejection> {
    let mut values = headers.get_all(CONTENT_TYPE).iter();
    let Some(value) = values.next() else {
        return Err(ProtocolRejection {
            status: GrpcStatus::Internal,
            reason: "content_type_missing",
        });
    };
    if values.next().is_some() {
        return Err(ProtocolRejection {
            status: GrpcStatus::Internal,
            reason: "content_type_duplicated",
        });
    }
    let Ok(value) = value.to_str() else {
        return Err(ProtocolRejection {
            status: GrpcStatus::Internal,
            reason: "content_type_malformed",
        });
    };
    // RFC 9110 section 8.3.1: parameters after `;` are not part of the media
    // type, and type/subtype are case-insensitive.
    let media_type = value
        .split(';')
        .next()
        .unwrap_or_default()
        .trim_matches(|character: char| character.is_ascii_whitespace());

    GRPC_CONTENT_TYPES
        .iter()
        .find(|allowed| media_type.eq_ignore_ascii_case(allowed))
        .map(|allowed| HeaderValue::from_static(allowed))
        .ok_or(ProtocolRejection {
            // The specification's own answer for a content type a gRPC server
            // does not serve.
            status: GrpcStatus::Internal,
            reason: "content_type_not_grpc",
        })
}

/// Requires `TE: trailers`.
///
/// The gRPC specification makes this mandatory, and it is load-bearing rather
/// than ceremonial: a client that did not ask for trailers may not be prepared
/// to read `grpc-status`, and an intermediary that saw no `TE: trailers` is
/// permitted to strip them. Refusing the call is better than completing one
/// whose status the client will never see.
pub(crate) fn validate_te_trailers(headers: &HeaderMap) -> Result<(), ProtocolRejection> {
    let present = headers.get_all(http::header::TE).iter().any(|value| {
        value.to_str().is_ok_and(|value| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("trailers"))
        })
    });

    if present {
        Ok(())
    } else {
        Err(ProtocolRejection::invalid("te_trailers_missing"))
    }
}

/// Parses a `grpc-timeout` value.
///
/// The grammar is `TimeoutValue TimeoutUnit`, where the value is at most eight
/// ASCII digits and the unit is one of `H M S m u n`. Anything else -- a sign,
/// whitespace, a missing unit, an out-of-range value -- is refused rather than
/// interpreted charitably, because a misread deadline is a call that runs for
/// the wrong length of time in a direction nobody chose.
pub(crate) fn parse_grpc_timeout(value: &HeaderValue) -> Result<Duration, ProtocolRejection> {
    let Ok(value) = value.to_str() else {
        return Err(ProtocolRejection::invalid("grpc_timeout_malformed"));
    };
    if value.len() > MAX_TIMEOUT_VALUE_BYTES || value.len() < 2 {
        return Err(ProtocolRejection::invalid("grpc_timeout_malformed"));
    }
    let (digits, unit) = value.split_at(value.len() - 1);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ProtocolRejection::invalid("grpc_timeout_malformed"));
    }
    let Ok(amount) = digits.parse::<u64>() else {
        return Err(ProtocolRejection::invalid("grpc_timeout_malformed"));
    };
    let nanos_per_unit: u64 = match unit {
        "H" => 3_600_000_000_000,
        "M" => 60_000_000_000,
        "S" => 1_000_000_000,
        "m" => 1_000_000,
        "u" => 1_000,
        "n" => 1,
        _ => return Err(ProtocolRejection::invalid("grpc_timeout_unit")),
    };

    // Eight digits of hours is under 2^63 nanoseconds, so this cannot overflow
    // for any value the grammar admits. Saturating anyway means a future change
    // to the digit bound cannot turn into a wrap.
    Ok(Duration::from_nanos(amount.saturating_mul(nanos_per_unit)))
}

/// The gRPC length-prefixed message header: one compression flag byte and a
/// four-byte big-endian length.
pub(crate) const MESSAGE_HEADER_BYTES: usize = 5;

/// Incremental parser for the gRPC message framing.
///
/// Only the five-byte envelope header is ever inspected; the message bytes
/// themselves are counted and forwarded, never read. That is what "no protobuf
/// inspection" means in practice, and it is why this holds at most four bytes
/// of partial header rather than a message buffer.
#[derive(Debug, Default)]
pub(crate) struct MessageFramer {
    /// Bytes of the current envelope header seen so far.
    header: [u8; MESSAGE_HEADER_BYTES],
    header_len: usize,
    /// Payload bytes still expected for the message being forwarded.
    remaining_payload: u64,
}

/// Why a framer refused a chunk.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FramingError {
    /// A single encoded message exceeded the configured ceiling.
    MessageTooLarge,
    /// The stream ended in the middle of a message.
    Truncated,
}

impl MessageFramer {
    /// Feeds one body chunk through the framer.
    ///
    /// Returns the number of complete messages that ended in this chunk. The
    /// chunk itself is untouched: this observes framing, it does not rewrite it.
    pub(crate) fn observe(
        &mut self,
        chunk: &[u8],
        max_message_bytes: usize,
    ) -> Result<u64, FramingError> {
        let mut offset = 0;
        let mut completed = 0;

        while offset < chunk.len() {
            if self.remaining_payload > 0 {
                let available = u64::try_from(chunk.len() - offset).unwrap_or(u64::MAX);
                let consumed = self.remaining_payload.min(available);
                self.remaining_payload -= consumed;
                offset += usize::try_from(consumed).unwrap_or(chunk.len() - offset);
                if self.remaining_payload == 0 {
                    completed += 1;
                }
                continue;
            }

            let wanted = MESSAGE_HEADER_BYTES - self.header_len;
            let take = wanted.min(chunk.len() - offset);
            self.header[self.header_len..self.header_len + take]
                .copy_from_slice(&chunk[offset..offset + take]);
            self.header_len += take;
            offset += take;

            if self.header_len < MESSAGE_HEADER_BYTES {
                break;
            }

            let length = u32::from_be_bytes([
                self.header[1],
                self.header[2],
                self.header[3],
                self.header[4],
            ]);
            self.header_len = 0;
            if u64::from(length) > u64::try_from(max_message_bytes).unwrap_or(u64::MAX) {
                return Err(FramingError::MessageTooLarge);
            }
            if length == 0 {
                // A legal empty message: the envelope is the whole message.
                completed += 1;
            } else {
                self.remaining_payload = u64::from(length);
            }
        }

        Ok(completed)
    }

    /// Checks that the stream ended on a message boundary.
    pub(crate) fn finish(&self) -> Result<(), FramingError> {
        if self.header_len == 0 && self.remaining_payload == 0 {
            Ok(())
        } else {
            Err(FramingError::Truncated)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_method_paths_are_accepted() {
        for path in [
            "/helloworld.Greeter/SayHello",
            "/Greeter/SayHello",
            "/a.b.c.d.Service/Method",
            "/_private.Service/_method0",
        ] {
            assert!(
                validate_method_path(path).is_ok(),
                "{path} should be a legitimate gRPC method path"
            );
        }

        let method = validate_method_path("/helloworld.Greeter/SayHello")
            .expect("a canonical path should parse");
        assert_eq!(method.service, "helloworld.Greeter");
        assert_eq!(method.method, "SayHello");
    }

    #[test]
    fn path_confusion_shapes_are_refused() {
        for (path, reason) in [
            ("helloworld.Greeter/SayHello", "method_path_not_absolute"),
            ("/helloworld.Greeter", "method_path_shape"),
            ("/helloworld.Greeter/SayHello/Extra", "method_path_shape"),
            ("/helloworld.Greeter/", "method_path_shape"),
            ("//SayHello", "method_path_shape"),
            ("/helloworld..Greeter/SayHello", "service_name_grammar"),
            ("/.Greeter/SayHello", "service_name_grammar"),
            ("/helloworld.Greeter./SayHello", "service_name_grammar"),
            ("/hello-world.Greeter/SayHello", "service_name_grammar"),
            ("/0Greeter/SayHello", "service_name_grammar"),
            ("/Greeter/Say Hello", "method_name_grammar"),
            ("/Greeter/Say.Hello", "method_name_grammar"),
            ("/Greeter/0SayHello", "method_name_grammar"),
        ] {
            let rejection = validate_method_path(path)
                .expect_err(&format!("{path} must be refused as a method path"));
            assert_eq!(rejection.reason, reason, "{path}");
            assert_eq!(rejection.status, GrpcStatus::InvalidArgument, "{path}");
        }
    }

    #[test]
    fn an_over_long_method_path_is_refused_before_it_is_parsed() {
        let path = format!("/{}.Service/Method", "a".repeat(MAX_METHOD_PATH_BYTES));
        let rejection = validate_method_path(&path).expect_err("an over-long path must be refused");
        assert_eq!(rejection.reason, "method_path_too_long");
    }

    /// The interaction #312 makes worth stating: the pre-RBAC unsafe-path guard
    /// must not reject a legitimate gRPC path, and must still reject the shapes
    /// that create an authorization gap.
    #[test]
    fn the_unsafe_path_guard_and_the_method_grammar_agree() {
        for path in [
            "/helloworld.Greeter/SayHello",
            "/a.b.c.Service/Method",
            "/_x.Y/Z",
        ] {
            assert!(
                !crate::path_match::is_unsafe_request_path(path),
                "{path} is a legitimate gRPC method path and must survive the unsafe-path guard"
            );
            assert!(validate_method_path(path).is_ok(), "{path}");
        }

        for path in [
            "/helloworld.Greeter%2fSayHello",
            "/helloworld.Greeter//SayHello",
            "/./Greeter/SayHello",
            "/helloworld.Greeter/../SayHello",
            "/helloworld.Greeter\\SayHello",
        ] {
            assert!(
                crate::path_match::is_unsafe_request_path(path),
                "{path} must be caught before RBAC"
            );
            assert!(
                validate_method_path(path).is_err(),
                "{path} must also fail the method grammar, so the two guards cannot disagree"
            );
        }
    }

    #[test]
    fn content_type_is_canonicalized_rather_than_echoed() {
        for raw in [
            "application/grpc",
            "APPLICATION/GRPC",
            "application/grpc; charset=utf-8",
            "  application/grpc  ",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(CONTENT_TYPE, HeaderValue::from_str(raw).expect("value"));
            assert_eq!(
                validate_content_type(&headers).expect("a gRPC media type should be accepted"),
                "application/grpc",
                "{raw} must forward the canonical spelling, not the caller's bytes"
            );
        }

        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("Application/GRPC+PROTO"),
        );
        assert_eq!(
            validate_content_type(&headers).expect("a gRPC media type should be accepted"),
            "application/grpc+proto"
        );
    }

    #[test]
    fn non_grpc_and_ambiguous_content_types_are_refused() {
        let mut headers = HeaderMap::new();
        assert_eq!(
            validate_content_type(&headers)
                .expect_err("a missing content type must be refused")
                .reason,
            "content_type_missing"
        );

        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        assert_eq!(
            validate_content_type(&headers)
                .expect_err("a non-gRPC media type must be refused")
                .reason,
            "content_type_not_grpc"
        );

        // `application/grpc-web` shares a prefix with `application/grpc` and is
        // a different protocol this gateway does not transcode.
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/grpc-web"),
        );
        assert_eq!(
            validate_content_type(&headers)
                .expect_err("grpc-web must not be mistaken for grpc")
                .reason,
            "content_type_not_grpc"
        );

        headers.append(CONTENT_TYPE, HeaderValue::from_static("application/grpc"));
        assert_eq!(
            validate_content_type(&headers)
                .expect_err("two content types must be refused rather than half-read")
                .reason,
            "content_type_duplicated"
        );
    }

    #[test]
    fn te_trailers_is_required_and_token_matched() {
        let mut headers = HeaderMap::new();
        assert!(validate_te_trailers(&headers).is_err());

        headers.insert(http::header::TE, HeaderValue::from_static("trailers"));
        assert!(validate_te_trailers(&headers).is_ok());

        headers.insert(http::header::TE, HeaderValue::from_static("gzip, TRAILERS"));
        assert!(validate_te_trailers(&headers).is_ok());

        // A token that merely contains "trailers" is not the token.
        headers.insert(http::header::TE, HeaderValue::from_static("trailerspoof"));
        assert_eq!(
            validate_te_trailers(&headers)
                .expect_err("a lookalike token must not satisfy TE")
                .reason,
            "te_trailers_missing"
        );
    }

    #[test]
    fn grpc_timeout_units_parse_exactly() {
        for (raw, expected) in [
            ("1H", Duration::from_secs(3600)),
            ("2M", Duration::from_secs(120)),
            ("30S", Duration::from_secs(30)),
            ("250m", Duration::from_millis(250)),
            ("1500u", Duration::from_micros(1500)),
            ("99n", Duration::from_nanos(99)),
            ("99999999n", Duration::from_nanos(99_999_999)),
        ] {
            assert_eq!(
                parse_grpc_timeout(&HeaderValue::from_static(raw)).expect(raw),
                expected,
                "{raw}"
            );
        }
    }

    #[test]
    fn malformed_grpc_timeouts_are_refused_rather_than_interpreted() {
        for raw in [
            "",
            "S",
            "10",
            "-1S",
            "1 S",
            " 10S",
            "10s",
            "10X",
            "999999999S",
            "1.5S",
            "+1S",
        ] {
            let value = HeaderValue::from_str(raw).expect("test header value");
            assert!(
                parse_grpc_timeout(&value).is_err(),
                "{raw:?} must be refused rather than read as a deadline"
            );
        }
    }

    #[test]
    fn the_http_mapping_covers_every_status_the_middleware_stack_produces() {
        for (status, expected) in [
            (StatusCode::UNAUTHORIZED, GrpcStatus::Unauthenticated),
            (StatusCode::FORBIDDEN, GrpcStatus::PermissionDenied),
            (StatusCode::TOO_MANY_REQUESTS, GrpcStatus::ResourceExhausted),
            (StatusCode::PAYLOAD_TOO_LARGE, GrpcStatus::ResourceExhausted),
            (
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                GrpcStatus::Unimplemented,
            ),
            (StatusCode::NOT_IMPLEMENTED, GrpcStatus::Unimplemented),
            (StatusCode::NOT_FOUND, GrpcStatus::Unimplemented),
            (StatusCode::BAD_REQUEST, GrpcStatus::Internal),
            (StatusCode::REQUEST_TIMEOUT, GrpcStatus::DeadlineExceeded),
            (StatusCode::SERVICE_UNAVAILABLE, GrpcStatus::Unavailable),
            (StatusCode::BAD_GATEWAY, GrpcStatus::Unavailable),
            (StatusCode::GATEWAY_TIMEOUT, GrpcStatus::Unavailable),
            (StatusCode::OK, GrpcStatus::Ok),
            (StatusCode::IM_A_TEAPOT, GrpcStatus::Unknown),
        ] {
            assert_eq!(grpc_status_for_http_status(status), expected, "{status}");
        }
    }

    /// The wire values, checked against the canonical gRPC error model rather
    /// than against each other. A typo here is a call reported with the wrong
    /// status, which a client acts on.
    #[test]
    fn status_header_values_match_the_canonical_error_model() {
        for (status, code) in [
            (GrpcStatus::Ok, "0"),
            (GrpcStatus::Cancelled, "1"),
            (GrpcStatus::Unknown, "2"),
            (GrpcStatus::InvalidArgument, "3"),
            (GrpcStatus::DeadlineExceeded, "4"),
            (GrpcStatus::PermissionDenied, "7"),
            (GrpcStatus::ResourceExhausted, "8"),
            (GrpcStatus::Unimplemented, "12"),
            (GrpcStatus::Internal, "13"),
            (GrpcStatus::Unavailable, "14"),
            (GrpcStatus::Unauthenticated, "16"),
        ] {
            assert_eq!(
                status.header_value().to_str().expect("ascii"),
                code,
                "{status:?}"
            );
        }
    }

    fn framed(messages: &[&[u8]]) -> Vec<u8> {
        let mut encoded = Vec::new();
        for message in messages {
            encoded.push(0);
            encoded.extend_from_slice(
                &u32::try_from(message.len())
                    .expect("test message fits")
                    .to_be_bytes(),
            );
            encoded.extend_from_slice(message);
        }
        encoded
    }

    #[test]
    fn framing_counts_messages_across_arbitrary_chunk_boundaries() {
        let encoded = framed(&[b"one", b"", b"three-three"]);

        for chunk_size in 1..=encoded.len() {
            let mut framer = MessageFramer::default();
            let mut completed = 0;
            for chunk in encoded.chunks(chunk_size) {
                completed += framer
                    .observe(chunk, 1024)
                    .expect("well-formed framing should be accepted");
            }
            assert_eq!(completed, 3, "chunk_size={chunk_size}");
            assert!(framer.finish().is_ok(), "chunk_size={chunk_size}");
        }
    }

    #[test]
    fn a_message_one_byte_over_the_limit_is_refused() {
        let allowed = framed(&[&[7_u8; 64]]);
        let mut framer = MessageFramer::default();
        assert_eq!(
            framer
                .observe(&allowed, 64)
                .expect("a message exactly at the limit must be accepted"),
            1
        );

        let refused = framed(&[&[7_u8; 65]]);
        let mut framer = MessageFramer::default();
        assert_eq!(
            framer.observe(&refused, 64),
            Err(FramingError::MessageTooLarge),
            "a message one byte over the limit must be refused"
        );
    }

    /// The limit is read from the DECLARED length, not from bytes received, so
    /// an oversize message is refused on its header rather than after it has
    /// been forwarded.
    #[test]
    fn an_oversize_declaration_is_refused_before_any_payload_arrives() {
        let mut header = vec![0_u8];
        header.extend_from_slice(&1_000_000_u32.to_be_bytes());

        let mut framer = MessageFramer::default();
        assert_eq!(
            framer.observe(&header, 1024),
            Err(FramingError::MessageTooLarge)
        );
    }

    #[test]
    fn a_stream_that_ends_mid_message_is_truncated() {
        let encoded = framed(&[b"complete-message"]);

        let mut framer = MessageFramer::default();
        framer
            .observe(&encoded[..encoded.len() - 1], 1024)
            .expect("a partial message is not yet an error");
        assert_eq!(framer.finish(), Err(FramingError::Truncated));

        let mut framer = MessageFramer::default();
        framer
            .observe(&encoded[..3], 1024)
            .expect("a partial header is not yet an error");
        assert_eq!(framer.finish(), Err(FramingError::Truncated));

        let mut framer = MessageFramer::default();
        framer.observe(&encoded, 1024).expect("complete");
        assert!(framer.finish().is_ok());
    }
}
