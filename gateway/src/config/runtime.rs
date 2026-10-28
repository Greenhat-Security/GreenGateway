//! How the running gateway bounds its work -- the shutdown drain, discovery's
//! payload capture and signals, request bounds and rate limits, request
//! validation and the tool runtime -- compiled in pure stages (issue #433,
//! PR 2).
//!
//! `Config::from_env_vars` reads these in six blocks with other domains'
//! settings between them, and each block is requested where the legacy parser
//! requested it, so the read order does not move:
//!
//! 1. the shutdown drain ([`ShutdownInputs`]);
//! 2. payload capture and the discovery signals ([`SignalInputs`]);
//! 3. request bounds and rate limits ([`RequestBoundInputs`]);
//! 4. the content types request validation accepts ([`ContentTypeInputs`]);
//! 5. the tool runtime's queue ([`ToolRuntimeInputs`]);
//! 6. the tool runtime's default timeout ([`ToolTimeoutInputs`]), after
//!    which [`compile`] builds the [`RuntimePlan`].
//!
//! Every input here is a bound or a threshold checked on its own; none
//! relates to another. Whether payload capture has somewhere to store what it
//! captures depends on the state backend, so that rule is checked in
//! `storage`.

use std::env::VarError;

use super::{
    parse_comma_separated_header_values, parse_var,
    stage::{Checked, Findings, Provenance, RawInput},
    validate_cors_allow_origins, validate_finite_non_negative, validate_maximum_u64,
    validate_payload_capture_sample_rate, validate_positive_bounded_u64,
    validate_positive_timeout_ms, validate_positive_u64, validate_positive_usize,
    validate_range_usize, validate_rule_suggestion_baseline_window_hours,
    validate_signal_multiple_threshold, validate_signal_ratio_threshold, AuditDurability,
    AUDIT_DRAIN_TIMEOUT_MS, AUDIT_DURABILITY, AUDIT_DURABILITY_TIMEOUT_MS, CORS_ALLOW_ORIGINS,
    DEFAULT_AUDIT_DRAIN_TIMEOUT_MS, DEFAULT_AUDIT_DURABILITY, DEFAULT_AUDIT_DURABILITY_TIMEOUT_MS,
    DEFAULT_MAX_BODY_SIZE, DEFAULT_MAX_REQUEST_PATH_BYTES, DEFAULT_PAYLOAD_CAPTURE_SAMPLE_RATE,
    DEFAULT_RATE_LIMIT_BUCKET_TTL_MS, DEFAULT_RATE_LIMIT_MAX_BUCKETS,
    DEFAULT_RATE_LIMIT_READ_BURST, DEFAULT_RATE_LIMIT_READ_RPS, DEFAULT_RATE_LIMIT_WRITE_BURST,
    DEFAULT_RATE_LIMIT_WRITE_RPS, DEFAULT_SHUTDOWN_DRAIN_DELAY_MS, DEFAULT_SHUTDOWN_TIMEOUT_MS,
    DEFAULT_TOOL_RUNTIME_DEFAULT_TIMEOUT_MS, DEFAULT_TOOL_RUNTIME_GLOBAL_CONCURRENCY,
    DEFAULT_TOOL_RUNTIME_QUEUE_DEPTH, DEFAULT_TOOL_RUNTIME_QUEUE_TIMEOUT_MS,
    DEFAULT_VALIDATION_ALLOWED_CONTENT_TYPES, ERROR_RATE_SPIKE_SIGNAL_THRESHOLD,
    MAX_AUDIT_DRAIN_TIMEOUT_MS, MAX_AUDIT_DURABILITY_TIMEOUT_MS, MAX_BODY_SIZE,
    MAX_REQUEST_PATH_BYTES, MAX_SHUTDOWN_DRAIN_DELAY_MS, MAX_SHUTDOWN_TIMEOUT_MS,
    MIN_MAX_REQUEST_PATH_BYTES, PAYLOAD_CAPTURE_ENABLED, PAYLOAD_CAPTURE_SAMPLE_RATE,
    PRINCIPAL_NEW_TO_ENDPOINT_SIGNAL_THRESHOLD, RATE_LIMIT_BUCKET_TTL_MS, RATE_LIMIT_MAX_BUCKETS,
    RATE_LIMIT_READ_BURST, RATE_LIMIT_READ_RPS, RATE_LIMIT_WRITE_BURST, RATE_LIMIT_WRITE_RPS,
    RULE_SUGGESTION_BASELINE_WINDOW_HOURS, SCHEMA_MISMATCH_SIGNAL_THRESHOLD,
    SHUTDOWN_DRAIN_DELAY_MS, SHUTDOWN_TIMEOUT_MS, TOOL_RUNTIME_DEFAULT_TIMEOUT_MS,
    TOOL_RUNTIME_GLOBAL_CONCURRENCY, TOOL_RUNTIME_QUEUE_DEPTH, TOOL_RUNTIME_QUEUE_TIMEOUT_MS,
    VALIDATION_ALLOWED_CONTENT_TYPES, VOLUME_OUTLIER_SIGNAL_THRESHOLD,
};
use crate::discovery::{
    signals::{
        DEFAULT_ERROR_RATE_SPIKE_SIGNAL_THRESHOLD,
        DEFAULT_PRINCIPAL_NEW_TO_ENDPOINT_SIGNAL_THRESHOLD,
        DEFAULT_SCHEMA_MISMATCH_SIGNAL_THRESHOLD, DEFAULT_VOLUME_OUTLIER_SIGNAL_THRESHOLD,
    },
    suggestions::DEFAULT_RULE_SUGGESTION_BASELINE_WINDOW_HOURS,
};

/// The shutdown drain's inputs, and the request path's audit durability
/// (issue #425) the legacy parser read right after them, as the reader
/// returned them.
pub(super) struct ShutdownInputs {
    drain_delay_ms: RawInput,
    timeout_ms: RawInput,
    audit_drain_timeout_ms: RawInput,
    audit_durability: RawInput,
    audit_durability_timeout_ms: RawInput,
}

impl ShutdownInputs {
    /// Requests every input of the block once, in the inventory's order.
    pub(super) fn read(mut get_var: impl FnMut(&str) -> Result<String, VarError>) -> Self {
        Self {
            drain_delay_ms: RawInput::new(
                SHUTDOWN_DRAIN_DELAY_MS,
                get_var(SHUTDOWN_DRAIN_DELAY_MS),
            ),
            timeout_ms: RawInput::new(SHUTDOWN_TIMEOUT_MS, get_var(SHUTDOWN_TIMEOUT_MS)),
            audit_drain_timeout_ms: RawInput::new(
                AUDIT_DRAIN_TIMEOUT_MS,
                get_var(AUDIT_DRAIN_TIMEOUT_MS),
            ),
            audit_durability: RawInput::new(AUDIT_DURABILITY, get_var(AUDIT_DURABILITY)),
            audit_durability_timeout_ms: RawInput::new(
                AUDIT_DURABILITY_TIMEOUT_MS,
                get_var(AUDIT_DURABILITY_TIMEOUT_MS),
            ),
        }
    }
}

/// The shutdown drain and the audit durability, parsed.
pub(super) struct Shutdown {
    shutdown_drain_delay_ms: u64,
    shutdown_timeout_ms: u64,
    audit_drain_timeout_ms: u64,
    audit_durability: AuditDurability,
    audit_durability_timeout_ms: u64,
    provenance: Vec<Provenance>,
}

pub(super) fn compile_shutdown(inputs: ShutdownInputs) -> Checked<Shutdown> {
    let mut findings = Findings::default();
    let shutdown_drain_delay_ms = findings.input(SHUTDOWN_DRAIN_DELAY_MS, |problems| {
        let delay_ms = parse_var(
            SHUTDOWN_DRAIN_DELAY_MS,
            inputs.drain_delay_ms.value(),
            DEFAULT_SHUTDOWN_DRAIN_DELAY_MS,
            "millisecond duration",
            problems,
        );
        validate_maximum_u64(
            SHUTDOWN_DRAIN_DELAY_MS,
            delay_ms,
            MAX_SHUTDOWN_DRAIN_DELAY_MS,
            DEFAULT_SHUTDOWN_DRAIN_DELAY_MS,
            problems,
        )
    });
    let shutdown_timeout_ms = findings.input(SHUTDOWN_TIMEOUT_MS, |problems| {
        let timeout_ms = parse_var(
            SHUTDOWN_TIMEOUT_MS,
            inputs.timeout_ms.value(),
            DEFAULT_SHUTDOWN_TIMEOUT_MS,
            "millisecond duration",
            problems,
        );
        validate_positive_bounded_u64(
            SHUTDOWN_TIMEOUT_MS,
            timeout_ms,
            MAX_SHUTDOWN_TIMEOUT_MS,
            DEFAULT_SHUTDOWN_TIMEOUT_MS,
            problems,
        )
    });
    let audit_drain_timeout_ms = findings.input(AUDIT_DRAIN_TIMEOUT_MS, |problems| {
        let timeout_ms = parse_var(
            AUDIT_DRAIN_TIMEOUT_MS,
            inputs.audit_drain_timeout_ms.value(),
            DEFAULT_AUDIT_DRAIN_TIMEOUT_MS,
            "millisecond duration",
            problems,
        );
        validate_positive_bounded_u64(
            AUDIT_DRAIN_TIMEOUT_MS,
            timeout_ms,
            MAX_AUDIT_DRAIN_TIMEOUT_MS,
            DEFAULT_AUDIT_DRAIN_TIMEOUT_MS,
            problems,
        )
    });
    let audit_durability = findings.input(AUDIT_DURABILITY, |problems| {
        parse_var(
            AUDIT_DURABILITY,
            inputs.audit_durability.value(),
            DEFAULT_AUDIT_DURABILITY,
            "audit durability mode",
            problems,
        )
    });
    let audit_durability_timeout_ms = findings.input(AUDIT_DURABILITY_TIMEOUT_MS, |problems| {
        let timeout_ms = parse_var(
            AUDIT_DURABILITY_TIMEOUT_MS,
            inputs.audit_durability_timeout_ms.value(),
            DEFAULT_AUDIT_DURABILITY_TIMEOUT_MS,
            "millisecond duration",
            problems,
        );
        validate_positive_bounded_u64(
            AUDIT_DURABILITY_TIMEOUT_MS,
            timeout_ms,
            MAX_AUDIT_DURABILITY_TIMEOUT_MS,
            DEFAULT_AUDIT_DURABILITY_TIMEOUT_MS,
            problems,
        )
    });
    Checked::new(
        Shutdown {
            shutdown_drain_delay_ms,
            shutdown_timeout_ms,
            audit_drain_timeout_ms,
            audit_durability,
            audit_durability_timeout_ms,
            provenance: vec![
                inputs.drain_delay_ms.provenance(),
                inputs.timeout_ms.provenance(),
                inputs.audit_drain_timeout_ms.provenance(),
                inputs.audit_durability.provenance(),
                inputs.audit_durability_timeout_ms.provenance(),
            ],
        },
        findings,
    )
}

/// Payload capture's and the discovery signals' inputs, as the reader
/// returned them.
pub(super) struct SignalInputs {
    payload_capture_enabled: RawInput,
    payload_capture_sample_rate: RawInput,
    schema_mismatch_threshold: RawInput,
    error_rate_spike_threshold: RawInput,
    principal_new_to_endpoint_threshold: RawInput,
    volume_outlier_threshold: RawInput,
    rule_suggestion_baseline_window_hours: RawInput,
}

impl SignalInputs {
    /// Requests every input of the block once, in the inventory's order.
    pub(super) fn read(mut get_var: impl FnMut(&str) -> Result<String, VarError>) -> Self {
        Self {
            payload_capture_enabled: RawInput::new(
                PAYLOAD_CAPTURE_ENABLED,
                get_var(PAYLOAD_CAPTURE_ENABLED),
            ),
            payload_capture_sample_rate: RawInput::new(
                PAYLOAD_CAPTURE_SAMPLE_RATE,
                get_var(PAYLOAD_CAPTURE_SAMPLE_RATE),
            ),
            schema_mismatch_threshold: RawInput::new(
                SCHEMA_MISMATCH_SIGNAL_THRESHOLD,
                get_var(SCHEMA_MISMATCH_SIGNAL_THRESHOLD),
            ),
            error_rate_spike_threshold: RawInput::new(
                ERROR_RATE_SPIKE_SIGNAL_THRESHOLD,
                get_var(ERROR_RATE_SPIKE_SIGNAL_THRESHOLD),
            ),
            principal_new_to_endpoint_threshold: RawInput::new(
                PRINCIPAL_NEW_TO_ENDPOINT_SIGNAL_THRESHOLD,
                get_var(PRINCIPAL_NEW_TO_ENDPOINT_SIGNAL_THRESHOLD),
            ),
            volume_outlier_threshold: RawInput::new(
                VOLUME_OUTLIER_SIGNAL_THRESHOLD,
                get_var(VOLUME_OUTLIER_SIGNAL_THRESHOLD),
            ),
            rule_suggestion_baseline_window_hours: RawInput::new(
                RULE_SUGGESTION_BASELINE_WINDOW_HOURS,
                get_var(RULE_SUGGESTION_BASELINE_WINDOW_HOURS),
            ),
        }
    }

    fn provenance(&self) -> Vec<Provenance> {
        [
            &self.payload_capture_enabled,
            &self.payload_capture_sample_rate,
            &self.schema_mismatch_threshold,
            &self.error_rate_spike_threshold,
            &self.principal_new_to_endpoint_threshold,
            &self.volume_outlier_threshold,
            &self.rule_suggestion_baseline_window_hours,
        ]
        .into_iter()
        .map(RawInput::provenance)
        .collect()
    }
}

/// Payload capture and the discovery signals, parsed.
pub(super) struct Signals {
    payload_capture_enabled: bool,
    payload_capture_sample_rate: f64,
    schema_mismatch_signal_threshold: u64,
    error_rate_spike_signal_threshold: f64,
    principal_new_to_endpoint_signal_threshold: u64,
    volume_outlier_signal_threshold: f64,
    rule_suggestion_baseline_window_hours: u64,
    provenance: Vec<Provenance>,
}

pub(super) fn compile_signals(inputs: SignalInputs) -> Checked<Signals> {
    let mut findings = Findings::default();
    let payload_capture_enabled = findings.input(PAYLOAD_CAPTURE_ENABLED, |problems| {
        parse_var(
            PAYLOAD_CAPTURE_ENABLED,
            inputs.payload_capture_enabled.value(),
            false,
            "boolean",
            problems,
        )
    });
    let payload_capture_sample_rate = findings.input(PAYLOAD_CAPTURE_SAMPLE_RATE, |problems| {
        let rate = parse_var(
            PAYLOAD_CAPTURE_SAMPLE_RATE,
            inputs.payload_capture_sample_rate.value(),
            DEFAULT_PAYLOAD_CAPTURE_SAMPLE_RATE,
            "sample rate",
            problems,
        );
        validate_payload_capture_sample_rate(
            PAYLOAD_CAPTURE_SAMPLE_RATE,
            rate,
            DEFAULT_PAYLOAD_CAPTURE_SAMPLE_RATE,
            problems,
        )
    });
    let schema_mismatch_signal_threshold =
        findings.input(SCHEMA_MISMATCH_SIGNAL_THRESHOLD, |problems| {
            let threshold = parse_var(
                SCHEMA_MISMATCH_SIGNAL_THRESHOLD,
                inputs.schema_mismatch_threshold.value(),
                DEFAULT_SCHEMA_MISMATCH_SIGNAL_THRESHOLD,
                "positive integer",
                problems,
            );
            validate_positive_u64(
                SCHEMA_MISMATCH_SIGNAL_THRESHOLD,
                threshold,
                DEFAULT_SCHEMA_MISMATCH_SIGNAL_THRESHOLD,
                problems,
            )
        });
    let error_rate_spike_signal_threshold =
        findings.input(ERROR_RATE_SPIKE_SIGNAL_THRESHOLD, |problems| {
            let threshold = parse_var(
                ERROR_RATE_SPIKE_SIGNAL_THRESHOLD,
                inputs.error_rate_spike_threshold.value(),
                DEFAULT_ERROR_RATE_SPIKE_SIGNAL_THRESHOLD,
                "ratio threshold",
                problems,
            );
            validate_signal_ratio_threshold(
                ERROR_RATE_SPIKE_SIGNAL_THRESHOLD,
                threshold,
                DEFAULT_ERROR_RATE_SPIKE_SIGNAL_THRESHOLD,
                problems,
            )
        });
    let principal_new_to_endpoint_signal_threshold =
        findings.input(PRINCIPAL_NEW_TO_ENDPOINT_SIGNAL_THRESHOLD, |problems| {
            let threshold = parse_var(
                PRINCIPAL_NEW_TO_ENDPOINT_SIGNAL_THRESHOLD,
                inputs.principal_new_to_endpoint_threshold.value(),
                DEFAULT_PRINCIPAL_NEW_TO_ENDPOINT_SIGNAL_THRESHOLD,
                "positive integer",
                problems,
            );
            validate_positive_u64(
                PRINCIPAL_NEW_TO_ENDPOINT_SIGNAL_THRESHOLD,
                threshold,
                DEFAULT_PRINCIPAL_NEW_TO_ENDPOINT_SIGNAL_THRESHOLD,
                problems,
            )
        });
    let volume_outlier_signal_threshold =
        findings.input(VOLUME_OUTLIER_SIGNAL_THRESHOLD, |problems| {
            let threshold = parse_var(
                VOLUME_OUTLIER_SIGNAL_THRESHOLD,
                inputs.volume_outlier_threshold.value(),
                DEFAULT_VOLUME_OUTLIER_SIGNAL_THRESHOLD,
                "multiple threshold",
                problems,
            );
            validate_signal_multiple_threshold(
                VOLUME_OUTLIER_SIGNAL_THRESHOLD,
                threshold,
                DEFAULT_VOLUME_OUTLIER_SIGNAL_THRESHOLD,
                problems,
            )
        });
    let rule_suggestion_baseline_window_hours =
        findings.input(RULE_SUGGESTION_BASELINE_WINDOW_HOURS, |problems| {
            let hours = parse_var(
                RULE_SUGGESTION_BASELINE_WINDOW_HOURS,
                inputs.rule_suggestion_baseline_window_hours.value(),
                DEFAULT_RULE_SUGGESTION_BASELINE_WINDOW_HOURS,
                "hour count",
                problems,
            );
            validate_rule_suggestion_baseline_window_hours(
                RULE_SUGGESTION_BASELINE_WINDOW_HOURS,
                hours,
                DEFAULT_RULE_SUGGESTION_BASELINE_WINDOW_HOURS,
                problems,
            )
        });
    Checked::new(
        Signals {
            payload_capture_enabled,
            payload_capture_sample_rate,
            schema_mismatch_signal_threshold,
            error_rate_spike_signal_threshold,
            principal_new_to_endpoint_signal_threshold,
            volume_outlier_signal_threshold,
            rule_suggestion_baseline_window_hours,
            provenance: inputs.provenance(),
        },
        findings,
    )
}

/// Request bounds' and rate limits' inputs, as the reader returned them.
pub(super) struct RequestBoundInputs {
    cors_allow_origins: RawInput,
    max_body_size: RawInput,
    max_request_path_bytes: RawInput,
    rate_limit_read_rps: RawInput,
    rate_limit_read_burst: RawInput,
    rate_limit_write_rps: RawInput,
    rate_limit_write_burst: RawInput,
    rate_limit_max_buckets: RawInput,
    rate_limit_bucket_ttl_ms: RawInput,
}

impl RequestBoundInputs {
    /// Requests every input of the block once, in the inventory's order.
    pub(super) fn read(mut get_var: impl FnMut(&str) -> Result<String, VarError>) -> Self {
        Self {
            cors_allow_origins: RawInput::new(CORS_ALLOW_ORIGINS, get_var(CORS_ALLOW_ORIGINS)),
            max_body_size: RawInput::new(MAX_BODY_SIZE, get_var(MAX_BODY_SIZE)),
            max_request_path_bytes: RawInput::new(
                MAX_REQUEST_PATH_BYTES,
                get_var(MAX_REQUEST_PATH_BYTES),
            ),
            rate_limit_read_rps: RawInput::new(RATE_LIMIT_READ_RPS, get_var(RATE_LIMIT_READ_RPS)),
            rate_limit_read_burst: RawInput::new(
                RATE_LIMIT_READ_BURST,
                get_var(RATE_LIMIT_READ_BURST),
            ),
            rate_limit_write_rps: RawInput::new(
                RATE_LIMIT_WRITE_RPS,
                get_var(RATE_LIMIT_WRITE_RPS),
            ),
            rate_limit_write_burst: RawInput::new(
                RATE_LIMIT_WRITE_BURST,
                get_var(RATE_LIMIT_WRITE_BURST),
            ),
            rate_limit_max_buckets: RawInput::new(
                RATE_LIMIT_MAX_BUCKETS,
                get_var(RATE_LIMIT_MAX_BUCKETS),
            ),
            rate_limit_bucket_ttl_ms: RawInput::new(
                RATE_LIMIT_BUCKET_TTL_MS,
                get_var(RATE_LIMIT_BUCKET_TTL_MS),
            ),
        }
    }

    fn provenance(&self) -> Vec<Provenance> {
        [
            &self.cors_allow_origins,
            &self.max_body_size,
            &self.max_request_path_bytes,
            &self.rate_limit_read_rps,
            &self.rate_limit_read_burst,
            &self.rate_limit_write_rps,
            &self.rate_limit_write_burst,
            &self.rate_limit_max_buckets,
            &self.rate_limit_bucket_ttl_ms,
        ]
        .into_iter()
        .map(RawInput::provenance)
        .collect()
    }
}

/// Request bounds and rate limits, parsed.
pub(super) struct RequestBounds {
    cors_allow_origins: Vec<String>,
    max_body_size: usize,
    max_request_path_bytes: usize,
    rate_limit_read_rps: f64,
    rate_limit_read_burst: u32,
    rate_limit_write_rps: f64,
    rate_limit_write_burst: u32,
    rate_limit_max_buckets: usize,
    rate_limit_bucket_ttl_ms: u64,
    provenance: Vec<Provenance>,
}

pub(super) fn compile_request_bounds(inputs: RequestBoundInputs) -> Checked<RequestBounds> {
    let mut findings = Findings::default();
    let cors_allow_origins = findings.input(CORS_ALLOW_ORIGINS, |problems| {
        let origins = parse_comma_separated_header_values(
            CORS_ALLOW_ORIGINS,
            inputs.cors_allow_origins.value(),
            &[],
            problems,
        );
        validate_cors_allow_origins(CORS_ALLOW_ORIGINS, origins, problems)
    });
    let max_body_size = findings.input(MAX_BODY_SIZE, |problems| {
        parse_var(
            MAX_BODY_SIZE,
            inputs.max_body_size.value(),
            DEFAULT_MAX_BODY_SIZE,
            "byte size",
            problems,
        )
    });
    let max_request_path_bytes = findings.input(MAX_REQUEST_PATH_BYTES, |problems| {
        let bytes = parse_var(
            MAX_REQUEST_PATH_BYTES,
            inputs.max_request_path_bytes.value(),
            DEFAULT_MAX_REQUEST_PATH_BYTES,
            "byte count",
            problems,
        );
        validate_range_usize(
            MAX_REQUEST_PATH_BYTES,
            bytes,
            MIN_MAX_REQUEST_PATH_BYTES,
            crate::request_bounds::MAX_REQUEST_PATH_BYTES,
            DEFAULT_MAX_REQUEST_PATH_BYTES,
            problems,
        )
    });
    let rate_limit_read_rps = requests_per_second(
        RATE_LIMIT_READ_RPS,
        &inputs.rate_limit_read_rps,
        DEFAULT_RATE_LIMIT_READ_RPS,
        &mut findings,
    );
    let rate_limit_read_burst = findings.input(RATE_LIMIT_READ_BURST, |problems| {
        parse_var(
            RATE_LIMIT_READ_BURST,
            inputs.rate_limit_read_burst.value(),
            DEFAULT_RATE_LIMIT_READ_BURST,
            "request burst size",
            problems,
        )
    });
    let rate_limit_write_rps = requests_per_second(
        RATE_LIMIT_WRITE_RPS,
        &inputs.rate_limit_write_rps,
        DEFAULT_RATE_LIMIT_WRITE_RPS,
        &mut findings,
    );
    let rate_limit_write_burst = findings.input(RATE_LIMIT_WRITE_BURST, |problems| {
        parse_var(
            RATE_LIMIT_WRITE_BURST,
            inputs.rate_limit_write_burst.value(),
            DEFAULT_RATE_LIMIT_WRITE_BURST,
            "request burst size",
            problems,
        )
    });
    let rate_limit_max_buckets = findings.input(RATE_LIMIT_MAX_BUCKETS, |problems| {
        let buckets = parse_var(
            RATE_LIMIT_MAX_BUCKETS,
            inputs.rate_limit_max_buckets.value(),
            DEFAULT_RATE_LIMIT_MAX_BUCKETS,
            "bucket count",
            problems,
        );
        validate_positive_usize(
            RATE_LIMIT_MAX_BUCKETS,
            buckets,
            DEFAULT_RATE_LIMIT_MAX_BUCKETS,
            problems,
        )
    });
    let rate_limit_bucket_ttl_ms = findings.input(RATE_LIMIT_BUCKET_TTL_MS, |problems| {
        let ttl_ms = parse_var(
            RATE_LIMIT_BUCKET_TTL_MS,
            inputs.rate_limit_bucket_ttl_ms.value(),
            DEFAULT_RATE_LIMIT_BUCKET_TTL_MS,
            "millisecond duration",
            problems,
        );
        validate_positive_timeout_ms(
            RATE_LIMIT_BUCKET_TTL_MS,
            ttl_ms,
            DEFAULT_RATE_LIMIT_BUCKET_TTL_MS,
            problems,
        )
    });
    Checked::new(
        RequestBounds {
            cors_allow_origins,
            max_body_size,
            max_request_path_bytes,
            rate_limit_read_rps,
            rate_limit_read_burst,
            rate_limit_write_rps,
            rate_limit_write_burst,
            rate_limit_max_buckets,
            rate_limit_bucket_ttl_ms,
            provenance: inputs.provenance(),
        },
        findings,
    )
}

/// A finite, non-negative requests-per-second rate with a default.
fn requests_per_second(
    setting: &'static str,
    input: &RawInput,
    default: f64,
    findings: &mut Findings,
) -> f64 {
    findings.input(setting, |problems| {
        let rate = parse_var(
            setting,
            input.value(),
            default,
            "requests-per-second number",
            problems,
        );
        validate_finite_non_negative(setting, rate, default, problems)
    })
}

/// The accepted request content types' input, as the reader returned it.
pub(super) struct ContentTypeInputs {
    allowed_content_types: RawInput,
}

impl ContentTypeInputs {
    pub(super) fn read(mut get_var: impl FnMut(&str) -> Result<String, VarError>) -> Self {
        Self {
            allowed_content_types: RawInput::list_replacing_its_default(
                VALIDATION_ALLOWED_CONTENT_TYPES,
                get_var(VALIDATION_ALLOWED_CONTENT_TYPES),
            ),
        }
    }
}

/// The content types request validation accepts, parsed.
pub(super) struct ContentTypes {
    validation_allowed_content_types: Vec<String>,
    provenance: Vec<Provenance>,
}

pub(super) fn compile_content_types(inputs: ContentTypeInputs) -> Checked<ContentTypes> {
    let mut findings = Findings::default();
    let validation_allowed_content_types =
        findings.input(VALIDATION_ALLOWED_CONTENT_TYPES, |problems| {
            parse_comma_separated_header_values(
                VALIDATION_ALLOWED_CONTENT_TYPES,
                inputs.allowed_content_types.value(),
                DEFAULT_VALIDATION_ALLOWED_CONTENT_TYPES,
                problems,
            )
        });
    Checked::new(
        ContentTypes {
            validation_allowed_content_types,
            provenance: vec![inputs.allowed_content_types.provenance()],
        },
        findings,
    )
}

/// The tool runtime queue's inputs, as the reader returned them.
pub(super) struct ToolRuntimeInputs {
    queue_depth: RawInput,
    global_concurrency: RawInput,
    queue_timeout_ms: RawInput,
}

impl ToolRuntimeInputs {
    /// Requests every input of the block once, in the inventory's order.
    pub(super) fn read(mut get_var: impl FnMut(&str) -> Result<String, VarError>) -> Self {
        Self {
            queue_depth: RawInput::new(TOOL_RUNTIME_QUEUE_DEPTH, get_var(TOOL_RUNTIME_QUEUE_DEPTH)),
            global_concurrency: RawInput::new(
                TOOL_RUNTIME_GLOBAL_CONCURRENCY,
                get_var(TOOL_RUNTIME_GLOBAL_CONCURRENCY),
            ),
            queue_timeout_ms: RawInput::new(
                TOOL_RUNTIME_QUEUE_TIMEOUT_MS,
                get_var(TOOL_RUNTIME_QUEUE_TIMEOUT_MS),
            ),
        }
    }
}

/// The tool runtime's queue, parsed.
pub(super) struct ToolRuntime {
    tool_runtime_queue_depth: usize,
    tool_runtime_global_concurrency: usize,
    tool_runtime_queue_timeout_ms: u64,
    provenance: Vec<Provenance>,
}

pub(super) fn compile_tool_runtime(inputs: ToolRuntimeInputs) -> Checked<ToolRuntime> {
    let mut findings = Findings::default();
    let tool_runtime_queue_depth = findings.input(TOOL_RUNTIME_QUEUE_DEPTH, |problems| {
        let depth = parse_var(
            TOOL_RUNTIME_QUEUE_DEPTH,
            inputs.queue_depth.value(),
            DEFAULT_TOOL_RUNTIME_QUEUE_DEPTH,
            "positive integer",
            problems,
        );
        validate_positive_usize(
            TOOL_RUNTIME_QUEUE_DEPTH,
            depth,
            DEFAULT_TOOL_RUNTIME_QUEUE_DEPTH,
            problems,
        )
    });
    let tool_runtime_global_concurrency =
        findings.input(TOOL_RUNTIME_GLOBAL_CONCURRENCY, |problems| {
            let concurrency = parse_var(
                TOOL_RUNTIME_GLOBAL_CONCURRENCY,
                inputs.global_concurrency.value(),
                DEFAULT_TOOL_RUNTIME_GLOBAL_CONCURRENCY,
                "positive integer",
                problems,
            );
            validate_positive_usize(
                TOOL_RUNTIME_GLOBAL_CONCURRENCY,
                concurrency,
                DEFAULT_TOOL_RUNTIME_GLOBAL_CONCURRENCY,
                problems,
            )
        });
    let tool_runtime_queue_timeout_ms = findings.input(TOOL_RUNTIME_QUEUE_TIMEOUT_MS, |problems| {
        let timeout_ms = parse_var(
            TOOL_RUNTIME_QUEUE_TIMEOUT_MS,
            inputs.queue_timeout_ms.value(),
            DEFAULT_TOOL_RUNTIME_QUEUE_TIMEOUT_MS,
            "millisecond duration",
            problems,
        );
        validate_positive_u64(
            TOOL_RUNTIME_QUEUE_TIMEOUT_MS,
            timeout_ms,
            DEFAULT_TOOL_RUNTIME_QUEUE_TIMEOUT_MS,
            problems,
        )
    });
    Checked::new(
        ToolRuntime {
            tool_runtime_queue_depth,
            tool_runtime_global_concurrency,
            tool_runtime_queue_timeout_ms,
            provenance: vec![
                inputs.queue_depth.provenance(),
                inputs.global_concurrency.provenance(),
                inputs.queue_timeout_ms.provenance(),
            ],
        },
        findings,
    )
}

/// The tool runtime's default timeout's input, as the reader returned it.
pub(super) struct ToolTimeoutInputs {
    default_timeout_ms: RawInput,
}

impl ToolTimeoutInputs {
    pub(super) fn read(mut get_var: impl FnMut(&str) -> Result<String, VarError>) -> Self {
        Self {
            default_timeout_ms: RawInput::new(
                TOOL_RUNTIME_DEFAULT_TIMEOUT_MS,
                get_var(TOOL_RUNTIME_DEFAULT_TIMEOUT_MS),
            ),
        }
    }
}

/// The runtime blocks read before the last one.
pub(super) struct RuntimeBlocks {
    pub(super) shutdown: Shutdown,
    pub(super) signals: Signals,
    pub(super) request_bounds: RequestBounds,
    pub(super) content_types: ContentTypes,
    pub(super) tool_runtime: ToolRuntime,
}

/// The validated runtime bounds.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct RuntimePlan {
    pub(crate) shutdown_drain_delay_ms: u64,
    pub(crate) shutdown_timeout_ms: u64,
    pub(crate) audit_drain_timeout_ms: u64,
    pub(crate) audit_durability: AuditDurability,
    pub(crate) audit_durability_timeout_ms: u64,
    pub(crate) payload_capture_enabled: bool,
    pub(crate) payload_capture_sample_rate: f64,
    pub(crate) schema_mismatch_signal_threshold: u64,
    pub(crate) error_rate_spike_signal_threshold: f64,
    pub(crate) principal_new_to_endpoint_signal_threshold: u64,
    pub(crate) volume_outlier_signal_threshold: f64,
    pub(crate) rule_suggestion_baseline_window_hours: u64,
    pub(crate) cors_allow_origins: Vec<String>,
    pub(crate) max_body_size: usize,
    pub(crate) max_request_path_bytes: usize,
    pub(crate) rate_limit_read_rps: f64,
    pub(crate) rate_limit_read_burst: u32,
    pub(crate) rate_limit_write_rps: f64,
    pub(crate) rate_limit_write_burst: u32,
    pub(crate) rate_limit_max_buckets: usize,
    pub(crate) rate_limit_bucket_ttl_ms: u64,
    pub(crate) validation_allowed_content_types: Vec<String>,
    pub(crate) tool_runtime_queue_depth: usize,
    pub(crate) tool_runtime_global_concurrency: usize,
    pub(crate) tool_runtime_queue_timeout_ms: u64,
    pub(crate) tool_runtime_default_timeout_ms: u64,
    /// Where each of the six blocks' inputs came from, in the order they are
    /// read.
    #[allow(dead_code)] // Read by the stage tests until startup consumes the plan (#433 PR 3).
    pub(crate) provenance: Vec<Provenance>,
}

/// Parses the last runtime block and builds the plan.
pub(super) fn compile(inputs: ToolTimeoutInputs, blocks: RuntimeBlocks) -> Checked<RuntimePlan> {
    let mut findings = Findings::default();
    let tool_runtime_default_timeout_ms =
        findings.input(TOOL_RUNTIME_DEFAULT_TIMEOUT_MS, |problems| {
            let timeout_ms = parse_var(
                TOOL_RUNTIME_DEFAULT_TIMEOUT_MS,
                inputs.default_timeout_ms.value(),
                DEFAULT_TOOL_RUNTIME_DEFAULT_TIMEOUT_MS,
                "millisecond duration",
                problems,
            );
            validate_positive_u64(
                TOOL_RUNTIME_DEFAULT_TIMEOUT_MS,
                timeout_ms,
                DEFAULT_TOOL_RUNTIME_DEFAULT_TIMEOUT_MS,
                problems,
            )
        });

    let RuntimeBlocks {
        shutdown:
            Shutdown {
                shutdown_drain_delay_ms,
                shutdown_timeout_ms,
                audit_drain_timeout_ms,
                audit_durability,
                audit_durability_timeout_ms,
                provenance: shutdown_provenance,
            },
        signals:
            Signals {
                payload_capture_enabled,
                payload_capture_sample_rate,
                schema_mismatch_signal_threshold,
                error_rate_spike_signal_threshold,
                principal_new_to_endpoint_signal_threshold,
                volume_outlier_signal_threshold,
                rule_suggestion_baseline_window_hours,
                provenance: signals_provenance,
            },
        request_bounds:
            RequestBounds {
                cors_allow_origins,
                max_body_size,
                max_request_path_bytes,
                rate_limit_read_rps,
                rate_limit_read_burst,
                rate_limit_write_rps,
                rate_limit_write_burst,
                rate_limit_max_buckets,
                rate_limit_bucket_ttl_ms,
                provenance: request_bounds_provenance,
            },
        content_types:
            ContentTypes {
                validation_allowed_content_types,
                provenance: content_types_provenance,
            },
        tool_runtime:
            ToolRuntime {
                tool_runtime_queue_depth,
                tool_runtime_global_concurrency,
                tool_runtime_queue_timeout_ms,
                provenance: tool_runtime_provenance,
            },
    } = blocks;
    let provenance = [
        shutdown_provenance,
        signals_provenance,
        request_bounds_provenance,
        content_types_provenance,
        tool_runtime_provenance,
        vec![inputs.default_timeout_ms.provenance()],
    ]
    .concat();

    Checked::new(
        RuntimePlan {
            shutdown_drain_delay_ms,
            shutdown_timeout_ms,
            audit_drain_timeout_ms,
            audit_durability,
            audit_durability_timeout_ms,
            payload_capture_enabled,
            payload_capture_sample_rate,
            schema_mismatch_signal_threshold,
            error_rate_spike_signal_threshold,
            principal_new_to_endpoint_signal_threshold,
            volume_outlier_signal_threshold,
            rule_suggestion_baseline_window_hours,
            cors_allow_origins,
            max_body_size,
            max_request_path_bytes,
            rate_limit_read_rps,
            rate_limit_read_burst,
            rate_limit_write_rps,
            rate_limit_write_burst,
            rate_limit_max_buckets,
            rate_limit_bucket_ttl_ms,
            validation_allowed_content_types,
            tool_runtime_queue_depth,
            tool_runtime_global_concurrency,
            tool_runtime_queue_timeout_ms,
            tool_runtime_default_timeout_ms,
            provenance,
        },
        findings,
    )
}
