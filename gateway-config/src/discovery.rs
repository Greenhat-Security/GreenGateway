//! The discovery settings the configuration compiler reads: the signal
//! detector thresholds and the rule suggestion baseline window, with their
//! defaults.
//!
//! The gateway's detectors and suggestion engine take these as they are; the
//! gateway re-exports them from `discovery::signals` and
//! `discovery::suggestions`.

pub const DEFAULT_SCHEMA_MISMATCH_SIGNAL_THRESHOLD: u64 = 5;
pub const DEFAULT_ERROR_RATE_SPIKE_SIGNAL_THRESHOLD: f64 = 0.40;
pub const DEFAULT_PRINCIPAL_NEW_TO_ENDPOINT_SIGNAL_THRESHOLD: u64 = 1;
pub const DEFAULT_VOLUME_OUTLIER_SIGNAL_THRESHOLD: f64 = 3.0;

pub const DEFAULT_RULE_SUGGESTION_BASELINE_WINDOW_HOURS: u64 = 24;
pub const MAX_RULE_SUGGESTION_BASELINE_WINDOW_HOURS: u64 = 876_000;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SignalDetectorConfig {
    pub schema_mismatch_threshold: u64,
    pub error_rate_spike_threshold: f64,
    pub principal_new_to_endpoint_threshold: u64,
    pub volume_outlier_threshold: f64,
}

impl Default for SignalDetectorConfig {
    fn default() -> Self {
        Self {
            schema_mismatch_threshold: DEFAULT_SCHEMA_MISMATCH_SIGNAL_THRESHOLD,
            error_rate_spike_threshold: DEFAULT_ERROR_RATE_SPIKE_SIGNAL_THRESHOLD,
            principal_new_to_endpoint_threshold: DEFAULT_PRINCIPAL_NEW_TO_ENDPOINT_SIGNAL_THRESHOLD,
            volume_outlier_threshold: DEFAULT_VOLUME_OUTLIER_SIGNAL_THRESHOLD,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuleSuggestionConfig {
    pub baseline_window_hours: u64,
}

impl Default for RuleSuggestionConfig {
    fn default() -> Self {
        Self {
            baseline_window_hours: DEFAULT_RULE_SUGGESTION_BASELINE_WINDOW_HOURS,
        }
    }
}
