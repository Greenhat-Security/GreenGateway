//! The delivery cadence the cluster and the standalone dispatchers share
//! (issue #425): how often an idle dispatcher looks again, how many rows one
//! batch holds, and how long a failed step waits before it is retried.

use std::{hash::BuildHasher, time::Duration};

use tokio_util::sync::CancellationToken;

/// Defaults for the cadence. These are not settings: they bound load on the
/// authority, not anything an operator's sink needs to tune.
pub(crate) const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(1);
pub(crate) const DEFAULT_BATCH_SIZE: usize = 100;
pub(crate) const DEFAULT_RETRY_BASE: Duration = Duration::from_millis(500);
pub(crate) const DEFAULT_RETRY_CAP: Duration = Duration::from_secs(60);

/// How a dispatcher runs.
#[derive(Clone, Copy, Debug)]
pub(crate) struct DispatcherConfig {
    /// The wait when nothing is after the cursor.
    pub(crate) poll_interval: Duration,
    /// Rows per batch, at most the store's read bound.
    pub(crate) batch_size: usize,
    /// The first retry wait after a failure; it doubles per consecutive
    /// failure up to `retry_cap`.
    pub(crate) retry_base: Duration,
    pub(crate) retry_cap: Duration,
}

impl Default for DispatcherConfig {
    fn default() -> Self {
        Self {
            poll_interval: DEFAULT_POLL_INTERVAL,
            batch_size: DEFAULT_BATCH_SIZE,
            retry_base: DEFAULT_RETRY_BASE,
            retry_cap: DEFAULT_RETRY_CAP,
        }
    }
}

/// The wait before retry number `failures` (1 for the first): `base`
/// doubled per earlier failure, capped, plus up to a quarter more of jitter
/// so a fleet of dispatchers recovering from one outage does not retry in
/// lockstep. Never below one millisecond.
pub(crate) fn retry_backoff(base: Duration, cap: Duration, failures: u32) -> Duration {
    let exponent = failures.saturating_sub(1).min(20);
    let doubled = base.saturating_mul(1_u32 << exponent);
    let capped = doubled.min(cap).max(Duration::from_millis(1));
    let jitter_steps = std::collections::hash_map::RandomState::new().hash_one(failures) % 256;
    capped + capped.mul_f64(jitter_steps as f64 / 1024.0)
}

/// Sleep for `duration`, or less if `stop` fires first.
pub(crate) async fn sleep_or_stop(stop: &CancellationToken, duration: Duration) {
    tokio::select! {
        () = stop.cancelled() => {}
        () = tokio::time::sleep(duration) => {}
    }
}
