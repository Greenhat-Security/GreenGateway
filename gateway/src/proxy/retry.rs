use std::{collections::HashSet, sync::Arc, time::Duration};

use http::{Method, StatusCode};
use sha2::{Digest, Sha256};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::{config, egress};

const RETRY_BACKOFF_BASE: Duration = Duration::from_millis(25);
const RETRY_BACKOFF_MAX: Duration = Duration::from_millis(250);
const RETRY_BUDGET_DIVISOR: usize = 10;
const RETRY_BUDGET_MAX_CONCURRENT: usize = 32;

#[derive(Clone, Debug)]
pub(super) struct RetryPolicy {
    max_attempts: u8,
    methods: HashSet<Method>,
    statuses: HashSet<StatusCode>,
}

impl RetryPolicy {
    pub(super) fn disabled() -> Self {
        Self {
            max_attempts: config::DEFAULT_UPSTREAM_RETRY_MAX_ATTEMPTS,
            methods: HashSet::new(),
            statuses: HashSet::new(),
        }
    }

    pub(super) fn from_config(config: Option<&config::UpstreamRetryConfig>) -> Self {
        let Some(config) = config else {
            return Self::disabled();
        };
        Self {
            max_attempts: config.max_attempts,
            methods: config
                .methods
                .iter()
                .map(|method| {
                    Method::from_bytes(method.as_bytes())
                        .expect("validated retry method should parse")
                })
                .collect(),
            statuses: config
                .statuses
                .iter()
                .map(|status| {
                    StatusCode::from_u16(*status).expect("validated retry status should parse")
                })
                .collect(),
        }
    }

    pub(super) fn max_attempts_for(&self, method: &Method, replayable_body: bool) -> u8 {
        if replayable_body && self.methods.contains(method) {
            self.max_attempts
        } else {
            1
        }
    }

    pub(super) fn retries_status(&self, status: StatusCode) -> bool {
        self.statuses.contains(&status)
    }

    pub(super) fn retries_error(&self, error: &egress::EgressError) -> bool {
        error.is_retryable_transport_failure()
    }
}

#[derive(Clone)]
pub(super) struct RetryBudget {
    permits: Arc<Semaphore>,
}

impl RetryBudget {
    pub(super) fn new(max_in_flight: usize) -> Self {
        let max_concurrent = max_in_flight
            .div_ceil(RETRY_BUDGET_DIVISOR)
            .clamp(1, RETRY_BUDGET_MAX_CONCURRENT);
        Self {
            permits: Arc::new(Semaphore::new(max_concurrent)),
        }
    }

    pub(super) fn try_acquire(&self) -> Option<OwnedSemaphorePermit> {
        Arc::clone(&self.permits).try_acquire_owned().ok()
    }

    #[cfg(test)]
    fn max_concurrent(&self) -> usize {
        self.permits.available_permits()
    }
}

pub(super) fn retry_backoff(request_id: &[u8], failed_attempt: u8) -> Duration {
    let exponent = u32::from(failed_attempt.saturating_sub(1)).min(8);
    let ceiling_ms = RETRY_BACKOFF_BASE
        .as_millis()
        .saturating_mul(1_u128 << exponent)
        .min(RETRY_BACKOFF_MAX.as_millis()) as u64;
    let floor_ms = ceiling_ms.div_ceil(2);

    let mut digest = Sha256::new();
    digest.update(b"greengateway:proxy-retry-backoff:v1\0");
    digest.update(request_id);
    digest.update([failed_attempt]);
    let digest = digest.finalize();
    let random = u64::from_be_bytes(
        digest[..8]
            .try_into()
            .expect("SHA-256 prefix should be eight bytes"),
    );
    let width = ceiling_ms.saturating_sub(floor_ms).saturating_add(1);
    Duration::from_millis(floor_ms.saturating_add(random % width))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_defaults_to_exactly_one_attempt() {
        let policy = RetryPolicy::disabled();

        assert_eq!(policy.max_attempts_for(&Method::GET, true), 1);
        assert!(!policy.retries_status(StatusCode::BAD_GATEWAY));
    }

    #[test]
    fn non_replayable_body_and_unconfigured_method_force_one_attempt() {
        let config = config::UpstreamRetryConfig {
            max_attempts: 3,
            methods: vec!["GET".to_owned()],
            statuses: vec![502],
        };
        let policy = RetryPolicy::from_config(Some(&config));

        assert_eq!(policy.max_attempts_for(&Method::GET, true), 3);
        assert_eq!(policy.max_attempts_for(&Method::GET, false), 1);
        assert_eq!(policy.max_attempts_for(&Method::POST, true), 1);
    }

    #[test]
    fn policy_and_body_failures_are_never_retryable() {
        let config = config::UpstreamRetryConfig {
            max_attempts: 3,
            methods: vec!["GET".to_owned()],
            statuses: vec![502],
        };
        let policy = RetryPolicy::from_config(Some(&config));

        for error in [
            egress::EgressError::HostNotAllowed("secret.example".to_owned()),
            egress::EgressError::DnsResolutionFailed("secret.example".to_owned()),
            egress::EgressError::RequestBodyReadFailed,
            egress::EgressError::InvalidTlsCaBundle {
                path: "secret.pem".into(),
                message: "private".to_owned(),
            },
        ] {
            assert!(!policy.retries_error(&error));
        }
    }

    #[test]
    fn retry_budget_is_bounded_and_non_blocking() {
        let budget = RetryBudget::new(1_000);
        assert_eq!(budget.max_concurrent(), RETRY_BUDGET_MAX_CONCURRENT);
        let permits = (0..RETRY_BUDGET_MAX_CONCURRENT)
            .map(|_| budget.try_acquire().expect("budget permit"))
            .collect::<Vec<_>>();
        assert!(budget.try_acquire().is_none());
        drop(permits);
        assert!(budget.try_acquire().is_some());
    }

    #[test]
    fn backoff_is_bounded_exponential_and_request_scoped() {
        let first = retry_backoff(b"request-a", 1);
        let second = retry_backoff(b"request-a", 2);
        let capped = retry_backoff(b"request-a", 9);

        assert!((Duration::from_millis(13)..=Duration::from_millis(25)).contains(&first));
        assert!((Duration::from_millis(25)..=Duration::from_millis(50)).contains(&second));
        assert!((Duration::from_millis(125)..=RETRY_BACKOFF_MAX).contains(&capped));
        assert_eq!(first, retry_backoff(b"request-a", 1));
    }
}
