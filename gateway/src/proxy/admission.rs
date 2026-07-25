use std::{sync::Arc, time::Duration};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::metrics::{
    PROXY_ADMISSION_ACTIVE, PROXY_ADMISSION_QUEUED, PROXY_ADMISSION_REJECTIONS_TOTAL,
};

#[derive(Clone)]
pub(super) struct PoolAdmission {
    pool_id: Arc<str>,
    in_flight: Arc<Semaphore>,
    queue: Arc<Semaphore>,
    queue_timeout: Duration,
}

pub(super) struct PoolAdmissionPermit {
    pool_id: Arc<str>,
    _in_flight: OwnedSemaphorePermit,
}

struct QueuedGauge {
    pool_id: Arc<str>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PoolAdmissionError {
    QueueFull,
    QueueTimeout,
}

impl PoolAdmission {
    pub(super) fn new(
        pool_id: Arc<str>,
        max_in_flight: usize,
        queue_depth: usize,
        queue_timeout: Duration,
    ) -> Self {
        Self {
            pool_id,
            in_flight: Arc::new(Semaphore::new(max_in_flight)),
            queue: Arc::new(Semaphore::new(queue_depth)),
            queue_timeout,
        }
    }

    pub(super) async fn acquire(&self) -> Result<PoolAdmissionPermit, PoolAdmissionError> {
        if let Ok(permit) = Arc::clone(&self.in_flight).try_acquire_owned() {
            return Ok(self.permit(permit));
        }

        let queue_permit = Arc::clone(&self.queue).try_acquire_owned().map_err(|_| {
            self.record_rejection("queue_full");
            PoolAdmissionError::QueueFull
        })?;
        ::metrics::gauge!(
            PROXY_ADMISSION_QUEUED,
            "pool_id" => Arc::clone(&self.pool_id)
        )
        .increment(1.0);
        let queued_gauge = QueuedGauge {
            pool_id: Arc::clone(&self.pool_id),
        };

        let acquire = Arc::clone(&self.in_flight).acquire_owned();
        let permit = tokio::time::timeout(self.queue_timeout, acquire)
            .await
            .map_err(|_| {
                self.record_rejection("queue_timeout");
                PoolAdmissionError::QueueTimeout
            })
            .and_then(|result| {
                result.map_err(|_| {
                    self.record_rejection("closed");
                    PoolAdmissionError::QueueFull
                })
            });

        drop(queue_permit);
        drop(queued_gauge);
        permit.map(|permit| self.permit(permit))
    }

    fn permit(&self, permit: OwnedSemaphorePermit) -> PoolAdmissionPermit {
        ::metrics::gauge!(
            PROXY_ADMISSION_ACTIVE,
            "pool_id" => Arc::clone(&self.pool_id)
        )
        .increment(1.0);
        PoolAdmissionPermit {
            pool_id: Arc::clone(&self.pool_id),
            _in_flight: permit,
        }
    }

    fn record_rejection(&self, reason: &'static str) {
        ::metrics::counter!(
            PROXY_ADMISSION_REJECTIONS_TOTAL,
            "pool_id" => Arc::clone(&self.pool_id),
            "reason" => reason
        )
        .increment(1);
    }
}

impl Drop for PoolAdmissionPermit {
    fn drop(&mut self) {
        ::metrics::gauge!(
            PROXY_ADMISSION_ACTIVE,
            "pool_id" => Arc::clone(&self.pool_id)
        )
        .decrement(1.0);
    }
}

impl Drop for QueuedGauge {
    fn drop(&mut self) {
        ::metrics::gauge!(
            PROXY_ADMISSION_QUEUED,
            "pool_id" => Arc::clone(&self.pool_id)
        )
        .decrement(1.0);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[tokio::test]
    async fn queue_is_hard_bounded_and_times_out() {
        let admission = PoolAdmission::new(Arc::from("payments"), 1, 1, Duration::from_millis(10));
        let active = admission.acquire().await.expect("first request admits");
        let queued_admission = admission.clone();
        let queued = tokio::spawn(async move { queued_admission.acquire().await });
        tokio::task::yield_now().await;

        assert!(matches!(
            admission.acquire().await,
            Err(PoolAdmissionError::QueueFull)
        ));
        assert!(matches!(
            queued.await.expect("queued task should complete"),
            Err(PoolAdmissionError::QueueTimeout)
        ));
        drop(active);
        admission
            .acquire()
            .await
            .expect("permit should release after completion");
    }

    #[tokio::test]
    async fn cancelling_waiter_releases_queue_slot() {
        let admission = PoolAdmission::new(Arc::from("payments"), 1, 1, Duration::from_secs(1));
        let active = admission.acquire().await.expect("first request admits");
        let queued_admission = admission.clone();
        let queued = tokio::spawn(async move { queued_admission.acquire().await });
        tokio::task::yield_now().await;
        queued.abort();
        let _ = queued.await;

        drop(active);
        admission
            .acquire()
            .await
            .expect("cancelled waiter must release all permits");
    }
}
