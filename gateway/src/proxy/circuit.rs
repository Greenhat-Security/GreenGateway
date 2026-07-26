use std::{
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use serde_json::json;

use crate::{audit, config};

const DEFAULT_FAILURE_STATUSES: &[u16] = &[502, 503, 504];
const FAILURE_WINDOW: Duration = Duration::from_secs(60);

#[derive(Clone)]
pub(super) struct CircuitBreaker {
    inner: Arc<CircuitBreakerInner>,
}

struct CircuitBreakerInner {
    pool_id: Arc<str>,
    endpoint_id: Arc<str>,
    config: config::UpstreamCircuitBreakerConfig,
    clock: Arc<dyn CircuitClock>,
    audit: Option<audit::AuditLog>,
    failure_statuses: Vec<u16>,
    state: Mutex<CircuitState>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CircuitState {
    Closed {
        generation: u64,
        consecutive_failures: u32,
        window_started_at: Option<Instant>,
    },
    Open {
        generation: u64,
        until: Instant,
    },
    HalfOpen {
        generation: u64,
        in_flight: u32,
        successes: u32,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PermitKind {
    Closed,
    HalfOpen,
}

pub(super) struct CircuitPermit {
    breaker: CircuitBreaker,
    generation: u64,
    kind: PermitKind,
    completed: bool,
}

pub(super) trait CircuitClock: Send + Sync {
    fn now(&self) -> Instant;
}

#[derive(Debug, Default)]
pub(super) struct SystemCircuitClock;

impl CircuitClock for SystemCircuitClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

impl CircuitBreaker {
    pub(super) fn new(
        pool_id: Arc<str>,
        endpoint_id: Arc<str>,
        config: config::UpstreamCircuitBreakerConfig,
        retry: Option<&config::UpstreamRetryConfig>,
        audit: Option<audit::AuditLog>,
    ) -> Self {
        Self::new_with_clock(
            pool_id,
            endpoint_id,
            config,
            retry,
            Arc::new(SystemCircuitClock),
            audit,
        )
    }

    fn new_with_clock(
        pool_id: Arc<str>,
        endpoint_id: Arc<str>,
        config: config::UpstreamCircuitBreakerConfig,
        retry: Option<&config::UpstreamRetryConfig>,
        clock: Arc<dyn CircuitClock>,
        audit: Option<audit::AuditLog>,
    ) -> Self {
        Self {
            inner: Arc::new(CircuitBreakerInner {
                pool_id,
                endpoint_id,
                config,
                clock,
                audit,
                failure_statuses: retry.map_or_else(
                    || DEFAULT_FAILURE_STATUSES.to_vec(),
                    |retry| retry.statuses.clone(),
                ),
                state: Mutex::new(CircuitState::Closed {
                    generation: 0,
                    consecutive_failures: 0,
                    window_started_at: None,
                }),
            }),
        }
    }

    pub(super) fn try_acquire(&self) -> Option<CircuitPermit> {
        let now = self.inner.clock.now();
        let mut transition = None;
        let permit = {
            let mut state = self.lock_state();
            match *state {
                CircuitState::Closed { generation, .. } => Some(CircuitPermit {
                    breaker: self.clone(),
                    generation,
                    kind: PermitKind::Closed,
                    completed: false,
                }),
                CircuitState::Open { until, .. } if now < until => None,
                CircuitState::Open { generation, .. } => {
                    let generation = generation.wrapping_add(1);
                    *state = CircuitState::HalfOpen {
                        generation,
                        in_flight: 1,
                        successes: 0,
                    };
                    transition = Some(("open", "half_open", "cooldown_elapsed"));
                    Some(CircuitPermit {
                        breaker: self.clone(),
                        generation,
                        kind: PermitKind::HalfOpen,
                        completed: false,
                    })
                }
                CircuitState::HalfOpen {
                    generation,
                    in_flight,
                    successes,
                } if in_flight < self.inner.config.half_open_max_requests => {
                    *state = CircuitState::HalfOpen {
                        generation,
                        in_flight: in_flight + 1,
                        successes,
                    };
                    Some(CircuitPermit {
                        breaker: self.clone(),
                        generation,
                        kind: PermitKind::HalfOpen,
                        completed: false,
                    })
                }
                CircuitState::HalfOpen { .. } => None,
            }
        };
        if let Some((from, to, reason)) = transition {
            self.emit_transition(from, to, reason);
        }
        if permit.is_none() {
            ::metrics::counter!(
                crate::metrics::UPSTREAM_CIRCUIT_REJECTIONS_TOTAL,
                "pool_id" => Arc::clone(&self.inner.pool_id),
                "endpoint_id" => Arc::clone(&self.inner.endpoint_id)
            )
            .increment(1);
        }
        permit
    }

    pub(super) fn is_failure_status(&self, status: u16) -> bool {
        self.inner.failure_statuses.contains(&status)
    }

    fn record_success(&self, generation: u64, kind: PermitKind) {
        let mut transition = None;
        {
            let mut state = self.lock_state();
            match (*state, kind) {
                (
                    CircuitState::Closed {
                        generation: current,
                        ..
                    },
                    PermitKind::Closed,
                ) if current == generation => {
                    *state = CircuitState::Closed {
                        generation,
                        consecutive_failures: 0,
                        window_started_at: None,
                    };
                }
                (
                    CircuitState::HalfOpen {
                        generation: current,
                        in_flight,
                        successes,
                    },
                    PermitKind::HalfOpen,
                ) if current == generation => {
                    let successes = successes.saturating_add(1);
                    if successes >= self.inner.config.recovery_threshold {
                        let next_generation = generation.wrapping_add(1);
                        *state = CircuitState::Closed {
                            generation: next_generation,
                            consecutive_failures: 0,
                            window_started_at: None,
                        };
                        transition = Some(("half_open", "closed", "recovery_threshold"));
                    } else {
                        *state = CircuitState::HalfOpen {
                            generation,
                            in_flight: in_flight.saturating_sub(1),
                            successes,
                        };
                    }
                }
                _ => {}
            }
        }
        if let Some((from, to, reason)) = transition {
            self.emit_transition(from, to, reason);
        }
    }

    fn record_failure(&self, generation: u64, kind: PermitKind, reason: &'static str) {
        let now = self.inner.clock.now();
        let mut transition = None;
        {
            let mut state = self.lock_state();
            match (*state, kind) {
                (
                    CircuitState::Closed {
                        generation: current,
                        consecutive_failures,
                        window_started_at,
                    },
                    PermitKind::Closed,
                ) if current == generation => {
                    let window_expired = window_started_at.is_some_and(|started| {
                        now.saturating_duration_since(started) >= FAILURE_WINDOW
                    });
                    let failures = if window_expired {
                        1
                    } else {
                        consecutive_failures.saturating_add(1)
                    };
                    let window_started_at = if consecutive_failures == 0 || window_expired {
                        Some(now)
                    } else {
                        window_started_at
                    };
                    if failures >= self.inner.config.failure_threshold {
                        let next_generation = generation.wrapping_add(1);
                        *state = CircuitState::Open {
                            generation: next_generation,
                            until: now + Duration::from_millis(self.inner.config.open_ms),
                        };
                        transition = Some(("closed", "open", reason));
                    } else {
                        *state = CircuitState::Closed {
                            generation,
                            consecutive_failures: failures,
                            window_started_at,
                        };
                    }
                }
                (
                    CircuitState::HalfOpen {
                        generation: current,
                        ..
                    },
                    PermitKind::HalfOpen,
                ) if current == generation => {
                    let next_generation = generation.wrapping_add(1);
                    *state = CircuitState::Open {
                        generation: next_generation,
                        until: now + Duration::from_millis(self.inner.config.open_ms),
                    };
                    transition = Some(("half_open", "open", reason));
                }
                _ => {}
            }
        }
        if let Some((from, to, reason)) = transition {
            self.emit_transition(from, to, reason);
        }
    }

    fn cancel(&self, generation: u64, kind: PermitKind) {
        if kind != PermitKind::HalfOpen {
            return;
        }
        let mut state = self.lock_state();
        if let CircuitState::HalfOpen {
            generation: current,
            in_flight,
            successes,
        } = *state
        {
            if current == generation {
                *state = CircuitState::HalfOpen {
                    generation,
                    in_flight: in_flight.saturating_sub(1),
                    successes,
                };
            }
        }
    }

    fn lock_state(&self) -> MutexGuard<'_, CircuitState> {
        match self.inner.state.lock() {
            Ok(state) => state,
            Err(poisoned) => {
                ::metrics::counter!(
                    crate::metrics::LOCK_POISON_RECOVERIES_TOTAL,
                    "component" => "proxy_circuit"
                )
                .increment(1);
                poisoned.into_inner()
            }
        }
    }

    fn emit_transition(&self, from: &'static str, to: &'static str, reason: &'static str) {
        ::metrics::counter!(
            crate::metrics::UPSTREAM_CIRCUIT_TRANSITIONS_TOTAL,
            "pool_id" => Arc::clone(&self.inner.pool_id),
            "endpoint_id" => Arc::clone(&self.inner.endpoint_id),
            "from" => from,
            "to" => to,
            "reason" => reason
        )
        .increment(1);
        match to {
            "open" => tracing::warn!(
                pool_id = self.inner.pool_id.as_ref(),
                endpoint_id = self.inner.endpoint_id.as_ref(),
                from,
                reason,
                "upstream endpoint circuit opened"
            ),
            _ => tracing::info!(
                pool_id = self.inner.pool_id.as_ref(),
                endpoint_id = self.inner.endpoint_id.as_ref(),
                from,
                to,
                reason,
                "upstream endpoint circuit changed state"
            ),
        }
        if let Some(audit) = self.inner.audit.as_ref() {
            audit.emit(audit::AuditEvent::new(
                audit::event::UPSTREAM_CIRCUIT_STATE_CHANGED,
                "circuit",
                "internal",
                None::<audit::Actor>,
                json!({
                    "pool_id": self.inner.pool_id.as_ref(),
                    "endpoint_id": self.inner.endpoint_id.as_ref(),
                    "from": from,
                    "state": to,
                    "reason": reason,
                }),
            ));
        }
    }

    #[cfg(test)]
    fn state_name(&self) -> &'static str {
        match *self.lock_state() {
            CircuitState::Closed { .. } => "closed",
            CircuitState::Open { .. } => "open",
            CircuitState::HalfOpen { .. } => "half_open",
        }
    }
}

impl CircuitPermit {
    pub(super) fn success(mut self) {
        self.breaker.record_success(self.generation, self.kind);
        self.completed = true;
    }

    pub(super) fn failure(mut self, reason: &'static str) {
        self.breaker
            .record_failure(self.generation, self.kind, reason);
        self.completed = true;
    }
}

impl Drop for CircuitPermit {
    fn drop(&mut self) {
        if !self.completed {
            self.breaker.cancel(self.generation, self.kind);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    struct FakeClock(Mutex<Instant>);

    impl FakeClock {
        fn new() -> Self {
            Self(Mutex::new(Instant::now()))
        }

        fn advance(&self, duration: Duration) {
            let mut now = self.0.lock().expect("fake clock should not be poisoned");
            *now += duration;
        }
    }

    impl CircuitClock for FakeClock {
        fn now(&self) -> Instant {
            *self.0.lock().expect("fake clock should not be poisoned")
        }
    }

    fn breaker(
        clock: Arc<FakeClock>,
        failure_threshold: u32,
        half_open_max_requests: u32,
        recovery_threshold: u32,
    ) -> CircuitBreaker {
        CircuitBreaker::new_with_clock(
            Arc::from("payments"),
            Arc::from("primary"),
            config::UpstreamCircuitBreakerConfig {
                failure_threshold,
                open_ms: 1_000,
                half_open_max_requests,
                recovery_threshold,
            },
            None,
            clock,
            None,
        )
    }

    #[test]
    fn fake_clock_drives_closed_open_half_open_and_recovery() {
        let clock = Arc::new(FakeClock::new());
        let breaker = breaker(Arc::clone(&clock), 2, 1, 2);

        breaker
            .try_acquire()
            .expect("closed permit")
            .failure("connect");
        assert_eq!(breaker.state_name(), "closed");
        breaker
            .try_acquire()
            .expect("closed permit")
            .failure("connect");
        assert_eq!(breaker.state_name(), "open");
        assert!(breaker.try_acquire().is_none());

        clock.advance(Duration::from_millis(1_000));
        breaker.try_acquire().expect("half-open probe").success();
        assert_eq!(breaker.state_name(), "half_open");
        breaker.try_acquire().expect("second probe").success();
        assert_eq!(breaker.state_name(), "closed");
    }

    #[test]
    fn closed_failure_window_expires_before_threshold_is_reached() {
        let clock = Arc::new(FakeClock::new());
        let breaker = breaker(Arc::clone(&clock), 2, 1, 1);

        breaker
            .try_acquire()
            .expect("first closed permit")
            .failure("connect");
        clock.advance(FAILURE_WINDOW);
        breaker
            .try_acquire()
            .expect("expired failure should start a new window")
            .failure("connect");

        assert_eq!(breaker.state_name(), "closed");
        breaker
            .try_acquire()
            .expect("second failure in the new window")
            .failure("connect");
        assert_eq!(breaker.state_name(), "open");
    }

    #[test]
    fn half_open_probe_concurrency_is_bounded_and_cancellation_releases_capacity() {
        let clock = Arc::new(FakeClock::new());
        let breaker = breaker(Arc::clone(&clock), 1, 2, 3);
        breaker
            .try_acquire()
            .expect("closed permit")
            .failure("connect");
        clock.advance(Duration::from_millis(1_000));

        let first = breaker.try_acquire().expect("first probe");
        let second = breaker.try_acquire().expect("second probe");
        assert!(breaker.try_acquire().is_none());
        drop(first);
        assert!(breaker.try_acquire().is_some());
        drop(second);
    }

    #[test]
    fn one_half_open_failure_reopens_and_stale_probe_success_is_ignored() {
        let clock = Arc::new(FakeClock::new());
        let breaker = breaker(Arc::clone(&clock), 1, 2, 2);
        breaker
            .try_acquire()
            .expect("closed permit")
            .failure("connect");
        clock.advance(Duration::from_millis(1_000));

        let failing = breaker.try_acquire().expect("first probe");
        let stale = breaker.try_acquire().expect("second probe");
        failing.failure("timeout");
        stale.success();

        assert_eq!(breaker.state_name(), "open");
        assert!(breaker.try_acquire().is_none());
    }

    #[test]
    fn a_closed_success_resets_only_the_current_generation_failure_count() {
        let clock = Arc::new(FakeClock::new());
        let breaker = breaker(clock, 2, 1, 1);
        let stale_success = breaker.try_acquire().expect("first permit");
        breaker
            .try_acquire()
            .expect("second permit")
            .failure("connect");
        breaker
            .try_acquire()
            .expect("third permit")
            .failure("connect");
        stale_success.success();

        assert_eq!(breaker.state_name(), "open");
    }
}
