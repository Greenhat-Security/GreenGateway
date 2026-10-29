//! Required audit durability (issue #425): the receipt a request-path
//! decision waits on before the gateway acts on it.
//!
//! Under `AUDIT_DURABILITY=required` an authentication or authorization
//! stage does not only queue its decision record: it asks the audit log for
//! an [`AuditReceipt`] and waits for it. The receipt settles when the audit
//! store of record -- the SQLite sink in standalone mode, the PostgreSQL sink
//! in cluster mode -- reports the record committed, and fails when the store
//! reports it lost, when the record was never admitted to the writer, or when
//! the configured bound passes first. A failed receipt is the stage's cue to
//! refuse the request rather than act on a decision it cannot evidence.
//!
//! The handoff is a one-shot channel whose sending half, the [`DurableAck`],
//! travels with the event through the writer thread to the durable sink. A
//! sink reports exactly once. An acknowledgement dropped without a report --
//! a sink that is not a store of record, a buffer emptied at shutdown, a
//! writer that died -- reads as "not stored", so every path that loses the
//! acknowledgement fails closed without having to remember to.
//!
//! Under `AUDIT_DURABILITY=best_effort` the receipt is settled the moment the
//! event is queued, so the request path never waits and allocates nothing
//! for it.

use std::{fmt, time::Duration};

use tokio::sync::oneshot;

/// What a durable sink reports for one acknowledged event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableOutcome {
    /// The transaction that carried the event committed.
    Stored,
    /// The event will not be stored: its batch failed, or the sink refused it.
    NotStored,
}

/// The durable sink's half of one write-ahead record. Report it with
/// [`Self::stored`] once the event's transaction has committed, or with
/// [`Self::not_stored`] once it cannot; dropping it unreported is a
/// [`DurableOutcome::NotStored`] for the waiter.
#[derive(Debug)]
pub struct DurableAck {
    reply: oneshot::Sender<DurableOutcome>,
}

impl DurableAck {
    pub(crate) fn channel() -> (Self, oneshot::Receiver<DurableOutcome>) {
        let (reply, outcome) = oneshot::channel();
        (Self { reply }, outcome)
    }

    /// The event's transaction committed.
    pub fn stored(self) {
        // A waiter that has already given up has nothing left to tell.
        let _ = self.reply.send(DurableOutcome::Stored);
    }

    /// The event will not be stored.
    pub fn not_stored(self) {
        let _ = self.reply.send(DurableOutcome::NotStored);
    }
}

/// Why a decision record could not be confirmed durable. Each variant is
/// also the fixed `reason` label of `greengateway_audit_durability_refusals_total`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditUnavailable {
    /// The audit writer did not accept the record: its queue was full, its
    /// admission was closed for shutdown, or the writer was gone.
    Admission,
    /// The audit store of record reported the record lost, or nothing that
    /// could store it took it.
    Store,
    /// The record did not commit within `AUDIT_DURABILITY_TIMEOUT_MS`.
    Timeout,
}

/// The whole vocabulary of `greengateway_audit_durability_refusals_total`'s
/// `reason` label: every value the recorder seeds at `0` on install, and
/// the registry label audit's allowlist.
pub const AUDIT_DURABILITY_REFUSAL_REASONS: [&str; 3] = [
    AuditUnavailable::Admission.as_str(),
    AuditUnavailable::Store.as_str(),
    AuditUnavailable::Timeout.as_str(),
];

impl AuditUnavailable {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Admission => "admission",
            Self::Store => "store",
            Self::Timeout => "timeout",
        }
    }
}

impl fmt::Display for AuditUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Admission => write!(formatter, "the audit writer did not admit the record"),
            Self::Store => write!(formatter, "the audit store did not store the record"),
            Self::Timeout => write!(
                formatter,
                "the audit record did not commit within the durability timeout"
            ),
        }
    }
}

impl std::error::Error for AuditUnavailable {}

/// Count one request refused because its decision record could not be
/// confirmed durable. The reason is the only label, and it is one of three
/// constants: nothing about the request, its caller or the store error
/// reaches the registry.
pub(crate) fn record_durability_refusal(reason: AuditUnavailable) {
    ::metrics::counter!(
        crate::metrics::AUDIT_DURABILITY_REFUSALS_TOTAL,
        "reason" => reason.as_str()
    )
    .increment(1);
}

/// What [`super::AuditLog::record`] hands back for one decision record.
/// Confirm it with [`super::AuditLog::confirm`] before acting on the
/// decision it records.
#[must_use = "a decision record must be confirmed before the decision is acted on"]
#[derive(Debug)]
pub struct AuditReceipt {
    state: ReceiptState,
}

#[derive(Debug)]
enum ReceiptState {
    /// Best effort: the event was queued (or dropped and counted) and there
    /// is nothing to wait for.
    Settled,
    /// Required: the record was refused before it reached the writer.
    Refused(AuditUnavailable),
    /// Required: the record was admitted; the durable sink reports here.
    Pending {
        outcome: oneshot::Receiver<DurableOutcome>,
        deadline: tokio::time::Instant,
    },
}

impl AuditReceipt {
    pub(crate) fn settled() -> Self {
        Self {
            state: ReceiptState::Settled,
        }
    }

    pub(crate) fn refused(reason: AuditUnavailable) -> Self {
        Self {
            state: ReceiptState::Refused(reason),
        }
    }

    /// The deadline starts now, at admission, not when the receipt is first
    /// awaited: a stage that records two events and then confirms both waits
    /// one bound, not two.
    pub(crate) fn pending(outcome: oneshot::Receiver<DurableOutcome>, timeout: Duration) -> Self {
        Self {
            state: ReceiptState::Pending {
                outcome,
                deadline: tokio::time::Instant::now() + timeout,
            },
        }
    }

    /// Whether there is nothing to wait for (best-effort mode).
    pub(crate) fn is_settled(&self) -> bool {
        matches!(self.state, ReceiptState::Settled)
    }

    /// Wait for the record's outcome, bounded by its deadline.
    pub(crate) async fn outcome(self) -> Result<(), AuditUnavailable> {
        match self.state {
            ReceiptState::Settled => Ok(()),
            ReceiptState::Refused(reason) => Err(reason),
            ReceiptState::Pending { outcome, deadline } => {
                match tokio::time::timeout_at(deadline, outcome).await {
                    Ok(Ok(DurableOutcome::Stored)) => Ok(()),
                    // Reported lost, or the acknowledgement was dropped
                    // without a report: either way nothing stored it.
                    Ok(Ok(DurableOutcome::NotStored)) | Ok(Err(_)) => Err(AuditUnavailable::Store),
                    Err(_) => Err(AuditUnavailable::Timeout),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_settled_receipt_confirms_at_once() {
        assert!(AuditReceipt::settled().is_settled());
        assert_eq!(AuditReceipt::settled().outcome().await, Ok(()));
    }

    #[tokio::test]
    async fn a_refused_receipt_reports_its_reason() {
        let receipt = AuditReceipt::refused(AuditUnavailable::Admission);
        assert!(!receipt.is_settled());
        assert_eq!(receipt.outcome().await, Err(AuditUnavailable::Admission));
    }

    #[tokio::test]
    async fn a_pending_receipt_follows_the_sinks_report() {
        let (ack, outcome) = DurableAck::channel();
        let receipt = AuditReceipt::pending(outcome, Duration::from_secs(5));
        ack.stored();
        assert_eq!(receipt.outcome().await, Ok(()));

        let (ack, outcome) = DurableAck::channel();
        let receipt = AuditReceipt::pending(outcome, Duration::from_secs(5));
        ack.not_stored();
        assert_eq!(receipt.outcome().await, Err(AuditUnavailable::Store));
    }

    /// The fail-closed default: whoever loses the acknowledgement without
    /// reporting it has reported "not stored".
    #[tokio::test]
    async fn a_dropped_acknowledgement_is_not_stored() {
        let (ack, outcome) = DurableAck::channel();
        let receipt = AuditReceipt::pending(outcome, Duration::from_secs(5));
        drop(ack);
        assert_eq!(receipt.outcome().await, Err(AuditUnavailable::Store));
    }

    #[tokio::test]
    async fn a_pending_receipt_gives_up_at_its_deadline() {
        let (ack, outcome) = DurableAck::channel();
        let receipt = AuditReceipt::pending(outcome, Duration::from_millis(20));
        let started = std::time::Instant::now();
        assert_eq!(receipt.outcome().await, Err(AuditUnavailable::Timeout));
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the wait must end at the receipt's own deadline"
        );
        // The sink's late report goes nowhere and does not panic.
        ack.stored();
    }

    #[test]
    fn the_refusal_vocabulary_is_the_three_reasons() {
        assert_eq!(
            AUDIT_DURABILITY_REFUSAL_REASONS,
            ["admission", "store", "timeout"]
        );
        for reason in [
            AuditUnavailable::Admission,
            AuditUnavailable::Store,
            AuditUnavailable::Timeout,
        ] {
            assert!(!reason.to_string().is_empty());
        }
    }
}
