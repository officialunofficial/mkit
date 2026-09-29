//! Public, transport-neutral terminal outcomes for the delivery sink.

use core::time::Duration;

use crate::error::Redacted;
use crate::store::codec::{AbortReason, OutcomeRef, ReservationV1};

/// One durable reservation result. Delivery is at least once.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Outcome {
    /// Idempotency key; sinks deduplicate by this id.
    pub reservation_id: String,
    /// Canonical origin of the server that performed the operation.
    pub audience: String,
    /// Full repository identity.
    pub repository: String,
    /// Time the terminal result occurred.
    pub occurred_unix_ms: i64,
    /// Terminal result payload.
    pub kind: OutcomeKind,
}

/// Hooks.v1 terminal variants, field for field.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum OutcomeKind {
    /// A write committed durably.
    Committed {
        bytes_stored: u64,
        new_to_repo: u64,
        new_to_store: u64,
        refs: Vec<OutcomeRef>,
    },
    /// A write or read was aborted.
    Aborted { reason: AbortReason, detail: String },
    /// An unused ticket expired.
    Expired,
    /// An HTTP read completed, possibly after partial transmission.
    ReadServed { object: [u8; 32], bytes_served: u64 },
}

impl Outcome {
    /// Map a terminal stored row to the delivery contract.
    ///
    /// # Errors
    /// A pending or ticketed row is not deliverable.
    pub fn from_reservation(
        reservation_id: String,
        audience: String,
        row: ReservationV1,
    ) -> Result<Self, &'static str> {
        let (repository, occurred, kind) = match row {
            ReservationV1::Committed {
                repository,
                occurred_at_ms,
                bytes_stored,
                new_to_repo,
                new_to_store,
                refs,
            } => (
                repository,
                occurred_at_ms,
                OutcomeKind::Committed {
                    bytes_stored,
                    new_to_repo,
                    new_to_store,
                    refs,
                },
            ),
            ReservationV1::Aborted {
                repository,
                occurred_at_ms,
                reason,
                detail,
            } => (
                repository,
                occurred_at_ms,
                OutcomeKind::Aborted { reason, detail },
            ),
            ReservationV1::Expired {
                repository,
                occurred_at_ms,
            } => (repository, occurred_at_ms, OutcomeKind::Expired),
            ReservationV1::ReadServed {
                repository,
                occurred_at_ms,
                object,
                bytes_served,
            } => (
                repository,
                occurred_at_ms,
                OutcomeKind::ReadServed {
                    object,
                    bytes_served,
                },
            ),
            ReservationV1::Pending { .. } | ReservationV1::Ticketed { .. } => {
                return Err("outcome row is not terminal");
            }
        };
        Ok(Self {
            reservation_id,
            audience,
            repository,
            occurred_unix_ms: i64::try_from(occurred).map_err(|_| "outcome timestamp overflow")?,
            kind,
        })
    }
}

/// A failed sink call always means retry. Its reason is never printed.
#[derive(Debug, Clone)]
pub struct DeliveryError {
    /// Operator-only diagnostic text.
    pub reason: Redacted,
    /// Optional sink retry hint.
    pub retry_after: Option<Duration>,
}

impl DeliveryError {
    /// Construct a retryable delivery error.
    #[must_use]
    pub fn new(reason: impl Into<String>, retry_after: Option<Duration>) -> Self {
        Self {
            reason: Redacted::new(reason),
            retry_after,
        }
    }
}
