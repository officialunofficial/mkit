//! Public, transport-neutral terminal outcomes for the delivery sink.

use core::time::Duration;

use crate::error::Redacted;
use crate::op::Procedure;
use crate::store::codec::{AbortReason, OutcomeRef, ReservationV1};
use mkit_attest::grant::Visibility;

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
    /// The operation that produced the outcome: `UpdateRef`, `AdvanceRefs`
    /// (including each consumed ticket's outcome), `BeginUpload` (a ticket
    /// that expired), `UploadPack`, `SetRepoVisibility`, or an HTTP read.
    /// `None` for `RepoStorageChanged`, a system event without a request.
    pub procedure: Option<Procedure>,
    /// The visibility a [`Procedure::SetRepoVisibility`] outcome set or
    /// attempted; `None` for every other outcome.
    pub visibility: Option<Visibility>,
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
    /// The repository's stored-bytes counter changed: the absolute pack-byte
    /// total and a monotonic per-repository version. Delivery is at least
    /// once and may be out of order, so keep the value with the highest
    /// version.
    RepoStorageChanged { stored_bytes: u64, version: u64 },
}

impl OutcomeKind {
    /// A durably committed write and its accounting.
    #[must_use]
    pub fn committed(
        bytes_stored: u64,
        new_to_repo: u64,
        new_to_store: u64,
        refs: Vec<OutcomeRef>,
    ) -> Self {
        Self::Committed {
            bytes_stored,
            new_to_repo,
            new_to_store,
            refs,
        }
    }

    /// An aborted operation and its diagnostic detail.
    #[must_use]
    pub fn aborted(reason: AbortReason, detail: String) -> Self {
        Self::Aborted { reason, detail }
    }

    /// An unused ticket that expired.
    #[must_use]
    pub fn expired() -> Self {
        Self::Expired
    }

    /// A completed HTTP read, including partial transmission.
    #[must_use]
    pub fn read_served(object: [u8; 32], bytes_served: u64) -> Self {
        Self::ReadServed {
            object,
            bytes_served,
        }
    }

    /// An absolute repository pack-byte total and its monotonic version.
    #[must_use]
    pub fn repo_storage_changed(stored_bytes: u64, version: u64) -> Self {
        Self::RepoStorageChanged {
            stored_bytes,
            version,
        }
    }
}

impl Outcome {
    /// Construct a delivery payload with no request procedure or visibility.
    /// Set those public fields for request outcomes, or use
    /// [`Self::from_reservation`] to derive them from the recorded operation.
    #[must_use]
    pub fn new(
        reservation_id: String,
        audience: String,
        repository: String,
        occurred_unix_ms: i64,
        kind: OutcomeKind,
    ) -> Self {
        Self {
            reservation_id,
            audience,
            repository,
            occurred_unix_ms,
            kind,
            procedure: None,
            visibility: None,
        }
    }

    /// Map a terminal stored row to the delivery contract.
    ///
    /// # Errors
    /// A pending or ticketed row is not deliverable.
    pub fn from_reservation(
        reservation_id: String,
        audience: String,
        row: ReservationV1,
    ) -> Result<Self, &'static str> {
        let recorded = row.procedure();
        let (repository, occurred, kind) = match row {
            ReservationV1::Committed {
                repository,
                occurred_at_ms,
                bytes_stored,
                new_to_repo,
                new_to_store,
                refs,
                ..
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
                ..
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
                ..
            } => (
                repository,
                occurred_at_ms,
                OutcomeKind::ReadServed {
                    object,
                    bytes_served,
                },
            ),
            ReservationV1::RepoStorageChanged {
                repository,
                occurred_at_ms,
                stored_bytes,
                version,
            } => (
                repository,
                occurred_at_ms,
                OutcomeKind::RepoStorageChanged {
                    stored_bytes,
                    version,
                },
            ),
            ReservationV1::Pending { .. } | ReservationV1::Ticketed { .. } => {
                return Err("outcome row is not terminal");
            }
        };
        // An expired reservation is always an unconsumed ticket's.
        let recorded = match (&kind, recorded) {
            (OutcomeKind::Expired, None) => Some(crate::store::codec::StoredProcedure::BeginUpload),
            (_, recorded) => recorded,
        };
        let (procedure, visibility) = recorded.map_or((None, None), |recorded| {
            let (procedure, visibility) = recorded.parts();
            (Some(procedure), visibility)
        });
        Ok(Self {
            reservation_id,
            audience,
            repository,
            occurred_unix_ms: i64::try_from(occurred).map_err(|_| "outcome timestamp overflow")?,
            kind,
            procedure,
            visibility,
        })
    }
}

/// A failed sink call always means retry. Its reason is never printed.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct DeliveryError {
    /// Operator-only diagnostic text.
    pub reason: Redacted,
    /// Optional sink retry hint.
    pub retry_after: Option<Duration>,
}

impl core::fmt::Display for DeliveryError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("outcome delivery failed")
    }
}

impl std::error::Error for DeliveryError {}

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
