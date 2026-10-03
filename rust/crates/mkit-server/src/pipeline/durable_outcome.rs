//! Public, transport-neutral terminal outcomes for the delivery sink.

use core::time::Duration;

use crate::error::Redacted;
use crate::op::Procedure;
use crate::store::Value;
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
    /// The operation that produced the outcome, when it is recorded.
    ///
    /// `Some(Procedure::SetRepoVisibility)` marks a repository visibility
    /// change (its `Committed` carries no refs and no bytes). `None` means
    /// the outcome does not record its operation, as for every ref write and
    /// upload outcome and for a visibility reservation the reconciler
    /// abandoned after a crash.
    pub procedure: Option<Procedure>,
    /// The visibility a [`Procedure::SetRepoVisibility`] outcome set or
    /// attempted; `None` for every other outcome.
    pub visibility: Option<Visibility>,
}

/// Operation marker stored in the value of an outcome's delivery index row.
/// Rows written before the marker existed hold an empty value and decode to
/// `(None, None)`; an unrecognized marker is ignored.
const VISIBILITY_MARKER_PREFIX: &str = "set_repo_visibility:";

/// The index-row value that records a visibility change to `visibility`.
pub(crate) fn visibility_marker(visibility: Visibility) -> Value {
    let name = match visibility {
        Visibility::Public => "public",
        Visibility::Private => "private",
    };
    Value::new(format!("{VISIBILITY_MARKER_PREFIX}{name}").into_bytes())
}

fn decode_marker(marker: &[u8]) -> (Option<Procedure>, Option<Visibility>) {
    let visibility = match marker.strip_prefix(VISIBILITY_MARKER_PREFIX.as_bytes()) {
        Some(b"public") => Visibility::Public,
        Some(b"private") => Visibility::Private,
        _ => return (None, None),
    };
    (Some(Procedure::SetRepoVisibility), Some(visibility))
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
            procedure: None,
            visibility: None,
        })
    }

    /// Attach the operation recorded in the delivery index row's `marker`.
    #[must_use]
    pub(crate) fn with_marker(mut self, marker: &[u8]) -> Self {
        (self.procedure, self.visibility) = decode_marker(marker);
        self
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The marker bytes are a stored format: rows written by this form must
    /// keep decoding, and rows from v0.5.0 (empty value) carry no operation.
    #[test]
    fn marker_bytes_are_pinned_and_legacy_rows_carry_no_operation() {
        assert_eq!(
            visibility_marker(Visibility::Private).as_bytes(),
            b"set_repo_visibility:private"
        );
        assert_eq!(
            visibility_marker(Visibility::Public).as_bytes(),
            b"set_repo_visibility:public"
        );
        assert_eq!(
            decode_marker(b"set_repo_visibility:private"),
            (
                Some(Procedure::SetRepoVisibility),
                Some(Visibility::Private)
            )
        );
        assert_eq!(
            decode_marker(b"set_repo_visibility:public"),
            (Some(Procedure::SetRepoVisibility), Some(Visibility::Public))
        );
        for unrecognized in [&b""[..], b"set_repo_visibility:", b"future:x", b"\xff"] {
            assert_eq!(decode_marker(unrecognized), (None, None));
        }
    }
}
