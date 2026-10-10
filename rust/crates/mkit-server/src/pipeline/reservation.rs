//! Durable pending reservations and best-effort abort resolution.

use mkit_core::write_auth::MAX_CLOCK_LEAD_MS;

use super::{Authenticated, Pipeline, meta_error, ms};
use crate::error::{AbortCause, Code, ServerError};
use crate::pipeline::HookSet;
use crate::store::codec::{self, AbortReason, PendingOp, ReservationV1, StoredProcedure};
use crate::store::outbox::{OutboxBuilder, Terminal};
use crate::store::{
    Batch, BatchOutcome, Key, MultipartBlobStore, NamespaceStore, Partition, Precondition, Value,
    keys,
};

/// The exact pending row all apply, abort and reconcile contenders arbitrate.
#[derive(Debug, Clone)]
pub(crate) struct PendingGuard {
    pub(crate) rid: String,
    pub(crate) key: Key,
    pub(crate) value: Value,
    pub(crate) apply_deadline_ms: u64,
    pub(crate) repository: String,
    /// The operation the reservation admitted, copied to its terminal row.
    pub(crate) procedure: StoredProcedure,
}

/// Margin beyond the maximum permitted backend clock lead.
const RECONCILE_MARGIN_MS: u64 = 1_000;

/// Paid-read planner with the deployment's SPEC-SERVER §5 grace.
#[cfg(any(test, feature = "http-objects"))]
pub(crate) fn read_pending(
    repository: String,
    created_at_ms: u64,
    deadline_ms: u64,
    read_reconcile_grace: core::time::Duration,
    procedure: StoredProcedure,
) -> ReservationV1 {
    ReservationV1::Pending {
        repository,
        created_at_ms,
        reconcile_at_ms: deadline_ms
            .saturating_add(u64::try_from(read_reconcile_grace.as_millis()).unwrap_or(u64::MAX)),
        op: PendingOp::Read,
        procedure,
    }
}

pub(crate) fn abort_reason(err: &ServerError) -> (AbortReason, String) {
    let message = err.public_message();
    match err.abort_cause() {
        Some(AbortCause::EpochMismatch) => return (AbortReason::EpochMismatch, String::new()),
        Some(AbortCause::ReplayRace) => return (AbortReason::ReplayRace, String::new()),
        Some(AbortCause::QuotaWindow) => return (AbortReason::Unspecified, message.to_owned()),
        // Re-plan exhaustion is guard contention, not a decided ref conflict.
        Some(AbortCause::Contention) => return (AbortReason::Internal, String::new()),
        None => {}
    }
    if err.code() == Code::Aborted {
        (AbortReason::ReplayRace, String::new())
    } else if matches!(
        err.code(),
        Code::PermissionDenied | Code::ResourceExhausted | Code::FailedPrecondition
    ) {
        let detail = if message.len() <= 512 && !message.chars().any(char::is_control) {
            message.to_owned()
        } else {
            "write denied".into()
        };
        (AbortReason::Unspecified, detail)
    } else {
        (AbortReason::Internal, String::new())
    }
}

/// Re-reads of the outbox counters and re-attempts of an abort that lost a guard race.
const ABORT_ATTEMPTS: usize = 5;

impl<B: MultipartBlobStore, N: NamespaceStore, H: HookSet> Pipeline<B, N, H> {
    /// Ticketless ssh/enc uploads cannot settle a reserved success.
    pub(super) async fn abort_unsupported_stream(
        &self,
        a: &Authenticated,
        partition: &Partition,
        rid: &str,
    ) -> Result<(), ServerError> {
        let row = keys::reservation(rid).map_err(meta_error)?;
        for _ in 0..ABORT_ATTEMPTS {
            let read = [
                keys::outbox_sequence(),
                keys::outcome_backlog(),
                row.clone(),
            ];
            let values = self
                .meta
                .get_many(partition, &read)
                .await
                .map_err(meta_error)?;
            if values.get(2).is_some_and(Option::is_some) {
                // Another writer already settled this reservation.
                return Ok(());
            }
            let mut builder = OutboxBuilder::new(
                values.first().and_then(Option::as_ref),
                values.get(1).and_then(Option::as_ref),
            )
            .map_err(meta_error)?;
            let terminal = Terminal::new(ReservationV1::Aborted {
                repository: a.repo().identity.clone(),
                occurred_at_ms: ms(self.clock.now_ms()),
                reason: AbortReason::Unspecified,
                detail: "reservations unsupported on this transport".into(),
                procedure: StoredProcedure::UploadPack,
            })
            .map_err(meta_error)?;
            builder.abort_direct(rid, terminal);
            let mut batch = Batch::new();
            builder
                .try_finish(&mut batch.preconditions, &mut batch.writes)
                .map_err(meta_error)?;
            match self.apply_meta(partition, batch).await? {
                BatchOutcome::Committed => return Ok(()),
                BatchOutcome::PreconditionFailed { .. } => {}
                BatchOutcome::DeadlinePassed { .. } => {
                    return Err(ServerError::unavailable("outcome commit deadline passed"));
                }
            }
        }
        Err(ServerError::unavailable("admission unavailable"))
    }

    pub(super) async fn record_pending(
        &self,
        a: &Authenticated,
        partition: &Partition,
        rid: &str,
        procedure: StoredProcedure,
    ) -> Result<PendingGuard, ServerError> {
        self.record_pending_for(a, partition, rid, procedure, 0)
            .await
    }

    /// [`Self::record_pending`] for a durable job that settles the reservation
    /// itself: the reconciler may not abort it before `job_ttl_ms` after the
    /// request (plus the usual clock-lead margin), the lifetime of the job.
    pub(super) async fn record_pending_for(
        &self,
        a: &Authenticated,
        partition: &Partition,
        rid: &str,
        procedure: StoredProcedure,
        job_ttl_ms: u64,
    ) -> Result<PendingGuard, ServerError> {
        let now = ms(self.clock.now_ms());
        let apply_deadline_ms = now
            .saturating_add(
                u64::try_from(self.cfg.max_apply_window.as_millis()).unwrap_or(u64::MAX),
            )
            .min(a.auth.as_ref().map_or(u64::MAX, |auth| {
                ms(auth.expires_at_ms).saturating_add(MAX_CLOCK_LEAD_MS.unsigned_abs())
            }));
        let reconcile_at_ms = apply_deadline_ms
            .max(now.saturating_add(job_ttl_ms))
            .saturating_add(MAX_CLOCK_LEAD_MS.unsigned_abs())
            .saturating_add(RECONCILE_MARGIN_MS);
        let pending = ReservationV1::Pending {
            repository: a.repo().identity.clone(),
            created_at_ms: now,
            reconcile_at_ms,
            op: PendingOp::Write,
            procedure,
        };
        let value = codec::encode_reservation(&pending);
        let mut builder = OutboxBuilder::new(None, None).map_err(meta_error)?;
        builder.pending(rid, None, &pending);
        let mut batch = Batch::new();
        batch
            .preconditions
            .push(Precondition::NotAfter(apply_deadline_ms));
        builder
            .try_finish(&mut batch.preconditions, &mut batch.writes)
            .map_err(|_| ServerError::unavailable("admission unavailable"))?;
        match self.apply_meta(partition, batch).await? {
            BatchOutcome::Committed => Ok(PendingGuard {
                rid: rid.to_owned(),
                key: keys::reservation(rid).map_err(meta_error)?,
                value,
                apply_deadline_ms,
                repository: a.repo().identity.clone(),
                procedure,
            }),
            BatchOutcome::PreconditionFailed { .. } => {
                Err(ServerError::unavailable("admission unavailable"))
            }
            BatchOutcome::DeadlinePassed { .. } => {
                Err(ServerError::unavailable("commit deadline passed; retry"))
            }
        }
    }

    /// Failure to record Aborted is logged; kind-9 reconciliation retains the obligation.
    pub(super) async fn resolve_pending(
        &self,
        partition: &Partition,
        pending: &PendingGuard,
        reason: AbortReason,
        detail: String,
    ) {
        if let Err(err) = self.abort_pending(partition, pending, reason, detail).await {
            tracing::warn!(error = %err, "pending reservation abort failed; reconcile will retry");
        }
    }

    async fn abort_pending(
        &self,
        partition: &Partition,
        pending: &PendingGuard,
        reason: AbortReason,
        detail: String,
    ) -> Result<(), ServerError> {
        for _ in 0..ABORT_ATTEMPTS {
            let read = [
                keys::outbox_sequence(),
                keys::outcome_backlog(),
                pending.key.clone(),
            ];
            let values = self
                .meta
                .get_many(partition, &read)
                .await
                .map_err(meta_error)?;
            if values.get(2).and_then(Option::as_ref) != Some(&pending.value) {
                // The row is no longer this Pending: another contender settled it.
                return Ok(());
            }
            let mut builder = OutboxBuilder::new(
                values.first().and_then(Option::as_ref),
                values.get(1).and_then(Option::as_ref),
            )
            .map_err(meta_error)?;
            let record = ReservationV1::Aborted {
                repository: pending.repository.clone(),
                occurred_at_ms: ms(self.clock.now_ms()),
                reason,
                detail: detail.clone(),
                procedure: pending.procedure,
            };
            builder.outcome(
                &pending.rid,
                &pending.value,
                Terminal::new(record).map_err(meta_error)?,
            );
            let mut batch = Batch::new();
            builder
                .try_finish(&mut batch.preconditions, &mut batch.writes)
                .map_err(meta_error)?;
            match self.apply_meta(partition, batch).await? {
                BatchOutcome::Committed => return Ok(()),
                // A shard counter moved (or the row changed): re-read and decide.
                BatchOutcome::PreconditionFailed { .. } => {}
                BatchOutcome::DeadlinePassed { .. } => {
                    return Err(ServerError::unavailable(
                        "reservation abort deadline passed",
                    ));
                }
            }
        }
        Err(ServerError::unavailable(
            "reservation abort contended; reconcile will retry",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_planner_uses_sixty_second_reconcile_grace() {
        let pending = read_pending(
            "repo".into(),
            1,
            10_000,
            core::time::Duration::from_mins(1),
            StoredProcedure::HttpGetObject,
        );
        assert_eq!(
            pending,
            ReservationV1::Pending {
                repository: "repo".into(),
                created_at_ms: 1,
                reconcile_at_ms: 70_000,
                op: PendingOp::Read,
                procedure: StoredProcedure::HttpGetObject,
            }
        );
        let value = codec::encode_reservation(&pending);
        let mut builder = OutboxBuilder::new(None, None).unwrap();
        builder.outcome(
            "rid",
            &value,
            Terminal::new(ReservationV1::ReadServed {
                repository: "repo".into(),
                occurred_at_ms: 10_500,
                object: [1; 32],
                bytes_served: 7,
                procedure: StoredProcedure::HttpGetObject,
            })
            .unwrap(),
        );
        let mut batch = Batch::new();
        builder
            .try_finish(&mut batch.preconditions, &mut batch.writes)
            .unwrap();
        assert!(batch.preconditions.contains(&Precondition::Equals(
            keys::reservation("rid").unwrap(),
            value
        )));
    }
}
