//! Stages 3 and 8 for `SetRepoVisibility`: admission before any state
//! change, the durable reservation, and its settlement in the visibility
//! batch, as for every other mutating RPC (SPEC-SERVER §6.3, §6.5).

use super::plan::{Snapshot, plan_charge};
use super::{Allowance, Authenticated, Pipeline, ResponseMeta, admission, meta_error, reservation};
use crate::error::ServerError;
use crate::op::Operation;
use crate::pipeline::HookSet;
use crate::pipeline::durable_outcome::visibility_marker;
use crate::pipeline::hooks::AdmissionInput;
use crate::store::codec::{AbortReason, ReservationV1};
use crate::store::outbox::{OutboxBuilder, Terminal};
use crate::store::{Batch, MultipartBlobStore, NamespaceStore, Partition, keys};
use mkit_attest::grant::Visibility;

/// What stage 3 granted a visibility change.
pub(super) struct Admitted {
    allowance: Allowance,
    pending: Option<reservation::PendingGuard>,
    business_now_ms: i64,
}

impl Admitted {
    /// The latest instant the commit may land: the reservation's apply
    /// deadline when there is one.
    pub(super) fn apply_deadline_ms(&self) -> u64 {
        self.pending
            .as_ref()
            .map_or(u64::MAX, |pending| pending.apply_deadline_ms)
    }
}

/// How a visibility commit attempt ended without an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Landed {
    /// This request wrote the change, settling its reservation.
    Committed,
    /// The same change had already landed (a replay or an identical
    /// statement), so this request wrote nothing.
    Replayed,
}

impl<B: MultipartBlobStore, N: NamespaceStore, H: HookSet> Pipeline<B, N, H> {
    /// Stage 3 for `op`, then the reservation's durable pending row when
    /// admission granted one. Nothing else is written.
    pub(super) async fn admit_visibility(
        &self,
        a: &Authenticated,
        op: &Operation,
        p: &Partition,
        visibility: Visibility,
    ) -> Result<Admitted, ServerError> {
        self.check_outbox_backpressure(p, None).await?;
        let credentials = admission::validate_credentials(&a.credential_capture)?;
        let mut input = AdmissionInput::new(op);
        input.credential_headers = &credentials;
        let allowance = self.admit(input).await?;
        let pending = match allowance.reservation.as_deref() {
            Some(rid) => {
                let mut guard = self.record_pending(a, p, rid).await?;
                guard.marker = visibility_marker(visibility);
                Some(guard)
            }
            None => None,
        };
        Ok(Admitted {
            allowance,
            pending,
            business_now_ms: a.business_now_ms,
        })
    }

    /// Add the admission charges and the reservation's `Committed` outcome
    /// to the visibility batch, so they commit atomically with the `rv` row
    /// and the listing index.
    pub(super) async fn plan_visibility_settlement(
        &self,
        p: &Partition,
        batch: &mut Batch,
        admitted: &Admitted,
        now_ms: u64,
    ) -> Result<(), ServerError> {
        let mut snapshot = Snapshot::default();
        for charge in &admitted.allowance.charges {
            let key = keys::quota(&charge.scope);
            let value = self.meta.get(p, &key).await.map_err(meta_error)?;
            snapshot.insert(key, value);
            plan_charge(
                charge,
                &snapshot,
                admitted.business_now_ms,
                &mut batch.preconditions,
                &mut batch.writes,
            )?;
        }
        let Some(pending) = &admitted.pending else {
            return Ok(());
        };
        let rows = self
            .meta
            .get_many(p, &[keys::outbox_sequence(), keys::outcome_backlog()])
            .await
            .map_err(meta_error)?;
        let mut builder = OutboxBuilder::new(
            rows.first().and_then(Option::as_ref),
            rows.get(1).and_then(Option::as_ref),
        )
        .map_err(meta_error)?;
        let record = ReservationV1::Committed {
            repository: pending.repository.clone(),
            occurred_at_ms: now_ms,
            bytes_stored: 0,
            new_to_repo: 0,
            new_to_store: 0,
            refs: Vec::new(),
        };
        builder.outcome_marked(
            &pending.rid,
            &pending.value,
            Terminal::new(record).map_err(meta_error)?,
            pending.marker.clone(),
        );
        builder.relay_at(now_ms);
        builder
            .try_finish(&mut batch.preconditions, &mut batch.writes)
            .map_err(meta_error)
    }

    /// A commit attempt that lost a guard may have lost the reservation to
    /// the reconciler; re-planning against a settled row cannot succeed.
    pub(super) async fn require_pending_current(
        &self,
        p: &Partition,
        admitted: &Admitted,
    ) -> Result<(), ServerError> {
        let Some(pending) = &admitted.pending else {
            return Ok(());
        };
        let current = self.meta.get(p, &pending.key).await.map_err(meta_error)?;
        if current.as_ref() == Some(&pending.value) {
            Ok(())
        } else {
            Err(ServerError::unavailable(
                "admission reservation changed; retry",
            ))
        }
    }

    /// Resolve the reservation after the commit attempt: a refused or lost
    /// attempt aborts it with the reason other writes record, and a success
    /// returns the admission's response headers.
    pub(super) async fn settle_visibility(
        &self,
        p: &Partition,
        admitted: Admitted,
        landed: Result<Landed, ServerError>,
    ) -> Result<ResponseMeta, ServerError> {
        match landed {
            Ok(Landed::Committed) => {
                let allowance = admitted.allowance;
                if allowance.response_headers.is_empty() && allowance.external_ref.is_none() {
                    return Ok(ResponseMeta::default());
                }
                let mut headers = allowance.response_headers;
                if !headers.is_empty() {
                    headers.push(("Cache-Control".into(), "private".into()));
                }
                Ok(ResponseMeta {
                    headers,
                    external_ref: allowance.external_ref,
                })
            }
            Ok(Landed::Replayed) => {
                if let Some(pending) = &admitted.pending {
                    self.resolve_pending(p, pending, AbortReason::ReplayRace, String::new())
                        .await;
                }
                Ok(ResponseMeta::default())
            }
            Err(err) => {
                if let Some(pending) = &admitted.pending {
                    let (reason, detail) = reservation::abort_reason(&err);
                    self.resolve_pending(p, pending, reason, detail).await;
                }
                Err(err)
            }
        }
    }
}
