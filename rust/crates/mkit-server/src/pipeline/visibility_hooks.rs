//! Stages 3 and 8 for `SetRepoVisibility`: admission before any state
//! change, the durable reservation, and its settlement in the visibility
//! batch, as for every other mutating RPC (SPEC-SERVER §6.3, §6.5).

use super::plan::{Snapshot, plan_charge};
use super::{
    Allowance, Authenticated, Pipeline, ResponseMeta, admission, meta_error, reservation,
    stored_procedure,
};
use crate::error::ServerError;
use crate::op::Operation;
use crate::pipeline::HookSet;
use crate::pipeline::hooks::AdmissionInput;
use crate::store::codec::{AbortReason, ReservationV1};
use crate::store::outbox::{OutboxBuilder, Terminal};
use crate::store::{
    Batch, Key, MAX_BATCH_OPS, MultipartBlobStore, NamespaceStore, Partition, Precondition, Value,
    Write, keys,
};
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

/// Ops the envelope commit adds after planning: the `lease_recovery` and the
/// `authority_generation` guards.
pub(super) const FENCE_GUARDS: usize = 2;

/// Refuse a batch whose planned operations (plus `reserve` still to be added)
/// cannot fit the store's limit, with a client-visible error rather than an
/// invalid storage request. Only a very large admission charge list gets here.
pub(super) fn check_batch_room(batch: &Batch, reserve: usize) -> Result<(), ServerError> {
    if batch.preconditions.len() + batch.writes.len() + reserve > MAX_BATCH_OPS {
        return Err(ServerError::resource_exhausted(
            "too many admission charges for one visibility change",
        ));
    }
    Ok(())
}

impl<B: MultipartBlobStore, N: NamespaceStore, H: HookSet> Pipeline<B, N, H> {
    /// Stage 3 for `op`, then the reservation's durable pending row when
    /// admission granted one. Nothing else is written.
    ///
    /// The outcome-backlog bound applies only to a granted reservation (the
    /// only thing that adds an outcome row), and never to a change to
    /// `Private`: making a repository private must stay applicable while a
    /// sink is down, so that change exceeds the soft bound by its one row.
    pub(super) async fn admit_visibility(
        &self,
        a: &Authenticated,
        op: &Operation,
        p: &Partition,
        visibility: Visibility,
    ) -> Result<Admitted, ServerError> {
        let credentials = admission::validate_credentials(&a.credential_capture)?;
        let mut input = AdmissionInput::new(op);
        input.credential_headers = &credentials;
        let allowance = self.admit(input).await?;
        if allowance.reservation.is_some() && visibility != Visibility::Private {
            self.check_outbox_backpressure(p, None).await?;
        }
        let pending = match allowance.reservation.as_deref() {
            Some(rid) => Some(
                self.record_pending(a, p, rid, stored_procedure(&op.kind)?)
                    .await?,
            ),
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
            return check_batch_room(batch, 0);
        };
        // One outbox writer per batch: the automatic purge planned before us
        // may already have advanced the sequence and the shared backlog, so
        // the outcome is planned on top of its values and the batch keeps a
        // single guard and a single final put per counter.
        let (seq_key, backlog_key) = (keys::outbox_sequence(), keys::outcome_backlog());
        let rows = self
            .meta
            .get_many(p, &[seq_key.clone(), backlog_key.clone()])
            .await
            .map_err(meta_error)?;
        let stored_seq = rows.first().and_then(Option::as_ref);
        let stored_backlog = rows.get(1).and_then(Option::as_ref);
        let planned = |key: &Key, stored: Option<&Value>| {
            batch
                .writes
                .iter()
                .rev()
                .find_map(|write| match write {
                    Write::Put(k, v) if k == key => Some(v.clone()),
                    _ => None,
                })
                .or_else(|| stored.cloned())
        };
        let (current_seq, current_backlog) = (
            planned(&seq_key, stored_seq),
            planned(&backlog_key, stored_backlog),
        );
        let mut builder = OutboxBuilder::new(current_seq.as_ref(), current_backlog.as_ref())
            .map_err(meta_error)?;
        let record = ReservationV1::Committed {
            repository: pending.repository.clone(),
            occurred_at_ms: now_ms,
            bytes_stored: 0,
            new_to_repo: 0,
            new_to_store: 0,
            refs: Vec::new(),
            procedure: pending.procedure,
        };
        builder.outcome(
            &pending.rid,
            &pending.value,
            Terminal::new(record).map_err(meta_error)?,
        );
        builder.relay_at(now_ms);
        let (mut pre, mut puts) = (Vec::new(), Vec::new());
        builder
            .try_finish(&mut pre, &mut puts)
            .map_err(meta_error)?;
        let counter = |key: &Key| key == &seq_key || key == &backlog_key;
        let touches = |c: &Precondition| match c {
            Precondition::Equals(k, _) | Precondition::Absent(k) | Precondition::Present(k) => {
                counter(k)
            }
            Precondition::NotAfter(_) => false,
        };
        // The builder guarded the values it was given; the batch must guard
        // what is stored, which an earlier planner may already have done.
        pre.retain(|c| !touches(c));
        batch.writes.retain(|w| match w {
            Write::Put(k, _) | Write::Delete(k) => !counter(k),
        });
        for (key, stored) in [(&seq_key, stored_seq), (&backlog_key, stored_backlog)] {
            let guarded = batch.preconditions.iter().any(|c| match c {
                Precondition::Equals(k, _) | Precondition::Absent(k) | Precondition::Present(k) => {
                    k == key
                }
                Precondition::NotAfter(_) => false,
            });
            if !guarded {
                batch
                    .preconditions
                    .push(crate::store::outbox::guard(key.clone(), stored));
            }
        }
        batch.preconditions.extend(pre);
        batch.writes.extend(puts);
        check_batch_room(batch, 0)
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
