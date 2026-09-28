//! Ticket decisions before admission and guarded ticket consumption at apply.

use futures::future::join_all;
use mkit_core::hash::Hash;

use super::{
    Authenticated, HookSet, NamespaceStore, OpKind, Operation, Partition, Pipeline, PlanClock,
    ServerError, ShardMap, Snapshot, StorageOp, codec, internal, keys, meta_error, ms, store_error,
};
use crate::repo::RepoId;
use crate::store::codec::{AbortReason, OutcomeRef, ReservationV1, TicketV1};
use crate::store::outbox::{OutboxBuilder, Terminal};
use crate::store::tickets::{self, CloseReason};
use crate::store::{
    Batch, BatchOutcome, BlobKey, Key, MultipartBlobStore, Precondition, Value, Write,
};
use crate::upload::marker::upload_marker;

const INVALID: &str = "invalid or expired upload ticket";
const INCOMPLETE: &str = "upload not complete for ticket";

/// Context needed by the pure planner. The ticket rows are re-read on every plan.
#[derive(Clone)]
pub(super) struct AdvanceWrite<'a> {
    pub ids: &'a [Hash],
    pub signer: Hash,
    pub head_ref: &'a str,
    pub repo_id: &'a RepoId,
    pub repository: &'a str,
    pub source: &'a Partition,
    pub shards: &'a dyn ShardMap,
}

fn ticket(
    snap: &Snapshot,
    id: &Hash,
    advance: &AdvanceWrite<'_>,
    now: i64,
) -> Result<TicketV1, ServerError> {
    let raw = snap
        .get(&keys::ticket(id))
        .ok_or_else(|| ServerError::failed_precondition(INVALID))?;
    let value = codec::decode_ticket(raw).map_err(meta_error)?;
    if value.repo != advance.repo_id.name
        || value.ref_name != advance.head_ref
        || value.expires_at_ms <= ms(now)
        || tickets::ticket_id(&value.reservation_id) != *id
    {
        return Err(ServerError::failed_precondition(INVALID));
    }
    if value.signer != advance.signer {
        return Err(ServerError::permission_denied(
            "upload ticket binding mismatch",
        ));
    }
    Ok(value)
}

/// Validate all ticket rows in request order. Called again on every planner snapshot.
pub(super) fn validate(
    snap: &Snapshot,
    advance: &AdvanceWrite<'_>,
    now: i64,
) -> Result<Vec<TicketV1>, ServerError> {
    advance
        .ids
        .iter()
        .map(|id| ticket(snap, id, advance, now))
        .collect()
}

/// Keys that depend on the ticket row, fetched in the second metadata round.
pub(super) fn detail_keys(
    snap: &Snapshot,
    advance: &AdvanceWrite<'_>,
) -> Result<Vec<Key>, ServerError> {
    let mut out = vec![keys::outbox_sequence(), keys::outcome_backlog()];
    for id in advance.ids {
        if let Some(raw) = snap.get(&keys::ticket(id)) {
            let t = codec::decode_ticket(raw).map_err(meta_error)?;
            out.push(
                keys::ticket_index(&t.repo, &t.ref_name, &t.pack_id, &t.signer)
                    .map_err(meta_error)?,
            );
            out.push(keys::reservation(&t.reservation_id).map_err(meta_error)?);
            out.push(keys::membership(&t.repo, &t.pack_id));
            out.push(keys::tickets_per_ref(&t.repo, &t.ref_name).map_err(meta_error)?);
            out.push(
                keys::tickets_per_signer(&t.repo, &t.ref_name, &t.signer).map_err(meta_error)?,
            );
        }
    }
    Ok(out)
}

fn reservation<'a>(snap: &'a Snapshot, id: &Hash, t: &TicketV1) -> Result<&'a Value, ServerError> {
    let key = keys::reservation(&t.reservation_id).map_err(meta_error)?;
    let raw = snap
        .get(&key)
        .ok_or_else(|| internal("ticket lacks reservation"))?;
    if codec::decode_reservation(raw).map_err(meta_error)?
        != (ReservationV1::Ticketed { ticket_id: *id })
    {
        return Err(internal("ticket reservation binding mismatch"));
    }
    Ok(raw)
}

/// Append ticket closure, terminal outcomes and membership to the same ref batch.
pub(super) fn plan_consumption(
    snap: &Snapshot,
    advance: &AdvanceWrite<'_>,
    tickets: &[TicketV1],
    refs: &[super::RefUpdate],
    clock: &PlanClock,
    pre: &mut Vec<Precondition>,
    writes: &mut Vec<Write>,
) -> Result<(), ServerError> {
    let mut outbox = OutboxBuilder::new(
        snap.get(&keys::outbox_sequence()),
        snap.get(&keys::outcome_backlog()),
    )
    .map_err(meta_error)?;
    let outcome_refs: Vec<_> = refs
        .iter()
        .map(|r| OutcomeRef {
            name: r.name.clone(),
            new: r.new,
            deleted: r.new.is_none(),
        })
        .collect();
    for (id, t) in advance.ids.iter().zip(tickets) {
        let raw = snap
            .get(&keys::ticket(id))
            .ok_or_else(|| ServerError::failed_precondition(INVALID))?;
        let index =
            keys::ticket_index(&t.repo, &t.ref_name, &t.pack_id, &t.signer).map_err(meta_error)?;
        let tc = keys::tickets_per_ref(&t.repo, &t.ref_name).map_err(meta_error)?;
        let tu = keys::tickets_per_signer(&t.repo, &t.ref_name, &t.signer).map_err(meta_error)?;
        tickets::plan_ticket_close(
            id,
            t,
            raw,
            snap.get(&index),
            snap.get(&tc),
            snap.get(&tu),
            CloseReason::Consumed,
            pre,
            writes,
        )
        .map_err(meta_error)?;
        outbox.outcome(
            &t.reservation_id,
            reservation(snap, id, t)?,
            Terminal::new(ReservationV1::Committed {
                repository: advance.repository.to_owned(),
                occurred_at_ms: ms(clock.business_now_ms),
                bytes_stored: t.bytes,
                new_to_repo: if snap.get(&keys::membership(&t.repo, &t.pack_id)).is_some() {
                    0
                } else {
                    t.bytes
                },
                // Opaque M1 has no global content index; this is an upper bound (WP-3.3).
                new_to_store: t.bytes,
                refs: outcome_refs.clone(),
            })
            .map_err(meta_error)?,
        );
        tickets::plan_membership(
            &t.repo,
            &[t.pack_id],
            advance.source,
            advance.shards,
            advance.repo_id,
            &mut outbox,
            writes,
        );
    }
    outbox.relay_at(clock.plan_time_ms);
    outbox.try_finish(pre, writes).map_err(meta_error)
}

impl<B: MultipartBlobStore, N: NamespaceStore, H: HookSet> Pipeline<B, N, H> {
    /// Check ticket rows and proof blobs before admission or lease grants.
    /// A lost pack with a surviving marker gets a separate defensive abort.
    pub(super) async fn ticket_decision(
        &self,
        op: &Operation,
        a: &Authenticated,
        p: &Partition,
        snap: &mut Snapshot,
    ) -> Result<Option<super::StoredResult>, ServerError> {
        let OpKind::AdvanceRefs {
            head, tickets: ids, ..
        } = &op.kind
        else {
            return Ok(None);
        };
        if ids.is_empty() {
            return Ok(None);
        }
        let signer = op
            .auth
            .as_ref()
            .ok_or_else(|| internal("ticket advance lacks signer"))?
            .signer;
        let advance = AdvanceWrite {
            ids,
            signer,
            head_ref: &head.name,
            repo_id: &op.repo,
            repository: &a.repo().identity,
            source: p,
            shards: self.shards.as_ref(),
        };
        for _ in 0..super::MAX_REPLAN {
            let mut first = ids.iter().map(keys::ticket).collect::<Vec<_>>();
            if let Some(auth) = &op.auth {
                first.push(keys::replay(&auth.replay_scope));
            }
            self.fill(p, snap, first).await?;
            if let Some(stored) = Self::replay_lookup(op, Some(snap))? {
                return Ok(Some(stored));
            }
            let tickets = validate(
                snap,
                &advance,
                self.clock.now_ms().saturating_add(a.business_skew_ms),
            )?;
            let detail = detail_keys(snap, &advance)?;
            self.fill(p, snap, detail).await?;

            // TODO(WP-5.3a): remove a pack's GC mark before accepting its ticket.
            // TODO(WP-4.x): schedule verification and enforce §9.2 MKPL checks in indexed mode.
            // All marker heads run together; only marker-present packs are headed.
            let markers = join_all(ids.iter().zip(&tickets).map(|(id, t)| async move {
                let (key, _) = upload_marker(id, &t.pack_id);
                self.blobs.head(&key).await
            }))
            .await;
            let mut present = Vec::with_capacity(ids.len());
            for result in markers {
                present.push(
                    result
                        .map_err(|e| store_error(StorageOp::BlobHead, e))?
                        .is_some(),
                );
            }
            let packs = join_all(tickets.iter().zip(&present).map(|(t, marker)| async move {
                if *marker {
                    self.blobs
                        .head(&BlobKey::pack(t.pack_id))
                        .await
                        .map(|v| v.is_some())
                } else {
                    Ok(false)
                }
            }))
            .await;
            let mut lost = Vec::new();
            let mut incomplete = false;
            for (i, result) in packs.into_iter().enumerate() {
                let pack = result.map_err(|e| store_error(StorageOp::BlobHead, e))?;
                if !present[i] {
                    incomplete = true;
                } else if !pack {
                    lost.push(i);
                    incomplete = true;
                }
            }
            if lost.is_empty() {
                return if incomplete {
                    Err(ServerError::failed_precondition(INCOMPLETE))
                } else {
                    Ok(None)
                };
            }
            let now = ms(self.clock.now_ms().saturating_add(a.business_skew_ms));
            let mut batch =
                Batch::new().require(Precondition::NotAfter(now.saturating_add(30_000)));
            let mut outbox = OutboxBuilder::new(
                snap.get(&keys::outbox_sequence()),
                snap.get(&keys::outcome_backlog()),
            )
            .map_err(meta_error)?;
            for i in lost {
                let (id, t) = (&ids[i], &tickets[i]);
                let index = keys::ticket_index(&t.repo, &t.ref_name, &t.pack_id, &t.signer)
                    .map_err(meta_error)?;
                let tc = keys::tickets_per_ref(&t.repo, &t.ref_name).map_err(meta_error)?;
                let tu = keys::tickets_per_signer(&t.repo, &t.ref_name, &t.signer)
                    .map_err(meta_error)?;
                tickets::plan_ticket_close(
                    id,
                    t,
                    snap.get(&keys::ticket(id))
                        .ok_or_else(|| internal("ticket disappeared"))?,
                    snap.get(&index),
                    snap.get(&tc),
                    snap.get(&tu),
                    CloseReason::Aborted,
                    &mut batch.preconditions,
                    &mut batch.writes,
                )
                .map_err(meta_error)?;
                outbox.outcome(
                    &t.reservation_id,
                    reservation(snap, id, t)?,
                    Terminal::new(ReservationV1::Aborted {
                        repository: a.repo().identity.clone(),
                        occurred_at_ms: now,
                        reason: AbortReason::PackMissing,
                        detail: "ticket pack missing after upload".into(),
                    })
                    .map_err(meta_error)?,
                );
            }
            outbox
                .try_finish(&mut batch.preconditions, &mut batch.writes)
                .map_err(meta_error)?;
            match self.meta.apply(p, batch).await.map_err(meta_error)? {
                BatchOutcome::Committed => {
                    return Err(ServerError::failed_precondition(INCOMPLETE));
                }
                BatchOutcome::PreconditionFailed { .. } | BatchOutcome::DeadlinePassed { .. } => {
                    *snap = Snapshot::default();
                }
            }
        }
        Err(ServerError::aborted_retryable("upload ticket race"))
    }
}
