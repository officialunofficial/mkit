//! Ticket decisions before admission and guarded ticket consumption at apply.

use futures::future::join_all;
use mkit_core::hash::Hash;

use super::{
    Authenticated, HookSet, NamespaceStore, OpKind, Operation, Partition, Pipeline, PlanClock,
    ServerError, ShardMap, Snapshot, StorageOp, codec, internal, keys, meta_error, ms, store_error,
};
use crate::repo::RepoId;
use crate::store::codec::{AbortReason, OutcomeRef, ReservationV1, StoredProcedure, TicketV1};
use crate::store::outbox::{OutboxBuilder, Terminal};
use crate::store::repo_storage;
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
    /// Count consumed packs in the repository's stored-bytes counter (Multi).
    pub count_storage: bool,
}

impl AdvanceWrite<'_> {
    /// The counter is in this batch's own partition.
    fn counts_inline(&self) -> bool {
        self.count_storage && *self.source == self.shards.coordinator(&self.repo_id.namespace)
    }
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
    if tickets::ticket_id(&value.reservation_id) != *id {
        return Err(internal("ticket reservation id mismatch"));
    }
    keys::reservation(&value.reservation_id)
        .map_err(|_| internal("invalid ticket reservation id"))?;
    if value.repo != advance.repo_id.name
        || value.ref_name != advance.head_ref
        || value.expires_at_ms <= ms(now)
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
    let mut tickets = Vec::new();
    for id in advance.ids {
        if let Some(raw) = snap.get(&keys::ticket(id)) {
            tickets.push(codec::decode_ticket(raw).map_err(meta_error)?);
        }
    }
    detail_keys_for(advance, tickets.iter())
}

fn detail_keys_for<'a>(
    advance: &AdvanceWrite<'_>,
    tickets: impl IntoIterator<Item = &'a TicketV1>,
) -> Result<Vec<Key>, ServerError> {
    let mut out = vec![keys::outbox_sequence(), keys::outcome_backlog()];
    for t in tickets {
        if advance.counts_inline() {
            out.extend(repo_storage::read_keys(&t.repo, &[(t.pack_id, t.bytes)]));
        }
        out.push(
            keys::ticket_index(&t.repo, &t.ref_name, &t.pack_id, &t.signer).map_err(meta_error)?,
        );
        out.push(keys::reservation(&t.reservation_id).map_err(meta_error)?);
        out.push(keys::membership(&t.repo, &t.pack_id));
        out.push(keys::tickets_per_ref(&t.repo, &t.ref_name).map_err(meta_error)?);
        out.push(keys::tickets_per_signer(&t.repo, &t.ref_name, &t.signer).map_err(meta_error)?);
    }
    Ok(out)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Proof {
    Ready,
    MarkerMissing,
    PackMissing,
}

async fn ticket_proofs<B: crate::BlobStore>(
    blobs: &B,
    ids: &[Hash],
    pending: Vec<(usize, &TicketV1)>,
) -> Vec<(usize, TicketV1, Result<Proof, ServerError>)> {
    // A ticket holds only one backend response at a time: its marker HEAD
    // completes before the pack HEAD starts. Seven tickets share six slots.
    let mut proofs = Vec::with_capacity(pending.len());
    for group in pending.chunks(6) {
        proofs.extend(
            join_all(group.iter().map(|&(i, t)| async move {
                let (marker_key, _) = upload_marker(&ids[i], &t.pack_id);
                let proof = match blobs.head(&marker_key).await {
                    Err(e) => Err(store_error(StorageOp::BlobHead, e)),
                    Ok(None) => Ok(Proof::MarkerMissing),
                    Ok(Some(_)) => blobs
                        .head(&BlobKey::pack(t.pack_id))
                        .await
                        .map(|pack| {
                            if pack.is_some() {
                                Proof::Ready
                            } else {
                                Proof::PackMissing
                            }
                        })
                        .map_err(|e| store_error(StorageOp::BlobHead, e)),
                };
                (i, t.clone(), proof)
            }))
            .await,
        );
    }
    proofs
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
#[allow(clippy::too_many_arguments)] // One atomic fragment has explicit input and output slices.
pub(super) fn plan_consumption(
    snap: &Snapshot,
    advance: &AdvanceWrite<'_>,
    tickets: &[TicketV1],
    refs: &[super::RefUpdate],
    clock: &PlanClock,
    pre: &mut Vec<Precondition>,
    writes: &mut Vec<Write>,
    outbox: &mut OutboxBuilder,
    membership: bool,
) -> Result<(), ServerError> {
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
                // Exact where the counter is in this batch's partition; elsewhere an
                // observation from the consuming shard's local membership. The
                // `RepoStorageChanged` outcome is the authoritative value.
                new_to_repo: if snap
                    .get(&if advance.counts_inline() {
                        keys::repo_storage_pack(&t.repo, &t.pack_id)
                    } else {
                        keys::membership(&t.repo, &t.pack_id)
                    })
                    .is_some()
                {
                    0
                } else {
                    t.bytes
                },
                // Opaque M1 has no global content index; this is an upper bound (WP-3.3).
                new_to_store: t.bytes,
                refs: outcome_refs.clone(),
                procedure: StoredProcedure::AdvanceRefs,
            })
            .map_err(meta_error)?,
        );
        if membership {
            tickets::plan_membership(
                &t.repo,
                &[t.pack_id],
                advance.source,
                advance.shards,
                advance.repo_id,
                outbox,
                writes,
            );
        }
    }
    if advance.count_storage {
        let packs: Vec<_> = tickets.iter().map(|t| (t.pack_id, t.bytes)).collect();
        repo_storage::plan_count(
            advance.repo_id,
            &packs,
            advance.source,
            advance.shards,
            |key| snap.get(key),
            |pack| {
                snap.get(&keys::membership(&advance.repo_id.name, pack))
                    .is_some()
            },
            clock.plan_time_ms,
            outbox,
            pre,
            writes,
        )
        .map_err(meta_error)?;
    }
    Ok(())
}

impl<B: MultipartBlobStore, N: NamespaceStore, H: HookSet> Pipeline<B, N, H> {
    /// Check ticket rows and proof blobs before admission or lease grants.
    /// A lost pack with a surviving marker gets a separate defensive abort.
    #[allow(clippy::too_many_lines)] // One bounded stage validates, heads and defensively aborts tickets.
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
        let auth = op
            .auth
            .as_ref()
            .ok_or_else(|| ServerError::failed_precondition(INVALID))?;
        let advance = AdvanceWrite {
            ids,
            signer: auth.signer,
            head_ref: &head.name,
            repo_id: &op.repo,
            repository: &a.repo().identity,
            source: p,
            shards: self.shards.as_ref(),
            count_storage: matches!(self.cfg.addressing, crate::repo::Addressing::Multi(_)),
        };
        // A re-plan keeps proofs for unchanged ticket rows. Only a guard race
        // involving a ticket invalidates that ticket's blob observations.
        let mut proofs: Vec<Option<(TicketV1, Result<Proof, ServerError>)>> = vec![None; ids.len()];
        for _ in 0..super::MAX_REPLAN {
            let mut first = ids.iter().map(keys::ticket).collect::<Vec<_>>();
            first.push(keys::replay(&auth.replay_scope));
            self.fill(p, snap, first.clone()).await?;
            if let Some(stored) = Self::replay_lookup(op, Some(snap))? {
                return Ok(Some(stored));
            }
            let business_now = self.clock.now_ms().saturating_add(a.business_skew_ms);
            let rows = ids
                .iter()
                .map(|id| ticket(snap, id, &advance, business_now))
                .collect::<Vec<_>>();
            let detail =
                detail_keys_for(&advance, rows.iter().filter_map(|row| row.as_ref().ok()))?;
            self.fill(p, snap, detail.clone()).await?;

            // GC is disabled in the launch profile; when GC lands, remove a
            // pack's GC mark before accepting its ticket.
            // Indexed verification is invoked by write() after this ticket
            // decision succeeds, before the advance planner can commit.
            // One future per valid ticket preserves marker-before-pack order,
            // while at most six eligible tickets await a backend response.
            let pending = rows
                .iter()
                .enumerate()
                .filter_map(|(i, row)| {
                    let t = row.as_ref().ok()?;
                    if proofs[i].as_ref().is_some_and(|(prior, _)| prior == t) {
                        None
                    } else {
                        Some((i, t))
                    }
                })
                .collect::<Vec<_>>();
            for (i, t, proof) in ticket_proofs(&self.blobs, ids, pending).await {
                proofs[i] = Some((t, proof));
            }
            let first_failure = (0..ids.len()).find_map(|i| {
                if let Err(err) = &rows[i] {
                    return Some((i, err.clone()));
                }
                match &proofs[i].as_ref().expect("valid ticket has a proof").1 {
                    Ok(Proof::Ready) => None,
                    Ok(Proof::MarkerMissing | Proof::PackMissing) => {
                        Some((i, ServerError::failed_precondition(INCOMPLETE)))
                    }
                    Err(err) => Some((i, err.clone())),
                }
            });
            let Some((first_failure, answer)) = first_failure else {
                return Ok(None);
            };
            // Later tickets cannot supersede the first request-order failure.
            let lost = (0..=first_failure)
                .filter(|&i| {
                    // A row that failed validation this pass may keep a stale proof from an
                    // earlier pass; only a currently valid ticket can be aborted.
                    rows[i].is_ok()
                        && matches!(proofs[i].as_ref(), Some((_, Ok(Proof::PackMissing))))
                })
                .collect::<Vec<_>>();
            if lost.is_empty() {
                return Err(answer);
            }
            let plan_time = self.clock.now_ms();
            let clock = PlanClock {
                plan_time_ms: ms(plan_time),
                business_now_ms: plan_time.saturating_add(a.business_skew_ms),
                max_apply_window_ms: u64::try_from(self.cfg.max_apply_window.as_millis())
                    .unwrap_or(u64::MAX),
                deadline_cap: Some(
                    ms(auth.expires_at_ms).saturating_add(super::MAX_CLOCK_LEAD_MS.unsigned_abs()),
                ),
            };
            let now = ms(clock.business_now_ms);
            let mut batch = Batch::new().require(Precondition::NotAfter(clock.deadline()));
            let mut outbox = OutboxBuilder::new(
                snap.get(&keys::outbox_sequence()),
                snap.get(&keys::outcome_backlog()),
            )
            .map_err(meta_error)?;
            let mut ticket_guards = Vec::new();
            for i in lost {
                let (id, t) = (&ids[i], rows[i].as_ref().expect("lost pack has a ticket"));
                let index = keys::ticket_index(&t.repo, &t.ref_name, &t.pack_id, &t.signer)
                    .map_err(meta_error)?;
                let tc = keys::tickets_per_ref(&t.repo, &t.ref_name).map_err(meta_error)?;
                let tu = keys::tickets_per_signer(&t.repo, &t.ref_name, &t.signer)
                    .map_err(meta_error)?;
                let guard_start = batch.preconditions.len();
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
                ticket_guards.push((i, guard_start..batch.preconditions.len()));
                outbox.outcome(
                    &t.reservation_id,
                    reservation(snap, id, t)?,
                    Terminal::new(ReservationV1::Aborted {
                        repository: a.repo().identity.clone(),
                        occurred_at_ms: now,
                        reason: AbortReason::PackMissing,
                        detail: "ticket pack missing after upload".into(),
                        procedure: StoredProcedure::AdvanceRefs,
                    })
                    .map_err(meta_error)?,
                );
            }
            outbox
                .try_finish(&mut batch.preconditions, &mut batch.writes)
                .map_err(meta_error)?;
            // This separate transaction changes only ticket and outcome rows.
            // Equals(t) and Equals(o) arbitrate its terminal result, so lease,
            // grant and layout guards needed for a ref write are unnecessary.
            match self.apply_meta(p, batch).await? {
                BatchOutcome::Committed => return Err(answer),
                BatchOutcome::DeadlinePassed { .. } => {
                    return Err(ServerError::unavailable("commit deadline passed; retry"));
                }
                BatchOutcome::PreconditionFailed { index, .. } => {
                    for (i, range) in ticket_guards {
                        if range.contains(&index) {
                            proofs[i] = None;
                        }
                    }
                    // Refresh only ticket-dependent observations. Preserve
                    // ref, lease, grant and layout read-ahead for plan_write.
                    for key in first.into_iter().chain(detail) {
                        snap.remove(&key);
                    }
                }
            }
        }
        Err(ServerError::aborted_retryable("upload ticket race"))
    }
}

#[cfg(test)]
mod concurrency_tests {
    use super::*;
    use crate::{BlobBody, BlobMeta, BlobStore, ByteRange, MemoryBlobStore, StoreError};
    use futures::{FutureExt, executor::block_on};
    use std::sync::{
        Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    #[derive(Default)]
    struct PendingHeads {
        release: AtomicBool,
        active: AtomicUsize,
        peak: AtomicUsize,
        starts: Mutex<Vec<BlobKey>>,
    }
    impl BlobStore for PendingHeads {
        type Sink = <MemoryBlobStore as BlobStore>::Sink;
        async fn begin(&self, _: BlobKey, _: u64) -> Result<Self::Sink, StoreError> {
            unreachable!("ticket decisions cannot write payloads")
        }
        async fn get(
            &self,
            _: &BlobKey,
            _: Option<ByteRange>,
        ) -> Result<Option<BlobBody>, StoreError> {
            unreachable!("ticket decisions cannot read payloads")
        }
        async fn head(&self, key: &BlobKey) -> Result<Option<BlobMeta>, StoreError> {
            self.starts.lock().unwrap().push(*key);
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(active, Ordering::SeqCst);
            futures::future::poll_fn(|cx| {
                if self.release.load(Ordering::SeqCst) {
                    std::task::Poll::Ready(())
                } else {
                    cx.waker().wake_by_ref();
                    std::task::Poll::Pending
                }
            })
            .await;
            self.active.fetch_sub(1, Ordering::SeqCst);
            Ok(Some(BlobMeta { len: 32 }))
        }
        async fn probe(&self) -> Result<(), StoreError> {
            unreachable!()
        }
        async fn delete(&self, _: &BlobKey) -> Result<bool, StoreError> {
            unreachable!()
        }
    }

    #[test]
    fn seven_ticket_proofs_keep_at_most_six_backend_requests_active() {
        let blobs = PendingHeads::default();
        let tickets: Vec<_> = (0..crate::store::outbox::MAX_TICKETS_PER_ADVANCE)
            .map(|i| TicketV1 {
                authority_generation: None,
                repo: crate::RepoName::new("repo").unwrap(),
                ref_name: "refs/heads/main".into(),
                signer: [1; 32],
                pack_id: [u8::try_from(i).unwrap(); 32],
                bytes: 32,
                part_size: 8 << 20,
                created_at_ms: 0,
                expires_at_ms: 60_000,
                reservation_id: format!("ticket-{i}"),
                upload_session: None,
            })
            .collect();
        let ids: Vec<_> = tickets
            .iter()
            .map(|t| tickets::ticket_id(&t.reservation_id))
            .collect();
        let mut proofs = Box::pin(ticket_proofs(
            &blobs,
            &ids,
            tickets.iter().enumerate().collect(),
        ));
        assert!((&mut proofs).now_or_never().is_none());
        assert_eq!(blobs.active.load(Ordering::SeqCst), 6);
        assert_eq!(blobs.peak.load(Ordering::SeqCst), 6);
        blobs.release.store(true, Ordering::SeqCst);
        let result = block_on(proofs);
        assert_eq!(result.len(), 7);
        assert!(
            result
                .iter()
                .all(|(_, _, proof)| matches!(proof, Ok(Proof::Ready)))
        );
        let starts = blobs.starts.lock().unwrap();
        assert_eq!(starts.len(), 14);
        for (i, ticket, _) in result {
            assert_eq!(ticket, tickets[i]);
            let marker = upload_marker(&ids[i], &ticket.pack_id).0;
            let marker_at = starts.iter().position(|key| *key == marker).unwrap();
            let pack_at = starts
                .iter()
                .position(|key| *key == BlobKey::pack(ticket.pack_id))
                .unwrap();
            assert!(
                marker_at < pack_at,
                "each marker must precede its pack HEAD"
            );
        }
        assert!(blobs.peak.load(Ordering::SeqCst) <= 6);
        assert_eq!(blobs.active.load(Ordering::SeqCst), 0);
    }
}
