//! Pure ticket/counter and ref-shard membership fragments. Callers supply
//! time and read snapshots, compose these fragments with their ref/replay
//! writes, and apply the complete batch in one partition.

use std::collections::BTreeSet;

use super::codec::{self, TicketV1};
use super::outbox::{OutboxBuilder, guard};
use super::{BlobKey, Key, Partition, Precondition, StoreError, Value, Write, keys as layout};
use crate::pipeline::ShardMap;
use crate::repo::{RepoId, RepoName};
use crate::timers::registry::kinds;
use mkit_core::hash::Hash;

/// Caller-validated upload geometry and binding, plus the business clock.
#[derive(Debug, Clone)]
pub struct TicketSpec {
    /// Authority generation authorized when this ticket was created.
    pub authority_generation: Option<u64>,
    /// Repository name within this partition's namespace.
    pub repo: RepoName,
    /// Target ref (wire normalization is WP-1.9).
    pub ref_name: String,
    /// Authenticated signer.
    pub signer: Hash,
    /// Pack commitment.
    pub pack_id: Hash,
    /// Positive committed byte count.
    pub bytes: u64,
    /// Power-of-two part geometry.
    pub part_size: u64,
    /// Expiry, strictly less than seven days after creation.
    pub expires_at_ms: u64,
    /// Creation time.
    pub created_at_ms: u64,
    /// Business-clock observation used to classify an existing ticket.
    pub now_ms: u64,
    /// Admission id, or the synthetic replay-scope id.
    pub reservation_id: String,
    /// Optional backend multipart session identifier.
    pub upload_session: Option<Vec<u8>>,
}

impl TicketSpec {
    fn record(&self) -> TicketV1 {
        TicketV1 {
            authority_generation: self.authority_generation,
            repo: self.repo.clone(),
            ref_name: self.ref_name.clone(),
            signer: self.signer,
            pack_id: self.pack_id,
            bytes: self.bytes,
            part_size: self.part_size,
            expires_at_ms: self.expires_at_ms,
            created_at_ms: self.created_at_ms,
            reservation_id: self.reservation_id.clone(),
            upload_session: self.upload_session.clone(),
        }
    }
}

/// Open-ticket caps, decided by the embedding RPC.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct TicketCaps {
    /// Maximum across all signers of the ref.
    pub per_ref: u64,
    /// Maximum for one ref/signer pair.
    pub per_signer: u64,
}

impl TicketCaps {
    /// Construct explicit deployment settings; fields may be adjusted before use.
    #[must_use]
    pub const fn new(per_ref: u64, per_signer: u64) -> Self {
        Self {
            per_ref,
            per_signer,
        }
    }
}

/// Initial read set. After reading index, fetch its ticket separately if
/// it differs from ticket (the reservation-derived new id).
#[derive(Debug, Clone)]
pub struct TicketReadKeys {
    /// Proposed ticket row.
    pub ticket: Key,
    /// Idempotency index.
    pub index: Key,
    /// Shared ref counter.
    pub per_ref: Key,
    /// Signer counter.
    pub per_signer: Key,
    /// Reservation arbiter.
    pub reservation: Key,
}

/// Compute keys for a valid spec.
///
/// # Panics
/// If the caller supplies an invalid ref/reservation id. The open planner
/// validates untrusted specs and returns an error instead.
#[must_use]
pub fn keys(spec: &TicketSpec) -> TicketReadKeys {
    TicketReadKeys {
        ticket: layout::ticket(&ticket_id(&spec.reservation_id)),
        index: layout::ticket_index(&spec.repo, &spec.ref_name, &spec.pack_id, &spec.signer)
            .expect("validated ticket binding"),
        per_ref: layout::tickets_per_ref(&spec.repo, &spec.ref_name).expect("validated ref"),
        per_signer: layout::tickets_per_signer(&spec.repo, &spec.ref_name, &spec.signer)
            .expect("validated ref"),
        reservation: layout::reservation(&spec.reservation_id).expect("validated reservation id"),
    }
}

/// Snapshot for keys, plus the ticket named by the index (None means the
/// indexed row was read and is absent). If index names the proposed id,
/// ticket is also sufficient; an explicitly supplied `indexed_ticket` wins.
#[derive(Debug, Clone, Default)]
pub struct TicketReads {
    /// Proposed ticket value.
    pub ticket: Option<Value>,
    /// Ticket value fetched using the id in index.
    pub indexed_ticket: Option<Value>,
    /// Raw 32-byte ticket id in the idempotency index.
    pub index: Option<Value>,
    /// Ref counter.
    pub per_ref: Option<Value>,
    /// Ref/signer counter.
    pub per_signer: Option<Value>,
    /// Reservation row; a duplicate is rejected by Absent at apply.
    pub reservation: Option<Value>,
}

/// Open planning leaves output vectors untouched on every error.
#[derive(Debug)]
pub enum TicketPlanError {
    /// Idempotent re-creation returns the still-live ticket.
    Existing(TicketV1),
    /// Ref cap if true; otherwise signer cap.
    CapExceeded { per_ref: bool },
    /// Invalid stored data.
    Corrupt(StoreError),
    /// Invalid caller input.
    Invalid(&'static str),
}

/// Deterministic, audience-local ticket identifier.
#[must_use]
pub fn ticket_id(reservation_id: &str) -> Hash {
    mkit_core::hash::hash(&[b"mkit.ticket.v1\n".as_slice(), reservation_id.as_bytes()].concat())
}

fn counter(value: Option<&Value>) -> Result<u64, StoreError> {
    let n = value.map(codec::decode_u64).transpose()?.unwrap_or(0);
    if value.is_some() && n == 0 {
        return Err(StoreError::Corrupt("open counter stored as zero".into()));
    }
    Ok(n)
}

/// Coalesce repeated edits of a shared counter without duplicating its
/// snapshot guard. This is required when an advance consumes many tickets.
fn adjust_counter(
    key: Key,
    prior: Option<&Value>,
    increment: bool,
    pre: &mut Vec<Precondition>,
    writes: &mut Vec<Write>,
) -> Result<(), StoreError> {
    let observed = counter(prior)?;
    let expected = guard(key.clone(), prior);
    let existing = pre.iter().find(|p| match p {
        Precondition::Equals(k, _) | Precondition::Absent(k) | Precondition::Present(k) => {
            k == &key
        }
        Precondition::NotAfter(_) => false,
    });
    if existing.is_some_and(|p| p != &expected) {
        return Err(StoreError::Invalid("inconsistent counter snapshots".into()));
    }
    let position = writes.iter().rposition(|w| match w {
        Write::Put(k, _) | Write::Delete(k) => k == &key,
    });
    let current = match position.map(|i| &writes[i]) {
        Some(Write::Put(_, value)) => counter(Some(value))?,
        Some(Write::Delete(_)) => 0,
        None => observed,
    };
    let next = if increment {
        current.checked_add(1)
    } else {
        current.checked_sub(1)
    }
    .ok_or_else(|| StoreError::Corrupt("open counter overflow/underflow".into()))?;
    if existing.is_none() {
        pre.push(expected);
    }
    let write = if next == 0 {
        Write::Delete(key)
    } else {
        Write::Put(key, codec::encode_u64(next))
    };
    if let Some(i) = position {
        writes[i] = write;
    } else {
        writes.push(write);
    }
    Ok(())
}

/// Open a ticket and its Ticketed reservation in one fragment.
/// Only one open per ref may be composed in a batch, avoiding stale cap
/// snapshots. The reservation uses no sequence/backlog, so its local
/// builder requires neither os nor oc reads; callers may also finish their
/// own builder.
// The fixed public contract returns Existing(TicketV1) by value.
#[allow(clippy::result_large_err, clippy::too_many_lines)] // One atomic ticket, cap, index and reservation fragment.
pub fn plan_ticket_open(
    spec: &TicketSpec,
    reads: &TicketReads,
    caps: TicketCaps,
    pre: &mut Vec<Precondition>,
    writes: &mut Vec<Write>,
) -> Result<Hash, TicketPlanError> {
    let ticket = spec.record();
    let value = codec::encode_ticket(&ticket);
    codec::decode_ticket(&value)
        .map_err(|_| TicketPlanError::Invalid("invalid ticket specification"))?;
    if spec.expires_at_ms <= spec.now_ms {
        return Err(TicketPlanError::Invalid("new ticket is already expired"));
    }
    let read_keys = keys(spec);
    let id = ticket_id(&spec.reservation_id);
    if let Some(value) = &reads.reservation
        && !matches!(
            codec::decode_reservation(value).map_err(TicketPlanError::Corrupt)?,
            codec::ReservationV1::Pending {
                op: codec::PendingOp::Write,
                ..
            }
        )
    {
        return Err(TicketPlanError::Invalid("reservation id already in use"));
    }
    // A ticket row the index doesn't name as live must not exist.
    let mut unread_indexed = None;
    if let Some(index) = &reads.index {
        let indexed_id = codec::decode_ref_id(index).map_err(TicketPlanError::Corrupt)?;
        let raw = reads.indexed_ticket.as_ref().or_else(|| {
            (indexed_id == id)
                .then_some(reads.ticket.as_ref())
                .flatten()
        });
        if let Some(raw) = raw {
            let existing = codec::decode_ticket(raw).map_err(TicketPlanError::Corrupt)?;
            if existing.repo != spec.repo
                || existing.ref_name != spec.ref_name
                || existing.signer != spec.signer
                || existing.pack_id != spec.pack_id
                || ticket_id(&existing.reservation_id) != indexed_id
            {
                return Err(TicketPlanError::Corrupt(StoreError::Corrupt(
                    "ticket index binding mismatch".into(),
                )));
            }
            if existing.expires_at_ms > spec.now_ms {
                return Err(TicketPlanError::Existing(existing));
            }
        } else if indexed_id != id {
            // The caller didn't read the indexed ticket: require it gone, so
            // a live ticket can never be shadowed by a second one.
            unread_indexed = Some(layout::ticket(&indexed_id));
        }
    }
    if reads.ticket.is_some() {
        return Err(TicketPlanError::Invalid("ticket id already in use"));
    }
    // BeginUpload creates exactly one ticket. Reject a second open for
    // this ref in a composed batch rather than using stale cap snapshots.
    if writes
        .iter()
        .any(|w| matches!(w, Write::Put(k, _) | Write::Delete(k) if k == &read_keys.per_ref))
    {
        return Err(TicketPlanError::Invalid(
            "one ticket open per ref per batch",
        ));
    }
    let per_ref = counter(reads.per_ref.as_ref()).map_err(TicketPlanError::Corrupt)?;
    let per_signer = counter(reads.per_signer.as_ref()).map_err(TicketPlanError::Corrupt)?;
    if per_ref >= caps.per_ref {
        return Err(TicketPlanError::CapExceeded { per_ref: true });
    }
    if per_signer >= caps.per_signer {
        return Err(TicketPlanError::CapExceeded { per_ref: false });
    }
    let (mut staged_pre, mut staged_writes) = (pre.clone(), writes.clone());
    staged_pre.extend([
        Precondition::Absent(read_keys.ticket.clone()),
        guard(read_keys.index.clone(), reads.index.as_ref()),
    ]);
    if let Some(key) = unread_indexed {
        staged_pre.push(Precondition::Absent(key));
    }
    staged_writes.extend([
        Write::Put(read_keys.ticket, value),
        Write::Put(read_keys.index, codec::encode_ref_id(&id)),
    ]);
    adjust_counter(
        read_keys.per_ref,
        reads.per_ref.as_ref(),
        true,
        &mut staged_pre,
        &mut staged_writes,
    )
    .map_err(TicketPlanError::Corrupt)?;
    adjust_counter(
        read_keys.per_signer,
        reads.per_signer.as_ref(),
        true,
        &mut staged_pre,
        &mut staged_writes,
    )
    .map_err(TicketPlanError::Corrupt)?;
    staged_writes.push(Write::Put(
        layout::timer(spec.expires_at_ms, kinds::TICKET_EXPIRY.get(), &id),
        Value::default(),
    ));
    let mut outbox = OutboxBuilder::new(None, None).map_err(TicketPlanError::Corrupt)?;
    outbox.reserve(&spec.reservation_id, id, reads.reservation.as_ref());
    outbox
        .try_finish(&mut staged_pre, &mut staged_writes)
        .map_err(TicketPlanError::Corrupt)?;
    *pre = staged_pre;
    *writes = staged_writes;
    Ok(id)
}

/// A live ticket that a retried open replaces in the same batch.
#[derive(Debug, Clone, Copy)]
pub(crate) struct StaleTicket<'a> {
    pub ticket: &'a TicketV1,
    pub raw: &'a Value,
    /// The ticket's reservation row, still `Ticketed`.
    pub reservation: &'a Value,
    /// Wire repository identity recorded in the old reservation's outcome.
    pub repository: &'a str,
    /// Rows the expiry handler also clears for an unconsumed pack.
    pub verification: VerificationRows<'a>,
}

/// The pack's membership, verification state and scheduled-job rows.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct VerificationRows<'a> {
    pub member: Option<&'a Value>,
    pub state: Option<&'a Value>,
    pub job: Option<&'a Value>,
}

/// Whether `ticket` was issued under an older authority generation than the
/// one now authorized. Never true for an equal, newer or absent generation.
#[must_use]
pub(crate) fn is_superseded(ticket: &TicketV1, current: Option<u64>) -> bool {
    matches!((ticket.authority_generation, current), (Some(old), Some(new)) if old < new)
}

/// Replace `stale` with a new ticket for the same binding in one fragment:
/// close the old ticket (its timer goes with it), abort its reservation with
/// an `EpochMismatch` outcome, and open the new ticket and reservation.
/// The counters net to zero, so the caps do not apply. Nothing is refunded.
/// Errors change nothing.
// Shares `plan_ticket_open`'s error type, whose `Existing` variant is large.
#[allow(clippy::result_large_err, clippy::too_many_lines)] // One atomic close, abort and open fragment.
pub(crate) fn plan_ticket_replace(
    spec: &TicketSpec,
    stale: StaleTicket<'_>,
    reads: &TicketReads,
    outbox_rows: (Option<&Value>, Option<&Value>),
    pre: &mut Vec<Precondition>,
    writes: &mut Vec<Write>,
) -> Result<Hash, TicketPlanError> {
    let value = codec::encode_ticket(&spec.record());
    codec::decode_ticket(&value)
        .map_err(|_| TicketPlanError::Invalid("invalid ticket specification"))?;
    if spec.expires_at_ms <= spec.now_ms {
        return Err(TicketPlanError::Invalid("new ticket is already expired"));
    }
    let old = stale.ticket;
    let old_id = ticket_id(&old.reservation_id);
    let id = ticket_id(&spec.reservation_id);
    if old.repo != spec.repo
        || old.ref_name != spec.ref_name
        || old.signer != spec.signer
        || old.pack_id != spec.pack_id
        || reads
            .index
            .as_ref()
            .map(codec::decode_ref_id)
            .transpose()
            .map_err(TicketPlanError::Corrupt)?
            != Some(old_id)
    {
        return Err(TicketPlanError::Corrupt(StoreError::Corrupt(
            "ticket index binding mismatch".into(),
        )));
    }
    if id == old_id || reads.ticket.is_some() {
        return Err(TicketPlanError::Invalid("ticket id already in use"));
    }
    if !matches!(
        codec::decode_reservation(stale.reservation).map_err(TicketPlanError::Corrupt)?,
        codec::ReservationV1::Ticketed { ticket_id } if ticket_id == old_id
    ) {
        return Err(TicketPlanError::Corrupt(StoreError::Corrupt(
            "ticket reservation mismatch".into(),
        )));
    }
    let read_keys = keys(spec);
    let (mut staged_pre, mut staged_writes) = (pre.clone(), writes.clone());
    plan_ticket_close(
        &old_id,
        old,
        stale.raw,
        reads.index.as_ref(),
        reads.per_ref.as_ref(),
        reads.per_signer.as_ref(),
        CloseReason::Expired,
        &mut staged_pre,
        &mut staged_writes,
    )
    .map_err(TicketPlanError::Corrupt)?;
    // The close deleted the index; the new ticket takes it over, still
    // guarded by the old value.
    staged_writes.retain(|w| !matches!(w, Write::Delete(k) if k == &read_keys.index));
    staged_pre.push(Precondition::Absent(read_keys.ticket.clone()));
    staged_writes.extend([
        Write::Put(read_keys.ticket, value),
        Write::Put(read_keys.index, codec::encode_ref_id(&id)),
    ]);
    for (key, prior) in [
        (read_keys.per_ref, reads.per_ref.as_ref()),
        (read_keys.per_signer, reads.per_signer.as_ref()),
    ] {
        adjust_counter(key, prior, true, &mut staged_pre, &mut staged_writes)
            .map_err(TicketPlanError::Corrupt)?;
    }
    staged_writes.push(Write::Put(
        layout::timer(spec.expires_at_ms, kinds::TICKET_EXPIRY.get(), &id),
        Value::default(),
    ));
    let mut outbox =
        OutboxBuilder::new(outbox_rows.0, outbox_rows.1).map_err(TicketPlanError::Corrupt)?;
    outbox.outcome(
        &old.reservation_id,
        stale.reservation,
        super::outbox::Terminal::new(codec::ReservationV1::Aborted {
            repository: stale.repository.to_owned(),
            occurred_at_ms: spec.now_ms,
            reason: codec::AbortReason::EpochMismatch,
            detail: String::new(),
            procedure: codec::StoredProcedure::BeginUpload,
        })
        .map_err(TicketPlanError::Corrupt)?,
    );
    outbox.reserve(&spec.reservation_id, id, reads.reservation.as_ref());
    outbox
        .try_finish(&mut staged_pre, &mut staged_writes)
        .map_err(TicketPlanError::Corrupt)?;
    // Same cleanup as the old ticket's expiry: an unconsumed pack's
    // verification state goes, and a scheduled job is kicked to delete its rows.
    let VerificationRows { member, state, job } = stale.verification;
    if let (None, Some(raw)) = (member, state) {
        let key = layout::verification(&old.repo, &old.pack_id);
        staged_pre.push(Precondition::Equals(key.clone(), raw.clone()));
        staged_pre.push(Precondition::Absent(layout::membership(
            &old.repo,
            &old.pack_id,
        )));
        staged_writes.push(Write::Delete(key));
    } else {
        staged_pre.push(guard(layout::membership(&old.repo, &old.pack_id), member));
        staged_pre.push(guard(layout::verification(&old.repo, &old.pack_id), state));
    }
    if job.is_some() {
        staged_writes.push(Write::Put(
            layout::timer(
                spec.now_ms,
                kinds::VERIFY.get(),
                &crate::indexed::checkpoint::timer_reference(&old.repo, &old.pack_id),
            ),
            Value::default(),
        ));
    }
    *pre = staged_pre;
    *writes = staged_writes;
    Ok(id)
}

/// Whether the caller consumed the ticket or processed its expiry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReason {
    /// Keep the timer for the expiry handler's missing-ticket no-op.
    Consumed,
    /// A lost pack is terminal; keep the timer for the same missing-ticket no-op.
    Aborted,
    /// Remove the timer along with the ticket.
    Expired,
    /// The timer core removes the fired expiry row with the same batch.
    ExpiryTimerFired,
}

/// Close only the exact ticket observed (R-04). The caller writes its
/// Committed/Expired outcome using the same batch. Errors change nothing.
#[allow(clippy::too_many_arguments)]
pub fn plan_ticket_close(
    ticket_id: &Hash,
    ticket: &TicketV1,
    ticket_value: &Value,
    ti_value: Option<&Value>,
    tc: Option<&Value>,
    tu: Option<&Value>,
    why: CloseReason,
    pre: &mut Vec<Precondition>,
    writes: &mut Vec<Write>,
) -> Result<(), StoreError> {
    if codec::decode_ticket(ticket_value)? != *ticket
        || self::ticket_id(&ticket.reservation_id) != *ticket_id
    {
        return Err(StoreError::Corrupt("ticket value/id mismatch".into()));
    }
    let index = layout::ticket_index(
        &ticket.repo,
        &ticket.ref_name,
        &ticket.pack_id,
        &ticket.signer,
    )?;
    let indexed = ti_value.map(codec::decode_ref_id).transpose()?;
    let (mut staged_pre, mut staged_writes) = (pre.clone(), writes.clone());
    let key = layout::ticket(ticket_id);
    if writes
        .iter()
        .any(|w| matches!(w, Write::Delete(k) | Write::Put(k, _) if k == &key))
    {
        return Err(StoreError::Invalid(
            "ticket already planned in batch".into(),
        ));
    }
    staged_pre.push(Precondition::Equals(key.clone(), ticket_value.clone()));
    staged_writes.push(Write::Delete(key));
    if indexed.as_ref() == Some(ticket_id) {
        staged_pre.push(guard(index.clone(), ti_value));
        staged_writes.push(Write::Delete(index));
    }
    adjust_counter(
        layout::tickets_per_ref(&ticket.repo, &ticket.ref_name)?,
        tc,
        false,
        &mut staged_pre,
        &mut staged_writes,
    )?;
    adjust_counter(
        layout::tickets_per_signer(&ticket.repo, &ticket.ref_name, &ticket.signer)?,
        tu,
        false,
        &mut staged_pre,
        &mut staged_writes,
    )?;
    if why == CloseReason::Expired {
        staged_writes.push(Write::Delete(layout::timer(
            ticket.expires_at_ms,
            kinds::TICKET_EXPIRY.get(),
            ticket_id,
        )));
    }
    *pre = staged_pre;
    *writes = staged_writes;
    Ok(())
}

/// Add immediate local memberships and queue live/published upserts for every distinct
/// remote target. `SinglePartition` needs no relay row or sequence update.
pub fn plan_membership(
    repo: &RepoName,
    packs: &[Hash],
    source: &Partition,
    shards: &dyn ShardMap,
    repo_id: &RepoId,
    outbox: &mut OutboxBuilder,
    writes: &mut Vec<Write>,
) {
    debug_assert_eq!(repo, &repo_id.name, "membership repo must match its RepoId");
    for pack in packs.iter().collect::<BTreeSet<_>>() {
        let key = layout::membership(repo, pack);
        let put = Write::Put(key.clone(), Value::default());
        if !writes.contains(&put) {
            writes.push(put);
        }
        let target = shards.membership(repo_id, &BlobKey::pack(*pack));
        if target != *source {
            outbox.relay(
                &target,
                vec![
                    (key, Value::default()),
                    (layout::published_member(repo, pack), Value::default()),
                ],
            );
        }
    }
}

#[cfg(test)]
#[path = "tickets_tests.rs"]
mod tests;
