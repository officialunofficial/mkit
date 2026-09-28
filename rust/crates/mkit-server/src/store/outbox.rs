//! Pure reservation and outbox fragments. One guarded `o` row arbitrates
//! Ticketed -> terminal; delivery removes that row only after acknowledgement.
//! WP-3.3 adds Pending/ReadServed under `CODEC_V1` and extends the arbiter.

use std::collections::{BTreeMap, BTreeSet};

use mkit_core::hash::{Hash, to_hex};

use super::codec::{self, Backlog, RelayV1, ReservationV1};
use super::{
    Batch, Key, MAX_BATCH_BYTES, MAX_BATCH_OPS, MAX_KEY_BYTES, MAX_VALUE_BYTES, Partition,
    Precondition, StoreCapabilities, StoreError, Value, Write, keys,
};

/// Each ticket costs at most nine ops: ticket guard/delete, index
/// guard/delete, reservation guard/put, pending-outcome put, membership
/// put and one relay-row share. An advance uses one signer and runs no
/// admission (the quota planner asserts this in `pipeline::plan_namespace`),
/// so `tu` and `tc` are each guarded/written once. Shared
/// overhead is at most 23: deadline 1, lease guard/install 2, absent layout
/// version guard/install 2, absent repo-known guard/install 2, two ref CAS
/// pairs 4, replay 3, counters 4, outbox sequence/backlog 4, and relay kick
/// 1. These figures are D34's. On Single, a grant guard replaces the lease
/// pair and there is no relay share or relay kick, so seven tickets cost
/// `8 * 7 + 21 = 77`. The real maximal planner batches are tested
/// separately. On D34, seven tickets cost `9 * 7 + 23 = 86` ops before
/// opportunistic pruning.
pub const MAX_TICKETS_PER_ADVANCE: usize = 7;
/// The advance batch's ops outside the per-ticket and per-signer ones.
pub const ADVANCE_SHARED_OPS: usize = 23;
const _: () = assert!(MAX_TICKETS_PER_ADVANCE * 9 + ADVANCE_SHARED_OPS <= MAX_BATCH_OPS);

/// Maximum upserts per relay row; two ops guard/advance rh, two remain for hooks.
pub const MAX_RELAY_PUTS: usize = 96;
const _: () = assert!(MAX_RELAY_PUTS + 2 <= MAX_BATCH_OPS);
// The encoded row is at most 512 KiB, leaving room for the worst rh guard/put.
const _: () = assert!(MAX_VALUE_BYTES + 2 * (MAX_KEY_BYTES + 8) <= MAX_BATCH_BYTES);

/// Reservation id for an allowance that has no deployment reservation.
#[must_use]
pub fn synthetic_reservation_id(replay_scope: &Hash) -> String {
    format!("s:{}", to_hex(replay_scope))
}

/// A validated terminal value. A Ticketed value cannot be an outcome.
#[derive(Debug, Clone)]
pub struct Terminal(ReservationV1);

impl Terminal {
    /// Validate a terminal record before planning its replacement.
    pub fn new(record: ReservationV1) -> Result<Self, StoreError> {
        if matches!(record, ReservationV1::Ticketed { .. }) {
            return Err(StoreError::Invalid("outcome must be terminal".into()));
        }
        codec::decode_reservation(&codec::encode_reservation(&record))?;
        Ok(Self(record))
    }
}

pub(crate) fn guard(key: Key, prior: Option<&Value>) -> Precondition {
    match prior {
        Some(value) => Precondition::Equals(key, value.clone()),
        None => Precondition::Absent(key),
    }
}

fn corrupt(message: &'static str) -> StoreError {
    StoreError::Corrupt(message.into())
}

/// One batch's outbox edits, using a single snapshot of os and oc.
///
/// The fixed infallible fragment methods defer malformed inputs/overflow
/// until finish. `try_finish` reports these errors without changing its
/// output vectors. `finish` instead appends mutually exclusive guards,
/// making the entire caller batch fail closed with no writes applied.
/// Use one builder per batch, finishing it before any acknowledgements.
#[derive(Debug)]
pub struct OutboxBuilder {
    os: Option<Value>,
    oc: Option<Value>,
    seq: u64,
    backlog: Backlog,
    sequence_touched: bool,
    backlog_touched: bool,
    pre: Vec<Precondition>,
    writes: Vec<Write>,
    relays: BTreeMap<Partition, BTreeMap<Key, Value>>,
    reservations: BTreeSet<String>,
    error: Option<StoreError>,
    relay_at_ms: Option<u64>,
}

impl OutboxBuilder {
    /// Read sequence/backlog once. Missing rows mean zero.
    pub fn new(os: Option<&Value>, oc: Option<&Value>) -> Result<Self, StoreError> {
        let seq = os.map(codec::decode_u64).transpose()?.unwrap_or(0);
        if os.is_some() && seq == 0 {
            return Err(corrupt("outbox sequence is zero"));
        }
        Ok(Self {
            os: os.cloned(),
            oc: oc.cloned(),
            seq,
            backlog: oc
                .map(codec::decode_backlog)
                .transpose()?
                .unwrap_or(Backlog { rows: 0, bytes: 0 }),
            sequence_touched: false,
            backlog_touched: false,
            pre: Vec::new(),
            writes: Vec::new(),
            relays: BTreeMap::new(),
            reservations: BTreeSet::new(),
            error: None,
            relay_at_ms: None,
        })
    }

    fn allocate(&mut self) -> Result<u64, StoreError> {
        self.seq = self
            .seq
            .checked_add(1)
            .ok_or_else(|| corrupt("outbox sequence overflow"))?;
        self.sequence_touched = true;
        Ok(self.seq)
    }

    fn remember(&mut self, result: Result<(), StoreError>) {
        if self.error.is_none() {
            self.error = result.err();
        }
    }

    /// Reserve a unique id. An existing row fails Absent at commit even
    /// when it contains the same ticket; callers resolve replay beforehand.
    pub fn reserve(&mut self, rid: &str, ticket_id: [u8; 32], prior: Option<&Value>) {
        let result = (|| {
            let key = keys::reservation(rid)?;
            if !self.reservations.insert(rid.to_owned()) {
                return Err(StoreError::Invalid("duplicate reservation in batch".into()));
            }
            // A row the caller already observed is a duplicate id, not a
            // race: reject it now instead of planning a batch that fails.
            if prior.is_some() {
                return Err(StoreError::Invalid("reservation id already in use".into()));
            }
            self.pre.push(Precondition::Absent(key.clone()));
            self.writes.push(Write::Put(
                key,
                codec::encode_reservation(&ReservationV1::Ticketed { ticket_id }),
            ));
            Ok(())
        })();
        self.remember(result);
    }

    /// Replace still-Ticketed with exactly one terminal outcome, queued
    /// for delivery. A terminal prior is rejected rather than replaced.
    pub fn outcome(&mut self, rid: &str, prior: &Value, terminal: Terminal) {
        let record = terminal.0;
        let result = (|| {
            let key = keys::reservation(rid)?;
            if !matches!(
                codec::decode_reservation(prior)?,
                ReservationV1::Ticketed { .. }
            ) {
                return Err(corrupt("reservation is already terminal"));
            }
            if !self.reservations.insert(rid.to_owned()) {
                return Err(StoreError::Invalid("duplicate reservation in batch".into()));
            }
            let value = codec::encode_reservation(&record);
            let size = (key.as_bytes().len() + value.as_bytes().len()) as u64;
            self.backlog.rows = self
                .backlog
                .rows
                .checked_add(1)
                .ok_or_else(|| corrupt("backlog rows overflow"))?;
            self.backlog.bytes = self
                .backlog
                .bytes
                .checked_add(size)
                .ok_or_else(|| corrupt("backlog bytes overflow"))?;
            let seq = self.allocate()?;
            self.backlog_touched = true;
            self.pre
                .push(Precondition::Equals(key.clone(), prior.clone()));
            self.writes.push(Write::Put(key, value));
            self.writes.push(Write::Put(
                keys::outcome_pending(seq, rid)?,
                Value::default(),
            ));
            Ok(())
        })();
        self.remember(result);
    }

    /// Stamp relay rows and schedule their immediate source-side kick.
    pub fn relay_at(&mut self, now_ms: u64) {
        self.relay_at_ms = Some(now_ms);
    }

    /// Group idempotent upserts by target, sorting keys deterministically.
    /// Conflicting values for one target/key invalidate the whole fragment.
    pub fn relay(&mut self, target: &Partition, puts: Vec<(Key, Value)>) {
        let result = (|| {
            target.encode()?;
            let group = self.relays.entry(target.clone()).or_default();
            for (key, value) in puts {
                if group.get(&key).is_some_and(|old| old != &value) {
                    return Err(StoreError::Invalid("conflicting relay upserts".into()));
                }
                group.insert(key, value);
            }
            Ok(())
        })();
        self.remember(result);
    }

    /// Finish with error reporting. Errors leave output vectors unchanged.
    pub fn try_finish(
        mut self,
        pre: &mut Vec<Precondition>,
        writes: &mut Vec<Write>,
    ) -> Result<(), StoreError> {
        if let Some(error) = self.error.take() {
            return Err(error);
        }
        for rid in &self.reservations {
            require_unplanned(&keys::reservation(rid)?, pre, writes)?;
        }
        let mut relay_due = None;
        for (target, puts) in std::mem::take(&mut self.relays) {
            if puts.is_empty() {
                continue;
            }
            let at_ms = self
                .relay_at_ms
                .ok_or_else(|| StoreError::Invalid("relay rows need relay_at".into()))?;
            relay_due = Some(at_ms);
            let mut row = RelayV1 {
                at_ms,
                target,
                puts: Vec::new(),
            };
            let base_bytes = codec::encode_relay(&row)?.as_bytes().len();
            let mut encoded_bytes = base_bytes;
            for (key, value) in puts {
                // JSON uses hex strings: ["key","value"], plus a comma after the first.
                let bytes = 7 + 2 * (key.as_bytes().len() + value.as_bytes().len());
                if key.as_bytes().len() > MAX_KEY_BYTES
                    || value.as_bytes().len() > MAX_VALUE_BYTES
                    || base_bytes + bytes > MAX_VALUE_BYTES
                {
                    return Err(StoreError::Invalid(
                        "relay upsert cannot fit one row".into(),
                    ));
                }
                let addition = bytes + usize::from(!row.puts.is_empty());
                if row.puts.len() == MAX_RELAY_PUTS
                    || encoded_bytes + addition > MAX_VALUE_BYTES
                    || encoded_bytes + addition + 2 * (MAX_KEY_BYTES + 8) > MAX_BATCH_BYTES
                {
                    self.push_relay(&row)?;
                    row.puts.clear();
                    encoded_bytes = base_bytes;
                }
                encoded_bytes += bytes + usize::from(!row.puts.is_empty());
                row.puts.push((key, value));
            }
            self.push_relay(&row)?;
        }
        if let Some(due) = relay_due {
            self.writes.push(Write::Put(
                keys::timer(due, crate::timers::registry::kinds::RELAY.get(), b""),
                Value::default(),
            ));
        }
        if self.sequence_touched {
            require_unplanned(&keys::outbox_sequence(), pre, writes)?;
            self.pre
                .push(guard(keys::outbox_sequence(), self.os.as_ref()));
            self.writes.push(Write::Put(
                keys::outbox_sequence(),
                codec::encode_u64(self.seq),
            ));
        }
        if self.backlog_touched {
            require_unplanned(&keys::outcome_backlog(), pre, writes)?;
            self.pre
                .push(guard(keys::outcome_backlog(), self.oc.as_ref()));
            self.writes.push(Write::Put(
                keys::outcome_backlog(),
                codec::encode_backlog(&self.backlog),
            ));
        }
        let batch = Batch {
            preconditions: self.pre,
            writes: self.writes,
        };
        batch.validate(&StoreCapabilities::full())?;
        pre.extend(batch.preconditions);
        writes.extend(batch.writes);
        Ok(())
    }

    fn push_relay(&mut self, row: &RelayV1) -> Result<(), StoreError> {
        let value = codec::encode_relay(row)?;
        codec::decode_relay(&value)?;
        let seq = self.allocate()?;
        self.writes.push(Write::Put(keys::relay(seq), value));
        Ok(())
    }

    /// Finish the fixed fragment API; malformed input makes the caller's
    /// complete batch uncommittable, which looks like a retryable conflict.
    /// Wiring code (WP-1.9, 1.10, 1.14, 3.3) MUST call `try_finish` so the
    /// error is reported instead.
    pub fn finish(self, pre: &mut Vec<Precondition>, writes: &mut Vec<Write>) {
        if self.try_finish(pre, writes).is_err() {
            let key = keys::outbox_sequence();
            pre.extend([
                Precondition::Absent(key.clone()),
                Precondition::Present(key),
            ]);
        }
    }
}

fn require_unplanned(key: &Key, pre: &[Precondition], writes: &[Write]) -> Result<(), StoreError> {
    let guarded = pre.iter().any(|p| match p {
        Precondition::Equals(k, _) | Precondition::Absent(k) | Precondition::Present(k) => k == key,
        Precondition::NotAfter(_) => false,
    });
    let written = writes
        .iter()
        .any(|w| matches!(w, Write::Put(k, _) | Write::Delete(k) if k == key));
    if guarded || written {
        return Err(StoreError::Invalid(
            "outbox key already planned in batch".into(),
        ));
    }
    Ok(())
}

/// Acknowledge exactly this terminal row and pending index. Counting the
/// raw stored bytes makes the decrement independent of codec re-encoding.
pub fn plan_ack(
    rid: &str,
    value: &Value,
    oq_seq: u64,
    oc: Option<&Value>,
    pre: &mut Vec<Precondition>,
    writes: &mut Vec<Write>,
) -> Result<(), StoreError> {
    if oq_seq == 0
        || matches!(
            codec::decode_reservation(value)?,
            ReservationV1::Ticketed { .. }
        )
    {
        return Err(corrupt("ack requires a terminal indexed outcome"));
    }
    let key = keys::reservation(rid)?;
    let pending = keys::outcome_pending(oq_seq, rid)?;
    if writes
        .iter()
        .any(|w| matches!(w, Write::Put(k, _) | Write::Delete(k) if k == &key))
    {
        return Err(StoreError::Invalid(
            "outcome already planned in batch".into(),
        ));
    }
    let observed = oc
        .map(codec::decode_backlog)
        .transpose()?
        .ok_or_else(|| corrupt("missing outcome backlog"))?;
    let backlog_key = keys::outcome_backlog();
    let expected = guard(backlog_key.clone(), oc);
    let existing_guard = pre.iter().find(|p| match p {
        Precondition::Equals(k, _) | Precondition::Absent(k) | Precondition::Present(k) => {
            k == &backlog_key
        }
        Precondition::NotAfter(_) => false,
    });
    if existing_guard.is_some_and(|p| p != &expected) {
        return Err(StoreError::Invalid("inconsistent backlog snapshots".into()));
    }
    let position = writes
        .iter()
        .rposition(|w| matches!(w, Write::Put(k, _) | Write::Delete(k) if k == &backlog_key));
    let mut backlog = match position.map(|i| &writes[i]) {
        Some(Write::Put(_, value)) => codec::decode_backlog(value)?,
        Some(Write::Delete(_)) => Backlog::default(),
        None => observed,
    };
    backlog.rows = backlog
        .rows
        .checked_sub(1)
        .ok_or_else(|| corrupt("backlog rows underflow"))?;
    backlog.bytes = backlog
        .bytes
        .checked_sub((key.as_bytes().len() + value.as_bytes().len()) as u64)
        .ok_or_else(|| corrupt("backlog bytes underflow"))?;
    if (backlog.rows == 0) != (backlog.bytes == 0) {
        return Err(corrupt("inconsistent outcome backlog"));
    }
    let needs_guard = existing_guard.is_none();
    pre.extend([
        Precondition::Equals(key.clone(), value.clone()),
        Precondition::Equals(pending.clone(), Value::default()),
    ]);
    writes.extend([Write::Delete(key), Write::Delete(pending)]);
    if needs_guard {
        pre.push(expected);
    }
    let write = if backlog.rows == 0 {
        Write::Delete(backlog_key)
    } else {
        Write::Put(backlog_key, codec::encode_backlog(&backlog))
    };
    if let Some(i) = position {
        writes[i] = write;
    } else {
        writes.push(write);
    }
    Ok(())
}

#[cfg(test)]
#[path = "outbox_tests.rs"]
mod tests;
