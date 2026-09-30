//! Pure target holder consumer and durable late-block handoff (R-186).
use super::RelayHook;
use crate::store::{
    BlockEntry, HolderRecord, Key, ObjectState, Partition, PendingHolderV1, Precondition,
    StoreError, Value, Write, codec, content_shard, keys,
};
use crate::timers::{DueTimer, Fired, TimerCtx, TimerHandler, TimerKind, registry::kinds};
use crate::{BoxFuture, Clock};
use std::collections::BTreeSet;
use std::sync::Arc;

/// Real late-holder request retained until the future takedown owner consumes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentTakedownV1 {
    /// Exact holder provenance, including object/hold and domain-bound intent.
    pub identity: PendingHolderV1,
    /// Block entry observed atomically with holder installation.
    pub blocked: BlockEntry,
    /// Initial enqueue time, unchanged by redelivery.
    pub queued_at_ms: u64,
    /// Handoff materialization time; never means completed takedown.
    pub ready_at_ms: Option<u64>,
}
impl ContentTakedownV1 {
    /// Versioned bounded strict encoding.
    pub fn encode(&self) -> Result<Value, StoreError> {
        let mut bytes = vec![1];
        for value in [
            self.identity.encode()?,
            codec::encode_block_entry(&self.blocked),
        ] {
            let len = u16::try_from(value.as_bytes().len()).map_err(|_| bad())?;
            bytes.extend_from_slice(&len.to_be_bytes());
            bytes.extend_from_slice(value.as_bytes());
        }
        bytes.extend_from_slice(&self.queued_at_ms.to_be_bytes());
        bytes.push(u8::from(self.ready_at_ms.is_some()));
        if let Some(time) = self.ready_at_ms {
            bytes.extend_from_slice(&time.to_be_bytes());
        }
        if bytes.len() > 8192 {
            return Err(bad());
        }
        Ok(Value::new(bytes))
    }
    /// Refuse unknown, truncated, trailing or noncanonical values.
    pub fn decode(value: &Value) -> Result<Self, StoreError> {
        fn field(bytes: &mut &[u8]) -> Result<Value, StoreError> {
            let (len, tail) = bytes.split_first_chunk::<2>().ok_or_else(bad)?;
            let (value, rest) = tail
                .split_at_checked(usize::from(u16::from_be_bytes(*len)))
                .ok_or_else(bad)?;
            *bytes = rest;
            Ok(Value::new(value.to_vec()))
        }
        if value.as_bytes().len() > 8192 {
            return Err(bad());
        }
        let (&1, mut rest) = value.as_bytes().split_first().ok_or_else(bad)? else {
            return Err(bad());
        };
        let identity = PendingHolderV1::decode(&field(&mut rest)?)?;
        let blocked = codec::decode_block_entry(&field(&mut rest)?)?;
        let (time, tail) = rest.split_first_chunk::<8>().ok_or_else(bad)?;
        let queued_at_ms = u64::from_be_bytes(*time);
        let ready_at_ms = match tail {
            [0] => None,
            [1, time @ ..] if time.len() == 8 => {
                Some(u64::from_be_bytes(time.try_into().map_err(|_| bad())?))
            }
            _ => return Err(bad()),
        };
        let request = Self {
            identity,
            blocked,
            queued_at_ms,
            ready_at_ms,
        };
        if request.encode()? != *value {
            return Err(bad());
        }
        Ok(request)
    }
}
fn bad() -> StoreError {
    StoreError::Corrupt("bad content holder intent/request".into())
}
fn raw<'a>(seen: &'a [(Key, Option<Value>)], key: &Key) -> Result<Option<&'a Value>, StoreError> {
    seen.iter()
        .find(|(k, _)| k == key)
        .map(|(_, value)| value.as_ref())
        .ok_or_else(bad)
}
fn guard(seen: &[(Key, Option<Value>)], key: Key) -> Result<Precondition, StoreError> {
    Ok(match raw(seen, &key)? {
        Some(value) => Precondition::Equals(key, value.clone()),
        None => Precondition::Absent(key),
    })
}
fn intents(
    target: &Partition,
    rows: &[(u64, codec::RelayV1)],
) -> Result<Vec<(Key, Value, PendingHolderV1)>, StoreError> {
    let mut out = Vec::new();
    for (_, row) in rows {
        for (key, value) in &row.puts {
            if let Some(keys::ParsedKey::PendingHolder { object, hold_id }) = keys::parse(key) {
                if row.puts.len() != 1 || !row.deletes.is_empty() {
                    return Err(bad());
                }
                let identity = PendingHolderV1::decode(value)?;
                if identity.object != object
                    || identity.hold_id != hold_id
                    || content_shard(&object) != *target
                {
                    return Err(bad());
                }
                out.push((key.clone(), value.clone(), identity));
            }
        }
        if row.deletes.iter().any(|key| {
            matches!(
                keys::parse(key),
                Some(keys::ParsedKey::PendingHolder { .. })
            )
        }) {
            return Err(bad());
        }
    }
    Ok(out)
}

/// Uses supplied observations only: no store/client exists in this hook.
pub struct HolderRelayHook {
    /// Clock used for fresh bounded commit deadlines.
    pub clock: Arc<dyn Clock>,
}
impl std::fmt::Debug for HolderRelayHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HolderRelayHook").finish_non_exhaustive()
    }
}
impl RelayHook for HolderRelayHook {
    fn read_keys(
        &self,
        target: &Partition,
        rows: &[(u64, codec::RelayV1)],
    ) -> Result<Vec<Key>, StoreError> {
        let mut keys = BTreeSet::new();
        for (gp, _, identity) in intents(target, rows)? {
            keys.extend([
                gp,
                keys::object_state(&identity.object),
                keys::block(&identity.object),
                crate::takedown::denial::action_key(&identity.object),
                keys::hold(&identity.object, &identity.hold_id),
                keys::holder(&identity.object, &identity.holder.ns, &identity.holder.repo)?,
                keys::content_takedown(&identity.object, &identity.intent),
                keys::layout_version(),
            ]);
        }
        Ok(keys.into_iter().collect())
    }
    fn before_apply<'a>(
        &'a self,
        _: &'a Partition,
        _: &'a [(u64, codec::RelayV1)],
        _: &'a mut Vec<Precondition>,
        _: &'a mut Vec<Write>,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async {
            Err(StoreError::Unsupported(
                "holder consumer requires declared observations".into(),
            ))
        })
    }
    #[allow(clippy::too_many_lines)] // Fold all holder/count/protection effects into one atomic target plan.
    fn before_apply_observed<'a>(
        &'a self,
        target: &'a Partition,
        rows: &'a [(u64, codec::RelayV1)],
        seen: &'a [(Key, Option<Value>)],
        pre: &'a mut Vec<Precondition>,
        writes: &'a mut Vec<Write>,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            let intents = intents(target, rows)?;
            if intents.is_empty() {
                return Ok(());
            }
            let now = u64::try_from(self.clock.now_ms()).map_err(|_| bad())?;
            pre.push(Precondition::NotAfter(
                now.saturating_add(crate::store::CONTENT_APPLY_WINDOW_MS),
            ));
            let mut guarded = BTreeSet::new();
            let mut applied = BTreeSet::new();
            let mut folded = std::collections::BTreeMap::<_, ObjectState>::new();
            let mut holders = BTreeSet::new();
            for (gp, encoded, identity) in intents {
                if !seen.iter().any(|(key, _)| matches!(keys::parse(key), Some(keys::ParsedKey::RelayHighWater(source)) if source == identity.source)) { return Err(bad()); }
                let c = keys::object_state(&identity.object);
                let b = keys::block(&identity.object);
                let actions = crate::takedown::denial::action_key(&identity.object);
                let g = keys::hold(&identity.object, &identity.hold_id);
                let h = keys::holder(&identity.object, &identity.holder.ns, &identity.holder.repo)?;
                let ct = keys::content_takedown(&identity.object, &identity.intent);
                for key in [
                    c.clone(),
                    b.clone(),
                    actions.clone(),
                    g.clone(),
                    h.clone(),
                    gp.clone(),
                    ct.clone(),
                    keys::layout_version(),
                ] {
                    if guarded.insert(key.clone()) {
                        pre.push(guard(seen, key)?);
                    }
                }
                if raw(seen, &keys::layout_version())?
                    .map(codec::decode_u32)
                    .transpose()?
                    .is_some_and(|v| v != keys::LAYOUT_VERSION)
                {
                    return Err(bad());
                }
                writes.retain(|write| !matches!(write, Write::Put(key, _) if key == &gp));
                match raw(seen, &gp)? {
                    None => {
                        // The producer protected this intent before enqueue.
                        // A matching holder now covers a delivered duplicate;
                        // the exact h/c values and gp absence are guarded above.
                        let holder = raw(seen, &h)?.map(codec::decode_holder).transpose()?;
                        let state = raw(seen, &c)?.map(codec::decode_object_state).transpose()?;
                        if holder.is_some_and(|holder| holder.op_id == identity.ticket)
                            && state.is_some_and(|state| !state.deleting)
                        {
                            continue;
                        }
                        // The delivery engine logs this diagnostic and retains
                        // the row when its former holder cannot prove completion.
                        return Err(StoreError::unavailable(
                            "pending holder marker absent without matching live holder; retry",
                        ));
                    }
                    Some(prior) if prior != &encoded => return Err(bad()),
                    Some(_) => {}
                }
                if !applied.insert(identity.intent) {
                    continue;
                }
                let mut state = match folded.get(&identity.object) {
                    Some(state) => *state,
                    None => raw(seen, &c)?
                        .map(codec::decode_object_state)
                        .transpose()?
                        .unwrap_or_default(),
                };
                if state.deleting {
                    return Err(StoreError::Unavailable("object deleting; retry".into()));
                }
                let prior = raw(seen, &h)?.map(codec::decode_holder).transpose()?;
                // Decode even expired holds: malformed protection cannot be used
                // to accept delivery. gp is what covers expiration/recovery.
                raw(seen, &g)?.map(codec::decode_hold).transpose()?;
                if prior.is_none() && holders.insert(h.clone()) {
                    state.holders = state.holders.checked_add(1).ok_or_else(bad)?;
                }
                state.seq = state.seq.checked_add(1).ok_or_else(bad)?;
                state.changed_at_ms = state.changed_at_ms.max(now);
                writes.push(Write::Put(
                    h,
                    codec::encode_holder(&HolderRecord::new(state.seq, identity.ticket)),
                ));
                writes.extend([Write::Delete(g), Write::Delete(gp)]);
                let blocked = raw(seen, &b)?.map(codec::decode_block_entry).transpose()?;
                let independent = crate::takedown::denial::representative(raw(seen, &actions)?)?;
                if let Some(blocked) = blocked.or(independent) {
                    let request = match raw(seen, &ct)? {
                        Some(raw) => {
                            let request = ContentTakedownV1::decode(raw)?;
                            if request.identity != identity {
                                return Err(bad());
                            }
                            request
                        }
                        None => ContentTakedownV1 {
                            identity: identity.clone(),
                            blocked,
                            queued_at_ms: now,
                            ready_at_ms: None,
                        },
                    };
                    writes.push(Write::Put(ct, request.encode()?));
                    writes.push(Write::Put(
                        keys::timer(
                            now,
                            kinds::CONTENT_TAKEDOWN_REQUEST.get(),
                            &[identity.object.as_slice(), identity.intent.as_slice()].concat(),
                        ),
                        Value::default(),
                    ));
                } else if raw(seen, &ct)?.is_some() {
                    return Err(bad());
                }
                folded.insert(identity.object, state);
            }
            for (object, state) in folded {
                writes.push(Write::Put(
                    keys::object_state(&object),
                    codec::encode_object_state(&state),
                ));
            }
            Ok(())
        })
    }
}

/// Materializes a durable handoff, retaining request and timer for WP-5.6a.
/// It never acknowledges a takedown merely because this launch consumer ran.
#[derive(Debug)]
pub struct TakedownRequestTimer;
impl<S: crate::NamespaceStore> TimerHandler<S> for TakedownRequestTimer {
    fn kind(&self) -> TimerKind {
        kinds::CONTENT_TAKEDOWN_REQUEST
    }
    fn fire<'a>(
        &'a self,
        ctx: &'a TimerCtx<'a, S>,
        timer: &'a DueTimer,
    ) -> BoxFuture<'a, Result<Fired, StoreError>> {
        Box::pin(async move {
            let (object, intent) = timer.reference.split_first_chunk::<32>().ok_or_else(bad)?;
            let intent: [u8; 32] = intent.try_into().map_err(|_| bad())?;
            if content_shard(object) != *ctx.partition {
                return Err(bad());
            }
            let key = keys::content_takedown(object, &intent);
            let raw = ctx.store.get(ctx.partition, &key).await?.ok_or_else(bad)?;
            let mut request = ContentTakedownV1::decode(&raw)?;
            if request.identity.object != *object || request.identity.intent != intent {
                return Err(bad());
            }
            let mut batch = crate::Batch::new()
                .require(Precondition::Equals(key.clone(), raw))
                .require(Precondition::NotAfter(
                    ctx.now_ms
                        .saturating_add(crate::store::CONTENT_APPLY_WINDOW_MS),
                ));
            if request.ready_at_ms.is_none() {
                request.ready_at_ms = Some(ctx.now_ms);
                batch = batch.put(key, request.encode()?);
            }
            Ok(Fired::Reschedule {
                due_at_ms: ctx.now_ms.saturating_add(3_600_000),
                value: timer.value.clone(),
                batch,
            })
        })
    }
}
