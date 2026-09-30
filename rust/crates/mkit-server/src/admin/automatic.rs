//! Automatic audit events ride the existing source relay and target transaction.
use std::collections::BTreeMap;

use mkit_core::hash::{hash, to_hex, to_hex_bytes};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{
    Response, auth,
    ledger::{audit_entry, decode_head, encode, guarded, head_key},
};
use crate::{
    Batch, BoxFuture, Key, NamespaceStore, Partition, Precondition, StoreError, Value, Write,
    purge,
    relay::{RelayEnqueueSnapshot, RelayHook, enqueue_relay_rows},
    store::{
        codec::{self, RelayV1},
        keys,
    },
};

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Event {
    source_identity: String,
    operation_id: String,
    recorded_at_ms: u64,
    request: purge::Request,
}
fn invalid(message: &'static str) -> StoreError {
    StoreError::Invalid(message.into())
}
fn event_key(source: &str, purge_id: &str) -> Key {
    Key::new(
        format!(
            "ai\0{}",
            to_hex(&hash(format!("{source}\0{purge_id}").as_bytes()))
        )
        .into_bytes(),
    )
}
fn events(writes: &[Write]) -> Vec<(Key, Value)> {
    writes
        .iter()
        .filter_map(|w| match w {
            Write::Put(k, v) if k.as_bytes().starts_with(b"ai\0") => Some((k.clone(), v.clone())),
            _ => None,
        })
        .collect()
}

/// Source-local audit enqueue planner. No target effect happens before commit.
#[derive(Clone, Debug)]
pub struct SystemAudit<S> {
    store: S,
    root: Partition,
}
impl<S> SystemAudit<S> {
    /// Use the same root as the deployment admin engine and relay audit hook.
    pub fn new(store: S, root: Partition) -> Self {
        Self { store, root }
    }
    /// Produce an event for callers already allocating source relay sequences.
    /// Add this row to the same `OutboxBuilder`/`enqueue_relay_rows` allocation as
    /// other effects; do not merge independently allocated `os` batches.
    /// # Errors
    /// Invalid automatic operation, selectors, source identity, or storage bounds.
    pub fn relay_row(
        &self,
        source: &Partition,
        request: &purge::Request,
        operation_id: &str,
        now_ms: u64,
    ) -> Result<RelayV1, StoreError> {
        request.validate()?;
        if !auth::identifier(operation_id, 128, true) || request.trigger == purge::Trigger::Manual {
            return Err(invalid("invalid automatic audit identity"));
        }
        let source_identity = to_hex_bytes(&source.encode()?);
        let event = Event {
            source_identity: source_identity.clone(),
            operation_id: operation_id.into(),
            recorded_at_ms: now_ms,
            request: request.clone(),
        };
        let value =
            encode(&event).map_err(|_| invalid("automatic audit event exceeds storage bound"))?;
        Ok(RelayV1 {
            at_ms: now_ms,
            target: self.root.clone(),
            puts: vec![(event_key(&source_identity, &request.purge_id), value)],
            deletes: Vec::new(),
        })
    }
}
impl<S: NamespaceStore> purge::AutomaticAudit for SystemAudit<S> {
    fn plan<'a>(
        &'a self,
        partition: &'a Partition,
        request: &'a purge::Request,
        operation_id: &'a str,
        now_ms: u64,
    ) -> BoxFuture<'a, Result<Batch, StoreError>> {
        Box::pin(async move {
            let row = self.relay_row(partition, request, operation_id, now_ms)?;
            let values = self
                .store
                .get_many(partition, &[keys::outbox_sequence(), keys::epoch_lease()])
                .await?;
            if values.len() != 2 {
                return Err(invalid("invalid audit source read count"));
            }
            let lease = values[1]
                .clone()
                .filter(|_| matches!(partition, Partition::Ref { .. }));
            let deadline = lease
                .as_ref()
                .map(codec::decode_epoch_lease)
                .transpose()?
                .map_or(now_ms.saturating_add(30_000), |l| {
                    now_ms
                        .saturating_add(30_000)
                        .min(l.expires_at_ms.saturating_sub(1))
                });
            let snapshot = RelayEnqueueSnapshot {
                sequence: values[0].clone(),
                source_lease: lease,
                deadline_ms: deadline,
            };
            enqueue_relay_rows(&snapshot, partition, &[row], now_ms)?
                .pop()
                .ok_or_else(|| invalid("missing automatic audit relay"))
        })
    }
}

/// Extend an existing relay target transaction using reads from that transaction.
/// Dedup receipts, gapless chain entries, and relay watermarks commit atomically.
/// # Errors
/// Malformed events, changed receipts, or corrupt/unavailable audit metadata.
pub fn extend_audit_batch(
    partition: &Partition,
    batch: &mut Batch,
    mut get: impl FnMut(&Key) -> Result<Option<Value>, StoreError>,
) -> Result<(), StoreError> {
    let events = events(&batch.writes);
    if events.is_empty() {
        return Ok(());
    }
    let root = crate::NamespaceKey::deployment_default();
    if partition != &Partition::Namespace(root.clone())
        && partition != &Partition::Coordinator(root)
    {
        return Err(invalid("automatic audit target is not deployment root"));
    }
    let old = get(&head_key())?;
    let mut head = decode_head(old.as_ref()).map_err(|_| invalid("corrupt audit head"))?;
    let mut additions = guarded(Batch::new(), head_key(), old);
    let mut receipts = BTreeMap::new();
    for (key, value) in events {
        let event: Event = serde_json::from_slice(value.as_bytes())
            .map_err(|_| invalid("invalid automatic audit event"))?;
        event.request.validate()?;
        if !auth::identifier(&event.operation_id, 128, true)
            || event.request.trigger == purge::Trigger::Manual
            || key != event_key(&event.source_identity, &event.request.purge_id)
        {
            return Err(invalid("invalid automatic audit identity"));
        }
        if event.source_identity.len() > crate::MAX_KEY_BYTES * 2
            || !event.source_identity.len().is_multiple_of(2)
        {
            return Err(invalid("invalid audit source identity"));
        }
        let source = event
            .source_identity
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                std::str::from_utf8(pair)
                    .ok()
                    .and_then(|text| u8::from_str_radix(text, 16).ok())
                    .ok_or_else(|| invalid("invalid audit source identity"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        // Re-encoding rejects noncanonical partition bytes.
        let source = Partition::decode(&source)?;
        if to_hex_bytes(&source.encode()?) != event.source_identity {
            return Err(invalid("invalid audit source identity"));
        }
        if let Some(existing) = receipts.get(&key) {
            if existing != &value {
                return Err(invalid("automatic purge identity reused"));
            }
            continue;
        }
        let observed = get(&key)?;
        if let Some(existing) = &observed {
            if existing != &value {
                return Err(invalid("automatic purge identity reused"));
            }
        } else {
            let actor = match event.request.trigger {
                purge::Trigger::Takedown | purge::Trigger::Suspension => "system:inspector",
                purge::Trigger::LeaseDeletion => "system:timer",
                _ => "system:relay",
            };
            let details = json!({"purgeId":event.request.purge_id,
                "sourcePartitionHash":to_hex(&hash(&source.encode()?)),"trigger":event.request.trigger})
            .to_string();
            let (entry, next) = audit_entry(
                &head,
                actor,
                &format!("{actor}/cache-purge"),
                "",
                "",
                &event.operation_id,
                "",
                &[event.request.scope().to_owned()],
                &Response::json(&json!({})),
                &details,
                event.recorded_at_ms,
            )
            .map_err(|_| invalid("invalid automatic audit entry"))?;
            additions = additions.put(
                Key::new([b"ae\0".as_slice(), &next.seq.to_be_bytes()].concat()),
                encode(&entry).map_err(|_| invalid("automatic audit entry too large"))?,
            );
            head = next;
        }
        additions = guarded(additions, key.clone(), observed);
        receipts.insert(key, value);
    }
    additions = additions.put(
        head_key(),
        encode(&head).map_err(|_| invalid("invalid audit head"))?,
    );
    batch.preconditions.extend(additions.preconditions);
    batch.writes.extend(additions.writes);
    Ok(())
}

/// Native relay hook: extend the actual atomic target apply after bounded reads.
#[derive(Clone, Debug)]
pub struct AuditRelayHook<S> {
    store: S,
    root: Partition,
}
impl<S> AuditRelayHook<S> {
    /// The target metadata store and canonical admin root.
    pub fn new(store: S, root: Partition) -> Self {
        Self { store, root }
    }
}
impl<S: NamespaceStore> RelayHook for AuditRelayHook<S> {
    fn before_apply<'a>(
        &'a self,
        target: &'a Partition,
        rows: &'a [(u64, RelayV1)],
        pre: &'a mut Vec<Precondition>,
        writes: &'a mut Vec<Write>,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            if target != &self.root
                || !rows.iter().any(|(_, r)| {
                    r.puts
                        .iter()
                        .any(|(k, _)| k.as_bytes().starts_with(b"ai\0"))
                })
            {
                return Ok(());
            }
            let mut keys = vec![head_key()];
            keys.extend(events(writes).into_iter().map(|(k, _)| k));
            let values = self.store.get_many(target, &keys).await?;
            let snapshot: BTreeMap<_, _> = keys.into_iter().zip(values).collect();
            let mut batch = Batch {
                preconditions: pre.clone(),
                writes: writes.clone(),
            };
            extend_audit_batch(target, &mut batch, |k| {
                snapshot
                    .get(k)
                    .cloned()
                    .ok_or_else(|| invalid("missing audit snapshot"))
            })?;
            *pre = batch.preconditions;
            *writes = batch.writes;
            Ok(())
        })
    }
}

/// Worker relay hook reserves target-local SQL extension space without DO reads.
#[derive(Clone, Debug)]
pub struct AuditReserveHook {
    root: Partition,
}
impl AuditReserveHook {
    /// The canonical admin root extended inside the target SQL transaction.
    #[must_use]
    pub fn new(root: Partition) -> Self {
        Self { root }
    }
}
impl RelayHook for AuditReserveHook {
    fn reserved_ops(&self, target: &Partition, rows: &[(u64, RelayV1)]) -> usize {
        let n = rows
            .iter()
            .flat_map(|(_, r)| &r.puts)
            .filter(|(k, _)| k.as_bytes().starts_with(b"ai\0"))
            .count();
        if target == &self.root && n > 0 {
            n.saturating_mul(2).saturating_add(2)
        } else {
            0
        }
    }
    fn before_apply<'a>(
        &'a self,
        _target: &'a Partition,
        _rows: &'a [(u64, RelayV1)],
        _pre: &'a mut Vec<Precondition>,
        _writes: &'a mut Vec<Write>,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async { Ok(()) })
    }
}
