//! Bounded source batches for relay rows produced outside an advance batch.

use crate::store::{
    Batch, BatchOutcome, MAX_BATCH_BYTES, MAX_BATCH_OPS, NamespaceStore, Partition, Precondition,
    StoreCapabilities, StoreError, Value, Write,
    codec::{self, RelayV1},
    keys,
    outbox::MAX_RELAY_PUTS,
};

/// Snapshot used to plan a chain. `deadline_ms` includes the deployment's
/// clock-skew margin; for a D34 ref shard, `source_lease` is mandatory.
#[derive(Debug, Clone)]
pub struct RelayEnqueueSnapshot {
    /// Observed outbox sequence row, if any.
    pub sequence: Option<Value>,
    /// Observed source epoch lease on a D34 ref shard.
    pub source_lease: Option<Value>,
    /// Latest time each batch may commit on the backend clock.
    pub deadline_ms: u64,
}

fn guard(key: crate::Key, value: Option<&Value>) -> Precondition {
    match value {
        Some(value) => Precondition::Equals(key, value.clone()),
        None => Precondition::Absent(key),
    }
}

fn lease_lost() -> StoreError {
    StoreError::unavailable(std::io::Error::other("source epoch lease lost; retry"))
}

fn batch_for(
    prior: Option<&Value>,
    lease: Option<&Value>,
    seq: u64,
    row: &RelayV1,
    now_ms: u64,
    deadline_ms: u64,
) -> Result<Batch, StoreError> {
    if row.puts.len().saturating_add(row.deletes.len()) > MAX_RELAY_PUTS {
        return Err(StoreError::Invalid(
            "relay row exceeds MAX_RELAY_PUTS".into(),
        ));
    }
    let value = codec::encode_relay(row)?;
    let mut batch = Batch::new()
        .require(Precondition::NotAfter(deadline_ms))
        .require(guard(keys::outbox_sequence(), prior));
    if let Some(lease) = lease {
        batch = batch.require(Precondition::Equals(keys::epoch_lease(), lease.clone()));
    }
    Ok(batch
        .put(keys::outbox_sequence(), codec::encode_u64(seq))
        .put(
            keys::timer(now_ms, crate::timers::registry::kinds::RELAY.get(), b""),
            Value::default(),
        )
        .put(keys::relay(seq), value))
}

/// Plan chained source batches. Each has a deadline, an `os` guard/put,
/// one relay kick, optional source lease guard, and bounded row puts.
/// The caller commits in order; after an `os` CAS loss it re-plans only
/// the uncommitted suffix from a fresh snapshot.
pub fn enqueue_relay_rows(
    os: &RelayEnqueueSnapshot,
    source: &Partition,
    rows: &[RelayV1],
    now_ms: u64,
) -> Result<Vec<Batch>, StoreError> {
    if matches!(source, Partition::Ref { .. }) && os.source_lease.is_none() {
        return Err(StoreError::Corrupt(
            "D34 relay batch lacks source epoch lease".into(),
        ));
    }
    if rows.is_empty() {
        return Ok(Vec::new());
    }
    if let Some(raw) = &os.source_lease {
        let lease = codec::decode_epoch_lease(raw)?;
        if now_ms >= lease.expires_at_ms || os.deadline_ms >= lease.expires_at_ms {
            return Err(lease_lost());
        }
    }
    let mut seq = os
        .sequence
        .as_ref()
        .map(codec::decode_u64)
        .transpose()?
        .unwrap_or(0);
    let mut prior = os.sequence.clone();
    let mut batches = Vec::new();
    let mut index = 0;
    while index < rows.len() {
        seq = seq
            .checked_add(1)
            .ok_or_else(|| StoreError::Corrupt("outbox sequence overflow".into()))?;
        let mut batch = batch_for(
            prior.as_ref(),
            os.source_lease.as_ref(),
            seq,
            &rows[index],
            now_ms,
            os.deadline_ms,
        )?;
        batch.validate(&StoreCapabilities::full())?;
        index += 1;
        while index < rows.len() && batch.preconditions.len() + batch.writes.len() < MAX_BATCH_OPS {
            let next = seq
                .checked_add(1)
                .ok_or_else(|| StoreError::Corrupt("outbox sequence overflow".into()))?;
            if rows[index]
                .puts
                .len()
                .saturating_add(rows[index].deletes.len())
                > MAX_RELAY_PUTS
            {
                return Err(StoreError::Invalid(
                    "relay row exceeds MAX_RELAY_PUTS".into(),
                ));
            }
            let value = codec::encode_relay(&rows[index])?;
            let key = keys::relay(next);
            let mut candidate = batch.clone();
            candidate.writes.push(Write::Put(key, value));
            if candidate.validate(&StoreCapabilities::full()).is_err() {
                break;
            }
            batch = candidate;
            seq = next;
            index += 1;
        }
        let next_os = codec::encode_u64(seq);
        // The sequence put is the first write, after all preconditions.
        batch.writes[0] = Write::Put(keys::outbox_sequence(), next_os.clone());
        debug_assert!(batch.preconditions.len() + batch.writes.len() <= MAX_BATCH_OPS);
        debug_assert!(
            batch
                .writes
                .iter()
                .map(|w| match w {
                    Write::Put(k, v) => k.as_bytes().len() + v.as_bytes().len(),
                    Write::Delete(k) => k.as_bytes().len(),
                })
                .sum::<usize>()
                <= MAX_BATCH_BYTES
        );
        batches.push(batch);
        prior = Some(next_os);
    }
    Ok(batches)
}

/// Commit a relay-row chain, re-reading `os` and re-planning the remaining
/// rows when another writer wins. The caller supplies its current source
/// lease and deadline; a stale lease fails closed.
pub async fn commit_relay_rows<S: NamespaceStore>(
    store: &S,
    source: &Partition,
    rows: &[RelayV1],
    now_ms: u64,
    deadline_ms: u64,
    source_lease: Option<&Value>,
) -> Result<(), StoreError> {
    if matches!(source, Partition::Ref { .. }) && source_lease.is_none() {
        return Err(StoreError::Corrupt(
            "D34 relay batch lacks source epoch lease".into(),
        ));
    }
    let mut done = 0;
    let mut losses = 0;
    while done < rows.len() {
        let snapshot = RelayEnqueueSnapshot {
            sequence: store.get(source, &keys::outbox_sequence()).await?,
            source_lease: source_lease.cloned(),
            deadline_ms,
        };
        let batches = enqueue_relay_rows(&snapshot, source, &rows[done..], now_ms)?;
        let mut lost = false;
        for batch in batches {
            let count = batch.writes.iter().filter(|w| matches!(w, Write::Put(key, _) if matches!(keys::parse(key), Some(keys::ParsedKey::Relay(_))))).count();
            match store.apply(source, batch).await? {
                BatchOutcome::Committed => done += count,
                BatchOutcome::PreconditionFailed { index, .. }
                    if source_lease.is_some() && index == 2 =>
                {
                    return Err(lease_lost());
                }
                BatchOutcome::PreconditionFailed { .. } => {
                    lost = true;
                    break;
                }
                BatchOutcome::DeadlinePassed { .. } => {
                    return Err(StoreError::unavailable(std::io::Error::other(
                        "relay enqueue deadline passed",
                    )));
                }
            }
        }
        if lost {
            losses += 1;
            if losses == 8 {
                return Err(StoreError::unavailable(std::io::Error::other(
                    "relay enqueue contention",
                )));
            }
        }
    }
    Ok(())
}

/// Whether all source rows through `seq` have left its outbox. It uses the
/// source state scan; target watermark delivery precedes source cleanup.
pub async fn relay_delivered_through<S: NamespaceStore>(
    store: &S,
    source: &Partition,
    seq: u64,
) -> Result<bool, StoreError> {
    let allocated = store
        .get(source, &keys::outbox_sequence())
        .await?
        .as_ref()
        .map(codec::decode_u64)
        .transpose()?
        .unwrap_or(0);
    if allocated < seq {
        return Ok(false);
    }
    let (start, end) = keys::class_range(keys::TAG_RELAY);
    let page = store.scan(source, &start, &end, None, 1).await?;
    match page.entries.first().and_then(|(key, _)| keys::parse(key)) {
        Some(keys::ParsedKey::Relay(first)) => Ok(first > seq),
        None if page.entries.is_empty() => Ok(true),
        _ => Err(StoreError::Corrupt("invalid relay head".into())),
    }
}

#[cfg(all(test, feature = "memory"))]
mod tests {
    use super::*;
    use crate::memory::MemoryKv;
    use crate::repo::{NamespaceKey, RepoName};
    use futures_executor::block_on;

    fn source() -> Partition {
        Partition::Namespace(NamespaceKey::deployment_default())
    }
    fn ref_source() -> Partition {
        Partition::Ref {
            ns: NamespaceKey::deployment_default(),
            repo: RepoName::new("one").expect("valid repository name"),
            shard_ref: "refs/heads/main".into(),
        }
    }
    fn row(n: u16) -> RelayV1 {
        RelayV1 {
            at_ms: 1_000,
            target: source(),
            puts: vec![(
                crate::Key::new(n.to_be_bytes().to_vec()),
                Value::new(vec![u8::try_from(n % 256).unwrap_or(0)]),
            )],
            deletes: Vec::new(),
        }
    }

    #[test]
    fn chains_batches_and_detects_delivery() {
        let store = MemoryKv::default();
        let source = source();
        let rows: Vec<_> = (0..120).map(row).collect();
        let snapshot = RelayEnqueueSnapshot {
            sequence: None,
            source_lease: None,
            deadline_ms: u64::MAX,
        };
        let batches = enqueue_relay_rows(&snapshot, &source, &rows, 1_000).unwrap();
        assert!(batches.len() >= 2);
        for batch in batches {
            assert_eq!(
                block_on(store.apply(&source, batch)).unwrap(),
                BatchOutcome::Committed
            );
        }
        assert!(!block_on(relay_delivered_through(&store, &source, 120)).unwrap());
        let deletes = (1..=120).fold(Batch::new(), |batch, seq| batch.delete(keys::relay(seq)));
        // The store cap forbids one large delete; remove in bounded chunks.
        for chunk in deletes.writes.chunks(80) {
            let batch = Batch {
                preconditions: Vec::new(),
                writes: chunk.to_vec(),
            };
            assert_eq!(
                block_on(store.apply(&source, batch)).unwrap(),
                BatchOutcome::Committed
            );
        }
        assert!(block_on(relay_delivered_through(&store, &source, 120)).unwrap());
        assert!(!block_on(relay_delivered_through(&store, &source, 121)).unwrap());
    }

    #[test]
    fn stale_sequence_replans_uncommitted_rows() {
        let store = MemoryKv::default();
        let source = source();
        let stale = RelayEnqueueSnapshot {
            sequence: None,
            source_lease: None,
            deadline_ms: u64::MAX,
        };
        let batch = enqueue_relay_rows(&stale, &source, &[row(1)], 1_000)
            .unwrap()
            .remove(0);
        assert_eq!(
            block_on(store.apply(
                &source,
                Batch::new().put(keys::outbox_sequence(), codec::encode_u64(7))
            ))
            .unwrap(),
            BatchOutcome::Committed
        );
        assert!(matches!(
            block_on(store.apply(&source, batch)).unwrap(),
            BatchOutcome::PreconditionFailed { .. }
        ));
        block_on(commit_relay_rows(
            &store,
            &source,
            &[row(1)],
            1_000,
            u64::MAX,
            None,
        ))
        .unwrap();
        assert!(
            block_on(store.get(&source, &keys::relay(8)))
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn expired_source_lease_cannot_enqueue() {
        let lease = codec::encode_epoch_lease(&codec::EpochLease {
            epoch: 1,
            expires_at_ms: 1_010,
            config_version: 1,
        });
        let snapshot = RelayEnqueueSnapshot {
            sequence: None,
            source_lease: Some(lease),
            deadline_ms: 1_010,
        };
        assert!(enqueue_relay_rows(&snapshot, &source(), &[row(1)], 1_000).is_err());
    }

    #[test]
    fn ref_source_requires_lease_and_a_lost_lease_is_not_contention() {
        let source = ref_source();
        let snapshot = RelayEnqueueSnapshot {
            sequence: None,
            source_lease: None,
            deadline_ms: 2_000,
        };
        assert!(matches!(
            enqueue_relay_rows(&snapshot, &source, &[row(1)], 1_000),
            Err(StoreError::Corrupt(_))
        ));
        let stale = codec::encode_epoch_lease(&codec::EpochLease {
            epoch: 1,
            expires_at_ms: 10_000,
            config_version: 1,
        });
        let current = codec::encode_epoch_lease(&codec::EpochLease {
            epoch: 2,
            expires_at_ms: 10_000,
            config_version: 1,
        });
        let store = MemoryKv::with_clock(std::sync::Arc::new(crate::ManualClock::new(1_000)));
        block_on(store.apply(&source, Batch::new().put(keys::epoch_lease(), current))).unwrap();
        let error = block_on(commit_relay_rows(
            &store,
            &source,
            &[row(1)],
            1_000,
            2_000,
            Some(&stale),
        ))
        .unwrap_err();
        assert!(error.to_string().contains("source epoch lease lost"));
    }
}
