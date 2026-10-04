//! Denial reads shared only within one operation phase. The descriptor directory,
//! membership, inventory, authorization and final seam are never cached here.
use crate::store::{
    Batch, BatchOutcome, Cursor, Key, NamespaceStore, Partition, PartitionStats, RangeScan,
    ScanPage, StoreCapabilities, StoreError, Value,
};
use mkit_core::hash::Hash;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

type Reply = Vec<Option<Value>>;
type Saved = Result<Reply, ()>;
type Slot = Arc<tokio::sync::Mutex<Option<Saved>>>;
const MAX_CHECKS: usize = 256;
const MAX_BYTES: usize = 4 << 20;
#[derive(Default)]
struct Cache {
    slots: BTreeMap<Hash, Slot>,
    bytes: usize,
}

pub(super) struct Checks<'a, S> {
    store: &'a S,
    cache: Mutex<Cache>,
}
impl<'a, S> Checks<'a, S> {
    pub(super) fn new(store: &'a S) -> Self {
        Self {
            store,
            cache: Mutex::new(Cache::default()),
        }
    }
    pub(super) fn reset(&self) {
        *self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Cache::default();
    }
    fn slot(&self, partition: &Partition, keys: &[Key]) -> Option<Slot> {
        let [block, action] = keys else { return None };
        let id: Hash = block.as_bytes().strip_prefix(b"b\0")?.try_into().ok()?;
        if *partition != crate::store::content_shard(&id)
            || *action != crate::takedown::denial::action_key(&id)
        {
            return None;
        }
        let mut cache = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(slot) = cache.slots.get(&id) {
            return Some(slot.clone());
        }
        if cache.slots.len() >= MAX_CHECKS {
            return None;
        }
        let slot = Slot::default();
        cache.slots.insert(id, slot.clone());
        Some(slot)
    }
}
impl<S: NamespaceStore> Checks<'_, S> {
    /// Warm only guards already eligible for this operation. Public callers
    /// invoke this after structural proof, before any membership-dependent work.
    /// Errors stay attached to their guard: a denied target still short-circuits
    /// its pack, even if that pack's batched read failed.
    pub(super) async fn prefetch(&self, ids: &[Hash]) -> Result<(), StoreError> {
        let mut partitions = BTreeMap::<Partition, Vec<_>>::new();
        for id in ids
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
        {
            let partition = crate::store::content_shard(&id);
            let keys = [
                crate::store::keys::block(&id),
                crate::takedown::denial::action_key(&id),
            ];
            if let Some(slot) = self.slot(&partition, &keys)
                && slot.lock().await.is_none()
            {
                partitions.entry(partition).or_default().push((id, slot));
            }
        }
        let groups: Vec<_> = partitions
            .into_iter()
            .flat_map(|(partition, ids)| {
                // Each call has at most 32 rows. Across all retained guards
                // there are at most 512 rows, below the shared 1,000-row cap.
                ids.chunks(16)
                    .map(|ids| (partition.clone(), ids.to_vec()))
                    .collect::<Vec<_>>()
            })
            .collect();
        for wave in groups.chunks(crate::store::read_io::parallelism()) {
            let _reservation = self
                .store
                .reserve_read_calls(u32::try_from(wave.len()).map_err(|_| guard_failure())?)?;
            let replies = futures::future::join_all(wave.iter().map(|(partition, ids)| {
                let keys: Vec<_> = ids
                    .iter()
                    .flat_map(|(id, _)| {
                        [
                            crate::store::keys::block(id),
                            crate::takedown::denial::action_key(id),
                        ]
                    })
                    .collect();
                async move { self.store.get_many(partition, &keys).await }
            }))
            .await;
            // Retain and consume results in partition/id order, independently
            // of completion order. A cancelled wave retains no partial reply.
            for ((_, ids), reply) in wave.iter().zip(replies) {
                match reply {
                    Ok(reply) if reply.len() == ids.len() * 2 => {
                        for ((_, slot), pair) in ids.iter().zip(reply.chunks_exact(2)) {
                            self.retain(slot, Ok(pair.to_vec())).await;
                        }
                    }
                    _ => {
                        for (_, slot) in ids {
                            self.retain(slot, Err(())).await;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub(super) async fn prefetch_locations(
        &self,
        locations: &[(Hash, crate::store::index::LocatedObject)],
    ) -> Result<(), StoreError> {
        let ids: Vec<_> = locations
            .iter()
            .flat_map(|(id, loc)| [*id, loc.pack])
            .collect();
        self.prefetch(&ids).await
    }

    async fn retain(&self, slot: &Slot, reply: Saved) {
        let bytes = reply.as_ref().map_or(0, |reply| {
            reply
                .iter()
                .flatten()
                .map(|value| value.as_bytes().len())
                .sum()
        });
        let mut saved = slot.lock().await;
        if saved.is_some() {
            return;
        }
        let mut cache = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if bytes <= MAX_BYTES.saturating_sub(cache.bytes) {
            cache.bytes += bytes;
            *saved = Some(reply);
        }
    }
}
fn guard_failure() -> StoreError {
    StoreError::unavailable("denial guard read failed")
}
impl<S: NamespaceStore> NamespaceStore for Checks<'_, S> {
    fn capabilities(&self) -> StoreCapabilities {
        self.store.capabilities()
    }
    fn reserve_read_calls(
        &self,
        calls: u32,
    ) -> Result<Option<crate::store::ReadReservation>, StoreError> {
        self.store.reserve_read_calls(calls)
    }
    async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
        Ok(self
            .get_many(p, core::slice::from_ref(key))
            .await?
            .pop()
            .flatten())
    }
    async fn get_many(&self, p: &Partition, keys: &[Key]) -> Result<Reply, StoreError> {
        let mut selected = None;
        let pair;
        let requested = if let [key] = keys {
            let bytes = key.as_bytes();
            if let Some(raw) = bytes.strip_prefix(b"b\0") {
                if raw.len() == 32 || raw.len() == 40 && &raw[32..] == b"\0actions" {
                    let id: Hash = raw[..32]
                        .try_into()
                        .map_err(|_| StoreError::Corrupt("invalid denial key".into()))?;
                    pair = [
                        crate::store::keys::block(&id),
                        crate::takedown::denial::action_key(&id),
                    ];
                    selected = Some(usize::from(raw.len() != 32));
                    &pair[..]
                } else {
                    keys
                }
            } else {
                keys
            }
        } else {
            keys
        };
        let Some(slot) = self.slot(p, requested) else {
            return self.store.get_many(p, keys).await;
        };
        let project =
            |reply: &Reply| selected.map_or_else(|| reply.clone(), |n| vec![reply[n].clone()]);
        // A per-id read lock coalesces simultaneous pack checks; independent ids
        // share no lock while doing I/O. A failed or cancelled read stores nothing.
        let mut saved = slot.lock().await;
        if let Some(reply) = &*saved {
            return reply.as_ref().map(project).map_err(|()| guard_failure());
        }
        let reply = self.store.get_many(p, requested).await?;
        if reply.len() != requested.len() {
            return Err(StoreError::Corrupt("short denial read".into()));
        }
        let bytes = reply
            .iter()
            .flatten()
            .map(|v| v.as_bytes().len())
            .sum::<usize>();
        let mut cache = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if bytes <= MAX_BYTES.saturating_sub(cache.bytes) {
            cache.bytes += bytes;
            *saved = Some(Ok(reply.clone()));
        }
        Ok(project(&reply))
    }
    async fn scan_many(
        &self,
        p: &Partition,
        ranges: &[RangeScan],
    ) -> Result<Vec<ScanPage>, StoreError> {
        self.store.scan_many(p, ranges).await
    }
    async fn scan(
        &self,
        p: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<ScanPage, StoreError> {
        self.store.scan(p, start, end, after, limit).await
    }
    async fn apply(&self, _: &Partition, _: Batch) -> Result<BatchOutcome, StoreError> {
        Err(StoreError::Invalid("read-only operation".into()))
    }
    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        self.store.stats(p).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.store.probe().await
    }
}

#[cfg(test)]
#[path = "tests/reader_checks.rs"]
mod tests;
