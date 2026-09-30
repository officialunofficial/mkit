//! Route the firing partition through TimerCtx.store, never a self-DO request.
use crate::{
    Batch, BatchOutcome, Cursor, Key, NamespaceStore, Partition, PartitionStats, ScanPage,
    StoreCapabilities, StoreError, Value,
};

/// A borrowed local timer store plus the existing remote partition adapter.
#[derive(Debug)]
pub struct LocalStore<'a, L, R> {
    local: &'a L,
    partition: &'a Partition,
    remote: &'a R,
}
impl<L, R> Clone for LocalStore<'_, L, R> {
    fn clone(&self) -> Self {
        Self {
            local: self.local,
            partition: self.partition,
            remote: self.remote,
        }
    }
}
impl<'a, L, R> LocalStore<'a, L, R> {
    /// Use local SQL for exactly the firing partition and remote routing otherwise.
    pub fn new(local: &'a L, partition: &'a Partition, remote: &'a R) -> Self {
        Self {
            local,
            partition,
            remote,
        }
    }
}
impl<L: NamespaceStore, R: NamespaceStore> NamespaceStore for LocalStore<'_, L, R> {
    fn capabilities(&self) -> StoreCapabilities {
        self.local.capabilities()
    }
    async fn get(&self, p: &Partition, k: &Key) -> Result<Option<Value>, StoreError> {
        if p == self.partition {
            self.local.get(p, k).await
        } else {
            self.remote.get(p, k).await
        }
    }
    async fn get_many(&self, p: &Partition, k: &[Key]) -> Result<Vec<Option<Value>>, StoreError> {
        if p == self.partition {
            self.local.get_many(p, k).await
        } else {
            self.remote.get_many(p, k).await
        }
    }
    async fn scan(
        &self,
        p: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<ScanPage, StoreError> {
        if p == self.partition {
            self.local.scan(p, start, end, after, limit).await
        } else {
            self.remote.scan(p, start, end, after, limit).await
        }
    }
    async fn apply(&self, p: &Partition, b: Batch) -> Result<BatchOutcome, StoreError> {
        if p == self.partition {
            self.local.apply(p, b).await
        } else {
            self.remote.apply(p, b).await
        }
    }
    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        if p == self.partition {
            self.local.stats(p).await
        } else {
            self.remote.stats(p).await
        }
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.local.probe().await
    }
}
