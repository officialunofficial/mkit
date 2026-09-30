//! Request-local read view. Every batched read remains one underlying store call.
use super::{
    Batch, BatchOutcome, Cursor, Key, NamespaceStore, Partition, PartitionStats, RangeScan,
    ScanPage, StoreCapabilities, StoreError, Value, keys, publication::Witness,
};
use crate::pipeline::clearance::PublicationPolicy;
use crate::repo::RepoId;

/// A read-only store facade selected after repository authorization.
pub struct ViewStore<'a, S> {
    /// Underlying store; mutations through the facade are refused.
    pub store: &'a S,
    /// Authorized repository identity.
    pub repo: &'a RepoId,
    /// Writer view, without conferring read permission.
    pub writer: bool,
    /// Coherent serving-stop seam, shared by writer and reader views.
    pub policy: Option<&'a dyn PublicationPolicy>,
}
impl<S> core::fmt::Debug for ViewStore<'_, S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ViewStore").field("repo", self.repo).field("writer", &self.writer)
            .field("serving_stop", &self.policy.is_some()).finish_non_exhaustive()
    }
}
fn retag(key: &Key, from: &[u8], to: &[u8]) -> Key {
    let bytes = key.as_bytes();
    if bytes.starts_with(from) {
        Key::new([to, &bytes[from.len()..]].concat())
    } else {
        key.clone()
    }
}
impl<S: NamespaceStore> ViewStore<'_, S> {
    fn key(&self, p: &Partition, key: &Key) -> Key {
        if self.writer || !self.store.capabilities().atomic_multi_key {
            return key.clone();
        }
        let key = retag(key, b"r\0", b"pr\0");
        let key = retag(&key, b"x\0", b"py\0");
        if matches!(p, Partition::RepoIndex { .. }) {
            retag(&key, b"m\0", b"pm\0")
        } else {
            key
        }
    }
    fn value(&self, key: &Key, value: Option<Value>) -> Result<Option<Value>, StoreError> {
        let Some(value) = value else {
            return Ok(None);
        };
        if let Some(keys::ParsedKey::Membership { repo, pack_id }) = keys::parse(key) {
            if repo != self.repo.name {
                return Err(StoreError::Corrupt("view repository mismatch".into()));
            }
            let witness = Witness::decode(&value)?;
            if !witness.visible(self.writer, 0)
                || self
                    .policy
                    .is_some_and(|p| !p.pack_available(self.repo, &pack_id))
            {
                return Ok(None);
            }
        }
        Ok(Some(value))
    }
    fn page(&self, mut page: ScanPage) -> ScanPage {
        if !self.writer && self.store.capabilities().atomic_multi_key {
            for (key, _) in &mut page.entries {
                *key = retag(&retag(key, b"pr\0", b"r\0"), b"py\0", b"x\0");
            }
        }
        page
    }
}
impl<S: NamespaceStore> NamespaceStore for ViewStore<'_, S> {
    fn capabilities(&self) -> StoreCapabilities {
        self.store.capabilities()
    }
    async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
        self.value(key, self.store.get(p, &self.key(p, key)).await?)
    }
    async fn get_many(
        &self,
        p: &Partition,
        keys: &[Key],
    ) -> Result<Vec<Option<Value>>, StoreError> {
        let selected: Vec<_> = keys.iter().map(|key| self.key(p, key)).collect();
        let values = self.store.get_many(p, &selected).await?;
        if values.len() != keys.len() {
            return Err(StoreError::Corrupt("short view read".into()));
        }
        keys.iter()
            .zip(values)
            .map(|(key, value)| self.value(key, value))
            .collect()
    }
    async fn scan(
        &self,
        p: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<ScanPage, StoreError> {
        Ok(self.page(
            self.store
                .scan(p, &self.key(p, start), &self.key(p, end), after, limit)
                .await?,
        ))
    }
    async fn scan_many(
        &self,
        p: &Partition,
        ranges: &[RangeScan],
    ) -> Result<Vec<ScanPage>, StoreError> {
        let ranges: Vec<_> = ranges
            .iter()
            .map(|r| RangeScan {
                start: self.key(p, &r.start),
                end: self.key(p, &r.end),
                after: r.after.clone(),
                limit: r.limit,
            })
            .collect();
        Ok(self
            .store
            .scan_many(p, &ranges)
            .await?
            .into_iter()
            .map(|page| self.page(page))
            .collect())
    }
    async fn apply(&self, _: &Partition, _: Batch) -> Result<BatchOutcome, StoreError> {
        Err(StoreError::Invalid(
            "read view cannot mutate storage".into(),
        ))
    }
    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        self.store.stats(p).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.store.probe().await
    }
}
