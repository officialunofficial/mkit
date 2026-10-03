//! Retain authenticated immutable reads when an operation spans slices.
use crate::store::keys;
use crate::{Batch, BatchOutcome, Key, NamespaceStore, Partition, StoreError, Value};
use base64::{Engine, engine::general_purpose::STANDARD};
use mkit_core::hash::{Hash, hash};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

// A full worst-case radix path fits, with room for the other checkpoint fields.
const BYTES: usize = 300 * 1024;
const PAGES: usize = 256;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Page {
    digest: Hash,
    value: String,
}
fn corrupt() -> StoreError {
    StoreError::Corrupt("invalid immutable publication cache".into())
}
fn decode(page: &Page) -> Result<Value, StoreError> {
    let bytes = STANDARD.decode(&page.value).map_err(|_| corrupt())?;
    if bytes.len() > crate::store::publication_certificate::MAX_PAGE_BYTES
        || hash(&bytes) != page.digest
    {
        return Err(corrupt());
    }
    Ok(Value::new(bytes))
}
pub(super) fn validate(pages: &[Page]) -> Result<(), StoreError> {
    if pages.len() > PAGES {
        return Err(corrupt());
    }
    let mut bytes = 0;
    for page in pages {
        bytes += decode(page)?.as_bytes().len();
    }
    if bytes > BYTES {
        return Err(corrupt());
    }
    Ok(())
}
pub(super) struct Cached<S> {
    pub inner: S,
    pub pages: Mutex<Vec<Page>>,
}
impl<S> Cached<S> {
    pub(super) fn new(inner: S, pages: Vec<Page>) -> Self {
        Self {
            inner,
            pages: Mutex::new(pages),
        }
    }
    fn digest(p: &Partition, key: &Key) -> Option<Hash> {
        let keys::ParsedKey::PublicationPage(id) = keys::parse(key)? else {
            return None;
        };
        (crate::store::content_shard(&id) == *p).then_some(id)
    }
    fn remember(&self, digest: Hash, value: &Value) -> Result<(), StoreError> {
        if value.as_bytes().len() > crate::store::publication_certificate::MAX_PAGE_BYTES
            || hash(value.as_bytes()) != digest
        {
            return Err(corrupt());
        }
        let mut pages = self.pages.lock().map_err(|_| corrupt())?;
        pages.retain(|p| p.digest != digest);
        pages.push(Page {
            digest,
            value: STANDARD.encode(value.as_bytes()),
        });
        while pages.len() > PAGES
            || pages.iter().map(|p| p.value.len() * 3 / 4).sum::<usize>() > BYTES
        {
            pages.remove(0);
        }
        Ok(())
    }
}
impl<S: NamespaceStore> NamespaceStore for Cached<S> {
    fn capabilities(&self) -> crate::store::StoreCapabilities {
        self.inner.capabilities()
    }
    async fn get(&self, p: &Partition, k: &Key) -> Result<Option<Value>, StoreError> {
        let digest = Self::digest(p, k);
        if let Some(digest) = digest {
            let mut pages = self.pages.lock().map_err(|_| corrupt())?;
            if let Some(index) = pages.iter().position(|page| page.digest == digest) {
                let page = pages.remove(index);
                let value = decode(&page)?;
                pages.push(page);
                return Ok(Some(value));
            }
        }
        let value = self.inner.get(p, k).await?;
        if let (Some(digest), Some(value)) = (digest, &value) {
            self.remember(digest, value)?;
        }
        Ok(value)
    }
    async fn get_many(&self, p: &Partition, k: &[Key]) -> Result<Vec<Option<Value>>, StoreError> {
        self.inner.get_many(p, k).await
    }
    async fn scan(
        &self,
        p: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&crate::Cursor>,
        limit: u32,
    ) -> Result<crate::ScanPage, StoreError> {
        self.inner.scan(p, start, end, after, limit).await
    }
    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        // A duplicate-write comparison must observe the store rather than a cached value.
        {
            let mut pages = self.pages.lock().map_err(|_| corrupt())?;
            for write in &batch.writes {
                let key = match write {
                    crate::Write::Put(k, _) | crate::Write::Delete(k) => k,
                };
                if let Some(digest) = Self::digest(p, key) {
                    pages.retain(|page| page.digest != digest);
                }
            }
        }
        self.inner.apply(p, batch).await
    }
    async fn stats(&self, p: &Partition) -> Result<crate::PartitionStats, StoreError> {
        self.inner.stats(p).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.inner.probe().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::indexed::budget::{Budgeted, SliceBudget};
    use futures_executor::block_on;

    #[test]
    fn exhausted_immutable_reads_resume_but_mutable_rows_are_read_again() {
        block_on(async {
            let store =
                crate::MemoryKv::with_clock(std::sync::Arc::new(crate::rt::ManualClock::new(0)));
            let mut addresses = Vec::new();
            for id in [[1; 32], [2; 32], [3; 32]] {
                addresses.push(
                    crate::store::publication_certificate::insert(&store, None, id, 2, 0)
                        .await
                        .unwrap(),
                );
            }
            let budget = SliceBudget::new(2);
            let cached = Cached::new(Budgeted::new(&store, &budget), Vec::new());
            for id in &addresses[..2] {
                assert!(
                    cached
                        .get(
                            &crate::store::content_shard(id),
                            &keys::publication_page(id)
                        )
                        .await
                        .unwrap()
                        .is_some()
                );
            }
            assert!(
                cached
                    .get(
                        &crate::store::content_shard(&addresses[2]),
                        &keys::publication_page(&addresses[2])
                    )
                    .await
                    .is_err()
            );
            let pages = cached.pages.into_inner().unwrap();
            validate(&pages).unwrap();
            let budget = SliceBudget::new(1);
            let cached = Cached::new(Budgeted::new(&store, &budget), pages);
            for id in &addresses {
                assert!(
                    cached
                        .get(
                            &crate::store::content_shard(id),
                            &keys::publication_page(id)
                        )
                        .await
                        .unwrap()
                        .is_some()
                );
            }
            assert_eq!(budget.used(), 1);
            let partition = crate::store::content_shard(&[4; 32]);
            let key = keys::block(&[4; 32]);
            let cached = Cached::new(crate::store::BorrowedStore(&store), Vec::new());
            assert!(cached.get(&partition, &key).await.unwrap().is_none());
            store
                .apply(
                    &partition,
                    Batch::new().put(key.clone(), Value::new(vec![7])),
                )
                .await
                .unwrap();
            assert_eq!(
                cached.get(&partition, &key).await.unwrap(),
                Some(Value::new(vec![7]))
            );
        });
    }
}
