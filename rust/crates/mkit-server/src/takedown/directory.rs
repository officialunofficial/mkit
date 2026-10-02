//! Monotonic descriptor locations, reserved before shard-local activation.
use crate::store::{Cursor, Key, ScanPage};
use crate::{Batch, BatchOutcome, NamespaceStore, Partition, Precondition, StoreError, Value};
use mkit_core::hash::Hash;
use std::collections::VecDeque;

/// Fixed small global fan-out. Routing uses the high four object-id bits.
pub(crate) const DIRECTORY_SHARDS: u16 = 16;
pub(super) const PREFIX: &[u8] = b"b\0\xffdenial-descriptor-directory\0";
/// Small immutable pointers bound first-page replies across all sixteen shards.
pub(super) const PAGE_ROWS: u32 = 64;

fn partition(object: &Hash) -> Partition {
    Partition::ContentShard(u16::from(object[0] >> 4))
}
fn key(object: &Hash) -> Key {
    Key::new([PREFIX, object].concat())
}
fn value(object: &Hash) -> Value {
    Value::new([&[1][..], object].concat())
}
fn corrupt() -> StoreError {
    StoreError::Corrupt("invalid denial directory".into())
}
fn range() -> (Key, Key) {
    let mut end = PREFIX.to_vec();
    end[PREFIX.len() - 1] = 1;
    (Key::new(PREFIX.to_vec()), Key::new(end))
}

/// An uncertain reservation succeeds only after an exact strong read-back.
/// Registration is never removed, even when every local action is removed.
pub(crate) async fn reserve<S: NamespaceStore>(
    store: &S,
    object: &Hash,
    now: u64,
) -> Result<(), StoreError> {
    let (p, k, expected) = (partition(object), key(object), value(object));
    if let Some(old) = store.get(&p, &k).await? {
        return if old == expected {
            Ok(())
        } else {
            Err(corrupt())
        };
    }
    let result = store
        .apply(
            &p,
            Batch::new()
                .require(Precondition::Absent(k.clone()))
                .require(Precondition::NotAfter(
                    now.saturating_add(crate::store::CONTENT_APPLY_WINDOW_MS),
                ))
                .put(k.clone(), expected.clone()),
        )
        .await;
    if matches!(result, Ok(BatchOutcome::Committed)) {
        return Ok(());
    }
    match store.get(&p, &k).await? {
        Some(old) if old == expected => Ok(()),
        Some(_) => Err(corrupt()),
        None => Err(result.err().unwrap_or_else(|| {
            StoreError::unavailable("denial directory reservation did not commit")
        })),
    }
}

fn validate_page(shard: u16, page: &ScanPage) -> Result<(), StoreError> {
    if page.entries.len() > PAGE_ROWS as usize || page.entries.is_empty() && page.next.is_some() {
        return Err(corrupt());
    }
    let mut last: Option<&Key> = None;
    for (key, raw) in &page.entries {
        let id: Hash = key
            .as_bytes()
            .strip_prefix(PREFIX)
            .and_then(|b| b.try_into().ok())
            .ok_or_else(corrupt)?;
        if partition(&id) != Partition::ContentShard(shard)
            || *raw != value(&id)
            || last.is_some_and(|old| old.as_bytes() >= key.as_bytes())
        {
            return Err(corrupt());
        }
        last = Some(key);
    }
    Ok(())
}

/// Strong first pages are joined before any pointed-to descriptor is read.
/// A successful empty `ScanPage` is an empty directory; absent transport replies
/// and failed reads are errors, never interpreted as empty pages.
pub(super) struct Walk {
    pages: VecDeque<(u16, ScanPage)>,
    entries: VecDeque<(Key, Value)>,
    shard: u16,
    after: Option<Cursor>,
    next: Option<Cursor>,
    last: Option<Key>,
}
impl Walk {
    pub(super) async fn start<S: NamespaceStore>(
        store: &S,
        concurrency: usize,
    ) -> Result<Self, StoreError> {
        let (start, end) = range();
        let mut pages = VecDeque::new();
        for first in (0..DIRECTORY_SHARDS).step_by(concurrency.clamp(1, 6)) {
            let last =
                (usize::from(first) + concurrency.clamp(1, 6)).min(usize::from(DIRECTORY_SHARDS));
            let replies = futures::future::join_all((usize::from(first)..last).map(|shard| {
                let (start, end) = (&start, &end);
                async move {
                    let shard = u16::try_from(shard).map_err(|_| corrupt())?;
                    let page = store
                        .scan(&Partition::ContentShard(shard), start, end, None, PAGE_ROWS)
                        .await?;
                    Ok::<_, StoreError>((shard, page))
                }
            }))
            .await;
            for reply in replies {
                let (shard, page) = reply?;
                validate_page(shard, &page)?;
                pages.push_back((shard, page));
            }
        }
        Ok(Self {
            pages,
            entries: VecDeque::new(),
            shard: 0,
            after: None,
            next: None,
            last: None,
        })
    }

    pub(super) async fn next<S: NamespaceStore>(
        &mut self,
        store: &S,
    ) -> Result<Option<Hash>, StoreError> {
        loop {
            if let Some((k, raw)) = self.entries.pop_front() {
                let id: Hash = k
                    .as_bytes()
                    .strip_prefix(PREFIX)
                    .and_then(|b| b.try_into().ok())
                    .ok_or_else(corrupt)?;
                if partition(&id) != Partition::ContentShard(self.shard)
                    || raw != value(&id)
                    || self
                        .last
                        .as_ref()
                        .is_some_and(|last| last.as_bytes() >= k.as_bytes())
                {
                    return Err(corrupt());
                }
                self.last = Some(k);
                return Ok(Some(id));
            }
            let page = if let Some(next) = self.next.take() {
                if self.after.as_ref() == Some(&next) || self.last.is_none() {
                    return Err(corrupt());
                }
                self.after = Some(next);
                let (start, end) = range();
                store
                    .scan(
                        &Partition::ContentShard(self.shard),
                        &start,
                        &end,
                        self.after.as_ref(),
                        PAGE_ROWS,
                    )
                    .await?
            } else if let Some((shard, page)) = self.pages.pop_front() {
                self.shard = shard;
                self.after = None;
                self.last = None;
                page
            } else {
                return Ok(None);
            };
            validate_page(self.shard, &page)?;
            self.entries = page.entries.into();
            self.next = page.next;
        }
    }
}

/// Read both current descriptor forms together, after the directory proof cut.
pub(super) async fn descriptors<S: NamespaceStore>(
    store: &S,
    object: &Hash,
) -> Result<Vec<(Key, Value)>, StoreError> {
    let wanted = [
        super::denial::descriptor_key(object),
        super::denial::legacy_descriptor_key(object),
    ];
    let rows = store
        .get_many(&crate::store::content_shard(object), &wanted)
        .await?;
    if rows.len() != wanted.len() {
        return Err(corrupt());
    }
    Ok(wanted
        .into_iter()
        .zip(rows)
        .filter_map(|(k, v)| v.map(|v| (k, v)))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::BorrowedStore;
    use crate::store::{BlockEntry, ContentIndex};
    use crate::{MemoryFault, MemoryKv};
    use futures_executor::block_on;
    #[test]
    fn uncertain_committed_registration_is_resolved_before_activation() {
        block_on(async {
            let store = MemoryKv::with_clock(std::sync::Arc::new(crate::rt::ManualClock::new(0)))
                .with_fault(MemoryFault::ApplyAfterCommit);
            let object = [0x80; 32];
            ContentIndex::new(BorrowedStore(&store))
                .block(&object, &BlockEntry::new("legal", 1), 1)
                .await
                .unwrap();
            assert_eq!(
                store.get(&partition(&object), &key(&object)).await.unwrap(),
                Some(value(&object))
            );
            assert!(
                store
                    .get(
                        &crate::store::content_shard(&object),
                        &super::super::denial::legacy_descriptor_key(&object)
                    )
                    .await
                    .unwrap()
                    .is_some()
            );
        });
    }
    #[test]
    fn failed_registration_cannot_activate_and_entries_survive_unblock() {
        block_on(async {
            let store = MemoryKv::with_clock(std::sync::Arc::new(crate::rt::ManualClock::new(0)))
                .with_fault(MemoryFault::ApplyBefore);
            let object = [0x90; 32];
            let index = ContentIndex::new(BorrowedStore(&store));
            assert!(
                index
                    .block(&object, &BlockEntry::new("legal", 1), 1)
                    .await
                    .is_err()
            );
            assert!(index.blocked(&object).await.unwrap().is_none());
            index
                .block(&object, &BlockEntry::new("legal", 1), 1)
                .await
                .unwrap();
            index.unblock(&object, 2).await.unwrap();
            assert_eq!(
                store.get(&partition(&object), &key(&object)).await.unwrap(),
                Some(value(&object))
            );
        });
    }
    #[test]
    fn corrupt_registration_and_page_fail_closed() {
        block_on(async {
            let store = MemoryKv::with_clock(std::sync::Arc::new(crate::rt::ManualClock::new(0)));
            let object = [0xa0; 32];
            store
                .apply(
                    &partition(&object),
                    Batch::new().put(key(&object), Value::new(vec![1])),
                )
                .await
                .unwrap();
            assert!(reserve(&store, &object, 1).await.is_err());
            assert!(Walk::start(&store, 4).await.is_err());
        });
    }
}
