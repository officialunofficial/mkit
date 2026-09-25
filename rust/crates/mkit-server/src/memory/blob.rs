//! `MemoryBlobStore`: the reference [`BlobStore`].

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use mkit_core::hash::Hasher;

use super::{MemoryFault, lock, take_fault};
use crate::store::{
    BlobBody, BlobKey, BlobMeta, BlobStore, ByteRange, CommitOutcome, PackSink, StoreError,
};

#[derive(Debug, Default)]
struct Shared {
    blobs: Mutex<BTreeMap<BlobKey, Bytes>>,
    fault: Mutex<Option<MemoryFault>>,
}

/// An in-memory [`BlobStore`] for one keyspace. Clones share the blobs.
#[derive(Debug, Clone)]
pub struct MemoryBlobStore {
    keyspace: String,
    shared: Arc<Shared>,
}

/// The `packs` keyspace.
impl Default for MemoryBlobStore {
    fn default() -> Self {
        Self::new("packs")
    }
}

impl MemoryBlobStore {
    /// An empty store for `keyspace` (`packs` for pack uploads).
    #[must_use]
    pub fn new(keyspace: impl Into<String>) -> Self {
        Self {
            keyspace: keyspace.into(),
            shared: Arc::default(),
        }
    }

    /// The keyspace this store serves.
    #[must_use]
    pub fn keyspace(&self) -> &str {
        &self.keyspace
    }

    /// Arm a one-shot [`MemoryFault`] (`BlobWrite` or `BlobCommit`).
    #[must_use]
    pub fn with_fault(self, fault: MemoryFault) -> Self {
        *lock(&self.shared.fault) = Some(fault);
        self
    }
}

/// The upload handle of [`MemoryBlobStore`]. It hashes incrementally and
/// buffers the blob: the one exception to `PackSink`'s one-part memory
/// bound, since this backend holds every blob in memory anyway.
#[derive(Debug)]
pub struct MemoryPackSink {
    shared: Arc<Shared>,
    key: BlobKey,
    len: u64,
    hasher: Hasher,
    buf: Vec<u8>,
    writes: u32,
}

impl BlobStore for MemoryBlobStore {
    type Sink = MemoryPackSink;

    async fn begin(&self, key: BlobKey, len: u64) -> Result<MemoryPackSink, StoreError> {
        Ok(MemoryPackSink {
            shared: self.shared.clone(),
            key,
            len,
            hasher: Hasher::new(),
            buf: Vec::new(),
            writes: 0,
        })
    }

    async fn get(
        &self,
        key: &BlobKey,
        range: Option<ByteRange>,
    ) -> Result<Option<BlobBody>, StoreError> {
        let Some(blob) = lock(&self.shared.blobs).get(key).cloned() else {
            return Ok(None);
        };
        let Some(range) = range else {
            return Ok(Some(BlobBody::Bytes(blob)));
        };
        let span = range.resolve(blob.len() as u64)?;
        // `resolve` bounds the span by the blob's length, which is a usize.
        let index = |n: u64| usize::try_from(n).map_err(|_| StoreError::Invalid("range".into()));
        Ok(Some(BlobBody::Bytes(
            blob.slice(index(span.start)?..index(span.end)?),
        )))
    }

    async fn head(&self, key: &BlobKey) -> Result<Option<BlobMeta>, StoreError> {
        let blobs = lock(&self.shared.blobs);
        Ok(blobs.get(key).map(|b| BlobMeta {
            len: b.len() as u64,
        }))
    }

    async fn probe(&self) -> Result<(), StoreError> {
        Ok(())
    }

    async fn delete(&self, key: &BlobKey) -> Result<bool, StoreError> {
        Ok(lock(&self.shared.blobs).remove(key).is_some())
    }
}

impl PackSink for MemoryPackSink {
    async fn write(&mut self, chunk: Bytes) -> Result<(), StoreError> {
        let nth = self.writes;
        self.writes = self.writes.saturating_add(1);
        take_fault(&self.shared.fault, MemoryFault::BlobWrite(nth))?;
        if (self.buf.len() + chunk.len()) as u64 > self.len {
            return Err(StoreError::Invalid("blob is longer than declared".into()));
        }
        self.hasher.update(&chunk);
        self.buf.extend_from_slice(&chunk);
        Ok(())
    }

    async fn commit(self) -> Result<CommitOutcome, StoreError> {
        take_fault(&self.shared.fault, MemoryFault::BlobCommit)?;
        if self.buf.len() as u64 != self.len {
            return Err(StoreError::Invalid("blob length does not match".into()));
        }
        if self.hasher.finalize() != self.key.0 {
            return Err(StoreError::Invalid(
                "blob hash does not match its key".into(),
            ));
        }
        let mut blobs = lock(&self.shared.blobs);
        if blobs.contains_key(&self.key) {
            return Ok(CommitOutcome::AlreadyPresent);
        }
        blobs.insert(self.key, Bytes::from(self.buf));
        Ok(CommitOutcome::Created)
    }

    async fn abort(self) {}
}

#[cfg(test)]
mod tests {
    use futures_executor::block_on;
    use mkit_core::hash::hash;

    use super::*;

    fn key_of(bytes: &[u8]) -> BlobKey {
        BlobKey::new(hash(bytes))
    }

    fn put(
        store: &MemoryBlobStore,
        key: BlobKey,
        len: u64,
        chunks: &[&[u8]],
    ) -> Result<CommitOutcome, StoreError> {
        block_on(async {
            let mut sink = store.begin(key, len).await?;
            for chunk in chunks {
                sink.write(Bytes::copy_from_slice(chunk)).await?;
            }
            sink.commit().await
        })
    }

    fn get(store: &MemoryBlobStore, key: &BlobKey, range: Option<ByteRange>) -> Option<Bytes> {
        match block_on(store.get(key, range)).unwrap()? {
            BlobBody::Bytes(b) => Some(b),
            BlobBody::Stream { .. } => panic!("memory blobs are never streamed"),
        }
    }

    #[test]
    fn blob_commit_rejects_hash_and_len_mismatch_leaving_nothing() {
        let store = MemoryBlobStore::default();
        let key = key_of(b"hello");
        for (k, len, chunks) in [
            (key_of(b"other"), 5, &[&b"hello"[..]][..]),
            (key, 6, &[&b"hello"[..]][..]),
            (key, 4, &[&b"hel"[..], b"lo"][..]),
        ] {
            assert!(matches!(
                put(&store, k, len, chunks),
                Err(StoreError::Invalid(_))
            ));
        }
        assert_eq!(block_on(store.head(&key)).unwrap(), None);
        assert_eq!(get(&store, &key_of(b"other"), None), None);
        // Aborting leaves nothing either.
        block_on(async {
            let mut sink = store.begin(key, 5).await.unwrap();
            sink.write(Bytes::from_static(b"hello")).await.unwrap();
            sink.abort().await;
        });
        assert_eq!(block_on(store.head(&key)).unwrap(), None);
    }

    #[test]
    fn blob_commit_identical_bytes_is_already_present() {
        let store = MemoryBlobStore::default();
        let key = key_of(b"hello");
        assert_eq!(
            put(&store, key, 5, &[b"he", b"llo"]).unwrap(),
            CommitOutcome::Created
        );
        assert_eq!(
            put(&store, key, 5, &[b"hello"]).unwrap(),
            CommitOutcome::AlreadyPresent
        );
        assert_eq!(
            block_on(store.head(&key)).unwrap(),
            Some(BlobMeta { len: 5 })
        );
        assert_eq!(store.keyspace(), "packs");
        let empty = key_of(b"");
        assert_eq!(put(&store, empty, 0, &[]).unwrap(), CommitOutcome::Created);
        assert_eq!(get(&store, &empty, None).unwrap().len(), 0);
    }

    #[test]
    fn blob_get_range() {
        let store = MemoryBlobStore::default();
        let key = key_of(b"0123456789");
        put(&store, key, 10, &[b"0123456789"]).unwrap();
        let range = |start, end_inclusive| {
            Some(ByteRange {
                start,
                end_inclusive,
            })
        };
        assert_eq!(get(&store, &key, range(0, 0)).unwrap(), "0");
        assert_eq!(get(&store, &key, range(3, 5)).unwrap(), "345");
        assert_eq!(get(&store, &key, range(8, 100)).unwrap(), "89");
        assert!(matches!(
            block_on(store.get(&key, range(10, 12))),
            Err(StoreError::RangeNotSatisfiable { len: 10 })
        ));
        assert!(matches!(
            block_on(store.get(&key, range(5, 4))),
            Err(StoreError::Invalid(_))
        ));
    }

    #[test]
    fn blob_delete_then_get_none_and_second_delete_false() {
        let store = MemoryBlobStore::default();
        let key = key_of(b"x");
        put(&store, key, 1, &[b"x"]).unwrap();
        assert!(block_on(store.delete(&key)).unwrap());
        assert_eq!(get(&store, &key, None), None);
        assert!(!block_on(store.delete(&key)).unwrap());
    }

    #[test]
    fn blob_faults_fire_once_and_leave_nothing() {
        let key = key_of(b"abc");
        let store = MemoryBlobStore::default().with_fault(MemoryFault::BlobWrite(1));
        assert!(matches!(
            put(&store, key, 3, &[b"a", b"bc"]),
            Err(StoreError::Unavailable(_))
        ));
        assert_eq!(
            put(&store, key, 3, &[b"a", b"bc"]).unwrap(),
            CommitOutcome::Created
        );
        let store = MemoryBlobStore::default().with_fault(MemoryFault::BlobCommit);
        assert!(matches!(
            put(&store, key, 3, &[b"abc"]),
            Err(StoreError::Unavailable(_))
        ));
        assert_eq!(block_on(store.head(&key)).unwrap(), None);
        assert_eq!(
            put(&store, key, 3, &[b"abc"]).unwrap(),
            CommitOutcome::Created
        );
    }
}
