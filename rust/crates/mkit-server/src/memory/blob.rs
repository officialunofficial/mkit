//! `MemoryBlobStore`: the reference [`BlobStore`].

use std::collections::BTreeMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::Bytes;
use futures_core::Stream;
use mkit_core::hash::{Hash, Hasher};
use mkit_core::upload_parts::{PartHasher, PartPlan, merge_to_root};

use super::{MemoryFault, lock, take_fault};
use crate::store::{
    BlobBody, BlobKey, BlobMeta, BlobStore, ByteRange, CommitOutcome, MAX_BLOB_PIECE_BYTES,
    MultipartBlobStore, PackSink, PartRef, PartSink, StoreError,
};

/// Bodies longer than this are streamed in pieces of this size
/// (`BlobStore::get`).
const STREAM_CHUNK: usize = MAX_BLOB_PIECE_BYTES;

/// `bytes` as a body: whole, or streamed when longer than [`STREAM_CHUNK`].
fn body(bytes: Bytes) -> BlobBody {
    if bytes.len() <= STREAM_CHUNK {
        return BlobBody::Bytes(bytes);
    }
    BlobBody::Stream {
        len: bytes.len() as u64,
        stream: Box::pin(Chunks(bytes)),
    }
}

/// The remaining bytes of a streamed body.
struct Chunks(Bytes);

impl Stream for Chunks {
    type Item = Result<Bytes, StoreError>;

    fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let rest = &mut self.get_mut().0;
        if rest.is_empty() {
            return Poll::Ready(None);
        }
        let n = rest.len().min(STREAM_CHUNK);
        Poll::Ready(Some(Ok(rest.split_to(n))))
    }
}

#[derive(Debug, Default)]
struct Shared {
    blobs: Mutex<BTreeMap<BlobKey, Bytes>>,
    sessions: Mutex<BTreeMap<Vec<u8>, MemoryMultipart>>,
    next_session: AtomicU64,
    fault: Mutex<Option<MemoryFault>>,
}

#[derive(Debug)]
struct MemoryMultipart {
    key: BlobKey,
    len: u64,
    part_size: u64,
    parts: BTreeMap<u32, MemoryPart>,
}

#[derive(Debug)]
struct MemoryPart {
    bytes: Bytes,
    cv: [u8; 32],
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
    #[cfg(test)]
    pub(crate) fn multipart_session_count(&self) -> usize {
        lock(&self.shared.sessions).len()
    }

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

/// One attempted memory part. Its bytes are staged until its CV verifies.
#[derive(Debug)]
pub struct MemoryPartSink {
    shared: Arc<Shared>,
    key: BlobKey,
    session: Vec<u8>,
    index: u32,
    expected_cv: [u8; 32],
    hasher: PartHasher,
    bytes: Vec<u8>,
}

impl MultipartBlobStore for MemoryBlobStore {
    type PartSink = MemoryPartSink;
    const MAX_PARTS: u32 = u32::MAX;

    fn supports_multipart(&self) -> bool {
        true
    }

    async fn begin_multipart(
        &self,
        key: BlobKey,
        len: u64,
        part_size: u64,
    ) -> Result<Vec<u8>, StoreError> {
        PartPlan::new(len, part_size, Self::MAX_PARTS)
            .map_err(|e| StoreError::Invalid(e.to_string().into()))?;
        let session = self
            .shared
            .next_session
            .fetch_add(1, Ordering::Relaxed)
            .to_be_bytes()
            .to_vec();
        lock(&self.shared.sessions).insert(
            session.clone(),
            MemoryMultipart {
                key,
                len,
                part_size,
                parts: BTreeMap::new(),
            },
        );
        Ok(session)
    }

    async fn begin_part(
        &self,
        key: BlobKey,
        session: &[u8],
        plan: &PartPlan,
        index: u32,
        expected_cv: [u8; 32],
    ) -> Result<MemoryPartSink, StoreError> {
        let sessions = lock(&self.shared.sessions);
        let upload = sessions.get(session).ok_or(StoreError::SessionGone)?;
        if upload.key != key || upload.len != plan.total() || upload.part_size != plan.part_size() {
            return Err(StoreError::SessionGone);
        }
        let hasher =
            PartHasher::new(plan, index).map_err(|e| StoreError::Invalid(e.to_string().into()))?;
        Ok(MemoryPartSink {
            shared: Arc::clone(&self.shared),
            key,
            session: session.to_vec(),
            index,
            expected_cv,
            hasher,
            bytes: Vec::new(),
        })
    }

    async fn complete(
        &self,
        key: BlobKey,
        session: &[u8],
        plan: &PartPlan,
        parts: &[PartRef],
    ) -> Result<CommitOutcome, StoreError> {
        let mut sessions = lock(&self.shared.sessions);
        let upload = sessions.get(session).ok_or(StoreError::SessionGone)?;
        if upload.key != key || upload.len != plan.total() || upload.part_size != plan.part_size() {
            return Err(StoreError::SessionGone);
        }
        if parts.len() != plan.count() as usize {
            return Err(StoreError::Invalid("wrong number of parts".into()));
        }
        let mut cvs = Vec::with_capacity(parts.len());
        let mut bytes = Vec::new();
        for (i, part) in parts.iter().enumerate() {
            let index = u32::try_from(i).map_err(|_| StoreError::Invalid("part index".into()))?;
            let stored = upload.parts.get(&index).ok_or(StoreError::SessionGone)?;
            if part.index != index
                || part.len
                    != plan
                        .expected_len(index)
                        .map_err(|e| StoreError::Invalid(e.to_string().into()))?
                || part.tag.as_slice() != stored.cv
                || part.len != stored.bytes.len() as u64
            {
                return Err(StoreError::Invalid(
                    "part reference does not match stored part".into(),
                ));
            }
            cvs.push(stored.cv);
            bytes.extend_from_slice(&stored.bytes);
        }
        if bytes.len() as u64 != plan.total()
            || merge_to_root(plan, &cvs).map_err(|e| StoreError::Invalid(e.to_string().into()))?
                != *key.hash()
        {
            return Err(StoreError::Invalid(
                "merged part root does not match key".into(),
            ));
        }
        let mut blobs = lock(&self.shared.blobs);
        let outcome = if let std::collections::btree_map::Entry::Vacant(entry) = blobs.entry(key) {
            entry.insert(Bytes::from(bytes));
            CommitOutcome::Created
        } else {
            CommitOutcome::AlreadyPresent
        };
        sessions.remove(session);
        Ok(outcome)
    }

    async fn abort(&self, key: BlobKey, session: &[u8]) -> Result<(), StoreError> {
        let mut sessions = lock(&self.shared.sessions);
        if sessions
            .get(session)
            .is_some_and(|upload| upload.key == key)
        {
            sessions.remove(session);
        }
        Ok(())
    }
}

impl PartSink for MemoryPartSink {
    async fn write(&mut self, chunk: Bytes) -> Result<(), StoreError> {
        if chunk.is_empty() {
            return Err(StoreError::Invalid("empty part chunk".into()));
        }
        self.hasher
            .update(&chunk)
            .map_err(|e| StoreError::Invalid(e.to_string().into()))?;
        self.bytes.extend_from_slice(&chunk);
        Ok(())
    }

    async fn commit(self) -> Result<Vec<u8>, StoreError> {
        let cv = self
            .hasher
            .finalize()
            .map_err(|e| StoreError::Invalid(e.to_string().into()))?;
        if cv != self.expected_cv {
            return Err(StoreError::PartSubtreeMismatch);
        }
        let mut sessions = lock(&self.shared.sessions);
        let upload = sessions
            .get_mut(&self.session)
            .ok_or(StoreError::SessionGone)?;
        if upload.key != self.key {
            return Err(StoreError::SessionGone);
        }
        upload.parts.insert(
            self.index,
            MemoryPart {
                bytes: Bytes::from(self.bytes),
                cv,
            },
        );
        Ok(cv.to_vec())
    }

    async fn abort(self) {}
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
            return Ok(Some(body(blob)));
        };
        let span = range.resolve(blob.len() as u64)?;
        // `resolve` bounds the span by the blob's length, which is a usize.
        let index = |n: u64| usize::try_from(n).map_err(|_| StoreError::Invalid("range".into()));
        Ok(Some(body(blob.slice(index(span.start)?..index(span.end)?))))
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

impl MemoryPackSink {
    /// Verify against `root` (or the key, for `None`) and publish.
    fn finish(self, root: Option<Hash>) -> Result<CommitOutcome, StoreError> {
        take_fault(&self.shared.fault, MemoryFault::BlobCommit)?;
        let expected = self.key.expected_root(root)?;
        if self.buf.len() as u64 != self.len {
            return Err(StoreError::Invalid("blob length does not match".into()));
        }
        if self.hasher.finalize() != expected {
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
        self.finish(None)
    }

    async fn commit_with_root(self, content_root: Hash) -> Result<CommitOutcome, StoreError> {
        self.finish(Some(content_root))
    }

    async fn abort(self) {}
}

#[cfg(test)]
mod tests {
    use futures_executor::block_on;
    use mkit_core::hash::hash;
    use mkit_core::upload_parts::{MIN_PART_SIZE, PartPlan, part_subtree_cv};

    use super::*;

    fn key_of(bytes: &[u8]) -> BlobKey {
        BlobKey::pack(hash(bytes))
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
            BlobBody::Stream { .. } => panic!("a small memory blob is never streamed"),
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
    fn large_bodies_stream_in_bounded_pieces() {
        let store = MemoryBlobStore::default();
        let data: Vec<u8> = (0..=250_u8).cycle().take(STREAM_CHUNK * 2 + 7).collect();
        let key = key_of(&data);
        put(&store, key, data.len() as u64, &[&data]).unwrap();
        let read = |range| {
            let body = block_on(store.get(&key, range)).unwrap().unwrap();
            let BlobBody::Stream { len, mut stream } = body else {
                panic!("a large body is streamed");
            };
            let mut out = Vec::new();
            while let Some(piece) =
                block_on(core::future::poll_fn(|cx| stream.as_mut().poll_next(cx)))
            {
                let piece = piece.unwrap();
                assert!(piece.len() <= MAX_BLOB_PIECE_BYTES);
                out.extend_from_slice(&piece);
            }
            assert_eq!(out.len() as u64, len);
            out
        };
        assert_eq!(read(None), data);
        let range = ByteRange {
            start: 3,
            end_inclusive: STREAM_CHUNK as u64 + 3,
        };
        assert_eq!(read(Some(range)), &data[3..=STREAM_CHUNK + 3]);
        // Exactly one piece is still one buffer.
        let edge = &data[..STREAM_CHUNK];
        let edge_key = key_of(edge);
        put(&store, edge_key, edge.len() as u64, &[edge]).unwrap();
        assert_eq!(get(&store, &edge_key, None).unwrap().len(), STREAM_CHUNK);
    }

    #[test]
    fn poisoned_lock_recovers() {
        let store = MemoryBlobStore::default();
        let key = key_of(b"a");
        put(&store, key, 1, &[b"a"]).unwrap();
        let shared = store.shared.clone();
        let panicked = std::thread::spawn(move || {
            let _guard = shared.blobs.lock().unwrap();
            panic!("poison the blob lock");
        })
        .join();
        assert!(panicked.is_err() && store.shared.blobs.is_poisoned());
        assert_eq!(get(&store, &key, None).unwrap(), "a");
        let other = key_of(b"b");
        assert_eq!(
            put(&store, other, 1, &[b"b"]).unwrap(),
            CommitOutcome::Created
        );
        assert!(block_on(store.delete(&key)).unwrap());
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

    #[test]
    fn multipart_parts_are_idempotent_and_bad_reupload_keeps_the_good_part() {
        let store = MemoryBlobStore::default();
        let mut data = vec![0x31; usize::try_from(MIN_PART_SIZE).unwrap()];
        data.extend_from_slice(b"last part");
        let key = key_of(&data);
        let plan = PartPlan::new(data.len() as u64, MIN_PART_SIZE, 2).unwrap();
        let session = block_on(store.begin_multipart(key, plan.total(), plan.part_size())).unwrap();
        let first = &data[..usize::try_from(MIN_PART_SIZE).unwrap()];
        let last = &data[usize::try_from(MIN_PART_SIZE).unwrap()..];
        let cv0 = part_subtree_cv(&plan, 0, first).unwrap();
        let cv1 = part_subtree_cv(&plan, 1, last).unwrap();

        // Send the last part first, then the large part in bounded chunks.
        let mut sink = block_on(store.begin_part(key, &session, &plan, 1, cv1)).unwrap();
        block_on(sink.write(Bytes::copy_from_slice(last))).unwrap();
        let tag1 = block_on(sink.commit()).unwrap();
        let upload_first = || {
            let mut sink = block_on(store.begin_part(key, &session, &plan, 0, cv0)).unwrap();
            for chunk in first.chunks(MAX_BLOB_PIECE_BYTES) {
                block_on(sink.write(Bytes::copy_from_slice(chunk))).unwrap();
            }
            block_on(sink.commit()).unwrap()
        };
        let tag0 = upload_first();
        assert_eq!(upload_first(), tag0);

        let mut bad = block_on(store.begin_part(key, &session, &plan, 0, cv0)).unwrap();
        block_on(bad.write(Bytes::from(vec![
            0x32;
            usize::try_from(MIN_PART_SIZE).unwrap()
        ])))
        .unwrap();
        assert!(matches!(
            block_on(bad.commit()),
            Err(StoreError::PartSubtreeMismatch)
        ));
        assert_eq!(block_on(store.head(&key)).unwrap(), None);

        let parts = [
            PartRef {
                index: 0,
                len: MIN_PART_SIZE,
                tag: tag0,
            },
            PartRef {
                index: 1,
                len: last.len() as u64,
                tag: tag1,
            },
        ];
        assert_eq!(
            block_on(store.complete(key, &session, &plan, &parts)).unwrap(),
            CommitOutcome::Created
        );
        assert_eq!(
            block_on(store.head(&key)).unwrap(),
            Some(BlobMeta {
                len: data.len() as u64
            })
        );
        assert!(matches!(
            block_on(store.complete(key, &session, &plan, &parts)),
            Err(StoreError::SessionGone)
        ));
    }

    #[test]
    fn abort_and_unknown_sessions_are_gone() {
        let store = MemoryBlobStore::default();
        let plan = PartPlan::new(MIN_PART_SIZE + 1, MIN_PART_SIZE, 2).unwrap();
        let key = key_of(b"absent");
        let session = block_on(store.begin_multipart(key, plan.total(), plan.part_size())).unwrap();
        assert!(matches!(
            block_on(store.begin_part(key, b"unknown", &plan, 0, [0; 32])),
            Err(StoreError::SessionGone)
        ));
        block_on(store.abort(key, &session)).unwrap();
        block_on(store.abort(key, &session)).unwrap();
        assert!(matches!(
            block_on(store.begin_part(key, &session, &plan, 0, [0; 32])),
            Err(StoreError::SessionGone)
        ));
        assert_eq!(block_on(store.head(&key)).unwrap(), None);
    }

    #[test]
    fn marker_and_pack_hashes_have_separate_memory_keys() {
        let store = MemoryBlobStore::default();
        let content = b"marker";
        let pack = key_of(content);
        let marker = BlobKey::upload_marker(*pack.hash());
        assert_ne!(pack, marker);
        assert_eq!(
            put(&store, marker, content.len() as u64, &[content]).unwrap(),
            CommitOutcome::Created
        );
        assert_eq!(block_on(store.head(&pack)).unwrap(), None);
        assert_eq!(
            block_on(store.head(&marker)).unwrap(),
            Some(BlobMeta {
                len: content.len() as u64
            })
        );
    }
}
