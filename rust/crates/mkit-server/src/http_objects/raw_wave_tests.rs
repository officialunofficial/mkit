//! Large stalled frame bodies cannot multiply the serial resident envelope.
#![allow(clippy::unwrap_used)]
use super::*;
use crate::indexed::geometry::{CANONICAL_BYTES, FRAME_BYTES};
use crate::memory::{MemoryBlobStore, MemoryKv};
use crate::pipeline::SinglePartition;
use crate::store::{BlobMeta, StoreError, index::IndexValue};
use crate::{NamespaceKey, NoopMetrics, RepoName};
use futures::FutureExt as _;
use std::sync::atomic::{AtomicUsize, Ordering};

const PREFIX: usize = 36;

fn canonical(sequence: u8) -> Vec<u8> {
    mkit_core::serialize::serialize(&Object::Blob(mkit_core::object::Blob {
        data: vec![sequence; usize::try_from(CANONICAL_BYTES - BLOB_HEADER).unwrap()],
    }))
    .unwrap()
}

fn member(sequence: u8, large: bool) -> (Hash, LocatedObject) {
    (
        mkit_core::hash::hash(&canonical(sequence)),
        LocatedObject {
            pack: [sequence; 32],
            value: IndexValue {
                frame_offset: 8,
                frame_length: if large {
                    FRAME_BYTES
                } else {
                    5 + CANONICAL_BYTES
                },
                wire_type: if large { 3 } else { 0 },
                decoded_size: CANONICAL_BYTES,
                chain_depth: 0,
                delta_base: None,
            },
        },
    )
}

#[derive(Default)]
struct StalledFrames {
    completed_small: AtomicUsize,
    opened_large: AtomicUsize,
    inner: MemoryBlobStore,
}

impl BlobStore for StalledFrames {
    type Sink = <MemoryBlobStore as BlobStore>::Sink;

    async fn begin(&self, key: BlobKey, len: u64) -> Result<Self::Sink, StoreError> {
        self.inner.begin(key, len).await
    }

    async fn get(
        &self,
        key: &BlobKey,
        range: Option<ByteRange>,
    ) -> Result<Option<BlobBody>, StoreError> {
        let range = range.unwrap();
        if range.start == 0 {
            return Ok(Some(BlobBody::Bytes(Bytes::from_static(b"MKIT\x02\0\0\0"))));
        }
        let sequence = key.hash()[0];
        if usize::from(sequence) >= PREFIX {
            self.opened_large.fetch_add(1, Ordering::SeqCst);
            // frame_bytes reserves the whole declared frame before polling
            // this body, so every opened large body is a live large buffer.
            return Ok(Some(BlobBody::Stream {
                len: FRAME_BYTES,
                stream: Box::pin(futures::stream::pending()),
            }));
        }
        let bytes = canonical(sequence);
        let mut frame = vec![0];
        frame.extend_from_slice(&u32::try_from(bytes.len()).unwrap().to_le_bytes());
        frame.extend_from_slice(&bytes);
        self.completed_small.fetch_add(1, Ordering::SeqCst);
        Ok(Some(BlobBody::Bytes(Bytes::from(frame))))
    }

    async fn head(&self, key: &BlobKey) -> Result<Option<BlobMeta>, StoreError> {
        self.inner.head(key).await
    }

    async fn probe(&self) -> Result<(), StoreError> {
        Ok(())
    }

    async fn delete(&self, key: &BlobKey) -> Result<bool, StoreError> {
        self.inner.delete(key).await
    }
}

#[test]
fn retained_canonical_results_cannot_overlap_six_stalled_maximum_frames() {
    let members: Vec<_> = (0..42)
        .map(|n| member(n, usize::from(n) >= PREFIX))
        .collect();
    let blobs = StalledFrames::default();
    let meta = MemoryKv::default();
    let repo = RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: RepoName::new("resident").unwrap(),
    };
    let env = Env {
        no_reads: &BTreeSet::new(),
        blobs: &blobs,
        meta: &meta,
        shards: &SinglePartition,
        repo: &repo,
        indexed: &IndexedConfig::default(),
        cfg: &HttpObjectsConfig::default(),
        metrics: &NoopMetrics,
        caps: Caps::Reader,
    };
    let mut budget = Budget(256 << 20);
    let uncached = BTreeSet::new();
    let mut read = Box::pin(load_raw_many(&env, &members, &uncached, &mut budget));
    assert!(read.as_mut().now_or_never().is_none());
    assert_eq!(blobs.completed_small.load(Ordering::SeqCst), PREFIX);
    assert_eq!(blobs.opened_large.load(Ordering::SeqCst), 1);
    // Includes the actually retained prefix and eagerly reserved frame bytes.
    // The fixed decoder scratch can overlap only one synchronous decode.
    let payload = PREFIX as u64 * CANONICAL_BYTES + FRAME_BYTES + 2 * CANONICAL_BYTES;
    assert!(payload + (28 << 20) < (96 << 20));
    drop(read); // Cancelling a stalled wave must release its buffers.
    assert_eq!(budget.0, (256 << 20) - 37 * CANONICAL_BYTES);
}

#[test]
fn small_members_keep_six_way_io_and_bad_geometry_fails_before_dispatch() {
    let small: Vec<_> = (0..6).map(|n| member(n, false)).collect();
    assert_eq!(raw_wave_len(&small), Ok(6));
    let large: Vec<_> = (0..6).map(|n| member(n, true)).collect();
    assert_eq!(raw_wave_len(&large), Ok(1));
    for bad in [
        IndexValue {
            frame_length: FRAME_BYTES + 1,
            ..small[0].1.value
        },
        IndexValue {
            decoded_size: CANONICAL_BYTES + 1,
            ..small[0].1.value
        },
    ] {
        let mut members = small.clone();
        members[0].1.value = bad;
        assert_eq!(raw_wave_len(&members), Err(Miss::Capped));
    }
}
