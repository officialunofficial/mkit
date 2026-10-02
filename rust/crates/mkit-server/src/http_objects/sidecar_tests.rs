//! Fixed-range sidecar reads through byte and streaming stores.
#![allow(clippy::unwrap_used)]
use super::*;
use crate::memory::MemoryBlobStore;
use crate::store::{BlobMeta, StoreError};
use futures_executor::block_on;
use std::sync::Mutex;

struct StreamingBlobs {
    inner: MemoryBlobStore,
    response: Mutex<Option<BlobBody>>,
}

impl BlobStore for StreamingBlobs {
    type Sink = <MemoryBlobStore as BlobStore>::Sink;

    async fn begin(&self, key: BlobKey, len: u64) -> Result<Self::Sink, StoreError> {
        self.inner.begin(key, len).await
    }

    async fn get(
        &self,
        key: &BlobKey,
        range: Option<ByteRange>,
    ) -> Result<Option<BlobBody>, StoreError> {
        assert_eq!(*key, BlobKey::object_offsets([7; 32]));
        assert_eq!(
            range,
            Some(ByteRange {
                start: 296,
                end_inclusive: 303
            })
        );
        Ok(self.response.lock().unwrap().take())
    }

    async fn head(&self, key: &BlobKey) -> Result<Option<BlobMeta>, StoreError> {
        self.inner.head(key).await
    }

    async fn probe(&self) -> Result<(), StoreError> {
        self.inner.probe().await
    }

    async fn delete(&self, key: &BlobKey) -> Result<bool, StoreError> {
        self.inner.delete(key).await
    }
}

fn total(body: BlobBody) -> Result<u64, Miss> {
    block_on(sidecar_total(
        &StreamingBlobs {
            inner: MemoryBlobStore::default(),
            response: Mutex::new(Some(body)),
        },
        [7; 32],
        304,
    ))
}

fn stream(len: u64, pieces: Vec<Result<Bytes, StoreError>>) -> BlobBody {
    BlobBody::Stream {
        len,
        stream: Box::pin(futures::stream::iter(pieces)),
    }
}

#[test]
fn thirty_six_chunk_sidecar_tail_matches_bytes_and_fragmented_stream() {
    let offsets: Vec<u64> = (0..=36).map(|i| i * 250_000).collect();
    let mut sidecar = b"MKOF".to_vec();
    sidecar.extend_from_slice(&36_u32.to_le_bytes());
    for offset in offsets {
        sidecar.extend_from_slice(&offset.to_le_bytes());
    }
    assert_eq!(sidecar.len(), 304);
    let tail = Bytes::copy_from_slice(&sidecar[296..]);
    assert_eq!(total(BlobBody::Bytes(tail.clone())), Ok(9_000_000));
    assert_eq!(total(stream(8, vec![Ok(tail.clone())])), Ok(9_000_000));
    assert_eq!(
        total(stream(
            8,
            vec![Ok(tail.slice(..3)), Ok(Bytes::new()), Ok(tail.slice(3..))]
        )),
        Ok(9_000_000)
    );
}

#[test]
fn malformed_stream_tails_have_the_same_uniform_failure_as_bytes() {
    let tail = Bytes::copy_from_slice(&9_000_000_u64.to_le_bytes());
    for body in [
        BlobBody::Bytes(tail.slice(..7)),
        BlobBody::Bytes(Bytes::from_static(&[0; 9])),
        stream(7, vec![Ok(tail.clone())]),
        stream(9, vec![Ok(tail.clone())]),
        stream(8, vec![Ok(tail.slice(..7))]),
        stream(8, vec![Ok(Bytes::from_static(&[0; 9]))]),
        stream(8, vec![Ok(tail.clone()), Ok(Bytes::from_static(&[0]))]),
        stream(
            8,
            vec![
                Ok(tail),
                Err(StoreError::unavailable("injected tail failure")),
            ],
        ),
    ] {
        assert_eq!(total(body), Err(Miss::Unavailable));
    }
}
