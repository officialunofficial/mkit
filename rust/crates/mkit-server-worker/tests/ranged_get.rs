//! A bounded ranged blob read is one backend call, and keeps its observable
//! results: absent is `None`, a start past the end is unsatisfiable, the end
//! clamps, and a malformed range is invalid.
#![allow(clippy::unwrap_used)] // Invalid test fixtures must fail immediately.
mod common;

use std::sync::atomic::Ordering;

use bytes::Bytes;
use futures::StreamExt as _;
use futures::executor::block_on;
use mkit_server::{BlobBody, BlobKey, BlobStore, ByteRange, StoreError};
use mkit_server_worker::r2::{PACKS_KEYSPACE, R2BlobStore};

async fn bytes_of(body: BlobBody) -> Vec<u8> {
    match body {
        BlobBody::Bytes(b) => b.to_vec(),
        BlobBody::Stream { mut stream, .. } => {
            let mut out = Vec::new();
            while let Some(piece) = stream.next().await {
                out.extend_from_slice(&piece.unwrap());
            }
            out
        }
    }
}

fn range(start: u64, end_inclusive: u64) -> ByteRange {
    ByteRange {
        start,
        end_inclusive,
    }
}

#[test]
fn bounded_range_is_one_backend_call() {
    block_on(async {
        let bucket = common::SimBucket::default();
        let blobs = R2BlobStore::new(bucket.clone(), PACKS_KEYSPACE);
        let key = BlobKey::pack([7; 32]);
        bucket.replace_object(
            &blobs.object_key(&key).unwrap(),
            Bytes::from_static(b"0123456789"),
        );
        let calls = || bucket.operations.load(Ordering::SeqCst);

        let before = calls();
        let body = blobs.get(&key, Some(range(2, 4))).await.unwrap().unwrap();
        assert_eq!(calls() - before, 1, "no HEAD before a bounded GET");
        assert_eq!(bytes_of(body).await, b"234");

        // An exact-end range and an end past the object both read the tail.
        let body = blobs.get(&key, Some(range(7, 9))).await.unwrap().unwrap();
        assert_eq!(bytes_of(body).await, b"789");
        let body = blobs
            .get(&key, Some(range(7, u64::MAX)))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(bytes_of(body).await, b"789");
        let body = blobs.get(&key, Some(range(9, 9))).await.unwrap().unwrap();
        assert_eq!(bytes_of(body).await, b"9");

        // A start at or past the end is unsatisfiable, not a backend failure.
        for start in [10, 11] {
            let err = blobs
                .get(&key, Some(range(start, start + 3)))
                .await
                .unwrap_err();
            assert!(matches!(err, StoreError::RangeNotSatisfiable { len: 10 }));
        }
        // Starts at or beyond R2's range precision are unsatisfiable, never sent.
        for start in [(1 << 53) - 1, 1 << 53, u64::MAX - 1, u64::MAX] {
            let err = blobs
                .get(&key, Some(range(start, u64::MAX)))
                .await
                .unwrap_err();
            assert!(matches!(err, StoreError::RangeNotSatisfiable { len: 10 }));
        }
        // A malformed range on a present object is invalid.
        let err = blobs.get(&key, Some(range(5, 4))).await.unwrap_err();
        assert!(matches!(err, StoreError::Invalid(_)));
    });
}

#[test]
fn missing_object_is_absent_for_every_range_shape() {
    block_on(async {
        let bucket = common::SimBucket::default();
        let blobs = R2BlobStore::new(bucket.clone(), PACKS_KEYSPACE);
        let key = BlobKey::pack([8; 32]);
        for r in [
            None,
            Some(range(0, 3)),
            Some(range(5, 4)),
            Some(range(100, 200)),
            Some(range(0, u64::MAX)),
        ] {
            assert!(blobs.get(&key, r).await.unwrap().is_none(), "{r:?}");
        }
    });
}
