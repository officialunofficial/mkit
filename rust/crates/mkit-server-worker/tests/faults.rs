//! The `test-faults` store faults: each fails once, leaves nothing behind,
//! and the retry succeeds.
#![cfg(feature = "test-faults")]

mod common;

use bytes::Bytes;
use common::{DoConfig, SimBucket, SimDoConn};
use futures::executor::block_on;
use mkit_core::hash::hash;
use mkit_server::sql::SqlKvStore;
use mkit_server::{
    Batch, BatchOutcome, BlobKey, BlobStore, CommitOutcome, Key, NamespaceKey, NamespaceStore,
    PackSink, Partition, StoreError, Value,
};
use mkit_server_native::RusqliteConn;
use mkit_server_worker::faults::{FAIL_ONCE_MARKER, FaultConn};
use mkit_server_worker::r2::{PACKS_KEYSPACE, R2BlobStore};

#[test]
fn r2_final_chunk_fault_fails_once_and_publishes_nothing() {
    let bucket = SimBucket::default();
    let store = R2BlobStore::new(bucket.clone(), PACKS_KEYSPACE);
    let put = || {
        block_on(async {
            let mut sink = store.begin(BlobKey::new(hash(b"pack")), 4).await?;
            sink.write(Bytes::from_static(b"pa")).await?;
            sink.write(Bytes::from_static(b"ck")).await?;
            sink.commit().await
        })
    };
    store.fail_final_chunk_once();
    assert!(matches!(put(), Err(StoreError::Unavailable(_))));
    assert_eq!(bucket.objects(), 0);
    assert_eq!(
        block_on(store.head(&BlobKey::new(hash(b"pack")))).unwrap(),
        None
    );
    assert_eq!(put().unwrap(), CommitOutcome::Created);
}

#[test]
fn durable_object_fail_once_rolls_the_whole_batch_back() {
    let conn = SimDoConn::open(
        RusqliteConn::open_in_memory().unwrap(),
        DoConfig::default().hard_limit,
    );
    let store = SqlKvStore::open(FaultConn::new(conn)).unwrap();
    let p = Partition::Namespace(NamespaceKey::deployment_default());
    let plain = Key::new(b"r\0repo\0refs/mkit/packmap/a".to_vec());
    let marked = Key::new([b"r\0repo\0refs/heads/".as_slice(), FAIL_ONCE_MARKER, b"a"].concat());
    let batch = || {
        Batch::new()
            .put(plain.clone(), Value::new(b"packmap".to_vec()))
            .put(marked.clone(), Value::new(b"head".to_vec()))
    };
    // The batch's writes ran inside the transaction, then it failed.
    assert!(matches!(
        block_on(store.apply(&p, batch())),
        Err(StoreError::Unavailable(_))
    ));
    for k in [&plain, &marked] {
        assert_eq!(block_on(store.get(&p, k)).unwrap(), None, "rolled back");
    }
    // Once per key: the retry and later batches commit.
    assert_eq!(
        block_on(store.apply(&p, batch())).unwrap(),
        BatchOutcome::Committed
    );
    assert_eq!(
        block_on(store.apply(&p, batch())).unwrap(),
        BatchOutcome::Committed
    );
    assert_eq!(
        block_on(store.get(&p, &marked)).unwrap(),
        Some(Value::new(b"head".to_vec()))
    );
}
