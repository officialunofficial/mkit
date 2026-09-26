//! Behaviors of the Workers stores beyond the conformance suite, over the
//! simulated backends in `common`.

mod common;

use bytes::Bytes;
use common::{DoConfig, Loopback, SimBucket, SimDoConn, capacity_above_empty};
use futures::executor::block_on;
use mkit_core::hash::hash;
use mkit_server::sql::{Row, SqlConn, SqlError, SqlKvStore, SqlValue, TxFn};
use mkit_server::{
    Batch, BatchOutcome, BlobKey, BlobStore, CommitOutcome, Key, NamespaceKey, NamespaceStore,
    PackSink, Partition, StoreError, StoreMaintenance, Value,
};
use mkit_server_native::RusqliteConn;
use mkit_server_worker::naming::{REFSTORE, ROOT_INSTANCE};
use mkit_server_worker::r2::{PACKS_KEYSPACE, R2BlobStore};

fn key(i: u32) -> Key {
    Key::new([b"r\0cap\0".as_slice(), &i.to_be_bytes()].concat())
}

fn root() -> Partition {
    Partition::Namespace(NamespaceKey::deployment_default())
}

/// A connection whose size counts free pages too: what the soft cap would
/// see if `databaseSize` included the freelist.
#[derive(Debug, Clone)]
struct FilePages(SimDoConn);

impl SqlConn for FilePages {
    fn exec(&self, sql: &str, params: &[SqlValue]) -> Result<u64, SqlError> {
        self.0.exec(sql, params)
    }

    fn query(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Row>, SqlError> {
        self.0.query(sql, params)
    }

    fn transaction<T: 'static>(&self, f: TxFn<Self, T>) -> Result<T, SqlError> {
        self.0.transaction(Box::new(move |c| f(FilePages(c))))
    }

    fn now_ms(&self) -> u64 {
        self.0.now_ms()
    }

    fn size_bytes(&self) -> Result<u64, SqlError> {
        // Trusted host access to the engine, below the simulated Durable
        // Object's authorizer.
        let pages = |sql| match self.0.0.query(sql, &[]).expect("pragma")[0][0] {
            SqlValue::Integer(n) => u64::try_from(n).expect("page count"),
            _ => unreachable!(),
        };
        Ok(pages("PRAGMA page_count") * pages("PRAGMA page_size"))
    }
}

/// Fill `store` until `Full`, prune every key with delete-only batches,
/// then try one more put.
fn fill_prune_put<C: SqlConn>(store: &SqlKvStore<C>) -> Result<BatchOutcome, StoreError> {
    let p = root();
    let value = Value::new(vec![9; 1024]);
    let mut written = 0;
    loop {
        match block_on(store.apply(&p, Batch::new().put(key(written), value.clone()))) {
            Ok(BatchOutcome::Committed) => written += 1,
            Err(StoreError::Full) => break,
            other => panic!("filling: {other:?}"),
        }
        assert!(written < 10_000, "never full");
    }
    assert!(written > 100, "full after {written} rows");
    for start in (0..written).step_by(100) {
        let batch = (start..written.min(start + 100)).fold(Batch::new(), |b, i| b.delete(key(i)));
        assert_eq!(
            block_on(store.apply(&p, batch)).expect("prune"),
            BatchOutcome::Committed
        );
    }
    block_on(store.apply(&p, Batch::new().put(key(0), Value::new(vec![1]))))
}

fn do_conn(config: &DoConfig) -> SimDoConn {
    SimDoConn::open(
        RusqliteConn::open_in_memory().expect("a database"),
        config.hard_limit,
    )
}

/// Carry-forward from the M0-09 review: the soft cap measures
/// `databaseSize`, and it must drop after a prune or puts stay `Full`
/// forever. workerd's `databaseSize` counts pages in use only, so a pruned
/// Durable Object accepts puts again; a measure that counted free pages
/// would not.
#[test]
fn soft_cap_recovers_after_a_prune() {
    let config = capacity_above_empty(1024 * 1024);
    let store = SqlKvStore::open_with_capacity(do_conn(&config), config.capacity).unwrap();
    assert_eq!(fill_prune_put(&store).unwrap(), BatchOutcome::Committed);

    let stuck =
        SqlKvStore::open_with_capacity(FilePages(do_conn(&config)), config.capacity).unwrap();
    assert!(matches!(fill_prune_put(&stuck), Err(StoreError::Full)));
}

#[test]
fn durable_object_rejects_what_workerd_rejects_and_has_no_backup() {
    let config = DoConfig::default();
    let conn = do_conn(&config);
    let store = SqlKvStore::open(conn.clone()).unwrap();
    for sql in ["PRAGMA page_count", "VACUUM"] {
        assert!(
            matches!(conn.query(sql, &[]), Err(SqlError::Backend(_))),
            "{sql}"
        );
    }
    let too_many = vec![SqlValue::Null; 101];
    assert!(conn.query("SELECT 1", &too_many).is_err());
    assert!(matches!(
        block_on(store.backup_to("/tmp/x")),
        Err(StoreError::Unsupported(_))
    ));
}

#[test]
fn one_durable_object_call_per_method_and_one_object_per_partition() {
    let dir = tempfile::tempdir().unwrap();
    let store = Loopback::store(dir.path().to_path_buf(), DoConfig::default());
    let keys: Vec<Key> = (0..150).map(key).collect();
    let batch = keys[..50]
        .iter()
        .fold(Batch::new(), |b, k| b.put(k.clone(), Value::new(vec![1])));
    assert_eq!(
        block_on(store.apply(&root(), batch)).unwrap(),
        BatchOutcome::Committed
    );
    let got = block_on(store.get_many(&root(), &keys)).unwrap();
    assert_eq!(got.iter().filter(|v| v.is_some()).count(), 50);
    assert_eq!(
        store.transport().calls(),
        2,
        "apply and get_many are one call each"
    );
    // An oversize batch never reaches the object.
    let huge = Batch::new().put(key(0), Value::new(vec![0; 600 * 1024]));
    assert!(matches!(
        block_on(store.apply(&root(), huge)),
        Err(StoreError::Invalid(_))
    ));
    assert_eq!(store.transport().calls(), 2);
    // Another namespace lives in another object, and its rows stay there.
    let other = Partition::decode(b"nother\0").unwrap();
    assert_eq!(block_on(store.get(&other, &key(0))).unwrap(), None);
    block_on(store.probe()).unwrap();
    let mut names: Vec<String> = store
        .transport()
        .targets()
        .into_iter()
        .map(|t| format!("{}/{}", t.binding, t.name))
        .collect();
    names.sort();
    assert_eq!(
        names,
        [
            format!("{REFSTORE}/n:other"),
            format!("{REFSTORE}/{ROOT_INSTANCE}")
        ]
    );
    // The export page reads every row of the partition, labeled with it.
    let page = block_on(store.export_page(&root(), None, 1000)).unwrap();
    assert_eq!(page.records.len(), 50);
    assert!(page.records.iter().all(|r| r.partition == root()));
}

#[test]
fn a_failed_put_is_already_present_only_if_the_key_now_exists() {
    let bucket = SimBucket::default();
    let store = R2BlobStore::new(bucket.clone(), PACKS_KEYSPACE);
    let put = |bytes: &'static [u8]| {
        block_on(async {
            let mut sink = store
                .begin(BlobKey::new(hash(bytes)), bytes.len() as u64)
                .await?;
            sink.write(Bytes::from_static(bytes)).await?;
            sink.commit().await
        })
    };
    assert_eq!(put(b"hello").unwrap(), CommitOutcome::Created);
    // R2 refuses a second write of the key within a second: the key holds
    // verified bytes, so the upload succeeded.
    bucket.fail_next_puts(1);
    assert_eq!(put(b"hello").unwrap(), CommitOutcome::AlreadyPresent);
    // Absent key: a real failure, and nothing is visible.
    bucket.fail_next_puts(1);
    assert!(matches!(put(b"world"), Err(StoreError::Unavailable(_))));
    assert_eq!(bucket.objects(), 1);
    assert_eq!(put(b"world").unwrap(), CommitOutcome::Created);
    // Over the size cap: refused at begin.
    let small = R2BlobStore::new(bucket, PACKS_KEYSPACE).with_max_bytes(4);
    assert!(matches!(
        block_on(small.begin(BlobKey::new(hash(b"hello")), 5)),
        Err(StoreError::Invalid(_))
    ));
    assert_eq!(
        store.object_key(&BlobKey::new([0xab; 32])),
        format!("packs/{}", "ab".repeat(32))
    );
}

fn upload(
    store: &R2BlobStore<SimBucket>,
    key: BlobKey,
    data: &[u8],
) -> Result<CommitOutcome, StoreError> {
    block_on(async {
        let mut sink = store.begin(key, data.len() as u64).await?;
        // Many more chunks than the channel holds.
        for chunk in data.chunks(4096) {
            sink.write(Bytes::copy_from_slice(chunk)).await?;
        }
        sink.commit().await
    })
}

/// R2 may answer a put before reading its body (a failed condition, a
/// 429). The sink stops forwarding without hanging, still verifies every
/// byte, and reports the answer.
#[test]
fn early_put_answers_never_hang_and_still_verify() {
    let bucket = SimBucket::default().answer_early();
    let store = R2BlobStore::new(bucket.clone(), PACKS_KEYSPACE);
    let data: Vec<u8> = (0..64 * 4096_u32).map(|i| i.to_le_bytes()[1]).collect();
    let key = BlobKey::new(hash(&data));
    assert_eq!(upload(&store, key, &data).unwrap(), CommitOutcome::Created);
    // Early 412: the key exists.
    assert_eq!(
        upload(&store, key, &data).unwrap(),
        CommitOutcome::AlreadyPresent
    );
    // Early 412, but these bytes are not the key's: still `Invalid`.
    let mut wrong = data.clone();
    wrong[70_000] ^= 1;
    assert!(matches!(
        upload(&store, key, &wrong),
        Err(StoreError::Invalid(_))
    ));
    // Early 429 on a present key: our verified bytes are there.
    bucket.fail_next_puts(1);
    assert_eq!(
        upload(&store, key, &data).unwrap(),
        CommitOutcome::AlreadyPresent
    );
    // Early 429 on an absent key: a retryable failure, nothing visible.
    let other: Vec<u8> = data.iter().map(|b| b.wrapping_add(1)).collect();
    let other_key = BlobKey::new(hash(&other));
    bucket.fail_next_puts(1);
    assert!(matches!(
        upload(&store, other_key, &other),
        Err(StoreError::Unavailable(_))
    ));
    assert_eq!(block_on(store.head(&other_key)).unwrap(), None);
    assert_eq!(
        upload(&store, other_key, &other).unwrap(),
        CommitOutcome::Created
    );
}
