//! Behaviors of the Workers stores beyond the conformance suite, over the
//! simulated backends in `common`.

mod common;

use bytes::Bytes;
use common::{DoConfig, Loopback, SimBucket, SimDoConn, capacity_above_empty};
use futures::executor::block_on;
use mkit_core::hash::hash;
use mkit_core::upload_parts::{MIN_PART_SIZE, PartPlan, part_subtree_cv};
use mkit_server::sql::{Row, SqlConn, SqlError, SqlKvStore, SqlValue, TxFn};
use mkit_server::{
    Batch, BatchOutcome, BlobKey, BlobStore, CommitOutcome, Key, MultipartBlobStore, NamespaceKey,
    NamespaceStore, PackSink, PartRef, PartSink, Partition, StoreError, StoreMaintenance, Value,
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

#[test]
fn upload_marker_r2_key_is_not_a_pack_key() {
    let bucket = SimBucket::default();
    let store = R2BlobStore::new(bucket, PACKS_KEYSPACE);
    let content = b"marker bytes";
    let marker = BlobKey::upload_marker(hash(content));
    block_on(async {
        let mut sink = store.begin(marker, content.len() as u64).await.unwrap();
        sink.write(Bytes::from_static(content)).await.unwrap();
        sink.commit().await.unwrap();
        assert_eq!(
            store.object_key(&marker).unwrap(),
            format!("upload-markers/v1/{}", marker.to_hex())
        );
        assert!(store.head(&marker).await.unwrap().is_some());
        assert!(
            store
                .head(&BlobKey::pack(hash(content)))
                .await
                .unwrap()
                .is_none()
        );
    });
    let prefixed = R2BlobStore::new(SimBucket::default(), "tenant/a/packs");
    assert_eq!(
        prefixed.object_key(&marker).unwrap(),
        format!("tenant/a/upload-markers/v1/{}", marker.to_hex())
    );
}

#[test]
fn r2_corrupted_part_cannot_publish_pack() {
    let bucket = SimBucket::default();
    let store = R2BlobStore::new(bucket.clone(), PACKS_KEYSPACE);
    let data: Vec<u8> = (0_u8..=250)
        .cycle()
        .take(usize::try_from(MIN_PART_SIZE).unwrap() + 1)
        .collect();
    let key = BlobKey::pack(hash(&data));
    let plan = PartPlan::new(data.len() as u64, MIN_PART_SIZE, 10_000).unwrap();
    block_on(async {
        let ticket = hash(b"r2 corrupt test ticket");
        let session = store
            .begin_multipart_for_ticket(key, plan.total(), plan.part_size(), ticket)
            .await
            .unwrap();
        let mut parts = Vec::new();
        for index in 0..plan.count() {
            let start = usize::try_from(plan.offset(index).unwrap()).unwrap();
            let end = start + usize::try_from(plan.expected_len(index).unwrap()).unwrap();
            let cv = part_subtree_cv(&plan, index, &data[start..end]).unwrap();
            let mut sink = store
                .begin_part(key, &session, &plan, index, cv)
                .await
                .unwrap();
            for chunk in data[start..end].chunks(64 * 1024) {
                sink.write(Bytes::copy_from_slice(chunk)).await.unwrap();
            }
            parts.push(PartRef {
                index,
                len: (end - start) as u64,
                tag: sink.commit().await.unwrap(),
            });
        }
        let part_key = format!(
            "server-uploads/{}/0-{}",
            mkit_core::hash::to_hex_bytes(&session),
            mkit_core::hash::to_hex_bytes(&parts[0].tag)
        );
        bucket.replace_object(
            &part_key,
            Bytes::from(vec![0x99; usize::try_from(MIN_PART_SIZE).unwrap()]),
        );
        assert!(matches!(
            store.complete(key, &session, &plan, &parts).await,
            Err(StoreError::Invalid(_))
        ));
        assert!(store.head(&key).await.unwrap().is_none());
    });
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
                .begin(BlobKey::pack(hash(bytes)), bytes.len() as u64)
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
        block_on(small.begin(BlobKey::pack(hash(b"hello")), 5)),
        Err(StoreError::Invalid(_))
    ));
    assert_eq!(
        store.object_key(&BlobKey::pack([0xab; 32])).unwrap(),
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
    let key = BlobKey::pack(hash(&data));
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
    let other_key = BlobKey::pack(hash(&other));
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

#[test]
fn every_partition_kind_routes_and_is_isolated() {
    use mkit_server_worker::classes::ShardClass;
    use mkit_server_worker::naming::do_target;
    let dir = tempfile::tempdir().unwrap();
    let store = Loopback::store(dir.path().to_path_buf(), DoConfig::default());
    let cases: Vec<(&[u8], ShardClass)> = vec![
        (b"nroot\0", ShardClass::RefStore),
        (b"nother\0", ShardClass::RefStore),
        (b"croot\0", ShardClass::NsCoordinator),
        (b"cother\0", ShardClass::NsCoordinator),
        (b"rroot\0a\0refs/heads/main\0", ShardClass::RefShard),
        (b"rother\0a\0refs/heads/main\0", ShardClass::RefShard),
        (b"iroot\0a\x000\0", ShardClass::RepoIndexShard),
        (b"iother\0a\x000\0", ShardClass::RepoIndexShard),
        (b"xroot\0a\x000\0", ShardClass::RepoIndexShard),
        (b"xother\0a\x000\0", ShardClass::RepoIndexShard),
        (b"s0\0", ShardClass::ContentIndexShard),
        (b"s1\0", ShardClass::ContentIndexShard),
    ];
    let k = Key::new(b"test\0".to_vec());
    for (i, (encoded, class)) in cases.iter().enumerate() {
        let partition = Partition::decode(encoded).unwrap();
        assert!(class.accepts(&partition));
        assert_eq!(do_target(&partition).unwrap().binding, class.binding());
        assert_eq!(block_on(store.get(&partition, &k)).unwrap(), None);
        block_on(store.apply(
            &partition,
            Batch::new().put(k.clone(), Value::new(i.to_be_bytes().to_vec())),
        ))
        .unwrap();
    }
    for (i, (encoded, _)) in cases.iter().enumerate() {
        let partition = Partition::decode(encoded).unwrap();
        assert_eq!(
            block_on(store.get(&partition, &k))
                .unwrap()
                .unwrap()
                .as_bytes(),
            &i.to_be_bytes()
        );
    }
    assert_eq!(store.transport().targets().len(), cases.len());
}

#[test]
fn foreign_partition_kinds_are_rejected_before_store_access() {
    use mkit_server_worker::classes::ShardClass;
    use mkit_server_worker::naming::DoTarget;
    use mkit_server_worker::ns_client::NsTransport;
    use mkit_server_worker::wire::{NsCall, NsErrKind, NsReply, NsRequest, WireBatch};
    let dir = tempfile::tempdir().unwrap();
    let transport = Loopback::new(dir.path().to_path_buf(), DoConfig::default());
    let classes = [
        ShardClass::RefStore,
        ShardClass::NsCoordinator,
        ShardClass::RefShard,
        ShardClass::RepoIndexShard,
        ShardClass::ContentIndexShard,
    ];
    let partitions: Vec<Partition> = [
        b"nroot\0".as_slice(),
        b"croot\0",
        b"rroot\0a\0refs/heads/main\0",
        b"iroot\0a\x000\0",
        b"xroot\0a\x000\0",
        b"s0\0",
    ]
    .into_iter()
    .map(|bytes| Partition::decode(bytes).unwrap())
    .collect();
    for class in classes {
        let target = DoTarget {
            binding: class.binding(),
            name: "guard-test".into(),
        };
        for partition in &partitions {
            let batch = Batch::new().put(key(0), Value::new(b"foreign".to_vec()));
            let body = serde_json::to_string(
                &NsRequest::new(
                    partition,
                    NsCall::Apply {
                        batch: WireBatch::from(batch),
                    },
                )
                .unwrap(),
            )
            .unwrap();
            let reply: NsReply =
                serde_json::from_str(&block_on(transport.call(&target, "apply", body)).unwrap())
                    .unwrap();
            if class.accepts(partition) {
                assert!(matches!(reply, NsReply::Outcome { .. }));
            } else {
                assert_eq!(
                    reply,
                    NsReply::Err {
                        kind: NsErrKind::Invalid,
                        message: "partition kind not served by this class".into()
                    }
                );
                assert_eq!(
                    block_on(transport.raw_value(&target, partition, &key(0))),
                    None
                );
            }
        }
    }
}

#[test]
fn probe_targets_follow_the_deployment_sharding() {
    use mkit_server_worker::adapter::WorkerConfig;
    use mkit_server_worker::naming::do_target;
    use mkit_server_worker::ns_client::DoNamespaceStore;
    for mode in ["single", "d34"] {
        let cfg = WorkerConfig::from_vars(|name| match name {
            "AUTH_AUDIENCE" => Some("https://vcs.example".into()),
            "AUTH_REPOSITORY" => Some("default".into()),
            "SHARDING" => Some(mode.into()),
            _ => None,
        })
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let store = DoNamespaceStore::new(
            Loopback::new(dir.path().to_path_buf(), DoConfig::default()),
            cfg.probe_partition(),
        );
        block_on(store.probe()).unwrap();
        assert_eq!(
            store.transport().targets(),
            vec![do_target(&cfg.probe_partition()).unwrap()]
        );
        assert_eq!(
            cfg.probe_partition(),
            if mode == "single" {
                root()
            } else {
                Partition::Coordinator(NamespaceKey::deployment_default())
            }
        );
    }
}

#[derive(Default)]
struct PressureGauges(std::sync::Mutex<Vec<(String, String, f64)>>);

impl mkit_server::Metrics for PressureGauges {
    fn incr(&self, _: &'static str, _: &[(&'static str, &str)], _: u64) {}
    fn observe_ms(&self, _: &'static str, _: &[(&'static str, &str)], _: f64) {}
    fn gauge(&self, name: &'static str, labels: &[(&'static str, &str)], value: f64) {
        assert_eq!(labels[0].0, "kind");
        self.0.lock().expect("pressure gauge capture lock").push((
            name.into(),
            labels[0].1.into(),
            value,
        ));
    }
}

#[test]
fn committed_put_pressure_reads_physical_size_through_do_shim() {
    use mkit_server::ManualClock;
    use mkit_server_worker::classes::ShardClass;
    use mkit_server_worker::ns_object::{PressureStore, serve};
    use mkit_server_worker::wire::{Blob, NsCall, NsReply, NsRequest, WireBatch, WireOutcome};
    use std::sync::Arc;

    let config = capacity_above_empty(64 * 1024);
    let conn = SimDoConn(RusqliteConn::open_in_memory().unwrap());
    let inner = SqlKvStore::open_with_capacity(conn, config.capacity).unwrap();
    let clock = Arc::new(ManualClock::new(0));
    let metrics = Arc::new(PressureGauges::default());
    let store = PressureStore::new(inner, ShardClass::RefStore, clock.clone(), metrics.clone());
    let request = |call| {
        serde_json::to_string(&NsRequest {
            part: Blob(root().encode().unwrap().to_vec()),
            call,
        })
        .unwrap()
    };
    let batch = Batch::new().put(key(0), Value::new(vec![1; 55 * 1024]));
    let body = request(NsCall::Apply {
        batch: WireBatch::from(batch),
    });
    let reply: NsReply =
        serde_json::from_str(&block_on(serve(&store, &body, ShardClass::RefStore))).unwrap();
    assert_eq!(
        reply,
        NsReply::Outcome {
            outcome: WireOutcome::Committed
        }
    );
    let physical = store.conn().size_bytes().unwrap();
    let logical = block_on(store.stats(&root())).unwrap().bytes;
    assert_ne!(
        physical, logical,
        "gauge must measure the physical cap input"
    );
    assert!(u128::from(physical) * 100 >= u128::from(config.capacity.soft_limit()) * 70);
    #[allow(clippy::cast_precision_loss)]
    let expected = physical as f64;
    assert_eq!(
        *metrics.0.lock().unwrap(),
        vec![(
            "mkit_server_partition_bytes".into(),
            "namespace".into(),
            expected
        )]
    );
    // A conflict with a put, a read, an empty batch and a committed delete
    // must not publish a write-path sample.
    clock.set(1);
    for call in [
        NsCall::Apply {
            batch: Batch::new()
                .require(mkit_server::Precondition::Absent(key(0)))
                .put(key(1), Value::default())
                .into(),
        },
        NsCall::Stats,
        NsCall::Apply {
            batch: Batch::new().into(),
        },
        NsCall::Apply {
            batch: Batch::new().delete(key(0)).into(),
        },
    ] {
        block_on(serve(&store, &request(call), ShardClass::RefStore));
    }
    assert_eq!(metrics.0.lock().unwrap().len(), 1);
}

#[test]
fn backup_seeds_only_after_first_committed_put_and_raises_alarm_hint() {
    use mkit_server::ManualClock;
    use mkit_server::store::codec::decode_backup_state;
    use mkit_server::store::keys;
    use mkit_server::timers::registry::kinds;
    use mkit_server_worker::classes::ShardClass;
    use mkit_server_worker::ns_object::PressureStore;
    use std::sync::Arc;

    let conn = SimDoConn(RusqliteConn::open_in_memory().unwrap());
    let inner = SqlKvStore::open(conn).unwrap();
    let clock = Arc::new(ManualClock::new(1_000));
    let store = PressureStore::new(
        inner,
        ShardClass::RefStore,
        clock.clone(),
        Arc::new(PressureGauges::default()),
    )
    .with_backup_interval(100);
    assert!(
        block_on(store.get(&root(), &keys::backup_state()))
            .unwrap()
            .is_none()
    );
    assert!(block_on(store.stats(&root())).is_ok());
    assert!(
        block_on(store.get(&root(), &keys::timer(1_100, kinds::BACKUP.get(), b"")))
            .unwrap()
            .is_none()
    );
    let first = Batch::new().put(key(0), Value::new(vec![1]));
    assert_eq!(
        block_on(store.apply(&root(), first)).unwrap(),
        BatchOutcome::Committed
    );
    let state = block_on(store.get(&root(), &keys::backup_state()))
        .unwrap()
        .unwrap();
    assert_eq!(decode_backup_state(&state).unwrap().last_export_ms, 0);
    assert!(
        block_on(store.get(&root(), &keys::timer(1_100, kinds::BACKUP.get(), b"")))
            .unwrap()
            .is_some()
    );
    assert_eq!(store.take_seeded_due(), Some(1_100));
    assert_eq!(store.take_seeded_due(), None);
    clock.set(1_050);
    assert_eq!(
        block_on(store.apply(&root(), Batch::new().put(key(1), Value::new(vec![2])))).unwrap(),
        BatchOutcome::Committed
    );
    assert_eq!(store.take_seeded_due(), None);
    assert!(
        block_on(store.get(&root(), &keys::timer(1_150, kinds::BACKUP.get(), b"")))
            .unwrap()
            .is_none()
    );
}

#[test]
fn timer_reschedule_put_observes_pressure_through_do_shim() {
    use mkit_server::store::keys;
    use mkit_server::timers::{
        DueTimer, Fired, TickBudget, TimerCtx, TimerHandler, TimerKind, TimerRegistry, run_due,
    };
    use mkit_server::{BoxFuture, ManualClock};
    use mkit_server_worker::classes::ShardClass;
    use mkit_server_worker::ns_object::PressureStore;
    use std::sync::Arc;

    struct Reschedule;
    impl<S: NamespaceStore> TimerHandler<S> for Reschedule {
        fn kind(&self) -> TimerKind {
            TimerKind::new(0xF0)
        }
        fn fire<'a>(
            &'a self,
            _: &'a TimerCtx<'a, S>,
            _: &'a DueTimer,
        ) -> BoxFuture<'a, Result<Fired, StoreError>> {
            Box::pin(async {
                Ok(Fired::Reschedule {
                    due_at_ms: 100,
                    value: Value::new(vec![1; 55 * 1024]),
                    batch: Batch::new(),
                })
            })
        }
    }
    let config = capacity_above_empty(64 * 1024);
    let conn = SimDoConn(RusqliteConn::open_in_memory().unwrap());
    let inner = SqlKvStore::open_with_capacity(conn, config.capacity).unwrap();
    let old_key = keys::timer(0, 0xF0, b"pressure");
    assert_eq!(
        block_on(inner.apply(&root(), Batch::new().put(old_key.clone(), Value::default())))
            .unwrap(),
        BatchOutcome::Committed
    );
    let clock = Arc::new(ManualClock::new(0));
    let metrics = Arc::new(PressureGauges::default());
    let store = PressureStore::new(inner, ShardClass::RefStore, clock.clone(), metrics.clone());
    let registry = TimerRegistry::new().register(Reschedule);
    let report = block_on(run_due(
        &store,
        &root(),
        &registry,
        clock.as_ref(),
        0,
        &TickBudget::default(),
    ))
    .unwrap();
    assert_eq!(report.fired, 1);
    assert_eq!(report.next_wake_ms, Some(100));
    assert!(block_on(store.get(&root(), &old_key)).unwrap().is_none());
    assert!(
        block_on(store.get(&root(), &keys::timer(100, 0xF0, b"pressure")))
            .unwrap()
            .is_some()
    );
    let physical = store.conn().size_bytes().unwrap();
    assert!(u128::from(physical) * 100 >= u128::from(config.capacity.soft_limit()) * 70);
    #[allow(clippy::cast_precision_loss)]
    let expected = physical as f64;
    assert_eq!(
        *metrics.0.lock().unwrap(),
        vec![(
            "mkit_server_partition_bytes".into(),
            "namespace".into(),
            expected
        )]
    );
}
