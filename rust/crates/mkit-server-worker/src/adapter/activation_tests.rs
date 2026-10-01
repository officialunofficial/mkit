//! Integrated Worker registration and target-local SQL audit contracts.
use super::*;
use futures::executor::block_on;
use mkit_server::admin::SystemAudit;
use mkit_server::purge::{Request, Trigger};
use mkit_server::relay::{RelayEnqueueSnapshot, RelayHook, enqueue_relay_rows};
use mkit_server::sql::SqlKvStore;
use mkit_server::store::{codec, keys};
use mkit_server::timers::{TickBudget, run_due};
use mkit_server::{
    Batch, BatchOutcome, Key, ManualClock, MemoryKv, NamespaceKey, NamespaceStore, NoopMetrics,
    Partition, Value,
};
use mkit_server_native::RusqliteConn;
use std::sync::atomic::{AtomicU32, Ordering};

struct ReplyFaults {
    inner: Arc<crate::ns_object::PressureStore<RusqliteConn>>,
    stage: AtomicU32,
    calls: AtomicU32,
}
impl NamespaceStore for ReplyFaults {
    fn capabilities(&self) -> mkit_server::StoreCapabilities {
        self.inner.capabilities()
    }
    async fn get(
        &self,
        p: &Partition,
        key: &Key,
    ) -> Result<Option<Value>, mkit_server::StoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.get(p, key).await
    }
    async fn get_many(
        &self,
        p: &Partition,
        keys: &[Key],
    ) -> Result<Vec<Option<Value>>, mkit_server::StoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.get_many(p, keys).await
    }
    async fn scan(
        &self,
        p: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&mkit_server::Cursor>,
        limit: u32,
    ) -> Result<mkit_server::ScanPage, mkit_server::StoreError> {
        self.inner.scan(p, start, end, after, limit).await
    }
    async fn apply(
        &self,
        p: &Partition,
        batch: Batch,
    ) -> Result<BatchOutcome, mkit_server::StoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match self.stage.fetch_add(1, Ordering::SeqCst) {
            0 => Ok(BatchOutcome::PreconditionFailed {
                index: 0,
                observed: None,
            }),
            1 => {
                assert_eq!(self.inner.apply(p, batch).await?, BatchOutcome::Committed);
                Err(mkit_server::StoreError::unavailable("lost committed reply"))
            }
            _ => self.inner.apply(p, batch).await,
        }
    }
    async fn stats(
        &self,
        p: &Partition,
    ) -> Result<mkit_server::PartitionStats, mkit_server::StoreError> {
        self.inner.stats(p).await
    }
    async fn probe(&self) -> Result<(), mkit_server::StoreError> {
        self.inner.probe().await
    }
}

fn request(index: usize) -> Request {
    Request {
        purge_id: format!("purge:{index}"),
        audience: "https://server.example".into(),
        repository: "root/repo".into(),
        namespace: String::new(),
        trigger: Trigger::Takedown,
        url_paths: vec![],
        object_ids: vec![],
        refs: vec![],
    }
}

fn root(single: bool) -> Partition {
    let ns = NamespaceKey::deployment_default();
    if single {
        Partition::Namespace(ns)
    } else {
        Partition::Coordinator(ns)
    }
}

fn target(
    single: bool,
    clock: &Arc<ManualClock>,
) -> Arc<crate::ns_object::PressureStore<RusqliteConn>> {
    Arc::new(crate::ns_object::PressureStore::new(
        SqlKvStore::open(
            RusqliteConn::open_in_memory()
                .unwrap()
                .with_clock(clock.clone()),
        )
        .unwrap(),
        if single {
            crate::classes::ShardClass::RefStore
        } else {
            crate::classes::ShardClass::NsCoordinator
        },
        clock.clone(),
        Arc::new(NoopMetrics),
    ))
}

async fn enqueue<S: NamespaceStore>(
    source: &S,
    partition: &Partition,
    rows: &[codec::RelayV1],
    now: u64,
) {
    let snapshot = RelayEnqueueSnapshot {
        sequence: source
            .get(partition, &keys::outbox_sequence())
            .await
            .unwrap(),
        source_lease: None,
        deadline_ms: now + 30_000,
    };
    for batch in enqueue_relay_rows(&snapshot, partition, rows, now).unwrap() {
        assert_eq!(
            source.apply(partition, batch).await.unwrap(),
            BatchOutcome::Committed
        );
    }
}

async fn verify_chain<S: NamespaceStore>(target: &S, root: &Partition, count: u64) {
    let mut previous = "00".repeat(32);
    for seq in 1..=count {
        let raw = target
            .get(
                root,
                &Key::new([b"ae\0".as_slice(), &seq.to_be_bytes()].concat()),
            )
            .await
            .unwrap()
            .unwrap();
        let mut entry: serde_json::Value = serde_json::from_slice(raw.as_bytes()).unwrap();
        assert_eq!(entry["seq"], seq.to_string());
        assert_eq!(entry["prevHash"], previous);
        previous = entry
            .as_object_mut()
            .unwrap()
            .remove("entryHash")
            .unwrap()
            .as_str()
            .unwrap()
            .to_owned();
        let canonical = [
            b"mkit-admin-audit:v1".as_slice(),
            &serde_json::to_vec(&entry).unwrap(),
        ]
        .concat();
        assert_eq!(
            previous,
            mkit_core::hash::to_hex(&mkit_core::hash::hash(&canonical))
        );
    }
    let raw = target
        .get(root, &Key::new(b"ah\0".to_vec()))
        .await
        .unwrap()
        .unwrap();
    let head: serde_json::Value = serde_json::from_slice(raw.as_bytes()).unwrap();
    assert_eq!(head["seq"], count);
    assert_eq!(head["hash"], previous);
}

#[test]
fn content_audit_registration_uses_actual_single_and_d34_roots_and_atomic_dedup() {
    block_on(async {
        for single in [true, false] {
            let clock = Arc::new(ManualClock::new(10));
            let source = MemoryKv::with_clock(clock.clone());
            let target = target(single, &clock);
            let root = root(single);
            let partition = mkit_server::store::content_shard(&[9; 32]);
            let audit = SystemAudit::new(target.clone(), root.clone());
            let rows = (0..40)
                .map(|i| {
                    audit
                        .relay_row(&partition, &request(i), &format!("activation:{i}"), 10)
                        .unwrap()
                })
                .collect::<Vec<_>>();
            let allowance =
                mkit_server::purge::SliceBudget::new(crate::purge::LAUNCH_ALARM_OPERATIONS);
            enqueue(&source, &partition, &rows, 10).await;
            for now in 10..30 {
                clock.set(now);
                // A reconstructed registry models restart without changing durable identities.
                let registry = timer_registry_budgeted::<MemoryKv, _>(
                    crate::classes::ShardClass::ContentIndexShard,
                    Ok(target.clone()),
                    Some("paid"),
                    Some(&allowance),
                    None,
                    Some(&root),
                    None,
                );
                let before = allowance.used();
                run_due(
                    &source,
                    &partition,
                    &registry,
                    clock.as_ref(),
                    u64::try_from(now).unwrap(),
                    &TickBudget::default(),
                )
                .await
                .unwrap();
                assert!(
                    allowance.used() - before <= 2,
                    "target watermark/read/apply cap"
                );
                if source
                    .get(&partition, &keys::relay(40))
                    .await
                    .unwrap()
                    .is_none()
                {
                    break;
                }
            }
            verify_chain(target.as_ref(), &root, 40).await;
            assert_eq!(
                target
                    .get(&root, &keys::relay_high_water(&partition).unwrap())
                    .await
                    .unwrap(),
                Some(codec::encode_u64(40))
            );
            // Re-enqueue identical audit identities at later relay sequences.
            enqueue(&source, &partition, &rows, 30).await;
            for now in 30..50 {
                clock.set(now);
                let registry = timer_registry_budgeted::<MemoryKv, _>(
                    crate::classes::ShardClass::ContentIndexShard,
                    Ok(target.clone()),
                    Some("paid"),
                    Some(&allowance),
                    None,
                    Some(&root),
                    None,
                );
                run_due(
                    &source,
                    &partition,
                    &registry,
                    clock.as_ref(),
                    u64::try_from(now).unwrap(),
                    &TickBudget::default(),
                )
                .await
                .unwrap();
            }
            verify_chain(target.as_ref(), &root, 40).await;
            assert_eq!(
                target
                    .get(&root, &keys::relay_high_water(&partition).unwrap())
                    .await
                    .unwrap(),
                Some(codec::encode_u64(80))
            );
            assert!(allowance.used() < crate::purge::LAUNCH_ALARM_OPERATIONS);
        }
    });
}

#[test]
fn content_audit_refuses_remote_effects_at_shared_physical_limit_and_progresses_next_alarm() {
    block_on(async {
        let clock = Arc::new(ManualClock::new(10));
        let source = MemoryKv::with_clock(clock.clone());
        let target = target(true, &clock);
        let root = root(true);
        let partition = mkit_server::store::content_shard(&[8; 32]);
        let row = SystemAudit::new(target.clone(), root.clone())
            .relay_row(&partition, &request(1), "activation:1", 10)
            .unwrap();
        enqueue(&source, &partition, &[row], 10).await;
        let allowance = mkit_server::purge::SliceBudget::new(crate::purge::LAUNCH_ALARM_OPERATIONS);
        assert!(allowance.charge(crate::purge::LAUNCH_ALARM_OPERATIONS - 1));
        let registry = timer_registry_budgeted::<MemoryKv, _>(
            crate::classes::ShardClass::ContentIndexShard,
            Ok(target.clone()),
            Some("paid"),
            Some(&allowance),
            None,
            Some(&root),
            None,
        );
        run_due(
            &source,
            &partition,
            &registry,
            clock.as_ref(),
            10,
            &TickBudget::default(),
        )
        .await
        .unwrap();
        assert_eq!(allowance.used(), crate::purge::LAUNCH_ALARM_OPERATIONS);
        assert!(
            target
                .get(&root, &Key::new(b"ah\0".to_vec()))
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            source
                .get(&partition, &keys::relay(1))
                .await
                .unwrap()
                .is_some()
        );
        allowance.reset();
        clock.set(5010);
        run_due(
            &source,
            &partition,
            &registry,
            clock.as_ref(),
            5010,
            &TickBudget::default(),
        )
        .await
        .unwrap();
        verify_chain(target.as_ref(), &root, 1).await;
        assert_eq!(allowance.used(), 2);
    });
}

fn batch_bytes(measured: &Batch) -> usize {
    measured
        .preconditions
        .iter()
        .map(|pre| match pre {
            mkit_server::Precondition::Absent(key) => key.as_bytes().len(),
            _ => unreachable!(),
        })
        .sum::<usize>()
        + measured
            .writes
            .iter()
            .map(|write| match write {
                mkit_server::Write::Put(key, value) => {
                    key.as_bytes().len() + value.as_bytes().len()
                }
                mkit_server::Write::Delete(_) => unreachable!(),
            })
            .sum::<usize>()
}

#[test]
fn audit_groups_near_one_mib_make_bounded_progress() {
    block_on(async {
        let clock = Arc::new(ManualClock::new(10));
        let source = MemoryKv::with_clock(clock.clone());
        let target = target(false, &clock);
        let root = root(false);
        let partition = mkit_server::store::content_shard(&[7; 32]);
        let audit = SystemAudit::new(target.clone(), root.clone());
        let mut rows = (0..5)
            .map(|i| {
                audit
                    .relay_row(&partition, &request(i), &format!("activation:{i}"), 10)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let rh = keys::relay_high_water(&partition).unwrap();
        let base = Batch::new()
            .require(mkit_server::Precondition::Absent(rh.clone()))
            .put(rh, codec::encode_u64(5));
        let mut measured = base.clone();
        for row in &rows {
            for (key, value) in &row.puts {
                measured = measured.put(key.clone(), value.clone());
            }
        }
        let bytes = batch_bytes(&measured);
        // Five individually valid relay rows fit the target apply within five bytes of 1 MiB.
        let padding = (mkit_server::MAX_BATCH_BYTES - bytes - 5 * 2) / 5;
        for (i, row) in rows.iter_mut().enumerate() {
            row.puts.push((
                Key::new(vec![b'x', u8::try_from(i).unwrap()]),
                Value::new(vec![1; padding]),
            ));
        }
        let mut input = base;
        for row in &rows {
            for (key, value) in &row.puts {
                input = input.put(key.clone(), value.clone());
            }
        }
        input
            .validate(&mkit_server::StoreCapabilities::full())
            .unwrap();
        let refusal = target.apply(&root, input).await.unwrap_err();
        assert!(
            refusal
                .to_string()
                .contains("extended batch exceeds limits"),
            "{refusal}"
        );
        assert!(
            target
                .get(&root, &Key::new(b"ah\0".to_vec()))
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            target
                .get(&root, &keys::relay_high_water(&partition).unwrap())
                .await
                .unwrap()
                .is_none()
        );
        enqueue(&source, &partition, &rows, 10).await;
        let allowance = mkit_server::purge::SliceBudget::new(crate::purge::LAUNCH_ALARM_OPERATIONS);
        for now in [10, 5010, 10010, 15010] {
            clock.set(now);
            let registry = timer_registry_budgeted::<MemoryKv, _>(
                crate::classes::ShardClass::ContentIndexShard,
                Ok(target.clone()),
                Some("paid"),
                Some(&allowance),
                None,
                Some(&root),
                None,
            );
            let before = allowance.used();
            run_due(
                &source,
                &partition,
                &registry,
                clock.as_ref(),
                u64::try_from(now).unwrap(),
                &TickBudget::default(),
            )
            .await
            .unwrap();
            assert!(allowance.used() - before <= 2);
        }
        verify_chain(target.as_ref(), &root, 5).await;
        assert!(
            source
                .get(&partition, &keys::relay(5))
                .await
                .unwrap()
                .is_none()
        );
    });
}

#[test]
fn audit_target_conflict_lost_reply_and_registry_restart_keep_one_gapless_append() {
    block_on(async {
        for single in [true, false] {
            let clock = Arc::new(ManualClock::new(10));
            let source = MemoryKv::with_clock(clock.clone());
            let inner = target(single, &clock);
            let target = Arc::new(ReplyFaults {
                inner: inner.clone(),
                stage: AtomicU32::new(0),
                calls: AtomicU32::new(0),
            });
            let root = root(single);
            let partition = mkit_server::store::content_shard(&[6; 32]);
            let row = SystemAudit::new(target.clone(), root.clone())
                .relay_row(&partition, &request(1), "activation:1", 10)
                .unwrap();
            enqueue(&source, &partition, &[row], 10).await;
            let budget =
                mkit_server::purge::SliceBudget::new(crate::purge::LAUNCH_ALARM_OPERATIONS);
            for now in [10, 5010, 10010] {
                clock.set(now);
                let registry = timer_registry_budgeted::<MemoryKv, _>(
                    crate::classes::ShardClass::ContentIndexShard,
                    Ok(target.clone()),
                    Some("paid"),
                    Some(&budget),
                    None,
                    Some(&root),
                    None,
                );
                let before = target.calls.load(Ordering::SeqCst);
                run_due(
                    &source,
                    &partition,
                    &registry,
                    clock.as_ref(),
                    u64::try_from(now).unwrap(),
                    &TickBudget::default(),
                )
                .await
                .unwrap();
                assert!(target.calls.load(Ordering::SeqCst) - before <= 2);
                if now == 10 {
                    assert!(
                        inner
                            .get(&root, &Key::new(b"ah\0".to_vec()))
                            .await
                            .unwrap()
                            .is_none()
                    );
                } else {
                    verify_chain(inner.as_ref(), &root, 1).await;
                }
            }
            assert!(
                source
                    .get(&partition, &keys::relay(1))
                    .await
                    .unwrap()
                    .is_none()
            );
            assert_eq!(target.calls.load(Ordering::SeqCst), budget.used());
            assert_eq!(
                inner
                    .get(&root, &keys::relay_high_water(&partition).unwrap())
                    .await
                    .unwrap(),
                Some(codec::encode_u64(1))
            );
        }
    });
}

struct CacheFailure {
    calls: Arc<AtomicU32>,
    physical: mkit_server::purge::SliceBudget,
}
impl mkit_server::purge::LocalInvalidation for CacheFailure {
    fn invalidate<'a>(
        &'a self,
        _: &'a Request,
        _: u32,
        local: &'a mkit_server::purge::SliceBudget,
    ) -> mkit_server::BoxFuture<'a, Result<Option<u32>, mkit_server::StoreError>> {
        Box::pin(async move {
            assert!(self.physical.used() >= 64);
            assert!(local.charge(2));
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(mkit_server::StoreError::unavailable("cache failure"))
        })
    }
}

#[test]
fn late_owner_reserves_before_any_effect_and_keeps_durable_purge_and_audit_after_cache_failure() {
    block_on(async {
        let (clock, store, root, partition, row) = super::tests::late_holder_fixture().await;
        let physical = mkit_server::purge::SliceBudget::new(crate::purge::LAUNCH_ALARM_OPERATIONS);
        let calls = Arc::new(AtomicU32::new(0));
        let purge =
            mkit_server::purge::PurgeConfig::new("https://server.example".into(), true, true)
                .with_audit(Arc::new(SystemAudit::new(store.clone(), root.clone())))
                .with_local(Arc::new(CacheFailure {
                    calls: calls.clone(),
                    physical: physical.clone(),
                }));
        assert!(physical.charge(crate::purge::LAUNCH_ALARM_OPERATIONS - 63));
        let registry = timer_registry_budgeted::<MemoryKv, _>(
            crate::classes::ShardClass::ContentIndexShard,
            Ok(store.clone()),
            Some("paid"),
            Some(&physical),
            Some(&root),
            Some(&root),
            Some(&purge),
        );
        run_due(
            store.as_ref(),
            &partition,
            &registry,
            clock.as_ref(),
            1000,
            &TickBudget::default(),
        )
        .await
        .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(store.get(&partition, &row).await.unwrap().is_some());
        assert!(
            store
                .get(&root, &Key::new(b"ah\0".to_vec()))
                .await
                .unwrap()
                .is_none()
        );
        physical.reset();
        clock.set(3_601_000);
        run_due(
            store.as_ref(),
            &partition,
            &registry,
            clock.as_ref(),
            3_601_000,
            &TickBudget::default(),
        )
        .await
        .unwrap();
        assert!(store.get(&partition, &row).await.unwrap().is_none());
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "root acceptance and content activation each invoke the shared allowance"
        );
        assert!(physical.used() >= 64 && physical.used() < crate::purge::LAUNCH_ALARM_OPERATIONS);
        for p in [&partition, &root] {
            let (start, end) = keys::class_range(keys::TAG_TIMER);
            let timers = store.scan(p, &start, &end, None, 32).await.unwrap();
            assert!(timers.entries.iter().any(|(key, _)| matches!(
                keys::parse(key),
                Some(keys::ParsedKey::Timer { kind: 11, .. })
            )));
        }
        assert!(
            store
                .get(&partition, &keys::outbox_sequence())
                .await
                .unwrap()
                .is_some()
        );
        let audit_receipts = store
            .scan(
                &root,
                &Key::new(b"ai\0".to_vec()),
                &Key::new(b"ai\x01".to_vec()),
                None,
                32,
            )
            .await
            .unwrap();
        let (start, end) = keys::class_range(keys::TAG_RELAY);
        let queued = store
            .scan(&partition, &start, &end, None, 32)
            .await
            .unwrap();
        assert!(
            !audit_receipts.entries.is_empty() || !queued.entries.is_empty(),
            "automatic audit intent is committed before failed immediate deletion"
        );
    });
}

#[test]
fn audit_single_row_false_positive_uses_actual_sql_and_duplicate_receipt() {
    block_on(async {
        let clock = Arc::new(ManualClock::new(10));
        let target = target(false, &clock);
        let root = root(false);
        let partition = mkit_server::store::content_shard(&[9; 32]);
        let mut row = SystemAudit::new(target.clone(), root.clone())
            .relay_row(&partition, &request(9), "activation:9", 10)
            .unwrap();
        row = maximal_audit_row(row);
        assert!(
            codec::encode_relay(&row).unwrap().as_bytes().len() >= mkit_server::MAX_VALUE_BYTES - 2
        );
        let hook = mkit_server::admin::AuditReserveHook::new(root.clone());
        let rh = keys::relay_high_water(&partition).unwrap();
        let base = Batch::new()
            .require(mkit_server::Precondition::Absent(rh.clone()))
            .put(rh.clone(), codec::encode_u64(1))
            .put(row.puts[0].0.clone(), row.puts[0].1.clone());
        let mut estimate = base.clone();
        let error = hook
            .before_apply(
                &root,
                &[(1, row.clone()), (2, row.clone())],
                &mut estimate.preconditions,
                &mut estimate.writes,
            )
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid storage request: automatic audit combined batch capacity"
        );
        let mut single = base.clone();
        hook.before_apply(
            &root,
            &[(1, row.clone())],
            &mut single.preconditions,
            &mut single.writes,
        )
        .await
        .unwrap();
        assert_eq!(
            single, base,
            "preflight never changes the actual target apply"
        );
        assert_eq!(
            target.apply(&root, single).await.unwrap(),
            BatchOutcome::Committed
        );
        verify_chain(target.as_ref(), &root, 1).await;
        let duplicate = Batch::new()
            .require(mkit_server::Precondition::Equals(
                rh.clone(),
                codec::encode_u64(1),
            ))
            .put(rh, codec::encode_u64(2))
            .put(row.puts[0].0.clone(), row.puts[0].1.clone());
        assert_eq!(
            target.apply(&root, duplicate).await.unwrap(),
            BatchOutcome::Committed
        );
        verify_chain(target.as_ref(), &root, 1).await;
    });
}

#[test]
fn audit_noncanonical_head_maximum_sequence_and_mixed_receipts_remain_authoritative() {
    block_on(async {
        let clock = Arc::new(ManualClock::new(10));
        let target = target(false, &clock);
        let root = root(false);
        let partition = mkit_server::store::content_shard(&[10; 32]);
        let audit = SystemAudit::new(target.clone(), root.clone());
        let rows = [
            audit
                .relay_row(&partition, &request(1), "activation:1", 10)
                .unwrap(),
            audit
                .relay_row(&partition, &request(2), "activation:2", 10)
                .unwrap(),
        ];
        let mut raw = serde_json::to_vec(
            &serde_json::json!({"seq":u64::MAX-1,"hash":"a".repeat(64),"legacy":true}),
        )
        .unwrap();
        raw.resize(mkit_server::MAX_VALUE_BYTES, b' ');
        assert_eq!(
            target
                .apply(
                    &root,
                    Batch::new().put(rows[0].puts[0].0.clone(), rows[0].puts[0].1.clone())
                )
                .await
                .unwrap(),
            BatchOutcome::Committed
        );
        // Seed the accepted legacy spelling separately, so SQL observes it before extension.
        assert_eq!(
            target
                .apply(
                    &root,
                    Batch::new().put(Key::new(b"ah\0".to_vec()), Value::new(raw))
                )
                .await
                .unwrap(),
            BatchOutcome::Committed
        );
        let mut batch = Batch::new();
        for row in &rows {
            for (key, value) in &row.puts {
                batch = batch.put(key.clone(), value.clone());
            }
        }
        let before = batch.clone();
        let hook = mkit_server::admin::AuditReserveHook::new(root.clone());
        hook.before_apply(
            &root,
            &[(1, rows[0].clone()), (2, rows[1].clone())],
            &mut batch.preconditions,
            &mut batch.writes,
        )
        .await
        .unwrap();
        assert_eq!(batch, before);
        assert_eq!(
            target.apply(&root, batch).await.unwrap(),
            BatchOutcome::Committed
        );
        let head: serde_json::Value = serde_json::from_slice(
            target
                .get(&root, &Key::new(b"ah\0".to_vec()))
                .await
                .unwrap()
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        assert_eq!(head["seq"], u64::MAX);
        assert!(
            target
                .get(
                    &root,
                    &Key::new([b"ae\0".as_slice(), &u64::MAX.to_be_bytes()].concat())
                )
                .await
                .unwrap()
                .is_some()
        );
        let conflict = Batch::new().put(rows[0].puts[0].0.clone(), Value::new(b"{}".to_vec()));
        assert!(target.apply(&root, conflict).await.is_err());
        assert_eq!(
            target.get(&root, &rows[0].puts[0].0).await.unwrap(),
            Some(rows[0].puts[0].1.clone())
        );
    });
}

#[test]
fn audit_preflight_preserves_invalid_events_and_conflicting_duplicates() {
    block_on(async {
        let clock = Arc::new(ManualClock::new(10));
        let root = root(false);
        let row = SystemAudit::new(target(false, &clock), root.clone())
            .relay_row(
                &mkit_server::store::content_shard(&[11; 32]),
                &request(11),
                "activation:11",
                10,
            )
            .unwrap();
        let hook = mkit_server::admin::AuditReserveHook::new(root.clone());
        for invalid in [Value::new(b"{}".to_vec()), {
            let mut event: serde_json::Value =
                serde_json::from_slice(row.puts[0].1.as_bytes()).unwrap();
            event["recordedAtMs"] = serde_json::json!(11);
            Value::new(serde_json::to_vec(&event).unwrap())
        }] {
            let mut pre = Vec::new();
            let mut writes = vec![
                mkit_server::Write::Put(row.puts[0].0.clone(), row.puts[0].1.clone()),
                mkit_server::Write::Put(row.puts[0].0.clone(), invalid),
            ];
            let original = writes.clone();
            let error = hook
                .before_apply(
                    &root,
                    &[(1, row.clone()), (2, row.clone())],
                    &mut pre,
                    &mut writes,
                )
                .await
                .unwrap_err();
            assert!(!error.to_string().contains("combined batch capacity"));
            assert!(pre.is_empty());
            assert_eq!(writes, original);
        }
        let mut writes = vec![
            mkit_server::Write::Put(row.puts[0].0.clone(), row.puts[0].1.clone());
            mkit_server::MAX_BATCH_OPS + 1
        ];
        let error = hook
            .before_apply(&root, &[(1, row)], &mut Vec::new(), &mut writes)
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("invalid automatic audit entry count")
        );
    });
}

fn maximal_audit_row(mut row: codec::RelayV1) -> codec::RelayV1 {
    let original = row.puts[0].1.as_bytes().to_vec();
    // Whitespace is accepted event JSON. Find the largest source-valid hex row.
    let mut low = original.len();
    let mut high = mkit_server::MAX_VALUE_BYTES;
    while low + 1 < high {
        let mid = usize::midpoint(low, high);
        let mut raw = original.clone();
        raw.resize(mid, b' ');
        row.puts[0].1 = Value::new(raw);
        if codec::encode_relay(&row).is_ok() {
            low = mid;
        } else {
            high = mid;
        }
    }
    let mut raw = original;
    raw.resize(low, b' ');
    row.puts[0].1 = Value::new(raw);
    row
}

#[test]
fn audit_single_actual_oversize_still_rolls_back_atomically() {
    block_on(async {
        let clock = Arc::new(ManualClock::new(10));
        let target = target(false, &clock);
        let root = root(false);
        let partition = mkit_server::store::content_shard(&[12; 32]);
        let audit = SystemAudit::new(target.clone(), root.clone());
        let mut row = audit
            .relay_row(&partition, &request(12), "activation:12", 10)
            .unwrap();
        let new = audit
            .relay_row(&partition, &request(13), "activation:13", 10)
            .unwrap();
        row.puts.extend(new.puts);
        row = maximal_audit_row(row);
        codec::encode_relay(&row).unwrap();
        assert_eq!(
            target
                .apply(
                    &root,
                    Batch::new().put(row.puts[0].0.clone(), row.puts[0].1.clone())
                )
                .await
                .unwrap(),
            BatchOutcome::Committed
        );
        let mut old =
            serde_json::to_vec(&serde_json::json!({"seq":1,"hash":"a".repeat(64),"legacy":true}))
                .unwrap();
        old.resize(mkit_server::MAX_VALUE_BYTES, b' ');
        let head = Key::new(b"ah\0".to_vec());
        let old = Value::new(old);
        assert_eq!(
            target
                .apply(&root, Batch::new().put(head.clone(), old.clone()))
                .await
                .unwrap(),
            BatchOutcome::Committed
        );
        let rh = keys::relay_high_water(&partition).unwrap();
        let mut batch = Batch::new()
            .require(mkit_server::Precondition::Absent(rh.clone()))
            .put(rh.clone(), codec::encode_u64(1));
        for (key, value) in &row.puts {
            batch = batch.put(key.clone(), value.clone());
        }
        mkit_server::admin::AuditReserveHook::new(root.clone())
            .before_apply(
                &root,
                &[(1, row.clone())],
                &mut batch.preconditions,
                &mut batch.writes,
            )
            .await
            .unwrap();
        let error = target.apply(&root, batch).await.unwrap_err();
        assert!(
            error.to_string().contains("extended batch exceeds limits"),
            "{error}"
        );
        assert_eq!(target.get(&root, &head).await.unwrap(), Some(old));
        assert!(target.get(&root, &rh).await.unwrap().is_none());
        assert!(target.get(&root, &row.puts[1].0).await.unwrap().is_none());
    });
}

#[test]
fn audit_corrupt_zero_head_fails_closed_without_history_repair() {
    block_on(async {
        let clock = Arc::new(ManualClock::new(10));
        let source = MemoryKv::with_clock(clock.clone());
        let target = target(false, &clock);
        let root = root(false);
        let partition = mkit_server::store::content_shard(&[13; 32]);
        let audit = SystemAudit::new(target.clone(), root.clone());
        let mut rows = (0..5)
            .map(|i| {
                audit
                    .relay_row(&partition, &request(i), &format!("activation:{i}"), 10)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let mut receipts = Batch::new();
        for row in &rows {
            for (key, value) in &row.puts {
                receipts = receipts.put(key.clone(), value.clone());
            }
        }
        assert_eq!(
            target.apply(&root, receipts).await.unwrap(),
            BatchOutcome::Committed
        );
        let head = Key::new(b"ah\0".to_vec());
        let old = Value::new(
            serde_json::to_vec(&serde_json::json!({"seq":0,"hash":"a".repeat(300*1024)})).unwrap(),
        );
        assert_eq!(
            target
                .apply(&root, Batch::new().put(head.clone(), old.clone()))
                .await
                .unwrap(),
            BatchOutcome::Committed
        );
        for (i, row) in rows.iter_mut().enumerate() {
            row.puts.push((
                Key::new(vec![b'x', u8::try_from(i).unwrap()]),
                Value::new(vec![1; 100 * 1024]),
            ));
            codec::encode_relay(row).unwrap();
        }
        let rh = keys::relay_high_water(&partition).unwrap();
        let batch = unobserved_audit_batch(&partition, &rows);
        batch
            .validate(&mkit_server::StoreCapabilities::full())
            .unwrap();
        assert!(
            target
                .apply(&root, batch)
                .await
                .unwrap_err()
                .to_string()
                .contains("extended batch exceeds limits")
        );
        assert_eq!(target.get(&root, &head).await.unwrap(), Some(old.clone()));
        assert!(target.get(&root, &rh).await.unwrap().is_none());
        enqueue(&source, &partition, &rows, 10).await;
        let allowance = mkit_server::purge::SliceBudget::new(crate::purge::LAUNCH_ALARM_OPERATIONS);
        for now in [10, 5010, 10010, 15010, 20010] {
            clock.set(now);
            let registry = timer_registry_budgeted::<MemoryKv, _>(
                crate::classes::ShardClass::ContentIndexShard,
                Ok(target.clone()),
                Some("paid"),
                Some(&allowance),
                None,
                Some(&root),
                None,
            );
            let before = allowance.used();
            run_due(
                &source,
                &partition,
                &registry,
                clock.as_ref(),
                u64::try_from(now).unwrap(),
                &TickBudget::default(),
            )
            .await
            .unwrap();
            assert!(allowance.used() - before <= 2);
        }
        // D48: a manually replaced zero head after real receipts is corrupt history,
        // not an admitted progress case. Preserve it without repairing or normalizing.
        assert!(target.get(&root, &rh).await.unwrap().is_none());
        assert_eq!(target.get(&root, &head).await.unwrap(), Some(old));
        for row in &rows {
            assert_eq!(
                target.get(&root, &row.puts[0].0).await.unwrap(),
                Some(row.puts[0].1.clone())
            );
            assert!(target.get(&root, &row.puts[1].0).await.unwrap().is_none());
        }
        assert!(
            source
                .get(&partition, &keys::relay(5))
                .await
                .unwrap()
                .is_some()
        );
    });
}

fn unobserved_audit_batch(partition: &Partition, rows: &[codec::RelayV1]) -> Batch {
    let rh = keys::relay_high_water(partition).unwrap();
    let mut batch = Batch::new()
        .require(mkit_server::Precondition::Absent(rh.clone()))
        .put(rh, codec::encode_u64(u64::try_from(rows.len()).unwrap()));
    for row in rows {
        for (key, value) in &row.puts {
            batch = batch.put(key.clone(), value.clone());
        }
    }
    batch
}
