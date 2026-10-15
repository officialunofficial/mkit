//! Index emission may replay an enqueued page before its job checkpoint.
use super::*;
use std::sync::atomic::AtomicBool;

struct InterruptedRelay {
    inner: Arc<MemoryKv>,
    checkpoints: AtomicU32,
    armed: AtomicBool,
    failed: AtomicBool,
    lose_reply: bool,
}

impl NamespaceStore for InterruptedRelay {
    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }
    async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
        self.inner.get(p, key).await
    }
    async fn scan(
        &self,
        p: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<ScanPage, StoreError> {
        self.inner.scan(p, start, end, after, limit).await
    }
    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        let checkpoint = batch.writes.iter().any(|write| {
            matches!(write,
            crate::store::Write::Put(key, _) if matches!(keys::parse(key),
                Some(keys::ParsedKey::VerifyCursor { sub: keys::VC_JOB, .. })))
        });
        let relay = batch.writes.iter().any(|write| {
            matches!(write,
            crate::store::Write::Put(key, _) if matches!(keys::parse(key),
                Some(keys::ParsedKey::Relay(_))))
        });
        if checkpoint
            && self.armed.load(Ordering::SeqCst)
            && !self.failed.swap(true, Ordering::SeqCst)
        {
            return Err(StoreError::unavailable(
                "interrupted post-enqueue checkpoint",
            ));
        }
        let result = self.inner.apply(p, batch).await?;
        if result == BatchOutcome::Committed {
            if checkpoint {
                self.checkpoints.fetch_add(1, Ordering::SeqCst);
            }
            // The first checkpoint proves this enqueue belongs to a later
            // durable slice inside the same callback.
            if relay
                && self.checkpoints.load(Ordering::SeqCst) > 0
                && !self.failed.load(Ordering::SeqCst)
            {
                self.armed.store(true, Ordering::SeqCst);
                if self.lose_reply {
                    self.failed.store(true, Ordering::SeqCst);
                    return Err(StoreError::unavailable("lost relay enqueue reply"));
                }
            }
        }
        Ok(result)
    }
    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        self.inner.stats(p).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.inner.probe().await
    }
}

fn fixture(slices: u32) -> (Rig, TestExtraction, TicketV1) {
    let mut rig = Rig::named("replay", Arc::new(D34Shards));
    let (bytes, head) = tree_pack(240, 19);
    let (ticket, id) = rig.add(&bytes);
    assert!(rig.check(&[(&ticket, id)], head).is_err());
    let extension = TestExtraction::new(&rig);
    for _ in 0..100 {
        if rig.job(&ticket.pack_id).unwrap().phase == Phase::EmitIndex {
            rig.limits.emit_chain_slices = slices;
            return (rig, extension, ticket);
        }
        tick(&rig, &extension, rig.store.as_ref(), true);
        rig.clock.advance(1_000);
    }
    panic!("fixture did not enter index emission");
}

fn target_rows(rig: &Rig) -> Vec<(Key, Value)> {
    let (start, end) = keys::class_range(keys::TAG_OBJECT_INDEX);
    let mut rows = Vec::new();
    for target in rig.shards.object_index_partitions(&rig.repo) {
        rows.extend(
            block_on(rig.store.scan(&target, &start, &end, None, 10_000))
                .unwrap()
                .entries,
        );
    }
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    rows
}

fn queued(rig: &Rig) -> Vec<codec::RelayV1> {
    let (start, end) = keys::class_range(keys::TAG_RELAY);
    block_on(rig.store.scan(&rig.source(), &start, &end, None, 10_000))
        .unwrap()
        .entries
        .into_iter()
        .map(|(_, raw)| codec::decode_relay(&raw).unwrap())
        .collect()
}

#[test]
fn emit_callback_replays_enqueued_pages_before_checkpoint_and_waits_for_newest_sequence() {
    let (baseline, extension, ticket) = fixture(1);
    drive(&baseline, &extension, &[ticket.pack_id]);
    let expected = target_rows(&baseline);
    assert_eq!(expected.len(), 242);
    for lose_reply in [false, true] {
        let (rig, extension, ticket) = fixture(8);
        let store = InterruptedRelay {
            inner: rig.store.clone(),
            checkpoints: AtomicU32::new(0),
            armed: AtomicBool::new(false),
            failed: AtomicBool::new(false),
            lose_reply,
        };
        tick(&rig, &extension, &store, false);
        assert!(store.failed.load(Ordering::SeqCst));
        assert!(store.checkpoints.load(Ordering::SeqCst) >= 1);
        assert!(!queued(&rig).is_empty());
        assert_eq!(rig.job(&ticket.pack_id).unwrap().phase, Phase::EmitIndex);
        // Retain all outbox rows until the replay has enqueued every page.
        for _ in 0..100 {
            if rig.job(&ticket.pack_id).unwrap().phase == Phase::AwaitDelivery {
                break;
            }
            rig.clock.advance(1_000);
            tick(&rig, &extension, rig.store.as_ref(), false);
        }
        let job = rig.job(&ticket.pack_id).unwrap();
        assert_eq!(job.phase, Phase::AwaitDelivery);
        assert!(!job.usable());
        let latest = block_on(rig.store.get(&rig.source(), &keys::outbox_sequence()))
            .unwrap()
            .map(|raw| codec::decode_u64(&raw).unwrap())
            .unwrap();
        assert_eq!(job.last_relay_seq, Some(latest));
        let rows = queued(&rig);
        assert!(
            rows.iter().enumerate().any(|(i, row)| rows[..i]
                .iter()
                .any(|old| old.target == row.target
                    && old.puts == row.puts
                    && old.deletes == row.deletes)),
            "replay must produce duplicate index effects with fresh sequences"
        );
        assert!(
            !block_on(crate::relay::relay_delivered_through(
                rig.store.as_ref(),
                &rig.source(),
                latest
            ))
            .unwrap()
        );
        drive(&rig, &extension, &[ticket.pack_id]);
        assert!(rig.job(&ticket.pack_id).unwrap().usable());
        assert!(
            block_on(crate::relay::relay_delivered_through(
                rig.store.as_ref(),
                &rig.source(),
                latest
            ))
            .unwrap()
        );
        assert_eq!(
            target_rows(&rig),
            expected,
            "lost enqueue reply {lose_reply}"
        );
        assert!(queued(&rig).is_empty());
    }
}

#[test]
#[allow(clippy::too_many_lines)] // Keep protected intent setup and atomic delivery assertions together.
fn replayed_relay_holder_intents_fold_across_new_sequences() {
    block_on(async {
        let clock = Arc::new(ManualClock::new(NOW));
        let store = Arc::new(MemoryKv::with_clock(clock.clone()));
        let ns = NamespaceKey::deployment_default();
        let source = Partition::Namespace(ns.clone());
        let repo = RepoName::new("replay").unwrap();
        let object = [0x72; 32];
        let hold = [0x73; 32];
        let target = content_shard(&object);
        let identity = crate::store::PendingHolderV1::new(
            crate::store::Holder::new(ns, repo),
            source.clone(),
            [0x74; 32],
            object,
            hold,
            [0x75; 32],
        )
        .unwrap();
        let now = u64::try_from(NOW).unwrap();
        let index = ContentIndex::new(crate::store::BorrowedStore(store.as_ref()));
        assert_eq!(
            index
                .add_hold(&object, &hold, now + 60_000, now)
                .await
                .unwrap(),
            crate::store::HoldOutcome::Held
        );
        assert_eq!(
            index
                .protect_pending_holder(&object, &hold, &identity, now)
                .await
                .unwrap(),
            crate::store::HoldOutcome::Held
        );
        let before = codec::decode_object_state(
            &store
                .get(&target, &keys::object_state(&object))
                .await
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        let row = codec::RelayV1 {
            at_ms: now,
            target: target.clone(),
            puts: vec![(
                keys::pending_holder(&object, &hold),
                identity.encode().unwrap(),
            )],
            deletes: Vec::new(),
        };
        for _ in 0..2 {
            crate::relay::commit_relay_rows(
                store.as_ref(),
                &source,
                std::slice::from_ref(&row),
                now,
                now + 10_000,
                None,
            )
            .await
            .unwrap();
        }
        let registry = TimerRegistry::new().register(crate::relay::RelayHandler {
            target: Shared(store.clone()),
            hook: crate::relay::HolderRelayHook {
                clock: clock.clone(),
            },
            budget: crate::relay::RelayBudget::default(),
        });
        for _ in 0..10 {
            run_due(
                store.as_ref(),
                &source,
                &registry,
                clock.as_ref(),
                u64::try_from(clock.now_ms()).unwrap(),
                &TickBudget::default(),
            )
            .await
            .unwrap();
            if crate::relay::relay_delivered_through(store.as_ref(), &source, 2)
                .await
                .unwrap()
            {
                break;
            }
            clock.advance(1_000);
        }
        assert!(
            crate::relay::relay_delivered_through(store.as_ref(), &source, 2)
                .await
                .unwrap()
        );
        let after = codec::decode_object_state(
            &store
                .get(&target, &keys::object_state(&object))
                .await
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(after.holders, 1);
        assert_eq!(
            after.seq,
            before.seq + 1,
            "one logical holder intent bumps once"
        );
        assert!(
            store
                .get(&target, &keys::pending_holder(&object, &hold))
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .get(&target, &keys::hold(&object, &hold))
                .await
                .unwrap()
                .is_none()
        );
    });
}
