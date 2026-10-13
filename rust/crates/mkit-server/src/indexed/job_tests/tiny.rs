//! Faults at every durable boundary introduced by consecutive tiny slices.
use super::*;
use crate::Precondition;
use std::sync::atomic::AtomicBool;

struct ReplyLoss {
    inner: Arc<MemoryKv>,
    applies: AtomicU32,
    fail_at: u32,
    clock_jump: Mutex<Option<Arc<ManualClock>>>,
    jump_on_timer_guard: bool,
    race_on_timer_guard: AtomicBool,
    clock_jump_ms: i64,
}
impl NamespaceStore for ReplyLoss {
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
        let n = self.applies.fetch_add(1, Ordering::SeqCst) + 1;
        let timer_guard = batch.preconditions.iter().any(|guard| matches!(guard,
            Precondition::Equals(key, _) if matches!(keys::parse(key), Some(keys::ParsedKey::Timer { .. }))));
        if ((self.jump_on_timer_guard && timer_guard) || (!self.jump_on_timer_guard && n == 1))
            && let Some(clock) = self.clock_jump.lock().unwrap().take()
        {
            clock.advance(self.clock_jump_ms);
        }
        if timer_guard && self.race_on_timer_guard.swap(false, Ordering::SeqCst) {
            let (key, raw) = batch
                .preconditions
                .iter()
                .find_map(|guard| match guard {
                    Precondition::Equals(key, raw)
                        if matches!(
                            keys::parse(key),
                            Some(keys::ParsedKey::VerifyCursor {
                                sub: keys::VC_JOB,
                                ..
                            })
                        ) =>
                    {
                        Some((key, raw))
                    }
                    _ => None,
                })
                .expect("intermediate checkpoint guards its job");
            let mut concurrent = checkpoint::decode_job(raw)?;
            concurrent.generation += 1;
            self.inner
                .apply(
                    p,
                    Batch::new()
                        .require(Precondition::Equals(key.clone(), raw.clone()))
                        .put(key.clone(), checkpoint::encode_job(&concurrent)),
                )
                .await?;
        }
        let result = self.inner.apply(p, batch).await?;
        if n == self.fail_at {
            return Err(StoreError::unavailable("lost checkpoint reply"));
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

#[test]
fn tiny_slices_resume_after_failure_and_lost_reply_at_every_apply() {
    for pack in [
        mkit_core::transfer::encode_packlist(None, &[]).unwrap(),
        tree_pack(1, 36).0,
    ] {
        let reference = {
            let mut rig = Rig::new();
            rig.limits.tiny_chain_slices = 8;
            let (ticket, id) = rig.add(&pack);
            rig.create(&ticket, id);
            rig.drive(|rig| rig.finished(&ticket.pack_id));
            snapshot(&rig, &ticket.pack_id)
        };
        for lost in [false, true] {
            let mut boundaries = 0;
            for fail_at in 1..100 {
                let mut rig = Rig::new();
                rig.limits.tiny_chain_slices = 8;
                let (ticket, id) = rig.add(&pack);
                rig.create(&ticket, id);
                let applies = if lost {
                    let store = ReplyLoss {
                        inner: rig.store.clone(),
                        applies: AtomicU32::new(0),
                        fail_at,
                        clock_jump: Mutex::new(None),
                        jump_on_timer_guard: false,
                        race_on_timer_guard: AtomicBool::new(false),
                        clock_jump_ms: 2_000,
                    };
                    rig.drive_on(&store, |rig| rig.finished(&ticket.pack_id));
                    store.applies.load(Ordering::SeqCst)
                } else {
                    let store = Faulty {
                        inner: rig.store.clone(),
                        applies: AtomicU32::new(0),
                        fail_at: AtomicU32::new(fail_at),
                        inventory_guard: None,
                    };
                    rig.drive_on(&store, |rig| rig.finished(&ticket.pack_id));
                    store.applies.load(Ordering::SeqCst)
                };
                assert_eq!(
                    snapshot(&rig, &ticket.pack_id),
                    reference,
                    "lost={lost} boundary={fail_at}"
                );
                assert!(matches!(
                    rig.state(&ticket.pack_id),
                    Some(VerificationV1::Verified { .. })
                ));
                rig.verification_timer(&ticket.pack_id);
                if applies < fail_at {
                    break;
                }
                boundaries += 1;
            }
            assert!(boundaries > 3);
        }
    }
}

#[test]
fn tiny_slices_commit_decode_before_closure_and_stop_at_delivery() {
    let (pack, _) = tree_pack(1, 36);
    let mut rig = Rig::named("tiny", Arc::new(crate::pipeline::D34Shards));
    rig.limits.tiny_chain_slices = 8;
    let (ticket, id) = rig.add(&pack);
    rig.create(&ticket, id);
    let report = rig.tick();
    assert_eq!(report.failed, 0);
    assert!(rig.recorder.slices.lock().unwrap().iter().sum::<f64>() <= 256.0);
    assert_eq!(
        rig.job(&ticket.pack_id).unwrap().phase,
        Phase::AwaitDelivery
    );
    assert!(!rig.job(&ticket.pack_id).unwrap().usable());
    rig.drive(|rig| rig.finished(&ticket.pack_id));
    assert!(rig.job(&ticket.pack_id).unwrap().usable());
}

#[test]
fn tiny_slices_do_not_refresh_a_small_call_allowance() {
    let (pack, _) = tree_pack(1, 36);
    let mut rig = Rig::new();
    rig.limits.tiny_chain_slices = 8;
    rig.limits.max_subrequests = 96;
    let (ticket, id) = rig.add(&pack);
    rig.create(&ticket, id);
    let report = rig.tick();
    assert_eq!(report.failed, 0);
    assert_eq!(
        rig.job(&ticket.pack_id).unwrap().phase,
        Phase::ClosureResolve
    );
    rig.drive(|rig| rig.finished(&ticket.pack_id));
    assert!(rig.job(&ticket.pack_id).unwrap().usable());
}

#[test]
fn pending_detail_preserves_milliseconds_and_rounds_only_the_http_header() {
    for (hint, expected) in [
        (0, 1_000),
        (1, 100),
        (100, 100),
        (300, 300),
        (1_001, 1_001),
        (3_000, 3_000),
    ] {
        let error = super::super::pending(hint);
        assert_eq!(error.details().len(), 1);
        let bytes = &error.details()[0].value;
        assert_eq!(bytes[0], 0x08);
        let ms = bytes[1..]
            .iter()
            .enumerate()
            .fold(0_u64, |value, (i, byte)| {
                value | (u64::from(byte & 0x7f) << (7 * i))
            });
        assert_eq!(ms, expected);
        assert!(
            error
                .headers()
                .contains(&("Retry-After".into(), expected.div_ceil(1_000).to_string()))
        );
    }
}

#[test]
fn tiny_slices_stop_before_another_slice_at_the_elapsed_cutoff() {
    let (pack, _) = tree_pack(1, 36);
    let mut rig = Rig::new();
    rig.limits.tiny_chain_slices = 8;
    let (ticket, id) = rig.add(&pack);
    rig.create(&ticket, id);
    let store = ReplyLoss {
        inner: rig.store.clone(),
        applies: AtomicU32::new(0),
        fail_at: 0,
        clock_jump: Mutex::new(Some(rig.clock.clone())),
        jump_on_timer_guard: false,
        race_on_timer_guard: AtomicBool::new(false),
        clock_jump_ms: 2_000,
    };
    let report = rig.tick_on(&store);
    assert_eq!(report.failed, 0);
    assert_eq!(
        rig.job(&ticket.pack_id).unwrap().phase,
        Phase::ClosureResolve
    );
    rig.drive(|rig| rig.finished(&ticket.pack_id));
    assert!(rig.job(&ticket.pack_id).unwrap().usable());
}

#[test]
fn tiny_checkpoint_crossing_elapsed_cutoff_retains_a_runnable_timer() {
    let (pack, _) = tree_pack(1, 36);
    let mut rig = Rig::new();
    rig.limits.tiny_chain_slices = 8;
    let (ticket, id) = rig.add(&pack);
    rig.create(&ticket, id);
    let store = ReplyLoss {
        inner: rig.store.clone(),
        applies: AtomicU32::new(0),
        fail_at: 0,
        clock_jump: Mutex::new(Some(rig.clock.clone())),
        jump_on_timer_guard: true,
        race_on_timer_guard: AtomicBool::new(false),
        clock_jump_ms: 2_000,
    };
    let report = rig.tick_on(&store);
    assert_eq!(report.failed, 0);
    assert_eq!(
        rig.job(&ticket.pack_id).unwrap().phase,
        Phase::ClosureResolve
    );
    rig.verification_timer(&ticket.pack_id);
    rig.drive(|rig| rig.finished(&ticket.pack_id));
    assert!(rig.job(&ticket.pack_id).unwrap().usable());
}

#[test]
fn tiny_checkpoint_losing_a_concurrent_job_guard_recovers_without_stale_progress() {
    let (pack, _) = tree_pack(1, 36);
    let mut rig = Rig::new();
    rig.limits.tiny_chain_slices = 8;
    let (ticket, id) = rig.add(&pack);
    rig.create(&ticket, id);
    let store = ReplyLoss {
        inner: rig.store.clone(),
        applies: AtomicU32::new(0),
        fail_at: 0,
        clock_jump: Mutex::new(None),
        jump_on_timer_guard: false,
        race_on_timer_guard: AtomicBool::new(true),
        clock_jump_ms: 2_000,
    };
    let report = rig.tick_on(&store);
    assert_eq!(report.failed, 1);
    assert_eq!(rig.job(&ticket.pack_id).unwrap().phase, Phase::Decode);
    rig.verification_timer(&ticket.pack_id);
    rig.drive(|rig| rig.finished(&ticket.pack_id));
    assert!(rig.job(&ticket.pack_id).unwrap().usable());
}

#[test]
fn tiny_packlist_decode_and_verify_share_one_alarm() {
    let pack = mkit_core::transfer::encode_packlist(None, &[]).unwrap();
    let mut rig = Rig::new();
    rig.limits.tiny_chain_slices = 8;
    let (ticket, id) = rig.add(&pack);
    rig.create(&ticket, id);
    let report = rig.tick();
    assert_eq!(report.failed, 0);
    assert_eq!(report.fired, 1);
    assert!(rig.job(&ticket.pack_id).unwrap().usable());
    assert!(matches!(
        rig.state(&ticket.pack_id),
        Some(VerificationV1::Verified { .. })
    ));
    assert!(rig.recorder.slices.lock().unwrap().iter().sum::<f64>() <= 256.0);
}

#[test]
fn physical_tick_cutoff_prevents_another_tiny_slice() {
    let (pack, _) = tree_pack(1, 36);
    let mut rig = Rig::new();
    rig.limits.tiny_chain_slices = 8;
    let (ticket, id) = rig.add(&pack);
    rig.create(&ticket, id);
    let store = ReplyLoss {
        inner: rig.store.clone(),
        applies: AtomicU32::new(0),
        fail_at: 0,
        clock_jump: Mutex::new(Some(rig.clock.clone())),
        jump_on_timer_guard: false,
        race_on_timer_guard: AtomicBool::new(false),
        clock_jump_ms: 1,
    };
    let registry = TimerRegistry::new().register(rig.handler());
    let report = block_on(run_due(
        &store,
        &rig.source(),
        &registry,
        rig.clock.as_ref(),
        u64::try_from(rig.clock.now_ms()).unwrap(),
        &TickBudget::new(128, 32, 512, 1),
    ))
    .unwrap();
    assert_eq!(report.failed, 0);
    assert!(report.stopped_on_budget);
    assert_eq!(
        rig.job(&ticket.pack_id).unwrap().phase,
        Phase::ClosureResolve
    );
    rig.drive(|rig| rig.finished(&ticket.pack_id));
    assert!(rig.job(&ticket.pack_id).unwrap().usable());
}

#[test]
fn external_closure_keeps_its_full_slice_reservation_after_decode() {
    let (pack, _, _, (tree, tree_raw)) = split_packs();
    let mut rig = Rig::new();
    rig.limits.tiny_chain_slices = 8;
    seed_member(&rig, tree, &tree_raw);
    let (ticket, id) = rig.add(&pack);
    rig.create(&ticket, id);
    let report = rig.tick();
    assert_eq!(report.failed, 0);
    assert_eq!(
        rig.job(&ticket.pack_id).unwrap().phase,
        Phase::ClosureResolve
    );
    assert_eq!(
        rig.recorder.slices.lock().unwrap().len(),
        1,
        "external lookups cannot start with Decode's spent allowance"
    );
    rig.drive(|rig| rig.finished(&ticket.pack_id));
    assert!(rig.job(&ticket.pack_id).unwrap().usable());
}
