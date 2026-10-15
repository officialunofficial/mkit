//! Closure and index-emission callbacks retain durable boundaries while sharing one bounded allowance.
use super::*;
use crate::Precondition;

struct Checkpoints {
    phase: Phase,
    inner: Arc<MemoryKv>,
    commits: AtomicU32,
    fail_at: u32,
    lose_reply: bool,
}

impl NamespaceStore for Checkpoints {
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
        batch.validate(&self.capabilities()).unwrap();
        let checkpoint = batch.preconditions.iter().any(|guard| matches!(guard,
            Precondition::Equals(key, _) if matches!(keys::parse(key), Some(keys::ParsedKey::Timer { .. }))))
            && batch.writes.iter().any(|write| match write {
                crate::store::Write::Put(key, raw)
                    if matches!(keys::parse(key), Some(keys::ParsedKey::VerifyCursor { sub: keys::VC_JOB, .. })) =>
                {
                    decode_job(raw).unwrap().phase == self.phase
                }
                _ => false,
            });
        let fail = checkpoint && self.commits.fetch_add(1, Ordering::SeqCst) + 1 == self.fail_at;
        if fail && !self.lose_reply {
            return Err(StoreError::unavailable("interrupted phase checkpoint"));
        }
        let result = self.inner.apply(p, batch).await?;
        if fail {
            assert_eq!(result, BatchOutcome::Committed);
            return Err(StoreError::unavailable("lost phase checkpoint reply"));
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

struct Fixture {
    phase: Phase,
    rig: Rig,
    extension: TestExtraction,
    ticket: TicketV1,
    ticket_id: Hash,
    head: Hash,
}

fn closure(slices: u32) -> Fixture {
    closure_with_member(slices, false)
}

fn closure_with_member(slices: u32, external: bool) -> Fixture {
    fixture(Phase::ClosureResolve, slices, external)
}

fn emit(slices: u32) -> Fixture {
    fixture(Phase::EmitIndex, slices, false)
}

fn fixture(phase: Phase, slices: u32, external: bool) -> Fixture {
    fixture_with_shards(phase, slices, external, phase == Phase::EmitIndex)
}

fn fixture_with_shards(phase: Phase, slices: u32, external: bool, sharded: bool) -> Fixture {
    let mut rig = if sharded {
        Rig::named("one", Arc::new(D34Shards))
    } else {
        Rig::new()
    };
    rig.limits.closure_chain_slices = 1;
    let (bytes, head) = if external {
        let local: Vec<_> = (0..800).map(|n| blob(n, 64).0).collect();
        let (id, raw) = (800..2_000)
            .map(|n| blob(n, 19))
            .find(|(id, _)| (180..270).contains(&local.iter().filter(|local| *local < id).count()))
            .expect("an external child follows two complete local pages");
        seed_member(&rig, id, &raw);
        external_children_pack(800, &[id])
    } else {
        tree_pack(800, 19)
    };
    let (ticket, ticket_id) = rig.add(&bytes);
    assert!(rig.check(&[(&ticket, ticket_id)], head).is_err());
    let extension = TestExtraction::new(&rig);
    for _ in 0..500 {
        if rig.job(&ticket.pack_id).unwrap().phase == phase {
            assert!(!rig.job(&ticket.pack_id).unwrap().usable());
            match phase {
                Phase::ClosureResolve => rig.limits.closure_chain_slices = slices,
                Phase::EmitIndex => rig.limits.emit_chain_slices = slices,
                _ => unreachable!(),
            }
            return Fixture {
                phase,
                rig,
                extension,
                ticket,
                ticket_id,
                head,
            };
        }
        tick(&rig, &extension, rig.store.as_ref(), true);
        rig.clock.advance(1_000);
    }
    panic!("fixture did not enter requested phase");
}

fn durable_output(f: &Fixture) -> (Snapshot, Vec<(Key, Value)>) {
    let (start, end) = keys::class_range(keys::TAG_OBJECT_INDEX);
    let mut rows = Vec::new();
    for partition in f.rig.shards.object_index_partitions(&f.rig.repo) {
        rows.extend(
            block_on(f.rig.store.scan(&partition, &start, &end, None, 10_000))
                .unwrap()
                .entries,
        );
    }
    rows.sort_by(|left, right| left.0.cmp(&right.0));
    (snapshot(&f.rig, &f.ticket.pack_id), rows)
}

fn callback(f: &Fixture, store: &impl NamespaceStore) -> usize {
    let before = f.rig.recorder.slices.lock().unwrap().len();
    let now = f.rig.clock.now_ms();
    tick(&f.rig, &f.extension, store, true);
    assert_eq!(f.rig.clock.now_ms(), now, "callback uses a frozen clock");
    f.rig.recorder.slices.lock().unwrap().len() - before
}

#[test]
fn closure_callback_slice_ceiling_holds_with_a_frozen_clock() {
    for cap in [2, 4, 8, u32::MAX] {
        let f = closure(cap);
        let before = f.rig.recorder.slices.lock().unwrap().len();
        let count = callback(&f, f.rig.store.as_ref());
        assert!(count > 1, "closure chains durable slices: {count}");
        assert_eq!(count, cap.min(8) as usize, "cap {cap}");
        assert_eq!(
            f.rig.job(&f.ticket.pack_id).unwrap().phase,
            Phase::ClosureResolve
        );
        f.rig.verification_timer(&f.ticket.pack_id);
        assert!(
            f.rig.recorder.slices.lock().unwrap()[before..]
                .iter()
                .sum::<f64>()
                <= 256.0
        );
    }
}

#[test]
fn closure_callback_replays_each_committed_slice_after_failure_or_lost_reply() {
    replays_each_checkpoint(Phase::ClosureResolve);
}

fn replays_each_checkpoint(phase: Phase) {
    let reference = fixture(phase, 8, false);
    let store = Checkpoints {
        phase: reference.phase,
        inner: reference.rig.store.clone(),
        commits: AtomicU32::new(0),
        fail_at: 0,
        lose_reply: false,
    };
    assert!(callback(&reference, &store) > 1);
    let boundaries = store.commits.load(Ordering::SeqCst);
    assert!(boundaries > 1);
    drive(
        &reference.rig,
        &reference.extension,
        &[reference.ticket.pack_id],
    );
    let expected = durable_output(&reference);
    for lose_reply in [false, true] {
        for fail_at in 1..=boundaries {
            let f = fixture(phase, 8, false);
            let before = f.rig.job(&f.ticket.pack_id).unwrap();
            let store = Checkpoints {
                phase: f.phase,
                inner: f.rig.store.clone(),
                commits: AtomicU32::new(0),
                fail_at,
                lose_reply,
            };
            callback(&f, &store);
            assert_eq!(store.commits.load(Ordering::SeqCst), fail_at);
            f.rig.verification_timer(&f.ticket.pack_id);
            if lose_reply || fail_at > 1 {
                assert_ne!(f.rig.job(&f.ticket.pack_id).unwrap(), before);
            }
            drive(&f.rig, &f.extension, &[f.ticket.pack_id]);
            assert_eq!(
                durable_output(&f),
                expected,
                "checkpoint {fail_at}, lost reply {lose_reply}"
            );
            assert!(f.rig.job(&f.ticket.pack_id).unwrap().usable());
            assert!(f.extension.sessions.lock().unwrap().is_empty());
        }
    }
}

#[test]
fn closure_callback_spends_one_allowance_and_rearms_after_partial_progress() {
    let full = closure(8);
    let full_count = callback(&full, full.rig.store.as_ref());
    let limited = closure_with_member(8, true);
    let calls_before = limited.rig.recorder.slices.lock().unwrap().len();
    let before = limited.rig.job(&limited.ticket.pack_id).unwrap();
    let count = callback(&limited, limited.rig.store.as_ref());
    assert!(
        count > 1 && count < full_count,
        "limited {count}, full {full_count}"
    );
    let spent = limited.rig.recorder.slices.lock().unwrap()[calls_before..]
        .iter()
        .sum::<f64>();
    assert!(spent > 0.0 && spent <= 256.0, "charged calls: {spent}");
    assert_ne!(limited.rig.job(&limited.ticket.pack_id).unwrap(), before);
    limited.rig.verification_timer(&limited.ticket.pack_id);
    assert_eq!(
        limited.rig.job(&limited.ticket.pack_id).unwrap().phase,
        Phase::ClosureResolve
    );
    drive(&limited.rig, &limited.extension, &[limited.ticket.pack_id]);
    assert!(limited.rig.job(&limited.ticket.pack_id).unwrap().usable());
}

#[test]
fn closure_callback_preserves_the_usable_result_and_durable_output() {
    let mut results = Vec::new();
    for slices in [1, 8] {
        let f = closure(slices);
        drive(&f.rig, &f.extension, &[f.ticket.pack_id]);
        assert!(f.rig.job(&f.ticket.pack_id).unwrap().usable());
        assert!(f.extension.sessions.lock().unwrap().is_empty());
        results.push((
            durable_output(&f),
            f.rig.check(&[(&f.ticket, f.ticket_id)], f.head).unwrap(),
        ));
    }
    assert_eq!(results[0], results[1]);
}

struct RestartAfterCommit {
    inner: Checkpoints,
    repo: RepoName,
    pack: Hash,
    restarted: Mutex<Option<VerifyJobV1>>,
}

impl NamespaceStore for RestartAfterCommit {
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
        let result = self.inner.apply(p, batch).await?;
        if result == BatchOutcome::Committed
            && self.inner.commits.load(Ordering::SeqCst) == 1
            && self.restarted.lock().unwrap().is_none()
        {
            let key = keys::verify_job(&self.repo, &self.pack);
            let raw = self.inner.get(p, &key).await?.unwrap();
            let mut job = decode_job(&raw)?;
            assert_eq!(job.phase, self.inner.phase);
            job.restart();
            let batch = checkpoint::write_job(
                Batch::new().require(Precondition::Equals(key, raw.clone())),
                &mut job,
                Some(&raw),
                &self.repo,
                &self.pack,
            )?;
            assert_eq!(
                self.inner.inner.apply(p, batch).await?,
                BatchOutcome::Committed
            );
            *self.restarted.lock().unwrap() = Some(job);
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
fn closure_callback_rechecks_the_phase_after_a_concurrent_restart() {
    rechecks_phase(Phase::ClosureResolve);
}

fn rechecks_phase(phase: Phase) {
    let f = fixture(phase, 8, false);
    let store = RestartAfterCommit {
        inner: Checkpoints {
            phase: f.phase,
            inner: f.rig.store.clone(),
            commits: AtomicU32::new(0),
            fail_at: 0,
            lose_reply: false,
        },
        repo: f.rig.repo.name.clone(),
        pack: f.ticket.pack_id,
        restarted: Mutex::new(None),
    };
    let reads_before = f.rig.windows.reads.load(Ordering::SeqCst);
    callback(&f, &store);
    let expected = store.restarted.lock().unwrap().clone().unwrap();
    assert_eq!(expected.phase, Phase::Decode);
    assert_eq!(f.rig.job(&f.ticket.pack_id).unwrap(), expected);
    assert_eq!(
        f.rig.windows.reads.load(Ordering::SeqCst),
        reads_before,
        "the continuation cannot begin the restarted Decode"
    );
    assert_eq!(store.inner.commits.load(Ordering::SeqCst), 1);
    f.rig.verification_timer(&f.ticket.pack_id);
    drive(&f.rig, &f.extension, &[f.ticket.pack_id]);
    assert!(f.rig.job(&f.ticket.pack_id).unwrap().usable());
    f.rig.check(&[(&f.ticket, f.ticket_id)], f.head).unwrap();
}

#[test]
fn emit_callback_slice_ceiling_holds_with_a_frozen_clock() {
    for cap in [2, 4, 8, u32::MAX] {
        let f = emit(cap);
        assert_eq!(callback(&f, f.rig.store.as_ref()), cap.min(8) as usize);
        assert_eq!(
            f.rig.job(&f.ticket.pack_id).unwrap().phase,
            Phase::EmitIndex
        );
        f.rig.verification_timer(&f.ticket.pack_id);
    }
}

#[test]
fn emit_callback_replays_each_committed_slice_after_failure_or_lost_reply() {
    replays_each_checkpoint(Phase::EmitIndex);
}

#[test]
fn emit_callback_rechecks_the_phase_after_a_concurrent_restart() {
    rechecks_phase(Phase::EmitIndex);
}

#[test]
fn emit_callback_preserves_the_usable_result_and_durable_output() {
    let mut results = Vec::new();
    for slices in [1, 8] {
        let f = emit(slices);
        drive(&f.rig, &f.extension, &[f.ticket.pack_id]);
        assert!(f.rig.job(&f.ticket.pack_id).unwrap().usable());
        results.push((
            durable_output(&f),
            f.rig.check(&[(&f.ticket, f.ticket_id)], f.head).unwrap(),
        ));
    }
    assert_eq!(results[0], results[1]);
}

#[test]
fn emit_callback_spends_one_allowance_and_rearms_after_partial_progress() {
    let f = fixture_with_shards(Phase::EmitIndex, 8, false, false);
    let before = f.rig.recorder.slices.lock().unwrap().len();
    let count = callback(&f, f.rig.store.as_ref());
    assert!(count > 1 && count < 8, "chained slices: {count}");
    let spent = f.rig.recorder.slices.lock().unwrap()[before..]
        .iter()
        .sum::<f64>();
    assert!(spent > 0.0 && spent <= 256.0, "charged calls: {spent}");
    assert_eq!(
        f.rig.job(&f.ticket.pack_id).unwrap().phase,
        Phase::EmitIndex
    );
    f.rig.verification_timer(&f.ticket.pack_id);
    drive(&f.rig, &f.extension, &[f.ticket.pack_id]);
    assert!(f.rig.job(&f.ticket.pack_id).unwrap().usable());
}
