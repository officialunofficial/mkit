//! Chained Extract selection steps: bounds, effect stages and crash safety.
use super::*;
use crate::indexed::checkpoint::Phase;

struct Fixture {
    rig: Rig,
    extension: TestExtraction,
    pack: Hash,
    id: Hash,
}

fn fixture(chain: u32, edit: impl FnOnce(&mut Rig)) -> Fixture {
    fixture_on(Rig::new(), chain, edit)
}

fn fixture_on(mut rig: Rig, chain: u32, edit: impl FnOnce(&mut Rig)) -> Fixture {
    rig.limits.extract_chain_steps = chain;
    let chunk = Object::Blob(Blob {
        data: vec![92; 500],
    });
    let manifest = Object::ChunkedBlob(ChunkedBlob {
        total_size: 500,
        chunk_size: 0,
        chunks: vec![chunk.id().unwrap()],
    });
    let id = manifest.id().unwrap();
    let (tree, commit, head) = tree_head(&[id]);
    let canonical = serialize(&chunk).unwrap();
    seed_member(&rig, chunk.id().unwrap(), &canonical);
    let objects = [manifest, tree, commit];
    rig.cfg.decode_budget = objects
        .iter()
        .map(|object| serialize(object).unwrap().len() as u64)
        .sum::<u64>()
        + canonical.len() as u64;
    edit(&mut rig);
    let (ticket, ticket_id) = rig.add(&pack(&objects));
    assert!(rig.check(&[(&ticket, ticket_id)], head).is_err());
    let extension = TestExtraction::new(&rig);
    Fixture {
        rig,
        extension,
        pack: ticket.pack_id,
        id,
    }
}

fn stage(f: &Fixture) -> Option<u8> {
    f.rig
        .job(&f.pack)
        .unwrap()
        .extraction
        .as_ref()
        .map(|x| x.stage)
}

/// Ticks that start in the Extract phase before the first effect stage (3).
fn selection_ticks(f: &Fixture) -> u32 {
    let mut ticks = 0;
    for _ in 0..400 {
        if stage(f).is_some_and(|stage| stage >= 3) {
            return ticks;
        }
        let extract = f.rig.job(&f.pack).unwrap().phase == Phase::Extract;
        tick(&f.rig, &f.extension, f.rig.store.as_ref(), true);
        f.rig.clock.advance(1_000);
        ticks += u32::from(extract);
    }
    panic!("selection did not finish");
}

#[test]
fn the_step_cap_bounds_the_steps_of_a_slice() {
    let one = selection_ticks(&fixture(1, |_| {}));
    assert!(one >= 4, "one step per slice takes many slices: {one}");
    for cap in [2_u32, 3, 5] {
        let ticks = selection_ticks(&fixture(cap, |_| {}));
        // A slice runs at most `cap` steps, and a stalled step ends it early.
        assert!(
            ticks >= one.div_ceil(cap),
            "cap {cap}: {ticks} slices ran more than {cap} steps each (one-step: {one})"
        );
        assert!(ticks < one, "cap {cap} must chain: {ticks} vs {one}");
    }
    let chained = selection_ticks(&fixture(64, |_| {}));
    assert!(
        chained <= 2,
        "default chaining finishes selection: {chained}"
    );
}

/// Every call of the local store takes a fixed business-clock time.
struct Ticking<'a> {
    inner: &'a MemoryKv,
    clock: &'a ManualClock,
    ms: i64,
}
impl NamespaceStore for Ticking<'_> {
    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }
    async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
        self.clock.advance(self.ms);
        self.inner.get(p, key).await
    }
    async fn get_many(
        &self,
        p: &Partition,
        keys: &[Key],
    ) -> Result<Vec<Option<Value>>, StoreError> {
        self.clock.advance(self.ms);
        self.inner.get_many(p, keys).await
    }
    async fn scan(
        &self,
        p: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<ScanPage, StoreError> {
        self.clock.advance(self.ms);
        self.inner.scan(p, start, end, after, limit).await
    }
    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        self.clock.advance(self.ms);
        self.inner.apply(p, batch).await
    }
    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        self.inner.stats(p).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.inner.probe().await
    }
}

#[test]
fn a_slow_slice_stops_chaining_at_the_time_cap() {
    let fast = fixture(64, |_| {});
    let fast_ticks = selection_ticks(&fast);
    let slow = fixture(64, |_| {});
    let mut ticks = 0;
    let mut longest = 0;
    for _ in 0..400 {
        if stage(&slow).is_some_and(|stage| stage >= 3) {
            break;
        }
        let extract = slow.rig.job(&slow.pack).unwrap().phase == Phase::Extract;
        let before = slow.rig.clock.now_ms();
        let local = Ticking {
            inner: slow.rig.store.as_ref(),
            clock: slow.rig.clock.as_ref(),
            ms: 400,
        };
        tick(&slow.rig, &slow.extension, &local, true);
        slow.rig.clock.advance(1_000);
        ticks += u32::from(extract);
        if extract {
            longest = longest.max(slow.rig.clock.now_ms() - before - 1_000);
        }
    }
    assert!(
        ticks > fast_ticks,
        "{ticks} slow vs {fast_ticks} fast slices"
    );
    // The cap is 2 s; a slice may overshoot it by the one step in flight.
    assert!(longest < 2_000 + 20 * 400, "slice took {longest} ms");
}

#[test]
fn effect_stages_are_never_chained() {
    let f = fixture(64, |_| {});
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..3_000 {
        if f.rig.finished(&f.pack) {
            break;
        }
        tick(&f.rig, &f.extension, f.rig.store.as_ref(), true);
        f.rig.clock.advance(1_000);
        seen.extend(stage(&f));
    }
    assert!(f.rig.finished(&f.pack));
    for effect in [3_u8, 4, 6, 7, 8, 9] {
        assert!(seen.contains(&effect), "stage {effect} never ended a slice");
    }
}

#[test]
fn a_crash_at_every_apply_of_a_chained_slice_resumes_to_the_same_state() {
    for ticks_before in 0..6 {
        for fail_at in 1..=14 {
            let f = fixture(64, |_| {});
            for _ in 0..ticks_before {
                tick(&f.rig, &f.extension, f.rig.store.as_ref(), true);
                f.rig.clock.advance(1_000);
            }
            let faulty = Faulty {
                inner: f.rig.store.clone(),
                applies: AtomicU32::new(0),
                fail_at: AtomicU32::new(fail_at),
                inventory_guard: None,
            };
            tick(&f.rig, &f.extension, &faulty, false);
            if read_blob(&f.rig.blobs, &BlobKey::object(f.id)).is_some() {
                let index = ContentIndex::new(crate::store::BorrowedStore(f.rig.store.as_ref()));
                assert!(
                    block_on(index.collectable(
                        &f.id,
                        u64::try_from(f.rig.clock.now_ms()).unwrap(),
                        0
                    ))
                    .unwrap()
                    .is_none(),
                    "crash at apply {fail_at} after {ticks_before} slices lost protection"
                );
            }
            f.rig.clock.advance(1_000);
            drive(&f.rig, &f.extension, &[f.pack]);
            assert_eq!(
                read_blob(&f.rig.blobs, &BlobKey::object(f.id)),
                Some(vec![92; 500]),
                "crash at apply {fail_at} after {ticks_before} slices"
            );
            assert_eq!(
                read_blob(&f.rig.blobs, &BlobKey::object_offsets(f.id)),
                Some(crate::indexed::extract::encode_offsets(&[0, 500]))
            );
            assert_holder(&f.rig, f.id);
        }
    }
}

#[test]
fn an_undelivered_relay_is_polled_after_300_ms_then_every_second() {
    // Sharded placement emits relay rows; a single partition has none.
    let f = fixture_on(
        Rig::named("await", Arc::new(crate::pipeline::D34Shards)),
        64,
        |_| {},
    );
    let mut delays = Vec::new();
    for _ in 0..60 {
        // No relay handler: the emitted rows stay undelivered.
        tick(&f.rig, &f.extension, f.rig.store.as_ref(), false);
        if f.rig.job(&f.pack).unwrap().phase == Phase::AwaitDelivery {
            let (key, _) = f.rig.verification_timer(&f.pack);
            let Some(keys::ParsedKey::Timer { due_at_ms, .. }) = keys::parse(&key) else {
                panic!("timer key")
            };
            delays.push(due_at_ms - u64::try_from(f.rig.clock.now_ms()).unwrap());
            if delays.len() == 3 {
                break;
            }
        }
        f.rig.clock.advance(5_000);
    }
    assert_eq!(delays, [300, 1_000, 1_000]);
}
