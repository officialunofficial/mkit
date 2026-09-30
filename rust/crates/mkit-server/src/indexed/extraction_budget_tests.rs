//! A changing member-body snapshot must not reset one Advance's source budget.
use super::*;
use crate::Precondition;

fn relay_only(rig: &Rig) {
    let registry = TimerRegistry::new().register(crate::relay::RelayHandler {
        target: Shared(rig.store.clone()),
        hook: crate::relay::HolderRelayHook {
            clock: rig.clock.clone(),
        },
        budget: crate::relay::RelayBudget::default(),
    });
    block_on(run_due(
        rig.store.as_ref(),
        &rig.source(),
        &registry,
        rig.clock.as_ref(),
        u64::try_from(rig.clock.now_ms()).unwrap(),
        &TickBudget::default(),
    ))
    .unwrap();
}

#[test]
#[allow(clippy::too_many_lines)] // Native oracle and two-owner scheduling share one immutable fixture.
fn changing_a_peers_member_body_cannot_reset_the_group_source_charge() {
    let chunk = Object::Blob(Blob {
        data: vec![151; 500],
    });
    let chunk_id = chunk.id().unwrap();
    let canonical = serialize(&chunk).unwrap();
    let first_manifest = Object::ChunkedBlob(ChunkedBlob {
        total_size: 500,
        chunk_size: 0,
        chunks: vec![chunk_id],
    });
    let second_manifest = Object::ChunkedBlob(ChunkedBlob {
        total_size: 1_000,
        chunk_size: 0,
        chunks: vec![chunk_id, chunk_id],
    });
    let first_object = first_manifest.id().unwrap();
    let second_object = second_manifest.id().unwrap();
    let (tree, commit, head) = tree_head(&[first_object, second_object]);
    // Padding distinguishes this consumed pack from a subsequently published
    // single-object member pack satisfying the first owner's owed child.
    let second_objects = [
        second_manifest.clone(),
        Object::Blob(Blob { data: vec![152] }),
    ];
    let first_objects = [first_manifest, tree, commit];
    let staged_bytes: u64 = first_objects
        .iter()
        .chain(&second_objects)
        .map(|object| u64::try_from(serialize(object).unwrap().len()).unwrap())
        .sum();
    let decode_budget = staged_bytes + 2 * u64::try_from(canonical.len()).unwrap();
    let first_pack = pack(&first_objects);
    let second_pack = pack(&second_objects);

    let mut native_rig = Rig::new();
    native_rig.cfg.decode_budget = decode_budget;
    seed_member(&native_rig, chunk_id, &canonical);
    let native_tickets = [native_rig.add(&first_pack), native_rig.add(&second_pack)];
    let values = native_tickets
        .iter()
        .map(|(ticket, _)| ticket.clone())
        .collect::<Vec<_>>();
    let ids = native_tickets.iter().map(|(_, id)| *id).collect::<Vec<_>>();
    let native_error = block_on(crate::indexed::verify::verify_ticketed(
        native_rig.blobs.as_ref(),
        native_rig.store.as_ref(),
        native_rig.shards.as_ref(),
        &native_rig.repo,
        &native_rig.source(),
        &values,
        &ids,
        head,
        native_rig.cfg,
        native_rig.clock.as_ref(),
        native_rig.recorder.as_ref(),
    ))
    .unwrap_err();
    assert_eq!(
        native_error.public_message(),
        "pack exceeds indexed decode budget"
    );

    let mut rig = Rig::new();
    rig.cfg.decode_budget = decode_budget;
    seed_member(&rig, chunk_id, &canonical);
    let first = rig.add(&first_pack);
    let second = rig.add(&second_pack);
    assert!(
        rig.check(&[(&first.0, first.1), (&second.0, second.1)], head)
            .is_err()
    );
    let extension = TestExtraction::new(&rig);
    for _ in 0..200 {
        for owner in [&first.0.pack_id, &second.0.pack_id] {
            if rig.job(owner).unwrap().phase != Phase::Extract {
                fire_pack(&rig, &extension, *owner);
            }
        }
        relay_only(&rig);
        rig.clock.advance(1_000);
        if [first.0.pack_id, second.0.pack_id]
            .iter()
            .all(|owner| rig.job(owner).unwrap().phase == Phase::Extract)
        {
            break;
        }
    }
    for owner in [first.0.pack_id, second.0.pack_id] {
        assert_eq!(rig.job(&owner).unwrap().phase, Phase::Extract);
    }
    for _ in 0..300 {
        if rig.job(&first.0.pack_id).unwrap().usable() {
            break;
        }
        fire_pack(&rig, &extension, first.0.pack_id);
        relay_only(&rig);
        rig.clock.advance(1_000);
    }
    assert!(rig.job(&first.0.pack_id).unwrap().usable());
    assert_holder(&rig, first_object);
    let original_group = rig.job(&first.0.pack_id).unwrap().extraction.unwrap().group;
    assert!(rig.job(&second.0.pack_id).unwrap().extraction.is_none());

    // Final Recheck can gain a member after another ref publishes an owed
    // child. Use the current producer's guarded immutable-body writer.
    seed_member(&rig, second_object, &serialize(&second_manifest).unwrap());
    let added_member = hash(&pack(std::slice::from_ref(&second_manifest)));
    let key = keys::verify_job(&rig.repo.name, &first.0.pack_id);
    let prior = block_on(rig.store.get(&rig.source(), &key))
        .unwrap()
        .unwrap();
    let mut changed = checkpoint::decode_job(&prior).unwrap();
    block_on(checkpoint::hydrate_job(
        rig.store.as_ref(),
        &rig.source(),
        &rig.repo.name,
        &first.0.pack_id,
        &mut changed,
    ))
    .unwrap();
    let old_body = changed.member_body_id;
    assert!(!changed.satisfying.contains(&added_member));
    changed.satisfying.push(added_member);
    let batch = checkpoint::write_job(
        Batch::new()
            .require(Precondition::Equals(key, prior.clone()))
            .require(Precondition::NotAfter(
                u64::try_from(rig.clock.now_ms()).unwrap() + 10_000,
            )),
        &mut changed,
        Some(&prior),
        &rig.repo.name,
        &first.0.pack_id,
    )
    .unwrap();
    assert_eq!(
        block_on(rig.store.apply(&rig.source(), batch)).unwrap(),
        BatchOutcome::Committed
    );
    assert_ne!(changed.member_body_id, old_body);

    for _ in 0..300 {
        if rig.finished(&second.0.pack_id) {
            break;
        }
        fire_pack(&rig, &extension, second.0.pack_id);
        relay_only(&rig);
        rig.clock.advance(1_000);
    }
    let completed = rig.job(&second.0.pack_id).unwrap();
    assert_eq!(
        completed.outcome,
        Some(checkpoint::Outcome::DecodeBudget),
        "a changed peer member-body must not discard the first owner's source charge"
    );
    assert_eq!(completed.extraction.as_ref().unwrap().group, original_group);
    let scheduled_error = rig
        .check(&[(&first.0, first.1), (&second.0, second.1)], head)
        .unwrap_err();
    assert_eq!(scheduled_error.code(), native_error.code());
    assert_eq!(
        scheduled_error.public_message(),
        native_error.public_message()
    );
    assert!(
        block_on(rig.store.get(
            &content_shard(&second_object),
            &keys::holder(&second_object, &rig.repo.namespace, &rig.repo.name).unwrap()
        ))
        .unwrap()
        .is_none()
    );
}

/// Observe local row batches without changing their values or advancing jobs.
struct CountReads {
    inner: Arc<MemoryKv>,
    job: Key,
    maximum: Mutex<BTreeMap<u8, usize>>,
    calls: Arc<AtomicU32>,
}

impl NamespaceStore for CountReads {
    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }
    async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.get(p, key).await
    }
    async fn get_many(
        &self,
        p: &Partition,
        keys: &[Key],
    ) -> Result<Vec<Option<Value>>, StoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(raw) = self.inner.get(p, &self.job).await? {
            let job = checkpoint::decode_job(&raw)?;
            if job.phase == Phase::Extract
                && let Some(progress) = job.extraction
            {
                let mut maximum = self.maximum.lock().unwrap();
                let seen = maximum.entry(progress.stage).or_default();
                *seen = (*seen).max(keys.len());
            }
        }
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
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.scan(p, start, end, after, limit).await
    }
    async fn scan_many(
        &self,
        p: &Partition,
        ranges: &[RangeScan],
    ) -> Result<Vec<ScanPage>, StoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.scan_many(p, ranges).await
    }
    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.apply(p, batch).await
    }
    async fn stats(&self, p: &Partition) -> Result<crate::PartitionStats, StoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.stats(p).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.probe().await
    }
}

#[test]
fn multipart_preflight_upload_and_completion_read_at_most_eight_raw_rows() {
    let mut rig = Rig::new();
    rig.limits.window_bytes = 16 << 20;
    let mut data = (0..8_u8)
        .map(|i| vec![161 + i; (1 << 20) - 10])
        .collect::<Vec<_>>();
    data.extend([vec![169; 80], vec![170; 99]]);
    let chunks = data
        .iter()
        .map(|data| Object::Blob(Blob { data: data.clone() }))
        .collect::<Vec<_>>();
    let manifest = Object::ChunkedBlob(ChunkedBlob {
        total_size: (8 << 20) + 99,
        chunk_size: 0,
        chunks: chunks.iter().map(|object| object.id().unwrap()).collect(),
    });
    let id = manifest.id().unwrap();
    let (tree, commit, head) = tree_head(&[id]);
    let objects = chunks
        .into_iter()
        .chain([manifest, tree, commit])
        .collect::<Vec<_>>();
    let (ticket, ticket_id) = rig.add(&pack(&objects));
    assert!(rig.check(&[(&ticket, ticket_id)], head).is_err());
    let counted = CountReads {
        inner: rig.store.clone(),
        job: keys::verify_job(&rig.repo.name, &ticket.pack_id),
        maximum: Mutex::default(),
        calls: Arc::default(),
    };
    let extension = TestExtraction::new(&rig);
    for _ in 0..1_000 {
        if rig.finished(&ticket.pack_id) {
            break;
        }
        tick(&rig, &extension, &counted, true);
        rig.clock.advance(1_000);
    }
    assert!(rig.finished(&ticket.pack_id));
    assert_eq!(rig.job(&ticket.pack_id).unwrap().outcome, None);
    assert_eq!(
        read_blob(&rig.blobs, &BlobKey::object(id)),
        Some(data.concat())
    );
    assert_holder(&rig, id);
    let maximum = counted.maximum.lock().unwrap();
    for stage in [3, 5, 6] {
        let rows = maximum
            .get(&stage)
            .expect("the multipart phase was exercised");
        assert!(*rows > 0);
        assert!(
            *rows <= 8,
            "stage {stage} retained {rows} maximum-sized raw values"
        );
    }
}

#[derive(Clone)]
struct CountWindows {
    inner: Arc<Windows>,
    maximum: Arc<Mutex<u64>>,
}

impl PackWindows for CountWindows {
    fn read<'a>(
        &'a self,
        pack: &'a Hash,
        offset: u64,
        len: u64,
        etag: Option<&'a str>,
    ) -> BoxFuture<'a, Result<Window, WindowError>> {
        {
            let mut maximum = self.maximum.lock().unwrap();
            *maximum = (*maximum).max(len);
        }
        self.inner.read(pack, offset, len, etag)
    }
}

#[derive(Clone, Copy)]
enum BadFrame {
    Length,
    DecodedSize,
    Depth,
}

fn corrupt_frame_is_rejected_before_ranged_read(damage: BadFrame) {
    use crate::timers::{DueTimer, TimerCtx, TimerHandler};
    let mut rig = Rig::new();
    rig.cfg.extract_min_bytes = 8 << 20;
    let chunk = Object::Blob(Blob { data: vec![181] });
    let chunk_id = chunk.id().unwrap();
    let manifest = Object::ChunkedBlob(ChunkedBlob {
        total_size: 1,
        chunk_size: 0,
        chunks: vec![chunk_id],
    });
    let object = manifest.id().unwrap();
    let (tree, commit, head) = tree_head(&[object]);
    // The pack is larger than the entry/window allowance, while each current
    // producer's frame is individually valid and below the decoded limit.
    let objects = [chunk, manifest, tree, commit]
        .into_iter()
        .chain((0..6_u8).map(|i| {
            Object::Blob(Blob {
                data: vec![182 + i; 900_000],
            })
        }))
        .collect::<Vec<_>>();
    let bytes = pack(&objects);
    let (ticket, ticket_id) = rig.add(&bytes);
    assert!(rig.check(&[(&ticket, ticket_id)], head).is_err());
    let extension = TestExtraction::new(&rig);
    for _ in 0..500 {
        if rig
            .job(&ticket.pack_id)
            .unwrap()
            .extraction
            .is_some_and(|x| x.stage == 3 && x.object == Some(object))
        {
            break;
        }
        fire_pack(&rig, &extension, ticket.pack_id);
        relay_only(&rig);
        rig.clock.advance(1_000);
    }
    let job = rig.job(&ticket.pack_id).unwrap();
    let progress = job.extraction.unwrap();
    assert_eq!((progress.stage, progress.object), (3, Some(object)));
    let key = keys::verify_row(
        &rig.repo.name,
        &ticket.pack_id,
        keys::VC_FRAME,
        Some(&object),
    );
    let prior = block_on(rig.store.get(&rig.source(), &key))
        .unwrap()
        .unwrap();
    let mut frame = checkpoint::decode_frame(&object, &prior).unwrap();
    let decoded_limit = rig
        .limits
        .resident_bytes
        .saturating_sub(2 * rig.limits.window_bytes)
        .saturating_sub(8 << 20)
        / 8;
    match damage {
        BadFrame::Length => frame.value.frame_length = decoded_limit + 129,
        BadFrame::DecodedSize => frame.value.decoded_size = decoded_limit + 1,
        BadFrame::Depth => {
            frame.value.wire_type = 0x02;
            frame.value.delta_base = Some(chunk_id);
            frame.value.chain_depth = rig.cfg.max_delta_chain_depth + 1;
        }
    }
    assert!(frame.value.frame_offset + frame.value.frame_length < job.pack_len);
    assert_eq!(
        block_on(rig.store.apply(
            &rig.source(),
            Batch::new().put(key, checkpoint::encode_frame(&object, &frame).unwrap())
        ))
        .unwrap(),
        BatchOutcome::Committed
    );
    let maximum = Arc::new(Mutex::new(0));
    let h = extraction_handler(&rig, extension);
    let handler = VerifyTimer {
        windows: CountWindows {
            inner: h.windows,
            maximum: maximum.clone(),
        },
        remote: h.remote,
        blobs: h.blobs,
        shards: h.shards,
        cfg: h.cfg,
        limits: h.limits,
        lease: h.lease,
        clock: h.clock,
        metrics: h.metrics,
        extension: h.extension,
    };
    let now = u64::try_from(rig.clock.now_ms()).unwrap();
    let _fired = block_on(handler.fire(
        &TimerCtx {
            store: rig.store.as_ref(),
            partition: &rig.source(),
            now_ms: now,
        },
        &DueTimer {
            due_at_ms: now,
            kind: crate::timers::registry::kinds::VERIFY,
            reference: Bytes::from(checkpoint::timer_reference(&rig.repo.name, &ticket.pack_id)),
            value: Value::default(),
        },
    ));
    assert_eq!(
        *maximum.lock().unwrap(),
        0,
        "invalid frame metadata reached the ranged reader"
    );
    assert!(read_blob(&rig.blobs, &BlobKey::object(object)).is_none());
}

#[test]
fn oversized_persisted_frame_is_rejected_before_ranged_read() {
    corrupt_frame_is_rejected_before_ranged_read(BadFrame::Length);
}

#[test]
fn oversized_persisted_decoded_size_is_rejected_before_ranged_read() {
    corrupt_frame_is_rejected_before_ranged_read(BadFrame::DecodedSize);
}

#[test]
fn excessive_persisted_delta_depth_is_rejected_before_ranged_read() {
    corrupt_frame_is_rejected_before_ranged_read(BadFrame::Depth);
}

struct OneBase(Hash, Vec<u8>);

impl mkit_core::pack::DeltaBaseSource for OneBase {
    fn base(&mut self, id: &Hash) -> Result<Option<Vec<u8>>, mkit_core::pack::PackError> {
        Ok((*id == self.0).then(|| self.1.clone()))
    }
}

fn seed_fifty_cross_pack_member_deltas(rig: &Rig) -> Hash {
    let (mut base, mut prior) = blob(0, 2_000);
    seed_member(rig, base, &prior);
    for depth in 1..=50_u16 {
        let (id, raw) = blob(depth, 2_000);
        let bytes = thin(base, &prior, &raw);
        let (ticket, _) = rig.add(&bytes);
        let mut frames = Vec::new();
        decode_entries_with(
            &bytes,
            &mut OneBase(base, prior),
            DecodeLimits::default(),
            |entry| {
                frames.push(FrameMeta {
                    id: entry.id,
                    frame_offset: entry.frame_offset,
                    frame_length: entry.frame_length,
                    wire_type: entry.wire_type,
                    delta_base: entry.delta_base,
                    decoded_size: u64::try_from(entry.bytes.len()).unwrap(),
                });
                Ok(())
            },
        )
        .unwrap();
        let row = index_entries(&frames, 50).unwrap().remove(0);
        block_on(
            rig.store.apply(
                &rig.source(),
                Batch::new()
                    .put(
                        keys::membership(&rig.repo.name, &ticket.pack_id),
                        Value::default(),
                    )
                    .put(
                        keys::object_index(&rig.repo.name, &id, &ticket.pack_id),
                        codec::encode_object_index(&id, &row.value).unwrap(),
                    ),
            ),
        )
        .unwrap();
        base = id;
        prior = raw;
    }
    base
}

struct CountBlobCalls {
    inner: Arc<MemoryBlobStore>,
    calls: Arc<AtomicU32>,
}

impl BlobStore for CountBlobCalls {
    type Sink = <MemoryBlobStore as BlobStore>::Sink;
    async fn begin(&self, key: BlobKey, len: u64) -> Result<Self::Sink, StoreError> {
        self.inner.begin(key, len).await
    }
    async fn get(
        &self,
        key: &BlobKey,
        range: Option<ByteRange>,
    ) -> Result<Option<BlobBody>, StoreError> {
        self.calls
            .fetch_add(if range.is_some() { 2 } else { 1 }, Ordering::SeqCst);
        self.inner.get(key, range).await
    }
    async fn head(&self, key: &BlobKey) -> Result<Option<BlobMeta>, StoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.head(key).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.inner.probe().await
    }
    async fn delete(&self, key: &BlobKey) -> Result<bool, StoreError> {
        self.inner.delete(key).await
    }
}

#[test]
#[allow(clippy::too_many_lines)] // Native oracle and counted alarm replay share one valid depth-50 fixture.
fn a_valid_fifty_deep_member_chunk_finishes_under_the_default_alarm_budget() {
    use crate::timers::{DueTimer, Fired, TimerCtx, TimerHandler};
    let native = Rig::new();
    assert_eq!(native.cfg.max_delta_chain_depth, 50);
    let chunk = seed_fifty_cross_pack_member_deltas(&native);
    let manifest = Object::ChunkedBlob(ChunkedBlob {
        // The shared blob fixture prepends its two-byte distinguishing tag.
        total_size: 2_002,
        chunk_size: 0,
        chunks: vec![chunk],
    });
    let object = manifest.id().unwrap();
    let (tree, commit, head) = tree_head(&[object]);
    let bytes = pack(&[manifest, tree, commit]);
    let (ticket, id) = native.add(&bytes);
    block_on(crate::indexed::verify::verify_ticketed(
        native.blobs.as_ref(),
        native.store.as_ref(),
        native.shards.as_ref(),
        &native.repo,
        &native.source(),
        &[ticket],
        &[id],
        head,
        native.cfg,
        native.clock.as_ref(),
        native.recorder.as_ref(),
    ))
    .unwrap();
    assert_holder(&native, object);

    let rig = Rig::new();
    assert_eq!(seed_fifty_cross_pack_member_deltas(&rig), chunk);
    let (ticket, id) = rig.add(&bytes);
    assert!(rig.check(&[(&ticket, id)], head).is_err());
    let extension = TestExtraction::new(&rig);
    for _ in 0..200 {
        if rig.job(&ticket.pack_id).unwrap().phase == Phase::Extract {
            break;
        }
        fire_pack(&rig, &extension, ticket.pack_id);
        relay_only(&rig);
        rig.clock.advance(1_000);
    }
    assert_eq!(rig.job(&ticket.pack_id).unwrap().phase, Phase::Extract);
    let calls = Arc::new(AtomicU32::new(0));
    let h = extraction_handler(&rig, extension);
    let handler = VerifyTimer {
        remote: Shared(Arc::new(CountReads {
            inner: rig.store.clone(),
            job: keys::verify_job(&rig.repo.name, &ticket.pack_id),
            maximum: Mutex::default(),
            calls: calls.clone(),
        })),
        blobs: CountBlobCalls {
            inner: rig.blobs.clone(),
            calls: calls.clone(),
        },
        windows: h.windows,
        shards: h.shards,
        cfg: h.cfg,
        limits: h.limits,
        lease: h.lease,
        clock: h.clock,
        metrics: h.metrics,
        extension: h.extension,
    };
    let mut failures = Vec::new();
    for _ in 0..100 {
        if rig.finished(&ticket.pack_id) {
            break;
        }
        calls.store(0, Ordering::SeqCst);
        let now = u64::try_from(rig.clock.now_ms()).unwrap();
        match block_on(handler.fire(
            &TimerCtx {
                store: rig.store.as_ref(),
                partition: &rig.source(),
                now_ms: now,
            },
            &DueTimer {
                due_at_ms: now,
                kind: crate::timers::registry::kinds::VERIFY,
                reference: Bytes::from(checkpoint::timer_reference(
                    &rig.repo.name,
                    &ticket.pack_id,
                )),
                value: Value::default(),
            },
        )) {
            Ok(Fired::Done(batch) | Fired::Reschedule { batch, .. }) => {
                block_on(rig.store.apply(&rig.source(), batch)).unwrap();
            }
            Ok(Fired::Retry) => {}
            Err(error) => failures.push((calls.load(Ordering::SeqCst), error.to_string())),
        }
        assert!(calls.load(Ordering::SeqCst) <= 256);
        relay_only(&rig);
        rig.clock.advance(1_000);
        if failures.len() == 3 {
            break;
        }
    }
    assert!(
        rig.finished(&ticket.pack_id),
        "native accepted depth50; Scheduled stalled at {:?}, counted remote/R2 leaf requests {failures:?}",
        rig.job(&ticket.pack_id).unwrap().extraction
    );
    assert_eq!(rig.job(&ticket.pack_id).unwrap().outcome, None);
    assert_holder(&rig, object);
}

#[test]
fn a_corrupt_blob_chunk_cursor_fails_without_overflow_or_publication() {
    let rig = Rig::new();
    let (bytes, head) = tree_pack(1, 70_000);
    let (ticket, id) = rig.add(&bytes);
    assert!(rig.check(&[(&ticket, id)], head).is_err());
    let extension = TestExtraction::new(&rig);
    for _ in 0..300 {
        if rig
            .job(&ticket.pack_id)
            .unwrap()
            .extraction
            .is_some_and(|x| x.stage == 3)
        {
            break;
        }
        fire_pack(&rig, &extension, ticket.pack_id);
        relay_only(&rig);
        rig.clock.advance(1_000);
    }
    let key = keys::verify_job(&rig.repo.name, &ticket.pack_id);
    let raw = block_on(rig.store.get(&rig.source(), &key))
        .unwrap()
        .unwrap();
    let mut job = checkpoint::decode_job(&raw).unwrap();
    let x = job.extraction.as_mut().unwrap();
    assert_eq!(x.stage, 3);
    let object = x.object.unwrap();
    x.chunk = u32::MAX;
    let batch = checkpoint::write_job(
        Batch::new().require(Precondition::Equals(key, raw.clone())),
        &mut job,
        Some(&raw),
        &rig.repo.name,
        &ticket.pack_id,
    )
    .unwrap();
    block_on(rig.store.apply(&rig.source(), batch)).unwrap();
    tick(&rig, &extension, rig.store.as_ref(), false);
    assert_eq!(rig.job(&ticket.pack_id).unwrap().extraction, job.extraction);
    assert!(read_blob(&rig.blobs, &BlobKey::object(object)).is_none());
}
