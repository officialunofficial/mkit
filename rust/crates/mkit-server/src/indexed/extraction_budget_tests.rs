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
    calls: Option<Arc<AtomicU32>>,
}

impl PackWindows for CountWindows {
    fn read<'a>(
        &'a self,
        pack: &'a Hash,
        offset: u64,
        len: u64,
        etag: Option<&'a str>,
    ) -> BoxFuture<'a, Result<Window, WindowError>> {
        if let Some(calls) = &self.calls {
            calls.fetch_add(1, Ordering::SeqCst);
        }
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

#[allow(clippy::too_many_lines)] // One valid fixture isolates three faults at the same read boundary.
fn corrupt_frame_is_rejected_before_ranged_read(damage: BadFrame) {
    use crate::timers::{DueTimer, Fired, TimerCtx, TimerHandler};
    let mut rig = Rig::new();
    rig.cfg.extract_min_bytes = 8 << 20;
    let chunk = Object::Blob(Blob { data: vec![181] });
    let chunk_id = chunk.id().unwrap();
    let earlier_base = Object::Blob(Blob { data: vec![180] });
    let earlier_base_id = earlier_base.id().unwrap();
    let manifest = Object::ChunkedBlob(ChunkedBlob {
        total_size: 1,
        chunk_size: 0,
        chunks: vec![chunk_id],
    });
    let object = manifest.id().unwrap();
    let (tree, commit, head) = tree_head(&[object]);
    // The pack is larger than the entry/window allowance, while each current
    // producer's frame is individually valid and below the decoded limit.
    let objects = [earlier_base, chunk, manifest, tree, commit]
        .into_iter()
        .chain((0..20_u8).map(|i| {
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
        Some(&chunk_id),
    );
    let prior = block_on(rig.store.get(&rig.source(), &key))
        .unwrap()
        .unwrap();
    let mut frame = checkpoint::decode_frame(&chunk_id, &prior).unwrap();
    let decoded_limit =
        crate::indexed::geometry::decode_limits(rig.limits.resident_bytes, rig.limits.window_bytes)
            .max_decoded_bytes;
    match damage {
        BadFrame::Length => frame.value.frame_length = crate::indexed::geometry::FRAME_BYTES + 1,
        BadFrame::DecodedSize => frame.value.decoded_size = decoded_limit + 1,
        BadFrame::Depth => {
            frame.value.wire_type = 0x02;
            frame.value.delta_base = Some(earlier_base_id);
            frame.value.chain_depth = rig.cfg.max_delta_chain_depth + 1;
        }
    }
    assert!(frame.value.frame_offset + frame.value.frame_length < job.pack_len);
    assert_eq!(
        block_on(rig.store.apply(
            &rig.source(),
            Batch::new().put(key, checkpoint::encode_frame(&chunk_id, &frame).unwrap())
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
            calls: None,
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
    let mut rejected = false;
    for _ in 0..8 {
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
                assert_eq!(
                    block_on(rig.store.apply(&rig.source(), batch)).unwrap(),
                    BatchOutcome::Committed
                );
                if let Some(outcome) = rig.job(&ticket.pack_id).unwrap().outcome {
                    assert_eq!(outcome, checkpoint::Outcome::DecodeBudget);
                    rejected = true;
                    break;
                }
            }
            Err(StoreError::Corrupt(_)) => {
                rejected = true;
                break;
            }
            other => panic!("invalid source metadata did not fail closed: {other:?}"),
        }
        rig.clock.advance(1_000);
    }
    assert!(rejected, "invalid frame metadata was never rejected");
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

fn seed_fifty_cross_pack_member_deltas(rig: &Rig, payload_bytes: usize) -> Hash {
    seed_cross_pack_member_deltas(rig, payload_bytes, 50)
}

fn seed_cross_pack_member_deltas(rig: &Rig, payload_bytes: usize, depth: u16) -> Hash {
    let (mut base, mut prior) = blob(0, payload_bytes);
    seed_member(rig, base, &prior);
    for depth in 1..=depth {
        let (id, raw) = blob(depth, payload_bytes);
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
        let row = index_entries(&frames, rig.cfg.max_delta_chain_depth)
            .unwrap()
            .remove(0);
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

type CountedExtraction =
    VerifyTimer<Shared<CountReads>, CountBlobCalls, CountWindows, TestExtraction>;

fn counted_extraction(rig: &Rig, calls: Arc<AtomicU32>, pack: Hash) -> CountedExtraction {
    let h = extraction_handler(rig, TestExtraction::new(rig));
    VerifyTimer {
        remote: Shared(Arc::new(CountReads {
            inner: rig.store.clone(),
            job: keys::verify_job(&rig.repo.name, &pack),
            maximum: Mutex::default(),
            calls: calls.clone(),
        })),
        blobs: CountBlobCalls {
            inner: rig.blobs.clone(),
            calls: calls.clone(),
        },
        windows: CountWindows {
            inner: h.windows,
            maximum: Arc::default(),
            calls: Some(calls),
        },
        shards: h.shards,
        cfg: h.cfg,
        limits: h.limits,
        lease: h.lease,
        clock: h.clock,
        metrics: h.metrics,
        extension: h.extension,
    }
}

fn persisted_member_cursor(rig: &Rig, pack: Hash) -> serde_json::Value {
    let raw = block_on(
        rig.store
            .get(&rig.source(), &keys::verify_job(&rig.repo.name, &pack)),
    )
    .unwrap()
    .unwrap();
    let header: serde_json::Value = serde_json::from_slice(&raw.as_bytes()[1..]).unwrap();
    header
        .get("extraction")
        .and_then(|x| x.get("reconstruction"))
        .cloned()
        .unwrap_or(serde_json::Value::Null)
}

fn counted_fire_due(rig: &Rig, handler: &CountedExtraction, pack: Hash) -> Result<u64, StoreError> {
    use crate::timers::{DueTimer, Fired, TimerCtx, TimerHandler};
    let now = u64::try_from(rig.clock.now_ms()).unwrap();
    let fired = block_on(handler.fire(
        &TimerCtx {
            store: rig.store.as_ref(),
            partition: &rig.source(),
            now_ms: now,
        },
        &DueTimer {
            due_at_ms: now - 1,
            kind: crate::timers::registry::kinds::VERIFY,
            reference: Bytes::from(checkpoint::timer_reference(&rig.repo.name, &pack)),
            value: Value::default(),
        },
    ))?;
    let Fired::Reschedule {
        due_at_ms, batch, ..
    } = fired
    else {
        panic!("live verification must retain its timer")
    };
    assert_eq!(
        block_on(rig.store.apply(&rig.source(), batch))?,
        BatchOutcome::Committed
    );
    Ok(due_at_ms)
}

#[allow(clippy::too_many_lines)] // Native oracle, durable progress, restart and resource bounds share one valid fixture.
fn fifty_deep_member_chunk(payload_bytes: usize, window_bytes: u64, quota_shortfall: bool) {
    use crate::timers::{DueTimer, Fired, TimerCtx, TimerHandler};
    let mut native = Rig::new();
    native.limits.window_bytes = window_bytes;
    assert_eq!(native.cfg.max_delta_chain_depth, 50);
    let chunk = seed_fifty_cross_pack_member_deltas(&native, payload_bytes);
    let length = u64::try_from(payload_bytes).unwrap() + 2;
    let manifest = Object::ChunkedBlob(ChunkedBlob {
        // The shared blob fixture prepends its two-byte distinguishing tag.
        total_size: length,
        chunk_size: 0,
        chunks: vec![chunk],
    });
    let object = manifest.id().unwrap();
    let (tree, commit, head) = tree_head(&[object]);
    let objects = [manifest, tree, commit];
    let staged_bytes: u64 = objects
        .iter()
        .map(|o| u64::try_from(serialize(o).unwrap().len()).unwrap())
        .sum();
    let source_bytes: u64 = (0..=50)
        .map(|n| u64::try_from(blob(n, payload_bytes).1.len()).unwrap())
        .sum();
    let bytes = pack(&objects);
    native.cfg.max_pack_bytes = u64::try_from(payload_bytes).unwrap() + 1_000;
    native.cfg.max_extract_bytes = Some(source_bytes);
    native.cfg.decode_budget = staged_bytes + source_bytes - u64::from(quota_shortfall);
    let (ticket, id) = native.add(&bytes);
    let expected = block_on(crate::indexed::verify::verify_ticketed(
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
    ));
    if quota_shortfall {
        assert_eq!(
            expected.as_ref().unwrap_err().public_message(),
            "pack exceeds indexed decode budget"
        );
        assert!(read_blob(&native.blobs, &BlobKey::object(object)).is_none());
    } else {
        assert_eq!(expected.as_ref().unwrap().bytes, staged_bytes);
        assert_eq!(expected.as_ref().unwrap().objects, 3);
        assert_holder(&native, object);
        let Object::Blob(last_chunk) =
            mkit_core::serialize::deserialize(&blob(50, payload_bytes).1).unwrap()
        else {
            panic!("the member chain resolves a Blob");
        };
        assert_eq!(
            read_blob(&native.blobs, &BlobKey::object(object)),
            Some(last_chunk.data)
        );
        assert_eq!(
            read_blob(&native.blobs, &BlobKey::object_offsets(object)),
            Some(crate::indexed::extract::encode_offsets(&[0, length]))
        );
    }

    let mut rig = Rig::new();
    rig.limits.window_bytes = window_bytes;
    rig.cfg = native.cfg;
    assert_eq!(
        seed_fifty_cross_pack_member_deltas(&rig, payload_bytes),
        chunk
    );
    if payload_bytes == 250 << 10 {
        let entry_limit =
            crate::indexed::geometry::decode_limits(rig.limits.resident_bytes, window_bytes)
                .max_decoded_bytes;
        assert!(u64::try_from(blob(0, payload_bytes).1.len()).unwrap() < entry_limit);
        assert!(source_bytes > entry_limit && source_bytes > 12 << 20);
    }
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
    let mut handler = counted_extraction(&rig, calls.clone(), ticket.pack_id);
    rig.recorder.slices.lock().unwrap().clear();
    let mut failures = Vec::new();
    let mut total_calls = 0_u64;
    let mut progress_steps = 0;
    let mut restarted = false;
    for _ in 0..200 {
        if rig.finished(&ticket.pack_id) {
            break;
        }
        let before = rig.job(&ticket.pack_id).unwrap().extraction;
        let cursor_before = persisted_member_cursor(&rig, ticket.pack_id);
        let rows_before = rig.rows(&ticket.pack_id, keys::VC_CANDIDATE);
        calls.store(0, Ordering::SeqCst);
        let now = u64::try_from(rig.clock.now_ms()).unwrap();
        let fired = block_on(handler.fire(
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
        ));
        let succeeded = fired.is_ok();
        let due = match &fired {
            Ok(Fired::Reschedule { due_at_ms, .. }) => Some(*due_at_ms),
            _ => None,
        };
        match fired {
            Ok(Fired::Done(batch) | Fired::Reschedule { batch, .. }) => {
                assert_eq!(
                    block_on(rig.store.apply(&rig.source(), batch)).unwrap(),
                    BatchOutcome::Committed
                );
            }
            Ok(Fired::Retry) => {}
            Err(error) => failures.push((calls.load(Ordering::SeqCst), error.to_string())),
        }
        assert!(calls.load(Ordering::SeqCst) <= 256);
        let measured = u64::from(calls.load(Ordering::SeqCst));
        total_calls += measured;
        let charged = *rig.recorder.slices.lock().unwrap().last().unwrap();
        assert!(f64::from(calls.load(Ordering::SeqCst)) <= charged && charged <= 256.0);
        let after = rig.job(&ticket.pack_id).unwrap().extraction;
        let cursor_after = persisted_member_cursor(&rig, ticket.pack_id);
        if cursor_before.get("target").is_some()
            && cursor_before.get("target") == cursor_after.get("target")
            && cursor_before
                .get("ascending")
                .and_then(serde_json::Value::as_bool)
                == Some(false)
            && cursor_after
                .get("ascending")
                .and_then(serde_json::Value::as_bool)
                == Some(false)
        {
            assert!(
                cursor_after
                    .get("level")
                    .and_then(serde_json::Value::as_u64)
                    >= cursor_before
                        .get("level")
                        .and_then(serde_json::Value::as_u64),
                "restart must resume the saved chain prefix instead of resolving it again"
            );
        }
        if succeeded
            && before
                .as_ref()
                .is_some_and(|x| x.stage == 3 && x.chunk == 0 && x.written == 0)
            && after
                .as_ref()
                .is_some_and(|x| x.stage == 3 && x.chunk == 0 && x.written == 0)
        {
            assert_eq!(
                due,
                Some(now + 1),
                "durable source work must remain promptly due"
            );
            assert!(
                cursor_after != cursor_before
                    || rig.rows(&ticket.pack_id, keys::VC_CANDIDATE) != rows_before,
                "a source-resolution alarm must advance durable cursor or lookup state"
            );
            progress_steps += 1;
        }
        if !restarted
            && cursor_after
                .get("level")
                .and_then(serde_json::Value::as_u64)
                .is_some_and(|level| level >= 20)
            && cursor_after
                .get("ascending")
                .and_then(serde_json::Value::as_bool)
                == Some(false)
        {
            let key = keys::verify_job(&rig.repo.name, &ticket.pack_id);
            let saved = block_on(rig.store.get(&rig.source(), &key)).unwrap();
            let saved_rows = rig.rows(&ticket.pack_id, keys::VC_CANDIDATE);
            // Recreate all handler state over the same persisted storage.
            handler = counted_extraction(&rig, calls.clone(), ticket.pack_id);
            assert_eq!(block_on(rig.store.get(&rig.source(), &key)).unwrap(), saved);
            assert_eq!(rig.rows(&ticket.pack_id, keys::VC_CANDIDATE), saved_rows);
            restarted = true;
        }
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
    assert!(failures.is_empty());
    assert!(
        restarted,
        "the handler was recreated during the member-chain descent"
    );
    assert!(
        progress_steps >= 2,
        "member reconstruction must span durable alarms"
    );
    // For 51 nodes, allow two transitions per node at 32 charged calls each,
    // plus 256 calls for the remaining phases. Restart must reuse
    // saved work rather than replaying the already resolved chain prefix.
    let charged_total: f64 = rig.recorder.slices.lock().unwrap().iter().sum();
    assert!(
        charged_total > 256.0 && charged_total <= 3_520.0,
        "charged {charged_total} calls across alarms"
    );
    assert!(
        total_calls <= 3_520,
        "observed {total_calls} backend calls across alarms"
    );
    eprintln!(
        "depth50 {payload_bytes}-byte nodes: {progress_steps} durable steps, {total_calls} observed and {charged_total} charged calls"
    );
    if quota_shortfall {
        assert_eq!(
            rig.job(&ticket.pack_id).unwrap().outcome,
            Some(checkpoint::Outcome::DecodeBudget)
        );
        let actual = rig.check(&[(&ticket, id)], head).unwrap_err();
        let expected = expected.unwrap_err();
        assert_eq!(actual.code(), expected.code());
        assert_eq!(actual.public_message(), expected.public_message());
        assert!(read_blob(&rig.blobs, &BlobKey::object(object)).is_none());
        assert!(
            block_on(rig.store.get(
                &content_shard(&object),
                &keys::holder(&object, &rig.repo.namespace, &rig.repo.name).unwrap()
            ))
            .unwrap()
            .is_none()
        );
    } else {
        assert_eq!(rig.job(&ticket.pack_id).unwrap().outcome, None);
        assert_eq!(
            rig.check(&[(&ticket, id)], head).unwrap(),
            expected.unwrap()
        );
        for key in [BlobKey::object(object), BlobKey::object_offsets(object)] {
            assert_eq!(read_blob(&rig.blobs, &key), read_blob(&native.blobs, &key));
        }
        assert_holder(&rig, object);
    }
}

#[test]
fn a_valid_fifty_deep_member_chunk_finishes_under_the_default_alarm_budget() {
    fifty_deep_member_chunk(2_000, WINDOW, false);
}

#[test]
fn a_valid_fifty_deep_member_chunk_exceeding_one_entrys_memory_finishes() {
    fifty_deep_member_chunk(250 << 10, 16 << 20, false);
}

#[test]
fn a_fifty_deep_member_chunk_matches_native_at_the_whole_source_quota_boundary() {
    fifty_deep_member_chunk(250 << 10, 16 << 20, true);
}

fn on_small_stack(check: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(512 << 10)
        .spawn(check)
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn fifty_deep_quota_boundary_uses_a_small_stack() {
    on_small_stack(|| fifty_deep_member_chunk(250 << 10, 16 << 20, true));
}

fn member_chain_matches_native(depth: u16) {
    let mut reference = Rig::new();
    reference.cfg.max_delta_chain_depth = u32::from(depth);
    reference.cfg.extract_min_bytes = 1;
    let chunk = seed_cross_pack_member_deltas(&reference, 2_000, depth);
    let manifest = Object::ChunkedBlob(ChunkedBlob {
        total_size: 2_002,
        chunk_size: 0,
        chunks: vec![chunk],
    });
    let object = manifest.id().unwrap();
    let (tree, commit, head) = tree_head(&[object]);
    let bytes = pack(&[manifest, tree, commit]);
    let ticket = reference.add(&bytes);
    let expected = native(&reference, &[ticket], head);

    let mut scheduled = Rig::new();
    scheduled.cfg = reference.cfg;
    assert_eq!(
        seed_cross_pack_member_deltas(&scheduled, 2_000, depth),
        chunk
    );
    let (ticket, id) = scheduled.add(&bytes);
    assert!(scheduled.check(&[(&ticket, id)], head).is_err());
    drive(
        &scheduled,
        &TestExtraction::new(&scheduled),
        &[ticket.pack_id],
    );
    assert_eq!(scheduled.check(&[(&ticket, id)], head).unwrap(), expected);
    for key in [BlobKey::object(object), BlobKey::object_offsets(object)] {
        assert_eq!(
            read_blob(&scheduled.blobs, &key),
            read_blob(&reference.blobs, &key)
        );
    }
    assert_holder(&scheduled, object);
}

#[test]
fn depth_one_member_chain_matches_native() {
    member_chain_matches_native(1);
}

#[test]
fn maximum_configured_member_chain_matches_native_on_a_small_stack() {
    on_small_stack(|| {
        let maximum = IndexedConfig::default().max_delta_chain_depth;
        assert_eq!(maximum, 50);
        member_chain_matches_native(u16::try_from(maximum).unwrap());
        // The bound is configured, rather than hard-coded to the default.
        member_chain_matches_native(64);
    });
}

fn lower_order_forty_nine_hop_pack(before: Hash) -> Vec<u8> {
    let nodes: Vec<_> = (0..=49).map(|n| blob(n, 2_000)).collect();
    let deltas: Vec<_> = nodes
        .windows(2)
        .map(|pair| mkit_core::delta::encode(&pair[0].1, &pair[1].1).unwrap())
        .collect();
    for nonce in 1_000..10_000 {
        let mut writer = PackWriter::new();
        writer.push_raw(nodes[0].0, &nodes[0].1).unwrap();
        for (base, delta) in nodes.iter().zip(&deltas) {
            writer.push_delta(&base.0, delta).unwrap();
        }
        let (salt, canonical) = blob(nonce, 0);
        writer.push_raw(salt, &canonical).unwrap();
        let bytes = writer.finish().unwrap();
        if hash(&bytes) < before {
            return bytes;
        }
    }
    panic!("could not find a lower-order current-producer member pack");
}

fn publish_member_pack(rig: &Rig, bytes: &[u8]) -> Hash {
    let (ticket, _) = rig.add(bytes);
    let mut frames = Vec::new();
    decode_entries_with(
        bytes,
        &mut OneBase([0; 32], Vec::new()),
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
    let mut batch = Batch::new().put(
        keys::membership(&rig.repo.name, &ticket.pack_id),
        Value::default(),
    );
    for entry in index_entries(&frames, 50).unwrap() {
        batch = batch.put(
            keys::object_index(&rig.repo.name, &entry.object, &ticket.pack_id),
            codec::encode_object_index(&entry.object, &entry.value).unwrap(),
        );
    }
    block_on(rig.store.apply(&rig.source(), batch)).unwrap();
    ticket.pack_id
}

fn seed_one_thin_member(rig: &Rig, base: Hash, canonical_base: Vec<u8>, target: &[u8]) -> Hash {
    let bytes = thin(base, &canonical_base, target);
    let (ticket, _) = rig.add(&bytes);
    let mut frames = Vec::new();
    decode_entries_with(
        &bytes,
        &mut OneBase(base, canonical_base),
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
    let entry = index_entries(&frames, 50).unwrap().remove(0);
    block_on(
        rig.store.apply(
            &rig.source(),
            Batch::new()
                .put(
                    keys::membership(&rig.repo.name, &ticket.pack_id),
                    Value::default(),
                )
                .put(
                    keys::object_index(&rig.repo.name, &entry.object, &ticket.pack_id),
                    codec::encode_object_index(&entry.object, &entry.value).unwrap(),
                ),
        ),
    )
    .unwrap();
    ticket.pack_id
}

#[test]
fn a_thin_member_blob_with_a_tree_base_matches_native_identity_and_offsets() {
    let leaf = Object::Blob(Blob { data: vec![57] });
    let base = Object::Tree(Tree {
        entries: vec![TreeEntry {
            name: b"base".to_vec(),
            mode: EntryMode::Blob,
            object_hash: leaf.id().unwrap(),
        }],
    });
    let base_id = base.id().unwrap();
    let canonical_base = serialize(&base).unwrap();
    assert_ne!(hash(&canonical_base), base_id);
    let data = vec![61; 2_000];
    let chunk = Object::Blob(Blob { data: data.clone() });
    let canonical_chunk = serialize(&chunk).unwrap();
    let manifest = Object::ChunkedBlob(ChunkedBlob {
        total_size: u64::try_from(data.len()).unwrap(),
        chunk_size: 0,
        chunks: vec![chunk.id().unwrap()],
    });
    let object = manifest.id().unwrap();
    let (tree, commit, head) = tree_head(&[object]);
    let bytes = pack(&[manifest, tree, commit]);
    let scheduled = Rig::new();
    let oracle = Rig::new();
    for rig in [&scheduled, &oracle] {
        seed_member(rig, leaf.id().unwrap(), &serialize(&leaf).unwrap());
        seed_member(rig, base_id, &canonical_base);
        seed_one_thin_member(rig, base_id, canonical_base.clone(), &canonical_chunk);
    }
    let native_ticket = oracle.add(&bytes);
    let expected = native(&oracle, &[native_ticket], head);
    let ticket = scheduled.add(&bytes);
    assert!(scheduled.check(&[(&ticket.0, ticket.1)], head).is_err());
    let extension = TestExtraction::new(&scheduled);
    drive(&scheduled, &extension, &[ticket.0.pack_id]);
    assert_eq!(
        scheduled.check(&[(&ticket.0, ticket.1)], head).unwrap(),
        expected
    );
    assert_eq!(
        read_blob(&scheduled.blobs, &BlobKey::object(object)),
        Some(data)
    );
    assert_eq!(
        read_blob(&scheduled.blobs, &BlobKey::object_offsets(object)),
        Some(crate::indexed::extract::encode_offsets(&[0, 2_000]))
    );
    for key in [BlobKey::object(object), BlobKey::object_offsets(object)] {
        assert_eq!(
            read_blob(&scheduled.blobs, &key),
            read_blob(&oracle.blobs, &key)
        );
    }
    assert_holder(&scheduled, object);
}

#[test]
#[allow(clippy::too_many_lines)] // Bounded emit and immediate full-scan progress share native success/error oracles.
fn a_large_single_pack_emits_within_budget_and_reschedules_metadata_progress_immediately() {
    let mut objects = (0..720_u16)
        .map(|i| {
            Object::Blob(Blob {
                data: i.to_be_bytes().to_vec(),
            })
        })
        .collect::<Vec<_>>();
    let ids = objects
        .iter()
        .map(|object| object.id().unwrap())
        .collect::<Vec<_>>();
    let tree = Object::Tree(Tree {
        entries: ids
            .iter()
            .enumerate()
            .map(|(i, id)| TreeEntry {
                name: format!("f{i:03}").into_bytes(),
                mode: EntryMode::Blob,
                object_hash: *id,
            })
            .collect(),
    });
    let (commit, head) = signed_commit(tree.id().unwrap(), Vec::new(), 7, b"no extraction");
    objects.extend([tree, commit]);
    let bytes = pack(&objects);
    let rig = Rig::new();
    let oracle = Rig::new();
    let ticket = rig.add(&bytes);
    let oracle_ticket = oracle.add(&bytes);
    let expected = native(&oracle, std::slice::from_ref(&oracle_ticket), head);
    assert_eq!(expected.objects, 722);
    assert!(rig.check(&[(&ticket.0, ticket.1)], head).is_err());
    let extension = TestExtraction::new(&rig);
    let calls = Arc::new(AtomicU32::new(0));
    let handler = counted_extraction(&rig, calls.clone(), ticket.0.pack_id);
    let mut emitted = 0;
    for _ in 0..1_000 {
        if rig.job(&ticket.0.pack_id).unwrap().phase == Phase::Extract {
            break;
        }
        let phase = rig.job(&ticket.0.pack_id).unwrap().phase;
        calls.store(0, Ordering::SeqCst);
        counted_fire_due(&rig, &handler, ticket.0.pack_id).unwrap_or_else(|error| {
            panic!(
                "{phase:?}: {error}; {} actual calls",
                calls.load(Ordering::SeqCst)
            )
        });
        assert!(calls.load(Ordering::SeqCst) <= 256);
        if phase == Phase::EmitIndex {
            emitted += 1;
        }
        relay_only(&rig);
        rig.clock.advance(1);
    }
    assert!(
        emitted >= 6,
        "722 actual index rows must emit across bounded pages"
    );
    let before = rig.job(&ticket.0.pack_id).unwrap();
    assert_eq!(before.phase, Phase::Extract);
    assert!(!before.extract_needed);
    assert_eq!(before.extraction_group.len(), 1);
    assert!(before.extraction.is_none());
    let now = u64::try_from(rig.clock.now_ms()).unwrap();
    assert_eq!(
        counted_fire_due(&rig, &handler, ticket.0.pack_id).unwrap(),
        now
    );
    let after = rig.job(&ticket.0.pack_id).unwrap();
    assert_eq!(after.phase, Phase::Extract);
    assert!(after.extraction.is_some());
    // Full scan, closure and selection each visit every producer object once.
    let progress_bound = 3 * objects.len() + 128;
    for _ in 0..progress_bound {
        let before = rig.job(&ticket.0.pack_id).unwrap();
        if before.phase != Phase::Extract {
            break;
        }
        let now = u64::try_from(rig.clock.now_ms()).unwrap();
        calls.store(0, Ordering::SeqCst);
        assert_eq!(
            counted_fire_due(&rig, &handler, ticket.0.pack_id).unwrap(),
            now
        );
        assert!(calls.load(Ordering::SeqCst) <= 256);
        let after = rig.job(&ticket.0.pack_id).unwrap();
        assert!(after.extraction != before.extraction || after.phase != before.phase);
        rig.clock.advance(1);
    }
    assert!(matches!(
        rig.job(&ticket.0.pack_id).unwrap().phase,
        Phase::Verify | Phase::Recheck | Phase::Watch
    ));
    assert_eq!(rig.job(&ticket.0.pack_id).unwrap().outcome, None);
    for id in &ids {
        assert_no_extraction_effects(&rig, &extension, *id);
        assert!(read_blob(&rig.blobs, &BlobKey::object_offsets(*id)).is_none());
    }
    drive(&rig, &extension, &[ticket.0.pack_id]);
    assert_eq!(rig.check(&[(&ticket.0, ticket.1)], head).unwrap(), expected);
    let bad_head = [233; 32];
    let within_lag = rig.check(&[(&ticket.0, ticket.1)], bad_head).unwrap_err();
    assert_eq!(within_lag.code(), crate::Code::Unavailable);
    // Prompt metadata work must retain the existing repository-membership lag.
    rig.clock
        .advance(i64::try_from(rig.cfg.relay_lag_bound_ms).unwrap() + 1);
    let scheduled_error = rig.check(&[(&ticket.0, ticket.1)], bad_head).unwrap_err();
    oracle
        .clock
        .advance(rig.clock.now_ms() - oracle.clock.now_ms());
    let native_error = block_on(crate::indexed::verify::verify_ticketed(
        oracle.blobs.as_ref(),
        oracle.store.as_ref(),
        oracle.shards.as_ref(),
        &oracle.repo,
        &oracle.source(),
        std::slice::from_ref(&oracle_ticket.0),
        &[oracle_ticket.1],
        bad_head,
        oracle.cfg,
        oracle.clock.as_ref(),
        oracle.recorder.as_ref(),
    ))
    .unwrap_err();
    assert_eq!(scheduled_error.code(), native_error.code());
    assert_eq!(scheduled_error.code(), crate::Code::InvalidArgument);
}

#[test]
fn queued_holder_delivery_waits_while_successful_metadata_work_is_immediate() {
    let rig = Rig::new();
    let (bytes, head) = tree_pack(1, 70_000);
    let (ticket, ticket_id) = rig.add(&bytes);
    assert!(rig.check(&[(&ticket, ticket_id)], head).is_err());
    let extension = TestExtraction::new(&rig);
    for _ in 0..300 {
        fire_pack(&rig, &extension, ticket.pack_id);
        if rig
            .job(&ticket.pack_id)
            .unwrap()
            .extraction
            .is_some_and(|x| x.stage == 9)
        {
            break;
        }
        relay_only(&rig);
        rig.clock.advance(1);
    }
    let before = rig.job(&ticket.pack_id).unwrap().extraction.unwrap();
    assert_eq!(before.stage, 9);
    assert!(before.relay.is_some());
    let object = before.object.unwrap();
    assert!(
        block_on(rig.store.get(
            &content_shard(&object),
            &keys::holder(&object, &rig.repo.namespace, &rig.repo.name).unwrap(),
        ))
        .unwrap()
        .is_none()
    );
    let calls = Arc::new(AtomicU32::new(0));
    let handler = counted_extraction(&rig, calls.clone(), ticket.pack_id);
    let now = u64::try_from(rig.clock.now_ms()).unwrap();
    assert_eq!(
        counted_fire_due(&rig, &handler, ticket.pack_id).unwrap(),
        now + 1_000
    );
    assert_eq!(rig.job(&ticket.pack_id).unwrap().extraction, Some(before));
    assert!(calls.load(Ordering::SeqCst) <= 256);
    let content = ContentIndex::new(crate::store::BorrowedStore(rig.store.as_ref()));
    assert!(
        block_on(content.collectable(&object, now, 0))
            .unwrap()
            .is_none()
    );
    relay_only(&rig);
    assert_holder(&rig, object);
    rig.clock.advance(1_000);
    let now = u64::try_from(rig.clock.now_ms()).unwrap();
    assert_eq!(
        counted_fire_due(&rig, &handler, ticket.pack_id).unwrap(),
        now
    );
    let after = rig.job(&ticket.pack_id).unwrap().extraction.unwrap();
    assert_eq!(after.stage, 2);
    assert!(after.object.is_none());
    drive(&rig, &extension, &[ticket.pack_id]);
    rig.check(&[(&ticket, ticket_id)], head).unwrap();
}

#[test]
#[allow(clippy::too_many_lines)] // Live and restored denial identities share frozen-source and IO observations.
fn a_denial_after_source_descent_prevents_chunk_and_ancestor_reads() {
    use crate::timers::{DueTimer, Fired, TimerCtx, TimerHandler};
    for (ancestor, deny_pack, restored) in [
        (false, false, false),
        (false, true, false),
        (true, false, false),
        (true, true, false),
        (true, false, true),
        (true, true, true),
    ] {
        let rig = Rig::new();
        let (base, canonical_base) = blob(0, 2_000);
        seed_member(&rig, base, &canonical_base);
        let mut writer = PackWriter::new_raw_only();
        writer.push_raw(base, &canonical_base).unwrap();
        let base_pack = hash(&writer.finish().unwrap());
        let chunk = if ancestor {
            let (target, canonical) = blob(1, 2_000);
            seed_one_thin_member(&rig, base, canonical_base, &canonical);
            target
        } else {
            base
        };
        let manifest = Object::ChunkedBlob(ChunkedBlob {
            total_size: 2_002,
            chunk_size: 0,
            chunks: vec![chunk],
        });
        let object = manifest.id().unwrap();
        let (tree, commit, head) = tree_head(&[object]);
        let (ticket, id) = rig.add(&pack(&[manifest, tree, commit]));
        assert!(rig.check(&[(&ticket, id)], head).is_err());
        let extension = TestExtraction::new(&rig);
        for _ in 0..200 {
            let cursor = persisted_member_cursor(&rig, ticket.pack_id);
            if cursor.get("ascending").and_then(serde_json::Value::as_bool) == Some(true)
                && (!restored
                    || cursor
                        .get("canonical")
                        .is_some_and(|value| !value.is_null()))
            {
                assert_eq!(
                    cursor.get("level").and_then(serde_json::Value::as_u64),
                    Some(u64::from(ancestor && !restored))
                );
                if restored {
                    assert_eq!(
                        cursor.get("canonical").unwrap()[0],
                        serde_json::to_value(base).unwrap()
                    );
                    let group = rig.job(&ticket.pack_id).unwrap().extraction.unwrap().group;
                    let mut digest = mkit_core::hash::Hasher::new();
                    for bytes in [
                        b"mkit-extraction-row:v1".as_slice(),
                        b"member-bytes".as_slice(),
                        group.as_slice(),
                        base.as_slice(),
                        0_u32.to_be_bytes().as_slice(),
                    ] {
                        digest.update(bytes);
                    }
                    let key = keys::verify_row(
                        &rig.repo.name,
                        &ticket.pack_id,
                        keys::VC_CANDIDATE,
                        Some(&digest.finalize()),
                    );
                    let raw = block_on(rig.store.get(&rig.source(), &key))
                        .unwrap()
                        .unwrap();
                    assert_eq!(raw.as_bytes(), blob(0, 2_000).1);
                }
                break;
            }
            fire_pack(&rig, &extension, ticket.pack_id);
            relay_only(&rig);
            rig.clock.advance(1_000);
        }
        assert_eq!(
            persisted_member_cursor(&rig, ticket.pack_id)
                .get("ascending")
                .and_then(serde_json::Value::as_bool),
            Some(true)
        );
        let denied = if deny_pack { base_pack } else { base };
        let now = u64::try_from(rig.clock.now_ms()).unwrap();
        block_on(
            ContentIndex::new(crate::store::BorrowedStore(rig.store.as_ref())).block(
                &denied,
                &crate::store::BlockEntry::new("manual", now),
                now,
            ),
        )
        .unwrap();
        let error = block_on(crate::takedown::denial::require_clear(
            rig.store.as_ref(),
            &denied,
        ))
        .unwrap_err();
        assert_eq!(error.code(), crate::Code::PermissionDenied);
        let reads = Arc::new(AtomicU32::new(0));
        let h = extraction_handler(&rig, extension);
        let handler = VerifyTimer {
            blobs: CountBlobCalls {
                inner: rig.blobs.clone(),
                calls: reads.clone(),
            },
            remote: h.remote,
            windows: h.windows,
            shards: h.shards,
            cfg: h.cfg,
            limits: h.limits,
            lease: h.lease,
            clock: h.clock,
            metrics: h.metrics,
            extension: h.extension,
        };
        for _ in 0..8 {
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
            ))
            .unwrap()
            {
                Fired::Done(batch) | Fired::Reschedule { batch, .. } => assert_eq!(
                    block_on(rig.store.apply(&rig.source(), batch)).unwrap(),
                    BatchOutcome::Committed
                ),
                Fired::Retry => panic!("denial must become a definite blocked outcome"),
            }
            if rig.job(&ticket.pack_id).unwrap().outcome.is_some() {
                break;
            }
            rig.clock.advance(1_000);
        }
        assert_eq!(
            rig.job(&ticket.pack_id).unwrap().outcome,
            Some(checkpoint::Outcome::Blocked),
            "ancestor {ancestor}, pack denial {deny_pack}, restored {restored}"
        );
        assert_eq!(
            reads.load(Ordering::SeqCst),
            0,
            "denied source was read before denial admission"
        );
        assert!(read_blob(&rig.blobs, &BlobKey::object(object)).is_none());
        assert_eq!(
            rig.check(&[(&ticket, id)], head).unwrap_err().code(),
            crate::Code::PermissionDenied
        );
    }
}

#[test]
#[allow(clippy::too_many_lines)] // The late source change, native oracle and restarted alarms form one race regression.
fn a_staged_thin_chunk_resumes_when_its_member_base_changes_after_decode() {
    use crate::timers::{DueTimer, Fired, TimerCtx, TimerHandler};
    let (base, canonical_base) = blob(49, 2_000);
    let (chunk, canonical_chunk) = blob(50, 2_000);
    let mut raw_writer = PackWriter::new_raw_only();
    raw_writer.push_raw(base, &canonical_base).unwrap();
    let raw_pack = hash(&raw_writer.finish().unwrap());
    let later = lower_order_forty_nine_hop_pack(raw_pack);
    let manifest = Object::ChunkedBlob(ChunkedBlob {
        total_size: 2_002,
        chunk_size: 0,
        chunks: vec![chunk],
    });
    let object = manifest.id().unwrap();
    let (tree, commit, head) = tree_head(&[object]);
    let consumed = [
        thin(base, &canonical_base, &canonical_chunk),
        pack(&[manifest, tree, commit]),
    ];
    let rig = Rig::new();
    seed_member(&rig, base, &canonical_base);
    let tickets = consumed
        .iter()
        .map(|bytes| rig.add(bytes))
        .collect::<Vec<_>>();
    let items = tickets.iter().map(|(t, id)| (t, *id)).collect::<Vec<_>>();
    assert!(rig.check(&items, head).is_err());
    let extension = TestExtraction::new(&rig);
    for _ in 0..100 {
        if tickets
            .iter()
            .all(|(t, _)| rig.job(&t.pack_id).unwrap().phase == Phase::Extract)
        {
            break;
        }
        tick(&rig, &extension, rig.store.as_ref(), true);
        rig.clock.advance(1_000);
    }
    assert!(
        tickets
            .iter()
            .all(|(t, _)| rig.job(&t.pack_id).unwrap().phase == Phase::Extract)
    );
    assert!(read_blob(&rig.blobs, &BlobKey::object(object)).is_none());
    let later_pack = publish_member_pack(&rig, &later);
    assert!(later_pack < raw_pack);
    let chosen = block_on(crate::indexed::resolve::locate_split(
        rig.store.as_ref(),
        rig.shards.as_ref(),
        &rig.repo,
        &[base],
        rig.recorder.as_ref(),
    ))
    .unwrap();
    assert_eq!(
        chosen[&base].as_ref().unwrap().as_ref().unwrap().pack,
        later_pack
    );
    assert_eq!(
        chosen[&base]
            .as_ref()
            .unwrap()
            .as_ref()
            .unwrap()
            .value
            .chain_depth,
        49
    );

    let oracle = Rig::new();
    seed_member(&oracle, base, &canonical_base);
    publish_member_pack(&oracle, &later);
    let oracle_tickets = consumed
        .iter()
        .map(|bytes| oracle.add(bytes))
        .collect::<Vec<_>>();
    let expected = native(&oracle, &oracle_tickets, head);
    let Object::Blob(blob) = mkit_core::serialize::deserialize(&canonical_chunk).unwrap() else {
        panic!("expected Blob")
    };
    assert_eq!(
        read_blob(&oracle.blobs, &BlobKey::object(object)),
        Some(blob.data)
    );
    let owner = tickets[1].0.pack_id;
    let calls = Arc::new(AtomicU32::new(0));
    let mut handler = counted_extraction(&rig, calls.clone(), owner);
    let mut restarted = false;
    let mut total = 0_u64;
    let mut failures = Vec::new();
    for _ in 0..200 {
        if rig.finished(&owner) {
            break;
        }
        calls.store(0, Ordering::SeqCst);
        let now = u64::try_from(rig.clock.now_ms()).unwrap();
        let fired = block_on(handler.fire(
            &TimerCtx {
                store: rig.store.as_ref(),
                partition: &rig.source(),
                now_ms: now,
            },
            &DueTimer {
                due_at_ms: now,
                kind: crate::timers::registry::kinds::VERIFY,
                reference: Bytes::from(checkpoint::timer_reference(&rig.repo.name, &owner)),
                value: Value::default(),
            },
        ));
        match fired {
            Ok(Fired::Done(batch) | Fired::Reschedule { batch, .. }) => assert_eq!(
                block_on(rig.store.apply(&rig.source(), batch)).unwrap(),
                BatchOutcome::Committed
            ),
            Ok(Fired::Retry) => {}
            Err(error) => failures.push((calls.load(Ordering::SeqCst), error.to_string())),
        }
        let used = calls.load(Ordering::SeqCst);
        assert!(used <= 256);
        total += u64::from(used);
        let cursor = persisted_member_cursor(&rig, owner);
        if !restarted
            && cursor.get("target") == Some(&serde_json::to_value(chunk).unwrap())
            && cursor
                .get("level")
                .and_then(serde_json::Value::as_u64)
                .is_some_and(|level| level >= 20)
        {
            let before = rig.rows(&owner, keys::VC_CANDIDATE);
            handler = counted_extraction(&rig, calls.clone(), owner);
            assert_eq!(rig.rows(&owner, keys::VC_CANDIDATE), before);
            restarted = true;
        }
        relay_only(&rig);
        rig.clock.advance(1_000);
        if failures.len() == 3 {
            break;
        }
    }
    assert!(
        rig.finished(&owner),
        "staged thin source stalled after member changed: {failures:?}"
    );
    assert!(failures.is_empty());
    assert!(
        restarted,
        "staged reconstruction must resume a durable descent after restart"
    );
    assert!(
        total > 256 && total <= 3_520,
        "observed {total} backend calls"
    );
    drive(&rig, &extension, &[tickets[0].0.pack_id, owner]);
    let actual = rig.check(&items, head).unwrap();
    assert_eq!(actual.objects, expected.objects);
    assert_eq!(actual.bytes, expected.bytes);
    assert_eq!(actual.parents, expected.parents);
    // Decode's dependency snapshot was taken before the new member arrived.
    assert_eq!(
        actual.external_bases,
        std::collections::BTreeSet::from([raw_pack])
    );
    assert_eq!(
        expected.external_bases,
        std::collections::BTreeSet::from([later_pack])
    );
    for key in [BlobKey::object(object), BlobKey::object_offsets(object)] {
        assert_eq!(read_blob(&rig.blobs, &key), read_blob(&oracle.blobs, &key));
    }
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
