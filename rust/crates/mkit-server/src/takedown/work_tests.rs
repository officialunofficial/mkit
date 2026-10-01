#![allow(clippy::unwrap_used)]
use super::*;
use crate::admin::{AdminOperations, TAKEDOWN_PATH};
use crate::pipeline::SinglePartition;
use crate::store::{BorrowedStore, codec, index::IndexValue, keys};
use crate::{
    BatchOutcome, ManualClock, MemoryBlobStore, MemoryKv, NamespaceKey, PackSink, RepoName,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use mkit_core::{
    hash::hash,
    object::{Blob, ChunkedBlob, Object},
    serialize::serialize,
};
use serde_json::json;

type Runtime = Work<Arc<MemoryKv>, MemoryBlobStore, MemoryBlobStore>;
struct Fixture {
    work: Runtime,
    clock: Arc<ManualClock>,
    repo: RepoId,
    canonical: Vec<(Hash, Vec<u8>)>,
    pack: Hash,
}
async fn fixture(objects: &[Object], any: bool) -> Fixture {
    fixture_with_delta(objects, any, 0).await
}
async fn fixture_with_delta(objects: &[Object], any: bool, delta_wire: u8) -> Fixture {
    fixture_delta_encoding(objects, any, delta_wire, false).await
}
#[allow(
    clippy::too_many_lines,
    reason = "Build verified raw and compressed delta sources."
)]
async fn fixture_delta_encoding(
    objects: &[Object],
    any: bool,
    delta_wire: u8,
    literal_delta: bool,
) -> Fixture {
    let clock = Arc::new(ManualClock::new(10));
    let metadata = Arc::new(MemoryKv::with_clock(clock.clone()));
    let serving = MemoryBlobStore::default();
    let repo = RepoId {
        namespace: NamespaceKey::from_stored("0x1111111111111111111111111111111111111111".into()),
        name: RepoName::new("repo").unwrap(),
    };
    let mut packed = b"MKIT\x01\0\0\0\0\0\0\0".to_vec();
    if delta_wire == 4 {
        packed[4] = 2;
    }
    let mut canonical = vec![];
    let mut frames = Vec::new();
    for (index, object) in objects.iter().enumerate() {
        let bytes = serialize(object).unwrap();
        let id = match object {
            Object::ChunkedBlob(cb) => mkit_core::merkle::compute_chunked_id(cb),
            _ => hash(&bytes),
        };
        let (wire, payload, base) = if delta_wire != 0 && index == 1 {
            let (base, canonical): &(Hash, Vec<u8>) = &canonical[0];
            let delta = if literal_delta {
                let mut stream = vec![mkit_core::delta::STREAM_VERSION];
                stream.extend_from_slice(&u32::try_from(canonical.len()).unwrap().to_le_bytes());
                stream.extend_from_slice(&u32::try_from(bytes.len()).unwrap().to_le_bytes());
                for byte in &bytes {
                    stream.extend_from_slice(&[1, *byte]);
                }
                stream
            } else {
                mkit_core::delta::encode(canonical, &bytes).unwrap()
            };
            let delta = if delta_wire == 4 {
                let mut zstd = vec![0x28, 0xb5, 0x2f, 0xfd, 0, 0x68];
                let block = (u32::try_from(delta.len()).unwrap() << 3) | 1;
                zstd.extend_from_slice(&block.to_le_bytes()[..3]);
                zstd.extend_from_slice(&delta);
                [
                    u32::try_from(delta.len()).unwrap().to_le_bytes().as_slice(),
                    &zstd,
                ]
                .concat()
            } else {
                delta
            };
            (delta_wire, [base.as_slice(), &delta].concat(), Some(*base))
        } else {
            (0, bytes.clone(), None)
        };
        packed.push(wire);
        packed.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_le_bytes());
        packed.extend_from_slice(&payload);
        frames.push((wire, payload.len() as u64 + 5, base));
        canonical.push((id, bytes));
    }
    packed[8..12].copy_from_slice(&u32::try_from(objects.len()).unwrap().to_le_bytes());
    let trailer = hash(&packed);
    packed.extend_from_slice(&trailer);
    let bytes = packed;
    let pack = hash(&bytes);
    let mut sink = serving
        .begin(BlobKey::pack(pack), bytes.len() as u64)
        .await
        .unwrap();
    for chunk in bytes.chunks(crate::store::MAX_BLOB_PIECE_BYTES) {
        sink.write(Bytes::copy_from_slice(chunk)).await.unwrap();
    }
    sink.commit().await.unwrap();
    let mut offset = 12u64;
    let mut batch = Batch::new().put(keys::membership(&repo.name, &pack), Value::default());
    for (((id, canonical), object), (wire, length, base)) in
        canonical.iter().zip(objects).zip(frames)
    {
        let value = IndexValue {
            frame_offset: offset,
            frame_length: length,
            wire_type: wire,
            decoded_size: canonical.len() as u64,
            chain_depth: u32::from(base.is_some()),
            delta_base: base,
        };
        batch = batch.put(
            keys::object_index(&repo.name, id, &pack),
            codec::encode_object_index(id, &value).unwrap(),
        );
        offset += value.frame_length;
        inventory::stage(&metadata, &pack, bytes.len() as u64, id, object, None, 10)
            .await
            .unwrap();
    }
    inventory::complete(&metadata, &pack, bytes.len() as u64, 10)
        .await
        .unwrap();
    assert_eq!(
        metadata
            .apply(
                &SinglePartition.membership(&repo, &BlobKey::pack(pack)),
                batch
            )
            .await
            .unwrap(),
        BatchOutcome::Committed
    );
    // Namespace sharding still uses its repository registry under Multi addressing.
    metadata
        .apply(
            &Partition::Namespace(repo.namespace.clone()),
            Batch::new().put(
                keys::repo_record(&repo.name),
                codec::encode_repo_record(&codec::RepoRecord { created_at_ms: 10 }),
            ),
        )
        .await
        .unwrap();
    let policy = if any {
        crate::policy::NamespacePolicy::Any {
            unsafe_without_admission: true,
        }
    } else {
        crate::policy::NamespacePolicy::Allowlist(std::collections::BTreeSet::from([
            mkit_core::repo_identity::Namespace::parse(repo.namespace.as_str()).unwrap(),
        ]))
    };
    let work = Work {
        purge: None,
        metadata,
        serving,
        preserved: MemoryBlobStore::default(),
        root: Partition::Namespace(NamespaceKey::deployment_default()),
        shards: Arc::new(SinglePartition),
        addressing: Addressing::Multi(
            crate::repo::MultiAddressing::new().with_namespace_policy(policy),
        ),
        retention_ms: 1_000_000,
        discovery_margin_ms: 5000,
        profile: acquisition::Profile::scheduled(),
        clock: clock.clone(),
    };
    Fixture {
        work,
        clock,
        repo,
        canonical,
        pack,
    }
}
async fn accept(f: &Fixture, operation: &str, pack: Option<Hash>, objects: &[Hash]) -> Hash {
    let input = if let Some(pack) = pack {
        json!({"repository":format!("{}/{}",f.repo.namespace.as_str(),f.repo.name.as_str()),"packId":STANDARD.encode(pack),"operationId":operation,"reason":"test moderation"})
    } else {
        json!({"repository":format!("{}/{}",f.repo.namespace.as_str(),f.repo.name.as_str()),"objectIds":objects.iter().map(|id|STANDARD.encode(id)).collect::<Vec<_>>(),"operationId":operation,"reason":"test moderation"})
    };
    let service = Service::new(
        f.work.metadata.clone(),
        f.work.root.clone(),
        f.work.shards.clone(),
    )
    .with_purge(f.work.purge.clone());
    let budget = SliceBudget::new(9000);
    let prepared = service
        .plan(TAKEDOWN_PATH, &input, operation, 10, &budget)
        .await
        .unwrap();
    f.work
        .metadata
        .apply(&f.work.root, prepared.batch)
        .await
        .unwrap();
    let response = service
        .after_commit(TAKEDOWN_PATH, &input, prepared.response, 10, &budget)
        .await
        .unwrap();
    let reply: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(reply["complete"], false);
    mkit_core::hash::from_hex(reply["takedownId"].as_str().unwrap()).unwrap()
}
async fn advance(f: &Fixture, id: Hash, now: u64) -> (State, u32) {
    f.clock.set(i64::try_from(now).unwrap());
    let budget = SliceBudget::new(700);
    let store = Budgeted::new(&f.work.metadata, &budget);
    let fired = f.work.step(&store, id, now, &budget).await.unwrap();
    let Fired::Reschedule { batch, .. } = fired else {
        panic!("all unresolved requests keep their timer");
    };
    // The timer driver adds three operations to an ordinary reschedule batch.
    assert!(batch.writes.len() + batch.preconditions.len() + 3 <= crate::store::MAX_BATCH_OPS);
    batch.validate(&f.work.metadata.capabilities()).unwrap();
    assert_eq!(
        f.work.metadata.apply(&f.work.root, batch).await.unwrap(),
        BatchOutcome::Committed
    );
    let raw = f
        .work
        .metadata
        .get(&f.work.root, &key(b"state", &id, &[]))
        .await
        .unwrap()
        .unwrap();
    let state: State = decode(&raw).unwrap();
    // Deserialize at every tick: no in-memory workflow state survives a restart.
    let state = serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
    (state, budget.used())
}
fn small() -> Object {
    Object::Blob(Blob {
        data: b"owned evidence".to_vec(),
    })
}

#[derive(Clone, Debug)]
struct FaultBlobs {
    inner: MemoryBlobStore,
    mode: Arc<std::sync::atomic::AtomicU8>,
    reads: Arc<std::sync::atomic::AtomicUsize>,
    corrupt_offset: Option<u64>,
}
impl BlobStore for FaultBlobs {
    type Sink = <MemoryBlobStore as BlobStore>::Sink;
    async fn begin(&self, key: BlobKey, len: u64) -> Result<Self::Sink, StoreError> {
        self.inner.begin(key, len).await
    }
    async fn get(
        &self,
        key: &BlobKey,
        range: Option<crate::ByteRange>,
    ) -> Result<Option<crate::BlobBody>, StoreError> {
        use std::sync::atomic::Ordering::SeqCst;
        self.reads.fetch_add(1, SeqCst);
        if self.mode.load(SeqCst) == 1 {
            return Err(StoreError::unavailable("transient injected I/O"));
        }
        let body = self.inner.get(key, range).await?;
        if self.mode.load(SeqCst) >= 2
            && range.is_some_and(|r| {
                self.corrupt_offset
                    .map_or(r.start >= 12, |offset| r.start == offset)
            })
        {
            let Some(crate::BlobBody::Bytes(bytes)) = body else {
                panic!("small test frame")
            };
            let mut bytes = bytes.to_vec();
            if self.mode.load(SeqCst) == 5 {
                bytes[55..59].copy_from_slice(&(2u32 << 20).to_le_bytes());
            } else if self.mode.load(SeqCst) == 4 {
                // Only the historically verified delta result claim changes.
                bytes[42..46].copy_from_slice(&(2u32 << 20).to_le_bytes());
            } else if self.mode.load(SeqCst) == 3 {
                // Corrupted raw entry becomes compressed, with a claim above the
                // scheduled decode cap but the same immutable index and frame length.
                bytes[0] = 0x03;
                bytes[5..9].copy_from_slice(&(2u32 << 20).to_le_bytes());
            } else {
                bytes[0] = 255;
            }
            return Ok(Some(crate::BlobBody::Bytes(Bytes::from(bytes))));
        }
        Ok(body)
    }
    async fn head(&self, key: &BlobKey) -> Result<Option<crate::BlobMeta>, StoreError> {
        self.inner.head(key).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.inner.probe().await
    }
    async fn delete(&self, key: &BlobKey) -> Result<bool, StoreError> {
        self.inner.delete(key).await
    }
}
fn fault_work(
    f: &Fixture,
    serving: FaultBlobs,
) -> Work<Arc<MemoryKv>, FaultBlobs, MemoryBlobStore> {
    Work {
        purge: None,
        metadata: f.work.metadata.clone(),
        serving,
        preserved: f.work.preserved.clone(),
        root: f.work.root.clone(),
        shards: f.work.shards.clone(),
        addressing: f.work.addressing.clone(),
        retention_ms: f.work.retention_ms,
        discovery_margin_ms: f.work.discovery_margin_ms,
        profile: f.work.profile,
        clock: f.work.clock.clone(),
    }
}
async fn fault_advance(
    work: &Work<Arc<MemoryKv>, FaultBlobs, MemoryBlobStore>,
    id: Hash,
) -> Result<State, StoreError> {
    let budget = SliceBudget::new(700);
    let Fired::Reschedule { batch, .. } = work
        .step(&Budgeted::new(&work.metadata, &budget), id, 20_000, &budget)
        .await?
    else {
        panic!("pending timer")
    };
    assert_eq!(
        work.metadata.apply(&work.root, batch).await?,
        BatchOutcome::Committed
    );
    Ok(work.state(&work.metadata, &id, 10).await?.0)
}

#[tokio::test]
async fn corrupt_member_source_is_terminal_audited_and_denied_after_restart() {
    assert_terminal_source_corruption(2).await;
}

#[tokio::test]
async fn corrupt_compressed_claim_is_terminal_before_decode_budget_check() {
    assert_terminal_source_corruption(3).await;
}

#[tokio::test]
async fn corrupt_delta_result_claim_is_terminal_before_decode_budget_check() {
    assert_delta_claim_terminal(2, 4).await;
}

#[tokio::test]
async fn corrupt_zstd_delta_result_claim_is_terminal_before_decode_budget_check() {
    assert_delta_claim_terminal(4, 5).await;
}

#[allow(
    clippy::too_many_lines,
    reason = "Verify canonical control, one audit and terminal state across restart."
)]
async fn assert_delta_claim_terminal(delta_wire: u8, fault: u8) {
    use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering::SeqCst};
    let base = Object::Blob(Blob {
        data: vec![b'A'; 512],
    });
    let mut target_data = vec![b'A'; 512];
    target_data[256] = b'B';
    let target = Object::Blob(Blob { data: target_data });
    let f = fixture_with_delta(&[base, target], false, delta_wire).await;
    let object = f.canonical[1].0;
    // A fully valid selected delta completes before source corruption.
    let verified = acquisition::resolve(
        &f.work.serving,
        &f.work.metadata,
        f.work.shards.as_ref(),
        &f.repo,
        object,
        &f.work.profile,
        &crate::NoopMetrics,
    )
    .await
    .unwrap();
    assert_eq!(verified.canonical.as_ref(), f.canonical[1].1);
    let id = accept(&f, "corrupt-delta-result", None, &[object]).await;
    f.clock.set(20_000);
    for _ in 0..3 {
        advance(&f, id, 20_000).await;
    }
    let blobs = FaultBlobs {
        inner: f.work.serving.clone(),
        mode: Arc::new(AtomicU8::new(fault)),
        reads: Arc::new(AtomicUsize::new(0)),
        corrupt_offset: Some(12 + 5 + f.canonical[0].1.len() as u64),
    };
    let work = fault_work(&f, blobs.clone());
    let state = fault_advance(&work, id)
        .await
        .expect("corrupted delta result claim must commit a terminal checkpoint");
    assert_eq!(state.verification, Verification::SourceCorrupt);
    assert!(!state.acquisition_complete() && !state.discovery_complete);
    assert!(
        work.info(&work.metadata, &id, &object)
            .await
            .unwrap()
            .source_failed
    );
    assert!(
        work.metadata
            .get(&work.root, &key(b"todo", &id, &object))
            .await
            .unwrap()
            .is_none()
    );
    let page = work
        .metadata
        .scan(
            &work.root,
            &Key::new(b"ae\0".to_vec()),
            &Key::new(b"af".to_vec()),
            None,
            100,
        )
        .await
        .unwrap();
    let audits: Vec<serde_json::Value> = page
        .entries
        .iter()
        .map(|(_, value)| serde_json::from_slice(value.as_bytes()).unwrap())
        .filter(|audit: &serde_json::Value| {
            audit["procedure"] == "system:timer/PreservationSourceCorrupt"
        })
        .collect();
    assert_eq!(audits.len(), 1);
    for target in [to_hex(&id), to_hex(&object), to_hex(&f.pack)] {
        assert!(
            audits[0]["targets"]
                .as_array()
                .unwrap()
                .contains(&json!(target))
        );
    }
    let reads = blobs.reads.load(SeqCst);
    let restarted = fault_work(&f, blobs.clone());
    for _ in 0..40 {
        let next = fault_advance(&restarted, id).await.unwrap();
        assert!(!next.acquisition_complete() && !next.discovery_complete);
        if next.phase == Phase::Retain {
            break;
        }
    }
    assert_eq!(blobs.reads.load(SeqCst), reads);
    let page = restarted
        .metadata
        .scan(
            &restarted.root,
            &Key::new(b"ae\0".to_vec()),
            &Key::new(b"af".to_vec()),
            None,
            100,
        )
        .await
        .unwrap();
    assert_eq!(
        page.entries
            .iter()
            .filter(|(_, value)| {
                let audit: serde_json::Value = serde_json::from_slice(value.as_bytes()).unwrap();
                audit["procedure"] == "system:timer/PreservationSourceCorrupt"
            })
            .count(),
        1
    );
    assert!(
        ContentIndex::new(BorrowedStore(&work.metadata))
            .blocked(&object)
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn valid_compressed_delta_stream_budget_failure_remains_retryable() {
    let base = Object::Blob(Blob {
        data: vec![b'A'; 512],
    });
    let target = Object::Blob(Blob {
        data: vec![b'B'; 512],
    });
    // One-byte INSERTs are valid: the stream is 1053 bytes while its result is 522.
    let f = fixture_delta_encoding(&[base, target], false, 4, true).await;
    let object = f.canonical[1].0;
    let valid = acquisition::resolve(
        &f.work.serving,
        &f.work.metadata,
        f.work.shards.as_ref(),
        &f.repo,
        object,
        &f.work.profile,
        &crate::NoopMetrics,
    )
    .await
    .unwrap();
    assert_eq!(valid.canonical.as_ref(), f.canonical[1].1);
    let id = accept(&f, "delta-stream-budget", None, &[object]).await;
    f.clock.set(20_000);
    for _ in 0..3 {
        advance(&f, id, 20_000).await;
    }
    let blobs = FaultBlobs {
        inner: f.work.serving.clone(),
        mode: Arc::new(std::sync::atomic::AtomicU8::new(0)),
        reads: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        corrupt_offset: None,
    };
    let mut work = fault_work(&f, blobs.clone());
    work.profile.limits.max_decoded_bytes = 1024;
    let old = work
        .metadata
        .get(&work.root, &key(b"state", &id, &[]))
        .await
        .unwrap();
    for _ in 0..2 {
        let mut restarted = fault_work(&f, blobs.clone());
        restarted.profile = work.profile;
        assert!(fault_advance(&restarted, id).await.is_err());
        assert_eq!(
            old,
            work.metadata
                .get(&work.root, &key(b"state", &id, &[]))
                .await
                .unwrap()
        );
        assert!(
            !work
                .info(&work.metadata, &id, &object)
                .await
                .unwrap()
                .source_failed
        );
        assert!(
            work.metadata
                .get(&work.root, &key(b"todo", &id, &object))
                .await
                .unwrap()
                .is_some()
        );
    }
    work.profile = acquisition::Profile::scheduled();
    let state = fault_advance(&work, id).await.unwrap();
    assert_ne!(state.verification, Verification::SourceCorrupt);
    assert!(
        work.info(&work.metadata, &id, &object)
            .await
            .unwrap()
            .verified
    );
}

// Model a historically verified compressed member, then corrupt its stored
// outer claim while leaving this immutable metadata intact.
async fn mark_source_as_verified_zstd(f: &Fixture, object: Hash) {
    let partition = f.work.shards.object_index(&f.repo, &object);
    let index = keys::object_index(&f.repo.name, &object, &f.pack);
    let raw = f
        .work
        .metadata
        .get(&partition, &index)
        .await
        .unwrap()
        .unwrap();
    let mut located = codec::decode_object_index(&object, &raw).unwrap();
    located.wire_type = 0x03;
    f.work
        .metadata
        .apply(
            &partition,
            Batch::new().put(
                index,
                codec::encode_object_index(&object, &located).unwrap(),
            ),
        )
        .await
        .unwrap();
}

async fn assert_terminal_source_corruption(mode: u8) {
    use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering::SeqCst};
    let f = fixture(&[small()], false).await;
    let object = f.canonical[0].0;
    if mode == 3 {
        mark_source_as_verified_zstd(&f, object).await;
    }
    let id = accept(&f, "corrupt-source", None, &[object]).await;
    f.clock.set(20_000);
    advance(&f, id, 20_000).await;
    advance(&f, id, 20_000).await;
    let blobs = FaultBlobs {
        inner: f.work.serving.clone(),
        mode: Arc::new(AtomicU8::new(mode)),
        reads: Arc::new(AtomicUsize::new(0)),
        corrupt_offset: None,
    };
    let work = fault_work(&f, blobs.clone());
    let state = fault_advance(&work, id)
        .await
        .expect("corruption commits a terminal checkpoint");
    assert!(!state.acquisition_complete());
    assert!(!state.discovery_complete);
    assert_eq!(state.verification, Verification::SourceCorrupt);
    assert!(
        work.info(&work.metadata, &id, &object)
            .await
            .unwrap()
            .source_failed
    );
    assert!(
        work.metadata
            .get(&work.root, &key(b"todo", &id, &object))
            .await
            .unwrap()
            .is_none()
    );
    let source_frame = key(
        b"source-frame",
        &id,
        &[object.as_slice(), &0u32.to_be_bytes()].concat(),
    );
    assert!(
        work.metadata
            .get(&work.root, &source_frame)
            .await
            .unwrap()
            .is_some()
    );
    let page = work
        .metadata
        .scan(
            &work.root,
            &Key::new(b"ae\0".to_vec()),
            &Key::new(b"af".to_vec()),
            None,
            100,
        )
        .await
        .unwrap();
    let audits: Vec<serde_json::Value> = page
        .entries
        .iter()
        .map(|(_, v)| serde_json::from_slice(v.as_bytes()).unwrap())
        .filter(|a: &serde_json::Value| a["procedure"] == "system:timer/PreservationSourceCorrupt")
        .collect();
    assert_eq!(audits.len(), 1);
    for target in [to_hex(&id), to_hex(&object), to_hex(&f.pack)] {
        assert!(
            audits[0]["targets"]
                .as_array()
                .unwrap()
                .contains(&json!(target))
        );
    }
    let before = blobs.reads.load(SeqCst);
    // Reconstruct the runtime, then run acquisition, discovery and retention ticks.
    let restarted = fault_work(&f, blobs.clone());
    let mut state = state;
    for _ in 0..40 {
        state = fault_advance(&restarted, id).await.unwrap();
        assert!(!state.acquisition_complete() && !state.discovery_complete);
        if state.phase == Phase::Retain {
            break;
        }
    }
    assert_eq!(state.phase, Phase::Retain);
    assert_eq!(
        blobs.reads.load(SeqCst),
        before,
        "terminal source must never be decoded again"
    );
    assert!(
        ContentIndex::new(BorrowedStore(&work.metadata))
            .blocked(&object)
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn transient_member_source_io_retries_and_can_complete() {
    use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering::SeqCst};
    let f = fixture(&[small()], false).await;
    let object = f.canonical[0].0;
    let id = accept(&f, "transient-source", None, &[object]).await;
    f.clock.set(20_000);
    advance(&f, id, 20_000).await;
    advance(&f, id, 20_000).await;
    let blobs = FaultBlobs {
        inner: f.work.serving.clone(),
        mode: Arc::new(AtomicU8::new(1)),
        reads: Arc::new(AtomicUsize::new(0)),
        corrupt_offset: None,
    };
    let work = fault_work(&f, blobs.clone());
    let old = work
        .metadata
        .get(&work.root, &key(b"state", &id, &[]))
        .await
        .unwrap();
    assert!(fault_advance(&work, id).await.is_err());
    assert_eq!(
        work.metadata
            .get(&work.root, &key(b"state", &id, &[]))
            .await
            .unwrap(),
        old
    );
    assert!(
        work.metadata
            .get(&work.root, &key(b"todo", &id, &object))
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        ContentIndex::new(BorrowedStore(&work.metadata))
            .blocked(&object)
            .await
            .unwrap()
            .is_some()
    );
    blobs.mode.store(0, SeqCst);
    let mut complete = false;
    for _ in 0..40 {
        if fault_advance(&work, id)
            .await
            .unwrap()
            .acquisition_complete()
        {
            complete = true;
            break;
        }
    }
    assert!(complete);
}

#[tokio::test]
async fn corrupt_manifest_child_is_not_reenqueued_and_other_sources_finish() {
    use std::sync::atomic::{AtomicU8, AtomicUsize};
    let chunk = small();
    let chunk_id = hash(&serialize(&chunk).unwrap());
    // Make the child sort first, so it fails between the manifest's bounded passes.
    let manifest = (65..130)
        .map(|count| {
            Object::ChunkedBlob(ChunkedBlob {
                total_size: 14 * count,
                chunk_size: 14,
                chunks: vec![chunk_id; usize::try_from(count).unwrap()],
            })
        })
        .find(|object| {
            let Object::ChunkedBlob(cb) = object else {
                unreachable!()
            };
            chunk_id < mkit_core::merkle::compute_chunked_id(cb)
        })
        .unwrap();
    let healthy = Object::Blob(Blob {
        data: b"independent source".to_vec(),
    });
    let f = fixture(&[manifest, chunk, healthy], false).await;
    let manifest_id = f.canonical[0].0;
    let id = accept(&f, "corrupt-child", None, &[manifest_id, f.canonical[2].0]).await;
    f.clock.set(20_000);
    let blobs = FaultBlobs {
        inner: f.work.serving.clone(),
        mode: Arc::new(AtomicU8::new(2)),
        reads: Arc::new(AtomicUsize::new(0)),
        corrupt_offset: Some(12 + 5 + f.canonical[0].1.len() as u64),
    };
    let work = fault_work(&f, blobs);
    let mut last = None;
    for _ in 0..80 {
        let state = fault_advance(&work, id).await.unwrap();
        last = Some(state.clone());
        if state.phase == Phase::Retain {
            break;
        }
    }
    let state = last.unwrap();
    assert_eq!(state.phase, Phase::Retain);
    assert_eq!(state.verification, Verification::SourceCorrupt);
    assert!(!state.acquisition_complete() && !state.discovery_complete);
    assert!(
        work.info(&work.metadata, &id, &chunk_id)
            .await
            .unwrap()
            .source_failed
    );
    assert!(
        work.info(&work.metadata, &id, &f.canonical[2].0)
            .await
            .unwrap()
            .verified
    );
    assert_eq!(
        state.verified_objects, 2,
        "manifest and independent source copied, failed child excluded"
    );
}

#[tokio::test]
async fn any_denies_immediately_preserves_named_repository_and_never_claims_discovery_complete() {
    let f = fixture(&[small()], true).await;
    let object = f.canonical[0].0;
    let id = accept(&f, "any", None, &[object]).await;
    assert!(
        ContentIndex::new(BorrowedStore(&f.work.metadata))
            .blocked(&object)
            .await
            .unwrap()
            .is_some()
    );
    let mut max_calls = 0;
    let mut last = None;
    for _ in 0..50 {
        let (state, calls) = advance(&f, id, 20_000).await;
        max_calls = max_calls.max(calls);
        assert!(!state.discovery_complete);
        last = Some(state.clone());
        if state.phase == Phase::Retain {
            break;
        }
    }
    let state = last.unwrap();
    assert_eq!(state.phase, Phase::Retain);
    assert!(state.acquisition_complete());
    assert_eq!(state.verified_objects, 1);
    assert!(
        max_calls <= 30,
        "assert the real shared acquisition+metadata call count: {max_calls}"
    );
    let (start, end) = range(b"piece", &id);
    let page = f
        .work
        .metadata
        .scan(&f.work.root, &start, &end, None, 8)
        .await
        .unwrap();
    assert_eq!(page.entries.len(), 1);
    let piece: copy::Piece = decode(&page.entries[0].1).unwrap();
    assert_eq!(
        copy::read(&f.work.preserved, &id, &piece)
            .await
            .unwrap()
            .unwrap(),
        f.canonical[0].1[..]
    );
    let service = Service::new(
        f.work.metadata.clone(),
        f.work.root.clone(),
        f.work.shards.clone(),
    )
    .with_purge(f.work.purge.clone());
    assert!(
        service
            .record(&f.work.metadata, &id)
            .await
            .unwrap()
            .unwrap()
            .0
            .preservation_pending
    );
}
#[tokio::test]
async fn finite_sweep_completes_only_after_canonical_acquisition_and_watermarks() {
    let f = fixture(&[small()], false).await;
    let id = accept(&f, "finite", None, &[f.canonical[0].0]).await;
    for _ in 0..30 {
        let (state, _) = advance(&f, id, 20_000).await;
        if state.phase == Phase::Retain {
            assert!(state.acquisition_complete() && state.discovery_complete);
            return;
        }
    }
    panic!("finite sweep did not finish");
}
#[tokio::test]
async fn duplicate_manifest_chunks_are_queued_once_and_wrong_child_kind_fails_closed() {
    let child = small();
    let id = hash(&serialize(&child).unwrap());
    let manifest = Object::ChunkedBlob(ChunkedBlob {
        total_size: 13 * 80,
        chunk_size: 13,
        chunks: vec![id; 80],
    });
    let f = fixture(&[manifest, child], false).await;
    let action = accept(&f, "duplicate", None, &[f.canonical[0].0]).await;
    advance(&f, action, 20_000).await;
    advance(&f, action, 20_000).await;
    let (state, calls) = advance(&f, action, 20_000).await;
    assert_eq!(state.phase, Phase::Acquire);
    assert!(calls < 100);
    let (start, end) = range(b"todo", &action);
    let rows = f
        .work
        .metadata
        .scan(&f.work.root, &start, &end, None, 8)
        .await
        .unwrap();
    assert_eq!(
        rows.entries.len(),
        2,
        "manifest remainder plus one duplicate child"
    );
    // Existing metadata for a non-Blob child must not be accepted as a valid manifest closure.
    f.work
        .metadata
        .apply(
            &f.work.root,
            Batch::new().put(
                key(b"object", &action, &id),
                value(&ObjectInfo {
                    kind: 5,
                    verified: true,
                    ..ObjectInfo::default()
                })
                .unwrap(),
            ),
        )
        .await
        .unwrap();
    let budget = SliceBudget::new(700);
    assert!(
        f.work
            .step(
                &Budgeted::new(&f.work.metadata, &budget),
                action,
                20_000,
                &budget
            )
            .await
            .is_err()
    );
    let raw = f
        .work
        .metadata
        .get(&f.work.root, &key(b"state", &action, &[]))
        .await
        .unwrap()
        .unwrap();
    assert!(!decode::<State>(&raw).unwrap().acquisition_complete());
}
#[tokio::test]
async fn whole_packlist_walks_dependency_inventories_before_verified_claim() {
    let f = fixture(&[small()], false).await;
    let parent = [87; 32];
    inventory::dependency(&f.work.metadata, &parent, 80, &f.pack, 10)
        .await
        .unwrap();
    inventory::complete(&f.work.metadata, &parent, 80, 10)
        .await
        .unwrap();
    f.work
        .metadata
        .apply(
            &SinglePartition.membership(&f.repo, &BlobKey::pack(parent)),
            Batch::new().put(keys::membership(&f.repo.name, &parent), Value::default()),
        )
        .await
        .unwrap();
    let id = accept(&f, "packlist", Some(parent), &[]).await;
    for _ in 0..60 {
        let (state, _) = advance(&f, id, 20_000).await;
        if state.acquisition_complete() {
            assert_eq!(state.verified_objects, 1);
            return;
        }
    }
    panic!("packlist did not preserve dependency contents");
}
#[tokio::test]
async fn failed_checkpoint_leaves_a_durable_piece_intent_that_retention_can_purge() {
    let f = fixture(&[small()], true).await;
    let id = accept(&f, "crash", None, &[f.canonical[0].0]).await;
    advance(&f, id, 20_000).await;
    advance(&f, id, 20_000).await;
    let budget = SliceBudget::new(700);
    // PUT and its owner intent are durable, but intentionally lose the final acquisition checkpoint.
    let _lost = f
        .work
        .step(
            &Budgeted::new(&f.work.metadata, &budget),
            id,
            20_000,
            &budget,
        )
        .await
        .unwrap();
    let (start, end) = range(b"piece", &id);
    let page = f
        .work
        .metadata
        .scan(&f.work.root, &start, &end, None, 1)
        .await
        .unwrap();
    assert_eq!(page.entries.len(), 1);
    let piece: copy::Piece = decode(&page.entries[0].1).unwrap();
    assert!(
        copy::read(&f.work.preserved, &id, &piece)
            .await
            .unwrap()
            .is_some()
    );
    f.work.serving.delete(&BlobKey::pack(f.pack)).await.unwrap();
    for _ in 0..30 {
        let (state, _) = advance(&f, id, 1_100_000).await;
        assert!(!state.acquisition_complete() && !state.discovery_complete);
        if state.purged {
            break;
        }
    }
    assert!(
        copy::read(&f.work.preserved, &id, &piece)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        f.work
            .metadata
            .get(&f.work.root, &page.entries[0].0)
            .await
            .unwrap()
            .is_some(),
        "retain intents for delayed PUT recovery"
    );
    // Model a stale in-flight PUT finishing after purge: a later timer pass removes it again.
    copy::write(
        &f.work.preserved,
        &id,
        &piece.object,
        piece.offset,
        &f.canonical[0].1,
    )
    .await
    .unwrap();
    for _ in 0..30 {
        advance(&f, id, 5_000_000).await;
    }
    assert!(
        copy::read(&f.work.preserved, &id, &piece)
            .await
            .unwrap()
            .is_none()
    );
}
#[tokio::test]
async fn hold_suspends_timed_purge_and_overlapping_action_keeps_its_copy() {
    let f = fixture(&[small()], false).await;
    let object = f.canonical[0].0;
    let first = accept(&f, "first", None, &[object]).await;
    let second = accept(&f, "second", None, &[object]).await;
    for id in [first, second] {
        for _ in 0..30 {
            let (state, _) = advance(&f, id, 20_000).await;
            if state.phase == Phase::Retain {
                break;
            }
        }
    }
    let hold = f
        .work
        .plan_legal_hold(&f.work.metadata, second, true, 20_000)
        .await
        .unwrap();
    assert_eq!(
        f.work.metadata.apply(&f.work.root, hold).await.unwrap(),
        BatchOutcome::Committed
    );
    let (state, _) = advance(&f, second, 1_100_000).await;
    assert!(state.hold && !state.purged);
    for _ in 0..10 {
        advance(&f, first, 1_100_000).await;
    }
    for (id, present) in [(first, false), (second, true)] {
        let (start, end) = range(b"piece", &id);
        let piece: copy::Piece = decode(
            &f.work
                .metadata
                .scan(&f.work.root, &start, &end, None, 1)
                .await
                .unwrap()
                .entries[0]
                .1,
        )
        .unwrap();
        assert_eq!(
            copy::read(&f.work.preserved, &id, &piece)
                .await
                .unwrap()
                .is_some(),
            present
        );
    }
    assert!(
        ContentIndex::new(BorrowedStore(&f.work.metadata))
            .blocked(&object)
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn ordinary_pack_external_object_dependencies_are_not_mistaken_for_child_packs() {
    let f = fixture(&[small()], false).await;
    let parent = [88; 32];
    let object = f.canonical[0].0;
    inventory::dependency(&f.work.metadata, &parent, 80, &object, 10)
        .await
        .unwrap();
    inventory::complete(&f.work.metadata, &parent, 80, 10)
        .await
        .unwrap();
    f.work
        .metadata
        .apply(
            &SinglePartition.membership(&f.repo, &BlobKey::pack(parent)),
            Batch::new().put(keys::membership(&f.repo.name, &parent), Value::default()),
        )
        .await
        .unwrap();
    let id = accept(&f, "external-base", Some(parent), &[]).await;
    for _ in 0..40 {
        let (state, _) = advance(&f, id, 20_000).await;
        if state.acquisition_complete() {
            assert_eq!(state.verified_objects, 1);
            return;
        }
    }
    panic!("external canonical dependency was treated as a pack hash");
}

#[tokio::test]
async fn any_work_visits_known_holder_namespaces_one_at_a_time_without_completing() {
    let f = fixture(&[small()], true).await;
    let object = f.canonical[0].0;
    let second = RepoId {
        namespace: NamespaceKey::from_stored("0x2222222222222222222222222222222222222222".into()),
        name: RepoName::new("second").unwrap(),
    };
    let first_index = f
        .work
        .metadata
        .get(
            &SinglePartition.object_index(&f.repo, &object),
            &keys::object_index(&f.repo.name, &object, &f.pack),
        )
        .await
        .unwrap()
        .unwrap();
    f.work
        .metadata
        .apply(
            &Partition::Namespace(second.namespace.clone()),
            Batch::new()
                .put(
                    keys::object_index(&second.name, &object, &f.pack),
                    first_index,
                )
                .put(keys::membership(&second.name, &f.pack), Value::default())
                .put(
                    keys::repo_record(&second.name),
                    codec::encode_repo_record(&codec::RepoRecord { created_at_ms: 10 }),
                ),
        )
        .await
        .unwrap();
    ContentIndex::new(BorrowedStore(&f.work.metadata))
        .add_holder(
            &object,
            &crate::store::Holder::new(second.namespace.clone(), second.name),
            &[9; 32],
            None,
            10,
        )
        .await
        .unwrap();
    let id = accept(&f, "known-holders", None, &[object]).await;
    for _ in 0..60 {
        let (state, _) = advance(&f, id, 20_000).await;
        assert!(!state.discovery_complete);
        if state.phase == Phase::Retain {
            break;
        }
    }
    let prefix = Key::new([b"b\0\xffdiscovery-context\0".as_slice(), &id, &object].concat());
    let page = f
        .work
        .metadata
        .scan(&f.work.root, &prefix, &prefix_end(&prefix), None, 8)
        .await
        .unwrap();
    assert_eq!(
        page.entries.len(),
        2,
        "both named and discovered holder namespaces traversed"
    );
}

#[tokio::test]
async fn retention_retry_does_not_depend_on_discovery_making_progress() {
    let f = fixture(&[small()], true).await;
    let id = accept(&f, "purge-progress", None, &[f.canonical[0].0]).await;
    advance(&f, id, 20_000).await;
    advance(&f, id, 20_000).await;
    advance(&f, id, 20_000).await;
    advance(&f, id, 1_100_000).await;
    advance(&f, id, 1_100_000).await;
    let (state, _) = advance(&f, id, 1_100_000).await;
    assert!(state.purged && state.phase == Phase::Discover);
    let (start, end) = range(b"piece", &id);
    let piece: copy::Piece = decode(
        &f.work
            .metadata
            .scan(&f.work.root, &start, &end, None, 1)
            .await
            .unwrap()
            .entries[0]
            .1,
    )
    .unwrap();
    copy::write(
        &f.work.preserved,
        &id,
        &piece.object,
        piece.offset,
        &f.canonical[0].1,
    )
    .await
    .unwrap();
    // A corrupt owning discovery cursor would fail if discovery were attempted first.
    let mut blocked = state;
    blocked.discovery = None;
    blocked.current = Some([255; 32]);
    f.work
        .metadata
        .apply(
            &f.work.root,
            Batch::new().put(key(b"state", &id, &[]), value(&blocked).unwrap()),
        )
        .await
        .unwrap();
    let (state, _) = advance(&f, id, 5_000_000).await;
    assert_eq!(state.phase, Phase::Purging);
    advance(&f, id, 5_000_000).await;
    assert!(
        copy::read(&f.work.preserved, &id, &piece)
            .await
            .unwrap()
            .is_none()
    );
}

#[derive(Clone, Debug)]
struct RemoteOnly(Arc<MemoryKv>, Partition);
impl NamespaceStore for RemoteOnly {
    fn capabilities(&self) -> crate::StoreCapabilities {
        self.0.capabilities()
    }
    async fn get(&self, p: &Partition, k: &Key) -> Result<Option<Value>, StoreError> {
        assert_ne!(p, &self.1, "self-DO get");
        self.0.get(p, k).await
    }
    async fn get_many(&self, p: &Partition, k: &[Key]) -> Result<Vec<Option<Value>>, StoreError> {
        assert_ne!(p, &self.1, "self-DO batched get");
        self.0.get_many(p, k).await
    }
    async fn scan(
        &self,
        p: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<crate::ScanPage, StoreError> {
        assert_ne!(p, &self.1, "self-DO scan");
        self.0.scan(p, start, end, after, limit).await
    }
    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        assert_ne!(p, &self.1, "self-DO apply");
        self.0.apply(p, batch).await
    }
    async fn stats(&self, p: &Partition) -> Result<crate::PartitionStats, StoreError> {
        assert_ne!(p, &self.1, "self-DO stats");
        self.0.stats(p).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.0.probe().await
    }
}
#[tokio::test]
async fn timer15_uses_firing_local_store_for_owner_and_durable_copy_intents() {
    let f = fixture(&[small()], true).await;
    let id = accept(&f, "local-timer", None, &[f.canonical[0].0]).await;
    f.clock.set(20_000);
    let work = Work {
        purge: None,
        metadata: RemoteOnly(f.work.metadata.clone(), f.work.root.clone()),
        serving: f.work.serving.clone(),
        preserved: f.work.preserved.clone(),
        root: f.work.root.clone(),
        shards: f.work.shards.clone(),
        addressing: f.work.addressing.clone(),
        retention_ms: f.work.retention_ms,
        discovery_margin_ms: f.work.discovery_margin_ms,
        profile: f.work.profile,
        clock: f.work.clock.clone(),
    };
    let ctx = TimerCtx {
        store: f.work.metadata.as_ref(),
        partition: &f.work.root,
        now_ms: 20_000,
    };
    let timer = DueTimer {
        due_at_ms: 20_000,
        kind: kinds::TAKEDOWN_WORK,
        reference: Bytes::copy_from_slice(&id),
        value: Value::default(),
    };
    for _ in 0..4 {
        let Fired::Reschedule { batch, .. } = work.fire(&ctx, &timer).await.unwrap() else {
            panic!("pending timer drained");
        };
        assert_eq!(
            ctx.store.apply(ctx.partition, batch).await.unwrap(),
            BatchOutcome::Committed
        );
    }
    assert!(
        work.state(ctx.store, &id, 10)
            .await
            .unwrap()
            .0
            .acquisition_complete()
    );
    assert_eq!(<Work<RemoteOnly,MemoryBlobStore,MemoryBlobStore> as TimerHandler<MemoryKv>>::max_per_tick(&work), Some(1));
}

#[tokio::test]
async fn malformed_manifest_closure_stays_unresolved_after_restart() {
    let chunk = small();
    let object = hash(&serialize(&chunk).unwrap());
    let manifest = Object::ChunkedBlob(ChunkedBlob {
        total_size: 1,
        chunk_size: 1,
        chunks: vec![object, object],
    });
    let f = fixture(&[manifest, chunk], true).await;
    let id = accept(&f, "pending-closure", None, &[f.canonical[0].0]).await;
    f.clock.set(20_000);
    for _ in 0..40 {
        let budget = SliceBudget::new(700);
        let result = f
            .work
            .step(
                &Budgeted::new(&f.work.metadata, &budget),
                id,
                20_000,
                &budget,
            )
            .await;
        if result.is_err() {
            let state = f.work.state(&f.work.metadata, &id, 10).await.unwrap().0;
            assert_eq!(state.phase, Phase::Closure);
            assert_eq!(state.verification, Verification::ManifestClosurePending);
            assert!(!state.acquisition_complete() && !state.discovery_complete);
            assert!(
                ContentIndex::new(BorrowedStore(&f.work.metadata))
                    .blocked(&f.canonical[0].0)
                    .await
                    .unwrap()
                    .is_some()
            );
            return;
        }
        let Fired::Reschedule { batch, .. } = result.unwrap() else {
            panic!("missing checkpoint")
        };
        assert_eq!(
            f.work.metadata.apply(&f.work.root, batch).await.unwrap(),
            BatchOutcome::Committed
        );
    }
    panic!("invalid manifest incorrectly completed preservation");
}

#[tokio::test]
async fn legal_hold_and_purge_claim_race_atomically_in_both_orders() {
    for hold_first in [true, false] {
        let f = fixture(&[small()], false).await;
        let id = accept(&f, "hold-race", None, &[f.canonical[0].0]).await;
        for _ in 0..30 {
            if advance(&f, id, 20_000).await.0.phase == Phase::Retain {
                break;
            }
        }
        f.clock.set(1_100_000);
        let hold = f
            .work
            .plan_legal_hold(&f.work.metadata, id, true, 1_100_000)
            .await
            .unwrap();
        let budget = SliceBudget::new(700);
        let Fired::Reschedule { batch: purge, .. } = f
            .work
            .step(
                &Budgeted::new(&f.work.metadata, &budget),
                id,
                1_100_000,
                &budget,
            )
            .await
            .unwrap()
        else {
            panic!("missing purge claim")
        };
        let (winner, loser) = if hold_first {
            (hold, purge)
        } else {
            (purge, hold)
        };
        assert_eq!(
            f.work.metadata.apply(&f.work.root, winner).await.unwrap(),
            BatchOutcome::Committed
        );
        assert_ne!(
            f.work.metadata.apply(&f.work.root, loser).await.unwrap(),
            BatchOutcome::Committed
        );
        let state = f.work.state(&f.work.metadata, &id, 10).await.unwrap().0;
        assert_eq!(state.hold, hold_first);
        if hold_first {
            assert_ne!(state.phase, Phase::Purging);
            let release = f
                .work
                .plan_legal_hold(&f.work.metadata, id, false, 1_100_000)
                .await
                .unwrap();
            assert_eq!(
                f.work.metadata.apply(&f.work.root, release).await.unwrap(),
                BatchOutcome::Committed
            );
            assert_eq!(advance(&f, id, 1_100_000).await.0.phase, Phase::Purging);
        }
        assert!(
            f.work
                .plan_legal_hold(&f.work.metadata, id, true, 1_100_000)
                .await
                .is_err()
        );
        for _ in 0..5 {
            advance(&f, id, 1_100_000).await;
        }
        assert!(
            f.work
                .state(&f.work.metadata, &id, 10)
                .await
                .unwrap()
                .0
                .purged
        );
        assert!(
            f.work
                .plan_legal_hold(&f.work.metadata, id, true, 1_100_000)
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn ordered_duplicate_manifest_closure_completes_using_bounded_verified_preserved_reads() {
    let child = small();
    let chunk = hash(&serialize(&child).unwrap());
    let manifest = Object::ChunkedBlob(ChunkedBlob {
        total_size: 14 * 129,
        chunk_size: 14,
        chunks: vec![chunk; 129],
    });
    let f = fixture(&[manifest, child], false).await;
    let id = accept(&f, "closed-manifest", None, &[f.canonical[0].0]).await;
    let mut closure_ticks = 0;
    let mut max_calls = 0;
    for _ in 0..80 {
        let (state, calls) = advance(&f, id, 20_000).await;
        max_calls = max_calls.max(calls);
        if state.phase == Phase::Closure {
            closure_ticks += 1;
            assert!(!state.acquisition_complete());
            // Closure must survive loss of its serving source.
            f.work.serving.delete(&BlobKey::pack(f.pack)).await.unwrap();
        }
        if state.phase == Phase::Retain {
            assert!(state.acquisition_complete() && state.discovery_complete);
            assert_eq!(state.verified_objects, 2);
            assert!(
                closure_ticks >= 3,
                "129 ordered chunks require multiple bounded checkpoints"
            );
            assert!(
                max_calls < 350,
                "assert the shared real closure+acquisition metadata/blob calls: {max_calls}"
            );
            return;
        }
    }
    panic!("verified manifest did not finish");
}

#[derive(Debug)]
struct StaleSource<'a> {
    store: &'a MemoryKv,
    key: Key,
    old: Value,
}
impl NamespaceStore for StaleSource<'_> {
    fn capabilities(&self) -> crate::StoreCapabilities {
        self.store.capabilities()
    }
    async fn get(&self, p: &Partition, k: &Key) -> Result<Option<Value>, StoreError> {
        if k == &self.key {
            Ok(Some(self.old.clone()))
        } else {
            self.store.get(p, k).await
        }
    }
    async fn get_many(&self, p: &Partition, k: &[Key]) -> Result<Vec<Option<Value>>, StoreError> {
        self.store.get_many(p, k).await
    }
    async fn scan(
        &self,
        p: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<crate::ScanPage, StoreError> {
        self.store.scan(p, start, end, after, limit).await
    }
    async fn apply(&self, p: &Partition, b: Batch) -> Result<BatchOutcome, StoreError> {
        self.store.apply(p, b).await
    }
    async fn stats(&self, p: &Partition) -> Result<crate::PartitionStats, StoreError> {
        self.store.stats(p).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.store.probe().await
    }
}
#[tokio::test]
async fn stale_source_cursor_cannot_overwrite_progress_with_a_fresh_audit_head() {
    let f = fixture(&[small()], true).await;
    let object = f.canonical[0].0;
    let original = codec::encode_object_index(
        &object,
        &IndexValue {
            frame_offset: 12,
            frame_length: f.canonical[0].1.len() as u64 + 5,
            wire_type: 0,
            decoded_size: f.canonical[0].1.len() as u64,
            chain_depth: 0,
            delta_base: None,
        },
    )
    .unwrap();
    let mut batch = Batch::new();
    for number in 1u64..=16 {
        let mut pack = [0; 32];
        pack[24..].copy_from_slice(&number.to_be_bytes());
        assert!(pack < f.pack);
        batch = batch.put(
            keys::object_index(&f.repo.name, &object, &pack),
            original.clone(),
        );
    }
    f.work
        .metadata
        .apply(&SinglePartition.object_index(&f.repo, &object), batch)
        .await
        .unwrap();
    let id = accept(&f, "stale-source", None, &[object]).await;
    advance(&f, id, 20_000).await;
    advance(&f, id, 20_000).await;
    let checkpoint_key = key(b"source", &id, &object);
    let stale = f
        .work
        .metadata
        .get(&f.work.root, &checkpoint_key)
        .await
        .unwrap()
        .unwrap();
    advance(&f, id, 20_000).await;
    advance(&f, id, 20_000).await;
    let ready = f
        .work
        .metadata
        .get(&f.work.root, &checkpoint_key)
        .await
        .unwrap()
        .unwrap();
    assert!(decode::<source::Checkpoint>(&ready).unwrap().next.is_none());
    let stale_store = StaleSource {
        store: f.work.metadata.as_ref(),
        key: checkpoint_key.clone(),
        old: stale,
    };
    let budget = SliceBudget::new(700);
    let Fired::Reschedule { batch, .. } = f
        .work
        .step(&Budgeted::new(&stale_store, &budget), id, 20_000, &budget)
        .await
        .unwrap()
    else {
        panic!("missing stale continuation")
    };
    // State is unchanged and the audit head is fresh; only the source CAS detects this race.
    assert_ne!(
        f.work.metadata.apply(&f.work.root, batch).await.unwrap(),
        BatchOutcome::Committed
    );
    assert_eq!(
        f.work
            .metadata
            .get(&f.work.root, &checkpoint_key)
            .await
            .unwrap(),
        Some(ready)
    );
}

#[derive(Default)]
struct CacheProbe {
    local: std::sync::Mutex<Vec<crate::purge::Request>>,
    remote: std::sync::Mutex<Vec<crate::purge::Request>>,
    fail_once: std::sync::atomic::AtomicBool,
}
impl crate::purge::LocalInvalidation for CacheProbe {
    fn invalidate<'a>(
        &'a self,
        request: &'a crate::purge::Request,
        _: u32,
        _: &'a crate::purge::SliceBudget,
    ) -> crate::BoxFuture<'a, Result<Option<u32>, StoreError>> {
        Box::pin(async move {
            self.local.lock().unwrap().push(request.clone());
            Ok(None)
        })
    }
}
impl crate::purge::PurgeSink for CacheProbe {
    fn deliver<'a>(
        &'a self,
        request: &'a crate::purge::Request,
    ) -> crate::BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            self.remote.lock().unwrap().push(request.clone());
            if self
                .fail_once
                .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                Err(StoreError::unavailable("purger unavailable"))
            } else {
                Ok(())
            }
        })
    }
}
fn cache_config(f: &Fixture, probe: Arc<CacheProbe>) -> crate::purge::PurgeConfig {
    crate::purge::PurgeConfig::new("https://server.example".into(), true, true)
        .with_audit(Arc::new(crate::admin::SystemAudit::new(
            f.work.metadata.clone(),
            f.work.root.clone(),
        )))
        .with_local(probe)
}
async fn purges(store: &Arc<MemoryKv>, partition: &Partition) -> Vec<crate::purge::Request> {
    store
        .scan(
            partition,
            &Key::new(b"cp\0".to_vec()),
            &Key::new(b"cp\x01".to_vec()),
            None,
            100,
        )
        .await
        .unwrap()
        .entries
        .iter()
        .map(|(_, v)| serde_json::from_slice(v.as_bytes()).unwrap())
        .collect()
}
fn purge_service(f: &Fixture) -> Service<Arc<MemoryKv>> {
    Service::new(
        f.work.metadata.clone(),
        f.work.root.clone(),
        f.work.shards.clone(),
    )
    .with_purge(f.work.purge.clone())
}
#[tokio::test]
async fn accepting_takedown_owns_automatic_cache_purge() {
    use crate::timers::{TickBudget, TimerRegistry, run_due};
    let mut f = fixture(&[Object::Blob(Blob { data: vec![9; 32] })], false).await;
    let probe = Arc::new(CacheProbe::default());
    probe
        .fail_once
        .store(true, std::sync::atomic::Ordering::SeqCst);
    f.work.purge = Some(cache_config(&f, probe.clone()));
    let object = f.canonical[0].0;
    let input = json!({"repository":format!("{}/{}", f.repo.namespace.as_str(), f.repo.name.as_str()), "objectIds":[STANDARD.encode(object)], "operationId":"automatic-cache", "reason":"review"});
    let service = purge_service(&f);
    let prepared = service
        .plan(
            TAKEDOWN_PATH,
            &input,
            "automatic-cache",
            10,
            &SliceBudget::new(9000),
        )
        .await
        .unwrap();
    let capabilities = f.work.metadata.capabilities();
    prepared.batch.validate(&capabilities).unwrap();
    assert!(
        prepared
            .batch
            .writes
            .iter()
            .any(|w| matches!(w, crate::Write::Put(k, _) if k.as_bytes().starts_with(b"cp\0")))
    );
    assert!(
        prepared
            .batch
            .writes
            .iter()
            .any(|w| matches!(w, crate::Write::Put(k, _) if k.as_bytes().starts_with(b"or\0")))
    );
    let denied = prepared.batch.clone().require(Precondition::Equals(
        Key::new(b"missing".to_vec()),
        Value::default(),
    ));
    assert!(matches!(
        f.work.metadata.apply(&f.work.root, denied).await.unwrap(),
        BatchOutcome::PreconditionFailed { .. }
    ));
    assert!(purges(&f.work.metadata, &f.work.root).await.is_empty());
    assert_eq!(
        f.work
            .metadata
            .apply(&f.work.root, prepared.batch)
            .await
            .unwrap(),
        BatchOutcome::Committed
    );
    let accepted = purges(&f.work.metadata, &f.work.root).await;
    assert_eq!(
        accepted.len(),
        1,
        "acceptance must durably own a cache purge"
    );
    assert!(accepted[0].object_ids.is_empty()); // whole repository includes all denied objects
    assert_eq!(accepted[0].trigger, crate::purge::Trigger::Takedown);
    // Reconstruct request-side service after acceptance, before activation.
    let cold = purge_service(&f);
    cold.after_commit(
        TAKEDOWN_PATH,
        &input,
        prepared.response.clone(),
        10,
        &SliceBudget::new(9000),
    )
    .await
    .unwrap();
    let activated = purges(&f.work.metadata, &crate::store::content_shard(&object)).await;
    assert_eq!(activated.len(), 1);
    assert_ne!(activated[0].purge_id, accepted[0].purge_id);
    assert_eq!(probe.local.lock().unwrap().len(), 2);
    for now in [10, 2010] {
        f.clock.set(now);
        // A new delivery registry is created on each fire, as after restart.
        let registry = TimerRegistry::new().register(crate::purge::PurgeDelivery::new(
            probe.clone(),
            Some(probe.clone()),
            crate::purge::SliceBudget::new(16),
        ));
        run_due(
            &f.work.metadata,
            &f.work.root,
            &registry,
            f.clock.as_ref(),
            u64::try_from(now).unwrap(),
            &TickBudget::new(32, 32, 128, 1000),
        )
        .await
        .unwrap();
        if now == 10 {
            assert_eq!(purges(&f.work.metadata, &f.work.root).await, accepted);
        }
    }
    assert!(purges(&f.work.metadata, &f.work.root).await.is_empty());
    assert_eq!(
        *probe.remote.lock().unwrap(),
        [accepted[0].clone(), accepted[0].clone()]
    );
}

#[tokio::test]
async fn discovery_checkpoints_purge_for_holders_and_namespace_members() {
    let mut f = fixture(&[small()], false).await;
    let probe = Arc::new(CacheProbe::default());
    f.work.purge = Some(cache_config(&f, probe.clone()));
    let object = f.canonical[0].0;
    let holder =
        crate::store::Holder::new(f.repo.namespace.clone(), RepoName::new("holder").unwrap());
    ContentIndex::new(BorrowedStore(&f.work.metadata))
        .add_holder(&object, &holder, &[9; 32], None, 10)
        .await
        .unwrap();
    let hidden = RepoId {
        namespace: f.repo.namespace.clone(),
        name: RepoName::new("hidden").unwrap(),
    };
    let index = f
        .work
        .metadata
        .get(
            &SinglePartition.object_index(&f.repo, &object),
            &keys::object_index(&f.repo.name, &object, &f.pack),
        )
        .await
        .unwrap()
        .unwrap();
    f.work
        .metadata
        .apply(
            &Partition::Namespace(hidden.namespace.clone()),
            Batch::new()
                .put(
                    keys::repo_record(&hidden.name),
                    codec::encode_repo_record(&codec::RepoRecord { created_at_ms: 10 }),
                )
                .put(keys::membership(&hidden.name, &f.pack), Value::default())
                .put(keys::object_index(&hidden.name, &object, &f.pack), index),
        )
        .await
        .unwrap();
    let id = accept(&f, "cache-discovery", None, &[object]).await;
    for _ in 0..150 {
        let (state, calls) = advance(&f, id, 50_000).await;
        assert!(calls <= 700);
        if state.phase == Phase::Retain {
            break;
        }
    }
    let requests = purges(&f.work.metadata, &f.work.root).await;
    for name in ["holder", "hidden"] {
        assert!(
            requests
                .iter()
                .any(|r| r.repository == format!("{}/{name}", f.repo.namespace.as_str())),
            "missing purge for {name}"
        );
    }
    assert!(
        f.work
            .state(&f.work.metadata, &id, 10)
            .await
            .unwrap()
            .0
            .discovery_complete
    );
}

struct ParentChargedLocal {
    parent: SliceBudget,
    effects: std::sync::atomic::AtomicU32,
    attempts: std::sync::atomic::AtomicU32,
}
impl crate::purge::LocalInvalidation for ParentChargedLocal {
    fn invalidate<'a>(
        &'a self,
        _: &'a crate::purge::Request,
        cursor: u32,
        budget: &'a crate::purge::SliceBudget,
    ) -> crate::BoxFuture<'a, Result<Option<u32>, StoreError>> {
        Box::pin(async move {
            use std::sync::atomic::Ordering;
            self.attempts.fetch_add(1, Ordering::SeqCst);
            let before = self.parent.used();
            let mut effects = 0;
            for index in cursor..16 {
                if !budget.charge(2) {
                    assert_eq!(self.parent.used() - before, effects * 2);
                    return Ok(Some(index));
                }
                self.effects.fetch_add(1, Ordering::SeqCst);
                effects += 1;
            }
            assert_eq!(
                self.parent.used() - before,
                effects * 2,
                "cache enumeration/deletes are charged before effects"
            );
            Ok(None)
        })
    }
}
#[tokio::test]
async fn multi_action_activation_shares_one_immediate_allowance_with_parent_calls() {
    use std::sync::atomic::Ordering;
    let mut f = fixture(
        &[
            Object::Blob(Blob { data: vec![1; 32] }),
            Object::Blob(Blob { data: vec![2; 32] }),
            Object::Blob(Blob { data: vec![3; 32] }),
        ],
        false,
    )
    .await;
    let parent = SliceBudget::new(4000);
    let local = Arc::new(ParentChargedLocal {
        parent: parent.clone(),
        effects: 0.into(),
        attempts: 0.into(),
    });
    f.work.purge = Some(
        crate::purge::PurgeConfig::new("https://server.example".into(), false, false)
            .with_audit(Arc::new(crate::admin::SystemAudit::new(
                f.work.metadata.clone(),
                f.work.root.clone(),
            )))
            .with_local(local.clone()),
    );
    let ids: Vec<_> = f
        .canonical
        .iter()
        .map(|(id, _)| STANDARD.encode(id))
        .collect();
    let input = json!({"repository":format!("{}/{}", f.repo.namespace.as_str(), f.repo.name.as_str()), "objectIds":ids, "operationId":"shared-cache-budget", "reason":"review"});
    let service = Service::new(
        f.work.metadata.clone(),
        f.work.root.clone(),
        f.work.shards.clone(),
    )
    .with_purge(f.work.purge.clone());
    let prepared = service
        .plan(
            TAKEDOWN_PATH,
            &input,
            "shared-cache-budget",
            10,
            &SliceBudget::new(9000),
        )
        .await
        .unwrap();
    assert_eq!(
        f.work
            .metadata
            .apply(&f.work.root, prepared.batch)
            .await
            .unwrap(),
        BatchOutcome::Committed
    );
    service
        .after_commit(
            TAKEDOWN_PATH,
            &input,
            prepared.response.clone(),
            10,
            &parent,
        )
        .await
        .unwrap();
    assert_eq!(
        local.attempts.load(Ordering::SeqCst),
        4,
        "acceptance plus every activation attempts local invalidation"
    );
    assert_eq!(
        local.effects.load(Ordering::SeqCst),
        32,
        "one shared 64-operation enumeration/deletion allowance"
    );
    assert!(parent.used() >= 64 && parent.used() <= 4000);
    assert_eq!(purges(&f.work.metadata, &f.work.root).await.len(), 1);
    for (object, _) in &f.canonical {
        assert_eq!(
            purges(&f.work.metadata, &crate::store::content_shard(object))
                .await
                .len(),
            1,
            "exhausted immediate work remains durably owned by timer11"
        );
    }
}
