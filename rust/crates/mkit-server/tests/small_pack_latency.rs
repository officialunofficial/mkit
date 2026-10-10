//! Small-pack scheduled verification latency with every storage call taking 50 ms:
//! chained Extract selection steps against one step per slice.
#![cfg(feature = "memory")]
#![allow(clippy::unwrap_used)]
mod support;
use mkit_core::{
    hash::{Hash, hash},
    object::{EntryMode, Object, Tree, TreeEntry},
    pack::PackWriter,
    serialize::serialize,
};
use mkit_server::{Clock, ManualClock, MemoryBlobStore, MemoryKv, NamespaceKey, RepoId, RepoName};
use mkit_server::{
    indexed::{
        IndexedConfig,
        checkpoint::{self, Phase},
        job::{FailClosedExtraction, SliceLimits, VerifyTimer},
    },
    pipeline::{D34Shards, LeaseParams, ShardMap},
    timers::{TickBudget, TimerRegistry, run_due},
};
use std::sync::{Arc, atomic::Ordering};
use support::*;

/// A pack of `count` blobs of `size` bytes, a tree naming them and a signed
/// commit on it. Returns the pack, its head, the tree and the blob ids.
fn tree_pack(count: u16, size: usize) -> (Vec<u8>, Hash) {
    let mut writer = PackWriter::new_raw_only();
    let mut entries = Vec::new();
    for n in 0..count {
        let (id, raw) = blob(n, size);
        writer.push_raw(id, &raw).unwrap();
        entries.push(TreeEntry {
            name: format!("f{n:05}").into_bytes(),
            mode: EntryMode::Blob,
            object_hash: id,
        });
    }
    let tree = Object::Tree(Tree { entries });
    writer
        .push_raw(tree.id().unwrap(), &serialize(&tree).unwrap())
        .unwrap();
    let (commit, head) = signed_commit(tree.id().unwrap(), Vec::new(), 7, b"head");
    writer.push_raw(head, &serialize(&commit).unwrap()).unwrap();
    (writer.finish().unwrap(), head)
}

/// An extraction-enabled run that finds nothing to extract, as on the Worker.
#[derive(Clone, Copy)]
struct Enabled;
impl mkit_server::indexed::job::SliceExtension for Enabled {
    fn needs_extraction(&self, object: &Object, cfg: &IndexedConfig) -> bool {
        FailClosedExtraction.needs_extraction(object, cfg)
    }
    fn extraction_enabled(&self) -> bool {
        true
    }
}

struct Run {
    elapsed_ms: i64,
    slices: u32,
    calls: u64,
}

#[allow(clippy::too_many_lines)] // One alarm-driven fixture, kept together.
async fn measure(objects: u16, chain: u32) -> Run {
    let clock = Arc::new(ManualClock::new(1_700_000_000_000));
    let inner = Arc::new(MemoryKv::with_clock(clock.clone()));
    let store = Slow {
        inner: inner.clone(),
        clock: clock.clone(),
        stages: Arc::default(),
        fault: None,
        barrier: None,
        heads: Arc::default(),
        ledger: Arc::default(),
        race_block: Arc::default(),
    };
    let blobs = Shared(Arc::new(MemoryBlobStore::default()), clock.clone());
    let (bytes, head) = tree_pack(objects.saturating_sub(2), 8);
    let pack = hash(&bytes);
    let owner = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    let namespace = mkit_core::repo_identity::Namespace::Ed25519(*owner.verifying_key().as_bytes());
    let repo = RepoId {
        namespace: NamespaceKey::from_namespace(&namespace),
        name: RepoName::new("slow-verification").unwrap(),
    };
    let shards: Arc<dyn ShardMap> = Arc::new(D34Shards);
    let source = shards.ref_shard(&repo, "refs/heads/main");
    let cfg = IndexedConfig::scheduled(1 << 30);
    let recorder = Arc::new(Recorder::default());
    let mut pipeline_cfg = mkit_server::pipeline::PipelineConfig::new(
        mkit_server::Addressing::Multi(mkit_server::MultiAddressing::new().with_namespace_policy(
            mkit_server::policy::NamespacePolicy::Allowlist([namespace].into()),
        )),
        mkit_server::pipeline::AuthMode::AuthV2(
            mkit_server::auth_v2::AuthV2Config::new(
                "https://verification.example",
                "slow-verification",
            )
            .unwrap(),
        ),
        mkit_server::upload::UploadLimits::new(1 << 30, 64),
    );
    pipeline_cfg.begin_upload_threshold_bytes = 0;
    pipeline_cfg.write_policy = mkit_server::policy::WritePolicy::Owner;
    pipeline_cfg.sharding = mkit_server::pipeline::Sharding::D34;
    pipeline_cfg.indexed = Some(cfg);
    pipeline_cfg.ticket_keys =
        Some(mkit_server::upload::token::TicketKeys::new(vec![("test".into(), [7; 32])]).unwrap());
    let pipe = Pipeline::new(
        blobs.clone(),
        store.clone(),
        mkit_server::pipeline::Hooks::new(),
        pipeline_cfg,
        clock.clone(),
        recorder.clone(),
    )
    .unwrap();
    let packmap_bytes = mkit_core::transfer::encode_packlist(None, &[pack]).unwrap();
    let map = hash(&packmap_bytes);
    let tickets = vec![
        upload(&pipe, &blobs, &clock, bytes, 1).await,
        upload(&pipe, &blobs, &clock, packmap_bytes, 2).await,
    ];
    let advance = |name: &str, id| mkit_server::RefUpdate {
        name: name.into(),
        condition: mkit_core::refs::RefWriteCondition::Missing,
        new: Some(id),
    };
    let auth = authenticate(&pipe, &clock, mkit_server::Procedure::AdvanceRefs, 3);
    let error = pipe
        .advance_refs_with_tickets(
            &auth,
            advance("refs/heads/main", head),
            advance("refs/mkit/packmap/main", map),
            tickets.clone(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.public_message(), "pack verification pending");
    let started = clock.now_ms();
    let calls_before = store.ledger.lock().unwrap().calls;
    let handler = VerifyTimer {
        remote: store.clone(),
        blobs: blobs.clone(),
        windows: Windows {
            blobs: blobs.clone(),
        },
        shards,
        cfg,
        limits: SliceLimits::default().with_extract_chain_steps(chain),
        lease: LeaseParams::default(),
        clock: clock.clone(),
        metrics: recorder.clone(),
        extension: Enabled,
    };
    let registry =
        TimerRegistry::new()
            .register(handler)
            .register(mkit_server::relay::RelayHandler {
                target: store.clone(),
                hook: mkit_server::relay::NoHook,
                budget: mkit_server::relay::RelayBudget::default(),
            });
    for _ in 0..16_384 {
        let now = u64::try_from(clock.now_ms()).unwrap();
        let report = run_due(
            &store,
            &source,
            &registry,
            clock.as_ref(),
            now,
            &TickBudget::default(),
        )
        .await
        .unwrap();
        assert_eq!(report.failed, 0);
        let job = checkpoint::read_job(inner.as_ref(), &source, &repo.name, &pack)
            .await
            .unwrap()
            .0
            .unwrap()
            .0;
        let map_ready = checkpoint::read_job(inner.as_ref(), &source, &repo.name, &map)
            .await
            .unwrap()
            .0
            .is_some_and(|(job, _)| job.usable());
        if job.phase == Phase::Watch && map_ready {
            assert!(job.usable(), "verification outcome: {:?}", job.outcome);
            assert_eq!(job.entries, u64::from(objects.max(2)));
            return Run {
                elapsed_ms: clock.now_ms() - started,
                slices: recorder.attempts.load(Ordering::SeqCst),
                calls: store.ledger.lock().unwrap().calls - calls_before,
            };
        }
        let next = report
            .next_wake_ms
            .unwrap_or(now + 1_000)
            .max(u64::try_from(clock.now_ms()).unwrap() + 1);
        clock.set(i64::try_from(next).unwrap());
    }
    panic!("{objects} objects exceeded 16384 alarm ticks");
}

#[tokio::test(start_paused = true)]
async fn chained_extract_steps_cut_small_pack_slices_and_time_at_50ms() {
    for objects in [2_u16, 6, 50] {
        let unchained = measure(objects, 1).await;
        let chained = measure(objects, SliceLimits::default().extract_chain_steps).await;
        eprintln!(
            "SP1 objects={objects} unchained: {} ms, {} slices, {} calls; chained: {} ms, {} slices, {} calls",
            unchained.elapsed_ms,
            unchained.slices,
            unchained.calls,
            chained.elapsed_ms,
            chained.slices,
            chained.calls
        );
        assert!(chained.slices < unchained.slices);
        assert!(chained.calls < unchained.calls);
        assert!(chained.elapsed_ms < unchained.elapsed_ms);
        // Selection no longer takes a slice per frame, row and stage.
        assert!(chained.slices <= 8 + u32::from(objects) / 2);
    }
}

#[tokio::test(start_paused = true)]
async fn chained_extract_steps_do_not_slow_large_packs_at_50ms() {
    for objects in [500_u16, 3_000] {
        let unchained = measure(objects, 1).await;
        let chained = measure(objects, SliceLimits::default().extract_chain_steps).await;
        eprintln!(
            "SP1 objects={objects} unchained: {} ms, {} slices, {} calls; chained: {} ms, {} slices, {} calls",
            unchained.elapsed_ms,
            unchained.slices,
            unchained.calls,
            chained.elapsed_ms,
            chained.slices,
            chained.calls
        );
        assert!(chained.slices <= unchained.slices);
        assert!(chained.calls <= unchained.calls);
        assert!(chained.elapsed_ms <= unchained.elapsed_ms);
    }
}
