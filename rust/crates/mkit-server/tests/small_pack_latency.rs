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
use std::{
    sync::{Arc, atomic::Ordering},
    time::Instant,
};
use support::*;

/// A pack of `count` blobs of `size` bytes, a tree naming them and a signed
/// commit on it. Returns the pack, its head, the tree and the blob ids.
fn tree_pack(count: u16, size: usize) -> (Vec<u8>, Hash, Hash) {
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
    (writer.finish().unwrap(), head, tree.id().unwrap())
}

fn commit_pack(tree: Hash, parent: Hash) -> (Vec<u8>, Hash) {
    let (commit, head) = signed_commit(tree, vec![parent], 8, b"single");
    let mut writer = PackWriter::new_raw_only();
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
    alarms: u32,
    calls: u64,
    max_tick_wall_ms: u128,
}

#[allow(clippy::too_many_lines)] // One alarm-driven fixture, kept together.
async fn measure(objects: u16, chain: u32, tiny_slices: u32) -> Run {
    let trace = std::env::var_os("MKIT_LATENCY_TRACE").is_some();
    let events = Events::default();
    let _subscriber = trace.then(|| tracing::subscriber::set_default(events.clone()));
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
    let handler = VerifyTimer {
        remote: store.clone(),
        blobs: blobs.clone(),
        windows: Windows {
            blobs: blobs.clone(),
        },
        shards: shards.clone(),
        cfg,
        limits: SliceLimits::default()
            .with_extract_chain_steps(chain)
            .with_tiny_chain_slices(tiny_slices),
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
    // A commit-only pack needs its tree and parent in already published
    // membership. Prepare that base outside the measured verification run.
    let seed = if objects == 1 {
        let (base_bytes, base_head, tree) = tree_pack(0, 8);
        let base_pack = hash(&base_bytes);
        let base_map_bytes = mkit_core::transfer::encode_packlist(None, &[base_pack]).unwrap();
        let base_map = hash(&base_map_bytes);
        let base_tickets = vec![
            upload(&pipe, &blobs, &clock, base_bytes, 11).await,
            upload(&pipe, &blobs, &clock, base_map_bytes, 12).await,
        ];
        let missing = |name: &str, id| mkit_server::RefUpdate {
            name: name.into(),
            condition: mkit_core::refs::RefWriteCondition::Missing,
            new: Some(id),
        };
        let auth = authenticate(&pipe, &clock, mkit_server::Procedure::AdvanceRefs, 13);
        let pending = pipe
            .advance_refs_with_tickets(
                &auth,
                missing("refs/heads/main", base_head),
                missing("refs/mkit/packmap/main", base_map),
                base_tickets.clone(),
            )
            .await
            .unwrap_err();
        assert_eq!(pending.public_message(), "pack verification pending");
        for _ in 0..4_096 {
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
            let mut ready = true;
            for id in [base_pack, base_map] {
                ready &= checkpoint::read_job(inner.as_ref(), &source, &repo.name, &id)
                    .await
                    .unwrap()
                    .0
                    .is_some_and(|(job, _)| job.usable());
            }
            if ready {
                break;
            }
            let next = report
                .next_wake_ms
                .unwrap_or(now + 1_000)
                .max(u64::try_from(clock.now_ms()).unwrap() + 1);
            clock.set(i64::try_from(next).unwrap());
        }
        let auth = authenticate(&pipe, &clock, mkit_server::Procedure::AdvanceRefs, 14);
        pipe.advance_refs_with_tickets(
            &auth,
            missing("refs/heads/main", base_head),
            missing("refs/mkit/packmap/main", base_map),
            base_tickets,
        )
        .await
        .unwrap();
        Some((tree, base_head, base_map))
    } else {
        None
    };
    let (bytes, head) = seed.map_or_else(
        || {
            let (bytes, head, _) = tree_pack(objects - 2, 8);
            (bytes, head)
        },
        |(tree, parent, _)| commit_pack(tree, parent),
    );
    let pack = hash(&bytes);
    let packmap_bytes =
        mkit_core::transfer::encode_packlist(seed.map(|(_, _, map)| map), &[pack]).unwrap();
    let map = hash(&packmap_bytes);
    let tickets = vec![
        upload(&pipe, &blobs, &clock, bytes, 1).await,
        upload(&pipe, &blobs, &clock, packmap_bytes, 2).await,
    ];
    let advance = |name: &str, id: Hash, old: Option<Hash>| mkit_server::RefUpdate {
        name: name.into(),
        condition: old.map_or(
            mkit_core::refs::RefWriteCondition::Missing,
            mkit_core::refs::RefWriteCondition::Match,
        ),
        new: Some(id),
    };
    let auth = authenticate(&pipe, &clock, mkit_server::Procedure::AdvanceRefs, 3);
    let error = pipe
        .advance_refs_with_tickets(
            &auth,
            advance("refs/heads/main", head, seed.map(|(_, old, _)| old)),
            advance("refs/mkit/packmap/main", map, seed.map(|(_, _, old)| old)),
            tickets.clone(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.public_message(), "pack verification pending");
    let started = clock.now_ms();
    let slices_before = recorder.slice_attempts.load(Ordering::SeqCst);
    let ledger_before = store.ledger.lock().unwrap().by_class.clone();
    events.0.lock().unwrap().clear();
    let calls_before = store.ledger.lock().unwrap().calls;
    let mut max_tick_wall_ms = 0;
    for alarms in 1..=16_384 {
        let now = u64::try_from(clock.now_ms()).unwrap();
        let tick_started = Instant::now();
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
        max_tick_wall_ms = max_tick_wall_ms.max(tick_started.elapsed().as_millis());
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
            assert_eq!(job.entries, u64::from(objects));
            if trace {
                for event in events.0.lock().unwrap().iter().filter(|event| {
                    event.get("event").is_some_and(|name| {
                        name == "verification_slice_result"
                            || name == "verification_inventory_progress"
                    })
                }) {
                    eprintln!("trace tiny={tiny_slices}: {event:?}");
                }
                let ledger = store.ledger.lock().unwrap();
                let delta: std::collections::BTreeMap<_, _> = ledger
                    .by_class
                    .iter()
                    .map(|(name, calls)| {
                        (name, calls - ledger_before.get(name).copied().unwrap_or(0))
                    })
                    .collect();
                eprintln!("ledger tiny={tiny_slices}: {delta:?}");
            }
            return Run {
                elapsed_ms: clock.now_ms() - started,
                alarms,
                slices: recorder.slice_attempts.load(Ordering::SeqCst) - slices_before,
                calls: store.ledger.lock().unwrap().calls - calls_before,
                max_tick_wall_ms,
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
    for objects in [1_u16, 2, 3, 6, 50] {
        let unchained = measure(objects, 1, 1).await;
        let chained = measure(objects, SliceLimits::default().extract_chain_steps, 1).await;
        eprintln!(
            "SP1 objects={objects} unchained: {} ms, {} slices, {} calls, max tick {} ms; chained: {} ms, {} slices, {} calls, max tick {} ms",
            unchained.elapsed_ms,
            unchained.slices,
            unchained.calls,
            unchained.max_tick_wall_ms,
            chained.elapsed_ms,
            chained.slices,
            chained.calls,
            chained.max_tick_wall_ms
        );
        assert!(chained.slices < unchained.slices);
        assert!(chained.calls < unchained.calls);
        assert!(chained.elapsed_ms < unchained.elapsed_ms);
        // Selection no longer takes a slice per frame, row and stage.
        assert!(chained.slices <= 12 + u32::from(objects) / 2);
    }
}

#[tokio::test(start_paused = true)]
async fn chained_extract_steps_do_not_slow_large_packs_at_50ms() {
    for objects in [500_u16, 3_000] {
        let unchained = measure(objects, 1, 1).await;
        let chained = measure(objects, SliceLimits::default().extract_chain_steps, 1).await;
        eprintln!(
            "SP1 objects={objects} unchained: {} ms, {} slices, {} calls, max tick {} ms; chained: {} ms, {} slices, {} calls, max tick {} ms",
            unchained.elapsed_ms,
            unchained.slices,
            unchained.calls,
            unchained.max_tick_wall_ms,
            chained.elapsed_ms,
            chained.slices,
            chained.calls,
            chained.max_tick_wall_ms
        );
        let default_tiny = measure(
            objects,
            SliceLimits::default().extract_chain_steps,
            SliceLimits::default().tiny_chain_slices,
        )
        .await;
        eprintln!(
            "default tiny objects={objects}: {} ms, {} alarms, {} slices, {} calls",
            default_tiny.elapsed_ms, default_tiny.alarms, default_tiny.slices, default_tiny.calls
        );
        assert!(default_tiny.alarms <= chained.alarms);
        assert!(default_tiny.slices <= chained.slices);
        assert!(default_tiny.calls <= chained.calls);
        assert!(default_tiny.elapsed_ms <= chained.elapsed_ms);
        assert!(chained.slices <= unchained.slices);
        assert!(chained.calls <= unchained.calls);
        assert!(chained.elapsed_ms <= unchained.elapsed_ms);
    }
}

async fn assert_consecutive_tiny(objects: u16) {
    let single = measure(objects, SliceLimits::default().extract_chain_steps, 1).await;
    let tiny = measure(objects, SliceLimits::default().extract_chain_steps, 8).await;
    eprintln!(
        "tiny objects={objects} single: {} ms, {} alarms, {} slices, {} calls; consecutive: {} ms, {} alarms, {} slices, {} calls",
        single.elapsed_ms,
        single.alarms,
        single.slices,
        single.calls,
        tiny.elapsed_ms,
        tiny.alarms,
        tiny.slices,
        tiny.calls
    );
    assert!(tiny.alarms < single.alarms);
    assert!(tiny.elapsed_ms < single.elapsed_ms);
    assert!(tiny.calls <= single.calls);
}

#[tokio::test(start_paused = true)]
async fn consecutive_one_entry_slices_reduce_alarms_and_modeled_latency() {
    assert_consecutive_tiny(1).await;
}

#[tokio::test(start_paused = true)]
async fn consecutive_three_entry_slices_reduce_alarms_and_modeled_latency() {
    assert_consecutive_tiny(3).await;
}
