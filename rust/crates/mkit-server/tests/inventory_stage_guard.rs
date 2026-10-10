//! Full scheduled verification with storage I/O advancing the business clock.
#![cfg(feature = "memory")]
#![allow(clippy::unwrap_used)]
mod support;
use mkit_core::{
    hash::{Hash, hash},
    object::{Blob, EntryMode, Object, Tree, TreeEntry},
    pack::PackWriter,
    serialize::serialize,
};
use mkit_server::{
    Clock, Key, ManualClock, MemoryBlobStore, MemoryKv, NamespaceKey, NamespaceStore, RepoId,
    RepoName, StoreError, Value,
};
use mkit_server::{
    indexed::{
        self, IndexedConfig,
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

/// A pack of `count` blobs and a tree naming each, then a signed commit on the
/// last tree: every tree stages with its own reference page.
fn tree_heavy_pack(count: u16) -> (Vec<u8>, Hash) {
    let mut writer = PackWriter::new_raw_only();
    let mut last = None;
    // Blobs first: the trees then arrive as one run of paged entries.
    for n in 0..count {
        writer.push_raw(blob(n, 8).0, &blob(n, 8).1).unwrap();
    }
    for n in 0..count {
        let tree = Object::Tree(Tree {
            entries: vec![TreeEntry {
                name: format!("f{n:05}").into_bytes(),
                mode: EntryMode::Blob,
                object_hash: blob(n, 8).0,
            }],
        });
        writer
            .push_raw(tree.id().unwrap(), &serialize(&tree).unwrap())
            .unwrap();
        last = Some(tree.id().unwrap());
    }
    let (commit, head) = signed_commit(last.unwrap(), Vec::new(), 7, b"head");
    writer.push_raw(head, &serialize(&commit).unwrap()).unwrap();
    (writer.finish().unwrap(), head)
}

/// What the pack under test looks like.
#[derive(Clone, Copy, Default)]
struct Shape {
    /// A takedown of one object lands just before the first batch's inventory
    /// apply, after the batch was decoded.
    race: bool,
    /// Every object is a one-entry tree beside its blob, or a commit.
    tree_heavy: bool,
    /// Bytes per blob when set.
    blob_bytes: Option<usize>,
}

async fn verifies(objects: u16, fault: Option<&'static str>) {
    Box::pin(verifies_with(objects, fault, Shape::default())).await;
}

#[allow(clippy::too_many_lines)] // Keep the full alarm-driven fixture and progress assertions together.
async fn verifies_with(objects: u16, fault: Option<&'static str>, shape: Shape) {
    let race = shape.race;
    let events = Events::default();
    let _subscriber = tracing::subscriber::set_default(events.clone());
    let clock = Arc::new(ManualClock::new(1_700_000_000_000));
    let inner = Arc::new(MemoryKv::with_clock(clock.clone()));
    let store = Slow {
        inner: inner.clone(),
        clock: clock.clone(),
        stages: Arc::default(),
        fault,
        barrier: None,
        heads: Arc::default(),
        ledger: Arc::default(),
        race_block: Arc::new(std::sync::Mutex::new(race.then(|| blob(5, 8).0))),
    };
    let blobs = Shared(Arc::new(MemoryBlobStore::default()), clock.clone());
    let (bytes, head) = if shape.tree_heavy {
        tree_heavy_pack((objects - 1) / 2)
    } else {
        tree_pack(objects - 2, shape.blob_bytes.unwrap_or(8))
    };
    let pack = hash(&bytes);
    let owner = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    let namespace = mkit_core::repo_identity::Namespace::Ed25519(*owner.verifying_key().as_bytes());
    let repo = RepoId {
        namespace: NamespaceKey::from_namespace(&namespace),
        name: RepoName::new("slow-verification").unwrap(),
    };
    let shards: Arc<dyn ShardMap> = Arc::new(D34Shards);
    let source = shards.ref_shard(&repo, "refs/heads/main");
    let mut cfg = IndexedConfig::scheduled(1 << 30);
    if shape.blob_bytes.is_some() {
        // Large blobs are the point; they need no extraction here.
        cfg.extract_min_bytes = 8 << 20;
    }
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
    let started = clock.now_ms();
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
    let handler = VerifyTimer {
        remote: store.clone(),
        blobs: blobs.clone(),
        windows: Windows {
            blobs: blobs.clone(),
        },
        shards,
        cfg,
        limits: if shape.tree_heavy {
            // A slice that ends mid-run of paged entries, between batches.
            let mut limits = SliceLimits::default();
            limits.max_subrequests = 200;
            limits
        } else {
            SliceLimits::default()
        },
        lease: LeaseParams::default(),
        clock: clock.clone(),
        metrics: recorder.clone(),
        extension: FailClosedExtraction,
    };
    let registry =
        TimerRegistry::new()
            .register(handler)
            .register(mkit_server::relay::RelayHandler {
                target: store.clone(),
                hook: mkit_server::relay::NoHook,
                budget: mkit_server::relay::RelayBudget::default(),
            });
    let mut waits = 0;
    let mut failed_waits = 0;
    let mut max_jobs = 0;
    let mut failures = 0;
    let mut previous_entries = 0;
    for attempt in 1_u32..=1024 {
        let now = u64::try_from(clock.now_ms()).unwrap();
        let before_jobs = store.ledger.lock().unwrap().job_writes;
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
        max_jobs = max_jobs.max(store.ledger.lock().unwrap().job_writes - before_jobs);
        let (job, state) = checkpoint::read_job(inner.as_ref(), &source, &repo.name, &pack)
            .await
            .unwrap();
        let job = job.unwrap().0;
        if report.failed > 0 {
            assert!(
                fault.is_some(),
                "{objects} objects: attempt {attempt}, phase {:?}, durable entries {}",
                job.phase,
                job.entries
            );
            assert_eq!(job.phase, Phase::Decode);
            assert!(
                job.entries > previous_entries,
                "retry failed without strictly more durable progress"
            );
            failures += report.failed;
        }
        assert!(job.entries >= previous_entries, "durable cursor regressed");
        previous_entries = job.entries;
        let map_ready = checkpoint::read_job(inner.as_ref(), &source, &repo.name, &map)
            .await
            .unwrap()
            .0
            .is_some_and(|(job, _)| job.usable());
        if race && job.phase == Phase::Watch {
            // The takedown landed after the batch's decode and before its
            // apply: the denial reads that follow the apply refuse it.
            assert_eq!(job.outcome, Some(indexed::checkpoint::Outcome::Blocked));
            assert!(!job.usable());
            assert!(store.race_block.lock().unwrap().is_none());
            let auth = authenticate(&pipe, &clock, mkit_server::Procedure::AdvanceRefs, 4);
            let refused = pipe
                .advance_refs_with_tickets(
                    &auth,
                    advance("refs/heads/main", head),
                    advance("refs/mkit/packmap/main", map),
                    tickets.clone(),
                )
                .await;
            assert!(refused.is_err(), "a blocked pack must not publish");
            return;
        }
        if job.phase == Phase::Watch && map_ready {
            assert!(job.usable(), "verification outcome: {:?}", job.outcome);
            assert!(matches!(
                state,
                Some((indexed::state::VerificationV1::Verified { .. }, _))
            ));
            assert_eq!(job.entries, u64::from(objects));
            if let Some(label) = fault {
                assert!(failures > 1, "fault test must exercise repeated retry");
                assert!(
                    recorder
                        .results
                        .lock()
                        .unwrap()
                        .iter()
                        .any(|(r, p, v)| r == label && p == "checkpointed" && *v > 0.0)
                );
            }
            eprintln!(
                "{objects} objects completed in {} verification timer fires, {attempt} alarm ticks ({failures} failed retries); entries={}",
                recorder.attempts.load(Ordering::SeqCst),
                job.entries
            );
            let auth = authenticate(&pipe, &clock, mkit_server::Procedure::AdvanceRefs, 4);
            assert_eq!(
                pipe.advance_refs_with_tickets(
                    &auth,
                    advance("refs/heads/main", head),
                    advance("refs/mkit/packmap/main", map),
                    tickets.clone()
                )
                .await
                .unwrap(),
                mkit_core::protocol::AdvanceOutcome::Committed
            );
            let mut publication_ticks = 0;
            loop {
                let auth = authenticate(&pipe, &clock, mkit_server::Procedure::ListRefs, 5);
                let refs = pipe.list_refs(&auth, "refs/heads/").await.unwrap();
                if refs
                    .iter()
                    .any(|entry| entry.name == "main" && entry.id == head)
                {
                    break;
                }
                publication_ticks += 1;
                assert!(publication_ticks < 10);
                run_due(
                    &store,
                    &source,
                    &registry,
                    clock.as_ref(),
                    u64::try_from(clock.now_ms()).unwrap(),
                    &TickBudget::default(),
                )
                .await
                .unwrap();
            }
            let results = recorder.results.lock().unwrap();
            let checkpoints: f64 = results
                .iter()
                .filter(|(_, progress, _)| progress == "checkpointed")
                .map(|(_, _, value)| *value)
                .sum();
            let max_checkpoints = results
                .iter()
                .filter(|(_, progress, _)| progress == "checkpointed")
                .map(|(_, _, value)| *value)
                .fold(0.0_f64, f64::max);
            let ledger = store.ledger.lock().unwrap();
            assert!((checkpoints - f64::from(objects)).abs() < f64::EPSILON);
            let elapsed = clock.now_ms() - started;
            if fault.is_none() {
                assert_eq!(failures, 0);
                assert_eq!(failed_waits, 0);
                // Successful slices have no fixed alarm cadence or retry backoff.
                // Allow one delivery wait, plus the driver's immediate wake ticks.
                assert!(waits <= u64::from(attempt) * 2 + 2_000);
                assert!(elapsed <= i64::from(objects) * 700 + 20_000);
            }
            eprintln!(
                "CHECKPOINTS objects={objects} entries={checkpoints} max_per_slice={max_checkpoints}"
            );
            eprintln!(
                "LEDGER objects={objects} publication_ticks={publication_ticks} elapsed_ms={} waits_ms={waits} failed_waits_ms={failed_waits} calls={} job_writes={} max_jobs_tick={max_jobs} max_ops={} max_bytes={}",
                elapsed,
                ledger.calls,
                ledger.job_writes,
                ledger.max_batch_ops,
                ledger.max_batch_bytes
            );
            if fault.is_none() {
                let sums = attribution(
                    &events,
                    objects,
                    !shape.tree_heavy && shape.blob_bytes.is_none(),
                );
                eprintln!("{sums}");
            }
            eprintln!(
                "INVENTORY objects={objects} reads={} applies={} total={} max_ops={}",
                ledger.inventory_reads,
                ledger.inventory_applies,
                ledger.inventory_reads + ledger.inventory_applies,
                ledger.max_inventory_ops
            );
            if shape.blob_bytes.is_some() {
                // Each 200 KiB blob counts 400 KiB: two per group, so ten blobs
                // take five applies where tiny ones take one. The plain 12-object
                // shape applies 4 times in all; this one applies 8.
                assert_eq!(ledger.inventory_applies, 8);
            }
            return;
        }
        let next = report
            .next_wake_ms
            .unwrap_or(now + 1_000)
            .max(u64::try_from(clock.now_ms()).unwrap() + 1);
        let wait = next - u64::try_from(clock.now_ms()).unwrap();
        waits += wait;
        if report.failed > 0 {
            failed_waits += wait;
        }
        clock.set(i64::try_from(next).unwrap());
    }
    panic!("{objects} objects exceeded 1024 alarm ticks");
}
/// Sum the per-slice Decode attribution; assert it accounts for every object.
fn attribution(events: &Events, objects: u16, plain: bool) -> String {
    let logs = events.0.lock().unwrap();
    let mut sum = std::collections::BTreeMap::<&str, u64>::new();
    let mut decode_slices = 0_u64;
    for event in logs.iter().filter(|e| {
        e.get("event")
            .is_some_and(|v| v == "verification_inventory_progress")
    }) {
        assert_eq!(event.len(), 18, "fixed fields only: {event:?}");
        decode_slices += u64::from(event["entries_checkpointed"] != "0");
        for key in [
            "entries_staged",
            "entries_checkpointed",
            "remote_inventory_calls",
            "inventory_batches",
            "denial_calls",
            "window_read_ms",
            "decode_ms",
            "denial_ms",
            "staging_duration_ms",
            "write_ms",
            "checkpoint_ms",
        ] {
            *sum.entry(key).or_default() += event[key].parse::<u64>().unwrap();
        }
    }
    let objects = u64::from(objects);
    // The packmap's own MKPL facts are staged by its Decode slice too.
    assert_eq!(sum["entries_staged"], objects + 1);
    assert_eq!(sum["entries_checkpointed"], objects);
    assert_eq!(sum["denial_calls"], objects, "one denial read per object");
    // Hundredths of a remote call per object: denial plus staging.
    let per_entry = (sum["remote_inventory_calls"] + sum["denial_calls"]) * 100 / objects;
    // Main spent four calls per object and ended a slice after 48 objects.
    // Small packs are dominated by their paged tree and commit.
    if objects >= 100 && plain {
        assert!(per_entry <= 125, "remote calls per entry x100: {per_entry}");
        assert!(
            decode_slices <= objects.div_ceil(170),
            "{decode_slices} Decode slices for {objects} objects"
        );
    }
    format!(
        "ATTRIBUTION objects={objects} decode_slices={decode_slices} remote_calls_per_entry_x100={per_entry} {sum:?}"
    )
}
#[tokio::test(start_paused = true)]
async fn decode_inventory_500_objects_at_50ms() {
    Box::pin(verifies(500, None)).await;
}
#[tokio::test(start_paused = true)]
#[ignore = "large scheduled verification; exercised by the ignored-lane CI profile"]
async fn decode_inventory_3000_objects_at_50ms() {
    Box::pin(verifies(3000, None)).await;
}

/// Two hundred trees, each staged alone with a reference page, must neither
/// exhaust a slice's subrequest budget (a failed fire) nor skip an entry.
#[tokio::test(start_paused = true)]
async fn tree_heavy_batches_settle_inside_the_slice_budget() {
    Box::pin(verifies_with(
        401,
        None,
        Shape {
            tree_heavy: true,
            ..Shape::default()
        },
    ))
    .await;
}

/// Decoded entries over the batch's memory allowance settle in smaller groups.
#[tokio::test(start_paused = true)]
async fn large_entries_settle_in_groups_under_the_batch_memory_bound() {
    Box::pin(verifies_with(
        12,
        None,
        Shape {
            blob_bytes: Some(200 << 10),
            ..Shape::default()
        },
    ))
    .await;
}

#[tokio::test(start_paused = true)]
async fn a_takedown_landing_before_a_batch_apply_still_blocks_the_pack() {
    Box::pin(verifies_with(
        60,
        None,
        Shape {
            race: true,
            ..Shape::default()
        },
    ))
    .await;
}

#[tokio::test(start_paused = true)]
async fn decode_retries_checkpoint_strict_progress_after_cas_contention() {
    Box::pin(verifies(400, Some("cas_contention"))).await;
}
#[tokio::test(start_paused = true)]
async fn decode_retries_checkpoint_strict_progress_after_expiry() {
    Box::pin(verifies(400, Some("expired"))).await;
}

#[tokio::test(start_paused = true)]
async fn concurrent_inventory_stagers_keep_cas_and_distinct_expiry() {
    use mkit_server::takedown::inventory::{self, StagingFailure};
    let clock = Arc::new(ManualClock::new(0));
    let inner = Arc::new(MemoryKv::with_clock(clock.clone()));
    let store = Slow {
        inner: inner.clone(),
        clock: clock.clone(),
        stages: Arc::default(),
        fault: None,
        barrier: Some(Arc::new(tokio::sync::Barrier::new(2))),
        heads: Arc::default(),
        ledger: Arc::default(),
        race_block: Arc::default(),
    };
    let pack = [7; 32];
    let a = Object::Blob(Blob { data: vec![1] });
    let b = Object::Blob(Blob { data: vec![2] });
    let aid = a.id().unwrap();
    let bid = b.id().unwrap();
    let (left, right, reads) = tokio::join!(
        inventory::stage(&store, &pack, 100, &aid, &a, None, 0),
        inventory::stage(&store, &pack, 100, &bid, &b, None, 0),
        async {
            for _ in 0..32 {
                inventory::entry(&store, &pack, &aid).await.unwrap();
                inventory::entry(&store, &pack, &bid).await.unwrap();
            }
            64
        }
    );
    assert_eq!(reads, 64);
    assert_eq!(store.ledger.lock().unwrap().cas_retries, 1);
    assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
    let failed = left.as_ref().err().or(right.as_ref().err()).unwrap();
    let StoreError::Unavailable(source) = failed else {
        panic!("expected typed contention")
    };
    assert!(matches!(
        source.downcast_ref::<StagingFailure>(),
        Some(StagingFailure::CasContention { index: 0 })
    ));
    inventory::stage(&store, &pack, 100, &aid, &a, None, 0)
        .await
        .unwrap();
    inventory::stage(&store, &pack, 100, &bid, &b, None, 0)
        .await
        .unwrap();
    inventory::complete(&store, &pack, 100, 0).await.unwrap();
    let mut ids = std::collections::BTreeSet::new();
    inventory::visit(inner.as_ref(), &pack, false, |id, _| {
        ids.insert(id);
        async { Ok(false) }
    })
    .await
    .unwrap();
    assert_eq!(ids, std::collections::BTreeSet::from([aid, bid]));
    clock.advance(10_001);
    let failure = inventory::stage(&store, &[8; 32], 100, &aid, &a, None, 0)
        .await
        .unwrap_err();
    let StoreError::Unavailable(source) = failure else {
        panic!("expected typed expiry")
    };
    assert!(matches!(
        source.downcast_ref::<StagingFailure>(),
        Some(StagingFailure::Expired { .. })
    ));
}

#[tokio::test(start_paused = true)]
async fn small_inventory_write_shapes_at_50ms() {
    Box::pin(verifies(3, None)).await;
    Box::pin(verifies(12, None)).await;
}

fn slow_store(clock: Arc<ManualClock>) -> Slow {
    Slow {
        inner: Arc::new(MemoryKv::with_clock(clock.clone())),
        clock,
        stages: Arc::default(),
        fault: None,
        barrier: None,
        heads: Arc::default(),
        ledger: Arc::default(),
        race_block: Arc::default(),
    }
}

async fn inventory_rows(store: &MemoryKv, pack: &Hash) -> Vec<(Key, Value)> {
    store
        .scan(
            &mkit_server::store::content_shard(pack),
            &Key::new(vec![]),
            &Key::new(vec![255]),
            None,
            100,
        )
        .await
        .unwrap()
        .entries
}

#[tokio::test(start_paused = true)]
async fn reference_free_staging_lost_reply_preserves_exact_inventory_and_first_occurrence() {
    use mkit_server::takedown::inventory;
    let pack = [11; 32];
    // The entry row holds lengths, never these bytes: entry size cannot expand
    // its apply or the three awaited storage calls inside its deadline.
    let object = Object::Blob(Blob {
        data: vec![1; 16 << 20],
    });
    let id = object.id().unwrap();
    let clock = Arc::new(ManualClock::new(0));
    let reference = slow_store(clock.clone());
    inventory::stage(&reference, &pack, 100, &id, &object, None, 0)
        .await
        .unwrap();
    assert_eq!(reference.ledger.lock().unwrap().calls, 3);
    assert_eq!(clock.now_ms(), 150);
    assert_eq!(reference.ledger.lock().unwrap().max_inventory_ops, 6);
    inventory::complete(&reference, &pack, 100, 0)
        .await
        .unwrap();

    let mut replay = slow_store(Arc::new(ManualClock::new(0)));
    replay.fault = Some("lost_reply");
    replay.stages.store(6, Ordering::SeqCst);
    assert!(
        inventory::stage(&replay, &pack, 100, &id, &object, None, 0)
            .await
            .is_err()
    );
    // Crash before the caller can checkpoint, then replay with a different
    // occurrence's base. The committed first occurrence must still own the row.
    let calls = replay.ledger.lock().unwrap().calls;
    inventory::stage(&replay, &pack, 100, &id, &object, Some([12; 32]), 0)
        .await
        .unwrap();
    assert_eq!(replay.ledger.lock().unwrap().calls - calls, 1);
    inventory::complete(&replay, &pack, 100, 0).await.unwrap();
    assert_eq!(
        inventory_rows(&reference.inner, &pack).await,
        inventory_rows(&replay.inner, &pack).await
    );
}

#[tokio::test(start_paused = true)]
async fn concurrent_packs_sharing_reference_free_objects_do_not_contend() {
    use mkit_server::takedown::inventory;
    let store = slow_store(Arc::new(ManualClock::new(0)));
    let object = Object::Blob(Blob { data: vec![1] });
    let id = object.id().unwrap();
    let a = [21; 32];
    let b = [22; 32];
    let (left, right) = tokio::join!(
        inventory::stage(&store, &a, 100, &id, &object, None, 0),
        inventory::stage(&store, &b, 100, &id, &object, None, 0)
    );
    left.unwrap();
    right.unwrap();
    assert_eq!(store.ledger.lock().unwrap().cas_retries, 0);
    assert_eq!(store.ledger.lock().unwrap().calls, 6);
    inventory::complete(&store, &a, 100, 0).await.unwrap();
    inventory::complete(&store, &b, 100, 0).await.unwrap();
    let left = inventory::entry(&store, &a, &id).await.unwrap().unwrap();
    let right = inventory::entry(&store, &b, &id).await.unwrap().unwrap();
    assert_eq!(
        (left.kind, left.canonical_len, left.base),
        (right.kind, right.canonical_len, right.base)
    );
    assert_eq!(left.references.action.id, id);
    assert_eq!(right.references.action.id, id);
    assert_eq!(left.references.action.takedown_id, a);
    assert_eq!(right.references.action.takedown_id, b);
}
