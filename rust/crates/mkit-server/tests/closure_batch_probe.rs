//! A push whose tree names every existing file: owed closure children are
//! looked up in batches, so its storage calls stay near the small-tree case.
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
        self, IndexedConfig,
        checkpoint::{self, Phase},
        job::{FailClosedExtraction, SliceLimits, VerifyTimer},
    },
    pipeline::{D34Shards, LeaseParams, ShardMap},
    timers::{TickBudget, TimerRegistry, run_due},
};
use std::sync::{Arc, atomic::Ordering};
use support::*;

fn tree_pack_ids(count: u16, size: usize) -> (Vec<u8>, Hash, Vec<Hash>) {
    let mut writer = PackWriter::new_raw_only();
    let mut entries = Vec::new();
    let mut ids = Vec::new();
    for n in 0..count {
        let (id, raw) = blob(n, size);
        writer.push_raw(id, &raw).unwrap();
        ids.push(id);
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
    ids.push(tree.id().unwrap());
    let (commit, head) = signed_commit(tree.id().unwrap(), Vec::new(), 7, b"head");
    writer.push_raw(head, &serialize(&commit).unwrap()).unwrap();
    ids.push(head);
    (writer.finish().unwrap(), head, ids)
}
/// Remix-shaped follow-on: one new file, a tree that names every old file plus the new one, one commit.
fn follow_pack(count: u16, size: usize, parent: Hash, full: bool) -> (Vec<u8>, Hash) {
    let mut writer = PackWriter::new_raw_only();
    let mut entries = Vec::new();
    for n in 0..(if full { count } else { 1 }) {
        let (id, _) = blob(n, size);
        entries.push(TreeEntry {
            name: format!("f{n:05}").into_bytes(),
            mode: EntryMode::Blob,
            object_hash: id,
        });
    }
    let (nid, nraw) = blob(60_000, size);
    writer.push_raw(nid, &nraw).unwrap();
    entries.push(TreeEntry {
        name: b"g00000".to_vec(),
        mode: EntryMode::Blob,
        object_hash: nid,
    });
    let tree = Object::Tree(Tree { entries });
    writer
        .push_raw(tree.id().unwrap(), &serialize(&tree).unwrap())
        .unwrap();
    let (commit, head) = signed_commit(tree.id().unwrap(), vec![parent], 7, b"remix");
    writer.push_raw(head, &serialize(&commit).unwrap()).unwrap();
    (writer.finish().unwrap(), head)
}
#[allow(clippy::too_many_lines)] // One alarm-driven fixture.
async fn probe(objects: u16, full_tree: bool) -> (u64, i64, u32) {
    let fault: Option<&'static str> = None;
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
    };
    let blobs = Shared(Arc::new(MemoryBlobStore::default()), clock.clone());
    let (bytes, head, _) = tree_pack_ids(objects - 2, 8);
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
        limits: SliceLimits::default(),
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
            let first_calls = store.ledger.lock().unwrap().calls;
            let first_class = store.ledger.lock().unwrap().by_class.clone();
            eprintln!(
                "FIRST objects={objects} calls={first_calls} elapsed_ms={} waits_ms={waits} classes={first_class:?}",
                clock.now_ms() - started
            );
            // ---------------- follow-on push on top of the N-object history
            store.ledger.lock().unwrap().by_class.clear();
            let c0 = store.ledger.lock().unwrap().calls;
            let t0 = clock.now_ms();
            let (bytes2, head2) = follow_pack(objects - 2, 8, head, full_tree);
            let pack2 = hash(&bytes2);
            let node2 = mkit_core::transfer::encode_packlist(Some(map), &[pack2]).unwrap();
            let map2 = hash(&node2);
            let tickets2 = vec![
                upload(&pipe, &blobs, &clock, bytes2, 10).await,
                upload(&pipe, &blobs, &clock, node2, 11).await,
            ];
            let mut waits2 = 0u64;
            let mut ticks = 0;
            let mut nonce = 20u32;
            loop {
                let auth = authenticate(&pipe, &clock, mkit_server::Procedure::AdvanceRefs, nonce);
                nonce += 1;
                let r = pipe
                    .advance_refs_with_tickets(
                        &auth,
                        mkit_server::RefUpdate {
                            name: "refs/heads/main".into(),
                            condition: mkit_core::refs::RefWriteCondition::Match(head),
                            new: Some(head2),
                        },
                        mkit_server::RefUpdate {
                            name: "refs/mkit/packmap/main".into(),
                            condition: mkit_core::refs::RefWriteCondition::Match(map),
                            new: Some(map2),
                        },
                        tickets2.clone(),
                    )
                    .await;
                match r {
                    Ok(o) => {
                        assert_eq!(o, mkit_core::protocol::AdvanceOutcome::Committed);
                        break;
                    }
                    Err(e)
                        if e.public_message().contains("pending")
                            || e.public_message().contains("not yet visible") => {}
                    Err(e) => panic!("follow-on advance failed: {e:?}"),
                }
                ticks += 1;
                assert!(ticks < 4000, "follow-on did not settle");
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
                let next = report
                    .next_wake_ms
                    .unwrap_or(now + 1_000)
                    .max(u64::try_from(clock.now_ms()).unwrap() + 1);
                waits2 += next - u64::try_from(clock.now_ms()).unwrap();
                clock.set(i64::try_from(next).unwrap());
            }
            let mut pubticks = 0;
            loop {
                let auth = authenticate(&pipe, &clock, mkit_server::Procedure::ListRefs, nonce);
                nonce += 1;
                let refs = pipe.list_refs(&auth, "refs/heads/").await.unwrap();
                if refs.iter().any(|e| e.name == "main" && e.id == head2) {
                    break;
                }
                pubticks += 1;
                assert!(pubticks < 20);
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
            let c1 = store.ledger.lock().unwrap().calls;
            let cls = store.ledger.lock().unwrap().by_class.clone();
            eprintln!(
                "FOLLOWON full_tree={full_tree} objects={objects} calls={} elapsed_ms={} waits_ms={waits2} ticks={ticks} classes={cls:?}",
                c1 - c0,
                clock.now_ms() - t0
            );
            return (c1 - c0, clock.now_ms() - t0, ticks);
        }
        let next = report
            .next_wake_ms
            .unwrap_or(now + 1_000)
            .max(u64::try_from(clock.now_ms()).unwrap() + 1);
        let wait = next - u64::try_from(clock.now_ms()).unwrap();
        waits += wait;
        clock.set(i64::try_from(next).unwrap());
    }
    panic!("{objects} objects exceeded 1024 alarm ticks");
}

// A push whose tree names every existing file used to cost one lookup and one
// alarm fire per file (10,743 calls at 500 files, 63,475 at 3,000). Owed
// children are now looked up in batches, so the bounds below hold with margin.
#[tokio::test(start_paused = true)]
async fn remix_naming_500_existing_files_batches_its_closure_lookups() {
    let (calls, _, ticks) = Box::pin(probe(500, true)).await;
    eprintln!("REMIX n=500 calls={calls} ticks={ticks}");
    assert!(calls < 600 && ticks < 30, "calls={calls} ticks={ticks}");
}

#[tokio::test(start_paused = true)]
async fn remix_naming_3000_existing_files_batches_its_closure_lookups() {
    let (calls, _, ticks) = Box::pin(probe(3000, true)).await;
    eprintln!("REMIX n=3000 calls={calls} ticks={ticks}");
    assert!(calls < 1_500 && ticks < 60, "calls={calls} ticks={ticks}");
}

#[tokio::test(start_paused = true)]
async fn remix_naming_one_existing_file_costs_no_more_than_before() {
    let (calls, _, _) = Box::pin(probe(500, false)).await;
    assert!(calls <= 298, "calls={calls}");
}
