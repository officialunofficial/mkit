//! Real D34/Multi publication regressions from the reachable-content fixtures.
#![allow(clippy::unwrap_used)]
use super::indexed::{begin_and_upload, environment_with, signed};
use super::*;
use crate::indexed::IndexedConfig;
use crate::indexed::job::{FailClosedExtraction, SliceExtension, SliceLimits, VerifyTimer};
use crate::store::BorrowedStore;
use mkit_core::object::{Blob, ChunkedBlob, Commit, EntryMode, Identity, Object, Tree, TreeEntry};
use mkit_core::pack::PackWriter;
use mkit_core::serialize::serialize;
use mkit_core::sign::{KeyPair, sign_commit};
use std::time::Instant;
struct Extract;
impl SliceExtension for Extract {
    fn needs_extraction(&self, o: &Object, c: &IndexedConfig) -> bool {
        FailClosedExtraction.needs_extraction(o, c)
    }
    fn extraction_enabled(&self) -> bool {
        true
    }
}
fn pack(count: usize, len: usize, chunked: bool) -> (Vec<u8>, Hash) {
    let mut objects: Vec<Object> = (0..count)
        .map(|i| {
            Object::Blob(Blob {
                data: vec![u8::try_from(i).unwrap() + 1; len],
            })
        })
        .collect();
    let files = if chunked {
        let manifest = Object::ChunkedBlob(ChunkedBlob {
            total_size: (count * len) as u64,
            chunk_size: u32::try_from(len).unwrap(),
            chunks: objects.iter().map(|o| o.id().unwrap()).collect(),
        });
        let ids = vec![manifest.id().unwrap()];
        objects.push(manifest);
        ids
    } else {
        objects.iter().map(|o| o.id().unwrap()).collect()
    };
    let tree = Object::Tree(Tree {
        entries: files
            .iter()
            .enumerate()
            .map(|(i, id)| TreeEntry {
                name: format!("f{i:03}").into_bytes(),
                mode: EntryMode::Blob,
                object_hash: *id,
            })
            .collect(),
    });
    let kp = KeyPair::from_seed([9; 32]);
    let mut commit = Commit::new_unannotated(
        tree.id().unwrap(),
        vec![],
        Identity::ed25519(kp.public.0),
        kp.public.0,
        b"uno".to_vec(),
        42,
        [0; 64],
    );
    commit.signature = sign_commit(&commit, &kp).unwrap().0;
    let commit = Object::Commit(commit);
    let head = commit.id().unwrap();
    objects.extend([tree, commit]);
    let mut writer = PackWriter::new_raw_only();
    for o in objects {
        writer
            .push_raw(o.id().unwrap(), &serialize(&o).unwrap())
            .unwrap();
    }
    (writer.finish().unwrap(), head)
}
#[allow(clippy::too_many_lines)] // End-to-end fixture includes verifier, restart and publication assertions.
fn run(count: usize, len: usize, chunked: bool, delay: i64, custom_policy: bool) {
    let cfg = IndexedConfig::scheduled(1 << 30);
    let (mut env, owner, identity) = environment_with(Sharding::D34, cfg);
    env.pipe.cfg.upload_limits.max_total_bytes = 1 << 30;
    env.pipe.cfg.begin_upload_threshold_bytes = 0;
    env.pipe.cfg.takedown_denial = true;
    if custom_policy {
        env.pipe.publication_policy = Some(Arc::new(clearance::Immediate));
    }
    let clock = env.clock.clone();
    env.pipe.meta.scan_hook = Some(Box::new(move |_, p| {
        if matches!(p, Partition::ContentShard(_)) {
            clock.advance(delay);
        }
    }));
    let (bytes, head) = pack(count, len, chunked);
    let pid = hash(&bytes);
    let map = mkit_core::transfer::encode_packlist(None, &[pid]).unwrap();
    let mapid = hash(&map);
    let tickets = vec![
        begin_and_upload(&env, &owner, &identity, &bytes, 60000),
        begin_and_upload(&env, &owner, &identity, &map, 60001),
    ];
    let req = signed(&owner, &identity, Procedure::AdvanceRefs, 60002);
    let attempt = |env: &Env| {
        block_on(env.pipe.advance_refs_with_tickets(
            &env.auth(&req).unwrap(),
            upd(HEAD, Missing, head),
            upd(PACKMAP, Missing, mapid),
            tickets.clone(),
        ))
    };
    assert_eq!(
        attempt(&env).unwrap_err().public_message(),
        "pack verification pending"
    );
    let auth = env.auth(&req).unwrap();
    let source = env.pipe.shards.ref_shard(&auth.repo().repo, HEAD);
    let registry = crate::timers::TimerRegistry::new()
        .register(VerifyTimer {
            remote: BorrowedStore(&env.pipe.meta),
            blobs: env.pipe.blobs.clone(),
            windows: crate::indexed::budget::BlobWindows(&env.pipe.blobs),
            shards: env.pipe.shards.clone(),
            cfg,
            limits: SliceLimits::default(),
            lease: LeaseParams::from(&env.pipe.cfg),
            clock: env.clock.clone(),
            metrics: env.metrics.clone(),
            extension: Extract,
        })
        .register(crate::relay::RelayHandler {
            target: BorrowedStore(&env.pipe.meta),
            hook: crate::relay::NoHook,
            budget: crate::relay::RelayBudget::default(),
        })
        .register(crate::timers::publication_recheck::PublicationRecheck::new(
            BorrowedStore(&env.pipe.meta),
        ));
    for round in 0..280 {
        block_on(crate::timers::run_due(
            &env.pipe.meta,
            &source,
            &registry,
            env.clock.as_ref(),
            u64::try_from(env.clock.now_ms()).unwrap(),
            &crate::timers::TickBudget::default(),
        ))
        .unwrap();
        let finished = [pid, mapid].iter().all(|id| {
            block_on(
                env.pipe
                    .meta
                    .get(&source, &keys::verification(&auth.repo().repo.name, id)),
            )
            .unwrap()
            .is_some_and(|v| {
                matches!(
                    crate::indexed::state::decode(&v).unwrap(),
                    crate::indexed::state::VerificationV1::Verified { .. }
                )
            })
        });
        if finished {
            eprintln!(
                "takedown fixture objects={count} chunks={chunked} verify_rounds={}",
                round + 1
            );
            break;
        }
        assert!(round < 279, "pack verifier must finish");
        env.clock.advance(1000);
    }
    let mut continuation_rounds = 0;
    loop {
        let meta = env.pipe.meta.calls();
        let blob = env.pipe.blobs.read_calls();
        let seen = env.pipe.meta.seen().len();
        let sim = env.clock.now_ms();
        let start = Instant::now();
        let result = attempt(&env);
        let directory_scans = env.pipe.meta.seen()[seen..]
            .iter()
            .filter(|k| k.as_bytes() == b"b\0\xffdenial-descriptor-directory\0")
            .count();
        eprintln!(
            "takedown fixture objects={count} chunks={chunked} continuation_rounds={continuation_rounds} metadata={} blob_reads={} directory_scans={directory_scans} simulated_ms={} wall_ms={:.3} result={:?}",
            env.pipe.meta.calls() - meta,
            env.pipe.blobs.read_calls() - blob,
            env.clock.now_ms() - sim,
            start.elapsed().as_secs_f64() * 1000.,
            result.as_ref().map_err(|e| (e.code(), e.public_message()))
        );
        match result {
            Err(error) if custom_policy => {
                assert_eq!(error.code(), Code::InvalidArgument);
                assert_eq!(
                    error.public_message(),
                    crate::indexed::resolve::DECODE_BUDGET_MESSAGE
                );
                assert_eq!(continuation_rounds, 0);
                assert_eq!(
                    block_on(
                        env.pipe
                            .meta
                            .get(&source, &keys::ref_key(&auth.repo().repo.name, HEAD))
                    )
                    .unwrap(),
                    None,
                    "canonical fallback exhaustion never moves refs"
                );
                break;
            }
            Ok(AdvanceOutcome::Committed) => {
                assert!(
                    !custom_policy,
                    "canonical fallback must refuse this closure"
                );
                assert_eq!(directory_scans, 16);
                assert!(env.clock.now_ms() - sim < 1000);
                break;
            }
            Err(error) if error.public_message() == "pack verification pending" => {
                assert_eq!(
                    block_on(
                        env.pipe
                            .meta
                            .get(&source, &keys::ref_key(&auth.repo().repo.name, HEAD))
                    )
                    .unwrap(),
                    None,
                    "pending evidence never moves refs"
                );
                env.clock.advance(1000);
                let resumed = crate::timers::TimerRegistry::new().register(
                    crate::timers::publication_recheck::PublicationRecheck::new(BorrowedStore(
                        &env.pipe.meta,
                    )),
                );
                block_on(crate::timers::run_due(
                    &env.pipe.meta,
                    &source,
                    &resumed,
                    env.clock.as_ref(),
                    u64::try_from(env.clock.now_ms()).unwrap(),
                    &crate::timers::TickBudget::default(),
                ))
                .unwrap();
                continuation_rounds += 1;
                assert!(
                    continuation_rounds < 20,
                    "publication must make bounded progress after restart"
                );
            }
            other => panic!("valid takedown-on publication refused: {other:?}"),
        }
    }
    if count >= 32 {
        assert!(continuation_rounds > 0);
    }
}
#[test]
fn nine_canonical_mib_blobs_publish_with_takedown_on() {
    run(9, (1 << 20) - 10, false, 0, false);
}
#[test]
fn thirty_two_distinct_chunks_resume_and_publish_with_takedown_on() {
    run(32, 62500, true, 0, false);
}
#[test]
fn empty_directory_advance_has_commit_window_headroom() {
    run(1, 20, false, 3, false);
}
#[test]
fn custom_publication_policy_retains_canonical_memory_bound() {
    run(9, (1 << 20) - 10, false, 0, true);
}
