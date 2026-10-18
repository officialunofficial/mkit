#![allow(clippy::unwrap_used)]
use super::*;
use crate::Code;
use crate::indexed::publication::verify_within;
use crate::repo::RepoName;
use crate::store::index::{IndexEntry, IndexValue, plan_index_rows_direct};
use crate::store::publication::Clearance;
use crate::{BlobKey, BlobStore, MemoryBlobStore, MemoryKv, NamespaceKey, PackSink};
use bytes::Bytes;
use futures_executor::block_on;
use mkit_core::object::{Blob, Object};
use mkit_core::protocol::PackKey;
use std::collections::{BTreeMap, BTreeSet};
fn repo() -> RepoId {
    RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: RepoName::new("proof").unwrap(),
    }
}
fn advance(root: Hash) -> Advance {
    Advance {
        sequence: 1,
        generation: 0,
        value: Pair {
            head: None,
            packmap: Some(root),
        },
        additions: vec![root],
        dependencies: vec![],
        external_bases: vec![],
        obligations: vec![],
        state: Clearance::Cleared,
        operation: [7; 32],
    }
}
fn progress(a: &Advance) -> Progress {
    let cfg = IndexedConfig::default();
    let mut p = Progress {
        binding: binding(a, cfg).unwrap(),
        value: a.value.clone(),
        branch: a.value.packmap.is_some(),
        generation: a.generation,
        additions: a.additions.clone(),
        walk: None,
        runs: 0,
        dependencies: BTreeSet::new(),
        bases: BTreeSet::new(),
        bytes: 0,
        calls: 0,
        byte_limit: cfg.decode_budget,
        depth_limit: cfg.max_delta_chain_depth,
        failure: None,
        terminal: None,
        missing: false,
        missing_base: false,
        complete: false,
    };
    p.walk = Some(hex_encode(&fresh_walker(&p).checkpoint().unwrap()));
    p
}
/// A walker at the pair's initial position, matching `prepare_with`'s binding.
fn fresh_walker(p: &Progress) -> PairWalker {
    PairWalker::new(
        progress_pair(p),
        &p.additions,
        crate::indexed::publication::pair_identity(&repo()),
        Revision(p.binding),
        crate::indexed::publication::PAIR_RULESET,
        walker_limits(p),
        true,
        p.runs + 1,
    )
    .unwrap()
}
/// Resume the stored checkpoint, giving tests the machine's live view.
fn walk_of(p: &Progress) -> PairWalker {
    walker_resume(&repo(), p).unwrap()
}
/// Checkpoint at a base cursor, built by driving a walker to that position.
fn walk_with_cursor(p: &Progress, pack: Hash, base: Hash) -> String {
    let mut walker = fresh_walker(p);
    loop {
        let request = match walker.step() {
            Ok(PairStep::Request(request)) => request.clone(),
            Ok(PairStep::Progress) => continue,
            _ => panic!("walker must keep requesting"),
        };
        match request {
            PairRequest::PackmapNode {
                request,
                pack: node,
                ..
            } => walker
                .answer(PairResponse::PackmapNode {
                    request,
                    pack: node,
                    value: Acquisition::Present(PairNode {
                        prev: None,
                        packs: &[pack],
                        boundary: false,
                    }),
                })
                .unwrap(),
            PairRequest::Object {
                request, object, ..
            } => {
                walker
                    .answer(PairResponse::Object {
                        request,
                        object,
                        value: Acquisition::Present(ObjectFact {
                            pack,
                            kind: mkit_core::object::ObjectType::Commit,
                            children: &[],
                            suppliers: &[],
                            base: Some(base),
                        }),
                    })
                    .unwrap();
                break;
            }
            _ => panic!("chain and walk requests only"),
        }
    }
    hex_encode(&walker.checkpoint().unwrap())
}
/// Checkpoint one node into a self-looping chain.
fn walk_chain_repeat(p: &Progress) -> String {
    let mut walker = fresh_walker(p);
    let request = match walker.step() {
        Ok(PairStep::Request(request)) => request.clone(),
        _ => panic!("chain phase must request the packmap node"),
    };
    let PairRequest::PackmapNode { request, pack, .. } = request else {
        panic!("chain phase must request the packmap node")
    };
    walker
        .answer(PairResponse::PackmapNode {
            request,
            pack,
            value: Acquisition::Present(PairNode {
                prev: Some(pack),
                packs: &[],
                boundary: false,
            }),
        })
        .unwrap();
    hex_encode(&walker.checkpoint().unwrap())
}
async fn facts(kv: &MemoryKv, id: Hash, prev: Option<Hash>) {
    facts_with(kv, id, prev, &[]).await;
}
async fn facts_with(kv: &MemoryKv, id: Hash, prev: Option<Hash>, packs: &[Hash]) {
    inventory::stage_packlist(kv, &id, 100, prev, packs, 0)
        .await
        .unwrap();
    inventory::complete(kv, &id, 100, 0).await.unwrap();
}
async fn verified(kv: &MemoryKv, repo: &RepoId, root: Hash) {
    state::write(
        kv,
        &SinglePartition.ref_shard(repo, "refs/heads/main"),
        &repo.name,
        &root,
        None,
        &state::VerificationV1::Verified {
            pack_len: 100,
            verified_at_ms: 0,
            publication: None,
        },
        10_000,
    )
    .await
    .unwrap();
}
async fn read_progress(kv: &MemoryKv, repo: &RepoId, root: Hash) -> Progress {
    let (
        state::VerificationV1::Verified {
            publication: Some(p),
            ..
        },
        _,
    ) = state::read(
        kv,
        &SinglePartition.ref_shard(repo, "refs/heads/main"),
        &repo.name,
        &root,
    )
    .await
    .unwrap()
    .unwrap()
    else {
        panic!("expected retained proof");
    };
    *p
}
#[test]
fn missing_predecessor_recovers_without_resetting_cumulative_work() {
    block_on(async {
        let kv = MemoryKv::with_clock(std::sync::Arc::new(crate::rt::ManualClock::new(0)));
        let repo = repo();
        let root = [1; 32];
        let prev = [2; 32];
        facts(&kv, root, Some(prev)).await;
        verified(&kv, &repo, root).await;
        let source = SinglePartition.ref_shard(&repo, "refs/heads/main");
        let cfg = IndexedConfig::default();
        let mut a = advance(root);
        let error = prepare(
            &kv,
            &source,
            &SinglePartition,
            &repo,
            &mut a,
            cfg,
            0,
            &crate::telemetry::NoopMetrics,
            0,
            true,
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), Code::Unavailable);
        assert_eq!(
            error.public_message(),
            "repository membership not yet visible"
        );
        let first = read_progress(&kv, &repo, root).await;
        let aged = prepare(
            &kv,
            &source,
            &SinglePartition,
            &repo,
            &mut a,
            cfg,
            cfg.relay_lag_bound_ms,
            &crate::telemetry::NoopMetrics,
            0,
            true,
        )
        .await
        .unwrap_err();
        assert_eq!(aged.public_message(), "open closure");
        facts(&kv, prev, None).await;
        kv.apply(
            &SinglePartition.membership(&repo, &crate::BlobKey::pack(prev)),
            Batch::new().put(keys::membership(&repo.name, &prev), Value::default()),
        )
        .await
        .unwrap();
        assert!(
            prepare(
                &kv,
                &source,
                &SinglePartition,
                &repo,
                &mut a,
                cfg,
                0,
                &crate::telemetry::NoopMetrics,
                0,
                true
            )
            .await
            .unwrap()
        );
        let done = read_progress(&kv, &repo, root).await;
        assert!(done.complete);
        assert!(done.calls > first.calls);
        assert_eq!(done.bytes, 200);
    });
}
#[test]
fn changed_generation_rebinds_and_corrupt_completion_fails_closed() {
    block_on(async {
        let kv = MemoryKv::with_clock(std::sync::Arc::new(crate::rt::ManualClock::new(0)));
        let repo = repo();
        let root = [3; 32];
        facts(&kv, root, None).await;
        verified(&kv, &repo, root).await;
        let source = SinglePartition.ref_shard(&repo, "refs/heads/main");
        let cfg = IndexedConfig::default();
        let mut a = advance(root);
        prepare(
            &kv,
            &source,
            &SinglePartition,
            &repo,
            &mut a,
            cfg,
            0,
            &crate::telemetry::NoopMetrics,
            0,
            true,
        )
        .await
        .unwrap();
        let first = read_progress(&kv, &repo, root).await;
        a.generation = 1;
        prepare(
            &kv,
            &source,
            &SinglePartition,
            &repo,
            &mut a,
            cfg,
            0,
            &crate::telemetry::NoopMetrics,
            0,
            true,
        )
        .await
        .unwrap();
        let next = read_progress(&kv, &repo, root).await;
        assert_ne!(first.binding, next.binding);
        let mut corrupt = next.clone();
        corrupt.additions.clear();
        assert!(corrupt.validate().is_err());
        let mut corrupt = next.clone();
        corrupt.walk = Some("zz".into());
        assert!(corrupt.validate().is_err());
        let mut corrupt = next;
        corrupt.generation = 2;
        assert!(
            state::decode(&state::encode(&state::VerificationV1::Verified {
                pack_len: 100,
                verified_at_ms: 0,
                publication: Some(Box::new(corrupt))
            }))
            .is_err()
        );
    });
}
#[test]
fn exhaustion_and_shared_alarm_refusal_remain_typed_and_bounded() {
    block_on(async {
        let kv = MemoryKv::with_clock(std::sync::Arc::new(crate::rt::ManualClock::new(0)));
        let repo = repo();
        let root = [4; 32];
        facts(&kv, root, None).await;
        let a = advance(root);
        let mut p = progress(&a);
        let alarm = crate::purge::SliceBudget::new(0);
        slice(
            &kv,
            &SinglePartition,
            &repo,
            &mut p,
            &crate::telemetry::NoopMetrics,
            Some(&alarm),
        )
        .await
        .unwrap();
        assert_eq!(alarm.used(), 0);
        assert!(!p.complete);
        assert_eq!(walk_of(&p).pending_packmap(), Some(root));
        let charged = p.calls;
        slice(
            &kv,
            &SinglePartition,
            &repo,
            &mut p,
            &crate::telemetry::NoopMetrics,
            None,
        )
        .await
        .unwrap();
        assert!(p.complete);
        assert!(p.calls > charged);
        let mut p = progress(&a);
        p.calls = TOTAL_CALLS;
        slice(
            &kv,
            &SinglePartition,
            &repo,
            &mut p,
            &crate::telemetry::NoopMetrics,
            None,
        )
        .await
        .unwrap();
        assert_eq!(p.failure, Some(Exhaustion::IndexCalls));
        assert_eq!(
            p.result(&mut advance(root), 0, 0, 1)
                .unwrap_err()
                .public_message(),
            "publication verification limit reached"
        );
        let mut p = progress(&a);
        p.byte_limit = 50;
        slice(
            &kv,
            &SinglePartition,
            &repo,
            &mut p,
            &crate::telemetry::NoopMetrics,
            None,
        )
        .await
        .unwrap();
        assert_eq!(p.failure, Some(Exhaustion::DecodeBudget));
        assert_ne!(
            p.result(&mut advance(root), 0, 0, 1)
                .unwrap_err()
                .public_message(),
            "open closure"
        );
    });
}
async fn fifty_base_fixture(kv: &MemoryKv, repo: &RepoId) -> (Hash, Hash, Hash, u64) {
    let pack = [5; 32];
    let mut previous = None;
    let mut entries = vec![];
    let mut first = None;
    for n in 0..50u8 {
        let object = Object::Blob(Blob { data: vec![n] });
        let id = object.id().unwrap();
        first.get_or_insert(id);
        inventory::stage(kv, &pack, 10_000, &id, &object, previous, 0)
            .await
            .unwrap();
        entries.push(IndexEntry {
            object: id,
            value: IndexValue {
                frame_offset: u64::from(n) * 20,
                frame_length: 20,
                wire_type: if previous.is_some() { 2 } else { 0 },
                decoded_size: 11,
                chain_depth: u32::from(previous.is_some()),
                delta_base: previous,
            },
        });
        previous = Some(id);
    }
    let head = Object::Commit(mkit_core::object::Commit::new_unannotated(
        first.unwrap(),
        vec![],
        mkit_core::object::Identity::ed25519([0; 32]),
        [0; 32],
        vec![],
        0,
        [0; 64],
    ));
    let head_id = head.id().unwrap();
    let head_len = mkit_core::serialize::serialize(&head).unwrap().len() as u64;
    inventory::stage(kv, &pack, 10_000, &head_id, &head, previous, 0)
        .await
        .unwrap();
    entries.push(IndexEntry {
        object: head_id,
        value: IndexValue {
            frame_offset: 1_000,
            frame_length: 20,
            wire_type: 2,
            decoded_size: head_len,
            chain_depth: 1,
            delta_base: previous,
        },
    });
    inventory::complete(kv, &pack, 10_000, 0).await.unwrap();
    let source = SinglePartition.ref_shard(repo, "refs/heads/main");
    for batch in plan_index_rows_direct(&SinglePartition, repo, &source, &pack, &entries, 0)
        .unwrap()
        .direct
    {
        let mut writes = Batch::new();
        for (k, v) in batch.puts {
            writes = writes.put(k, v);
        }
        kv.apply(&batch.target, writes).await.unwrap();
    }
    (pack, previous.unwrap(), head_id, head_len)
}
#[test]
fn fifty_base_hops_cross_slices_without_restarting_the_object() {
    block_on(async {
        let kv = MemoryKv::with_clock(std::sync::Arc::new(crate::rt::ManualClock::new(0)));
        let repo = repo();
        let (pack, _last, head, head_len) = fifty_base_fixture(&kv, &repo).await;
        let mut a = advance(pack);
        a.value.packmap = None;
        a.value.head = Some(head);
        let mut p = progress(&a);
        let mut rounds = 0;
        while !p.complete {
            let before = p.calls;
            slice(
                &kv,
                &SinglePartition,
                &repo,
                &mut p,
                &crate::telemetry::NoopMetrics,
                None,
            )
            .await
            .unwrap();
            assert!(p.calls - before <= u64::from(SLICE_CALLS));
            assert!(p.failure.is_none());
            p = serde_json::from_slice(&serde_json::to_vec(&p).unwrap()).unwrap();
            rounds += 1;
            assert!(rounds < 10);
        }
        assert!(
            rounds > 1,
            "the walk must span slices; grow the fixture if SLICE_CALLS rises"
        );
        assert!(p.calls > u64::from(SLICE_CALLS));
        assert_eq!(p.bytes, head_len + 550 + 11);
    });
}

#[test]
fn oversized_frontier_compacts_into_terminal_typed_exhaustion() {
    let a = advance([8; 32]);
    let mut p = progress(&a);
    for n in 0..MAX_ADVANCE_ITEMS {
        let id = hash(&n.to_be_bytes());
        p.dependencies.insert(id);
        p.bases.insert(id);
    }
    p.calls = 123;
    let mut retained = state::VerificationV1::Verified {
        pack_len: 100,
        verified_at_ms: 0,
        publication: Some(Box::new(p)),
    };
    assert!(state::encode(&retained).as_bytes().len() > MAX_STATE_BYTES);
    let encoded = bounded_state(&mut retained);
    assert!(encoded.as_bytes().len() <= MAX_STATE_BYTES);
    let state::VerificationV1::Verified {
        publication: Some(p),
        ..
    } = state::decode(&encoded).unwrap()
    else {
        panic!("expected terminal proof");
    };
    assert_eq!(p.failure, Some(Exhaustion::Traversal));
    assert_eq!(p.calls, 123);
    assert_ne!(
        p.result(&mut advance([8; 32]), 0, 0, 1)
            .unwrap_err()
            .public_message(),
        "pack verification pending"
    );
    let batch = Batch::new()
        .require(Precondition::Equals(
            crate::Key::new(vec![1; 1024]),
            Value::new(vec![0; MAX_STATE_BYTES]),
        ))
        .put(crate::Key::new(vec![2; 1024]), encoded);
    batch.validate(&MemoryKv::default().capabilities()).unwrap();
}

struct FailingMembership<'a> {
    store: &'a MemoryKv,
    key: crate::Key,
    armed: std::sync::atomic::AtomicBool,
}
impl NamespaceStore for FailingMembership<'_> {
    fn capabilities(&self) -> crate::store::StoreCapabilities {
        self.store.capabilities()
    }
    async fn get(&self, p: &Partition, k: &crate::Key) -> Result<Option<Value>, StoreError> {
        if *k == self.key && self.armed.swap(false, std::sync::atomic::Ordering::SeqCst) {
            return Err(StoreError::unavailable("injected membership outage"));
        }
        self.store.get(p, k).await
    }
    async fn scan(
        &self,
        p: &Partition,
        start: &crate::Key,
        end: &crate::Key,
        after: Option<&crate::Cursor>,
        limit: u32,
    ) -> Result<crate::ScanPage, StoreError> {
        self.store.scan(p, start, end, after, limit).await
    }
    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        self.store.apply(p, batch).await
    }
    async fn stats(&self, p: &Partition) -> Result<crate::PartitionStats, StoreError> {
        self.store.stats(p).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.store.probe().await
    }
}

#[test]
#[allow(clippy::too_many_lines)] // Foreground and real timer settlement share one recovery fixture.
fn storage_retry_retains_safe_progress_and_dispatched_calls() {
    block_on(async {
        let clock = std::sync::Arc::new(crate::rt::ManualClock::new(0));
        let kv = MemoryKv::with_clock(clock.clone());
        let repo = repo();
        let root = [11; 32];
        let prev = [12; 32];
        facts(&kv, root, Some(prev)).await;
        facts(&kv, prev, None).await;
        verified(&kv, &repo, root).await;
        let source = SinglePartition.ref_shard(&repo, "refs/heads/main");
        let membership = keys::membership(&repo.name, &prev);
        kv.apply(
            &source,
            Batch::new().put(membership.clone(), Value::default()),
        )
        .await
        .unwrap();
        let target = FailingMembership {
            store: &kv,
            key: membership,
            armed: std::sync::atomic::AtomicBool::new(true),
        };
        let mut a = advance(root);
        let error = prepare(
            &target,
            &source,
            &SinglePartition,
            &repo,
            &mut a,
            IndexedConfig::default(),
            0,
            &crate::telemetry::NoopMetrics,
            0,
            true,
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), Code::Unavailable);
        assert_eq!(error.public_message(), "object storage request failed");
        let first = read_progress(&kv, &repo, root).await;
        assert_eq!(first.calls, 2, "successful and failed dispatch both count");
        assert_eq!(first.bytes, 100);
        assert_eq!(walk_of(&first).pending_packmap(), Some(prev));
        assert_eq!(walk_of(&first).counts().chain, 1);
        assert!(!first.complete);
        first.validate().unwrap();

        target
            .armed
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let registry = crate::timers::TimerRegistry::new().register(
            crate::timers::publication_recheck::PublicationRecheck::new(
                crate::store::BorrowedStore(&target),
            ),
        );
        clock.advance(1_000);
        let report = crate::timers::run_due(
            &kv,
            &source,
            &registry,
            clock.as_ref(),
            1_000,
            &crate::timers::TickBudget::default(),
        )
        .await
        .unwrap();
        assert_eq!(
            report.fired, 1,
            "error progress settles with its timer move"
        );
        let failed = read_progress(&kv, &repo, root).await;
        assert_eq!(failed.calls, first.calls + 1);
        assert_eq!(failed.bytes, first.bytes);
        assert_eq!(failed.walk, first.walk);
        assert_eq!(walk_of(&failed).pending_packmap(), Some(prev));
        assert!(!failed.complete);
        failed.validate().unwrap();
        let key = keys::verification(&repo.name, &root);
        assert!(
            kv.get(&source, &keys::timer(1_000, 12, key.as_bytes()))
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            kv.get(&source, &keys::timer(6_000, 12, key.as_bytes()))
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            kv.get(&source, &keys::ref_key(&repo.name, "refs/heads/main"))
                .await
                .unwrap()
                .is_none()
        );

        clock.advance(5_000);
        crate::timers::run_due(
            &kv,
            &source,
            &registry,
            clock.as_ref(),
            6_000,
            &crate::timers::TickBudget::default(),
        )
        .await
        .unwrap();
        let done = read_progress(&kv, &repo, root).await;
        assert!(done.complete);
        assert_eq!(done.bytes, 200);
        assert!(done.calls > failed.calls);
        assert!(
            kv.get(&source, &keys::ref_key(&repo.name, "refs/heads/main"))
                .await
                .unwrap()
                .is_none()
        );
    });
}

#[test]
fn failing_dispatch_at_total_limit_is_terminal_typed_exhaustion() {
    block_on(async {
        let kv = MemoryKv::default();
        let repo = repo();
        let prev = [13; 32];
        let target = FailingMembership {
            store: &kv,
            key: keys::membership(&repo.name, &prev),
            armed: std::sync::atomic::AtomicBool::new(true),
        };
        let mut p = progress(&advance(prev));
        p.calls = TOTAL_CALLS;
        slice(
            &target,
            &SinglePartition,
            &repo,
            &mut p,
            &crate::telemetry::NoopMetrics,
            None,
        )
        .await
        .unwrap();
        assert_eq!(p.calls, TOTAL_CALLS + 1);
        assert_eq!(p.failure, Some(Exhaustion::IndexCalls));
        let w = walk_of(&p);
        assert_eq!(w.pending_packmap(), Some(prev));
        assert_eq!(w.counts().chain, 0, "failed item changes are rolled back");
        p.validate().unwrap();
        assert_eq!(
            p.result(&mut advance([14; 32]), 0, 0, 1)
                .unwrap_err()
                .public_message(),
            "publication verification limit reached"
        );
    });
}

#[test]
#[allow(clippy::too_many_lines)] // Durable binding, timer continuation and repeated permanent refusal.
fn lowered_delta_depth_becomes_durable_terminal_failure_across_timers() {
    block_on(async {
        let clock = std::sync::Arc::new(crate::rt::ManualClock::new(0));
        let kv = MemoryKv::with_clock(clock.clone());
        let repo = repo();
        let (pack, last, head, _) = fifty_base_fixture(&kv, &repo).await;
        let root = [15; 32];
        let mut a = advance(root);
        a.additions.push(pack);
        let cfg = IndexedConfig {
            max_delta_chain_depth: 30,
            ..IndexedConfig::default()
        };
        // Existing sealed content can have been verified under a higher cap.
        // This is the frozen proof after its MKPL phase, at a base-hop boundary.
        a.value.head = Some(head);
        let mut p = progress(&a);
        p.binding = binding(&a, cfg).unwrap();
        p.depth_limit = cfg.max_delta_chain_depth;
        p.dependencies.extend([root, pack]);
        p.walk = Some(walk_with_cursor(&p, pack, last));
        p.validate().unwrap();
        let source = SinglePartition.ref_shard(&repo, "refs/heads/main");
        let key = keys::verification(&repo.name, &root);
        let binding = p.binding;
        state::write(
            &kv,
            &source,
            &repo.name,
            &root,
            None,
            &state::VerificationV1::Verified {
                pack_len: 100,
                verified_at_ms: 0,
                publication: Some(Box::new(p)),
            },
            10_000,
        )
        .await
        .unwrap();
        kv.apply(
            &source,
            Batch::new().put(
                keys::timer(1_000, 12, key.as_bytes()),
                Value::new(binding.to_vec()),
            ),
        )
        .await
        .unwrap();
        let registry = crate::timers::TimerRegistry::new().register(
            crate::timers::publication_recheck::PublicationRecheck::new(
                crate::store::BorrowedStore(&kv),
            ),
        );
        let mut rounds = 0;
        let mut previous_calls = 0;
        loop {
            rounds += 1;
            clock.advance(1_000);
            crate::timers::run_due(
                &kv,
                &source,
                &registry,
                clock.as_ref(),
                rounds * 1_000,
                &crate::timers::TickBudget::default(),
            )
            .await
            .unwrap();
            let retained = read_progress(&kv, &repo, root).await;
            assert!(retained.calls >= previous_calls);
            assert!(retained.calls - previous_calls <= u64::from(SLICE_CALLS));
            previous_calls = retained.calls;
            retained.validate().unwrap();
            assert!(!retained.complete);
            assert!(
                kv.get(&source, &keys::ref_key(&repo.name, "refs/heads/main"))
                    .await
                    .unwrap()
                    .is_none()
            );
            if retained.terminal.is_some() {
                assert_eq!(retained.terminal, Some(TerminalFailure::DeltaDepth));
                // Exactly 30 base hops were charged at one 11-byte canonical
                // blob entry each; the cursor checkpoint starts mid-walk.
                assert_eq!(retained.bytes, 30 * 11);
                break;
            }
            assert!(rounds < 10);
        }
        assert!(rounds > 1, "the permanent refusal follows a continuation");
        for _ in 0..2 {
            let error = prepare(
                &kv,
                &source,
                &SinglePartition,
                &repo,
                &mut a,
                cfg,
                rounds * 1_000,
                &crate::telemetry::NoopMetrics,
                0,
                true,
            )
            .await
            .unwrap_err();
            assert_eq!(error.code(), Code::InvalidArgument);
            assert_eq!(error.public_message(), "delta chain too deep");
        }
        assert!(
            kv.get(
                &source,
                &keys::timer((rounds + 1) * 1_000, 12, key.as_bytes())
            )
            .await
            .unwrap()
            .is_none()
        );
        let mut corrupt = serde_json::to_value(read_progress(&kv, &repo, root).await).unwrap();
        corrupt["terminal"] = serde_json::json!("UnknownFailure");
        assert!(serde_json::from_value::<Progress>(corrupt).is_err());
    });
}

#[test]
fn spent_request_ledger_checkpoints_resumable_work_without_a_terminal_verdict() {
    block_on(async {
        let clock = std::sync::Arc::new(crate::rt::ManualClock::new(0));
        let kv = MemoryKv::with_clock(clock.clone());
        let repo = repo();
        let root = [21; 32];
        facts(&kv, root, None).await;
        verified(&kv, &repo, root).await;
        let source = SinglePartition.ref_shard(&repo, "refs/heads/main");
        let cfg = IndexedConfig::default();
        let mut a = advance(root);
        // The request's proof share is already spent: no read can be charged,
        // but the checkpoint write is reserved headroom and still lands.
        let ledger = SliceBudget::new(0);
        let error = prepare_with(
            &kv,
            &source,
            &SinglePartition,
            &repo,
            &mut a,
            cfg,
            0,
            &crate::telemetry::NoopMetrics,
            0,
            true,
            Some(&ledger),
            None,
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), Code::Unavailable);
        assert!(ledger.refused());
        let kept = read_progress(&kv, &repo, root).await;
        assert!(kept.failure.is_none() && kept.terminal.is_none() && !kept.complete);
        assert_eq!(walk_of(&kept).pending_packmap(), Some(root));
        // The retained timer resumes the same proof under the alarm's own allowance.
        let registry = crate::timers::TimerRegistry::new().register(
            crate::timers::publication_recheck::PublicationRecheck::new(
                crate::store::BorrowedStore(&kv),
            ),
        );
        clock.advance(1_000);
        crate::timers::run_due(
            &kv,
            &source,
            &registry,
            clock.as_ref(),
            1_000,
            &crate::timers::TickBudget::default(),
        )
        .await
        .unwrap();
        assert!(read_progress(&kv, &repo, root).await.complete);
    });
}

#[test]
fn unsupported_historical_capacity_is_one_terminal_stop_not_a_recurring_alarm() {
    block_on(async {
        let clock = std::sync::Arc::new(crate::rt::ManualClock::new(0));
        let kv = MemoryKv::with_clock(clock.clone());
        let repo = repo();
        let root = [22; 32];
        facts(&kv, root, None).await;
        let a = advance(root);
        let mut p = progress(&a);
        // The whole-pair allowance is spent: the next step cannot be supported.
        p.calls = TOTAL_CALLS;
        let source = SinglePartition.ref_shard(&repo, "refs/heads/main");
        let key = keys::verification(&repo.name, &root);
        let binding = p.binding;
        state::write(
            &kv,
            &source,
            &repo.name,
            &root,
            None,
            &state::VerificationV1::Verified {
                pack_len: 100,
                verified_at_ms: 0,
                publication: Some(Box::new(p)),
            },
            10_000,
        )
        .await
        .unwrap();
        let timer = keys::timer(1_000, 12, key.as_bytes());
        kv.apply(
            &source,
            Batch::new().put(timer.clone(), Value::new(binding.to_vec())),
        )
        .await
        .unwrap();
        let registry = crate::timers::TimerRegistry::new().register(
            crate::timers::publication_recheck::PublicationRecheck::new(
                crate::store::BorrowedStore(&kv),
            ),
        );
        clock.advance(1_000);
        crate::timers::run_due(
            &kv,
            &source,
            &registry,
            clock.as_ref(),
            1_000,
            &crate::timers::TickBudget::default(),
        )
        .await
        .unwrap();
        let stopped = read_progress(&kv, &repo, root).await;
        assert_eq!(stopped.failure, Some(Exhaustion::IndexCalls));
        // The one alarm retired the timer: no later alarm finds work.
        for later in [2_000_u64, 600_000] {
            clock.advance(i64::try_from(later).unwrap());
            assert!(kv.get(&source, &timer).await.unwrap().is_none());
            let report = crate::timers::run_due(
                &kv,
                &source,
                &registry,
                clock.as_ref(),
                later,
                &crate::timers::TickBudget::default(),
            )
            .await
            .unwrap();
            assert_eq!(report.fired, 0);
        }
        assert_eq!(read_progress(&kv, &repo, root).await, stopped);
        // Foreground callers see documented capacity, not an invalid-content verdict.
        for _ in 0..2 {
            let error = prepare(
                &kv,
                &source,
                &SinglePartition,
                &repo,
                &mut advance(root),
                IndexedConfig::default(),
                600_000,
                &crate::telemetry::NoopMetrics,
                0,
                true,
            )
            .await
            .unwrap_err();
            assert_eq!(error.code(), Code::Unavailable);
            assert_eq!(
                error.public_message(),
                "publication verification limit reached"
            );
        }
    });
}

#[test]
fn a_per_lookup_index_cap_keeps_its_input_error_on_the_resumable_path() {
    let a = advance([30; 32]);
    let mut p = progress(&a);
    p.failure = Some(Exhaustion::IndexLookup);
    p.validate().unwrap();
    let error = p.result(&mut advance([30; 32]), 0, 0, 1).unwrap_err();
    // The same specified error as the canonical path's lookup cap.
    assert_eq!(error.code(), Code::InvalidArgument);
    assert_eq!(error.public_message(), "object index limit exceeded");
    // A retained-evidence bound is capacity and says so distinctly.
    p.failure = Some(Exhaustion::Traversal);
    let error = p.result(&mut advance([30; 32]), 0, 0, 1).unwrap_err();
    assert_eq!(error.code(), Code::Unavailable);
    assert_eq!(
        error.public_message(),
        "publication verification limit reached"
    );
}

#[derive(Default)]
struct LimitMetrics(std::sync::Mutex<Vec<String>>);
impl crate::Metrics for LimitMetrics {
    fn incr(&self, name: &'static str, labels: &[(&'static str, &str)], by: u64) {
        if name == crate::telemetry::METRIC_PUBLICATION_LIMIT_REACHED {
            assert_eq!(by, 1);
            self.0.lock().unwrap().push(labels[0].1.to_owned());
        }
    }
    fn observe_ms(&self, _: &'static str, _: &[(&'static str, &str)], _: f64) {}
}
struct ConflictingCheckpoint<'a> {
    store: &'a MemoryKv,
    conflict: std::sync::atomic::AtomicBool,
}
impl NamespaceStore for ConflictingCheckpoint<'_> {
    fn capabilities(&self) -> crate::store::StoreCapabilities {
        self.store.capabilities()
    }
    async fn get(&self, p: &Partition, k: &crate::Key) -> Result<Option<Value>, StoreError> {
        self.store.get(p, k).await
    }
    async fn scan(
        &self,
        p: &Partition,
        start: &crate::Key,
        end: &crate::Key,
        after: Option<&crate::Cursor>,
        limit: u32,
    ) -> Result<crate::ScanPage, StoreError> {
        self.store.scan(p, start, end, after, limit).await
    }
    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        if self
            .conflict
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Ok(BatchOutcome::PreconditionFailed {
                index: 1,
                observed: None,
            });
        }
        self.store.apply(p, batch).await
    }
    async fn stats(&self, p: &Partition) -> Result<crate::PartitionStats, StoreError> {
        self.store.stats(p).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.store.probe().await
    }
}
#[test]
#[allow(clippy::too_many_lines)] // Conflicting checkpoint, commit and replay for each stop class.
fn limit_counter_counts_only_committed_capacity_stops_once() {
    block_on(async {
        for failure in [
            Exhaustion::IndexCalls,
            Exhaustion::Traversal,
            Exhaustion::IndexLookup,
            Exhaustion::DecodeBudget,
        ] {
            let kv = MemoryKv::with_clock(std::sync::Arc::new(crate::rt::ManualClock::new(0)));
            let repo = repo();
            let root = [31; 32];
            facts(&kv, root, None).await;
            let source = SinglePartition.ref_shard(&repo, "refs/heads/main");
            let mut cfg = IndexedConfig::default();
            if failure == Exhaustion::DecodeBudget {
                cfg.decode_budget = 50;
            }
            let mut a = advance(root);
            if failure == Exhaustion::Traversal {
                // The flagged member read must happen: root is not an addition.
                a.additions.clear();
            }
            let mut p = progress(&a);
            p.binding = binding(&a, cfg).unwrap();
            p.byte_limit = cfg.decode_budget;
            // The checkpoint binds the progress fields it was built against.
            p.walk = Some(hex_encode(&fresh_walker(&p).checkpoint().unwrap()));
            p.missing = true; // Resume the retained slice on a foreground retry.
            if failure == Exhaustion::IndexCalls {
                p.calls = TOTAL_CALLS;
            }
            if failure == Exhaustion::Traversal {
                // A cleared-set supplier list over the retained-items bound
                // exhausts at the completion merge — the one accumulating set
                // that is not checkpointed, so the retained row stays small.
                // The flagged witness makes the machine ask for it.
                let flagged = crate::store::publication::Witness {
                    generation: 0,
                    sequence: 0,
                    published: true,
                    held: false,
                    boundary: true,
                }
                .encode();
                let mut bases = Vec::new();
                for n in 0..=MAX_ADVANCE_ITEMS {
                    bases.extend_from_slice(&hash(&n.to_be_bytes()));
                }
                kv.apply(
                    &SinglePartition.membership(&repo, &crate::BlobKey::pack(root)),
                    Batch::new().put(keys::membership(&repo.name, &root), flagged),
                )
                .await
                .unwrap();
                kv.apply(
                    &SinglePartition.coordinator(&repo.namespace),
                    Batch::new().put(keys::fork_set(&repo.name, 3), Value::new(bases)),
                )
                .await
                .unwrap();
            }
            if failure == Exhaustion::IndexLookup {
                // A self-looping packmap hits the input lookup cap.
                p.walk = Some(walk_chain_repeat(&p));
            }
            state::write(
                &kv,
                &source,
                &repo.name,
                &root,
                None,
                &state::VerificationV1::Verified {
                    pack_len: 100,
                    verified_at_ms: 0,
                    publication: Some(Box::new(p)),
                },
                10_000,
            )
            .await
            .unwrap();
            let target = ConflictingCheckpoint {
                store: &kv,
                conflict: std::sync::atomic::AtomicBool::new(true),
            };
            let metrics = LimitMetrics::default();
            let error = prepare(
                &target,
                &source,
                &SinglePartition,
                &repo,
                &mut a,
                cfg,
                0,
                &metrics,
                0,
                true,
            )
            .await
            .unwrap_err();
            assert_eq!(error.public_message(), "pack verification pending");
            assert!(metrics.0.lock().unwrap().is_empty());
            assert!(read_progress(&kv, &repo, root).await.failure.is_none());
            for _ in 0..2 {
                let error = prepare(
                    &target,
                    &source,
                    &SinglePartition,
                    &repo,
                    &mut a,
                    cfg,
                    0,
                    &metrics,
                    0,
                    true,
                )
                .await
                .unwrap_err();
                assert_eq!(error.code(), failure.error().code());
                assert_eq!(error.public_message(), failure.error().public_message());
            }
            assert_eq!(read_progress(&kv, &repo, root).await.failure, Some(failure));
            let expected: Vec<String> = match failure {
                Exhaustion::IndexCalls => vec!["index_calls".into()],
                Exhaustion::Traversal => vec!["retained_items".into()],
                _ => vec![],
            };
            assert_eq!(*metrics.0.lock().unwrap(), expected);
        }
    });
}

#[test]
#[allow(clippy::too_many_lines)] // Corrupt and retryable loads in one fixture.
fn a_failing_cleared_set_load_is_charged_and_a_corrupt_one_ends_the_proof() {
    use crate::store::publication::Witness;
    block_on(async {
        let flagged = Witness {
            generation: 0,
            sequence: 0,
            published: true,
            held: false,
            boundary: true,
        }
        .encode();
        let repo = repo();
        let root = [1; 32];
        let fixture = |bytes: Option<Vec<u8>>| {
            let repo = repo.clone();
            let flagged = flagged.clone();
            async move {
                let kv = MemoryKv::with_clock(std::sync::Arc::new(crate::rt::ManualClock::new(0)));
                facts(&kv, root, None).await;
                verified(&kv, &repo, root).await;
                kv.apply(
                    &SinglePartition.membership(&repo, &crate::BlobKey::pack(root)),
                    Batch::new().put(keys::membership(&repo.name, &root), flagged),
                )
                .await
                .unwrap();
                if let Some(bytes) = bytes {
                    kv.apply(
                        &SinglePartition.coordinator(&repo.namespace),
                        Batch::new().put(keys::fork_set(&repo.name, 0), Value::new(bytes)),
                    )
                    .await
                    .unwrap();
                } else {
                    kv.apply(
                        &SinglePartition.coordinator(&repo.namespace),
                        Batch::new()
                            .put(keys::fork_set(&repo.name, 3), Value::new([9; 32].to_vec())),
                    )
                    .await
                    .unwrap();
                }
                kv
            }
        };
        let mut a = advance(root);
        a.additions.clear();
        let source = SinglePartition.ref_shard(&repo, "refs/heads/main");
        let cfg = IndexedConfig::default();
        // A corrupt row ends the verification at once.
        let kv = fixture(Some(vec![1, 2, 3])).await;
        prepare(
            &kv,
            &source,
            &SinglePartition,
            &repo,
            &mut a,
            cfg,
            0,
            &crate::telemetry::NoopMetrics,
            0,
            true,
        )
        .await
        .unwrap_err();
        assert_eq!(
            read_progress(&kv, &repo, root).await.failure,
            Some(Exhaustion::Traversal)
        );
        // A failing read is retried, its calls kept, and the proof completes.
        let kv = fixture(None).await;
        let failing = FailingMembership {
            store: &kv,
            key: keys::fork_set(&repo.name, 0),
            armed: std::sync::atomic::AtomicBool::new(true),
        };
        let error = prepare(
            &failing,
            &source,
            &SinglePartition,
            &repo,
            &mut a,
            cfg,
            0,
            &crate::telemetry::NoopMetrics,
            0,
            true,
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), Code::Unavailable);
        let first = read_progress(&kv, &repo, root).await;
        assert_eq!(first.failure, None);
        assert!(first.calls > 0, "the failed load was charged");
        // The timer's continuation reads the set again and completes.
        let mut done = first.clone();
        slice(
            &kv,
            &SinglePartition,
            &repo,
            &mut done,
            &crate::telemetry::NoopMetrics,
            None,
        )
        .await
        .unwrap();
        assert!(done.complete);
        assert!(done.calls > first.calls);
        // The boundary answer was honored: its cleared supplier merged into
        // the retained bases.
        assert_eq!(done.bases, BTreeSet::from_iter([[9; 32]]));
    });
}

#[test]
#[allow(clippy::too_many_lines)] // Staged inventory, flagged witnesses and the slice loop share one fixture.
fn a_cleared_tree_is_never_skipped_as_the_head_of_a_pair() {
    use crate::store::publication::Witness;
    use mkit_core::object::Tree;
    block_on(async {
        let kv = MemoryKv::with_clock(std::sync::Arc::new(crate::rt::ManualClock::new(0)));
        let repo = repo();
        let (root, pack) = ([1; 32], [2; 32]);
        // A packmap node listing one pack that holds one (empty) tree.
        inventory::stage_packlist(&kv, &root, 100, None, &[pack], 0)
            .await
            .unwrap();
        inventory::complete(&kv, &root, 100, 0).await.unwrap();
        let tree = Object::Tree(Tree { entries: vec![] });
        let id = tree.id().unwrap();
        let length = mkit_core::serialize::serialize(&tree).unwrap().len() as u64;
        inventory::stage(&kv, &pack, 10_000, &id, &tree, None, 0)
            .await
            .unwrap();
        inventory::complete(&kv, &pack, 10_000, 0).await.unwrap();
        let source = SinglePartition.ref_shard(&repo, "refs/heads/main");
        let entry = IndexEntry {
            object: id,
            value: IndexValue {
                frame_offset: 0,
                frame_length: 20,
                wire_type: 0,
                decoded_size: length,
                chain_depth: 0,
                delta_base: None,
            },
        };
        for batch in plan_index_rows_direct(&SinglePartition, &repo, &source, &pack, &[entry], 0)
            .unwrap()
            .direct
        {
            let mut writes = Batch::new();
            for (k, v) in batch.puts {
                writes = writes.put(k, v);
            }
            kv.apply(&batch.target, writes).await.unwrap();
        }
        let flagged = Witness {
            generation: 0,
            sequence: 0,
            published: true,
            held: false,
            boundary: true,
        }
        .encode();
        kv.apply(
            &SinglePartition.membership(&repo, &crate::BlobKey::pack(root)),
            Batch::new()
                .put(keys::membership(&repo.name, &root), flagged)
                .put(keys::membership(&repo.name, &pack), Value::default())
                .put(keys::fork_set(&repo.name, 0), Value::new(id.to_vec())),
        )
        .await
        .unwrap();
        // `put` of the set landed in the same (single) partition as everything.
        verified(&kv, &repo, root).await;
        let mut a = advance(root);
        a.additions.clear();
        a.value.head = Some(id);
        let cfg = IndexedConfig::default();
        let counter = CountGet {
            store: &kv,
            key: keys::fork_set(&repo.name, 0),
            hits: std::sync::atomic::AtomicUsize::new(0),
        };
        let _ = prepare(
            &counter,
            &source,
            &SinglePartition,
            &repo,
            &mut a,
            cfg,
            0,
            &crate::telemetry::NoopMetrics,
            0,
            true,
        )
        .await;
        let mut progress = read_progress(&kv, &repo, root).await;
        let mut rounds = 0;
        while progress.terminal.is_none() && !progress.complete {
            slice(
                &kv,
                &SinglePartition,
                &repo,
                &mut progress,
                &crate::telemetry::NoopMetrics,
                None,
            )
            .await
            .unwrap();
            rounds += 1;
            assert!(rounds < 8);
        }
        // The cleared set was actually loaded before the head was read and
        // refused: requests are sequential, so a hit precedes the verdict.
        assert!(
            counter.hits.load(std::sync::atomic::Ordering::SeqCst) > 0,
            "the fork cleared set was loaded"
        );
        assert_eq!(progress.terminal, Some(TerminalFailure::OpenClosure));
        assert!(!progress.complete);
    });
}

/// Store a packlist node body in the blob store under its content id.
async fn store_packlist_blob(blobs: &MemoryBlobStore, bytes: &[u8]) -> Hash {
    let id = hash(bytes);
    let mut sink = blobs
        .begin(PackKey::new(id).into(), bytes.len() as u64)
        .await
        .unwrap();
    sink.write(Bytes::copy_from_slice(bytes)).await.unwrap();
    sink.commit().await.unwrap();
    id
}
/// A two-node packmap chain staged for both verification paths: inventory
/// rows for the resumable walk and packlist blobs for the inline one.
async fn chain_fixture(
    kv: &MemoryKv,
    blobs: &MemoryBlobStore,
    repo: &RepoId,
) -> (Hash, Hash, Hash) {
    let pack = [9; 32];
    let tail = mkit_core::transfer::encode_packlist(None, &[pack]).unwrap();
    let tail_id = store_packlist_blob(blobs, &tail).await;
    facts_with(kv, tail_id, None, &[pack]).await;
    // The tail is a previously-published chain node: it carries the live
    // membership witness the inline membership read and the resumable
    // chain_member read both expect for non-additions.
    kv.apply(
        &SinglePartition.membership(repo, &crate::BlobKey::pack(tail_id)),
        Batch::new().put(
            keys::membership(&repo.name, &tail_id),
            crate::store::publication::Witness {
                generation: 0,
                sequence: 0,
                published: true,
                held: false,
                boundary: false,
            }
            .encode(),
        ),
    )
    .await
    .unwrap();
    let head_node = mkit_core::transfer::encode_packlist(Some(tail_id), &[]).unwrap();
    let root = store_packlist_blob(blobs, &head_node).await;
    let _ = repo;
    inventory::stage_packlist(kv, &root, 100, Some(tail_id), &[], 0)
        .await
        .unwrap();
    inventory::complete(kv, &root, 100, 0).await.unwrap();
    (root, tail_id, pack)
}
/// The same frozen chain drives inline `verify_within` and resumable
/// `prepare`; both must produce identical evidence sets.
#[test]
fn pair_coverage_inline_and_resumable_agree_on_chain_evidence() {
    block_on(async {
        let kv = MemoryKv::with_clock(std::sync::Arc::new(crate::rt::ManualClock::new(0)));
        let blobs = MemoryBlobStore::default();
        let repo = repo();
        let (root, tail, pack) = chain_fixture(&kv, &blobs, &repo).await;
        verified(&kv, &repo, root).await;
        let source = SinglePartition.ref_shard(&repo, "refs/heads/main");
        let cfg = IndexedConfig::default();
        // Inline path.
        let mut inline = advance(root);
        verify_within(
            &blobs,
            &kv,
            &SinglePartition,
            &repo,
            &inline.value.clone(),
            true,
            &mut inline,
            &crate::pipeline::clearance::Immediate,
            cfg,
            &crate::telemetry::NoopMetrics,
            true,
            crate::indexed::publication::Lag {
                now: 0,
                created: 0,
                bound: cfg.relay_lag_bound_ms,
            },
            &SliceBudget::new(10_000),
        )
        .await
        .unwrap();
        // Resumable path over the same fixture.
        let mut resumed = advance(root);
        loop {
            let done = prepare(
                &kv,
                &source,
                &SinglePartition,
                &repo,
                &mut resumed,
                cfg,
                0,
                &crate::telemetry::NoopMetrics,
                0,
                true,
            )
            .await
            .unwrap();
            if done {
                break;
            }
        }
        let want: Vec<Hash> = BTreeSet::from_iter([root, tail, pack])
            .into_iter()
            .collect();
        assert_eq!(inline.dependencies, want);
        assert_eq!(resumed.dependencies, want);
        assert_eq!(inline.external_bases, resumed.external_bases);
        assert!(resumed.external_bases.is_empty());
    });
}

/// Real pack bodies for the inline path: a `PackWriter` v1 pack with raw
/// (`0x00`) and delta (`0x02`) frames, staged with the inventory rows the
/// resumable path reads and the index rows both locate paths need.
/// Delta bases staged in sibling packs for `decode_entries_with` lookups.
struct StagedBases(BTreeMap<Hash, Vec<u8>>);
impl mkit_core::pack::DeltaBaseSource for StagedBases {
    fn base(&mut self, id: &Hash) -> Result<Option<Vec<u8>>, mkit_core::pack::PackError> {
        Ok(self.0.get(id).cloned())
    }
}
/// Real pack bodies for the inline path: a `PackWriter` pack with raw and
/// delta frames, staged with the inventory rows the resumable path reads
/// and the index rows both locate paths need.
#[allow(clippy::too_many_lines)] // Fixture stages blob, inventory, and index rows.
async fn stage_member_pack(
    kv: &MemoryKv,
    blobs: &MemoryBlobStore,
    repo: &RepoId,
    source: &Partition,
    raw: &[&Object],
    deltas: &[(&Object, &Object)],
) -> Hash {
    use mkit_core::pack::PackWriter;
    let mut pack_writer = PackWriter::new();
    for object in raw {
        let bytes = mkit_core::serialize::serialize(object).unwrap();
        pack_writer.push_raw(object.id().unwrap(), &bytes).unwrap();
    }
    for (object, base) in deltas {
        let object_bytes = mkit_core::serialize::serialize(object).unwrap();
        let base_bytes = mkit_core::serialize::serialize(base).unwrap();
        let stream = mkit_core::delta::encode(&base_bytes, &object_bytes).unwrap();
        pack_writer
            .push_delta(&base.id().unwrap(), &stream)
            .unwrap();
    }
    let body = pack_writer.finish().unwrap();
    let pack = hash(&body);
    let mut sink = blobs
        .begin(BlobKey::pack(pack), body.len() as u64)
        .await
        .unwrap();
    sink.write(Bytes::copy_from_slice(&body)).await.unwrap();
    sink.commit().await.unwrap();
    // Decode the written pack for the exact frame metadata the index rows
    // carry; external bases are answered from the staged base objects.
    let mut bases = StagedBases(
        deltas
            .iter()
            .map(|(_, b)| (b.id().unwrap(), mkit_core::serialize::serialize(b).unwrap()))
            .collect(),
    );
    let mut entries = vec![];
    mkit_core::pack::decode_entries_with(
        &body,
        &mut bases,
        mkit_core::pack::DecodeLimits::default(),
        |entry| {
            entries.push(IndexEntry {
                object: entry.id,
                value: IndexValue {
                    frame_offset: entry.frame_offset,
                    frame_length: entry.frame_length,
                    wire_type: entry.wire_type,
                    decoded_size: entry.bytes.len() as u64,
                    chain_depth: u32::from(entry.from_delta),
                    delta_base: deltas
                        .iter()
                        .find(|(o, _)| o.id().unwrap() == entry.id)
                        .map(|(_, b)| b.id().unwrap()),
                },
            });
            Ok(())
        },
    )
    .unwrap();
    let objects: BTreeMap<Hash, &Object> = raw
        .iter()
        .chain(deltas.iter().map(|(o, _)| o))
        .map(|o| (o.id().unwrap(), *o))
        .collect();
    let length = body.len() as u64;
    for entry in &entries {
        inventory::stage(
            kv,
            &pack,
            length,
            &entry.object,
            objects[&entry.object],
            entry.value.delta_base,
            0,
        )
        .await
        .unwrap();
    }
    inventory::complete(kv, &pack, length, 0).await.unwrap();
    for batch in plan_index_rows_direct(&SinglePartition, repo, source, &pack, &entries, 0)
        .unwrap()
        .direct
    {
        let mut writes = Batch::new();
        for (k, v) in batch.puts {
            writes = writes.put(k, v);
        }
        kv.apply(&batch.target, writes).await.unwrap();
    }
    // Member packs carry a live membership witness for the object reads.
    kv.apply(
        &SinglePartition.membership(repo, &crate::BlobKey::pack(pack)),
        Batch::new().put(
            keys::membership(&repo.name, &pack),
            crate::store::publication::Witness {
                generation: 0,
                sequence: 0,
                published: true,
                held: false,
                boundary: false,
            }
            .encode(),
        ),
    )
    .await
    .unwrap();
    pack
}
/// A chain pair whose member pack holds one commit head over one tree over
/// one blob, all raw: the smallest head-bearing pair both paths walk.
struct PairFixture {
    root: Hash,
    pack: Hash,
}
async fn head_fixture(
    kv: &MemoryKv,
    blobs: &MemoryBlobStore,
    repo: &RepoId,
    extra: &[Object],
    head_kind: Object,
) -> PairFixture {
    let source = SinglePartition.ref_shard(repo, "refs/heads/main");
    let mut members = vec![head_kind];
    members.extend_from_slice(extra);
    let members: Vec<&Object> = members.iter().collect();
    let pack = stage_member_pack(kv, blobs, repo, &source, &members, &[]).await;
    let node = mkit_core::transfer::encode_packlist(None, &[pack]).unwrap();
    let root = store_packlist_blob(blobs, &node).await;
    facts_with(kv, root, None, &[pack]).await;
    verified(kv, repo, root).await;
    PairFixture { root, pack }
}
fn history_objects() -> (Object, Object, Object) {
    let blob = Object::Blob(Blob { data: vec![7] });
    let blob_id = blob.id().unwrap();
    let tree = Object::Tree(mkit_core::object::Tree {
        entries: vec![mkit_core::object::TreeEntry {
            mode: mkit_core::object::EntryMode::Blob,
            name: b"f".to_vec(),
            object_hash: blob_id,
        }],
    });
    let tree_id = tree.id().unwrap();
    let commit = Object::Commit(mkit_core::object::Commit::new_unannotated(
        tree_id,
        vec![],
        mkit_core::object::Identity::ed25519([0; 32]),
        [0; 32],
        vec![],
        0,
        [0; 64],
    ));
    (commit, tree, blob)
}
/// Drive the inline and resumable pair-verification paths over the same
/// staged repository and return their normalized evidence.
async fn drive_both(
    kv: &MemoryKv,
    blobs: &MemoryBlobStore,
    repo: &RepoId,
    pair: crate::store::publication::Pair,
    branch: bool,
    additions: Vec<Hash>,
) -> (Result<Advance, ServerError>, Result<Advance, ServerError>) {
    drive_both_at(kv, blobs, repo, pair, branch, additions, 0).await
}
/// [`drive_both`] with the consuming ticket `age` ms old on both paths.
async fn drive_both_at(
    kv: &MemoryKv,
    blobs: &MemoryBlobStore,
    repo: &RepoId,
    pair: crate::store::publication::Pair,
    branch: bool,
    additions: Vec<Hash>,
    age: u64,
) -> (Result<Advance, ServerError>, Result<Advance, ServerError>) {
    let source = SinglePartition.ref_shard(repo, "refs/heads/main");
    let cfg = IndexedConfig::default();
    let mut inline = advance([0; 32]);
    inline.value = pair.clone();
    inline.additions = additions;
    let additions_before = inline.additions.clone();
    let inline_result = verify_within(
        blobs,
        kv,
        &SinglePartition,
        repo,
        &pair,
        branch,
        &mut inline,
        &crate::pipeline::clearance::Immediate,
        cfg,
        &crate::telemetry::NoopMetrics,
        true,
        crate::indexed::publication::Lag {
            now: age,
            created: 0,
            bound: cfg.relay_lag_bound_ms,
        },
        &SliceBudget::new(1_000_000),
    )
    .await
    .map(|()| inline);
    let mut resumed = advance([0; 32]);
    resumed.value = pair;
    resumed.additions = additions_before.clone();
    let resumed_result = loop {
        match prepare(
            kv,
            &source,
            &SinglePartition,
            repo,
            &mut resumed,
            cfg,
            age,
            &crate::telemetry::NoopMetrics,
            0,
            branch,
        )
        .await
        {
            Ok(true) => break Ok(resumed),
            Ok(false) => {
                if resumed.dependencies.is_empty() && resumed.external_bases.is_empty() {
                    break Ok(resumed);
                }
            }
            Err(error) => break Err(error),
        }
    };
    (inline_result, resumed_result)
}

/// `SortedUnion` merge: overlapping walk and cleared suppliers count once.
#[test]
fn sorted_union_len_counts_overlap_once() {
    use crate::indexed::publication::sorted_union_len;
    let a: Vec<Hash> = (0..4u8).map(|n| [n; 32]).collect();
    let b: Vec<Hash> = (2..6u8).map(|n| [n; 32]).collect();
    assert_eq!(sorted_union_len(&a, &b), 6);
    assert_eq!(sorted_union_len(&a, &a), 4);
    assert_eq!(sorted_union_len(&a, &[]), 4);
    assert_eq!(sorted_union_len(&[], &[]), 0);
}
/// Linear history parity: one commit head over a tree over a blob, all raw
/// in one member pack listed by the chain.
#[test]
fn pair_coverage_inline_and_resumable_agree_on_head_walk() {
    block_on(async {
        let kv = MemoryKv::with_clock(std::sync::Arc::new(crate::rt::ManualClock::new(0)));
        let blobs = MemoryBlobStore::default();
        let repo = repo();
        let (commit, tree, blob) = history_objects();
        let f = head_fixture(&kv, &blobs, &repo, &[tree, blob], commit.clone()).await;
        let pair = Pair {
            head: Some(commit.id().unwrap()),
            packmap: Some(f.root),
        };
        let (inline, resumed) = drive_both(&kv, &blobs, &repo, pair, true, vec![f.root]).await;
        let inline = inline.unwrap();
        let resumed = resumed.unwrap();
        let want: Vec<Hash> = BTreeSet::from_iter([f.root, f.pack]).into_iter().collect();
        assert_eq!(inline.dependencies, want);
        assert_eq!(resumed.dependencies, want);
        assert_eq!(inline.external_bases, resumed.external_bases);
    });
}

/// Shared subtrees: two commits point at the same tree; the walk must
/// dedupe it and both paths must agree on the dependency set.
#[test]
fn pair_coverage_shared_subtrees_dedupe_identically() {
    block_on(async {
        let kv = MemoryKv::with_clock(std::sync::Arc::new(crate::rt::ManualClock::new(0)));
        let blobs = MemoryBlobStore::default();
        let repo = repo();
        let (c1, tree, blob) = history_objects();
        let c2 = Object::Commit(mkit_core::object::Commit::new_unannotated(
            tree.id().unwrap(),
            vec![c1.id().unwrap()],
            mkit_core::object::Identity::ed25519([1; 32]),
            [1; 32],
            b"c2".to_vec(),
            1,
            [1; 64],
        ));
        let f = head_fixture(&kv, &blobs, &repo, &[tree, blob, c1], c2.clone()).await;
        let pair = Pair {
            head: Some(c2.id().unwrap()),
            packmap: Some(f.root),
        };
        let (inline, resumed) = drive_both(&kv, &blobs, &repo, pair, true, vec![f.root]).await;
        let inline = inline.unwrap();
        let resumed = resumed.unwrap();
        let want: Vec<Hash> = BTreeSet::from_iter([f.root, f.pack]).into_iter().collect();
        assert_eq!(inline.dependencies, want);
        assert_eq!(resumed.dependencies, want);
        assert_eq!(inline.external_bases, resumed.external_bases);
    });
}
/// External delta supplier: the head tree's blob is a delta in pack B
/// whose raw base lives in pack A — an external supplier neither path may
/// satisfy from this advance's own additions.
#[test]
fn pair_coverage_external_delta_supplier_recorded_by_both() {
    block_on(async {
        let kv = MemoryKv::with_clock(std::sync::Arc::new(crate::rt::ManualClock::new(0)));
        let blobs = MemoryBlobStore::default();
        let repo = repo();
        let source = SinglePartition.ref_shard(&repo, "refs/heads/main");
        let base = Object::Blob(Blob {
            data: vec![1, 2, 3],
        });
        let pack_a = stage_member_pack(&kv, &blobs, &repo, &source, &[&base], &[]).await;
        let target = Object::Blob(Blob {
            data: vec![1, 2, 3, 4],
        });
        let target_id = target.id().unwrap();
        let tree = Object::Tree(mkit_core::object::Tree {
            entries: vec![mkit_core::object::TreeEntry {
                mode: mkit_core::object::EntryMode::Blob,
                name: b"f".to_vec(),
                object_hash: target_id,
            }],
        });
        let tree_id = tree.id().unwrap();
        let commit = Object::Commit(mkit_core::object::Commit::new_unannotated(
            tree_id,
            vec![],
            mkit_core::object::Identity::ed25519([0; 32]),
            [0; 32],
            vec![],
            0,
            [0; 64],
        ));
        let pack_b = stage_member_pack(
            &kv,
            &blobs,
            &repo,
            &source,
            &[&commit, &tree],
            &[(&target, &base)],
        )
        .await;
        let node = mkit_core::transfer::encode_packlist(None, &[pack_a, pack_b]).unwrap();
        let root = store_packlist_blob(&blobs, &node).await;
        facts_with(&kv, root, None, &[pack_a, pack_b]).await;
        verified(&kv, &repo, root).await;
        let pair = Pair {
            head: Some(commit.id().unwrap()),
            packmap: Some(root),
        };
        let (inline, resumed) = drive_both(&kv, &blobs, &repo, pair, true, vec![root]).await;
        let inline = inline.unwrap();
        let resumed = resumed.unwrap();
        let deps: Vec<Hash> = BTreeSet::from_iter([root, pack_a, pack_b])
            .into_iter()
            .collect();
        assert_eq!(inline.dependencies, deps);
        assert_eq!(resumed.dependencies, deps);
        // Pack A supplies the delta base; it is an external supplier, not a
        // dependency owned by this advance.
        assert_eq!(inline.external_bases, vec![pack_a]);
        assert_eq!(resumed.external_bases, vec![pack_a]);
    });
}
/// Fork boundary: a cleared-set object on the walk is skipped on both
/// paths; cleared delta suppliers merge into `external_bases` identically.
#[test]
fn pair_coverage_fork_boundary_cleared_set_agrees() {
    block_on(async {
        let kv = MemoryKv::with_clock(std::sync::Arc::new(crate::rt::ManualClock::new(0)));
        let blobs = MemoryBlobStore::default();
        let repo = repo();
        let cleared_obj = [77; 32];
        let cleared_supplier = [88; 32];
        // Boundary rows: cleared objects at set 0, cleared suppliers at 1.
        let p = SinglePartition.coordinator(&repo.namespace);
        kv.apply(
            &p,
            Batch::new()
                .put(
                    keys::fork_set(&repo.name, 0),
                    crate::Value::new(cleared_obj.to_vec()),
                )
                .put(
                    keys::fork_set(&repo.name, 3),
                    crate::Value::new(cleared_supplier.to_vec()),
                ),
        )
        .await
        .unwrap();
        let (_commit, _tree, blob) = history_objects();
        // The commit's tree references both the staged blob and the cleared id.
        let tree = Object::Tree(mkit_core::object::Tree {
            entries: vec![
                mkit_core::object::TreeEntry {
                    mode: mkit_core::object::EntryMode::Blob,
                    name: b"a".to_vec(),
                    object_hash: blob.id().unwrap(),
                },
                mkit_core::object::TreeEntry {
                    mode: mkit_core::object::EntryMode::Blob,
                    name: b"z".to_vec(),
                    object_hash: cleared_obj,
                },
            ],
        });
        let commit = Object::Commit(mkit_core::object::Commit::new_unannotated(
            tree.id().unwrap(),
            vec![],
            mkit_core::object::Identity::ed25519([0; 32]),
            [0; 32],
            vec![],
            0,
            [0; 64],
        ));
        let source = SinglePartition.ref_shard(&repo, "refs/heads/main");
        let member_pack =
            stage_member_pack(&kv, &blobs, &repo, &source, &[&commit, &tree, &blob], &[]).await;
        // The chain node is a flagged member: its boundary flag makes the
        // machine ask for the cleared set.
        let node = mkit_core::transfer::encode_packlist(None, &[member_pack]).unwrap();
        let root = store_packlist_blob(&blobs, &node).await;
        facts_with(&kv, root, None, &[member_pack]).await;
        verified(&kv, &repo, root).await;
        kv.apply(
            &SinglePartition.membership(&repo, &crate::BlobKey::pack(root)),
            Batch::new().put(
                keys::membership(&repo.name, &root),
                crate::store::publication::Witness {
                    generation: 0,
                    sequence: 0,
                    published: true,
                    held: false,
                    boundary: true,
                }
                .encode(),
            ),
        )
        .await
        .unwrap();
        let pair = Pair {
            head: Some(commit.id().unwrap()),
            packmap: Some(root),
        };
        let (inline, resumed) = drive_both(&kv, &blobs, &repo, pair, true, vec![]).await;
        let inline = inline.unwrap();
        let resumed = resumed.unwrap();
        let deps: Vec<Hash> = BTreeSet::from_iter([root, member_pack])
            .into_iter()
            .collect();
        assert_eq!(inline.dependencies, deps);
        assert_eq!(resumed.dependencies, deps);
        // The cleared supplier merges into external suppliers on both paths.
        assert_eq!(inline.external_bases, vec![cleared_supplier]);
        assert_eq!(resumed.external_bases, vec![cleared_supplier]);
    });
}
/// A cleared head is still read by both paths (the machine exempts the
/// pair head from the skip).
#[test]
fn pair_coverage_cleared_head_is_still_read_on_both_paths() {
    block_on(async {
        let kv = MemoryKv::with_clock(std::sync::Arc::new(crate::rt::ManualClock::new(0)));
        let blobs = MemoryBlobStore::default();
        let repo = repo();
        let (commit, tree, blob) = history_objects();
        let head_id = commit.id().unwrap();
        let p = SinglePartition.coordinator(&repo.namespace);
        kv.apply(
            &p,
            Batch::new().put(
                keys::fork_set(&repo.name, 0),
                crate::Value::new(head_id.to_vec()),
            ),
        )
        .await
        .unwrap();
        let f = head_fixture(&kv, &blobs, &repo, &[tree, blob], commit).await;
        // Flag the chain node so the boundary answer carries the cleared set.
        kv.apply(
            &SinglePartition.membership(&repo, &crate::BlobKey::pack(f.root)),
            Batch::new().put(
                keys::membership(&repo.name, &f.root),
                crate::store::publication::Witness {
                    generation: 0,
                    sequence: 0,
                    published: true,
                    held: false,
                    boundary: true,
                }
                .encode(),
            ),
        )
        .await
        .unwrap();
        let pair = Pair {
            head: Some(head_id),
            packmap: Some(f.root),
        };
        // The cleared head must still be read: the walk covers it.
        let (inline, resumed) = drive_both(&kv, &blobs, &repo, pair, true, vec![]).await;
        let inline = inline.unwrap();
        let resumed = resumed.unwrap();
        let deps: Vec<Hash> = BTreeSet::from_iter([f.root, f.pack]).into_iter().collect();
        assert_eq!(inline.dependencies, deps);
        assert_eq!(resumed.dependencies, deps);
    });
}
/// Missing object: the head's tree is absent from both indexes. Both paths
/// share one lag-classified mapper: retryable inside the lag window, an open
/// closure only after it.
#[test]
fn pair_coverage_missing_object_maps_per_path() {
    block_on(async {
        let kv = MemoryKv::with_clock(std::sync::Arc::new(crate::rt::ManualClock::new(0)));
        let blobs = MemoryBlobStore::default();
        let repo = repo();
        let missing_tree = [66; 32];
        let commit = Object::Commit(mkit_core::object::Commit::new_unannotated(
            missing_tree,
            vec![],
            mkit_core::object::Identity::ed25519([0; 32]),
            [0; 32],
            vec![],
            0,
            [0; 64],
        ));
        let source = SinglePartition.ref_shard(&repo, "refs/heads/main");
        let pack = stage_member_pack(&kv, &blobs, &repo, &source, &[&commit], &[]).await;
        let node = mkit_core::transfer::encode_packlist(None, &[pack]).unwrap();
        let root = store_packlist_blob(&blobs, &node).await;
        facts_with(&kv, root, None, &[pack]).await;
        verified(&kv, &repo, root).await;
        let pair = Pair {
            head: Some(commit.id().unwrap()),
            packmap: Some(root),
        };
        let (inline, resumed) =
            drive_both(&kv, &blobs, &repo, pair.clone(), true, vec![root]).await;
        // Inside the lag window a missing object is retryable on both paths.
        for error in [inline.unwrap_err(), resumed.unwrap_err()] {
            assert_eq!(
                error.public_message(),
                "repository membership not yet visible"
            );
        }
        let stored = read_progress(&kv, &repo, root).await;
        assert!(stored.missing && !stored.missing_base);
        // Only after the window does it open the closure, on both paths.
        let after = IndexedConfig::default().relay_lag_bound_ms;
        let (inline, resumed) =
            drive_both_at(&kv, &blobs, &repo, pair, true, vec![root], after).await;
        for error in [inline.unwrap_err(), resumed.unwrap_err()] {
            assert_eq!(error.public_message(), "open closure");
        }
    });
}
/// A non-history head is refused closed on the inline path and as the
/// terminal open-closure verdict on the resumable path.
#[test]
fn pair_coverage_non_history_head_refuses_on_both_paths() {
    block_on(async {
        let kv = MemoryKv::with_clock(std::sync::Arc::new(crate::rt::ManualClock::new(0)));
        let blobs = MemoryBlobStore::default();
        let repo = repo();
        let blob = Object::Blob(Blob { data: vec![3] });
        let head = blob.id().unwrap();
        let f = head_fixture(&kv, &blobs, &repo, &[], blob).await;
        let pair = Pair {
            head: Some(head),
            packmap: Some(f.root),
        };
        let (inline, resumed) = drive_both(&kv, &blobs, &repo, pair, true, vec![f.root]).await;
        assert_eq!(inline.unwrap_err().public_message(), "open closure");
        assert_eq!(resumed.unwrap_err().public_message(), "open closure");
    });
}
/// Restart test: resuming the stored checkpoint after every slice must
/// produce the same result as the uninterrupted run.
#[test]
fn pair_coverage_resume_after_each_slice_matches_uninterrupted() {
    block_on(async {
        let kv = MemoryKv::with_clock(std::sync::Arc::new(crate::rt::ManualClock::new(0)));
        let repo = repo();
        let (pack, _last, head, _head_len) = fifty_base_fixture(&kv, &repo).await;
        let node = mkit_core::transfer::encode_packlist(None, &[pack]).unwrap();
        let root = store_packlist_blob(&MemoryBlobStore::default(), &node).await;
        facts_with(&kv, root, None, &[pack]).await;
        kv.apply(
            &SinglePartition.membership(&repo, &crate::BlobKey::pack(pack)),
            Batch::new().put(
                keys::membership(&repo.name, &pack),
                crate::store::publication::Witness {
                    generation: 0,
                    sequence: 0,
                    published: true,
                    held: false,
                    boundary: false,
                }
                .encode(),
            ),
        )
        .await
        .unwrap();
        let mut a = advance(root);
        a.value.head = Some(head);
        let mut p = progress(&a);
        // 51 object reads against a 128-call slice cross several boundaries;
        // each round simulates a timer restart by serializing the row.
        let mut rounds = 0;
        while !p.complete {
            let before = p.calls;
            slice(
                &kv,
                &SinglePartition,
                &repo,
                &mut p,
                &crate::telemetry::NoopMetrics,
                None,
            )
            .await
            .unwrap();
            assert!(p.calls - before <= u64::from(SLICE_CALLS));
            assert!(p.failure.is_none());
            assert!(p.terminal.is_none());
            // The serialized checkpoint resumes into the same position.
            let resumed: Progress =
                serde_json::from_slice(&serde_json::to_vec(&p).unwrap()).unwrap();
            assert!(walker_resume(&repo, &resumed).is_ok() || resumed.complete);
            p = resumed;
            rounds += 1;
            assert!(rounds < 20);
        }
        assert!(rounds > 1, "the restart must follow a continuation");
        let want: Vec<Hash> = BTreeSet::from_iter([root, pack]).into_iter().collect();
        assert_eq!(p.dependencies.into_iter().collect::<Vec<Hash>>(), want);
        assert!(p.bases.is_empty());
    });
}

/// A chain member with no witness row is a missing stop, not an error.
#[test]
fn chain_member_row_absent_is_a_missing_stop() {
    block_on(async {
        let kv = MemoryKv::with_clock(std::sync::Arc::new(crate::rt::ManualClock::new(0)));
        let repo = repo();
        let root = [3; 32];
        facts(&kv, root, None).await;
        let mut a = advance(root);
        a.additions.clear(); // root is a live member, not an addition
        let mut p = progress(&a);
        slice(
            &kv,
            &SinglePartition,
            &repo,
            &mut p,
            &crate::telemetry::NoopMetrics,
            None,
        )
        .await
        .unwrap();
        assert!(p.missing && !p.missing_base);
        assert_eq!(
            p.result(&mut a, 0, 0, 1).unwrap_err().public_message(),
            crate::indexed::verify::closure_error(0, 0, 1).public_message()
        );
    });
}
/// An index row without its inventory entry is a missing stop on the
/// object path.
#[test]
fn object_entry_absent_is_a_missing_stop() {
    block_on(async {
        let kv = MemoryKv::with_clock(std::sync::Arc::new(crate::rt::ManualClock::new(0)));
        let blobs = MemoryBlobStore::default();
        let repo = repo();
        let source = SinglePartition.ref_shard(&repo, "refs/heads/main");
        let (commit, tree, blob) = history_objects();
        let pack = stage_member_pack(&kv, &blobs, &repo, &source, &[&commit, &tree], &[]).await;
        // The blob child has an index row but no inventory entry.
        let entries = vec![IndexEntry {
            object: blob.id().unwrap(),
            value: IndexValue {
                frame_offset: 900,
                frame_length: 16,
                wire_type: 0,
                decoded_size: 11,
                chain_depth: 0,
                delta_base: None,
            },
        }];
        for batch in plan_index_rows_direct(&SinglePartition, &repo, &source, &pack, &entries, 0)
            .unwrap()
            .direct
        {
            let mut writes = Batch::new();
            for (k, v) in batch.puts {
                writes = writes.put(k, v);
            }
            kv.apply(&batch.target, writes).await.unwrap();
        }
        let node = mkit_core::transfer::encode_packlist(None, &[pack]).unwrap();
        let root = store_packlist_blob(&blobs, &node).await;
        facts_with(&kv, root, None, &[pack]).await;
        let mut a = advance(root);
        a.value.head = Some(commit.id().unwrap());
        let mut p = progress(&a);
        while !p.missing {
            slice(
                &kv,
                &SinglePartition,
                &repo,
                &mut p,
                &crate::telemetry::NoopMetrics,
                None,
            )
            .await
            .unwrap();
        }
        assert!(!p.missing_base);
    });
}
/// A located delta base without its inventory entry is a missing stop
/// flagged as a base miss.
#[test]
fn base_entry_absent_is_a_missing_base_stop() {
    block_on(async {
        let kv = MemoryKv::with_clock(std::sync::Arc::new(crate::rt::ManualClock::new(0)));
        let blobs = MemoryBlobStore::default();
        let repo = repo();
        let source = SinglePartition.ref_shard(&repo, "refs/heads/main");
        let base_obj = Object::Blob(Blob { data: vec![5] });
        let target = Object::Blob(Blob { data: vec![6] });
        // Pack A: index row only — the entry row the Base arm needs is absent.
        let pack_a = [41; 32];
        let entries = vec![IndexEntry {
            object: base_obj.id().unwrap(),
            value: IndexValue {
                frame_offset: 12,
                frame_length: 16,
                wire_type: 0,
                decoded_size: 11,
                chain_depth: 0,
                delta_base: None,
            },
        }];
        for batch in plan_index_rows_direct(&SinglePartition, &repo, &source, &pack_a, &entries, 0)
            .unwrap()
            .direct
        {
            let mut writes = Batch::new();
            for (k, v) in batch.puts {
                writes = writes.put(k, v);
            }
            kv.apply(&batch.target, writes).await.unwrap();
        }
        kv.apply(
            &SinglePartition.membership(&repo, &crate::BlobKey::pack(pack_a)),
            Batch::new().put(
                keys::membership(&repo.name, &pack_a),
                crate::store::publication::Witness {
                    generation: 0,
                    sequence: 0,
                    published: true,
                    held: false,
                    boundary: false,
                }
                .encode(),
            ),
        )
        .await
        .unwrap();
        // Pack B: commit head + the delta target whose base is in pack A.
        let tree = Object::Tree(mkit_core::object::Tree {
            entries: vec![mkit_core::object::TreeEntry {
                mode: mkit_core::object::EntryMode::Blob,
                name: b"d".to_vec(),
                object_hash: target.id().unwrap(),
            }],
        });
        let commit = Object::Commit(mkit_core::object::Commit::new_unannotated(
            tree.id().unwrap(),
            vec![],
            mkit_core::object::Identity::ed25519([0; 32]),
            [0; 32],
            vec![],
            0,
            [0; 64],
        ));
        let pack_b = stage_member_pack(
            &kv,
            &blobs,
            &repo,
            &source,
            &[&commit, &tree],
            &[(&target, &base_obj)],
        )
        .await;
        let node = mkit_core::transfer::encode_packlist(None, &[pack_b]).unwrap();
        let root = store_packlist_blob(&blobs, &node).await;
        facts_with(&kv, root, None, &[pack_b]).await;
        let mut a = advance(root);
        a.value.head = Some(commit.id().unwrap());
        let mut p = progress(&a);
        while !p.missing {
            slice(
                &kv,
                &SinglePartition,
                &repo,
                &mut p,
                &crate::telemetry::NoopMetrics,
                None,
            )
            .await
            .unwrap();
        }
        assert!(p.missing_base);
        let _ = pack_a;
    });
}
/// A non-branch pair resumes correctly across slices: the checkpoint binds
/// `branch=false` and resume must not rebuild it as `true`.
#[test]
fn non_branch_pair_resumes_across_slices() {
    block_on(async {
        let kv = MemoryKv::with_clock(std::sync::Arc::new(crate::rt::ManualClock::new(0)));
        let blobs = MemoryBlobStore::default();
        let repo = repo();
        let (commit, tree, blob) = history_objects();
        let head = commit.id().unwrap();
        let f = head_fixture(&kv, &blobs, &repo, &[tree, blob], commit).await;
        let mut a = advance(f.root);
        a.value.head = Some(head);
        let mut p = progress(&a);
        p.branch = false;
        p.walk = Some(hex_encode(&fresh_walker(&p).checkpoint().unwrap()));
        let mut rounds = 0;
        while !p.complete {
            slice(
                &kv,
                &SinglePartition,
                &repo,
                &mut p,
                &crate::telemetry::NoopMetrics,
                None,
            )
            .await
            .unwrap();
            let resumed: Progress =
                serde_json::from_slice(&serde_json::to_vec(&p).unwrap()).unwrap();
            assert!(walker_resume(&repo, &resumed).is_ok() || resumed.complete);
            p = resumed;
            rounds += 1;
            assert!(rounds < 10);
        }
        assert!(rounds >= 1);
        assert_eq!(
            p.dependencies.into_iter().collect::<Vec<Hash>>(),
            BTreeSet::from_iter([f.root, f.pack])
                .into_iter()
                .collect::<Vec<Hash>>()
        );
    });
}

/// Counts gets against one key: proves a specific row was read.
struct CountGet<'a> {
    store: &'a MemoryKv,
    key: crate::Key,
    hits: std::sync::atomic::AtomicUsize,
}
impl NamespaceStore for CountGet<'_> {
    fn capabilities(&self) -> crate::store::StoreCapabilities {
        self.store.capabilities()
    }
    async fn get(&self, p: &Partition, k: &crate::Key) -> Result<Option<Value>, StoreError> {
        if k == &self.key {
            self.hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        self.store.get(p, k).await
    }
    async fn scan(
        &self,
        p: &Partition,
        start: &crate::Key,
        end: &crate::Key,
        after: Option<&crate::Cursor>,
        limit: u32,
    ) -> Result<crate::ScanPage, StoreError> {
        self.store.scan(p, start, end, after, limit).await
    }
    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        self.store.apply(p, batch).await
    }
    async fn stats(&self, p: &Partition) -> Result<crate::PartitionStats, StoreError> {
        self.store.stats(p).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.store.probe().await
    }
}
/// Counts `denial::page` reads: every chunk-page get carries the
/// `\0chunks\0` marker in its key bytes.
struct CountPages<'a> {
    inner: &'a MemoryKv,
    pages: std::sync::atomic::AtomicUsize,
}
impl NamespaceStore for CountPages<'_> {
    fn capabilities(&self) -> crate::store::StoreCapabilities {
        self.inner.capabilities()
    }
    async fn get(&self, p: &Partition, k: &crate::Key) -> Result<Option<Value>, StoreError> {
        if k.as_bytes().windows(8).any(|w| w == b"\0chunks\0") {
            self.pages.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        self.inner.get(p, k).await
    }
    async fn scan(
        &self,
        p: &Partition,
        start: &crate::Key,
        end: &crate::Key,
        after: Option<&crate::Cursor>,
        limit: u32,
    ) -> Result<crate::ScanPage, StoreError> {
        self.inner.scan(p, start, end, after, limit).await
    }
    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        self.inner.apply(p, batch).await
    }
    async fn stats(&self, p: &Partition) -> Result<crate::PartitionStats, StoreError> {
        self.inner.stats(p).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.inner.probe().await
    }
}
/// A non-history head (`ChunkedBlob`, inventory kind 5) with a non-empty
/// reference-page set must hit the terminal open-closure verdict without
/// any reference-page read — the reference refused before touching pages.
#[test]
fn non_history_head_never_reads_reference_pages() {
    block_on(async {
        let kv = MemoryKv::with_clock(std::sync::Arc::new(crate::rt::ManualClock::new(0)));
        let blobs = MemoryBlobStore::default();
        let repo = repo();
        let chunk = Object::Blob(Blob { data: vec![9] });
        let chunked = Object::ChunkedBlob(mkit_core::object::ChunkedBlob {
            total_size: 1,
            chunk_size: 0,
            chunks: vec![chunk.id().unwrap()],
        });
        let source = SinglePartition.ref_shard(&repo, "refs/heads/main");
        let pack = stage_member_pack(&kv, &blobs, &repo, &source, &[&chunked, &chunk], &[]).await;
        let node = mkit_core::transfer::encode_packlist(None, &[pack]).unwrap();
        let root = store_packlist_blob(&blobs, &node).await;
        facts_with(&kv, root, None, &[pack]).await;
        let mut a = advance(root);
        a.value.head = Some(chunked.id().unwrap());
        let mut p = progress(&a);
        let store = CountPages {
            inner: &kv,
            pages: std::sync::atomic::AtomicUsize::new(0),
        };
        while p.terminal.is_none() && !p.complete {
            slice(
                &store,
                &SinglePartition,
                &repo,
                &mut p,
                &crate::telemetry::NoopMetrics,
                None,
            )
            .await
            .unwrap();
        }
        assert_eq!(p.terminal, Some(TerminalFailure::OpenClosure));
        assert_eq!(store.pages.load(std::sync::atomic::Ordering::SeqCst), 0);
        // Control: a history head with a tree child reads its reference page.
        let kv2 = MemoryKv::with_clock(std::sync::Arc::new(crate::rt::ManualClock::new(0)));
        let (commit, tree, blob) = history_objects();
        let f = head_fixture(&kv2, &blobs, &repo, &[tree, blob], commit.clone()).await;
        let mut a2 = advance(f.root);
        a2.value.head = Some(commit.id().unwrap());
        let mut p2 = progress(&a2);
        let store2 = CountPages {
            inner: &kv2,
            pages: std::sync::atomic::AtomicUsize::new(0),
        };
        slice(
            &store2,
            &SinglePartition,
            &repo,
            &mut p2,
            &crate::telemetry::NoopMetrics,
            None,
        )
        .await
        .unwrap();
        assert!(store2.pages.load(std::sync::atomic::Ordering::SeqCst) > 0);
    });
}
