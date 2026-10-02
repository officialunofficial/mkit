#![allow(clippy::unwrap_used)]
use super::*;
use crate::repo::RepoName;
use crate::store::index::{IndexEntry, IndexValue, plan_index_rows_direct};
use crate::store::publication::Clearance;
use crate::{Code, MemoryKv, NamespaceKey};
use futures_executor::block_on;
use mkit_core::object::{Blob, Object};
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
    Progress {
        binding: binding(a, cfg).unwrap(),
        value: a.value.clone(),
        generation: a.generation,
        additions: a.additions.clone(),
        next_packmap: a.value.packmap,
        chain: BTreeSet::new(),
        packs: BTreeSet::new(),
        queue: VecDeque::from_iter(a.value.head),
        visited: BTreeSet::new(),
        dependencies: BTreeSet::new(),
        bases: BTreeSet::new(),
        bytes: 0,
        calls: 0,
        byte_limit: cfg.decode_budget,
        depth_limit: cfg.max_delta_chain_depth,
        base_cursor: None,
        failure: None,
        terminal: None,
        missing: false,
        missing_base: false,
        canonical_fallback: false,
        complete: false,
    }
}
async fn facts(kv: &MemoryKv, id: Hash, prev: Option<Hash>) {
    inventory::stage_packlist(kv, &id, 100, prev, &[], 0)
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
                0
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
        )
        .await
        .unwrap();
        let next = read_progress(&kv, &repo, root).await;
        assert_ne!(first.binding, next.binding);
        let mut corrupt = next.clone();
        corrupt.chain.clear();
        assert!(corrupt.validate().is_err());
        let mut corrupt = next.clone();
        corrupt.dependencies.clear();
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
        assert_eq!(p.next_packmap, Some(root));
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
            "object index limit exceeded"
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
async fn fifty_base_fixture(kv: &MemoryKv, repo: &RepoId) -> (Hash, Hash) {
    let pack = [5; 32];
    let mut previous = None;
    let mut entries = vec![];
    for n in 0..50u8 {
        let object = Object::Blob(Blob { data: vec![n] });
        let id = object.id().unwrap();
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
    (pack, previous.unwrap())
}
#[test]
fn fifty_base_hops_cross_slices_without_restarting_the_object() {
    block_on(async {
        let kv = MemoryKv::with_clock(std::sync::Arc::new(crate::rt::ManualClock::new(0)));
        let repo = repo();
        let (pack, last) = fifty_base_fixture(&kv, &repo).await;
        let mut a = advance(pack);
        a.value.packmap = None;
        let mut p = progress(&a);
        p.base_cursor = Some(BaseCursor {
            origin: pack,
            next: last,
            depth: 0,
        });
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
        assert!(rounds > 1);
        assert!(p.calls > u64::from(SLICE_CALLS));
        assert_eq!(p.bytes, 550);
    });
}

#[test]
fn oversized_frontier_compacts_into_terminal_typed_exhaustion() {
    let a = advance([8; 32]);
    let mut p = progress(&a);
    for n in 0..MAX_ADVANCE_ITEMS {
        let id = hash(&n.to_be_bytes());
        p.queue.push_back(id);
        p.visited.insert(id);
        p.dependencies.insert(id);
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
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), Code::Unavailable);
        assert_eq!(error.public_message(), "object storage request failed");
        let first = read_progress(&kv, &repo, root).await;
        assert_eq!(first.calls, 2, "successful and failed dispatch both count");
        assert_eq!(first.bytes, 100);
        assert_eq!(first.next_packmap, Some(prev));
        assert_eq!(first.chain, BTreeSet::from([root]));
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
        assert_eq!(failed.chain, first.chain);
        assert_eq!(failed.next_packmap, Some(prev));
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
        let mut p = progress(&advance([14; 32]));
        p.next_packmap = Some(prev);
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
        assert_eq!(p.next_packmap, Some(prev));
        assert!(p.chain.is_empty(), "failed item changes are rolled back");
        p.validate().unwrap();
        assert_eq!(
            p.result(&mut advance([14; 32]), 0, 0, 1)
                .unwrap_err()
                .public_message(),
            "object index limit exceeded"
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
        let (pack, last) = fifty_base_fixture(&kv, &repo).await;
        let root = [15; 32];
        let mut a = advance(root);
        a.additions.push(pack);
        let cfg = IndexedConfig {
            max_delta_chain_depth: 30,
            ..IndexedConfig::default()
        };
        // Existing sealed content can have been verified under a higher cap.
        // This is the frozen proof after its MKPL phase, at a base-hop boundary.
        let mut p = progress(&a);
        p.binding = binding(&a, cfg).unwrap();
        p.depth_limit = cfg.max_delta_chain_depth;
        p.next_packmap = None;
        p.chain.insert(root);
        p.packs.insert(pack);
        p.dependencies.extend([root, pack]);
        p.base_cursor = Some(BaseCursor {
            origin: pack,
            next: last,
            depth: 0,
        });
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
                assert_eq!(retained.base_cursor.as_ref().unwrap().depth, 30);
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
fn canonical_fallback_chain_uses_canonical_fallback_without_inventory_rewrite_or_timer() {
    block_on(async {
        let kv = MemoryKv::with_clock(std::sync::Arc::new(crate::rt::ManualClock::new(0)));
        let repo = repo();
        let root = [51; 32];
        let prev = [52; 32];
        facts(&kv, root, Some(prev)).await;
        facts(&kv, prev, None).await;
        verified(&kv, &repo, root).await;
        inventory::tests::install_legacy_pack(&kv, &prev).await;
        let source = SinglePartition.ref_shard(&repo, "refs/heads/main");
        let seal = inventory::seal(&kv, &prev).await.unwrap();
        let calls = SliceBudget::new(9000);
        let store = crate::indexed::budget::Budgeted::new(&kv, &calls);
        let mut a = advance(root);
        a.additions.push(prev);
        assert!(
            !prepare(
                &store,
                &source,
                &SinglePartition,
                &repo,
                &mut a,
                IndexedConfig::default(),
                0,
                &crate::NoopMetrics,
                0
            )
            .await
            .unwrap()
        );
        assert_eq!(calls.used(), 4); // State, two sealed heads, and checkpoint CAS.
        assert!(read_progress(&kv, &repo, root).await.canonical_fallback);
        assert_eq!(inventory::seal(&kv, &prev).await.unwrap(), seal);
        let key = keys::verification(&repo.name, &root);
        assert!(
            kv.get(&source, &keys::timer(1000, 12, key.as_bytes()))
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            !prepare(
                &store,
                &source,
                &SinglePartition,
                &repo,
                &mut a,
                IndexedConfig::default(),
                0,
                &crate::NoopMetrics,
                0
            )
            .await
            .unwrap()
        );
        assert_eq!(calls.used(), 5); // Retained fallback needs only the state read.
    });
}

#[test]
fn alarm_that_reaches_legacy_inventory_stops_and_requests_canonical_fallback() {
    block_on(async {
        let clock = std::sync::Arc::new(crate::rt::ManualClock::new(0));
        let kv = MemoryKv::with_clock(clock.clone());
        let repo = repo();
        let root = [61; 32];
        let prev = [62; 32];
        facts(&kv, root, Some(prev)).await;
        facts(&kv, prev, None).await;
        inventory::tests::install_legacy_pack(&kv, &prev).await;
        let source = SinglePartition.ref_shard(&repo, "refs/heads/main");
        let mut a = advance(root);
        a.additions.push(prev);
        let mut p = progress(&a);
        p.next_packmap = Some(prev);
        p.chain.insert(root);
        p.dependencies.insert(root);
        p.bytes = 100;
        p.calls = 1;
        // Existing 0.5.0 checkpoints omit the new false marker.
        let json = serde_json::to_value(&p).unwrap();
        assert!(json.get("canonical_fallback").is_none());
        assert!(
            !serde_json::from_value::<Progress>(json)
                .unwrap()
                .canonical_fallback
        );
        let key = keys::verification(&repo.name, &root);
        let timer = keys::timer(1000, 12, key.as_bytes());
        kv.apply(
            &source,
            Batch::new()
                .put(
                    key,
                    state::encode(&state::VerificationV1::Verified {
                        pack_len: 100,
                        verified_at_ms: 0,
                        publication: Some(Box::new(p.clone())),
                    }),
                )
                .put(timer.clone(), Value::new(p.binding.to_vec())),
        )
        .await
        .unwrap();
        let registry = crate::timers::TimerRegistry::new().register(
            crate::timers::publication_recheck::PublicationRecheck::new(
                crate::store::BorrowedStore(&kv),
            ),
        );
        clock.advance(1000);
        let report = crate::timers::run_due(
            &kv,
            &source,
            &registry,
            clock.as_ref(),
            1000,
            &crate::timers::TickBudget::default(),
        )
        .await
        .unwrap();
        assert_eq!(report.fired, 1);
        assert!(kv.get(&source, &timer).await.unwrap().is_none());
        let p = read_progress(&kv, &repo, root).await;
        assert!(p.canonical_fallback && !p.complete);
        p.validate().unwrap();
        assert!(
            !prepare(
                &kv,
                &source,
                &SinglePartition,
                &repo,
                &mut a,
                IndexedConfig::default(),
                1000,
                &crate::NoopMetrics,
                0
            )
            .await
            .unwrap()
        );
    });
}
