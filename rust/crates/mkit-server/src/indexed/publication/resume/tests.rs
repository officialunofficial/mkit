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
        missing: false,
        missing_base: false,
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
#[test]
fn fifty_base_hops_cross_slices_without_restarting_the_object() {
    block_on(async {
        let kv = MemoryKv::with_clock(std::sync::Arc::new(crate::rt::ManualClock::new(0)));
        let repo = repo();
        let pack = [5; 32];
        let mut previous = None;
        let mut entries = vec![];
        for n in 0..50u8 {
            let object = Object::Blob(Blob { data: vec![n] });
            let id = object.id().unwrap();
            inventory::stage(&kv, &pack, 10_000, &id, &object, previous, 0)
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
        inventory::complete(&kv, &pack, 10_000, 0).await.unwrap();
        let source = SinglePartition.ref_shard(&repo, "refs/heads/main");
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
        let mut a = advance(pack);
        a.value.packmap = None;
        let mut p = progress(&a);
        p.base_cursor = Some(BaseCursor {
            origin: pack,
            next: previous.unwrap(),
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
