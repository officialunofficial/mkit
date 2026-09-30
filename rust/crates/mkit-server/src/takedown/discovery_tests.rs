#![allow(clippy::unwrap_used)]
use super::*;
use crate::memory::MemoryKv;
use crate::pipeline::{D34Shards, SinglePartition};
use crate::store::{BatchOutcome, index::IndexValue};
fn multi(repos: &[&RepoId]) -> Addressing {
    let allowed = repos
        .iter()
        .map(|repo| mkit_core::repo_identity::Namespace::parse(repo.namespace.as_str()).unwrap())
        .collect();
    Addressing::Multi(
        crate::repo::MultiAddressing::new()
            .with_namespace_policy(crate::policy::NamespacePolicy::Allowlist(allowed)),
    )
}
const OBJECT: Hash = [3; 32];
const PACK: Hash = [4; 32];
const ACTION: Hash = [5; 32];
fn repo(ns: &str, name: &str) -> RepoId {
    RepoId {
        namespace: NamespaceKey::from_stored(ns.into()),
        name: RepoName::new(name).unwrap(),
    }
}
fn lease(mark: u64) -> codec::LeasedShard {
    codec::LeasedShard {
        epoch: 1,
        expires_at_ms: 100_000,
        acked_epoch: 1,
        authority_generation: None,
        acked_authority_generation: None,
        relay_watermark_ms: mark,
        sweep_due_ms: 100_000,
    }
}
async fn apply(store: &MemoryKv, p: &Partition, batch: Batch) {
    assert_eq!(
        store.apply(p, batch).await.unwrap(),
        BatchOutcome::Committed
    );
}
async fn index(store: &MemoryKv, shards: &dyn ShardMap, repo: &RepoId) {
    let row = IndexValue {
        frame_offset: 0,
        frame_length: 10,
        wire_type: 0,
        decoded_size: 1,
        chain_depth: 0,
        delta_base: None,
    };
    apply(
        store,
        &shards.object_index(repo, &OBJECT),
        Batch::new().put(
            keys::object_index(&repo.name, &OBJECT, &PACK),
            codec::encode_object_index(&OBJECT, &row).unwrap(),
        ),
    )
    .await;
}
async fn advance(
    store: &MemoryKv,
    shards: &dyn ShardMap,
    root: &Partition,
    state: DiscoveryState,
) -> DiscoveryStep {
    // Serialization on every boundary models alarm restart; context/checkpoint
    // commit is the owner's responsibility, and all returned contexts are saved.
    let state = serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
    let result = step(store, shards, root, &ACTION, &OBJECT, false, 20000, state)
        .await
        .unwrap();
    apply(store, root, result.batch.clone()).await;
    result
}
#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "Exercise the complete delayed two-namespace sweep across restart boundaries."
)]
async fn finite_two_namespace_sweep_waits_for_undelivered_membership_then_unions_sources() {
    let store = MemoryKv::default();
    let shards = D34Shards;
    let first = repo("0x1111111111111111111111111111111111111111", "registry");
    let second = repo("0x2222222222222222222222222222222222222222", "active-only");
    let root = Partition::Namespace(NamespaceKey::deployment_default());
    for r in [&first, &second] {
        index(&store, &shards, r).await;
    }
    apply(
        &store,
        &shards.coordinator(&first.namespace),
        Batch::new()
            .put(
                keys::repo_record(&first.name),
                codec::encode_repo_record(&codec::RepoRecord { created_at_ms: 1 }),
            )
            .put(
                keys::leased_shard(&first.name, "refs/heads/main"),
                codec::encode_leased_shard(&lease(1)),
            )
            .put(
                keys::leased_shard(&first.name, "refs/heads/other"),
                codec::encode_leased_shard(&lease(1)),
            ),
    )
    .await;
    apply(
        &store,
        &shards.coordinator(&second.namespace),
        Batch::new().put(
            keys::leased_shard(&second.name, "refs/heads/main"),
            codec::encode_leased_shard(&lease(20000)),
        ),
    )
    .await;
    // Source membership committed while its RepoIndex relay remains undelivered.
    apply(
        &store,
        &shards.ref_shard(&first, "refs/heads/main"),
        Batch::new()
            .put(keys::membership(&first.name, &PACK), Value::default())
            .put(
                keys::relay(1),
                codec::encode_relay(&codec::RelayV1 {
                    at_ms: 1,
                    target: shards.membership(&first, &BlobKey::pack(PACK)),
                    puts: vec![(keys::membership(&first.name, &PACK), Value::default())],
                    deletes: vec![],
                })
                .unwrap(),
            ),
    )
    .await;
    let mut state =
        DiscoveryState::new(&multi(&[&first, &second]), &first.namespace, 1, 5000).unwrap();
    let mut saw_pending_watermark = false;
    for _ in 0..8 {
        let result = advance(&store, &shards, &root, state).await;
        assert!(!result.complete);
        assert_eq!(result.state.namespace, 0);
        saw_pending_watermark |= result.state.watermark.is_some();
        state = result.state;
    }
    assert!(
        saw_pending_watermark,
        "watermark scan resumes after restart"
    );
    for r in [&first, &second] {
        apply(
            &store,
            &shards.membership(r, &BlobKey::pack(PACK)),
            Batch::new().put(keys::membership(&r.name, &PACK), Value::default()),
        )
        .await;
        apply(
            &store,
            &shards.coordinator(&r.namespace),
            Batch::new()
                .put(
                    keys::leased_shard(&r.name, "refs/heads/main"),
                    codec::encode_leased_shard(&lease(20000)),
                )
                .put(
                    keys::leased_shard(&r.name, "refs/heads/other"),
                    codec::encode_leased_shard(&lease(20000)),
                ),
        )
        .await;
    }
    apply(
        &store,
        &shards.ref_shard(&first, "refs/heads/main"),
        Batch::new().delete(keys::relay(1)),
    )
    .await;
    let mut complete = false;
    for _ in 0..40 {
        let result = advance(&store, &shards, &root, state).await;
        complete = result.complete;
        state = result.state;
        if complete {
            break;
        }
    }
    assert!(complete);
    let start = Key::new(b"b\0\xffdiscovery-context\0".to_vec());
    let contexts = store
        .scan(
            &root,
            &start,
            &Key::new(b"b\0\xffdiscovery-context\x01".to_vec()),
            None,
            10,
        )
        .await
        .unwrap();
    assert_eq!(contexts.entries.len(), 2);
    for (_, value) in contexts.entries {
        let row: serde_json::Value = serde_json::from_slice(value.as_bytes()).unwrap();
        assert_eq!(row["known_signers"], serde_json::json!([]));
        assert_eq!(row["context_complete"], false);
    }
}
#[tokio::test]
async fn corrupt_index_and_membership_never_complete() {
    let store = MemoryKv::default();
    let shards = SinglePartition;
    let r = repo("root", "bad");
    let root = shards.coordinator(&r.namespace);
    apply(
        &store,
        &root,
        Batch::new()
            .put(
                keys::repo_record(&r.name),
                codec::encode_repo_record(&codec::RepoRecord { created_at_ms: 1 }),
            )
            .put(
                keys::object_index(&r.name, &OBJECT, &PACK),
                Value::new(b"bad".to_vec()),
            ),
    )
    .await;
    let mut state = DiscoveryState::new(
        &Addressing::Single { repo: r.clone() },
        &r.namespace,
        1,
        5000,
    )
    .unwrap();
    state = advance(&store, &shards, &root, state).await.state;
    assert!(
        step(
            &store,
            &shards,
            &root,
            &ACTION,
            &OBJECT,
            false,
            20000,
            state.clone()
        )
        .await
        .is_err()
    );
    index(&store, &shards, &r).await;
    apply(
        &store,
        &root,
        Batch::new().put(
            keys::membership(&r.name, &PACK),
            Value::new(b"bad".to_vec()),
        ),
    )
    .await;
    assert!(
        step(
            &store, &shards, &root, &ACTION, &OBJECT, false, 20000, state
        )
        .await
        .is_err()
    );
}
#[tokio::test]
async fn recovery_change_resets_the_namespace_without_deleting_contexts() {
    let store = MemoryKv::default();
    let shards = SinglePartition;
    let r = repo("root", "held");
    let root = shards.coordinator(&r.namespace);
    apply(
        &store,
        &root,
        Batch::new().put(
            keys::repo_record(&r.name),
            codec::encode_repo_record(&codec::RepoRecord { created_at_ms: 1 }),
        ),
    )
    .await;
    let state = DiscoveryState::new(
        &Addressing::Single { repo: r.clone() },
        &r.namespace,
        1,
        5000,
    )
    .unwrap();
    let state = advance(&store, &shards, &root, state).await.state;
    assert_eq!(state.phase, 3);
    apply(
        &store,
        &root,
        Batch::new().put(keys::lease_reconcile(), codec::encode_u64(42)),
    )
    .await;
    let result = advance(&store, &shards, &root, state).await;
    assert!(!result.complete);
    assert_eq!(result.state.phase, 0);
    assert!(result.batch.writes.is_empty());
}

#[tokio::test]
async fn single_real_producer_without_registry_uses_the_bound_repository() {
    let store = MemoryKv::default();
    let shards = SinglePartition;
    let r = repo("root", "configured");
    let root = shards.coordinator(&r.namespace);
    index(&store, &shards, &r).await;
    apply(
        &store,
        &root,
        Batch::new().put(keys::membership(&r.name, &PACK), Value::default()),
    )
    .await;
    assert!(
        store
            .get(&root, &keys::repo_record(&r.name))
            .await
            .unwrap()
            .is_none()
    );
    let mut unbound = DiscoveryState::new(
        &Addressing::Single { repo: r.clone() },
        &r.namespace,
        1,
        5000,
    )
    .unwrap();
    unbound.single_repo = None;
    assert!(
        step(
            &store, &shards, &root, &ACTION, &OBJECT, false, 20000, unbound
        )
        .await
        .is_err()
    );
    let mut mismatched = DiscoveryState::new(
        &Addressing::Single { repo: r.clone() },
        &r.namespace,
        1,
        5000,
    )
    .unwrap();
    mismatched.single_repo = Some(("other".into(), r.name.as_str().to_owned()));
    assert!(
        step(
            &store, &shards, &root, &ACTION, &OBJECT, false, 20000, mismatched
        )
        .await
        .is_err()
    );
    let mut state = DiscoveryState::new(
        &Addressing::Single { repo: r.clone() },
        &r.namespace,
        1,
        5000,
    )
    .unwrap();
    let mut writes = 0;
    let mut complete = false;
    for _ in 0..8 {
        let result = advance(&store, &shards, &root, state).await;
        writes += result.batch.writes.len();
        complete = result.complete;
        state = result.state;
        if complete {
            break;
        }
    }
    assert!(complete);
    assert_eq!(writes, 1, "configured Single repository has one held pack");
}

#[tokio::test]
async fn whole_pack_membership_without_object_index_is_discovered_and_kind_is_bound() {
    let store = MemoryKv::default();
    let shards = D34Shards;
    let r = repo("0x3333333333333333333333333333333333333333", "pack");
    let root = Partition::Namespace(NamespaceKey::deployment_default());
    apply(
        &store,
        &shards.coordinator(&r.namespace),
        Batch::new().put(
            keys::repo_record(&r.name),
            codec::encode_repo_record(&codec::RepoRecord { created_at_ms: 1 }),
        ),
    )
    .await;
    apply(
        &store,
        &shards.membership(&r, &BlobKey::pack(PACK)),
        Batch::new().put(keys::membership(&r.name, &PACK), Value::default()),
    )
    .await;
    let range = keys::object_index_range(&r.name, &PACK);
    assert!(
        store
            .scan(&shards.object_index(&r, &PACK), &range.0, &range.1, None, 1)
            .await
            .unwrap()
            .entries
            .is_empty()
    );
    let mut state = DiscoveryState::new(&multi(&[&r]), &r.namespace, 1, 5000).unwrap();
    let mut writes = 0;
    let mut complete = false;
    for iteration in 0..8 {
        let result = step(&store, &shards, &root, &ACTION, &PACK, true, 20000, state)
            .await
            .unwrap();
        apply(&store, &root, result.batch.clone()).await;
        if iteration == 0 {
            assert!(
                step(
                    &store,
                    &shards,
                    &root,
                    &ACTION,
                    &PACK,
                    false,
                    20000,
                    result.state.clone()
                )
                .await
                .is_err()
            );
        }
        writes += result.batch.writes.len();
        complete = result.complete;
        state = serde_json::from_slice(&serde_json::to_vec(&result.state).unwrap()).unwrap();
        if complete {
            break;
        }
    }
    assert!(complete);
    assert_eq!(
        writes, 1,
        "pack membership is sufficient without an object-index row"
    );
}

#[tokio::test]
async fn multi_addressing_with_namespace_shards_discovers_all_registered_repositories() {
    let store = MemoryKv::default();
    let shards = SinglePartition;
    let first = repo("0x4444444444444444444444444444444444444444", "first");
    let sibling = repo(first.namespace.as_str(), "sibling");
    let other = repo("0x5555555555555555555555555555555555555555", "other");
    let root = Partition::Namespace(NamespaceKey::deployment_default());
    for r in [&first, &sibling, &other] {
        index(&store, &shards, r).await;
        apply(
            &store,
            &shards.coordinator(&r.namespace),
            Batch::new()
                .put(
                    keys::repo_record(&r.name),
                    codec::encode_repo_record(&codec::RepoRecord { created_at_ms: 1 }),
                )
                .put(keys::membership(&r.name, &PACK), Value::default()),
        )
        .await;
    }
    let mut state =
        DiscoveryState::new(&multi(&[&first, &other]), &first.namespace, 1, 5000).unwrap();
    let mut writes = 0;
    let mut complete = false;
    for _ in 0..24 {
        let result = advance(&store, &shards, &root, state).await;
        writes += result.batch.writes.len();
        complete = result.complete;
        state = result.state;
        if complete {
            break;
        }
    }
    assert!(complete);
    assert_eq!(
        writes, 3,
        "Multi addressing enumerates rr even with Namespace partitions"
    );
}

#[tokio::test]
async fn any_streams_one_namespace_candidate_and_never_claims_discovery_complete() {
    let store = MemoryKv::default();
    let shards = D34Shards;
    let named = repo("0x6666666666666666666666666666666666666666", "named");
    let holder = repo("0x7777777777777777777777777777777777777777", "known-holder");
    let root = Partition::Namespace(NamespaceKey::deployment_default());
    for r in [&named, &holder] {
        index(&store, &shards, r).await;
        apply(
            &store,
            &shards.coordinator(&r.namespace),
            Batch::new().put(
                keys::repo_record(&r.name),
                codec::encode_repo_record(&codec::RepoRecord { created_at_ms: 1 }),
            ),
        )
        .await;
        apply(
            &store,
            &shards.membership(r, &BlobKey::pack(PACK)),
            Batch::new().put(keys::membership(&r.name, &PACK), Value::default()),
        )
        .await;
    }
    let addressing = Addressing::Multi(crate::repo::MultiAddressing::new().with_namespace_policy(
        crate::policy::NamespacePolicy::Any {
            unsafe_without_admission: false,
        },
    ));
    let mut state = DiscoveryState::new(&addressing, &named.namespace, 1, 5000).unwrap();
    assert!(!state.exhaustive());
    assert!(state.next_candidate(&holder.namespace).is_err());
    for namespace in [&named.namespace, &holder.namespace, &named.namespace] {
        if state.traversed() {
            state.next_candidate(namespace).unwrap();
        }
        assert_eq!(
            state.namespaces.len(),
            1,
            "Any stores one bounded candidate"
        );
        for _ in 0..12 {
            let result = advance(&store, &shards, &root, state).await;
            assert!(!result.complete, "Any cannot prove an exhaustive universe");
            state = result.state;
            if result.traversed {
                break;
            }
        }
        assert!(state.traversed());
    }
    let start = Key::new(b"b\0\xffdiscovery-context\0".to_vec());
    let contexts = store
        .scan(
            &root,
            &start,
            &Key::new(b"b\0\xffdiscovery-context\x01".to_vec()),
            None,
            10,
        )
        .await
        .unwrap();
    assert_eq!(
        contexts.entries.len(),
        2,
        "repeated candidates overwrite idempotently"
    );
    let mut finite = DiscoveryState::new(&multi(&[&named]), &named.namespace, 1, 5000).unwrap();
    assert!(finite.exhaustive());
    for _ in 0..12 {
        let result = advance(&store, &shards, &root, finite).await;
        finite = result.state;
        if result.complete {
            break;
        }
    }
    assert!(finite.traversed());
    assert!(finite.next_candidate(&holder.namespace).is_err());
}
