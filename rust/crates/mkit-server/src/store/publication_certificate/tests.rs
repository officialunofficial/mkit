#![allow(clippy::unwrap_used)]
use super::*;
use crate::indexed::budget::{Budgeted, SliceBudget};
use crate::{MemoryKv, NamespaceKey, RepoName};
use futures_executor::block_on;
use std::sync::Arc;

fn kv() -> MemoryKv {
    MemoryKv::with_clock(Arc::new(crate::rt::ManualClock::new(0)))
}

#[test]
fn certificate_key_goldens_and_restore_validation() {
    let digest = [9; 32];
    assert_eq!(
        keys::publication_certificate(&digest).as_bytes(),
        [b"pc\0".as_slice(), &digest].concat()
    );
    assert_eq!(
        keys::publication_page(&digest).as_bytes(),
        [b"pn\0".as_slice(), &digest].concat()
    );
    assert_eq!(
        keys::parse(&keys::publication_certificate(&digest)),
        Some(keys::ParsedKey::PublicationCertificate(digest))
    );
    assert_eq!(
        keys::parse(&keys::publication_page(&digest)),
        Some(keys::ParsedKey::PublicationPage(digest))
    );
    assert!(keys::parse(&super::super::Key::new(b"pn\0short".to_vec())).is_none());
    let value = Value::new(
        Node::Leaf {
            id: digest,
            flags: DENIAL,
        }
        .encode(),
    );
    let address = hash(value.as_bytes());
    let key = keys::publication_page(&address);
    validate_record(&content_shard(&address), &key, &value).unwrap();
    assert!(
        validate_record(
            &super::super::Partition::Namespace(NamespaceKey::deployment_default()),
            &key,
            &value
        )
        .is_err()
    );
    assert!(validate_record(&content_shard(&address), &key, &Value::new(vec![1, 0])).is_err());
    let malformed = Value::new(vec![1, 0]);
    let address = hash(malformed.as_bytes());
    assert!(
        validate_record(
            &content_shard(&address),
            &keys::publication_page(&address),
            &malformed
        )
        .is_err()
    );
}
async fn size(store: &MemoryKv) -> u64 {
    let mut bytes = 0;
    for p in super::super::content_shards() {
        bytes += store.stats(&p).await.unwrap().bytes;
    }
    bytes
}
async fn raw(store: &MemoryKv, bytes: Vec<u8>) -> Hash {
    let digest = hash(&bytes);
    store
        .apply(
            &content_shard(&digest),
            Batch::new().put(keys::publication_page(&digest), Value::new(bytes)),
        )
        .await
        .unwrap();
    digest
}

#[test]
fn large_history_shares_pages_and_bounds_each_new_identifier() {
    block_on(async {
        let store = kv();
        let mut root = None;
        for n in 0_u32..4_100 {
            let budget = SliceBudget::new(INSERT_CALLS);
            root = Some(
                insert(
                    &Budgeted::new(&store, &budget),
                    root,
                    hash(&n.to_be_bytes()),
                    REACHABLE | DENIAL,
                    0,
                )
                .await
                .unwrap(),
            );
            assert!(budget.used() <= INSERT_CALLS);
        }
        let old_root = root;
        let before = size(&store).await;
        for n in 4_100_u32..4_103 {
            let budget = SliceBudget::new(INSERT_CALLS);
            root = Some(
                insert(
                    &Budgeted::new(&store, &budget),
                    root,
                    hash(&n.to_be_bytes()),
                    REACHABLE | DENIAL,
                    0,
                )
                .await
                .unwrap(),
            );
            assert!(budget.used() <= INSERT_CALLS);
        }
        assert!(size(&store).await - before <= 3 * 34 * (MAX_PAGE_BYTES as u64 + 35));
        for n in [0_u32, 100, 4_099, 4_100, 4_102, 4_103] {
            let budget = SliceBudget::new(LOOKUP_CALLS);
            assert_eq!(
                get(
                    &Budgeted::new(&store, &budget),
                    root,
                    &hash(&n.to_be_bytes())
                )
                .await
                .unwrap(),
                if n < 4_103 { REACHABLE | DENIAL } else { 0 }
            );
        }
        assert_eq!(
            get(&store, old_root, &hash(&4_100_u32.to_be_bytes()))
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            get(&store, old_root, &hash(&0_u32.to_be_bytes()))
                .await
                .unwrap(),
            REACHABLE | DENIAL
        );
    });
}

#[test]
fn deep_adversarial_prefixes_fit_the_lookup_and_insert_allowances() {
    block_on(async {
        let store = kv();
        let id = [0; 32];
        let mut root = Some(insert(&store, None, id, REACHABLE, 0).await.unwrap());
        for n in (0..32).rev() {
            let mut other = id;
            other[n] = 1;
            let budget = SliceBudget::new(INSERT_CALLS);
            root = Some(
                insert(&Budgeted::new(&store, &budget), root, other, DENIAL, 0)
                    .await
                    .unwrap(),
            );
        }
        let budget = SliceBudget::new(LOOKUP_CALLS);
        assert_eq!(
            get(&Budgeted::new(&store, &budget), root, &id)
                .await
                .unwrap(),
            REACHABLE
        );
        assert_eq!(budget.used(), LOOKUP_CALLS);
        let budget = SliceBudget::new(INSERT_CALLS);
        let updated = insert(&Budgeted::new(&store, &budget), root, id, DENIAL, 0)
            .await
            .unwrap();
        assert_eq!(
            get(&store, Some(updated), &id).await.unwrap(),
            REACHABLE | DENIAL
        );
    });
}

#[test]
fn support_successors_are_sorted_and_fit_65_calls_at_maximum_depth() {
    block_on(async {
        let store = kv();
        let mut ids = vec![[0; 32]];
        for n in 0..32 {
            let mut id = [0; 32];
            id[n] = 1;
            ids.push(id);
        }
        ids.sort_unstable();
        let mut root = None;
        for id in ids.iter().rev() {
            root = Some(
                insert(&store, root, *id, SUPPORT | EXTERNAL, 0)
                    .await
                    .unwrap(),
            );
        }
        let mut after = None;
        for expected in &ids {
            let budget = SliceBudget::new(65);
            assert_eq!(
                next(&Budgeted::new(&store, &budget), root, after)
                    .await
                    .unwrap(),
                Some((*expected, SUPPORT | EXTERNAL))
            );
            assert!(budget.used() <= 65);
            after = Some(*expected);
        }
        let budget = SliceBudget::new(65);
        assert_eq!(
            next(&Budgeted::new(&store, &budget), root, after)
                .await
                .unwrap(),
            None
        );
    });
}

#[test]
fn exhausted_partial_insert_does_not_change_the_old_root_and_can_retry() {
    block_on(async {
        let store = kv();
        let root = Some(insert(&store, None, [1; 32], REACHABLE, 0).await.unwrap());
        let budget = SliceBudget::new(2);
        assert!(
            insert(&Budgeted::new(&store, &budget), root, [2; 32], DENIAL, 0)
                .await
                .is_err()
        );
        assert_eq!(get(&store, root, &[2; 32]).await.unwrap(), 0);
        let budget = SliceBudget::new(INSERT_CALLS);
        let next = insert(&Budgeted::new(&store, &budget), root, [2; 32], DENIAL, 0)
            .await
            .unwrap();
        assert_eq!(get(&store, Some(next), &[2; 32]).await.unwrap(), DENIAL);
    });
}

#[test]
fn missing_corrupt_and_wrong_role_pages_never_prove_absence() {
    block_on(async {
        let store = kv();
        assert!(get(&store, Some([9; 32]), &[1; 32]).await.is_err());
        for bytes in [
            vec![],
            vec![2, 0],
            vec![1, 0],
            [vec![1, 0], vec![1; 32], vec![16]].concat(),
        ] {
            let digest = raw(&store, bytes).await;
            assert!(get(&store, Some(digest), &[1; 32]).await.is_err());
        }
        let frontier = Frontier {
            tasks: vec![Task::new(0, [1; 32]).unwrap()],
            next: None,
        };
        let digest = frontier.write(&store, 0).await.unwrap();
        assert!(get(&store, Some(digest), &[1; 32]).await.is_err());
        let leaf = insert(&store, None, [1; 32], DENIAL, 0).await.unwrap();
        assert!(Frontier::read(&store, &leaf).await.is_err());
        store
            .apply(
                &content_shard(&leaf),
                Batch::new().put(keys::publication_page(&leaf), Value::new(vec![1, 0])),
            )
            .await
            .unwrap();
        assert!(get(&store, Some(leaf), &[1; 32]).await.is_err());
    });
}

#[test]
fn malformed_labels_prefixes_and_depths_fail_closed() {
    block_on(async {
        let store = kv();
        let leaf = insert(&store, None, [1; 32], REACHABLE, 0).await.unwrap();
        let node = Node::Branch {
            depth: 0,
            prefix: [0; 32],
            children: BTreeMap::from([(1, leaf), (2, leaf)]),
        };
        let mut bytes = node.encode();
        bytes[70] = 1;
        let digest = raw(&store, bytes).await;
        assert!(
            get(&store, Some(digest), &[9; 32]).await.is_err(),
            "even missing labels require page validation"
        );
        let mut bytes = node.encode();
        bytes[3] = 1;
        let digest = raw(&store, bytes).await;
        assert!(get(&store, Some(digest), &[9; 32]).await.is_err());
        let digest = raw(&store, node.encode()).await;
        assert!(
            get(&store, Some(digest), &[2; 32]).await.is_err(),
            "leaf disagrees with ancestor label"
        );
        let nested = Node::Branch {
            depth: 0,
            prefix: [0; 32],
            children: BTreeMap::from([(1, digest), (2, leaf)]),
        };
        let digest = raw(&store, nested.encode()).await;
        assert!(
            get(&store, Some(digest), &[1; 32]).await.is_err(),
            "depth must increase"
        );
    });
}

#[test]
fn bounded_frontier_preserves_pending_tasks_and_immutable_links() {
    block_on(async {
        let store = kv();
        let tasks: Vec<_> = (0..FRONTIER_TASKS)
            .map(|n| Task::new(0, hash(&n.to_be_bytes())).unwrap())
            .collect();
        let tail = Frontier {
            tasks: tasks.clone(),
            next: None,
        };
        let tail_id = tail.write(&store, 0).await.unwrap();
        let head = Frontier {
            tasks: vec![Task::new(1, [8; 32]).unwrap()],
            next: Some(tail_id),
        };
        let head_id = head.write(&store, 0).await.unwrap();
        assert_eq!(Frontier::read(&store, &head_id).await.unwrap(), head);
        assert_eq!(Frontier::read(&store, &tail_id).await.unwrap(), tail);
        assert_eq!(tail.write(&store, 0).await.unwrap(), tail_id);
        assert!(
            Frontier {
                tasks: vec![],
                next: None
            }
            .write(&store, 0)
            .await
            .is_err()
        );
        assert!(
            Frontier {
                tasks: [tasks.clone(), tasks].concat(),
                next: None
            }
            .write(&store, 0)
            .await
            .is_err()
        );
        assert!(Task::new(4, [0; 32]).is_err());
    });
}

#[test]
fn header_binding_and_absent_legacy_anchor_do_not_grant_authority() {
    block_on(async {
        let store = kv();
        let repo = RepoId {
            namespace: NamespaceKey::deployment_default(),
            name: RepoName::new("certificate").unwrap(),
        };
        let pair = super::super::publication::Pair {
            head: Some([1; 32]),
            packmap: Some([2; 32]),
        };
        let root = insert(&store, None, [1; 32], REACHABLE, 0).await.unwrap();
        let header = Header::new(&repo, 3, pair.clone(), 50, Some(root));
        let digest = header.write(&store, 0).await.unwrap();
        let read = Header::read(&store, &digest).await.unwrap();
        assert!(read.matches(&repo, 3, &pair, 50));
        assert!(!read.matches(&repo, 4, &pair, 50));
        assert!(!read.matches(&repo, 3, &pair, 49));
        assert!(!read.matches(&repo, 3, &super::super::publication::Pair::default(), 50));
        assert!(Header::read(&store, &[0; 32]).await.is_err());
        assert_eq!(get(&store, None, &[1; 32]).await.unwrap(), 0);
    });
}
