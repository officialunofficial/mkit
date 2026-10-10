use super::inventory;
use crate::{ManualClock, MemoryKv};
use mkit_core::hash::Hash;
use mkit_core::object::{Blob, Object};
use std::collections::BTreeSet;
use std::sync::Arc;

fn store() -> MemoryKv {
    MemoryKv::with_clock(Arc::new(ManualClock::new(0)))
}

fn blob(n: u8) -> (Hash, Object) {
    let object = Object::Blob(Blob { data: vec![n] });
    (object.id().unwrap(), object)
}

async fn dependencies(store: &MemoryKv, pack: &Hash) -> BTreeSet<Hash> {
    let seen = std::sync::Mutex::new(BTreeSet::new());
    let seen_ref = &seen;
    let stopped = inventory::visit_dependencies(store, pack, |id, row| async move {
        assert_eq!(row.kind, 0);
        seen_ref.lock().unwrap().insert(id);
        Ok(false)
    })
    .await
    .unwrap();
    assert!(!stopped);
    seen.into_inner().unwrap()
}

#[tokio::test]
async fn dependency_rows_list_only_missing_bases_under_the_seal() {
    let store = store();
    let pack = [7; 32];
    let (kept, kept_object) = blob(1);
    let (base_a, _) = blob(2);
    let (base_b, _) = blob(3);
    let (late, late_object) = blob(4);
    inventory::dependency(&store, &pack, 9, &base_a, 1)
        .await
        .unwrap();
    inventory::dependency(&store, &pack, 9, &base_b, 1)
        .await
        .unwrap();
    inventory::dependency(&store, &pack, 9, &late, 1)
        .await
        .unwrap();
    inventory::stage(&store, &pack, 9, &kept, &kept_object, None, 1)
        .await
        .unwrap();
    // A placeholder later supplied by the pack itself leaves the dependency
    // range; a repeated placeholder changes nothing.
    inventory::stage(&store, &pack, 9, &late, &late_object, None, 1)
        .await
        .unwrap();
    inventory::dependency(&store, &pack, 9, &base_a, 1)
        .await
        .unwrap();
    inventory::complete(&store, &pack, 9, 1).await.unwrap();
    assert_eq!(
        dependencies(&store, &pack).await,
        BTreeSet::from([base_a, base_b])
    );
    // The complete traversal still verifies against the same seal.
    let mut all = 0;
    inventory::visit(&store, &pack, false, |_, _| {
        all += 1;
        async { Ok(false) }
    })
    .await
    .unwrap();
    assert_eq!(all, 4);
}

#[tokio::test]
async fn a_pack_without_dependencies_scans_an_empty_range() {
    let store = store();
    let pack = [8; 32];
    let (id, object) = blob(5);
    inventory::stage(&store, &pack, 3, &id, &object, None, 1)
        .await
        .unwrap();
    inventory::complete(&store, &pack, 3, 1).await.unwrap();
    assert!(dependencies(&store, &pack).await.is_empty());
}

#[tokio::test]
async fn dependency_range_is_refused_when_unsealed_or_tampered() {
    use crate::store::{Batch, Key, NamespaceStore, content_shard, keys};
    let store = store();
    let pack = [9; 32];
    let (base, _) = blob(6);
    inventory::dependency(&store, &pack, 4, &base, 1)
        .await
        .unwrap();
    // Not sealed yet.
    assert!(
        inventory::visit_dependencies(&store, &pack, |_, _| async { Ok(false) })
            .await
            .is_err()
    );
    inventory::complete(&store, &pack, 4, 1).await.unwrap();
    assert_eq!(dependencies(&store, &pack).await, BTreeSet::from([base]));
    // Removing a dependency row without the head no longer matches its count.
    let row = Key::new(
        [
            keys::block(&pack).as_bytes(),
            b"\0inventory-dependency\0",
            &base,
        ]
        .concat(),
    );
    store
        .apply(&content_shard(&pack), Batch::new().delete(row))
        .await
        .unwrap();
    assert!(
        inventory::visit_dependencies(&store, &pack, |_, _| async { Ok(false) })
            .await
            .is_err()
    );
}

mod batched {
    use super::*;
    use crate::store::{Key, NamespaceStore, Value, content_shard};
    use inventory::Staged;
    use mkit_core::object::{EntryMode, Tree, TreeEntry};

    const PACK: Hash = [5; 32];
    const LENGTH: u64 = 77;

    async fn rows(store: &MemoryKv) -> Vec<(Key, Value)> {
        store
            .scan(
                &content_shard(&PACK),
                &Key::new(vec![]),
                &Key::new(vec![255]),
                None,
                10_000,
            )
            .await
            .unwrap()
            .entries
    }

    /// Blobs, a duplicate, the empty tree, and a tree with references.
    fn objects(blobs: u8) -> Vec<(Hash, Object)> {
        let mut all: Vec<_> = (0..blobs).map(blob).collect();
        all.push(blob(3));
        let empty = Object::Tree(Tree {
            entries: Vec::new(),
        });
        all.push((empty.id().unwrap(), empty));
        let named = Object::Tree(Tree {
            entries: vec![TreeEntry {
                name: b"a".to_vec(),
                mode: EntryMode::Blob,
                object_hash: all[0].0,
            }],
        });
        all.push((named.id().unwrap(), named));
        all
    }

    async fn batched(store: &MemoryKv, items: &[(Hash, Object)]) -> Result<(), crate::StoreError> {
        let staged: Vec<_> = items
            .iter()
            .map(|(id, object)| Staged {
                id: *id,
                object,
                base: None,
            })
            .collect();
        let clock = ManualClock::new(0);
        inventory::stage_many_with_clock(store, &PACK, LENGTH, &staged, &clock).await
    }

    async fn one_by_one(store: &MemoryKv, items: &[(Hash, Object)]) {
        for (id, object) in items {
            inventory::stage(store, &PACK, LENGTH, id, object, None, 0)
                .await
                .unwrap();
        }
    }

    async fn sealed_ids(store: &MemoryKv) -> BTreeSet<Hash> {
        inventory::complete(store, &PACK, LENGTH, 0).await.unwrap();
        let ids = std::sync::Mutex::new(BTreeSet::new());
        let seen = &ids;
        inventory::visit(store, &PACK, false, |id, _| async move {
            seen.lock().unwrap().insert(id);
            Ok(false)
        })
        .await
        .unwrap();
        ids.into_inner().unwrap()
    }

    #[tokio::test]
    async fn a_batch_stores_exactly_what_one_by_one_staging_stores() {
        // 40 distinct blobs span three applies; placeholders upgrade in place.
        let items = objects(40);
        let (late, _) = blob(10);
        let (tree, _) = items[items.len() - 2].clone();
        let reference = store();
        let candidate = store();
        for store in [&reference, &candidate] {
            inventory::dependency(store, &PACK, LENGTH, &late, 0)
                .await
                .unwrap();
            inventory::dependency(store, &PACK, LENGTH, &tree, 0)
                .await
                .unwrap();
        }
        one_by_one(&reference, &items).await;
        batched(&candidate, &items).await.unwrap();
        assert_eq!(rows(&candidate).await, rows(&reference).await);
        let ids = sealed_ids(&candidate).await;
        assert_eq!(ids, sealed_ids(&reference).await);
        assert_eq!(ids.len(), 40 + 2);
        assert!(dependencies(&candidate, &PACK).await.is_empty());
    }

    #[tokio::test]
    async fn a_repeated_object_in_one_group_is_staged_once() {
        let (a, b) = (blob(1), blob(2));
        let items = vec![a.clone(), b.clone(), a.clone(), b, a];
        let reference = store();
        one_by_one(&reference, &items).await;
        let candidate = store();
        batched(&candidate, &items).await.unwrap();
        assert_eq!(rows(&candidate).await, rows(&reference).await);
        assert_eq!(sealed_ids(&candidate).await.len(), 2);
    }

    #[tokio::test]
    async fn a_replayed_or_partly_staged_batch_changes_nothing() {
        let items = objects(20);
        let reference = store();
        one_by_one(&reference, &items).await;
        // A lost reply or a crash before the checkpoint replays the batch.
        let replayed = store();
        batched(&replayed, &items).await.unwrap();
        let once = rows(&replayed).await;
        batched(&replayed, &items).await.unwrap();
        assert_eq!(rows(&replayed).await, once);
        assert_eq!(once, rows(&reference).await);
        // A crash part-way left a prefix, staged by either path.
        for cut in [1, 7, 16, 21] {
            let partial = store();
            batched(&partial, &items[..cut]).await.unwrap();
            batched(&partial, &items).await.unwrap();
            assert_eq!(rows(&partial).await, once, "prefix of {cut}");
            let mixed = store();
            one_by_one(&mixed, &items[..cut]).await;
            batched(&mixed, &items).await.unwrap();
            assert_eq!(rows(&mixed).await, once, "prefix of {cut} one by one");
        }
    }

    #[tokio::test]
    async fn sixteen_placeholder_upgrades_fit_one_apply() {
        // Sixteen placeholders upgrade in one apply: guard, row, marker and
        // dependency delete each, plus the head. The five-operation worst case
        // (a parent descriptor too) is held by `STAGE_BATCH_ENTRIES`'s const
        // assertion; reference-free objects are almost all blobs.
        let items: Vec<_> = (0..16).map(blob).collect();
        let store = store();
        for (id, _) in &items {
            inventory::dependency(&store, &PACK, LENGTH, id, 0)
                .await
                .unwrap();
        }
        batched(&store, &items).await.unwrap();
        assert_eq!(sealed_ids(&store).await.len(), 16);
        assert!(dependencies(&store, &PACK).await.is_empty());
    }

    /// Stages another entry of the pack between the batch's reads and its apply.
    struct Racing {
        kv: MemoryKv,
        armed: std::sync::Mutex<Option<(Hash, Object)>>,
    }

    impl NamespaceStore for Racing {
        fn capabilities(&self) -> crate::store::StoreCapabilities {
            self.kv.capabilities()
        }

        async fn get(
            &self,
            p: &crate::store::Partition,
            key: &Key,
        ) -> Result<Option<Value>, crate::StoreError> {
            self.kv.get(p, key).await
        }

        async fn scan(
            &self,
            p: &crate::store::Partition,
            start: &Key,
            end: &Key,
            after: Option<&crate::store::Cursor>,
            limit: u32,
        ) -> Result<crate::store::ScanPage, crate::StoreError> {
            self.kv.scan(p, start, end, after, limit).await
        }

        async fn apply(
            &self,
            p: &crate::store::Partition,
            batch: crate::Batch,
        ) -> Result<crate::BatchOutcome, crate::StoreError> {
            let race = self.armed.lock().unwrap().take();
            if let Some((id, object)) = race {
                inventory::stage(&self.kv, &PACK, LENGTH, &id, &object, None, 0)
                    .await
                    .unwrap();
            }
            self.kv.apply(p, batch).await
        }

        async fn stats(
            &self,
            p: &crate::store::Partition,
        ) -> Result<crate::store::PartitionStats, crate::StoreError> {
            self.kv.stats(p).await
        }

        async fn probe(&self) -> Result<(), crate::StoreError> {
            self.kv.probe().await
        }
    }

    #[tokio::test]
    async fn a_concurrent_stager_makes_the_batch_retry_without_partial_effects() {
        let items: Vec<_> = (0..12).map(blob).collect();
        let rival = blob(200);
        let racing = Racing {
            kv: store(),
            armed: std::sync::Mutex::new(Some(rival.clone())),
        };
        let staged: Vec<_> = items
            .iter()
            .map(|(id, object)| Staged {
                id: *id,
                object,
                base: None,
            })
            .collect();
        let clock = ManualClock::new(0);
        let error = inventory::stage_many_with_clock(&racing, &PACK, LENGTH, &staged, &clock)
            .await
            .unwrap_err();
        let crate::StoreError::Unavailable(source) = error else {
            panic!("expected typed contention")
        };
        assert!(matches!(
            source.downcast_ref::<inventory::StagingFailure>(),
            Some(inventory::StagingFailure::CasContention { index: 0 })
        ));
        // Only the rival's rows are there: the lost batch wrote nothing.
        let reference = store();
        one_by_one(&reference, std::slice::from_ref(&rival)).await;
        assert_eq!(rows(&racing.kv).await, rows(&reference).await);
        // The replan reads the new head and lands every entry exactly once.
        inventory::stage_many_with_clock(&racing, &PACK, LENGTH, &staged, &clock)
            .await
            .unwrap();
        one_by_one(&reference, &items).await;
        assert_eq!(rows(&racing.kv).await, rows(&reference).await);
    }
}
