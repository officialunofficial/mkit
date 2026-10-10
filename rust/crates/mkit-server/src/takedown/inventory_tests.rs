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
