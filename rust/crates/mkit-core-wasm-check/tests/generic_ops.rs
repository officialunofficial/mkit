//! Compile and execute the storage-independent operations on wasm32.

use mkit_core::hash::Hash;
use mkit_core::object::{Blob, Commit, EntryMode, Identity, Object, Tree, TreeEntry};
use mkit_core::ops::{cherry_pick, find_merge_base, is_ancestor, merge_trees, revert};
use mkit_core::store::{MemoryOverlay, MemoryOverlayLimits, MemorySource, ObjectSource};

fn insert(source: &mut MemorySource, object: &Object) -> Hash {
    let id = object.id().expect("fixture object id");
    source
        .insert(
            id,
            mkit_core::serialize::serialize(object).expect("fixture canonical bytes"),
        )
        .expect("verified fixture insert");
    id
}

fn tree(source: &mut MemorySource, content: &[u8]) -> Hash {
    let blob = insert(
        source,
        &Object::Blob(Blob {
            data: content.to_vec(),
        }),
    );
    insert(
        source,
        &Object::Tree(Tree {
            entries: vec![TreeEntry {
                name: b"file".to_vec(),
                mode: EntryMode::Blob,
                object_hash: blob,
            }],
        }),
    )
}

fn commit(source: &mut MemorySource, tree_hash: Hash, parents: Vec<Hash>) -> Hash {
    insert(
        source,
        &Object::Commit(Commit {
            tree_hash,
            parents,
            author: Identity::ed25519([0; 32]),
            signer: [0; 32],
            message: b"change".to_vec(),
            timestamp: 1,
            message_hash: [0; 32],
            content_digest: [0; 32],
            signature: [0; 64],
        }),
    )
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn generic_ops_read_their_own_writes() {
    let mut source = MemorySource::default();
    let base = tree(&mut source, b"a\nb\nc\n");
    let ours = tree(&mut source, b"A\nb\nc\n");
    let theirs = tree(&mut source, b"a\nb\nC\n");
    let expected_blob = Object::Blob(Blob {
        data: b"A\nb\nC\n".to_vec(),
    })
    .id()
    .unwrap();
    let expected = Object::Tree(Tree {
        entries: vec![TreeEntry {
            name: b"file".to_vec(),
            mode: EntryMode::Blob,
            object_hash: expected_blob,
        }],
    })
    .id()
    .unwrap();
    assert!(matches!(
        source.read(&expected),
        Err(mkit_core::store::StoreError::ObjectNotFound(_))
    ));
    assert!(matches!(
        source.read(&expected_blob),
        Err(mkit_core::store::StoreError::ObjectNotFound(_))
    ));
    let root = commit(&mut source, base, vec![]);
    let target = commit(&mut source, theirs, vec![root]);
    let store = MemoryOverlay::new(
        source,
        MemoryOverlayLimits {
            read_calls: 100,
            read_bytes: 64 * 1024,
            written_bytes: 64 * 1024,
            written_objects: 100,
        },
    );
    let merged = merge_trees(&store, Some(base), Some(ours), Some(theirs)).unwrap();
    assert!(!merged.has_conflicts());
    assert_eq!(merged.tree_hash, expected);
    let picked = cherry_pick(&store, target, ours, None).unwrap();
    assert!(!picked.has_conflicts());
    assert_eq!(picked.tree_hash, merged.tree_hash);
    // This revert reads a newly emitted tree and text blob from the overlay.
    let reverted = revert(&store, target, picked.tree_hash).unwrap();
    assert!(!reverted.has_conflicts());
    assert_eq!(reverted.tree_hash, ours);
    assert!(matches!(
        store.read_object(&reverted.tree_hash).unwrap(),
        Object::Tree(_)
    ));
    assert_eq!(find_merge_base(&store, root, target).unwrap(), Some(root));
    assert!(is_ancestor(&store, root, target).unwrap());
    assert!(!is_ancestor(&store, target, root).unwrap());
    let mut ancestors = std::collections::HashSet::new();
    mkit_core::ops::collect_ancestor_set(&store, target, &mut ancestors).unwrap();
    assert_eq!(ancestors, std::collections::HashSet::from([root, target]));
    let empty = revert(&store, root, base).unwrap();
    assert!(
        matches!(store.read_object(&empty.tree_hash).unwrap(), Object::Tree(t) if t.entries.is_empty())
    );
}
