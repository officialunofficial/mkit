//! Opt-in resource fixtures; no generated data is committed or used as goldens.
#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::path::Path;

use mkit_core::object::{ChunkedBlob, id_from_object};
use mkit_core::sign::{KeyPair, sign_commit};
use mkit_core::store::ObjectSource;
use mkit_core::{
    Blob, Commit, EntryMode, Hash, Identity, Object, PartialLimits, PartialPath, StoreError,
    StoreResult, Tree, TreeEntry, build_partial_snapshot, serialize,
};

struct Source(BTreeMap<Hash, Vec<u8>>);
impl ObjectSource for Source {
    fn read(&self, id: &Hash) -> StoreResult<Vec<u8>> {
        self.0
            .get(id)
            .cloned()
            .ok_or_else(|| StoreError::ObjectNotFound(hex::encode(id)))
    }
}
impl Source {
    fn put(&mut self, object: Object) -> Hash {
        let bytes = serialize(&object).unwrap();
        let id = id_from_object(&object, &bytes);
        self.0.insert(id, bytes);
        id
    }
}

fn signed_bundle(
    source: &mut Source,
    root: Hash,
    paths: &[PartialPath],
    message_bytes: usize,
) -> (Hash, Vec<u8>) {
    let key = KeyPair::from_seed([23; 32]);
    let mut commit = Commit::new_unannotated(
        root,
        Vec::new(),
        Identity::ed25519(key.public.0),
        key.public.0,
        vec![b'r'; message_bytes],
        1_700_000_002,
        [0; 64],
    );
    commit.signature = sign_commit(&commit, &key).unwrap().0;
    let base = source.put(Object::Commit(commit));
    let bundle = build_partial_snapshot(source, base, paths, &PartialLimits::V1)
        .unwrap()
        .encode(&PartialLimits::V1)
        .unwrap();
    (base, bundle)
}

fn write_fixture(
    dir: &Path,
    name: &str,
    base: Hash,
    paths: &[PartialPath],
    bundle: &[u8],
    witness_bytes: usize,
    selected_bytes: usize,
) {
    std::fs::write(dir.join(format!("{name}.mkwb")), bundle).unwrap();
    let paths: Vec<Vec<String>> = paths
        .iter()
        .map(|components| components.iter().map(hex::encode).collect())
        .collect();
    let metadata = serde_json::json!({
        "base": hex::encode(base), "paths": paths,
        "digest": hex::encode(mkit_core::hash::hash(bundle)),
        "bundle_bytes": bundle.len(), "witness_bytes": witness_bytes,
        "selected_bytes": selected_bytes,
    });
    std::fs::write(
        dir.join(format!("{name}.json")),
        serde_json::to_vec_pretty(&metadata).unwrap(),
    )
    .unwrap();
}

fn large_fixture(dir: &Path, label: &str, file_count: usize, file_bytes: usize) {
    let mut source = Source(BTreeMap::new());
    let mut paths = Vec::new();
    let mut entries = Vec::new();
    for index in 0..file_count {
        let name = format!("file{index:03}").into_bytes();
        paths.push(vec![name.clone()]);
        let object_hash = source.put(Object::Blob(Blob {
            data: vec![u8::try_from(index).unwrap(); file_bytes],
        }));
        entries.push(TreeEntry {
            name,
            mode: EntryMode::Blob,
            object_hash,
        });
    }
    // Hidden sibling triples authenticate structure but are never selected/read.
    for index in 0..4_000 {
        entries.push(TreeEntry {
            name: format!("hidden{index:05}").into_bytes(),
            mode: EntryMode::Blob,
            object_hash: [42; 32],
        });
    }
    let target = 1024 * 1024;
    let mut tree = Tree { entries };
    let initial = serialize(&Object::Tree(tree.clone())).unwrap().len();
    let mut remaining = target - initial;
    for entry in tree.entries.iter_mut().skip(file_count) {
        let extra = remaining.min(255 - entry.name.len());
        entry.name.resize(entry.name.len() + extra, b'x');
        remaining -= extra;
    }
    assert_eq!(remaining, 0);
    assert_eq!(
        serialize(&Object::Tree(tree.clone())).unwrap().len(),
        target
    );
    let root = source.put(Object::Tree(tree));
    let (base, bundle) = signed_bundle(&mut source, root, &paths, 1);
    write_fixture(
        dir,
        label,
        base,
        &paths,
        &bundle,
        target,
        file_count * file_bytes,
    );
    if label != "large" {
        return;
    }

    // Legitimate signed base-message bytes fill the complete MKWB boundary,
    // without adding selected files or exceeding the 4 MiB base-object bound.
    let target_bundle = 4 * 1024 * 1024;
    let mut message_bytes = target_bundle - bundle.len() + 1;
    for _ in 0..4 {
        let (base, bundle) = signed_bundle(&mut source, root, &paths, message_bytes);
        if bundle.len() == target_bundle {
            write_fixture(
                dir,
                "bundle_limit",
                base,
                &paths,
                &bundle,
                target,
                file_count * file_bytes,
            );
            return;
        }
        message_bytes = message_bytes + target_bundle - bundle.len();
    }
    panic!("could not reach exact canonical bundle boundary");
}

fn shared_fixture(dir: &Path) {
    let mut source = Source(BTreeMap::new());
    let one = source.put(Object::Blob(Blob { data: vec![1] }));
    let empty = source.put(Object::Blob(Blob { data: Vec::new() }));
    let mut chunks = vec![empty; 120_000];
    chunks[0] = one;
    let object_hash = source.put(Object::ChunkedBlob(ChunkedBlob {
        total_size: 1,
        chunk_size: 0,
        chunks,
    }));
    let mut paths = Vec::new();
    let entries = (0..256)
        .map(|index| {
            let name = format!("file{index:03}").into_bytes();
            paths.push(vec![name.clone()]);
            TreeEntry {
                name,
                mode: EntryMode::Blob,
                object_hash,
            }
        })
        .collect();
    let tree = Object::Tree(Tree { entries });
    let witness_bytes = serialize(&tree).unwrap().len();
    let root = source.put(tree);
    let (base, bundle) = signed_bundle(&mut source, root, &paths, 1);
    write_fixture(dir, "shared", base, &paths, &bundle, witness_bytes, 256);
}

#[test]
fn write_partial_consumer_resources_if_requested() {
    let Ok(dir) = std::env::var("MKIT_PARTIAL_RESOURCE_DIR") else {
        return;
    };
    let dir = Path::new(&dir);
    assert!(
        dir.is_absolute(),
        "resource output must be an explicit absolute directory"
    );
    std::fs::create_dir_all(dir).unwrap();
    large_fixture(dir, "large", 4, 256 * 1024);
    large_fixture(dir, "many", 256, 4 * 1024);
    shared_fixture(dir);
}
