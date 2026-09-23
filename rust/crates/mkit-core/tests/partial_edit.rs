#![allow(clippy::similar_names)] // signer/signed names mirror the protocol roles
#![allow(clippy::too_many_lines)] // end-to-end cases keep their evidence together
#![allow(clippy::unwrap_used)] // unwrap is the assertion in integration test helpers

use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::BTreeSet;

use mkit_core::object::{ChunkedBlob, id_from_object};
use mkit_core::pack::{PackEntries, PackEntry};
use mkit_core::sign::{sign_commit, sign_remix};
use mkit_core::store::ObjectSource;
use mkit_core::verify::{export_closure, verify_closure, verify_closure_store};
use mkit_core::{
    Blob, ClosureMode, Commit, EntryMode, FileReplacement, Hash, Identity, Object, ObjectStore,
    PartialError, PartialLimits, PartialPath, PartialUpdate, Remix, RepoLayout, StoreResult, Tree,
    TreeEntry, build_partial_snapshot, export_partial_update, prepare_partial_commit,
    replace_files, serialize, verify_partial_snapshot,
};

struct CountingSource<'a> {
    store: &'a ObjectStore,
    forbidden: BTreeSet<Hash>,
    reads: RefCell<Vec<Hash>>,
}

struct HiddenMissingSource<'a> {
    store: &'a ObjectStore,
    hidden: Hash,
}

struct CorruptSource<'a> {
    store: &'a ObjectStore,
    corrupted: Hash,
    bytes: Vec<u8>,
}

impl mkit_core::verify::ObjectSource for CorruptSource<'_> {
    fn fetch(
        &mut self,
        id: &Hash,
    ) -> Result<Option<Cow<'_, [u8]>>, mkit_core::verify::VerifyError> {
        if *id == self.corrupted {
            return Ok(Some(Cow::Borrowed(&self.bytes)));
        }
        self.store
            .read(id)
            .map(|bytes| Some(Cow::Owned(bytes)))
            .map_err(Into::into)
    }
}

impl mkit_core::verify::ObjectSource for HiddenMissingSource<'_> {
    fn fetch(
        &mut self,
        id: &Hash,
    ) -> Result<Option<Cow<'_, [u8]>>, mkit_core::verify::VerifyError> {
        if *id == self.hidden {
            return Ok(None);
        }
        self.store
            .read(id)
            .map(|bytes| Some(Cow::Owned(bytes)))
            .map_err(Into::into)
    }
}

impl ObjectSource for CountingSource<'_> {
    fn read(&self, id: &Hash) -> StoreResult<Vec<u8>> {
        assert!(!self.forbidden.contains(id), "hidden object was read");
        self.reads.borrow_mut().push(*id);
        self.store.read(id)
    }
}

impl mkit_core::verify::ObjectSource for CountingSource<'_> {
    fn fetch(
        &mut self,
        id: &Hash,
    ) -> Result<Option<Cow<'_, [u8]>>, mkit_core::verify::VerifyError> {
        self.reads.borrow_mut().push(*id);
        self.store
            .read(id)
            .map(|bytes| Some(Cow::Owned(bytes)))
            .map_err(Into::into)
    }
}

struct Fixture {
    _dir: tempfile::TempDir,
    store: ObjectStore,
    base_id: Hash,
    paths: Vec<PartialPath>,
    old_file: Hash,
    shared_tree: Hash,
    hidden_ids: BTreeSet<Hash>,
}

fn put(store: &ObjectStore, object: &Object) -> Hash {
    let bytes = serialize(object).unwrap();
    let expected = id_from_object(object, &bytes);
    assert_eq!(store.write(&bytes).unwrap(), expected);
    expected
}

fn tree(store: &ObjectStore, mut entries: Vec<TreeEntry>) -> Hash {
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    put(store, &Object::Tree(Tree { entries }))
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
    let old_file = mkit_core::store_file_object(&store, b"old").unwrap();
    let exec = mkit_core::store_file_object(&store, b"#!/bin/sh\n").unwrap();
    let shared_tree = tree(
        &store,
        vec![TreeEntry {
            name: b"x.txt".to_vec(),
            mode: EntryMode::Blob,
            object_hash: old_file,
        }],
    );

    let hidden_blob = mkit_core::store_file_object(&store, b"hidden payload").unwrap();
    let nested_hidden = mkit_core::store_file_object(&store, b"nested secret").unwrap();
    let hidden_tree = tree(
        &store,
        vec![TreeEntry {
            name: b"secret.txt".to_vec(),
            mode: EntryMode::Blob,
            object_hash: nested_hidden,
        }],
    );
    let link = mkit_core::store_file_object(&store, b"a/x.txt").unwrap();
    let empty_tree = tree(&store, vec![]);
    let root = tree(
        &store,
        vec![
            TreeEntry {
                name: b"a".to_vec(),
                mode: EntryMode::Tree,
                object_hash: shared_tree,
            },
            TreeEntry {
                name: b"b".to_vec(),
                mode: EntryMode::Tree,
                object_hash: shared_tree,
            },
            TreeEntry {
                name: b"empty".to_vec(),
                mode: EntryMode::Tree,
                object_hash: empty_tree,
            },
            TreeEntry {
                name: b"exec".to_vec(),
                mode: EntryMode::Executable,
                object_hash: exec,
            },
            TreeEntry {
                name: b"hidden.txt".to_vec(),
                mode: EntryMode::Blob,
                object_hash: hidden_blob,
            },
            TreeEntry {
                name: b"link".to_vec(),
                mode: EntryMode::Symlink,
                object_hash: link,
            },
            TreeEntry {
                name: b"secret".to_vec(),
                mode: EntryMode::Tree,
                object_hash: hidden_tree,
            },
        ],
    );
    let base_key = mkit_core::KeyPair::from_seed([7; 32]);
    let mut remix = Remix {
        tree_hash: root,
        // Snapshot validation intentionally does not require this history.
        parents: vec![mkit_core::hash::hash(b"absent parent history")],
        sources: Vec::new(),
        author: Identity::opaque(b"base author".to_vec()),
        signer: base_key.public.0,
        message: b"base remix".to_vec(),
        timestamp: 1_700_000_000,
        signature: [0; 64],
    };
    remix.signature = sign_remix(&remix, &base_key).unwrap().0;
    let base_id = put(&store, &Object::Remix(remix));
    Fixture {
        _dir: dir,
        store,
        base_id,
        paths: vec![
            vec![b"a".to_vec(), b"x.txt".to_vec()],
            vec![b"b".to_vec(), b"x.txt".to_vec()],
            vec![b"exec".to_vec()],
        ],
        old_file,
        shared_tree,
        hidden_ids: BTreeSet::from([hidden_blob, nested_hidden, hidden_tree, link, empty_tree]),
    }
}

fn verified(fixture: &Fixture) -> mkit_core::VerifiedPartialSnapshot {
    let limits = PartialLimits::V1;
    let source = CountingSource {
        store: &fixture.store,
        forbidden: fixture.hidden_ids.clone(),
        reads: RefCell::new(Vec::new()),
    };
    let bundle = build_partial_snapshot(&source, fixture.base_id, &fixture.paths, &limits).unwrap();
    assert!(
        fixture
            .hidden_ids
            .iter()
            .all(|id| !source.reads.borrow().contains(id))
    );
    verify_partial_snapshot(
        fixture.base_id,
        &fixture.paths,
        &bundle.encode(&limits).unwrap(),
        &limits,
    )
    .unwrap()
}

fn replace_hidden_base_entry(fixture: &mut Fixture, replacement: Hash) {
    let Object::Remix(mut base) = fixture.store.read_object(&fixture.base_id).unwrap() else {
        panic!("base remix")
    };
    let Object::Tree(mut root) = fixture.store.read_object(&base.tree_hash).unwrap() else {
        panic!("base tree")
    };
    root.entries
        .iter_mut()
        .find(|entry| entry.name == b"hidden.txt")
        .unwrap()
        .object_hash = replacement;
    base.tree_hash = put(&fixture.store, &Object::Tree(root));
    let key = mkit_core::KeyPair::from_seed([7; 32]);
    base.signature = sign_remix(&base, &key).unwrap().0;
    fixture.base_id = put(&fixture.store, &Object::Remix(base));
    if replacement != fixture.shared_tree {
        fixture.hidden_ids.insert(replacement);
    }
}

fn export_one_update(fixture: &Fixture) -> Vec<u8> {
    let limits = PartialLimits::V1;
    let verified = verified(fixture);
    let prepared = replace_files(
        &verified,
        &[FileReplacement::bytes(
            fixture.paths[0].clone(),
            b"fresh".to_vec(),
        )],
        &limits,
    )
    .unwrap();
    let key = mkit_core::KeyPair::from_seed([9; 32]);
    let unsigned = prepare_partial_commit(
        &verified,
        &prepared,
        Identity::opaque(b"recipient test".to_vec()),
        key.public.0,
        b"replace".to_vec(),
        1_700_000_101,
        &limits,
    )
    .unwrap();
    let mut signed = unsigned.clone();
    signed.signature = sign_commit(&signed, &key).unwrap().0;
    export_partial_update(&verified, &prepared, &unsigned, &signed, &limits)
        .unwrap()
        .encode(&limits)
        .unwrap()
}

fn append_varint(out: &mut Vec<u8>, mut value: usize) {
    while value >= 0x80 {
        out.push(u8::try_from(value & 0x7f).unwrap() | 0x80);
        value >>= 7;
    }
    out.push(u8::try_from(value).unwrap());
}

/// Re-sign a candidate after mutating an *unselected* root entry. The
/// portable decoder still authenticates its exact raw pack and selected path;
/// only a complete-base recipient can reject the semantic lie.
fn forge_hidden_candidate(update_bytes: &[u8], change: impl FnOnce(&mut Tree)) -> Vec<u8> {
    let update = PartialUpdate::decode(update_bytes, &PartialLimits::V1).unwrap();
    let mut inventory = std::collections::BTreeMap::new();
    for entry in PackEntries::new(update.pack_bytes()).unwrap() {
        let PackEntry::Raw { bytes } = entry.unwrap() else {
            panic!("raw pack")
        };
        let object = mkit_core::deserialize(bytes.as_ref()).unwrap();
        inventory.insert(id_from_object(&object, bytes.as_ref()), bytes.into_owned());
    }
    let Object::Commit(mut candidate) =
        mkit_core::deserialize(inventory.get(update.candidate_id()).unwrap()).unwrap()
    else {
        panic!("candidate")
    };
    let old_root = candidate.tree_hash;
    let Object::Tree(mut root) = mkit_core::deserialize(inventory.get(&old_root).unwrap()).unwrap()
    else {
        panic!("root")
    };
    change(&mut root);
    let root_object = Object::Tree(root);
    let root_bytes = serialize(&root_object).unwrap();
    let new_root = id_from_object(&root_object, &root_bytes);
    candidate.tree_hash = new_root;
    let key = mkit_core::KeyPair::from_seed([9; 32]);
    candidate.signature = sign_commit(&candidate, &key).unwrap().0;
    let candidate_object = Object::Commit(candidate);
    let candidate_bytes = serialize(&candidate_object).unwrap();
    let new_candidate = id_from_object(&candidate_object, &candidate_bytes);
    inventory.remove(&old_root);
    inventory.remove(update.candidate_id());
    inventory.insert(new_root, root_bytes);
    inventory.insert(new_candidate, candidate_bytes);
    let mut writer = mkit_core::PackWriter::new_raw_only();
    for (id, bytes) in &inventory {
        writer.push_raw(*id, bytes).unwrap();
    }
    let pack = writer.finish().unwrap();
    let pack_hash = mkit_core::pack::pack_key(&pack);
    let pack_hash_at = update_bytes
        .windows(32)
        .position(|window| window == update.pack_hash())
        .unwrap();
    let mut forged = update_bytes[..pack_hash_at].to_vec();
    forged[37..69].copy_from_slice(&new_candidate);
    forged.extend_from_slice(&pack_hash);
    forged.extend_from_slice(&(pack.len() as u64).to_be_bytes());
    append_varint(&mut forged, pack.len());
    forged.extend_from_slice(&pack);
    assert!(PartialUpdate::decode(&forged, &PartialLimits::V1).is_ok());
    forged
}

type HiddenMutation = Box<dyn FnOnce(&mut Tree)>;

#[test]
fn recipient_rejects_re_signed_hidden_sibling_subtree_mode_and_symlink_changes() {
    let fixture = fixture();
    let valid = export_one_update(&fixture);
    let new_blob = mkit_core::store_file_object(&fixture.store, b"different hidden bytes").unwrap();
    let new_tree = tree(
        &fixture.store,
        vec![TreeEntry {
            name: b"grafted.txt".to_vec(),
            mode: EntryMode::Blob,
            object_hash: new_blob,
        }],
    );
    let mutations: Vec<HiddenMutation> = vec![
        Box::new(move |root| {
            root.entries
                .iter_mut()
                .find(|e| e.name == b"hidden.txt")
                .unwrap()
                .object_hash = new_blob;
        }),
        Box::new(move |root| {
            root.entries
                .iter_mut()
                .find(|e| e.name == b"secret")
                .unwrap()
                .object_hash = new_tree;
        }),
        Box::new(|root| {
            root.entries
                .iter_mut()
                .find(|e| e.name == b"hidden.txt")
                .unwrap()
                .mode = EntryMode::Executable;
        }),
        Box::new(move |root| {
            root.entries
                .iter_mut()
                .find(|e| e.name == b"link")
                .unwrap()
                .object_hash = new_blob;
        }),
    ];
    for mutate in mutations {
        let forged = forge_hidden_candidate(&valid, mutate);
        let mut source = &fixture.store;
        assert!(matches!(
            mkit_core::partial::verify_partial_update(
                fixture.base_id,
                &forged,
                &mut source,
                &PartialLimits::V1,
                &mkit_core::partial::RecipientLimits::DEFAULT,
            ),
            Err(mkit_core::partial::RecipientError::InvalidChange)
        ));
    }
}

#[test]
fn recipient_checks_hidden_edge_roles_and_chunk_layout() {
    let mut wrong_role = fixture();
    let wrong_child = wrong_role.shared_tree;
    replace_hidden_base_entry(&mut wrong_role, wrong_child);
    let update = export_one_update(&wrong_role);
    let mut source = &wrong_role.store;
    assert!(matches!(
        mkit_core::partial::verify_partial_update(
            wrong_role.base_id,
            &update,
            &mut source,
            &PartialLimits::V1,
            &mkit_core::partial::RecipientLimits::DEFAULT,
        ),
        Err(mkit_core::partial::RecipientError::WrongObjectType(_))
    ));

    let mut bad_chunks = fixture();
    let chunk = mkit_core::store_file_object(&bad_chunks.store, b"abc").unwrap();
    let invalid = put(
        &bad_chunks.store,
        &Object::ChunkedBlob(ChunkedBlob {
            total_size: 4,
            chunk_size: 3,
            chunks: vec![chunk],
        }),
    );
    replace_hidden_base_entry(&mut bad_chunks, invalid);
    let update = export_one_update(&bad_chunks);
    let mut source = &bad_chunks.store;
    assert!(matches!(
        mkit_core::partial::verify_partial_update(
            bad_chunks.base_id,
            &update,
            &mut source,
            &PartialLimits::V1,
            &mkit_core::partial::RecipientLimits::DEFAULT,
        ),
        Err(mkit_core::partial::RecipientError::InvalidChunkLayout)
    ));

    let mut repeated_chunks = fixture();
    let chunk = mkit_core::store_file_object(&repeated_chunks.store, b"abc").unwrap();
    let invalid = put(
        &repeated_chunks.store,
        &Object::ChunkedBlob(ChunkedBlob {
            total_size: 5,
            chunk_size: 3,
            chunks: vec![chunk, chunk],
        }),
    );
    replace_hidden_base_entry(&mut repeated_chunks, invalid);
    let update = export_one_update(&repeated_chunks);
    let mut source = &repeated_chunks.store;
    assert!(matches!(
        mkit_core::partial::verify_partial_update(
            repeated_chunks.base_id,
            &update,
            &mut source,
            &PartialLimits::V1,
            &mkit_core::partial::RecipientLimits::DEFAULT,
        ),
        Err(mkit_core::partial::RecipientError::InvalidChunkLayout)
    ));
}

#[test]
fn recipient_rechecks_shared_tree_at_its_deepest_occurrence() {
    let mut fixture = fixture();
    let nested = tree(
        &fixture.store,
        vec![TreeEntry {
            name: b"again".to_vec(),
            mode: EntryMode::Tree,
            object_hash: fixture.shared_tree,
        }],
    );
    let Object::Remix(mut base) = fixture.store.read_object(&fixture.base_id).unwrap() else {
        panic!("base")
    };
    let Object::Tree(mut root) = fixture.store.read_object(&base.tree_hash).unwrap() else {
        panic!("root")
    };
    root.entries
        .iter_mut()
        .find(|e| e.name == b"secret")
        .unwrap()
        .object_hash = nested;
    base.tree_hash = put(&fixture.store, &Object::Tree(root));
    let key = mkit_core::KeyPair::from_seed([7; 32]);
    base.signature = sign_remix(&base, &key).unwrap().0;
    fixture.base_id = put(&fixture.store, &Object::Remix(base));
    fixture.hidden_ids.insert(nested);
    let update = export_one_update(&fixture);
    let mut source = &fixture.store;
    let received = mkit_core::partial::verify_partial_update(
        fixture.base_id,
        &update,
        &mut source,
        &PartialLimits::V1,
        &mkit_core::partial::RecipientLimits::DEFAULT,
    )
    .unwrap();
    assert_eq!(received.usage().max_tree_depth, 2);
    let limits = mkit_core::partial::RecipientLimits {
        max_tree_depth: 1,
        ..Default::default()
    };
    assert!(matches!(
        mkit_core::partial::verify_partial_update(
            fixture.base_id,
            &update,
            &mut source,
            &PartialLimits::V1,
            &limits,
        ),
        Err(mkit_core::partial::RecipientError::BudgetExceeded)
    ));
}

#[test]
fn recipient_rejects_substituted_and_noncanonical_source_bytes() {
    let fixture = fixture();
    let update = export_one_update(&fixture);
    let hidden = *fixture.hidden_ids.iter().next().unwrap();
    let substitute = serialize(&Object::Blob(Blob {
        data: b"substitute".to_vec(),
    }))
    .unwrap();
    let mut noncanonical = fixture.store.read(&hidden).unwrap();
    noncanonical.push(0);
    for bytes in [substitute, noncanonical] {
        let mut source = CorruptSource {
            store: &fixture.store,
            corrupted: hidden,
            bytes,
        };
        assert!(matches!(
            mkit_core::partial::verify_partial_update(
                fixture.base_id, &update, &mut source, &PartialLimits::V1,
                &mkit_core::partial::RecipientLimits::DEFAULT,
            ),
            Err(mkit_core::partial::RecipientError::Corrupt(id)) if id == hidden
        ));
    }
}

#[test]
fn large_valid_carrier_tiny_recipient_budget_reads_no_source() {
    let fixture = fixture();
    let verified = verified(&fixture);
    let replacements = fixture
        .paths
        .iter()
        .enumerate()
        .map(|(seed, path)| {
            let bytes = (0usize..(4 * 1024 * 1024 - 1))
                .map(|index| u8::try_from((index.wrapping_mul(31) + seed) % 251).unwrap())
                .collect();
            FileReplacement::bytes(path.clone(), bytes)
        })
        .collect::<Vec<_>>();
    let limits = PartialLimits::V1;
    let prepared = replace_files(&verified, &replacements, &limits).unwrap();
    let signer = mkit_core::KeyPair::from_seed([9; 32]);
    let unsigned = prepare_partial_commit(
        &verified,
        &prepared,
        Identity::opaque(b"large carrier".to_vec()),
        signer.public.0,
        b"large update".to_vec(),
        1_700_000_101,
        &limits,
    )
    .unwrap();
    let mut signed = unsigned.clone();
    signed.signature = sign_commit(&signed, &signer).unwrap().0;
    let bytes = export_partial_update(&verified, &prepared, &unsigned, &signed, &limits)
        .unwrap()
        .encode(&limits)
        .unwrap();
    assert!(bytes.len() > 10 * 1024 * 1024);
    assert!(PartialUpdate::decode(&bytes, &limits).is_ok());
    let mut source = CountingSource {
        store: &fixture.store,
        forbidden: BTreeSet::new(),
        reads: RefCell::new(Vec::new()),
    };
    let recipient = mkit_core::partial::RecipientLimits {
        max_object_bytes: 1,
        ..Default::default()
    };
    assert!(matches!(
        mkit_core::partial::verify_partial_update(
            fixture.base_id,
            &bytes,
            &mut source,
            &limits,
            &recipient,
        ),
        Err(mkit_core::partial::RecipientError::BudgetExceeded)
    ));
    assert!(source.reads.borrow().is_empty());
}

#[test]
fn recipient_accepts_large_untouched_file_beyond_selected_caps() {
    let mut fixture = fixture();
    let large = mkit_core::store_file_object(&fixture.store, &vec![b'L'; 5 * 1024 * 1024]).unwrap();
    replace_hidden_base_entry(&mut fixture, large);
    let update = export_one_update(&fixture);
    let mut source = &fixture.store;
    let received = mkit_core::partial::verify_partial_update(
        fixture.base_id,
        &update,
        &mut source,
        &PartialLimits::V1,
        &mkit_core::partial::RecipientLimits::DEFAULT,
    )
    .unwrap();
    assert!(received.snapshot_closure().is_complete());
}

#[test]
fn occurrence_rebuild_preserves_hidden_triples_and_exports_complete_raw_inventory() {
    let fixture = fixture();
    let verified = verified(&fixture);
    let limits = PartialLimits::V1;
    let recipient_dir = tempfile::tempdir().unwrap();
    let recipient = ObjectStore::init(&RepoLayout::single(recipient_dir.path())).unwrap();
    let base_closure = export_closure(&fixture.store, &fixture.base_id, ClosureMode::Snapshot)
        .expect("complete base closure");
    for pack in &base_closure.packs {
        mkit_core::PackReader::read(pack, &recipient).expect("import pristine base closure");
    }
    let replacements = vec![
        FileReplacement::bytes(fixture.paths[1].clone(), b"new b".to_vec()),
        FileReplacement::bytes(fixture.paths[0].clone(), b"new a".to_vec()),
    ];
    let prepared = replace_files(&verified, &replacements, &limits).unwrap();

    let a_file = mkit_core::store_file_object(&fixture.store, b"new a").unwrap();
    let b_file = mkit_core::store_file_object(&fixture.store, b"new b").unwrap();
    let a_tree = tree(
        &fixture.store,
        vec![TreeEntry {
            name: b"x.txt".to_vec(),
            mode: EntryMode::Blob,
            object_hash: a_file,
        }],
    );
    let b_tree = tree(
        &fixture.store,
        vec![TreeEntry {
            name: b"x.txt".to_vec(),
            mode: EntryMode::Blob,
            object_hash: b_file,
        }],
    );
    let Object::Remix(base) = fixture.store.read_object(&fixture.base_id).unwrap() else {
        panic!("base remix")
    };
    let Object::Tree(mut root) = fixture.store.read_object(&base.tree_hash).unwrap() else {
        panic!("root tree")
    };
    let untouched: Vec<_> = root
        .entries
        .iter()
        .filter(|entry| entry.name != b"a" && entry.name != b"b")
        .cloned()
        .collect();
    root.entries
        .iter_mut()
        .find(|entry| entry.name == b"a")
        .unwrap()
        .object_hash = a_tree;
    root.entries
        .iter_mut()
        .find(|entry| entry.name == b"b")
        .unwrap()
        .object_hash = b_tree;
    let expected_root = put(&fixture.store, &Object::Tree(root));
    assert_eq!(*prepared.root_id(), expected_root);
    let Object::Tree(actual_root) = fixture.store.read_object(&expected_root).unwrap() else {
        panic!("actual root")
    };
    let actual_untouched: Vec<_> = actual_root
        .entries
        .iter()
        .filter(|entry| entry.name != b"a" && entry.name != b"b")
        .cloned()
        .collect();
    assert_eq!(actual_untouched, untouched);
    assert_ne!(a_tree, fixture.shared_tree);
    assert_ne!(b_tree, fixture.shared_tree);
    assert_ne!(a_tree, b_tree);

    let signer = mkit_core::KeyPair::from_seed([9; 32]);
    let unsigned = prepare_partial_commit(
        &verified,
        &prepared,
        Identity::opaque(b"different author".to_vec()),
        signer.public.0,
        b"partial edit".to_vec(),
        1_700_000_100,
        &limits,
    )
    .unwrap();
    let mut signed = unsigned.clone();
    signed.signature = sign_commit(&signed, &signer).unwrap().0;
    mkit_core::verify_commit(&signed).unwrap();
    assert_ne!(signed.author, Identity::ed25519(signed.signer));

    let update = export_partial_update(&verified, &prepared, &unsigned, &signed, &limits).unwrap();
    let encoded = update.encode(&limits).unwrap();
    assert_eq!(PartialUpdate::decode(&encoded, &limits).unwrap(), update);
    let mut full_source = &recipient;
    let received = mkit_core::partial::verify_partial_update(
        fixture.base_id,
        &encoded,
        &mut full_source,
        &limits,
        &mkit_core::partial::RecipientLimits::DEFAULT,
    )
    .unwrap();
    assert_eq!(received.replacements().len(), 2);
    assert_eq!(received.snapshot_closure().mode, ClosureMode::Snapshot);
    assert!(received.snapshot_closure().is_complete());
    let Object::Remix(base) = recipient.read_object(&fixture.base_id).unwrap() else {
        panic!("base remix")
    };
    assert!(recipient.read_object(&base.parents[0]).is_err());
    assert_eq!(*received.candidate_id(), *update.candidate_id());
    let usage = received.usage();
    let mut exact = mkit_core::partial::RecipientLimits::DEFAULT;
    exact.max_objects = usage.objects;
    exact.max_canonical_bytes = usage.canonical_bytes;
    exact.max_tree_depth = usage.max_tree_depth;
    exact.max_occurrences = usage.occurrences;
    assert!(
        mkit_core::partial::verify_partial_update(
            fixture.base_id,
            &encoded,
            &mut full_source,
            &limits,
            &exact,
        )
        .is_ok()
    );
    for tightened in [
        mkit_core::partial::RecipientLimits {
            max_objects: exact.max_objects - 1,
            ..exact
        },
        mkit_core::partial::RecipientLimits {
            max_canonical_bytes: exact.max_canonical_bytes - 1,
            ..exact
        },
        mkit_core::partial::RecipientLimits {
            max_tree_depth: exact.max_tree_depth - 1,
            ..exact
        },
        mkit_core::partial::RecipientLimits {
            max_occurrences: exact.max_occurrences - 1,
            ..exact
        },
    ] {
        assert!(matches!(
            mkit_core::partial::verify_partial_update(
                fixture.base_id,
                &encoded,
                &mut full_source,
                &limits,
                &tightened,
            ),
            Err(mkit_core::partial::RecipientError::BudgetExceeded)
        ));
    }

    let mut old_id_lie = encoded.clone();
    let manifest_old_id = old_id_lie
        .windows(32)
        .position(|window| window == fixture.old_file)
        .unwrap();
    old_id_lie[manifest_old_id] ^= 1;
    assert!(PartialUpdate::decode(&old_id_lie, &limits).is_ok());
    assert!(matches!(
        mkit_core::partial::verify_partial_update(
            fixture.base_id,
            &old_id_lie,
            &mut full_source,
            &limits,
            &mkit_core::partial::RecipientLimits::DEFAULT,
        ),
        Err(mkit_core::partial::RecipientError::InvalidChange)
    ));
    let mut one_object = mkit_core::partial::RecipientLimits::DEFAULT;
    one_object.max_objects = 1;
    assert!(matches!(
        mkit_core::partial::verify_partial_update(
            fixture.base_id,
            &encoded,
            &mut full_source,
            &limits,
            &one_object,
        ),
        Err(mkit_core::partial::RecipientError::BudgetExceeded)
    ));
    let mut hidden_missing = HiddenMissingSource {
        store: &recipient,
        hidden: *fixture.hidden_ids.iter().next().unwrap(),
    };
    assert!(matches!(
        mkit_core::partial::verify_partial_update(
            fixture.base_id,
            &encoded,
            &mut hidden_missing,
            &limits,
            &mkit_core::partial::RecipientLimits::DEFAULT,
        ),
        Err(mkit_core::partial::RecipientError::Missing(_))
    ));
    let again = export_partial_update(&verified, &prepared, &unsigned, &signed, &limits).unwrap();
    assert_eq!(again.encode(&limits).unwrap(), encoded);

    let raw_objects = PackEntries::new(update.pack_bytes())
        .unwrap()
        .map(|entry| match entry.unwrap() {
            PackEntry::Raw { bytes } => bytes.into_owned(),
            PackEntry::Delta { .. } => panic!("raw-only update"),
        })
        .collect::<Vec<_>>();
    let partial_report = verify_closure(
        update.candidate_id(),
        ClosureMode::Snapshot,
        raw_objects.iter().map(Vec::as_slice),
    )
    .unwrap();
    assert!(
        !partial_report.is_complete(),
        "export does not claim hidden closure"
    );

    mkit_core::PackReader::read(update.pack_bytes(), &recipient).unwrap();
    let complete =
        verify_closure_store(&recipient, update.candidate_id(), ClosureMode::Snapshot).unwrap();
    assert!(complete.is_complete());
}

#[test]
fn noops_are_semantic_and_unsupported_batches_are_atomic() {
    let fixture = fixture();
    let verified = verified(&fixture);
    let limits = PartialLimits::V1;
    assert!(matches!(
        replace_files(
            &verified,
            &[FileReplacement::bytes(
                fixture.paths[0].clone(),
                b"old".to_vec()
            )],
            &limits
        ),
        Err(PartialError::NoChanges)
    ));
    assert!(matches!(
        replace_files(
            &verified,
            &[
                FileReplacement::bytes(fixture.paths[0].clone(), b"one".to_vec()),
                FileReplacement::bytes(fixture.paths[0].clone(), b"two".to_vec()),
            ],
            &limits
        ),
        Err(PartialError::UnsupportedPartialOperation)
    ));
    assert!(matches!(
        replace_files(
            &verified,
            &[FileReplacement::bytes(
                vec![b"hidden.txt".to_vec()],
                b"no".to_vec()
            )],
            &limits
        ),
        Err(PartialError::UnsupportedPartialOperation)
    ));
}

#[test]
fn one_sided_edit_of_shared_tree_keeps_other_occurrence_unchanged() {
    let fixture = fixture();
    let verified = verified(&fixture);
    let prepared = replace_files(
        &verified,
        &[FileReplacement::bytes(
            fixture.paths[0].clone(),
            b"only a".to_vec(),
        )],
        &PartialLimits::V1,
    )
    .unwrap();
    let Object::Tree(root) = deserialize_produced(&prepared, prepared.root_id()) else {
        panic!("rebuilt root")
    };
    let a = root
        .entries
        .iter()
        .find(|entry| entry.name == b"a")
        .unwrap();
    let b = root
        .entries
        .iter()
        .find(|entry| entry.name == b"b")
        .unwrap();
    assert_ne!(a.object_hash, fixture.shared_tree);
    assert_eq!(b.object_hash, fixture.shared_tree);
}

#[test]
fn sibling_and_nested_edits_converge_without_overwriting() {
    let dir = tempfile::tempdir().unwrap();
    let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
    let old_a = mkit_core::store_file_object(&store, b"old a").unwrap();
    let old_b = mkit_core::store_file_object(&store, b"old b").unwrap();
    let hidden = mkit_core::store_file_object(&store, b"keep").unwrap();
    let sub = tree(
        &store,
        vec![TreeEntry {
            name: b"b".to_vec(),
            mode: EntryMode::Blob,
            object_hash: old_b,
        }],
    );
    let inner = tree(
        &store,
        vec![
            TreeEntry {
                name: b"a".to_vec(),
                mode: EntryMode::Blob,
                object_hash: old_a,
            },
            TreeEntry {
                name: b"hidden".to_vec(),
                mode: EntryMode::Blob,
                object_hash: hidden,
            },
            TreeEntry {
                name: b"sub".to_vec(),
                mode: EntryMode::Tree,
                object_hash: sub,
            },
        ],
    );
    let root = tree(
        &store,
        vec![TreeEntry {
            name: b"dir".to_vec(),
            mode: EntryMode::Tree,
            object_hash: inner,
        }],
    );
    let key = mkit_core::KeyPair::from_seed([18; 32]);
    let mut commit = Commit::new_unannotated(
        root,
        vec![],
        Identity::ed25519(key.public.0),
        key.public.0,
        vec![],
        9,
        [0; 64],
    );
    commit.signature = sign_commit(&commit, &key).unwrap().0;
    let base = put(&store, &Object::Commit(commit));
    let paths = vec![
        vec![b"dir".to_vec(), b"a".to_vec()],
        vec![b"dir".to_vec(), b"sub".to_vec(), b"b".to_vec()],
    ];
    let limits = PartialLimits::V1;
    let bundle = build_partial_snapshot(&store, base, &paths, &limits).unwrap();
    let verified =
        verify_partial_snapshot(base, &paths, &bundle.encode(&limits).unwrap(), &limits).unwrap();
    let prepared = replace_files(
        &verified,
        &[
            FileReplacement::bytes(paths[1].clone(), b"new b".to_vec()),
            FileReplacement::bytes(paths[0].clone(), b"new a".to_vec()),
        ],
        &limits,
    )
    .unwrap();
    let Object::Tree(new_root) = deserialize_produced(&prepared, prepared.root_id()) else {
        panic!("root")
    };
    let new_inner_id = new_root.entries[0].object_hash;
    let Object::Tree(new_inner) = deserialize_produced(&prepared, &new_inner_id) else {
        panic!("inner")
    };
    assert_eq!(
        new_inner
            .entries
            .iter()
            .find(|entry| entry.name == b"hidden")
            .unwrap()
            .object_hash,
        hidden
    );
    assert_ne!(
        new_inner
            .entries
            .iter()
            .find(|entry| entry.name == b"a")
            .unwrap()
            .object_hash,
        old_a
    );
    let new_sub_id = new_inner
        .entries
        .iter()
        .find(|entry| entry.name == b"sub")
        .unwrap()
        .object_hash;
    let Object::Tree(new_sub) = deserialize_produced(&prepared, &new_sub_id) else {
        panic!("sub")
    };
    assert_ne!(new_sub.entries[0].object_hash, old_b);
}

#[test]
fn large_replacement_uses_canonical_writer_and_substitution_rejects() {
    let fixture = fixture();
    let verified = verified(&fixture);
    let limits = PartialLimits::V1;
    let large: Vec<u8> = (0usize..(1024 * 1024 + 257 * 1024))
        .map(|i| u8::try_from(i.wrapping_mul(31) % 251).expect("value is below 251"))
        .collect();
    let prepared = replace_files(
        &verified,
        &[FileReplacement::bytes(
            fixture.paths[2].clone(),
            large.clone(),
        )],
        &limits,
    )
    .unwrap();
    let canonical = mkit_core::store_file_object(&fixture.store, &large).unwrap();
    let Object::Tree(root) = deserialize_produced(&prepared, prepared.root_id()) else {
        panic!("rebuilt root")
    };
    let exec = root
        .entries
        .iter()
        .find(|entry| entry.name == b"exec")
        .unwrap();
    assert_eq!(exec.mode, EntryMode::Executable);
    assert_eq!(exec.object_hash, canonical);
    assert!(matches!(
        fixture.store.read_object(&canonical).unwrap(),
        Object::ChunkedBlob(_)
    ));

    let Object::Remix(mut other_base) = fixture.store.read_object(&fixture.base_id).unwrap() else {
        panic!("base Remix")
    };
    let base_key = mkit_core::KeyPair::from_seed([7; 32]);
    other_base.timestamp += 1;
    other_base.signature = sign_remix(&other_base, &base_key).unwrap().0;
    let other_base_id = put(&fixture.store, &Object::Remix(other_base));
    let other_bundle =
        build_partial_snapshot(&fixture.store, other_base_id, &fixture.paths, &limits).unwrap();
    let other_verified = verify_partial_snapshot(
        other_base_id,
        &fixture.paths,
        &other_bundle.encode(&limits).unwrap(),
        &limits,
    )
    .unwrap();
    assert!(matches!(
        prepare_partial_commit(
            &other_verified,
            &prepared,
            Identity::opaque(vec![1]),
            [2; 32],
            Vec::new(),
            5,
            &limits
        ),
        Err(PartialError::CommitMismatch)
    ));

    let signer = mkit_core::KeyPair::from_seed([11; 32]);
    let unsigned = prepare_partial_commit(
        &verified,
        &prepared,
        Identity::ed25519([3; 32]),
        signer.public.0,
        b"large".to_vec(),
        5,
        &limits,
    )
    .unwrap();
    let mut signed = unsigned.clone();
    signed.signature = sign_commit(&signed, &signer).unwrap().0;
    let mut substituted = signed.clone();
    substituted.message = b"substituted".to_vec();
    substituted.signature = sign_commit(&substituted, &signer).unwrap().0;
    assert!(mkit_core::verify_commit(&substituted).is_ok());
    assert!(matches!(
        export_partial_update(&verified, &prepared, &unsigned, &substituted, &limits),
        Err(PartialError::CommitMismatch)
    ));
    let mut corrupted = signed.clone();
    corrupted.signature[0] ^= 0x80;
    assert!(matches!(
        export_partial_update(&verified, &prepared, &unsigned, &corrupted, &limits),
        Err(PartialError::CommitMismatch)
    ));
    let mut annotated = signed;
    annotated.message_hash = [1; 32];
    assert!(mkit_core::verify_commit(&annotated).is_ok());
    assert!(matches!(
        export_partial_update(&verified, &prepared, &unsigned, &annotated, &limits),
        Err(PartialError::CommitMismatch)
    ));
}

fn deserialize_produced(prepared: &mkit_core::PreparedPartialEdit, id: &Hash) -> Object {
    let bytes = prepared
        .produced_objects()
        .find_map(|(candidate, bytes)| (candidate == id).then_some(bytes))
        .unwrap();
    mkit_core::deserialize(bytes).unwrap()
}

#[test]
fn selected_representation_reuse_exports_even_when_already_in_base() {
    let fixture = fixture();
    let verified = verified(&fixture);
    let limits = PartialLimits::V1;
    let prepared = replace_files(
        &verified,
        &[FileReplacement::reuse_selected(
            fixture.paths[2].clone(),
            fixture.paths[0].clone(),
        )],
        &limits,
    )
    .unwrap();
    let signer = mkit_core::KeyPair::from_seed([13; 32]);
    let unsigned = prepare_partial_commit(
        &verified,
        &prepared,
        Identity::opaque(vec![1]),
        signer.public.0,
        b"reuse".to_vec(),
        6,
        &limits,
    )
    .unwrap();
    let mut signed = unsigned.clone();
    signed.signature = sign_commit(&signed, &signer).unwrap().0;
    let update = export_partial_update(&verified, &prepared, &unsigned, &signed, &limits).unwrap();
    let ids = PackEntries::new(update.pack_bytes())
        .unwrap()
        .map(|entry| match entry.unwrap() {
            PackEntry::Raw { bytes } => {
                let object = mkit_core::deserialize(bytes.as_ref()).unwrap();
                id_from_object(&object, bytes.as_ref())
            }
            PackEntry::Delta { .. } => unreachable!(),
        })
        .collect::<BTreeSet<_>>();
    assert!(ids.contains(&fixture.old_file));
}

#[test]
fn alternative_valid_representation_is_a_noop() {
    let dir = tempfile::tempdir().unwrap();
    let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
    let chunk = put(
        &store,
        &Object::Blob(Blob {
            data: b"same".to_vec(),
        }),
    );
    let alternate = put(
        &store,
        &Object::ChunkedBlob(ChunkedBlob {
            total_size: 4,
            chunk_size: 4,
            chunks: vec![chunk],
        }),
    );
    let plain = mkit_core::store_file_object(&store, b"same").unwrap();
    let root = tree(
        &store,
        vec![
            TreeEntry {
                name: b"a".to_vec(),
                mode: EntryMode::Blob,
                object_hash: plain,
            },
            TreeEntry {
                name: b"b".to_vec(),
                mode: EntryMode::Blob,
                object_hash: alternate,
            },
        ],
    );
    let key = mkit_core::KeyPair::from_seed([15; 32]);
    let mut commit = Commit::new_unannotated(
        root,
        vec![],
        Identity::ed25519(key.public.0),
        key.public.0,
        vec![],
        7,
        [0; 64],
    );
    commit.signature = sign_commit(&commit, &key).unwrap().0;
    let base = put(&store, &Object::Commit(commit));
    let paths = vec![vec![b"a".to_vec()], vec![b"b".to_vec()]];
    let limits = PartialLimits::V1;
    let bundle = build_partial_snapshot(&store, base, &paths, &limits).unwrap();
    let verified =
        verify_partial_snapshot(base, &paths, &bundle.encode(&limits).unwrap(), &limits).unwrap();
    assert!(matches!(
        replace_files(
            &verified,
            &[FileReplacement::reuse_selected(
                paths[0].clone(),
                paths[1].clone()
            )],
            &limits
        ),
        Err(PartialError::NoChanges)
    ));
}

#[test]
fn lowered_limits_fail_incrementally_and_exact_update_limit_passes() {
    let fixture = fixture();
    let verified = verified(&fixture);
    let too_small_file = PartialLimits {
        max_selected_file_bytes: 2,
        ..PartialLimits::V1
    };
    assert!(matches!(
        replace_files(
            &verified,
            &[FileReplacement::bytes(
                fixture.paths[0].clone(),
                b"new".to_vec()
            )],
            &too_small_file
        ),
        Err(PartialError::WorkspaceTooLarge)
    ));

    let deduplicated_per_occurrence = PartialLimits {
        max_total_selected_bytes: 19,
        ..PartialLimits::V1
    };
    assert!(matches!(
        replace_files(
            &verified,
            &[
                FileReplacement::reuse_selected(fixture.paths[0].clone(), fixture.paths[2].clone()),
                FileReplacement::reuse_selected(fixture.paths[1].clone(), fixture.paths[2].clone()),
            ],
            &deduplicated_per_occurrence
        ),
        Err(PartialError::WorkspaceTooLarge)
    ));

    let cumulative = PartialLimits {
        max_selected_file_bytes: 8,
        max_total_selected_bytes: 7,
        ..PartialLimits::V1
    };
    assert!(matches!(
        replace_files(
            &verified,
            &[
                FileReplacement::bytes(fixture.paths[0].clone(), b"aaaa".to_vec()),
                FileReplacement::bytes(fixture.paths[1].clone(), b"bbbb".to_vec()),
            ],
            &cumulative
        ),
        Err(PartialError::WorkspaceTooLarge)
    ));

    let tiny_pack = PartialLimits {
        max_raw_pack_bytes: 64,
        ..PartialLimits::V1
    };
    assert!(matches!(
        replace_files(
            &verified,
            &[FileReplacement::bytes(
                fixture.paths[0].clone(),
                b"changed".to_vec()
            )],
            &tiny_pack
        ),
        Err(PartialError::SubmissionTooLarge)
    ));

    let limits = PartialLimits::V1;
    let prepared = replace_files(
        &verified,
        &[FileReplacement::bytes(
            fixture.paths[0].clone(),
            b"changed".to_vec(),
        )],
        &limits,
    )
    .unwrap();
    let signer = mkit_core::KeyPair::from_seed([17; 32]);
    let exact_message = PartialLimits {
        max_commit_message_bytes: 4,
        ..limits
    };
    let unsigned = prepare_partial_commit(
        &verified,
        &prepared,
        Identity::opaque(vec![9]),
        signer.public.0,
        b"1234".to_vec(),
        8,
        &exact_message,
    )
    .unwrap();
    assert!(
        prepare_partial_commit(
            &verified,
            &prepared,
            Identity::opaque(vec![9]),
            signer.public.0,
            b"12345".to_vec(),
            8,
            &exact_message,
        )
        .is_err()
    );
    let mut signed = unsigned.clone();
    signed.signature = sign_commit(&signed, &signer).unwrap().0;
    let update =
        export_partial_update(&verified, &prepared, &unsigned, &signed, &exact_message).unwrap();
    let bytes = update.encode(&exact_message).unwrap();
    let exact_update = PartialLimits {
        max_update_bytes: bytes.len(),
        ..exact_message
    };
    assert!(PartialUpdate::decode(&bytes, &exact_update).is_ok());
    let no_tree_entries = PartialLimits {
        max_tree_entries: 0,
        ..exact_message
    };
    assert!(matches!(
        PartialUpdate::decode(&bytes, &no_tree_entries),
        Err(PartialError::ValidationBudgetExceeded)
    ));
    let smaller_file = PartialLimits {
        max_selected_file_bytes: b"changed".len() - 1,
        ..exact_message
    };
    assert!(matches!(
        PartialUpdate::decode(&bytes, &smaller_file),
        Err(PartialError::WorkspaceTooLarge)
    ));
    let short_update = PartialLimits {
        max_update_bytes: bytes.len() - 1,
        ..exact_message
    };
    assert!(matches!(
        PartialUpdate::decode(&bytes, &short_update),
        Err(PartialError::SubmissionTooLarge)
    ));
}

#[test]
fn export_revalidates_stricter_file_and_tree_limits() {
    let fixture = fixture();
    let verified = verified(&fixture);
    let prepared = replace_files(
        &verified,
        &[FileReplacement::bytes(
            fixture.paths[0].clone(),
            b"changed".to_vec(),
        )],
        &PartialLimits::V1,
    )
    .unwrap();
    let signer = mkit_core::KeyPair::from_seed([18; 32]);
    let unsigned = prepare_partial_commit(
        &verified,
        &prepared,
        Identity::opaque(vec![9]),
        signer.public.0,
        b"limits".to_vec(),
        9,
        &PartialLimits::V1,
    )
    .unwrap();
    let mut signed = unsigned.clone();
    signed.signature = sign_commit(&signed, &signer).unwrap().0;

    let smaller_file = PartialLimits {
        max_selected_file_bytes: b"changed".len() - 1,
        ..PartialLimits::V1
    };
    assert!(matches!(
        export_partial_update(&verified, &prepared, &unsigned, &signed, &smaller_file),
        Err(PartialError::WorkspaceTooLarge)
    ));
    let exact_file = PartialLimits {
        max_selected_file_bytes: b"changed".len(),
        max_total_selected_bytes: b"changed".len(),
        ..PartialLimits::V1
    };
    assert!(export_partial_update(&verified, &prepared, &unsigned, &signed, &exact_file).is_ok());
    assert!(matches!(
        prepare_partial_commit(
            &verified,
            &prepared,
            Identity::opaque(vec![9]),
            signer.public.0,
            b"limits".to_vec(),
            9,
            &smaller_file,
        ),
        Err(PartialError::WorkspaceTooLarge)
    ));

    let no_tree_entries = PartialLimits {
        max_tree_entries: 0,
        ..PartialLimits::V1
    };
    assert!(matches!(
        export_partial_update(&verified, &prepared, &unsigned, &signed, &no_tree_entries),
        Err(PartialError::ValidationBudgetExceeded)
    ));
    let (largest_tree_bytes, largest_tree_entries) = prepared
        .produced_objects()
        .filter_map(|(_, bytes)| match mkit_core::deserialize(bytes).unwrap() {
            Object::Tree(tree) => Some((bytes.len(), tree.entries.len())),
            _ => None,
        })
        .fold((0, 0), |(max_bytes, max_entries), (bytes, entries)| {
            (max_bytes.max(bytes), max_entries.max(entries))
        });
    let exact_tree = PartialLimits {
        max_tree_object_bytes: largest_tree_bytes,
        max_tree_entries: largest_tree_entries,
        ..PartialLimits::V1
    };
    assert!(export_partial_update(&verified, &prepared, &unsigned, &signed, &exact_tree).is_ok());
    let tree_bytes_one_short = PartialLimits {
        max_tree_object_bytes: largest_tree_bytes - 1,
        ..PartialLimits::V1
    };
    assert!(matches!(
        export_partial_update(
            &verified,
            &prepared,
            &unsigned,
            &signed,
            &tree_bytes_one_short,
        ),
        Err(PartialError::WitnessTooLarge)
    ));
    let tree_entries_one_short = PartialLimits {
        max_tree_entries: largest_tree_entries - 1,
        ..PartialLimits::V1
    };
    assert!(matches!(
        export_partial_update(
            &verified,
            &prepared,
            &unsigned,
            &signed,
            &tree_entries_one_short,
        ),
        Err(PartialError::ValidationBudgetExceeded)
    ));
    assert!(matches!(
        prepare_partial_commit(
            &verified,
            &prepared,
            Identity::opaque(vec![9]),
            signer.public.0,
            b"limits".to_vec(),
            9,
            &no_tree_entries,
        ),
        Err(PartialError::ValidationBudgetExceeded)
    ));

    let two_prepared = replace_files(
        &verified,
        &[
            FileReplacement::bytes(fixture.paths[0].clone(), b"changed".to_vec()),
            FileReplacement::bytes(fixture.paths[1].clone(), b"changed".to_vec()),
        ],
        &PartialLimits::V1,
    )
    .unwrap();
    let two_unsigned = prepare_partial_commit(
        &verified,
        &two_prepared,
        Identity::opaque(vec![9]),
        signer.public.0,
        b"aggregate".to_vec(),
        10,
        &PartialLimits::V1,
    )
    .unwrap();
    let mut two_signed = two_unsigned.clone();
    two_signed.signature = sign_commit(&two_signed, &signer).unwrap().0;
    let aggregate_one_short = PartialLimits {
        max_total_selected_bytes: 2 * b"changed".len() - 1,
        ..PartialLimits::V1
    };
    assert!(matches!(
        export_partial_update(
            &verified,
            &two_prepared,
            &two_unsigned,
            &two_signed,
            &aggregate_one_short,
        ),
        Err(PartialError::WorkspaceTooLarge)
    ));
    let aggregate_exact = PartialLimits {
        max_selected_file_bytes: b"changed".len(),
        max_total_selected_bytes: 2 * b"changed".len(),
        ..PartialLimits::V1
    };
    let exact_update = export_partial_update(
        &verified,
        &two_prepared,
        &two_unsigned,
        &two_signed,
        &aggregate_exact,
    )
    .unwrap();
    let exact_bytes = exact_update.encode(&aggregate_exact).unwrap();
    assert!(PartialUpdate::decode(&exact_bytes, &aggregate_exact).is_ok());
}

#[test]
fn candidate_object_and_framing_limits_round_trip_at_exact_bounds() {
    let dir = tempfile::tempdir().unwrap();
    let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
    let old = mkit_core::store_file_object(&store, b"old").unwrap();
    let root = tree(
        &store,
        vec![TreeEntry {
            name: b"f".to_vec(),
            mode: EntryMode::Blob,
            object_hash: old,
        }],
    );
    let base_key = mkit_core::KeyPair::from_seed([19; 32]);
    let mut base_commit = Commit::new_unannotated(
        root,
        Vec::new(),
        Identity::ed25519(base_key.public.0),
        base_key.public.0,
        b"base".to_vec(),
        1,
        [0; 64],
    );
    base_commit.signature = sign_commit(&base_commit, &base_key).unwrap().0;
    let base = put(&store, &Object::Commit(base_commit));
    let paths = vec![vec![b"f".to_vec()]];
    let bundle = build_partial_snapshot(&store, base, &paths, &PartialLimits::V1).unwrap();
    let verified = verify_partial_snapshot(
        base,
        &paths,
        &bundle.encode(&PartialLimits::V1).unwrap(),
        &PartialLimits::V1,
    )
    .unwrap();
    let signer = mkit_core::KeyPair::from_seed([20; 32]);
    let replacement = [FileReplacement::bytes(paths[0].clone(), b"new".to_vec())];
    let prepared = replace_files(&verified, &replacement, &PartialLimits::V1).unwrap();
    let unsigned = prepare_partial_commit(
        &verified,
        &prepared,
        Identity::opaque(b"author".to_vec()),
        signer.public.0,
        b"candidate cap".to_vec(),
        2,
        &PartialLimits::V1,
    )
    .unwrap();
    let mut signed = unsigned.clone();
    signed.signature = sign_commit(&signed, &signer).unwrap().0;
    let candidate_len = serialize(&Object::Commit(signed.clone())).unwrap().len();
    assert!(
        prepared
            .produced_objects()
            .all(|(_, bytes)| bytes.len() < candidate_len)
    );

    let candidate_too_small = PartialLimits {
        max_object_bytes: candidate_len - 1,
        ..PartialLimits::V1
    };
    assert!(replace_files(&verified, &replacement, &candidate_too_small).is_ok());
    assert!(matches!(
        prepare_partial_commit(
            &verified,
            &prepared,
            Identity::opaque(b"author".to_vec()),
            signer.public.0,
            b"candidate cap".to_vec(),
            2,
            &candidate_too_small,
        ),
        Err(PartialError::SubmissionTooLarge)
    ));
    assert!(matches!(
        export_partial_update(
            &verified,
            &prepared,
            &unsigned,
            &signed,
            &candidate_too_small,
        ),
        Err(PartialError::SubmissionTooLarge)
    ));

    let exact_object = PartialLimits {
        max_object_bytes: candidate_len,
        ..PartialLimits::V1
    };
    let initial =
        export_partial_update(&verified, &prepared, &unsigned, &signed, &exact_object).unwrap();
    let initial_bytes = initial.encode(&exact_object).unwrap();
    let exact = PartialLimits {
        max_raw_pack_bytes: initial.pack_bytes().len(),
        max_update_bytes: initial_bytes.len(),
        ..exact_object
    };
    let update = export_partial_update(&verified, &prepared, &unsigned, &signed, &exact).unwrap();
    let encoded = update.encode(&exact).unwrap();
    assert_eq!(encoded.len(), exact.max_update_bytes);
    assert_eq!(update.pack_bytes().len(), exact.max_raw_pack_bytes);
    assert!(PartialUpdate::decode(&encoded, &exact).is_ok());

    let pack_one_short = PartialLimits {
        max_raw_pack_bytes: exact.max_raw_pack_bytes - 1,
        ..exact
    };
    assert!(matches!(
        export_partial_update(&verified, &prepared, &unsigned, &signed, &pack_one_short,),
        Err(PartialError::SubmissionTooLarge)
    ));
    let update_one_short = PartialLimits {
        max_update_bytes: exact.max_update_bytes - 1,
        ..exact
    };
    assert!(matches!(
        export_partial_update(&verified, &prepared, &unsigned, &signed, &update_one_short,),
        Err(PartialError::SubmissionTooLarge)
    ));
}
