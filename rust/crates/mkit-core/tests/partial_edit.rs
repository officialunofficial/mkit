#![allow(clippy::similar_names)] // signer/signed names mirror the protocol roles
#![allow(clippy::too_many_lines)] // end-to-end cases keep their evidence together
#![allow(clippy::unwrap_used)] // unwrap is the assertion in integration test helpers

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

impl ObjectSource for CountingSource<'_> {
    fn read(&self, id: &Hash) -> StoreResult<Vec<u8>> {
        assert!(!self.forbidden.contains(id), "hidden object was read");
        self.reads.borrow_mut().push(*id);
        self.store.read(id)
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
        parents: Vec::new(),
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
