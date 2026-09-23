#![allow(clippy::unwrap_used)]

use mkit_core::ClosureMode;
use mkit_core::hash::{Hash, hash};
use mkit_core::partial::{
    FileReplacement, PartialExchangeContext, PartialLimits, PartialUpdate, PublicationOutcome,
    build_partial_snapshot, export_partial_update, prepare_partial_commit, publish_explicit_update,
    replace_files, verify_partial_snapshot,
};
use mkit_core::protocol::{
    AdvanceOutcome, PackKey, RefWriteCondition, SingleAttemptAdvance, Transport, TransportError,
    TransportResult,
};
use mkit_core::sign::{KeyPair, sign_commit};
use mkit_core::transfer::decode_packlist;
use mkit_core::verify::{export_closure, verify_closure_store};
use mkit_core::{
    Commit, EntryMode, Identity, Object, ObjectStore, RepoLayout, Tree, TreeEntry, serialize,
};
use mkit_transport_file::FileTransport;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

fn update_bytes() -> Vec<u8> {
    std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/golden/partial_update/ordinary_update.bin"
    ))
    .unwrap()
}

fn base_store() -> (tempfile::TempDir, ObjectStore, Hash) {
    let dir = tempfile::tempdir().unwrap();
    let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
    let old = mkit_core::store_file_object(&store, b"old golden bytes").unwrap();
    let tree = Object::Tree(Tree {
        entries: vec![TreeEntry {
            name: b"a.txt".to_vec(),
            mode: EntryMode::Blob,
            object_hash: old,
        }],
    });
    let root = store.write(&serialize(&tree).unwrap()).unwrap();
    let key = KeyPair::from_seed([21; 32]);
    let mut commit = Commit::new_unannotated(
        root,
        vec![],
        Identity::ed25519(key.public.0),
        key.public.0,
        b"golden base".to_vec(),
        1_700_000_000,
        [0; 64],
    );
    commit.signature = sign_commit(&commit, &key).unwrap().0;
    let base = store
        .write(&serialize(&Object::Commit(commit)).unwrap())
        .unwrap();
    (dir, store, base)
}

fn second_valid_update() -> Vec<u8> {
    let (_dir, store, base) = base_store();
    let limits = PartialLimits::V1;
    let paths = vec![vec![b"a.txt".to_vec()]];
    let bundle = build_partial_snapshot(&store, base, &paths, &limits).unwrap();
    let verified =
        verify_partial_snapshot(base, &paths, &bundle.encode(&limits).unwrap(), &limits).unwrap();
    let prepared = replace_files(
        &verified,
        &[FileReplacement::bytes(
            paths[0].clone(),
            b"different valid sibling".to_vec(),
        )],
        &limits,
    )
    .unwrap();
    let key = KeyPair::from_seed([22; 32]);
    let unsigned = prepare_partial_commit(
        &verified,
        &prepared,
        Identity::opaque(b"other writer".to_vec()),
        key.public.0,
        b"second sibling".to_vec(),
        1_700_000_002,
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

fn disjoint_file_updates() -> (Hash, Vec<Vec<u8>>, Vec<u8>, Vec<u8>, Hash) {
    let dir = tempfile::tempdir().unwrap();
    let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
    let old_a = mkit_core::store_file_object(&store, b"old a").unwrap();
    let old_b = mkit_core::store_file_object(&store, b"old b").unwrap();
    let root = store
        .write(
            &serialize(&Object::Tree(Tree {
                entries: vec![
                    TreeEntry {
                        name: b"a.txt".to_vec(),
                        mode: EntryMode::Blob,
                        object_hash: old_a,
                    },
                    TreeEntry {
                        name: b"b.txt".to_vec(),
                        mode: EntryMode::Blob,
                        object_hash: old_b,
                    },
                ],
            }))
            .unwrap(),
        )
        .unwrap();
    let key = KeyPair::from_seed([31; 32]);
    let mut base_commit = Commit::new_unannotated(
        root,
        vec![],
        Identity::ed25519(key.public.0),
        key.public.0,
        b"two file base".to_vec(),
        1_700_000_000,
        [0; 64],
    );
    base_commit.signature = sign_commit(&base_commit, &key).unwrap().0;
    let base = store
        .write(&serialize(&Object::Commit(base_commit)).unwrap())
        .unwrap();
    let closure = export_closure(&store, &base, ClosureMode::Snapshot).unwrap();
    let make = |path: &[u8], content: &[u8], seed: u8| {
        let limits = PartialLimits::V1;
        let paths = vec![vec![path.to_vec()]];
        let bundle = build_partial_snapshot(&store, base, &paths, &limits).unwrap();
        let verified =
            verify_partial_snapshot(base, &paths, &bundle.encode(&limits).unwrap(), &limits)
                .unwrap();
        let prepared = replace_files(
            &verified,
            &[FileReplacement::bytes(paths[0].clone(), content.to_vec())],
            &limits,
        )
        .unwrap();
        let writer = KeyPair::from_seed([seed; 32]);
        let unsigned = prepare_partial_commit(
            &verified,
            &prepared,
            Identity::opaque(b"disjoint writer".to_vec()),
            writer.public.0,
            b"edit".to_vec(),
            1_700_000_001,
            &limits,
        )
        .unwrap();
        let mut signed = unsigned.clone();
        signed.signature = sign_commit(&signed, &writer).unwrap().0;
        export_partial_update(&verified, &prepared, &unsigned, &signed, &limits)
            .unwrap()
            .encode(&limits)
            .unwrap()
    };
    (
        base,
        closure.packs,
        make(b"a.txt", b"new a", 32),
        make(b"b.txt", b"new b", 33),
        old_b,
    )
}

fn setup() -> (
    tempfile::TempDir,
    FileTransport,
    Vec<u8>,
    PartialUpdate,
    PartialExchangeContext,
) {
    let dir = tempfile::tempdir().unwrap();
    let tx = FileTransport::new(dir.path());
    let bytes = update_bytes();
    let update = PartialUpdate::decode(&bytes, &PartialLimits::V1).unwrap();
    let (_base_dir, store, base) = base_store();
    let key = KeyPair::from_seed([21; 32]);
    assert_eq!(base, *update.base_id());
    // A prior publication contributes an older packmap node. The golden base
    // itself is parentless, so this tests transfer inventory history rather
    // than claiming commit ancestry that the fixture does not have.
    let Object::Commit(base_commit) = store.read_object(&base).unwrap() else {
        panic!("base")
    };
    let mut earlier = base_commit.clone();
    earlier.message = b"prior publication".to_vec();
    earlier.signature = sign_commit(&earlier, &key).unwrap().0;
    let earlier_id = store
        .write(&serialize(&Object::Commit(earlier)).unwrap())
        .unwrap();
    let earlier_closure = export_closure(&store, &earlier_id, ClosureMode::Snapshot).unwrap();
    let earlier_packs: Vec<_> = earlier_closure
        .packs
        .iter()
        .map(|pack| {
            let key = hash(pack);
            tx.upload_pack(pack, &PackKey::from_hash(key)).unwrap();
            key
        })
        .collect();
    let earlier_node = mkit_core::transfer::encode_packlist(None, &earlier_packs).unwrap();
    let earlier_node_id = hash(&earlier_node);
    tx.upload_blob(&earlier_node, &PackKey::from_hash(earlier_node_id))
        .unwrap();
    let closure = export_closure(&store, &base, ClosureMode::Snapshot).unwrap();
    let old_packs: Vec<_> = closure
        .packs
        .iter()
        .map(|pack| {
            let key = hash(pack);
            tx.upload_pack(pack, &PackKey::from_hash(key)).unwrap();
            key
        })
        .collect();
    tx.write_ref("refs/heads/main", update.base_id()).unwrap();
    let old_node = mkit_core::transfer::encode_packlist(Some(earlier_node_id), &old_packs).unwrap();
    let old_node_id = hash(&old_node);
    tx.upload_blob(&old_node, &PackKey::from_hash(old_node_id))
        .unwrap();
    tx.write_ref("refs/mkit/packmap/main", &old_node_id)
        .unwrap();
    let context = PartialExchangeContext::bind(
        "repo-one",
        "refs/heads/main",
        [7; 32],
        *update.base_id(),
        &bytes,
    );
    (dir, tx, bytes, update, context)
}

#[test]
fn publishes_exact_pack_and_appends_to_prior_history() {
    let (_dir, tx, bytes, update, context) = setup();
    assert!(matches!(
        publish_explicit_update(&tx, &bytes, &PartialLimits::V1, &context).unwrap(),
        PublicationOutcome::Published
    ));
    assert_eq!(
        tx.read_ref("refs/heads/main").unwrap(),
        Some(*update.candidate_id())
    );
    assert_eq!(
        tx.download_pack(&PackKey::from_hash(*update.pack_hash()))
            .unwrap(),
        update.pack_bytes()
    );
    let node_id = tx.read_ref("refs/mkit/packmap/main").unwrap().unwrap();
    let node_bytes = tx.download_blob(&PackKey::from_hash(node_id)).unwrap();
    let node = decode_packlist(&node_bytes).unwrap();
    assert_eq!(node.packs, vec![*update.pack_hash()]);
    let old = node.prev.unwrap();
    let earlier = decode_packlist(&tx.download_blob(&PackKey::from_hash(old)).unwrap()).unwrap();
    assert!(!earlier.packs.is_empty());
    assert!(earlier.prev.is_some(), "older publication remains linked");
    for pack in earlier.packs {
        assert!(tx.pack_exists(&PackKey::from_hash(pack)).unwrap());
    }
    let rebuilt_dir = tempfile::tempdir().unwrap();
    let rebuilt = ObjectStore::init(&RepoLayout::single(rebuilt_dir.path())).unwrap();
    let mut chain = Vec::new();
    let mut current = Some(node_id);
    while let Some(id) = current {
        let node = decode_packlist(&tx.download_blob(&PackKey::from_hash(id)).unwrap()).unwrap();
        chain.push(node.packs);
        current = node.prev;
    }
    for packs in chain.iter().rev() {
        for key in packs {
            mkit_core::PackReader::read(
                &tx.download_pack(&PackKey::from_hash(*key)).unwrap(),
                &rebuilt,
            )
            .unwrap();
        }
    }
    assert!(
        verify_closure_store(&rebuilt, update.candidate_id(), ClosureMode::Snapshot)
            .unwrap()
            .is_complete()
    );
}

#[test]
fn two_valid_sibling_updates_share_base_and_one_loses_cas() {
    let (_dir, tx, first, first_update, first_context) = setup();
    let second = second_valid_update();
    let second_update = PartialUpdate::decode(&second, &PartialLimits::V1).unwrap();
    assert_eq!(first_update.base_id(), second_update.base_id());
    assert_ne!(first_update.candidate_id(), second_update.candidate_id());
    let second_context = PartialExchangeContext::bind(
        "repo-one",
        "refs/heads/main",
        [8; 32],
        *second_update.base_id(),
        &second,
    );
    assert!(matches!(
        publish_explicit_update(&tx, &first, &PartialLimits::V1, &first_context).unwrap(),
        PublicationOutcome::Published
    ));
    assert!(matches!(
        publish_explicit_update(&tx, &second, &PartialLimits::V1, &second_context).unwrap(),
        PublicationOutcome::HeadConflict
    ));
    assert_eq!(
        tx.read_ref("refs/heads/main").unwrap(),
        Some(*first_update.candidate_id())
    );
    assert!(
        !tx.pack_exists(&PackKey::from_hash(*second_update.pack_hash()))
            .unwrap()
    );
}

#[test]
fn disjoint_file_edits_from_same_base_do_not_auto_merge() {
    let (base, base_packs, a_bytes, b_bytes, old_b) = disjoint_file_updates();
    let a = PartialUpdate::decode(&a_bytes, &PartialLimits::V1).unwrap();
    let b = PartialUpdate::decode(&b_bytes, &PartialLimits::V1).unwrap();
    assert_eq!(a.base_id(), b.base_id());
    assert_ne!(a.changed_paths().next(), b.changed_paths().next());
    let dir = tempfile::tempdir().unwrap();
    let tx = FileTransport::new(dir.path());
    let keys: Vec<_> = base_packs
        .iter()
        .map(|pack| {
            let key = hash(pack);
            tx.upload_pack(pack, &PackKey::from_hash(key)).unwrap();
            key
        })
        .collect();
    let node = mkit_core::transfer::encode_packlist(None, &keys).unwrap();
    let node_id = hash(&node);
    tx.upload_blob(&node, &PackKey::from_hash(node_id)).unwrap();
    tx.write_ref("refs/mkit/packmap/main", &node_id).unwrap();
    tx.write_ref("refs/heads/main", &base).unwrap();
    let a_context =
        PartialExchangeContext::bind("two-file-repo", "refs/heads/main", [41; 32], base, &a_bytes);
    let b_context =
        PartialExchangeContext::bind("two-file-repo", "refs/heads/main", [42; 32], base, &b_bytes);
    assert!(matches!(
        publish_explicit_update(&tx, &a_bytes, &PartialLimits::V1, &a_context).unwrap(),
        PublicationOutcome::Published
    ));
    assert!(matches!(
        publish_explicit_update(&tx, &b_bytes, &PartialLimits::V1, &b_context).unwrap(),
        PublicationOutcome::HeadConflict
    ));
    assert_eq!(
        tx.read_ref("refs/heads/main").unwrap(),
        Some(*a.candidate_id())
    );
    let rebuilt_dir = tempfile::tempdir().unwrap();
    let rebuilt = ObjectStore::init(&RepoLayout::single(rebuilt_dir.path())).unwrap();
    for pack in &base_packs {
        mkit_core::PackReader::read(pack, &rebuilt).unwrap();
    }
    mkit_core::PackReader::read(a.pack_bytes(), &rebuilt).unwrap();
    let Object::Commit(winner) = rebuilt.read_object(a.candidate_id()).unwrap() else {
        panic!("winner commit")
    };
    let Object::Tree(tree) = rebuilt.read_object(&winner.tree_hash).unwrap() else {
        panic!("winner tree")
    };
    assert_eq!(
        tree.entries[1].object_hash, old_b,
        "b was not silently merged"
    );
}

struct LostReply<'a>(&'a FileTransport);

impl Transport for LostReply<'_> {
    fn upload_pack(&self, bytes: &[u8], key: &PackKey) -> TransportResult<()> {
        self.0.upload_pack(bytes, key)
    }
    fn download_pack(&self, key: &PackKey) -> TransportResult<Vec<u8>> {
        self.0.download_pack(key)
    }
    fn pack_exists(&self, key: &PackKey) -> TransportResult<bool> {
        self.0.pack_exists(key)
    }
    fn update_ref(
        &self,
        name: &str,
        condition: RefWriteCondition,
        hash: &Hash,
    ) -> TransportResult<()> {
        self.0.update_ref(name, condition, hash)
    }
    fn read_ref(&self, name: &str) -> TransportResult<Option<Hash>> {
        self.0.read_ref(name)
    }
    fn list_refs(&self, prefix: &str) -> TransportResult<Vec<mkit_core::refs::Ref>> {
        self.0.list_refs(prefix)
    }
}

impl SingleAttemptAdvance for LostReply<'_> {
    fn advance_refs_once(
        &self,
        head_ref: &str,
        head_condition: RefWriteCondition,
        head_value: &Hash,
        packmap_ref: &str,
        packmap_condition: RefWriteCondition,
        packmap_value: &Hash,
    ) -> TransportResult<AdvanceOutcome> {
        assert_eq!(
            self.0
                .advance_refs_once(
                    head_ref,
                    head_condition,
                    head_value,
                    packmap_ref,
                    packmap_condition,
                    packmap_value
                )
                .unwrap(),
            AdvanceOutcome::Committed
        );
        Err(TransportError::ConnectionFailed)
    }
}

struct SiblingWinsBeforeAdvance<'a>(&'a FileTransport);

impl Transport for SiblingWinsBeforeAdvance<'_> {
    fn upload_pack(&self, bytes: &[u8], key: &PackKey) -> TransportResult<()> {
        self.0.upload_pack(bytes, key)
    }
    fn download_pack(&self, key: &PackKey) -> TransportResult<Vec<u8>> {
        self.0.download_pack(key)
    }
    fn pack_exists(&self, key: &PackKey) -> TransportResult<bool> {
        self.0.pack_exists(key)
    }
    fn update_ref(
        &self,
        name: &str,
        condition: RefWriteCondition,
        hash: &Hash,
    ) -> TransportResult<()> {
        self.0.update_ref(name, condition, hash)
    }
    fn read_ref(&self, name: &str) -> TransportResult<Option<Hash>> {
        self.0.read_ref(name)
    }
    fn list_refs(&self, prefix: &str) -> TransportResult<Vec<mkit_core::refs::Ref>> {
        self.0.list_refs(prefix)
    }
}

impl SingleAttemptAdvance for SiblingWinsBeforeAdvance<'_> {
    fn advance_refs_once(
        &self,
        head_ref: &str,
        head_condition: RefWriteCondition,
        head_value: &Hash,
        packmap_ref: &str,
        packmap_condition: RefWriteCondition,
        packmap_value: &Hash,
    ) -> TransportResult<AdvanceOutcome> {
        // Another writer wins the head race after the caller's initial read.
        self.0.write_ref(head_ref, &hash(b"sibling candidate"))?;
        self.0.advance_refs_once(
            head_ref,
            head_condition,
            head_value,
            packmap_ref,
            packmap_condition,
            packmap_value,
        )
    }
}

#[test]
fn lost_reply_stays_unknown_even_when_today_head_matches_candidate() {
    let (_dir, tx, bytes, update, context) = setup();
    assert!(matches!(
        publish_explicit_update(&LostReply(&tx), &bytes, &PartialLimits::V1, &context).unwrap(),
        PublicationOutcome::PublicationUnknown(TransportError::ConnectionFailed)
    ));
    assert_eq!(
        tx.read_ref("refs/heads/main").unwrap(),
        Some(*update.candidate_id())
    );
}

#[test]
fn file_packmap_first_head_conflict_leaves_append_only_superset() {
    let (_dir, tx, bytes, _update, context) = setup();
    let outcome = publish_explicit_update(
        &SiblingWinsBeforeAdvance(&tx),
        &bytes,
        &PartialLimits::V1,
        &context,
    )
    .unwrap();
    assert!(matches!(outcome, PublicationOutcome::HeadConflict));
    assert_eq!(
        tx.read_ref("refs/heads/main").unwrap(),
        Some(hash(b"sibling candidate"))
    );
    let node_id = tx.read_ref("refs/mkit/packmap/main").unwrap().unwrap();
    let node = decode_packlist(&tx.download_blob(&PackKey::from_hash(node_id)).unwrap()).unwrap();
    assert!(
        node.prev.is_some(),
        "old complete-base chain remains reachable"
    );
}

#[test]
fn invalid_context_and_preexisting_sibling_conflict_do_not_upload() {
    let (_dir, tx, bytes, update, mut context) = setup();
    context.exact_ref = "refs/tags/not-a-branch".to_owned();
    assert!(publish_explicit_update(&tx, &bytes, &PartialLimits::V1, &context).is_err());
    assert!(
        !tx.pack_exists(&PackKey::from_hash(*update.pack_hash()))
            .unwrap()
    );
    context.exact_ref = "refs/heads/main".to_owned();
    tx.write_ref("refs/heads/main", &hash(b"concurrent sibling"))
        .unwrap();
    assert!(matches!(
        publish_explicit_update(&tx, &bytes, &PartialLimits::V1, &context).unwrap(),
        PublicationOutcome::HeadConflict
    ));
    assert!(
        !tx.pack_exists(&PackKey::from_hash(*update.pack_hash()))
            .unwrap()
    );
}

#[test]
fn missing_packmap_refuses_before_upload() {
    let (dir, tx, bytes, update, context) = setup();
    // Use the existing transport root and remove only its test-created
    // packmap ref to model a recipient that cannot advertise retained base.
    std::fs::remove_file(dir.path().join("refs/mkit/packmap/main")).unwrap();
    assert!(matches!(
        publish_explicit_update(&tx, &bytes, &PartialLimits::V1, &context).unwrap(),
        PublicationOutcome::UnsupportedRecipient
    ));
    assert_eq!(
        tx.read_ref("refs/heads/main").unwrap(),
        Some(*update.base_id())
    );
    assert!(
        !tx.pack_exists(&PackKey::from_hash(*update.pack_hash()))
            .unwrap()
    );
}

#[derive(Clone, Copy)]
enum PackmapRace {
    OneConflict,
    AlwaysConflict,
    Disappears,
}

struct RacingPackmap<'a> {
    inner: &'a FileTransport,
    root: &'a Path,
    race: PackmapRace,
    attempts: AtomicUsize,
}

impl Transport for RacingPackmap<'_> {
    fn upload_pack(&self, bytes: &[u8], key: &PackKey) -> TransportResult<()> {
        self.inner.upload_pack(bytes, key)
    }
    fn download_pack(&self, _: &PackKey) -> TransportResult<Vec<u8>> {
        panic!("partial publisher must not download hidden packs or packmap nodes")
    }
    fn pack_exists(&self, _: &PackKey) -> TransportResult<bool> {
        panic!("partial publisher must not inspect recipient pack inventory")
    }
    fn update_ref(
        &self,
        name: &str,
        condition: RefWriteCondition,
        value: &Hash,
    ) -> TransportResult<()> {
        self.inner.update_ref(name, condition, value)
    }
    fn read_ref(&self, name: &str) -> TransportResult<Option<Hash>> {
        self.inner.read_ref(name)
    }
    fn list_refs(&self, prefix: &str) -> TransportResult<Vec<mkit_core::refs::Ref>> {
        self.inner.list_refs(prefix)
    }
}

impl SingleAttemptAdvance for RacingPackmap<'_> {
    fn advance_refs_once(
        &self,
        head_ref: &str,
        head_condition: RefWriteCondition,
        head_value: &Hash,
        packmap_ref: &str,
        packmap_condition: RefWriteCondition,
        packmap_value: &Hash,
    ) -> TransportResult<AdvanceOutcome> {
        let attempt = self.attempts.fetch_add(1, Ordering::SeqCst) + 1;
        if matches!(self.race, PackmapRace::Disappears) {
            std::fs::remove_file(self.root.join(packmap_ref)).unwrap();
            return Ok(AdvanceOutcome::PackmapConflict);
        }
        if matches!(self.race, PackmapRace::AlwaysConflict) || attempt == 1 {
            let prior = self.inner.read_ref(packmap_ref)?.unwrap();
            let node = mkit_core::transfer::encode_packlist(Some(prior), &[]).unwrap();
            let node_id = hash(&node);
            self.inner
                .upload_blob(&node, &PackKey::from_hash(node_id))?;
            self.inner
                .update_ref(packmap_ref, RefWriteCondition::Match(prior), &node_id)?;
            return Ok(AdvanceOutcome::PackmapConflict);
        }
        self.inner.advance_refs_once(
            head_ref,
            head_condition,
            head_value,
            packmap_ref,
            packmap_condition,
            packmap_value,
        )
    }
}

#[test]
fn packmap_conflict_retries_from_new_tip_without_hidden_download() {
    let (dir, tx, bytes, update, context) = setup();
    let race = RacingPackmap {
        inner: &tx,
        root: dir.path(),
        race: PackmapRace::OneConflict,
        attempts: AtomicUsize::new(0),
    };
    assert!(matches!(
        publish_explicit_update(&race, &bytes, &PartialLimits::V1, &context).unwrap(),
        PublicationOutcome::Published
    ));
    assert_eq!(race.attempts.load(Ordering::SeqCst), 2);
    assert_eq!(
        tx.read_ref("refs/heads/main").unwrap(),
        Some(*update.candidate_id())
    );
    let tip = tx.read_ref("refs/mkit/packmap/main").unwrap().unwrap();
    let appended = decode_packlist(&tx.download_blob(&PackKey::from_hash(tip)).unwrap()).unwrap();
    assert_eq!(appended.packs, vec![*update.pack_hash()]);
    let raced = decode_packlist(
        &tx.download_blob(&PackKey::from_hash(appended.prev.unwrap()))
            .unwrap(),
    )
    .unwrap();
    assert!(raced.packs.is_empty());
    assert!(raced.prev.is_some());
}

#[test]
fn packmap_conflict_exhausts_exactly_three_retries() {
    let (dir, tx, bytes, update, context) = setup();
    let race = RacingPackmap {
        inner: &tx,
        root: dir.path(),
        race: PackmapRace::AlwaysConflict,
        attempts: AtomicUsize::new(0),
    };
    assert!(matches!(
        publish_explicit_update(&race, &bytes, &PartialLimits::V1, &context).unwrap(),
        PublicationOutcome::PackmapBusy
    ));
    assert_eq!(race.attempts.load(Ordering::SeqCst), 4);
    assert_eq!(
        tx.read_ref("refs/heads/main").unwrap(),
        Some(*update.base_id())
    );
}

#[test]
fn missing_packmap_after_conflict_refuses_without_head_change() {
    let (dir, tx, bytes, update, context) = setup();
    let race = RacingPackmap {
        inner: &tx,
        root: dir.path(),
        race: PackmapRace::Disappears,
        attempts: AtomicUsize::new(0),
    };
    assert!(matches!(
        publish_explicit_update(&race, &bytes, &PartialLimits::V1, &context).unwrap(),
        PublicationOutcome::UnsupportedRecipient
    ));
    assert_eq!(race.attempts.load(Ordering::SeqCst), 1);
    assert_eq!(
        tx.read_ref("refs/heads/main").unwrap(),
        Some(*update.base_id())
    );
}
