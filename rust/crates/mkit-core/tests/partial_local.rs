//! Integration coverage for durable scoped-workspace local state
//! (`ScopedWorkspaceLayout`, `.mkit-scoped/` generations, CURRENT).
#![allow(clippy::unwrap_used)] // unwrap is the assertion in integration tests
#![allow(clippy::too_many_lines)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use mkit_core::object::id_from_object;
use mkit_core::sign::sign_remix;
use mkit_core::store::ObjectSource;
use mkit_core::{
    EntryMode, FileReplacement, Hash, Identity, Object, ObjectStore, PartialError, PartialLimits,
    PartialPath, PartialStateError, PendingOperationV1, PendingOutcomeV1, PendingStateV1,
    PendingStatusV1, Remix, RepoLayout, ScopedWorkspaceLayout, ScopedWorkspaceState, StoreResult,
    Tree, TreeEntry, WorkspaceStateV1, build_partial_snapshot, export_partial_update,
    prepare_partial_commit, replace_files, serialize, sign_commit,
};

const LIMITS: PartialLimits = PartialLimits::V1;

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

struct Fixture {
    base_id: Hash,
    paths: Vec<PartialPath>,
    bundle_bytes: Vec<u8>,
}

/// Build a base remix with selected and hidden files, then produce the
/// exact verified bundle bytes the workspace will be created from.
fn fixture(extra_paths: &[&[&str]]) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
    let old_file = mkit_core::store_file_object(&store, b"old").unwrap();
    let exec = mkit_core::store_file_object(&store, b"#!/bin/sh\n").unwrap();
    let empty = mkit_core::store_file_object(&store, b"").unwrap();
    let shared_tree = tree(
        &store,
        vec![TreeEntry {
            name: b"x.txt".to_vec(),
            mode: EntryMode::Blob,
            object_hash: old_file,
        }],
    );
    let hidden_blob = mkit_core::store_file_object(&store, b"hidden").unwrap();
    let root_entries: Vec<TreeEntry> = vec![
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
            mode: EntryMode::Blob,
            object_hash: empty,
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
    ];
    let mut root_entries = root_entries;
    for extra in extra_paths {
        assert_eq!(extra.len(), 1, "fixture extras are root files");
        let blob = mkit_core::store_file_object(&store, b"extra").unwrap();
        root_entries.push(TreeEntry {
            name: extra[0].as_bytes().to_vec(),
            mode: EntryMode::Blob,
            object_hash: blob,
        });
    }
    let root = tree(&store, root_entries);
    let base_key = mkit_core::KeyPair::from_seed([7; 32]);
    let mut remix = Remix {
        tree_hash: root,
        parents: Vec::new(),
        sources: Vec::new(),
        author: Identity::opaque(b"base author".to_vec()),
        signer: base_key.public.0,
        message: b"base".to_vec(),
        timestamp: 1_700_000_000,
        signature: [0; 64],
    };
    remix.signature = sign_remix(&remix, &base_key).unwrap().0;
    let base_id = put(&store, &Object::Remix(remix));
    let mut paths: Vec<PartialPath> = vec![
        vec![b"a".to_vec(), b"x.txt".to_vec()],
        vec![b"b".to_vec(), b"x.txt".to_vec()],
        vec![b"empty".to_vec()],
        vec![b"exec".to_vec()],
    ];
    for extra in extra_paths {
        paths.push(extra.iter().map(|c| c.as_bytes().to_vec()).collect());
    }
    paths.sort();
    let bundle = build_partial_snapshot(&store, base_id, &paths, &LIMITS).unwrap();
    Fixture {
        base_id,
        paths,
        bundle_bytes: bundle.encode(&LIMITS).unwrap(),
    }
}

fn create_workspace(
    fixture: &Fixture,
    destination: &Path,
) -> Result<ScopedWorkspaceLayout, PartialStateError> {
    ScopedWorkspaceLayout::create(
        destination,
        fixture.base_id,
        &fixture.paths,
        &fixture.bundle_bytes,
        LIMITS,
        None,
    )
}

fn workspace() -> (tempfile::TempDir, ScopedWorkspaceLayout) {
    let fixture = fixture(&[]);
    let dir = tempfile::tempdir().unwrap();
    let layout = create_workspace(&fixture, &dir.path().join("ws")).unwrap();
    (dir, layout)
}

fn snap(layout: &ScopedWorkspaceLayout) -> ScopedWorkspaceState {
    layout.read_state().unwrap()
}

fn generation(state: &ScopedWorkspaceState) -> u64 {
    state.workspace().transaction_generation()
}

fn stage_a(layout: &ScopedWorkspaceLayout, bytes: &[u8]) -> ScopedWorkspaceState {
    let tx = generation(&snap(layout));
    layout
        .replace_stage(
            tx,
            &[FileReplacement::bytes(
                vec![b"a".to_vec(), b"x.txt".to_vec()],
                bytes.to_vec(),
            )],
        )
        .unwrap()
}

/// Object source over a state's verified base objects plus its persisted
/// stage objects — the same union the loader verifies.
struct StateSource<'a> {
    state: &'a ScopedWorkspaceState,
}

impl ObjectSource for StateSource<'_> {
    fn read(&self, id: &Hash) -> StoreResult<Vec<u8>> {
        if let Some(bytes) = self.state.verified().object_bytes(id) {
            return Ok(bytes.to_vec());
        }
        self.state
            .local_object(id)
            .map(<[u8]>::to_vec)
            .ok_or_else(|| mkit_core::StoreError::ObjectNotFound(mkit_core::to_hex(id)))
    }
}

fn read_staged(state: &ScopedWorkspaceState, id: &Hash) -> Vec<u8> {
    mkit_core::read_blob(&StateSource { state }, id).unwrap()
}

fn pending(layout: &ScopedWorkspaceLayout, state: &ScopedWorkspaceState) -> ScopedWorkspaceState {
    let fixture_signer = mkit_core::KeyPair::from_seed([9; 32]);
    let limits = LIMITS;
    let verified = state.verified();
    // Rebuild the same staged edit as byte replacements.
    let mut feed = Vec::new();
    let base: std::collections::BTreeMap<&PartialPath, &Hash> = state
        .workspace()
        .selection()
        .iter()
        .map(|entry| (entry.path(), entry.base_file_id()))
        .collect();
    for entry in state.stage().entries() {
        if entry.staged_id() != base[entry.path()] {
            let bytes = read_staged(state, entry.staged_id());
            feed.push(FileReplacement::bytes(entry.path().clone(), bytes));
        }
    }
    let prepared = replace_files(verified, &feed, &limits).unwrap();
    let unsigned = prepare_partial_commit(
        verified,
        &prepared,
        Identity::opaque(b"op author".to_vec()),
        fixture_signer.public.0,
        b"pending op".to_vec(),
        1_700_000_100,
        &limits,
    )
    .unwrap();
    let mut signed = unsigned.clone();
    signed.signature = sign_commit(&signed, &fixture_signer).unwrap().0;
    let update = export_partial_update(verified, &prepared, &unsigned, &signed, &limits).unwrap();
    let bytes = update.encode(&limits).unwrap();
    layout
        .save_pending(
            generation(state),
            &unsigned,
            &signed,
            &bytes,
            Some(PendingOperationV1 {
                operation_id: [1; 32],
                request_fingerprint: [2; 32],
            }),
        )
        .unwrap()
}

fn current_generation_dir(root: &Path) -> PathBuf {
    // CURRENT is [magic:4][version:1][generation u64][manifest digest:32][checksum:32].
    let current = std::fs::read(root.join(".mkit-scoped/CURRENT")).unwrap();
    let digest = Hash::try_from(&current[13..45]).unwrap();
    root.join(".mkit-scoped/generations")
        .join(mkit_core::to_hex(&digest))
}

// -- 1. offline create / open -------------------------------------------------

#[test]
fn create_and_open_roundtrip_offline() {
    let (_dir, layout) = workspace();
    let state = snap(&layout);
    assert_eq!(generation(&state), 0);
    assert_eq!(state.workspace().base_revision(), 0);
    assert!(state.pending().is_none());
    assert!(state.accepted().is_none());
    assert!(state.stage_is_clean());
    // Marker + state tree on disk.
    let root = layout.root().to_path_buf();
    assert_eq!(
        std::fs::read(root.join(".mkit")).unwrap(),
        b"mkit-scoped: 1\n"
    );
    assert!(root.join(".mkit-scoped/CURRENT").is_file());
    assert!(root.join(".mkit-scoped/workspace.lock").is_file());
    assert!(root.join(".mkit-scoped/generations").is_dir());
    assert!(!root.join(".mkit-scoped/objects").join("x").exists());
    // Re-open from a cold path reads the same generation.
    let reopened = ScopedWorkspaceLayout::open(&root).unwrap();
    let again = snap(&reopened);
    assert_eq!(generation(&again), 0);
    assert_eq!(
        again.workspace().workspace_id(),
        state.workspace().workspace_id()
    );
}

#[test]
fn create_materializes_exact_bytes_modes_and_empty_files() {
    let (_dir, layout) = workspace();
    let root = layout.root().to_path_buf();
    assert_eq!(std::fs::read(root.join("a/x.txt")).unwrap(), b"old");
    assert_eq!(std::fs::read(root.join("b/x.txt")).unwrap(), b"old");
    assert_eq!(std::fs::read(root.join("empty")).unwrap(), b"");
    assert_eq!(
        std::fs::metadata(root.join("exec"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
    assert_eq!(
        std::fs::metadata(root.join("a/x.txt"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o644
    );
    // The shared a/ and b/ ancestors both exist as real directories.
    assert!(root.join("a").is_dir());
    assert!(root.join("b").is_dir());
    // No hidden or unselected file was materialized.
    assert!(!root.join("hidden.txt").exists());
}

// -- 2. pinned-base mismatch --------------------------------------------------

#[test]
fn create_rejects_pinned_mismatch_and_leaves_no_destination() {
    let fixture = fixture(&[]);
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("ws");
    assert!(matches!(
        ScopedWorkspaceLayout::create(
            &dest,
            [0xAB; 32],
            &fixture.paths,
            &fixture.bundle_bytes,
            LIMITS,
            None,
        ),
        Err(PartialStateError::Partial(PartialError::BaseMismatch))
    ));
    assert!(!dest.exists());
    let mut wrong_paths = fixture.paths.clone();
    wrong_paths.pop();
    assert!(matches!(
        ScopedWorkspaceLayout::create(
            &dest,
            fixture.base_id,
            &wrong_paths,
            &fixture.bundle_bytes,
            LIMITS,
            None,
        ),
        Err(PartialStateError::Partial(PartialError::SelectionMismatch))
    ));
    assert!(!dest.exists());
}

#[test]
fn create_rejects_nested_and_existing_destinations() {
    let fixture = fixture(&[]);
    let dir = tempfile::tempdir().unwrap();
    // Inside an ordinary repository root.
    let repo_dir = dir.path().join("repo");
    std::fs::create_dir(&repo_dir).unwrap();
    ObjectStore::init(&RepoLayout::single(&repo_dir)).unwrap();
    assert!(matches!(
        create_workspace(&fixture, &repo_dir.join("ws")),
        Err(PartialStateError::NestedLayout(_))
    ));
    // Inside a scoped workspace root.
    let (_parent, layout) = workspace();
    assert!(matches!(
        create_workspace(&fixture, &layout.root().join("ws")),
        Err(PartialStateError::NestedLayout(_))
    ));
    // Existing destination.
    let existing = dir.path().join("taken");
    std::fs::create_dir(&existing).unwrap();
    assert!(matches!(
        create_workspace(&fixture, &existing),
        Err(PartialStateError::DestinationExists(_))
    ));
}

// -- 3/4. staging and restart -------------------------------------------------

#[test]
fn stage_persists_across_restart_and_workfile_is_ignored() {
    let (_dir, layout) = workspace();
    let staged = stage_a(&layout, b"work A");
    assert_eq!(generation(&staged), 1);
    assert!(!staged.stage_is_clean());
    assert!(!staged.stage().required_object_ids().is_empty());
    // Diverge the working file — state must stay authoritative.
    std::fs::write(layout.root().join("a/x.txt"), b"work B").unwrap();
    let reopened = ScopedWorkspaceLayout::open(layout.root()).unwrap();
    let reread = snap(&reopened);
    assert_eq!(generation(&reread), 1);
    let a_entry = reread
        .stage()
        .entries()
        .iter()
        .find(|e| e.path() == &vec![b"a".to_vec(), b"x.txt".to_vec()])
        .unwrap();
    let base_entry = reread
        .workspace()
        .selection()
        .iter()
        .find(|e| e.path() == a_entry.path())
        .unwrap();
    assert_ne!(a_entry.staged_id(), base_entry.base_file_id());
    // The working file still says B — the workspace never rewrote it.
    assert_eq!(
        std::fs::read(layout.root().join("a/x.txt")).unwrap(),
        b"work B"
    );
}

#[test]
fn partial_stage_and_clean_restore() {
    let (_dir, layout) = workspace();
    stage_a(&layout, b"A1");
    let tx = generation(&snap(&layout));
    // Stage b too — unrelated staged entry preserved.
    let two = layout
        .replace_stage(
            tx,
            &[FileReplacement::bytes(
                vec![b"b".to_vec(), b"x.txt".to_vec()],
                b"B1".to_vec(),
            )],
        )
        .unwrap();
    let after_two = snap(&layout);
    assert_eq!(
        two.stage()
            .entries()
            .iter()
            .filter(|e| {
                let base = after_two
                    .workspace()
                    .selection()
                    .iter()
                    .find(|s| s.path() == e.path())
                    .unwrap();
                e.staged_id() != base.base_file_id()
            })
            .count(),
        2
    );
    // Restore both to base bytes → clean stage.
    let tx = generation(&snap(&layout));
    let restored = layout
        .replace_stage(
            tx,
            &[
                FileReplacement::bytes(vec![b"a".to_vec(), b"x.txt".to_vec()], b"old".to_vec()),
                FileReplacement::bytes(vec![b"b".to_vec(), b"x.txt".to_vec()], b"old".to_vec()),
            ],
        )
        .unwrap();
    assert!(restored.stage_is_clean());
    assert!(restored.stage().required_object_ids().is_empty());
}

#[test]
fn reuse_selected_uses_the_base_representation() {
    // Stage S to staged bytes X, then reuse_selected(D, S): D must get
    // S's verified BASE representation — never the staged bytes X.
    let (_dir, layout) = workspace();
    let staged = stage_a(&layout, b"staged X");
    let tx = generation(&staged);
    let a_path = vec![b"a".to_vec(), b"x.txt".to_vec()];
    let b_path = vec![b"b".to_vec(), b"x.txt".to_vec()];
    let state = layout
        .replace_stage(
            tx,
            &[FileReplacement::reuse_selected(
                b_path.clone(),
                a_path.clone(),
            )],
        )
        .unwrap();
    let staged_id = |state: &ScopedWorkspaceState, path: &PartialPath| {
        *state
            .stage()
            .entries()
            .iter()
            .find(|e| e.path() == path)
            .unwrap()
            .staged_id()
    };
    let base_id = |state: &ScopedWorkspaceState, path: &PartialPath| {
        *state
            .workspace()
            .selection()
            .iter()
            .find(|e| e.path() == path)
            .unwrap()
            .base_file_id()
    };
    // D carries S's base object (the fixture gives a/b the same base),
    // which equals D's own base — D is clean, not staged to X.
    assert_eq!(staged_id(&state, &b_path), base_id(&state, &b_path));
    assert_eq!(read_staged(&state, &staged_id(&state, &b_path)), b"old");
    // The unrelated staged entry at S is preserved.
    assert_ne!(staged_id(&state, &a_path), base_id(&state, &a_path));
    assert_eq!(
        read_staged(&state, &staged_id(&state, &a_path)),
        b"staged X"
    );
}

/// A base whose selected source `s.txt` carries a valid alternate
/// `ChunkedBlob` representation of short content — the representation
/// identity a staged reuse must retain. `d.txt` differs from `s.txt`;
/// `u.txt` is unrelated; `hidden.txt` is never selected.
fn chunked_fixture() -> (Fixture, Hash) {
    let dir = tempfile::tempdir().unwrap();
    let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
    let c1 = put(
        &store,
        &Object::Blob(mkit_core::object::Blob {
            data: b"shared-".to_vec(),
        }),
    );
    let c2 = put(
        &store,
        &Object::Blob(mkit_core::object::Blob {
            data: b"content".to_vec(),
        }),
    );
    let manifest = Object::ChunkedBlob(mkit_core::object::ChunkedBlob {
        total_size: 14,
        chunk_size: 0,
        chunks: vec![c1, c2],
    });
    let manifest_id = put(&store, &manifest);
    let dest = mkit_core::store_file_object(&store, b"dest-content").unwrap();
    let other = mkit_core::store_file_object(&store, b"unrelated").unwrap();
    let hidden = mkit_core::store_file_object(&store, b"hidden").unwrap();
    let root = tree(
        &store,
        vec![
            TreeEntry {
                name: b"d.txt".to_vec(),
                mode: EntryMode::Blob,
                object_hash: dest,
            },
            TreeEntry {
                name: b"hidden.txt".to_vec(),
                mode: EntryMode::Blob,
                object_hash: hidden,
            },
            TreeEntry {
                name: b"s.txt".to_vec(),
                mode: EntryMode::Blob,
                object_hash: manifest_id,
            },
            TreeEntry {
                name: b"u.txt".to_vec(),
                mode: EntryMode::Blob,
                object_hash: other,
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
        message: b"base".to_vec(),
        timestamp: 1_700_000_000,
        signature: [0; 64],
    };
    remix.signature = sign_remix(&remix, &base_key).unwrap().0;
    let base_id = put(&store, &Object::Remix(remix));
    let mut paths: Vec<PartialPath> = vec![
        vec![b"d.txt".to_vec()],
        vec![b"s.txt".to_vec()],
        vec![b"u.txt".to_vec()],
    ];
    paths.sort();
    let bundle = build_partial_snapshot(&store, base_id, &paths, &LIMITS).unwrap();
    (
        Fixture {
            base_id,
            paths,
            bundle_bytes: bundle.encode(&LIMITS).unwrap(),
        },
        manifest_id,
    )
}

/// The representation-preserving counterpart of `pending`: each staged
/// entry that differs from base replays through `reuse_selected` when
/// its persisted id names a verified SELECTED representation — exactly
/// what the authoritative stage recorded — instead of re-canonicalizing
/// it to bytes.
fn pending_preserving(
    layout: &ScopedWorkspaceLayout,
    state: &ScopedWorkspaceState,
) -> ScopedWorkspaceState {
    let fixture_signer = mkit_core::KeyPair::from_seed([9; 32]);
    let limits = LIMITS;
    let verified = state.verified();
    let base: std::collections::BTreeMap<&PartialPath, &Hash> = state
        .workspace()
        .selection()
        .iter()
        .map(|entry| (entry.path(), entry.base_file_id()))
        .collect();
    let mut feed = Vec::new();
    for entry in state.stage().entries() {
        if entry.staged_id() == base[entry.path()] {
            continue;
        }
        if let Some(source) = verified
            .files()
            .iter()
            .find(|file| file.object_id() == entry.staged_id())
        {
            feed.push(FileReplacement::reuse_selected(
                entry.path().clone(),
                source.path().clone(),
            ));
        } else {
            let bytes = read_staged(state, entry.staged_id());
            feed.push(FileReplacement::bytes(entry.path().clone(), bytes));
        }
    }
    let prepared = replace_files(verified, &feed, &limits).unwrap();
    let unsigned = prepare_partial_commit(
        verified,
        &prepared,
        Identity::opaque(b"op author".to_vec()),
        fixture_signer.public.0,
        b"pending op".to_vec(),
        1_700_000_100,
        &limits,
    )
    .unwrap();
    let mut signed = unsigned.clone();
    signed.signature = sign_commit(&signed, &fixture_signer).unwrap().0;
    let update = export_partial_update(verified, &prepared, &unsigned, &signed, &limits).unwrap();
    let bytes = update.encode(&limits).unwrap();
    layout
        .save_pending(
            generation(state),
            &unsigned,
            &signed,
            &bytes,
            Some(PendingOperationV1 {
                operation_id: [1; 32],
                request_fingerprint: [2; 32],
            }),
        )
        .unwrap()
}

/// An alternate-layout selected representation reused onto another path
/// must keep its persisted id through unrelated staging, restart, and
/// the pending/accept cycle — never silently re-canonicalized.
#[test]
fn staged_alternate_reuse_survives_replay_and_pending() {
    let (fixture, manifest_id) = chunked_fixture();
    let dir = tempfile::tempdir().unwrap();
    let layout = create_workspace(&fixture, &dir.path().join("ws")).unwrap();
    let d_path: PartialPath = vec![b"d.txt".to_vec()];
    let s_path: PartialPath = vec![b"s.txt".to_vec()];
    let u_path: PartialPath = vec![b"u.txt".to_vec()];
    let staged_id = |state: &ScopedWorkspaceState, path: &PartialPath| {
        *state
            .stage()
            .entries()
            .iter()
            .find(|e| e.path() == path)
            .unwrap()
            .staged_id()
    };
    // Stage D := S's chunked representation.
    let state = layout
        .replace_stage(
            0,
            &[FileReplacement::reuse_selected(
                d_path.clone(),
                s_path.clone(),
            )],
        )
        .unwrap();
    assert_eq!(staged_id(&state, &d_path), manifest_id);
    // Unrelated staging must not rewrite D's persisted representation.
    let state = layout
        .replace_stage(
            generation(&state),
            &[FileReplacement::bytes(u_path.clone(), b"U2".to_vec())],
        )
        .unwrap();
    assert_eq!(
        staged_id(&state, &d_path),
        manifest_id,
        "unrelated staging must preserve the reused representation id"
    );
    // Restart: the persisted id survives a cold load.
    let reopened = ScopedWorkspaceLayout::open(layout.root()).unwrap();
    let state = reopened.read_state().unwrap();
    assert_eq!(staged_id(&state, &d_path), manifest_id);
    // The candidate built from the ORIGINAL reuse representation is the
    // one the authoritative stage describes: it pends and accepts.
    let state = pending_preserving(&reopened, &state);
    assert!(state.pending().is_some());
    let identity = state.pending().unwrap().identity();
    let state = reopened
        .record_outcome(generation(&state), &identity, PendingOutcomeV1::Accepted)
        .unwrap();
    // After acceptance D's base representation is S's manifest — the
    // reused id survives the whole cycle — while diverged working bytes
    // and the hidden entry are untouched.
    let d_base = state
        .workspace()
        .selection()
        .iter()
        .find(|entry| entry.path() == &d_path)
        .unwrap()
        .base_file_id();
    assert_eq!(d_base, &manifest_id);
    assert_eq!(read_staged(&state, &manifest_id), b"shared-content");
    // Accepted advancement never rewrites working files: the materialized
    // bytes are the pre-accept content, and the hidden entry was never
    // materialized at all.
    assert_eq!(
        std::fs::read(layout.root().join("d.txt")).unwrap(),
        b"dest-content"
    );
    assert!(!layout.root().join("hidden.txt").exists());
    // Semantic no-op: reusing D's own (now base) representation changes
    // nothing.
    let state = reopened
        .replace_stage(
            generation(&state),
            &[FileReplacement::reuse_selected(
                d_path.clone(),
                d_path.clone(),
            )],
        )
        .unwrap();
    assert!(state.stage_is_clean());
}

// -- 6. stale / concurrent generations ----------------------------------------

#[test]
fn stale_generation_is_rejected() {
    let (_dir, layout) = workspace();
    stage_a(&layout, b"A1");
    // generation 0 is now stale.
    assert!(matches!(
        layout.replace_stage(
            0,
            &[FileReplacement::bytes(
                vec![b"b".to_vec(), b"x.txt".to_vec()],
                b"B".to_vec()
            )]
        ),
        Err(PartialStateError::GenerationMismatch {
            expected: 0,
            actual: 1
        })
    ));
}

/// Two handles run sequentially: the second's view of generation 0 is
/// stale after the first commits. This proves generation rejection
/// across handles, NOT lock contention — real contention coverage is
/// `contention_*` below.
#[test]
fn stale_generation_rejected_across_handles() {
    let (_dir, layout) = workspace();
    let other = ScopedWorkspaceLayout::open(layout.root()).unwrap();
    let first = stage_a(&layout, b"from first");
    // The second handle's view of generation 0 is now stale.
    assert!(matches!(
        other.replace_stage(
            0,
            &[FileReplacement::bytes(
                vec![b"b".to_vec(), b"x.txt".to_vec()],
                b"from second".to_vec()
            )]
        ),
        Err(PartialStateError::GenerationMismatch {
            expected: 0,
            actual: 1
        })
    ));
    assert_eq!(generation(&first), 1);
}

/// Hold the kernel lock on an independently opened descriptor so both
/// contenders park at acquisition; release it after both are spawned.
/// The kernel decides which thread proceeds first — the serialized
/// loser must then observe the winner's generation, not publish a
/// second generation-1 state over the top.
fn flock_hold(path: &Path) -> std::fs::File {
    use std::os::unix::io::AsRawFd;
    let held = std::fs::File::options()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    // SAFETY: flock(2) on a valid fd we own for the test's duration.
    #[allow(unsafe_code)]
    let rc = unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX) };
    assert_eq!(rc, 0);
    held
}

fn flock_release(held: &std::fs::File) {
    use std::os::unix::io::AsRawFd;
    // SAFETY: releasing the test's own flock.
    #[allow(unsafe_code)]
    unsafe {
        libc::flock(held.as_raw_fd(), libc::LOCK_UN);
    }
}

/// A workspace over a wider selection: staging every file produces
/// dozens of artifacts and fsyncs, so a same-handle contender that
/// skips real serialization reliably overlaps inside the transition.
fn wide_workspace() -> (tempfile::TempDir, ScopedWorkspaceLayout) {
    const EXTRAS: &[&[&str]] = &[
        &["f00"],
        &["f01"],
        &["f02"],
        &["f03"],
        &["f04"],
        &["f05"],
        &["f06"],
        &["f07"],
        &["f08"],
        &["f09"],
        &["f10"],
        &["f11"],
        &["f12"],
        &["f13"],
        &["f14"],
        &["f15"],
        &["f16"],
        &["f17"],
        &["f18"],
        &["f19"],
        &["f20"],
        &["f21"],
        &["f22"],
        &["f23"],
    ];
    let fixture = fixture(EXTRAS);
    let dir = tempfile::tempdir().unwrap();
    let layout = create_workspace(&fixture, &dir.path().join("ws")).unwrap();
    (dir, layout)
}

/// The losing contender must observe the winner's generation; the
/// reopened state must contain exactly the winner's stage at
/// generation 1 — never two generation-1 states and never a torn mix.
fn assert_exactly_one_committed(
    results: &[Result<ScopedWorkspaceState, PartialStateError>; 2],
    edits: [&std::collections::BTreeMap<PartialPath, Vec<u8>>; 2],
    root: &Path,
) {
    let wins: Vec<usize> = results
        .iter()
        .enumerate()
        .filter_map(|(i, r)| r.is_ok().then_some(i))
        .collect();
    assert_eq!(
        wins.len(),
        1,
        "exactly one overlapping mutation may commit: {results:?}"
    );
    for result in results {
        if let Err(error) = result {
            assert!(
                matches!(
                    error,
                    PartialStateError::GenerationMismatch {
                        expected: 0,
                        actual: 1
                    }
                ),
                "the loser must observe the winner's generation, not a torn publish: {error:?}"
            );
        }
    }
    let reopened = ScopedWorkspaceLayout::open(root).unwrap();
    let state = snap(&reopened);
    assert_eq!(generation(&state), 1);
    let base: std::collections::BTreeMap<&PartialPath, &Hash> = state
        .workspace()
        .selection()
        .iter()
        .map(|entry| (entry.path(), entry.base_file_id()))
        .collect();
    let winner = edits[wins[0]];
    let mut staged = 0;
    for entry in state.stage().entries() {
        match winner.get(entry.path()) {
            Some(bytes) => {
                staged += 1;
                assert_eq!(read_staged(&state, entry.staged_id()), *bytes);
            }
            None => assert_eq!(entry.staged_id(), base[entry.path()]),
        }
    }
    assert_eq!(staged, winner.len());
}

/// Drive the overlapping two-generation-0 pattern: the fast contender is
/// spawned only once the slow contender is provably inside its
/// transition (a staged-object artifact exists), so a lock that lets the
/// second flock no-op through produces two committed generation-1
/// states rather than a serialized `GenerationMismatch`.
fn contention_pair(
    first: &std::sync::Arc<ScopedWorkspaceLayout>,
    second: &std::sync::Arc<ScopedWorkspaceLayout>,
    root: &Path,
) {
    let every_path: Vec<PartialPath> = snap(first)
        .workspace()
        .selection()
        .iter()
        .map(|entry| entry.path().clone())
        .collect();
    let held = flock_hold(&root.join(".mkit-scoped/workspace.lock"));
    let slow_edit: Vec<FileReplacement> = every_path
        .iter()
        .map(|path| FileReplacement::bytes(path.clone(), vec![b'W'; 4096]))
        .collect();
    let fast_edit = [FileReplacement::bytes(
        vec![b"a".to_vec(), b"x.txt".to_vec()],
        b"from fast".to_vec(),
    )];
    let slow_expect: std::collections::BTreeMap<PartialPath, Vec<u8>> = every_path
        .iter()
        .map(|path| (path.clone(), vec![b'W'; 4096]))
        .collect();
    let fast_expect: std::collections::BTreeMap<PartialPath, Vec<u8>> = [(
        PartialPath::from(vec![b"a".to_vec(), b"x.txt".to_vec()]),
        b"from fast".to_vec(),
    )]
    .into_iter()
    .collect();
    let ta = {
        let first = first.clone();
        std::thread::spawn(move || first.replace_stage(0, &slow_edit))
    };
    // Let the slow contender park at the kernel lock, then release it.
    std::thread::sleep(std::time::Duration::from_millis(200));
    flock_release(&held);
    drop(held);
    // Wait until the winner is provably inside: the first staged-object
    // artifact only appears mid-commit, well before CURRENT is replaced.
    let objects_dir = root.join(".mkit-scoped/objects");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while std::time::Instant::now() < deadline {
        if objects_dir.read_dir().is_ok_and(|mut d| d.next().is_some()) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    let tb = {
        let second = second.clone();
        std::thread::spawn(move || second.replace_stage(0, &fast_edit))
    };
    assert_exactly_one_committed(
        &[ta.join().unwrap(), tb.join().unwrap()],
        [&slow_expect, &fast_expect],
        root,
    );
}

/// Two threads share ONE `Arc<ScopedWorkspaceLayout>` and both attempt
/// generation 0. flock ownership belongs to the open-file description:
/// a second flock arriving while the shared descriptor already holds the
/// lock is a no-op, so both threads would enter the critical section and
/// publish two different generation-1 states. Per-operation descriptors
/// must serialize them.
#[test]
fn contention_same_handle_serializes() {
    let (_dir, layout) = wide_workspace();
    let root = layout.root().to_path_buf();
    // One Arc, cloned for the second thread — the same stored handle.
    let shared = std::sync::Arc::new(layout);
    contention_pair(&shared, &shared, &root);
}

/// The same overlapping pattern across two separately opened handles:
/// independent open-file descriptions must still serialize the
/// transitions, so this held green even before same-handle handling.
#[test]
fn contention_separate_handles_serializes() {
    let (_dir, layout) = wide_workspace();
    let root = layout.root().to_path_buf();
    let other = ScopedWorkspaceLayout::open(&root).unwrap();
    contention_pair(
        &std::sync::Arc::new(layout),
        &std::sync::Arc::new(other),
        &root,
    );
}

#[test]
fn lock_file_inode_is_stable_across_transitions() {
    use std::os::unix::fs::MetadataExt;
    let (_dir, layout) = workspace();
    let lock_path = layout.root().join(".mkit-scoped/workspace.lock");
    let before = std::fs::metadata(&lock_path).unwrap().ino();
    stage_a(&layout, b"A1");
    stage_a(&layout, b"A2");
    let after = std::fs::metadata(&lock_path).unwrap().ino();
    assert_eq!(before, after);
}

// -- 9/10. corruption and no-fallback -----------------------------------------

fn corrupt(path: &Path, offset: usize) {
    let mut bytes = std::fs::read(path).unwrap();
    bytes[offset] ^= 0xFF;
    std::fs::write(path, bytes).unwrap();
}

#[test]
fn missing_or_corrupt_current_fails_closed() {
    let (_dir, layout) = workspace();
    let current = layout.root().join(".mkit-scoped/CURRENT");
    let saved = std::fs::read(&current).unwrap();
    std::fs::remove_file(&current).unwrap();
    assert!(matches!(
        ScopedWorkspaceLayout::open(layout.root()),
        Err(PartialStateError::IncompleteInstall(_))
    ));
    std::fs::write(&current, &saved).unwrap();
    corrupt(&current, 6);
    assert!(ScopedWorkspaceLayout::open(layout.root()).is_err());
}

#[test]
fn corrupt_manifest_member_bundle_object_update_all_fail_closed() {
    let (_dir, layout) = workspace();
    let staged = stage_a(&layout, b"A1");
    let pending_state = pending(&layout, &staged);
    let gen_dir = current_generation_dir(layout.root());

    // Manifest corruption → CURRENT digest mismatch.
    let manifest_path = gen_dir.join("manifest.bin");
    let saved_manifest = std::fs::read(&manifest_path).unwrap();
    corrupt(&manifest_path, 6);
    assert!(matches!(
        ScopedWorkspaceLayout::open(layout.root()),
        Err(PartialStateError::CorruptArtifact { .. })
    ));
    std::fs::write(&manifest_path, &saved_manifest).unwrap();

    // Member corruption → manifest digest mismatch.
    corrupt(&gen_dir.join("workspace.bin"), 40);
    assert!(ScopedWorkspaceLayout::open(layout.root()).is_err());
    let good = std::fs::read(gen_dir.join("workspace.bin")).unwrap();
    let mut restored = good.clone();
    restored[40] ^= 0xFF;
    std::fs::write(gen_dir.join("workspace.bin"), restored).unwrap();

    // Missing stage member.
    let stage_path = gen_dir.join("stage.bin");
    let saved = std::fs::read(&stage_path).unwrap();
    std::fs::remove_file(&stage_path).unwrap();
    assert!(matches!(
        ScopedWorkspaceLayout::open(layout.root()),
        Err(PartialStateError::MissingArtifact { .. })
    ));
    std::fs::write(&stage_path, saved).unwrap();

    // Missing bundle artifact.
    let bundle_digest = mkit_core::to_hex(pending_state.workspace().base_bundle_digest());
    let bundle_path = layout
        .root()
        .join(format!(".mkit-scoped/bundles/{bundle_digest}.mkwb"));
    let saved = std::fs::read(&bundle_path).unwrap();
    std::fs::remove_file(&bundle_path).unwrap();
    assert!(matches!(
        ScopedWorkspaceLayout::open(layout.root()),
        Err(PartialStateError::MissingArtifact { .. })
    ));
    std::fs::write(&bundle_path, &saved).unwrap();
    corrupt(&bundle_path, 6);
    assert!(ScopedWorkspaceLayout::open(layout.root()).is_err());
    std::fs::write(&bundle_path, &saved).unwrap();

    // Missing required stage object.
    let object_id = staged.stage().required_object_ids()[0];
    let object_path = layout.root().join(format!(
        ".mkit-scoped/objects/{}",
        mkit_core::to_hex(&object_id)
    ));
    let saved = std::fs::read(&object_path).unwrap();
    std::fs::remove_file(&object_path).unwrap();
    assert!(matches!(
        ScopedWorkspaceLayout::open(layout.root()),
        Err(PartialStateError::MissingArtifact { .. })
    ));
    std::fs::write(&object_path, saved).unwrap();

    // Missing / corrupt pending update.
    let update_name = pending_state.pending().unwrap().update_file_name();
    let update_path = layout
        .root()
        .join(format!(".mkit-scoped/updates/{update_name}"));
    let saved = std::fs::read(&update_path).unwrap();
    std::fs::remove_file(&update_path).unwrap();
    assert!(matches!(
        ScopedWorkspaceLayout::open(layout.root()),
        Err(PartialStateError::MissingArtifact { .. })
    ));
    std::fs::write(&update_path, &saved[..saved.len() - 1]).unwrap();
    assert!(ScopedWorkspaceLayout::open(layout.root()).is_err());
    std::fs::write(&update_path, &saved).unwrap();
    assert!(ScopedWorkspaceLayout::open(layout.root()).is_ok());
}

#[test]
fn no_highest_generation_or_worktree_fallback() {
    let (_dir, layout) = workspace();
    stage_a(&layout, b"A1");
    // Repoint CURRENT at a nonexistent manifest: readers must fail, not
    // scan generations for the highest surviving one.
    let current_path = layout.root().join(".mkit-scoped/CURRENT");
    let mut bogus = std::fs::read(&current_path).unwrap();
    // MKCR payload: [u64 generation][32-byte manifest digest]; flip a
    // digest byte then fix the checksum.
    bogus[5 + 8] ^= 0x01;
    let checksum = mkit_core::hash::hash(&bogus[..bogus.len() - 32]);
    bogus.truncate(bogus.len() - 32);
    bogus.extend_from_slice(&checksum);
    std::fs::write(&current_path, bogus).unwrap();
    assert!(matches!(
        ScopedWorkspaceLayout::open(layout.root()),
        Err(PartialStateError::MissingArtifact { .. })
    ));
    // Working files remain irrelevant to state reads.
    std::fs::write(layout.root().join("a/x.txt"), b"totally different").unwrap();
    assert!(ScopedWorkspaceLayout::open(layout.root()).is_err());
}

// -- 11/12. filesystem safety ---------------------------------------------------

#[test]
fn symlinked_metadata_is_refused() {
    let (_dir, layout) = workspace();
    let root = layout.root().to_path_buf();
    // Marker symlink.
    let marker = root.join(".mkit");
    let saved = std::fs::read(&marker).unwrap();
    std::fs::remove_file(&marker).unwrap();
    std::os::unix::fs::symlink("/dev/null", &marker).unwrap();
    assert!(matches!(
        ScopedWorkspaceLayout::open(&root),
        Err(PartialStateError::UnsafeFilesystemEntry { .. }
            | PartialStateError::NotScopedWorkspace(_),)
    ));
    std::fs::remove_file(&marker).unwrap();
    std::fs::write(&marker, &saved).unwrap();
    // workspace.lock symlink.
    let lock = root.join(".mkit-scoped/workspace.lock");
    let saved_lock = std::fs::read(&lock).unwrap();
    std::fs::remove_file(&lock).unwrap();
    std::os::unix::fs::symlink("/dev/null", &lock).unwrap();
    assert!(matches!(
        ScopedWorkspaceLayout::open(&root),
        Err(PartialStateError::UnsafeFilesystemEntry { .. }
            | PartialStateError::IncompleteInstall(_),)
    ));
    std::fs::remove_file(&lock).unwrap();
    std::fs::write(&lock, &saved_lock).unwrap();
    // CURRENT leaf symlink.
    let current = root.join(".mkit-scoped/CURRENT");
    let saved_current = std::fs::read(&current).unwrap();
    std::fs::remove_file(&current).unwrap();
    std::os::unix::fs::symlink("/dev/null", &current).unwrap();
    assert!(matches!(
        ScopedWorkspaceLayout::open(&root),
        Err(PartialStateError::UnsafeFilesystemEntry { .. }
            | PartialStateError::IncompleteInstall(_),)
    ));
    std::fs::remove_file(&current).unwrap();
    std::fs::write(&current, &saved_current).unwrap();
    // Authoritative ancestor symlink: `.mkit-scoped/generations`.
    let gens = root.join(".mkit-scoped/generations");
    let gens_real = root.join(".mkit-scoped/generations.real");
    std::fs::rename(&gens, &gens_real).unwrap();
    std::os::unix::fs::symlink("generations.real", &gens).unwrap();
    let err = ScopedWorkspaceLayout::open(&root).unwrap_err();
    assert!(
        matches!(err, PartialStateError::UnsafeFilesystemEntry { .. }),
        "generations symlink: {err}"
    );
    std::fs::remove_file(&gens).unwrap();
    std::fs::rename(&gens_real, &gens).unwrap();
    // Authoritative ancestor symlink: the CURRENT-selected generation dir.
    let gen_dir = current_generation_dir(&root);
    let moved_gen = gen_dir.with_file_name("real-gen");
    std::fs::rename(&gen_dir, &moved_gen).unwrap();
    std::os::unix::fs::symlink("real-gen", &gen_dir).unwrap();
    assert!(matches!(
        ScopedWorkspaceLayout::open(&root),
        Err(PartialStateError::UnsafeFilesystemEntry { .. })
    ));
    std::fs::remove_file(&gen_dir).unwrap();
    std::fs::rename(&moved_gen, &gen_dir).unwrap();
    // Member leaf symlink: workspace.bin inside the generation.
    let ws_bin = gen_dir.join("workspace.bin");
    let saved_ws = std::fs::read(&ws_bin).unwrap();
    std::fs::remove_file(&ws_bin).unwrap();
    std::os::unix::fs::symlink("/dev/null", &ws_bin).unwrap();
    assert!(matches!(
        ScopedWorkspaceLayout::open(&root),
        Err(PartialStateError::UnsafeFilesystemEntry { .. })
    ));
    std::fs::remove_file(&ws_bin).unwrap();
    std::fs::write(&ws_bin, &saved_ws).unwrap();
    assert!(ScopedWorkspaceLayout::open(&root).is_ok());
}

#[test]
fn symlinked_workspace_root_is_refused() {
    let (_dir, layout) = workspace();
    let link = layout.root().with_file_name("ws-link");
    std::os::unix::fs::symlink(layout.root(), &link).unwrap();
    assert!(matches!(
        ScopedWorkspaceLayout::open(&link),
        Err(PartialStateError::UnsafeFilesystemEntry { .. })
    ));
    // The real root still opens.
    assert!(ScopedWorkspaceLayout::open(layout.root()).is_ok());
}

#[test]
fn hardlinked_marker_or_members_are_refused() {
    let (_dir, layout) = workspace();
    let root = layout.root().to_path_buf();
    let marker = root.join(".mkit");
    let twin = root.join("marker-twin");
    std::fs::hard_link(&marker, &twin).unwrap();
    assert!(matches!(
        ScopedWorkspaceLayout::open(&root),
        Err(PartialStateError::UnsafeFilesystemEntry { .. })
    ));
    std::fs::remove_file(&twin).unwrap();
    assert!(ScopedWorkspaceLayout::open(&root).is_ok());
    // A CURRENT-selected generation member must likewise be one-link.
    let gen_dir = current_generation_dir(&root);
    let ws_bin = gen_dir.join("workspace.bin");
    let ws_twin = gen_dir.join("workspace-twin.bin");
    std::fs::hard_link(&ws_bin, &ws_twin).unwrap();
    assert!(matches!(
        ScopedWorkspaceLayout::open(&root),
        Err(PartialStateError::UnsafeFilesystemEntry { .. })
    ));
    std::fs::remove_file(&ws_twin).unwrap();
    assert!(ScopedWorkspaceLayout::open(&root).is_ok());
}

#[test]
fn malformed_marker_bytes_are_distinguished() {
    let (_dir, layout) = workspace();
    let marker = layout.root().join(".mkit");
    std::fs::write(&marker, b"mkit-scoped: 2\n").unwrap();
    assert!(matches!(
        ScopedWorkspaceLayout::open(layout.root()),
        Err(PartialStateError::MarkerCorrupt(_))
    ));
    std::fs::write(&marker, b"hello\n").unwrap();
    assert!(matches!(
        ScopedWorkspaceLayout::open(layout.root()),
        Err(PartialStateError::NotScopedWorkspace(_))
    ));
}

#[test]
fn reserved_and_aliased_paths_are_rejected() {
    // `.mkit-scoped` as a first component is a reserved name in the
    // selection profile.
    let fixture = fixture(&[]);
    let dir = tempfile::tempdir().unwrap();
    let bad_paths: Vec<PartialPath> = vec![vec![b".mkit-scoped".to_vec(), b"x".to_vec()]];
    assert!(
        ScopedWorkspaceLayout::create(
            &dir.path().join("ws"),
            fixture.base_id,
            &bad_paths,
            &fixture.bundle_bytes,
            LIMITS,
            None,
        )
        .is_err()
    );
}

#[test]
fn case_alias_prefix_collision_is_caught_on_folding_filesystems() {
    // Truthful detection first: only run the alias assertion when the
    // filesystem actually folds case.
    let probe = tempfile::tempdir().unwrap();
    let upper = probe.path().join("ProbeA");
    std::fs::create_dir(&upper).unwrap();
    if std::fs::metadata(probe.path().join("probea")).is_err() {
        eprintln!("case-sensitive filesystem: alias-collision check skipped");
        return;
    }
    // A selection containing A/x and a/y collides on a folding fs.
    let dir = tempfile::tempdir().unwrap();
    let store = ObjectStore::init(&RepoLayout::single(dir.path().join("repo"))).unwrap();
    let f1 = mkit_core::store_file_object(&store, b"1").unwrap();
    let f2 = mkit_core::store_file_object(&store, b"2").unwrap();
    let a_dir = tree(
        &store,
        vec![TreeEntry {
            name: b"x".to_vec(),
            mode: EntryMode::Blob,
            object_hash: f1,
        }],
    );
    let b_dir = tree(
        &store,
        vec![TreeEntry {
            name: b"y".to_vec(),
            mode: EntryMode::Blob,
            object_hash: f2,
        }],
    );
    let root = tree(
        &store,
        vec![
            TreeEntry {
                name: b"Case".to_vec(),
                mode: EntryMode::Tree,
                object_hash: a_dir,
            },
            TreeEntry {
                name: b"case".to_vec(),
                mode: EntryMode::Tree,
                object_hash: b_dir,
            },
        ],
    );
    let key = mkit_core::KeyPair::from_seed([3; 32]);
    let mut remix = Remix {
        tree_hash: root,
        parents: Vec::new(),
        sources: Vec::new(),
        author: Identity::opaque(b"a".to_vec()),
        signer: key.public.0,
        message: b"base".to_vec(),
        timestamp: 1,
        signature: [0; 64],
    };
    remix.signature = sign_remix(&remix, &key).unwrap().0;
    let base = put(&store, &Object::Remix(remix));
    let paths: Vec<PartialPath> = vec![
        vec![b"Case".to_vec(), b"x".to_vec()],
        vec![b"case".to_vec(), b"y".to_vec()],
    ];
    let bundle = build_partial_snapshot(&store, base, &paths, &LIMITS).unwrap();
    assert!(matches!(
        ScopedWorkspaceLayout::create(
            &dir.path().join("ws"),
            base,
            &paths,
            &bundle.encode(&LIMITS).unwrap(),
            LIMITS,
            None,
        ),
        Err(PartialStateError::UnsafeFilesystemEntry { .. })
    ));
}

#[test]
fn normalization_alias_collision_is_caught_on_normalizing_filesystems() {
    // NFC `é` (U+00E9) vs NFD `e` + U+0301 — same file on filesystems that
    // normalize names (macOS). Probe truthfully first.
    use std::os::unix::ffi::OsStrExt;
    let nfc: &[u8] = "caf\u{E9}".as_bytes();
    let nfd: &[u8] = "cafe\u{301}".as_bytes();
    let probe = tempfile::tempdir().unwrap();
    let nfc_path = probe.path().join(std::ffi::OsStr::from_bytes(nfc));
    std::fs::write(&nfc_path, b"p").unwrap();
    if std::fs::metadata(probe.path().join(std::ffi::OsStr::from_bytes(nfd))).is_err() {
        eprintln!("non-normalizing filesystem: normalization-collision check skipped");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let store = ObjectStore::init(&RepoLayout::single(dir.path().join("repo"))).unwrap();
    let f1 = mkit_core::store_file_object(&store, b"1").unwrap();
    let f2 = mkit_core::store_file_object(&store, b"2").unwrap();
    let root = tree(
        &store,
        vec![
            TreeEntry {
                name: nfc.to_vec(),
                mode: EntryMode::Blob,
                object_hash: f1,
            },
            TreeEntry {
                name: nfd.to_vec(),
                mode: EntryMode::Blob,
                object_hash: f2,
            },
        ],
    );
    let key = mkit_core::KeyPair::from_seed([4; 32]);
    let mut remix = Remix {
        tree_hash: root,
        parents: Vec::new(),
        sources: Vec::new(),
        author: Identity::opaque(b"a".to_vec()),
        signer: key.public.0,
        message: b"base".to_vec(),
        timestamp: 1,
        signature: [0; 64],
    };
    remix.signature = sign_remix(&remix, &key).unwrap().0;
    let base = put(&store, &Object::Remix(remix));
    let mut paths: Vec<PartialPath> = vec![vec![nfc.to_vec()], vec![nfd.to_vec()]];
    paths.sort();
    let bundle = build_partial_snapshot(&store, base, &paths, &LIMITS).unwrap();
    assert!(matches!(
        ScopedWorkspaceLayout::create(
            &dir.path().join("ws"),
            base,
            &paths,
            &bundle.encode(&LIMITS).unwrap(),
            LIMITS,
            None,
        ),
        Err(PartialStateError::UnsafeFilesystemEntry { .. })
    ));
}

// -- 13. marker-last / unrelated parent ----------------------------------------

#[test]
fn failed_create_never_exposes_destination() {
    let fixture = fixture(&[]);
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("ws");
    // Corrupt the bundle → verify fails before any install begins.
    let mut bad = fixture.bundle_bytes.clone();
    bad[10] ^= 0xFF;
    assert!(
        ScopedWorkspaceLayout::create(&dest, fixture.base_id, &fixture.paths, &bad, LIMITS, None,)
            .is_err()
    );
    assert!(!dest.exists());
    // No scratch dirs leak into the unrelated parent.
    let leftovers: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| {
            let name = e.unwrap().file_name();
            name.to_string_lossy()
                .starts_with(".mkit-scoped-new-")
                .then_some(name)
        })
        .collect();
    assert!(
        leftovers.is_empty(),
        "scratch dirs must be cleaned: {leftovers:?}"
    );
}

// -- 14. pending, outcomes, acceptance ------------------------------------------

#[test]
fn pending_lifecycle_and_accepted_advancement() {
    let (_dir, layout) = workspace();
    let staged = stage_a(&layout, b"work A");
    let pend = pending(&layout, &staged);
    assert_eq!(pend.pending().unwrap().status(), PendingStatusV1::Prepared);
    let identity = pend.pending().unwrap().identity();
    let update_digest = *pend.pending().unwrap().update_digest();
    let base_id = *pend.workspace().base_id();
    // Diverge the working file AFTER pending A was recorded: accepted
    // advancement of A must leave these exact bytes alone.
    let workfile = layout.root().join("a/x.txt");
    std::fs::write(&workfile, b"work B diverged").unwrap();
    // Blocked: stage refused while pending.
    assert!(matches!(
        layout.replace_stage(
            generation(&pend),
            &[FileReplacement::bytes(
                vec![b"b".to_vec(), b"x.txt".to_vec()],
                b"no".to_vec()
            )]
        ),
        Err(PartialStateError::PendingConflict)
    ));
    // Non-accepted outcomes update only the status: base id/revision and
    // the pending identity/update digest stay pinned.
    let mut current = pend;
    for (outcome, status) in [
        (PendingOutcomeV1::Exported, PendingStatusV1::Exported),
        (PendingOutcomeV1::Conflict, PendingStatusV1::Conflict),
        (PendingOutcomeV1::Unknown, PendingStatusV1::Unknown),
    ] {
        let next = layout
            .record_outcome(generation(&current), &identity, outcome)
            .unwrap();
        let pending = next.pending().unwrap();
        assert_eq!(pending.status(), status);
        assert_eq!(pending.identity(), identity);
        assert_eq!(pending.update_digest(), &update_digest);
        assert_eq!(next.workspace().base_id(), &base_id);
        assert_eq!(next.workspace().base_revision(), 0);
        current = next;
    }
    // Same outcome is idempotent (no generation advance).
    let again = layout
        .record_outcome(999, &identity, PendingOutcomeV1::Unknown)
        .unwrap();
    assert_eq!(generation(&again), generation(&current));
    // Accept advances the base.
    let accepted = layout
        .record_outcome(generation(&current), &identity, PendingOutcomeV1::Accepted)
        .unwrap();
    assert!(accepted.pending().is_none());
    assert!(accepted.accepted().is_some());
    assert_eq!(accepted.workspace().base_revision(), 1);
    assert_ne!(accepted.workspace().base_id(), &base_id);
    assert_eq!(accepted.accepted().unwrap().prior_base_id(), &base_id);
    assert!(accepted.stage_is_clean());
    // Replaying the same Accepted identity is idempotent even with a stale
    // expected generation.
    let replay = layout
        .record_outcome(0, &identity, PendingOutcomeV1::Accepted)
        .unwrap();
    assert_eq!(generation(&replay), generation(&accepted));
    // Working B survives accepted A byte-for-byte.
    assert_eq!(std::fs::read(&workfile).unwrap(), b"work B diverged");
}

#[test]
fn exact_pending_retry_is_generation_neutral() {
    let (_dir, layout) = workspace();
    let staged = stage_a(&layout, b"A");
    let pend = pending(&layout, &staged);
    let tx = generation(&pend);
    // Rebuild the identical call.
    let verified = pend.verified();
    let feed = vec![FileReplacement::bytes(
        vec![b"a".to_vec(), b"x.txt".to_vec()],
        b"A".to_vec(),
    )];
    let prepared = replace_files(verified, &feed, &LIMITS).unwrap();
    let key = mkit_core::KeyPair::from_seed([9; 32]);
    let unsigned = prepare_partial_commit(
        verified,
        &prepared,
        Identity::opaque(b"op author".to_vec()),
        key.public.0,
        b"pending op".to_vec(),
        1_700_000_100,
        &LIMITS,
    )
    .unwrap();
    let mut signed = unsigned.clone();
    signed.signature = sign_commit(&signed, &key).unwrap().0;
    let update = export_partial_update(verified, &prepared, &unsigned, &signed, &LIMITS).unwrap();
    let bytes = update.encode(&LIMITS).unwrap();
    let operation = Some(PendingOperationV1 {
        operation_id: [1; 32],
        request_fingerprint: [2; 32],
    });
    let same = layout
        .save_pending(tx, &unsigned, &signed, &bytes, operation)
        .unwrap();
    assert_eq!(generation(&same), tx);
    // A stale expected generation refuses even a byte-identical retry.
    assert!(matches!(
        layout.save_pending(tx + 1, &unsigned, &signed, &bytes, operation),
        Err(PartialStateError::GenerationMismatch { .. })
    ));
    // Byte-identical bytes with substituted commit inputs are not a
    // neutral retry: the commits must reproduce the recorded update.
    let mut bogus_unsigned = unsigned.clone();
    bogus_unsigned.message = b"bogus".to_vec();
    assert!(matches!(
        layout.save_pending(tx, &bogus_unsigned, &signed, &bytes, operation),
        Err(PartialStateError::CandidateMismatch | PartialStateError::PendingConflict)
    ));
    let mut bogus_signed = signed.clone();
    bogus_signed.signature = [0xAB; 64];
    assert!(matches!(
        layout.save_pending(tx, &unsigned, &bogus_signed, &bytes, operation),
        Err(PartialStateError::CandidateMismatch | PartialStateError::PendingConflict)
    ));
    // A substituted operation pair is a conflict.
    assert!(matches!(
        layout.save_pending(
            tx,
            &unsigned,
            &signed,
            &bytes,
            Some(PendingOperationV1 {
                operation_id: [9; 32],
                request_fingerprint: [2; 32],
            }),
        ),
        Err(PartialStateError::PendingConflict)
    ));
}

#[test]
fn altered_signed_candidate_without_pending_is_candidate_mismatch() {
    // Same base, same stage, NO recorded pending: original expected
    // commits + a re-signed altered-message update must not be stored.
    let (_dir, layout) = workspace();
    let staged = stage_a(&layout, b"A");
    let verified = staged.verified();
    let feed = vec![FileReplacement::bytes(
        vec![b"a".to_vec(), b"x.txt".to_vec()],
        b"A".to_vec(),
    )];
    let prepared = replace_files(verified, &feed, &LIMITS).unwrap();
    let key = mkit_core::KeyPair::from_seed([9; 32]);
    let unsigned = prepare_partial_commit(
        verified,
        &prepared,
        Identity::opaque(b"op author".to_vec()),
        key.public.0,
        b"pending op".to_vec(),
        1_700_000_100,
        &LIMITS,
    )
    .unwrap();
    let mut signed = unsigned.clone();
    signed.signature = sign_commit(&signed, &key).unwrap().0;
    // Independently build a VALID altered-message candidate/update for the
    // same prepared edit — different message, honestly re-signed.
    let mut altered_unsigned = unsigned.clone();
    altered_unsigned.message = b"altered op".to_vec();
    let mut altered_signed = altered_unsigned.clone();
    altered_signed.signature = sign_commit(&altered_signed, &key).unwrap().0;
    let altered = export_partial_update(
        verified,
        &prepared,
        &altered_unsigned,
        &altered_signed,
        &LIMITS,
    )
    .unwrap();
    let altered_bytes = altered.encode(&LIMITS).unwrap();
    assert!(matches!(
        layout.save_pending(
            generation(&staged),
            &unsigned,
            &signed,
            &altered_bytes,
            None,
        ),
        Err(PartialStateError::CandidateMismatch)
    ));
    assert!(snap(&layout).pending().is_none());
}

#[test]
fn structurally_valid_foreign_update_is_rejected() {
    // A workspace with a staged edit but NO pending operation, handed a
    // perfectly valid MKWU built for a different base/candidate.
    let (_dir, layout) = workspace();
    let staged = stage_a(&layout, b"A");
    // Build the foreign update inside a second workspace pinned to a
    // different base commit.
    let ffix = fixture(&[&["foreign-marker"]]);
    let fdir = tempfile::tempdir().unwrap();
    let fdest = fdir.path().join("foreign-ws");
    let fws = ScopedWorkspaceLayout::create(
        &fdest,
        ffix.base_id,
        &ffix.paths,
        &ffix.bundle_bytes,
        LIMITS,
        None,
    )
    .unwrap();
    let fstaged = fws
        .replace_stage(
            0,
            &[FileReplacement::bytes(
                vec![b"a".to_vec(), b"x.txt".to_vec()],
                b"foreign content".to_vec(),
            )],
        )
        .unwrap();
    let verified = fstaged.verified();
    let feed = vec![FileReplacement::bytes(
        vec![b"a".to_vec(), b"x.txt".to_vec()],
        b"foreign content".to_vec(),
    )];
    let prepared = replace_files(verified, &feed, &LIMITS).unwrap();
    let key = mkit_core::KeyPair::from_seed([5; 32]);
    let unsigned = prepare_partial_commit(
        verified,
        &prepared,
        Identity::opaque(b"foreign".to_vec()),
        key.public.0,
        b"foreign op".to_vec(),
        1_700_000_200,
        &LIMITS,
    )
    .unwrap();
    let mut signed = unsigned.clone();
    signed.signature = sign_commit(&signed, &key).unwrap().0;
    let update = export_partial_update(verified, &prepared, &unsigned, &signed, &LIMITS).unwrap();
    let bytes = update.encode(&LIMITS).unwrap();
    // The update is structurally valid — but its recorded base is not this
    // workspace's base.
    assert!(matches!(
        layout.save_pending(generation(&staged), &unsigned, &signed, &bytes, None,),
        Err(PartialStateError::CandidateMismatch)
    ));
    // And nothing was persisted.
    assert!(snap(&layout).pending().is_none());
    assert_eq!(generation(&snap(&layout)), 1);
}

// -- codec edges ---------------------------------------------------------------

/// Recompute the trailing BLAKE3 checksum so a mutated envelope reaches
/// the payload decoder instead of failing integrity first.
fn reseal(mut bytes: Vec<u8>) -> Vec<u8> {
    let body_len = bytes.len() - 32;
    let checksum = mkit_core::hash::hash(&bytes[..body_len]);
    bytes.truncate(body_len);
    bytes.extend_from_slice(&checksum);
    bytes
}

#[test]
fn codec_rejects_malformed_envelopes() {
    let (_dir, layout) = workspace();
    let staged = stage_a(&layout, b"A");
    let _ = pending(&layout, &staged);
    let gen_dir = current_generation_dir(layout.root());
    let ws_bytes = std::fs::read(gen_dir.join("workspace.bin")).unwrap();
    let pn_bytes = std::fs::read(gen_dir.join("pending.bin")).unwrap();

    // Bit flips without a resealed checksum fail integrity.
    for offset in [6usize, ws_bytes.len() - 1] {
        let mut bad = ws_bytes.clone();
        bad[offset] ^= 0xFF;
        assert!(matches!(
            WorkspaceStateV1::decode(&bad),
            Err(PartialStateError::ChecksumMismatch)
        ));
    }

    // Unsupported version (resealed so the version check is reached).
    let mut bad = ws_bytes.clone();
    bad[4] = 2;
    assert!(matches!(
        WorkspaceStateV1::decode(&reseal(bad)),
        Err(PartialStateError::UnsupportedVersion(2))
    ));

    // Trailing payload byte.
    let mut bad = ws_bytes.clone();
    bad.insert(bad.len() - 32, 0);
    assert!(matches!(
        WorkspaceStateV1::decode(&reseal(bad)),
        Err(PartialStateError::NonCanonical(_))
    ));

    // Non-minimal varint on the selection count: workspace_id[32] +
    // generation[8] + base_rev[8] + base_id[32] + bundle_digest[32] puts
    // the count at absolute offset 117.
    let mut bad = ws_bytes.clone();
    assert!(bad[117] < 0x80);
    let count = bad[117];
    bad.splice(117..118, [count | 0x80, 0x00]);
    assert!(matches!(
        WorkspaceStateV1::decode(&reseal(bad)),
        Err(PartialStateError::NonCanonical(_))
    ));

    // Unknown option tag: the workspace target tag is the last payload
    // byte in this fixture.
    let mut bad = ws_bytes.clone();
    let tag = bad.len() - 33;
    assert_eq!(bad[tag], 0);
    bad[tag] = 2;
    assert!(matches!(
        WorkspaceStateV1::decode(&reseal(bad)),
        Err(PartialStateError::NonCanonical(_))
    ));

    // Unknown pending status: fixed fields put status at payload offset
    // 152 → absolute 157.
    let mut bad = pn_bytes.clone();
    assert!(bad[157] <= 3);
    bad[157] = 9;
    assert!(matches!(
        PendingStateV1::decode(&reseal(bad)),
        Err(PartialStateError::NonCanonical(_))
    ));

    // One byte over the 1 MiB envelope bound.
    let oversized = vec![0u8; 1024 * 1024 + 1];
    assert!(matches!(
        WorkspaceStateV1::decode(&oversized),
        Err(PartialStateError::EnvelopeTooLarge)
    ));

    // Exactly 1 MiB: envelope-level checks run; the error is a payload
    // error, never EnvelopeTooLarge.
    let mut big = ws_bytes.clone();
    let pad = 1024 * 1024 - big.len();
    big.splice(big.len() - 32..big.len() - 32, vec![0u8; pad]);
    assert_eq!(big.len(), 1024 * 1024);
    let result = WorkspaceStateV1::decode(&reseal(big));
    assert!(matches!(result, Err(PartialStateError::NonCanonical(_))));
}

fn raw_envelope(magic: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 37);
    out.extend_from_slice(&magic);
    out.push(1);
    out.extend_from_slice(payload);
    out.extend_from_slice(&mkit_core::hash::hash(&out));
    out
}

fn leb128(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            return out;
        }
    }
}

/// The 20 persisted `PartialLimits` u64 fields in MKWS declaration order.
fn limits_payload() -> Vec<u8> {
    let l = PartialLimits::V1;
    let fields = [
        l.max_selected_paths,
        l.max_path_depth,
        l.max_component_bytes,
        l.max_path_bytes,
        l.max_total_path_bytes,
        l.max_selected_file_bytes,
        l.max_total_selected_bytes,
        l.max_base_object_bytes,
        l.max_tree_object_bytes,
        l.max_tree_entries,
        l.max_witness_bytes,
        l.max_tree_visits,
        l.max_bundle_bytes,
        l.max_objects,
        l.max_object_bytes,
        l.max_update_bytes,
        l.max_raw_pack_bytes,
        l.max_update_objects,
        l.max_commit_message_bytes,
        l.max_changed_paths,
    ];
    fields
        .iter()
        .flat_map(|f| (*f as u64).to_be_bytes())
        .collect()
}

/// MKWS fixed header: `workspace_id` + generation + revision + `base_id` +
/// bundle digest — enough for the decoder to reach the selection count.
fn ws_header() -> Vec<u8> {
    vec![0u8; 32 + 8 + 8 + 32 + 32]
}

#[test]
fn codec_count_and_byte_string_bounds_are_exact() {
    // Selection count: the bound itself passes the count check (the error
    // moves on to missing entries); one over is refused as a count bound.
    let exact = raw_envelope(*b"MKWS", &[ws_header().as_slice(), &leb128(256)].concat());
    assert!(matches!(
        WorkspaceStateV1::decode(&exact),
        Err(PartialStateError::NonCanonical("truncated"))
    ));
    let over = raw_envelope(*b"MKWS", &[ws_header().as_slice(), &leb128(257)].concat());
    assert!(matches!(
        WorkspaceStateV1::decode(&over),
        Err(PartialStateError::NonCanonical("count bound"))
    ));

    // Component byte-string: exactly 255 bytes decodes; 256 is a bound.
    let mut payload = ws_header();
    payload.extend_from_slice(&leb128(1)); // selection count
    payload.extend_from_slice(&leb128(1)); // path depth
    payload.extend_from_slice(&leb128(255));
    payload.extend_from_slice(&vec![b'x'; 255]);
    payload.push(0x01); // mode Blob
    payload.extend_from_slice(&[0u8; 32]); // base_file_id
    payload.extend_from_slice(&limits_payload());
    payload.push(0); // no target
    assert!(WorkspaceStateV1::decode(&raw_envelope(*b"MKWS", &payload)).is_ok());
    let over_component = raw_envelope(
        *b"MKWS",
        &[ws_header().as_slice(), &leb128(1), &leb128(1), &leb128(256)].concat(),
    );
    assert!(matches!(
        WorkspaceStateV1::decode(&over_component),
        Err(PartialStateError::NonCanonical("count bound"))
    ));

    // Path depth: 32 components decode; 33 is a bound.
    let mut deep = ws_header();
    deep.extend_from_slice(&leb128(1)); // selection count
    deep.extend_from_slice(&leb128(32)); // path depth
    for _ in 0..32 {
        deep.extend_from_slice(&leb128(1));
        deep.push(b'x');
    }
    deep.push(0x01);
    deep.extend_from_slice(&[0u8; 32]);
    deep.extend_from_slice(&limits_payload());
    deep.push(0);
    assert!(WorkspaceStateV1::decode(&raw_envelope(*b"MKWS", &deep)).is_ok());
    let over_depth = raw_envelope(
        *b"MKWS",
        &[ws_header().as_slice(), &leb128(1), &leb128(33)].concat(),
    );
    assert!(matches!(
        WorkspaceStateV1::decode(&over_depth),
        Err(PartialStateError::NonCanonical("count bound"))
    ));
}

#[test]
fn mismatched_pending_identity_and_candidate_are_rejected() {
    let (_dir, layout) = workspace();
    let staged = stage_a(&layout, b"A");
    let pend = pending(&layout, &staged);
    // A foreign workspace's pending identity cannot record outcomes here.
    let foreign = {
        let (_d2, other) = workspace();
        let staged = stage_a(&other, b"A");
        pending(&other, &staged).pending().unwrap().identity()
    };
    assert!(matches!(
        layout.record_outcome(generation(&pend), &foreign, PendingOutcomeV1::Exported),
        Err(PartialStateError::PendingMismatch)
    ));
    // A re-signed/altered update fails the byte-exact binding.
    let verified = pend.verified();
    let feed = vec![FileReplacement::bytes(
        vec![b"a".to_vec(), b"x.txt".to_vec()],
        b"A".to_vec(),
    )];
    let prepared = replace_files(verified, &feed, &LIMITS).unwrap();
    let key = mkit_core::KeyPair::from_seed([9; 32]);
    let mut unsigned = prepare_partial_commit(
        verified,
        &prepared,
        Identity::opaque(b"op author".to_vec()),
        key.public.0,
        b"pending op".to_vec(),
        1_700_000_100,
        &LIMITS,
    )
    .unwrap();
    unsigned.message = b"altered".to_vec();
    let mut signed = unsigned.clone();
    signed.signature = sign_commit(&signed, &key).unwrap().0;
    let update = export_partial_update(verified, &prepared, &unsigned, &signed, &LIMITS).unwrap();
    let bytes = update.encode(&LIMITS).unwrap();
    assert!(matches!(
        layout.save_pending(generation(&pend), &unsigned, &signed, &bytes, None),
        Err(PartialStateError::PendingConflict)
    ));
}
