//! End-to-end integration tests for Phase 5b — rebase / bisect /
//! blame / stash / restore. Each test mirrors a Zig integration
//! scenario from `src/{rebase,bisect,blame,stash,restore}.zig`.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use mkit_core::hash::{self, Hash};
use mkit_core::object::{Commit, EntryMode, Identity, Object, Tree, TreeEntry};
use mkit_core::ops::bisect::{self, BisectState, BisectStep};
use mkit_core::ops::blame;
use mkit_core::ops::rebase::{self, RebaseState};
use mkit_core::ops::restore::{self, RestoreOptions, SparsePattern};
use mkit_core::ops::stash;
use mkit_core::refs;
use mkit_core::serialize;
use mkit_core::store::ObjectStore;

use tempfile::TempDir;

fn fresh_store_in(dir: &Path) -> ObjectStore {
    ObjectStore::init(dir).unwrap()
}

fn put_blob(store: &ObjectStore, data: &[u8]) -> Hash {
    let bytes = serialize::serialize(&Object::Blob(mkit_core::object::Blob {
        data: data.to_vec(),
    }))
    .unwrap();
    store.write(&bytes).unwrap()
}

fn put_single_file_tree(store: &ObjectStore, name: &str, blob_h: Hash) -> Hash {
    let tree = Object::Tree(Tree {
        entries: vec![TreeEntry {
            name: name.as_bytes().to_vec(),
            mode: EntryMode::Blob,
            object_hash: blob_h,
        }],
    });
    store.write(&serialize::serialize(&tree).unwrap()).unwrap()
}

fn put_commit(store: &ObjectStore, tree_h: Hash, parents: Vec<Hash>, ts: u64) -> Hash {
    let commit = Object::Commit(Commit::new_unannotated(
        tree_h,
        parents,
        Identity::ed25519([0u8; 32]),
        [0u8; 32],
        b"msg".to_vec(),
        ts,
        [0u8; 64],
    ));
    store
        .write(&serialize::serialize(&commit).unwrap())
        .unwrap()
}

fn put_file_commit(
    store: &ObjectStore,
    name: &str,
    content: &[u8],
    parents: Vec<Hash>,
    author_mid: u64,
    ts: u64,
) -> Hash {
    let blob = put_blob(store, content);
    let tree = put_single_file_tree(store, name, blob);
    let commit = Object::Commit(Commit::new_unannotated(
        tree,
        parents,
        Identity::opaque(author_mid.to_le_bytes()),
        [0u8; 32],
        b"msg".to_vec(),
        ts,
        [0u8; 64],
    ));
    store
        .write(&serialize::serialize(&commit).unwrap())
        .unwrap()
}

// -- REBASE ---------------------------------------------------------------

#[test]
fn rebase_state_persists_and_reloads_after_simulated_crash() {
    // Mid-rebase crash leaves a recoverable state on disk.
    let tmp = TempDir::new().unwrap();
    let mkit = tmp.path().join(".mkit");
    fs::create_dir_all(&mkit).unwrap();

    let state = RebaseState {
        head_name: "feature/foo".to_string(),
        orig_head: hash::hash(b"orig"),
        onto: hash::hash(b"onto"),
        todo: vec![hash::hash(b"t1"), hash::hash(b"t2"), hash::hash(b"t3")],
        done: vec![hash::hash(b"d1")],
    };
    rebase::write_state(&mkit, &state).unwrap();
    assert!(rebase::is_rebase_in_progress(&mkit));

    // "Process exits"; new process re-reads state.
    let read = rebase::read_state(&mkit).unwrap();
    assert_eq!(read, state);

    // Abort: cleanup must drop the directory entirely.
    rebase::cleanup_rebase(&mkit).unwrap();
    assert!(!rebase::is_rebase_in_progress(&mkit));
    // Idempotent.
    rebase::cleanup_rebase(&mkit).unwrap();
}

#[test]
fn rebase_collect_commits_to_replay_y_shape() {
    let tmp = TempDir::new().unwrap();
    let store = fresh_store_in(tmp.path());
    let blob = put_blob(&store, b"data");
    let tree = put_single_file_tree(&store, "f.txt", blob);
    let c1 = put_commit(&store, tree, vec![], 1);
    let c2 = put_commit(&store, tree, vec![c1], 2);
    let c3 = put_commit(&store, tree, vec![c2], 3);
    let c4 = put_commit(&store, tree, vec![c1], 4);
    let c5 = put_commit(&store, tree, vec![c4], 5);
    let res = rebase::collect_commits_to_replay(&store, c5, c3).unwrap();
    assert_eq!(res, vec![c4, c5]);
}

// -- BISECT ---------------------------------------------------------------

#[test]
fn bisect_runs_to_completion_finds_first_bad_commit() {
    // Linear history c0..c5. Truth: c3 is the first bad commit.
    let tmp = TempDir::new().unwrap();
    let store = fresh_store_in(tmp.path());
    let blob = put_blob(&store, b"d");
    let tree = put_single_file_tree(&store, "f.txt", blob);
    let mut commits = Vec::new();
    commits.push(put_commit(&store, tree, vec![], 1));
    for i in 1..6 {
        let parent = commits[i - 1];
        commits.push(put_commit(&store, tree, vec![parent], (i + 1) as u64));
    }
    let truth = commits[3];

    let mut state = BisectState {
        orig_head: commits[5],
        orig_branch: None,
        bad_hash: Some(commits[5]),
        good_hashes: vec![commits[0]],
        skipped: BTreeSet::default(),
    };
    let mut iters = 0;
    let found = loop {
        assert!(iters < 8);
        iters += 1;
        match bisect::next_step(&store, &state).unwrap() {
            BisectStep::Found(h) => break h,
            BisectStep::Testing { hash, .. } => {
                let idx = commits.iter().position(|c| *c == hash).unwrap();
                let truth_idx = commits.iter().position(|c| *c == truth).unwrap();
                if idx < truth_idx {
                    state.good_hashes.push(hash);
                } else {
                    state.bad_hash = Some(hash);
                }
            }
            BisectStep::NeedMore => panic!("unexpected NeedMore"),
        }
    };
    assert_eq!(found, truth);
}

#[test]
fn bisect_state_persists_to_disk() {
    let tmp = TempDir::new().unwrap();
    let mkit = tmp.path().join(".mkit");
    fs::create_dir_all(&mkit).unwrap();
    let state = BisectState {
        orig_head: hash::hash(b"orig"),
        orig_branch: Some("main".to_string()),
        bad_hash: Some(hash::hash(b"bad")),
        good_hashes: vec![hash::hash(b"g1")],
        skipped: BTreeSet::default(),
    };
    bisect::write_state(&mkit, &state).unwrap();
    let back = bisect::read_state(&mkit).unwrap();
    assert_eq!(back, state);
    bisect::cleanup_bisect(&mkit).unwrap();
    assert!(!bisect::is_bisect_in_progress(&mkit));
}

// -- BLAME ----------------------------------------------------------------

#[test]
fn blame_three_commit_file_attributes_each_line_correctly() {
    // c_a: "a\nb\n"
    // c_b: "a\nb\nc\n"  (added c)
    // c_c: "a\nX\nc\n"  (modified b → X)
    let tmp = TempDir::new().unwrap();
    let store = fresh_store_in(tmp.path());
    let c_a = put_file_commit(&store, "f.txt", b"a\nb\n", vec![], 1, 100);
    let c_b = put_file_commit(&store, "f.txt", b"a\nb\nc\n", vec![c_a], 2, 200);
    let c_c = put_file_commit(&store, "f.txt", b"a\nX\nc\n", vec![c_b], 3, 300);
    let r = blame::blame_file(&store, c_c, "f.txt").unwrap();
    assert_eq!(r.lines.len(), 3);
    assert_eq!(r.lines[0].commit_hash, c_a);
    assert_eq!(r.lines[1].commit_hash, c_c);
    assert_eq!(r.lines[2].commit_hash, c_b);

    // Check golden output is byte-for-byte identical to the pinned vector.
    let pinned = read_golden("blame_three_commit.txt");
    let actual = blame::format_blame_text(&r);
    // Replace the dynamic short-hashes in the actual output with their
    // commit-key labels so the golden pin doesn't depend on hashes that
    // change as the object format evolves.
    let labelled = label_blame(&actual, &[("a", c_a), ("b", c_b), ("c", c_c)]);
    assert_eq!(labelled, String::from_utf8(pinned).unwrap());
}

fn label_blame(text: &str, labels: &[(&str, Hash)]) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    for line in text.lines() {
        let mut parts = line.splitn(3, '\t');
        let short = parts.next().unwrap();
        let lineno = parts.next().unwrap();
        let body = parts.next().unwrap();
        let mut found = false;
        for (label, h) in labels {
            let hex = hash::to_hex(h);
            if &hex[..12] == short {
                let _ = writeln!(out, "{label}\t{lineno}\t{body}");
                found = true;
                break;
            }
        }
        if !found {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

fn goldens_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(Path::parent)
        .map(|workspace| workspace.join("tests").join("golden").join("phase5b"))
        .expect("workspace layout: crates/mkit-core/.. → workspace root")
}

fn read_golden(name: &str) -> Vec<u8> {
    let path = goldens_root().join(name);
    fs::read(&path).unwrap_or_else(|e| panic!("read golden {}: {e}", path.display()))
}

// -- STASH ----------------------------------------------------------------

#[test]
fn stash_save_pop_roundtrip_restores_dirty_changes() {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path();
    let mkit_dir = repo.join(".mkit");
    fs::create_dir_all(&mkit_dir).unwrap();
    refs::init(&mkit_dir).unwrap();

    // Use a separate store directory so its `.mkit/objects/` does not
    // get treated as part of the worktree.
    let store_dir = TempDir::new().unwrap();
    let store = fresh_store_in(store_dir.path());

    // Initial commit: "original" content.
    fs::write(repo.join("hello.txt"), b"original").unwrap();
    let initial_tree = mkit_core::worktree::build_tree(&store, repo).unwrap();
    let initial_commit = put_commit(&store, initial_tree, vec![], 1000);
    refs::update_head(&mkit_dir, &initial_commit).unwrap();

    // Modify the file; stash; verify worktree restored to "original".
    fs::write(repo.join("hello.txt"), b"modified content").unwrap();
    stash::save(&store, repo, "WIP changes").unwrap();
    assert_eq!(fs::read(repo.join("hello.txt")).unwrap(), b"original");

    // List should contain one entry.
    let list = stash::list(repo).unwrap();
    assert_eq!(list.entries.len(), 1);
    assert_eq!(list.entries[0].message, "WIP changes");

    // Pop restores the modification.
    stash::pop(&store, repo, 0).unwrap();
    assert_eq!(
        fs::read(repo.join("hello.txt")).unwrap(),
        b"modified content"
    );
    let list_after = stash::list(repo).unwrap();
    assert!(list_after.entries.is_empty());
}

#[test]
fn stash_drop_removes_without_applying() {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path();
    let mkit_dir = repo.join(".mkit");
    fs::create_dir_all(&mkit_dir).unwrap();
    refs::init(&mkit_dir).unwrap();
    let store_dir = TempDir::new().unwrap();
    let store = fresh_store_in(store_dir.path());

    fs::write(repo.join("hello.txt"), b"original").unwrap();
    let tree = mkit_core::worktree::build_tree(&store, repo).unwrap();
    let commit = put_commit(&store, tree, vec![], 1000);
    refs::update_head(&mkit_dir, &commit).unwrap();

    fs::write(repo.join("hello.txt"), b"modified").unwrap();
    stash::save(&store, repo, "WIP").unwrap();

    stash::drop(repo, 0).unwrap();
    let list = stash::list(repo).unwrap();
    assert!(list.entries.is_empty());
    // Worktree is at HEAD's tree (the save reset it before drop ran).
    assert_eq!(fs::read(repo.join("hello.txt")).unwrap(), b"original");
}

#[test]
fn stash_index_out_of_range_errors() {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path();
    let mkit_dir = repo.join(".mkit");
    fs::create_dir_all(&mkit_dir).unwrap();
    refs::init(&mkit_dir).unwrap();
    let store_dir = TempDir::new().unwrap();
    let store = fresh_store_in(store_dir.path());
    let err1 = stash::pop(&store, repo, 0).unwrap_err();
    assert!(matches!(
        err1,
        mkit_core::ops::stash::StashError::IndexOutOfRange(0)
    ));
    let err2 = stash::drop(repo, 5).unwrap_err();
    assert!(matches!(
        err2,
        mkit_core::ops::stash::StashError::IndexOutOfRange(5)
    ));
}

// -- RESTORE --------------------------------------------------------------

#[test]
fn restore_with_sparse_include_and_exclude_patterns() {
    // include:src/**, exclude:src/test/**
    let tmp = TempDir::new().unwrap();
    let store_dir = TempDir::new().unwrap();
    let store = fresh_store_in(store_dir.path());

    let blob_main = put_blob(&store, b"main");
    let blob_lib = put_blob(&store, b"lib");
    let blob_test = put_blob(&store, b"test");
    let blob_readme = put_blob(&store, b"# readme");

    let test_tree = store
        .write(
            &serialize::serialize(&Object::Tree(Tree {
                entries: vec![TreeEntry {
                    name: b"smoke.rs".to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: blob_test,
                }],
            }))
            .unwrap(),
        )
        .unwrap();
    let src_tree = store
        .write(
            &serialize::serialize(&Object::Tree(Tree {
                entries: vec![
                    TreeEntry {
                        name: b"lib.rs".to_vec(),
                        mode: EntryMode::Blob,
                        object_hash: blob_lib,
                    },
                    TreeEntry {
                        name: b"main.rs".to_vec(),
                        mode: EntryMode::Blob,
                        object_hash: blob_main,
                    },
                    TreeEntry {
                        name: b"test".to_vec(),
                        mode: EntryMode::Tree,
                        object_hash: test_tree,
                    },
                ],
            }))
            .unwrap(),
        )
        .unwrap();
    let root_tree = store
        .write(
            &serialize::serialize(&Object::Tree(Tree {
                entries: vec![
                    TreeEntry {
                        name: b"README.md".to_vec(),
                        mode: EntryMode::Blob,
                        object_hash: blob_readme,
                    },
                    TreeEntry {
                        name: b"src".to_vec(),
                        mode: EntryMode::Tree,
                        object_hash: src_tree,
                    },
                ],
            }))
            .unwrap(),
        )
        .unwrap();

    let opts = RestoreOptions {
        clean: true,
        sparse_patterns: Some(vec![
            SparsePattern {
                pattern: "src".to_string(),
                negated: false,
                dir_only: false,
            },
            SparsePattern {
                pattern: "src/test".to_string(),
                negated: true,
                dir_only: false,
            },
        ]),
    };
    restore::restore_tree(&store, root_tree, tmp.path(), &opts).unwrap();
    assert!(tmp.path().join("src/main.rs").exists());
    assert!(tmp.path().join("src/lib.rs").exists());
    assert!(!tmp.path().join("src/test/smoke.rs").exists());
    assert!(!tmp.path().join("README.md").exists());
}

#[test]
fn restore_preserves_mkit_directory_when_cleaning() {
    let tmp = TempDir::new().unwrap();
    let store_dir = TempDir::new().unwrap();
    let store = fresh_store_in(store_dir.path());

    fs::create_dir_all(tmp.path().join(".mkit")).unwrap();
    fs::write(tmp.path().join(".mkit/config"), b"important").unwrap();
    let empty_tree = store
        .write(&serialize::serialize(&Object::Tree(Tree { entries: vec![] })).unwrap())
        .unwrap();
    restore::restore_tree(&store, empty_tree, tmp.path(), &RestoreOptions::default()).unwrap();
    assert_eq!(
        fs::read(tmp.path().join(".mkit/config")).unwrap(),
        b"important"
    );
}
