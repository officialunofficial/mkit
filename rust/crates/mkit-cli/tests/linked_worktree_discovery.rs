//! #493 Phase 1: linked-worktree discovery, end to end.
//!
//! `mkit worktree add` does not exist yet (Phase 2), so these tests
//! hand-build the exact on-disk shape it will produce — a
//! `worktrees/<id>/` state dir under the main `.mkit` and a
//! `mkitdir: …` pointer file — and then drive the REAL binary from
//! inside the linked tree. This pins the Phase 1 contract:
//!
//! - a linked tree shares the main repository's object store and refs;
//! - its HEAD/index/op-state live in its own state dir, and tree-local
//!   commands never touch the main tree's state;
//! - a broken pointer fails closed with a clear diagnostic, never
//!   operating on the wrong directory.

mod common;

use std::path::{Path, PathBuf};

use common::{Repo, mkit};
use mkit_core::layout::RepoLayout;

/// Hand-build a linked worktree of `repo` in its own tempdir, the way
/// Phase 2's `worktree add` will: state dir + commondir + back-pointer
/// under the main `.mkit`, pointer file in the new tree, HEAD on
/// `branch`, and the tree's files materialized by `checkout` run from
/// the linked tree itself. Returns the tempdir (keep it alive) and the
/// tree root inside it.
fn link_worktree(repo: &Repo, name: &str, branch: &str) -> (tempfile::TempDir, PathBuf) {
    let host = tempfile::tempdir().expect("linked-tree tempdir");
    let tree = host.path().join(name);
    let state = repo.mkit_dir().join("worktrees").join(name);
    std::fs::create_dir_all(&state).expect("create state dir");
    std::fs::write(state.join("commondir"), b"../..\n").expect("write commondir");
    std::fs::create_dir_all(&tree).expect("create tree");
    std::fs::write(
        state.join("mkitdir"),
        format!("{}\n", tree.join(".mkit").display()),
    )
    .expect("write back-pointer");
    mkit_core::layout::write_pointer_file(&tree, &state).expect("write pointer");
    // Seed the linked tree's HEAD, then let the real binary materialize
    // files + index via a forced checkout run INSIDE the linked tree.
    std::fs::write(state.join("HEAD"), format!("ref: refs/heads/{branch}\n")).expect("seed HEAD");
    let out = mkit(&tree, repo.xdg(), &["checkout", "--force", branch]);
    assert!(
        out.status.success(),
        "checkout in linked tree: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    (host, tree)
}

fn object_count(mkit_dir: &Path) -> usize {
    fn walk(d: &Path, n: &mut usize) {
        for e in std::fs::read_dir(d).expect("read objects dir") {
            let p = e.expect("dir entry").path();
            if p.is_dir() {
                walk(&p, n);
            } else {
                *n += 1;
            }
        }
    }
    let mut n = 0;
    walk(&mkit_dir.join("objects"), &mut n);
    n
}

#[test]
fn linked_tree_shares_store_and_keeps_state_local() {
    let repo = Repo::new();
    repo.commit_file("shared.txt", b"from main\n", "seed");
    repo.ok(&["branch", "feature"]);

    let (_host, tree) = link_worktree(&repo, "wt1", "feature");

    // Discovery resolves the split layout.
    let layout = mkit_core::layout::discover(&tree).unwrap();
    assert!(!layout.is_single());
    assert_eq!(layout.common_dir(), repo.mkit_dir().canonicalize().unwrap());

    // The checkout materialized main's content into the linked tree.
    assert_eq!(
        std::fs::read(tree.join("shared.txt")).unwrap(),
        b"from main\n"
    );

    // Commit from INSIDE the linked tree...
    let before = object_count(&repo.mkit_dir());
    std::fs::write(tree.join("linked.txt"), b"from linked\n").unwrap();
    let out = mkit(&tree, repo.xdg(), &["add", "linked.txt"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = mkit(&tree, repo.xdg(), &["commit", "-m", "from linked tree"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // ...objects landed in the ONE shared store (no second store).
    assert!(
        object_count(&repo.mkit_dir()) > before,
        "linked-tree commit must write into the shared object store"
    );
    assert!(
        !tree.join(".mkit").is_dir(),
        "the linked tree must not grow its own .mkit directory"
    );

    // The shared ref moved; the main tree sees the commit.
    let out = repo.ok(&["log", "feature"]);
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("from linked tree"),
        "main tree must see the linked tree's commit on the shared ref"
    );

    // Per-tree state stayed per-tree: main HEAD on main, linked HEAD on
    // feature; index files are distinct.
    assert_eq!(
        std::fs::read_to_string(repo.mkit_dir().join("HEAD")).unwrap(),
        "ref: refs/heads/main\n"
    );
    let state = repo.mkit_dir().join("worktrees/wt1");
    assert_eq!(
        std::fs::read_to_string(state.join("HEAD")).unwrap(),
        "ref: refs/heads/feature\n"
    );
    assert!(state.join("index").is_file());

    // Tree-local status: the linked tree is clean, and the main tree's
    // status is unaffected by anything the linked tree did.
    let out = mkit(&tree, repo.xdg(), &["status", "--porcelain"]);
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout), "");
    let out = repo.ok(&["status", "--porcelain"]);
    assert_eq!(String::from_utf8_lossy(&out.stdout), "");
}

#[test]
fn stash_in_linked_tree_is_tree_local() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"one\n", "seed");
    repo.ok(&["branch", "feature"]);
    let (_host, tree) = link_worktree(&repo, "wt1", "feature");

    std::fs::write(tree.join("a.txt"), b"dirty\n").unwrap();
    let out = mkit(&tree, repo.xdg(), &["stash", "save", "-m", "wip"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The stash manifest lives in the linked tree's state dir, not the
    // main `.mkit` (stash is per-worktree state per #493).
    assert!(
        repo.mkit_dir().join("worktrees/wt1/stash").is_file(),
        "stash must land in the linked tree's state dir"
    );
    assert!(
        !repo.mkit_dir().join("stash").exists(),
        "the main tree's stash must be untouched"
    );
    let out = repo.ok(&["stash", "list"]);
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "",
        "main tree's stash list must be empty"
    );
}

#[test]
fn broken_pointer_fails_closed_with_clear_error() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"one\n", "seed");
    let host = tempfile::tempdir().expect("broken-tree tempdir");
    let tree = host.path().join("broken-tree");
    std::fs::create_dir_all(&tree).unwrap();

    // Garbage pointer.
    std::fs::write(tree.join(".mkit"), b"gitdir: /somewhere\n").unwrap();
    let out = mkit(&tree, repo.xdg(), &["status"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("worktree discovery"),
        "diagnostic must name discovery: {stderr}"
    );

    // Dangling pointer (state dir never created / pruned).
    std::fs::write(
        tree.join(".mkit"),
        format!(
            "mkitdir: {}\n",
            repo.mkit_dir().join("worktrees/gone").display()
        ),
    )
    .unwrap();
    let out = mkit(&tree, repo.xdg(), &["status"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("worktree discovery") && stderr.contains("pruned"),
        "dangling pointer must fail closed with guidance: {stderr}"
    );
}

#[test]
fn single_worktree_repos_are_untouched_by_discovery() {
    // Belt and braces on top of layout_phase0_pin: a normal repo's
    // full add/commit/status flow is oblivious to Phase 1.
    let repo = Repo::new();
    repo.commit_file("a.txt", b"one\n", "seed");
    let layout = RepoLayout::single(repo.path());
    let discovered = mkit_core::layout::discover(repo.path()).unwrap();
    assert_eq!(discovered, layout);
    assert!(discovered.is_single());
}
