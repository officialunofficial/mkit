//! #493 Phase 3: cross-worktree gc correctness and the lock split.
//!
//! Root collection unions HEAD + index + `ORIG_HEAD` + in-progress-op
//! state across EVERY worktree, and gc's "shared lock spanning trees"
//! is the union of all per-tree worktree locks, taken in deterministic
//! order. The ~5s lock-timeout test lives in the serial `#[ignore]`
//! lane per the #505 test-suite policy.

mod common;

use std::path::PathBuf;
use std::process::Output;

use common::{Repo, mkit};

fn wt_add(repo: &Repo, extra: &[&str], name: &str) -> (tempfile::TempDir, PathBuf, Output) {
    let host = tempfile::tempdir().expect("worktree host dir");
    let tree = host.path().join(name);
    let target_arg = tree.to_string_lossy().into_owned();
    let mut argv = vec!["worktree", "add", &target_arg];
    argv.extend_from_slice(extra);
    let out = repo.run(&argv);
    (host, tree, out)
}

#[test]
fn gc_keeps_sibling_in_progress_merge_state() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"base\n", "seed");
    repo.ok(&["branch", "feature"]);
    let (_host, tree, out) = wt_add(&repo, &["feature"], "wt1");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Diverge: main edits a.txt, the linked tree edits it differently
    // and merges main's branch — conflict, leaving MERGE_HEAD +
    // conflict sidecar in the LINKED tree's state dir.
    repo.write("a.txt", b"ours-main\n");
    repo.ok(&["add", "a.txt"]);
    repo.ok(&["commit", "-m", "main change"]);

    std::fs::write(tree.join("a.txt"), b"theirs-linked\n").unwrap();
    let out = mkit(&tree, repo.xdg(), &["add", "a.txt"]);
    assert!(out.status.success());
    let out = mkit(&tree, repo.xdg(), &["commit", "-m", "linked change"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let merge = mkit(&tree, repo.xdg(), &["merge", "main"]);
    assert!(
        !merge.status.success(),
        "merge should conflict: {}",
        String::from_utf8_lossy(&merge.stdout)
    );
    assert!(
        repo.mkit_dir().join("worktrees/wt1/MERGE_HEAD").is_file(),
        "conflict state must live in the sibling's state dir"
    );

    // gc from the MAIN tree with zero grace: the sibling's op state
    // (MERGE_HEAD commit, ORIG_HEAD, conflict base/ours/theirs blobs)
    // must all stay live.
    repo.ok(&["gc", "--grace-secs", "0"]);

    // The sibling can still resolve and conclude the merge.
    std::fs::write(tree.join("a.txt"), b"resolved\n").unwrap();
    let out = mkit(&tree, repo.xdg(), &["add", "a.txt"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = mkit(&tree, repo.xdg(), &["merge", "--continue"]);
    assert!(
        out.status.success(),
        "merge --continue after cross-tree gc: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    common::check_invariants(repo.path(), "after gc + sibling merge").unwrap();
}

#[test]
fn destructive_commands_in_linked_tree_stay_tree_local() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"one\n", "seed");
    let (_host, tree, out) = wt_add(&repo, &[], "topic");
    assert!(out.status.success());

    // Dirty BOTH trees, then reset --hard / clean only in the linked one.
    repo.write("a.txt", b"main-dirty\n");
    repo.write("untracked-main.txt", b"keep\n");
    std::fs::write(tree.join("a.txt"), b"linked-dirty\n").unwrap();
    std::fs::write(tree.join("junk.txt"), b"drop\n").unwrap();

    let out = mkit(&tree, repo.xdg(), &["reset", "--hard", "-f", "HEAD"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = mkit(&tree, repo.xdg(), &["clean", "-f"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Linked tree is pristine again...
    assert_eq!(std::fs::read(tree.join("a.txt")).unwrap(), b"one\n");
    assert!(!tree.join("junk.txt").exists());
    // ...while the main tree's local state is untouched.
    assert_eq!(
        std::fs::read(repo.path().join("a.txt")).unwrap(),
        b"main-dirty\n"
    );
    assert!(repo.path().join("untracked-main.txt").exists());
}

/// gc must block (and then time out) while a SIBLING tree's worktree
/// lock is held — the cross-tree half of the lock split. ~5s of
/// deliberate lock-timeout spinning, so this runs in the serial
/// `--run-ignored` CI lane (see #505), not the default suite.
#[test]
#[ignore = "deliberate ~5s lock-timeout; serial CI lane (#505)"]
fn gc_blocks_on_a_sibling_worktree_lock() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"one\n", "seed");
    let (_host, _tree, out) = wt_add(&repo, &[], "topic");
    assert!(out.status.success());

    // Hold the SIBLING's worktree lock the way a concurrent mkit
    // process would (the sentinel protocol: exclusive-create).
    let lock = repo.mkit_dir().join("worktrees/topic/worktree.lock");
    std::fs::write(&lock, b"").unwrap();

    let out = repo.run(&["gc", "--grace-secs", "0"]);
    assert!(
        !out.status.success(),
        "gc must not run while a sibling tree is mid-mutation"
    );
    assert_eq!(out.status.code(), Some(75), "TEMPFAIL on lock contention");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("lock"),
        "diagnostic must name the lock: {stderr}"
    );

    // Release and retry: gc proceeds.
    std::fs::remove_file(&lock).unwrap();
    repo.ok(&["gc", "--grace-secs", "0"]);
}
