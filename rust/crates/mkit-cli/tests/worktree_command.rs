//! `mkit worktree add/list/remove/prune` (#493 Phase 2) — acceptance
//! criteria from the issue, driven through the real binary:
//! a second tree shares the one object store; branch double-checkout
//! is refused everywhere; tree-local commands stay tree-local;
//! `remove` protects local work; `prune` reaps only dead registry
//! entries; and gc unions retention roots across every tree (Phase 3).

mod common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::{Repo, mkit};

/// Run `mkit worktree add` from the main tree; return the new tree
/// root (inside its own tempdir, which the caller keeps alive).
fn wt_add(repo: &Repo, extra: &[&str], name: &str) -> (tempfile::TempDir, PathBuf, Output) {
    let host = tempfile::tempdir().expect("worktree host dir");
    let tree = host.path().join(name);
    let target_arg = tree.to_string_lossy().into_owned();
    let mut argv = vec!["worktree", "add", &target_arg];
    argv.extend_from_slice(extra);
    let out = repo.run(&argv);
    (host, tree, out)
}

fn object_count(mkit_dir: &Path) -> usize {
    fn walk(d: &Path, n: &mut usize) {
        for e in std::fs::read_dir(d).expect("read dir") {
            let p = e.expect("entry").path();
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
fn add_creates_branch_named_after_path_and_shares_store() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"one\n", "seed");

    let (_host, tree, out) = wt_add(&repo, &[], "topic");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Preparing worktree (new branch 'topic')"),
        "unexpected output: {stdout}"
    );

    // Materialized, discovered, and NOT a second store.
    assert_eq!(std::fs::read(tree.join("a.txt")).unwrap(), b"one\n");
    assert!(tree.join(".mkit").is_file(), "pointer file expected");
    let branches = repo.ok(&["branch"]);
    assert!(String::from_utf8_lossy(&branches.stdout).contains("topic"));

    // Acceptance: the second tree shares the object store — a commit
    // made there grows the MAIN store and creates no store in the tree.
    let before = object_count(&repo.mkit_dir());
    std::fs::write(tree.join("b.txt"), b"two\n").unwrap();
    let out = mkit(&tree, repo.xdg(), &["add", "b.txt"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = mkit(&tree, repo.xdg(), &["commit", "-m", "in topic"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(object_count(&repo.mkit_dir()) > before);
    assert!(!tree.join(".mkit").is_dir());

    common::check_invariants(repo.path(), "after linked-tree commit").unwrap();
}

#[test]
fn add_existing_branch_and_detached_forms() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"one\n", "seed");
    repo.ok(&["branch", "feature"]);

    // Existing branch.
    let (_h1, t1, out) = wt_add(&repo, &["feature"], "wt-feature");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("checking out 'feature'"),);
    let head = std::fs::read_to_string(repo.mkit_dir().join("worktrees/wt-feature/HEAD")).unwrap();
    assert_eq!(head, "ref: refs/heads/feature\n");
    let _ = t1;

    // Detached HEAD from an explicit revision.
    let (_h2, _t2, out) = wt_add(&repo, &["HEAD"], "wt-detached");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("detached HEAD"),);
}

#[test]
fn branch_checked_out_elsewhere_is_refused_everywhere() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"one\n", "seed");
    repo.ok(&["branch", "feature"]);
    let (_host, tree, out) = wt_add(&repo, &["feature"], "wt1");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // A second worktree on the same branch: refused.
    let (_h2, _t2, out) = wt_add(&repo, &["feature"], "wt2");
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("already checked out at"),);

    // Checking the branch out in the MAIN tree: refused (acceptance
    // criterion: clear error naming the other tree).
    let out = repo.run(&["checkout", "feature"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("already checked out at") && stderr.contains("wt1"),
        "diagnostic must name the holding tree: {stderr}"
    );
    // `switch` routes through checkout — same refusal.
    let out = repo.run(&["switch", "feature"]);
    assert!(!out.status.success());

    // Deleting or renaming a branch a sibling holds: refused.
    let out = repo.run(&["branch", "-D", "feature"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("checked out at"));
    let out = repo.run(&["branch", "-m", "feature", "renamed"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("checked out at"));

    // The linked tree itself can still move its own branch's tip.
    std::fs::write(tree.join("a.txt"), b"changed\n").unwrap();
    let out = mkit(&tree, repo.xdg(), &["add", "a.txt"]);
    assert!(out.status.success());
    let out = mkit(&tree, repo.xdg(), &["commit", "-m", "advance"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn add_refusals_nested_nonempty_existing_branch_no_commits() {
    let repo = Repo::new();

    // No commits yet.
    let (_h0, _t0, out) = wt_add(&repo, &[], "early");
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("no commits yet"));

    repo.commit_file("a.txt", b"one\n", "seed");

    // Nested inside the main worktree.
    let inside = repo.path().join("nested-wt").to_string_lossy().into_owned();
    let out = repo.run(&["worktree", "add", &inside]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("inside the worktree"));

    // Non-empty target.
    let host = tempfile::tempdir().unwrap();
    let busy = host.path().join("busy");
    std::fs::create_dir_all(&busy).unwrap();
    std::fs::write(busy.join("x"), b"x").unwrap();
    let busy_str = busy.to_string_lossy().into_owned();
    let out = repo.run(&["worktree", "add", &busy_str]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("not empty"));

    // Default-branch name collides with an existing branch.
    repo.ok(&["branch", "taken"]);
    let taken = host.path().join("taken").to_string_lossy().into_owned();
    let out = repo.run(&["worktree", "add", &taken]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("already exists"));
}

#[test]
fn list_shows_main_and_linked_trees() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"one\n", "seed");
    let (_host, tree, out) = wt_add(&repo, &[], "topic");
    assert!(out.status.success());

    let out = repo.ok(&["worktree", "list"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("[main]"), "main row missing: {stdout}");
    assert!(stdout.contains("[topic]"), "linked row missing: {stdout}");

    let out = repo.ok(&["worktree", "list", "--porcelain"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("branch refs/heads/main"));
    assert!(stdout.contains("branch refs/heads/topic"));
    assert!(
        stdout.contains(&format!(
            "worktree {}",
            tree.canonicalize().unwrap().display()
        )) || stdout.contains(&format!("worktree {}", tree.display())),
        "porcelain must name the tree path: {stdout}"
    );

    // Listing works from inside the linked tree too.
    let out = mkit(&tree, repo.xdg(), &["worktree", "list"]);
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("[main]"));
}

#[test]
fn remove_protects_local_work_and_force_overrides() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"one\n", "seed");
    let (_host, tree, out) = wt_add(&repo, &[], "topic");
    assert!(out.status.success());
    let tree_str = tree.to_string_lossy().into_owned();

    // Dirty tracked file: refused.
    std::fs::write(tree.join("a.txt"), b"dirty\n").unwrap();
    let out = repo.run(&["worktree", "remove", &tree_str]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("local changes"));

    // Clean it up; untracked file still blocks.
    std::fs::write(tree.join("a.txt"), b"one\n").unwrap();
    std::fs::write(tree.join("scratch.txt"), b"keep me\n").unwrap();
    let out = repo.run(&["worktree", "remove", &tree_str]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("untracked file"));

    // --force removes tree + state dir; the branch survives.
    let out = repo.ok(&["worktree", "remove", "--force", &tree_str]);
    assert!(out.status.success());
    assert!(!tree.exists());
    assert!(!repo.mkit_dir().join("worktrees/topic").exists());
    let out = repo.ok(&["branch"]);
    assert!(String::from_utf8_lossy(&out.stdout).contains("topic"));

    // The main tree is never removable.
    let main = repo.path().to_string_lossy().into_owned();
    let out = repo.run(&["worktree", "remove", &main]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("main working tree"));

    common::check_invariants(repo.path(), "after worktree remove").unwrap();
}

#[test]
fn prune_reaps_only_dead_entries_and_honors_dry_run() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"one\n", "seed");
    let (_h1, live, out) = wt_add(&repo, &[], "alive");
    assert!(out.status.success());
    let (_h2, dead, out) = wt_add(&repo, &[], "dead");
    assert!(out.status.success());

    // Kill one tree behind mkit's back.
    std::fs::remove_dir_all(&dead).unwrap();

    // list marks it prunable.
    let out = repo.ok(&["worktree", "list"]);
    assert!(String::from_utf8_lossy(&out.stdout).contains("prunable"));

    // Dry run deletes nothing.
    let out = repo.ok(&["worktree", "prune", "--dry-run"]);
    assert!(String::from_utf8_lossy(&out.stdout).contains("would prune worktrees/dead"));
    assert!(repo.mkit_dir().join("worktrees/dead").exists());

    // Real prune removes exactly the dead entry.
    let out = repo.ok(&["worktree", "prune"]);
    assert!(String::from_utf8_lossy(&out.stdout).contains("pruned worktrees/dead"));
    assert!(!repo.mkit_dir().join("worktrees/dead").exists());
    assert!(repo.mkit_dir().join("worktrees/alive").exists());
    assert!(live.join("a.txt").exists());
}

#[test]
fn worktree_ids_uniquify_on_basename_collision() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"one\n", "seed");
    let (_h1, _t1, out) = wt_add(&repo, &["HEAD"], "same");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let (_h2, _t2, out) = wt_add(&repo, &["HEAD"], "same");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(repo.mkit_dir().join("worktrees/same").is_dir());
    assert!(repo.mkit_dir().join("worktrees/same-1").is_dir());
}

#[test]
fn gc_keeps_sibling_staged_objects_and_prunes_real_garbage() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"one\n", "seed");
    let (_host, tree, out) = wt_add(&repo, &[], "topic");
    assert!(out.status.success());

    // Stage (don't commit) work in the SIBLING — exactly the object a
    // non-worktree-aware gc would prune (#493 Phase 3 acceptance).
    std::fs::write(tree.join("staged-only.txt"), b"precious\n").unwrap();
    let out = mkit(&tree, repo.xdg(), &["add", "staged-only.txt"]);
    assert!(out.status.success());

    // Manufacture true garbage in the MAIN tree: stage a blob, then
    // unstage it (mixed reset), leaving it reachable from nothing.
    repo.write("garbage.txt", b"transient\n");
    repo.ok(&["add", "garbage.txt"]);
    repo.ok(&["rm", "--cached", "garbage.txt"]);
    std::fs::remove_file(repo.path().join("garbage.txt")).unwrap();
    let before = object_count(&repo.mkit_dir());

    // gc with a zero grace window, from the main tree.
    repo.ok(&["gc", "--grace-secs", "0"]);

    // The garbage went; the sibling's staged object did not.
    assert!(
        object_count(&repo.mkit_dir()) < before,
        "unreachable object must be pruned"
    );
    let out = mkit(&tree, repo.xdg(), &["status", "--porcelain"]);
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("staged-only.txt"),
        "sibling staged entry must survive"
    );
    // And it still commits cleanly afterwards — the blob is intact.
    let out = mkit(&tree, repo.xdg(), &["commit", "-m", "staged survived"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    common::check_invariants(repo.path(), "after cross-tree gc").unwrap();
}
