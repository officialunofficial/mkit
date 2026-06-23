//! `mkit revert` (#255) end-to-end: a clean revert undoes a commit as a
//! new forward commit, the reverted commit stays reachable, and the
//! conflict path records resumable state that `--abort` unwinds. Spawns
//! the real binary.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::fs;
use std::path::Path;
use std::process::Command;

fn mkit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_mkit")
}

fn run_in(cwd: &Path, args: &[&str]) -> std::process::Output {
    let xdg = tempfile::tempdir().expect("xdg tempdir");
    let out = Command::new(mkit_bin())
        .args(args)
        .current_dir(cwd)
        .env("XDG_CONFIG_HOME", xdg.path())
        .output()
        .expect("spawn mkit");
    drop(xdg);
    out
}

fn init_repo() -> tempfile::TempDir {
    let td = tempfile::tempdir().unwrap();
    assert!(run_in(td.path(), &["init"]).status.success());
    assert!(run_in(td.path(), &["keygen"]).status.success());
    td
}

fn commit(root: &Path, name: &str, content: &[u8], msg: &str) {
    fs::write(root.join(name), content).unwrap();
    assert!(run_in(root, &["add", name]).status.success(), "add {name}");
    assert!(
        run_in(root, &["commit", "-m", msg]).status.success(),
        "commit {msg}"
    );
}

fn main_tip(root: &Path) -> String {
    fs::read_to_string(root.join(".mkit/refs/heads/main"))
        .unwrap()
        .trim()
        .to_owned()
}

#[test]
fn revert_of_an_add_removes_the_file_as_a_new_commit() {
    let td = init_repo();
    let root = td.path();
    commit(root, "a.txt", b"a\n", "base");
    commit(root, "b.txt", b"b\n", "add b");
    let added = main_tip(root); // commit that added b.txt

    let out = run_in(root, &["revert", &added]);
    assert!(out.status.success(), "revert: {out:?}");

    // b.txt is gone from the worktree, a.txt remains.
    assert!(!root.join("b.txt").exists(), "revert should remove b.txt");
    assert!(root.join("a.txt").exists());

    // A NEW commit was made (HEAD moved forward), and the reverted commit
    // is still reachable (forward commit, not a rewrite).
    assert_ne!(main_tip(root), added, "revert creates a new commit");
    assert!(
        run_in(root, &["cat", &added]).status.success(),
        "reverted commit stays reachable"
    );

    // The revert commit message is the git-style `Revert "..."`.
    let log = run_in(root, &["log"]);
    let text = String::from_utf8_lossy(&log.stdout);
    assert!(
        text.contains("Revert \"add b\"") && text.contains("This reverts commit"),
        "revert message: {text}"
    );
}

#[test]
fn revert_conflict_records_state_and_abort_restores() {
    let td = init_repo();
    let root = td.path();
    commit(root, "a.txt", b"one\n", "base");
    commit(root, "a.txt", b"two\n", "change a"); // the commit we'll revert
    let target = main_tip(root);
    // Diverge a.txt again so reverting "change a" conflicts.
    commit(root, "a.txt", b"three\n", "change a again");
    let before = main_tip(root);

    let out = run_in(root, &["revert", &target]);
    assert!(!out.status.success(), "revert should conflict");
    assert!(
        root.join(".mkit/REVERT_HEAD").exists(),
        "conflict must record REVERT_HEAD"
    );

    // Abort restores HEAD and clears state.
    let ab = run_in(root, &["revert", "--abort"]);
    assert!(ab.status.success(), "revert --abort: {ab:?}");
    assert_eq!(main_tip(root), before, "abort restores HEAD");
    assert!(
        !root.join(".mkit/REVERT_HEAD").exists(),
        "abort clears REVERT_HEAD"
    );
    assert_eq!(
        fs::read(root.join("a.txt")).unwrap(),
        b"three\n",
        "worktree restored"
    );
}

#[test]
fn revert_continue_without_revert_in_progress_errors() {
    let td = init_repo();
    let root = td.path();
    commit(root, "a.txt", b"a\n", "base");
    let out = run_in(root, &["revert", "--continue"]);
    assert!(!out.status.success(), "no revert in progress must error");
}

#[test]
fn revert_no_commit_stages_without_committing() {
    let td = init_repo();
    let root = td.path();
    commit(root, "a.txt", b"a\n", "base");
    commit(root, "b.txt", b"b\n", "add b");
    let added = main_tip(root);

    let out = run_in(root, &["revert", "--no-commit", &added]);
    assert!(out.status.success(), "revert --no-commit: {out:?}");

    // The reverted change is applied to the worktree...
    assert!(
        !root.join("b.txt").exists(),
        "--no-commit still applies the revert"
    );
    // ...but HEAD did NOT move (no commit created).
    assert_eq!(
        main_tip(root),
        added,
        "--no-commit must not create a commit"
    );
}

#[test]
fn revert_refuses_a_merge_commit() {
    let td = init_repo();
    let root = td.path();
    commit(root, "base.txt", b"base\n", "base");
    assert!(run_in(root, &["branch", "feature"]).status.success());
    commit(root, "a.txt", b"a\n", "on main");
    assert!(run_in(root, &["checkout", "feature"]).status.success());
    commit(root, "b.txt", b"b\n", "on feature");
    assert!(run_in(root, &["checkout", "main"]).status.success());
    // Non-fast-forward merge → a real 2-parent merge commit.
    assert!(
        run_in(root, &["merge", "feature"]).status.success(),
        "merge"
    );
    let merge = main_tip(root);

    let out = run_in(root, &["revert", &merge]);
    assert!(
        !out.status.success(),
        "reverting a merge commit must be refused"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("merge commit"),
        "error should explain the merge-commit refusal: {stderr}"
    );
}
