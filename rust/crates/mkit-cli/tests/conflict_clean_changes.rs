//! #269 regression: the conflict workflow must apply an operation's
//! *clean* (non-conflicting) changes to the index/worktree, and must
//! refuse `--continue` when a regular conflicted file was resolved in the
//! worktree but not staged. Exercised via cherry-pick (the shared
//! `materialize_conflicts` path is the same for merge/rebase/revert).
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

fn write(root: &Path, name: &str, content: &[u8]) {
    fs::write(root.join(name), content).unwrap();
}
fn commit_all(root: &Path, msg: &str) {
    assert!(run_in(root, &["add", "."]).status.success(), "add .");
    assert!(
        run_in(root, &["commit", "-m", msg]).status.success(),
        "commit {msg}"
    );
}
fn branch_tip(root: &Path, branch: &str) -> String {
    fs::read_to_string(root.join(format!(".mkit/refs/heads/{branch}")))
        .unwrap()
        .trim()
        .to_owned()
}

/// Build: main has base; `feature` modifies a.txt AND adds b.txt; main
/// modifies a.txt differently. Cherry-picking feature onto main conflicts
/// on a.txt while b.txt is a clean add. Returns the feature tip hash.
fn setup_conflict_with_clean_add(root: &Path) -> String {
    write(root, "a.txt", b"base\n");
    commit_all(root, "base");
    assert!(run_in(root, &["branch", "feature"]).status.success());

    // feature: change a.txt + add b.txt
    assert!(run_in(root, &["checkout", "feature"]).status.success());
    write(root, "a.txt", b"feature\n");
    write(root, "b.txt", b"added by feature\n");
    commit_all(root, "feature: change a, add b");
    let feature = branch_tip(root, "feature");

    // main: change a.txt differently
    assert!(run_in(root, &["checkout", "main"]).status.success());
    write(root, "a.txt", b"main\n");
    commit_all(root, "main: change a");
    feature
}

#[test]
fn continue_preserves_clean_changes_alongside_a_conflict() {
    let td = init_repo();
    let root = td.path();
    let feature = setup_conflict_with_clean_add(root);

    // Cherry-pick conflicts on a.txt; b.txt is a clean add.
    let out = run_in(root, &["cherry-pick", &feature]);
    assert!(
        !out.status.success(),
        "cherry-pick should conflict on a.txt"
    );

    // #269: the clean add must already be applied to the worktree (not
    // deferred until some later step that never staged it).
    assert!(
        root.join("b.txt").exists(),
        "clean add b.txt must be applied during conflict materialization"
    );

    // Resolve a.txt and stage it, then continue.
    write(root, "a.txt", b"resolved\n");
    assert!(run_in(root, &["add", "a.txt"]).status.success());
    let cont = run_in(root, &["cherry-pick", "--continue"]);
    assert!(cont.status.success(), "cherry-pick --continue: {cont:?}");

    // The committed result must include the clean add b.txt — the bug was
    // that it was silently dropped because only conflicted paths were
    // staged.
    assert!(
        root.join("b.txt").exists(),
        "b.txt present in worktree after continue"
    );
    let status = run_in(root, &["status", "--porcelain"]);
    let s = String::from_utf8_lossy(&status.stdout);
    assert!(
        !s.contains("b.txt"),
        "b.txt must be committed (clean status), not dangling untracked: {s}"
    );
}

#[test]
fn continue_refuses_resolved_but_unstaged_regular_file() {
    let td = init_repo();
    let root = td.path();
    let feature = setup_conflict_with_clean_add(root);

    let out = run_in(root, &["cherry-pick", &feature]);
    assert!(!out.status.success(), "cherry-pick should conflict");

    // Resolve a.txt in the worktree (markers removed) but FORGET to add.
    write(root, "a.txt", b"resolved\n");
    let cont = run_in(root, &["cherry-pick", "--continue"]);
    assert!(
        !cont.status.success(),
        "continue must refuse an unstaged resolution"
    );
    let err = String::from_utf8_lossy(&cont.stderr);
    assert!(
        err.contains("not staged") && err.contains("a.txt"),
        "error should name the unstaged path: {err}"
    );

    // Staging it then continuing works.
    assert!(run_in(root, &["add", "a.txt"]).status.success());
    assert!(
        run_in(root, &["cherry-pick", "--continue"])
            .status
            .success(),
        "continue succeeds once staged"
    );
}

#[test]
fn continue_refuses_unstaged_deletion_resolution() {
    let td = init_repo();
    let root = td.path();
    let feature = setup_conflict_with_clean_add(root);

    let out = run_in(root, &["cherry-pick", &feature]);
    assert!(!out.status.success(), "cherry-pick should conflict");

    // Resolve by DELETING the conflicted file, but forget `mkit rm` — the
    // stale staged ours-entry would otherwise be committed (#269 finding 1).
    fs::remove_file(root.join("a.txt")).unwrap();
    let cont = run_in(root, &["cherry-pick", "--continue"]);
    assert!(
        !cont.status.success(),
        "continue must refuse an unstaged deletion resolution"
    );
    let err = String::from_utf8_lossy(&cont.stderr);
    assert!(err.contains("a.txt"), "error should name the path: {err}");

    // `mkit rm` then continue succeeds (a.txt stays deleted).
    assert!(run_in(root, &["rm", "a.txt"]).status.success());
    assert!(
        run_in(root, &["cherry-pick", "--continue"])
            .status
            .success(),
        "continue succeeds once the deletion is staged"
    );
    assert!(
        !root.join("a.txt").exists(),
        "deletion resolution committed"
    );
}
