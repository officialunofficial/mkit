//! Integration test for the history-MMR journal-lifecycle fix (issue
//! #648): `mkit branch -d`/`-D` must destroy the deleted branch's
//! `history/<branch>__*` journal partition, and `mkit branch -m` must
//! destroy the renamed-away OLD name's partition. Without this, a
//! branch recreated (or a name reused) after delete/rename would reopen
//! a dead incarnation's non-empty journal and resume appending on top
//! of its old leaves — the new branch's MMR root would then span two
//! unrelated incarnations, with stale leaves from the deleted branch
//! still producing valid-looking inclusion proofs "on this branch".
//!
//! This file is compiled only with `--features history-mmr` (a default
//! build has no history journal to inspect).

#![cfg(feature = "history-mmr")]
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;

use mkit_core::history::{CommitHistory, Position, TokioExecutor, verify_inclusion};
use mkit_core::layout::RepoLayout;
use mkit_core::refs;

fn mkit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_mkit")
}

fn run(cwd: &Path, args: &[&str]) -> Output {
    let xdg = tempfile::tempdir().expect("xdg");
    let out = Command::new(mkit_bin())
        .args(args)
        .current_dir(cwd)
        .env("XDG_CONFIG_HOME", xdg.path())
        .output()
        .expect("spawn mkit");
    drop(xdg);
    out
}

fn ok(cwd: &Path, args: &[&str]) -> Output {
    let out = run(cwd, args);
    assert!(
        out.status.success(),
        "mkit {:?} failed: stdout={} stderr={}",
        args,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    out
}

fn init_repo() -> tempfile::TempDir {
    let td = tempfile::tempdir().unwrap();
    ok(td.path(), &["init"]);
    ok(td.path(), &["keygen"]);
    td
}

fn write_file(root: &Path, rel: &str, body: &str) {
    let path = root.join(rel);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, body).unwrap();
}

fn commit_file(root: &Path, rel: &str, body: &str, message: &str) {
    write_file(root, rel, body);
    ok(root, &["add", rel]);
    ok(root, &["commit", "-m", message]);
}

fn mkit_dir(root: &Path) -> PathBuf {
    root.join(mkit_core::MKIT_DIR)
}

fn journal_blobs_path(root: &Path, sanitized_branch: &str) -> PathBuf {
    mkit_dir(root)
        .join("history")
        .join(format!("{sanitized_branch}__journal-blobs"))
}

fn open_history(root: &Path, branch: &str) -> CommitHistory<TokioExecutor> {
    let exec = Arc::new(TokioExecutor::new().expect("tokio runtime"));
    CommitHistory::open_at(exec, &RepoLayout::single(root), branch).expect("open history")
}

/// The core regression test (issue #648, TDD step 1): delete a branch
/// via `mkit branch -d`, create a NEW branch with the SAME name, and
/// advance it once. The new incarnation's on-disk journal must be
/// fresh — one leaf, not resuming the deleted incarnation's leaves.
#[test]
fn branch_delete_then_recreate_starts_a_fresh_journal() {
    let td = init_repo();
    let root = td.path();
    commit_file(root, "root.txt", "root\n", "root");

    // Branch "feature", advanced twice off main. `checkout -b` itself
    // appends one "branch creation" leaf (issue #206's `write_ref_recording_history`
    // Missing-CAS create), so two commits on top make three leaves total.
    ok(root, &["checkout", "-b", "feature"]);
    commit_file(root, "a.txt", "a\n", "a");
    commit_file(root, "b.txt", "b\n", "b");
    let feature_journal = journal_blobs_path(root, "feature");
    assert!(feature_journal.exists(), "journal must exist after appends");
    {
        let hist = open_history(root, "feature");
        assert_eq!(
            hist.len(),
            3,
            "branch creation + two commits on feature -> three leaves"
        );
    }

    // Switch away and delete "feature".
    ok(root, &["checkout", "main"]);
    ok(root, &["branch", "-d", "feature"]);
    assert_eq!(
        refs::read_ref(&RepoLayout::single(root), "feature").unwrap(),
        None,
        "branch ref must be gone"
    );
    assert!(
        !feature_journal.exists(),
        "branch -d must destroy the deleted branch's journal partition"
    );

    // Recreate a NEW branch also named "feature" and advance it once.
    // The new incarnation gets its own creation leaf + one commit leaf
    // (two total) — NOT the old incarnation's three leaves plus these
    // two, which is what resuming the dead incarnation's journal would
    // produce.
    ok(root, &["checkout", "-b", "feature"]);
    commit_file(root, "c.txt", "c\n", "c (new incarnation)");

    let hist = open_history(root, "feature");
    assert_eq!(
        hist.len(),
        2,
        "recreated branch's journal must contain only its OWN leaves \
         (creation + one commit), not resume the deleted incarnation's leaves"
    );
}

/// `mkit branch -m` must destroy the OLD name's journal partition, so a
/// later branch (re)using that name does not inherit it.
#[test]
fn branch_rename_destroys_the_old_names_journal() {
    let td = init_repo();
    let root = td.path();
    commit_file(root, "root.txt", "root\n", "root");

    ok(root, &["checkout", "-b", "old-name"]);
    commit_file(root, "a.txt", "a\n", "a");

    let old_journal = journal_blobs_path(root, "old-name");
    let new_journal = journal_blobs_path(root, "new-name");
    assert!(old_journal.exists());

    ok(root, &["branch", "-m", "old-name", "new-name"]);

    assert_eq!(
        refs::read_ref(&RepoLayout::single(root), "old-name").unwrap(),
        None
    );
    assert!(
        !old_journal.exists(),
        "branch -m must destroy the renamed-away OLD name's journal partition"
    );
    assert!(new_journal.exists(), "new name must have its own journal");

    let hist_new = open_history(root, "new-name");
    assert_eq!(
        hist_new.len(),
        1,
        "renamed branch's journal must seed fresh, exactly one leaf for the existing tip"
    );

    // Recreating "old-name" afterward must not resume the destroyed
    // incarnation's two leaves (creation + commit "a") — the new
    // incarnation gets its own creation leaf + one commit leaf only.
    ok(root, &["checkout", "main"]);
    ok(root, &["checkout", "-b", "old-name"]);
    commit_file(root, "d.txt", "d\n", "d (new old-name incarnation)");
    let hist_old_reopened = open_history(root, "old-name");
    assert_eq!(
        hist_old_reopened.len(),
        2,
        "the new 'old-name' incarnation must start fresh (its own creation + one \
         commit leaf), not resume the destroyed incarnation's leaves"
    );
}

/// End-to-end proof-splicing check: after delete + recreate, an
/// inclusion proof for a leaf appended under the OLD incarnation must
/// NOT verify against the NEW incarnation's root at any position.
#[test]
fn stale_leaves_from_a_deleted_branch_do_not_verify_against_the_recreated_branchs_root() {
    let td = init_repo();
    let root = td.path();
    commit_file(root, "root.txt", "root\n", "root");

    ok(root, &["checkout", "-b", "feature"]);
    commit_file(root, "a.txt", "a\n", "a");
    let old_tip = {
        let layout = RepoLayout::single(root);
        refs::read_ref(&layout, "feature").unwrap().unwrap()
    };

    ok(root, &["checkout", "main"]);
    ok(root, &["branch", "-d", "feature"]);
    ok(root, &["checkout", "-b", "feature"]);
    commit_file(root, "b.txt", "b\n", "b (new incarnation)");

    let hist_new = open_history(root, "feature");
    let root_new = hist_new.root();
    for pos in 0..hist_new.len() {
        let proof = hist_new.prove(Position(pos)).unwrap();
        assert!(
            !verify_inclusion(&old_tip, Position(pos), &proof, &root_new),
            "the deleted incarnation's leaf must not verify against the recreated branch's root"
        );
    }
}
