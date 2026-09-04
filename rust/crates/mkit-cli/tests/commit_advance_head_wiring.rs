//! Issue #658, Fix B — regression tests for `commit.rs`'s `expected_tip`
//! wiring (the value `run` hands to `advance_head` as the CAS
//! precondition per commit mode). `commands::commit::advance_head_tests`
//! (a `mkit-cli` unit test module) already proves the CAS MECHANISM
//! itself refuses a stale advance; these tests instead pin down that
//! `run` feeds it the RIGHT value for two specific, easy-to-get-wrong
//! modes:
//!
//! - **merge-conclusion**: the issue explicitly warns against reusing
//!   `parents[0]` (`state.orig_head`) here — that value is deliberately
//!   decoupled from live HEAD (see `commit.rs`'s parent-selection
//!   comment), so a merge concluded after something else moved the
//!   branch is INTENDED to succeed, not spuriously conflict. If Fix B
//!   were wired to the wrong variable, this would incorrectly abort.
//! - **plain commit**: confirms a branch moved during message
//!   composition (before the lock, so already-expected to be picked up
//!   fresh) still lands cleanly with `advance_head`'s CAS aligned to
//!   that fresh read, not a stale one.
//!
//! `branch_rename_commit_race.rs` covers the live-race / TEMPFAIL side
//! end-to-end.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;

use common::Repo;
use mkit_core::hash::to_hex;
use mkit_core::layout::RepoLayout;
use mkit_core::object::Object;
use mkit_core::refs;
use mkit_core::store::ObjectStore;

/// Write a POSIX shell script that sleeps `sleep_secs`, runs `extra`
/// (already-shell-escaped, empty for none), then overwrites its one
/// argument (the tempfile path) with `payload`. Mirrors
/// `commit_lock_scope.rs`'s `write_slow_editor_script`, extended with an
/// arbitrary extra command run mid-sleep.
fn write_editor_script(
    sleep_secs: f64,
    extra: &str,
    payload: &str,
) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("editor.sh");
    let script =
        format!("#!/bin/sh\nsleep {sleep_secs}\n{extra}\nprintf '%s' \"{payload}\" > \"$1\"\n");
    fs::write(&path, script).unwrap();
    let mut perms = fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&path, perms).unwrap();
    (dir, path)
}

/// Merge-conclusion mode: `merge --no-commit` leaves `main` at its
/// pre-merge tip (`ORIG_HEAD`) with `MERGE_HEAD`/`MERGE_MSG` sidecars
/// staged. Before running the concluding `commit`, move `main` (via
/// `update-ref`, the same "deliberately skips higher-level locks"
/// primitive `refs.rs`'s docs cite) to an unrelated-but-valid object —
/// simulating "something else advanced the branch between merge-start
/// and merge-conclude" (the existing "e.g. a reset" scenario the
/// parent-selection comment already treats as legitimate, unchanged by
/// #658).
///
/// If Fix B's `expected_tip` for this mode were wired to `parents[0]`
/// (`state.orig_head`, the PRE-merge tip) instead of a fresh
/// `resolve_head` read, this commit would spuriously CAS-fail
/// (`Match(orig_head)` against a ref that no longer holds it) and exit
/// `TEMPFAIL` even though nothing is actually racing here — a real
/// regression this test catches.
#[test]
fn merge_conclusion_commit_succeeds_after_branch_moved_since_merge_started() {
    let repo = Repo::new();
    repo.commit_file("base.txt", b"base\n", "base");
    repo.ok(&["branch", "feature"]);
    repo.ok(&["checkout", "feature"]);
    repo.commit_file("feature.txt", b"feature\n", "feature commit");
    repo.ok(&["checkout", "main"]);
    repo.commit_file("main.txt", b"main\n", "main commit");

    let layout = RepoLayout::single(repo.path());
    let orig_head = refs::read_ref(&layout, "main").unwrap().unwrap();
    let feature_tip = refs::read_ref(&layout, "feature").unwrap().unwrap();

    // Clean (non-conflicting: disjoint files) merge, left uncommitted.
    repo.ok(&["merge", "--no-commit", "feature"]);
    assert_eq!(
        refs::read_ref(&layout, "main").unwrap().unwrap(),
        orig_head,
        "merge --no-commit must not itself move the branch ref"
    );

    // Simulate a concurrent mover: `main` now points at `feature`'s tip
    // instead of `orig_head` — an arbitrary-but-valid existing object,
    // standing in for "some other commit landed here meanwhile".
    let out = repo.run(&[
        "update-ref",
        "refs/heads/main",
        &to_hex(&feature_tip),
        &to_hex(&orig_head),
    ]);
    assert!(
        out.status.success(),
        "setup: update-ref should move main: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        refs::read_ref(&layout, "main").unwrap().unwrap(),
        feature_tip
    );

    // Conclude the merge. No `-m`/`-F` needed: the merge's own recorded
    // message is used, so no `$EDITOR` is spawned here.
    let commit_out = repo.run(&["commit"]);
    assert!(
        commit_out.status.success(),
        "merge-conclusion commit must succeed (the branch move is a legitimate, \
         non-racing prior event, not a live conflict) — got: {}",
        String::from_utf8_lossy(&commit_out.stderr)
    );

    // The resulting merge commit's parents must be the ORIGINAL merge
    // pair (orig_head, feature_tip) — proving the CAS precondition used
    // a fresh HEAD read (which happened to already equal `feature_tip`)
    // rather than corrupting the parent list itself.
    let store = ObjectStore::open(&layout).unwrap();
    let new_tip = refs::read_ref(&layout, "main").unwrap().unwrap();
    match store.read_object(&new_tip).unwrap() {
        Object::Commit(c) => {
            assert_eq!(
                c.parents,
                vec![orig_head, feature_tip],
                "merge commit's parents must be [orig_head, merge_head], unaffected by Fix B"
            );
        }
        other => panic!("expected a commit at the new tip, got {other:?}"),
    }
}

/// Plain-commit mode: a branch move that lands during `$EDITOR`
/// composition (before `commit` takes its write lock) is ALREADY
/// expected to be picked up fresh by the existing (pre-#658) parent
/// read — this pins that Fix B's `expected_tip` stays aligned with that
/// same fresh read (not some earlier snapshot), so the commit still
/// lands cleanly rather than spuriously CAS-failing against a value
/// nothing actually still holds.
#[test]
fn plain_commit_succeeds_and_builds_on_a_branch_moved_during_message_composition() {
    let repo = Repo::new();
    repo.commit_file("base.txt", b"base\n", "base");
    repo.ok(&["branch", "other"]);
    repo.ok(&["checkout", "other"]);
    repo.commit_file("other.txt", b"other\n", "other commit");
    repo.ok(&["checkout", "main"]);

    let layout = RepoLayout::single(repo.path());
    let t0 = refs::read_ref(&layout, "main").unwrap().unwrap();
    let moved = refs::read_ref(&layout, "other").unwrap().unwrap();

    repo.write("f.txt", b"staged\n");
    repo.ok(&["add", "f.txt"]);

    // The editor script moves `main` (via `update-ref`, bypassing
    // `commit`'s own lock entirely) mid-composition, then supplies the
    // commit message.
    let extra = format!(
        "\"{}\" update-ref refs/heads/main {} {} || exit 1",
        env!("CARGO_BIN_EXE_mkit"),
        to_hex(&moved),
        to_hex(&t0),
    );
    let (_script_dir, script) = write_editor_script(0.2, &extra, "plain-commit-after-move");

    let out = repo.run_env(
        &["commit"],
        &[
            ("EDITOR", script.to_str().unwrap()),
            ("VISUAL", script.to_str().unwrap()),
            ("GIT_EDITOR", script.to_str().unwrap()),
        ],
    );
    assert!(
        out.status.success(),
        "plain commit must succeed after a pre-lock branch move: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let store = ObjectStore::open(&layout).unwrap();
    let new_tip = refs::read_ref(&layout, "main").unwrap().unwrap();
    match store.read_object(&new_tip).unwrap() {
        Object::Commit(c) => {
            assert_eq!(
                c.parents,
                vec![moved],
                "the commit must build on the MOVED value (fresh read), not the stale t0"
            );
        }
        other => panic!("expected a commit at the new tip, got {other:?}"),
    }
}
