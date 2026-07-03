//! Integration tests for `mkit status` — verifies three-way grouping of
//! committed / staged / unstaged changes by spawning the real binary.
//!
//! Tests assert against `--porcelain` output (XY codes on stdout) rather
//! than the default human prose, which lives on stderr. The porcelain
//! contract is the long-term machine interface; the human format is
//! presentation-only and free to change.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::fs;
use std::process::Command;

fn mkit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_mkit")
}

fn run_in(cwd: &std::path::Path, args: &[&str]) -> std::process::Output {
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

/// Run `mkit status --porcelain` and return `(stdout, stderr)` as
/// owned strings. Asserts the command succeeded.
fn status_porcelain(cwd: &std::path::Path) -> (String, String) {
    let out = run_in(cwd, &["status", "--porcelain"]);
    assert!(out.status.success(), "status --porcelain failed: {out:?}");
    (
        String::from_utf8(out.stdout).expect("stdout utf-8"),
        String::from_utf8(out.stderr).expect("stderr utf-8"),
    )
}

/// True iff some line in `out` has both the given XY code (first two
/// chars) and the given path (tail after the single space separator).
fn has_entry(out: &str, code: &str, path: &str) -> bool {
    let target = format!("{code} {path}");
    out.lines().any(|l| l == target)
}

/// Initialise a fresh repo and make an initial commit containing `files`.
/// Returns the temp dir (kept alive via the returned handle).
fn init_with_commit(files: &[(&str, &[u8])]) -> tempfile::TempDir {
    let td = tempfile::tempdir().unwrap();
    assert!(run_in(td.path(), &["init"]).status.success());
    // explicit keygen required.
    assert!(run_in(td.path(), &["keygen"]).status.success());
    for (name, content) in files {
        fs::write(td.path().join(name), content).unwrap();
        assert!(
            run_in(td.path(), &["add", name]).status.success(),
            "add {name} failed"
        );
    }
    assert!(
        run_in(td.path(), &["commit", "-m", "initial"])
            .status
            .success(),
        "commit failed"
    );
    td
}

// -----------------------------------------------------------------------
// 1. Clean working tree — empty stdout.
// -----------------------------------------------------------------------

#[test]
fn status_clean_working_tree() {
    let td = init_with_commit(&[("a.txt", b"hello")]);
    let (stdout, _stderr) = status_porcelain(td.path());
    assert!(
        stdout.is_empty(),
        "expected empty porcelain output for clean tree, got: {stdout:?}"
    );
}

#[test]
fn status_reports_invalid_index_instead_of_falling_back_to_worktree() {
    use mkit_core::hash::ZERO;
    use mkit_core::index::{EntryStatus, Index, IndexEntry};

    let td = tempfile::tempdir().unwrap();
    let p = td.path();
    assert!(run_in(p, &["init"]).status.success());

    let mut idx = Index::new();
    idx.entries.push(IndexEntry {
        path: "same.txt".into(),
        status: EntryStatus::Blob,
        object_hash: ZERO,
        mtime_ns: 0,
        size: 0,
        ino: 0,
        ctime_ns: 0,
    });
    idx.entries.push(IndexEntry {
        path: "same.txt".into(),
        status: EntryStatus::Blob,
        object_hash: ZERO,
        mtime_ns: 0,
        size: 0,
        ino: 0,
        ctime_ns: 0,
    });
    fs::write(p.join(".mkit/index"), idx.serialize()).unwrap();

    let out = run_in(p, &["status", "--porcelain"]);
    assert!(!out.status.success(), "status must reject invalid index");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("read index") && stderr.contains("duplicate index path"),
        "status should surface the index integrity error, got: {stderr}"
    );
}

#[cfg(unix)]
#[test]
fn status_clean_for_committed_executable_that_remains_executable() {
    use std::os::unix::fs::PermissionsExt;

    let td = tempfile::tempdir().unwrap();
    let p = td.path();
    assert!(run_in(p, &["init"]).status.success());
    assert!(run_in(p, &["keygen"]).status.success());

    let script = p.join("run.sh");
    fs::write(&script, b"#!/bin/sh\n").unwrap();
    let mut perms = fs::metadata(&script).unwrap().permissions();
    perms.set_mode(perms.mode() | 0o111);
    fs::set_permissions(&script, perms).unwrap();

    assert!(run_in(p, &["add", "run.sh"]).status.success());
    assert!(
        run_in(p, &["commit", "-m", "add executable"])
            .status
            .success()
    );

    let (stdout, _stderr) = status_porcelain(p);
    assert!(
        stdout.is_empty(),
        "executable mode should remain clean after commit, got: {stdout:?}"
    );
}

// -----------------------------------------------------------------------
// 2. Untracked file appears as `??`.
// -----------------------------------------------------------------------

#[test]
fn status_untracked_file_is_unstaged() {
    let td = init_with_commit(&[("a.txt", b"hello")]);
    fs::write(td.path().join("b.txt"), b"new").unwrap();
    let (stdout, _) = status_porcelain(td.path());
    assert!(
        has_entry(&stdout, "??", "b.txt"),
        "b.txt should be ?? (untracked); got: {stdout:?}"
    );
}

// -----------------------------------------------------------------------
// 3. Staged new file appears as `A ` (X=A, Y=space).
// -----------------------------------------------------------------------

#[test]
fn status_staged_file_shows_committed_section() {
    let td = init_with_commit(&[("a.txt", b"hello")]);
    fs::write(td.path().join("c.txt"), b"staged content").unwrap();
    assert!(run_in(td.path(), &["add", "c.txt"]).status.success());
    let (stdout, _) = status_porcelain(td.path());
    assert!(
        has_entry(&stdout, "A ", "c.txt"),
        "c.txt should be `A ` (staged-added); got: {stdout:?}"
    );
}

// -----------------------------------------------------------------------
// 4. Modified committed file appears in status (somewhere — either
//    staged or unstaged depending on index state).
// -----------------------------------------------------------------------

#[test]
fn status_modified_committed_file_appears_in_status() {
    let td = init_with_commit(&[("a.txt", b"original")]);
    fs::write(td.path().join("a.txt"), b"changed").unwrap();
    let (stdout, _) = status_porcelain(td.path());
    // a.txt was modified in the worktree but not staged → ` M`.
    assert!(
        has_entry(&stdout, " M", "a.txt"),
        "a.txt should be ` M` (unstaged-modified); got: {stdout:?}"
    );
}

// -----------------------------------------------------------------------
// 5. Three-state scenario: modified, newly-staged, deleted.
// -----------------------------------------------------------------------

#[test]
fn status_three_states() {
    // Start: a.txt committed, b.txt committed.
    let td = init_with_commit(&[("a.txt", b"alpha"), ("b.txt", b"beta")]);

    // Modify a.txt (unstaged).
    fs::write(td.path().join("a.txt"), b"alpha modified").unwrap();

    // Stage a new file c.txt.
    fs::write(td.path().join("c.txt"), b"gamma").unwrap();
    assert!(run_in(td.path(), &["add", "c.txt"]).status.success());

    // Remove b.txt from disk (worktree deletion, unstaged).
    fs::remove_file(td.path().join("b.txt")).unwrap();

    let (stdout, _) = status_porcelain(td.path());

    assert!(
        has_entry(&stdout, "A ", "c.txt"),
        "c.txt should be `A ` (staged-added); got: {stdout:?}"
    );
    // a.txt was modified, not staged → ` M`.
    assert!(
        has_entry(&stdout, " M", "a.txt"),
        "a.txt should be ` M` (unstaged-modified); got: {stdout:?}"
    );
    // b.txt was deleted from worktree, not staged → ` D`.
    assert!(
        has_entry(&stdout, " D", "b.txt"),
        "b.txt should be ` D` (unstaged-deleted); got: {stdout:?}"
    );
}

// -----------------------------------------------------------------------
// 6. No HEAD (fresh init, nothing committed yet).
// -----------------------------------------------------------------------

#[test]
fn status_no_head_shows_all_as_changes() {
    let td = tempfile::tempdir().unwrap();
    assert!(run_in(td.path(), &["init"]).status.success());
    fs::write(td.path().join("x.txt"), b"content").unwrap();
    let (stdout, _) = status_porcelain(td.path());
    assert!(
        stdout.lines().any(|l| l.ends_with(" x.txt")),
        "x.txt missing from status: {stdout:?}"
    );
}

/// Reviewer finding 3 (PR #103): `mkit commit` now signs HEAD↔index,
/// but `mkit status` was still computing HEAD↔worktree. A user who
/// stages a change and then reverts the worktree to match HEAD would
/// see "nothing to commit" while `mkit commit` happily commits the
/// staged-but-no-longer-on-disk content. Status must show the staged
/// change.
#[test]
fn staged_change_remains_visible_after_worktree_revert() {
    let td = init_with_commit(&[("a.txt", b"v1")]);
    let p = td.path();

    // Stage a new version.
    fs::write(p.join("a.txt"), b"v2").unwrap();
    assert!(run_in(p, &["add", "a.txt"]).status.success());

    // Now revert the worktree to v1 (matches HEAD).
    fs::write(p.join("a.txt"), b"v1").unwrap();

    // Status MUST surface the staged delta — the index still has v2.
    // Per git porcelain, this is one combined record `MM a.txt`: X=M is
    // the staged (index-vs-HEAD) change, Y=M is the worktree-vs-index
    // change (the revert). The staged side stays visible in column X.
    let (stdout, _) = status_porcelain(p);
    assert!(
        !stdout.is_empty(),
        "status hid a staged change behind a worktree revert"
    );
    assert!(
        has_entry(&stdout, "MM", "a.txt"),
        "expected combined `MM` (staged M in X) for a.txt; got: {stdout:?}"
    );
}

#[test]
fn missing_index_with_clean_head_is_reported_clean() {
    let td = init_with_commit(&[("a.txt", b"v1")]);
    fs::remove_file(td.path().join(".mkit/index")).unwrap();

    let (stdout, _) = status_porcelain(td.path());
    assert!(
        stdout.is_empty(),
        "missing/empty index should not look like staged removals: {stdout:?}"
    );
}

// -----------------------------------------------------------------------
// Default-mode behaviour: human prose goes to stderr, stdout stays
// empty when porcelain isn't requested. This pins the contract that
// `mkit status > /tmp/out` produces an empty file in clean state.
// -----------------------------------------------------------------------

// -----------------------------------------------------------------------
// `-s` / `--short` is an alias for `--porcelain`: identical stdout.
// -----------------------------------------------------------------------

#[test]
fn short_flag_matches_porcelain() {
    let td = init_with_commit(&[("a.txt", b"v1")]);
    // Create an unstaged edit + an untracked file so output is non-empty.
    fs::write(td.path().join("a.txt"), b"v2").unwrap();
    fs::write(td.path().join("new.txt"), b"x").unwrap();

    let porc = run_in(td.path(), &["status", "--porcelain"]);
    let short_s = run_in(td.path(), &["status", "-s"]);
    let short_long = run_in(td.path(), &["status", "--short"]);
    assert!(porc.status.success() && short_s.status.success() && short_long.status.success());

    let porc_out = String::from_utf8(porc.stdout).unwrap();
    assert_eq!(
        String::from_utf8(short_s.stdout).unwrap(),
        porc_out,
        "`-s` stdout must match `--porcelain`"
    );
    assert_eq!(
        String::from_utf8(short_long.stdout).unwrap(),
        porc_out,
        "`--short` stdout must match `--porcelain`"
    );
    assert!(
        has_entry(&porc_out, " M", "a.txt") && has_entry(&porc_out, "??", "new.txt"),
        "expected non-empty short/porcelain output, got: {porc_out:?}"
    );
}

#[test]
fn default_mode_writes_prose_to_stderr_not_stdout() {
    let td = init_with_commit(&[("a.txt", b"hello")]);
    let out = run_in(td.path(), &["status"]);
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stdout.is_empty(),
        "default-mode `mkit status` must not write to stdout (got: {stdout:?})"
    );
    assert!(
        stderr.contains("nothing to commit"),
        "default-mode prose should be on stderr (got: {stderr:?})"
    );
}
