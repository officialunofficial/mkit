//! Integration tests for `mkit status` — verifies three-way grouping of
//! committed / staged / unstaged changes by spawning the real binary.

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
// 1. Clean working tree — nothing to report.
// -----------------------------------------------------------------------

#[test]
fn status_clean_working_tree() {
    let td = init_with_commit(&[("a.txt", b"hello")]);
    let out = run_in(td.path(), &["status"]);
    assert!(out.status.success(), "status failed: {out:?}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains("nothing to commit"),
        "expected clean output, got: {stdout}"
    );
}

// -----------------------------------------------------------------------
// 2. Untracked (worktree only) file shows as unstaged.
// -----------------------------------------------------------------------

#[test]
fn status_untracked_file_is_unstaged() {
    let td = init_with_commit(&[("a.txt", b"hello")]);
    fs::write(td.path().join("b.txt"), b"new").unwrap();
    let out = run_in(td.path(), &["status"]);
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains("b.txt"),
        "b.txt missing from status: {stdout}"
    );
    assert!(
        stdout.contains("not staged"),
        "expected 'not staged' section: {stdout}"
    );
}

// -----------------------------------------------------------------------
// 3. Staged file (add but not commit) shows in "Changes to be committed".
// -----------------------------------------------------------------------

#[test]
fn status_staged_file_shows_committed_section() {
    let td = init_with_commit(&[("a.txt", b"hello")]);
    fs::write(td.path().join("c.txt"), b"staged content").unwrap();
    assert!(run_in(td.path(), &["add", "c.txt"]).status.success());
    let out = run_in(td.path(), &["status"]);
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains("c.txt"),
        "c.txt missing from status: {stdout}"
    );
    assert!(
        stdout.contains("to be committed"),
        "expected staged section: {stdout}"
    );
}

// -----------------------------------------------------------------------
// 4. Modified committed file shows in status (staged or partially-staged,
// depending on whether the index still holds the committed snapshot).
// -----------------------------------------------------------------------

#[test]
fn status_modified_committed_file_appears_in_status() {
    let td = init_with_commit(&[("a.txt", b"original")]);
    fs::write(td.path().join("a.txt"), b"changed").unwrap();
    let out = run_in(td.path(), &["status"]);
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    // a.txt must appear somewhere in the status output.
    assert!(
        stdout.contains("a.txt"),
        "a.txt missing from status: {stdout}"
    );
    // The repo is NOT clean.
    assert!(
        !stdout.contains("nothing to commit"),
        "unexpectedly clean: {stdout}"
    );
}

// -----------------------------------------------------------------------
// 5. Three-state scenario: committed file modified + new file staged.
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

    let out = run_in(td.path(), &["status"]);
    assert!(out.status.success(), "status failed: {out:?}");
    let stdout = String::from_utf8(out.stdout).unwrap();

    // c.txt should be in the staged section (its index hash matches the worktree).
    assert!(
        stdout.contains("to be committed"),
        "expected staged section: {stdout}"
    );
    assert!(stdout.contains("c.txt"), "c.txt missing: {stdout}");

    // a.txt and b.txt must appear somewhere in the output.
    // They will be in 'partially staged' since the committed index holds
    // their old hashes but the worktree has different content.
    assert!(stdout.contains("a.txt"), "a.txt missing: {stdout}");
    assert!(stdout.contains("b.txt"), "b.txt missing: {stdout}");
}

// -----------------------------------------------------------------------
// 6. No HEAD (fresh init, nothing committed yet).
// -----------------------------------------------------------------------

#[test]
fn status_no_head_shows_all_as_changes() {
    let td = tempfile::tempdir().unwrap();
    assert!(run_in(td.path(), &["init"]).status.success());
    fs::write(td.path().join("x.txt"), b"content").unwrap();
    let out = run_in(td.path(), &["status"]);
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    // Should report x.txt somehow (not staged, since no index entry).
    assert!(
        stdout.contains("x.txt"),
        "x.txt missing from status: {stdout}"
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
    let out = run_in(p, &["status"]);
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        !stdout.contains("nothing to commit"),
        "status hid a staged change behind a worktree revert: {stdout}"
    );
    assert!(
        stdout.contains("a.txt"),
        "staged a.txt missing from status: {stdout}"
    );
    assert!(
        stdout.contains("Changes to be committed"),
        "expected staged-section header, got: {stdout}"
    );
}

#[test]
fn missing_index_with_clean_head_is_reported_clean() {
    let td = init_with_commit(&[("a.txt", b"v1")]);
    fs::remove_file(td.path().join(".mkit/index")).unwrap();

    let out = run_in(td.path(), &["status"]);
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains("nothing to commit"),
        "missing/empty index should not look like staged removals: {stdout}"
    );
    assert!(
        !stdout.contains("Changes to be committed"),
        "missing/empty index unexpectedly created staged changes: {stdout}"
    );
}
