//! `mkit gc` (#233) end-to-end: prunes unreachable objects, honors
//! `--dry-run` and the grace window, and never reclaims a commit that the
//! recovery log pins (the amend/reset/rebase safety net). Spawns the real
//! binary.

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

/// Write an unreferenced blob via `mkit hash`; returns its 64-hex id.
fn orphan_blob(root: &Path, content: &[u8]) -> String {
    fs::write(root.join("orphan.bin"), content).unwrap();
    let out = run_in(root, &["hash", "orphan.bin"]);
    assert!(out.status.success(), "hash: {out:?}");
    let h = String::from_utf8(out.stdout).unwrap().trim().to_owned();
    // Remove the worktree file so it isn't picked up as untracked content;
    // the stored blob object is now unreferenced.
    fs::remove_file(root.join("orphan.bin")).unwrap();
    h
}

fn object_exists(root: &Path, hex: &str) -> bool {
    run_in(root, &["cat", hex]).status.success()
}

#[test]
fn gc_prunes_unreachable_blob_with_zero_grace() {
    let td = init_repo();
    let root = td.path();
    commit(root, "a.txt", b"live\n", "live");
    let orphan = orphan_blob(root, b"orphan contents\n");
    assert!(object_exists(root, &orphan), "orphan present before gc");

    let out = run_in(root, &["gc", "--grace-secs", "0"]);
    assert!(out.status.success(), "gc: {out:?}");

    assert!(
        !object_exists(root, &orphan),
        "gc must prune the unreachable blob"
    );
    // The live history is intact.
    let log = run_in(root, &["log", "--oneline"]);
    assert!(
        String::from_utf8_lossy(&log.stdout).contains("live"),
        "gc must not touch live history"
    );
}

#[test]
fn gc_dry_run_keeps_everything() {
    let td = init_repo();
    let root = td.path();
    commit(root, "a.txt", b"live\n", "live");
    let orphan = orphan_blob(root, b"orphan\n");

    let out = run_in(root, &["gc", "--dry-run", "--grace-secs", "0"]);
    assert!(out.status.success(), "gc --dry-run: {out:?}");
    assert!(
        object_exists(root, &orphan),
        "dry run must not delete the orphan"
    );
}

#[test]
fn gc_grace_window_keeps_recent_orphan() {
    let td = init_repo();
    let root = td.path();
    commit(root, "a.txt", b"live\n", "live");
    let orphan = orphan_blob(root, b"recent\n");

    // Default 14-day grace: the just-written orphan is too young to prune.
    let out = run_in(root, &["gc"]);
    assert!(out.status.success(), "gc: {out:?}");
    assert!(
        object_exists(root, &orphan),
        "default grace window must keep a freshly-written orphan"
    );
}

#[test]
fn gc_does_not_prune_recovery_logged_commit() {
    let td = init_repo();
    let root = td.path();
    commit(root, "a.txt", b"one\n", "one");
    let superseded = fs::read_to_string(root.join(".mkit/refs/heads/main"))
        .unwrap()
        .trim()
        .to_owned();

    // amend records the old HEAD in the recovery log.
    assert!(
        run_in(root, &["commit", "--amend", "-m", "one-amended"])
            .status
            .success(),
        "amend"
    );
    assert_ne!(
        fs::read_to_string(root.join(".mkit/refs/heads/main"))
            .unwrap()
            .trim(),
        superseded,
        "amend moved the branch"
    );

    // Even with grace 0, the superseded commit is pinned by the recovery
    // log and must survive gc.
    let out = run_in(root, &["gc", "--grace-secs", "0"]);
    assert!(out.status.success(), "gc: {out:?}");
    assert!(
        object_exists(root, &superseded),
        "gc must not prune a commit pinned by the recovery log"
    );
}
