//! #267 — root-publishing commands take the repo lock.
//!
//! `tag -a`/`-s`, `fetch`/`pull`, and `attest` write an object (or
//! attestation) before the ref/sidecar that makes it reachable, so they must
//! serialize against `gc` via the same `worktree.lock`. These tests hold that
//! lock from the test process and assert the object-writing publishers
//! (`tag -a`, `attest`) block and then fail with a lock error rather than
//! racing — proving they acquire it. (fetch/pull take the lock in
//! `remote_dispatch`; covered by the remote round-trip tests.)

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn mkit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_mkit")
}

fn run(cwd: &Path, xdg: &Path, args: &[&str]) -> Output {
    Command::new(mkit_bin())
        .args(args)
        .current_dir(cwd)
        .env("XDG_CONFIG_HOME", xdg)
        .output()
        .expect("spawn mkit")
}

fn ok(cwd: &Path, xdg: &Path, args: &[&str]) -> Output {
    let out = run(cwd, xdg, args);
    assert!(
        out.status.success(),
        "mkit {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

/// A repo with one commit and a signing key, plus the XDG dir to reuse.
fn repo_with_commit() -> (tempfile::TempDir, tempfile::TempDir) {
    let td = tempfile::tempdir().unwrap();
    let xdg = tempfile::tempdir().unwrap();
    ok(td.path(), xdg.path(), &["init"]);
    ok(td.path(), xdg.path(), &["keygen"]);
    fs::write(td.path().join("f.txt"), b"hi\n").unwrap();
    ok(td.path(), xdg.path(), &["add", "."]);
    ok(td.path(), xdg.path(), &["commit", "-m", "first"]);
    (td, xdg)
}

/// Assert a held repo lock makes `args` fail (busy → `exit::TEMPFAIL` 75)
/// with a lock diagnostic — i.e. the command acquired the lock.
fn assert_blocks_on_held_lock(args: &[&str]) {
    let (td, xdg) = repo_with_commit();
    let mkit_dir = td.path().join(".mkit");

    // Hold the same lock gc/the publishers use.
    let guard = mkit_core::repo_lock::acquire_default(&mkit_dir, "worktree.lock")
        .expect("acquire repo lock in test");

    let out = run(td.path(), xdg.path(), args);
    assert!(
        !out.status.success(),
        "mkit {args:?} should fail while the repo lock is held"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("repo lock") || stderr.contains("busy"),
        "expected a lock-contention error for {args:?}, got: {stderr}"
    );

    // Releasing the lock lets the same command succeed (no stale lock left).
    drop(guard);
    ok(td.path(), xdg.path(), args);
}

#[test]
fn annotated_tag_acquires_repo_lock() {
    assert_blocks_on_held_lock(&["tag", "-a", "v1.0.0", "-m", "release"]);
}

#[test]
fn attest_acquires_repo_lock() {
    assert_blocks_on_held_lock(&["attest"]);
}
