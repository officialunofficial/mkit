//! Issue #641 — `mkit commit`'s interactive message composition
//! (`$EDITOR`) and signer/key loading must happen OUTSIDE the write
//! lock (`worktree.lock`); the lock should be held only around the
//! actual index/ref mutation.
//!
//! These are integration-style tests (real `mkit` binary) because the
//! behavior spans `commit.rs`'s whole control flow, not one function.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use std::time::Duration;

use common::Repo;

/// Write a POSIX shell script that sleeps `sleep_secs`, then overwrites
/// its one argument (the tempfile path) with `payload`. Marks it
/// executable and returns its path; the returned [`tempfile::TempDir`]
/// must be kept alive by the caller for the script's lifetime.
fn write_slow_editor_script(
    sleep_secs: f64,
    payload: &str,
) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("slow-editor.sh");
    let script = format!("#!/bin/sh\nsleep {sleep_secs}\nprintf '%s' \"{payload}\" > \"$1\"\n");
    fs::write(&path, script).unwrap();
    let mut perms = fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&path, perms).unwrap();
    (dir, path)
}

/// While `mkit commit` (no `-m`) is blocked inside its stubbed `$EDITOR`,
/// a concurrent lock-acquire attempt on `worktree.lock` (the same lock
/// `mkit commit` itself takes) must succeed promptly. Before the #641
/// fix, `commit.rs` acquires the lock BEFORE spawning `$EDITOR`, so this
/// acquire attempt is `Busy` until the editor exits; after the fix, the
/// lock is not taken until the message (and signer) are already
/// resolved, so the window is free.
#[test]
fn editor_window_does_not_hold_the_write_lock() {
    let repo = Repo::new();
    repo.write("hello.txt", b"hi\n");
    repo.ok(&["add", "."]);

    // Editor takes long enough that the test reliably samples the
    // lock state while it's still "open", without making the suite slow.
    let (_script_dir, script) = write_slow_editor_script(1.5, "commit-from-slow-editor");

    let repo_path = repo.path().to_path_buf();
    let xdg_path = repo.xdg().to_path_buf();
    let script_owned = script.clone();
    let commit_thread = std::thread::spawn(move || {
        Command::new(env!("CARGO_BIN_EXE_mkit"))
            .args(["commit"])
            .current_dir(&repo_path)
            .env("XDG_CONFIG_HOME", &xdg_path)
            .env("HOME", &xdg_path)
            .env("EDITOR", &script_owned)
            .env_remove("GIT_EDITOR")
            .env_remove("VISUAL")
            .output()
            .expect("spawn mkit commit")
    });

    // Give `mkit commit` time to get past open/config/message-precondition
    // work and into the editor sleep, well before the editor's 1.5s is up.
    std::thread::sleep(Duration::from_millis(400));

    // Try to take the SAME lock `mkit commit` itself takes
    // (`.mkit/worktree.lock`, see `acquire_worktree_lock` in
    // `commands/mod.rs`), with a short timeout so the test stays fast.
    // Success here means nothing currently holds it.
    let acquire_result = mkit_core::repo_lock::acquire(
        &repo.mkit_dir(),
        "worktree.lock",
        Duration::from_millis(300),
    );
    let acquired = acquire_result.is_ok();
    // Release immediately (if taken) so `mkit commit`'s own later lock
    // acquisition (for the actual write) is never blocked by the test
    // itself holding this guard across the `join()` below.
    drop(acquire_result);

    let out = commit_thread.join().expect("commit thread panicked");
    assert!(
        out.status.success(),
        "mkit commit should still succeed: stdout={}, stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("commit-from-slow-editor"),
        "expected the editor-supplied message to land, got: {stderr}"
    );

    assert!(
        acquired,
        "worktree.lock was held while `$EDITOR` was still open — the write lock's \
         scope must not cover interactive message composition (issue #641)"
    );
}

/// Same scenario, but through the full CLI path rather than the lock
/// primitive directly: a second, genuinely mutating command
/// (`mkit tag`, which itself calls `acquire_worktree_lock` with the
/// normal 5s timeout — see `commands/mod.rs`) must complete promptly
/// while `mkit commit`'s `$EDITOR` is open, rather than blocking until
/// the editor exits (or, in the worst case, timing out).
///
/// This mirrors the issue's testing decision #1: "stub `$EDITOR` with a
/// script that sleeps briefly, then concurrently run a second
/// lightweight command ... and assert it succeeds promptly rather than
/// blocking or timing out."
#[test]
fn concurrent_tag_completes_promptly_during_editor_window() {
    let repo = Repo::new();
    // A base commit so HEAD exists and `tag` has something to point at.
    repo.commit_file("base.txt", b"base\n", "base");
    repo.write("hello.txt", b"hi\n");
    repo.ok(&["add", "."]);

    let (_script_dir, script) = write_slow_editor_script(1.5, "commit-from-slow-editor-2");

    let repo_path = repo.path().to_path_buf();
    let xdg_path = repo.xdg().to_path_buf();
    let script_owned = script.clone();
    let commit_thread = std::thread::spawn(move || {
        Command::new(env!("CARGO_BIN_EXE_mkit"))
            .args(["commit"])
            .current_dir(&repo_path)
            .env("XDG_CONFIG_HOME", &xdg_path)
            .env("HOME", &xdg_path)
            .env("EDITOR", &script_owned)
            .env_remove("GIT_EDITOR")
            .env_remove("VISUAL")
            .output()
            .expect("spawn mkit commit")
    });

    // `commit_file` in the setup above already created a base commit, so
    // HEAD exists and `tag` has something to point at.
    std::thread::sleep(Duration::from_millis(400));

    let start = std::time::Instant::now();
    let tag_out = repo.run(&["tag", "concurrent-probe"]);
    let elapsed = start.elapsed();
    assert!(
        tag_out.status.success(),
        "tag should succeed promptly, not block on the editor window: stderr={}",
        String::from_utf8_lossy(&tag_out.stderr)
    );
    assert!(
        elapsed < Duration::from_millis(800),
        "tag took {elapsed:?} while `mkit commit`'s $EDITOR was open — it looks like it \
         waited out (part of) the editor window instead of running unobstructed (issue #641)"
    );

    let out = commit_thread.join().expect("commit thread panicked");
    assert!(out.status.success(), "mkit commit should still succeed");
}
