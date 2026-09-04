//! Regression tests for MKIT-11: `mkit serve` holds a shared kernel
//! lock on `<common_dir>/serve.lock` for its whole lifetime, and local
//! worktree-mutating commands (`commit`, `gc`, ...) probe that lock and
//! warn on stderr when at least one `serve` is alive against the same
//! root. See `docs/specs/SPEC-CONCURRENCY.md` §3.1 and
//! `docs/INVARIANTS.md`.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::fs;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

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

fn init_repo(td: &Path) {
    assert!(run_in(td, &["init"]).status.success());
    assert!(run_in(td, &["keygen"]).status.success());
}

fn make_commit(td: &Path, file: &str, body: &[u8], msg: &str) {
    fs::write(td.join(file), body).unwrap();
    assert!(run_in(td, &["add", file]).status.success());
    let out = run_in(td, &["commit", "-m", msg]);
    assert!(out.status.success(), "commit failed: {out:?}");
}

/// Spawn `mkit serve <root>` with a piped, never-written stdin so it
/// blocks forever inside the handshake's `read_frame` — keeping the
/// process (and therefore its `serve.lock` hold) alive until the test
/// drops its stdin handle.
fn spawn_serve_blocked_in_handshake(root: &Path) -> Child {
    Command::new(mkit_bin())
        .args(["serve", root.to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mkit serve")
}

/// Poll `mkit_core::repo_lock::probe_exclusive` until it reports the
/// lock busy (a live `serve` holds it) or the deadline passes, returning
/// whether it became busy in time. Polling (rather than a fixed sleep)
/// keeps the test fast on a quiet machine and robust on a slow one.
fn wait_until_serve_lock_busy(mkit_dir: &Path, deadline: Duration) -> bool {
    let start = Instant::now();
    loop {
        match mkit_core::repo_lock::probe_exclusive(mkit_dir, "serve.lock") {
            Ok(false) => return true, // busy: something holds it
            Ok(true) => {}            // still free, keep polling
            Err(e) => panic!("probe_exclusive failed: {e}"),
        }
        if start.elapsed() > deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

const SERVE_MARKER: &str = "is currently being served by `mkit serve`";

#[test]
fn serve_holds_shared_lock_while_alive() {
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    let mkit_dir = td.path().join(".mkit");

    let mut child = spawn_serve_blocked_in_handshake(td.path());

    assert!(
        wait_until_serve_lock_busy(&mkit_dir, Duration::from_secs(5)),
        "serve.lock must become busy while `mkit serve` is alive"
    );
    // A blocking `acquire` (exclusive) must also observe the busy lock,
    // not merely the non-blocking probe.
    let err = mkit_core::repo_lock::acquire(&mkit_dir, "serve.lock", Duration::from_millis(200))
        .unwrap_err();
    assert!(matches!(err, mkit_core::repo_lock::LockError::Busy(_)));

    // Let the child exit gracefully (EOF on stdin fails the handshake).
    drop(child.stdin.take());
    let status = child.wait().expect("wait for serve");
    assert!(status.code().is_some());

    // The kernel releases the lock the moment the process's fds close.
    let lock = mkit_core::repo_lock::acquire(&mkit_dir, "serve.lock", Duration::from_secs(2))
        .expect("serve.lock must be free once `mkit serve` has exited");
    drop(lock);
}

#[test]
fn commit_warns_when_root_is_being_served() {
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    let mkit_dir = td.path().join(".mkit");

    let mut child = spawn_serve_blocked_in_handshake(td.path());
    assert!(
        wait_until_serve_lock_busy(&mkit_dir, Duration::from_secs(5)),
        "serve.lock must become busy before running the local command"
    );

    fs::write(td.path().join("a.txt"), b"hello\n").unwrap();
    assert!(run_in(td.path(), &["add", "a.txt"]).status.success());
    let out = run_in(td.path(), &["commit", "-m", "c1"]);
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        out.status.success(),
        "commit must still succeed (warn, not refuse): {out:?}"
    );
    assert!(
        stderr.contains(SERVE_MARKER),
        "expected the serve-guard warning on stderr, got: {stderr}"
    );

    drop(child.stdin.take());
    let _ = child.wait();
}

#[test]
fn gc_warns_when_root_is_being_served() {
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(td.path(), "a.txt", b"hello\n", "c1");
    let mkit_dir = td.path().join(".mkit");

    // No subprocess needed: hold the shared lock directly, exactly as a
    // live `mkit serve` would.
    let serve_lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(mkit_dir.join("serve.lock"))
        .unwrap();
    serve_lock.lock_shared().unwrap();

    let out = run_in(td.path(), &["gc"]);
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(out.status.success(), "gc failed: {out:?}");
    assert!(
        stderr.contains(SERVE_MARKER),
        "expected the serve-guard warning on stderr, got: {stderr}"
    );

    drop(serve_lock);
}

#[test]
fn commit_does_not_warn_when_not_served() {
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());

    fs::write(td.path().join("a.txt"), b"hello\n").unwrap();
    assert!(run_in(td.path(), &["add", "a.txt"]).status.success());
    let out = run_in(td.path(), &["commit", "-m", "c1"]);
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(out.status.success(), "commit failed: {out:?}");
    assert!(
        !stderr.contains(SERVE_MARKER),
        "no serve is alive; must not warn, got: {stderr}"
    );
}
