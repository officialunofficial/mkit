//! Remote roundtrip test against the in-process `MemoryTransport`.
//!
//! `MemoryTransport` is not URL-reachable by design — it lives in a
//! single process address space. To satisfy the remote test matrix
//! ("remote add + push + pull against the memory transport") we wire
//! up the dispatch helpers (`push_all`, `pull_all`) directly rather
//! than spawning the binary.
//!
//! For a full argv → binary → transport path we also run `remote add`
//! / `remote` (show) against the `mkit+memory://` URL so the string
//! contract (URL format accepted, roundtripped through config) stays
//! under test.

use std::fs;
use std::process::Command;
use std::sync::Arc;

use mkit_cli::remote_dispatch::{pull_all, push_all};
use mkit_transport_memory::MemoryTransport;

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

#[test]
fn remote_add_memory_url_roundtrips_through_config() {
    let td = tempfile::tempdir().unwrap();
    assert!(run_in(td.path(), &["init"]).status.success());
    let out = run_in(td.path(), &["remote", "add", "mkit+memory://example"]);
    assert!(out.status.success(), "remote add failed: {out:?}");

    // Bare `remote` lists NAMES only (git-shaped); the URL appears under
    // `remote -v` as `<name>\t<url> (fetch)` / `(push)`.
    let names = run_in(td.path(), &["remote"]);
    assert!(names.status.success());
    assert!(String::from_utf8(names.stdout).unwrap().contains("default"));

    let out = run_in(td.path(), &["remote", "-v"]);
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("mkit+memory://example"));
    assert!(stdout.contains("(fetch)"));
    assert!(stdout.contains("(push)"));
}

#[test]
fn remote_add_rejects_non_mkit_urls() {
    let td = tempfile::tempdir().unwrap();
    assert!(run_in(td.path(), &["init"]).status.success());
    let out = run_in(td.path(), &["remote", "add", "https://example.com/repo"]);
    assert!(!out.status.success(), "bare https:// must be rejected");
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("mkit+<scheme>://"),
        "error message should mention required URL prefix, got: {stderr}"
    );
}

#[test]
fn push_then_pull_roundtrips_refs_via_memory_transport() {
    // Two sibling repos sharing a single MemoryTransport, like `alice`
    // pushing to a bare remote and `bob` pulling from it.
    let alice = tempfile::tempdir().unwrap();
    let bob = tempfile::tempdir().unwrap();

    assert!(run_in(alice.path(), &["init"]).status.success());
    assert!(run_in(alice.path(), &["keygen"]).status.success());
    assert!(run_in(bob.path(), &["init"]).status.success());
    assert!(run_in(bob.path(), &["keygen"]).status.success());

    // Alice commits something.
    fs::write(alice.path().join("a.txt"), b"hello from alice\n").unwrap();
    assert!(run_in(alice.path(), &["add", "a.txt"]).status.success());
    let out = run_in(alice.path(), &["commit", "-m", "alice-1"]);
    assert!(out.status.success(), "alice commit failed: {out:?}");

    // Shared in-process transport.
    let tx: Arc<MemoryTransport> = Arc::new(MemoryTransport::new());

    // Push alice -> remote.
    let pushed = push_all(alice.path(), tx.as_ref()).expect("push");
    assert!(pushed >= 1, "expected at least one ref pushed");

    // Pull remote -> bob.
    let pulled = pull_all(bob.path(), tx.as_ref(), "default").expect("pull");
    assert_eq!(pulled, pushed, "push/pull ref count mismatch");

    // Bob now has `refs/heads/main` pointing at alice's commit.
    let alice_main = fs::read_to_string(alice.path().join(".mkit/refs/heads/main")).unwrap();
    let bob_main = fs::read_to_string(bob.path().join(".mkit/refs/heads/main")).unwrap();
    assert_eq!(
        alice_main.trim(),
        bob_main.trim(),
        "bob's main should point at alice's HEAD commit"
    );
}
