//! Issue #692: `clone`/`pull`/`fetch` must verify every newly-fetched
//! commit/remix/tag's Ed25519 signature and fail closed by default —
//! mirroring the manual `mkit verify <rev>` check
//! (`mkit_core::sign::{verify_commit,verify_remix,verify_tag}`).
//!
//! Two layers of coverage:
//!   * in-process, via `remote_dispatch::{pull_all,fetch_all,pull_all_with}`
//!     against a `MemoryTransport` — precise error-variant and
//!     ref-untouched assertions.
//!   * CLI subprocess, via `mkit pull`/`mkit clone` against a
//!     `mkit+file://` remote — proves the exit code and `--no-verify-signatures`
//!     opt-out actually thread through the real binary.
//!
//! In every case the "hostile remote" is simulated by tampering a
//! validly-content-addressed commit's `signature` bytes in place and
//! force-moving the branch ref to point at it directly via
//! `mkit_core::refs::write_ref` (bypassing `mkit commit`, which cannot
//! itself produce an invalid signature) — content addressing stays
//! intact (the object's hash still matches its bytes), only the
//! cryptographic signature is wrong, exactly the "unsigned or
//! self-signed history" attacker model from THREAT-MODEL §3.1.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::fs;
use std::process::Command;
use std::sync::Arc;

use mkit_cli::remote_dispatch::{DispatchError, fetch_all, pull_all, pull_all_with, push_all};
use mkit_core::layout::RepoLayout;
use mkit_core::object::Object;
use mkit_core::refs;
use mkit_core::serialize::serialize;
use mkit_core::store::ObjectStore;
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

fn init_and_key(dir: &std::path::Path) {
    assert!(run_in(dir, &["init"]).status.success());
    assert!(run_in(dir, &["keygen"]).status.success());
}

/// Flip the HEAD commit's signature (valid content-addressing, invalid
/// crypto) and force `main` to point at the tampered object. Returns the
/// tampered commit's hash.
fn tamper_head_commit_signature(dir: &std::path::Path) -> mkit_core::hash::Hash {
    let layout = RepoLayout::single(dir);
    let store = ObjectStore::open(&layout).unwrap();
    let head = refs::resolve_head(&layout).unwrap().expect("HEAD commit");
    let Object::Commit(mut c) = store.read_object(&head).unwrap() else {
        panic!("HEAD is not a commit");
    };
    c.signature[0] ^= 0xff;
    let bytes = serialize(&Object::Commit(c)).unwrap();
    let tampered = store.write(&bytes).unwrap();
    refs::write_ref(&layout, "main", &tampered).unwrap();
    tampered
}

// ---------------------------------------------------------------------------
// In-process (MemoryTransport) coverage
// ---------------------------------------------------------------------------

#[test]
fn pull_rejects_a_tampered_commit_signature_and_leaves_bob_untouched() {
    let alice = tempfile::tempdir().unwrap();
    let bob = tempfile::tempdir().unwrap();
    init_and_key(alice.path());
    init_and_key(bob.path());

    fs::write(alice.path().join("a.txt"), b"hello\n").unwrap();
    assert!(run_in(alice.path(), &["add", "a.txt"]).status.success());
    assert!(
        run_in(alice.path(), &["commit", "-m", "first"])
            .status
            .success()
    );
    let tampered = tamper_head_commit_signature(alice.path());

    let tx: Arc<MemoryTransport> = Arc::new(MemoryTransport::new());
    // Push does not verify signatures (out of scope for #692 — see the
    // issue's "Out of scope" section); the tampered history reaches the
    // remote exactly as a hostile remote's own unsigned/forged commits
    // would appear to a fetcher who never pushed them at all.
    push_all(alice.path(), tx.as_ref()).expect("push (no verification on push side)");

    let err = pull_all(bob.path(), tx.as_ref(), "default", None).expect_err(
        "pull must reject a commit whose signature does not verify, by default (issue #692)",
    );
    match &err {
        DispatchError::UnsignedOrInvalidObject { hash, .. } => {
            assert_eq!(*hash, mkit_core::hash::to_hex(&tampered));
        }
        other => panic!("expected UnsignedOrInvalidObject, got: {other:?}"),
    }

    // Bob's local branch, remote-tracking ref, and working tree must all
    // be untouched — the fetch phase fails before the fast-forward phase
    // (or any tracking-ref publish) ever runs.
    let bob_layout = RepoLayout::single(bob.path());
    assert_eq!(refs::read_ref(&bob_layout, "main").unwrap(), None);
    assert_eq!(
        refs::read_remote_ref(&bob_layout, "default", "main").unwrap(),
        None
    );
    assert!(!bob.path().join("a.txt").exists());
}

#[test]
fn fetch_rejects_a_tampered_commit_signature_and_does_not_publish_tracking_ref() {
    let alice = tempfile::tempdir().unwrap();
    let bob = tempfile::tempdir().unwrap();
    init_and_key(alice.path());
    init_and_key(bob.path());

    fs::write(alice.path().join("a.txt"), b"hello\n").unwrap();
    assert!(run_in(alice.path(), &["add", "a.txt"]).status.success());
    assert!(
        run_in(alice.path(), &["commit", "-m", "first"])
            .status
            .success()
    );
    tamper_head_commit_signature(alice.path());

    let tx: Arc<MemoryTransport> = Arc::new(MemoryTransport::new());
    push_all(alice.path(), tx.as_ref()).expect("push (no verification on push side)");

    let err = fetch_all(bob.path(), tx.as_ref(), "default")
        .expect_err("fetch must reject an invalid signature by default");
    assert!(
        matches!(err, DispatchError::UnsignedOrInvalidObject { .. }),
        "expected UnsignedOrInvalidObject, got: {err:?}"
    );
    let bob_layout = RepoLayout::single(bob.path());
    assert_eq!(
        refs::read_remote_ref(&bob_layout, "default", "main").unwrap(),
        None
    );
}

#[test]
fn pull_all_accepts_a_validly_signed_history() {
    let alice = tempfile::tempdir().unwrap();
    let bob = tempfile::tempdir().unwrap();
    init_and_key(alice.path());
    init_and_key(bob.path());

    fs::write(alice.path().join("a.txt"), b"hello\n").unwrap();
    assert!(run_in(alice.path(), &["add", "a.txt"]).status.success());
    assert!(
        run_in(alice.path(), &["commit", "-m", "first"])
            .status
            .success()
    );

    let tx: Arc<MemoryTransport> = Arc::new(MemoryTransport::new());
    push_all(alice.path(), tx.as_ref()).expect("push");

    // Signature verification is ON by default (`pull_all`) and a validly
    // signed history still fast-forwards cleanly.
    pull_all(bob.path(), tx.as_ref(), "default", None).expect("pull of a validly signed history");

    let alice_layout = RepoLayout::single(alice.path());
    let bob_layout = RepoLayout::single(bob.path());
    assert_eq!(
        refs::read_ref(&alice_layout, "main").unwrap(),
        refs::read_ref(&bob_layout, "main").unwrap()
    );
    assert_eq!(fs::read(bob.path().join("a.txt")).unwrap(), b"hello\n");
}

#[test]
fn require_signed_false_bypasses_the_check() {
    let alice = tempfile::tempdir().unwrap();
    let bob = tempfile::tempdir().unwrap();
    init_and_key(alice.path());
    init_and_key(bob.path());

    fs::write(alice.path().join("a.txt"), b"hello\n").unwrap();
    assert!(run_in(alice.path(), &["add", "a.txt"]).status.success());
    assert!(
        run_in(alice.path(), &["commit", "-m", "first"])
            .status
            .success()
    );
    let tampered = tamper_head_commit_signature(alice.path());

    let tx: Arc<MemoryTransport> = Arc::new(MemoryTransport::new());
    push_all(alice.path(), tx.as_ref()).expect("push");

    // The explicit opt-out (mirrors `--no-verify-signatures` /
    // `pull.require_signed = false`) accepts the same tampered history
    // `pull_all` (verification on) rejects above.
    pull_all_with(bob.path(), tx.as_ref(), "default", None, false)
        .expect("require_signed=false must bypass the signature check");
    let bob_layout = RepoLayout::single(bob.path());
    assert_eq!(refs::read_ref(&bob_layout, "main").unwrap(), Some(tampered));
}

// ---------------------------------------------------------------------------
// CLI subprocess coverage (mkit+file:// transport) — proves the flag /
// exit code / config wiring, not just the underlying dispatch functions.
// ---------------------------------------------------------------------------

#[test]
fn cli_pull_exits_nonzero_and_does_not_update_state_on_a_tampered_remote() {
    let alice = tempfile::tempdir().unwrap();
    init_and_key(alice.path());
    fs::write(alice.path().join("a.txt"), b"hello\n").unwrap();
    assert!(run_in(alice.path(), &["add", "a.txt"]).status.success());
    assert!(
        run_in(alice.path(), &["commit", "-m", "first"])
            .status
            .success()
    );
    tamper_head_commit_signature(alice.path());

    let bare = tempfile::tempdir().unwrap();
    let url = format!("mkit+file://{}", bare.path().display());
    assert!(
        run_in(alice.path(), &["remote", "add", &url])
            .status
            .success()
    );
    // Push doesn't verify signatures (out of scope for #692); the
    // tampered history reaches the bare remote.
    assert!(run_in(alice.path(), &["push"]).status.success());

    let bob = tempfile::tempdir().unwrap();
    init_and_key(bob.path());
    assert!(
        run_in(bob.path(), &["remote", "add", &url])
            .status
            .success()
    );
    let out = run_in(bob.path(), &["pull"]);
    assert!(
        !out.status.success(),
        "expected `mkit pull` to reject the tampered remote, stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("signature"),
        "stderr should mention signature verification: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let bob_layout = RepoLayout::single(bob.path());
    assert_eq!(refs::read_ref(&bob_layout, "main").unwrap(), None);
    assert!(!bob.path().join("a.txt").exists());
}

#[test]
fn cli_clone_exits_nonzero_on_a_tampered_remote() {
    let alice = tempfile::tempdir().unwrap();
    init_and_key(alice.path());
    fs::write(alice.path().join("a.txt"), b"hello\n").unwrap();
    assert!(run_in(alice.path(), &["add", "a.txt"]).status.success());
    assert!(
        run_in(alice.path(), &["commit", "-m", "first"])
            .status
            .success()
    );
    tamper_head_commit_signature(alice.path());

    let bare = tempfile::tempdir().unwrap();
    let url = format!("mkit+file://{}", bare.path().display());
    assert!(
        run_in(alice.path(), &["remote", "add", &url])
            .status
            .success()
    );
    assert!(run_in(alice.path(), &["push"]).status.success());

    let parent = tempfile::tempdir().unwrap();
    let out = Command::new(mkit_bin())
        .args(["clone", &url, "bob-clone"])
        .current_dir(parent.path())
        .env("XDG_CONFIG_HOME", parent.path())
        .output()
        .expect("spawn clone");
    assert!(
        !out.status.success(),
        "expected `mkit clone` to reject the tampered remote, stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!parent.path().join("bob-clone").join("a.txt").exists());
}

#[test]
fn cli_pull_no_verify_signatures_flag_bypasses_the_check() {
    let alice = tempfile::tempdir().unwrap();
    init_and_key(alice.path());
    fs::write(alice.path().join("a.txt"), b"hello\n").unwrap();
    assert!(run_in(alice.path(), &["add", "a.txt"]).status.success());
    assert!(
        run_in(alice.path(), &["commit", "-m", "first"])
            .status
            .success()
    );
    tamper_head_commit_signature(alice.path());

    let bare = tempfile::tempdir().unwrap();
    let url = format!("mkit+file://{}", bare.path().display());
    assert!(
        run_in(alice.path(), &["remote", "add", &url])
            .status
            .success()
    );
    assert!(run_in(alice.path(), &["push"]).status.success());

    let bob = tempfile::tempdir().unwrap();
    init_and_key(bob.path());
    assert!(
        run_in(bob.path(), &["remote", "add", &url])
            .status
            .success()
    );
    let out = run_in(bob.path(), &["pull", "--no-verify-signatures"]);
    assert!(
        out.status.success(),
        "expected `mkit pull --no-verify-signatures` to succeed against a tampered remote: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(bob.path().join("a.txt").exists());
}
