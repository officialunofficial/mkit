//! End-to-end roundtrip tests for the core command set. These spawn
//! the real `mkit` binary in a fresh temp directory so they exercise
//! the full argv → dispatch → library-crate path.
//!
//! Coverage:
//! - `init`
//! - `keygen`
//! - `add` + `commit` + `log` roundtrip
//! - `show <hash>` round-trip (here: `mkit cat <hash>`; `show` is an
//! alias we do not expose).

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

#[test]
fn init_creates_mkit_directory() {
    let td = tempfile::tempdir().unwrap();
    let out = run_in(td.path(), &["init"]);
    assert!(out.status.success(), "init failed: {out:?}");
    assert!(td.path().join(".mkit/objects").is_dir());
    assert!(td.path().join(".mkit/refs").is_dir());
    assert!(td.path().join(".mkit/HEAD").is_file());
}

#[test]
fn init_second_time_fails() {
    let td = tempfile::tempdir().unwrap();
    assert!(run_in(td.path(), &["init"]).status.success());
    let out = run_in(td.path(), &["init"]);
    assert!(!out.status.success(), "second init must fail");
}

#[test]
fn keygen_creates_key_file() {
    let td = tempfile::tempdir().unwrap();
    assert!(run_in(td.path(), &["init"]).status.success());
    let out = run_in(td.path(), &["keygen"]);
    assert!(out.status.success(), "keygen failed: {out:?}");
    let key_path = td.path().join(".mkit/keys/default.key");
    assert!(key_path.is_file(), "key file not created");
    let meta = fs::metadata(&key_path).unwrap();
    assert_eq!(meta.len(), 32, "ed25519 seed must be 32 bytes");
}

#[test]
fn add_commit_log_roundtrip() {
    let td = tempfile::tempdir().unwrap();
    assert!(run_in(td.path(), &["init"]).status.success());
    // explicit keygen required.
    assert!(run_in(td.path(), &["keygen"]).status.success());
    fs::write(td.path().join("hello.txt"), b"hello, mkit\n").unwrap();

    let out = run_in(td.path(), &["add", "hello.txt"]);
    assert!(out.status.success(), "add failed: {out:?}");

    let out = run_in(td.path(), &["commit", "-m", "first"]);
    assert!(out.status.success(), "commit failed: {out:?}");

    let out = run_in(td.path(), &["log", "--oneline"]);
    assert!(out.status.success(), "log failed: {out:?}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains("first"),
        "log did not show commit title: {stdout}"
    );
}

#[test]
fn cat_after_hash_prints_stored_blob() {
    let td = tempfile::tempdir().unwrap();
    assert!(run_in(td.path(), &["init"]).status.success());

    let payload = b"round-trip-me";
    fs::write(td.path().join("f.txt"), payload).unwrap();

    let out = run_in(td.path(), &["hash", "f.txt"]);
    assert!(out.status.success(), "hash failed: {out:?}");
    let hex = String::from_utf8(out.stdout).unwrap().trim().to_owned();
    assert_eq!(hex.len(), 64, "expected 64 hex chars, got {hex:?}");

    let out = run_in(td.path(), &["cat", &hex]);
    assert!(out.status.success(), "cat failed: {out:?}");
    assert_eq!(out.stdout, payload, "cat output did not match input");
}

#[test]
fn status_reports_staged_entries() {
    let td = tempfile::tempdir().unwrap();
    assert!(run_in(td.path(), &["init"]).status.success());
    fs::write(td.path().join("a.txt"), b"a").unwrap();
    assert!(run_in(td.path(), &["add", "a.txt"]).status.success());
    // Default mode routes prose to stderr; use --porcelain for a
    // stable stdout contract. See tests/status_integration.rs for the
    // full porcelain matrix.
    let out = run_in(td.path(), &["status", "--porcelain"]);
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.lines().any(|l| l.ends_with(" a.txt")),
        "status missing staged file: {stdout}"
    );
}
