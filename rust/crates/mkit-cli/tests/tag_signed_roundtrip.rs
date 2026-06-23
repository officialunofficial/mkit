//! End-to-end tests for annotated / signed tags (issue #230).
//!
//! Spawns the real `mkit` binary so the full argv → dispatch →
//! object-store → refs path is exercised:
//! - lightweight tag still points straight at a commit,
//! - `tag -a` writes an annotated tag object the ref points at,
//! - `tag -s` writes a signed tag object that `mkit verify <name>`
//!   accepts,
//! - tampering the stored signed-tag object makes verify fail.
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

/// Init a repo, keygen, and create one commit. Returns the temp dir.
fn repo_with_commit() -> tempfile::TempDir {
    let td = tempfile::tempdir().unwrap();
    assert!(run_in(td.path(), &["init"]).status.success());
    assert!(run_in(td.path(), &["keygen"]).status.success());
    fs::write(td.path().join("a.txt"), b"hello").unwrap();
    assert!(run_in(td.path(), &["add", "a.txt"]).status.success());
    assert!(
        run_in(td.path(), &["commit", "-m", "first"])
            .status
            .success()
    );
    td
}

fn read_tag_ref(root: &std::path::Path, name: &str) -> String {
    let p = root.join(".mkit/refs/tags").join(name);
    fs::read_to_string(p)
        .expect("tag ref file")
        .trim()
        .to_owned()
}

#[test]
fn lightweight_tag_points_at_commit() {
    let td = repo_with_commit();
    let out = run_in(td.path(), &["tag", "light"]);
    assert!(out.status.success(), "lightweight tag failed: {out:?}");
    // The ref hash must be a commit object, not a tag object.
    let h = read_tag_ref(td.path(), "light");
    let cat = run_in(td.path(), &["cat", &h]);
    let s = String::from_utf8(cat.stdout).unwrap();
    assert!(
        s.starts_with("tree "),
        "lightweight tag should point at a commit: {s}"
    );
}

#[test]
fn annotated_tag_creates_tag_object() {
    let td = repo_with_commit();
    let out = run_in(
        td.path(),
        &["tag", "-a", "v1.0.0", "-m", "annotated release"],
    );
    assert!(out.status.success(), "annotated tag failed: {out:?}");

    let h = read_tag_ref(td.path(), "v1.0.0");
    let cat = run_in(td.path(), &["cat", &h]);
    let s = String::from_utf8(cat.stdout).unwrap();
    assert!(s.contains("tag v1.0.0"), "cat should show tag name: {s}");
    assert!(s.contains("signed false"), "annotated tag is unsigned: {s}");
    assert!(s.contains("annotated release"), "message missing: {s}");
}

#[test]
fn signed_tag_verifies() {
    let td = repo_with_commit();
    let out = run_in(td.path(), &["tag", "-s", "v2.0.0", "-m", "signed release"]);
    assert!(out.status.success(), "signed tag failed: {out:?}");

    // Verify by tag name (resolves the annotated-tag object).
    let v = run_in(td.path(), &["verify", "v2.0.0"]);
    assert!(v.status.success(), "verify signed tag failed: {v:?}");
    let s = String::from_utf8(v.stdout).unwrap();
    assert!(s.contains("ok"), "verify did not report ok: {s}");

    let h = read_tag_ref(td.path(), "v2.0.0");
    let cat = run_in(td.path(), &["cat", &h]);
    let cs = String::from_utf8(cat.stdout).unwrap();
    assert!(
        cs.contains("signed true"),
        "signed tag should mark signed: {cs}"
    );
}

#[test]
fn tampered_signed_tag_fails_verify() {
    let td = repo_with_commit();
    assert!(
        run_in(td.path(), &["tag", "-s", "v3.0.0", "-m", "tamper me"])
            .status
            .success()
    );
    let h = read_tag_ref(td.path(), "v3.0.0");
    let (shard, rest) = h.split_at(2);
    let obj_path = td.path().join(".mkit/objects").join(shard).join(rest);

    // Flip a byte inside the message region (before the 64-byte
    // signature trailer) so the embedded signature no longer matches.
    let mut bytes = fs::read(&obj_path).unwrap();
    let idx = bytes.len() - 64 - 1;
    bytes[idx] ^= 0xFF;

    // Recompute the object's storage path from the tampered bytes
    // (BLAKE3 of the raw object) so the store's read-time integrity
    // check passes and ONLY the signature check is exercised. We hash
    // with the same primitive mkit uses.
    let new_hash = mkit_core::hash::to_hex(&mkit_core::hash::hash(&bytes));
    let (nshard, nrest) = new_hash.split_at(2);
    let new_dir = td.path().join(".mkit/objects").join(nshard);
    fs::create_dir_all(&new_dir).unwrap();
    fs::write(new_dir.join(nrest), &bytes).unwrap();

    let v = run_in(td.path(), &["verify", &new_hash]);
    assert!(
        !v.status.success(),
        "tampered signed tag must fail verify: {v:?}"
    );
    let s = String::from_utf8(v.stdout).unwrap();
    assert!(s.contains("bad"), "verify should report bad signature: {s}");
}
