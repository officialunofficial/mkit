//! `mkit trust` + `mkit verify --trusted` end-to-end coverage (issue
//! #693).
//!
//! Spawns the real `mkit` binary so the full argv -> dispatch ->
//! trust-roots-file -> commit-verification path is exercised — not
//! just the in-process unit tests in `commands/trust.rs` /
//! `commands/verify.rs`.
//!
//! Core regression this file pins (the issue's "Testing Decisions"):
//! signing a commit with a key that is absent from a trust-roots file
//! makes `mkit verify --trusted <rev>` exit non-zero with a clear
//! "untrusted signer" message, even though the bare cryptographic
//! signature is perfectly valid.
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

/// Init a repo, keygen, and create one signed commit. Returns the temp
/// dir and the commit's Ed25519 signer pubkey hex, read straight off
/// `mkit keygen --print-pubkey`'s canonical `ed25519:<64-hex>` keyid
/// (`commands/keygen.rs`) — the same key `mkit commit` signs with.
fn repo_with_signed_commit() -> (tempfile::TempDir, String) {
    let td = tempfile::tempdir().unwrap();
    assert!(run_in(td.path(), &["init"]).status.success());
    let keygen = run_in(td.path(), &["keygen", "--print-pubkey"]);
    assert!(keygen.status.success());
    let keyid = String::from_utf8(keygen.stdout).unwrap().trim().to_owned();
    let hex = keyid
        .strip_prefix("ed25519:")
        .expect("keygen --print-pubkey should emit an ed25519:<hex> keyid")
        .to_owned();
    fs::write(td.path().join("a.txt"), b"hello").unwrap();
    assert!(run_in(td.path(), &["add", "a.txt"]).status.success());
    assert!(
        run_in(td.path(), &["commit", "-m", "first"])
            .status
            .success()
    );
    (td, hex)
}

fn write_trust_roots(path: &std::path::Path, keyid: &str, pubkey_hex: &str) {
    fs::write(
        path,
        format!(
            "[[trust_root]]\nkeyid = \"{keyid}\"\nkind = \"ed25519\"\npubkey_hex = \"{pubkey_hex}\"\n"
        ),
    )
    .unwrap();
}

#[test]
fn verify_without_trusted_flag_ignores_trust_roots() {
    // Baseline: plain `mkit verify HEAD` (no --trusted) verifies the
    // signature and says nothing about trust — this is the exact gap
    // issue #693 closes for the --trusted path, pinned here so a
    // regression can't silently make the default flag-less path start
    // failing closed too.
    let (td, _signer) = repo_with_signed_commit();
    let out = run_in(td.path(), &["verify", "HEAD"]);
    assert!(out.status.success(), "verify failed: {out:?}");
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(s.contains("ok: signature valid"), "unexpected output: {s}");
}

#[test]
fn verify_trusted_fails_closed_for_unregistered_signer() {
    let (td, _real_signer_hex) = repo_with_signed_commit();
    let trust_path = td.path().join("trust-roots.toml");
    // Trust-roots file lists a DIFFERENT (syntactically valid) key,
    // never the commit's actual signer.
    let other_hex = "99".repeat(32);
    let other_keyid = format!("ed25519:{other_hex}");
    write_trust_roots(&trust_path, &other_keyid, &other_hex);

    let out = run_in(
        td.path(),
        &[
            "verify",
            "--trusted",
            "--trust-roots",
            trust_path.to_str().unwrap(),
            "HEAD",
        ],
    );
    assert!(
        !out.status.success(),
        "verify --trusted must fail closed for an unregistered signer: {out:?}"
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains("not in the trust-roots registry"),
        "expected a clear untrusted-signer message, got: {stdout}"
    );
}

#[test]
fn verify_trusted_fails_closed_when_trust_roots_file_is_empty() {
    // An empty/missing trust-roots file is the "nothing configured"
    // state — still fails closed, never silently "ok".
    let (td, _signer) = repo_with_signed_commit();
    let trust_path = td.path().join("does-not-exist.toml");
    let out = run_in(
        td.path(),
        &[
            "verify",
            "--trusted",
            "--trust-roots",
            trust_path.to_str().unwrap(),
            "HEAD",
        ],
    );
    assert!(!out.status.success());
}

#[test]
fn verify_trusted_passes_for_registered_signer() {
    let (td, signer_hex) = repo_with_signed_commit();
    let trust_path = td.path().join("trust-roots.toml");
    let keyid = format!("ed25519:{signer_hex}");
    write_trust_roots(&trust_path, &keyid, &signer_hex);

    let out = run_in(
        td.path(),
        &[
            "verify",
            "--trusted",
            "--trust-roots",
            trust_path.to_str().unwrap(),
            "HEAD",
        ],
    );
    assert!(out.status.success(), "verify --trusted failed: {out:?}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains("signer trusted"),
        "expected a trusted-signer confirmation, got: {stdout}"
    );
}

#[test]
fn tampered_commit_fails_trusted_verify_on_signature_not_just_trust() {
    // Even a signer that IS registered must not pass if the object
    // bytes were tampered — the trust cross-check is layered on top of
    // (never a substitute for) the underlying signature check.
    let (td, signer_hex) = repo_with_signed_commit();
    let trust_path = td.path().join("trust-roots.toml");
    let keyid = format!("ed25519:{signer_hex}");
    write_trust_roots(&trust_path, &keyid, &signer_hex);

    // Mutate the signature bytes directly (never part of the signed
    // message) and re-store at the tampered content's own hash — same
    // technique as tests/corruption_rejection.rs's
    // `tampered_commit_signature_is_rejected_by_verify`.
    let layout = mkit_core::layout::RepoLayout::single(td.path());
    let head = mkit_core::refs::resolve_head(&layout).unwrap().unwrap();
    let store = mkit_core::store::ObjectStore::open(&layout).unwrap();
    let mkit_core::object::Object::Commit(mut c) = store.read_object(&head).unwrap() else {
        panic!("HEAD is not a commit");
    };
    c.signature[0] ^= 0xff;
    let bytes = mkit_core::serialize::serialize(&mkit_core::object::Object::Commit(c)).unwrap();
    let new = store.write(&bytes).unwrap();
    let new_hash = mkit_core::to_hex(&new);

    let out = run_in(
        td.path(),
        &[
            "verify",
            "--trusted",
            "--trust-roots",
            trust_path.to_str().unwrap(),
            &new_hash,
        ],
    );
    assert!(!out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.starts_with("bad:") && !stdout.contains("trust-roots registry"),
        "tampered object should fail on signature, not report an untrusted-signer message: {stdout}"
    );
}

#[test]
fn trust_add_list_remove_round_trip_via_cli() {
    let td = tempfile::tempdir().unwrap();
    let trust_path = td.path().join("trust-roots.toml");
    let hex = "ab".repeat(32);
    let keyid = format!("ed25519:{hex}");

    let add = run_in(
        td.path(),
        &[
            "trust",
            "add",
            &keyid,
            &hex,
            "--trust-roots",
            trust_path.to_str().unwrap(),
        ],
    );
    assert!(add.status.success(), "trust add failed: {add:?}");

    let list = run_in(
        td.path(),
        &[
            "trust",
            "list",
            "--trust-roots",
            trust_path.to_str().unwrap(),
        ],
    );
    assert!(list.status.success());
    let list_out = String::from_utf8(list.stdout).unwrap();
    assert!(
        list_out.contains(&keyid),
        "trust list should show the added keyid: {list_out}"
    );

    let remove = run_in(
        td.path(),
        &[
            "trust",
            "remove",
            &keyid,
            "--trust-roots",
            trust_path.to_str().unwrap(),
            "--yes",
        ],
    );
    assert!(remove.status.success(), "trust remove failed: {remove:?}");

    let list_after = run_in(
        td.path(),
        &[
            "trust",
            "list",
            "--trust-roots",
            trust_path.to_str().unwrap(),
        ],
    );
    let list_after_out = String::from_utf8(list_after.stdout).unwrap();
    assert!(
        !list_after_out.contains(&keyid),
        "keyid should be gone after remove: {list_after_out}"
    );
}

#[test]
fn trust_add_rejects_bad_hex() {
    let td = tempfile::tempdir().unwrap();
    let trust_path = td.path().join("trust-roots.toml");
    let out = run_in(
        td.path(),
        &[
            "trust",
            "add",
            "ed25519:zz",
            "not-hex",
            "--trust-roots",
            trust_path.to_str().unwrap(),
        ],
    );
    assert!(!out.status.success());
}
