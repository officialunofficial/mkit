//! `mkit commit` must honour `config.user_identity` when set, falling
//! back to the pubkey-derived Identity otherwise. Integration test:
//! seed `.mkit/config` with a known identity, commit, then read the
//! commit object back and assert `author.bytes` match.

use std::fmt::Write as _;
use std::fs;
use std::process::Command;

use mkit_core::object::{IdentityKind, Object};
use mkit_core::refs;
use mkit_core::store::ObjectStore;

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

fn encode_ed25519_user_identity(pubkey: &[u8; 32]) -> String {
    // Canonical user.identity hex: [kind=0x01][len=32 LE][32 bytes].
    let mut s = String::with_capacity(6 + 64);
    s.push_str("012000");
    for b in pubkey {
        write!(&mut s, "{b:02x}").unwrap();
    }
    s
}

#[test]
fn commit_uses_config_user_identity_when_set() {
    let td = tempfile::tempdir().unwrap();
    assert!(run_in(td.path(), &["init"]).status.success());
    // 0.3.0: explicit keygen required.
    assert!(run_in(td.path(), &["keygen"]).status.success());

    // Pick a deterministic, known-non-signing-key identity and pin it
    // into `.mkit/config`. 0xAA repeated is distinct from whatever
    // ed25519 key `mkit commit` auto-generates.
    let identity_pubkey = [0xAAu8; 32];
    let hex = encode_ed25519_user_identity(&identity_pubkey);
    let config_path = td.path().join(".mkit/config");
    fs::write(
        &config_path,
        format!(
            "signing_key = .mkit/keys/default.key\ndefault_branch = main\nuser.identity = {hex}\n"
        ),
    )
    .unwrap();

    fs::write(td.path().join("f.txt"), b"hi").unwrap();
    assert!(run_in(td.path(), &["add", "."]).status.success());
    let out = run_in(td.path(), &["commit", "-m", "with-identity"]);
    assert!(out.status.success(), "commit failed: {out:?}");

    let mkit_dir = td.path().join(".mkit");
    let tip = refs::read_ref(&mkit_dir, "main").unwrap().unwrap();
    let store = ObjectStore::open(td.path()).unwrap();
    let obj = store.read_object(&tip).unwrap();
    let Object::Commit(c) = obj else {
        panic!("tip is not a commit");
    };
    assert_eq!(c.author.kind, IdentityKind::Ed25519);
    assert_eq!(
        c.author.bytes, identity_pubkey,
        "commit author must match config.user_identity"
    );
    // And — critically — the signer is the auto-generated key, NOT
    // the user.identity pubkey. Confirms the two slots are decoupled.
    assert_ne!(
        c.signer, identity_pubkey,
        "signer should be the generated key, not the config identity"
    );
}

#[test]
fn commit_author_flag_overrides_config_and_default() {
    let td = tempfile::tempdir().unwrap();
    assert!(run_in(td.path(), &["init"]).status.success());
    // 0.3.0: explicit keygen required.
    assert!(run_in(td.path(), &["keygen"]).status.success());

    // Seed config with identity A — the flag must win over it.
    let cfg_identity = [0x11u8; 32];
    let cfg_hex = encode_ed25519_user_identity(&cfg_identity);
    fs::write(
        td.path().join(".mkit/config"),
        format!(
            "signing_key = .mkit/keys/default.key\ndefault_branch = main\nuser.identity = {cfg_hex}\n"
        ),
    )
    .unwrap();

    // Flag passes identity B.
    let flag_identity = [0x22u8; 32];
    let mut flag_hex = String::with_capacity(64);
    for b in &flag_identity {
        write!(&mut flag_hex, "{b:02x}").unwrap();
    }

    fs::write(td.path().join("f.txt"), b"hi").unwrap();
    assert!(run_in(td.path(), &["add", "."]).status.success());
    let out = run_in(
        td.path(),
        &[
            "commit",
            "-m",
            "flag-wins",
            "--author",
            &format!("ed25519:{flag_hex}"),
        ],
    );
    assert!(out.status.success(), "commit failed: {out:?}");

    let mkit_dir = td.path().join(".mkit");
    let tip = refs::read_ref(&mkit_dir, "main").unwrap().unwrap();
    let store = ObjectStore::open(td.path()).unwrap();
    let Object::Commit(c) = store.read_object(&tip).unwrap() else {
        panic!("tip is not a commit");
    };
    assert_eq!(
        c.author.bytes, flag_identity,
        "--author must win over config"
    );
}

#[test]
fn commit_falls_back_to_pubkey_when_no_identity_set() {
    let td = tempfile::tempdir().unwrap();
    assert!(run_in(td.path(), &["init"]).status.success());
    // 0.3.0: explicit keygen required.
    assert!(run_in(td.path(), &["keygen"]).status.success());
    // No user.identity in config.

    fs::write(td.path().join("f.txt"), b"hi").unwrap();
    assert!(run_in(td.path(), &["add", "."]).status.success());
    let out = run_in(td.path(), &["commit", "-m", "pubkey-default"]);
    assert!(out.status.success(), "commit failed: {out:?}");

    let mkit_dir = td.path().join(".mkit");
    let tip = refs::read_ref(&mkit_dir, "main").unwrap().unwrap();
    let store = ObjectStore::open(td.path()).unwrap();
    let Object::Commit(c) = store.read_object(&tip).unwrap() else {
        panic!("tip is not a commit");
    };
    // When no user.identity / --author is set, author == signer pubkey.
    assert_eq!(c.author.kind, IdentityKind::Ed25519);
    assert_eq!(c.author.bytes, c.signer.to_vec());
}
