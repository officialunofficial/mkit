//! `mkit rebase` replays preserve the ORIGINAL commit's author and
//! timestamp (git parity: a replay re-signs but never re-attributes).
//! `user.identity` config is not consulted during replay at all — it
//! applies to NEW commits (`commit`, `merge`), not rewritten ones.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::fmt::Write as _;
use std::fs;
use std::process::Command;

use mkit_core::object::{IdentityKind, Object};
use mkit_core::refs;
use mkit_core::store::ObjectStore;

fn mkit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_mkit")
}

fn run_in_with_xdg(
    cwd: &std::path::Path,
    xdg: &std::path::Path,
    args: &[&str],
) -> std::process::Output {
    Command::new(mkit_bin())
        .args(args)
        .current_dir(cwd)
        .env("XDG_CONFIG_HOME", xdg)
        .output()
        .expect("spawn mkit")
}

fn encode_ed25519_user_identity(pubkey: &[u8; 32]) -> String {
    let mut s = String::with_capacity(6 + 64);
    s.push_str("012000");
    for b in pubkey {
        write!(&mut s, "{b:02x}").unwrap();
    }
    s
}

fn commit_file(cwd: &std::path::Path, xdg: &std::path::Path, path: &str, body: &[u8], msg: &str) {
    fs::write(cwd.join(path), body).unwrap();
    assert!(run_in_with_xdg(cwd, xdg, &["add", path]).status.success());
    let out = run_in_with_xdg(cwd, xdg, &["commit", "-m", msg]);
    assert!(out.status.success(), "commit failed: {out:?}");
}

fn resolve_head(root: &std::path::Path) -> String {
    let head = fs::read_to_string(root.join(".mkit/HEAD")).expect("HEAD");
    let head = head.trim();
    if let Some(refname) = head.strip_prefix("ref: ") {
        fs::read_to_string(root.join(".mkit").join(refname))
            .expect("ref")
            .trim()
            .to_owned()
    } else {
        head.to_owned()
    }
}

#[test]
fn rebase_preserves_original_author_despite_user_identity() {
    let td = tempfile::tempdir().unwrap();
    let xdg = tempfile::tempdir().unwrap();
    assert!(
        run_in_with_xdg(td.path(), xdg.path(), &["init"])
            .status
            .success()
    );
    assert!(
        run_in_with_xdg(td.path(), xdg.path(), &["keygen"])
            .status
            .success()
    );

    commit_file(td.path(), xdg.path(), "base.txt", b"base\n", "base");
    assert!(
        run_in_with_xdg(td.path(), xdg.path(), &["branch", "feature"])
            .status
            .success()
    );

    assert!(
        run_in_with_xdg(td.path(), xdg.path(), &["checkout", "feature"])
            .status
            .success()
    );
    commit_file(
        td.path(),
        xdg.path(),
        "feature.txt",
        b"feature\n",
        "feature",
    );

    assert!(
        run_in_with_xdg(td.path(), xdg.path(), &["checkout", "main"])
            .status
            .success()
    );
    commit_file(td.path(), xdg.path(), "main.txt", b"main\n", "main");

    let identity_pubkey = [0xBBu8; 32];
    let hex = encode_ed25519_user_identity(&identity_pubkey);
    let user_cfg_dir = xdg.path().join("mkit");
    fs::create_dir_all(&user_cfg_dir).unwrap();
    fs::write(
        user_cfg_dir.join("config"),
        format!("user.identity = {hex}\n"),
    )
    .unwrap();

    assert!(
        run_in_with_xdg(td.path(), xdg.path(), &["checkout", "feature"])
            .status
            .success()
    );
    // Capture the original authorship before the replay.
    let mkit_dir = td.path().join(".mkit");
    let store = ObjectStore::open(td.path()).unwrap();
    let orig_tip = refs::read_ref(&mkit_dir, "feature").unwrap().unwrap();
    let Object::Commit(orig) = store.read_object(&orig_tip).unwrap() else {
        panic!("original tip is not a commit");
    };

    let out = run_in_with_xdg(td.path(), xdg.path(), &["rebase", "main"]);
    assert!(out.status.success(), "rebase failed: {out:?}");

    let tip = refs::read_ref(&mkit_dir, "feature").unwrap().unwrap();
    assert_ne!(tip, orig_tip, "rebase must produce a new commit");
    let Object::Commit(c) = store.read_object(&tip).unwrap() else {
        panic!("tip is not a commit");
    };

    // Replay preserves the original author + timestamp; the configured
    // user.identity (0xBB) must NOT re-attribute the rewritten commit.
    assert_eq!(c.author, orig.author, "replay must preserve the author");
    assert_eq!(
        c.timestamp, orig.timestamp,
        "replay must preserve the original timestamp"
    );
    assert_ne!(
        c.author.bytes, identity_pubkey,
        "user.identity must not re-attribute replayed commits"
    );
    assert_eq!(c.author.kind, IdentityKind::Ed25519);
    // The SIGNER half of the split: the replayed commit is signed by
    // the rebaser's repo key (and verifies under it) — a regression
    // that kept or forged the original signature would fail here.
    let kp = mkit_core::sign::load_key(&mkit_dir.join("keys/default.key")).unwrap();
    assert_eq!(
        c.signer, kp.public.0,
        "replayed commit must be signed by the rebaser's key"
    );
    assert!(mkit_core::sign::verify_commit(&c).is_ok());
}

#[test]
fn rebase_ignores_invalid_user_identity_on_replay() {
    let td = tempfile::tempdir().unwrap();
    let xdg = tempfile::tempdir().unwrap();
    assert!(
        run_in_with_xdg(td.path(), xdg.path(), &["init"])
            .status
            .success()
    );
    assert!(
        run_in_with_xdg(td.path(), xdg.path(), &["keygen"])
            .status
            .success()
    );

    commit_file(td.path(), xdg.path(), "base.txt", b"base\n", "base");
    assert!(
        run_in_with_xdg(td.path(), xdg.path(), &["branch", "feature"])
            .status
            .success()
    );

    assert!(
        run_in_with_xdg(td.path(), xdg.path(), &["checkout", "feature"])
            .status
            .success()
    );
    commit_file(
        td.path(),
        xdg.path(),
        "feature.txt",
        b"feature\n",
        "feature",
    );

    assert!(
        run_in_with_xdg(td.path(), xdg.path(), &["checkout", "main"])
            .status
            .success()
    );
    commit_file(td.path(), xdg.path(), "main.txt", b"main\n", "main");

    let user_cfg_dir = xdg.path().join("mkit");
    fs::create_dir_all(&user_cfg_dir).unwrap();
    fs::write(user_cfg_dir.join("config"), "user.identity = zzzzzz\n").unwrap();

    assert!(
        run_in_with_xdg(td.path(), xdg.path(), &["checkout", "feature"])
            .status
            .success()
    );
    let head_before = fs::read_to_string(td.path().join(".mkit/HEAD")).expect("HEAD before");
    let resolved_head_before = resolve_head(td.path());

    // Capture the original feature-tip authorship before the replay so
    // we can prove the malformed user.identity did not re-attribute it.
    let mkit_dir = td.path().join(".mkit");
    let store = ObjectStore::open(td.path()).unwrap();
    let orig_tip = refs::read_ref(&mkit_dir, "feature").unwrap().unwrap();
    let Object::Commit(orig) = store.read_object(&orig_tip).unwrap() else {
        panic!("original tip is not a commit");
    };

    // Replays never consult user.identity, so a malformed value cannot
    // block (or alter) the rebase — authorship comes from the original
    // commits.
    let out = run_in_with_xdg(td.path(), xdg.path(), &["rebase", "main"]);
    assert!(
        out.status.success(),
        "rebase must ignore user.identity entirely: {out:?}"
    );
    assert!(
        !td.path().join(".mkit/rebase-apply").exists(),
        "completed rebase must clear its state"
    );
    assert!(
        td.path().join("feature.txt").exists() && td.path().join("main.txt").exists(),
        "rebased worktree must contain both branches' files"
    );
    // HEAD still points at the feature branch (rebase never detaches
    // it), and the branch actually moved to a new replayed commit.
    let head_after = fs::read_to_string(td.path().join(".mkit/HEAD")).expect("HEAD after");
    assert_eq!(head_after, head_before, "rebase must not re-point HEAD");
    assert_ne!(
        resolve_head(td.path()),
        resolved_head_before,
        "rebase must advance the branch to a replayed commit"
    );
    // The replayed tip keeps the ORIGINAL author + timestamp — the
    // malformed user.identity was ignored, not applied and not fatal.
    let new_tip = refs::read_ref(&mkit_dir, "feature").unwrap().unwrap();
    assert_ne!(new_tip, orig_tip, "rebase must rewrite the feature tip");
    let Object::Commit(replayed) = store.read_object(&new_tip).unwrap() else {
        panic!("replayed tip is not a commit");
    };
    assert_eq!(
        replayed.author, orig.author,
        "replay must preserve the original author despite the bad identity"
    );
    assert_eq!(
        replayed.timestamp, orig.timestamp,
        "replay must preserve the original timestamp"
    );
}
