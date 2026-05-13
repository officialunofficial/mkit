//! `mkit rebase` must use user-scoped `user.identity` for rewritten commits,
//! matching `commit`, `merge`, and `cherry-pick` author resolution.

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
fn rebase_uses_config_user_identity_for_rewritten_commits() {
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
    let out = run_in_with_xdg(td.path(), xdg.path(), &["rebase", "main"]);
    assert!(out.status.success(), "rebase failed: {out:?}");

    let mkit_dir = td.path().join(".mkit");
    let tip = refs::read_ref(&mkit_dir, "feature").unwrap().unwrap();
    let store = ObjectStore::open(td.path()).unwrap();
    let Object::Commit(c) = store.read_object(&tip).unwrap() else {
        panic!("tip is not a commit");
    };

    assert_eq!(c.author.kind, IdentityKind::Ed25519);
    assert_eq!(
        c.author.bytes, identity_pubkey,
        "rebased commit author must match user-scoped user.identity"
    );
    assert_ne!(
        c.signer, identity_pubkey,
        "rebase signer should remain the generated signing key"
    );
}

#[test]
fn rebase_rejects_invalid_user_identity_before_mutating_state() {
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
    let index_before = fs::read(td.path().join(".mkit/index")).expect("index before");

    let out = run_in_with_xdg(td.path(), xdg.path(), &["rebase", "main"]);
    assert!(!out.status.success(), "rebase unexpectedly succeeded");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("author:") || stderr.contains("user.identity"),
        "expected author/user.identity error, got: {stderr}"
    );
    assert!(
        !td.path().join(".mkit/rebase-apply").exists(),
        "invalid author must fail before writing rebase state"
    );
    assert_eq!(
        fs::read_to_string(td.path().join(".mkit/HEAD")).expect("HEAD after"),
        head_before,
        "invalid author must not detach HEAD"
    );
    assert_eq!(
        resolve_head(td.path()),
        resolved_head_before,
        "invalid author must not move the current branch"
    );
    assert_eq!(
        fs::read(td.path().join(".mkit/index")).expect("index after"),
        index_before,
        "invalid author must not rewrite the index"
    );
    assert!(
        td.path().join("feature.txt").exists(),
        "invalid author must not restore away the feature worktree"
    );
    assert!(
        !td.path().join("main.txt").exists(),
        "invalid author must fail before restoring the target worktree"
    );
}
