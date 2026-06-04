//! Git-compatibility `config` aliases (#250, Phase 2): `user.name` /
//! `user.email`. They round-trip like git, but are **non-authoritative** —
//! they must never feed mkit's cryptographic commit author (which is
//! `user.identity` / the signing key). These tests pin both the parity
//! (round-trip) and the security boundary (no author spoofing).

use std::fs;
use std::path::Path;
use std::process::Output;

fn mkit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_mkit")
}

fn run_in(cwd: &Path, xdg: &Path, args: &[&str]) -> Output {
    std::process::Command::new(mkit_bin())
        .args(args)
        .current_dir(cwd)
        .env("XDG_CONFIG_HOME", xdg)
        .output()
        .expect("spawn mkit")
}

fn repo() -> (tempfile::TempDir, tempfile::TempDir) {
    let td = tempfile::tempdir().unwrap();
    let xdg = tempfile::tempdir().unwrap();
    let (root, x) = (td.path(), xdg.path());
    assert!(run_in(root, x, &["init"]).status.success());
    assert!(run_in(root, x, &["keygen"]).status.success());
    fs::write(root.join("a.txt"), b"hello\n").unwrap();
    assert!(run_in(root, x, &["add", "."]).status.success());
    assert!(run_in(root, x, &["commit", "-m", "init"]).status.success());
    (td, xdg)
}

fn config_get(root: &Path, x: &Path, key: &str) -> String {
    let out = run_in(root, x, &["config", key]);
    assert!(out.status.success(), "config {key} failed: {out:?}");
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

/// Extract the `"author":"..."` value from a `log --format=json` line.
fn author_of_head(root: &Path, x: &Path) -> String {
    let out = run_in(root, x, &["log", "--format=json", "-n", "1"]);
    assert!(out.status.success(), "log failed: {out:?}");
    let s = String::from_utf8(out.stdout).unwrap();
    let key = "\"author\":\"";
    let start = s.find(key).expect("author field") + key.len();
    let rest = &s[start..];
    let end = rest.find('"').expect("author end");
    rest[..end].to_string()
}

#[test]
fn user_name_and_email_round_trip_like_git() {
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());

    assert!(
        run_in(root, x, &["config", "user.name", "Alice Example"])
            .status
            .success()
    );
    assert!(
        run_in(root, x, &["config", "user.email", "alice@example.com"])
            .status
            .success()
    );

    assert_eq!(config_get(root, x, "user.name"), "Alice Example");
    assert_eq!(config_get(root, x, "user.email"), "alice@example.com");

    // Round-trips through the JSON view too.
    let json = run_in(root, x, &["config", "--format=json"]);
    let s = String::from_utf8(json.stdout).unwrap();
    assert!(s.contains("\"user.name\":\"Alice Example\""), "json: {s:?}");
    assert!(
        s.contains("\"user.email\":\"alice@example.com\""),
        "json: {s:?}"
    );
}

#[test]
fn user_name_is_repo_scoped_not_user_scoped() {
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());
    assert!(
        run_in(root, x, &["config", "user.name", "Repo Local"])
            .status
            .success()
    );

    // Unlike `user.identity` (a REPO_FORBIDDEN_KEY routed to user scope),
    // the non-authoritative alias is written to the repo config.
    let repo_cfg = fs::read_to_string(root.join(".mkit/config")).unwrap();
    assert!(
        repo_cfg.contains("user.name = Repo Local"),
        "user.name should persist in the repo config: {repo_cfg:?}"
    );
}

#[test]
fn unrelated_repo_write_does_not_leak_user_scoped_aliases() {
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());
    // A user-scoped (global) user.email, as a user might keep for all repos.
    fs::create_dir_all(x.join("mkit")).unwrap();
    fs::write(x.join("mkit/config"), b"user.email = private@example.com\n").unwrap();

    // Setting an unrelated repo key must NOT copy the user-scoped value
    // into the repo config (which travels with clones).
    assert!(
        run_in(root, x, &["config", "default_branch", "trunk"])
            .status
            .success()
    );
    let repo_cfg = fs::read_to_string(root.join(".mkit/config")).unwrap();
    assert!(
        !repo_cfg.contains("private@example.com"),
        "user-scoped user.email leaked into repo config: {repo_cfg:?}"
    );
    // The merged value is still readable (it lives in the user config).
    assert_eq!(config_get(root, x, "user.email"), "private@example.com");
}

#[test]
fn remote_add_does_not_leak_user_scoped_aliases() {
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());
    fs::create_dir_all(x.join("mkit")).unwrap();
    fs::write(x.join("mkit/config"), b"user.email = private@example.com\n").unwrap();

    // `remote add` is another repo-config writer; it must persist only the
    // repo layer, not the merged view, so the user-scoped email stays out
    // of the clone-traveling repo config.
    assert!(
        run_in(root, x, &["remote", "add", "origin", "mkit+file:///tmp/r"])
            .status
            .success()
    );
    let repo_cfg = fs::read_to_string(root.join(".mkit/config")).unwrap();
    assert!(
        !repo_cfg.contains("private@example.com"),
        "user-scoped user.email leaked into repo config via remote add: {repo_cfg:?}"
    );
    assert!(
        repo_cfg.contains("remote.origin.url"),
        "remote was not recorded: {repo_cfg:?}"
    );
}

#[test]
fn user_name_does_not_spoof_the_signed_author() {
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());

    // Baseline author (no user.name set) — derived from the signing key
    // since user.identity is unset.
    let baseline = author_of_head(root, x);
    assert!(!baseline.is_empty(), "expected a derived author identity");

    // A hostile-looking user.name / user.email must NOT change the signed
    // author: authorship is cryptographic (user.identity / key), and these
    // aliases are non-authoritative.
    assert!(
        run_in(root, x, &["config", "user.name", "Mallory Spoof"])
            .status
            .success()
    );
    assert!(
        run_in(root, x, &["config", "user.email", "mallory@evil.test"])
            .status
            .success()
    );
    fs::write(root.join("b.txt"), b"more\n").unwrap();
    assert!(run_in(root, x, &["add", "."]).status.success());
    assert!(
        run_in(root, x, &["commit", "-m", "second"])
            .status
            .success()
    );

    let after = author_of_head(root, x);
    assert_eq!(
        after, baseline,
        "user.name/user.email must not influence the signed commit author"
    );
    let log = run_in(root, x, &["log"]);
    let log_s = String::from_utf8(log.stdout).unwrap();
    assert!(
        !log_s.contains("Mallory") && !log_s.contains("mallory@evil"),
        "the non-authoritative alias must never appear as the commit author: {log_s:?}"
    );
}
