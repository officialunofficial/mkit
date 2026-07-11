//! `mkit clone -b <branch> -o <name>` (#709): land on an explicit
//! branch instead of the remote's default, and name the persisted
//! remote instead of the implicit flat `default`.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn mkit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_mkit")
}

fn run_in(cwd: &Path, args: &[&str]) -> Output {
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

fn stderr_str(out: &Output) -> String {
    String::from_utf8(out.stderr.clone()).unwrap()
}

fn stdout_str(out: &Output) -> String {
    String::from_utf8(out.stdout.clone()).unwrap()
}

fn file_url(dir: &Path) -> String {
    format!("mkit+file://{}", dir.display())
}

fn read_ref(repo: &Path, r#ref: &str) -> Option<String> {
    fs::read_to_string(repo.join(".mkit").join(r#ref))
        .ok()
        .map(|s| s.trim().to_string())
}

/// Build an upstream repo with `main` (commit c1) and `feature` (commit
/// c2, a descendant of c1), pushed with `--all` to a bare `mkit+file://`
/// store. Returns `(workdir, bare remote dir, url, main tip, feature
/// tip)` — both temp dirs must stay alive for the URL to keep resolving.
fn multi_branch_upstream() -> (tempfile::TempDir, tempfile::TempDir, String, String, String) {
    let td = tempfile::tempdir().unwrap();
    assert!(run_in(td.path(), &["init"]).status.success());
    assert!(run_in(td.path(), &["keygen"]).status.success());
    fs::write(td.path().join("a.txt"), b"c1").unwrap();
    assert!(run_in(td.path(), &["add", "a.txt"]).status.success());
    assert!(run_in(td.path(), &["commit", "-m", "c1"]).status.success());
    let main_tip = read_ref(td.path(), "refs/heads/main").unwrap();

    assert!(run_in(td.path(), &["branch", "feature"]).status.success());
    assert!(run_in(td.path(), &["checkout", "feature"]).status.success());
    fs::write(td.path().join("a.txt"), b"c2").unwrap();
    assert!(run_in(td.path(), &["add", "a.txt"]).status.success());
    assert!(run_in(td.path(), &["commit", "-m", "c2"]).status.success());
    let feature_tip = read_ref(td.path(), "refs/heads/feature").unwrap();

    let bare = tempfile::tempdir().unwrap();
    let url = file_url(bare.path());
    assert!(
        run_in(td.path(), &["remote", "add", "origin", &url])
            .status
            .success()
    );
    assert!(
        run_in(td.path(), &["push", "origin", "--all"])
            .status
            .success()
    );
    (td, bare, url, main_tip, feature_tip)
}

#[test]
fn clone_dash_b_lands_on_the_named_branch() {
    let (_td, _bare, url, main_tip, feature_tip) = multi_branch_upstream();
    assert_ne!(main_tip, feature_tip);

    let dest = tempfile::tempdir().unwrap();
    let target = dest.path().join("clone1");
    let out = run_in(
        dest.path(),
        &["clone", "-b", "feature", &url, target.to_str().unwrap()],
    );
    assert!(out.status.success(), "clone -b failed: {out:?}");

    assert_eq!(
        read_ref(&target, "HEAD"),
        Some("ref: refs/heads/feature".to_string())
    );
    assert_eq!(
        read_ref(&target, "refs/heads/feature").as_deref(),
        Some(feature_tip.as_str())
    );
    // The other branch was NOT checked out, but its history/refs are
    // not required to exist locally either — only the target branch's
    // tracking ref matters here.
    assert!(!target.join("a.txt").exists() || fs::read(target.join("a.txt")).unwrap() == b"c2");
}

#[test]
fn clone_dash_b_missing_branch_fails_loudly() {
    let (_td, _bare, url, _main_tip, _feature_tip) = multi_branch_upstream();
    let dest = tempfile::tempdir().unwrap();
    let target = dest.path().join("clone1");
    let out = run_in(
        dest.path(),
        &[
            "clone",
            "-b",
            "does-not-exist",
            &url,
            target.to_str().unwrap(),
        ],
    );
    assert!(!out.status.success(), "clone -b <missing branch> must fail");
    let stderr = stderr_str(&out);
    assert!(
        stderr.contains("not found") || stderr.contains("does-not-exist"),
        "expected an actionable missing-branch error: {stderr}"
    );
}

#[test]
fn clone_dash_o_persists_the_named_remote() {
    let (_td, _bare, url, main_tip, _feature_tip) = multi_branch_upstream();
    let dest = tempfile::tempdir().unwrap();
    let target = dest.path().join("clone1");
    let out = run_in(
        dest.path(),
        &["clone", "-o", "upstream", &url, target.to_str().unwrap()],
    );
    assert!(out.status.success(), "clone -o failed: {out:?}");

    // HEAD landed on the remote's default branch as usual.
    assert_eq!(
        read_ref(&target, "refs/heads/main").as_deref(),
        Some(main_tip.as_str())
    );
    // The remote is recorded under the given name, not the flat default.
    let cfg = fs::read_to_string(target.join(".mkit/config")).unwrap();
    assert!(
        cfg.contains(&format!("remote.upstream.url = {url}")),
        ".mkit/config should record the named remote: {cfg}"
    );
    assert!(
        !cfg.contains("remote_endpoint"),
        "flat remote_endpoint should not be set when -o names a remote: {cfg}"
    );

    let show = run_in(&target, &["remote", "get-url", "upstream"]);
    assert!(show.status.success(), "remote get-url upstream: {show:?}");
    assert_eq!(stdout_str(&show).trim(), url);

    // Tracking refs land under the named remote, not `default`.
    assert!(target.join(".mkit/refs/remotes/upstream/main").exists());
}

#[test]
fn clone_dash_b_and_dash_o_together() {
    let (_td, _bare, url, _main_tip, feature_tip) = multi_branch_upstream();
    let dest = tempfile::tempdir().unwrap();
    let target = dest.path().join("clone1");
    let out = run_in(
        dest.path(),
        &[
            "clone",
            "-b",
            "feature",
            "-o",
            "upstream",
            &url,
            target.to_str().unwrap(),
        ],
    );
    assert!(out.status.success(), "clone -b -o failed: {out:?}");
    assert_eq!(
        read_ref(&target, "HEAD"),
        Some("ref: refs/heads/feature".to_string())
    );
    assert_eq!(
        read_ref(&target, "refs/heads/feature").as_deref(),
        Some(feature_tip.as_str())
    );
    assert!(target.join(".mkit/refs/remotes/upstream/feature").exists());
}

#[test]
fn clone_dash_o_rejects_dotted_and_reserved_names() {
    let (_td, _bare, url, ..) = multi_branch_upstream();
    let dest = tempfile::tempdir().unwrap();
    for bad in ["has.dot", ""] {
        let target = dest.path().join(format!("clone-{}", bad.replace('.', "_")));
        let out = run_in(
            dest.path(),
            &["clone", "-o", bad, &url, target.to_str().unwrap()],
        );
        assert!(
            !out.status.success(),
            "-o '{bad}' should be rejected: {out:?}"
        );
    }
}
