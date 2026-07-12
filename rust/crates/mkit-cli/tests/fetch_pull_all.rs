//! `mkit fetch --all` / `mkit pull --all` (#709): loop the existing
//! per-remote fetch/pull dispatch over every configured remote instead
//! of just one, reusing the same per-remote tracking-ref snapshot +
//! report shape fetch/pull already use for a single remote.
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

/// Init a repo with a key and one commit; returns the temp dir.
fn repo_with_commit(content: &[u8]) -> tempfile::TempDir {
    let td = tempfile::tempdir().unwrap();
    assert!(run_in(td.path(), &["init"]).status.success());
    assert!(run_in(td.path(), &["keygen"]).status.success());
    fs::write(td.path().join("a.txt"), content).unwrap();
    assert!(run_in(td.path(), &["add", "a.txt"]).status.success());
    assert!(run_in(td.path(), &["commit", "-m", "c1"]).status.success());
    td
}

fn file_url(dir: &Path) -> String {
    format!("mkit+file://{}", dir.display())
}

fn local_main(repo: &Path) -> String {
    fs::read_to_string(repo.join(".mkit/refs/heads/main"))
        .unwrap()
        .trim()
        .to_string()
}

fn remote_tracking(repo: &Path, remote: &str, branch: &str) -> Option<String> {
    fs::read_to_string(repo.join(format!(".mkit/refs/remotes/{remote}/{branch}")))
        .ok()
        .map(|s| s.trim().to_string())
}

/// `fetch --all` downloads every configured remote's tracking refs in
/// one invocation, without touching local branches.
#[test]
fn fetch_all_syncs_every_configured_remote() {
    // Two independent upstream histories, each pushed to its own bare
    // `mkit+file://` store.
    let upstream_a = repo_with_commit(b"hello a");
    let upstream_b = repo_with_commit(b"hello b");
    let bare_a = tempfile::tempdir().unwrap();
    let bare_b = tempfile::tempdir().unwrap();
    let url_a = file_url(bare_a.path());
    let url_b = file_url(bare_b.path());
    assert!(
        run_in(upstream_a.path(), &["remote", "add", &url_a])
            .status
            .success()
    );
    assert!(run_in(upstream_a.path(), &["push"]).status.success());
    assert!(
        run_in(upstream_b.path(), &["remote", "add", &url_b])
            .status
            .success()
    );
    assert!(run_in(upstream_b.path(), &["push"]).status.success());

    let sink = tempfile::tempdir().unwrap();
    assert!(run_in(sink.path(), &["init"]).status.success());
    assert!(
        run_in(sink.path(), &["remote", "add", "a", &url_a])
            .status
            .success()
    );
    assert!(
        run_in(sink.path(), &["remote", "add", "b", &url_b])
            .status
            .success()
    );

    let out = run_in(sink.path(), &["fetch", "--all"]);
    assert!(out.status.success(), "fetch --all failed: {out:?}");

    assert_eq!(
        remote_tracking(sink.path(), "a", "main").as_deref(),
        Some(local_main(upstream_a.path()).as_str()),
        "remote 'a' tracking ref did not move"
    );
    assert_eq!(
        remote_tracking(sink.path(), "b", "main").as_deref(),
        Some(local_main(upstream_b.path()).as_str()),
        "remote 'b' tracking ref did not move"
    );

    // Neither pushed a local branch (fetch never moves HEAD/branches).
    assert!(!sink.path().join(".mkit/refs/heads/main").exists());

    // Per-remote summary: both endpoints get their own `From <url>`
    // report line, reusing fetch's existing single-remote report shape.
    let stderr = stderr_str(&out);
    assert!(
        stderr.contains(&format!("From {url_a}")),
        "stderr: {stderr}"
    );
    assert!(
        stderr.contains(&format!("From {url_b}")),
        "stderr: {stderr}"
    );
}

/// `pull --all` fast-forwards the current branch from each configured
/// remote in turn (alphabetical by name); a fast-forward-compatible
/// pair of remotes lands the union of their history.
#[test]
fn pull_all_fast_forwards_current_branch_from_each_remote() {
    let local = repo_with_commit(b"c1");
    let bare_a = tempfile::tempdir().unwrap();
    let url_a = file_url(bare_a.path());
    assert!(
        run_in(local.path(), &["remote", "add", "a", &url_a])
            .status
            .success()
    );
    assert!(run_in(local.path(), &["push", "a"]).status.success());
    let c1_tip = local_main(local.path());

    // c2 is a fast-forward descendant of c1, pushed to a second remote.
    fs::write(local.path().join("a.txt"), b"c2").unwrap();
    assert!(run_in(local.path(), &["add", "a.txt"]).status.success());
    assert!(
        run_in(local.path(), &["commit", "-m", "c2"])
            .status
            .success()
    );
    let bare_b = tempfile::tempdir().unwrap();
    let url_b = file_url(bare_b.path());
    assert!(
        run_in(local.path(), &["remote", "add", "b", &url_b])
            .status
            .success()
    );
    assert!(run_in(local.path(), &["push", "b"]).status.success());
    let c2_tip = local_main(local.path());
    assert_ne!(c1_tip, c2_tip);

    let sink = tempfile::tempdir().unwrap();
    assert!(run_in(sink.path(), &["init"]).status.success());
    assert!(
        run_in(sink.path(), &["remote", "add", "a", &url_a])
            .status
            .success()
    );
    assert!(
        run_in(sink.path(), &["remote", "add", "b", &url_b])
            .status
            .success()
    );

    let out = run_in(sink.path(), &["pull", "--all"]);
    assert!(out.status.success(), "pull --all failed: {out:?}");
    assert_eq!(
        local_main(sink.path()),
        c2_tip,
        "current branch was not fast-forwarded through both remotes"
    );
    // Both remotes' tracking refs moved: 'a' to c1 (the tip it holds),
    // 'b' to c2 (the tip it holds) — the union of both remotes' history
    // ends up locally even though each remote only advertises part of it.
    assert_eq!(
        remote_tracking(sink.path(), "a", "main").as_deref(),
        Some(c1_tip.as_str()),
        "remote 'a' tracking ref did not move to its own tip"
    );
    assert_eq!(
        remote_tracking(sink.path(), "b", "main").as_deref(),
        Some(c2_tip.as_str()),
        "remote 'b' tracking ref did not move to its own tip"
    );
}

/// `--all` and an explicit `<remote>` argument are mutually exclusive
/// on both `fetch` and `pull`.
#[test]
fn all_and_explicit_remote_are_mutually_exclusive() {
    let td = repo_with_commit(b"hi");
    for cmd in ["fetch", "pull"] {
        let out = run_in(td.path(), &[cmd, "origin", "--all"]);
        assert!(
            !out.status.success(),
            "{cmd} --all <remote> should be rejected"
        );
    }
}

/// `--all` with no configured remotes at all fails actionably, same as
/// the bare single-remote path.
#[test]
fn all_with_no_remotes_configured_is_actionable() {
    let td = tempfile::tempdir().unwrap();
    assert!(run_in(td.path(), &["init"]).status.success());
    for cmd in ["fetch", "pull"] {
        let out = run_in(td.path(), &[cmd, "--all"]);
        assert!(
            !out.status.success(),
            "{cmd} --all with no remotes must fail"
        );
        let stderr = stderr_str(&out);
        assert!(
            stderr.contains("no remote configured"),
            "expected actionable no-remote message for {cmd}: {stderr}"
        );
    }
}
