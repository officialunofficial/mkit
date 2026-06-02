//! Named-remote + upstream-tracking + CAS-safe push tests (#175).
//!
//! Driven end-to-end through the real binary against a `mkit+file://`
//! bare-directory remote (the file transport is URL-reachable and
//! honours CAS `update_ref`, so non-fast-forward rejection is exercised
//! for real).

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

fn remote_main(remote_dir: &Path) -> Option<String> {
    fs::read_to_string(remote_dir.join("refs/heads/main"))
        .ok()
        .map(|s| s.trim().to_string())
}

#[test]
fn named_remote_add_lists_in_default_and_json() {
    let td = repo_with_commit(b"hi");
    let remote = tempfile::tempdir().unwrap();
    let url = file_url(remote.path());
    let add = run_in(td.path(), &["remote", "add", "origin", &url]);
    assert!(add.status.success(), "remote add origin failed: {add:?}");

    let out = run_in(td.path(), &["remote"]);
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("origin"), "default listing: {stdout}");
    assert!(stdout.contains(&url));

    let out = run_in(td.path(), &["remote", "--format=json"]);
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains("\"name\":\"origin\""),
        "json listing should carry name=origin: {stdout}"
    );
    assert!(stdout.contains("\"transport\":\"file\""));
}

#[test]
fn default_push_records_upstream_and_pushes_current_branch() {
    let td = repo_with_commit(b"hi");
    let remote = tempfile::tempdir().unwrap();
    let url = file_url(remote.path());
    assert!(
        run_in(td.path(), &["remote", "add", "origin", &url])
            .status
            .success()
    );

    // First push must name the remote (no upstream yet).
    let out = run_in(td.path(), &["push", "origin"]);
    assert!(out.status.success(), "push origin failed: {out:?}");
    assert_eq!(
        remote_main(remote.path()).as_deref(),
        Some(local_main(td.path()).as_str())
    );

    // Upstream is now recorded → bare `mkit push` works.
    fs::write(td.path().join("a.txt"), b"hi2").unwrap();
    assert!(run_in(td.path(), &["add", "a.txt"]).status.success());
    assert!(run_in(td.path(), &["commit", "-m", "c2"]).status.success());
    let out = run_in(td.path(), &["push"]);
    assert!(out.status.success(), "bare push failed: {out:?}");
    assert_eq!(
        remote_main(remote.path()).as_deref(),
        Some(local_main(td.path()).as_str())
    );
}

#[test]
fn push_with_no_upstream_and_no_default_refuses_actionably() {
    let td = repo_with_commit(b"hi");
    let out = run_in(td.path(), &["push"]);
    assert!(!out.status.success(), "push with no remote must fail");
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("no upstream") || stderr.contains("no remote"),
        "expected actionable no-upstream message: {stderr}"
    );
}

#[test]
fn non_fast_forward_push_is_rejected_without_force() {
    let td = repo_with_commit(b"hi");
    let remote = tempfile::tempdir().unwrap();
    let url = file_url(remote.path());
    assert!(
        run_in(td.path(), &["remote", "add", "origin", &url])
            .status
            .success()
    );
    assert!(run_in(td.path(), &["push", "origin"]).status.success());

    // Simulate the remote moving forward independently: rewrite the
    // remote ref to a different (bogus-but-valid) hash so our cached
    // tracking ref no longer matches.
    let other = "0".repeat(64);
    fs::write(remote.path().join("refs/heads/main"), format!("{other}\n")).unwrap();

    // New local commit; default push should be rejected (CAS Match
    // against our last-seen tracking tip, which the remote no longer
    // holds).
    fs::write(td.path().join("a.txt"), b"hi2").unwrap();
    assert!(run_in(td.path(), &["add", "a.txt"]).status.success());
    assert!(run_in(td.path(), &["commit", "-m", "c2"]).status.success());
    let out = run_in(td.path(), &["push"]);
    assert!(
        !out.status.success(),
        "non-ff push must be rejected: {out:?}"
    );
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("non-fast-forward"),
        "expected non-fast-forward error: {stderr}"
    );

    // --force overrides.
    let out = run_in(td.path(), &["push", "--force"]);
    assert!(out.status.success(), "force push should succeed: {out:?}");
    assert_eq!(
        remote_main(remote.path()).as_deref(),
        Some(local_main(td.path()).as_str())
    );
}

#[test]
fn dry_run_contacts_nothing() {
    let td = repo_with_commit(b"hi");
    let remote = tempfile::tempdir().unwrap();
    let url = file_url(remote.path());
    assert!(
        run_in(td.path(), &["remote", "add", "origin", &url])
            .status
            .success()
    );
    let out = run_in(td.path(), &["push", "origin", "--dry-run"]);
    assert!(out.status.success(), "dry-run failed: {out:?}");
    // Nothing written to the remote.
    assert_eq!(remote_main(remote.path()), None);
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("dry-run"),
        "expected dry-run note: {stderr}"
    );
}

#[test]
fn push_all_mirrors_every_branch() {
    let td = repo_with_commit(b"hi");
    let remote = tempfile::tempdir().unwrap();
    let url = file_url(remote.path());
    assert!(
        run_in(td.path(), &["remote", "add", "origin", &url])
            .status
            .success()
    );
    assert!(run_in(td.path(), &["branch", "feature"]).status.success());

    let out = run_in(td.path(), &["push", "origin", "--all"]);
    assert!(out.status.success(), "push --all failed: {out:?}");
    assert!(remote.path().join("refs/heads/main").exists());
    assert!(remote.path().join("refs/heads/feature").exists());
}

/// #175 must not weaken #97: a hostile *named* repo remote with ambient
/// credentials is still refused per ENDPOINT.
#[test]
fn named_repo_remote_with_token_is_still_gated() {
    let td = repo_with_commit(b"hi");
    // Plant a repo-scoped named remote pointing at an HTTP endpoint.
    let cfg = "remote.evil.url = mkit+https://attacker.invalid/repo\n\
               remote.evil.type = http\n";
    fs::write(td.path().join(".mkit/config"), cfg).unwrap();

    let xdg = tempfile::tempdir().unwrap();
    let out = Command::new(mkit_bin())
        .args(["push", "evil"])
        .current_dir(td.path())
        .env("XDG_CONFIG_HOME", xdg.path())
        .env("MKIT_API_TOKEN", "secret")
        .output()
        .expect("spawn mkit");
    drop(xdg);
    assert!(
        !out.status.success(),
        "hostile named remote must be refused"
    );
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("refusing repo-configured remote"),
        "expected credential refusal for named repo remote: {stderr}"
    );
}
