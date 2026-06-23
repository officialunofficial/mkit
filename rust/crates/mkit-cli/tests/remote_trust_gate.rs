#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers
use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn mkit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_mkit")
}

fn run_in_with_env(
    cwd: &Path,
    args: &[&str],
    envs: &[(&str, &str)],
    user_cfg: Option<&str>,
) -> Output {
    let xdg_root = tempfile::tempdir().expect("xdg tempdir");
    if let Some(text) = user_cfg {
        let cfg_dir = xdg_root.path().join("mkit");
        fs::create_dir_all(&cfg_dir).unwrap();
        fs::write(cfg_dir.join("config"), text).unwrap();
    }
    let mut cmd = Command::new(mkit_bin());
    cmd.args(args)
        .current_dir(cwd)
        .env("XDG_CONFIG_HOME", xdg_root.path());
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("spawn mkit");
    drop(xdg_root);
    out
}

#[test]
fn push_rejects_repo_configured_http_remote_with_token() {
    let td = tempfile::tempdir().unwrap();
    let root = td.path();
    assert!(run_in_with_env(root, &["init"], &[], None).status.success());
    let add = run_in_with_env(
        root,
        &["remote", "add", "mkit+https://example.invalid/repo"],
        &[],
        None,
    );
    assert!(add.status.success(), "remote add failed: {add:?}");

    let out = run_in_with_env(root, &["push"], &[("MKIT_API_TOKEN", "secret-xyz")], None);
    assert!(
        !out.status.success(),
        "push unexpectedly succeeded: {out:?}"
    );
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("refusing repo-configured remote"));
    assert!(stderr.contains("trusted_remote_endpoint"));
}

/// The gate keys on PROVENANCE, not mere credential presence. A
/// user-scoped `remote_endpoint` (the user's own decision, not a hostile
/// clone's) carrying a token must NOT be refused. We do not have the
/// remote actually reachable, so the push proceeds *past* the gate and
/// then fails to connect — but it must NOT fail with the trust refusal.
#[test]
fn push_does_not_refuse_user_scoped_endpoint_with_token() {
    let td = tempfile::tempdir().unwrap();
    let root = td.path();
    assert!(run_in_with_env(root, &["init"], &[], None).status.success());
    // Endpoint lives ONLY in user-scoped config — i.e. the user chose
    // it, so `repo_chosen` is false and the gate must pass.
    let out = run_in_with_env(
        root,
        &["push"],
        &[("MKIT_API_TOKEN", "secret-xyz")],
        Some("remote_endpoint = mkit+https://example.invalid/repo\n"),
    );
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        !stderr.contains("refusing repo-configured remote"),
        "user-scoped endpoint must not trip the credential gate: {stderr}"
    );
}

/// A repo-configured HTTP remote that the user has explicitly trusted in
/// user-scoped `trusted_remote_endpoint` proceeds past the gate even
/// with a token present (it then fails to connect to the unreachable
/// host, but NOT with the trust refusal).
#[test]
fn push_allows_repo_remote_when_user_trusts_endpoint() {
    let td = tempfile::tempdir().unwrap();
    let root = td.path();
    assert!(run_in_with_env(root, &["init"], &[], None).status.success());
    let add = run_in_with_env(
        root,
        &["remote", "add", "mkit+https://example.invalid/repo"],
        &[],
        None,
    );
    assert!(add.status.success(), "remote add failed: {add:?}");

    let out = run_in_with_env(
        root,
        &["push"],
        &[("MKIT_API_TOKEN", "secret-xyz")],
        Some("trusted_remote_endpoint = mkit+https://example.invalid/repo\n"),
    );
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        !stderr.contains("refusing repo-configured remote"),
        "user-trusted endpoint must pass the credential gate: {stderr}"
    );
}

#[test]
fn push_rejects_repo_configured_s3_remote_with_env_creds() {
    let td = tempfile::tempdir().unwrap();
    let root = td.path();
    assert!(run_in_with_env(root, &["init"], &[], None).status.success());
    let add = run_in_with_env(
        root,
        &["remote", "add", "mkit+s3://r2.example.com/bucket/proj"],
        &[],
        None,
    );
    assert!(add.status.success(), "remote add failed: {add:?}");

    let out = run_in_with_env(
        root,
        &["push"],
        &[
            ("MKIT_R2_ACCESS_KEY_ID", "test-key"),
            ("MKIT_R2_SECRET_ACCESS_KEY", "test-secret"),
        ],
        None,
    );
    assert!(
        !out.status.success(),
        "push unexpectedly succeeded: {out:?}"
    );
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("refusing repo-configured remote"));
    assert!(stderr.contains("trusted_remote_endpoint"));
}
