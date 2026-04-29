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
