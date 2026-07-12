//! `mkit config --unset <key>` and `--local`/`--global` scope
//! overrides (#709).
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn mkit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_mkit")
}

/// Fresh ephemeral `XDG_CONFIG_HOME` per call — used where user-scoped
/// state does not need to persist across invocations.
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

/// Caller-provided `XDG_CONFIG_HOME` so user-scoped settings persist
/// across a sequence of calls within one test.
fn run_in_with_xdg(cwd: &Path, xdg: &Path, args: &[&str]) -> Output {
    Command::new(mkit_bin())
        .args(args)
        .current_dir(cwd)
        .env("XDG_CONFIG_HOME", xdg)
        .output()
        .expect("spawn mkit")
}

fn stdout_str(out: &Output) -> String {
    String::from_utf8(out.stdout.clone()).unwrap()
}

fn stderr_str(out: &Output) -> String {
    String::from_utf8(out.stderr.clone()).unwrap()
}

fn init_repo() -> tempfile::TempDir {
    let td = tempfile::tempdir().unwrap();
    assert!(run_in(td.path(), &["init"]).status.success());
    td
}

/// A repo-scoped key: set, verify, `--unset`, verify it's gone from
/// both the effective value and the on-disk repo config. Uses
/// `user.email` rather than `default_branch` because the latter has a
/// non-empty compiled-in default (`main`) that shows through once the
/// repo override is cleared — `user.email` has no such fallback, so an
/// unset repo value reads back as truly empty.
#[test]
fn unset_removes_a_repo_scoped_key() {
    let td = init_repo();
    assert!(
        run_in(td.path(), &["config", "user.email", "a@example.com"])
            .status
            .success()
    );
    let show = run_in(td.path(), &["config", "user.email"]);
    assert_eq!(stdout_str(&show).trim(), "a@example.com");

    let unset = run_in(td.path(), &["config", "--unset", "user.email"]);
    assert!(unset.status.success(), "unset failed: {unset:?}");

    let show = run_in(td.path(), &["config", "user.email"]);
    assert_eq!(
        stdout_str(&show).trim(),
        "",
        "user.email should be empty after --unset"
    );
    let cfg = fs::read_to_string(td.path().join(".mkit/config")).unwrap_or_default();
    assert!(
        !cfg.contains("user.email"),
        ".mkit/config still contains user.email: {cfg}"
    );
}

/// A `REPO_FORBIDDEN_KEYS` key lives user-scoped; `--unset` must delete
/// it from the user-scoped file, not attempt (and fail) a repo write.
#[test]
fn unset_removes_a_user_scoped_forbidden_key() {
    let td = init_repo();
    let xdg = tempfile::tempdir().unwrap();

    assert!(
        run_in_with_xdg(
            td.path(),
            xdg.path(),
            &["config", "user.identity", "mid:42"]
        )
        .status
        .success()
    );
    let show = run_in_with_xdg(td.path(), xdg.path(), &["config", "user.identity"]);
    assert!(
        !stdout_str(&show).trim().is_empty(),
        "user.identity should be set before unset"
    );

    let unset = run_in_with_xdg(
        td.path(),
        xdg.path(),
        &["config", "--unset", "user.identity"],
    );
    assert!(unset.status.success(), "unset failed: {unset:?}");

    let show = run_in_with_xdg(td.path(), xdg.path(), &["config", "user.identity"]);
    assert_eq!(
        stdout_str(&show).trim(),
        "",
        "user.identity should be empty after --unset"
    );
    let user_cfg = fs::read_to_string(xdg.path().join("mkit/config")).unwrap_or_default();
    assert!(
        !user_cfg.contains("user.identity"),
        "user-scoped config still contains user.identity: {user_cfg}"
    );
    // Never written to the repo layer.
    let repo_cfg = fs::read_to_string(td.path().join(".mkit/config")).unwrap_or_default();
    assert!(!repo_cfg.contains("user.identity"));
}

/// Unsetting a key that was never set is a silent success, not an
/// error — idempotent, like `rm -f`.
#[test]
fn unset_of_an_already_unset_key_is_idempotent() {
    let td = init_repo();
    let out = run_in(td.path(), &["config", "--unset", "default_branch"]);
    assert!(
        out.status.success(),
        "unsetting an absent key should succeed: {out:?}"
    );
}

/// Unsetting an unknown key name is rejected.
#[test]
fn unset_of_unknown_key_errors() {
    let td = init_repo();
    let out = run_in(td.path(), &["config", "--unset", "not.a.real.key"]);
    assert!(!out.status.success(), "unknown key must be rejected");
    let stderr = stderr_str(&out);
    assert!(
        stderr.contains("unknown config key"),
        "expected unknown-key message: {stderr}"
    );
}

/// `--unset` takes no positional arguments.
#[test]
fn unset_rejects_positional_arguments() {
    let td = init_repo();
    let out = run_in(td.path(), &["config", "--unset", "default_branch", "extra"]);
    assert!(!out.status.success());
}

/// `--local` on a `REPO_FORBIDDEN_KEYS` key is refused for both set and
/// unset — it must never be persuadable into the clone-traveling repo
/// config.
#[test]
fn local_refuses_a_forbidden_key_on_set_and_unset() {
    let td = init_repo();
    let set = run_in(td.path(), &["config", "--local", "user.identity", "mid:7"]);
    assert!(
        !set.status.success(),
        "--local set of forbidden key must fail"
    );

    // `--local`/`--global` must precede `--unset <KEY>` on the command
    // line — like any clap value-taking option, `--unset` greedily
    // consumes the very next token as its value, so a flag placed
    // between `--unset` and the key would be swallowed as (an invalid)
    // key text rather than parsed as a separate flag.
    let unset = run_in(
        td.path(),
        &["config", "--local", "--unset", "user.identity"],
    );
    assert!(
        !unset.status.success(),
        "--local unset of forbidden key must fail"
    );
}

/// `--global` forces an otherwise repo-safe key into the user-scoped
/// layer instead of the repo layer.
#[test]
fn global_forces_a_repo_safe_key_to_user_scope() {
    let td = init_repo();
    let xdg = tempfile::tempdir().unwrap();

    let set = run_in_with_xdg(
        td.path(),
        xdg.path(),
        &["config", "--global", "default_branch", "trunk"],
    );
    assert!(set.status.success(), "--global set failed: {set:?}");

    // Not written to the repo layer.
    let repo_cfg = fs::read_to_string(td.path().join(".mkit/config")).unwrap_or_default();
    assert!(
        !repo_cfg.contains("default_branch"),
        "repo config should not contain default_branch when --global forced user scope: {repo_cfg}"
    );
    // Written to the user-scoped layer.
    let user_cfg = fs::read_to_string(xdg.path().join("mkit/config")).unwrap_or_default();
    assert!(
        user_cfg.contains("default_branch"),
        "user-scoped config should contain default_branch: {user_cfg}"
    );

    // The effective (merged) value still shows through.
    let show = run_in_with_xdg(td.path(), xdg.path(), &["config", "default_branch"]);
    assert_eq!(stdout_str(&show).trim(), "trunk");

    // --global --unset removes it again from the user-scoped layer.
    let unset = run_in_with_xdg(
        td.path(),
        xdg.path(),
        &["config", "--global", "--unset", "default_branch"],
    );
    assert!(unset.status.success(), "--global unset failed: {unset:?}");
    let user_cfg = fs::read_to_string(xdg.path().join("mkit/config")).unwrap_or_default();
    assert!(!user_cfg.contains("default_branch"));
}

/// `--local` and `--global` are mutually exclusive.
#[test]
fn local_and_global_are_mutually_exclusive() {
    let td = init_repo();
    let out = run_in(
        td.path(),
        &["config", "--local", "--global", "default_branch", "trunk"],
    );
    assert!(!out.status.success());
}
