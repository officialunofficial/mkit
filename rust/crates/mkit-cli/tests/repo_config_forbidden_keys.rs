//! Per-key end-to-end regression tests for the hostile-clone config
//! attack surface tracked in #97 and GHSA-001. Each test plants a
//! `.mkit/config` containing exactly one forbidden key, runs `mkit
//! config <key>` against the repo, and asserts:
//!
//! 1. the value did NOT propagate to the effective config (stdout),
//! 2. the user got a stderr warning naming the dropped key.
//!
//! The warning shape is pinned via an `insta` snapshot so any future
//! drift in the message — wording, path layout, capitalisation — shows
//! up as a reviewable diff rather than a silent regression. The repo
//! path inside the warning is filtered out to keep the snapshot stable
//! across machines.
//!
//! The companion in-process unit test
//! `every_forbidden_key_is_actually_dropped_from_repo_scope` in
//! `mkit_cli::config` keeps the parser-side coverage tight; this file
//! adds the CLI-surface coverage.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::fs;
use std::process::Command;

fn mkit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_mkit")
}

fn run_in(cwd: &std::path::Path, args: &[&str]) -> std::process::Output {
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

/// Seed a repo with a `.mkit/config` containing exactly the one
/// `key = value` line under test, then return the temp dir holding it.
fn repo_with_repo_config(line: &str) -> tempfile::TempDir {
    let td = tempfile::tempdir().unwrap();
    fs::create_dir_all(td.path().join(".mkit")).unwrap();
    fs::write(td.path().join(".mkit/config"), line).unwrap();
    td
}

fn stderr_str(out: &std::process::Output) -> String {
    String::from_utf8(out.stderr.clone()).expect("stderr utf-8")
}

fn stdout_str(out: &std::process::Output) -> String {
    String::from_utf8(out.stdout.clone()).expect("stdout utf-8")
}

/// Run `mkit config <key>` and assert:
/// - exit 0,
/// - stdout is empty / default (value did NOT propagate),
/// - stderr contains the standard "ignoring `<key>` from per-repo config" warning.
fn assert_forbidden_key_dropped(key: &str, attacker_value: &str, expected_stdout_value: &str) {
    let line = format!("{key} = {attacker_value}\n");
    let td = repo_with_repo_config(&line);

    let out = run_in(td.path(), &["config", key]);
    assert!(
        out.status.success(),
        "`mkit config {key}` should succeed; stderr=\n{}",
        stderr_str(&out)
    );

    let stdout = stdout_str(&out);
    assert_eq!(
        stdout.trim(),
        expected_stdout_value,
        "value for `{key}` leaked from hostile repo config: stdout=`{stdout}`",
    );

    let stderr = stderr_str(&out);
    assert!(
        stderr.contains(&format!("ignoring `{key}`")),
        "stderr should warn about dropped key `{key}`; got:\n{stderr}",
    );
    assert!(
        stderr.contains("per-repo config"),
        "stderr should mention `per-repo config`; got:\n{stderr}",
    );
}

#[test]
fn repo_user_identity_dropped() {
    assert_forbidden_key_dropped("user.identity", "012000aaaaaaaa", "");
}

#[test]
fn repo_trusted_remote_endpoint_dropped() {
    assert_forbidden_key_dropped(
        "trusted_remote_endpoint",
        "mkit+https://attacker.invalid/repo",
        "",
    );
}

#[test]
fn repo_signer_dropped() {
    assert_forbidden_key_dropped("signer", "keystore", "legacy");
}

#[test]
fn repo_key_backend_dropped() {
    assert_forbidden_key_dropped("key.backend", "yubikey", "software");
}

#[test]
fn repo_key_default_ref_dropped() {
    assert_forbidden_key_dropped("key.default_ref", "yubikey:main", "software:default");
}

#[test]
fn repo_key_ed25519_ref_dropped() {
    assert_forbidden_key_dropped("key.ed25519_ref", "yubikey:main", "software:default");
}

#[test]
fn repo_key_secp256k1_ref_dropped() {
    assert_forbidden_key_dropped(
        "key.secp256k1_ref",
        "yubikey:wallet",
        "software:default-secp256k1",
    );
}

#[test]
fn repo_key_p256_ref_dropped() {
    assert_forbidden_key_dropped("key.p256_ref", "yubikey:piv-9c", "software:default-p256");
}

#[test]
fn repo_signing_key_dropped() {
    assert_forbidden_key_dropped(
        "signing_key",
        "../../../etc/passwd",
        ".mkit/keys/default.key",
    );
}

#[test]
fn repo_ssh_strict_host_key_checking_dropped() {
    assert_forbidden_key_dropped("ssh.strict_host_key_checking", "no", "");
}

#[test]
fn repo_ssh_user_known_hosts_file_dropped() {
    assert_forbidden_key_dropped("ssh.user_known_hosts_file", "/dev/null", "");
}

#[test]
fn repo_ssh_identity_file_dropped() {
    assert_forbidden_key_dropped("ssh.identity_file", "/home/victim/.ssh/id_ed25519", "");
}

#[test]
fn repo_attest_signer_dropped() {
    assert_forbidden_key_dropped("attest.signer", "external", "repo-key");
}

#[test]
fn repo_attest_default_algorithm_dropped() {
    assert_forbidden_key_dropped("attest.default_algorithm", "secp256k1", "ed25519");
}

#[test]
fn repo_attest_external_signer_path_dropped() {
    assert_forbidden_key_dropped("attest.external_signer_path", "/usr/bin/curl", "");
}

#[test]
fn repo_attest_external_signer_args_dropped() {
    assert_forbidden_key_dropped(
        "attest.external_signer_args",
        "-X|POST|attacker.example.com",
        "",
    );
}

#[test]
fn repo_attest_secp256k1_key_path_dropped() {
    assert_forbidden_key_dropped(
        "attest.secp256k1_key_path",
        "/home/victim/.wallet/seed",
        ".mkit/keys/secp256k1.key",
    );
}

#[test]
fn repo_attest_p256_key_path_dropped() {
    assert_forbidden_key_dropped(
        "attest.p256_key_path",
        "/home/victim/.ssh/id_ecdsa",
        ".mkit/keys/p256.key",
    );
}

/// Snapshot the exact shape of the stderr warning for one representative
/// forbidden key. The repo path inside the message is filtered out so
/// the snapshot is stable across machines and temp-dir layouts.
///
/// We pick `attest.external_signer_path` because it's the textbook
/// RCE-shaped forbidden key, so a regression in this warning is the
/// most useful to detect.
#[test]
fn warning_message_snapshot() {
    let td = repo_with_repo_config("attest.external_signer_path = /tmp/evil\n");
    let out = run_in(td.path(), &["config", "attest.external_signer_path"]);
    assert!(out.status.success());
    let stderr = stderr_str(&out);
    insta::with_settings!({filters => vec![
        // Absolute path to the planted `.mkit/config` — varies per machine.
        (r"at [^ ]+/\.mkit/config", "at <REPO>/.mkit/config"),
        // Absolute path to the user-scoped config under XDG_CONFIG_HOME.
        (r"see [^ ]+/mkit/config", "see <XDG>/mkit/config"),
    ]}, {
        insta::assert_snapshot!("repo_config_forbidden_warning", stderr);
    });
}

/// Multi-key plant: hostile clone tries every angle at once. The
/// effective config must contain none of the values, and the user
/// must get one warning per dropped key (i.e. they aren't deduped
/// silently).
#[test]
fn multiple_forbidden_keys_each_emit_a_warning() {
    let td = repo_with_repo_config(
        "signing_key = ../../../etc/passwd\n\
         attest.external_signer_path = /usr/bin/curl\n\
         ssh.identity_file = /home/victim/.ssh/id_ed25519\n\
         attest.signer = external\n",
    );
    let out = run_in(td.path(), &["config"]);
    assert!(out.status.success(), "`mkit config` should succeed");
    let stderr = stderr_str(&out);
    for key in [
        "signing_key",
        "attest.external_signer_path",
        "ssh.identity_file",
        "attest.signer",
    ] {
        assert!(
            stderr.contains(&format!("ignoring `{key}`")),
            "missing warning for `{key}` in:\n{stderr}",
        );
    }
}
