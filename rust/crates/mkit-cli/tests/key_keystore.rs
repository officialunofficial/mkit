//! Integration tests for `mkit key` keystore commands.

use std::process::{Command, Output};

fn mkit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_mkit")
}

fn run(root: &std::path::Path, args: &[&str]) -> Output {
    Command::new(mkit_bin())
        .args(args)
        .current_dir(root.join("repo"))
        .env("XDG_CONFIG_HOME", root.join("config"))
        .env("XDG_DATA_HOME", root.join("data"))
        .output()
        .expect("spawn mkit")
}

fn assert_key_list_json_includes_capabilities(root: &std::path::Path) {
    let list_json = run(root, &["key", "list", "--json"]);
    assert!(
        list_json.status.success(),
        "list json stderr: {}",
        String::from_utf8_lossy(&list_json.stderr)
    );
    let stdout = String::from_utf8(list_json.stdout).expect("stdout utf8");
    assert!(stdout.trim_start().starts_with('['));
    assert!(stdout.trim_end().ends_with(']'));
    assert!(stdout.contains("\"backend\":\"software\""));
    assert!(stdout.contains("\"label\":\"ci\""));
    assert!(stdout.contains("\"algorithm\":\"ed25519\""));
    assert!(stdout.contains("\"keyid\":\"ed25519:"));
    assert!(stdout.contains("\"capabilities\":{\"backend\":\"software\""));
    assert!(stdout.contains("\"can_generate\":true"));
    assert!(stdout.contains("\"supports_non_extractable\":false"));
}

#[test]
fn key_import_list_export_delete_roundtrip() {
    let td = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(td.path().join("repo")).expect("repo dir");
    let secret = "03".repeat(32);

    let import = run(
        td.path(),
        &[
            "key",
            "import",
            "--algorithm",
            "ed25519",
            "--label",
            "ci",
            "--hex",
            &secret,
        ],
    );
    assert!(
        import.status.success(),
        "import stderr: {}",
        String::from_utf8_lossy(&import.stderr)
    );
    let import_stdout = String::from_utf8(import.stdout).expect("stdout utf8");
    assert!(import_stdout.contains("keyid = ed25519:"));

    let list = run(td.path(), &["key", "list"]);
    assert!(
        list.status.success(),
        "list stderr: {}",
        String::from_utf8_lossy(&list.stderr)
    );
    let list_stdout = String::from_utf8(list.stdout).expect("stdout utf8");
    assert!(list_stdout.contains("software ci ed25519 ed25519:"));
    assert!(list_stdout.contains("can_generate=true"));
    assert!(list_stdout.contains("supports_non_extractable=false"));
    assert_key_list_json_includes_capabilities(td.path());

    let export_without_flag = run(
        td.path(),
        &["key", "export", "--label", "ci", "--algorithm", "ed25519"],
    );
    assert_eq!(export_without_flag.status.code(), Some(64));

    let export = run(
        td.path(),
        &[
            "key",
            "export",
            "--label",
            "ci",
            "--algorithm",
            "ed25519",
            "--unsafe-print-secret",
        ],
    );
    assert!(
        export.status.success(),
        "export stderr: {}",
        String::from_utf8_lossy(&export.stderr)
    );
    assert_eq!(
        String::from_utf8(export.stdout)
            .expect("stdout utf8")
            .trim(),
        secret
    );

    let delete_without_yes = run(
        td.path(),
        &["key", "delete", "--label", "ci", "--algorithm", "ed25519"],
    );
    assert_eq!(delete_without_yes.status.code(), Some(64));

    let delete = run(
        td.path(),
        &[
            "key",
            "delete",
            "--label",
            "ci",
            "--algorithm",
            "ed25519",
            "--yes",
        ],
    );
    assert!(
        delete.status.success(),
        "delete stderr: {}",
        String::from_utf8_lossy(&delete.stderr)
    );

    let list_after_delete = run(td.path(), &["key", "list"]);
    assert!(list_after_delete.status.success());
    assert!(
        String::from_utf8(list_after_delete.stdout)
            .expect("stdout utf8")
            .trim()
            .is_empty()
    );
}

#[test]
fn key_generate_prints_stable_keyid_line() {
    let td = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(td.path().join("repo")).expect("repo dir");
    let output = run(
        td.path(),
        &["key", "generate", "--label", "generated", "--print-pubkey"],
    );
    assert!(
        output.status.success(),
        "generate stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    assert!(stdout.contains("capabilities.can_generate = true"));
    assert!(stdout.contains("capabilities.can_import = true"));
    assert!(stdout.contains("capabilities.can_export = true"));
    assert!(stdout.contains("capabilities.can_delete = true"));
    assert!(stdout.contains("capabilities.supports_listing = true"));
    assert!(stdout.contains("capabilities.supports_user_presence = false"));
    assert!(stdout.contains("capabilities.supports_device_bound = false"));
    assert!(stdout.contains("capabilities.supports_non_extractable = false"));
    assert!(
        stdout
            .lines()
            .last()
            .unwrap_or_default()
            .starts_with("ed25519:")
    );
}

#[test]
fn key_default_ref_drives_unlabeled_commands() {
    let td = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(td.path().join("repo")).expect("repo dir");
    let cfg_dir = td.path().join("config/mkit");
    std::fs::create_dir_all(&cfg_dir).expect("config dir");
    std::fs::write(
        cfg_dir.join("config"),
        "key.default_ref = software:shared\n",
    )
    .expect("user config");

    let secret = "04".repeat(32);
    let import = run(
        td.path(),
        &["key", "import", "--algorithm", "ed25519", "--hex", &secret],
    );
    assert!(
        import.status.success(),
        "import stderr: {}",
        String::from_utf8_lossy(&import.stderr)
    );

    let list = run(td.path(), &["key", "list"]);
    assert!(list.status.success());
    let stdout = String::from_utf8(list.stdout).expect("stdout utf8");
    assert!(
        stdout.contains("software shared ed25519 ed25519:"),
        "default ref label should be used: {stdout}"
    );
}

#[test]
fn unlabeled_key_commands_use_key_backend_not_ref_backend() {
    let td = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(td.path().join("repo")).expect("repo dir");
    let cfg_dir = td.path().join("config/mkit");
    std::fs::create_dir_all(&cfg_dir).expect("config dir");
    std::fs::write(
        cfg_dir.join("config"),
        "key.backend = yubikey\nkey.default_ref = software:shared\n",
    )
    .expect("user config");

    let secret = "05".repeat(32);
    let import = run(
        td.path(),
        &["key", "import", "--algorithm", "ed25519", "--hex", &secret],
    );
    assert!(!import.status.success());
    let stderr = String::from_utf8_lossy(&import.stderr);
    assert!(
        stderr.contains("backend `yubikey` is not supported"),
        "stderr should show key.backend was selected: {stderr}"
    );

    let import = run(
        td.path(),
        &[
            "key",
            "import",
            "--backend",
            "software",
            "--algorithm",
            "ed25519",
            "--hex",
            &secret,
        ],
    );
    assert!(
        import.status.success(),
        "explicit backend should override config: {}",
        String::from_utf8_lossy(&import.stderr)
    );

    let list = run(td.path(), &["key", "list", "--backend", "software"]);
    assert!(list.status.success());
    let stdout = String::from_utf8(list.stdout).expect("stdout utf8");
    assert!(
        stdout.contains("software shared ed25519 ed25519:"),
        "default ref label should still be used: {stdout}"
    );
}

#[test]
fn config_shows_attest_signer() {
    let td = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(td.path().join("repo")).expect("repo dir");
    let cfg_dir = td.path().join("config/mkit");
    std::fs::create_dir_all(&cfg_dir).expect("config dir");
    std::fs::write(cfg_dir.join("config"), "attest.signer = keystore\n").expect("user config");

    let show_one = run(td.path(), &["config", "attest.signer"]);
    assert!(show_one.status.success());
    assert_eq!(
        String::from_utf8(show_one.stdout)
            .expect("stdout utf8")
            .trim(),
        "keystore"
    );

    let show_all = run(td.path(), &["config"]);
    assert!(show_all.status.success());
    let stdout = String::from_utf8(show_all.stdout).expect("stdout utf8");
    assert!(stdout.contains("attest.signer = keystore"));
}

#[test]
fn commit_can_use_keystore_signer_without_legacy_keygen() {
    let td = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(td.path().join("repo")).expect("repo dir");
    assert!(run(td.path(), &["init"]).status.success());

    let secret = "09".repeat(32);
    let import = run(
        td.path(),
        &[
            "key",
            "import",
            "--algorithm",
            "ed25519",
            "--label",
            "committer",
            "--hex",
            &secret,
        ],
    );
    assert!(
        import.status.success(),
        "import stderr: {}",
        String::from_utf8_lossy(&import.stderr)
    );

    let cfg_dir = td.path().join("config/mkit");
    std::fs::create_dir_all(&cfg_dir).expect("config dir");
    std::fs::write(
        cfg_dir.join("config"),
        "signer = keystore\nkey.ed25519_ref = software:committer\n",
    )
    .expect("user config");

    std::fs::write(td.path().join("repo/README.md"), b"hello\n").expect("README");
    assert!(run(td.path(), &["add", "README.md"]).status.success());
    let commit = run(td.path(), &["commit", "-m", "keystore commit"]);
    assert!(
        commit.status.success(),
        "commit stderr: {}",
        String::from_utf8_lossy(&commit.stderr)
    );
    assert!(
        !td.path().join("repo/.mkit/keys/default.key").exists(),
        "keystore commit must not silently create the legacy key"
    );

    let head = resolve_head(&td.path().join("repo"));
    let verify = run(td.path(), &["verify", &head]);
    assert!(
        verify.status.success(),
        "verify stderr: {}",
        String::from_utf8_lossy(&verify.stderr)
    );
}

#[test]
fn keystore_commit_missing_key_fails_without_generation() {
    let td = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(td.path().join("repo")).expect("repo dir");
    assert!(run(td.path(), &["init"]).status.success());

    let cfg_dir = td.path().join("config/mkit");
    std::fs::create_dir_all(&cfg_dir).expect("config dir");
    std::fs::write(
        cfg_dir.join("config"),
        "signer = keystore\nkey.ed25519_ref = software:missing\n",
    )
    .expect("user config");

    std::fs::write(td.path().join("repo/README.md"), b"hello\n").expect("README");
    assert!(run(td.path(), &["add", "README.md"]).status.success());
    let commit = run(td.path(), &["commit", "-m", "missing keystore key"]);
    assert_eq!(commit.status.code(), Some(66));
    let stderr = String::from_utf8_lossy(&commit.stderr);
    assert!(
        stderr.contains("mkit key generate"),
        "stderr should point to key generation: {stderr}"
    );
    assert!(
        !td.path().join("repo/.mkit/keys/default.key").exists(),
        "keystore commit must not silently create the legacy key"
    );
    assert!(
        !td.path().join("data/mkit/keys").exists(),
        "keystore commit must not silently create a keystore key"
    );
}

#[test]
fn keystore_commit_malformed_key_is_not_reported_as_missing() {
    let td = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(td.path().join("repo")).expect("repo dir");
    assert!(run(td.path(), &["init"]).status.success());

    let import = run(
        td.path(),
        &[
            "key",
            "import",
            "--algorithm",
            "ed25519",
            "--label",
            "broken",
            "--hex",
            &"09".repeat(32),
        ],
    );
    assert!(
        import.status.success(),
        "import stderr: {}",
        String::from_utf8_lossy(&import.stderr)
    );
    std::fs::write(
        td.path().join("data/mkit/keys/ed25519/62726f6b656e.key"),
        b"short",
    )
    .expect("corrupt keystore key");

    let cfg_dir = td.path().join("config/mkit");
    std::fs::create_dir_all(&cfg_dir).expect("config dir");
    std::fs::write(
        cfg_dir.join("config"),
        "signer = keystore\nkey.ed25519_ref = software:broken\n",
    )
    .expect("user config");

    std::fs::write(td.path().join("repo/README.md"), b"hello\n").expect("README");
    assert!(run(td.path(), &["add", "README.md"]).status.success());
    let commit = run(td.path(), &["commit", "-m", "malformed keystore key"]);
    assert!(!commit.status.success());
    let stderr = String::from_utf8_lossy(&commit.stderr);
    assert!(
        stderr.contains("keystore signing key `software:broken`"),
        "stderr should report a keystore key error: {stderr}"
    );
    assert!(
        !stderr.contains("missing keystore signing key"),
        "malformed key must not be reported as missing: {stderr}"
    );
    assert!(
        !stderr.contains("mkit key generate"),
        "malformed key must not suggest generation: {stderr}"
    );
}

fn resolve_head(root: &std::path::Path) -> String {
    let head = std::fs::read_to_string(root.join(".mkit/HEAD")).expect("HEAD");
    let head = head.trim();
    if let Some(refname) = head.strip_prefix("ref: ") {
        std::fs::read_to_string(root.join(".mkit").join(refname))
            .expect("ref")
            .trim()
            .to_owned()
    } else {
        head.to_owned()
    }
}
