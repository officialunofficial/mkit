//! Integration tests for `mkit key` keystore commands.

use std::process::{Command, Output};

use mkit_core::object::Object;

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
    let list_json = run(
        root,
        &["key", "list", "--backend", "software-raw", "--json"],
    );
    assert!(
        list_json.status.success(),
        "list json stderr: {}",
        String::from_utf8_lossy(&list_json.stderr)
    );
    let stdout = String::from_utf8(list_json.stdout).expect("stdout utf8");
    assert!(stdout.trim_start().starts_with('['));
    assert!(stdout.trim_end().ends_with(']'));
    assert!(stdout.contains("\"backend\":\"software-raw\""));
    assert!(stdout.contains("\"label\":\"ci\""));
    assert!(stdout.contains("\"algorithm\":\"ed25519\""));
    assert!(stdout.contains("\"keyid\":\"ed25519:"));
    assert!(stdout.contains("\"capabilities\":{\"backend\":\"software-raw\""));
    assert!(stdout.contains("\"can_generate\":true"));
    assert!(stdout.contains("\"supports_non_extractable\":false"));
}

#[test]
#[allow(clippy::too_many_lines)]
fn key_import_list_export_delete_roundtrip() {
    let td = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(td.path().join("repo")).expect("repo dir");
    let secret = "03".repeat(32);

    let import = run(
        td.path(),
        &[
            "key",
            "import",
            "--backend",
            "software-raw",
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

    let list = run(td.path(), &["key", "list", "--backend", "software-raw"]);
    assert!(
        list.status.success(),
        "list stderr: {}",
        String::from_utf8_lossy(&list.stderr)
    );
    let list_stdout = String::from_utf8(list.stdout).expect("stdout utf8");
    assert!(list_stdout.contains("software-raw ci ed25519 ed25519:"));
    assert!(list_stdout.contains("can_generate=true"));
    assert!(list_stdout.contains("supports_non_extractable=false"));
    assert_key_list_json_includes_capabilities(td.path());

    let export_without_flag = run(
        td.path(),
        &[
            "key",
            "export",
            "--backend",
            "software-raw",
            "--label",
            "ci",
            "--algorithm",
            "ed25519",
        ],
    );
    assert_eq!(export_without_flag.status.code(), Some(64));

    let export = run(
        td.path(),
        &[
            "key",
            "export",
            "--backend",
            "software-raw",
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
        &[
            "key",
            "delete",
            "--backend",
            "software-raw",
            "--label",
            "ci",
            "--algorithm",
            "ed25519",
        ],
    );
    assert_eq!(delete_without_yes.status.code(), Some(64));

    let delete = run(
        td.path(),
        &[
            "key",
            "delete",
            "--backend",
            "software-raw",
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

    let list_after_delete = run(td.path(), &["key", "list", "--backend", "software-raw"]);
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
        &[
            "key",
            "generate",
            "--backend",
            "software-raw",
            "--label",
            "generated",
            "--print-pubkey",
        ],
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
fn key_generate_help_exits_successfully() {
    let td = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(td.path().join("repo")).expect("repo dir");

    let output = run(td.path(), &["key", "generate", "--help"]);
    assert!(
        output.status.success(),
        "help stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty(), "help should write stderr empty");
    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    assert!(stdout.contains("Usage: mkit key generate"));
    assert!(stdout.contains("--print-pubkey"));
}

#[test]
fn key_generate_and_import_accept_equals_options() {
    let td = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(td.path().join("repo")).expect("repo dir");

    let generate = run(
        td.path(),
        &[
            "key",
            "generate",
            "--backend=software-raw",
            "--algorithm=ed25519",
            "--label=equals-generated",
        ],
    );
    assert!(
        generate.status.success(),
        "generate stderr: {}",
        String::from_utf8_lossy(&generate.stderr)
    );

    let secret = "07".repeat(32);
    let hex_arg = format!("--hex={secret}");
    let import = run(
        td.path(),
        &[
            "key",
            "import",
            "--backend=software-raw",
            "--algorithm=ed25519",
            "--label=equals-imported",
            &hex_arg,
        ],
    );
    assert!(
        import.status.success(),
        "import stderr: {}",
        String::from_utf8_lossy(&import.stderr)
    );

    let list = run(td.path(), &["key", "list", "--backend=software-raw"]);
    assert!(
        list.status.success(),
        "list stderr: {}",
        String::from_utf8_lossy(&list.stderr)
    );
    let stdout = String::from_utf8(list.stdout).expect("stdout utf8");
    assert!(stdout.contains("software-raw equals-generated ed25519 ed25519:"));
    assert!(stdout.contains("software-raw equals-imported ed25519 ed25519:"));
}

#[test]
fn key_default_ref_drives_unlabeled_commands() {
    let td = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(td.path().join("repo")).expect("repo dir");
    let cfg_dir = td.path().join("config/mkit");
    std::fs::create_dir_all(&cfg_dir).expect("config dir");
    std::fs::write(
        cfg_dir.join("config"),
        "key.default_ref = software-raw:shared\n",
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

    let list = run(td.path(), &["key", "list", "--backend", "software-raw"]);
    assert!(list.status.success());
    let stdout = String::from_utf8(list.stdout).expect("stdout utf8");
    assert!(
        stdout.contains("software-raw shared ed25519 ed25519:"),
        "default ref label should be used: {stdout}"
    );
}

#[test]
fn key_backend_drives_unlabeled_commands_when_refs_are_unset() {
    let td = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(td.path().join("repo")).expect("repo dir");
    let cfg_dir = td.path().join("config/mkit");
    std::fs::create_dir_all(&cfg_dir).expect("config dir");
    std::fs::write(cfg_dir.join("config"), "key.backend = software-raw\n").expect("user config");

    let secret = "06".repeat(32);
    let import = run(
        td.path(),
        &["key", "import", "--algorithm", "ed25519", "--hex", &secret],
    );
    assert!(
        import.status.success(),
        "import stderr: {}",
        String::from_utf8_lossy(&import.stderr)
    );
    let stdout = String::from_utf8(import.stdout).expect("stdout utf8");
    assert!(stdout.contains("backend = software-raw"));
    assert!(stdout.contains("label = default"));

    let list = run(td.path(), &["key", "list"]);
    assert!(list.status.success());
    let stdout = String::from_utf8(list.stdout).expect("stdout utf8");
    assert!(stdout.contains("software-raw default ed25519 ed25519:"));

    let export = run(
        td.path(),
        &[
            "key",
            "export",
            "--algorithm",
            "ed25519",
            "--unsafe-print-secret",
        ],
    );
    assert!(export.status.success());
    assert_eq!(String::from_utf8(export.stdout).unwrap().trim(), secret);

    let delete = run(
        td.path(),
        &["key", "delete", "--algorithm", "ed25519", "--yes"],
    );
    assert!(delete.status.success());
    let stdout = String::from_utf8(delete.stdout).expect("stdout utf8");
    assert!(stdout.contains("deleted software-raw:default"));
}

#[test]
fn unlabeled_key_commands_use_configured_ref_backend() {
    let td = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(td.path().join("repo")).expect("repo dir");
    let cfg_dir = td.path().join("config/mkit");
    std::fs::create_dir_all(&cfg_dir).expect("config dir");
    std::fs::write(
        cfg_dir.join("config"),
        "key.backend = yubikey\nkey.default_ref = software-raw:shared\n",
    )
    .expect("user config");

    let secret = "05".repeat(32);
    let import = run(
        td.path(),
        &["key", "import", "--algorithm", "ed25519", "--hex", &secret],
    );
    assert!(
        import.status.success(),
        "configured ref backend should be selected: {}",
        String::from_utf8_lossy(&import.stderr)
    );
    let stdout = String::from_utf8(import.stdout).expect("stdout utf8");
    assert!(stdout.contains("backend = software-raw"));

    let import = run(
        td.path(),
        &[
            "key",
            "import",
            "--backend",
            "software-raw",
            "--label",
            "explicit",
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

    let unsupported = run(
        td.path(),
        &[
            "key",
            "import",
            "--backend",
            "yubikey",
            "--label",
            "hardware",
            "--algorithm",
            "ed25519",
            "--hex",
            &secret,
        ],
    );
    assert!(!unsupported.status.success());
    let stderr = String::from_utf8_lossy(&unsupported.stderr);
    assert!(
        stderr.contains("keystore backend unavailable"),
        "stderr should show generic backend routing failed closed: {stderr}"
    );

    let list = run(td.path(), &["key", "list", "--backend", "software-raw"]);
    assert!(list.status.success());
    let stdout = String::from_utf8(list.stdout).expect("stdout utf8");
    assert!(
        stdout.contains("software-raw shared ed25519 ed25519:"),
        "configured ref backend and label should be used: {stdout}"
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
            "--backend",
            "software-raw",
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
        "signer = keystore\nkey.ed25519_ref = software-raw:committer\n",
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
fn commit_ignores_repo_controlled_signing_key_ref() {
    let td = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(td.path().join("repo")).expect("repo dir");
    assert!(run(td.path(), &["init"]).status.success());

    let user_secret = [0x31; 32];
    let attacker_secret = [0x32; 32];
    import_raw_ed25519(td.path(), "user-committer", &user_secret);
    import_raw_ed25519(td.path(), "repo-attacker", &attacker_secret);

    let cfg_dir = td.path().join("config/mkit");
    std::fs::create_dir_all(&cfg_dir).expect("config dir");
    std::fs::write(
        cfg_dir.join("config"),
        "signer = keystore\nkey.ed25519_ref = software-raw:user-committer\n",
    )
    .expect("user config");
    std::fs::write(
        td.path().join("repo/.mkit/config"),
        "signer = keystore\nkey.default_ref = software-raw:repo-attacker\nkey.ed25519_ref = software-raw:repo-attacker\n",
    )
    .expect("repo config");

    std::fs::write(td.path().join("repo/README.md"), b"hello\n").expect("README");
    assert!(run(td.path(), &["add", "README.md"]).status.success());
    let commit = run(td.path(), &["commit", "-m", "repo selector ignored"]);
    assert!(
        commit.status.success(),
        "commit stderr: {}",
        String::from_utf8_lossy(&commit.stderr)
    );

    let signer = head_commit_signer(&td.path().join("repo"));
    assert_eq!(signer, ed25519_public_key(&user_secret));
    assert_ne!(signer, ed25519_public_key(&attacker_secret));
}

#[test]
fn commit_with_corrupt_head_does_not_fallback_to_main() {
    let td = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(td.path().join("repo")).expect("repo dir");
    assert!(run(td.path(), &["init"]).status.success());
    import_raw_ed25519(td.path(), "user-committer", &[0x33; 32]);

    let cfg_dir = td.path().join("config/mkit");
    std::fs::create_dir_all(&cfg_dir).expect("config dir");
    std::fs::write(
        cfg_dir.join("config"),
        "signer = keystore\nkey.ed25519_ref = software-raw:user-committer\n",
    )
    .expect("user config");
    std::fs::write(td.path().join("repo/README.md"), b"hello\n").expect("README");
    assert!(run(td.path(), &["add", "README.md"]).status.success());
    std::fs::write(td.path().join("repo/.mkit/HEAD"), b"ref: ").expect("corrupt HEAD");

    let commit = run(td.path(), &["commit", "-m", "corrupt head"]);
    assert!(!commit.status.success());
    assert!(String::from_utf8_lossy(&commit.stderr).contains("read HEAD"));
    assert!(
        !td.path().join("repo/.mkit/refs/heads/main").exists(),
        "corrupt HEAD must not advance refs/heads/main"
    );
}

#[test]
fn commit_can_use_software_raw_keystore_ref() {
    let td = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(td.path().join("repo")).expect("repo dir");
    assert!(run(td.path(), &["init"]).status.success());

    let secret = "08".repeat(32);
    let import = run(
        td.path(),
        &[
            "key",
            "import",
            "--backend",
            "software-raw",
            "--algorithm",
            "ed25519",
            "--label",
            "raw-committer",
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
        "signer = keystore\nkey.ed25519_ref = software-raw:raw-committer\n",
    )
    .expect("user config");

    std::fs::write(td.path().join("repo/README.md"), b"hello raw\n").expect("README");
    assert!(run(td.path(), &["add", "README.md"]).status.success());
    let commit = run(td.path(), &["commit", "-m", "software raw keystore commit"]);
    assert!(
        commit.status.success(),
        "commit stderr: {}",
        String::from_utf8_lossy(&commit.stderr)
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
        "signer = keystore\nkey.ed25519_ref = software:secret-commit-label\n",
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
        !stderr.contains("secret-commit-label") && !stderr.contains("software:secret-commit-label"),
        "stderr must not leak keystore label or key ref: {stderr}"
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
            "--backend",
            "software-raw",
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
        td.path()
            .join("data/mkit/keys/raw/ed25519/62726f6b656e.raw"),
        b"short",
    )
    .expect("corrupt keystore key");

    let cfg_dir = td.path().join("config/mkit");
    std::fs::create_dir_all(&cfg_dir).expect("config dir");
    std::fs::write(
        cfg_dir.join("config"),
        "signer = keystore\nkey.ed25519_ref = software-raw:broken\n",
    )
    .expect("user config");

    std::fs::write(td.path().join("repo/README.md"), b"hello\n").expect("README");
    assert!(run(td.path(), &["add", "README.md"]).status.success());
    let commit = run(td.path(), &["commit", "-m", "malformed keystore key"]);
    assert!(!commit.status.success());
    let stderr = String::from_utf8_lossy(&commit.stderr);
    assert!(
        stderr.contains("keystore signing key for algorithm ed25519"),
        "stderr should report a keystore key error: {stderr}"
    );
    assert!(
        !stderr.contains("software-raw:broken") && !stderr.contains("broken"),
        "stderr must not leak keystore label or key ref: {stderr}"
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

#[test]
fn key_export_and_delete_unknown_label_fail_cleanly() {
    let td = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(td.path().join("repo")).expect("repo dir");

    let export = run(
        td.path(),
        &[
            "key",
            "export",
            "--backend",
            "software-raw",
            "--label",
            "missing",
            "--algorithm",
            "ed25519",
            "--unsafe-print-secret",
        ],
    );
    assert_eq!(export.status.code(), Some(65));
    assert!(String::from_utf8_lossy(&export.stderr).contains("key not found"));

    let delete = run(
        td.path(),
        &[
            "key",
            "delete",
            "--backend",
            "software-raw",
            "--label",
            "missing",
            "--algorithm",
            "ed25519",
            "--yes",
        ],
    );
    assert_eq!(delete.status.code(), Some(65));
    assert!(String::from_utf8_lossy(&delete.stderr).contains("key not found"));
}

#[test]
fn key_list_does_not_cross_software_variants() {
    let td = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(td.path().join("repo")).expect("repo dir");

    import_raw_ed25519(td.path(), "raw-only", &[0x44; 32]);

    let encrypted_list = run(td.path(), &["key", "list", "--backend", "software"]);
    assert!(encrypted_list.status.success());
    assert!(
        !String::from_utf8(encrypted_list.stdout)
            .expect("stdout utf8")
            .contains("raw-only")
    );

    let raw_list = run(td.path(), &["key", "list", "--backend", "software-raw"]);
    assert!(raw_list.status.success());
    assert!(
        String::from_utf8(raw_list.stdout)
            .expect("stdout utf8")
            .contains("raw-only")
    );
}

#[test]
fn keystore_merge_missing_key_fails_without_generation() {
    let td = tempfile::tempdir().expect("tempdir");
    prepare_history_repo(td.path());
    run(td.path(), &["branch", "feature"]);

    assert!(run(td.path(), &["checkout", "feature"]).status.success());
    commit_file(td.path(), "feature.txt", b"feature\n", "feature commit");
    assert!(run(td.path(), &["checkout", "main"]).status.success());
    commit_file(td.path(), "main.txt", b"main\n", "main commit");
    configure_keystore_signer(td.path(), "software-raw:missing");

    let merge = run(td.path(), &["merge", "feature"]);
    assert_missing_history_key_failure(td.path(), &merge);
}

#[test]
fn keystore_cherry_pick_missing_key_fails_without_generation() {
    let td = tempfile::tempdir().expect("tempdir");
    prepare_history_repo(td.path());
    assert!(run(td.path(), &["branch", "feature"]).status.success());

    assert!(run(td.path(), &["checkout", "feature"]).status.success());
    commit_file(td.path(), "feature.txt", b"feature\n", "feature commit");
    let feature_commit = resolve_head(&td.path().join("repo"));
    assert!(run(td.path(), &["checkout", "main"]).status.success());
    commit_file(td.path(), "main.txt", b"main\n", "main commit");
    configure_keystore_signer(td.path(), "software-raw:missing");

    let cherry_pick = run(td.path(), &["cherry-pick", &feature_commit]);
    assert_missing_history_key_failure(td.path(), &cherry_pick);
}

#[test]
fn keystore_rebase_missing_key_fails_without_generation() {
    let td = tempfile::tempdir().expect("tempdir");
    prepare_history_repo(td.path());
    assert!(run(td.path(), &["branch", "feature"]).status.success());

    assert!(run(td.path(), &["checkout", "feature"]).status.success());
    commit_file(td.path(), "feature.txt", b"feature\n", "feature commit");
    assert!(run(td.path(), &["checkout", "main"]).status.success());
    commit_file(td.path(), "main.txt", b"main\n", "main commit");
    assert!(run(td.path(), &["checkout", "feature"]).status.success());
    configure_keystore_signer(td.path(), "software-raw:missing");

    let repo = td.path().join("repo");
    let head_before = std::fs::read_to_string(repo.join(".mkit/HEAD")).expect("HEAD before");
    let resolved_head_before = resolve_head(&repo);
    let index_before = std::fs::read(repo.join(".mkit/index")).expect("index before");

    let rebase = run(td.path(), &["rebase", "main"]);
    assert_missing_history_key_failure(td.path(), &rebase);
    assert!(
        !repo.join(".mkit/rebase-apply").exists(),
        "missing signer must fail before writing rebase state"
    );
    assert_eq!(
        std::fs::read_to_string(repo.join(".mkit/HEAD")).expect("HEAD after"),
        head_before,
        "missing signer must not detach HEAD"
    );
    assert_eq!(
        resolve_head(&repo),
        resolved_head_before,
        "missing signer must not move the current branch"
    );
    assert_eq!(
        std::fs::read(repo.join(".mkit/index")).expect("index after"),
        index_before,
        "missing signer must not rewrite the index"
    );
    assert!(
        repo.join("feature.txt").exists(),
        "missing signer must not restore away the feature worktree"
    );
    assert!(
        !repo.join("main.txt").exists(),
        "missing signer must fail before restoring the target worktree"
    );
}

fn prepare_history_repo(root: &std::path::Path) {
    std::fs::create_dir(root.join("repo")).expect("repo dir");
    assert!(run(root, &["init"]).status.success());
    let import = run(
        root,
        &[
            "key",
            "import",
            "--backend",
            "software-raw",
            "--algorithm",
            "ed25519",
            "--label",
            "history",
            "--hex",
            &"0a".repeat(32),
        ],
    );
    assert!(
        import.status.success(),
        "import stderr: {}",
        String::from_utf8_lossy(&import.stderr)
    );
    configure_keystore_signer(root, "software-raw:history");
    commit_file(root, "base.txt", b"base\n", "base commit");
}

fn configure_keystore_signer(root: &std::path::Path, key_ref: &str) {
    let cfg_dir = root.join("config/mkit");
    std::fs::create_dir_all(&cfg_dir).expect("config dir");
    std::fs::write(
        cfg_dir.join("config"),
        format!("signer = keystore\nkey.ed25519_ref = {key_ref}\n"),
    )
    .expect("user config");
}

fn commit_file(root: &std::path::Path, file: &str, body: &[u8], message: &str) {
    std::fs::write(root.join("repo").join(file), body).expect("write file");
    assert!(run(root, &["add", file]).status.success());
    let commit = run(root, &["commit", "-m", message]);
    assert!(
        commit.status.success(),
        "commit stderr: {}",
        String::from_utf8_lossy(&commit.stderr)
    );
}

fn import_raw_ed25519(root: &std::path::Path, label: &str, secret: &[u8; 32]) {
    let secret_hex = hex_lower(secret);
    let import = run(
        root,
        &[
            "key",
            "import",
            "--backend",
            "software-raw",
            "--algorithm",
            "ed25519",
            "--label",
            label,
            "--hex",
            &secret_hex,
        ],
    );
    assert!(
        import.status.success(),
        "import {label} stderr: {}",
        String::from_utf8_lossy(&import.stderr)
    );
}

fn assert_missing_history_key_failure(root: &std::path::Path, output: &Output) {
    assert!(!output.status.success(), "command unexpectedly succeeded");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("mkit key generate"),
        "stderr should point to key generation: {stderr}"
    );
    assert!(
        !root.join("repo/.mkit/keys/default.key").exists(),
        "history command must not silently create the legacy key"
    );
    assert!(
        !root
            .join("data/mkit/keys/raw/ed25519/6d697373696e67.raw")
            .exists(),
        "history command must not silently create a keystore key"
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

fn head_commit_signer(root: &std::path::Path) -> Vec<u8> {
    let head = resolve_head(root);
    let hash = mkit_core::hash::from_hex(&head).expect("head hash");
    let store = mkit_core::ObjectStore::open(root).expect("object store");
    match store.read_object(&hash).expect("head object") {
        Object::Commit(commit) => commit.signer.to_vec(),
        other => panic!("expected commit, got {other:?}"),
    }
}

fn ed25519_public_key(secret: &[u8; 32]) -> Vec<u8> {
    ed25519_dalek::SigningKey::from_bytes(secret)
        .verifying_key()
        .to_bytes()
        .to_vec()
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// `mkit key generate --algorithm bls12381-thr --threshold 3 --total 4
/// --label release` produces an N-share trusted-dealer set, stores
/// each share under `<label>-<index>` in the software keystore, and
/// prints the cohort keyid on stdout. Pinned to Phase 2 of issue
/// #160.
#[cfg(feature = "bls-threshold")]
#[test]
fn bls_threshold_key_generate_stores_shares_and_prints_keyid() {
    let td = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(td.path().join("repo")).expect("repo dir");

    let out = run(
        td.path(),
        &[
            "key",
            "generate",
            "--backend",
            "software",
            "--algorithm",
            "bls12381-thr",
            "--threshold",
            "3",
            "--total",
            "4",
            "--label",
            "release",
        ],
    );
    let stdout = String::from_utf8(out.stdout).expect("stdout utf8");
    let stderr = String::from_utf8(out.stderr).expect("stderr utf8");
    assert!(
        out.status.success(),
        "generate stderr: {stderr}\nstdout: {stdout}"
    );

    // stdout begins with the keyid `bls12381-thr:<192 hex chars>`.
    let first_line = stdout.lines().next().expect("at least one stdout line");
    assert!(
        first_line.starts_with("bls12381-thr:"),
        "expected bls12381-thr keyid, got: {first_line:?}"
    );
    let hex_body = first_line.strip_prefix("bls12381-thr:").unwrap();
    assert_eq!(
        hex_body.len(),
        192,
        "cohort pubkey hex must be 96 bytes = 192 hex chars",
    );

    // stderr reports the four share labels.
    assert!(
        stderr.contains("share 0: software:release-0"),
        "stderr: {stderr}"
    );
    assert!(
        stderr.contains("share 3: software:release-3"),
        "stderr: {stderr}"
    );
}

/// `--threshold` must equal the N3f1 quorum the Phase 1 dealer
/// produces; mismatched values are rejected so the caller doesn't
/// silently get a different M than they asked for.
#[cfg(feature = "bls-threshold")]
#[test]
fn bls_threshold_rejects_wrong_threshold_for_total() {
    let td = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(td.path().join("repo")).expect("repo dir");

    let out = run(
        td.path(),
        &[
            "key",
            "generate",
            "--backend",
            "software",
            "--algorithm",
            "bls12381-thr",
            "--threshold",
            "2",
            "--total",
            "4",
            "--label",
            "release",
        ],
    );
    assert!(!out.status.success(), "expected nonzero exit");
    let stderr = String::from_utf8(out.stderr).expect("stderr utf8");
    assert!(
        stderr.contains("N3f1 quorum"),
        "expected diagnostic about N3f1 quorum, got: {stderr}"
    );
}
