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
    assert!(
        stdout
            .lines()
            .last()
            .unwrap_or_default()
            .starts_with("ed25519:")
    );
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
