//! End-to-end coverage for `attest.signer = keystore`.

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn mkit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_mkit")
}

fn run(root: &Path, args: &[&str]) -> Output {
    Command::new(mkit_bin())
        .args(args)
        .current_dir(root.join("repo"))
        .env("XDG_CONFIG_HOME", root.join("config"))
        .env("XDG_DATA_HOME", root.join("data"))
        .output()
        .expect("spawn mkit")
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

#[test]
fn attest_with_keystore_ed25519_roundtrip() {
    let td = tempfile::tempdir().expect("tempdir");
    let repo = td.path().join("repo");
    fs::create_dir(&repo).expect("repo dir");

    assert!(run(td.path(), &["init"]).status.success());
    assert!(run(td.path(), &["keygen"]).status.success());
    fs::write(repo.join("README.md"), b"hello\n").expect("write README");
    assert!(run(td.path(), &["add", "README.md"]).status.success());
    let commit = run(td.path(), &["commit", "-m", "init"]);
    assert!(
        commit.status.success(),
        "commit stderr: {}",
        String::from_utf8_lossy(&commit.stderr)
    );

    let secret = [0x55; 32];
    let secret_hex = hex_lower(&secret);
    let import = run(
        td.path(),
        &[
            "key",
            "import",
            "--algorithm",
            "ed25519",
            "--label",
            "attester",
            "--hex",
            &secret_hex,
        ],
    );
    assert!(
        import.status.success(),
        "import stderr: {}",
        String::from_utf8_lossy(&import.stderr)
    );

    let cfg_dir = td.path().join("config/mkit");
    fs::create_dir_all(&cfg_dir).expect("config dir");
    fs::write(
        cfg_dir.join("config"),
        "attest.signer = keystore\nkey.ed25519_ref = software:attester\n",
    )
    .expect("user config");

    let attest = run(td.path(), &["attest", "--algorithm", "ed25519"]);
    assert!(
        attest.status.success(),
        "attest stderr: {}",
        String::from_utf8_lossy(&attest.stderr)
    );

    let public_key = ed25519_dalek::SigningKey::from_bytes(&secret)
        .verifying_key()
        .to_bytes();
    let public_hex = hex_lower(&public_key);
    fs::write(
        repo.join(".mkit/attest-trust-roots.toml"),
        format!(
            "[[trust_root]]\nkeyid = \"ed25519:{public_hex}\"\nkind = \"ed25519\"\npubkey_hex = \"{public_hex}\"\n"
        ),
    )
    .expect("trust roots");

    let verify = run(
        td.path(),
        &[
            "verify-attest",
            "--trust-roots",
            ".mkit/attest-trust-roots.toml",
        ],
    );
    assert!(
        verify.status.success(),
        "verify stdout: {}\nverify stderr: {}",
        String::from_utf8_lossy(&verify.stdout),
        String::from_utf8_lossy(&verify.stderr)
    );
}
