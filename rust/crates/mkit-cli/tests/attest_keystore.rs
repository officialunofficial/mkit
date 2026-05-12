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

fn public_key_and_trust_kind(algorithm: &str, secret: &[u8; 32]) -> (Vec<u8>, &'static str) {
    match algorithm {
        "ed25519" => (
            ed25519_dalek::SigningKey::from_bytes(secret)
                .verifying_key()
                .to_bytes()
                .to_vec(),
            "ed25519",
        ),
        "secp256k1" => {
            let signing_key = k256::ecdsa::SigningKey::from_bytes(secret.into()).unwrap();
            (
                signing_key
                    .verifying_key()
                    .to_encoded_point(true)
                    .as_bytes()
                    .to_vec(),
                "secp256k1",
            )
        }
        "p256" => {
            let signing_key = p256::ecdsa::SigningKey::from_bytes(&(*secret).into()).unwrap();
            (
                signing_key
                    .verifying_key()
                    .to_encoded_point(true)
                    .as_bytes()
                    .to_vec(),
                "p256-sec1",
            )
        }
        other => panic!("unsupported test algorithm: {other}"),
    }
}

fn init_repo_with_commit(root: &Path) {
    let repo = root.join("repo");
    fs::create_dir(&repo).expect("repo dir");
    assert!(run(root, &["init"]).status.success());
    assert!(run(root, &["keygen"]).status.success());
    fs::write(repo.join("README.md"), b"hello\n").expect("write README");
    assert!(run(root, &["add", "README.md"]).status.success());
    let commit = run(root, &["commit", "-m", "init"]);
    assert!(
        commit.status.success(),
        "commit stderr: {}",
        String::from_utf8_lossy(&commit.stderr)
    );
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

#[test]
fn attest_with_software_raw_keystore_all_algorithms_roundtrip() {
    let mut secp256k1_secret = [0u8; 32];
    secp256k1_secret[31] = 42;
    let mut p256_secret = [0u8; 32];
    p256_secret[31] = 7;

    for (algorithm, ref_key, label, secret) in [
        ("ed25519", "key.ed25519_ref", "raw-ed", [0x55; 32]),
        ("secp256k1", "key.secp256k1_ref", "raw-k1", secp256k1_secret),
        ("p256", "key.p256_ref", "raw-p256", p256_secret),
    ] {
        let td = tempfile::tempdir().expect("tempdir");
        init_repo_with_commit(td.path());

        let secret_hex = hex_lower(&secret);
        let import = run(
            td.path(),
            &[
                "key",
                "import",
                "--backend",
                "software-raw",
                "--algorithm",
                algorithm,
                "--label",
                label,
                "--hex",
                &secret_hex,
            ],
        );
        assert!(
            import.status.success(),
            "{algorithm} import stderr: {}",
            String::from_utf8_lossy(&import.stderr)
        );

        let cfg_dir = td.path().join("config/mkit");
        fs::create_dir_all(&cfg_dir).expect("config dir");
        fs::write(
            cfg_dir.join("config"),
            format!("attest.signer = keystore\n{ref_key} = software-raw:{label}\n"),
        )
        .expect("user config");

        let attest = run(td.path(), &["attest", "--algorithm", algorithm]);
        assert!(
            attest.status.success(),
            "{algorithm} attest stderr: {}",
            String::from_utf8_lossy(&attest.stderr)
        );

        let repo = td.path().join("repo");
        let (public_key, trust_kind) = public_key_and_trust_kind(algorithm, &secret);
        let public_hex = hex_lower(&public_key);
        fs::write(
            repo.join(".mkit/attest-trust-roots.toml"),
            format!(
                "[[trust_root]]\nkeyid = \"{algorithm}:{public_hex}\"\nkind = \"{trust_kind}\"\npubkey_hex = \"{public_hex}\"\n"
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
            "{algorithm} verify stdout: {}\nverify stderr: {}",
            String::from_utf8_lossy(&verify.stdout),
            String::from_utf8_lossy(&verify.stderr)
        );
    }
}

#[test]
fn attest_with_keystore_missing_key_fails_without_generation() {
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

    let cfg_dir = td.path().join("config/mkit");
    fs::create_dir_all(&cfg_dir).expect("config dir");
    fs::write(
        cfg_dir.join("config"),
        "attest.signer = keystore\nkey.ed25519_ref = software:missing\n",
    )
    .expect("user config");

    let attest = run(td.path(), &["attest", "--algorithm", "ed25519"]);
    assert_eq!(attest.status.code(), Some(66));
    let stderr = String::from_utf8_lossy(&attest.stderr);
    assert!(
        stderr.contains("mkit key generate"),
        "stderr should point to key generation: {stderr}"
    );
    assert!(
        !td.path().join("data/mkit/keys").exists(),
        "keystore attest must not silently create a keystore key"
    );
}
