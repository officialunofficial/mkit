//! End-to-end tests for `mkit attest` + `mkit verify-attest`.
//!
//! For each supported algorithm we:
//!   1. Generate a raw 32-byte secret, write it to `.mkit/keys/<algo>.key`.
//!   2. Init a fresh repo, stage a file, commit.
//!   3. Shell out to `mkit attest --algorithm <X> --signer repo-key`.
//!   4. Build a trust-roots TOML with the matching pubkey.
//!   5. Shell out to `mkit verify-attest` and assert exit 0 + one
//!      verified signature in the output.

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn mkit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_mkit")
}

fn run_in(cwd: &Path, args: &[&str]) -> Output {
    Command::new(mkit_bin())
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("spawn mkit")
}

fn init_repo_with_commit(cwd: &Path) {
    assert!(run_in(cwd, &["init"]).status.success());
    fs::write(cwd.join("README.md"), b"hello\n").unwrap();
    assert!(run_in(cwd, &["add", "README.md"]).status.success());
    assert!(run_in(cwd, &["commit", "-m", "init"]).status.success());
}

/// Write a 32-byte raw key file with mode 0600.
fn write_key(path: &Path, bytes: &[u8; 32]) {
    if let Some(p) = path.parent() {
        fs::create_dir_all(p).unwrap();
    }
    fs::write(path, bytes).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perm = fs::metadata(path).unwrap().permissions();
        perm.set_mode(0o600);
        fs::set_permissions(path, perm).unwrap();
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0F) as usize] as char);
    }
    s
}

// -- Per-algorithm helpers. The CLI will load raw 32-byte key files,
// but the test itself must know the public key to embed in the
// trust-roots TOML.

fn ed25519_pubkey(secret: &[u8; 32]) -> Vec<u8> {
    use ed25519_dalek::SigningKey;
    let sk = SigningKey::from_bytes(secret);
    sk.verifying_key().to_bytes().to_vec()
}

#[test]
fn attest_and_verify_ed25519_roundtrip() {
    let td = tempfile::tempdir().unwrap();
    let root = td.path();
    init_repo_with_commit(root);

    // For ed25519 repo-key signer, mkit uses the existing `.mkit/keys/default.key`
    // (already created by `commit`). Read it to derive the pubkey.
    let key_path = root.join(".mkit/keys/default.key");
    let secret_bytes = fs::read(&key_path).unwrap();
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&secret_bytes);
    let pk = ed25519_pubkey(&secret);

    let pk_hash = {
        // Per repo-key signer convention, keyid is "blake3:<hex(BLAKE3(pk))>".
        let h = mkit_core::hash::hash(&pk);
        mkit_core::hash::to_hex(&h)
    };

    let out = run_in(
        root,
        &["attest", "--algorithm", "ed25519", "--signer", "repo-key"],
    );
    assert!(
        out.status.success(),
        "attest failed: status={:?} stderr={}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );

    // Trust-roots: keyid is "blake3:<blake3(pk)>", kind = "ed25519", pubkey_hex = hex(pk).
    let toml = format!(
        "[[trust_root]]\n\
         keyid = \"blake3:{}\"\n\
         kind = \"ed25519\"\n\
         pubkey_hex = \"{}\"\n",
        pk_hash,
        hex_lower(&pk)
    );
    let trust_path = root.join(".mkit/attest-trust-roots.toml");
    fs::write(&trust_path, toml).unwrap();

    let out = run_in(root, &["verify-attest"]);
    assert!(
        out.status.success(),
        "verify-attest failed: status={:?} stdout={} stderr={}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains("verified") || stdout.contains("Ok"),
        "verify-attest did not report verified signature: {stdout}"
    );
}

#[test]
fn attest_and_verify_secp256k1_roundtrip() {
    use k256::ecdsa::SigningKey;

    let td = tempfile::tempdir().unwrap();
    let root = td.path();
    init_repo_with_commit(root);

    // Fresh secp256k1 secret — avoid zero / small values. Use a
    // deterministic one that's guaranteed valid.
    let mut secret = [0u8; 32];
    secret[31] = 42;
    let pk = {
        let sk = SigningKey::from_bytes((&secret).into()).unwrap();
        sk.verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec()
    };
    let keyid = format!("secp256k1:{}", hex_lower(&pk));

    let key_path = root.join(".mkit/keys/secp256k1.key");
    write_key(&key_path, &secret);

    // Configure the secp256k1 key path.
    fs::create_dir_all(root.join(".mkit")).unwrap();
    fs::write(
        root.join(".mkit/config"),
        b"attest.secp256k1_key_path = .mkit/keys/secp256k1.key\n",
    )
    .unwrap();

    let out = run_in(
        root,
        &["attest", "--algorithm", "secp256k1", "--signer", "repo-key"],
    );
    assert!(
        out.status.success(),
        "attest failed: status={:?} stdout={} stderr={}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let toml = format!(
        "[[trust_root]]\n\
         keyid = \"{}\"\n\
         kind = \"secp256k1\"\n\
         pubkey_hex = \"{}\"\n",
        keyid,
        hex_lower(&pk)
    );
    fs::write(root.join(".mkit/attest-trust-roots.toml"), toml).unwrap();

    let out = run_in(root, &["verify-attest"]);
    assert!(
        out.status.success(),
        "verify-attest failed: status={:?} stdout={} stderr={}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains("verified") || stdout.contains("Ok"),
        "verify-attest did not report verified signature: {stdout}"
    );
}

#[test]
fn attest_and_verify_p256_roundtrip() {
    use p256::ecdsa::SigningKey;

    let td = tempfile::tempdir().unwrap();
    let root = td.path();
    init_repo_with_commit(root);

    let mut secret = [0u8; 32];
    secret[31] = 7;
    let pk = {
        let sk = SigningKey::from_bytes(&secret.into()).unwrap();
        sk.verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec()
    };
    let keyid = format!("p256:{}", hex_lower(&pk));

    let key_path = root.join(".mkit/keys/p256.key");
    write_key(&key_path, &secret);

    fs::create_dir_all(root.join(".mkit")).unwrap();
    fs::write(
        root.join(".mkit/config"),
        b"attest.p256_key_path = .mkit/keys/p256.key\n",
    )
    .unwrap();

    let out = run_in(
        root,
        &["attest", "--algorithm", "p256", "--signer", "repo-key"],
    );
    assert!(
        out.status.success(),
        "attest failed: status={:?} stdout={} stderr={}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let toml = format!(
        "[[trust_root]]\n\
         keyid = \"{}\"\n\
         kind = \"p256-sec1\"\n\
         pubkey_hex = \"{}\"\n",
        keyid,
        hex_lower(&pk)
    );
    fs::write(root.join(".mkit/attest-trust-roots.toml"), toml).unwrap();

    let out = run_in(root, &["verify-attest"]);
    assert!(
        out.status.success(),
        "verify-attest failed: status={:?} stdout={} stderr={}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains("verified") || stdout.contains("Ok"),
        "verify-attest did not report verified signature: {stdout}"
    );
}

#[test]
fn attest_missing_keyfile_errors_cleanly() {
    // For secp256k1 without a key file, we should get a clear error
    // pointing the user at `mkit keygen --algorithm secp256k1`.
    let td = tempfile::tempdir().unwrap();
    let root = td.path();
    init_repo_with_commit(root);

    // Force secp256k1 path at a file that doesn't exist.
    fs::write(
        root.join(".mkit/config"),
        b"attest.secp256k1_key_path = .mkit/keys/does-not-exist.key\n",
    )
    .unwrap();

    let out = run_in(
        root,
        &["attest", "--algorithm", "secp256k1", "--signer", "repo-key"],
    );
    assert!(!out.status.success(), "attest should have failed");
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("keygen") || stderr.contains("secp256k1"),
        "error message should mention keygen/secp256k1: {stderr}"
    );
}

#[test]
fn attest_unknown_algorithm_errors() {
    let td = tempfile::tempdir().unwrap();
    let root = td.path();
    init_repo_with_commit(root);

    let out = run_in(root, &["attest", "--algorithm", "rsa"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("rsa") || stderr.contains("algorithm"),
        "error did not explain unknown algorithm: {stderr}"
    );
}

#[test]
fn attest_malformed_predicate_file_errors() {
    let td = tempfile::tempdir().unwrap();
    let root = td.path();
    init_repo_with_commit(root);

    let bad = root.join("bad-predicate.json");
    fs::write(&bad, b"not valid json").unwrap();

    let out = run_in(
        root,
        &[
            "attest",
            "--algorithm",
            "ed25519",
            "--predicate-file",
            bad.to_str().unwrap(),
        ],
    );
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("predicate") || stderr.contains("JSON") || stderr.contains("json"),
        "error did not mention predicate: {stderr}"
    );
}
