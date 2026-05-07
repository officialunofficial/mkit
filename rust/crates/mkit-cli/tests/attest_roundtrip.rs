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

/// Locate `mkit-sign-file` in the same `target/<profile>/` directory
/// `mkit` lives in. Assumes `cargo test --workspace` (or at least a
/// previous `cargo build -p mkit-sign-file`) has populated it; the
/// workspace CI target does so by construction, and a direct
/// `cargo test -p mkit-cli --test attest_roundtrip` triggers the build
/// via the explicit `CARGO_BIN_EXE_mkit` dependency — we mirror that
/// target dir here.
fn mkit_sign_file_bin() -> std::path::PathBuf {
    let mkit = std::path::PathBuf::from(mkit_bin());
    let target_dir = mkit.parent().expect("mkit_bin has a parent");
    let candidate = target_dir.join(if cfg!(windows) {
        "mkit-sign-file.exe"
    } else {
        "mkit-sign-file"
    });
    if !candidate.exists() {
        // The CI matrix always builds the whole workspace, but an
        // individual `cargo test -p mkit-cli` invocation might not.
        // Fall back to an on-the-fly build rather than silently skipping.
        let status = Command::new(env!("CARGO"))
            .args(["build", "-p", "mkit-sign-file"])
            .status()
            .expect("spawn cargo");
        assert!(status.success(), "cargo build -p mkit-sign-file failed");
    }
    candidate
}

fn run_in(cwd: &Path, args: &[&str]) -> Output {
    run_in_with_user_config(cwd, args, None)
}

/// Run `mkit` with `XDG_CONFIG_HOME` pointed at a per-call tempdir so
/// the developer's real user config does not leak into the test, and
/// optionally seed a `mkit/config` under that tempdir. Mirrors the
/// 0.3.0 split where security-sensitive keys live in user-scoped
/// config and per-repo `.mkit/config` cannot set them.
fn run_in_with_user_config(cwd: &Path, args: &[&str], user_cfg: Option<&str>) -> Output {
    let xdg_root = tempfile::tempdir().expect("xdg tempdir");
    if let Some(text) = user_cfg {
        let cfg_dir = xdg_root.path().join("mkit");
        fs::create_dir_all(&cfg_dir).unwrap();
        fs::write(cfg_dir.join("config"), text).unwrap();
    }
    let out = Command::new(mkit_bin())
        .args(args)
        .current_dir(cwd)
        .env("XDG_CONFIG_HOME", xdg_root.path())
        .output()
        .expect("spawn mkit");
    // Keep `xdg_root` alive until after the process completes — the
    // child reads the file lazily; if `xdg_root` dropped before this
    // line, the file would be removed mid-run.
    drop(xdg_root);
    out
}

fn init_repo_with_commit(cwd: &Path) {
    assert!(run_in(cwd, &["init"]).status.success());
    // 0.3.0 removed auto-keygen on `mkit commit`; tests now create
    // the signing key explicitly.
    let kg = run_in(cwd, &["keygen"]);
    assert!(
        kg.status.success(),
        "keygen failed: {}",
        String::from_utf8_lossy(&kg.stderr)
    );
    fs::write(cwd.join("README.md"), b"hello\n").unwrap();
    assert!(run_in(cwd, &["add", "README.md"]).status.success());
    let c = run_in(cwd, &["commit", "-m", "init"]);
    assert!(
        c.status.success(),
        "commit failed: {}",
        String::from_utf8_lossy(&c.stderr)
    );
}

/// Write a 32-byte raw key file with mode 0600.
fn write_key(path: &Path, bytes: &[u8; 32]) {
    if let Some(p) = path.parent() {
        fs::create_dir_all(p).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut dir_perm = fs::metadata(p).unwrap().permissions();
            dir_perm.set_mode(0o700);
            fs::set_permissions(p, dir_perm).unwrap();
        }
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

    let out = run_in(
        root,
        &[
            "verify-attest",
            "--trust-roots",
            ".mkit/attest-trust-roots.toml",
        ],
    );
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

    let out = run_in(
        root,
        &[
            "verify-attest",
            "--trust-roots",
            ".mkit/attest-trust-roots.toml",
        ],
    );
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

    let out = run_in(
        root,
        &[
            "verify-attest",
            "--trust-roots",
            ".mkit/attest-trust-roots.toml",
        ],
    );
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

// -- External-signer argv pass-through ---------------------------------
//
// The following three tests cover the gap that motivated PR #66 + #68:
// previously, `mkit attest --signer external` spawned the signer with
// zero argv and forced wrapper shell scripts. Each test drives the real
// `mkit-sign-file` reference binary, which takes `--key <path>` on
// argv — without the pass-through there's no way for the attest to
// reach the key file short of setting `MKIT_SIGN_FILE_KEY` in env.

/// Write a 32-byte ed25519 secret to `path` with mode 0600. Returns
/// the matching 32-byte pubkey bytes.
fn write_ed25519_key(path: &Path, secret: &[u8; 32]) -> Vec<u8> {
    write_key(path, secret);
    ed25519_pubkey(secret)
}

/// Shared skeleton for all three pass-through tests: init a repo with a
/// commit, write a 32-byte ed25519 key outside .mkit/ (so the CLI has to
/// reach it via argv), and return `(root, key_path, pubkey)`.
fn fixture_for_external_ed25519() -> (tempfile::TempDir, std::path::PathBuf, Vec<u8>) {
    let td = tempfile::tempdir().unwrap();
    let root = td.path().to_path_buf();
    init_repo_with_commit(&root);
    let key_path = root.join("external-signer.key");
    let mut secret = [0u8; 32];
    secret[31] = 9;
    let pk = write_ed25519_key(&key_path, &secret);
    (td, key_path, pk)
}

/// Turn a 32-byte ed25519 pubkey into the `blake3:<hex>` keyid mkit-sign-file
/// emits for that key.
fn blake3_keyid(pk: &[u8]) -> String {
    let h = mkit_core::hash::hash(pk);
    format!("blake3:{}", mkit_core::hash::to_hex(&h))
}

#[test]
fn attest_external_cli_flag_passes_argv() {
    // `--external-signer-arg --key --external-signer-arg <path>` must
    // reach `mkit-sign-file`'s `Args::parse`. Without pass-through the
    // binary errors with "no key path".
    //
    // 0.3.0: `attest.external_signer_path` is user-scoped, NOT
    // per-repo, so we point XDG_CONFIG_HOME at a tempdir and write
    // the config there.
    let (td, key_path, pk) = fixture_for_external_ed25519();
    let root = td.path();
    let signer_bin = mkit_sign_file_bin();

    let user_cfg = format!(
        "attest.external_signer_path = {}\n",
        signer_bin.to_str().unwrap()
    );
    let out = run_in_with_user_config(
        root,
        &[
            "attest",
            "--algorithm",
            "ed25519",
            "--signer",
            "external",
            "--external-signer-arg",
            "--key",
            "--external-signer-arg",
            key_path.to_str().unwrap(),
        ],
        Some(&user_cfg),
    );
    assert!(
        out.status.success(),
        "attest failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // Prove the attestation verifies against the key we wrote.
    let toml = format!(
        "[[trust_root]]\n\
         keyid = \"{}\"\n\
         kind = \"ed25519\"\n\
         pubkey_hex = \"{}\"\n",
        blake3_keyid(&pk),
        hex_lower(&pk)
    );
    fs::write(root.join(".mkit/attest-trust-roots.toml"), toml).unwrap();
    let out = run_in(
        root,
        &[
            "verify-attest",
            "--trust-roots",
            ".mkit/attest-trust-roots.toml",
        ],
    );
    assert!(
        out.status.success(),
        "verify failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn attest_external_config_args_pass_through() {
    // Same workflow via `attest.external_signer_args` in user-scoped
    // config. The per-repo path was an attack vector and is rejected
    // with a warning; this test verifies the legitimate user-scoped
    // configuration still works end-to-end.
    let (td, key_path, pk) = fixture_for_external_ed25519();
    let root = td.path();
    let signer_bin = mkit_sign_file_bin();

    let user_cfg = format!(
        "attest.external_signer_path = {}\n\
         attest.external_signer_args = --key|{}\n",
        signer_bin.to_str().unwrap(),
        key_path.to_str().unwrap()
    );

    let out = run_in_with_user_config(
        root,
        &["attest", "--algorithm", "ed25519", "--signer", "external"],
        Some(&user_cfg),
    );
    assert!(
        out.status.success(),
        "attest failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let toml = format!(
        "[[trust_root]]\n\
         keyid = \"{}\"\n\
         kind = \"ed25519\"\n\
         pubkey_hex = \"{}\"\n",
        blake3_keyid(&pk),
        hex_lower(&pk)
    );
    fs::write(root.join(".mkit/attest-trust-roots.toml"), toml).unwrap();
    let out = run_in(
        root,
        &[
            "verify-attest",
            "--trust-roots",
            ".mkit/attest-trust-roots.toml",
        ],
    );
    assert!(out.status.success());
}

#[test]
fn attest_additional_signer_args_clause_pass_through() {
    // Multi-sig: primary is repo-key ed25519 (auto-generated), additional
    // signer is external ed25519 via mkit-sign-file + `args=` clause.
    // Both signatures must land in the envelope and verify.
    let (td, key_path, pk_ext) = fixture_for_external_ed25519();
    let root = td.path();
    let signer_bin = mkit_sign_file_bin();

    // Primary (repo-key) ed25519 is whatever `.mkit/keys/default.key`
    // the commit step created. Read it to derive its pubkey.
    let primary_secret = fs::read(root.join(".mkit/keys/default.key")).unwrap();
    let mut primary = [0u8; 32];
    primary.copy_from_slice(&primary_secret);
    let pk_primary = ed25519_pubkey(&primary);

    // No need for a config — the additional-signer spec carries its
    // own path=.
    let spec = format!(
        "algorithm=ed25519,signer=external,path={},args=--key|{}",
        signer_bin.to_str().unwrap(),
        key_path.to_str().unwrap()
    );
    let out = run_in(
        root,
        &[
            "attest",
            "--algorithm",
            "ed25519",
            "--signer",
            "repo-key",
            "--additional-signer",
            &spec,
        ],
    );
    assert!(
        out.status.success(),
        "attest failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains("2 signature(s)"),
        "expected envelope to carry two signatures; got: {stdout}"
    );

    // Trust roots must list BOTH keys so verify-attest accepts both.
    let toml = format!(
        "[[trust_root]]\n\
         keyid = \"{}\"\n\
         kind = \"ed25519\"\n\
         pubkey_hex = \"{}\"\n\
         \n\
         [[trust_root]]\n\
         keyid = \"{}\"\n\
         kind = \"ed25519\"\n\
         pubkey_hex = \"{}\"\n",
        blake3_keyid(&pk_primary),
        hex_lower(&pk_primary),
        blake3_keyid(&pk_ext),
        hex_lower(&pk_ext),
    );
    fs::write(root.join(".mkit/attest-trust-roots.toml"), toml).unwrap();
    let out = run_in(
        root,
        &[
            "verify-attest",
            "--trust-roots",
            ".mkit/attest-trust-roots.toml",
        ],
    );
    assert!(
        out.status.success(),
        "verify failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}
