//! Integration tests for `mkit keygen --algorithm` + `mkit attest
//! --additional-signer` (Phase 2 multi-algorithm / multi-signature).
//!
//! These tests drive the `mkit` binary end-to-end:
//! * Generate per-algorithm keys with `mkit keygen --algorithm <algo>`.
//! * Extract the public key via `--print-pubkey`.
//! * Produce a multi-signature envelope with `mkit attest
//! --additional-signer ...`.
//! * Verify the envelope with `mkit verify-attest` against a
//! trust-roots TOML listing every pubkey.

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn mkit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_mkit")
}

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

fn init_repo_with_commit(cwd: &Path) {
    assert!(run_in(cwd, &["init"]).status.success());
    // explicit keygen required (auto-keygen on commit removed).
    assert!(run_in(cwd, &["keygen"]).status.success());
    fs::write(cwd.join("README.md"), b"hello\n").unwrap();
    assert!(run_in(cwd, &["add", "README.md"]).status.success());
    assert!(run_in(cwd, &["commit", "-m", "init"]).status.success());
}

// ---------------------------------------------------------------------------
// `mkit keygen --algorithm`
// ---------------------------------------------------------------------------

#[test]
fn keygen_secp256k1_writes_32_byte_key_with_mode_0600() {
    let td = tempfile::tempdir().unwrap();
    let root = td.path();
    init_repo_with_commit(root);

    let out = run_in(root, &["keygen", "--algorithm", "secp256k1"]);
    assert!(
        out.status.success(),
        "keygen failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    let key_path = root.join(".mkit/keys/secp256k1.key");
    assert!(key_path.exists(), "secp256k1 key file not created");
    let bytes = fs::read(&key_path).unwrap();
    assert_eq!(bytes.len(), 32, "secp256k1 secret must be 32 bytes");

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let mode = fs::metadata(&key_path).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o600, "key file mode should be 0600, got {mode:o}");
    }
}

#[test]
fn keygen_p256_writes_to_custom_config_path() {
    // `attest.p256_key_path` is user-scoped only — a per-repo
    // value would let a hostile clone redirect where keys land. We
    // honour it from `$XDG_CONFIG_HOME/mkit/config` and ignore it
    // from `<repo>/.mkit/config` (with a stderr warning).
    let td = tempfile::tempdir().unwrap();
    let root = td.path();
    let xdg = tempfile::tempdir().unwrap();
    let xdg_path = xdg.path().to_path_buf();
    let cfg_dir = xdg_path.join("mkit");
    fs::create_dir_all(&cfg_dir).unwrap();
    fs::write(
        cfg_dir.join("config"),
        b"attest.p256_key_path = .mkit/keys/custom-p256.key\n",
    )
    .unwrap();

    // init + keygen (ed25519 default, populates .mkit/keys/default.key
    // for the upcoming commit).
    assert!(
        Command::new(mkit_bin())
            .args(["init"])
            .current_dir(root)
            .env("XDG_CONFIG_HOME", &xdg_path)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new(mkit_bin())
            .args(["keygen"])
            .current_dir(root)
            .env("XDG_CONFIG_HOME", &xdg_path)
            .status()
            .unwrap()
            .success()
    );
    fs::write(root.join("README.md"), b"hello\n").unwrap();
    assert!(
        Command::new(mkit_bin())
            .args(["add", "README.md"])
            .current_dir(root)
            .env("XDG_CONFIG_HOME", &xdg_path)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new(mkit_bin())
            .args(["commit", "-m", "init"])
            .current_dir(root)
            .env("XDG_CONFIG_HOME", &xdg_path)
            .status()
            .unwrap()
            .success()
    );

    // Now keygen --algorithm p256 — should land at the custom path
    // configured in user-scoped config.
    let out = Command::new(mkit_bin())
        .args(["keygen", "--algorithm", "p256"])
        .current_dir(root)
        .env("XDG_CONFIG_HOME", &xdg_path)
        .output()
        .expect("spawn mkit");
    assert!(
        out.status.success(),
        "keygen failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    assert!(root.join(".mkit/keys/custom-p256.key").exists());
    assert!(!root.join(".mkit/keys/p256.key").exists());
}

#[test]
fn keygen_default_ed25519_behavior_preserved() {
    // `mkit keygen` with no flag must still generate the ed25519 key at
    // `.mkit/keys/default.key` — backward compat.
    let td = tempfile::tempdir().unwrap();
    let root = td.path();
    fs::create_dir_all(root.join(".mkit")).unwrap();
    // Don't use init_repo_with_commit (that creates default.key via commit).

    let out = run_in(root, &["keygen"]);
    assert!(
        out.status.success(),
        "default keygen failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(root.join(".mkit/keys/default.key").exists());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains("ed25519:"),
        "default keygen should print ed25519 pubkey line: {stdout}"
    );
}

#[test]
fn keygen_refuses_to_overwrite_without_force() {
    let td = tempfile::tempdir().unwrap();
    let root = td.path();
    init_repo_with_commit(root);

    let out = run_in(root, &["keygen", "--algorithm", "secp256k1"]);
    assert!(out.status.success());

    let out = run_in(root, &["keygen", "--algorithm", "secp256k1"]);
    assert!(
        !out.status.success(),
        "second keygen without --force should fail"
    );
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("already exists") || stderr.contains("--force"),
        "error should mention existing key / --force: {stderr}"
    );
}

#[test]
fn keygen_force_overwrites_existing_key() {
    let td = tempfile::tempdir().unwrap();
    let root = td.path();
    init_repo_with_commit(root);

    assert!(
        run_in(root, &["keygen", "--algorithm", "secp256k1"])
            .status
            .success()
    );
    let first = fs::read(root.join(".mkit/keys/secp256k1.key")).unwrap();

    let out = run_in(root, &["keygen", "--algorithm", "secp256k1", "--force"]);
    assert!(
        out.status.success(),
        "forced keygen failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let second = fs::read(root.join(".mkit/keys/secp256k1.key")).unwrap();
    assert_eq!(second.len(), 32);
    assert_ne!(first, second, "forced keygen should produce fresh bytes");
}

#[test]
fn keygen_print_pubkey_secp256k1_parseable() {
    let td = tempfile::tempdir().unwrap();
    let root = td.path();
    init_repo_with_commit(root);

    // Generate the key first.
    assert!(
        run_in(root, &["keygen", "--algorithm", "secp256k1"])
            .status
            .success()
    );
    // Now print its pubkey; must NOT regenerate (idempotent read).
    let out = run_in(
        root,
        &["keygen", "--algorithm", "secp256k1", "--print-pubkey"],
    );
    assert!(
        out.status.success(),
        "--print-pubkey failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    // The pubkey keyid line must be exactly `secp256k1:<66-hex>\n`.
    let line = stdout
        .lines()
        .find(|l| l.starts_with("secp256k1:"))
        .unwrap_or_else(|| panic!("no secp256k1: line in stdout: {stdout}"));
    let hex = line.strip_prefix("secp256k1:").unwrap();
    assert_eq!(
        hex.len(),
        66,
        "compressed SEC1 pubkey is 33 bytes = 66 hex chars"
    );
    assert!(
        hex.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()),
        "hex must be lowercase: {line}"
    );
}

#[test]
fn keygen_print_pubkey_p256_format() {
    let td = tempfile::tempdir().unwrap();
    let root = td.path();
    init_repo_with_commit(root);

    assert!(
        run_in(root, &["keygen", "--algorithm", "p256"])
            .status
            .success()
    );
    let out = run_in(root, &["keygen", "--algorithm", "p256", "--print-pubkey"]);
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    let line = stdout
        .lines()
        .find(|l| l.starts_with("p256:"))
        .unwrap_or_else(|| panic!("no p256: line in stdout: {stdout}"));
    let hex = line.strip_prefix("p256:").unwrap();
    assert_eq!(hex.len(), 66, "compressed p256 is 66 hex chars");
}

#[test]
fn keygen_unknown_algorithm_errors() {
    let td = tempfile::tempdir().unwrap();
    let root = td.path();
    init_repo_with_commit(root);

    let out = run_in(root, &["keygen", "--algorithm", "rsa"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("rsa") || stderr.contains("algorithm"),
        "error should mention the bad algorithm: {stderr}"
    );
}

#[test]
fn keygen_secp256k1_produces_usable_key_for_attest() {
    // End-to-end: keygen → attest → verify with --print-pubkey output.
    let td = tempfile::tempdir().unwrap();
    let root = td.path();
    init_repo_with_commit(root);

    assert!(
        run_in(root, &["keygen", "--algorithm", "secp256k1"])
            .status
            .success()
    );
    let print = run_in(
        root,
        &["keygen", "--algorithm", "secp256k1", "--print-pubkey"],
    );
    assert!(print.status.success());
    let print_stdout = String::from_utf8(print.stdout).unwrap();
    let keyid = print_stdout
        .lines()
        .find(|l| l.starts_with("secp256k1:"))
        .unwrap()
        .to_owned();
    let pubkey_hex = keyid.strip_prefix("secp256k1:").unwrap();

    let out = run_in(root, &["attest", "--algorithm", "secp256k1"]);
    assert!(
        out.status.success(),
        "attest with keygen'd key failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Build trust-roots and verify.
    let toml = format!(
        "[[trust_root]]\n\
         keyid = \"{keyid}\"\n\
         kind = \"secp256k1\"\n\
         pubkey_hex = \"{pubkey_hex}\"\n"
    );
    fs::write(root.join(".mkit/attest-trust-roots.toml"), toml).unwrap();

    let v = run_in(
        root,
        &[
            "verify-attest",
            "--trust-roots",
            ".mkit/attest-trust-roots.toml",
        ],
    );
    assert!(
        v.status.success(),
        "verify-attest failed: stdout={} stderr={}",
        String::from_utf8_lossy(&v.stdout),
        String::from_utf8_lossy(&v.stderr)
    );
}

// ---------------------------------------------------------------------------
// `mkit attest --additional-signer`
// ---------------------------------------------------------------------------

#[test]
#[allow(clippy::too_many_lines)]
fn attest_three_way_envelope_ed25519_secp256k1_p256() {
    use ed25519_dalek::SigningKey;

    // Primary ed25519 + additional secp256k1 + additional p256, all
    // repo-key signers. Envelope must carry exactly three signatures
    // with the right keyid prefixes, all verifying under a trust-roots
    // file listing all three pubkeys.
    let td = tempfile::tempdir().unwrap();
    let root = td.path();
    init_repo_with_commit(root);

    // Generate the secp256k1 + p256 keys.
    assert!(
        run_in(root, &["keygen", "--algorithm", "secp256k1"])
            .status
            .success()
    );
    assert!(
        run_in(root, &["keygen", "--algorithm", "p256"])
            .status
            .success()
    );

    // Capture all three keyids for the trust-roots file.
    let ed25519_kid = {
        // ed25519 repo-key signer emits `blake3:<hex>` keyid.
        let secret_bytes = fs::read(root.join(".mkit/keys/default.key")).unwrap();
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&secret_bytes);
        let sk = SigningKey::from_bytes(&secret);
        let pk = sk.verifying_key().to_bytes();
        let h = mkit_core::hash::hash(&pk);
        (
            format!("blake3:{}", mkit_core::hash::to_hex(&h)),
            pk.to_vec(),
        )
    };
    let secp_kid = {
        let line = String::from_utf8(
            run_in(
                root,
                &["keygen", "--algorithm", "secp256k1", "--print-pubkey"],
            )
            .stdout,
        )
        .unwrap();
        let kid_line = line
            .lines()
            .find(|l| l.starts_with("secp256k1:"))
            .unwrap()
            .to_owned();
        let hex = kid_line.strip_prefix("secp256k1:").unwrap().to_owned();
        let bytes = hex_decode(&hex);
        (kid_line, bytes)
    };
    let p256_kid = {
        let line = String::from_utf8(
            run_in(root, &["keygen", "--algorithm", "p256", "--print-pubkey"]).stdout,
        )
        .unwrap();
        let kid_line = line
            .lines()
            .find(|l| l.starts_with("p256:"))
            .unwrap()
            .to_owned();
        let hex = kid_line.strip_prefix("p256:").unwrap().to_owned();
        let bytes = hex_decode(&hex);
        (kid_line, bytes)
    };

    // Three-way attest: primary ed25519 + additional secp256k1 + p256.
    let out = run_in(
        root,
        &[
            "attest",
            "--algorithm",
            "ed25519",
            "--additional-signer",
            "algorithm=secp256k1,signer=repo-key",
            "--additional-signer",
            "algorithm=p256,signer=repo-key",
        ],
    );
    assert!(
        out.status.success(),
        "three-way attest failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Verify the envelope has three signatures.
    let commit_hash = resolve_head(root);
    let att_dir = root.join(format!(".mkit/attestations/{commit_hash}"));
    let entries: Vec<_> = fs::read_dir(&att_dir)
        .unwrap()
        .filter_map(std::result::Result::ok)
        .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("dsse"))
        .collect();
    assert_eq!(entries.len(), 1, "expected exactly one envelope on disk");
    let env_bytes = fs::read(entries[0].path()).unwrap();
    let env = mkit_attest::envelope::decode(&env_bytes).unwrap();
    assert_eq!(env.signatures.len(), 3, "envelope must carry 3 signatures");

    // Order-preserving keyid prefix check.
    assert!(
        env.signatures[0].keyid.starts_with("blake3:")
            || env.signatures[0].keyid.starts_with("ed25519:"),
        "first sig should be ed25519/blake3: {:?}",
        env.signatures[0].keyid
    );
    assert!(
        env.signatures[1].keyid.starts_with("secp256k1:"),
        "second sig should be secp256k1: {:?}",
        env.signatures[1].keyid
    );
    assert!(
        env.signatures[2].keyid.starts_with("p256:"),
        "third sig should be p256: {:?}",
        env.signatures[2].keyid
    );

    // Trust-roots listing all three pubkeys.
    let toml = format!(
        "[[trust_root]]\nkeyid = \"{}\"\nkind = \"ed25519\"\npubkey_hex = \"{}\"\n\
         [[trust_root]]\nkeyid = \"{}\"\nkind = \"secp256k1\"\npubkey_hex = \"{}\"\n\
         [[trust_root]]\nkeyid = \"{}\"\nkind = \"p256-sec1\"\npubkey_hex = \"{}\"\n",
        ed25519_kid.0,
        hex_encode(&ed25519_kid.1),
        secp_kid.0,
        hex_encode(&secp_kid.1),
        p256_kid.0,
        hex_encode(&p256_kid.1),
    );
    fs::write(root.join(".mkit/attest-trust-roots.toml"), toml).unwrap();

    let v = run_in(
        root,
        &[
            "verify-attest",
            "--trust-roots",
            ".mkit/attest-trust-roots.toml",
        ],
    );
    assert!(
        v.status.success(),
        "verify-attest failed: stdout={} stderr={}",
        String::from_utf8_lossy(&v.stdout),
        String::from_utf8_lossy(&v.stderr)
    );
    let vstdout = String::from_utf8(v.stdout).unwrap();
    // All three signatures should be reported as verified.
    let verified_count = vstdout.matches("verified").count();
    assert!(
        verified_count >= 3,
        "expected 3 verified lines, got: {vstdout}"
    );
}

#[test]
fn attest_additional_signer_malformed_spec_errors() {
    let td = tempfile::tempdir().unwrap();
    let root = td.path();
    init_repo_with_commit(root);

    let out = run_in(
        root,
        &[
            "attest",
            "--additional-signer",
            "algorithm=ed25519 signer=repo-key", // missing comma
        ],
    );
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("additional-signer")
            || stderr.contains("spec")
            || stderr.contains("algorithm"),
        "error should explain bad spec: {stderr}"
    );
}

#[test]
fn attest_one_additional_signer_failure_aborts_no_partial_envelope() {
    let td = tempfile::tempdir().unwrap();
    let root = td.path();
    init_repo_with_commit(root);

    // Get commit hash before attest.
    let commit_hash = resolve_head(root);

    // Point additional-signer at a non-existent external binary.
    let out = run_in(
        root,
        &[
            "attest",
            "--additional-signer",
            "algorithm=ed25519,signer=external,path=/definitely/does/not/exist/mkit-fake-signer",
        ],
    );
    assert!(!out.status.success(), "attest should have failed");

    // No envelope should have been written.
    let att_dir = root.join(format!(".mkit/attestations/{commit_hash}"));
    if att_dir.exists() {
        let entries: Vec<_> = fs::read_dir(&att_dir)
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("dsse"))
            .collect();
        assert!(
            entries.is_empty(),
            "partial envelope should not have been written: {entries:?}"
        );
    }
}

#[test]
fn attest_additional_signer_ed25519_from_separate_keyfile() {
    // Primary repo ed25519 + additional ed25519 from a separate keyfile
    // path. Two signatures in the envelope, both ed25519.
    let td = tempfile::tempdir().unwrap();
    let root = td.path();
    init_repo_with_commit(root);

    // Create a backup ed25519 key at a custom path — just 32 bytes 0600.
    let backup_key = root.join(".mkit/keys/backup.key");
    fs::create_dir_all(backup_key.parent().unwrap()).unwrap();
    let backup_secret: [u8; 32] = [0x42; 32];
    fs::write(&backup_key, backup_secret).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perm = fs::metadata(&backup_key).unwrap().permissions();
        perm.set_mode(0o600);
        fs::set_permissions(&backup_key, perm).unwrap();
    }

    let out = run_in(
        root,
        &[
            "attest",
            "--algorithm",
            "ed25519",
            "--additional-signer",
            "algorithm=ed25519,signer=repo-key,path=.mkit/keys/backup.key",
        ],
    );
    assert!(
        out.status.success(),
        "attest failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Find the envelope, decode, assert 2 sigs.
    let commit_hash = resolve_head(root);
    let att_dir = root.join(format!(".mkit/attestations/{commit_hash}"));
    let entries: Vec<_> = fs::read_dir(&att_dir)
        .unwrap()
        .filter_map(std::result::Result::ok)
        .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("dsse"))
        .collect();
    assert_eq!(entries.len(), 1);
    let env = mkit_attest::envelope::decode(&fs::read(entries[0].path()).unwrap()).unwrap();
    assert_eq!(env.signatures.len(), 2);
    assert_ne!(
        env.signatures[0].keyid, env.signatures[1].keyid,
        "two distinct ed25519 keys should have distinct keyids"
    );
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Read `.mkit/HEAD` (which is `ref: refs/heads/<name>`) and follow
/// to the raw commit hash.
fn resolve_head(root: &Path) -> String {
    let head = fs::read_to_string(root.join(".mkit/HEAD")).unwrap();
    let head = head.trim();
    if let Some(refname) = head.strip_prefix("ref: ") {
        let path = root.join(".mkit").join(refname);
        fs::read_to_string(path).unwrap().trim().to_owned()
    } else {
        head.to_owned()
    }
}

fn hex_decode(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2));
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let hi = nibble(b[i]);
        let lo = nibble(b[i + 1]);
        out.push((hi << 4) | lo);
        i += 2;
    }
    out
}
fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => 10 + c - b'a',
        b'A'..=b'F' => 10 + c - b'A',
        _ => panic!("bad hex char {c}"),
    }
}
fn hex_encode(b: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        s.push(HEX[(byte >> 4) as usize] as char);
        s.push(HEX[(byte & 0x0F) as usize] as char);
    }
    s
}
