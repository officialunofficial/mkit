//! End-to-end: spawn `mkit-sign-file` as a subprocess, round-trip one
//! signature per algorithm, and verify it via mkit-attest's verifier
//! paths. This is the contract-level test for the reference signer —
//! if this passes, any third party writing a signer to the same
//! protocol can plug in and know it'll interoperate.
//!
//! Covered:
//!
//! * Ed25519 — `keyid` shape `blake3:<hex>` (legacy compat), verified
//!   via `verify_signature(Algorithm::Ed25519, …)` with the derived
//!   raw pubkey.
//! * secp256k1 — `keyid` shape `secp256k1:<hex>`, verified via
//!   `verify_signature(Algorithm::Secp256k1, …)`.
//! * P-256 — `keyid` shape `p256:<hex>`, verified via
//!   `verify_signature(Algorithm::P256, …)`.
//! * Unix permission enforcement — a key file with mode 0644 must be
//!   rejected, mode 0600 must be accepted.
//!
//! The tests use fixed 32-byte seeds so runs are deterministic; the
//! ECDSA paths additionally pin RFC 6979 nonces inside mkit-attest's
//! signers, so repeated runs produce byte-identical signatures.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;

use mkit_attest::{Algorithm, verify_signature};

/// Resolve the built `mkit-sign-file` binary path. Cargo sets
/// `CARGO_BIN_EXE_<name>` for each `[[bin]]` in the current package
/// before running integration tests, so we never have to guess the
/// `target/` layout.
fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_mkit-sign-file"))
}

/// Write `bytes` to `<tmp>/key.bin` with mode 0600 and return the
/// absolute path. On non-Unix hosts the permission step is a no-op,
/// which matches the binary's own `#[cfg(unix)]` gate.
fn write_key(tmp: &Path, bytes: &[u8; 32]) -> PathBuf {
    let path = tmp.join("key.bin");
    std::fs::write(&path, bytes).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut p = std::fs::metadata(&path).unwrap().permissions();
        p.set_mode(0o600);
        std::fs::set_permissions(&path, p).unwrap();
    }
    path
}

/// Spawn the signer, pipe `request_json` to its stdin, and capture
/// `(stdout, stderr, status)`. The request is written with a trailing
/// newline as SPEC-EXTERNAL-SIGNER §3 requires.
fn run_signer(key_path: &Path, request_json: &str) -> (String, String, std::process::ExitStatus) {
    let mut child = Command::new(binary())
        .arg("--key")
        .arg(key_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mkit-sign-file");
    {
        let stdin = child.stdin.as_mut().expect("stdin piped");
        stdin.write_all(request_json.as_bytes()).unwrap();
        stdin.write_all(b"\n").unwrap();
    }
    let out = child.wait_with_output().expect("wait");
    (
        String::from_utf8(out.stdout).unwrap(),
        String::from_utf8(out.stderr).unwrap(),
        out.status,
    )
}

#[derive(serde::Deserialize)]
struct Response {
    keyid: String,
    sig_base64: String,
}

/// Parse a one-line response. Tolerates trailing whitespace and
/// enforces the fields SPEC-EXTERNAL-SIGNER §4 requires.
fn parse(stdout: &str) -> Response {
    serde_json::from_str(stdout.trim()).expect("response JSON")
}

/// DSSE PAE used across all three end-to-end tests. Its exact content
/// doesn't matter — any byte string would round-trip — but pinning a
/// value here makes the test output repeatable.
const PAE: &[u8] = b"DSSEv1 28 application/vnd.in-toto+json 2 {}";

// --- Ed25519 --------------------------------------------------------

#[test]
fn ed25519_roundtrip_through_subprocess() {
    let tmp = tempfile::tempdir().unwrap();
    // Fixed seed. Known pubkey hex was taken from the derived Ed25519
    // verifying-key; we don't pin it here so a future dalek bump that
    // changes nothing observable still passes.
    let seed = [0x11u8; 32];
    let key = write_key(tmp.path(), &seed);

    let req = format!(
        "{{\"pae_base64\":\"{}\",\"algorithm\":\"ed25519\"}}",
        B64.encode(PAE)
    );
    let (stdout, stderr, status) = run_signer(&key, &req);
    assert!(status.success(), "signer failed: stderr={stderr}");
    assert!(stderr.is_empty(), "clean run must produce no stderr");

    let resp = parse(&stdout);
    // Ed25519 keyid in the reference signer uses the legacy `blake3:`
    // prefix because it reuses RepoKeySigner. The verifier accepts
    // both prefixes (see Algorithm::from_keyid).
    assert!(
        resp.keyid.starts_with("blake3:"),
        "expected blake3: keyid, got {}",
        resp.keyid
    );

    let sig = B64.decode(resp.sig_base64.as_bytes()).unwrap();
    assert_eq!(sig.len(), 64, "ed25519 sig is 64 bytes");

    // Re-derive the raw pubkey from the seed and verify.
    let kp = mkit_core::sign::KeyPair::from_seed(seed);
    verify_signature(Algorithm::Ed25519, &kp.public.0, PAE, &sig)
        .expect("ed25519 signature must verify");
}

// --- secp256k1 ------------------------------------------------------

#[test]
fn secp256k1_roundtrip_through_subprocess() {
    let tmp = tempfile::tempdir().unwrap();
    // Canonical secp256k1 test scalar (1). Produces a known pubkey.
    let mut seed = [0u8; 32];
    seed[31] = 1;
    let key = write_key(tmp.path(), &seed);

    let req = format!(
        "{{\"pae_base64\":\"{}\",\"algorithm\":\"secp256k1\"}}",
        B64.encode(PAE)
    );
    let (stdout, stderr, status) = run_signer(&key, &req);
    assert!(status.success(), "signer failed: stderr={stderr}");

    let resp = parse(&stdout);
    assert!(
        resp.keyid.starts_with("secp256k1:"),
        "expected secp256k1: keyid, got {}",
        resp.keyid
    );
    // `secp256k1:` (10) + 66 hex chars (33-byte SEC1 compressed) = 76.
    assert_eq!(resp.keyid.len(), 76);

    let sig = B64.decode(resp.sig_base64.as_bytes()).unwrap();
    assert_eq!(sig.len(), 64, "secp256k1 compact sig is 64 bytes");

    // Extract the hex pubkey from the keyid, decode, and verify.
    let hex_pk = &resp.keyid["secp256k1:".len()..];
    let pk = hex_decode(hex_pk);
    verify_signature(Algorithm::Secp256k1, &pk, PAE, &sig)
        .expect("secp256k1 signature must verify");
}

// --- P-256 ----------------------------------------------------------

#[test]
fn p256_roundtrip_through_subprocess() {
    let tmp = tempfile::tempdir().unwrap();
    // Readable non-trivial seed. Not a NIST vector — just something
    // in-range.
    let seed: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];
    let key = write_key(tmp.path(), &seed);

    let req = format!(
        "{{\"pae_base64\":\"{}\",\"algorithm\":\"p256\"}}",
        B64.encode(PAE)
    );
    let (stdout, stderr, status) = run_signer(&key, &req);
    assert!(status.success(), "signer failed: stderr={stderr}");

    let resp = parse(&stdout);
    assert!(
        resp.keyid.starts_with("p256:"),
        "expected p256: keyid, got {}",
        resp.keyid
    );
    // `p256:` (5) + 66 hex chars (33-byte SEC1 compressed) = 71.
    assert_eq!(resp.keyid.len(), 71);

    let sig = B64.decode(resp.sig_base64.as_bytes()).unwrap();
    assert_eq!(sig.len(), 64, "p256 compact sig is 64 bytes");

    let hex_pk = &resp.keyid["p256:".len()..];
    let pk = hex_decode(hex_pk);
    verify_signature(Algorithm::P256, &pk, PAE, &sig).expect("p256 signature must verify");
}

// --- Permission enforcement (Unix only) -----------------------------

/// Mode 0644 (world-readable) MUST cause the signer to bail out before
/// it even reads the key. This is the only access-control story the
/// reference signer has — don't let it silently accept a leaky key.
#[cfg(unix)]
#[test]
fn rejects_key_with_world_readable_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("bad.key");
    std::fs::write(&path, [0x22u8; 32]).unwrap();

    // 0644 = owner rw, group r, world r. Classic leak.
    let mut perm = std::fs::metadata(&path).unwrap().permissions();
    perm.set_mode(0o644);
    std::fs::set_permissions(&path, perm).unwrap();

    let req = format!(
        "{{\"pae_base64\":\"{}\",\"algorithm\":\"ed25519\"}}",
        B64.encode(PAE)
    );
    let (stdout, stderr, status) = run_signer(&path, &req);
    assert!(
        !status.success(),
        "signer must reject 0644 key, but exit was success"
    );
    // Per spec: stdout SHOULD be empty on error.
    assert!(
        stdout.is_empty(),
        "signer must not emit stdout on error, got {stdout:?}"
    );
    assert!(
        stderr.contains("0644") || stderr.contains("permissions"),
        "stderr should mention the permission failure, got {stderr:?}"
    );
}

/// Companion to the above: the same bytes at 0600 must succeed. Keeps
/// the permission test honest about WHY 0644 failed (it's the mode,
/// not the bytes).
#[cfg(unix)]
#[test]
fn accepts_key_with_owner_only_permissions() {
    let tmp = tempfile::tempdir().unwrap();
    let key = write_key(tmp.path(), &[0x22u8; 32]);
    let req = format!(
        "{{\"pae_base64\":\"{}\",\"algorithm\":\"ed25519\"}}",
        B64.encode(PAE)
    );
    let (stdout, _stderr, status) = run_signer(&key, &req);
    assert!(status.success());
    assert!(!stdout.is_empty());
}

// --- Helpers --------------------------------------------------------

fn hex_decode(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    assert_eq!(bytes.len() % 2, 0, "hex len must be even");
    for chunk in bytes.chunks_exact(2) {
        out.push(from_hex_nibble(chunk[0]) << 4 | from_hex_nibble(chunk[1]));
    }
    out
}

fn from_hex_nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("not hex: {c:?}"),
    }
}
