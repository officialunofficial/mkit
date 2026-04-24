#![allow(
    clippy::doc_markdown,
    clippy::items_after_statements,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    non_snake_case
)]
//! Protocol-shape tests for `mkit-sign-ctap`.
//!
//! These tests do NOT require a physical authenticator. They build a
//! fake v1.1 response from a deterministic in-process P-256 signer,
//! push it through `mkit-attest::verify_webauthn_wrapping`, and
//! assert the signature verifies. The goal is to lock down the
//! on-the-wire shape (field names, base64 flavours, JSON key order)
//! independently of the CTAP driver.
//!
//! The hardware-gated end-to-end test lives in `tests/e2e.sh`.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD as B64_STD, URL_SAFE_NO_PAD as B64_URL_NOPAD};
use mkit_attest::{WebAuthnWrapping, build_client_data_json, verify_webauthn_wrapping};
use p256::ecdsa::{Signature as P256Sig, SigningKey, signature::Signer as _};
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// Mirrors the v1.1 response shape so we can parse what the signer
/// emits (or, in these tests, a hand-built fake).
#[derive(Debug, Deserialize)]
struct V1_1Response {
    keyid: String,
    sig_base64: String,
    webauthn: WebAuthnBlock,
}

#[derive(Debug, Deserialize)]
struct WebAuthnBlock {
    authenticator_data: String,
    client_data_json: String,
}

/// Compute a P-256 WebAuthn-wrapped signature over the given PAE and
/// emit a fully-formed v1.1 response JSON string. This is the same
/// sequence `mkit-sign-ctap sign` runs, minus the CTAP dance.
fn mock_sign(pae: &[u8], secret: [u8; 32], rp_id: &str, origin: &str) -> String {
    let rp_id_hash = Sha256::digest(rp_id.as_bytes());
    let mut auth_data = Vec::with_capacity(37);
    auth_data.extend_from_slice(&rp_id_hash);
    auth_data.push(0x05); // UP + UV
    auth_data.extend_from_slice(&[0u8; 4]); // signCount = 0

    let cdj = build_client_data_json(pae, origin, false);

    let mut signed = Vec::with_capacity(auth_data.len() + 32);
    signed.extend_from_slice(&auth_data);
    signed.extend_from_slice(&Sha256::digest(&cdj));

    let sk = SigningKey::from_bytes(&secret.into()).unwrap();
    let sig: P256Sig = sk.sign(&signed);
    let sig = sig.normalize_s().unwrap_or(sig);
    let sig_bytes = sig.to_bytes();

    // Build pubkey + keyid exactly like the binary does.
    let vk = sk.verifying_key();
    let compressed = vk.to_encoded_point(true);
    let keyid = format!("p256:{}", to_hex(compressed.as_bytes()));

    // Hand-render to match proto::render_response_json's exact shape.
    format!(
        "{{\"keyid\":\"{keyid}\",\"sig_base64\":\"{}\",\"webauthn\":{{\"authenticator_data\":\"{}\",\"client_data_json\":\"{}\"}}}}",
        B64_STD.encode(sig_bytes),
        B64_URL_NOPAD.encode(&auth_data),
        B64_URL_NOPAD.encode(&cdj),
    )
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0F) as usize] as char);
    }
    out
}

// -- Tests --------------------------------------------------------------

#[test]
fn mock_response_parses_and_verifies() {
    let pae = b"DSSEv1 28 application/vnd.in-toto+json 2 {}";
    let secret = [42u8; 32];
    let resp_json = mock_sign(pae, secret, "mkit.local", "https://mkit.local");

    // 1. Parse.
    let resp: V1_1Response = serde_json::from_str(&resp_json).expect("response parses");

    // 2. keyid shape.
    assert!(resp.keyid.starts_with("p256:"), "keyid prefix");
    assert_eq!(
        resp.keyid.len(),
        "p256:".len() + 66,
        "p256 keyid = prefix + 33-byte pubkey as hex"
    );

    // 3. sig_base64 decodes to 64 bytes.
    let sig = B64_STD.decode(resp.sig_base64.as_bytes()).unwrap();
    assert_eq!(sig.len(), 64, "compact ECDSA sig");

    // 4. webauthn block decodes via the canonical helper.
    let wrap = WebAuthnWrapping::from_b64url_fields(
        &resp.webauthn.authenticator_data,
        &resp.webauthn.client_data_json,
    )
    .unwrap();

    // 5. The real deal: reconstruct pubkey, verify via mkit-attest.
    let sk = SigningKey::from_bytes(&secret.into()).unwrap();
    let vk = sk.verifying_key();
    let pub_sec1 = vk.to_encoded_point(true).as_bytes().to_vec();
    verify_webauthn_wrapping(pae, &wrap, &pub_sec1, &sig).expect("round-trip verifies");
}

#[test]
fn binary_rejects_non_p256() {
    // Drive the actual bin with a non-p256 request and assert exit 2.
    // Path to the cargo-built binary at $CARGO_BIN_EXE_mkit-sign-ctap.
    let bin = env!("CARGO_BIN_EXE_mkit-sign-ctap");
    let cred_id = B64_URL_NOPAD.encode(b"any-credential-id");
    let req = br#"{"pae_base64":"aGVsbG8=","algorithm":"ed25519"}"#;

    let mut child = std::process::Command::new(bin)
        .args(["sign", "--credential-id", &cred_id])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn");
    use std::io::Write as _;
    child.stdin.as_mut().unwrap().write_all(req).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(!out.status.success(), "ed25519 request must fail");
    assert_eq!(out.status.code(), Some(2), "exit 2 for algorithm mismatch");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("algorithm mismatch"),
        "stderr mentions reason: {stderr}"
    );
    assert!(out.stdout.is_empty(), "stdout empty on error path");
}

#[test]
fn binary_help_exits_zero() {
    let bin = env!("CARGO_BIN_EXE_mkit-sign-ctap");
    let out = std::process::Command::new(bin)
        .arg("--help")
        .output()
        .unwrap();
    assert!(out.status.success(), "--help must exit 0");
}

#[test]
fn binary_unknown_subcommand_fails() {
    let bin = env!("CARGO_BIN_EXE_mkit-sign-ctap");
    let out = std::process::Command::new(bin).arg("wat").output().unwrap();
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    assert!(!out.stderr.is_empty());
}

#[test]
#[ignore = "sample emitter — run with --ignored --nocapture to print a v1.1 response for docs"]
fn emit_sample_v1_1_response() {
    let pae = b"DSSEv1 28 application/vnd.in-toto+json 2 {}";
    let secret = [42u8; 32];
    let resp_json = mock_sign(pae, secret, "mkit.local", "https://mkit.local");
    println!("SAMPLE v1.1 RESPONSE:\n{resp_json}");
}
