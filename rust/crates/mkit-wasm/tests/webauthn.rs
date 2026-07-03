//! Integration tests for the `WebAuthn` / passkey wasm exports
//! (`attest_pae`, `verify_webauthn_wrapping`,
//! `verify_webauthn_wrapping_with_policy`).
//!
//! These prove the wiring that lets a browser passkey drive mkit's
//! attestation signing lifecycle from the demo pages: derive the DSSE
//! PAE, use it as the `WebAuthn` `challenge`, then verify the resulting
//! assertion. Platform passkeys are P-256-only, and mkit's core commit
//! signing is Ed25519-only, so the passkey path is attestations — see
//! `docs/research/passkey-signing-demo.md`.
//!
//! We have no published (authenticatorData, clientDataJSON, signature)
//! golden triple (authenticator secrets are per-device), so — exactly
//! like `mkit-attest`'s `webauthn_shape_self_consistency_compressed_and_uncompressed`
//! test — we forge the assertion with the deterministic P-256 signer and
//! assert the wrapping verifies through the wasm exports. Tests run on
//! native: the wasm-bindgen wrappers delegate to the same Rust functions
//! the wasm build exports. Only success paths are asserted directly,
//! because the error path constructs a `JsError`, which panics outside a
//! wasm host; the negative case is covered via `catch_unwind`.

#![allow(clippy::unwrap_used)]

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64_URL_NOPAD;
use mkit_attest::build_client_data_json;
use mkit_attest::signer_p256::P256Signer;
use mkit_wasm::{attest_pae, verify_webauthn_wrapping, verify_webauthn_wrapping_with_policy};
use sha2::{Digest, Sha256};

/// Deterministic 32-byte P-256 scalar for the forged authenticator.
const SECRET: [u8; 32] = [
    0x4a, 0x7c, 0x6b, 0x5a, 0x49, 0x38, 0x27, 0x16, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02,
    0xd1, 0xc0, 0xbf, 0xb8, 0xa7, 0x96, 0x83, 0x72, 0x61, 0x50, 0x40, 0x3a, 0x2b, 0x1c, 0x0d, 0x0e,
];

const COMMIT: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
const PREDICATE_TYPE: &str = "https://mkit.sh/Review/v1";
const PREDICATE: &[u8] = br#"{"approved":true}"#;
const RP_ID: &str = "mkit.sh";
const ORIGIN: &str = "https://mkit.sh";

/// Build a complete forged passkey assertion over the attestation PAE,
/// returning everything the wasm verify functions consume.
fn forge_assertion() -> (Vec<u8>, Vec<u8>, Vec<u8>, String, Vec<u8>) {
    let pae = attest_pae(COMMIT, PREDICATE_TYPE, PREDICATE).unwrap();

    // clientDataJSON with challenge == base64url-nopad(PAE) — exactly
    // what the verifier re-derives. Built via the shared mkit-attest
    // helper so signer and verifier agree byte-for-byte.
    let client_data_json = build_client_data_json(&pae, ORIGIN, false);

    // authenticatorData: rpIdHash(SHA256(rp_id)) || flags || signCount.
    // flags = 0x05 → UP (0x01) + UV (0x04). signCount = 0.
    let mut authenticator_data = vec![0u8; 37];
    authenticator_data[..32].copy_from_slice(&Sha256::digest(RP_ID.as_bytes()));
    authenticator_data[32] = 0x05;

    // The authenticator signs authenticatorData || SHA256(clientDataJSON).
    let mut webauthn_input = authenticator_data.clone();
    webauthn_input.extend_from_slice(&Sha256::digest(&client_data_json));

    let signer = P256Signer::new(SECRET).unwrap();
    let signature = signer.sign_dsse(&webauthn_input).unwrap();
    let pubkey_hex = hex::encode(signer.public_key_sec1());

    (
        pae,
        authenticator_data,
        client_data_json,
        pubkey_hex,
        signature,
    )
}

#[test]
fn verifies_a_forged_passkey_assertion() {
    let (pae, auth, cdj, pk, sig) = forge_assertion();
    verify_webauthn_wrapping(&pae, &auth, &cdj, &pk, &sig)
        .expect("permissive verify of a well-formed assertion");
}

#[test]
fn verifies_under_strict_rp_id_and_origin_policy() {
    let (pae, auth, cdj, pk, sig) = forge_assertion();
    let policy = format!(
        r#"{{"expected_rp_id":"{RP_ID}","allowed_origins":["{ORIGIN}"],"require_user_presence":true,"require_user_verification":true,"allow_cross_origin":false}}"#
    );
    verify_webauthn_wrapping_with_policy(&pae, &auth, &cdj, &pk, &sig, &policy)
        .expect("strict policy verify with matching rp_id/origin/flags");
}

#[test]
fn empty_policy_is_permissive() {
    let (pae, auth, cdj, pk, sig) = forge_assertion();
    verify_webauthn_wrapping_with_policy(&pae, &auth, &cdj, &pk, &sig, "")
        .expect("empty policy_json must behave like the permissive verifier");
}

#[test]
fn challenge_not_bound_to_pae_is_rejected() {
    // Sign over a *different* PAE than we verify against — the challenge
    // binding must fail. Error path builds a JsError (panics natively),
    // so we assert the panic rather than an Err value.
    let (_unused, auth, cdj, pk, sig) = forge_assertion();
    let tampered = attest_pae(COMMIT, PREDICATE_TYPE, br#"{"approved":false}"#).unwrap();
    let result = std::panic::catch_unwind(|| {
        let _ = verify_webauthn_wrapping(&tampered, &auth, &cdj, &pk, &sig);
    });
    assert!(result.is_err(), "challenge/PAE mismatch must not verify");
}

#[test]
fn pae_is_signer_independent_and_stable() {
    // The challenge a passkey signs is the same bytes a software key
    // would sign over the same statement — proving a passkey assertion
    // and `attest_build` bind to identical content.
    let a = attest_pae(COMMIT, PREDICATE_TYPE, PREDICATE).unwrap();
    let b = attest_pae(COMMIT, PREDICATE_TYPE, PREDICATE).unwrap();
    assert_eq!(a, b, "attest_pae must be deterministic");
    assert!(a.starts_with(b"DSSEv1 "), "PAE carries the DSSE prologue");
    // And the challenge round-trips through base64url-nopad as the
    // clientDataJSON carries it.
    let cdj = build_client_data_json(&a, ORIGIN, false);
    let cdj_str = String::from_utf8(cdj).unwrap();
    assert!(cdj_str.contains(&B64_URL_NOPAD.encode(&a)));
}
