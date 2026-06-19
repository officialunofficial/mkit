//! Golden-vector regression test for the secp256k1 / ES256K signer.
//!
//! Pins the exact 64-byte `r ‖ s` that the signer must emit for a fixed
//! secret + fixed PAE input. If RFC 6979 determinism, SHA-256 hashing,
//! low-S normalization, or compact encoding ever regresses, this test
//! breaks and the diff is obvious.
//!
//! Inputs — intentionally boring so they are easy to eyeball against
//! the Signer trait foundation:
//!   secret = 32 bytes, all zeros except last byte = 0x01
//!   pae    = b"DSSEv1 28 application/vnd.in-toto+json 2 {}"
//!
//! The public key (compressed SEC1 of secret=1) is the well-known
//! secp256k1 generator G — the literal constant from SEC2 §2.4.1 /
//! BIP-340 test vector #1. That makes the pubkey side of the expected
//! value independently verifiable.
//!
//! Feature-gated behind `algo-secp256k1`; when the feature is off the
//! test file is an empty compilation unit.

#![cfg(feature = "algo-secp256k1")]

use mkit_attest::signer_k256::{Secp256k1Signer, verify_secp256k1};

/// Fixed secret scalar = 1 (i.e. big-endian 32-byte [0;31] + [1]).
/// Matches BIP-340 test vector #1 and SEC2 §2.4.1 for the generator G,
/// so the pubkey pins to a value auditors can spot-check against spec.
fn fixed_secret() -> [u8; 32] {
    let mut k = [0u8; 32];
    k[31] = 1;
    k
}

/// Fixed PAE. Length-prefix math in the DSSE spec requires the bytes
/// be an exact pre-agreed sequence — this one is the smallest well-
/// formed in-toto PAE (`{}` payload).
const FIXED_PAE: &[u8] = b"DSSEv1 28 application/vnd.in-toto+json 2 {}";

/// Expected compressed SEC1 public key for secret = 1. This is the
/// generator G; the 0x02 prefix says "y is even" and the remaining 32
/// bytes are Gx from SEC2 §2.4.1.
const EXPECT_PUBKEY_SEC1_HEX: &str =
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

/// Expected 64-byte compact signature (`r ‖ s`, big-endian) produced
/// by the signer under RFC 6979 / SHA-256 / low-S. Pinned from a
/// fresh-build run of this crate's own `sign_dsse` — any subsequent
/// change to nonce generation, hash choice, or s-normalization breaks
/// this test immediately.
const EXPECT_SIG_HEX: &str = "834cd126c1bcadb2998d6881e3dd35f6c10b87905b3dd5ba4714f59fcb018d79\
     085c75876fd776083affcf1fc5c982b1e2bea4f0cfc14876ca4305de964521c9";

fn expect_sig_hex_nospace() -> String {
    EXPECT_SIG_HEX
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect()
}

#[test]
fn golden_pubkey_matches_generator_g() {
    let signer = Secp256k1Signer::new(fixed_secret()).unwrap();
    let pk = signer.public_key_sec1();
    assert_eq!(
        hex::encode(&pk),
        EXPECT_PUBKEY_SEC1_HEX,
        "secret=1 must yield the compressed secp256k1 generator G"
    );
    assert_eq!(pk.len(), 33, "compressed SEC1 pubkey must be 33 bytes");
}

#[test]
fn golden_signature_is_deterministic() {
    // This is the core regression guard: sign the fixed PAE and
    // compare to the pinned hex. If RFC 6979, SHA-256, or low-S ever
    // changes, this diff tells integration reviewers exactly what moved.
    let signer = Secp256k1Signer::new(fixed_secret()).unwrap();
    let sig = signer.sign_dsse(FIXED_PAE).unwrap();
    assert_eq!(sig.len(), 64, "ES256K compact signature must be 64 bytes");
    assert_eq!(
        hex::encode(&sig),
        expect_sig_hex_nospace(),
        "signer output drifted from pinned golden vector"
    );
}

#[test]
fn golden_signature_verifies() {
    // Sanity: the pinned bytes are not only stable but also valid.
    let pk = hex::decode(EXPECT_PUBKEY_SEC1_HEX).unwrap();
    let sig = hex::decode(expect_sig_hex_nospace()).unwrap();
    verify_secp256k1(&pk, FIXED_PAE, &sig).expect("golden vector must verify");
}

#[test]
fn golden_tampered_payload_fails() {
    // Flip a single byte of the PAE — signature must stop verifying.
    let pk = hex::decode(EXPECT_PUBKEY_SEC1_HEX).unwrap();
    let sig = hex::decode(expect_sig_hex_nospace()).unwrap();
    let mut tampered = FIXED_PAE.to_vec();
    tampered[0] ^= 0x01;
    assert!(
        verify_secp256k1(&pk, &tampered, &sig).is_err(),
        "tampered PAE must not verify against the golden signature"
    );
}
