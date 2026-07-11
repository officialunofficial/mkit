//! End-to-end DSSE roundtrip: sign with `RepoKeySigner` over a known
//! payload, verify with `mkit_core::sign::verify` directly over the PAE
//! (NOT through the attest verifier — this guards against the two
//! crates diverging on what they consider "the signed bytes").
//!
//! Feature-gated on `algo-ed25519` because `RepoKeySigner` itself is
//! gated on it; with that feature off the entire file compiles out.

#![cfg(feature = "algo-ed25519")]
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use ed25519_dalek::{Signature as DalekSig, Verifier, VerifyingKey};

use mkit_attest::envelope::{self as env_mod, Envelope, PAYLOAD_TYPE_IN_TOTO, Sig};
use mkit_attest::signer::Signer;
use mkit_attest::signer_repo_key::{KEYID_PREFIX, RepoKeySigner};
use mkit_attest::statement;
use mkit_attest::verify::{self, Reason, Registry, TrustRoot};
use mkit_core::hash::{hash, to_hex};
use mkit_core::sign::KeyPair;

const COMMIT_BYTES: &[u8] = b"dsse-roundtrip-fixed-commit-bytes";
const SEED: [u8; 32] = [0x42; 32];

fn build_envelope_signed_with_repo_key() -> (Envelope, [u8; 32], String) {
    let kp = KeyPair::from_seed(SEED);
    let pk = kp.public.0;
    let mut signer = RepoKeySigner::new(kp);
    let keyid = signer.keyid().expect("keyid");

    // Build the payload (in-toto Statement) and the PAE we sign.
    let commit = hash(COMMIT_BYTES);
    let payload = statement::for_commit(
        &commit,
        COMMIT_BYTES,
        "https://example.com/predicate/v1",
        b"{\"k\":1}",
    )
    .unwrap();
    let pae = env_mod::pae_of(PAYLOAD_TYPE_IN_TOTO, payload.as_bytes());
    let sig_bytes = signer.sign(&pae).unwrap();

    let env = Envelope {
        payload_type: PAYLOAD_TYPE_IN_TOTO.into(),
        payload: payload.into_bytes(),
        signatures: vec![Sig {
            keyid: keyid.clone(),
            sig: sig_bytes,
        }],
    };
    (env, pk, keyid)
}

#[test]
fn dsse_signature_verifies_directly_under_dalek() {
    let (env, pk, _keyid) = build_envelope_signed_with_repo_key();
    let pae = env.pae();
    let vk = VerifyingKey::from_bytes(&pk).unwrap();
    let sig_arr: [u8; 64] = env.signatures[0]
        .sig
        .as_slice()
        .try_into()
        .expect("64-byte sig");
    let sig = DalekSig::from_bytes(&sig_arr);
    vk.verify(&pae, &sig)
        .expect("Ed25519 must verify the DSSE PAE under the same key");
}

#[test]
fn dsse_signature_verifies_via_attest_verifier() {
    let (env, pk, keyid) = build_envelope_signed_with_repo_key();
    let mut reg = Registry::new();
    reg.add(keyid, TrustRoot::Ed25519PubKey(pk));

    let r = verify::verify(&env, &reg).unwrap();
    assert!(r.any_verified);
    assert_eq!(r.signatures[0].reason, Reason::Ok);
}

#[test]
fn tampered_payload_rejected() {
    let (mut env, pk, keyid) = build_envelope_signed_with_repo_key();
    // Flip a payload byte; signature must no longer verify.
    let mid = env.payload.len() / 2;
    env.payload[mid] ^= 0x01;

    let mut reg = Registry::new();
    reg.add(keyid, TrustRoot::Ed25519PubKey(pk));

    let r = verify::verify(&env, &reg).unwrap();
    assert!(!r.any_verified);
    assert_eq!(r.signatures[0].reason, Reason::SignatureMismatch);
}

#[test]
fn wrong_keyid_falls_back_to_unknown() {
    let (env, pk, _keyid) = build_envelope_signed_with_repo_key();
    let mut reg = Registry::new();
    // Register the correct pubkey under the WRONG keyid; the lookup
    // should miss the envelope's keyid.
    reg.add(
        "blake3:wrong-keyid-shape-but-string-is-arbitrary",
        TrustRoot::Ed25519PubKey(pk),
    );

    let r = verify::verify(&env, &reg).unwrap();
    assert!(!r.any_verified);
    assert_eq!(r.signatures[0].reason, Reason::UnknownKeyid);
}

#[test]
fn keyid_matches_blake3_of_pubkey() {
    let kp = KeyPair::from_seed(SEED);
    let pk = kp.public.0;
    let signer = RepoKeySigner::new(kp);
    let kid = signer.keyid().unwrap();
    let expected = format!("{KEYID_PREFIX}{}", to_hex(&mkit_core::hash::hash(&pk)));
    assert_eq!(kid, expected);
}
