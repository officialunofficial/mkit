//! Attestation goldens.
//!
//! Fixed deterministic vectors pin two contracts:
//!
//! 1. **JCS-canonical Statement bytes** — `statement::for_commit` emits
//!    the pinned byte sequence for the fixed inputs.
//! 2. **DSSE envelope shape + signature acceptance** — `envelope::decode`
//!    accepts the pinned envelope, the embedded payload re-encodes
//!    back to the canonical Statement bytes, and `verify::verify_envelope`
//!    accepts the embedded Ed25519 signature against the trust root
//!    recovered from the deterministic seed.
//!
//! See `docs/specs/SPEC-ATTESTATIONS.md` and `rust/tests/golden/attest/MANIFEST.txt`.
//!
//! Feature-gated on `algo-ed25519` because the pinned vectors here are
//! Ed25519 signatures produced by `RepoKeySigner`, which is gated on
//! that feature. With `algo-ed25519` off, the file compiles out.

#![cfg(feature = "algo-ed25519")]
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::path::PathBuf;

use ed25519_dalek::SigningKey;
use mkit_attest::envelope::{self as env_mod, PAYLOAD_TYPE_IN_TOTO};
use mkit_attest::signer_repo_key::RepoKeySigner;
use mkit_attest::statement::{self, Statement, Subject};
use mkit_attest::verify::{self, Reason, Registry, TrustRoot};
use mkit_core::hash::{hash, to_hex};
use mkit_core::sign::KeyPair;

// The subject digest is now a pair (blake3 + sha256) of the SAME
// underlying bytes (SPEC-ATTESTATIONS §4.2), so the golden vector's
// commit hash must be derived from real bytes rather than an arbitrary
// fixed hash value — there's no way to pick bytes whose sha256 AND
// blake3 both equal chosen constants.
const ATTEST_COMMIT_BYTES: &[u8] = b"pretend-serialised-commit-bytes-for-attest-golden-v1";
const ATTEST_PREDICATE_TYPE: &str = "https://example.com/predicate/v1";
const ATTEST_PREDICATE_JCS: &[u8] = b"{}";
const ATTEST_ED25519_SEED: [u8; 32] = [0xAB; 32];

fn attest_commit_hash() -> [u8; 32] {
    hash(ATTEST_COMMIT_BYTES)
}

/// Derive the keyid string from the fixed seed.
/// keyid = "blake3:" || hex(BLAKE3(pubkey)) where pubkey is derived from seed.
fn attest_keyid() -> String {
    RepoKeySigner::new(KeyPair::from_seed(ATTEST_ED25519_SEED)).keyid_string()
}

fn golden_dir() -> PathBuf {
    // CARGO_MANIFEST_DIR points at rust/crates/mkit-attest. Goldens live
    // under rust/tests/golden/attest.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("golden")
        .join("attest")
}

#[test]
fn statement_basic_matches_golden_jcs_bytes() {
    let golden = std::fs::read(golden_dir().join("statement_basic.json"))
        .expect("read statement_basic.json");

    let got = statement::for_commit(
        &attest_commit_hash(),
        ATTEST_COMMIT_BYTES,
        ATTEST_PREDICATE_TYPE,
        ATTEST_PREDICATE_JCS,
    )
    .expect("encode");

    assert_eq!(
        got.as_bytes(),
        golden.as_slice(),
        "JCS encoder output diverges from pinned golden"
    );
}

#[test]
fn statement_basic_built_via_struct_form_also_matches() {
    let golden = std::fs::read(golden_dir().join("statement_basic.json")).unwrap();
    let hex = to_hex(&attest_commit_hash());
    let sha256_hex = statement::sha256_hex(ATTEST_COMMIT_BYTES);
    let got = statement::encode(&Statement {
        subjects: vec![Subject {
            name: Some("commit".into()),
            digest_blake3_hex: hex,
            digest_sha256_hex: sha256_hex,
        }],
        predicate_type: ATTEST_PREDICATE_TYPE.into(),
        predicate_jcs: ATTEST_PREDICATE_JCS,
    })
    .unwrap();
    assert_eq!(got.as_bytes(), golden.as_slice());
}

#[test]
fn envelope_basic_decodes_and_signature_verifies() {
    let golden =
        std::fs::read(golden_dir().join("envelope_basic.json")).expect("read envelope_basic.json");

    // Strict decode of the pinned envelope.
    let env = env_mod::decode(&golden).expect("decode envelope");
    assert_eq!(env.payload_type, PAYLOAD_TYPE_IN_TOTO);
    assert_eq!(env.signatures.len(), 1);

    // Derive keyid from the fixed seed.
    let keyid = attest_keyid();
    assert_eq!(env.signatures[0].keyid, keyid);

    // The decoded payload must be byte-identical to the Statement golden.
    let stmt_golden = std::fs::read(golden_dir().join("statement_basic.json")).unwrap();
    assert_eq!(env.payload, stmt_golden);

    // Recover the public key from the deterministic seed and verify.
    let signing = SigningKey::from_bytes(&ATTEST_ED25519_SEED);
    let pk = signing.verifying_key().to_bytes();

    let mut reg = Registry::new();
    reg.add(&keyid, TrustRoot::Ed25519PubKey(pk));

    let r = verify::verify(&env, &reg).expect("verify");
    assert!(r.any_verified, "pinned signature must verify");
    assert_eq!(r.signatures[0].reason, Reason::Ok);
}

#[test]
fn envelope_basic_subject_extraction_recovers_commit_hash() {
    let golden = std::fs::read(golden_dir().join("envelope_basic.json")).unwrap();
    let env = env_mod::decode(&golden).unwrap();
    let recovered = verify::extract_primary_commit_hash(&env.payload).unwrap();
    assert_eq!(recovered, attest_commit_hash());
}

#[test]
fn envelope_basic_blake3_matches_manifest() {
    // The manifest carries BLAKE3(envelope_bytes) — the att-id used as
    // the on-disk filename. Recompute and compare so a stale manifest
    // is caught here rather than at deploy time.
    let golden = std::fs::read(golden_dir().join("envelope_basic.json")).unwrap();
    let manifest = std::fs::read_to_string(golden_dir().join("MANIFEST.txt")).unwrap();
    let line = manifest
        .lines()
        .find(|l| l.starts_with("envelope_basic "))
        .expect("envelope_basic line in MANIFEST.txt");
    let expected_hex = line.split_whitespace().nth(1).expect("blake3 hex");
    let got = to_hex(&hash(&golden));
    assert_eq!(got, expected_hex);
}
