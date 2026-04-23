//! Phase 8 cross-implementation goldens.
//!
//! These vectors are produced by `scripts/harvest-golden-vectors-phase8.sh`
//! from the Zig reference (`src/attestations/`). They pin two contracts:
//!
//! 1. **JCS-canonical Statement bytes** — the Rust `statement::for_commit`
//!    encoder produces the exact same byte sequence as the Zig encoder
//!    when given the same fixed inputs.
//! 2. **DSSE envelope shape + signature acceptance** — the Rust
//!    `envelope::decode` accepts the Zig-produced envelope, the embedded
//!    payload re-encodes back to the canonical Statement bytes, and
//!    `verify::verify_envelope` accepts the embedded Ed25519 signature
//!    against the trust root recovered from the deterministic seed.
//!
//! See `docs/SPEC-ATTESTATIONS.md` and `rust/tests/golden/phase8/MANIFEST.txt`.

use std::path::PathBuf;

use ed25519_dalek::SigningKey;
use mkit_attest::envelope::{self as env_mod, PAYLOAD_TYPE_IN_TOTO};
use mkit_attest::statement::{self, Statement, Subject};
use mkit_attest::verify::{self, Reason, Registry, TrustRoot};
use mkit_core::hash::{hash, to_hex};

const ATTEST_COMMIT_HASH: [u8; 32] = [0xCC; 32];
const ATTEST_PREDICATE_TYPE: &str = "https://example.com/predicate/v1";
const ATTEST_PREDICATE_JCS: &[u8] = b"{}";
const ATTEST_ED25519_SEED: [u8; 32] = [0xAB; 32];
const ATTEST_KEYID: &str =
    "blake3:00000000000000000000000000000000000000000000000000000000000000aa";

fn golden_dir() -> PathBuf {
    // CARGO_MANIFEST_DIR points at rust/crates/mkit-attest. Goldens live
    // under rust/tests/golden/phase8.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("golden")
        .join("phase8")
}

#[test]
fn statement_basic_matches_zig_jcs_bytes() {
    let golden = std::fs::read(golden_dir().join("statement_basic.json"))
        .expect("read statement_basic.json (run scripts/harvest-golden-vectors-phase8.sh)");

    let got = statement::for_commit(
        &ATTEST_COMMIT_HASH,
        ATTEST_PREDICATE_TYPE,
        ATTEST_PREDICATE_JCS,
    )
    .expect("encode");

    assert_eq!(
        got.as_bytes(),
        golden.as_slice(),
        "Rust and Zig JCS encoders disagree on Statement bytes"
    );
}

#[test]
fn statement_basic_built_via_struct_form_also_matches() {
    let golden = std::fs::read(golden_dir().join("statement_basic.json")).unwrap();
    let hex = to_hex(&ATTEST_COMMIT_HASH);
    let got = statement::encode(&Statement {
        subjects: vec![Subject {
            name: Some("commit".into()),
            digest_blake3_hex: hex,
        }],
        predicate_type: ATTEST_PREDICATE_TYPE.into(),
        predicate_jcs: ATTEST_PREDICATE_JCS,
    })
    .unwrap();
    assert_eq!(got.as_bytes(), golden.as_slice());
}

#[test]
fn envelope_basic_decodes_and_signature_verifies() {
    let golden = std::fs::read(golden_dir().join("envelope_basic.json"))
        .expect("read envelope_basic.json (run scripts/harvest-golden-vectors-phase8.sh)");

    // Strict decode of the Zig-produced envelope.
    let env = env_mod::decode(&golden).expect("decode envelope");
    assert_eq!(env.payload_type, PAYLOAD_TYPE_IN_TOTO);
    assert_eq!(env.signatures.len(), 1);
    assert_eq!(env.signatures[0].keyid, ATTEST_KEYID);

    // The decoded payload must be byte-identical to the Statement golden.
    let stmt_golden = std::fs::read(golden_dir().join("statement_basic.json")).unwrap();
    assert_eq!(env.payload, stmt_golden);

    // Recover the public key from the deterministic seed and verify.
    let signing = SigningKey::from_bytes(&ATTEST_ED25519_SEED);
    let pk = signing.verifying_key().to_bytes();

    let mut reg = Registry::new();
    reg.add(ATTEST_KEYID, TrustRoot::Ed25519PubKey(pk));

    let r = verify::verify(&env, &reg).expect("verify");
    assert!(r.any_verified, "Zig-produced signature must verify in Rust");
    assert_eq!(r.signatures[0].reason, Reason::Ok);
}

#[test]
fn envelope_basic_subject_extraction_recovers_commit_hash() {
    let golden = std::fs::read(golden_dir().join("envelope_basic.json")).unwrap();
    let env = env_mod::decode(&golden).unwrap();
    let recovered = verify::extract_primary_commit_hash(&env.payload).unwrap();
    assert_eq!(recovered, ATTEST_COMMIT_HASH);
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
