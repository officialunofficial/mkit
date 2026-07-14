//! Cross-verification of a real mkit-attest DSSE envelope against an
//! INDEPENDENT reference verifier (`scripts/verify-dsse-envelope.py`,
//! written from the DSSE spec using Python's `cryptography` package —
//! not mkit code, not even the same language). The other tests in this
//! crate (`dsse_roundtrip.rs`) already cross-check against `ed25519-dalek`
//! directly; this goes one step further and checks against a completely
//! independent implementation, which is what would actually catch a
//! shared misunderstanding of the DSSE PAE construction rather than a
//! bug specific to one Rust crate.
//!
//! `#[ignore]`d: requires `python3` with the `cryptography` package
//! installed (`pip install cryptography`), which isn't guaranteed on
//! every CI runner (in particular Cloud Build's pinned `_CI_IMAGE`).
//! Run manually with `cargo test --test dsse_cross_verify -- --ignored`
//! after `pip install cryptography` when touching DSSE envelope or PAE
//! code.
#![cfg(feature = "algo-ed25519")]
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::path::PathBuf;
use std::process::Command;

use mkit_attest::envelope::{self as env_mod, Envelope, PAYLOAD_TYPE_IN_TOTO, Sig};
use mkit_attest::signer::Signer;
use mkit_attest::signer_repo_key::RepoKeySigner;
use mkit_attest::statement;
use mkit_core::hash::{hash, to_hex};
use mkit_core::sign::KeyPair;

const COMMIT_BYTES: &[u8] = b"dsse-cross-verify-fixed-commit-bytes";
const SEED: [u8; 32] = [0x77; 32];

fn build_envelope() -> (Envelope, [u8; 32]) {
    let kp = KeyPair::from_seed(SEED);
    let pk = kp.public.0;
    let mut signer = RepoKeySigner::new(kp);
    let keyid = signer.keyid().unwrap();

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
            keyid,
            sig: sig_bytes,
        }],
    };
    (env, pk)
}

fn verifier_script() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../scripts/verify-dsse-envelope.py")
}

fn run_verifier(envelope_path: &std::path::Path, pubkey_hex: &str) -> std::process::Output {
    Command::new("python3")
        .arg(verifier_script())
        .arg(envelope_path)
        .arg(pubkey_hex)
        .output()
        .expect("python3 must be on PATH")
}

#[test]
#[ignore = "requires python3 with `pip install cryptography` — see module docs"]
fn independent_python_verifier_accepts_valid_envelope() {
    let (env, pk) = build_envelope();
    let dir = tempfile::tempdir().unwrap();
    let envelope_path = dir.path().join("envelope.json");
    std::fs::write(&envelope_path, env.encode().unwrap()).unwrap();

    let out = run_verifier(&envelope_path, &to_hex(&pk));
    assert!(
        out.status.success(),
        "independent verifier rejected a validly-signed envelope:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

#[test]
#[ignore = "requires python3 with `pip install cryptography` — see module docs"]
fn independent_python_verifier_rejects_tampered_payload() {
    let (mut env, pk) = build_envelope();
    let mid = env.payload.len() / 2;
    env.payload[mid] ^= 0x01;

    let dir = tempfile::tempdir().unwrap();
    let envelope_path = dir.path().join("envelope.json");
    std::fs::write(&envelope_path, env.encode().unwrap()).unwrap();

    let out = run_verifier(&envelope_path, &to_hex(&pk));
    assert!(
        !out.status.success(),
        "independent verifier accepted a tampered envelope — PAE/signature check is broken"
    );
}

#[test]
#[ignore = "requires python3 with `pip install cryptography` — see module docs"]
fn independent_python_verifier_rejects_wrong_pubkey() {
    let (env, _pk) = build_envelope();
    let wrong_pk = KeyPair::from_seed([0x99; 32]).public.0;

    let dir = tempfile::tempdir().unwrap();
    let envelope_path = dir.path().join("envelope.json");
    std::fs::write(&envelope_path, env.encode().unwrap()).unwrap();

    let out = run_verifier(&envelope_path, &to_hex(&wrong_pk));
    assert!(
        !out.status.success(),
        "independent verifier accepted a signature under the wrong public key"
    );
}
