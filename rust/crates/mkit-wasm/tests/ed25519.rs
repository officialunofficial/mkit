//! Integration tests for the raw Ed25519 wasm exports (`ed25519_sign`,
//! `ed25519_verify`, `ed25519_pubkey_from_seed`).
//!
//! These exports let `@makechain/mkit-wasm` consumers drop a separate
//! `@noble/ed25519` dependency: the same `ed25519_dalek::verify_strict`
//! path mkit-attest uses internally is now reachable from JS. Tests run
//! on native — the wasm-bindgen wrappers delegate straight to the same
//! Rust functions the wasm build exports, so covering them here covers
//! correctness without spinning up a node/browser test driver.
//!
//! See `https://github.com/officialunofficial/mkit/issues/90`.

#![allow(clippy::unwrap_used)]

use mkit_wasm::{ed25519_pubkey_from_seed, ed25519_sign, ed25519_verify};

/// Deterministic 32-byte test seed. Same shape as Ed25519 RFC 8032
/// "secret key" (the input to `SHA512`).
const SEED: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];

/// Pubkey corresponding to `SEED` — RFC 8032 §7.1 test vector 1.
/// Used to pin determinism without re-deriving on every run.
const PUBKEY: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];

/// Test 1 — round-trip. Sign-then-verify should always succeed.
#[test]
fn round_trip_sign_verify() {
    let msg = b"hello, mkit";
    let sig = ed25519_sign(msg, &SEED).unwrap();
    let pubkey = ed25519_pubkey_from_seed(&SEED).unwrap();
    assert!(ed25519_verify(&sig, msg, &pubkey));
}

/// Test 2 — cross-impl parity. Bytes from `ed25519_sign` must match
/// exactly what `ed25519_dalek::SigningKey::from_bytes(seed).sign(msg)`
/// emits. Ed25519 is deterministic (RFC 8032) so this is byte-equal.
/// Also verifies the dalek output cross-validates via our wasm verifier.
#[test]
fn cross_impl_parity_with_dalek() {
    use ed25519_dalek::{Signer, SigningKey};
    let msg = b"mkit-wasm parity check";

    let our_sig = ed25519_sign(msg, &SEED).unwrap();
    let dalek_sig = SigningKey::from_bytes(&SEED).sign(msg).to_bytes();
    assert_eq!(
        our_sig.as_slice(),
        &dalek_sig[..],
        "wasm export must produce byte-identical signatures to ed25519-dalek"
    );

    let our_pk = ed25519_pubkey_from_seed(&SEED).unwrap();
    let dalek_pk = SigningKey::from_bytes(&SEED).verifying_key().to_bytes();
    assert_eq!(our_pk.as_slice(), &dalek_pk[..]);
}

/// Test 3 — hdevalence-style rejection. Two cases the strict verifier
/// rejects but a permissive Ed25519 implementation (such as `@noble/
/// ed25519`'s default `verifyAsync` without strict opts, or any lib
/// shipped before the hdevalence/ed25519consensus criteria
/// <https://github.com/hdevalence/ed25519consensus> were widely
/// adopted) might accept:
///
///   3a. **Non-canonical `s`** — `s' = s + L` mod `2^256`. The loose
///       check `s[31] & 224 == 0` admits values up to `2^253`, which
///       includes `s + L` for many `s`.
///
///   3b. **Small-order public key** — the all-zero compressed-Y
///       (the curve identity, order 1). `verify_strict` rejects any
///       signature under such a key; permissive verifiers happily
///       accept a forged signature.
///
/// Demonstrating either rejection — without false-positive accepts on
/// canonical data — is sufficient evidence that `ed25519_verify` is on
/// the strict path. We assert both.
#[test]
fn rejects_hdevalence_strict_vectors() {
    use ed25519_dalek::{Signer, SigningKey};

    // L = 2^252 + 27742317777372353535851937790883648493 (little-endian).
    const L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ];

    // ---- 3a: s + L malleation ----
    let sk = SigningKey::from_bytes(&SEED);
    let pk = sk.verifying_key().to_bytes();

    // Sweep a small message space to find a sig whose `s + L` fits in
    // 32 bytes — i.e. `s[31] < 0xef`. About 87% of `s` qualify, so this
    // hits in 1–3 iterations on average.
    let mut malleated = [0u8; 64];
    let mut canonical = [0u8; 64];
    let mut found_msg: Vec<u8> = Vec::new();
    for n in 0u32..256 {
        let msg = format!("hdevalence-probe-{n}").into_bytes();
        let sig = sk.sign(&msg).to_bytes();
        if sig[63] >= 0xef {
            continue;
        }
        let mut sum = sig;
        let mut carry: u16 = 0;
        for i in 0..32 {
            let v = u16::from(sum[32 + i]) + u16::from(L[i]) + carry;
            sum[32 + i] = u8::try_from(v & 0xff).unwrap();
            carry = v >> 8;
        }
        if carry == 0 {
            malleated = sum;
            canonical = sig;
            found_msg = msg;
            break;
        }
    }
    assert!(
        !found_msg.is_empty(),
        "could not find a non-canonical-s vector in 256 attempts (extremely unlikely)"
    );

    // Canonical signature verifies (positive control).
    assert!(ed25519_verify(&canonical, &found_msg, &pk));

    // Mauled-s signature is rejected by our strict verifier.
    assert!(
        !ed25519_verify(&malleated, &found_msg, &pk),
        "ed25519_verify must reject non-canonical s (verify_strict path)"
    );

    // ---- 3b: small-order pubkey (all-zero compressed-Y is order 1) ----
    let identity_pk = [0u8; 32];
    let arbitrary_sig = sk.sign(b"any").to_bytes();
    assert!(
        !ed25519_verify(&arbitrary_sig, b"any", &identity_pk),
        "ed25519_verify must reject identity-element pubkeys (verify_strict A check)"
    );
}

/// Test 4a — malformed sig length. 63 bytes → false (not a valid Ed25519 sig).
#[test]
fn rejects_short_signature() {
    let msg = b"x";
    let pk = ed25519_pubkey_from_seed(&SEED).unwrap();
    let short = vec![0u8; 63];
    assert!(!ed25519_verify(&short, msg, &pk));
}

/// Test 4b — malformed pubkey length. 31 bytes → false.
/// `ed25519_verify` returns `bool` (no `JsError` wrap), so this works
/// on native; size-erroring sign/pubkey paths return `Result<_, JsError>`
/// and exercising those on native would panic out of wasm-bindgen's
/// imported-function shim, so we cover their happy paths instead.
#[test]
fn rejects_short_pubkey() {
    let msg = b"x";
    let sig = ed25519_sign(msg, &SEED).unwrap();
    let short_pk = vec![0u8; 31];
    assert!(!ed25519_verify(&sig, msg, &short_pk));
}

/// Test 4c — empty message with a valid sig over the empty message
/// must still verify. Edge-case from RFC 8032 §7.1 vector 1, which
/// signs the empty string.
#[test]
fn empty_message_round_trip() {
    let sig = ed25519_sign(&[], &SEED).unwrap();
    let pk = ed25519_pubkey_from_seed(&SEED).unwrap();
    assert!(ed25519_verify(&sig, &[], &pk));
}

/// Test 5 — `pubkey_from_seed` determinism. The same seed must always
/// derive the same public key (Ed25519 is a deterministic scheme), and
/// it must match the RFC 8032 §7.1 test vector for our `SEED`.
#[test]
fn pubkey_from_seed_is_deterministic() {
    let pk_a = ed25519_pubkey_from_seed(&SEED).unwrap();
    let pk_b = ed25519_pubkey_from_seed(&SEED).unwrap();
    assert_eq!(pk_a, pk_b);
    assert_eq!(pk_a.as_slice(), &PUBKEY[..]);
}

/// Test 6 — wrong-seed length is a structural error, not a panic.
///
/// Gated to wasm: the `JsValue` error path constructs a `JsError` via
/// a wasm-bindgen imported function, which panics on native targets.
/// Browser-side this is the consumer-visible "throws on bad seed"
/// contract; wasm-bindgen-test would drive it under `wasm-pack test`.
#[cfg(target_arch = "wasm32")]
#[test]
fn sign_rejects_short_seed() {
    let short = [0u8; 31];
    assert!(ed25519_sign(b"x", &short).is_err());
    assert!(ed25519_pubkey_from_seed(&short).is_err());
}

/// Native port of `sign_rejects_short_seed` (#505 PR 2/5): CI never runs
/// `wasm-pack test`, so the wasm-gated test above never actually
/// executes and the "throws on bad seed" contract goes unverified. On
/// native, the same `JsValue` error path still constructs a `JsError` via
/// a wasm-bindgen imported function, which panics rather than returning —
/// so assert the panic via `catch_unwind` for both exports, following
/// `webauthn.rs::challenge_not_bound_to_pae_is_rejected`.
#[cfg(not(target_arch = "wasm32"))]
#[test]
fn sign_rejects_short_seed() {
    let short = [0u8; 31];
    let sign_result = std::panic::catch_unwind(|| {
        let _ = ed25519_sign(b"x", &short);
    });
    assert!(
        sign_result.is_err(),
        "ed25519_sign with a short seed must reject (panics natively via JsError)"
    );
    let pubkey_result = std::panic::catch_unwind(|| {
        let _ = ed25519_pubkey_from_seed(&short);
    });
    assert!(
        pubkey_result.is_err(),
        "ed25519_pubkey_from_seed with a short seed must reject (panics natively via JsError)"
    );
}
