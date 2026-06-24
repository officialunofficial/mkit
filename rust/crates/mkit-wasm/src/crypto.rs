//! Ed25519 keygen + sign/verify wrappers — both the mkit commit-domain
//! variants and the raw byte-level Ed25519 ops that mirror
//! `@noble/ed25519`. Plus the `KeyPairJs` view struct.

use wasm_bindgen::prelude::*;

use mkit_core::hash::{hash, to_hex};
use mkit_core::sign::{COMMIT_DOMAIN, KeyPair, PublicKey, Signature, verify};

use zeroize::Zeroizing;

use crate::common::{js_err, parse_fixed, parse_hash_hex};

// ---------------------------------------------------------------------
// Ed25519 keygen + raw sign/verify
// ---------------------------------------------------------------------

/// Derive `{ seed_hex, pubkey_hex }` from a 32-byte seed. Deterministic:
/// the same seed always yields the same public key.
#[wasm_bindgen]
pub fn keypair_from_seed(seed_hex: &str) -> Result<KeyPairJs, JsValue> {
    // See zeroization note on `commit_encode_and_sign`. JS-passed seed
    // material is mirrored to Rust through a `Zeroizing` wrapper so
    // every Rust-side copy scrubs on drop.
    let seed: Zeroizing<[u8; 32]> = Zeroizing::new(parse_hash_hex(seed_hex)?);
    let kp = KeyPair::from_seed_zeroizing(&seed);
    Ok(KeyPairJs {
        seed_hex: seed_hex.to_string(),
        pubkey_hex: hex::encode(kp.public.0),
    })
}

/// Generate a fresh Ed25519 keypair from the browser CSPRNG.
#[wasm_bindgen]
pub fn keypair_generate() -> Result<KeyPairJs, JsValue> {
    let kp = KeyPair::generate().map_err(|e| js_err(format!("rng: {e}")))?;
    Ok(KeyPairJs {
        seed_hex: hex::encode(kp.secret.0),
        pubkey_hex: hex::encode(kp.public.0),
    })
}

/// Sign arbitrary bytes under mkit's commit signing domain. Exposed for
/// the signing demo — real mkit commits go through `commit_encode_and_sign`.
#[wasm_bindgen]
pub fn sign_bytes_commit_domain(seed_hex: &str, bytes: &[u8]) -> Result<String, JsValue> {
    // See zeroization note on `commit_encode_and_sign`.
    let seed: Zeroizing<[u8; 32]> = Zeroizing::new(parse_hash_hex(seed_hex)?);
    let kp = KeyPair::from_seed_zeroizing(&seed);
    let sig = kp.sign(COMMIT_DOMAIN, bytes);
    Ok(hex::encode(sig.0))
}

/// Verify a signature made by [`sign_bytes_commit_domain`].
#[wasm_bindgen]
#[must_use]
pub fn verify_bytes_commit_domain(pubkey_hex: &str, bytes: &[u8], sig_hex: &str) -> bool {
    let Ok(pk) = parse_hash_hex(pubkey_hex) else {
        return false;
    };
    let Ok(sig_bytes) = hex::decode(sig_hex) else {
        return false;
    };
    let Ok(sig_arr) = parse_fixed::<64>(&sig_bytes) else {
        return false;
    };
    verify(&PublicKey(pk), COMMIT_DOMAIN, bytes, &Signature(sig_arr)).is_ok()
}

// ---------------------------------------------------------------------
// Raw Ed25519 — sign / verify / pubkey-from-seed (issue #90)
// ---------------------------------------------------------------------
//
// These are byte-level Ed25519 wrappers that match what `@noble/ed25519`
// exposes — no domain prefix, no BLAKE3 mixing, no commit framing. The
// goal is to let JS consumers drop a separate `@noble/ed25519`
// dependency and route every Ed25519 op through the same `ed25519-dalek`
// crate mkit's commit-signing path uses.
//
// Verify uses the strict path (`verify_ed25519` in `mkit-attest`), which
// rejects the hdevalence malleability vectors. This is deliberately
// stricter than noble's default loose verify; verifiers that disagree
// on which signatures are valid produce nondeterministic agreement on
// commit / attestation hashes downstream.

/// Verify a raw Ed25519 signature, with strict canonical-encoding checks.
///
/// Returns `true` only if all of the following hold:
/// - `sig` decodes as a 64-byte Ed25519 signature with canonical `R` and
///   canonical `s` (rejects `s + L` and torsion-malleated `R`).
/// - `pubkey` is a canonical 32-byte `A` encoding (rejects small-subgroup
///   keys).
/// - The signature verifies under `verify_strict` over `msg`.
///
/// Wrong-length `sig` or `pubkey` return `false` (the JS API matches the
/// noble shape — boolean out, no exceptions on shape errors).
#[wasm_bindgen]
#[must_use]
pub fn ed25519_verify(sig: &[u8], msg: &[u8], pubkey: &[u8]) -> bool {
    // Direct shape check rather than going through `parse_fixed`, which
    // eagerly constructs a `JsError` on failure — that path would panic
    // on native test targets even though we discard the error.
    let Ok(pk) = <[u8; 32]>::try_from(pubkey) else {
        return false;
    };
    matches!(
        mkit_attest::verify::verify_ed25519(pk, sig, msg),
        mkit_attest::verify::Reason::Ok
    )
}

/// Sign `msg` with the Ed25519 secret derived from a 32-byte `seed`.
///
/// Returns the 64-byte signature (`R || s`). Errors only if `seed` is
/// not exactly 32 bytes — Ed25519 signing itself is infallible once the
/// key material is the right shape (RFC 8032 is deterministic; no RNG).
///
/// The output is byte-equal to
/// `ed25519_dalek::SigningKey::from_bytes(seed).sign(msg)`, which is the
/// same signing path `mkit-core::sign::KeyPair` drives for commit
/// signatures (modulo the BLAKE3-domain wrapper that commits add on
/// top — those callers should keep using `commit_encode_and_sign`).
#[wasm_bindgen]
pub fn ed25519_sign(msg: &[u8], seed: &[u8]) -> Result<Vec<u8>, JsValue> {
    use ed25519_dalek::{Signer, SigningKey};
    // `JsValue`-flavoured error (rather than `JsError`) keeps these
    // callable on native test targets — `JsError::new` walks through a
    // wasm-bindgen imported function and panics outside wasm. JS-side
    // shape is identical: a thrown `Error` either way.
    //
    // # Zeroization
    //
    // The JS-passed `seed` slice we can't reach into and scrub, but
    // the Rust-side `[u8; 32]` copy lives inside a `Zeroizing` wrapper
    // so it zeros at end of scope. `SigningKey` owns its own copy and
    // zeros on drop in `ed25519-dalek` 2.x.
    let seed_arr: Zeroizing<[u8; 32]> = Zeroizing::new(
        parse_fixed::<32>(seed).map_err(|_| js_err("seed must be exactly 32 bytes"))?,
    );
    let sk = SigningKey::from_bytes(&seed_arr);
    let sig = sk.sign(msg);
    Ok(sig.to_bytes().to_vec())
}

/// Derive the 32-byte Ed25519 public key from a 32-byte seed.
///
/// Pure function: same seed → same pubkey. Errors only if `seed` is not
/// exactly 32 bytes. Internally goes through `mkit-core`'s
/// `KeyPair::from_seed`, which is the same derivation step the commit
/// signer uses, so a key minted here interoperates 1:1 with on-disk
/// `.mkit/keys/default.key` material.
#[wasm_bindgen]
pub fn ed25519_pubkey_from_seed(seed: &[u8]) -> Result<Vec<u8>, JsValue> {
    // `JsValue` flavour (rather than `JsError`) for the same native-test
    // reason as `ed25519_sign`. JS-side shape is identical.
    //
    // # Zeroization — see `ed25519_sign`.
    let seed_arr: Zeroizing<[u8; 32]> = Zeroizing::new(
        parse_fixed::<32>(seed).map_err(|_| js_err("seed must be exactly 32 bytes"))?,
    );
    let kp = KeyPair::from_seed_zeroizing(&seed_arr);
    Ok(kp.public.0.to_vec())
}

/// BLAKE3 of arbitrary bytes, as 64-char lowercase hex. This is the
/// object id mkit uses for every stored object.
#[wasm_bindgen]
#[must_use]
pub fn blake3_hex(data: &[u8]) -> String {
    to_hex(&hash(data))
}

// ---------------------------------------------------------------------
// View struct
// ---------------------------------------------------------------------

#[wasm_bindgen]
#[derive(Debug)]
pub struct KeyPairJs {
    seed_hex: String,
    pubkey_hex: String,
}

#[wasm_bindgen]
impl KeyPairJs {
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn seed_hex(&self) -> String {
        self.seed_hex.clone()
    }
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn pubkey_hex(&self) -> String {
        self.pubkey_hex.clone()
    }
}
