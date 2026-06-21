//! WASM bindings for the mkit demo site.
//!
//! Thin wrappers over the pure byte-format and crypto paths in
//! `mkit-core` and `mkit-attest`. No filesystem access — the demo runs
//! entirely in the browser.

#![forbid(unsafe_code)]
#![allow(clippy::multiple_crate_versions)]

use wasm_bindgen::prelude::*;

use mkit_attest::algorithm::Algorithm;
use mkit_attest::envelope::{Envelope, Sig};
use mkit_attest::signer_k256::Secp256k1Signer;
use mkit_attest::signer_p256::P256Signer;
use mkit_attest::statement::{Statement, Subject, encode as encode_statement};
use mkit_attest::verify::{Registry, TrustRoot, verify_envelope};
use mkit_attest::{PAYLOAD_TYPE_IN_TOTO, Signer, signer_repo_key::RepoKeySigner};
use mkit_core::chunker::{AVG_SIZE, ChunkIterator, FastCdc, MAX_SIZE, MIN_SIZE};
use mkit_core::delta;
use mkit_core::hash::{from_hex, hash, to_hex};
use mkit_core::object::{
    Blob, Commit, EntryMode, Identity, Object, Tree, TreeEntry, id_from_object,
};
use mkit_core::serialize::serialize;
use mkit_core::sign::{COMMIT_DOMAIN, KeyPair, PublicKey, Signature, commit_signing_bytes, verify};

use std::io::Read;
use zeroize::Zeroizing;

/// Upper bound on the JSON input accepted by [`parse_json_triples`].
///
/// The hand-rolled parser is O(n) in input length but performs a string
/// allocation per escaped token, so a hostile caller pasting a giant
/// blob would cause the WASM blob to allocate well beyond what the
/// demo site can recover from. 16 MiB is comfortably larger than any
/// realistic triple list and small enough to keep the tab responsive
/// when an attacker tries to wedge it.
const MAX_JSON_BYTES: usize = 16 * 1024 * 1024;

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

fn js_err(msg: impl Into<String>) -> JsValue {
    JsError::new(&msg.into()).into()
}

fn parse_hash_hex(hex: &str) -> Result<[u8; 32], JsValue> {
    from_hex(hex).map_err(|_| js_err("expected 64 lowercase hex characters"))
}

fn parse_fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N], JsValue> {
    <[u8; N]>::try_from(bytes).map_err(|_| js_err(format!("expected {N} bytes")))
}

/// Parse `"ed25519" | "secp256k1" | "p256"` into the attestation-side `Algorithm` tag. These are the only three
/// algorithms the attestation verifier dispatches on today.
fn parse_algo(s: &str) -> Result<Algorithm, JsValue> {
    s.parse::<Algorithm>()
        .map_err(|e| js_err(format!("unknown algorithm: {}", e.0)))
}

/// `len()` of a slice exposed to JS as a `u32`, saturating at `u32::MAX`.
///
/// Single home for the count/index boundary policy shared by every
/// `*_count` getter on the result structs, so the saturation choice
/// lives in one place rather than being re-justified per struct.
fn js_vec_count<T>(xs: &[T]) -> u32 {
    u32::try_from(xs.len()).unwrap_or(u32::MAX)
}

/// Indexed accessor matching [`js_vec_count`]: clones the element at the
/// JS-supplied `u32` index, or `None` when out of range.
fn js_vec_get<T: Clone>(xs: &[T], i: u32) -> Option<T> {
    xs.get(i as usize).cloned()
}

// ---------------------------------------------------------------------
// 1. Content-addressing primitives
// ---------------------------------------------------------------------

/// BLAKE3 of arbitrary bytes, as 64-char lowercase hex. This is the
/// object id mkit uses for every stored object.
#[wasm_bindgen]
#[must_use]
pub fn blake3_hex(data: &[u8]) -> String {
    to_hex(&hash(data))
}

/// Serialize a blob object and return `{ bytes, hash_hex }`.
///
/// The returned `bytes` are the canonical on-disk v1 object bytes
/// (see `docs/SPEC-OBJECTS.md`); `hash_hex` is the object's content id
/// (via `id_from_object`) — for a non-merkelized `Blob`, BLAKE3 of those bytes.
#[wasm_bindgen]
pub fn blob_encode(data: &[u8]) -> Result<EncodedObject, JsValue> {
    let obj = Object::Blob(Blob {
        data: data.to_vec(),
    });
    encode_object(&obj)
}

/// Build a tree object from a JSON array of `[name, mode, hash_hex]`
/// triples and return its serialized bytes + hash. `mode` is one of
/// `"blob" | "tree" | "symlink" | "exec"`.
#[wasm_bindgen]
pub fn tree_encode(entries_json: &str) -> Result<EncodedObject, JsValue> {
    let parsed: Vec<(String, String, String)> =
        parse_json_triples(entries_json).map_err(|e| js_err(format!("entries JSON: {e}")))?;

    let mut entries = Vec::with_capacity(parsed.len());
    for (name, mode, hash_hex) in parsed {
        let mode = match mode.as_str() {
            "blob" => EntryMode::Blob,
            "tree" => EntryMode::Tree,
            "symlink" => EntryMode::Symlink,
            "exec" => EntryMode::Executable,
            other => return Err(js_err(format!("unknown entry mode `{other}`"))),
        };
        let name_bytes = name.into_bytes();
        if !TreeEntry::validate_name(&name_bytes) {
            return Err(js_err("invalid tree entry name"));
        }
        let object_hash = parse_hash_hex(&hash_hex)?;
        entries.push(TreeEntry {
            name: name_bytes,
            mode,
            object_hash,
        });
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));

    let tree = Tree { entries };
    if !tree.is_sorted() {
        return Err(js_err("tree entries must have unique names"));
    }
    encode_object(&Object::Tree(tree))
}

/// Build and sign a commit, returning `{ bytes, hash_hex, signature_hex }`.
///
/// `parent_hex` is a comma-separated list of parent commit hashes (empty
/// string = root commit). `seed_hex` is the 32-byte Ed25519 seed.
#[wasm_bindgen]
pub fn commit_encode_and_sign(
    tree_hash_hex: &str,
    parent_hex: &str,
    message: &str,
    timestamp: u64,
    seed_hex: &str,
) -> Result<EncodedCommit, JsValue> {
    let tree_hash = parse_hash_hex(tree_hash_hex)?;
    let parents = parse_parent_list(parent_hex)?;
    // # Zeroization
    //
    // We cannot scrub the JS-side ArrayBuffer that backed `seed_hex`,
    // but every Rust-side temporary holding the raw seed must zero on
    // drop. `Zeroizing` carries that scrub into the destructor; the
    // `from_seed_zeroizing` constructor avoids the `[u8; 32]: Copy`
    // synthesis that a `*seed` deref would create.
    let seed: Zeroizing<[u8; 32]> = Zeroizing::new(parse_hash_hex(seed_hex)?);

    let kp = KeyPair::from_seed_zeroizing(&seed);
    let signer_pub = kp.public.0;
    let author = Identity::ed25519(signer_pub);

    // Start from an empty signature so `commit_signing_bytes` excludes it,
    // then populate after we compute the signature.
    let mut commit = Commit::new_unannotated(
        tree_hash,
        parents,
        author,
        signer_pub,
        message.as_bytes().to_vec(),
        timestamp,
        [0u8; 64],
    );

    let signing_bytes =
        commit_signing_bytes(&commit).map_err(|e| js_err(format!("signing bytes: {e}")))?;
    let sig: Signature = kp.sign(COMMIT_DOMAIN, &signing_bytes);
    commit.signature = sig.0;

    let encoded = encode_object(&Object::Commit(commit))?;
    Ok(EncodedCommit {
        bytes: encoded.bytes,
        hash_hex: encoded.hash_hex,
        signature_hex: hex::encode(sig.0),
    })
}

/// Verify a commit signature, given the raw on-disk commit bytes.
/// Returns `true` on pass, `false` on structural or crypto failure.
#[wasm_bindgen]
#[must_use]
pub fn commit_verify(commit_bytes: &[u8]) -> bool {
    let Ok(obj) = mkit_core::deserialize(commit_bytes) else {
        return false;
    };
    let Object::Commit(c) = obj else { return false };
    mkit_core::sign::verify_commit(&c).is_ok()
}

// ---------------------------------------------------------------------
// 2. Ed25519 keygen + raw sign/verify
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
// 2b. Raw Ed25519 — sign / verify / pubkey-from-seed (issue #90)
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

// ---------------------------------------------------------------------
// 3. Attestations — in-toto v1 Statement wrapped in a DSSE envelope
// ---------------------------------------------------------------------

/// Derive the pubkey + canonical keyid for the given attestation algorithm from a 32-byte seed. `algo` is one of
/// `"ed25519" | "secp256k1" | "p256"`. Deterministic: same seed + same algorithm always produces the same pubkey.
///
/// Pubkey encoding depends on the algorithm:
///   * `ed25519`   — 32-byte raw pubkey
///   * `secp256k1` — 33-byte compressed SEC1 (`0x02`/`0x03` prefix + x)
///   * `p256`      — 33-byte compressed SEC1 (same shape)
///
/// `keyid` follows the canonical `<prefix>:<hex-pubkey>` form described in SPEC-ATTESTATIONS §6.3 for ES256K / ES256,
/// and the legacy `blake3:<hex-of-blake3(pubkey)>` form for Ed25519 (what `RepoKeySigner` emits; verifier accepts).
#[wasm_bindgen]
pub fn attest_keypair(seed_hex: &str, algo: &str) -> Result<AttestKeyPairJs, JsValue> {
    // # Zeroization
    //
    // JS callers pass the seed across the wasm boundary as a hex string.
    // We cannot scrub the JS-side ArrayBuffer, but every Rust-side
    // temporary holding the raw bytes must zero on drop. `Zeroizing`
    // carries that scrub into the destructor.
    let seed: Zeroizing<[u8; 32]> = Zeroizing::new(parse_hash_hex(seed_hex)?);
    let alg = parse_algo(algo)?;
    match alg {
        Algorithm::Ed25519 => {
            let kp = KeyPair::from_seed_zeroizing(&seed);
            let pk = kp.public.0;
            let signer = RepoKeySigner::new(kp);
            let keyid = signer.keyid().map_err(|e| js_err(format!("keyid: {e}")))?;
            Ok(AttestKeyPairJs {
                seed_hex: seed_hex.to_string(),
                pubkey_hex: hex::encode(pk),
                keyid,
                algo: "ed25519".to_string(),
            })
        }
        Algorithm::Secp256k1 => {
            let s = Secp256k1Signer::from_seed_zeroizing(&seed)
                .map_err(|e| js_err(format!("secp256k1: {e}")))?;
            Ok(AttestKeyPairJs {
                seed_hex: seed_hex.to_string(),
                pubkey_hex: hex::encode(s.public_key_sec1()),
                keyid: s.keyid_string(),
                algo: "secp256k1".to_string(),
            })
        }
        Algorithm::P256 => {
            let s =
                P256Signer::from_seed_zeroizing(&seed).map_err(|e| js_err(format!("p256: {e}")))?;
            Ok(AttestKeyPairJs {
                seed_hex: seed_hex.to_string(),
                pubkey_hex: hex::encode(s.public_key_sec1()),
                keyid: s.keyid(),
                algo: "p256".to_string(),
            })
        }
        #[cfg(feature = "bls-threshold")]
        Algorithm::Bls12381Threshold => Err(js_err(
            "BLS threshold keypair generation is not supported in WASM (Phase 1)",
        )),
    }
}

/// Build a DSSE-wrapped in-toto v1 attestation over a commit hash, signed with the chosen algorithm.
///
/// * `predicate_type` is a URI like `https://example.com/Review/v1`.
/// * `predicate_jcs` is the predicate body as already-canonical JCS bytes (must start with `{` and end with `}`).
/// * `seed_hex` is a 32-byte seed. How it's interpreted depends on `algo`:
///   * `ed25519`   — raw Ed25519 seed
///   * `secp256k1` — raw 32-byte scalar
///   * `p256`      — raw 32-byte scalar
///
/// Returns `{ envelope_json, keyid, attestation_id_hex }`. The keyid's prefix reveals which algorithm was used.
#[wasm_bindgen]
pub fn attest_build(
    commit_hash_hex: &str,
    predicate_type: &str,
    predicate_jcs: &[u8],
    seed_hex: &str,
    algo: &str,
) -> Result<AttestationJs, JsValue> {
    let _ = parse_hash_hex(commit_hash_hex)?;
    // # Zeroization — see `attest_keypair`.
    let seed: Zeroizing<[u8; 32]> = Zeroizing::new(parse_hash_hex(seed_hex)?);
    let alg = parse_algo(algo)?;

    let stmt = Statement {
        subjects: vec![Subject {
            name: Some("commit".to_string()),
            digest_blake3_hex: commit_hash_hex.to_string(),
        }],
        predicate_type: predicate_type.to_string(),
        predicate_jcs,
    };
    let statement_json = encode_statement(&stmt).map_err(|e| js_err(format!("statement: {e}")))?;
    let payload = statement_json.into_bytes();

    let mut env = Envelope {
        payload_type: PAYLOAD_TYPE_IN_TOTO.to_string(),
        payload,
        signatures: Vec::new(),
    };
    let pae = env.pae();

    let (keyid, sig_bytes) = match alg {
        Algorithm::Ed25519 => {
            let mut signer = RepoKeySigner::from_seed_zeroizing(&seed);
            let keyid = signer.keyid().map_err(|e| js_err(format!("keyid: {e}")))?;
            let sig = signer
                .sign(&pae)
                .map_err(|e| js_err(format!("sign: {e}")))?;
            (keyid, sig)
        }
        Algorithm::Secp256k1 => {
            let s = Secp256k1Signer::from_seed_zeroizing(&seed)
                .map_err(|e| js_err(format!("secp256k1: {e}")))?;
            let sig = s
                .sign_dsse(&pae)
                .map_err(|e| js_err(format!("sign: {e}")))?;
            (s.keyid_string(), sig)
        }
        Algorithm::P256 => {
            let s =
                P256Signer::from_seed_zeroizing(&seed).map_err(|e| js_err(format!("p256: {e}")))?;
            let sig = s
                .sign_dsse(&pae)
                .map_err(|e| js_err(format!("sign: {e}")))?;
            (s.keyid(), sig)
        }
        #[cfg(feature = "bls-threshold")]
        Algorithm::Bls12381Threshold => {
            return Err(js_err(
                "BLS threshold signing is not supported in WASM (Phase 1)",
            ));
        }
    };

    env.signatures.push(Sig {
        keyid: keyid.clone(),
        sig: sig_bytes,
    });

    let envelope_json = env.encode().map_err(|e| js_err(format!("envelope: {e}")))?;
    let att_id = env
        .attestation_id()
        .map_err(|e| js_err(format!("attestation_id: {e}")))?;

    Ok(AttestationJs {
        envelope_json,
        keyid,
        attestation_id_hex: to_hex(&att_id),
    })
}

/// Normalize a SEC1-encoded EC public key to its 33-byte compressed form.
///
/// Both secp256k1 and P-256 share the SEC1 point encoding, so a single
/// byte-level helper covers both arms of [`attest_verify`]:
///   * an already-compressed key (`0x02`/`0x03` ‖ X, 33 bytes) is returned as-is;
///   * an uncompressed key (`0x04` ‖ X ‖ Y, 65 bytes) is compressed by
///     keeping X and deriving the prefix from the parity of Y (LSB of the
///     last byte): `0x02` if Y is even, `0x03` if Y is odd.
///
/// Returns `None` for any other length/prefix so a malformed input fails
/// closed rather than producing a bogus keyid. No curve math is required:
/// compression only re-tags the prefix and drops Y, and the still-valid
/// SEC1 bytes are what the underlying verifier decodes.
///
/// CAVEAT: this performs NO on-curve / point-validity check — it only
/// reshapes bytes to derive a stable keyid. Callers MUST hand the key to
/// an on-curve-validating verifier (both [`attest_verify`] arms do, via
/// `k256`/`p256` `from_sec1_bytes`, which reject off-curve points); a
/// not-on-curve input here just yields a keyid that no valid signature
/// will ever match.
fn sec1_to_compressed(bytes: &[u8]) -> Option<Vec<u8>> {
    match bytes {
        // Already compressed: 0x02/0x03 ‖ X(32).
        [0x02 | 0x03, ..] if bytes.len() == 33 => Some(bytes.to_vec()),
        // Uncompressed: 0x04 ‖ X(32) ‖ Y(32). Compressed prefix encodes
        // the parity of Y, which is the LSB of Y's final byte.
        [0x04, ..] if bytes.len() == 65 => {
            let mut out = Vec::with_capacity(33);
            let y_is_odd = bytes[64] & 1 == 1;
            out.push(if y_is_odd { 0x03 } else { 0x02 });
            out.extend_from_slice(&bytes[1..33]);
            Some(out)
        }
        _ => None,
    }
}

/// Verify a DSSE envelope against a single trust root of the given algorithm.
///
/// * `envelope_json` is the canonical DSSE envelope JSON emitted by [`attest_build`].
/// * `pubkey_hex` is the public key, hex-encoded:
///   * `ed25519`   — 32-byte raw pubkey (64 hex chars)
///   * `secp256k1` — 33-byte compressed SEC1 (66 hex chars) or 65-byte uncompressed (130 hex chars)
///   * `p256`      — same shape as `secp256k1`
/// * `algo` selects which trust-root variant the registry dispatches on.
///
/// Returns `true` iff at least one signature in the envelope verifies.
#[wasm_bindgen]
#[must_use]
pub fn attest_verify(envelope_json: &str, pubkey_hex: &str, algo: &str) -> bool {
    let Ok(alg) = parse_algo(algo) else {
        return false;
    };
    let Ok(pubkey_bytes) = hex::decode(pubkey_hex) else {
        return false;
    };

    let mut registry = Registry::new();
    match alg {
        Algorithm::Ed25519 => {
            let Ok(pk) = <[u8; 32]>::try_from(pubkey_bytes.as_slice()) else {
                return false;
            };
            // RepoKeySigner (what we emit for ed25519) uses the legacy `blake3:<hex-of-blake3(pubkey)>` form.
            let keyid = format!("blake3:{}", to_hex(&hash(&pk)));
            registry.add(keyid, TrustRoot::Ed25519PubKey(pk));
        }
        Algorithm::Secp256k1 => {
            // The envelope keyid emitted by `attest_build` is always the
            // *compressed* SEC1 form (66 hex). Normalize an uncompressed
            // (130 hex) input to compressed before building the lookup
            // keyid, so the documented "accepts uncompressed" contract
            // actually matches the envelope's keyid in the registry.
            let Some(sec1) = sec1_to_compressed(&pubkey_bytes) else {
                return false;
            };
            let keyid = format!("secp256k1:{}", hex::encode(&sec1));
            registry.add(keyid, TrustRoot::Secp256k1PubKeySec1(sec1));
        }
        Algorithm::P256 => {
            let Some(sec1) = sec1_to_compressed(&pubkey_bytes) else {
                return false;
            };
            let keyid = format!("p256:{}", hex::encode(&sec1));
            registry.add(keyid, TrustRoot::P256PubKeySec1(sec1));
        }
        #[cfg(feature = "bls-threshold")]
        Algorithm::Bls12381Threshold => return false,
    }

    match verify_envelope(envelope_json.as_bytes(), &registry) {
        Ok(r) => r.any_verified,
        Err(_) => false,
    }
}

// ---------------------------------------------------------------------
// 4. Streaming primitives — chunker / chunked-blob / delta / Bao
// ---------------------------------------------------------------------

// Frozen v1 chunker constants are well under u32::MAX (max = 256 KiB).
// Lift them to module-level `u32` constants so the `as` cast is pinned
// once behind a compile-time assert, rather than being re-justified at
// each call site.
#[allow(clippy::cast_possible_truncation)]
const CHUNKER_AVG_U32: u32 = AVG_SIZE as u32;
#[allow(clippy::cast_possible_truncation)]
const CHUNKER_MIN_U32: u32 = MIN_SIZE as u32;
#[allow(clippy::cast_possible_truncation)]
const CHUNKER_MAX_U32: u32 = MAX_SIZE as u32;
const _: () = assert!(MAX_SIZE <= u32::MAX as usize);

/// Run the frozen v1 `FastCDC` chunker over `bytes` and return
/// `{ chunks: [{ offset, len, hash_hex }], avg, min, max }`.
///
/// Each `hash_hex` is BLAKE3 of the chunk payload — handy for colouring
/// chips in the web demo when an edit shifts boundaries.
#[wasm_bindgen]
pub fn chunk_boundaries(bytes: &[u8]) -> Result<ChunkerResult, JsValue> {
    let cdc = FastCdc::v1();
    let mut chunks: Vec<ChunkInfo> = Vec::new();
    for b in ChunkIterator::new(cdc, bytes) {
        let offset = u32::try_from(b.offset).map_err(|_| js_err("chunk offset exceeds u32"))?;
        let len = u32::try_from(b.length).map_err(|_| js_err("chunk length exceeds u32"))?;
        let h = hash(&bytes[b.offset..b.offset + b.length]);
        chunks.push(ChunkInfo {
            offset,
            len,
            hash_hex: to_hex(&h),
        });
    }
    Ok(ChunkerResult {
        chunks,
        avg: CHUNKER_AVG_U32,
        min: CHUNKER_MIN_U32,
        max: CHUNKER_MAX_U32,
    })
}

/// Build a `ChunkedBlob` manifest from raw bytes: chunk with `FastCDC` v1 and
/// return `{ root_hash_hex, chunks: [{ offset, len, hash_hex }], bytes_len }`.
///
/// `root_hash_hex` is the object's content id — the BMT root of the manifest,
/// whose leaves are the per-chunk **Blob object ids** (built via the shared
/// `worktree::chunked_blob_from_bytes`), so it equals the id the native store
/// keys the `ChunkedBlob` under. Each chunk's `hash_hex` is the **raw**
/// BLAKE3 of the chunk payload — for UI colouring/dedup, distinct from the
/// manifest leaf. `chunk_size` is `0` (the CDC marker, SPEC-OBJECTS §13.7).
#[wasm_bindgen]
pub fn chunked_blob_encode(bytes: &[u8]) -> Result<ChunkedBlobJs, JsValue> {
    let bytes_len = u32::try_from(bytes.len()).map_err(|_| js_err("bytes length exceeds u32"))?;
    // Per-chunk display info: offset, length, and the raw chunk-content hash
    // (the UI colours and dedups by this — it is NOT the manifest leaf).
    let mut infos: Vec<ChunkInfo> = Vec::new();
    for b in ChunkIterator::new(FastCdc::v1(), bytes) {
        let offset = u32::try_from(b.offset).map_err(|_| js_err("chunk offset exceeds u32"))?;
        let len = u32::try_from(b.length).map_err(|_| js_err("chunk length exceeds u32"))?;
        infos.push(ChunkInfo {
            offset,
            len,
            hash_hex: to_hex(&hash(&bytes[b.offset..b.offset + b.length])),
        });
    }
    // The manifest addresses each chunk by its Blob object id (not the raw
    // chunk hash), exactly as the native store does, so root_hash_hex matches
    // the store's key. Single source of the recipe: chunked_blob_from_bytes.
    let cb = mkit_core::worktree::chunked_blob_from_bytes(bytes)
        .map_err(|e| js_err(format!("chunk: {e}")))?;
    let root_hash_hex = to_hex(&mkit_core::merkle::compute_chunked_id(&cb));
    Ok(ChunkedBlobJs {
        root_hash_hex,
        chunks: infos,
        bytes_len,
    })
}

/// Build a SPEC-DELTA v1 stream of `base -> target` and return a
/// structural summary: `{ ops, bytes_on_wire, full_size }`.
///
/// `ops` contains one entry per opcode — `{ kind: "copy", offset, len }`
/// or `{ kind: "insert", len }` — without the insert payloads, so the
/// whole thing stays cheap to pass across the JS boundary. `bytes_on_wire`
/// is the total delta stream length; `full_size` is `target.len()` for
/// easy delta-savings calculation.
#[wasm_bindgen]
pub fn delta_encode(base: &[u8], target: &[u8]) -> Result<DeltaSummary, JsValue> {
    let stream = delta::encode(base, target).map_err(|e| js_err(format!("delta encode: {e}")))?;
    let bytes_on_wire =
        u32::try_from(stream.len()).map_err(|_| js_err("delta stream exceeds u32"))?;
    let full_size = u32::try_from(target.len()).map_err(|_| js_err("target length exceeds u32"))?;

    // Walk the stream ourselves so we can report each op individually
    // without re-encoding. The header layout + opcodes are in
    // `mkit_core::delta` (`HEADER_LEN`, `OP_COPY`, 0x01..=0x7F = INSERT).
    let mut ops: Vec<DeltaOp> = Vec::new();
    let mut pos = delta::HEADER_LEN;
    while pos < stream.len() {
        let op = stream[pos];
        pos += 1;
        if op & 0x80 != 0 {
            // COPY [u32 LE offset][u16 LE length]
            if pos + 6 > stream.len() {
                return Err(js_err("truncated COPY op"));
            }
            let offset = u32::from_le_bytes(
                stream[pos..pos + 4]
                    .try_into()
                    .map_err(|_| js_err("bad offset"))?,
            );
            pos += 4;
            let length = u16::from_le_bytes(
                stream[pos..pos + 2]
                    .try_into()
                    .map_err(|_| js_err("bad length"))?,
            );
            pos += 2;
            ops.push(DeltaOp {
                kind: "copy".to_string(),
                offset: Some(offset),
                len: u32::from(length),
            });
        } else if op > 0 {
            let length = op as usize;
            if pos + length > stream.len() {
                return Err(js_err("truncated INSERT op"));
            }
            pos += length;
            ops.push(DeltaOp {
                kind: "insert".to_string(),
                offset: None,
                len: u32::from(op), // INSERT length is always in 1..=127
            });
        } else {
            return Err(js_err("reserved 0x00 opcode"));
        }
    }

    Ok(DeltaSummary {
        ops,
        bytes_on_wire,
        full_size,
    })
}

/// Encode `bytes` in Bao outboard mode and return `{ hash_hex, outboard }`.
/// Outboard keeps the encoded tree proof separate from the payload so
/// the demo can stream the original bytes on one track and the proof on
/// another.
#[wasm_bindgen]
pub fn bao_encode(bytes: &[u8]) -> Result<BaoEncoded, JsValue> {
    // `bao::encode::outboard` takes `AsRef<[u8]>` and returns
    // `(Vec<u8>, blake3::Hash)`. Equivalent to the streaming Encoder
    // with `new_outboard`, but all-at-once matches the demo's needs.
    let (outboard, h) = bao::encode::outboard(bytes);
    Ok(BaoEncoded {
        hash_hex: hex::encode(h.as_bytes()),
        outboard,
    })
}

/// Extract a proof-carrying slice from a Bao outboard encoding. The
/// returned bytes are in the format `bao::decode::SliceDecoder`
/// consumes — the original payload plus just enough tree proof to
/// verify it against the root hash.
#[wasm_bindgen]
pub fn bao_slice(
    outboard: &[u8],
    bytes: &[u8],
    offset: u32,
    len: u32,
) -> Result<Box<[u8]>, JsValue> {
    let mut extractor = bao::encode::SliceExtractor::new_outboard(
        std::io::Cursor::new(bytes),
        std::io::Cursor::new(outboard),
        u64::from(offset),
        u64::from(len),
    );
    let mut out = Vec::new();
    extractor
        .read_to_end(&mut out)
        .map_err(|e| js_err(format!("slice extract: {e}")))?;
    Ok(out.into_boxed_slice())
}

/// Verify a Bao slice against a root hash. On success returns
/// `{ ok: true, bytes }` with the verified payload. On tamper returns
/// `{ ok: false, error }` with the error message — a convenience over
/// throwing, since the demo wants to render both outcomes side-by-side.
#[wasm_bindgen]
pub fn bao_verify_slice(
    hash_hex: &str,
    slice_bytes: &[u8],
    offset: u32,
    len: u32,
) -> Result<BaoVerify, JsValue> {
    let h_bytes = parse_hash_hex(hash_hex)?;
    let h: bao::Hash = h_bytes.into();
    let mut decoder = bao::decode::SliceDecoder::new(
        std::io::Cursor::new(slice_bytes),
        &h,
        u64::from(offset),
        u64::from(len),
    );
    let mut out = Vec::new();
    match decoder.read_to_end(&mut out) {
        Ok(_) => Ok(BaoVerify {
            ok: true,
            bytes: Some(out.into_boxed_slice()),
            error: None,
        }),
        Err(e) => Ok(BaoVerify {
            ok: false,
            bytes: None,
            error: Some(e.to_string()),
        }),
    }
}

// ---------------------------------------------------------------------
// Returned structs (plain JS objects via wasm-bindgen getters)
// ---------------------------------------------------------------------

#[wasm_bindgen]
#[derive(Debug)]
pub struct EncodedObject {
    bytes: Vec<u8>,
    hash_hex: String,
}

#[wasm_bindgen]
impl EncodedObject {
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn bytes(&self) -> Box<[u8]> {
        self.bytes.clone().into_boxed_slice()
    }
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn hash_hex(&self) -> String {
        self.hash_hex.clone()
    }
}

#[wasm_bindgen]
#[derive(Debug)]
pub struct EncodedCommit {
    bytes: Vec<u8>,
    hash_hex: String,
    signature_hex: String,
}

#[wasm_bindgen]
impl EncodedCommit {
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn bytes(&self) -> Box<[u8]> {
        self.bytes.clone().into_boxed_slice()
    }
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn hash_hex(&self) -> String {
        self.hash_hex.clone()
    }
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn signature_hex(&self) -> String {
        self.signature_hex.clone()
    }
}

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

#[wasm_bindgen]
#[derive(Debug)]
pub struct AttestKeyPairJs {
    seed_hex: String,
    pubkey_hex: String,
    keyid: String,
    algo: String,
}

#[wasm_bindgen]
impl AttestKeyPairJs {
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
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn keyid(&self) -> String {
        self.keyid.clone()
    }
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn algo(&self) -> String {
        self.algo.clone()
    }
}

#[wasm_bindgen]
#[derive(Debug)]
pub struct AttestationJs {
    envelope_json: String,
    keyid: String,
    attestation_id_hex: String,
}

#[wasm_bindgen]
impl AttestationJs {
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn envelope_json(&self) -> String {
        self.envelope_json.clone()
    }
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn keyid(&self) -> String {
        self.keyid.clone()
    }
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn attestation_id_hex(&self) -> String {
        self.attestation_id_hex.clone()
    }
}

// ---- Streaming primitives ----

/// One `FastCDC` chunk boundary plus its BLAKE3.
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct ChunkInfo {
    offset: u32,
    len: u32,
    hash_hex: String,
}

// `len` is a field exposed across the JS boundary (spec says
// `{ offset, len, hash_hex }`). `is_empty` wouldn't be meaningful here —
// every chunk has a positive length. Suppress the lint at the impl block.
#[allow(clippy::len_without_is_empty)]
#[wasm_bindgen]
impl ChunkInfo {
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn offset(&self) -> u32 {
        self.offset
    }
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn len(&self) -> u32 {
        self.len
    }
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn hash_hex(&self) -> String {
        self.hash_hex.clone()
    }
}

#[wasm_bindgen]
#[derive(Debug)]
pub struct ChunkerResult {
    chunks: Vec<ChunkInfo>,
    avg: u32,
    min: u32,
    max: u32,
}

#[wasm_bindgen]
impl ChunkerResult {
    /// Number of chunks. The `chunk(i)` getter returns each one by index,
    /// which is cheaper than materialising a JS array of opaque handles
    /// when the web caller only wants a few.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn chunk_count(&self) -> u32 {
        js_vec_count(&self.chunks)
    }
    #[wasm_bindgen]
    #[must_use]
    pub fn chunk(&self, i: u32) -> Option<ChunkInfo> {
        js_vec_get(&self.chunks, i)
    }
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn avg(&self) -> u32 {
        self.avg
    }
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn min(&self) -> u32 {
        self.min
    }
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn max(&self) -> u32 {
        self.max
    }
}

#[wasm_bindgen]
#[derive(Debug)]
pub struct ChunkedBlobJs {
    root_hash_hex: String,
    chunks: Vec<ChunkInfo>,
    bytes_len: u32,
}

#[wasm_bindgen]
impl ChunkedBlobJs {
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn root_hash_hex(&self) -> String {
        self.root_hash_hex.clone()
    }
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn chunk_count(&self) -> u32 {
        js_vec_count(&self.chunks)
    }
    #[wasm_bindgen]
    #[must_use]
    pub fn chunk(&self, i: u32) -> Option<ChunkInfo> {
        js_vec_get(&self.chunks, i)
    }
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn bytes_len(&self) -> u32 {
        self.bytes_len
    }
}

/// One entry in the delta summary. `offset` is populated only for `copy` ops.
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct DeltaOp {
    kind: String,
    offset: Option<u32>,
    len: u32,
}

// Same rationale as `ChunkInfo` — `len` mirrors the agreed JSON shape.
#[allow(clippy::len_without_is_empty)]
#[wasm_bindgen]
impl DeltaOp {
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn kind(&self) -> String {
        self.kind.clone()
    }
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn offset(&self) -> Option<u32> {
        self.offset
    }
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn len(&self) -> u32 {
        self.len
    }
}

#[wasm_bindgen]
#[derive(Debug)]
pub struct DeltaSummary {
    ops: Vec<DeltaOp>,
    bytes_on_wire: u32,
    full_size: u32,
}

#[wasm_bindgen]
impl DeltaSummary {
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn op_count(&self) -> u32 {
        js_vec_count(&self.ops)
    }
    #[wasm_bindgen]
    #[must_use]
    pub fn op(&self, i: u32) -> Option<DeltaOp> {
        js_vec_get(&self.ops, i)
    }
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn bytes_on_wire(&self) -> u32 {
        self.bytes_on_wire
    }
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn full_size(&self) -> u32 {
        self.full_size
    }
}

#[wasm_bindgen]
#[derive(Debug)]
pub struct BaoEncoded {
    hash_hex: String,
    outboard: Vec<u8>,
}

#[wasm_bindgen]
impl BaoEncoded {
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn hash_hex(&self) -> String {
        self.hash_hex.clone()
    }
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn outboard(&self) -> Box<[u8]> {
        self.outboard.clone().into_boxed_slice()
    }
}

#[wasm_bindgen]
#[derive(Debug)]
pub struct BaoVerify {
    ok: bool,
    bytes: Option<Box<[u8]>>,
    error: Option<String>,
}

#[wasm_bindgen]
impl BaoVerify {
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn ok(&self) -> bool {
        self.ok
    }
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn bytes(&self) -> Option<Box<[u8]>> {
        self.bytes.clone()
    }
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn error(&self) -> Option<String> {
        self.error.clone()
    }
}

// ---------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------

fn encode_object(obj: &Object) -> Result<EncodedObject, JsValue> {
    let bytes = serialize(obj).map_err(|e| js_err(format!("serialize: {e}")))?;
    // Canonical content id: the BMT root for merkelized types (Tree /
    // ChunkedBlob), BLAKE3 of the bytes otherwise. Routing through the same
    // `id_from_object` dispatch the native store uses keeps wasm-computed ids
    // equal to the key mkit stores the object under (no flat-hash drift).
    let hash_hex = to_hex(&id_from_object(obj, &bytes));
    Ok(EncodedObject { bytes, hash_hex })
}

fn parse_parent_list(s: &str) -> Result<Vec<[u8; 32]>, JsValue> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(Vec::new());
    }
    s.split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(parse_hash_hex)
        .collect()
}

/// Tiny JSON parser for `[["name","mode","hex"], ...]`. We avoid pulling
/// serde into this crate: the input shape is fixed and we control both
/// sides, so a hand-rolled parser keeps the wasm blob small.
fn parse_json_triples(s: &str) -> Result<Vec<(String, String, String)>, &'static str> {
    // Cheap up-front guard against pathological inputs — see
    // `MAX_JSON_BYTES` for rationale.
    if s.len() > MAX_JSON_BYTES {
        return Err("input exceeds 16 MiB cap");
    }
    let s = s.trim();
    let inner = s
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .ok_or("expected top-level JSON array")?;
    let mut out = Vec::new();
    let mut chars = inner.chars().peekable();
    loop {
        skip_ws(&mut chars);
        if chars.peek().is_none() {
            break;
        }
        if *chars.peek().unwrap() != '[' {
            return Err("expected `[` opening a triple");
        }
        chars.next();
        let a = read_string(&mut chars)?;
        expect_comma(&mut chars)?;
        let b = read_string(&mut chars)?;
        expect_comma(&mut chars)?;
        let c = read_string(&mut chars)?;
        skip_ws(&mut chars);
        match chars.next() {
            Some(']') => {}
            _ => return Err("expected `]` closing a triple"),
        }
        out.push((a, b, c));
        skip_ws(&mut chars);
        match chars.peek() {
            Some(',') => {
                chars.next();
            }
            None => break,
            _ => return Err("expected `,` or end of array"),
        }
    }
    Ok(out)
}

fn skip_ws(it: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    while let Some(&c) = it.peek() {
        if c.is_whitespace() {
            it.next();
        } else {
            break;
        }
    }
}

fn expect_comma(it: &mut std::iter::Peekable<std::str::Chars<'_>>) -> Result<(), &'static str> {
    skip_ws(it);
    match it.next() {
        Some(',') => Ok(()),
        _ => Err("expected `,`"),
    }
}

fn read_string(it: &mut std::iter::Peekable<std::str::Chars<'_>>) -> Result<String, &'static str> {
    skip_ws(it);
    match it.next() {
        Some('"') => {}
        _ => return Err("expected `\"`"),
    }
    let mut out = String::new();
    loop {
        match it.next() {
            Some('"') => return Ok(out),
            Some('\\') => match it.next() {
                Some('"') => out.push('"'),
                Some('\\') => out.push('\\'),
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                _ => return Err("unsupported escape"),
            },
            Some(c) => out.push(c),
            None => return Err("unterminated string"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_json_triples_rejects_oversize_input() {
        // One byte over the cap is enough — the guard must fire before
        // the parser even looks for a leading `[`.
        let oversize = "x".repeat(MAX_JSON_BYTES + 1);
        let err = parse_json_triples(&oversize).expect_err("must reject oversize input");
        assert!(
            err.contains("16 MiB cap"),
            "unexpected error message: {err}"
        );
    }

    #[test]
    fn parse_json_triples_accepts_small_valid_input() {
        let out = parse_json_triples(r#"[["a","b","c"]]"#).expect("small input is valid");
        assert_eq!(out, vec![("a".into(), "b".into(), "c".into())]);
    }

    /// Finding 1 regression: `tree_encode` must key a tree by its **BMT root**
    /// (`merkle::compute_tree_id`), matching the id the native store uses — and
    /// must NOT be the pre-merkle flat BLAKE3 of the serialized bytes.
    #[test]
    fn tree_encode_id_matches_native_bmt_root() {
        let h1 = [0x11u8; 32];
        let h2 = [0x22u8; 32];
        let entries_json = format!(
            r#"[["a.txt","blob","{}"],["b.txt","blob","{}"]]"#,
            to_hex(&h1),
            to_hex(&h2)
        );
        let wasm_id = tree_encode(&entries_json).expect("tree encodes").hash_hex();

        let tree = Tree {
            entries: vec![
                TreeEntry {
                    name: b"a.txt".to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: h1,
                },
                TreeEntry {
                    name: b"b.txt".to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: h2,
                },
            ],
        };
        let native_root = to_hex(&mkit_core::merkle::compute_tree_id(&tree));
        assert_eq!(wasm_id, native_root, "tree_encode must emit the BMT root");

        let flat = to_hex(&hash(&serialize(&Object::Tree(tree)).unwrap()));
        assert_ne!(wasm_id, flat, "tree id regressed to pre-merkle flat BLAKE3");
    }

    /// `chunked_blob_encode` must emit the id the **native store** keys the
    /// `ChunkedBlob` under — `worktree::hash_file_object` (the change-detection
    /// path, itself pinned to `store_file_object`). This cross-checks the real
    /// addressing path, not a same-recipe reconstruction; in particular the
    /// manifest leaves must be per-chunk **Blob object ids**, not the raw
    /// chunk-content hashes the UI displays.
    #[test]
    fn chunked_blob_encode_id_matches_native_store() {
        // > CHUNK_THRESHOLD (1 MiB) so the native store actually chunks it,
        // with byte variation so FastCDC cuts real content-defined boundaries.
        let data: Vec<u8> = (0..2_500_000u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8)
            .collect();
        let wasm_id = chunked_blob_encode(&data)
            .expect("chunked blob encodes")
            .root_hash_hex();

        let native_id = to_hex(&mkit_core::worktree::hash_file_object(&data).unwrap());
        assert_eq!(
            wasm_id, native_id,
            "wasm chunked id must equal the native store id"
        );

        // Guard against regressing to a manifest of raw chunk-content hashes
        // (the prior bug): those leaves are not resolvable Blob ids.
        let raw_chunks: Vec<[u8; 32]> = ChunkIterator::new(FastCdc::v1(), &data)
            .map(|b| hash(&data[b.offset..b.offset + b.length]))
            .collect();
        let raw_cb = mkit_core::object::ChunkedBlob {
            total_size: data.len() as u64,
            chunk_size: 0,
            chunks: raw_chunks,
        };
        let raw_root = to_hex(&mkit_core::merkle::compute_chunked_id(&raw_cb));
        assert_ne!(
            wasm_id, raw_root,
            "manifest must use Blob object ids, not raw chunk hashes"
        );
    }

    #[test]
    fn sec1_to_compressed_passes_through_compressed() {
        // A 33-byte 0x02/0x03-prefixed key is already compressed.
        let mut k = vec![0x03u8; 33];
        k[0] = 0x02;
        assert_eq!(sec1_to_compressed(&k).as_deref(), Some(k.as_slice()));
        k[0] = 0x03;
        assert_eq!(sec1_to_compressed(&k).as_deref(), Some(k.as_slice()));
    }

    #[test]
    fn sec1_to_compressed_rejects_malformed() {
        assert!(sec1_to_compressed(&[]).is_none());
        assert!(sec1_to_compressed(&[0x04u8; 64]).is_none()); // wrong length
        assert!(sec1_to_compressed(&[0x02u8; 32]).is_none()); // wrong length
        assert!(sec1_to_compressed(&[0x05u8; 33]).is_none()); // bad tag
        assert!(sec1_to_compressed(&[0x01u8; 65]).is_none()); // uncompressed bad tag
    }

    /// `sec1_to_compressed` must reproduce exactly the compressed encoding
    /// that the signer emits when fed the matching *uncompressed* point —
    /// this is what makes the keyid match the envelope's keyid.
    #[test]
    fn sec1_to_compressed_matches_signer_p256() {
        let mut seed = [0u8; 32];
        seed[31] = 7;
        let signer = P256Signer::from_seed_zeroizing(&Zeroizing::new(seed)).unwrap();
        let compressed = signer.public_key_sec1();
        let uncompressed = signer.public_key_sec1_uncompressed();
        assert_eq!(uncompressed.len(), 65);
        assert_eq!(uncompressed[0], 0x04);
        assert_eq!(
            sec1_to_compressed(&uncompressed).as_deref(),
            Some(compressed.as_slice()),
            "compressing the uncompressed key must equal the signer's compressed key"
        );
    }

    /// Regression: an envelope built (and thus keyed) with the compressed
    /// SEC1 form must still verify when the caller supplies the *uncompressed*
    /// 130-hex pubkey, as the public docstring promises. Before normalization
    /// this returned `false` (keyid mismatch → lookup miss).
    #[test]
    fn attest_verify_accepts_uncompressed_p256_pubkey() {
        let commit = to_hex(&hash(b"commit-bytes"));
        let mut seed = [0u8; 32];
        seed[31] = 7;
        let seed_hex = to_hex(&seed);

        let att = attest_build(
            &commit,
            "https://example/predicate",
            b"{}",
            &seed_hex,
            "p256",
        )
        .expect("build p256 envelope");

        // Sanity: the natural compressed pubkey verifies.
        let compressed_hex = att.keyid.strip_prefix("p256:").unwrap().to_string();
        assert!(attest_verify(&att.envelope_json, &compressed_hex, "p256"));

        // The documented uncompressed form must verify too.
        let signer = P256Signer::from_seed_zeroizing(&Zeroizing::new(seed)).unwrap();
        let uncompressed_hex = hex::encode(signer.public_key_sec1_uncompressed());
        assert_eq!(uncompressed_hex.len(), 130);
        assert!(
            attest_verify(&att.envelope_json, &uncompressed_hex, "p256"),
            "uncompressed SEC1 pubkey must verify per the documented contract"
        );
    }
}
