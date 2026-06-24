//! Attestations: in-toto v1 Statements wrapped in DSSE envelopes, signed
//! with Ed25519 / secp256k1 / P-256, plus the `WebAuthn` (passkey) signing
//! lifecycle and the `AttestKeyPairJs` / `AttestationJs` view structs.

use wasm_bindgen::prelude::*;

use mkit_attest::algorithm::Algorithm;
use mkit_attest::envelope::{Envelope, Sig};
use mkit_attest::signer_k256::Secp256k1Signer;
use mkit_attest::signer_p256::P256Signer;
use mkit_attest::statement::{Statement, Subject, encode as encode_statement};
use mkit_attest::verify::{Registry, TrustRoot, verify_envelope};
use mkit_attest::webauthn::{WebAuthnPolicy, WebAuthnWrapping};
use mkit_attest::{PAYLOAD_TYPE_IN_TOTO, Signer, signer_repo_key::RepoKeySigner};
use mkit_core::hash::{hash, to_hex};
use mkit_core::sign::KeyPair;

use zeroize::Zeroizing;

use crate::common::{js_err, parse_algo, parse_hash_hex};

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
            "BLS threshold keypair generation is not supported in WASM",
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
            return Err(js_err("BLS threshold signing is not supported in WASM"));
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
// WebAuthn / passkey signing — browser passkeys (P-256) signing a
// DSSE attestation. mkit's core commit signing is Ed25519-only, but
// attestations are P-256-capable, and platform passkeys (Touch ID /
// Face ID / Android biometric) only ever produce P-256 (ES256), so
// the passkey lifecycle lands here. See
// docs/research/passkey-signing-demo.md.
//
// A passkey does NOT sign arbitrary bytes: the authenticator signs
// `authenticatorData || SHA-256(clientDataJSON)` where the DSSE PAE
// is carried inside `clientDataJSON.challenge`. The demo therefore:
//   1. calls `attest_pae(...)` to get the exact challenge bytes,
//   2. runs `navigator.credentials.get({ challenge: <pae>, ... })`,
//   3. feeds the assertion back into `verify_webauthn_wrapping(...)`.
// Key extraction (COSE -> SEC1) and signature normalisation
// (DER -> compact r||s, low-S) happen JS-side (ox / webauthx); the
// functions below expect a SEC1 pubkey + 64-byte compact signature.
// ---------------------------------------------------------------------

/// Compute the DSSE PAE for an (unsigned) in-toto attestation over a
/// commit hash. This is the exact byte string a browser passkey MUST
/// place in its `WebAuthn` `challenge` so the resulting assertion
/// verifies under [`verify_webauthn_wrapping`].
///
/// Same `(commit_hash_hex, predicate_type, predicate_jcs)` inputs as
/// [`attest_build`], minus the key — the PAE is signer-independent, so a
/// passkey and a software key over the same statement bind to identical
/// bytes. Returns the raw PAE; the JS side passes it straight to
/// `navigator.credentials.get` as a `BufferSource` challenge.
///
/// NOTE: the `WebAuthn` `challenge` here is the *whole* PAE, and platform
/// authenticators cap challenge size in practice — keep demo predicates
/// small (see the research note's "challenge sizing" fork).
///
/// # Errors
/// `commit_hash_hex` is not 64 lowercase hex chars, or the statement
/// fails to encode.
#[wasm_bindgen]
pub fn attest_pae(
    commit_hash_hex: &str,
    predicate_type: &str,
    predicate_jcs: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let _ = parse_hash_hex(commit_hash_hex)?;
    let stmt = Statement {
        subjects: vec![Subject {
            name: Some("commit".to_string()),
            digest_blake3_hex: commit_hash_hex.to_string(),
        }],
        predicate_type: predicate_type.to_string(),
        predicate_jcs,
    };
    let statement_json = encode_statement(&stmt).map_err(|e| js_err(format!("statement: {e}")))?;
    let env = Envelope {
        payload_type: PAYLOAD_TYPE_IN_TOTO.to_string(),
        payload: statement_json.into_bytes(),
        signatures: Vec::new(),
    };
    Ok(env.pae())
}

/// Verify a browser passkey (`WebAuthn` / P-256) assertion against a DSSE
/// PAE — cryptographic checks only, no ceremony policy.
///
/// Thin wrapper over `mkit_attest::verify_webauthn_wrapping`. Checks the
/// `type == "webauthn.get"`, `challenge == base64url-nopad(pae)`, the
/// `authenticatorData` shape, and the P-256 signature over
/// `authenticatorData || SHA-256(clientDataJSON)`. It does NOT bind the
/// RP ID or origin — use [`verify_webauthn_wrapping_with_policy`] for
/// that (which is what a real demo should do, pinning the RP ID to the
/// site so the green check proves origin binding, not just a signature).
///
/// * `pae` — the bytes from [`attest_pae`].
/// * `authenticator_data` / `client_data_json` — raw bytes from the
///   browser assertion (`response.authenticatorData` /
///   `response.clientDataJSON`), passed as a `Uint8Array`.
/// * `pubkey_hex` — SEC1 P-256 public key, 33-byte compressed (66 hex)
///   or 65-byte uncompressed (130 hex).
/// * `signature` — 64-byte compact `r || s` (DER must be converted and
///   low-S-normalised JS-side first).
///
/// Returns `Ok(())` when the assertion verifies. On failure the `Err`
/// carries the typed reason (challenge mismatch, signature failed, …) so
/// the demo can show *why* — more instructive than a bare boolean.
///
/// # Errors
/// `pubkey_hex` is not valid hex, or any `WebAuthn` verification failure.
#[wasm_bindgen]
pub fn verify_webauthn_wrapping(
    pae: &[u8],
    authenticator_data: &[u8],
    client_data_json: &[u8],
    pubkey_hex: &str,
    signature: &[u8],
) -> Result<(), JsValue> {
    let pubkey = hex::decode(pubkey_hex).map_err(|_| js_err("pubkey_hex is not valid hex"))?;
    let wrapping = WebAuthnWrapping {
        authenticator_data: authenticator_data.to_vec(),
        client_data_json: client_data_json.to_vec(),
    };
    attest_verify_webauthn(pae, &wrapping, &pubkey, signature, &WebAuthnPolicy::permissive())
}

/// Policy-aware counterpart of [`verify_webauthn_wrapping`].
///
/// Same cryptographic checks, plus the ceremony policy parsed from
/// `policy_json` — an empty string (or `"{}"`) is fully permissive.
/// Recognised keys (all optional):
///
/// ```json
/// {
///   "expected_rp_id": "mkit.sh",
///   "allowed_origins": ["https://mkit.sh"],
///   "require_user_presence": true,
///   "require_user_verification": false,
///   "allow_cross_origin": false,
///   "previous_sign_count": 0
/// }
/// ```
///
/// Defaults match `WebAuthnPolicy::permissive` (no RP-ID/origin binding,
/// UP/UV off, cross-origin allowed, counter unenforced) — only keys
/// present in `policy_json` tighten the check.
///
/// # Errors
/// Malformed `policy_json`, `pubkey_hex` is not valid hex, or any
/// `WebAuthn` verification failure.
#[wasm_bindgen]
pub fn verify_webauthn_wrapping_with_policy(
    pae: &[u8],
    authenticator_data: &[u8],
    client_data_json: &[u8],
    pubkey_hex: &str,
    signature: &[u8],
    policy_json: &str,
) -> Result<(), JsValue> {
    let pubkey = hex::decode(pubkey_hex).map_err(|_| js_err("pubkey_hex is not valid hex"))?;
    let policy = parse_webauthn_policy(policy_json)?;
    let wrapping = WebAuthnWrapping {
        authenticator_data: authenticator_data.to_vec(),
        client_data_json: client_data_json.to_vec(),
    };
    attest_verify_webauthn(pae, &wrapping, &pubkey, signature, &policy)
}

/// Shared verify tail for the two `WebAuthn` exports: run the
/// policy-aware verifier and map the typed `mkit-attest` error into a JS
/// `Error` whose message names the failure mode.
fn attest_verify_webauthn(
    pae: &[u8],
    wrapping: &WebAuthnWrapping,
    pubkey_sec1: &[u8],
    signature: &[u8],
    policy: &WebAuthnPolicy,
) -> Result<(), JsValue> {
    // Fully-qualified to avoid colliding with the wasm export of the
    // same name above; we always route through the policy-aware variant.
    mkit_attest::webauthn::verify_webauthn_wrapping_with_policy(
        pae,
        wrapping,
        pubkey_sec1,
        signature,
        policy,
    )
    .map_err(|e| js_err(format!("webauthn verify failed: {e}")))
}

/// Parse the optional `policy_json` blob into a [`WebAuthnPolicy`]. An
/// empty string is treated as `"{}"` (fully permissive). Any present key
/// overrides its permissive default; absent keys keep the default.
fn parse_webauthn_policy(policy_json: &str) -> Result<WebAuthnPolicy, JsValue> {
    let trimmed = policy_json.trim();
    if trimmed.is_empty() {
        return Ok(WebAuthnPolicy::permissive());
    }
    let v: serde_json::Value =
        serde_json::from_str(trimmed).map_err(|e| js_err(format!("policy_json: {e}")))?;
    let obj = v
        .as_object()
        .ok_or_else(|| js_err("policy_json must be a JSON object"))?;

    let mut policy = WebAuthnPolicy::permissive();
    if let Some(rp) = obj.get("expected_rp_id").and_then(serde_json::Value::as_str) {
        policy.expected_rp_id = Some(rp.to_string());
    }
    if let Some(arr) = obj.get("allowed_origins").and_then(serde_json::Value::as_array) {
        let origins = arr
            .iter()
            .map(|o| {
                o.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| js_err("allowed_origins entries must be strings"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        policy.allowed_origins = Some(origins);
    }
    if let Some(b) = obj.get("require_user_presence").and_then(serde_json::Value::as_bool) {
        policy.require_user_presence = b;
    }
    if let Some(b) = obj
        .get("require_user_verification")
        .and_then(serde_json::Value::as_bool)
    {
        policy.require_user_verification = b;
    }
    if let Some(b) = obj.get("allow_cross_origin").and_then(serde_json::Value::as_bool) {
        policy.allow_cross_origin = b;
    }
    if let Some(n) = obj.get("previous_sign_count").and_then(serde_json::Value::as_u64) {
        policy.previous_sign_count = Some(u32::try_from(n).unwrap_or(u32::MAX));
    }
    Ok(policy)
}

// ---------------------------------------------------------------------
// View structs
// ---------------------------------------------------------------------

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

#[cfg(test)]
mod tests {
    use super::*;

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
