//! secp256k1 / ES256K signer + verifier (COSE alg -47).
//!
//! Feature-gated behind `algo-secp256k1`. See `docs/SPEC-ATTESTATIONS.md`
//! §6 for the trait contract, and this crate's [`signer_repo_key`] module
//! for the Ed25519 analogue.
//!
//! Signing semantics:
//!   * ECDSA over secp256k1, hash = SHA-256 of the PAE bytes.
//!   * Nonce is derived per RFC 6979 (k256's default), so the output is
//!     **deterministic** — a fixed secret + fixed PAE always produce the
//!     same signature, which is what the `golden_secp256k1.rs` regression
//!     test pins.
//!   * Signature encoding is 64-byte compact `r ‖ s`, with **low-S
//!     normalization** applied (prevents signature malleability; matches
//!     what Ethereum / BIP-146 require).
//!
//! Public key format on the wire: 33-byte compressed SEC1 (`0x02`/`0x03`
//! prefix + x). The verifier will also accept 65-byte uncompressed
//! (`0x04` + x + y) to stay liberal in what it reads.
//!
use crate::{Algorithm, Error};

#[cfg(feature = "algo-secp256k1")]
use k256::ecdsa::{
    Signature as K256Sig, SigningKey, VerifyingKey,
    signature::{DigestSigner, hazmat::PrehashVerifier},
};
#[cfg(feature = "algo-secp256k1")]
use sha2::{Digest, Sha256};

/// secp256k1 / ES256K Signer. Carries the 32-byte secret scalar wrapped
/// in k256's zeroizing `SigningKey`. Construct via [`Secp256k1Signer::new`]
/// for a raw 32-byte secret or [`Secp256k1Signer::from_der_pkcs8`] for a
/// PKCS#8-DER-encoded key from disk.
#[cfg(feature = "algo-secp256k1")]
#[derive(Debug, Clone)]
pub struct Secp256k1Signer {
    sk: SigningKey,
}

#[cfg(feature = "algo-secp256k1")]
impl Secp256k1Signer {
    /// Build from a raw 32-byte secret scalar.
    ///
    /// The parameter is taken `mut` so we can scrub it before this
    /// constructor returns — the underlying `SigningKey` zeroizes its
    /// own internal scalar on drop, but our parameter copy lives on
    /// the function's stack frame until the frame is reused. Callers
    /// that hold the secret on their own stack are still expected to
    /// scrub their copy after this call returns; we cannot reach back
    /// across the call boundary.
    ///
    /// # Errors
    /// [`Error::Secp256k1KeyInvalid`] if the scalar is zero or >= n.
    pub fn new(mut secret: [u8; 32]) -> Result<Self, Error> {
        use zeroize::Zeroize;
        let result =
            SigningKey::from_bytes((&secret).into()).map_err(|_| Error::Secp256k1KeyInvalid);
        secret.zeroize();
        let sk = result?;
        Ok(Self { sk })
    }

    /// Build from a [`zeroize::Zeroizing`]-wrapped raw 32-byte scalar.
    /// Avoids the intermediate `[u8; 32]` `Copy` on the caller's stack
    /// that [`Secp256k1Signer::new`] requires.
    ///
    /// # Zeroization
    ///
    /// The caller's `Zeroizing` wrapper still owns the seed and scrubs
    /// it on drop. Internally we materialise one `[u8; 32]` to feed
    /// into `SigningKey::from_bytes`, then scrub it before returning.
    ///
    /// # Errors
    /// [`Error::Secp256k1KeyInvalid`] if the scalar is zero or >= n.
    pub fn from_seed_zeroizing(secret: &zeroize::Zeroizing<[u8; 32]>) -> Result<Self, Error> {
        use zeroize::Zeroize;
        let mut tmp = [0u8; 32];
        tmp.copy_from_slice(secret.as_slice());
        let result = SigningKey::from_bytes((&tmp).into()).map_err(|_| Error::Secp256k1KeyInvalid);
        tmp.zeroize();
        let sk = result?;
        Ok(Self { sk })
    }

    /// Build from a PKCS#8-DER-encoded secp256k1 private key.
    ///
    /// # Errors
    /// [`Error::Secp256k1KeyInvalid`] on any parse failure.
    pub fn from_der_pkcs8(bytes: &[u8]) -> Result<Self, Error> {
        use k256::pkcs8::DecodePrivateKey;
        let sk = SigningKey::from_pkcs8_der(bytes).map_err(|_| Error::Secp256k1KeyInvalid)?;
        Ok(Self { sk })
    }

    /// 33-byte compressed SEC1 public key.
    #[must_use]
    pub fn public_key_sec1(&self) -> Vec<u8> {
        self.sk
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec()
    }

    /// Algorithm tag — stable against future `Algorithm` dispatch.
    #[must_use]
    pub fn algorithm(&self) -> Algorithm {
        Algorithm::Secp256k1
    }

    /// `secp256k1:<hex(compressed_pubkey)>` — 66 hex chars + 10-byte
    /// prefix = 76 bytes total.
    #[must_use]
    pub fn keyid_string(&self) -> String {
        let pk = self.public_key_sec1();
        format!("secp256k1:{}", hex_lower(&pk))
    }

    /// Deterministic ES256K signature (RFC 6979 nonce) over `SHA256(pae)`,
    /// low-S normalized, encoded as 64-byte compact `r ‖ s`.
    ///
    /// # Errors
    /// [`Error::Secp256k1SignatureInvalid`] if the underlying k256 sign
    /// call fails (should not happen for well-formed inputs).
    pub fn sign_dsse(&self, pae: &[u8]) -> Result<Vec<u8>, Error> {
        // DigestSigner consumes the hasher state and produces an ECDSA
        // signature over the 32-byte digest. k256's ecdsa impl applies
        // low-S normalization automatically on encode (confirmed at
        // https://docs.rs/k256/0.13/k256/ecdsa/index.html#usage) so the
        // resulting (r, s) pair has s < n/2.
        let mut h = Sha256::new();
        h.update(pae);
        let sig: K256Sig = self
            .sk
            .try_sign_digest(h)
            .map_err(|_| Error::Secp256k1SignatureInvalid)?;
        // `to_bytes` yields the 64-byte compact form (r || s, big-endian).
        Ok(sig.to_bytes().to_vec())
    }
}

#[cfg(feature = "algo-secp256k1")]
impl crate::signer::Signer for Secp256k1Signer {
    fn algorithm(&self) -> Algorithm {
        Algorithm::Secp256k1
    }
    fn keyid(&self) -> Result<String, Error> {
        Ok(self.keyid_string())
    }
    fn sign(&mut self, pae: &[u8]) -> Result<Vec<u8>, Error> {
        self.sign_dsse(pae)
    }
}

/// Verify an ES256K signature.
///
/// * `pubkey_sec1` — 33-byte compressed or 65-byte uncompressed SEC1.
/// * `msg`        — the DSSE PAE bytes (hashed internally with SHA-256).
/// * `sig_compact`— 64-byte `r ‖ s` (big-endian).
///
/// Rejects high-S signatures by first normalizing; a signature whose s
/// value is in the upper half of the curve order is treated as
/// `Secp256k1VerifyFailed` to match the signer-side invariant.
///
/// # Errors
/// * [`Error::Secp256k1KeyInvalid`] — pubkey cannot be parsed.
/// * [`Error::Secp256k1SignatureInvalid`] — wrong-length or malformed
///   signature bytes.
/// * [`Error::Secp256k1VerifyFailed`] — signature is well-formed but
///   does not verify against the pubkey + message.
#[cfg(feature = "algo-secp256k1")]
pub fn verify_secp256k1(pubkey_sec1: &[u8], msg: &[u8], sig_compact: &[u8]) -> Result<(), Error> {
    let vk = VerifyingKey::from_sec1_bytes(pubkey_sec1).map_err(|_| Error::Secp256k1KeyInvalid)?;
    if sig_compact.len() != 64 {
        return Err(Error::Secp256k1SignatureInvalid);
    }
    let sig = K256Sig::from_slice(sig_compact).map_err(|_| Error::Secp256k1SignatureInvalid)?;
    // Enforce low-S: reject malleable high-S form. `normalize_s` returns
    // Some(normalized) iff the input was high-s; we refuse those outright
    // so the verifier contract matches what the signer emits.
    if sig.normalize_s().is_some() {
        return Err(Error::Secp256k1VerifyFailed);
    }
    let mut h = Sha256::new();
    h.update(msg);
    // DigestVerifier consumes the hasher state; equivalent to
    // `verify_prehash(&hash.finalize(), &sig)` but avoids an extra alloc.
    let digest = h.finalize();
    vk.verify_prehash(&digest, &sig)
        .map_err(|_| Error::Secp256k1VerifyFailed)?;
    Ok(())
}

// ---------------------------------------------------------------------------

#[cfg(feature = "algo-secp256k1")]
fn hex_lower(b: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        s.push(HEX[(byte >> 4) as usize] as char);
        s.push(HEX[(byte & 0x0F) as usize] as char);
    }
    s
}

#[cfg(all(test, feature = "algo-secp256k1"))]
mod tests {
    use super::*;
    use crate::signer::Signer;

    fn fixed_secret() -> [u8; 32] {
        // All zeros with last byte = 1 — the canonical RFC 6979 /
        // secp256k1 test scalar (also the BIP-340 "test key #1" base).
        let mut k = [0u8; 32];
        k[31] = 1;
        k
    }

    const FIXED_PAE: &[u8] = b"DSSEv1 28 application/vnd.in-toto+json 2 {}";

    #[test]
    fn sign_verify_roundtrip_secp256k1() {
        let signer = Secp256k1Signer::new(fixed_secret()).unwrap();
        let sig = signer.sign_dsse(FIXED_PAE).unwrap();
        assert_eq!(sig.len(), 64, "compact ES256K signature must be 64 bytes");
        let pk = signer.public_key_sec1();
        assert_eq!(pk.len(), 33, "compressed SEC1 pubkey must be 33 bytes");
        verify_secp256k1(&pk, FIXED_PAE, &sig).expect("roundtrip must verify");
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let signer = Secp256k1Signer::new(fixed_secret()).unwrap();
        let mut sig = signer.sign_dsse(FIXED_PAE).unwrap();
        sig[10] ^= 0x01;
        let pk = signer.public_key_sec1();
        assert!(matches!(
            verify_secp256k1(&pk, FIXED_PAE, &sig),
            Err(Error::Secp256k1VerifyFailed | Error::Secp256k1SignatureInvalid)
        ));
    }

    #[test]
    fn verify_rejects_wrong_pubkey() {
        let signer = Secp256k1Signer::new(fixed_secret()).unwrap();
        let sig = signer.sign_dsse(FIXED_PAE).unwrap();
        // A different secret → different pubkey.
        let other = {
            let mut k = [0u8; 32];
            k[31] = 2;
            k
        };
        let other_pk = Secp256k1Signer::new(other).unwrap().public_key_sec1();
        assert!(matches!(
            verify_secp256k1(&other_pk, FIXED_PAE, &sig),
            Err(Error::Secp256k1VerifyFailed)
        ));
    }

    #[test]
    fn keyid_has_secp256k1_prefix() {
        let signer = Secp256k1Signer::new(fixed_secret()).unwrap();
        let kid = signer.keyid_string();
        assert!(kid.starts_with("secp256k1:"), "keyid = {kid}");
        // prefix (10) + hex(33 bytes) = 10 + 66 = 76
        assert_eq!(kid.len(), 76);
    }

    #[test]
    fn algorithm_returns_secp256k1() {
        let signer = Secp256k1Signer::new(fixed_secret()).unwrap();
        assert_eq!(signer.algorithm(), Algorithm::Secp256k1);
    }

    #[test]
    fn signer_trait_dispatch() {
        let mut signer: Box<dyn Signer> = Box::new(Secp256k1Signer::new(fixed_secret()).unwrap());
        let kid = signer.keyid().unwrap();
        assert!(kid.starts_with("secp256k1:"));
        let sig = signer.sign(FIXED_PAE).unwrap();
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn rfc6979_determinism() {
        // Signing the same PAE twice with the same key must produce
        // bit-identical output — that's what lets the golden-vector
        // regression test be stable.
        let s1 = Secp256k1Signer::new(fixed_secret())
            .unwrap()
            .sign_dsse(FIXED_PAE)
            .unwrap();
        let s2 = Secp256k1Signer::new(fixed_secret())
            .unwrap()
            .sign_dsse(FIXED_PAE)
            .unwrap();
        assert_eq!(s1, s2, "RFC 6979 output must be deterministic");
    }

    #[test]
    fn low_s_enforced_on_output() {
        // The signer's output s-value MUST already be in the lower half
        // of the curve order. Re-parse, try to normalize, and assert no
        // normalization was needed.
        let sig_bytes = Secp256k1Signer::new(fixed_secret())
            .unwrap()
            .sign_dsse(FIXED_PAE)
            .unwrap();
        let sig = K256Sig::from_slice(&sig_bytes).unwrap();
        assert!(
            sig.normalize_s().is_none(),
            "signer emitted a high-S signature; low-S normalization regressed"
        );
    }

    #[test]
    fn verify_rejects_wrong_length_signature() {
        let signer = Secp256k1Signer::new(fixed_secret()).unwrap();
        let pk = signer.public_key_sec1();
        assert!(matches!(
            verify_secp256k1(&pk, FIXED_PAE, &[0u8; 63]),
            Err(Error::Secp256k1SignatureInvalid)
        ));
    }

    #[test]
    fn zero_secret_rejected() {
        assert!(matches!(
            Secp256k1Signer::new([0u8; 32]),
            Err(Error::Secp256k1KeyInvalid)
        ));
    }
}
