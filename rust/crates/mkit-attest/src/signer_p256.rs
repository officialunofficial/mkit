//! P-256 (`secp256r1` / `prime256v1`) ECDSA signer — ES256 / COSE alg −7.
//!
//! This is *the* curve for mobile and browser signing: `WebAuthn`, Apple
//! `Secure Enclave`, Android `Keystore`, iOS `CryptoKit`, and browser
//! `WebCrypto` all speak ECDSA over NIST P-256 with SHA-256. We emit a
//! 64-byte compact signature (`r || s`), low-S normalised, and we
//! accept both SEC1 compressed (33-byte, `0x02`/`0x03` prefix) and
//! SEC1 uncompressed (65-byte, `0x04` prefix) public keys on the verify
//! side — `WebAuthn` authenticators publish uncompressed; our sending
//! side publishes compressed.
//!
//! Signing is deterministic per RFC 6979 (the default inside
//! [`p256::ecdsa::SigningKey::sign`]) so golden vectors are stable
//! across runs and across machines.
//!
//! Feature-gated behind `algo-p256` so non-P-256 builds pay no cost.

#![cfg(feature = "algo-p256")]

use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::pkcs8::DecodePrivateKey;

use crate::{Algorithm, Error};

/// Keyid prefix for P-256 signers. The canonical source is
/// [`Algorithm::P256`]`.prefix()`; this constant duplicates it so
/// callers that don't import the enum still have a single
/// source-of-truth string.
pub const KEYID_PREFIX: &str = "p256:";

/// A P-256 ECDSA signer over SHA-256(PAE).
#[derive(Debug, Clone)]
pub struct P256Signer {
    sk: SigningKey,
}

impl P256Signer {
    /// Build a signer from a raw 32-byte scalar. The scalar MUST be in
    /// `[1, n-1]` where `n` is the P-256 group order; out-of-range
    /// values (zero or ≥ n) are rejected by the underlying crate and
    /// surface as [`Error::P256KeyInvalid`].
    ///
    /// The parameter is taken `mut` so the constructor can scrub it
    /// before returning — see [`super::signer_k256::Secp256k1Signer::new`]
    /// for the rationale.
    ///
    /// # Errors
    /// [`Error::P256KeyInvalid`] if the scalar is invalid.
    pub fn new(mut secret: [u8; 32]) -> Result<Self, Error> {
        use zeroize::Zeroize;
        let result = SigningKey::from_bytes(&secret.into()).map_err(|_| Error::P256KeyInvalid);
        secret.zeroize();
        let sk = result?;
        Ok(Self { sk })
    }

    /// Build from a [`zeroize::Zeroizing`]-wrapped raw 32-byte scalar.
    /// Avoids the intermediate `[u8; 32]` `Copy` on the caller's stack
    /// that [`P256Signer::new`] requires.
    ///
    /// # Zeroization
    ///
    /// The caller's `Zeroizing` wrapper still owns the seed and scrubs
    /// it on drop. Internally we materialise one `[u8; 32]` to feed
    /// into `SigningKey::from_bytes`, then scrub it before returning.
    ///
    /// # Errors
    /// [`Error::P256KeyInvalid`] if the scalar is invalid.
    pub fn from_seed_zeroizing(secret: &zeroize::Zeroizing<[u8; 32]>) -> Result<Self, Error> {
        use zeroize::Zeroize;
        let mut tmp = [0u8; 32];
        tmp.copy_from_slice(secret.as_slice());
        let result = SigningKey::from_bytes(&tmp.into()).map_err(|_| Error::P256KeyInvalid);
        tmp.zeroize();
        let sk = result?;
        Ok(Self { sk })
    }

    /// Build a signer from a DER-encoded PKCS#8 private key. This is
    /// the format `openssl pkcs8 -topk8` emits and the format
    /// `WebCrypto` `exportKey("pkcs8", …)` produces.
    ///
    /// # Errors
    /// [`Error::P256KeyInvalid`] on any decode or validation failure.
    pub fn from_der_pkcs8(bytes: &[u8]) -> Result<Self, Error> {
        let sk = SigningKey::from_pkcs8_der(bytes).map_err(|_| Error::P256KeyInvalid)?;
        Ok(Self { sk })
    }

    /// 33-byte SEC1 compressed encoding of the verifying key —
    /// `0x02 || x` or `0x03 || x` depending on y-parity. This is the
    /// compact form we publish alongside attestations; `WebAuthn`
    /// authenticators emit the 65-byte uncompressed form instead, and
    /// [`verify_p256`] accepts both.
    #[must_use]
    pub fn public_key_sec1(&self) -> Vec<u8> {
        self.sk
            .verifying_key()
            .to_sec1_point(true)
            .as_bytes()
            .to_vec()
    }

    /// 65-byte SEC1 uncompressed encoding of the verifying key —
    /// `0x04 || x || y`. Offered as a convenience for interop with
    /// `WebAuthn` / `COSE_Key` consumers.
    #[must_use]
    pub fn public_key_sec1_uncompressed(&self) -> Vec<u8> {
        self.sk
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec()
    }

    /// The algorithm this signer produces.
    #[must_use]
    pub fn algorithm(&self) -> Algorithm {
        Algorithm::P256
    }

    /// `p256:<hex(compressed-pubkey)>` — stable, deterministic,
    /// 5 + 66 = 71-byte string. Matches the shape of the Ed25519
    /// `blake3:<hex>` keyid so the verifier registry needs no
    /// special-casing.
    #[must_use]
    pub fn keyid(&self) -> String {
        let hex = to_hex(&self.public_key_sec1());
        format!("{KEYID_PREFIX}{hex}")
    }

    /// Sign the DSSE PAE. Returns a 64-byte compact ECDSA signature
    /// (`r || s`), low-S normalised, RFC 6979 deterministic. The PAE
    /// already carries its own `"DSSEv1 "` domain separator so we sign
    /// it directly — the p256 crate hashes with SHA-256 internally.
    ///
    /// # Errors
    /// This path is infallible for a well-formed signer, but the
    /// interface returns `Result` for parity with the shared trait;
    /// a hard cryptography failure would surface as
    /// [`Error::P256SignatureInvalid`].
    pub fn sign_dsse(&self, pae: &[u8]) -> Result<Vec<u8>, Error> {
        // `SigningKey::sign` does SHA-256(pae) + RFC-6979 deterministic
        // k + returns a `Signature` already normalised to low-S by the
        // crate's default. `to_bytes()` emits the 64-byte `r || s`
        // concatenation we want.
        let sig: Signature = self.sk.sign(pae);
        // Defence-in-depth: re-normalise. If the crate ever relaxes the
        // low-S default we still emit a canonical signature.
        let sig = sig.normalize_s();
        Ok(sig.to_bytes().to_vec())
    }
}

impl crate::signer::Signer for P256Signer {
    fn algorithm(&self) -> Algorithm {
        Algorithm::P256
    }
    fn keyid(&self) -> Result<String, Error> {
        Ok(Self::keyid(self))
    }
    fn sign(&mut self, pae: &[u8]) -> Result<Vec<u8>, Error> {
        Self::sign_dsse(self, pae)
    }
}

// -- Verifier --------------------------------------------------------

/// Verify a 64-byte compact P-256 ECDSA signature over SHA-256(`msg`)
/// using a SEC1-encoded public key. Accepts both compressed (33 bytes,
/// `0x02`/`0x03` prefix) and uncompressed (65 bytes, `0x04` prefix)
/// forms — `WebAuthn` emits uncompressed, our own signer emits
/// compressed.
///
/// Enforces low-S: any signature with `s > n/2` is rejected even if the
/// math checks out. This blocks the ECDSA malleability family the same
/// way `ed25519-dalek::verify_strict` blocks the Ed25519 one.
///
/// # Errors
/// * [`Error::P256KeyInvalid`] — malformed pubkey bytes.
/// * [`Error::P256SignatureInvalid`] — signature not 64 bytes, or not
///   in low-S form, or not a valid `(r, s)` pair.
/// * [`Error::P256VerifyFailed`] — math says no.
pub fn verify_p256(pubkey_sec1: &[u8], msg: &[u8], sig_compact: &[u8]) -> Result<(), Error> {
    let vk = VerifyingKey::from_sec1_bytes(pubkey_sec1).map_err(|_| Error::P256KeyInvalid)?;

    if sig_compact.len() != 64 {
        return Err(Error::P256SignatureInvalid);
    }
    let mut arr = [0u8; 64];
    arr.copy_from_slice(sig_compact);
    let sig = Signature::from_bytes(&arr.into()).map_err(|_| Error::P256SignatureInvalid)?;

    // Low-S enforcement: normalize_s is a no-op iff the input was
    // already low-S. If it changed anything the wire signature was not
    // canonical, so reject regardless of whether the raw math verifies.
    if sig.normalize_s() != sig {
        return Err(Error::P256SignatureInvalid);
    }

    vk.verify(msg, &sig).map_err(|_| Error::P256VerifyFailed)
}

// -- Internals -------------------------------------------------------

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0F) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixed 32-byte secret used across the inline tests. Not a
    /// published NIST vector — chosen for readability. The cross-check
    /// against a real RFC / `WebAuthn` vector lives in
    /// `tests/golden_p256.rs`.
    const TEST_SECRET: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];

    #[test]
    fn sign_verify_roundtrip_p256() {
        let signer = P256Signer::new(TEST_SECRET).unwrap();
        let pae = b"DSSEv1 28 application/vnd.in-toto+json 2 {}";
        let sig = signer.sign_dsse(pae).unwrap();
        assert_eq!(sig.len(), 64, "compact ECDSA sig is 64 bytes");
        verify_p256(&signer.public_key_sec1(), pae, &sig).expect("roundtrip verify");
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let signer = P256Signer::new(TEST_SECRET).unwrap();
        let pae = b"DSSEv1 4 test 2 hi";
        let mut sig = signer.sign_dsse(pae).unwrap();
        // Flip a byte in `s` (offset 40 is mid-s).
        sig[40] ^= 0x01;
        assert!(verify_p256(&signer.public_key_sec1(), pae, &sig).is_err());
    }

    #[test]
    fn verify_rejects_wrong_pubkey() {
        let signer = P256Signer::new(TEST_SECRET).unwrap();
        let other = P256Signer::new([0x77; 32]).unwrap();
        let pae = b"DSSEv1 4 test 2 hi";
        let sig = signer.sign_dsse(pae).unwrap();
        assert!(verify_p256(&other.public_key_sec1(), pae, &sig).is_err());
    }

    #[test]
    fn keyid_has_p256_prefix() {
        let signer = P256Signer::new(TEST_SECRET).unwrap();
        let kid = signer.keyid();
        assert!(
            kid.starts_with(KEYID_PREFIX),
            "keyid {kid} lacks p256: prefix"
        );
        // p256: + 66 hex (33 bytes compressed)
        assert_eq!(kid.len(), KEYID_PREFIX.len() + 66);
        let hex = &kid[KEYID_PREFIX.len()..];
        assert!(
            hex.bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
            "keyid hex is lowercase-only"
        );
    }

    #[test]
    fn pubkey_round_trip_compressed_and_uncompressed() {
        let signer = P256Signer::new(TEST_SECRET).unwrap();
        let pae = b"DSSEv1 4 test 2 hi";
        let sig = signer.sign_dsse(pae).unwrap();

        let compressed = signer.public_key_sec1();
        assert_eq!(compressed.len(), 33, "SEC1 compressed is 33 bytes");
        assert!(
            compressed[0] == 0x02 || compressed[0] == 0x03,
            "compressed prefix is 0x02/0x03"
        );
        verify_p256(&compressed, pae, &sig).expect("verify with compressed pubkey");

        let uncompressed = signer.public_key_sec1_uncompressed();
        assert_eq!(uncompressed.len(), 65, "SEC1 uncompressed is 65 bytes");
        assert_eq!(uncompressed[0], 0x04, "uncompressed prefix is 0x04");
        verify_p256(&uncompressed, pae, &sig).expect("verify with uncompressed pubkey");
    }

    #[test]
    fn determinism_rfc6979() {
        let signer = P256Signer::new(TEST_SECRET).unwrap();
        let pae = b"the quick brown fox";
        let a = signer.sign_dsse(pae).unwrap();
        let b = signer.sign_dsse(pae).unwrap();
        assert_eq!(a, b, "RFC 6979: same key + same msg ⇒ same signature");
    }

    #[test]
    fn verify_rejects_high_s_signature() {
        // Craft a high-S form of an otherwise-valid signature and
        // confirm the verifier refuses it. We build the signature the
        // crate emits (already low-S), compute `s' = n - s` (which is
        // the matching high-S form of the same `(r, s)` pair), and
        // serialise `r || s'` manually — the `Signature` type's
        // constructors would otherwise try to keep us honest.
        //
        // P-256 group order `n` (RFC 5903 §3.1 / FIPS 186-4):
        //   FFFFFFFF 00000000 FFFFFFFF FFFFFFFF BCE6FAAD A7179E84
        //   F3B9CAC2 FC632551
        let n: [u8; 32] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2,
            0xFC, 0x63, 0x25, 0x51,
        ];

        let signer = P256Signer::new(TEST_SECRET).unwrap();
        let pae = b"low-s guard";
        let sig = signer.sign_dsse(pae).unwrap();

        // Sanity: our own signer always emits low-S.
        let s_bytes: [u8; 32] = sig[32..].try_into().unwrap();
        // low-S means s < n/2, i.e. first byte ≤ 0x7F.
        assert!(s_bytes[0] <= 0x7F, "signer emitted non-low-S");

        // Compute s' = n - s as a big-endian 256-bit subtract. The
        // widened arithmetic is done in u16 so the truncating cast
        // back to u8 is a documented, in-range narrowing.
        let mut s_prime = [0u8; 32];
        let mut borrow: u16 = 0;
        for i in (0..32).rev() {
            let lhs = u16::from(n[i]);
            let rhs = u16::from(s_bytes[i]) + borrow;
            if lhs >= rhs {
                s_prime[i] = u8::try_from(lhs - rhs).expect("difference fits in u8");
                borrow = 0;
            } else {
                s_prime[i] = u8::try_from((lhs + 256) - rhs).expect("difference fits in u8");
                borrow = 1;
            }
        }
        // High-S: first byte should now be > 0x7F.
        assert!(s_prime[0] > 0x7F, "s' should be high-S");

        let mut high = sig.clone();
        high[32..].copy_from_slice(&s_prime);

        let err = verify_p256(&signer.public_key_sec1(), pae, &high).unwrap_err();
        assert!(
            matches!(err, Error::P256SignatureInvalid),
            "got {err:?}, want P256SignatureInvalid"
        );

        // And the original low-S sig still verifies — guard against
        // accidentally breaking the happy path.
        verify_p256(&signer.public_key_sec1(), pae, &sig).unwrap();
    }

    #[test]
    fn pkcs8_round_trip() {
        // Build a PKCS#8 DER blob via the underlying SecretKey path —
        // the p256 0.13 ecdsa::SigningKey does not itself impl
        // EncodePrivateKey, but p256::SecretKey does.
        use p256::SecretKey;
        use p256::pkcs8::EncodePrivateKey;

        let sk = SecretKey::from_bytes(&TEST_SECRET.into()).unwrap();
        let der = sk.to_pkcs8_der().unwrap();
        let reloaded = P256Signer::from_der_pkcs8(der.as_bytes()).unwrap();

        let direct = P256Signer::new(TEST_SECRET).unwrap();
        assert_eq!(direct.public_key_sec1(), reloaded.public_key_sec1());
    }

    #[test]
    fn rejects_zero_scalar() {
        let err = P256Signer::new([0u8; 32]).unwrap_err();
        assert!(matches!(err, Error::P256KeyInvalid));
    }

    #[test]
    fn verify_rejects_malformed_pubkey() {
        let pae = b"hi";
        let sig = vec![0u8; 64];
        assert!(matches!(
            verify_p256(&[0xFF], pae, &sig),
            Err(Error::P256KeyInvalid)
        ));
    }

    #[test]
    fn verify_rejects_wrong_signature_length() {
        let signer = P256Signer::new(TEST_SECRET).unwrap();
        assert!(matches!(
            verify_p256(&signer.public_key_sec1(), b"hi", &[0u8; 63]),
            Err(Error::P256SignatureInvalid)
        ));
        assert!(matches!(
            verify_p256(&signer.public_key_sec1(), b"hi", &[0u8; 65]),
            Err(Error::P256SignatureInvalid)
        ));
    }
}
