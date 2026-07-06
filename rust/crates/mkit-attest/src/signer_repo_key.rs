//! Repo-key signer — the default `Signer` impl.
//!
//! Wraps the same Ed25519 [`KeyPair`] that signs commits. The caller
//! loads the key from `.mkit/keys/default.key` (this module does no
//! I/O) and hands us the [`KeyPair`]. `sign` signs the DSSE PAE bytes
//! directly: no extra domain prefix, because the PAE's own `"DSSEv1 "`
//! prefix is the domain separator per SPEC-ATTESTATIONS §7.2 and §2.1.
//!
//! `keyid` convention (SPEC-ATTESTATIONS §6.3):
//! `"blake3:" || hex(BLAKE3(pubkey))` — 7-byte prefix + 64 hex chars =
//! 71 bytes total.

use ed25519_dalek::{Signer as _, SigningKey};
use zeroize::Zeroizing;

use crate::Error;
use crate::algorithm::Algorithm;
use crate::signer::Signer;
use mkit_core::sign::KeyPair;

/// Prefix prepended to the BLAKE3-of-pubkey hex to form the keyid.
///
/// The `blake3:` prefix is preserved for backward compatibility with
/// attestations produced before the multi-algorithm split. The verifier
/// recognises it and maps it to [`Algorithm::Ed25519`].
pub const KEYID_PREFIX: &str = "blake3:";

#[derive(Debug)]
pub struct RepoKeySigner {
    kp: KeyPair,
}

impl RepoKeySigner {
    #[must_use]
    pub fn new(kp: KeyPair) -> Self {
        Self { kp }
    }

    /// Build a `RepoKeySigner` directly from a [`Zeroizing`]-wrapped
    /// 32-byte seed. Avoids the intermediate `[u8; 32]` `Copy` on the
    /// caller's stack — every internal step works through references.
    ///
    /// # Zeroization
    ///
    /// The caller's `Zeroizing` wrapper still owns the seed bytes and
    /// scrubs them at end of scope. The returned signer owns its own
    /// copy inside [`KeyPair::secret`], which is itself zeroized on
    /// drop. No intermediate plain `[u8; 32]` is materialised.
    #[must_use]
    pub fn from_seed_zeroizing(seed: &Zeroizing<[u8; 32]>) -> Self {
        Self {
            kp: KeyPair::from_seed_zeroizing(seed),
        }
    }

    /// Return the `blake3:<hex>` keyid this signer reports.
    #[must_use]
    pub fn keyid_string(&self) -> String {
        let h = mkit_core::hash::hash(&self.kp.public.0);
        let hex = mkit_core::hash::to_hex(&h);
        format!("{KEYID_PREFIX}{hex}")
    }
}

impl Signer for RepoKeySigner {
    fn algorithm(&self) -> Algorithm {
        Algorithm::Ed25519
    }

    fn keyid(&self) -> Result<String, Error> {
        Ok(self.keyid_string())
    }

    fn sign(&mut self, pae: &[u8]) -> Result<Vec<u8>, Error> {
        // The "DSSEv1 " prefix inside the PAE is already the domain
        // separator; sign the PAE bytes directly.
        let signing = SigningKey::from_bytes(&self.kp.secret.0);
        let sig = signing.sign(pae);
        Ok(sig.to_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature as DalekSig, VerifyingKey};

    #[test]
    fn signature_verifies_with_dalek() {
        let kp = KeyPair::from_seed([0x42; 32]);
        let pk = kp.public.0;
        let mut s = RepoKeySigner::new(kp);

        let pae = b"DSSEv1 28 application/vnd.in-toto+json 2 {}";
        let sig_bytes = s.sign(pae).unwrap();
        assert_eq!(sig_bytes.len(), 64);

        let vk = VerifyingKey::from_bytes(&pk).unwrap();
        let sig = DalekSig::from_bytes(sig_bytes.as_slice().try_into().unwrap());
        // verify_strict: if our signer ever produces a non-canonical
        // signature (high-s, non-canonical R, etc.) this assertion fails
        // — a regression guard on the signer output.
        vk.verify_strict(pae, &sig).expect("verify");

        // Tampered PAE must break verification.
        let tampered = b"DSSEv1 28 application/vnd.in-toto+json 2 {X";
        assert!(vk.verify_strict(tampered, &sig).is_err());
    }

    /// DSSE signs the raw PAE bytes directly (this module's `sign`);
    /// commit/remix/tag sign `BLAKE3(domain || signing_bytes)` via
    /// `mkit_core::sign::KeyPair::sign`. The two schemes share no
    /// domain tag at the raw-Ed25519-verify layer, so a signature
    /// produced under one must never verify under the other, even with
    /// the same key and the same underlying bytes.
    #[test]
    fn dsse_signature_never_verifies_as_a_commit_signature_and_vice_versa() {
        use mkit_core::sign::{self, COMMIT_DOMAIN, Signature as CoreSignature};

        let kp = KeyPair::from_seed([0x77; 32]);
        let payload = b"shared bytes reused across both schemes";

        // A DSSE-style signature: raw Ed25519 over `payload` directly.
        let mut dsse_signer = RepoKeySigner::new(KeyPair::from_seed([0x77; 32]));
        let dsse_sig_bytes = dsse_signer.sign(payload).unwrap();
        let mut dsse_sig = [0u8; 64];
        dsse_sig.copy_from_slice(&dsse_sig_bytes);

        // It must not verify as a commit signature over the same bytes:
        // commit verification hashes `payload` through
        // `BLAKE3(COMMIT_DOMAIN || payload)` first, but the DSSE
        // signature was produced directly over `payload`, never over
        // that digest.
        assert!(
            sign::verify(&kp.public, COMMIT_DOMAIN, payload, &CoreSignature(dsse_sig)).is_err(),
            "a DSSE-domain signature must not verify as a commit signature"
        );

        // Converse: a commit-domain signature over `payload` must not
        // verify as a raw DSSE signature over those same `payload`
        // bytes — the commit signature was produced over the domain
        // digest, not over `payload` itself.
        let commit_sig = kp.sign(COMMIT_DOMAIN, payload);
        let vk = VerifyingKey::from_bytes(&kp.public.0).unwrap();
        let dalek_commit_sig = DalekSig::from_bytes(&commit_sig.0);
        assert!(
            vk.verify_strict(payload, &dalek_commit_sig).is_err(),
            "a commit-domain signature must not verify as a DSSE signature over the same bytes"
        );
    }

    #[test]
    fn keyid_shape_blake3_of_pubkey() {
        let kp = KeyPair::from_seed([0x11; 32]);
        let pk = kp.public.0;
        let s = RepoKeySigner::new(kp);
        let kid = s.keyid().unwrap();

        assert_eq!(kid.len(), 71);
        assert!(kid.starts_with(KEYID_PREFIX));

        let hex = &kid[KEYID_PREFIX.len()..];
        assert_eq!(hex.len(), 64);
        assert!(
            hex.bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        );

        let expected = mkit_core::hash::to_hex(&mkit_core::hash::hash(&pk));
        assert_eq!(hex, expected);
    }
}
