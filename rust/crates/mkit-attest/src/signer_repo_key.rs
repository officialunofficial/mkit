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
        let mut s = RepoKeySigner::new(kp.clone());

        let pae = b"DSSEv1 28 application/vnd.in-toto+json 2 {}";
        let sig_bytes = s.sign(pae).unwrap();
        assert_eq!(sig_bytes.len(), 64);

        let vk = VerifyingKey::from_bytes(&kp.public.0).unwrap();
        let sig = DalekSig::from_bytes(sig_bytes.as_slice().try_into().unwrap());
        // verify_strict: if our signer ever produces a non-canonical
        // signature (high-s, non-canonical R, etc.) this assertion fails
        // — a regression guard on the signer output.
        vk.verify_strict(pae, &sig).expect("verify");

        // Tampered PAE must break verification.
        let tampered = b"DSSEv1 28 application/vnd.in-toto+json 2 {X";
        assert!(vk.verify_strict(tampered, &sig).is_err());
    }

    #[test]
    fn keyid_shape_blake3_of_pubkey() {
        let kp = KeyPair::from_seed([0x11; 32]);
        let s = RepoKeySigner::new(kp.clone());
        let kid = s.keyid().unwrap();

        assert_eq!(kid.len(), 71);
        assert!(kid.starts_with(KEYID_PREFIX));

        let hex = &kid[KEYID_PREFIX.len()..];
        assert_eq!(hex.len(), 64);
        assert!(
            hex.bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        );

        let expected = mkit_core::hash::to_hex(&mkit_core::hash::hash(&kp.public.0));
        assert_eq!(hex, expected);
    }

    #[test]
    fn keyid_is_deterministic() {
        let kp = KeyPair::from_seed([0x7F; 32]);
        let s = RepoKeySigner::new(kp);
        let a = s.keyid().unwrap();
        let b = s.keyid().unwrap();
        assert_eq!(a, b);
    }
}
