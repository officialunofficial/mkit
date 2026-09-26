//! Owner-signature dispatch (SPEC-WRITE-GRANTS §4).
//!
//! The `ed25519` scheme is implemented here. The ECDSA schemes
//! (`secp256k1-eip191`, `webauthn-p256`) return
//! [`GrantError::SchemeNotImplemented`] until WP-2.5.

use ed25519_dalek::{Signature, VerifyingKey};
use mkit_core::repo_identity::Namespace;

use super::{GrantError, OwnerScheme, VerifierConfig};

/// Length of an `ed25519` blob: one signature.
const ED25519_BLOB_LEN: usize = 64;

/// §4 steps for one signed statement, in order: the scheme is advertised
/// (`SchemeNotAdvertised`); it is valid for the namespace form, `ed25519`
/// for `ed25519-` and the ECDSA schemes for `0x`
/// (`SchemeNamespaceMismatch`); and the signature verifies with the
/// namespace as the owner.
///
/// `ed25519`: the blob is exactly 64 bytes (`SignatureLength`), and the
/// signature verifies under the namespace's key over the 32-byte BLAKE3 of
/// `statement` with the strict predicate of SPEC-SIGNING §1
/// (`VerifyingKey::verify_strict`: canonical `s < L`, no small-order key or
/// `R`), else `BadSignature`. The key is the namespace itself, so the
/// derived owner always equals it (§7 step 4).
///
/// Success is only a signature check: callers still apply the audience,
/// window and scope rules of the statement they verified.
///
/// # Errors
/// As above; `SchemeNotImplemented` for the ECDSA schemes.
pub fn verify_owner_signature(
    cfg: &VerifierConfig,
    scheme: OwnerScheme,
    statement: &[u8],
    blob: &[u8],
    namespace: &Namespace,
) -> Result<(), GrantError> {
    if !cfg.schemes().contains(scheme) {
        return Err(GrantError::SchemeNotAdvertised);
    }
    match (scheme, namespace) {
        (OwnerScheme::Ed25519, Namespace::Ed25519(key)) => verify_ed25519(statement, blob, key),
        (OwnerScheme::Secp256k1Eip191 | OwnerScheme::WebAuthnP256, Namespace::Address(_)) => {
            Err(GrantError::SchemeNotImplemented)
        }
        _ => Err(GrantError::SchemeNamespaceMismatch),
    }
}

fn verify_ed25519(statement: &[u8], blob: &[u8], key: &[u8; 32]) -> Result<(), GrantError> {
    let signature: &[u8; ED25519_BLOB_LEN] =
        blob.try_into().map_err(|_| GrantError::SignatureLength)?;
    let key = VerifyingKey::from_bytes(key).map_err(|_| GrantError::BadSignature)?;
    let digest = mkit_core::hash::hash(statement);
    key.verify_strict(&digest, &Signature::from_bytes(signature))
        .map_err(|_| GrantError::BadSignature)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::super::AcceptedSchemes;
    use super::*;

    const STATEMENT: &[u8] = b"mkit-write-epoch:v1\nany bytes: the scheme signs what it is given";

    fn cfg(schemes: &[OwnerScheme]) -> VerifierConfig {
        VerifierConfig::new("https://git.example.com", AcceptedSchemes::of(schemes)).unwrap()
    }

    fn owner() -> (SigningKey, Namespace) {
        let key = SigningKey::from_bytes(&[9; 32]);
        let ns = Namespace::Ed25519(key.verifying_key().to_bytes());
        (key, ns)
    }

    fn sign(key: &SigningKey, statement: &[u8]) -> Vec<u8> {
        key.sign(&mkit_core::hash::hash(statement))
            .to_bytes()
            .to_vec()
    }

    #[test]
    fn ed25519_owner_signature_verifies() {
        let (key, ns) = owner();
        let cfg = cfg(&[OwnerScheme::Ed25519]);
        let sig = sign(&key, STATEMENT);
        assert_eq!(
            verify_owner_signature(&cfg, OwnerScheme::Ed25519, STATEMENT, &sig, &ns),
            Ok(())
        );
        // The signed message is BLAKE3(statement), not the statement.
        let raw = key.sign(STATEMENT).to_bytes();
        assert_eq!(
            verify_owner_signature(&cfg, OwnerScheme::Ed25519, STATEMENT, &raw, &ns),
            Err(GrantError::BadSignature)
        );
        // Another statement, another key.
        assert_eq!(
            verify_owner_signature(&cfg, OwnerScheme::Ed25519, b"other", &sig, &ns),
            Err(GrantError::BadSignature)
        );
        let other = SigningKey::from_bytes(&[10; 32]);
        assert_eq!(
            verify_owner_signature(
                &cfg,
                OwnerScheme::Ed25519,
                STATEMENT,
                &sign(&other, STATEMENT),
                &ns
            ),
            Err(GrantError::BadSignature)
        );
    }

    #[test]
    fn ed25519_owner_signature_rejects_blob_lengths() {
        let (key, ns) = owner();
        let cfg = cfg(&[OwnerScheme::Ed25519]);
        let sig = sign(&key, STATEMENT);
        for len in [0, 63, 65, 128] {
            let mut blob = sig.clone();
            blob.resize(len, 0);
            assert_eq!(
                verify_owner_signature(&cfg, OwnerScheme::Ed25519, STATEMENT, &blob, &ns),
                Err(GrantError::SignatureLength),
                "{len}"
            );
        }
    }

    #[test]
    fn ed25519_owner_signature_is_strict() {
        let (key, ns) = owner();
        let cfg = cfg(&[OwnerScheme::Ed25519]);
        let sig = sign(&key, STATEMENT);
        // s + L: the same signature with a non-canonical scalar.
        let l: [u8; 32] = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
        ];
        let mut high = sig.clone();
        let mut carry = 0u16;
        for i in 0..32 {
            let sum = u16::from(high[32 + i]) + u16::from(l[i]) + carry;
            high[32 + i] = sum.to_le_bytes()[0];
            carry = sum >> 8;
        }
        assert_eq!(carry, 0);
        assert_eq!(
            verify_owner_signature(&cfg, OwnerScheme::Ed25519, STATEMENT, &high, &ns),
            Err(GrantError::BadSignature)
        );
        // Small-order namespace keys: the identity, the order-2 point, and
        // the all-zero encoding (order 4). With R = identity and s = 0 the
        // cofactored equation holds for any message; the strict predicate
        // must still refuse it.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let mut order2 = [0xffu8; 32];
        order2[0] = 0xec;
        order2[31] = 0x7f;
        let mut forged = identity.to_vec();
        forged.extend([0; 32]);
        for weak in [identity, order2, [0; 32]] {
            assert_eq!(
                verify_owner_signature(
                    &cfg,
                    OwnerScheme::Ed25519,
                    STATEMENT,
                    &forged,
                    &Namespace::Ed25519(weak)
                ),
                Err(GrantError::BadSignature)
            );
        }
        // A namespace key that is not a curve point.
        let mut not_a_point = [0u8; 32];
        not_a_point[0] = 2;
        assert_eq!(
            verify_owner_signature(
                &cfg,
                OwnerScheme::Ed25519,
                STATEMENT,
                &sig,
                &Namespace::Ed25519(not_a_point)
            ),
            Err(GrantError::BadSignature)
        );
    }

    #[test]
    fn owner_scheme_must_be_advertised_and_match_the_namespace_form() {
        let (key, ns) = owner();
        let sig = sign(&key, STATEMENT);
        let addr = Namespace::Address([7; 20]);
        assert_eq!(
            verify_owner_signature(
                &cfg(&[OwnerScheme::Secp256k1Eip191]),
                OwnerScheme::Ed25519,
                STATEMENT,
                &sig,
                &ns
            ),
            Err(GrantError::SchemeNotAdvertised)
        );
        let all = cfg(&[OwnerScheme::Ed25519, OwnerScheme::Secp256k1Eip191]);
        assert_eq!(
            verify_owner_signature(&all, OwnerScheme::Ed25519, STATEMENT, &sig, &addr),
            Err(GrantError::SchemeNamespaceMismatch)
        );
        assert_eq!(
            verify_owner_signature(&all, OwnerScheme::Secp256k1Eip191, STATEMENT, &[0; 65], &ns),
            Err(GrantError::SchemeNamespaceMismatch)
        );
    }

    /// WP-2.5 replaces this test with the ECDSA implementations.
    #[test]
    fn ecdsa_owner_schemes_are_not_implemented_yet() {
        let all = cfg(&[OwnerScheme::Ed25519, OwnerScheme::Secp256k1Eip191]);
        assert_eq!(
            verify_owner_signature(
                &all,
                OwnerScheme::Secp256k1Eip191,
                STATEMENT,
                &[0; 65],
                &Namespace::Address([7; 20])
            ),
            Err(GrantError::SchemeNotImplemented)
        );
    }
}
