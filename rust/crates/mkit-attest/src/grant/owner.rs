//! Owner-signature dispatch (SPEC-WRITE-GRANTS §4): `ed25519`,
//! `secp256k1-eip191` and `webauthn-p256` (the last in [`super::webauthn`]).

use ed25519_dalek::{Signature, VerifyingKey};
use mkit_core::repo_identity::Namespace;

use super::webauthn::{WebAuthnBinding, verify_webauthn};
use super::{GrantError, OwnerScheme, VerifierConfig};
use crate::eth::{self, Address, EthError};

/// Length of an `ed25519` blob: one signature.
const ED25519_BLOB_LEN: usize = 64;
/// Length of a `secp256k1-eip191` blob: `r ‖ s ‖ v`.
const EIP191_BLOB_LEN: usize = 65;

/// §4 steps for one signed statement, in order: the scheme is advertised
/// (`SchemeNotAdvertised`); it is valid for the namespace form, `ed25519`
/// for `ed25519-` and the ECDSA schemes for `0x`
/// (`SchemeNamespaceMismatch`); and the signature verifies with the
/// namespace as the owner.
///
/// * `ed25519`: the blob is exactly 64 bytes (`SignatureLength`), and the
///   signature verifies under the namespace's key over the 32-byte BLAKE3
///   of `statement` with the strict predicate of SPEC-SIGNING §1
///   (`VerifyingKey::verify_strict`: canonical `s < L`, no small-order key
///   or `R`), else `BadSignature`. The key is the namespace itself, so the
///   derived owner always equals it (§7 step 4).
/// * `secp256k1-eip191`: the blob is exactly 65 bytes `r ‖ s ‖ v`
///   (`SignatureLength`); `v` is 27 or 28 (`SignatureRecoveryId`); `r` and
///   `s` are in `[1, n − 1]` (`SignatureScalar`) and `s <= n / 2` (`HighS`,
///   never normalized, §4.4); a key recovers from the EIP-191 digest of
///   `statement` (`BadSignature`); and its §4.1 address is exactly the
///   namespace (`OwnerMismatch`). Recovery alone authorizes nothing: every
///   well-formed signature recovers *some* key.
/// * `webauthn-p256`, in this order: the blob is four length-prefixed
///   fields with a 64-byte key and a 64-byte signature and nothing after
///   (`WebAuthnBlob`); `r`, `s` in `[1, n − 1]` (`SignatureScalar`) and
///   `s <= n / 2` (`HighS`); the key is a P-256 point (`InvalidOwnerKey`)
///   whose §4.1 address is exactly the namespace (`OwnerMismatch`);
///   `authenticatorData` has at least 37 bytes (`AuthenticatorData`) and
///   the UP flag (`UserNotPresent`; UV and the counter are not checked);
///   its rpIdHash is a configured relying party's (`RelyingPartyMismatch`);
///   `clientDataJSON` is a JSON object with no duplicate member name at any
///   depth (`ClientData`), `type` is `webauthn.get` (`ClientDataType`),
///   `challenge` is [`super::webauthn_challenge`] of `statement`
///   (`Challenge`), `crossOrigin` is absent or `false` (`CrossOrigin`),
///   there is no `topOrigin` (`TopOrigin`), and `origin` is configured for
///   that relying party (`OriginNotAllowed`); and the signature verifies
///   over `authenticatorData ‖ SHA-256(clientDataJSON)` exactly as received
///   (`BadSignature`).
///
/// Success is only a signature check: callers still apply the audience,
/// window and scope rules of the statement they verified.
///
/// # Errors
/// As above.
pub fn verify_owner_signature(
    cfg: &VerifierConfig,
    scheme: OwnerScheme,
    statement: &[u8],
    blob: &[u8],
    namespace: &Namespace,
) -> Result<(), GrantError> {
    verify_owner(cfg, scheme, statement, blob, namespace).map(|_| ())
}

/// [`verify_owner_signature`], returning the relying party and origin a
/// `webauthn-p256` signature was bound to.
pub(crate) fn verify_owner(
    cfg: &VerifierConfig,
    scheme: OwnerScheme,
    statement: &[u8],
    blob: &[u8],
    namespace: &Namespace,
) -> Result<Option<WebAuthnBinding>, GrantError> {
    if !cfg.schemes().contains(scheme) {
        return Err(GrantError::SchemeNotAdvertised);
    }
    match (scheme, namespace) {
        (OwnerScheme::Ed25519, Namespace::Ed25519(key)) => {
            verify_ed25519(statement, blob, key).map(|()| None)
        }
        (OwnerScheme::Secp256k1Eip191, Namespace::Address(address)) => {
            verify_eip191(statement, blob, address).map(|()| None)
        }
        (OwnerScheme::WebAuthnP256, Namespace::Address(address)) => {
            verify_webauthn(cfg.relying_parties(), statement, blob, address).map(Some)
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

fn verify_eip191(statement: &[u8], blob: &[u8], namespace: &Address) -> Result<(), GrantError> {
    let signature: &[u8; EIP191_BLOB_LEN] =
        blob.try_into().map_err(|_| GrantError::SignatureLength)?;
    let address = eth::eip191_recover_address(statement, signature).map_err(|e| match e {
        EthError::RecoveryIdInvalid => GrantError::SignatureRecoveryId,
        EthError::ScalarOutOfRange => GrantError::SignatureScalar,
        EthError::HighS => GrantError::HighS,
        _ => GrantError::BadSignature,
    })?;
    if address != *namespace {
        return Err(GrantError::OwnerMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::super::AcceptedSchemes;
    use super::*;

    const STATEMENT: &[u8] = b"mkit-write-epoch:v1\nany bytes: the scheme signs what it is given";

    fn cfg(schemes: &[OwnerScheme]) -> VerifierConfig {
        VerifierConfig::new(
            "https://git.example.com",
            AcceptedSchemes::of(schemes),
            vec![],
        )
        .unwrap()
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

    fn eip191_sign(key: &k256::ecdsa::SigningKey, statement: &[u8]) -> [u8; 65] {
        let (sig, recid) = key.sign_prehash_recoverable(&eth::eip191_hash(statement));
        let mut out = [0u8; 65];
        out[..64].copy_from_slice(&sig.to_bytes());
        out[64] = 27 + recid.to_byte();
        out
    }

    fn eip191_owner(seed: u8) -> (k256::ecdsa::SigningKey, Namespace) {
        let key = k256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap();
        let point = key.verifying_key().to_sec1_point(false);
        let xy: [u8; 64] = point.as_bytes()[1..].try_into().unwrap();
        (
            key,
            Namespace::Address(eth::address_secp256k1(&xy).unwrap()),
        )
    }

    #[test]
    fn secp256k1_eip191_owner_signature_verifies() {
        let (key, ns) = eip191_owner(0x11);
        let cfg = cfg(&[OwnerScheme::Secp256k1Eip191]);
        let sig = eip191_sign(&key, STATEMENT);
        assert_eq!(
            verify_owner_signature(&cfg, OwnerScheme::Secp256k1Eip191, STATEMENT, &sig, &ns),
            Ok(())
        );
        // Recovery succeeds for another statement or key, but the address
        // is not the namespace: that is the authorization check.
        assert_eq!(
            verify_owner_signature(&cfg, OwnerScheme::Secp256k1Eip191, b"other", &sig, &ns),
            Err(GrantError::OwnerMismatch)
        );
        let (other, _) = eip191_owner(0x12);
        assert_eq!(
            verify_owner_signature(
                &cfg,
                OwnerScheme::Secp256k1Eip191,
                STATEMENT,
                &eip191_sign(&other, STATEMENT),
                &ns
            ),
            Err(GrantError::OwnerMismatch)
        );
        // Flipping v recovers the other candidate key.
        let mut flipped = sig;
        flipped[64] = if sig[64] == 27 { 28 } else { 27 };
        assert_eq!(
            verify_owner_signature(&cfg, OwnerScheme::Secp256k1Eip191, STATEMENT, &flipped, &ns),
            Err(GrantError::OwnerMismatch)
        );
    }

    #[test]
    fn secp256k1_eip191_owner_signature_rejects() {
        let (key, ns) = eip191_owner(0x11);
        let cfg = cfg(&[OwnerScheme::Secp256k1Eip191, OwnerScheme::Ed25519]);
        let sig = eip191_sign(&key, STATEMENT);
        let run = |blob: &[u8]| {
            verify_owner_signature(&cfg, OwnerScheme::Secp256k1Eip191, STATEMENT, blob, &ns)
        };
        assert_eq!(run(&sig[..64]), Err(GrantError::SignatureLength));
        assert_eq!(
            run(&[&sig[..], &[0]].concat()),
            Err(GrantError::SignatureLength)
        );
        for v in [0u8, 1, 26, 29, 255] {
            let mut bad = sig;
            bad[64] = v;
            assert_eq!(run(&bad), Err(GrantError::SignatureRecoveryId), "v = {v}");
        }
        let mut zero_r = sig;
        zero_r[..32].fill(0);
        assert_eq!(run(&zero_r), Err(GrantError::SignatureScalar));
        let high = eth::normalize_eip191_signature(sig).unwrap();
        assert_eq!(high, sig);
        // The high-`s` twin: `n - s`, `v` flipped.
        let n = hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
            .unwrap();
        let mut twin = sig;
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let d = i16::from(n[i]) - i16::from(sig[32 + i]) - borrow;
            borrow = i16::from(d < 0);
            twin[32 + i] = (d + 256 * borrow).to_le_bytes()[0];
        }
        twin[64] = if sig[64] == 27 { 28 } else { 27 };
        assert_eq!(run(&twin), Err(GrantError::HighS));
        assert_eq!(eth::normalize_eip191_signature(twin), Ok(sig));
        // The ECDSA schemes need a `0x` namespace.
        let (_, ed_ns) = owner();
        assert_eq!(
            verify_owner_signature(&cfg, OwnerScheme::Secp256k1Eip191, STATEMENT, &sig, &ed_ns),
            Err(GrantError::SchemeNamespaceMismatch)
        );
    }
}
