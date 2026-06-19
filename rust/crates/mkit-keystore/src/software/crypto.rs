//! Per-algorithm crypto dispatch for the in-process software signer.
//!
//! Validation, public-key derivation, and signing for the 32-byte
//! scalar algorithms (Ed25519, secp256k1, P-256). BLS12-381 threshold
//! shares are variable-length and do not flow through these paths; the
//! BLS arms return [`Error::UnsupportedAlgorithm`].

use ed25519_dalek::{Signer as _, SigningKey as Ed25519SigningKey};
use k256::ecdsa::{Signature as K256Signature, SigningKey as K256SigningKey};
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::{Algorithm, Error, Result};

pub(super) fn validate_secret(algorithm: Algorithm, secret: &[u8; 32]) -> Result<()> {
    match algorithm {
        Algorithm::Ed25519 => {
            let _ = Ed25519SigningKey::from_bytes(secret);
            Ok(())
        }
        Algorithm::Secp256k1 => K256SigningKey::from_bytes(secret.into())
            .map(|_| ())
            .map_err(|_| invalid_key_material(algorithm, "invalid secp256k1 scalar")),
        Algorithm::P256 => P256SigningKey::from_bytes(secret.into())
            .map(|_| ())
            .map_err(|_| invalid_key_material(algorithm, "invalid P-256 scalar")),
        // BLS12-381 threshold shares are variable-length wire-encoded
        // `Share` values (≈52 bytes), not 32-byte scalars. The
        // SecretKey path is closed to BLS; software-backend BLS storage
        // flows through `SoftwareKeystore::store_bls_share` instead.
        #[cfg(feature = "bls-threshold")]
        Algorithm::Bls12381Threshold => Err(Error::UnsupportedAlgorithm(algorithm)),
    }
}

pub(super) fn public_key(algorithm: Algorithm, secret: &[u8; 32]) -> Result<Vec<u8>> {
    match algorithm {
        Algorithm::Ed25519 => Ok(Ed25519SigningKey::from_bytes(secret)
            .verifying_key()
            .to_bytes()
            .to_vec()),
        Algorithm::Secp256k1 => Ok(K256SigningKey::from_bytes(secret.into())
            .map_err(|_| invalid_key_material(algorithm, "invalid secp256k1 scalar"))?
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec()),
        Algorithm::P256 => Ok(P256SigningKey::from_bytes(secret.into())
            .map_err(|_| invalid_key_material(algorithm, "invalid P-256 scalar"))?
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec()),
        // BLS shares carry their own group-public-key recovery; the
        // 32-byte SecretKey path can't represent them.
        #[cfg(feature = "bls-threshold")]
        Algorithm::Bls12381Threshold => Err(Error::UnsupportedAlgorithm(algorithm)),
    }
}

pub(super) fn sign_message(algorithm: Algorithm, secret: &[u8; 32], msg: &[u8]) -> Result<Vec<u8>> {
    match algorithm {
        Algorithm::Ed25519 => Ok(Ed25519SigningKey::from_bytes(secret)
            .sign(msg)
            .to_bytes()
            .to_vec()),
        Algorithm::Secp256k1 => {
            use k256::ecdsa::signature::DigestSigner as _;
            let key = K256SigningKey::from_bytes(secret.into())
                .map_err(|_| invalid_key_material(algorithm, "invalid secp256k1 scalar"))?;
            let mut hash = Sha256::new();
            hash.update(msg);
            let sig: K256Signature = key
                .try_sign_digest(hash)
                .map_err(|_| Error::Internal("secp256k1 signing failed".into()))?;
            let sig = sig.normalize_s().unwrap_or(sig);
            Ok(sig.to_bytes().to_vec())
        }
        Algorithm::P256 => {
            use p256::ecdsa::signature::Signer as _;
            let key = P256SigningKey::from_bytes(secret.into())
                .map_err(|_| invalid_key_material(algorithm, "invalid P-256 scalar"))?;
            let sig: P256Signature = key.sign(msg);
            let sig = sig.normalize_s().unwrap_or(sig);
            Ok(sig.to_bytes().to_vec())
        }
        // BLS shares use `mkit_attest::signer_bls_threshold::ThresholdSigner`
        // which lives in the attest crate; the SoftwareSigner path is
        // closed to BLS.
        #[cfg(feature = "bls-threshold")]
        Algorithm::Bls12381Threshold => Err(Error::UnsupportedAlgorithm(algorithm)),
    }
}

pub(super) fn random_valid_secret(algorithm: Algorithm) -> Result<[u8; 32]> {
    let mut secret = [0u8; 32];
    for _ in 0..8 {
        getrandom::fill(&mut secret).map_err(|_| Error::Internal("rng failed".into()))?;
        if validate_secret(algorithm, &secret).is_ok() {
            return Ok(secret);
        }
    }
    secret.zeroize();
    Err(Error::Internal(
        "rng failed to produce a valid scalar".into(),
    ))
}

fn invalid_key_material(algorithm: Algorithm, reason: &str) -> Error {
    Error::InvalidKeyMaterial {
        algorithm,
        reason: reason.into(),
    }
}
