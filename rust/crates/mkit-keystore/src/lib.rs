//! Signing-key keystore abstraction for mkit.
//!
//! This crate owns keystore backends and signer handles. `mkit-core` remains
//! independent and continues to own canonical object signing bytes.

#![forbid(unsafe_code)]

mod backend;
mod encrypted_record;
mod error;
mod software;
mod types;

pub use backend::open_backend;
pub use error::{Error, Result};
pub use software::{SoftwareKeystore, SoftwareSigner};
pub use types::{
    Algorithm, BackendKind, Capabilities, GenerateOptions, ImportOptions, KeyAttrs, KeyMetadata,
    KeyRef, KeySelector, SecretKey, validate_label,
};

/// Signing handle returned by a keystore backend.
pub trait KeySigner: Send {
    /// Signing algorithm.
    fn algorithm(&self) -> Algorithm;
    /// Backend-local label.
    fn label(&self) -> &str;
    /// Public metadata for this key.
    fn metadata(&self) -> Result<KeyMetadata>;
    /// Encoded public key bytes.
    fn public_key(&self) -> Result<Vec<u8>>;
    /// Canonical key ID.
    fn keyid(&self) -> Result<String>;
    /// Sign bytes according to this key's algorithm semantics.
    fn sign(&mut self, msg: &[u8]) -> Result<Vec<u8>>;
}

/// Keystore backend interface.
pub trait Keystore: Send + Sync {
    /// Runtime backend capabilities.
    fn capabilities(&self) -> Capabilities;

    /// Generate a new key.
    fn generate(
        &self,
        label: &str,
        algorithm: Algorithm,
        attrs: KeyAttrs,
        options: GenerateOptions,
    ) -> Result<Box<dyn KeySigner>>;

    /// Import secret key material.
    fn import(
        &self,
        label: &str,
        secret: SecretKey,
        attrs: KeyAttrs,
        options: ImportOptions,
    ) -> Result<Box<dyn KeySigner>>;

    /// Open a key for signing.
    fn open(&self, selector: &KeySelector) -> Result<Box<dyn KeySigner>>;
    /// List keys visible to the backend.
    fn list(&self) -> Result<Vec<KeyMetadata>>;
    /// Export secret key material.
    fn export(&self, selector: &KeySelector) -> Result<SecretKey>;
    /// Delete the selected key.
    fn delete(&self, selector: &KeySelector) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn algorithms_parse_and_display_canonical_strings() {
        for algorithm in [Algorithm::Ed25519, Algorithm::Secp256k1, Algorithm::P256] {
            let parsed: Algorithm = algorithm.as_str().parse().expect("algorithm parses");
            assert_eq!(parsed, algorithm);
            assert_eq!(algorithm.to_string(), algorithm.as_str());
        }
    }

    #[test]
    fn key_ref_round_trips() {
        let key_ref: KeyRef = "software:default".parse().expect("key ref parses");
        assert_eq!(key_ref.backend, BackendKind::Software);
        assert_eq!(key_ref.label, "default");
        assert_eq!(key_ref.to_string(), "software:default");
    }

    #[test]
    fn software_raw_key_ref_round_trips() {
        let key_ref: KeyRef = "software-raw:default".parse().expect("key ref parses");
        assert_eq!(key_ref.backend, BackendKind::SoftwareRaw);
        assert_eq!(key_ref.label, "default");
        assert_eq!(key_ref.to_string(), "software-raw:default");
    }

    #[test]
    fn label_validation_accepts_simple_backend_local_names() {
        for label in ["default", "release-2026", "team_a", "key.1"] {
            validate_label(label).expect("label should be valid");
            KeySelector::new(label, Some(Algorithm::Ed25519)).expect("selector should be valid");
        }
    }

    #[test]
    fn label_validation_rejects_unsafe_labels() {
        for label in [
            "", " default", "default ", "a:b", "a/b", "a\\b", "a\n", "a\0",
        ] {
            assert!(
                validate_label(label).is_err(),
                "label should fail: {label:?}"
            );
        }
    }

    #[test]
    fn key_ref_rejects_non_ref_syntax() {
        for key_ref in [
            "software/default",
            "software:",
            "software:a/b",
            "software:$HOME",
            "software:~default",
            "software:key*",
            "software:key|cmd",
            "https://example.com/key",
        ] {
            assert!(
                key_ref.parse::<KeyRef>().is_err(),
                "ref should fail: {key_ref:?}"
            );
        }
    }

    #[test]
    fn secret_key_debug_is_redacted() {
        let secret = SecretKey::new(Algorithm::Ed25519, [7; 32]);
        let debug = format!("{secret:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("7, 7"));
    }

    #[test]
    fn secret_key_accessors_are_explicit() {
        let secret = SecretKey::new(Algorithm::Secp256k1, [11; 32]);
        assert_eq!(secret.algorithm(), Algorithm::Secp256k1);
        assert_eq!(secret.expose_secret(), &[11; 32]);

        let bytes = secret.into_bytes();
        assert_eq!(&*bytes, &[11; 32]);
    }
}
