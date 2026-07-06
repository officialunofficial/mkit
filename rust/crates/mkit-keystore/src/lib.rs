#![cfg_attr(not(test), deny(clippy::print_stdout, clippy::print_stderr))]
#![doc = include_str!("../README.md")]
//!
//! Signing-key keystore abstraction for mkit.
//!
//! This crate owns keystore backends and signer handles. `mkit-core` remains
//! independent and continues to own canonical object signing bytes.

#![forbid(unsafe_code)]

mod backend;
#[cfg(all(target_os = "linux", feature = "linux-secret-service"))]
mod backend_linux_secret_service;
#[cfg(all(target_os = "macos", feature = "macos-keychain"))]
mod backend_macos_keychain;
#[cfg(all(target_os = "linux", feature = "systemd-creds"))]
mod backend_systemd_creds;
#[cfg(all(windows, feature = "windows-credential"))]
mod backend_windows_credential;
#[cfg(feature = "backend-yubikey")]
mod backend_yubikey;
mod encrypted_record;
mod error;
#[cfg(any(
    all(target_os = "linux", feature = "linux-secret-service"),
    all(target_os = "linux", feature = "systemd-creds"),
    all(target_os = "macos", feature = "macos-keychain"),
    all(windows, feature = "windows-credential")
))]
mod native_list;
mod software;
mod types;

pub use backend::open_backend;
#[cfg(all(target_os = "linux", feature = "linux-secret-service"))]
pub use backend_linux_secret_service::LinuxSecretServiceKeystore;
#[cfg(all(target_os = "macos", feature = "macos-keychain"))]
pub use backend_macos_keychain::MacosKeychainKeystore;
#[cfg(all(target_os = "linux", feature = "systemd-creds"))]
pub use backend_systemd_creds::SystemdCredsKeystore;
#[cfg(all(windows, feature = "windows-credential"))]
pub use backend_windows_credential::WindowsCredentialKeystore;
#[cfg(feature = "backend-yubikey")]
pub use backend_yubikey::YubiKeyKeystore;
pub use error::{Error, Result};
#[cfg(feature = "bls-threshold")]
pub use software::{BlsShareMetadata, LoadedBlsShare};
pub use software::{SoftwareKeystore, SoftwareRawKeystore, SoftwareSigner};
pub use types::{
    Algorithm, BackendKind, Capabilities, GenerateOptions, ImportOptions, KeyAttrs, KeyId,
    KeyLabel, KeyMetadata, KeyRef, KeyRefLabel, KeySelector, PublicKeyBytes, SecretKey,
    validate_label,
};

/// Decode a software key record for fuzzing harnesses.
///
/// This intentionally exposes only the parser success/failure boundary, not
/// the decoded record internals.
#[cfg(feature = "fuzzing")]
pub fn fuzz_decode_software_key_record(input: &[u8]) -> Result<()> {
    encrypted_record::EncryptedKeyRecord::decode(input).map(|_| ())
}

#[allow(dead_code)]
static KEYRING_DEFAULT_STORE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[allow(dead_code)]
pub(crate) fn keyring_default_store_lock() -> std::sync::MutexGuard<'static, ()> {
    KEYRING_DEFAULT_STORE_LOCK
        .lock()
        .expect("keyring default-store mutex poisoned")
}

/// Signing handle returned by a keystore backend.
pub trait KeySigner: Send {
    /// Signing algorithm.
    fn algorithm(&self) -> Algorithm;
    /// Backend-local label.
    fn label(&self) -> &KeyLabel;
    /// Public metadata for this key.
    fn metadata(&self) -> Result<KeyMetadata>;
    /// Encoded public key bytes.
    fn public_key(&self) -> Result<PublicKeyBytes>;
    /// Canonical key ID.
    fn keyid(&self) -> Result<KeyId>;
    /// Sign a raw message according to this key's algorithm semantics.
    ///
    /// # Returns
    ///
    /// Ed25519 signers return the 64-byte RFC 8032 signature over `msg`.
    /// ECDSA signers return a 64-byte IEEE-P1363 signature (`r || s`) with
    /// low-S normalization; secp256k1 signs SHA-256(`msg`) and P-256 uses the
    /// backend's P-256 signing semantics for `msg`.
    ///
    /// # Errors
    ///
    /// Returns an error if backend authentication, user presence, hardware I/O,
    /// or signature generation fails.
    fn sign(&mut self, msg: &[u8]) -> Result<Vec<u8>>;
}

/// Backend operation that can generate keys.
pub trait KeyGenerator: Send + Sync {
    /// Generate a new key.
    ///
    /// # Errors
    ///
    /// Returns an error if the backend cannot generate keys, cannot honor the
    /// requested attributes, the label is invalid, the key already exists and
    /// overwrite is disabled, or persistence fails.
    fn generate(
        &self,
        label: &KeyLabel,
        algorithm: Algorithm,
        attrs: KeyAttrs,
        options: GenerateOptions,
    ) -> Result<Box<dyn KeySigner>>;
}

/// Backend operation that can import extractable key material.
pub trait KeyImporter: Send + Sync {
    /// Import secret key material.
    ///
    /// # Errors
    ///
    /// Returns an error if the backend cannot import extractable material, the
    /// label or secret is invalid, requested attributes are unsupported, the key
    /// already exists and overwrite is disabled, or persistence fails.
    fn import(
        &self,
        label: &KeyLabel,
        secret: SecretKey,
        attrs: KeyAttrs,
        options: ImportOptions,
    ) -> Result<Box<dyn KeySigner>>;
}

/// Backend operation that can open keys for signing.
pub trait KeyOpener: Send + Sync {
    /// Open a key for signing.
    ///
    /// # Errors
    ///
    /// Returns an error if the selector is invalid, missing, ambiguous, or the
    /// backend cannot make the key available for signing.
    fn open(&self, selector: &KeySelector) -> Result<Box<dyn KeySigner>>;
}

/// Backend operation that can list keys.
pub trait KeyLister: Send + Sync {
    /// List keys visible to the backend.
    ///
    /// # Errors
    ///
    /// Returns an error if backend enumeration fails. Malformed entries owned by
    /// other applications may be skipped by backend-specific implementations.
    fn list(&self) -> Result<Vec<KeyMetadata>>;
}

/// Backend operation that can export secret key material.
pub trait KeyExporter: Send + Sync {
    /// Export secret key material.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotExtractable`] or [`Error::UnsupportedOperation`] for
    /// backends or keys that cannot export secret material. Also returns errors
    /// for invalid, missing, ambiguous, or unreadable selectors.
    fn export(&self, selector: &KeySelector) -> Result<SecretKey>;
}

/// Backend operation that can delete keys.
pub trait KeyDeleter: Send + Sync {
    /// Delete the selected key.
    ///
    /// # Errors
    ///
    /// Returns an error if deletion is unsupported, the selector is invalid,
    /// missing, ambiguous, or backend cleanup fails.
    fn delete(&self, selector: &KeySelector) -> Result<()>;
}

/// Keystore backend operation registry.
pub trait Keystore: Send + Sync {
    /// Backend capabilities.
    ///
    /// # Returns
    ///
    /// Capabilities for this backend instance. Operation booleans describe
    /// structural backend support and must match the corresponding operation
    /// accessor availability; operation calls still fail closed if the current
    /// session, daemon, hardware token, or protector is unavailable.
    fn capabilities(&self) -> Capabilities;

    /// Key-generation operation, if supported by this backend.
    fn generator(&self) -> Option<&dyn KeyGenerator> {
        None
    }

    /// Key-import operation, if supported by this backend.
    fn importer(&self) -> Option<&dyn KeyImporter> {
        None
    }

    /// Key-open operation, if supported by this backend.
    fn opener(&self) -> Option<&dyn KeyOpener> {
        None
    }

    /// Key-list operation, if supported by this backend.
    fn lister(&self) -> Option<&dyn KeyLister> {
        None
    }

    /// Key-export operation, if supported by this backend.
    fn exporter(&self) -> Option<&dyn KeyExporter> {
        None
    }

    /// Key-delete operation, if supported by this backend.
    fn deleter(&self) -> Option<&dyn KeyDeleter> {
        None
    }
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
        assert_eq!(key_ref.backend(), BackendKind::Software);
        assert_eq!(key_ref.label(), "default");
        assert_eq!(key_ref.to_string(), "software:default");
    }

    #[test]
    fn software_raw_key_ref_round_trips() {
        let key_ref: KeyRef = "software-raw:default".parse().expect("key ref parses");
        assert_eq!(key_ref.backend(), BackendKind::SoftwareRaw);
        assert_eq!(key_ref.label(), "default");
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
    fn label_validation_rejects_overlong_labels() {
        validate_label(&"a".repeat(255)).expect("255-byte label is valid");
        assert!(validate_label(&"a".repeat(256)).is_err());
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
}
