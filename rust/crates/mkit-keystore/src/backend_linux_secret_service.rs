//! Linux Secret Service-backed keystore.

use std::collections::HashMap;

use zeroize::{Zeroize, Zeroizing};

use crate::{
    Algorithm, BackendKind, Capabilities, Error, GenerateOptions, ImportOptions, KeyAttrs,
    KeyDeleter, KeyExporter, KeyGenerator, KeyImporter, KeyLabel, KeyLister, KeyMetadata,
    KeyOpener, KeySelector, KeySigner, Keystore, Result, SecretKey, SoftwareSigner, validate_label,
};

const SERVICE: &str = "dev.mkit.keystore.signing-key.v1";

/// User-scoped Freedesktop Secret Service backend.
#[derive(Clone, Debug, Default)]
pub struct LinuxSecretServiceKeystore;

impl LinuxSecretServiceKeystore {
    /// Create a Linux Secret Service backend instance.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    fn account(label: &KeyLabel, algorithm: Algorithm) -> String {
        format!("{}:{}", algorithm.as_str(), label.as_str())
    }

    fn entry(label: &KeyLabel, algorithm: Algorithm) -> Result<keyring_core::Entry> {
        let store = zbus_secret_service_keyring_store::Store::new()
            .map_err(|error| keyring_backend_error("create Secret Service store", error))?;
        let _guard = crate::keyring_default_store_lock();
        keyring_core::set_default_store(store);
        keyring_core::Entry::new(SERVICE, &Self::account(label, algorithm))
            .map_err(|error| map_keyring_error(error, label, algorithm))
    }

    fn get_secret(label: &KeyLabel, algorithm: Algorithm) -> Result<SecretKey> {
        let secret = Zeroizing::new(
            Self::entry(label, algorithm)?
                .get_secret()
                .map_err(|error| map_keyring_error(error, label, algorithm))?,
        );
        if secret.len() != 32 {
            return Err(Error::InvalidKeyMaterial {
                algorithm,
                reason: format!("expected 32 bytes, got {}", secret.len()),
            });
        }
        let mut secret_bytes = Zeroizing::new([0u8; 32]);
        secret_bytes.copy_from_slice(secret.as_slice());
        Ok(SecretKey::from_zeroizing(algorithm, secret_bytes))
    }
}

impl Keystore for LinuxSecretServiceKeystore {
    fn capabilities(&self) -> Capabilities {
        linux_secret_service_capabilities()
    }

    fn generator(&self) -> Option<&dyn KeyGenerator> {
        Some(self)
    }

    fn importer(&self) -> Option<&dyn KeyImporter> {
        Some(self)
    }

    fn opener(&self) -> Option<&dyn KeyOpener> {
        Some(self)
    }

    fn lister(&self) -> Option<&dyn KeyLister> {
        Some(self)
    }

    fn exporter(&self) -> Option<&dyn KeyExporter> {
        Some(self)
    }

    fn deleter(&self) -> Option<&dyn KeyDeleter> {
        Some(self)
    }
}

impl KeyGenerator for LinuxSecretServiceKeystore {
    fn generate(
        &self,
        label: &KeyLabel,
        algorithm: Algorithm,
        attrs: KeyAttrs,
        options: GenerateOptions,
    ) -> Result<Box<dyn KeySigner>> {
        crate::native_list::validate_attrs("Linux Secret Service", &attrs)?;
        let mut secret =
            crate::native_list::random_valid_secret(BackendKind::LinuxSecretService, algorithm)?;
        let wrapped = SecretKey::new(algorithm, secret);
        secret.zeroize();
        self.import(
            label,
            wrapped,
            attrs,
            ImportOptions {
                overwrite: options.overwrite,
            },
        )
    }
}

impl KeyImporter for LinuxSecretServiceKeystore {
    fn import(
        &self,
        label: &KeyLabel,
        secret: SecretKey,
        attrs: KeyAttrs,
        options: ImportOptions,
    ) -> Result<Box<dyn KeySigner>> {
        crate::native_list::validate_attrs("Linux Secret Service", &attrs)?;
        let signer = SoftwareSigner::new(
            label.clone(),
            BackendKind::LinuxSecretService,
            secret.algorithm(),
            *secret.expose_secret(),
        )?;
        let entry = Self::entry(label, secret.algorithm())?;
        let exists = match entry.get_secret() {
            Ok(secret) => {
                let _secret = Zeroizing::new(secret);
                true
            }
            Err(keyring_core::Error::NoEntry) => false,
            Err(error) => return Err(map_keyring_error(error, label, secret.algorithm())),
        };
        if exists && !options.overwrite {
            return Err(Error::KeyAlreadyExists {
                label: label.clone(),
                algorithm: secret.algorithm(),
            });
        }
        entry
            .set_secret(secret.expose_secret())
            .map_err(|error| map_keyring_error(error, label, secret.algorithm()))?;
        Ok(Box::new(signer))
    }
}

impl KeyOpener for LinuxSecretServiceKeystore {
    fn open(&self, selector: &KeySelector) -> Result<Box<dyn KeySigner>> {
        validate_label(selector.label())?;
        let algorithm = crate::native_list::resolve_selector_algorithm(selector, Self::get_secret)?;
        let secret = Self::get_secret(selector.label_id(), algorithm)?;
        Ok(Box::new(SoftwareSigner::new(
            selector.label_id().clone(),
            BackendKind::LinuxSecretService,
            algorithm,
            *secret.expose_secret(),
        )?))
    }
}

impl KeyLister for LinuxSecretServiceKeystore {
    fn list(&self) -> Result<Vec<KeyMetadata>> {
        let store = zbus_secret_service_keyring_store::Store::new()
            .map_err(|error| keyring_backend_error("create Secret Service store", error))?;
        let _guard = crate::keyring_default_store_lock();
        keyring_core::set_default_store(store);
        let spec = HashMap::from([("service", SERVICE)]);
        let entries = keyring_core::Entry::search(&spec).map_err(keyring_list_error)?;

        let mut out = Vec::new();
        for entry in entries {
            let Some((service, account)) = entry.get_specifiers() else {
                continue;
            };
            if service != SERVICE {
                continue;
            }
            let secret = match entry.get_secret() {
                Ok(secret) => secret,
                Err(keyring_core::Error::NoEntry) => continue,
                Err(error) => {
                    return Err(map_keyring_error(
                        error,
                        &KeyLabel::new("list")?,
                        Algorithm::Ed25519,
                    ));
                }
            };
            if let Some(metadata) = crate::native_list::list_metadata_from_account_secret(
                &account,
                BackendKind::LinuxSecretService,
                secret,
            )? {
                out.push(metadata);
            }
        }
        crate::native_list::sort_metadata(&mut out);
        Ok(out)
    }
}

impl KeyExporter for LinuxSecretServiceKeystore {
    fn export(&self, selector: &KeySelector) -> Result<SecretKey> {
        validate_label(selector.label())?;
        let algorithm = crate::native_list::resolve_selector_algorithm(selector, Self::get_secret)?;
        Self::get_secret(selector.label_id(), algorithm)
    }
}

impl KeyDeleter for LinuxSecretServiceKeystore {
    fn delete(&self, selector: &KeySelector) -> Result<()> {
        validate_label(selector.label())?;
        let algorithm = crate::native_list::resolve_selector_algorithm(selector, Self::get_secret)?;
        Self::entry(selector.label_id(), algorithm)?
            .delete_credential()
            .map_err(|error| map_keyring_error(error, selector.label_id(), algorithm))
    }
}

fn linux_secret_service_capabilities() -> Capabilities {
    Capabilities {
        backend: BackendKind::LinuxSecretService,
        algorithms: vec![Algorithm::Ed25519, Algorithm::Secp256k1, Algorithm::P256],
        can_generate: true,
        can_import: true,
        can_export: true,
        can_delete: true,
        supports_listing: true,
        supports_user_presence: false,
        supports_device_bound: false,
        supports_non_extractable: false,
    }
}

fn map_keyring_error(error: keyring_core::Error, label: &KeyLabel, algorithm: Algorithm) -> Error {
    match error {
        keyring_core::Error::NoEntry => Error::KeyNotFound(KeySelector {
            label: label.clone(),
            algorithm: Some(algorithm),
        }),
        keyring_core::Error::NoStorageAccess(error) => Error::AccessDenied(error.to_string()),
        keyring_core::Error::NotSupportedByStore(error) => Error::BackendUnavailable(format!(
            "Linux Secret Service operation unsupported: {error}"
        )),
        other => Error::Io(format!("Linux Secret Service: {other}")),
    }
}

fn keyring_backend_error(operation: &str, error: keyring_core::Error) -> Error {
    match error {
        keyring_core::Error::NoStorageAccess(error) => Error::AccessDenied(error.to_string()),
        keyring_core::Error::NotSupportedByStore(error) => {
            Error::BackendUnavailable(format!("Linux Secret Service {operation}: {error}"))
        }
        other => Error::BackendUnavailable(format!("Linux Secret Service {operation}: {other}")),
    }
}

fn keyring_list_error(error: keyring_core::Error) -> Error {
    match error {
        keyring_core::Error::NoEntry => Error::KeyNotFound(KeySelector {
            label: static_label("list"),
            algorithm: None,
        }),
        keyring_core::Error::NoStorageAccess(error) => Error::AccessDenied(error.to_string()),
        keyring_core::Error::NotSupportedByStore(error) => {
            Error::BackendUnavailable(format!("Linux Secret Service listing unsupported: {error}"))
        }
        other => Error::Io(format!("Linux Secret Service listing: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capabilities_are_backend_accurate() {
        let capabilities = linux_secret_service_capabilities();
        assert_eq!(capabilities.backend, BackendKind::LinuxSecretService);
        assert_eq!(
            capabilities.algorithms,
            vec![Algorithm::Ed25519, Algorithm::Secp256k1, Algorithm::P256]
        );
        assert!(capabilities.can_generate);
        assert!(capabilities.can_import);
        assert!(capabilities.can_export);
        assert!(capabilities.can_delete);
        assert!(capabilities.supports_listing);
        assert!(!capabilities.supports_user_presence);
        assert!(!capabilities.supports_device_bound);
        assert!(!capabilities.supports_non_extractable);
    }

    #[test]
    fn capabilities_report_structural_support_when_runtime_unavailable() {
        let capabilities = linux_secret_service_capabilities();
        let store = LinuxSecretServiceKeystore::new();
        assert_eq!(capabilities.backend, BackendKind::LinuxSecretService);
        assert_eq!(
            capabilities.algorithms,
            vec![Algorithm::Ed25519, Algorithm::Secp256k1, Algorithm::P256]
        );
        assert!(capabilities.can_generate);
        assert!(capabilities.can_import);
        assert!(capabilities.can_export);
        assert!(capabilities.can_delete);
        assert!(capabilities.supports_listing);
        assert!(!capabilities.supports_user_presence);
        assert!(!capabilities.supports_device_bound);
        assert!(!capabilities.supports_non_extractable);
        assert_eq!(capabilities.can_generate, store.generator().is_some());
        assert_eq!(capabilities.can_import, store.importer().is_some());
        assert_eq!(capabilities.can_export, store.exporter().is_some());
        assert_eq!(capabilities.can_delete, store.deleter().is_some());
        assert_eq!(capabilities.supports_listing, store.lister().is_some());
    }

    #[test]
    fn invalid_ecdsa_import_rejected_before_secret_service_write() {
        let store = LinuxSecretServiceKeystore::new();
        let result = store.import(
            &KeyLabel::new("invalid").unwrap(),
            SecretKey::new(Algorithm::P256, [0; 32]),
            KeyAttrs::default(),
            ImportOptions::default(),
        );

        assert!(matches!(result, Err(Error::InvalidKeyMaterial { .. })));
    }

    #[test]
    #[ignore = "set MKIT_RUN_NATIVE_KEYSTORE_TESTS=1 to exercise Linux Secret Service"]
    fn live_backend_create_open_list_export_delete_roundtrip() {
        crate::native_list::run_required_native_backend_roundtrip_test(
            &LinuxSecretServiceKeystore::new(),
        );
    }
}
