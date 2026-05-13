//! Linux Secret Service-backed keystore.

use std::collections::HashMap;

use zeroize::{Zeroize, Zeroizing};

use crate::{
    Algorithm, BackendKind, Capabilities, Error, GenerateOptions, ImportOptions, KeyAttrs,
    KeyMetadata, KeySelector, KeySigner, Keystore, Result, SecretKey, SoftwareSigner,
    validate_label,
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

    fn account(label: &str, algorithm: Algorithm) -> Result<String> {
        validate_label(label)?;
        Ok(format!("{}:{label}", algorithm.as_str()))
    }

    fn entry(label: &str, algorithm: Algorithm) -> Result<keyring_core::Entry> {
        let store = zbus_secret_service_keyring_store::Store::new()
            .map_err(|error| keyring_backend_error("create Secret Service store", error))?;
        keyring_core::set_default_store(store);
        keyring_core::Entry::new(SERVICE, &Self::account(label, algorithm)?)
            .map_err(|error| map_keyring_error(error, label, algorithm))
    }

    fn get_secret(label: &str, algorithm: Algorithm) -> Result<SecretKey> {
        let secret = Zeroizing::new(
            Self::entry(label, algorithm)?
                .get_secret()
                .map_err(|error| map_keyring_error(error, label, algorithm))?,
        );
        let secret: [u8; 32] =
            secret
                .as_slice()
                .try_into()
                .map_err(|_| Error::InvalidKeyMaterial {
                    algorithm,
                    reason: format!("expected 32 bytes, got {}", secret.len()),
                })?;
        Ok(SecretKey::new(algorithm, secret))
    }
}

impl Keystore for LinuxSecretServiceKeystore {
    fn capabilities(&self) -> Capabilities {
        linux_secret_service_capabilities(linux_secret_service_runtime_available())
    }

    fn generate(
        &self,
        label: &str,
        algorithm: Algorithm,
        attrs: KeyAttrs,
        options: GenerateOptions,
    ) -> Result<Box<dyn KeySigner>> {
        validate_attrs(&attrs)?;
        let mut secret = random_valid_secret(algorithm)?;
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

    fn import(
        &self,
        label: &str,
        secret: SecretKey,
        attrs: KeyAttrs,
        options: ImportOptions,
    ) -> Result<Box<dyn KeySigner>> {
        validate_attrs(&attrs)?;
        let signer = SoftwareSigner::new(
            label.into(),
            BackendKind::LinuxSecretService,
            secret.algorithm(),
            *secret.expose_secret(),
        )?;
        let entry = Self::entry(label, secret.algorithm())?;
        let exists = match entry.get_secret() {
            Ok(_) => true,
            Err(keyring_core::Error::NoEntry) => false,
            Err(error) => return Err(map_keyring_error(error, label, secret.algorithm())),
        };
        if exists && !options.overwrite {
            return Err(Error::KeyAlreadyExists {
                label: label.into(),
                algorithm: secret.algorithm(),
            });
        }
        entry
            .set_secret(secret.expose_secret())
            .map_err(|error| map_keyring_error(error, label, secret.algorithm()))?;
        Ok(Box::new(signer))
    }

    fn open(&self, selector: &KeySelector) -> Result<Box<dyn KeySigner>> {
        validate_label(&selector.label)?;
        let algorithm = crate::native_list::resolve_selector_algorithm(self, selector)?;
        let secret = Self::get_secret(&selector.label, algorithm)?;
        Ok(Box::new(SoftwareSigner::new(
            selector.label.clone(),
            BackendKind::LinuxSecretService,
            algorithm,
            *secret.expose_secret(),
        )?))
    }

    fn list(&self) -> Result<Vec<KeyMetadata>> {
        let store = zbus_secret_service_keyring_store::Store::new()
            .map_err(|error| keyring_backend_error("create Secret Service store", error))?;
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
                Err(error) => return Err(map_keyring_error(error, "list", Algorithm::Ed25519)),
            };
            if let Some(metadata) = crate::native_list::metadata_from_account_secret(
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

    fn export(&self, selector: &KeySelector) -> Result<SecretKey> {
        validate_label(&selector.label)?;
        let algorithm = crate::native_list::resolve_selector_algorithm(self, selector)?;
        Self::get_secret(&selector.label, algorithm)
    }

    fn delete(&self, selector: &KeySelector) -> Result<()> {
        validate_label(&selector.label)?;
        let algorithm = crate::native_list::resolve_selector_algorithm(self, selector)?;
        Self::entry(&selector.label, algorithm)?
            .delete_credential()
            .map_err(|error| map_keyring_error(error, &selector.label, algorithm))
    }
}

fn linux_secret_service_capabilities(runtime_available: bool) -> Capabilities {
    let algorithms = if runtime_available {
        vec![Algorithm::Ed25519, Algorithm::Secp256k1, Algorithm::P256]
    } else {
        Vec::new()
    };

    Capabilities {
        backend: BackendKind::LinuxSecretService,
        algorithms,
        can_generate: runtime_available,
        can_import: runtime_available,
        can_export: runtime_available,
        can_delete: runtime_available,
        supports_listing: runtime_available,
        supports_user_presence: false,
        supports_device_bound: false,
        supports_non_extractable: false,
    }
}

fn linux_secret_service_runtime_available() -> bool {
    zbus_secret_service_keyring_store::Store::new().is_ok()
}

fn validate_attrs(attrs: &KeyAttrs) -> Result<()> {
    if !attrs.extractable {
        return Err(Error::UnsupportedAttributes(
            "Linux Secret Service backend does not support non-extractable keys".into(),
        ));
    }
    if attrs.require_user_presence {
        return Err(Error::UnsupportedAttributes(
            "Linux Secret Service backend does not support user presence in V1".into(),
        ));
    }
    if attrs.device_bound {
        return Err(Error::UnsupportedAttributes(
            "Linux Secret Service backend does not support device-bound keys in V1".into(),
        ));
    }
    Ok(())
}

fn random_valid_secret(algorithm: Algorithm) -> Result<[u8; 32]> {
    let mut secret = [0u8; 32];
    loop {
        getrandom::fill(&mut secret).map_err(|_| Error::Internal("rng failed".into()))?;
        if SoftwareSigner::new(
            "validation".into(),
            BackendKind::LinuxSecretService,
            algorithm,
            secret,
        )
        .is_ok()
        {
            return Ok(secret);
        }
    }
}

fn map_keyring_error(error: keyring_core::Error, label: &str, algorithm: Algorithm) -> Error {
    match error {
        keyring_core::Error::NoEntry => Error::KeyNotFound(KeySelector {
            label: label.into(),
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
            label: "list".into(),
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
        let capabilities = linux_secret_service_capabilities(true);
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
    fn capabilities_disable_operations_when_runtime_unavailable() {
        let capabilities = linux_secret_service_capabilities(false);
        assert_eq!(capabilities.backend, BackendKind::LinuxSecretService);
        assert!(capabilities.algorithms.is_empty());
        assert!(!capabilities.can_generate);
        assert!(!capabilities.can_import);
        assert!(!capabilities.can_export);
        assert!(!capabilities.can_delete);
        assert!(!capabilities.supports_listing);
        assert!(!capabilities.supports_user_presence);
        assert!(!capabilities.supports_device_bound);
        assert!(!capabilities.supports_non_extractable);
    }

    #[test]
    fn invalid_ecdsa_import_rejected_before_secret_service_write() {
        let store = LinuxSecretServiceKeystore::new();
        let result = store.import(
            "invalid",
            SecretKey::new(Algorithm::P256, [0; 32]),
            KeyAttrs::default(),
            ImportOptions::default(),
        );

        assert!(matches!(result, Err(Error::InvalidKeyMaterial { .. })));
    }

    #[test]
    fn live_backend_create_open_list_export_delete_roundtrip() {
        crate::native_list::run_required_native_backend_roundtrip_test(
            &LinuxSecretServiceKeystore::new(),
        );
    }
}
