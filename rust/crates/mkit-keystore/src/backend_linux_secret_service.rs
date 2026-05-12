//! Linux Secret Service-backed keystore.

use zeroize::Zeroize;

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

    fn selector_algorithm(selector: &KeySelector) -> Result<Algorithm> {
        selector.algorithm.ok_or(Error::UnsupportedOperation(
            "Linux Secret Service backend requires an algorithm in key selectors",
        ))
    }

    fn entry(label: &str, algorithm: Algorithm) -> Result<keyring_core::Entry> {
        let store = zbus_secret_service_keyring_store::Store::new()
            .map_err(|error| keyring_backend_error("create Secret Service store", error))?;
        keyring_core::set_default_store(store)
            .map_err(|error| keyring_backend_error("select Secret Service store", error))?;
        keyring_core::Entry::new(SERVICE, &Self::account(label, algorithm)?)
            .map_err(|error| map_keyring_error(error, label, algorithm))
    }

    fn get_secret(label: &str, algorithm: Algorithm) -> Result<SecretKey> {
        let secret = Self::entry(label, algorithm)?
            .get_secret()
            .map_err(|error| map_keyring_error(error, label, algorithm))?;
        let secret: [u8; 32] =
            secret
                .try_into()
                .map_err(|secret: Vec<u8>| Error::InvalidKeyMaterial {
                    algorithm,
                    reason: format!("expected 32 bytes, got {}", secret.len()),
                })?;
        Ok(SecretKey::new(algorithm, secret))
    }
}

impl Keystore for LinuxSecretServiceKeystore {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            backend: BackendKind::LinuxSecretService,
            algorithms: vec![Algorithm::Ed25519, Algorithm::Secp256k1, Algorithm::P256],
            can_generate: true,
            can_import: true,
            can_export: true,
            can_delete: true,
            supports_listing: false,
            supports_user_presence: false,
            supports_device_bound: false,
            supports_non_extractable: false,
        }
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
        Ok(Box::new(SoftwareSigner::new(
            label.into(),
            BackendKind::LinuxSecretService,
            secret.algorithm(),
            *secret.expose_secret(),
        )?))
    }

    fn open(&self, selector: &KeySelector) -> Result<Box<dyn KeySigner>> {
        validate_label(&selector.label)?;
        let algorithm = Self::selector_algorithm(selector)?;
        let secret = Self::get_secret(&selector.label, algorithm)?;
        Ok(Box::new(SoftwareSigner::new(
            selector.label.clone(),
            BackendKind::LinuxSecretService,
            algorithm,
            *secret.expose_secret(),
        )?))
    }

    fn list(&self) -> Result<Vec<KeyMetadata>> {
        Err(Error::UnsupportedOperation(
            "Linux Secret Service backend does not support listing in V1",
        ))
    }

    fn export(&self, selector: &KeySelector) -> Result<SecretKey> {
        validate_label(&selector.label)?;
        let algorithm = Self::selector_algorithm(selector)?;
        Self::get_secret(&selector.label, algorithm)
    }

    fn delete(&self, selector: &KeySelector) -> Result<()> {
        validate_label(&selector.label)?;
        let algorithm = Self::selector_algorithm(selector)?;
        Self::entry(&selector.label, algorithm)?
            .delete_credential()
            .map_err(|error| map_keyring_error(error, &selector.label, algorithm))
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capabilities_are_backend_accurate() {
        let capabilities = LinuxSecretServiceKeystore::new().capabilities();
        assert_eq!(capabilities.backend, BackendKind::LinuxSecretService);
        assert_eq!(
            capabilities.algorithms,
            vec![Algorithm::Ed25519, Algorithm::Secp256k1, Algorithm::P256]
        );
        assert!(capabilities.can_generate);
        assert!(capabilities.can_import);
        assert!(capabilities.can_export);
        assert!(capabilities.can_delete);
        assert!(!capabilities.supports_listing);
        assert!(!capabilities.supports_user_presence);
        assert!(!capabilities.supports_device_bound);
        assert!(!capabilities.supports_non_extractable);
    }
}
