//! macOS Keychain-backed keystore.

use std::collections::HashMap;

use security_framework::item::{ItemClass, ItemSearchOptions, Limit};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    Algorithm, BackendKind, Capabilities, Error, GenerateOptions, ImportOptions, KeyAttrs,
    KeyMetadata, KeySelector, KeySigner, Keystore, Result, SecretKey, SoftwareSigner,
    validate_label,
};

const SERVICE: &str = "dev.mkit.keystore.signing-key.v1";
const ERR_SEC_ITEM_NOT_FOUND: i32 = -25_300;

/// User-scoped macOS Keychain backend.
#[derive(Clone, Debug, Default)]
pub struct MacosKeychainKeystore;

impl MacosKeychainKeystore {
    /// Create a macOS Keychain backend instance.
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
            "macOS Keychain backend requires an algorithm in key selectors",
        ))
    }

    fn get_secret(label: &str, algorithm: Algorithm) -> Result<SecretKey> {
        let account = Self::account(label, algorithm)?;
        let password = Zeroizing::new(
            security_framework::passwords::get_generic_password(SERVICE, &account)
                .map_err(|error| map_keychain_error(error, label, algorithm))?,
        );
        let secret: [u8; 32] =
            password
                .as_slice()
                .try_into()
                .map_err(|_| Error::InvalidKeyMaterial {
                    algorithm,
                    reason: format!("expected 32 bytes, got {}", password.len()),
                })?;
        Ok(SecretKey::new(algorithm, secret))
    }
}

impl Keystore for MacosKeychainKeystore {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            backend: BackendKind::MacosKeychain,
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
        let account = Self::account(label, secret.algorithm())?;
        let exists = match security_framework::passwords::get_generic_password(SERVICE, &account) {
            Ok(_) => true,
            Err(error) if is_not_found(error) => false,
            Err(error) => return Err(map_keychain_error(error, label, secret.algorithm())),
        };
        if exists && !options.overwrite {
            return Err(Error::KeyAlreadyExists {
                label: label.into(),
                algorithm: secret.algorithm(),
            });
        }
        security_framework::passwords::set_generic_password(
            SERVICE,
            &account,
            secret.expose_secret(),
        )
        .map_err(|error| keychain_io("set", error))?;
        Ok(Box::new(SoftwareSigner::new(
            label.into(),
            BackendKind::MacosKeychain,
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
            BackendKind::MacosKeychain,
            algorithm,
            *secret.expose_secret(),
        )?))
    }

    fn list(&self) -> Result<Vec<KeyMetadata>> {
        let mut options = ItemSearchOptions::new();
        options
            .class(ItemClass::generic_password())
            .service(SERVICE)
            .load_attributes(true)
            .limit(Limit::All);
        let results = match options.search() {
            Ok(results) => results,
            Err(error) if is_not_found(error) => return Ok(Vec::new()),
            Err(error) => return Err(keychain_io("list", error)),
        };

        let mut out = Vec::new();
        for result in results {
            let Some(attributes) = result.simplify_dict() else {
                continue;
            };
            let Some(account) = account_from_attributes(&attributes) else {
                continue;
            };
            let Some((algorithm, label)) = crate::native_list::parse_account(account) else {
                continue;
            };
            let secret = Self::get_secret(&label, algorithm)?;
            if let Some(metadata) = crate::native_list::metadata_from_account_secret(
                account,
                BackendKind::MacosKeychain,
                secret.expose_secret().to_vec(),
            )? {
                out.push(metadata);
            }
        }
        crate::native_list::sort_metadata(&mut out);
        Ok(out)
    }

    fn export(&self, selector: &KeySelector) -> Result<SecretKey> {
        validate_label(&selector.label)?;
        let algorithm = Self::selector_algorithm(selector)?;
        Self::get_secret(&selector.label, algorithm)
    }

    fn delete(&self, selector: &KeySelector) -> Result<()> {
        validate_label(&selector.label)?;
        let algorithm = Self::selector_algorithm(selector)?;
        let account = Self::account(&selector.label, algorithm)?;
        security_framework::passwords::delete_generic_password(SERVICE, &account)
            .map_err(|error| map_keychain_error(error, &selector.label, algorithm))
    }
}

fn account_from_attributes(attributes: &HashMap<String, String>) -> Option<&str> {
    attributes
        .get("acct")
        .or_else(|| attributes.get("account"))
        .map(String::as_str)
}

fn validate_attrs(attrs: &KeyAttrs) -> Result<()> {
    if !attrs.extractable {
        return Err(Error::UnsupportedAttributes(
            "macOS Keychain generic-password backend does not support non-extractable keys".into(),
        ));
    }
    if attrs.require_user_presence {
        return Err(Error::UnsupportedAttributes(
            "macOS Keychain backend does not support user presence in V1".into(),
        ));
    }
    if attrs.device_bound {
        return Err(Error::UnsupportedAttributes(
            "macOS Keychain backend does not support device-bound keys in V1".into(),
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
            BackendKind::MacosKeychain,
            algorithm,
            secret,
        )
        .is_ok()
        {
            return Ok(secret);
        }
    }
}

fn is_not_found(error: security_framework::base::Error) -> bool {
    error.code() == ERR_SEC_ITEM_NOT_FOUND
}

fn map_keychain_error(
    error: security_framework::base::Error,
    label: &str,
    algorithm: Algorithm,
) -> Error {
    if is_not_found(error) {
        Error::KeyNotFound(KeySelector {
            label: label.into(),
            algorithm: Some(algorithm),
        })
    } else {
        keychain_io("get", error)
    }
}

fn keychain_io(operation: &str, error: security_framework::base::Error) -> Error {
    Error::Io(format!("macOS Keychain {operation}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capabilities_are_backend_accurate() {
        let capabilities = MacosKeychainKeystore::new().capabilities();
        assert_eq!(capabilities.backend, BackendKind::MacosKeychain);
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
    fn keychain_attribute_account_uses_short_or_readable_key() {
        let mut attributes = HashMap::from([("acct".into(), "ed25519:short".into())]);
        assert_eq!(account_from_attributes(&attributes), Some("ed25519:short"));

        attributes = HashMap::from([("account".into(), "ed25519:readable".into())]);
        assert_eq!(
            account_from_attributes(&attributes),
            Some("ed25519:readable")
        );
    }

    #[test]
    fn live_backend_create_open_list_export_delete_roundtrip() {
        crate::native_list::run_native_backend_roundtrip_test(&MacosKeychainKeystore::new());
    }
}
