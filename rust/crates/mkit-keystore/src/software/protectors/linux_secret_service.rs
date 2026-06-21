//! Linux Secret Service-backed DEK protector for the software keystore.

use super::random_handle;
use crate::encrypted_record::KeyProtector;
use crate::{Error, Result};

#[derive(Debug)]
pub(crate) struct LinuxSecretServiceProtector;

impl LinuxSecretServiceProtector {
    pub(crate) const ID: &'static str = "linux-secret-service";
    const SERVICE: &'static str = "dev.mkit.keystore.software-dek.v1";

    pub(crate) fn available() -> Result<bool> {
        match zbus_secret_service_keyring_store::Store::new() {
            Ok(_) => Ok(true),
            Err(error) => Err(Error::BackendUnavailable(format!(
                "Linux Secret Service software protector: {error}"
            ))),
        }
    }

    fn entry(account: &str) -> Result<keyring_core::Entry> {
        let store = zbus_secret_service_keyring_store::Store::new().map_err(|error| {
            Error::BackendUnavailable(format!("Linux Secret Service software protector: {error}"))
        })?;
        let _guard = crate::keyring_default_store_lock();
        keyring_core::set_default_store(store);
        keyring_core::Entry::new(Self::SERVICE, account)
            .map_err(|error| Error::Io(format!("Linux Secret Service software protector: {error}")))
    }
}

impl KeyProtector for LinuxSecretServiceProtector {
    fn id(&self) -> &'static str {
        Self::ID
    }

    fn wrap_dek(&self, dek: &[u8; 32], _aad: &[u8]) -> Result<Vec<u8>> {
        let account = random_handle()?;
        Self::entry(&account)?.set_secret(dek).map_err(|error| {
            Error::Io(format!(
                "Linux Secret Service software protector set: {error}"
            ))
        })?;
        Ok(account.into_bytes())
    }

    fn unwrap_dek(&self, wrapped: &[u8], _aad: &[u8]) -> Result<zeroize::Zeroizing<[u8; 32]>> {
        let account = std::str::from_utf8(wrapped)
            .map_err(|error| Error::Encoding(format!("protector handle is not UTF-8: {error}")))?;
        let secret =
            zeroize::Zeroizing::new(Self::entry(account)?.get_secret().map_err(|error| {
                Error::Io(format!(
                    "Linux Secret Service software protector get: {error}"
                ))
            })?);
        if secret.len() != 32 {
            return Err(Error::Encoding(format!(
                "protected DEK length: {}",
                secret.len()
            )));
        }
        let mut dek = zeroize::Zeroizing::new([0u8; 32]);
        dek.copy_from_slice(secret.as_slice());
        Ok(dek)
    }

    fn delete_wrapped_dek(&self, wrapped: &[u8]) -> Result<()> {
        let account = std::str::from_utf8(wrapped)
            .map_err(|error| Error::Encoding(format!("protector handle is not UTF-8: {error}")))?;
        Self::entry(account)?.delete_credential().map_err(|error| {
            Error::Io(format!(
                "Linux Secret Service software protector delete: {error}"
            ))
        })
    }
}

/// Heuristic for whether a desktop session (and thus a Secret Service
/// provider) is likely available, used to decide whether to prefer this
/// protector over systemd-creds.
pub(crate) fn linux_desktop_session_available() -> bool {
    std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_some()
        || std::env::var_os("XDG_CURRENT_DESKTOP").is_some()
        || std::env::var_os("DESKTOP_SESSION").is_some()
}
