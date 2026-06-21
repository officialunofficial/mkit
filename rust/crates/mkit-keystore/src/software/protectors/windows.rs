//! Windows Credential Manager-backed DEK protector for the software keystore.

use super::random_handle;
use crate::encrypted_record::KeyProtector;
use crate::{Error, Result};

#[derive(Debug)]
pub(crate) struct WindowsCredentialProtector;

impl WindowsCredentialProtector {
    pub(crate) const ID: &'static str = "windows-credential";
    const SERVICE: &'static str = "dev.mkit.keystore.software-dek.v1";

    fn entry(account: &str) -> Result<keyring_core::Entry> {
        let store = windows_native_keyring_store::Store::new().map_err(|error| {
            Error::BackendUnavailable(format!("Windows Credential software protector: {error}"))
        })?;
        let _guard = crate::keyring_default_store_lock();
        keyring_core::set_default_store(store);
        keyring_core::Entry::new(Self::SERVICE, account)
            .map_err(|error| Error::Io(format!("Windows Credential software protector: {error}")))
    }
}

impl KeyProtector for WindowsCredentialProtector {
    fn id(&self) -> &'static str {
        Self::ID
    }

    fn wrap_dek(&self, dek: &[u8; 32], _aad: &[u8]) -> Result<Vec<u8>> {
        let account = random_handle()?;
        Self::entry(&account)?.set_secret(dek).map_err(|error| {
            Error::Io(format!(
                "Windows Credential software protector set: {error}"
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
                    "Windows Credential software protector get: {error}"
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
                "Windows Credential software protector delete: {error}"
            ))
        })
    }
}
