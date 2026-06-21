//! macOS Keychain-backed DEK protector for the software keystore.

use super::random_handle;
use crate::encrypted_record::KeyProtector;
use crate::{Error, Result};

#[derive(Debug)]
pub(crate) struct MacosKeychainProtector;

impl MacosKeychainProtector {
    pub(crate) const ID: &'static str = "macos-keychain";
    const SERVICE: &'static str = "dev.mkit.keystore.software-dek.v1";
}

impl KeyProtector for MacosKeychainProtector {
    fn id(&self) -> &'static str {
        Self::ID
    }

    fn wrap_dek(&self, dek: &[u8; 32], _aad: &[u8]) -> Result<Vec<u8>> {
        let account = random_handle()?;
        security_framework::passwords::set_generic_password(Self::SERVICE, &account, dek).map_err(
            |error| Error::Io(format!("macOS Keychain software protector set: {error}")),
        )?;
        Ok(account.into_bytes())
    }

    fn unwrap_dek(&self, wrapped: &[u8], _aad: &[u8]) -> Result<zeroize::Zeroizing<[u8; 32]>> {
        let account = std::str::from_utf8(wrapped)
            .map_err(|error| Error::Encoding(format!("protector handle is not UTF-8: {error}")))?;
        let secret = zeroize::Zeroizing::new(
            security_framework::passwords::get_generic_password(Self::SERVICE, account).map_err(
                |error| Error::Io(format!("macOS Keychain software protector get: {error}")),
            )?,
        );
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
        security_framework::passwords::delete_generic_password(Self::SERVICE, account).map_err(
            |error| Error::Io(format!("macOS Keychain software protector delete: {error}")),
        )
    }
}
