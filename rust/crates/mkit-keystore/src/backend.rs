//! Backend construction helpers.

use crate::{BackendKind, Error, Keystore, Result, SoftwareKeystore, SoftwareRawKeystore};

/// Open a backend by family.
///
/// Backends that are not implemented or not compiled in for the current target
/// fail closed with a typed unavailable-backend error.
pub fn open_backend(kind: BackendKind) -> Result<Box<dyn Keystore>> {
    match kind {
        BackendKind::Software => Ok(Box::new(SoftwareKeystore::new()?)),
        BackendKind::SoftwareRaw => Ok(Box::new(SoftwareRawKeystore::new()?)),
        BackendKind::MacosKeychain => open_macos_keychain_backend(),
        BackendKind::WindowsCredentialManager => open_windows_credential_backend(),
        other => Err(Error::BackendUnavailable(format!(
            "backend `{other}` is not implemented in this build"
        ))),
    }
}

#[cfg(all(target_os = "macos", feature = "macos-keychain"))]
#[allow(clippy::unnecessary_wraps)]
fn open_macos_keychain_backend() -> Result<Box<dyn Keystore>> {
    Ok(Box::new(crate::MacosKeychainKeystore::new()))
}

#[cfg(not(all(target_os = "macos", feature = "macos-keychain")))]
fn open_macos_keychain_backend() -> Result<Box<dyn Keystore>> {
    Err(Error::BackendUnavailable(
        "macOS Keychain backend requires macOS and the `macos-keychain` feature".into(),
    ))
}

#[cfg(all(windows, feature = "windows-credential"))]
#[allow(clippy::unnecessary_wraps)]
fn open_windows_credential_backend() -> Result<Box<dyn Keystore>> {
    Ok(Box::new(crate::WindowsCredentialKeystore::new()))
}

#[cfg(not(all(windows, feature = "windows-credential")))]
fn open_windows_credential_backend() -> Result<Box<dyn Keystore>> {
    Err(Error::BackendUnavailable(
        "Windows Credential Manager backend requires Windows and the `windows-credential` feature"
            .into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_backend_fails_closed() {
        match open_backend(BackendKind::YubiKey) {
            Err(Error::BackendUnavailable(_)) => {}
            Err(error) => panic!("unexpected error: {error}"),
            Ok(_) => panic!("unexpected backend"),
        }
    }

    #[cfg(not(all(windows, feature = "windows-credential")))]
    #[test]
    fn windows_backend_fails_closed_when_unavailable() {
        match open_backend(BackendKind::WindowsCredentialManager) {
            Err(Error::BackendUnavailable(_)) => {}
            Err(error) => panic!("unexpected error: {error}"),
            Ok(_) => panic!("unexpected backend"),
        }
    }
}
