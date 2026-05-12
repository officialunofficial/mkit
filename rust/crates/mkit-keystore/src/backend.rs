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
        BackendKind::LinuxSecretService => open_linux_secret_service_backend(),
        BackendKind::SystemdCreds => open_systemd_creds_backend(),
        BackendKind::YubiKey => open_yubikey_backend(),
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

#[cfg(all(target_os = "linux", feature = "linux-secret-service"))]
#[allow(clippy::unnecessary_wraps)]
fn open_linux_secret_service_backend() -> Result<Box<dyn Keystore>> {
    Ok(Box::new(crate::LinuxSecretServiceKeystore::new()))
}

#[cfg(not(all(target_os = "linux", feature = "linux-secret-service")))]
fn open_linux_secret_service_backend() -> Result<Box<dyn Keystore>> {
    Err(Error::BackendUnavailable(
        "Linux Secret Service backend requires Linux and the `linux-secret-service` feature".into(),
    ))
}

#[cfg(all(target_os = "linux", feature = "systemd-creds"))]
#[allow(clippy::unnecessary_wraps)]
fn open_systemd_creds_backend() -> Result<Box<dyn Keystore>> {
    Ok(Box::new(crate::SystemdCredsKeystore::new()?))
}

#[cfg(not(all(target_os = "linux", feature = "systemd-creds")))]
fn open_systemd_creds_backend() -> Result<Box<dyn Keystore>> {
    Err(Error::BackendUnavailable(
        "systemd-creds backend requires Linux and the `systemd-creds` feature".into(),
    ))
}

#[cfg(feature = "backend-yubikey")]
fn open_yubikey_backend() -> Result<Box<dyn Keystore>> {
    Ok(Box::new(crate::YubiKeyKeystore::new()?))
}

#[cfg(not(feature = "backend-yubikey"))]
fn open_yubikey_backend() -> Result<Box<dyn Keystore>> {
    Err(Error::BackendUnavailable(
        "YubiKey backend requires the `backend-yubikey` feature".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_backend_fails_closed() {
        match open_backend(BackendKind::External) {
            Err(Error::BackendUnavailable(_)) => {}
            Err(error) => panic!("unexpected error: {error}"),
            Ok(_) => panic!("unexpected backend"),
        }
    }

    #[cfg(not(feature = "backend-yubikey"))]
    #[test]
    fn yubikey_backend_fails_closed_when_unavailable() {
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

    #[cfg(not(all(target_os = "linux", feature = "linux-secret-service")))]
    #[test]
    fn linux_secret_service_backend_fails_closed_when_unavailable() {
        match open_backend(BackendKind::LinuxSecretService) {
            Err(Error::BackendUnavailable(_)) => {}
            Err(error) => panic!("unexpected error: {error}"),
            Ok(_) => panic!("unexpected backend"),
        }
    }

    #[cfg(not(all(target_os = "linux", feature = "systemd-creds")))]
    #[test]
    fn systemd_creds_backend_fails_closed_when_unavailable() {
        match open_backend(BackendKind::SystemdCreds) {
            Err(Error::BackendUnavailable(_)) => {}
            Err(error) => panic!("unexpected error: {error}"),
            Ok(_) => panic!("unexpected backend"),
        }
    }
}
