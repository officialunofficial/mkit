//! OS-backed key-protector integrations for the software keystore.
//!
//! Each supported platform credential store gets its own submodule
//! implementing [`crate::encrypted_record::KeyProtector`] for wrapping the
//! per-record data-encryption key (DEK). The protectors are feature- and
//! target-gated; only the ones compiled in for the current platform are
//! reachable from [`super::default_protector_for_write`] /
//! [`super::default_protector_by_id`].

use crate::Error;
use crate::Result;
use crate::types::hex_lower;

#[cfg(all(target_os = "macos", feature = "macos-keychain"))]
pub(super) mod macos;
#[cfg(all(target_os = "macos", feature = "macos-keychain"))]
pub(super) use macos::MacosKeychainProtector;

#[cfg(all(windows, feature = "windows-credential"))]
pub(super) mod windows;
#[cfg(all(windows, feature = "windows-credential"))]
pub(super) use windows::WindowsCredentialProtector;

#[cfg(all(target_os = "linux", feature = "linux-secret-service"))]
pub(super) mod linux_secret_service;
#[cfg(all(target_os = "linux", feature = "linux-secret-service"))]
pub(super) use linux_secret_service::{
    LinuxSecretServiceProtector, linux_desktop_session_available,
};

#[cfg(all(target_os = "linux", feature = "systemd-creds"))]
pub(super) mod systemd_creds;
#[cfg(all(target_os = "linux", feature = "systemd-creds"))]
#[cfg_attr(not(test), allow(unused_imports))]
pub(super) use systemd_creds::systemd_creds_protector_for_availability;
#[cfg(all(target_os = "linux", feature = "systemd-creds"))]
pub(super) use systemd_creds::{SystemdCredsProtector, systemd_creds_protector};

/// Random opaque handle used by the credential-store protectors as the
/// account/credential name under which the wrapped DEK is stored.
#[allow(dead_code)]
pub(super) fn random_handle() -> Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| Error::Internal("rng failed".into()))?;
    Ok(hex_lower(&bytes))
}
