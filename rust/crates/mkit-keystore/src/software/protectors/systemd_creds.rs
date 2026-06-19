//! systemd-creds-backed DEK protector for the software keystore.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::random_handle;
use crate::encrypted_record::KeyProtector;
use crate::{Error, Result};

#[derive(Debug)]
pub(crate) struct SystemdCredsProtector {
    pub(crate) storage_root: PathBuf,
    pub(crate) dek_root: PathBuf,
}

impl SystemdCredsProtector {
    pub(crate) const ID: &'static str = "systemd-creds";

    pub(crate) fn path_for(&self, handle: &str) -> PathBuf {
        self.dek_root.join(format!("{handle}.cred"))
    }

    fn credential_name(handle: &str) -> String {
        format!("mkit.software-dek.{handle}")
    }

    pub(crate) fn prepare_write_path(&self, path: &Path) -> Result<()> {
        #[cfg(unix)]
        {
            let parent = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            super::super::ensure_no_symlink_path(&self.storage_root, parent)?;
            std::fs::create_dir_all(parent)
                .map_err(|error| Error::Io(format!("mkdir {}: {error}", parent.display())))?;
            super::super::set_private_dir_permissions(&self.storage_root)?;
            super::super::ensure_owned_by_euid(&self.storage_root)?;
            if parent != self.storage_root {
                super::super::set_private_dir_permissions(parent)?;
                super::super::ensure_owned_by_euid(parent)?;
            }
        }

        #[cfg(not(unix))]
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| Error::Io(format!("mkdir {}: {error}", parent.display())))?;
        }

        Ok(())
    }

    fn validate_existing_path(&self, path: &Path) -> Result<()> {
        #[cfg(unix)]
        super::super::ensure_no_symlink_path(&self.storage_root, path)?;

        Ok(())
    }
}

pub(crate) fn systemd_creds_protector(root: &Path) -> Result<Arc<dyn KeyProtector>> {
    systemd_creds_protector_for_availability(
        root,
        crate::backend_systemd_creds::systemd_creds_runtime_available(),
    )
}

pub(crate) fn systemd_creds_protector_for_availability(
    root: &Path,
    runtime_available: bool,
) -> Result<Arc<dyn KeyProtector>> {
    if !runtime_available {
        return Err(Error::BackendUnavailable(
            "systemd-creds executable was not found or is unusable".into(),
        ));
    }
    Ok(Arc::new(SystemdCredsProtector {
        storage_root: root.into(),
        dek_root: root.join("deks"),
    }))
}

impl KeyProtector for SystemdCredsProtector {
    fn id(&self) -> &'static str {
        Self::ID
    }

    fn wrap_dek(&self, dek: &[u8; 32], _aad: &[u8]) -> Result<Vec<u8>> {
        let handle = random_handle()?;
        let path = self.path_for(&handle);
        self.prepare_write_path(&path)?;
        crate::backend_systemd_creds::encrypt_credential_create_new(
            dek,
            &path,
            &Self::credential_name(&handle),
        )?;
        Ok(handle.into_bytes())
    }

    fn unwrap_dek(&self, wrapped: &[u8], _aad: &[u8]) -> Result<zeroize::Zeroizing<[u8; 32]>> {
        let handle = std::str::from_utf8(wrapped)
            .map_err(|error| Error::Encoding(format!("protector handle is not UTF-8: {error}")))?;
        let path = self.path_for(handle);
        self.validate_existing_path(&path)?;
        let secret = zeroize::Zeroizing::new(crate::backend_systemd_creds::decrypt_credential(
            &path,
            &Self::credential_name(handle),
        )?);
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
        let handle = std::str::from_utf8(wrapped)
            .map_err(|error| Error::Encoding(format!("protector handle is not UTF-8: {error}")))?;
        let path = self.path_for(handle);
        self.validate_existing_path(&path)?;
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(Error::Io(format!("delete systemd-creds DEK: {error}"))),
        }
    }
}
