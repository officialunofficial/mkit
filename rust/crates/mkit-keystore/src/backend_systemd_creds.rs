//! Linux systemd-creds-backed keystore.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use zeroize::{Zeroize, Zeroizing};

use crate::{
    Algorithm, BackendKind, Capabilities, Error, GenerateOptions, ImportOptions, KeyAttrs,
    KeyMetadata, KeySelector, KeySigner, Keystore, Result, SecretKey, SoftwareSigner,
    validate_label,
};

/// User-scoped systemd encrypted credentials backend.
#[derive(Clone, Debug)]
pub struct SystemdCredsKeystore {
    root: PathBuf,
}

impl SystemdCredsKeystore {
    /// Create a systemd-creds keystore using the default user-scoped root.
    pub fn new() -> Result<Self> {
        Ok(Self {
            root: default_storage_root()?,
        })
    }

    /// Create a systemd-creds keystore at an explicit root, useful for tests.
    #[must_use]
    pub fn with_root(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn path_for(&self, label: &str, algorithm: Algorithm) -> Result<PathBuf> {
        validate_label(label)?;
        Ok(self
            .root
            .join(algorithm.as_str())
            .join(format!("{}.cred", hex_lower(label.as_bytes()))))
    }

    fn credential_name(label: &str, algorithm: Algorithm) -> Result<String> {
        validate_label(label)?;
        Ok(format!("mkit.{}.{}", algorithm.as_str(), label))
    }

    fn load_secret(&self, label: &str, algorithm: Algorithm) -> Result<SecretKey> {
        let path = self.path_for(label, algorithm)?;
        self.ensure_storage_path_not_symlink(&path)?;
        if !path.exists() {
            return Err(Error::KeyNotFound(KeySelector {
                label: label.into(),
                algorithm: Some(algorithm),
            }));
        }
        Self::secret_from_plaintext(
            algorithm,
            decrypt_credential(&path, &Self::credential_name(label, algorithm)?)?,
        )
    }

    fn load_secret_for_list(&self, label: &str, algorithm: Algorithm) -> Result<Option<SecretKey>> {
        self.load_secret_for_list_with_command(label, algorithm, "systemd-creds")
    }

    fn load_secret_for_list_with_command(
        &self,
        label: &str,
        algorithm: Algorithm,
        command: &str,
    ) -> Result<Option<SecretKey>> {
        let path = self.path_for(label, algorithm)?;
        self.ensure_storage_path_not_symlink(&path)?;
        if !path.exists() {
            return Ok(None);
        }
        let plaintext = match decrypt_credential_with_command_result(
            command,
            &path,
            &Self::credential_name(label, algorithm)?,
        ) {
            Ok(plaintext) => plaintext,
            Err(CredentialDecryptError::Status(_)) => return Ok(None),
            Err(error) => return Err(error.into_error()),
        };
        match Self::secret_from_plaintext(algorithm, plaintext) {
            Ok(secret) => Ok(Some(secret)),
            Err(error) if crate::native_list::is_malformed_list_entry_error(&error) => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn secret_from_plaintext(algorithm: Algorithm, plaintext: Vec<u8>) -> Result<SecretKey> {
        let plaintext = Zeroizing::new(plaintext);
        if plaintext.len() != 32 {
            return Err(Error::InvalidKeyMaterial {
                algorithm,
                reason: format!("expected 32 bytes, got {}", plaintext.len()),
            });
        }
        let mut secret = Zeroizing::new([0u8; 32]);
        secret.copy_from_slice(plaintext.as_slice());
        Ok(SecretKey::from_zeroizing(algorithm, secret))
    }

    fn metadata_for(
        label: String,
        algorithm: Algorithm,
        secret: &SecretKey,
    ) -> Result<KeyMetadata> {
        let signer = SoftwareSigner::new(
            label.clone(),
            BackendKind::SystemdCreds,
            secret.algorithm(),
            *secret.expose_secret(),
        )?;
        Ok(KeyMetadata {
            label,
            backend: BackendKind::SystemdCreds,
            algorithm,
            public_key: signer.public_key()?,
            keyid: signer.keyid()?,
            extractable: true,
            require_user_presence: false,
            device_bound: false,
        })
    }

    fn list_metadata_for(
        label: String,
        algorithm: Algorithm,
        secret: &SecretKey,
    ) -> Result<Option<KeyMetadata>> {
        match Self::metadata_for(label, algorithm, secret) {
            Ok(metadata) => Ok(Some(metadata)),
            Err(error) if crate::native_list::is_malformed_list_entry_error(&error) => Ok(None),
            Err(error) => Err(error),
        }
    }
}

impl Default for SystemdCredsKeystore {
    fn default() -> Self {
        Self::new().expect("default systemd-creds keystore root should be discoverable")
    }
}

impl Keystore for SystemdCredsKeystore {
    fn capabilities(&self) -> Capabilities {
        systemd_creds_capabilities(systemd_creds_runtime_available())
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
            BackendKind::SystemdCreds,
            secret.algorithm(),
            *secret.expose_secret(),
        )?;
        let path = self.path_for(label, secret.algorithm())?;
        self.prepare_write_path(&path)?;
        if options.overwrite {
            encrypt_credential(
                secret.expose_secret(),
                &path,
                &Self::credential_name(label, secret.algorithm())?,
            )?;
        } else {
            encrypt_key_credential_create_new(
                secret.expose_secret(),
                &path,
                &Self::credential_name(label, secret.algorithm())?,
                label,
                secret.algorithm(),
            )?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .map_err(|error| Error::Io(format!("chmod {}: {error}", path.display())))?;
        }
        Ok(Box::new(signer))
    }

    fn open(&self, selector: &KeySelector) -> Result<Box<dyn KeySigner>> {
        validate_label(&selector.label)?;
        let algorithm = self.resolve_selector_algorithm(selector)?;
        let secret = self.load_secret(&selector.label, algorithm)?;
        Ok(Box::new(SoftwareSigner::new(
            selector.label.clone(),
            BackendKind::SystemdCreds,
            algorithm,
            *secret.expose_secret(),
        )?))
    }

    fn list(&self) -> Result<Vec<KeyMetadata>> {
        let mut out = Vec::new();
        for algorithm in [Algorithm::Ed25519, Algorithm::Secp256k1, Algorithm::P256] {
            let dir = self.root.join(algorithm.as_str());
            self.ensure_storage_path_not_symlink(&dir)?;
            let entries = match std::fs::read_dir(&dir) {
                Ok(entries) => entries,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(Error::Io(format!("read_dir {}: {error}", dir.display())));
                }
            };
            for entry in entries {
                let entry = entry.map_err(|error| Error::Io(format!("read_dir entry: {error}")))?;
                let path = entry.path();
                if !path
                    .extension()
                    .and_then(|extension| extension.to_str())
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("cred"))
                {
                    continue;
                }
                let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
                    continue;
                };
                let Ok(label_bytes) = hex_decode(stem) else {
                    continue;
                };
                let Ok(label) = String::from_utf8(label_bytes) else {
                    continue;
                };
                if validate_label(&label).is_err() {
                    continue;
                }
                let Some(secret) = self.load_secret_for_list(&label, algorithm)? else {
                    continue;
                };
                if let Some(metadata) = Self::list_metadata_for(label, algorithm, &secret)? {
                    out.push(metadata);
                }
            }
        }
        out.sort_by(|left, right| {
            (&left.backend, &left.label, left.algorithm).cmp(&(
                &right.backend,
                &right.label,
                right.algorithm,
            ))
        });
        Ok(out)
    }

    fn export(&self, selector: &KeySelector) -> Result<SecretKey> {
        validate_label(&selector.label)?;
        let algorithm = self.resolve_selector_algorithm(selector)?;
        self.load_secret(&selector.label, algorithm)
    }

    fn delete(&self, selector: &KeySelector) -> Result<()> {
        validate_label(&selector.label)?;
        let algorithm = self.resolve_selector_algorithm(selector)?;
        let path = self.path_for(&selector.label, algorithm)?;
        self.ensure_storage_path_not_symlink(&path)?;
        if !path.exists() {
            return Err(Error::KeyNotFound(KeySelector {
                label: selector.label.clone(),
                algorithm: Some(algorithm),
            }));
        }
        std::fs::remove_file(&path)
            .map_err(|error| Error::Io(format!("delete {}: {error}", path.display())))
    }
}

fn systemd_creds_capabilities(runtime_available: bool) -> Capabilities {
    let algorithms = if runtime_available {
        vec![Algorithm::Ed25519, Algorithm::Secp256k1, Algorithm::P256]
    } else {
        Vec::new()
    };
    Capabilities {
        backend: BackendKind::SystemdCreds,
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

pub(crate) fn systemd_creds_runtime_available() -> bool {
    systemd_creds_runtime_available_with_command("systemd-creds")
}

fn systemd_creds_runtime_available_with_command(command: &str) -> bool {
    if !Command::new(command)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
    {
        return false;
    }
    systemd_creds_roundtrip_available_with_command(command)
}

impl SystemdCredsKeystore {
    #[cfg(unix)]
    fn ensure_storage_path_not_symlink(&self, path: &Path) -> Result<()> {
        let mut current = Some(path);
        while let Some(candidate) = current {
            if !candidate.starts_with(&self.root) {
                break;
            }
            match std::fs::symlink_metadata(candidate) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    return Err(Error::Io(format!(
                        "keystore path is a symlink: {}",
                        candidate.display()
                    )));
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(Error::Io(format!("lstat {}: {error}", candidate.display())));
                }
            }
            if candidate == self.root {
                break;
            }
            current = candidate.parent();
        }
        Ok(())
    }

    #[cfg(unix)]
    fn prepare_write_path(&self, path: &Path) -> Result<()> {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        self.ensure_storage_path_not_symlink(parent)?;
        std::fs::create_dir_all(parent)
            .map_err(|error| Error::Io(format!("mkdir {}: {error}", parent.display())))?;
        set_private_dir_permissions(&self.root)?;
        ensure_owned_by_euid(&self.root)?;
        if parent != self.root {
            set_private_dir_permissions(parent)?;
            ensure_owned_by_euid(parent)?;
        }
        self.ensure_storage_path_not_symlink(path)
    }

    #[cfg(not(unix))]
    fn prepare_write_path(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| Error::Io(format!("mkdir {}: {error}", parent.display())))?;
        }
        Ok(())
    }

    fn resolve_selector_algorithm(&self, selector: &KeySelector) -> Result<Algorithm> {
        if let Some(algorithm) = selector.algorithm {
            return Ok(algorithm);
        }
        let mut matches = Vec::new();
        for algorithm in [Algorithm::Ed25519, Algorithm::Secp256k1, Algorithm::P256] {
            match self.load_secret(&selector.label, algorithm) {
                Ok(_) => matches.push(algorithm),
                Err(Error::KeyNotFound(_)) => {}
                Err(error) => return Err(error),
            }
        }
        match matches.as_slice() {
            [] => Err(Error::KeyNotFound(selector.clone())),
            [algorithm] => Ok(*algorithm),
            _ => Err(Error::AmbiguousKeySelector(selector.clone())),
        }
    }
}

fn validate_attrs(attrs: &KeyAttrs) -> Result<()> {
    if !attrs.extractable {
        return Err(Error::UnsupportedAttributes(
            "systemd-creds backend does not support non-extractable keys in V1".into(),
        ));
    }
    if attrs.require_user_presence {
        return Err(Error::UnsupportedAttributes(
            "systemd-creds backend does not support user presence".into(),
        ));
    }
    if attrs.device_bound {
        return Err(Error::UnsupportedAttributes(
            "systemd-creds backend does not expose device-bound key requests in V1".into(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_owned_by_euid(path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = std::fs::metadata(path)
        .map_err(|error| Error::Io(format!("metadata {}: {error}", path.display())))?;
    let actual = metadata.uid();
    let expected = mkit_core::sign::effective_uid();
    if actual == expected {
        Ok(())
    } else {
        Err(Error::AccessDenied(format!(
            "keystore path is owned by uid {actual}, expected {expected}: {}",
            path.display()
        )))
    }
}

#[cfg(unix)]
fn set_private_dir_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .map_err(|error| Error::Io(format!("chmod {}: {error}", path.display())))
}

pub(crate) fn encrypt_credential(secret: &[u8; 32], path: &Path, name: &str) -> Result<()> {
    let tmp_path = write_temp_credential(secret, path, name)?;
    if let Err(error) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(Error::Io(format!(
            "rename {} to {}: {error}",
            tmp_path.display(),
            path.display()
        )));
    }
    Ok(())
}

pub(crate) fn encrypt_credential_create_new(
    secret: &[u8; 32],
    path: &Path,
    name: &str,
) -> Result<()> {
    let tmp_path = write_temp_credential(secret, path, name)?;
    if let Err(error) = publish_temp_credential_create_new(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(Error::Io(format!(
            "create credential {} from {}: {error}",
            path.display(),
            tmp_path.display()
        )));
    }
    Ok(())
}

fn encrypt_key_credential_create_new(
    secret: &[u8; 32],
    path: &Path,
    name: &str,
    label: &str,
    algorithm: Algorithm,
) -> Result<()> {
    let tmp_path = write_temp_credential(secret, path, name)?;
    if let Err(error) = publish_temp_credential_create_new(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return if error.kind() == std::io::ErrorKind::AlreadyExists {
            Err(Error::KeyAlreadyExists {
                label: label.into(),
                algorithm,
            })
        } else {
            Err(Error::Io(format!(
                "create credential {} from {}: {error}",
                path.display(),
                tmp_path.display()
            )))
        };
    }
    Ok(())
}

fn write_temp_credential(secret: &[u8; 32], path: &Path, name: &str) -> Result<PathBuf> {
    let tmp_path = temp_credential_path(path)?;
    if let Err(error) = encrypt_credential_to_path(secret, &tmp_path, name) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(error);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600))
            .map_err(|error| Error::Io(format!("chmod {}: {error}", tmp_path.display())))?;
    }
    Ok(tmp_path)
}

#[cfg(unix)]
fn publish_temp_credential_create_new(tmp_path: &Path, path: &Path) -> std::io::Result<()> {
    std::fs::hard_link(tmp_path, path)?;
    std::fs::remove_file(tmp_path)
}

#[cfg(not(unix))]
fn publish_temp_credential_create_new(tmp_path: &Path, path: &Path) -> std::io::Result<()> {
    use std::io::{Read as _, Write as _};

    let mut tmp_file = std::fs::File::open(tmp_path)?;
    let mut bytes = Vec::new();
    tmp_file.read_to_end(&mut bytes)?;
    let mut final_file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    final_file.write_all(&bytes)?;
    final_file.sync_all()?;
    std::fs::remove_file(tmp_path)
}

fn encrypt_credential_to_path(secret: &[u8; 32], path: &Path, name: &str) -> Result<()> {
    encrypt_credential_to_path_with_command("systemd-creds", secret, path, name)
}

fn encrypt_credential_to_path_with_command(
    command: &str,
    secret: &[u8; 32],
    path: &Path,
    name: &str,
) -> Result<()> {
    let mut child = Command::new(command)
        .args(["--with-key=auto", "--name", name])
        .arg("encrypt")
        .arg("-")
        .arg(path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| systemd_creds_spawn_error(&error))?;
    child
        .stdin
        .as_mut()
        .ok_or_else(|| Error::Internal("systemd-creds stdin unavailable".into()))?
        .write_all(secret)
        .map_err(|error| Error::Io(format!("systemd-creds stdin: {error}")))?;
    let output = child
        .wait_with_output()
        .map_err(|error| Error::Io(format!("systemd-creds encrypt: {error}")))?;
    if output.status.success() {
        Ok(())
    } else {
        let _ = std::fs::remove_file(path);
        Err(systemd_creds_status_error("encrypt", &output))
    }
}

fn temp_credential_path(path: &Path) -> Result<PathBuf> {
    let parent = path
        .parent()
        .ok_or_else(|| Error::Io(format!("path has no parent: {}", path.display())))?;
    let filename = path
        .file_name()
        .ok_or_else(|| Error::Io(format!("path has no filename: {}", path.display())))?;
    let mut suffix = [0u8; 8];
    getrandom::fill(&mut suffix).map_err(|_| Error::Internal("rng failed".into()))?;
    Ok(parent.join(format!(
        ".{}.{}.tmp",
        filename.to_string_lossy(),
        hex_lower(&suffix)
    )))
}

pub(crate) fn decrypt_credential(path: &Path, name: &str) -> Result<Vec<u8>> {
    decrypt_credential_with_command("systemd-creds", path, name)
}

fn decrypt_credential_with_command(command: &str, path: &Path, name: &str) -> Result<Vec<u8>> {
    decrypt_credential_with_command_result(command, path, name)
        .map_err(CredentialDecryptError::into_error)
}

enum CredentialDecryptError {
    Spawn(Error),
    Status(Error),
}

impl CredentialDecryptError {
    fn into_error(self) -> Error {
        match self {
            Self::Spawn(error) | Self::Status(error) => error,
        }
    }
}

fn decrypt_credential_with_command_result(
    command: &str,
    path: &Path,
    name: &str,
) -> std::result::Result<Vec<u8>, CredentialDecryptError> {
    let output = Command::new(command)
        .args(["--name", name])
        .arg("decrypt")
        .arg(path)
        .arg("-")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|error| CredentialDecryptError::Spawn(systemd_creds_spawn_error(&error)))?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(CredentialDecryptError::Status(systemd_creds_status_error(
            "decrypt", &output,
        )))
    }
}

fn systemd_creds_roundtrip_available_with_command(command: &str) -> bool {
    let mut suffix = [0u8; 8];
    if getrandom::fill(&mut suffix).is_err() {
        return false;
    }
    let dir = std::env::temp_dir().join(format!("mkit-systemd-creds-{}", hex_lower(&suffix)));
    let path = dir.join("probe.cred");
    let name = "mkit.runtime-probe";
    let secret = [0x5a; 32];
    let result = std::fs::create_dir_all(&dir)
        .map_err(|error| Error::Io(format!("mkdir {}: {error}", dir.display())))
        .and_then(|()| encrypt_credential_to_path_with_command(command, &secret, &path, name))
        .and_then(|()| decrypt_credential_with_command(command, &path, name))
        .is_ok_and(|plaintext| plaintext == secret);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_dir(&dir);
    result
}

fn systemd_creds_spawn_error(error: &std::io::Error) -> Error {
    if error.kind() == std::io::ErrorKind::NotFound {
        Error::BackendUnavailable("systemd-creds executable was not found".into())
    } else {
        Error::Io(format!("systemd-creds spawn: {error}"))
    }
}

fn systemd_creds_status_error(operation: &str, output: &std::process::Output) -> Error {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    if stderr.is_empty() {
        Error::BackendUnavailable(format!(
            "systemd-creds {operation} failed with status {}",
            output.status
        ))
    } else {
        Error::BackendUnavailable(format!("systemd-creds {operation}: {stderr}"))
    }
}

fn random_valid_secret(algorithm: Algorithm) -> Result<[u8; 32]> {
    let mut secret = [0u8; 32];
    loop {
        getrandom::fill(&mut secret).map_err(|_| Error::Internal("rng failed".into()))?;
        if SoftwareSigner::new(
            "validation".into(),
            BackendKind::SystemdCreds,
            algorithm,
            secret,
        )
        .is_ok()
        {
            return Ok(secret);
        }
    }
}

fn default_storage_root() -> Result<PathBuf> {
    if let Some(data_home) = std::env::var_os("XDG_DATA_HOME") {
        return Ok(PathBuf::from(data_home).join("mkit").join("systemd-creds"));
    }
    let Some(home) = std::env::var_os("HOME") else {
        return Err(Error::BackendUnavailable(
            "HOME is unset and XDG_DATA_HOME is unset".into(),
        ));
    };
    Ok(PathBuf::from(home)
        .join(".local")
        .join("share")
        .join("mkit")
        .join("systemd-creds"))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn hex_decode(input: &str) -> Result<Vec<u8>> {
    if !input.len().is_multiple_of(2) {
        return Err(Error::Encoding("hex string has odd length".into()));
    }
    let mut out = Vec::with_capacity(input.len() / 2);
    for chunk in input.as_bytes().chunks_exact(2) {
        let hi = hex_value(chunk[0])?;
        let lo = hex_value(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_value(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(Error::Encoding("invalid lowercase hex".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capabilities_are_backend_accurate() {
        let capabilities = systemd_creds_capabilities(true);
        assert_eq!(capabilities.backend, BackendKind::SystemdCreds);
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
        let capabilities = systemd_creds_capabilities(false);
        assert_eq!(capabilities.backend, BackendKind::SystemdCreds);
        assert!(capabilities.algorithms.is_empty());
        assert!(!capabilities.can_generate);
        assert!(!capabilities.can_import);
        assert!(!capabilities.can_export);
        assert!(!capabilities.can_delete);
        assert!(!capabilities.supports_listing);
    }

    #[test]
    fn runtime_probe_reports_missing_systemd_creds_unavailable() {
        assert!(!systemd_creds_runtime_available_with_command(
            "mkit-systemd-creds-missing-test-command"
        ));
    }

    #[test]
    fn credential_names_bind_algorithm_and_label() {
        assert_eq!(
            SystemdCredsKeystore::credential_name("release", Algorithm::Ed25519).unwrap(),
            "mkit.ed25519.release"
        );
    }

    #[test]
    fn temp_credential_path_is_hidden_sibling() {
        let dir = tempfile::tempdir().expect("tempdir");
        let final_path = dir.path().join("release.cred");
        let temp_path = temp_credential_path(&final_path).expect("temp path");

        assert_eq!(temp_path.parent(), final_path.parent());
        let filename = temp_path
            .file_name()
            .and_then(|name| name.to_str())
            .expect("temp filename");
        assert!(filename.starts_with(".release.cred."));
        assert!(
            filename
                .rsplit_once('.')
                .is_some_and(|(_, extension)| extension == "tmp")
        );
        assert_ne!(temp_path, final_path);
    }

    #[cfg(unix)]
    #[test]
    fn prepare_write_path_hardens_parent_directories() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let dir = tempfile::tempdir().expect("tempdir");
        let store = SystemdCredsKeystore::with_root(dir.path().join("systemd-creds"));
        let path = store.path_for("release", Algorithm::Ed25519).unwrap();

        store.prepare_write_path(&path).expect("prepare write path");

        let root_metadata = std::fs::metadata(&store.root).expect("root metadata");
        let parent = path.parent().expect("key parent");
        let parent_metadata = std::fs::metadata(parent).expect("parent metadata");
        assert_eq!(root_metadata.permissions().mode() & 0o777, 0o700);
        assert_eq!(parent_metadata.permissions().mode() & 0o777, 0o700);
        assert_eq!(root_metadata.uid(), mkit_core::sign::effective_uid());
        assert_eq!(parent_metadata.uid(), mkit_core::sign::effective_uid());
    }

    #[cfg(unix)]
    #[test]
    fn prepare_write_path_rejects_symlinked_algorithm_dir() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("systemd-creds");
        let real_algorithm_dir = dir.path().join("real-ed25519");
        std::fs::create_dir_all(&root).expect("root");
        std::fs::create_dir_all(&real_algorithm_dir).expect("real algorithm dir");
        std::os::unix::fs::symlink(&real_algorithm_dir, root.join("ed25519"))
            .expect("algorithm dir symlink");
        let store = SystemdCredsKeystore::with_root(root);
        let path = store.path_for("release", Algorithm::Ed25519).unwrap();

        let result = store.prepare_write_path(&path);

        assert!(matches!(result, Err(Error::Io(message)) if message.contains("symlink")));
    }

    #[cfg(unix)]
    #[test]
    fn create_new_publish_refuses_existing_final_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let tmp_path = dir.path().join("tmp.cred");
        let final_path = dir.path().join("release.cred");
        std::fs::write(&tmp_path, b"new").expect("tmp credential");
        std::fs::write(&final_path, b"old").expect("existing credential");

        let error = publish_temp_credential_create_new(&tmp_path, &final_path)
            .expect_err("create-new publish must not replace existing file");

        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&final_path).expect("final bytes"), b"old");
        assert_eq!(std::fs::read(&tmp_path).expect("tmp bytes"), b"new");
    }

    #[test]
    fn invalid_ecdsa_import_rejected_before_credential_write() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = SystemdCredsKeystore::with_root(dir.path().join("systemd-creds"));
        let result = store.import(
            "invalid",
            SecretKey::new(Algorithm::P256, [0; 32]),
            KeyAttrs::default(),
            ImportOptions::default(),
        );

        assert!(matches!(result, Err(Error::InvalidKeyMaterial { .. })));
        assert!(
            !store.path_for("invalid", Algorithm::P256).unwrap().exists(),
            "invalid import must not leave a credential file"
        );
    }

    #[test]
    fn list_metadata_skips_invalid_ecdsa_secret() {
        let invalid = SecretKey::new(Algorithm::P256, [0; 32]);
        assert!(
            SystemdCredsKeystore::list_metadata_for("invalid".into(), Algorithm::P256, &invalid)
                .unwrap()
                .is_none()
        );

        let valid = SecretKey::new(Algorithm::Ed25519, [1; 32]);
        let metadata =
            SystemdCredsKeystore::list_metadata_for("valid".into(), Algorithm::Ed25519, &valid)
                .unwrap()
                .expect("valid metadata should list");
        assert_eq!(metadata.label, "valid");
        assert_eq!(metadata.algorithm, Algorithm::Ed25519);
    }

    #[test]
    fn list_secret_skips_corrupt_decrypt_status_but_exact_decrypt_fails() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = SystemdCredsKeystore::with_root(dir.path().join("systemd-creds"));
        let path = store.path_for("corrupt", Algorithm::Ed25519).unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).expect("algorithm dir");
        std::fs::write(&path, b"not a systemd credential").expect("corrupt credential");

        assert!(
            store
                .load_secret_for_list_with_command("corrupt", Algorithm::Ed25519, "false")
                .unwrap()
                .is_none()
        );

        assert!(matches!(
            decrypt_credential_with_command(
                "false",
                &path,
                &SystemdCredsKeystore::credential_name("corrupt", Algorithm::Ed25519).unwrap(),
            ),
            Err(Error::BackendUnavailable(_))
        ));
    }

    #[test]
    fn list_secret_does_not_hide_missing_systemd_creds_command() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = SystemdCredsKeystore::with_root(dir.path().join("systemd-creds"));
        let path = store.path_for("release", Algorithm::Ed25519).unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).expect("algorithm dir");
        std::fs::write(&path, b"credential").expect("credential");

        let result = store.load_secret_for_list_with_command(
            "release",
            Algorithm::Ed25519,
            "mkit-systemd-creds-missing-test-command",
        );

        assert!(matches!(
            result,
            Err(Error::BackendUnavailable(message)) if message.contains("executable was not found")
        ));
    }

    #[test]
    fn live_backend_create_open_list_export_delete_roundtrip() {
        if std::env::var_os("MKIT_RUN_SYSTEMD_CREDS_TESTS").as_deref() != Some("1".as_ref()) {
            eprintln!(
                "skipping systemd-creds live backend roundtrip; set MKIT_RUN_SYSTEMD_CREDS_TESTS=1 to run"
            );
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let store = SystemdCredsKeystore::with_root(dir.path().join("systemd-creds"));
        crate::native_list::run_required_native_backend_roundtrip_test(&store);
    }
}
