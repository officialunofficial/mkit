//! Linux systemd-creds-backed keystore.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use zeroize::Zeroize;

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
        let plaintext = decrypt_credential(&path, &Self::credential_name(label, algorithm)?)?;
        let secret: [u8; 32] =
            plaintext
                .try_into()
                .map_err(|plaintext: Vec<u8>| Error::InvalidKeyMaterial {
                    algorithm,
                    reason: format!("expected 32 bytes, got {}", plaintext.len()),
                })?;
        Ok(SecretKey::new(algorithm, secret))
    }

    fn metadata_for(
        &self,
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
}

impl Default for SystemdCredsKeystore {
    fn default() -> Self {
        Self::new().expect("default systemd-creds keystore root should be discoverable")
    }
}

impl Keystore for SystemdCredsKeystore {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            backend: BackendKind::SystemdCreds,
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
        let path = self.path_for(label, secret.algorithm())?;
        self.ensure_storage_path_not_symlink(&path)?;
        if path.exists() && !options.overwrite {
            return Err(Error::KeyAlreadyExists {
                label: label.into(),
                algorithm: secret.algorithm(),
            });
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| Error::Io(format!("mkdir {}: {error}", parent.display())))?;
        }
        encrypt_credential(
            secret.expose_secret(),
            &path,
            &Self::credential_name(label, secret.algorithm())?,
        )?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .map_err(|error| Error::Io(format!("chmod {}: {error}", path.display())))?;
        }
        Ok(Box::new(SoftwareSigner::new(
            label.into(),
            BackendKind::SystemdCreds,
            secret.algorithm(),
            *secret.expose_secret(),
        )?))
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
                if path.extension().and_then(|extension| extension.to_str()) != Some("cred") {
                    continue;
                }
                let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
                    continue;
                };
                let label = String::from_utf8(hex_decode(stem)?).map_err(|error| {
                    Error::Encoding(format!(
                        "stored label is not UTF-8 in {}: {error}",
                        path.display()
                    ))
                })?;
                validate_label(&label)?;
                let secret = self.load_secret(&label, algorithm)?;
                out.push(self.metadata_for(label, algorithm, &secret)?);
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

    fn resolve_selector_algorithm(&self, selector: &KeySelector) -> Result<Algorithm> {
        if let Some(algorithm) = selector.algorithm {
            return Ok(algorithm);
        }
        let matches: Vec<_> = self
            .list()?
            .into_iter()
            .filter(|metadata| metadata.label == selector.label)
            .collect();
        match matches.as_slice() {
            [] => Err(Error::KeyNotFound(selector.clone())),
            [metadata] => Ok(metadata.algorithm),
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

fn encrypt_credential(secret: &[u8; 32], path: &Path, name: &str) -> Result<()> {
    let mut child = Command::new("systemd-creds")
        .args(["--user", "--uid=self", "--with-key=auto", "--name", name])
        .arg("encrypt")
        .arg("-")
        .arg(path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(systemd_creds_spawn_error)?;
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
        Err(systemd_creds_status_error("encrypt", output))
    }
}

fn decrypt_credential(path: &Path, name: &str) -> Result<Vec<u8>> {
    let output = Command::new("systemd-creds")
        .args(["--user", "--uid=self", "--name", name])
        .arg("decrypt")
        .arg(path)
        .arg("-")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(systemd_creds_spawn_error)?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(systemd_creds_status_error("decrypt", output))
    }
}

fn systemd_creds_spawn_error(error: std::io::Error) -> Error {
    if error.kind() == std::io::ErrorKind::NotFound {
        Error::BackendUnavailable("systemd-creds executable was not found".into())
    } else {
        Error::Io(format!("systemd-creds spawn: {error}"))
    }
}

fn systemd_creds_status_error(operation: &str, output: std::process::Output) -> Error {
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
        let store = SystemdCredsKeystore::with_root("/tmp/mkit-systemd-creds-test");
        let capabilities = store.capabilities();
        assert_eq!(capabilities.backend, BackendKind::SystemdCreds);
        assert!(capabilities.can_generate);
        assert!(capabilities.can_import);
        assert!(capabilities.can_export);
        assert!(capabilities.can_delete);
        assert!(capabilities.supports_listing);
        assert!(!capabilities.supports_device_bound);
    }

    #[test]
    fn credential_names_bind_algorithm_and_label() {
        assert_eq!(
            SystemdCredsKeystore::credential_name("release", Algorithm::Ed25519).unwrap(),
            "mkit.ed25519.release"
        );
    }
}
