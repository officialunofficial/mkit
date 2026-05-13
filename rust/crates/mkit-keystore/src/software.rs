//! User-scoped software compatibility backend.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use ed25519_dalek::{Signer as _, SigningKey as Ed25519SigningKey};
use k256::ecdsa::{Signature as K256Signature, SigningKey as K256SigningKey};
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::encrypted_record::{EncryptedKeyRecord, KeyProtector};
use crate::{
    Algorithm, BackendKind, Capabilities, Error, GenerateOptions, ImportOptions, KeyAttrs,
    KeyMetadata, KeySelector, KeySigner, Keystore, Result, SecretKey, validate_label,
};

/// Persistent Foundation V1 software keystore.
#[derive(Clone, Debug)]
pub struct SoftwareKeystore {
    root: PathBuf,
    backend: BackendKind,
    protector: Option<Arc<dyn KeyProtector>>,
}

/// Explicit raw-file compatibility backend.
#[derive(Clone, Debug)]
pub struct SoftwareRawKeystore {
    inner: SoftwareKeystore,
}

impl SoftwareKeystore {
    /// Create a software keystore using the default user-scoped root.
    pub fn new() -> Result<Self> {
        Self::new_with_backend(BackendKind::Software)
    }

    fn new_with_backend(backend: BackendKind) -> Result<Self> {
        Ok(Self {
            root: default_storage_root()?,
            backend,
            protector: None,
        })
    }

    /// Create a software keystore at an explicit root, useful for tests.
    #[must_use]
    pub fn with_root(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            backend: BackendKind::Software,
            protector: None,
        }
    }

    fn with_root_and_backend(root: impl Into<PathBuf>, backend: BackendKind) -> Self {
        Self {
            root: root.into(),
            backend,
            protector: None,
        }
    }

    #[cfg(test)]
    fn with_root_and_protector(root: impl Into<PathBuf>, protector: Arc<dyn KeyProtector>) -> Self {
        Self {
            root: root.into(),
            backend: BackendKind::Software,
            protector: Some(protector),
        }
    }

    /// Storage root for this backend.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn path_for(&self, label: &str, algorithm: Algorithm) -> Result<PathBuf> {
        validate_label(label)?;
        Ok(self.dir_for(algorithm).join(format!(
            "{}.{}",
            hex_lower(label.as_bytes()),
            self.extension()
        )))
    }

    fn dir_for(&self, algorithm: Algorithm) -> PathBuf {
        if self.is_raw() {
            self.root.join("raw").join(algorithm.as_str())
        } else {
            self.root.join(algorithm.as_str())
        }
    }

    fn extension(&self) -> &'static str {
        if self.is_raw() { "raw" } else { "key" }
    }

    fn is_raw(&self) -> bool {
        self.backend == BackendKind::SoftwareRaw
    }

    fn metadata_for_secret(
        &self,
        label: String,
        algorithm: Algorithm,
        secret: &SecretKey,
    ) -> Result<KeyMetadata> {
        let signer = SoftwareSigner::new(
            label.clone(),
            self.backend.clone(),
            secret.algorithm(),
            *secret.expose_secret(),
        )?;
        Ok(KeyMetadata {
            label,
            backend: self.backend.clone(),
            algorithm,
            public_key: signer.public_key()?,
            keyid: signer.keyid()?,
            extractable: true,
            require_user_presence: false,
            device_bound: false,
        })
    }

    fn metadata_for_record(&self, label: String, record: &EncryptedKeyRecord) -> KeyMetadata {
        KeyMetadata {
            label,
            backend: self.backend.clone(),
            algorithm: record.algorithm,
            public_key: record.public_key.clone(),
            keyid: record.keyid.clone(),
            extractable: record.attrs.extractable,
            require_user_presence: record.attrs.require_user_presence,
            device_bound: record.attrs.device_bound,
        }
    }

    fn load_secret(&self, label: &str, algorithm: Algorithm) -> Result<SecretKey> {
        if !self.is_raw() {
            let record = self.load_record(label, algorithm)?;
            let protector = self.protector_for_record(&record)?;
            return record.decrypt(label, protector.as_ref());
        }
        let path = self.path_for(label, algorithm)?;
        self.ensure_storage_path_not_symlink(&path)?;
        if !path.exists() {
            return Err(Error::KeyNotFound(KeySelector {
                label: label.into(),
                algorithm: Some(algorithm),
            }));
        }
        let bytes = mkit_core::sign::load_raw_32(&path).map_err(core_error)?;
        Ok(SecretKey::new(algorithm, *bytes))
    }

    fn load_record(&self, label: &str, algorithm: Algorithm) -> Result<EncryptedKeyRecord> {
        let path = self.path_for(label, algorithm)?;
        self.ensure_storage_path_not_symlink(&path)?;
        if !path.exists() {
            return Err(Error::KeyNotFound(KeySelector {
                label: label.into(),
                algorithm: Some(algorithm),
            }));
        }
        let bytes = std::fs::read(&path)
            .map_err(|error| Error::Io(format!("read {}: {error}", path.display())))?;
        let record = EncryptedKeyRecord::decode(&bytes)?;
        if record.algorithm != algorithm {
            return Err(Error::Encoding(format!(
                "software key record algorithm mismatch: path has {algorithm}, record has {}",
                record.algorithm
            )));
        }
        Ok(record)
    }

    fn protector_for_write(&self) -> Result<Arc<dyn KeyProtector>> {
        if let Some(protector) = &self.protector {
            return Ok(Arc::clone(protector));
        }
        default_protector_for_write(&self.root)
    }

    fn protector_for_record(&self, record: &EncryptedKeyRecord) -> Result<Arc<dyn KeyProtector>> {
        if let Some(protector) = &self.protector
            && protector.id() == record.protector
        {
            return Ok(Arc::clone(protector));
        }
        default_protector_by_id(&self.root, &record.protector)
    }
}

impl Default for SoftwareKeystore {
    fn default() -> Self {
        Self::new().expect("default software keystore root should be discoverable")
    }
}

impl SoftwareRawKeystore {
    /// Create a raw-file compatibility keystore using the default user-scoped root.
    pub fn new() -> Result<Self> {
        Ok(Self {
            inner: SoftwareKeystore::new_with_backend(BackendKind::SoftwareRaw)?,
        })
    }

    /// Create a raw-file compatibility keystore at an explicit root.
    #[must_use]
    pub fn with_root(root: impl Into<PathBuf>) -> Self {
        Self {
            inner: SoftwareKeystore::with_root_and_backend(root, BackendKind::SoftwareRaw),
        }
    }

    /// Storage root for this backend.
    #[must_use]
    pub fn root(&self) -> &Path {
        self.inner.root()
    }
}

impl Default for SoftwareRawKeystore {
    fn default() -> Self {
        Self::new().expect("default software-raw keystore root should be discoverable")
    }
}

impl Keystore for SoftwareRawKeystore {
    fn capabilities(&self) -> Capabilities {
        self.inner.capabilities()
    }

    fn generate(
        &self,
        label: &str,
        algorithm: Algorithm,
        attrs: KeyAttrs,
        options: GenerateOptions,
    ) -> Result<Box<dyn KeySigner>> {
        self.inner.generate(label, algorithm, attrs, options)
    }

    fn import(
        &self,
        label: &str,
        secret: SecretKey,
        attrs: KeyAttrs,
        options: ImportOptions,
    ) -> Result<Box<dyn KeySigner>> {
        self.inner.import(label, secret, attrs, options)
    }

    fn open(&self, selector: &KeySelector) -> Result<Box<dyn KeySigner>> {
        self.inner.open(selector)
    }

    fn list(&self) -> Result<Vec<KeyMetadata>> {
        self.inner.list()
    }

    fn export(&self, selector: &KeySelector) -> Result<SecretKey> {
        self.inner.export(selector)
    }

    fn delete(&self, selector: &KeySelector) -> Result<()> {
        self.inner.delete(selector)
    }
}

impl Keystore for SoftwareKeystore {
    fn capabilities(&self) -> Capabilities {
        let can_use_secret_material = self.can_use_secret_material();
        Capabilities {
            backend: self.backend.clone(),
            algorithms: vec![Algorithm::Ed25519, Algorithm::Secp256k1, Algorithm::P256],
            can_generate: can_use_secret_material,
            can_import: can_use_secret_material,
            can_export: can_use_secret_material,
            can_delete: can_use_secret_material,
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
        validate_label(label)?;
        validate_secret(secret.algorithm(), secret.expose_secret())?;
        let path = self.path_for(label, secret.algorithm())?;
        self.ensure_storage_path_not_symlink(&path)?;
        if self.is_raw() && options.overwrite {
            mkit_core::sign::save_raw_32(&path, secret.expose_secret()).map_err(core_error)?;
        } else if self.is_raw() {
            let created = mkit_core::sign::save_raw_32_create_new(&path, secret.expose_secret())
                .map_err(core_error)?;
            if !created {
                return Err(Error::KeyAlreadyExists {
                    label: label.into(),
                    algorithm: secret.algorithm(),
                });
            }
        } else {
            let signer = SoftwareSigner::new(
                label.into(),
                self.backend.clone(),
                secret.algorithm(),
                *secret.expose_secret(),
            )?;
            let protector = self.protector_for_write()?;
            let record = EncryptedKeyRecord::encrypt(
                label,
                &secret,
                attrs,
                signer.public_key()?,
                signer.keyid()?,
                protector.as_ref(),
            )?;
            write_key_file(
                &self.root,
                &path,
                label,
                secret.algorithm(),
                &record.encode()?,
                options.overwrite,
            )?;
            return Ok(Box::new(signer));
        }
        Ok(Box::new(SoftwareSigner::new(
            label.into(),
            self.backend.clone(),
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
            self.backend.clone(),
            algorithm,
            *secret.expose_secret(),
        )?))
    }

    fn list(&self) -> Result<Vec<KeyMetadata>> {
        let mut out = Vec::new();
        for algorithm in [Algorithm::Ed25519, Algorithm::Secp256k1, Algorithm::P256] {
            let dir = self.dir_for(algorithm);
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
                if path.extension().and_then(|extension| extension.to_str())
                    != Some(self.extension())
                {
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
                if self.is_raw() {
                    let secret = self.load_secret(&label, algorithm)?;
                    out.push(self.metadata_for_secret(label, algorithm, &secret)?);
                } else {
                    let record = self.load_record(&label, algorithm)?;
                    out.push(self.metadata_for_record(label, &record));
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
        let signer = self.open(selector)?;
        self.load_secret(signer.label(), signer.algorithm())
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
        if !self.is_raw() {
            let record = self.load_record(&selector.label, algorithm)?;
            let protector = self.protector_for_record(&record)?;
            protector.delete_wrapped_dek(record.wrapped_dek())?;
        }
        std::fs::remove_file(&path)
            .map_err(|error| Error::Io(format!("delete {}: {error}", path.display())))
    }
}

impl SoftwareKeystore {
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

    #[cfg(not(unix))]
    fn ensure_storage_path_not_symlink(&self, _path: &Path) -> Result<()> {
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

    fn can_use_secret_material(&self) -> bool {
        self.is_raw() || self.protector_for_write().is_ok()
    }
}

/// Software signer backed by in-memory secret material loaded from the software backend.
pub struct SoftwareSigner {
    label: String,
    backend: BackendKind,
    secret: SecretKey,
}

impl SoftwareSigner {
    pub(crate) fn new(
        label: String,
        backend: BackendKind,
        algorithm: Algorithm,
        mut secret: [u8; 32],
    ) -> Result<Self> {
        validate_secret(algorithm, &secret)?;
        let wrapped = SecretKey::new(algorithm, secret);
        secret.zeroize();
        Ok(Self {
            label,
            backend,
            secret: wrapped,
        })
    }
}

impl std::fmt::Debug for SoftwareSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SoftwareSigner")
            .field("label", &self.label)
            .field("backend", &self.backend)
            .field("algorithm", &self.secret.algorithm())
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl KeySigner for SoftwareSigner {
    fn algorithm(&self) -> Algorithm {
        self.secret.algorithm()
    }

    fn label(&self) -> &str {
        &self.label
    }

    fn metadata(&self) -> Result<KeyMetadata> {
        Ok(KeyMetadata {
            label: self.label.clone(),
            backend: self.backend.clone(),
            algorithm: self.algorithm(),
            public_key: self.public_key()?,
            keyid: self.keyid()?,
            extractable: true,
            require_user_presence: false,
            device_bound: false,
        })
    }

    fn public_key(&self) -> Result<Vec<u8>> {
        public_key(self.algorithm(), self.secret.expose_secret())
    }

    fn keyid(&self) -> Result<String> {
        let public_key = self.public_key()?;
        Ok(format!("{}:{}", self.algorithm(), hex_lower(&public_key)))
    }

    fn sign(&mut self, msg: &[u8]) -> Result<Vec<u8>> {
        sign_message(self.algorithm(), self.secret.expose_secret(), msg)
    }
}

fn validate_attrs(attrs: &KeyAttrs) -> Result<()> {
    if !attrs.extractable {
        return Err(Error::UnsupportedAttributes(
            "software backend does not support non-extractable keys in Foundation V1".into(),
        ));
    }
    if attrs.require_user_presence {
        return Err(Error::UnsupportedAttributes(
            "software backend does not support user presence".into(),
        ));
    }
    if attrs.device_bound {
        return Err(Error::UnsupportedAttributes(
            "software backend does not support device-bound keys".into(),
        ));
    }
    Ok(())
}

fn validate_secret(algorithm: Algorithm, secret: &[u8; 32]) -> Result<()> {
    match algorithm {
        Algorithm::Ed25519 => {
            let _ = Ed25519SigningKey::from_bytes(secret);
            Ok(())
        }
        Algorithm::Secp256k1 => K256SigningKey::from_bytes(secret.into())
            .map(|_| ())
            .map_err(|_| invalid_key_material(algorithm, "invalid secp256k1 scalar")),
        Algorithm::P256 => P256SigningKey::from_bytes(secret.into())
            .map(|_| ())
            .map_err(|_| invalid_key_material(algorithm, "invalid P-256 scalar")),
    }
}

fn public_key(algorithm: Algorithm, secret: &[u8; 32]) -> Result<Vec<u8>> {
    match algorithm {
        Algorithm::Ed25519 => Ok(Ed25519SigningKey::from_bytes(secret)
            .verifying_key()
            .to_bytes()
            .to_vec()),
        Algorithm::Secp256k1 => Ok(K256SigningKey::from_bytes(secret.into())
            .map_err(|_| invalid_key_material(algorithm, "invalid secp256k1 scalar"))?
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec()),
        Algorithm::P256 => Ok(P256SigningKey::from_bytes(secret.into())
            .map_err(|_| invalid_key_material(algorithm, "invalid P-256 scalar"))?
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec()),
    }
}

fn sign_message(algorithm: Algorithm, secret: &[u8; 32], msg: &[u8]) -> Result<Vec<u8>> {
    match algorithm {
        Algorithm::Ed25519 => Ok(Ed25519SigningKey::from_bytes(secret)
            .sign(msg)
            .to_bytes()
            .to_vec()),
        Algorithm::Secp256k1 => {
            use k256::ecdsa::signature::DigestSigner as _;
            let key = K256SigningKey::from_bytes(secret.into())
                .map_err(|_| invalid_key_material(algorithm, "invalid secp256k1 scalar"))?;
            let mut hash = Sha256::new();
            hash.update(msg);
            let sig: K256Signature = key
                .try_sign_digest(hash)
                .map_err(|_| Error::Internal("secp256k1 signing failed".into()))?;
            let sig = sig.normalize_s().unwrap_or(sig);
            Ok(sig.to_bytes().to_vec())
        }
        Algorithm::P256 => {
            use p256::ecdsa::signature::Signer as _;
            let key = P256SigningKey::from_bytes(secret.into())
                .map_err(|_| invalid_key_material(algorithm, "invalid P-256 scalar"))?;
            let sig: P256Signature = key.sign(msg);
            let sig = sig.normalize_s().unwrap_or(sig);
            Ok(sig.to_bytes().to_vec())
        }
    }
}

fn random_valid_secret(algorithm: Algorithm) -> Result<[u8; 32]> {
    let mut secret = [0u8; 32];
    loop {
        getrandom::fill(&mut secret).map_err(|_| Error::Internal("rng failed".into()))?;
        if validate_secret(algorithm, &secret).is_ok() {
            return Ok(secret);
        }
    }
}

fn write_key_file(
    root: &Path,
    path: &Path,
    label: &str,
    algorithm: Algorithm,
    bytes: &[u8],
    overwrite: bool,
) -> Result<()> {
    #[cfg(unix)]
    return write_key_file_unix(root, path, label, algorithm, bytes, overwrite);

    #[cfg(not(unix))]
    {
        let _ = root;
        return write_key_file_portable(path, label, algorithm, bytes, overwrite);
    }
}

#[cfg(unix)]
fn write_key_file_unix(
    root: &Path,
    path: &Path,
    label: &str,
    algorithm: Algorithm,
    bytes: &[u8],
    overwrite: bool,
) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    ensure_no_symlink_path(root, parent)?;
    std::fs::create_dir_all(parent)
        .map_err(|error| Error::Io(format!("mkdir {}: {error}", parent.display())))?;
    set_private_dir_permissions(root)?;
    ensure_owned_by_euid(root)?;
    if parent != root {
        set_private_dir_permissions(parent)?;
        ensure_owned_by_euid(parent)?;
    }

    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(Error::Io(format!(
                "keystore path is a symlink: {}",
                path.display()
            )));
        }
        Ok(metadata) => {
            if !overwrite {
                return Err(Error::KeyAlreadyExists {
                    label: label.into(),
                    algorithm,
                });
            }
            if metadata.uid() != euid() {
                return Err(Error::AccessDenied(format!(
                    "existing key file is owned by uid {}, expected {}: {}",
                    metadata.uid(),
                    euid(),
                    path.display()
                )));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(Error::Io(format!("lstat {}: {error}", path.display()))),
    }

    let filename = path
        .file_name()
        .ok_or_else(|| Error::Io(format!("path has no filename: {}", path.display())))?;
    let tmp_path = create_synced_tmp_key_file(parent, filename, bytes)?;

    if overwrite {
        if let Err(error) = std::fs::rename(&tmp_path, path) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(Error::Io(format!("rename {}: {error}", path.display())));
        }
    } else if let Err(error) = std::fs::hard_link(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return if error.kind() == std::io::ErrorKind::AlreadyExists {
            Err(Error::KeyAlreadyExists {
                label: label.into(),
                algorithm,
            })
        } else {
            Err(Error::Io(format!("link {}: {error}", path.display())))
        };
    } else if let Err(error) = std::fs::remove_file(&tmp_path) {
        return Err(Error::Io(format!(
            "unlink tmp {}: {error}",
            tmp_path.display()
        )));
    }

    let dir = std::fs::File::open(parent)
        .map_err(|error| Error::Io(format!("open dir for fsync: {error}")))?;
    dir.sync_all()
        .map_err(|error| Error::Io(format!("fsync dir: {error}")))
}

#[cfg(unix)]
fn create_synced_tmp_key_file(
    parent: &Path,
    filename: &std::ffi::OsStr,
    bytes: &[u8],
) -> Result<PathBuf> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut tmp_path = temp_key_file_path(parent, filename, 0);
    for attempt in 0..16u8 {
        if attempt > 0 {
            tmp_path = temp_key_file_path(parent, filename, attempt);
        }
        let mut file = match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o600)
            .open(&tmp_path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(Error::Io(format!(
                    "open tmp {}: {error}",
                    tmp_path.display()
                )));
            }
        };
        if let Err(error) = file.write_all(bytes) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(Error::Io(format!(
                "write tmp {}: {error}",
                tmp_path.display()
            )));
        }
        if let Err(error) = file.sync_all() {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(Error::Io(format!(
                "fsync tmp {}: {error}",
                tmp_path.display()
            )));
        }
        drop(file);
        return Ok(tmp_path);
    }
    Err(Error::Io(format!(
        "could not create unique temp file under {}",
        parent.display()
    )))
}

#[cfg(unix)]
fn temp_key_file_path(parent: &Path, filename: &std::ffi::OsStr, attempt: u8) -> PathBuf {
    if attempt == 0 {
        parent.join(format!(
            ".{}.tmp.{}",
            filename.to_string_lossy(),
            std::process::id()
        ))
    } else {
        parent.join(format!(
            ".{}.tmp.{}.{}",
            filename.to_string_lossy(),
            std::process::id(),
            attempt
        ))
    }
}

#[cfg(unix)]
fn ensure_no_symlink_path(root: &Path, path: &Path) -> Result<()> {
    let mut current = Some(path);
    while let Some(candidate) = current {
        if !candidate.starts_with(root) {
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
            Err(error) => return Err(Error::Io(format!("lstat {}: {error}", candidate.display()))),
        }
        if candidate == root {
            break;
        }
        current = candidate.parent();
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_owned_by_euid(path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = std::fs::metadata(path)
        .map_err(|error| Error::Io(format!("metadata {}: {error}", path.display())))?;
    let actual = metadata.uid();
    let expected = euid();
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

#[cfg(unix)]
fn euid() -> u32 {
    mkit_core::sign::effective_uid()
}

#[cfg(not(unix))]
fn write_key_file_portable(
    path: &Path,
    label: &str,
    algorithm: Algorithm,
    bytes: &[u8],
    overwrite: bool,
) -> Result<()> {
    use std::io::Write as _;

    if path.exists() && !overwrite {
        return Err(Error::KeyAlreadyExists {
            label: label.into(),
            algorithm,
        });
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| Error::Io(format!("mkdir {}: {error}", parent.display())))?;
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let filename = path
        .file_name()
        .ok_or_else(|| Error::Io(format!("path has no filename: {}", path.display())))?;
    let tmp_path = parent.join(format!(
        ".{}.tmp.{}",
        filename.to_string_lossy(),
        std::process::id()
    ));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp_path)
        .map_err(|error| Error::Io(format!("open tmp {}: {error}", tmp_path.display())))?;
    file.write_all(bytes)
        .map_err(|error| Error::Io(format!("write tmp {}: {error}", tmp_path.display())))?;
    file.sync_all()
        .map_err(|error| Error::Io(format!("fsync tmp {}: {error}", tmp_path.display())))?;
    drop(file);
    if let Err(error) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(Error::Io(format!("rename {}: {error}", path.display())));
    }
    Ok(())
}

#[allow(unreachable_code)]
fn default_protector_for_write(root: &Path) -> Result<Arc<dyn KeyProtector>> {
    #[cfg(all(target_os = "macos", feature = "macos-keychain"))]
    {
        let _ = root;
        return Ok(Arc::new(MacosKeychainProtector));
    }
    #[cfg(all(windows, feature = "windows-credential"))]
    {
        let _ = root;
        return Ok(Arc::new(WindowsCredentialProtector));
    }
    #[cfg(target_os = "linux")]
    {
        #[cfg(feature = "linux-secret-service")]
        if linux_desktop_session_available() && LinuxSecretServiceProtector::available() {
            let _ = root;
            return Ok(Arc::new(LinuxSecretServiceProtector));
        }
        #[cfg(feature = "systemd-creds")]
        {
            return systemd_creds_protector(root);
        }
    }
    let _ = root;
    Err(Error::BackendUnavailable(
        "software backend requires an OS key protector feature for encrypted storage".into(),
    ))
}

fn default_protector_by_id(_root: &Path, id: &str) -> Result<Arc<dyn KeyProtector>> {
    match id {
        #[cfg(all(target_os = "macos", feature = "macos-keychain"))]
        MacosKeychainProtector::ID => Ok(Arc::new(MacosKeychainProtector)),
        #[cfg(all(windows, feature = "windows-credential"))]
        WindowsCredentialProtector::ID => Ok(Arc::new(WindowsCredentialProtector)),
        #[cfg(all(target_os = "linux", feature = "linux-secret-service"))]
        LinuxSecretServiceProtector::ID => Ok(Arc::new(LinuxSecretServiceProtector)),
        #[cfg(all(target_os = "linux", feature = "systemd-creds"))]
        SystemdCredsProtector::ID => systemd_creds_protector(_root),
        _ => Err(Error::BackendUnavailable(format!(
            "software key record requires unavailable protector `{id}`"
        ))),
    }
}

#[allow(dead_code)]
fn random_handle() -> Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| Error::Internal("rng failed".into()))?;
    Ok(hex_lower(&bytes))
}

#[cfg(all(target_os = "macos", feature = "macos-keychain"))]
#[derive(Debug)]
struct MacosKeychainProtector;

#[cfg(all(target_os = "macos", feature = "macos-keychain"))]
impl MacosKeychainProtector {
    const ID: &'static str = "macos-keychain";
    const SERVICE: &'static str = "dev.mkit.keystore.software-dek.v1";
}

#[cfg(all(target_os = "macos", feature = "macos-keychain"))]
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
        let secret: [u8; 32] = secret
            .as_slice()
            .try_into()
            .map_err(|_| Error::Encoding(format!("protected DEK length: {}", secret.len())))?;
        Ok(zeroize::Zeroizing::new(secret))
    }

    fn delete_wrapped_dek(&self, wrapped: &[u8]) -> Result<()> {
        let account = std::str::from_utf8(wrapped)
            .map_err(|error| Error::Encoding(format!("protector handle is not UTF-8: {error}")))?;
        security_framework::passwords::delete_generic_password(Self::SERVICE, account).map_err(
            |error| Error::Io(format!("macOS Keychain software protector delete: {error}")),
        )
    }
}

#[cfg(all(windows, feature = "windows-credential"))]
#[derive(Debug)]
struct WindowsCredentialProtector;

#[cfg(all(windows, feature = "windows-credential"))]
impl WindowsCredentialProtector {
    const ID: &'static str = "windows-credential";
    const SERVICE: &'static str = "dev.mkit.keystore.software-dek.v1";

    fn entry(account: &str) -> Result<keyring_core::Entry> {
        let store = windows_native_keyring_store::Store::new().map_err(|error| {
            Error::BackendUnavailable(format!("Windows Credential software protector: {error}"))
        })?;
        keyring_core::set_default_store(store);
        keyring_core::Entry::new(Self::SERVICE, account)
            .map_err(|error| Error::Io(format!("Windows Credential software protector: {error}")))
    }
}

#[cfg(all(windows, feature = "windows-credential"))]
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
        let secret: [u8; 32] = secret
            .as_slice()
            .try_into()
            .map_err(|_| Error::Encoding(format!("protected DEK length: {}", secret.len())))?;
        Ok(zeroize::Zeroizing::new(secret))
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

#[cfg(all(target_os = "linux", feature = "linux-secret-service"))]
#[derive(Debug)]
struct LinuxSecretServiceProtector;

#[cfg(all(target_os = "linux", feature = "linux-secret-service"))]
impl LinuxSecretServiceProtector {
    const ID: &'static str = "linux-secret-service";
    const SERVICE: &'static str = "dev.mkit.keystore.software-dek.v1";

    fn available() -> bool {
        zbus_secret_service_keyring_store::Store::new().is_ok()
    }

    fn entry(account: &str) -> Result<keyring_core::Entry> {
        let store = zbus_secret_service_keyring_store::Store::new().map_err(|error| {
            Error::BackendUnavailable(format!("Linux Secret Service software protector: {error}"))
        })?;
        keyring_core::set_default_store(store);
        keyring_core::Entry::new(Self::SERVICE, account)
            .map_err(|error| Error::Io(format!("Linux Secret Service software protector: {error}")))
    }
}

#[cfg(all(target_os = "linux", feature = "linux-secret-service"))]
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
        let secret: [u8; 32] = secret
            .as_slice()
            .try_into()
            .map_err(|_| Error::Encoding(format!("protected DEK length: {}", secret.len())))?;
        Ok(zeroize::Zeroizing::new(secret))
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

#[cfg(all(target_os = "linux", feature = "linux-secret-service"))]
fn linux_desktop_session_available() -> bool {
    std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_some()
        || std::env::var_os("XDG_CURRENT_DESKTOP").is_some()
        || std::env::var_os("DESKTOP_SESSION").is_some()
}

#[cfg(all(target_os = "linux", feature = "systemd-creds"))]
#[derive(Debug)]
struct SystemdCredsProtector {
    root: PathBuf,
}

#[cfg(all(target_os = "linux", feature = "systemd-creds"))]
impl SystemdCredsProtector {
    const ID: &'static str = "systemd-creds";

    fn path_for(&self, handle: &str) -> PathBuf {
        self.root.join(format!("{handle}.cred"))
    }

    fn credential_name(handle: &str) -> String {
        format!("mkit.software-dek.{handle}")
    }
}

#[cfg(all(target_os = "linux", feature = "systemd-creds"))]
fn systemd_creds_protector(root: &Path) -> Result<Arc<dyn KeyProtector>> {
    systemd_creds_protector_for_availability(
        root,
        crate::backend_systemd_creds::systemd_creds_runtime_available(),
    )
}

#[cfg(all(target_os = "linux", feature = "systemd-creds"))]
fn systemd_creds_protector_for_availability(
    root: &Path,
    runtime_available: bool,
) -> Result<Arc<dyn KeyProtector>> {
    if !runtime_available {
        return Err(Error::BackendUnavailable(
            "systemd-creds executable was not found or is unusable".into(),
        ));
    }
    Ok(Arc::new(SystemdCredsProtector {
        root: root.join("deks"),
    }))
}

#[cfg(all(target_os = "linux", feature = "systemd-creds"))]
impl KeyProtector for SystemdCredsProtector {
    fn id(&self) -> &'static str {
        Self::ID
    }

    fn wrap_dek(&self, dek: &[u8; 32], _aad: &[u8]) -> Result<Vec<u8>> {
        let handle = random_handle()?;
        let path = self.path_for(&handle);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| Error::Io(format!("mkdir {}: {error}", parent.display())))?;
        }
        crate::backend_systemd_creds::encrypt_credential(
            dek,
            &path,
            &Self::credential_name(&handle),
        )?;
        Ok(handle.into_bytes())
    }

    fn unwrap_dek(&self, wrapped: &[u8], _aad: &[u8]) -> Result<zeroize::Zeroizing<[u8; 32]>> {
        let handle = std::str::from_utf8(wrapped)
            .map_err(|error| Error::Encoding(format!("protector handle is not UTF-8: {error}")))?;
        let secret = zeroize::Zeroizing::new(crate::backend_systemd_creds::decrypt_credential(
            &self.path_for(handle),
            &Self::credential_name(handle),
        )?);
        let secret: [u8; 32] = secret
            .as_slice()
            .try_into()
            .map_err(|_| Error::Encoding(format!("protected DEK length: {}", secret.len())))?;
        Ok(zeroize::Zeroizing::new(secret))
    }

    fn delete_wrapped_dek(&self, wrapped: &[u8]) -> Result<()> {
        let handle = std::str::from_utf8(wrapped)
            .map_err(|error| Error::Encoding(format!("protector handle is not UTF-8: {error}")))?;
        match std::fs::remove_file(self.path_for(handle)) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(Error::Io(format!("delete systemd-creds DEK: {error}"))),
        }
    }
}

fn default_storage_root() -> Result<PathBuf> {
    #[cfg(unix)]
    {
        if let Some(data_home) = std::env::var_os("XDG_DATA_HOME") {
            return Ok(PathBuf::from(data_home).join("mkit").join("keys"));
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
            .join("keys"))
    }
    #[cfg(windows)]
    {
        if let Some(appdata) = std::env::var_os("APPDATA") {
            return Ok(PathBuf::from(appdata).join("mkit").join("keys"));
        }
        let Some(profile) = std::env::var_os("USERPROFILE") else {
            return Err(Error::BackendUnavailable(
                "APPDATA is unset and USERPROFILE is unset".into(),
            ));
        };
        Ok(PathBuf::from(profile)
            .join("AppData")
            .join("Roaming")
            .join("mkit")
            .join("keys"))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let Some(home) = std::env::var_os("HOME") else {
            return Err(Error::BackendUnavailable("HOME is unset".into()));
        };
        Ok(PathBuf::from(home).join(".mkit").join("keys"))
    }
}

#[allow(clippy::needless_pass_by_value)]
fn core_error(error: mkit_core::MkitError) -> Error {
    Error::Io(error.to_string())
}

fn invalid_key_material(algorithm: Algorithm, reason: &str) -> Error {
    Error::InvalidKeyMaterial {
        algorithm,
        reason: reason.into(),
    }
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
    use zeroize::Zeroizing;

    #[derive(Debug)]
    struct TestProtector;

    impl KeyProtector for TestProtector {
        fn id(&self) -> &'static str {
            "test-protector"
        }

        fn wrap_dek(&self, dek: &[u8; 32], _aad: &[u8]) -> Result<Vec<u8>> {
            Ok(dek.to_vec())
        }

        fn unwrap_dek(&self, wrapped: &[u8], _aad: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
            let dek: [u8; 32] = wrapped
                .try_into()
                .map_err(|_| Error::Encoding(format!("test DEK length: {}", wrapped.len())))?;
            Ok(Zeroizing::new(dek))
        }
    }

    fn software_store(root: impl Into<PathBuf>) -> SoftwareKeystore {
        SoftwareKeystore::with_root_and_protector(root, Arc::new(TestProtector))
    }

    #[test]
    fn software_backend_import_open_list_export_delete_roundtrip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = software_store(dir.path().join("keys"));
        let secret = SecretKey::new(Algorithm::Ed25519, [3; 32]);
        let mut signer = store
            .import(
                "default",
                secret,
                KeyAttrs::default(),
                ImportOptions::default(),
            )
            .expect("import");
        assert_eq!(signer.algorithm(), Algorithm::Ed25519);
        assert_eq!(signer.public_key().expect("public key").len(), 32);

        let listed = store.list().expect("list");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].label, "default");
        assert_eq!(listed[0].algorithm, Algorithm::Ed25519);

        let selector = KeySelector::new("default", Some(Algorithm::Ed25519)).expect("selector");
        let exported = store.export(&selector).expect("export");
        assert_eq!(exported.expose_secret(), &[3; 32]);

        let sig = signer.sign(b"message").expect("sign");
        assert_eq!(sig.len(), 64);

        store.delete(&selector).expect("delete");
        assert!(matches!(store.open(&selector), Err(Error::KeyNotFound(_))));
    }

    #[test]
    fn software_backend_refuses_overwrite_without_force() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = software_store(dir.path().join("keys"));
        let selector = KeySelector::new("default", Some(Algorithm::Ed25519)).expect("selector");
        store
            .import(
                "default",
                SecretKey::new(Algorithm::Ed25519, [3; 32]),
                KeyAttrs::default(),
                ImportOptions::default(),
            )
            .expect("initial import");
        assert!(matches!(
            store.import(
                "default",
                SecretKey::new(Algorithm::Ed25519, [4; 32]),
                KeyAttrs::default(),
                ImportOptions::default(),
            ),
            Err(Error::KeyAlreadyExists { .. })
        ));
        store
            .import(
                "default",
                SecretKey::new(Algorithm::Ed25519, [4; 32]),
                KeyAttrs::default(),
                ImportOptions { overwrite: true },
            )
            .expect("overwrite import");
        assert_eq!(
            store.export(&selector).expect("export").expose_secret(),
            &[4; 32]
        );
    }

    #[test]
    fn software_backend_concurrent_import_without_force_allows_one_writer() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = software_store(dir.path().join("keys"));
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let mut handles = Vec::new();
        for seed in [[3; 32], [4; 32]] {
            let store = store.clone();
            let barrier = std::sync::Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                store.import(
                    "default",
                    SecretKey::new(Algorithm::Ed25519, seed),
                    KeyAttrs::default(),
                    ImportOptions::default(),
                )
            }));
        }
        barrier.wait();

        let mut successes = 0;
        let mut already_exists = 0;
        for handle in handles {
            match handle.join().expect("thread should not panic") {
                Ok(_) => successes += 1,
                Err(Error::KeyAlreadyExists { .. }) => already_exists += 1,
                Err(error) => panic!("unexpected import error: {error}"),
            }
        }
        assert_eq!(successes, 1);
        assert_eq!(already_exists, 1);

        let selector = KeySelector::new("default", Some(Algorithm::Ed25519)).expect("selector");
        let exported = store.export(&selector).expect("export");
        assert!(matches!(exported.expose_secret(), [3 | 4, ..]));
    }

    #[test]
    fn software_backend_rejects_unsupported_attrs() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = software_store(dir.path().join("keys"));
        let attrs = KeyAttrs {
            extractable: false,
            require_user_presence: false,
            device_bound: false,
        };
        assert!(matches!(
            store.import(
                "default",
                SecretKey::new(Algorithm::Ed25519, [3; 32]),
                attrs,
                ImportOptions::default(),
            ),
            Err(Error::UnsupportedAttributes(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn software_backend_rejects_symlinked_storage_root() {
        let dir = tempfile::tempdir().expect("tempdir");
        let real_root = dir.path().join("real-keys");
        let symlink_root = dir.path().join("keys");
        std::fs::create_dir_all(&real_root).expect("real root");
        std::os::unix::fs::symlink(&real_root, &symlink_root).expect("symlink root");
        let store = software_store(&symlink_root);

        let result = store.import(
            "default",
            SecretKey::new(Algorithm::Ed25519, [3; 32]),
            KeyAttrs::default(),
            ImportOptions::default(),
        );
        assert!(matches!(result, Err(Error::Io(message)) if message.contains("symlink")));
    }

    #[cfg(unix)]
    #[test]
    fn software_backend_rejects_symlinked_algorithm_dir() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("keys");
        let real_algorithm_dir = dir.path().join("real-ed25519");
        std::fs::create_dir_all(&root).expect("root");
        std::fs::create_dir_all(&real_algorithm_dir).expect("real algorithm dir");
        std::os::unix::fs::symlink(&real_algorithm_dir, root.join("ed25519"))
            .expect("symlink algorithm dir");
        let store = software_store(root);

        let result = store.import(
            "default",
            SecretKey::new(Algorithm::Ed25519, [3; 32]),
            KeyAttrs::default(),
            ImportOptions::default(),
        );
        assert!(matches!(result, Err(Error::Io(message)) if message.contains("symlink")));
    }

    #[cfg(unix)]
    #[test]
    fn software_backend_rejects_symlinked_final_key_path_for_open_and_delete() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = software_store(dir.path().join("keys"));
        let path = store
            .path_for("default", Algorithm::Ed25519)
            .expect("key path");
        std::fs::create_dir_all(path.parent().expect("key parent")).expect("key parent");
        let target = dir.path().join("target.key");
        std::fs::write(&target, [3; 32]).expect("target key");
        std::os::unix::fs::symlink(&target, &path).expect("symlink key path");
        let selector = KeySelector::new("default", Some(Algorithm::Ed25519)).expect("selector");

        assert!(
            matches!(store.open(&selector), Err(Error::Io(message)) if message.contains("symlink"))
        );
        assert!(
            matches!(store.delete(&selector), Err(Error::Io(message)) if message.contains("symlink"))
        );
        assert!(
            path.is_symlink(),
            "delete must not remove a symlinked key path"
        );
    }

    #[test]
    fn software_backend_generates_all_supported_algorithms() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = software_store(dir.path().join("keys"));
        for (algorithm, public_key_len, signature_len) in [
            (Algorithm::Ed25519, 32, 64),
            (Algorithm::Secp256k1, 33, 64),
            (Algorithm::P256, 33, 64),
        ] {
            let label = format!("generated-{algorithm}");
            let mut signer = store
                .generate(
                    &label,
                    algorithm,
                    KeyAttrs::default(),
                    GenerateOptions::default(),
                )
                .expect("generate");
            assert_eq!(
                signer.public_key().expect("public key").len(),
                public_key_len
            );
            assert_eq!(
                signer.sign(b"message").expect("signature").len(),
                signature_len
            );
            let selector = KeySelector::new(label, Some(algorithm)).expect("selector");
            assert_eq!(
                store.export(&selector).expect("export").algorithm(),
                algorithm
            );
        }
    }

    #[test]
    fn software_backend_writes_encrypted_record_not_raw_seed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = software_store(dir.path().join("keys"));
        let seed = [0x4a; 32];
        store
            .import(
                "encrypted",
                SecretKey::new(Algorithm::Ed25519, seed),
                KeyAttrs::default(),
                ImportOptions::default(),
            )
            .expect("import");

        let path = store.path_for("encrypted", Algorithm::Ed25519).unwrap();
        let encoded = std::fs::read(path).expect("record bytes");
        assert!(encoded.starts_with(b"MKITKSV1"));
        assert_ne!(encoded, seed);
        assert_eq!(store.list().unwrap()[0].label, "encrypted");
    }

    #[cfg(unix)]
    #[test]
    fn software_backend_writes_private_storage_permissions() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("keys");
        let store = software_store(&root);
        store
            .import(
                "encrypted",
                SecretKey::new(Algorithm::Ed25519, [0x4a; 32]),
                KeyAttrs::default(),
                ImportOptions::default(),
            )
            .expect("import");

        let algorithm_dir = root.join("ed25519");
        let key_path = store.path_for("encrypted", Algorithm::Ed25519).unwrap();
        assert_eq!(mode(&root), 0o700);
        assert_eq!(mode(&algorithm_dir), 0o700);
        assert_eq!(mode(&key_path), 0o600);
    }

    #[test]
    fn software_raw_backend_reports_raw_backend_kind() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = SoftwareRawKeystore::with_root(dir.path().join("keys"));
        let signer = store
            .import(
                "default",
                SecretKey::new(Algorithm::Ed25519, [9; 32]),
                KeyAttrs::default(),
                ImportOptions::default(),
            )
            .expect("import");

        assert_eq!(store.capabilities().backend, BackendKind::SoftwareRaw);
        assert_eq!(
            signer.metadata().expect("metadata").backend,
            BackendKind::SoftwareRaw
        );
        let selector = KeySelector::new("default", Some(Algorithm::Ed25519)).expect("selector");
        assert_eq!(
            store.list().expect("list")[0].backend,
            BackendKind::SoftwareRaw
        );
        assert_eq!(
            store.export(&selector).expect("export").expose_secret(),
            &[9; 32]
        );
    }

    #[test]
    fn software_and_raw_backends_do_not_alias_storage() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("keys");
        let software = software_store(&root);
        let raw = SoftwareRawKeystore::with_root(&root);

        software
            .import(
                "shared",
                SecretKey::new(Algorithm::Ed25519, [7; 32]),
                KeyAttrs::default(),
                ImportOptions::default(),
            )
            .expect("software import");
        raw.import(
            "shared",
            SecretKey::new(Algorithm::Ed25519, [8; 32]),
            KeyAttrs::default(),
            ImportOptions::default(),
        )
        .expect("raw import");

        let software_path = software.path_for("shared", Algorithm::Ed25519).unwrap();
        let raw_path = raw.inner.path_for("shared", Algorithm::Ed25519).unwrap();
        assert_ne!(software_path, raw_path);
        assert_eq!(std::fs::read(&raw_path).expect("raw bytes"), [8; 32]);
        assert_ne!(
            std::fs::read(&software_path).expect("record bytes"),
            [8; 32]
        );

        let selector = KeySelector::new("shared", Some(Algorithm::Ed25519)).unwrap();
        assert_eq!(
            software.export(&selector).unwrap().expose_secret(),
            &[7; 32]
        );
        assert_eq!(raw.export(&selector).unwrap().expose_secret(), &[8; 32]);
    }

    #[test]
    fn software_capabilities_are_backend_accurate() {
        let dir = tempfile::tempdir().expect("tempdir");
        for (store, backend) in [
            (
                Box::new(software_store(dir.path().join("software"))) as Box<dyn Keystore>,
                BackendKind::Software,
            ),
            (
                Box::new(SoftwareRawKeystore::with_root(dir.path().join("raw")))
                    as Box<dyn Keystore>,
                BackendKind::SoftwareRaw,
            ),
        ] {
            let capabilities = store.capabilities();
            assert_eq!(capabilities.backend, backend);
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
    }

    #[cfg(not(any(
        feature = "linux-secret-service",
        feature = "macos-keychain",
        feature = "systemd-creds",
        feature = "windows-credential"
    )))]
    #[test]
    fn software_capabilities_are_honest_without_protector() {
        let dir = tempfile::tempdir().expect("tempdir");
        let capabilities = SoftwareKeystore::with_root(dir.path().join("software")).capabilities();

        assert_eq!(capabilities.backend, BackendKind::Software);
        assert_eq!(
            capabilities.algorithms,
            vec![Algorithm::Ed25519, Algorithm::Secp256k1, Algorithm::P256]
        );
        assert!(!capabilities.can_generate);
        assert!(!capabilities.can_import);
        assert!(!capabilities.can_export);
        assert!(!capabilities.can_delete);
        assert!(capabilities.supports_listing);
    }

    #[cfg(all(target_os = "linux", feature = "systemd-creds"))]
    #[test]
    fn systemd_protector_requires_available_runtime() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(matches!(
            systemd_creds_protector_for_availability(dir.path(), false),
            Err(Error::BackendUnavailable(_))
        ));
    }

    #[cfg(unix)]
    fn mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt as _;

        std::fs::metadata(path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777
    }
}

#[cfg(all(test, feature = "attest"))]
mod compatibility_tests {
    use super::*;
    use mkit_attest::Signer as _;

    const PAE: &[u8] = b"DSSEv1 28 application/vnd.in-toto+json 2 {}";

    #[test]
    fn ed25519_signatures_match_existing_repo_key_signer() {
        let seed = [0x42; 32];
        let mut expected =
            mkit_attest::RepoKeySigner::new(mkit_core::sign::KeyPair::from_seed(seed));
        let mut actual = SoftwareSigner::new(
            "default".into(),
            BackendKind::Software,
            Algorithm::Ed25519,
            seed,
        )
        .unwrap();

        assert_eq!(
            actual.public_key().unwrap(),
            mkit_core::sign::KeyPair::from_seed(seed).public.0
        );
        assert_eq!(actual.sign(PAE).unwrap(), expected.sign(PAE).unwrap());
    }

    #[test]
    fn secp256k1_signatures_match_existing_software_signer() {
        let mut seed = [0u8; 32];
        seed[31] = 1;
        let expected = mkit_attest::signer_k256::Secp256k1Signer::new(seed).unwrap();
        let mut actual = SoftwareSigner::new(
            "default".into(),
            BackendKind::Software,
            Algorithm::Secp256k1,
            seed,
        )
        .unwrap();

        assert_eq!(actual.public_key().unwrap(), expected.public_key_sec1());
        assert_eq!(actual.keyid().unwrap(), expected.keyid_string());
        assert_eq!(actual.sign(PAE).unwrap(), expected.sign_dsse(PAE).unwrap());
    }

    #[test]
    fn p256_signatures_match_existing_software_signer() {
        let seed = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        let expected = mkit_attest::signer_p256::P256Signer::new(seed).unwrap();
        let mut actual = SoftwareSigner::new(
            "default".into(),
            BackendKind::Software,
            Algorithm::P256,
            seed,
        )
        .unwrap();

        assert_eq!(actual.public_key().unwrap(), expected.public_key_sec1());
        assert_eq!(actual.keyid().unwrap(), expected.keyid());
        assert_eq!(actual.sign(PAE).unwrap(), expected.sign_dsse(PAE).unwrap());
    }
}
