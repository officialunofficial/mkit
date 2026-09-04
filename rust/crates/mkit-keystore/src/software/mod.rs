//! User-scoped software compatibility backend.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use zeroize::Zeroize;

mod atomic_write;
#[cfg(feature = "bls-threshold")]
mod bls;
mod crypto;
mod protectors;
#[cfg(test)]
mod tests;

use atomic_write::{cleanup_new_dek_after_write_failure, write_key_file};
#[cfg(feature = "bls-threshold")]
pub use bls::{BlsShareMetadata, LoadedBlsShare};
use crypto::{public_key, random_valid_secret, sign_message, validate_secret};

#[cfg(all(target_os = "linux", feature = "linux-secret-service"))]
use protectors::LinuxSecretServiceProtector;
#[cfg(all(target_os = "macos", feature = "macos-keychain"))]
use protectors::MacosKeychainProtector;
#[cfg(all(target_os = "linux", feature = "systemd-creds"))]
use protectors::SystemdCredsProtector;
#[cfg(all(target_os = "linux", feature = "linux-secret-service"))]
use protectors::linux_desktop_session_available;
#[cfg(all(test, target_os = "linux", feature = "systemd-creds"))]
use protectors::systemd_creds::systemd_creds_protector_for_availability;
#[cfg(all(target_os = "linux", feature = "systemd-creds"))]
use protectors::systemd_creds_protector;

#[cfg(all(test, feature = "bls-threshold"))]
use crate::encrypted_record;
use crate::encrypted_record::{EncryptedKeyRecord, KeyProtector};

use crate::{
    Algorithm, BackendKind, Capabilities, Error, GenerateOptions, ImportOptions, KeyAttrs,
    KeyDeleter, KeyExporter, KeyGenerator, KeyId, KeyImporter, KeyLabel, KeyLister, KeyMetadata,
    KeyOpener, KeySelector, KeySigner, Keystore, PublicKeyBytes, Result, SecretKey, validate_label,
};
#[cfg(test)]
use atomic_write::KeyFileWriteError;

/// Persistent software keystore with encrypted-at-rest records by default.
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

    /// Build metadata for a key, reporting the key attributes that were
    /// stored with it. The raw backend has no persisted attrs, so callers
    /// pass `attrs = None` and the software-invariant defaults are reported;
    /// the encrypted backend passes the record's authenticated `attrs` so
    /// the listing reflects persisted state rather than constants.
    fn metadata_for_secret(
        &self,
        label: KeyLabel,
        algorithm: Algorithm,
        secret: &SecretKey,
        attrs: Option<&KeyAttrs>,
    ) -> Result<KeyMetadata> {
        let signer = SoftwareSigner::new(
            label.clone(),
            self.backend,
            secret.algorithm(),
            *secret.expose_secret(),
        )?;
        // The software backend only ever persists the default extractable
        // attribute set (enforced by `validate_attrs`), so the raw path's
        // `None` reports those defaults.
        let attrs = attrs.cloned().unwrap_or_default();
        Ok(KeyMetadata {
            label,
            backend: self.backend,
            algorithm,
            public_key: signer.public_key()?,
            keyid: signer.keyid()?,
            extractable: attrs.extractable,
            require_user_presence: attrs.require_user_presence,
            device_bound: attrs.device_bound,
        })
    }

    fn load_secret(&self, label: &KeyLabel, algorithm: Algorithm) -> Result<SecretKey> {
        if !self.is_raw() {
            let record = self.load_record(label, algorithm)?;
            let protector = self.protector_for_record(&record)?;
            return record.decrypt(label.as_str(), protector.as_ref());
        }
        let path = self.path_for(label.as_str(), algorithm)?;
        self.ensure_storage_path_not_symlink(&path)?;
        if !path.exists() {
            return Err(Error::KeyNotFound(KeySelector {
                label: label.clone(),
                algorithm: Some(algorithm),
            }));
        }
        let bytes = mkit_core::sign::load_raw_32(&path).map_err(core_error)?;
        Ok(SecretKey::new(algorithm, *bytes))
    }

    fn load_record(&self, label: &KeyLabel, algorithm: Algorithm) -> Result<EncryptedKeyRecord> {
        let path = self.path_for(label.as_str(), algorithm)?;
        self.ensure_storage_path_not_symlink(&path)?;
        if !path.exists() {
            return Err(Error::KeyNotFound(KeySelector {
                label: label.clone(),
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

#[cfg(test)]
impl SoftwareKeystore {
    fn generate(
        &self,
        label: &str,
        algorithm: Algorithm,
        attrs: KeyAttrs,
        options: GenerateOptions,
    ) -> Result<Box<dyn KeySigner>> {
        KeyGenerator::generate(self, &KeyLabel::new(label)?, algorithm, attrs, options)
    }

    fn import(
        &self,
        label: &str,
        secret: SecretKey,
        attrs: KeyAttrs,
        options: ImportOptions,
    ) -> Result<Box<dyn KeySigner>> {
        KeyImporter::import(self, &KeyLabel::new(label)?, secret, attrs, options)
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

#[cfg(test)]
impl SoftwareRawKeystore {
    fn import(
        &self,
        label: &str,
        secret: SecretKey,
        attrs: KeyAttrs,
        options: ImportOptions,
    ) -> Result<Box<dyn KeySigner>> {
        KeyImporter::import(self, &KeyLabel::new(label)?, secret, attrs, options)
    }
}

impl Keystore for SoftwareRawKeystore {
    fn capabilities(&self) -> Capabilities {
        self.inner.capabilities()
    }

    fn generator(&self) -> Option<&dyn KeyGenerator> {
        Some(self)
    }

    fn importer(&self) -> Option<&dyn KeyImporter> {
        Some(self)
    }

    fn opener(&self) -> Option<&dyn KeyOpener> {
        Some(self)
    }

    fn lister(&self) -> Option<&dyn KeyLister> {
        Some(self)
    }

    fn exporter(&self) -> Option<&dyn KeyExporter> {
        Some(self)
    }

    fn deleter(&self) -> Option<&dyn KeyDeleter> {
        Some(self)
    }
}

impl KeyGenerator for SoftwareRawKeystore {
    fn generate(
        &self,
        label: &KeyLabel,
        algorithm: Algorithm,
        attrs: KeyAttrs,
        options: GenerateOptions,
    ) -> Result<Box<dyn KeySigner>> {
        KeyGenerator::generate(&self.inner, label, algorithm, attrs, options)
    }
}

impl KeyImporter for SoftwareRawKeystore {
    fn import(
        &self,
        label: &KeyLabel,
        secret: SecretKey,
        attrs: KeyAttrs,
        options: ImportOptions,
    ) -> Result<Box<dyn KeySigner>> {
        KeyImporter::import(&self.inner, label, secret, attrs, options)
    }
}

impl KeyOpener for SoftwareRawKeystore {
    fn open(&self, selector: &KeySelector) -> Result<Box<dyn KeySigner>> {
        self.inner.open(selector)
    }
}

impl KeyLister for SoftwareRawKeystore {
    fn list(&self) -> Result<Vec<KeyMetadata>> {
        self.inner.list()
    }
}

impl KeyExporter for SoftwareRawKeystore {
    fn export(&self, selector: &KeySelector) -> Result<SecretKey> {
        self.inner.export(selector)
    }
}

impl KeyDeleter for SoftwareRawKeystore {
    fn delete(&self, selector: &KeySelector) -> Result<()> {
        self.inner.delete(selector)
    }
}

impl Keystore for SoftwareKeystore {
    fn capabilities(&self) -> Capabilities {
        // BLS12-381 threshold shares are advertised when the
        // `bls-threshold` feature is on: the software backend can
        // store and load them via `store_bls_share` /
        // `load_bls_share`. (They do not flow through the generic
        // `KeyImporter` / `KeyExporter` traits — those are pinned at
        // 32-byte secrets — but the algorithm is supported.)
        #[allow(unused_mut)]
        let mut algorithms = vec![Algorithm::Ed25519, Algorithm::Secp256k1, Algorithm::P256];
        #[cfg(feature = "bls-threshold")]
        if !self.is_raw() {
            algorithms.push(Algorithm::Bls12381Threshold);
        }
        Capabilities {
            backend: self.backend,
            algorithms,
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

    fn generator(&self) -> Option<&dyn KeyGenerator> {
        Some(self)
    }

    fn importer(&self) -> Option<&dyn KeyImporter> {
        Some(self)
    }

    fn opener(&self) -> Option<&dyn KeyOpener> {
        Some(self)
    }

    fn lister(&self) -> Option<&dyn KeyLister> {
        Some(self)
    }

    fn exporter(&self) -> Option<&dyn KeyExporter> {
        Some(self)
    }

    fn deleter(&self) -> Option<&dyn KeyDeleter> {
        Some(self)
    }
}

impl KeyGenerator for SoftwareKeystore {
    fn generate(
        &self,
        label: &KeyLabel,
        algorithm: Algorithm,
        attrs: KeyAttrs,
        options: GenerateOptions,
    ) -> Result<Box<dyn KeySigner>> {
        // BLS12-381 threshold shares are produced by a trusted dealer
        // running `mkit_attest::signer_bls_threshold::trusted_dealer`,
        // not by per-share RNG draws — a single share carries no
        // meaning without the cohort's `Sharing`. Callers use
        // `SoftwareKeystore::store_bls_share` to persist the dealt
        // shares one by one. See `mkit-cli`'s `key generate
        // --algorithm bls12381-thr --threshold M --total N`.
        #[cfg(feature = "bls-threshold")]
        if algorithm == Algorithm::Bls12381Threshold {
            let _ = (label, attrs, options);
            return Err(Error::UnsupportedOperation(
                "BLS12-381 threshold shares must be generated via a trusted-dealer ceremony, \
                 not the per-key `generate` trait — use `mkit key generate --algorithm \
                 bls12381-thr --threshold M --total N`",
            ));
        }
        validate_attrs(&attrs)?;
        let mut secret = random_valid_secret(algorithm)?;
        let wrapped = SecretKey::new(algorithm, secret);
        secret.zeroize();
        KeyImporter::import(
            self,
            label,
            wrapped,
            attrs,
            ImportOptions {
                overwrite: options.overwrite,
            },
        )
    }
}

impl KeyImporter for SoftwareKeystore {
    fn import(
        &self,
        label: &KeyLabel,
        secret: SecretKey,
        attrs: KeyAttrs,
        options: ImportOptions,
    ) -> Result<Box<dyn KeySigner>> {
        validate_attrs(&attrs)?;
        validate_label(label.as_str())?;
        validate_secret(secret.algorithm(), secret.expose_secret())?;
        let path = self.path_for(label.as_str(), secret.algorithm())?;
        self.ensure_storage_path_not_symlink(&path)?;
        if self.is_raw() && options.overwrite {
            mkit_core::sign::save_raw_32(&path, secret.expose_secret()).map_err(core_error)?;
        } else if self.is_raw() {
            let created = mkit_core::sign::save_raw_32_create_new(&path, secret.expose_secret())
                .map_err(core_error)?;
            if !created {
                return Err(Error::KeyAlreadyExists {
                    label: label.clone(),
                    algorithm: secret.algorithm(),
                });
            }
        } else {
            let old_wrapped_dek = if options.overwrite && path.exists() {
                let old_record = self.load_record(label, secret.algorithm())?;
                let old_protector = self.protector_for_record(&old_record)?;
                let _ = old_record.decrypt(label.as_str(), old_protector.as_ref())?;
                Some((old_protector, old_record.wrapped_dek().to_vec()))
            } else {
                None
            };
            let signer = SoftwareSigner::new(
                label.clone(),
                self.backend,
                secret.algorithm(),
                *secret.expose_secret(),
            )?;
            let protector = self.protector_for_write()?;
            let record = EncryptedKeyRecord::encrypt(
                label.as_str(),
                &secret,
                attrs,
                signer.public_key()?.into_vec(),
                signer.keyid()?.into_string(),
                protector.as_ref(),
            )?;
            if let Err(error) = record.decrypt(label.as_str(), protector.as_ref()) {
                let _ = protector.delete_wrapped_dek(record.wrapped_dek());
                return Err(error);
            }
            let encoded_record = match record.encode() {
                Ok(encoded) => encoded,
                Err(error) => {
                    let _ = protector.delete_wrapped_dek(record.wrapped_dek());
                    return Err(error);
                }
            };
            if let Err(error) = write_key_file(
                &self.root,
                &path,
                label.as_str(),
                secret.algorithm(),
                &encoded_record,
                options.overwrite,
            ) {
                return Err(cleanup_new_dek_after_write_failure(
                    protector.as_ref(),
                    record.wrapped_dek(),
                    error,
                ));
            }
            if let Some((old_protector, old_wrapped_dek)) = old_wrapped_dek {
                let _ = old_protector.delete_wrapped_dek(&old_wrapped_dek);
            }
            return Ok(Box::new(signer));
        }
        Ok(Box::new(SoftwareSigner::new(
            label.clone(),
            self.backend,
            secret.algorithm(),
            *secret.expose_secret(),
        )?))
    }
}

impl KeyOpener for SoftwareKeystore {
    fn open(&self, selector: &KeySelector) -> Result<Box<dyn KeySigner>> {
        validate_label(selector.label())?;
        let algorithm = self.resolve_selector_algorithm(selector)?;
        let secret = self.load_secret(selector.label_id(), algorithm)?;
        Ok(Box::new(SoftwareSigner::new(
            selector.label_id().clone(),
            self.backend,
            algorithm,
            *secret.expose_secret(),
        )?))
    }
}

impl KeyLister for SoftwareKeystore {
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
                if !path
                    .extension()
                    .and_then(|extension| extension.to_str())
                    .is_some_and(|extension| extension.eq_ignore_ascii_case(self.extension()))
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
                let label = KeyLabel::new(label)?;
                if self.is_raw() {
                    let secret = self.load_secret(&label, algorithm)?;
                    out.push(self.metadata_for_secret(label, algorithm, &secret, None)?);
                } else {
                    let record = self.load_record(&label, algorithm)?;
                    let protector = self.protector_for_record(&record)?;
                    let secret = record.decrypt(label.as_str(), protector.as_ref())?;
                    out.push(self.metadata_for_secret(
                        label,
                        algorithm,
                        &secret,
                        Some(&record.attrs),
                    )?);
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
}

impl KeyExporter for SoftwareKeystore {
    fn export(&self, selector: &KeySelector) -> Result<SecretKey> {
        let signer = self.open(selector)?;
        self.load_secret(signer.label(), signer.algorithm())
    }
}

impl KeyDeleter for SoftwareKeystore {
    fn delete(&self, selector: &KeySelector) -> Result<()> {
        validate_label(selector.label())?;
        let algorithm = self.resolve_selector_algorithm(selector)?;
        let path = self.path_for(selector.label(), algorithm)?;
        self.ensure_storage_path_not_symlink(&path)?;
        if !path.exists() {
            return Err(Error::KeyNotFound(KeySelector {
                label: selector.label_id().clone(),
                algorithm: Some(algorithm),
            }));
        }
        if !self.is_raw() {
            let record = self.load_record(selector.label_id(), algorithm)?;
            let protector = self.protector_for_record(&record)?;
            let _ = record.decrypt(selector.label(), protector.as_ref())?;
            let wrapped_dek = record.wrapped_dek().to_vec();
            std::fs::remove_file(&path)
                .map_err(|error| Error::Io(format!("delete {}: {error}", path.display())))?;
            let _ = protector.delete_wrapped_dek(&wrapped_dek);
            return Ok(());
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
    #[allow(clippy::unused_self, clippy::unnecessary_wraps)]
    fn ensure_storage_path_not_symlink(&self, _path: &Path) -> Result<()> {
        Ok(())
    }

    fn resolve_selector_algorithm(&self, selector: &KeySelector) -> Result<Algorithm> {
        if let Some(algorithm) = selector.algorithm {
            return Ok(algorithm);
        }
        let mut matches = Vec::new();
        for algorithm in [Algorithm::Ed25519, Algorithm::Secp256k1, Algorithm::P256] {
            let path = self.path_for(selector.label(), algorithm)?;
            self.ensure_storage_path_not_symlink(&path)?;
            if !path.exists() {
                continue;
            }
            let _ = self.load_secret(selector.label_id(), algorithm)?;
            matches.push(algorithm);
        }
        match matches.as_slice() {
            [] => Err(Error::KeyNotFound(selector.clone())),
            [algorithm] => Ok(*algorithm),
            _ => Err(Error::AmbiguousKeySelector(selector.clone())),
        }
    }
}

/// In-process signer backed by extractable secret material.
///
/// Used by software, software-raw, and OS-native backends that return 32-byte
/// secret material to this process. Hardware-backed signers use dedicated
/// signer types that keep private material on the device.
pub struct SoftwareSigner {
    label: KeyLabel,
    backend: BackendKind,
    secret: SecretKey,
}

impl SoftwareSigner {
    pub(crate) fn new(
        label: KeyLabel,
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

    fn label(&self) -> &KeyLabel {
        &self.label
    }

    fn metadata(&self) -> Result<KeyMetadata> {
        Ok(KeyMetadata {
            label: self.label.clone(),
            backend: self.backend,
            algorithm: self.algorithm(),
            public_key: self.public_key()?,
            keyid: self.keyid()?,
            extractable: true,
            require_user_presence: false,
            device_bound: false,
        })
    }

    fn public_key(&self) -> Result<PublicKeyBytes> {
        public_key(self.algorithm(), self.secret.expose_secret()).map(PublicKeyBytes::new)
    }

    fn keyid(&self) -> Result<KeyId> {
        let public_key = self.public_key()?;
        KeyId::new(format!(
            "{}:{}",
            self.algorithm(),
            hex_lower(public_key.as_bytes())
        ))
    }

    fn sign(&mut self, msg: &[u8]) -> Result<Vec<u8>> {
        sign_message(self.algorithm(), self.secret.expose_secret(), msg)
    }
}

fn validate_attrs(attrs: &KeyAttrs) -> Result<()> {
    if !attrs.extractable {
        return Err(Error::UnsupportedAttributes(
            "software backend does not support non-extractable keys".into(),
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

#[allow(unreachable_code)]
fn default_protector_for_write(root: &Path) -> Result<Arc<dyn KeyProtector>> {
    #[cfg(all(target_os = "macos", feature = "macos-keychain"))]
    {
        let _ = root;
        return Ok(Arc::new(MacosKeychainProtector));
    }
    #[cfg(target_os = "linux")]
    {
        #[cfg(feature = "linux-secret-service")]
        if linux_desktop_session_available() {
            match LinuxSecretServiceProtector::available() {
                Ok(true) => {
                    let _ = root;
                    return Ok(Arc::new(LinuxSecretServiceProtector));
                }
                Ok(false) => {}
                Err(error) => return Err(error),
            }
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

fn default_protector_by_id(root: &Path, id: &str) -> Result<Arc<dyn KeyProtector>> {
    #[cfg(not(all(target_os = "linux", feature = "systemd-creds")))]
    let _ = root;

    match id {
        #[cfg(all(target_os = "macos", feature = "macos-keychain"))]
        MacosKeychainProtector::ID => Ok(Arc::new(MacosKeychainProtector)),
        #[cfg(all(target_os = "linux", feature = "linux-secret-service"))]
        LinuxSecretServiceProtector::ID => Ok(Arc::new(LinuxSecretServiceProtector)),
        #[cfg(all(target_os = "linux", feature = "systemd-creds"))]
        SystemdCredsProtector::ID => systemd_creds_protector(root),
        _ => Err(Error::BackendUnavailable(format!(
            "software key record requires unavailable protector `{id}`"
        ))),
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

use crate::types::hex_lower;

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
            KeyLabel::new("default").unwrap(),
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
            KeyLabel::new("default").unwrap(),
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
            KeyLabel::new("default").unwrap(),
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
