//! User-scoped software compatibility backend.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use ed25519_dalek::{Signer as _, SigningKey as Ed25519SigningKey};
use k256::ecdsa::{Signature as K256Signature, SigningKey as K256SigningKey};
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

#[cfg(feature = "bls-threshold")]
use crate::encrypted_record;
use crate::encrypted_record::{EncryptedKeyRecord, KeyProtector};
use crate::{
    Algorithm, BackendKind, Capabilities, Error, GenerateOptions, ImportOptions, KeyAttrs,
    KeyDeleter, KeyExporter, KeyGenerator, KeyId, KeyImporter, KeyLabel, KeyLister, KeyMetadata,
    KeyOpener, KeySelector, KeySigner, Keystore, PublicKeyBytes, Result, SecretKey, validate_label,
};

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

    fn metadata_for_secret(
        &self,
        label: KeyLabel,
        algorithm: Algorithm,
        secret: &SecretKey,
    ) -> Result<KeyMetadata> {
        let signer = SoftwareSigner::new(
            label.clone(),
            self.backend,
            secret.algorithm(),
            *secret.expose_secret(),
        )?;
        Ok(KeyMetadata {
            label,
            backend: self.backend,
            algorithm,
            public_key: signer.public_key()?,
            keyid: signer.keyid()?,
            extractable: true,
            require_user_presence: false,
            device_bound: false,
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
                    out.push(self.metadata_for_secret(label, algorithm, &secret)?);
                } else {
                    let record = self.load_record(&label, algorithm)?;
                    let protector = self.protector_for_record(&record)?;
                    let secret = record.decrypt(label.as_str(), protector.as_ref())?;
                    out.push(self.metadata_for_secret(label, algorithm, &secret)?);
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

// -- BLS12-381 threshold share storage --------------------------------
//
// BLS shares can't ride the generic `KeyImporter` / `KeyExporter`
// traits because their plaintext is variable-length (a wire-encoded
// `Share`, ≈52 bytes). They have a dedicated API on
// `SoftwareKeystore` that uses the same crash-atomic write pattern
// and AEAD-bound AAD as the 32-byte path, just with a different
// record format (`BlsShareRecord`) and on-disk directory layout
// (`<root>/bls12381-thr/`).
//
// The release-party CLI (`mkit key generate --algorithm bls12381-thr
// --threshold M --total N --label <base>`) calls `store_bls_share`
// once per dealt share, using labels like `<base>-<index>`.

#[cfg(feature = "bls-threshold")]
/// Public metadata returned alongside a BLS share lookup.
#[derive(Clone, Debug)]
pub struct BlsShareMetadata {
    /// Cohort group public key (G2 compressed, 96 bytes for `MinSig`).
    pub cohort_public_key: Vec<u8>,
    /// Holder index within the cohort.
    pub share_index: u32,
    /// Quorum threshold (M).
    pub threshold: u32,
    /// Total holders in the cohort (N).
    pub total: u32,
    /// Canonical keyid `bls12381-thr:<hex(cohort_public_key)>`.
    pub keyid: String,
}

#[cfg(feature = "bls-threshold")]
/// A loaded BLS share plus its public metadata.
#[derive(Debug)]
pub struct LoadedBlsShare {
    /// Wire-encoded `Share` bytes (zeroized on drop).
    pub share_bytes: zeroize::Zeroizing<Vec<u8>>,
    /// Public metadata for this share.
    pub metadata: BlsShareMetadata,
}

#[cfg(feature = "bls-threshold")]
impl SoftwareKeystore {
    /// Subdirectory for BLS shares within the keystore root.
    const BLS_DIR: &'static str = "bls12381-thr";

    fn bls_dir(&self) -> PathBuf {
        self.root.join(Self::BLS_DIR)
    }

    fn bls_path_for(&self, label: &str) -> Result<PathBuf> {
        validate_label(label)?;
        Ok(self
            .bls_dir()
            .join(format!("{}.share", hex_lower(label.as_bytes()))))
    }

    /// Store a BLS12-381 threshold share under `label`.
    ///
    /// `share_bytes` is the wire-encoded
    /// `commonware_cryptography::bls12381::primitives::group::Share`.
    /// `cohort_public_key` is the G2 compressed group public key (96
    /// bytes for `MinSig`). `keyid` is the canonical
    /// `bls12381-thr:<hex>` keyid the cohort uses for verification.
    ///
    /// # Errors
    /// * [`Error::UnsupportedOperation`] on a `software-raw` backend
    ///   (BLS storage requires the AEAD-bound AAD; the raw backend has
    ///   none).
    /// * [`Error::KeyAlreadyExists`] when a share is already stored
    ///   under `label` and `overwrite` is `false`.
    /// * [`Error::BackendUnavailable`] when no OS-native protector is
    ///   available.
    #[allow(clippy::too_many_arguments)]
    pub fn store_bls_share(
        &self,
        label: &KeyLabel,
        share_bytes: &[u8],
        cohort_public_key: Vec<u8>,
        share_index: u32,
        threshold: u32,
        total: u32,
        keyid: String,
        overwrite: bool,
    ) -> Result<()> {
        if self.is_raw() {
            return Err(Error::UnsupportedOperation(
                "BLS share storage requires the encrypted software backend, not software-raw",
            ));
        }
        if share_bytes.is_empty() {
            return Err(Error::InvalidKeyMaterial {
                algorithm: Algorithm::Bls12381Threshold,
                reason: "share bytes are empty".into(),
            });
        }
        let path = self.bls_path_for(label.as_str())?;
        self.ensure_storage_path_not_symlink(&path)?;
        let protector = self.protector_for_write()?;
        let old_wrapped_dek = if overwrite && path.exists() {
            let old = self.load_bls_record(label)?;
            let old_protector = self.protector_for_bls_record(&old)?;
            let _ = old.decrypt(label.as_str(), old_protector.as_ref())?;
            Some((old_protector, old.wrapped_dek().to_vec()))
        } else {
            None
        };
        let record = encrypted_record::BlsShareRecord::encrypt(
            label.as_str(),
            share_bytes,
            cohort_public_key,
            share_index,
            threshold,
            total,
            keyid,
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
            Algorithm::Bls12381Threshold,
            &encoded_record,
            overwrite,
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
        Ok(())
    }

    /// Load a BLS share by label.
    pub fn load_bls_share(&self, label: &KeyLabel) -> Result<LoadedBlsShare> {
        let record = self.load_bls_record(label)?;
        let protector = self.protector_for_bls_record(&record)?;
        let share_bytes = record.decrypt(label.as_str(), protector.as_ref())?;
        let metadata = BlsShareMetadata {
            cohort_public_key: record.cohort_public_key.clone(),
            share_index: record.share_index,
            threshold: record.threshold,
            total: record.total,
            keyid: record.keyid.clone(),
        };
        Ok(LoadedBlsShare {
            share_bytes,
            metadata,
        })
    }

    /// Public metadata for a BLS share without decrypting the share
    /// itself. Useful for `mkit key list` when the protector is
    /// available but the share contents aren't needed.
    pub fn bls_share_metadata(&self, label: &KeyLabel) -> Result<BlsShareMetadata> {
        let record = self.load_bls_record(label)?;
        Ok(BlsShareMetadata {
            cohort_public_key: record.cohort_public_key,
            share_index: record.share_index,
            threshold: record.threshold,
            total: record.total,
            keyid: record.keyid,
        })
    }

    /// Delete a BLS share by label. Best-effort cleanup of the
    /// protector-side wrapped DEK happens after the file rename.
    pub fn delete_bls_share(&self, label: &KeyLabel) -> Result<()> {
        let path = self.bls_path_for(label.as_str())?;
        self.ensure_storage_path_not_symlink(&path)?;
        if !path.exists() {
            return Err(Error::KeyNotFound(KeySelector {
                label: label.clone(),
                algorithm: Some(Algorithm::Bls12381Threshold),
            }));
        }
        let record = self.load_bls_record(label)?;
        let protector = self.protector_for_bls_record(&record)?;
        let _ = record.decrypt(label.as_str(), protector.as_ref())?;
        let wrapped_dek = record.wrapped_dek().to_vec();
        std::fs::remove_file(&path)
            .map_err(|error| Error::Io(format!("delete {}: {error}", path.display())))?;
        let _ = protector.delete_wrapped_dek(&wrapped_dek);
        Ok(())
    }

    /// List BLS share labels visible to this backend, sorted.
    pub fn list_bls_shares(&self) -> Result<Vec<(KeyLabel, BlsShareMetadata)>> {
        let dir = self.bls_dir();
        self.ensure_storage_path_not_symlink(&dir)?;
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => {
                return Err(Error::Io(format!("read_dir {}: {error}", dir.display())));
            }
        };
        let mut out = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|error| Error::Io(format!("read_dir entry: {error}")))?;
            let path = entry.path();
            if !path
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| extension.eq_ignore_ascii_case("share"))
            {
                continue;
            }
            let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
                continue;
            };
            let label_bytes = hex_decode(stem)?;
            let label = String::from_utf8(label_bytes).map_err(|error| {
                Error::Encoding(format!(
                    "stored label is not UTF-8 in {}: {error}",
                    path.display()
                ))
            })?;
            let label = KeyLabel::new(label)?;
            let metadata = self.bls_share_metadata(&label)?;
            out.push((label, metadata));
        }
        out.sort_by(|left, right| left.0.cmp(&right.0));
        Ok(out)
    }

    fn load_bls_record(&self, label: &KeyLabel) -> Result<encrypted_record::BlsShareRecord> {
        let path = self.bls_path_for(label.as_str())?;
        self.ensure_storage_path_not_symlink(&path)?;
        if !path.exists() {
            return Err(Error::KeyNotFound(KeySelector {
                label: label.clone(),
                algorithm: Some(Algorithm::Bls12381Threshold),
            }));
        }
        let bytes = std::fs::read(&path)
            .map_err(|error| Error::Io(format!("read {}: {error}", path.display())))?;
        encrypted_record::BlsShareRecord::decode(&bytes)
    }

    fn protector_for_bls_record(
        &self,
        record: &encrypted_record::BlsShareRecord,
    ) -> Result<Arc<dyn KeyProtector>> {
        if let Some(protector) = &self.protector
            && protector.id() == record.protector
        {
            return Ok(Arc::clone(protector));
        }
        default_protector_by_id(&self.root, &record.protector)
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
        // BLS12-381 threshold shares are variable-length wire-encoded
        // `Share` values (≈52 bytes), not 32-byte scalars. The
        // SecretKey path is closed to BLS; software-backend BLS storage
        // flows through `SoftwareKeystore::store_bls_share` instead.
        #[cfg(feature = "bls-threshold")]
        Algorithm::Bls12381Threshold => Err(Error::UnsupportedAlgorithm(algorithm)),
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
        // BLS shares carry their own group-public-key recovery; the
        // 32-byte SecretKey path can't represent them.
        #[cfg(feature = "bls-threshold")]
        Algorithm::Bls12381Threshold => Err(Error::UnsupportedAlgorithm(algorithm)),
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
        // BLS shares use `mkit_attest::signer_bls_threshold::ThresholdSigner`
        // which lives in the attest crate; the SoftwareSigner path is
        // closed to BLS.
        #[cfg(feature = "bls-threshold")]
        Algorithm::Bls12381Threshold => Err(Error::UnsupportedAlgorithm(algorithm)),
    }
}

fn random_valid_secret(algorithm: Algorithm) -> Result<[u8; 32]> {
    let mut secret = [0u8; 32];
    for _ in 0..8 {
        getrandom::fill(&mut secret).map_err(|_| Error::Internal("rng failed".into()))?;
        if validate_secret(algorithm, &secret).is_ok() {
            return Ok(secret);
        }
    }
    secret.zeroize();
    Err(Error::Internal(
        "rng failed to produce a valid scalar".into(),
    ))
}

#[derive(Debug)]
struct KeyFileWriteError {
    error: Error,
    record_may_exist: bool,
}

impl KeyFileWriteError {
    fn before_record_install(error: Error) -> Self {
        Self {
            error,
            record_may_exist: false,
        }
    }

    fn after_record_install(error: Error) -> Self {
        Self {
            error,
            record_may_exist: true,
        }
    }
}

fn cleanup_new_dek_after_write_failure(
    protector: &dyn KeyProtector,
    wrapped_dek: &[u8],
    error: KeyFileWriteError,
) -> Error {
    if !error.record_may_exist {
        let _ = protector.delete_wrapped_dek(wrapped_dek);
    }
    error.error
}

fn write_key_file(
    root: &Path,
    path: &Path,
    label: &str,
    algorithm: Algorithm,
    bytes: &[u8],
    overwrite: bool,
) -> std::result::Result<(), KeyFileWriteError> {
    #[cfg(unix)]
    return write_key_file_unix(root, path, label, algorithm, bytes, overwrite);

    #[cfg(not(unix))]
    {
        let _ = root;
        write_key_file_portable(path, label, algorithm, bytes, overwrite)
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
) -> std::result::Result<(), KeyFileWriteError> {
    use std::os::unix::fs::MetadataExt as _;

    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    ensure_no_symlink_path(root, parent).map_err(KeyFileWriteError::before_record_install)?;
    std::fs::create_dir_all(parent)
        .map_err(|error| Error::Io(format!("mkdir {}: {error}", parent.display())))
        .map_err(KeyFileWriteError::before_record_install)?;
    set_private_dir_permissions(root).map_err(KeyFileWriteError::before_record_install)?;
    ensure_owned_by_euid(root).map_err(KeyFileWriteError::before_record_install)?;
    if parent != root {
        set_private_dir_permissions(parent).map_err(KeyFileWriteError::before_record_install)?;
        ensure_owned_by_euid(parent).map_err(KeyFileWriteError::before_record_install)?;
    }

    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(KeyFileWriteError::before_record_install(Error::Io(
                format!("keystore path is a symlink: {}", path.display()),
            )));
        }
        Ok(metadata) => {
            if !overwrite {
                return Err(KeyFileWriteError::before_record_install(
                    Error::KeyAlreadyExists {
                        label: KeyLabel::new(label)
                            .map_err(KeyFileWriteError::before_record_install)?,
                        algorithm,
                    },
                ));
            }
            if metadata.uid() != euid() {
                return Err(KeyFileWriteError::before_record_install(
                    Error::AccessDenied(format!(
                        "existing key file is owned by uid {}, expected {}: {}",
                        metadata.uid(),
                        euid(),
                        path.display()
                    )),
                ));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(KeyFileWriteError::before_record_install(Error::Io(
                format!("lstat {}: {error}", path.display()),
            )));
        }
    }

    let filename = path
        .file_name()
        .ok_or_else(|| Error::Io(format!("path has no filename: {}", path.display())))
        .map_err(KeyFileWriteError::before_record_install)?;
    let tmp_path = create_synced_tmp_key_file(parent, filename, bytes)
        .map_err(KeyFileWriteError::before_record_install)?;

    if overwrite {
        if let Err(error) = std::fs::rename(&tmp_path, path) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(KeyFileWriteError::before_record_install(Error::Io(
                format!("rename {}: {error}", path.display()),
            )));
        }
    } else if let Err(error) = std::fs::hard_link(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return if error.kind() == std::io::ErrorKind::AlreadyExists {
            Err(KeyFileWriteError::before_record_install(
                Error::KeyAlreadyExists {
                    label: KeyLabel::new(label)
                        .map_err(KeyFileWriteError::before_record_install)?,
                    algorithm,
                },
            ))
        } else {
            Err(KeyFileWriteError::before_record_install(Error::Io(
                format!("link {}: {error}", path.display()),
            )))
        };
    } else if let Err(error) = std::fs::remove_file(&tmp_path) {
        return Err(KeyFileWriteError::after_record_install(Error::Io(format!(
            "unlink tmp {}: {error}",
            tmp_path.display()
        ))));
    }

    let dir = std::fs::File::open(parent)
        .map_err(|error| Error::Io(format!("open dir for fsync: {error}")))
        .map_err(KeyFileWriteError::after_record_install)?;
    dir.sync_all()
        .map_err(|error| Error::Io(format!("fsync dir: {error}")))
        .map_err(KeyFileWriteError::after_record_install)
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
) -> std::result::Result<(), KeyFileWriteError> {
    use std::io::Write as _;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| Error::Io(format!("mkdir {}: {error}", parent.display())))
            .map_err(KeyFileWriteError::before_record_install)?;
    }
    if overwrite {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let filename = path
            .file_name()
            .ok_or_else(|| Error::Io(format!("path has no filename: {}", path.display())))
            .map_err(KeyFileWriteError::before_record_install)?;
        let (tmp_path, mut file) = create_synced_tmp_key_file_portable(parent, filename)
            .map_err(KeyFileWriteError::before_record_install)?;
        file.write_all(bytes)
            .map_err(|error| Error::Io(format!("write tmp {}: {error}", tmp_path.display())))
            .map_err(KeyFileWriteError::before_record_install)?;
        file.sync_all()
            .map_err(|error| Error::Io(format!("fsync tmp {}: {error}", tmp_path.display())))
            .map_err(KeyFileWriteError::before_record_install)?;
        drop(file);
        if let Err(error) = std::fs::rename(&tmp_path, path) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(KeyFileWriteError::before_record_install(Error::Io(
                format!("rename {}: {error}", path.display()),
            )));
        }
        Ok(())
    } else {
        write_key_file_portable_create_new(path, label, algorithm, bytes)
    }
}

#[cfg(not(unix))]
fn write_key_file_portable_create_new(
    path: &Path,
    label: &str,
    algorithm: Algorithm,
    bytes: &[u8],
) -> std::result::Result<(), KeyFileWriteError> {
    use std::io::Write as _;

    let mut file = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(KeyFileWriteError::before_record_install(
                Error::KeyAlreadyExists {
                    label: KeyLabel::new(label)
                        .map_err(KeyFileWriteError::before_record_install)?,
                    algorithm,
                },
            ));
        }
        Err(error) => {
            return Err(KeyFileWriteError::before_record_install(Error::Io(
                format!("open {}: {error}", path.display()),
            )));
        }
    };
    if let Err(error) = file.write_all(bytes) {
        let removed = std::fs::remove_file(path).is_ok();
        let error = Error::Io(format!("write {}: {error}", path.display()));
        return Err(if removed {
            KeyFileWriteError::before_record_install(error)
        } else {
            KeyFileWriteError::after_record_install(error)
        });
    }
    if let Err(error) = file.sync_all() {
        let removed = std::fs::remove_file(path).is_ok();
        let error = Error::Io(format!("fsync {}: {error}", path.display()));
        return Err(if removed {
            KeyFileWriteError::before_record_install(error)
        } else {
            KeyFileWriteError::after_record_install(error)
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn create_synced_tmp_key_file_portable(
    parent: &Path,
    filename: &std::ffi::OsStr,
) -> Result<(PathBuf, std::fs::File)> {
    for attempt in 0..16u8 {
        let tmp_path = if attempt == 0 {
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
        };
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
        {
            Ok(file) => return Ok((tmp_path, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(Error::Io(format!(
                    "open tmp {}: {error}",
                    tmp_path.display()
                )));
            }
        }
    }
    Err(Error::Io(format!(
        "could not create unique temp file under {}",
        parent.display()
    )))
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
        #[cfg(all(windows, feature = "windows-credential"))]
        WindowsCredentialProtector::ID => Ok(Arc::new(WindowsCredentialProtector)),
        #[cfg(all(target_os = "linux", feature = "linux-secret-service"))]
        LinuxSecretServiceProtector::ID => Ok(Arc::new(LinuxSecretServiceProtector)),
        #[cfg(all(target_os = "linux", feature = "systemd-creds"))]
        SystemdCredsProtector::ID => systemd_creds_protector(root),
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
        let _guard = crate::keyring_default_store_lock();
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

#[cfg(all(target_os = "linux", feature = "linux-secret-service"))]
#[derive(Debug)]
struct LinuxSecretServiceProtector;

#[cfg(all(target_os = "linux", feature = "linux-secret-service"))]
impl LinuxSecretServiceProtector {
    const ID: &'static str = "linux-secret-service";
    const SERVICE: &'static str = "dev.mkit.keystore.software-dek.v1";

    fn available() -> Result<bool> {
        match zbus_secret_service_keyring_store::Store::new() {
            Ok(_) => Ok(true),
            Err(error) => Err(Error::BackendUnavailable(format!(
                "Linux Secret Service software protector: {error}"
            ))),
        }
    }

    fn entry(account: &str) -> Result<keyring_core::Entry> {
        let store = zbus_secret_service_keyring_store::Store::new().map_err(|error| {
            Error::BackendUnavailable(format!("Linux Secret Service software protector: {error}"))
        })?;
        let _guard = crate::keyring_default_store_lock();
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
    storage_root: PathBuf,
    dek_root: PathBuf,
}

#[cfg(all(target_os = "linux", feature = "systemd-creds"))]
impl SystemdCredsProtector {
    const ID: &'static str = "systemd-creds";

    fn path_for(&self, handle: &str) -> PathBuf {
        self.dek_root.join(format!("{handle}.cred"))
    }

    fn credential_name(handle: &str) -> String {
        format!("mkit.software-dek.{handle}")
    }

    fn prepare_write_path(&self, path: &Path) -> Result<()> {
        #[cfg(unix)]
        {
            let parent = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            ensure_no_symlink_path(&self.storage_root, parent)?;
            std::fs::create_dir_all(parent)
                .map_err(|error| Error::Io(format!("mkdir {}: {error}", parent.display())))?;
            set_private_dir_permissions(&self.storage_root)?;
            ensure_owned_by_euid(&self.storage_root)?;
            if parent != self.storage_root {
                set_private_dir_permissions(parent)?;
                ensure_owned_by_euid(parent)?;
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
        ensure_no_symlink_path(&self.storage_root, path)?;

        Ok(())
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
        storage_root: root.into(),
        dek_root: root.join("deks"),
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
    use std::sync::atomic::{AtomicUsize, Ordering};
    use zeroize::Zeroizing;

    mod golden_vectors {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/common/vectors.rs"
        ));
    }

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

    #[derive(Debug)]
    struct CountingProtector {
        deletes: Arc<AtomicUsize>,
    }

    impl KeyProtector for CountingProtector {
        fn id(&self) -> &'static str {
            "counting-protector"
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

        fn delete_wrapped_dek(&self, _wrapped: &[u8]) -> Result<()> {
            self.deletes.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[derive(Debug)]
    struct FailingDeleteProtector;

    impl KeyProtector for FailingDeleteProtector {
        fn id(&self) -> &'static str {
            "failing-delete-protector"
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

        fn delete_wrapped_dek(&self, _wrapped: &[u8]) -> Result<()> {
            Err(Error::Io("test DEK cleanup failure".into()))
        }
    }

    #[derive(Debug)]
    struct FailingUnwrapProtector {
        deletes: Arc<AtomicUsize>,
    }

    impl KeyProtector for FailingUnwrapProtector {
        fn id(&self) -> &'static str {
            "failing-unwrap-protector"
        }

        fn wrap_dek(&self, dek: &[u8; 32], _aad: &[u8]) -> Result<Vec<u8>> {
            Ok(dek.to_vec())
        }

        fn unwrap_dek(&self, _wrapped: &[u8], _aad: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
            Err(Error::BackendUnavailable("test unwrap failure".into()))
        }

        fn delete_wrapped_dek(&self, _wrapped: &[u8]) -> Result<()> {
            self.deletes.fetch_add(1, Ordering::SeqCst);
            Ok(())
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

    #[test]
    fn software_import_proves_protector_roundtrip_before_record_write() {
        let dir = tempfile::tempdir().expect("tempdir");
        let deletes = Arc::new(AtomicUsize::new(0));
        let store = SoftwareKeystore::with_root_and_protector(
            dir.path().join("keys"),
            Arc::new(FailingUnwrapProtector {
                deletes: Arc::clone(&deletes),
            }),
        );

        let result = store.import(
            "encrypted",
            SecretKey::new(Algorithm::Ed25519, [0x4a; 32]),
            KeyAttrs::default(),
            ImportOptions::default(),
        );

        assert!(
            matches!(result, Err(Error::BackendUnavailable(message)) if message.contains("unwrap failure"))
        );
        assert_eq!(deletes.load(Ordering::SeqCst), 1);
        assert!(
            !store
                .path_for("encrypted", Algorithm::Ed25519)
                .unwrap()
                .exists(),
            "record must not be committed when protector cannot unwrap"
        );
    }

    #[test]
    fn software_pre_install_write_failure_cleans_new_dek() {
        let deletes = Arc::new(AtomicUsize::new(0));
        let protector = CountingProtector {
            deletes: Arc::clone(&deletes),
        };

        let error = cleanup_new_dek_after_write_failure(
            &protector,
            b"wrapped-dek",
            KeyFileWriteError::before_record_install(Error::Io("pre-install write failure".into())),
        );

        assert!(matches!(error, Error::Io(message) if message.contains("pre-install")));
        assert_eq!(deletes.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn software_post_install_write_failure_preserves_new_dek() {
        let deletes = Arc::new(AtomicUsize::new(0));
        let protector = CountingProtector {
            deletes: Arc::clone(&deletes),
        };

        let error = cleanup_new_dek_after_write_failure(
            &protector,
            b"wrapped-dek",
            KeyFileWriteError::after_record_install(Error::Io("post-install fsync failure".into())),
        );

        assert!(matches!(error, Error::Io(message) if message.contains("post-install")));
        assert_eq!(deletes.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn software_list_authenticates_record_metadata() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = software_store(dir.path().join("keys"));
        store
            .import(
                "encrypted",
                SecretKey::new(Algorithm::Ed25519, [0x4a; 32]),
                KeyAttrs::default(),
                ImportOptions::default(),
            )
            .expect("import");
        let path = store.path_for("encrypted", Algorithm::Ed25519).unwrap();
        let mut record = EncryptedKeyRecord::decode(&std::fs::read(&path).expect("record bytes"))
            .expect("record decode");
        record.keyid = "ed25519:forged".into();
        std::fs::write(&path, record.encode().expect("record encode")).expect("record write");

        assert!(
            matches!(store.list(), Err(Error::Encoding(message)) if message.contains("authentication"))
        );
    }

    #[test]
    fn software_label_only_resolution_ignores_unrelated_corrupt_record() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = software_store(dir.path().join("keys"));
        store
            .import(
                "valid",
                SecretKey::new(Algorithm::Ed25519, [0x4a; 32]),
                KeyAttrs::default(),
                ImportOptions::default(),
            )
            .expect("valid import");
        store
            .import(
                "corrupt",
                SecretKey::new(Algorithm::P256, [1; 32]),
                KeyAttrs::default(),
                ImportOptions::default(),
            )
            .expect("corrupt import");
        let corrupt_path = store.path_for("corrupt", Algorithm::P256).unwrap();
        let mut record =
            EncryptedKeyRecord::decode(&std::fs::read(&corrupt_path).expect("record bytes"))
                .expect("record decode");
        record.keyid = "p256:forged".into();
        std::fs::write(&corrupt_path, record.encode().expect("record encode"))
            .expect("record write");

        assert!(
            store.list().is_err(),
            "strict list still authenticates all records"
        );
        let selector = KeySelector::new("valid", None).unwrap();
        assert_eq!(
            store.open(&selector).unwrap().algorithm(),
            Algorithm::Ed25519
        );
        assert_eq!(
            store.export(&selector).unwrap().expose_secret(),
            &[0x4a; 32]
        );
        store.delete(&selector).unwrap();
    }

    #[test]
    fn software_label_only_resolution_fails_closed_for_matching_corrupt_record() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = software_store(dir.path().join("keys"));
        store
            .import(
                "corrupt",
                SecretKey::new(Algorithm::Ed25519, [0x4a; 32]),
                KeyAttrs::default(),
                ImportOptions::default(),
            )
            .expect("import");
        let path = store.path_for("corrupt", Algorithm::Ed25519).unwrap();
        let mut record = EncryptedKeyRecord::decode(&std::fs::read(&path).expect("record bytes"))
            .expect("record decode");
        record.keyid = "ed25519:forged".into();
        std::fs::write(&path, record.encode().expect("record encode")).expect("record write");
        let selector = KeySelector::new("corrupt", None).unwrap();

        assert!(
            matches!(store.open(&selector), Err(Error::Encoding(message)) if message.contains("authentication"))
        );
    }

    #[test]
    fn software_delete_authenticates_before_dek_cleanup() {
        let dir = tempfile::tempdir().expect("tempdir");
        let deletes = Arc::new(AtomicUsize::new(0));
        let store = SoftwareKeystore::with_root_and_protector(
            dir.path().join("keys"),
            Arc::new(CountingProtector {
                deletes: Arc::clone(&deletes),
            }),
        );
        store
            .import(
                "encrypted",
                SecretKey::new(Algorithm::Ed25519, [0x4a; 32]),
                KeyAttrs::default(),
                ImportOptions::default(),
            )
            .expect("import");
        let path = store.path_for("encrypted", Algorithm::Ed25519).unwrap();
        let mut record = EncryptedKeyRecord::decode(&std::fs::read(&path).expect("record bytes"))
            .expect("record decode");
        record.public_key = vec![0xff; 32];
        std::fs::write(&path, record.encode().expect("record encode")).expect("record write");
        let selector = KeySelector::new("encrypted", Some(Algorithm::Ed25519)).unwrap();

        assert!(
            matches!(store.delete(&selector), Err(Error::Encoding(message)) if message.contains("authentication"))
        );
        assert_eq!(deletes.load(Ordering::SeqCst), 0);
        assert!(
            path.exists(),
            "unauthenticated record must remain for inspection"
        );
    }

    #[test]
    fn software_delete_removes_record_before_best_effort_dek_cleanup() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = SoftwareKeystore::with_root_and_protector(
            dir.path().join("keys"),
            Arc::new(FailingDeleteProtector),
        );
        store
            .import(
                "encrypted",
                SecretKey::new(Algorithm::Ed25519, [0x4a; 32]),
                KeyAttrs::default(),
                ImportOptions::default(),
            )
            .expect("import");
        let path = store.path_for("encrypted", Algorithm::Ed25519).unwrap();
        let selector = KeySelector::new("encrypted", Some(Algorithm::Ed25519)).unwrap();

        store.delete(&selector).expect("delete");
        assert!(!path.exists(), "selected key record must be removed");
    }

    #[test]
    fn software_overwrite_cleans_up_old_dek_after_success() {
        let dir = tempfile::tempdir().expect("tempdir");
        let deletes = Arc::new(AtomicUsize::new(0));
        let store = SoftwareKeystore::with_root_and_protector(
            dir.path().join("keys"),
            Arc::new(CountingProtector {
                deletes: Arc::clone(&deletes),
            }),
        );
        store
            .import(
                "shared",
                SecretKey::new(Algorithm::Ed25519, [0x4a; 32]),
                KeyAttrs::default(),
                ImportOptions::default(),
            )
            .expect("initial import");
        store
            .import(
                "shared",
                SecretKey::new(Algorithm::P256, [1; 32]),
                KeyAttrs::default(),
                ImportOptions::default(),
            )
            .expect("other algorithm import");
        store
            .import(
                "shared",
                SecretKey::new(Algorithm::Ed25519, [0x5b; 32]),
                KeyAttrs::default(),
                ImportOptions { overwrite: true },
            )
            .expect("overwrite import");

        let ed25519 = KeySelector::new("shared", Some(Algorithm::Ed25519)).unwrap();
        let p256 = KeySelector::new("shared", Some(Algorithm::P256)).unwrap();
        assert_eq!(store.export(&ed25519).unwrap().expose_secret(), &[0x5b; 32]);
        assert_eq!(store.export(&p256).unwrap().expose_secret(), &[1; 32]);
        assert_eq!(deletes.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn software_failed_overwrite_does_not_cleanup_old_dek() {
        #[derive(Debug)]
        struct FailSecondWrapProtector {
            wraps: Arc<AtomicUsize>,
            deletes: Arc<AtomicUsize>,
        }

        impl KeyProtector for FailSecondWrapProtector {
            fn id(&self) -> &'static str {
                "fail-second-wrap-protector"
            }

            fn wrap_dek(&self, dek: &[u8; 32], _aad: &[u8]) -> Result<Vec<u8>> {
                if self.wraps.fetch_add(1, Ordering::SeqCst) == 0 {
                    Ok(dek.to_vec())
                } else {
                    Err(Error::Io("test wrap failure".into()))
                }
            }

            fn unwrap_dek(&self, wrapped: &[u8], _aad: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
                let dek: [u8; 32] = wrapped
                    .try_into()
                    .map_err(|_| Error::Encoding(format!("test DEK length: {}", wrapped.len())))?;
                Ok(Zeroizing::new(dek))
            }

            fn delete_wrapped_dek(&self, _wrapped: &[u8]) -> Result<()> {
                self.deletes.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let wraps = Arc::new(AtomicUsize::new(0));
        let deletes = Arc::new(AtomicUsize::new(0));
        let store = SoftwareKeystore::with_root_and_protector(
            dir.path().join("keys"),
            Arc::new(FailSecondWrapProtector {
                wraps: Arc::clone(&wraps),
                deletes: Arc::clone(&deletes),
            }),
        );
        store
            .import(
                "encrypted",
                SecretKey::new(Algorithm::Ed25519, [0x4a; 32]),
                KeyAttrs::default(),
                ImportOptions::default(),
            )
            .expect("import");

        assert!(matches!(
            store.import(
                "encrypted",
                SecretKey::new(Algorithm::Ed25519, [0x5b; 32]),
                KeyAttrs::default(),
                ImportOptions { overwrite: true },
            ),
            Err(Error::Io(message)) if message.contains("wrap failure")
        ));
        assert_eq!(deletes.load(Ordering::SeqCst), 0);
        let selector = KeySelector::new("encrypted", Some(Algorithm::Ed25519)).unwrap();
        assert_eq!(
            store.export(&selector).unwrap().expose_secret(),
            &[0x4a; 32]
        );
    }

    #[test]
    fn encrypted_software_backend_matches_golden_vectors() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = software_store(dir.path().join("keys"));
        for vector in golden_vectors::VECTORS {
            let algorithm: Algorithm = vector.algorithm.parse().expect("algorithm parses");
            let seed: [u8; 32] = hex_decode(vector.seed_hex)
                .expect("seed hex")
                .try_into()
                .expect("seed length");
            let mut signer = store
                .import(
                    vector.label,
                    SecretKey::new(algorithm, seed),
                    KeyAttrs::default(),
                    ImportOptions::default(),
                )
                .expect("import vector");
            assert_eq!(
                hex_lower(signer.public_key().expect("public key").as_bytes()),
                vector.public_hex
            );
            assert_eq!(
                signer.keyid().expect("keyid"),
                format!("{}:{}", vector.algorithm, vector.public_hex)
            );
            let message = match algorithm {
                Algorithm::Ed25519 => b"".as_slice(),
                Algorithm::Secp256k1 | Algorithm::P256 => golden_vectors::PAE,
                // Golden vectors cover ed25519/secp/p256 only; BLS
                // golden vectors live in mkit-attest. Skip via
                // `continue` would change the loop shape, so panic
                // here — the calling loop never produces this arm.
                #[cfg(feature = "bls-threshold")]
                Algorithm::Bls12381Threshold => {
                    unreachable!(
                        "golden-vector test does not enumerate BLS12-381 threshold algorithms"
                    )
                }
            };
            assert_eq!(
                hex_lower(&signer.sign(message).expect("sign")),
                vector.signature_hex
            );
        }
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
            // The encrypted software backend additionally advertises
            // Bls12381Threshold when `bls-threshold` is enabled (raw
            // does not, because BLS storage requires AEAD-bound AAD).
            #[allow(unused_mut)]
            let mut expected_algorithms =
                vec![Algorithm::Ed25519, Algorithm::Secp256k1, Algorithm::P256];
            #[cfg(feature = "bls-threshold")]
            if backend == BackendKind::Software {
                expected_algorithms.push(Algorithm::Bls12381Threshold);
            }
            assert_eq!(capabilities.algorithms, expected_algorithms);
            assert!(capabilities.can_generate);
            assert!(capabilities.can_import);
            assert!(capabilities.can_export);
            assert!(capabilities.can_delete);
            assert!(capabilities.supports_listing);
            assert!(!capabilities.supports_user_presence);
            assert!(!capabilities.supports_device_bound);
            assert!(!capabilities.supports_non_extractable);
            assert_eq!(capabilities.can_generate, store.generator().is_some());
            assert_eq!(capabilities.can_import, store.importer().is_some());
            assert_eq!(capabilities.can_export, store.exporter().is_some());
            assert_eq!(capabilities.can_delete, store.deleter().is_some());
            assert_eq!(capabilities.supports_listing, store.lister().is_some());
        }
    }

    #[cfg(not(any(
        feature = "linux-secret-service",
        feature = "macos-keychain",
        feature = "systemd-creds",
        feature = "windows-credential"
    )))]
    #[test]
    fn software_capabilities_report_structural_support_without_protector() {
        let dir = tempfile::tempdir().expect("tempdir");
        let capabilities = SoftwareKeystore::with_root(dir.path().join("software")).capabilities();

        assert_eq!(capabilities.backend, BackendKind::Software);
        assert_eq!(
            capabilities.algorithms,
            vec![Algorithm::Ed25519, Algorithm::Secp256k1, Algorithm::P256]
        );
        assert!(capabilities.can_generate);
        assert!(capabilities.can_import);
        assert!(capabilities.can_export);
        assert!(capabilities.can_delete);
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

    #[cfg(all(target_os = "linux", feature = "systemd-creds"))]
    #[test]
    fn systemd_protector_rejects_symlinked_storage_root() {
        let dir = tempfile::tempdir().expect("tempdir");
        let real_root = dir.path().join("real-keys");
        let symlink_root = dir.path().join("keys");
        std::fs::create_dir_all(&real_root).expect("real root");
        std::os::unix::fs::symlink(&real_root, &symlink_root).expect("symlink root");
        let protector = SystemdCredsProtector {
            storage_root: symlink_root.clone(),
            dek_root: symlink_root.join("deks"),
        };
        let path = protector.path_for("0123456789abcdef");

        assert!(
            matches!(protector.prepare_write_path(&path), Err(Error::Io(message)) if message.contains("symlink"))
        );
    }

    #[cfg(all(target_os = "linux", feature = "systemd-creds"))]
    #[test]
    fn systemd_protector_rejects_symlinked_dek_dir() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("keys");
        let real_deks = dir.path().join("real-deks");
        std::fs::create_dir_all(&root).expect("root");
        std::fs::create_dir_all(&real_deks).expect("real deks");
        std::os::unix::fs::symlink(&real_deks, root.join("deks")).expect("symlink deks");
        let protector = SystemdCredsProtector {
            storage_root: root.clone(),
            dek_root: root.join("deks"),
        };
        let path = protector.path_for("0123456789abcdef");

        assert!(
            matches!(protector.prepare_write_path(&path), Err(Error::Io(message)) if message.contains("symlink"))
        );
    }

    #[cfg(all(target_os = "linux", feature = "systemd-creds"))]
    #[test]
    fn systemd_protector_delete_rejects_symlinked_dek_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("keys");
        let protector = SystemdCredsProtector {
            storage_root: root.clone(),
            dek_root: root.join("deks"),
        };
        let path = protector.path_for("0123456789abcdef");
        std::fs::create_dir_all(path.parent().expect("dek parent")).expect("dek parent");
        let target = dir.path().join("target.cred");
        std::fs::write(&target, b"credential").expect("target credential");
        std::os::unix::fs::symlink(&target, &path).expect("symlink dek");

        assert!(
            matches!(protector.delete_wrapped_dek(b"0123456789abcdef"), Err(Error::Io(message)) if message.contains("symlink"))
        );
        assert!(
            path.is_symlink(),
            "delete must not remove symlinked DEK path"
        );
    }

    #[cfg(all(target_os = "linux", feature = "systemd-creds"))]
    #[test]
    fn systemd_protector_write_path_creates_private_dirs() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("keys");
        let protector = SystemdCredsProtector {
            storage_root: root.clone(),
            dek_root: root.join("deks"),
        };
        let path = protector.path_for("0123456789abcdef");

        protector.prepare_write_path(&path).expect("prepare path");

        assert_eq!(mode(&root), 0o700);
        assert_eq!(mode(&root.join("deks")), 0o700);
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

    // -- BLS12-381 threshold share storage --------------------------
    //
    // End-to-end test against the test protector: dealer → store one
    // share per holder → load each share → sign with three holders →
    // aggregate → verify. The test exercises every line on the BLS
    // path including delete and the per-share AAD binding (a share
    // record stored under one cohort cannot be passed off as a share
    // for another cohort, because the cohort public key + holder
    // index are in the AAD).
    #[cfg(feature = "bls-threshold")]
    #[test]
    fn bls_share_storage_round_trip_and_verify() {
        use commonware_codec::{DecodeExt, Encode as _};
        use commonware_cryptography::bls12381::primitives::group::Share;
        use commonware_utils::{NZU32, test_rng_seeded};
        use mkit_attest::Signer as _;
        use tempfile::TempDir;

        let dir = TempDir::new().expect("tempdir");
        let store = SoftwareKeystore::with_root_and_protector(
            dir.path(),
            Arc::new(TestProtector) as Arc<dyn KeyProtector>,
        );

        // 3-of-4 cohort via the in-tree trusted dealer.
        let mut rng = test_rng_seeded(0xF00D);
        let (sharing, shares) = mkit_attest::bls_threshold_trusted_dealer(&mut rng, NZU32!(4));
        let agg_pubkey = sharing.public().encode().to_vec();
        let keyid = format!(
            "{}{}",
            mkit_attest::BLS_THRESHOLD_KEYID_PREFIX,
            hex_lower(&agg_pubkey)
        );

        // Store each share as `release-{index}`.
        for (offset, share) in shares.iter().enumerate() {
            let index = u32::try_from(offset).expect("offset fits in u32");
            let label = KeyLabel::new(format!("release-{index}")).unwrap();
            let share_bytes = share.encode().to_vec();
            store
                .store_bls_share(
                    &label,
                    &share_bytes,
                    agg_pubkey.clone(),
                    index,
                    3,
                    4,
                    keyid.clone(),
                    false,
                )
                .expect("store share");
        }

        // List shows all four.
        let listed = store.list_bls_shares().expect("list");
        assert_eq!(listed.len(), 4);

        // Reload three shares, build a ThresholdSigner per share, sign,
        // aggregate, verify.
        let pae = b"DSSEv1 28 application/vnd.in-toto+json 12 release v0.2.0";
        let mut partials: Vec<Vec<u8>> = Vec::with_capacity(3);
        for index in 0u32..3 {
            let label = KeyLabel::new(format!("release-{index}")).unwrap();
            let loaded = store.load_bls_share(&label).expect("load share");
            assert_eq!(loaded.metadata.share_index, index);
            assert_eq!(loaded.metadata.threshold, 3);
            assert_eq!(loaded.metadata.total, 4);
            assert_eq!(loaded.metadata.cohort_public_key, agg_pubkey);
            assert_eq!(loaded.metadata.keyid, keyid);
            let share = Share::decode(loaded.share_bytes.as_slice()).expect("decode share");
            let mut signer = mkit_attest::ThresholdSigner::new(share, sharing.clone());
            partials.push(signer.sign(pae).expect("sign"));
        }

        let agg_sig = mkit_attest::bls_threshold_aggregate(&sharing, &partials).expect("aggregate");
        mkit_attest::bls_threshold_verify(&agg_pubkey, pae, &agg_sig)
            .expect("aggregated signature verifies");

        // Tamper test: delete one share and re-load — gone.
        let label = KeyLabel::new("release-2").unwrap();
        store.delete_bls_share(&label).expect("delete");
        assert!(matches!(
            store.load_bls_share(&label),
            Err(Error::KeyNotFound(_))
        ));
    }

    /// A BLS share record's AAD binds the cohort public key + holder
    /// index + threshold + total. Flipping any of those in the
    /// on-disk record breaks the AEAD authentication and the load
    /// fails closed.
    #[cfg(feature = "bls-threshold")]
    #[test]
    fn bls_share_aad_binds_cohort_metadata() {
        use commonware_codec::Encode as _;
        use commonware_utils::{NZU32, test_rng_seeded};
        use tempfile::TempDir;

        let dir = TempDir::new().expect("tempdir");
        let store = SoftwareKeystore::with_root_and_protector(
            dir.path(),
            Arc::new(TestProtector) as Arc<dyn KeyProtector>,
        );

        let mut rng = test_rng_seeded(0xC0DE);
        let (sharing, shares) = mkit_attest::bls_threshold_trusted_dealer(&mut rng, NZU32!(4));
        let agg_pubkey = sharing.public().encode().to_vec();
        let label = KeyLabel::new("aad-bind").unwrap();
        let share_bytes = shares[0].encode().to_vec();
        store
            .store_bls_share(
                &label,
                &share_bytes,
                agg_pubkey.clone(),
                0,
                3,
                4,
                format!("bls12381-thr:{}", hex_lower(&agg_pubkey)),
                false,
            )
            .expect("store");

        // Read raw record bytes, flip the encoded threshold value, and
        // write back. The decrypt must fail because the AAD no longer
        // matches the ciphertext.
        let path = store.bls_path_for(label.as_str()).unwrap();
        let mut raw = std::fs::read(&path).expect("read");
        // The threshold u32 sits a known number of bytes in after the
        // magic/version/protector/cohort_pubkey prefix. Rather than
        // hand-compute the offset, decode + re-encode through the
        // record type with a mutated threshold; that's the same
        // tamper a hostile editor would produce by re-running our
        // encoder.
        let mut record = encrypted_record::BlsShareRecord::decode(&raw).unwrap();
        record.threshold = 1; // attacker drops the quorum to 1-of-N
        raw = record.encode().expect("re-encode tampered");
        std::fs::write(&path, &raw).expect("write");

        let result = store.load_bls_share(&label);
        assert!(
            result.is_err(),
            "BLS share with tampered threshold must not decrypt"
        );
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
