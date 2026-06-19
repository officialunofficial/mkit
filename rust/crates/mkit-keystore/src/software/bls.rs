//! BLS12-381 threshold share storage for the software keystore.
//!
//! BLS shares can't ride the generic `KeyImporter` / `KeyExporter`
//! traits because their plaintext is variable-length (a wire-encoded
//! `Share`, ≈52 bytes). They have a dedicated API on
//! `SoftwareKeystore` that uses the same crash-atomic write pattern
//! and AEAD-bound AAD as the 32-byte path, just with a different
//! record format (`BlsShareRecord`) and on-disk directory layout
//! (`<root>/bls12381-thr/`).
//!
//! The release-party CLI (`mkit key generate --algorithm bls12381-thr
//! --threshold M --total N --label <base>`) calls `store_bls_share`
//! once per dealt share, using labels like `<base>-<index>`.

use std::path::PathBuf;
use std::sync::Arc;

use super::atomic_write::{cleanup_new_dek_after_write_failure, write_key_file};
use super::{SoftwareKeystore, hex_decode};
use crate::encrypted_record::{self, KeyProtector};
use crate::types::hex_lower;
use crate::{Algorithm, Error, KeyLabel, KeySelector, Result, validate_label};

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

/// A loaded BLS share plus its public metadata.
#[derive(Debug)]
pub struct LoadedBlsShare {
    /// Wire-encoded `Share` bytes (zeroized on drop).
    pub share_bytes: zeroize::Zeroizing<Vec<u8>>,
    /// Public metadata for this share.
    pub metadata: BlsShareMetadata,
}

impl SoftwareKeystore {
    /// Subdirectory for BLS shares within the keystore root.
    const BLS_DIR: &'static str = "bls12381-thr";

    fn bls_dir(&self) -> PathBuf {
        self.root.join(Self::BLS_DIR)
    }

    pub(super) fn bls_path_for(&self, label: &str) -> Result<PathBuf> {
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
        super::default_protector_by_id(&self.root, &record.protector)
    }
}
