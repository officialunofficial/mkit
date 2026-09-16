//! Bounded codec for `MKWB` v1 partial snapshot bundles.

use std::collections::BTreeSet;

use bytes::Buf;
use commonware_codec::{RangeCfg, Read, ReadExt, Write};

use crate::hash::Hash;

use super::{PartialError, PartialLimits, PartialPath, validate_paths};

const MAGIC: &[u8; 4] = b"MKWB";
const VERSION: u8 = 1;

pub(crate) type BundleParts = (Hash, Vec<PartialPath>, Vec<(Hash, Vec<u8>)>);

/// One canonical object carried by a partial snapshot bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialObject {
    id: Hash,
    canonical_bytes: Vec<u8>,
}

impl PartialObject {
    #[must_use]
    pub fn id(&self) -> &Hash {
        &self.id
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
}

/// Portable selected-file snapshot. This is a carrier, not an mkit object and
/// not a claim of full snapshot/history closure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialSnapshotBundle {
    base_id: Hash,
    paths: Vec<PartialPath>,
    objects: Vec<PartialObject>,
}

impl PartialSnapshotBundle {
    pub(crate) fn new(
        base_id: Hash,
        paths: Vec<PartialPath>,
        objects: Vec<(Hash, Vec<u8>)>,
        limits: &PartialLimits,
    ) -> Result<Self, PartialError> {
        let objects = objects
            .into_iter()
            .map(|(id, canonical_bytes)| PartialObject {
                id,
                canonical_bytes,
            })
            .collect();
        let bundle = Self {
            base_id,
            paths,
            objects,
        };
        bundle.validate_shape(limits)?;
        if bundle.encoded_len()? > limits.max_bundle_bytes {
            return Err(PartialError::WorkspaceTooLarge);
        }
        Ok(bundle)
    }

    #[must_use]
    pub fn base_id(&self) -> &Hash {
        &self.base_id
    }

    #[must_use]
    pub fn paths(&self) -> &[PartialPath] {
        &self.paths
    }

    #[must_use]
    pub fn objects(&self) -> &[PartialObject] {
        &self.objects
    }

    pub(crate) fn into_parts(self) -> BundleParts {
        (
            self.base_id,
            self.paths,
            self.objects
                .into_iter()
                .map(|object| (object.id, object.canonical_bytes))
                .collect(),
        )
    }

    /// Encode with fixed integers big-endian and minimal commonware varints.
    pub fn encode(&self, limits: &PartialLimits) -> Result<Vec<u8>, PartialError> {
        self.validate_shape(limits)?;
        let capacity = self.encoded_len()?;
        if capacity > limits.max_bundle_bytes {
            return Err(PartialError::WorkspaceTooLarge);
        }
        let mut out = Vec::with_capacity(capacity);
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        self.base_id.write(&mut out);
        self.paths.len().write(&mut out);
        for path in &self.paths {
            path.len().write(&mut out);
            for component in path {
                component.as_slice().write(&mut out);
            }
        }
        self.objects.len().write(&mut out);
        for object in &self.objects {
            object.id.write(&mut out);
            object.canonical_bytes.as_slice().write(&mut out);
        }
        Ok(out)
    }

    /// Decode untrusted bytes while checking every count and aggregate byte
    /// budget before allocating its corresponding vector.
    pub fn decode(bytes: &[u8], limits: &PartialLimits) -> Result<Self, PartialError> {
        if !limits.is_v1_subset() {
            return Err(PartialError::ValidationBudgetExceeded);
        }
        if bytes.len() > limits.max_bundle_bytes {
            return Err(PartialError::WorkspaceTooLarge);
        }
        if bytes.len() < 5 || &bytes[..4] != MAGIC {
            return Err(PartialError::NonCanonical);
        }
        if bytes[4] != VERSION {
            return Err(PartialError::UnsupportedVersion(bytes[4]));
        }
        let mut input = &bytes[5..];
        let base_id = Hash::read(&mut input).map_err(|_| PartialError::NonCanonical)?;
        let path_count = read_len(&mut input, 1, limits.max_selected_paths)?;
        let mut paths = Vec::with_capacity(path_count);
        let mut total_path_bytes = 0usize;
        for _ in 0..path_count {
            let components = read_len(&mut input, 1, limits.max_path_depth)?;
            let mut path = Vec::with_capacity(components);
            let mut path_bytes = 0usize;
            for _ in 0..components {
                let len = read_len(&mut input, 1, limits.max_component_bytes)?;
                let separator = usize::from(!path.is_empty());
                path_bytes = checked_add(path_bytes, separator)?;
                path_bytes = checked_add(path_bytes, len)?;
                total_path_bytes = total_path_bytes
                    .checked_add(separator)
                    .and_then(|total| total.checked_add(len))
                    .ok_or(PartialError::WorkspaceTooLarge)?;
                if path_bytes > limits.max_path_bytes
                    || total_path_bytes > limits.max_total_path_bytes
                    || input.remaining() < len
                {
                    return Err(PartialError::WorkspaceTooLarge);
                }
                path.push(input[..len].to_vec());
                input = &input[len..];
            }
            paths.push(path);
        }
        validate_paths(&paths, limits)?;

        let object_count = read_len(&mut input, 1, limits.max_objects)?;
        let mut objects = Vec::with_capacity(object_count);
        let mut object_bytes = 0usize;
        let mut prior = None;
        for _ in 0..object_count {
            let id = Hash::read(&mut input).map_err(|_| PartialError::NonCanonical)?;
            if prior.is_some_and(|p| p >= id) {
                return Err(PartialError::NonCanonical);
            }
            prior = Some(id);
            let len = read_len(&mut input, 1, limits.max_object_bytes)?;
            object_bytes = object_bytes
                .checked_add(len)
                .ok_or(PartialError::WorkspaceTooLarge)?;
            if object_bytes > limits.max_bundle_bytes || input.remaining() < len {
                return Err(PartialError::WorkspaceTooLarge);
            }
            objects.push(PartialObject {
                id,
                canonical_bytes: input[..len].to_vec(),
            });
            input = &input[len..];
        }
        if input.has_remaining() {
            return Err(PartialError::NonCanonical);
        }
        let bundle = Self {
            base_id,
            paths,
            objects,
        };
        bundle.validate_shape(limits)?;
        Ok(bundle)
    }

    fn validate_shape(&self, limits: &PartialLimits) -> Result<(), PartialError> {
        if !limits.is_v1_subset() {
            return Err(PartialError::ValidationBudgetExceeded);
        }
        validate_paths(&self.paths, limits)?;
        if self.objects.is_empty() || self.objects.len() > limits.max_objects {
            return Err(PartialError::ValidationBudgetExceeded);
        }
        let mut seen = BTreeSet::new();
        let mut prior = None;
        for object in &self.objects {
            if object.canonical_bytes.is_empty()
                || object.canonical_bytes.len() > limits.max_object_bytes
                || prior.is_some_and(|p| p >= object.id)
                || !seen.insert(object.id)
            {
                return Err(PartialError::NonCanonical);
            }
            prior = Some(object.id);
        }
        Ok(())
    }

    fn encoded_len(&self) -> Result<usize, PartialError> {
        let mut total = 5usize + 32 + varint_len(self.paths.len()) + varint_len(self.objects.len());
        for path in &self.paths {
            total = checked_add(total, varint_len(path.len()))?;
            for component in path {
                total = checked_add(total, varint_len(component.len()))?;
                total = checked_add(total, component.len())?;
            }
        }
        for object in &self.objects {
            total = checked_add(total, 32 + varint_len(object.canonical_bytes.len()))?;
            total = checked_add(total, object.canonical_bytes.len())?;
        }
        Ok(total)
    }
}

fn read_len(input: &mut &[u8], min: usize, max: usize) -> Result<usize, PartialError> {
    usize::read_cfg(input, &RangeCfg::new(min..=max)).map_err(|_| PartialError::NonCanonical)
}

fn checked_add(a: usize, b: usize) -> Result<usize, PartialError> {
    a.checked_add(b).ok_or(PartialError::WorkspaceTooLarge)
}

fn varint_len(mut value: usize) -> usize {
    let mut len = 1;
    while value >= 0x80 {
        value >>= 7;
        len += 1;
    }
    len
}
