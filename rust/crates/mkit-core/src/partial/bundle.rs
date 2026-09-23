//! Bounded codec for `MKWB` v1 partial snapshot bundles.

use std::collections::BTreeSet;

use bytes::Buf;
use commonware_codec::{RangeCfg, Read, ReadExt, Write};

use crate::hash::Hash;

use super::{PartialError, PartialLimits, PartialPath, validate_paths};

const MAGIC: &[u8; 4] = b"MKWB";
const VERSION: u8 = 1;

pub(crate) type BundleParts = (Hash, Vec<PartialPath>, Vec<(Hash, Vec<u8>)>);

/// Incremental accounting for the exact encoded size of an `MKWB` bundle.
///
/// The object-count prefix is adjusted at each varint boundary. Callers must
/// charge an object only once, after deduplicating it by id.
#[derive(Debug)]
pub(crate) struct BundleBudget {
    encoded_bytes: usize,
    object_count: usize,
    max_bytes: usize,
    max_objects: usize,
}

impl BundleBudget {
    pub(crate) fn new(paths: &[PartialPath], limits: &PartialLimits) -> Result<Self, PartialError> {
        let mut encoded_bytes = checked_add(5, 32)?;
        encoded_bytes = checked_add(encoded_bytes, varint_len(paths.len()))?;
        for path in paths {
            encoded_bytes = checked_add(encoded_bytes, varint_len(path.len()))?;
            for component in path {
                encoded_bytes = checked_add(encoded_bytes, varint_len(component.len()))?;
                encoded_bytes = checked_add(encoded_bytes, component.len())?;
            }
        }
        encoded_bytes = checked_add(encoded_bytes, varint_len(0))?;
        if encoded_bytes > limits.max_bundle_bytes {
            return Err(PartialError::WorkspaceTooLarge);
        }
        Ok(Self {
            encoded_bytes,
            object_count: 0,
            max_bytes: limits.max_bundle_bytes,
            max_objects: limits.max_objects,
        })
    }

    /// Reject before a source read when even the smallest legal object record
    /// cannot fit. The exact returned object length is charged after that one
    /// caller-bounded read and before the bytes are retained.
    pub(crate) fn ensure_object_read_possible(&self) -> Result<(), PartialError> {
        self.next_encoded_bytes(1).map(|_| ())
    }

    pub(crate) fn charge_object(&mut self, bytes_len: usize) -> Result<(), PartialError> {
        let next = self.next_encoded_bytes(bytes_len)?;
        self.encoded_bytes = next;
        self.object_count += 1;
        Ok(())
    }

    /// Largest next payload that can fit exactly, including its variable
    /// length prefix. Used as an advisory preallocation cap by a request
    /// driver; the producer still charges the actual response before decode.
    pub(crate) fn max_next_object_bytes(&self, role_cap: usize) -> Result<usize, PartialError> {
        self.ensure_object_read_possible()?;
        if role_cap == 0 {
            return Ok(0);
        }
        let mut low = 1usize;
        let mut high = role_cap;
        while low < high {
            let mid = low + (high - low).div_ceil(2);
            if self.next_encoded_bytes(mid).is_ok() {
                low = mid;
            } else {
                high = mid - 1;
            }
        }
        Ok(low)
    }

    pub(crate) fn encoded_bytes(&self) -> usize {
        self.encoded_bytes
    }

    fn next_encoded_bytes(&self, bytes_len: usize) -> Result<usize, PartialError> {
        let next_count = self
            .object_count
            .checked_add(1)
            .ok_or(PartialError::ValidationBudgetExceeded)?;
        if next_count > self.max_objects {
            return Err(PartialError::ValidationBudgetExceeded);
        }
        let count_prefix_growth = varint_len(next_count) - varint_len(self.object_count);
        let mut next = checked_add(self.encoded_bytes, count_prefix_growth)?;
        next = checked_add(next, 32)?;
        next = checked_add(next, varint_len(bytes_len))?;
        next = checked_add(next, bytes_len)?;
        if next > self.max_bytes {
            return Err(PartialError::WorkspaceTooLarge);
        }
        Ok(next)
    }
}

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
        bundle.encoded_len(limits)?;
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
        let capacity = self.encoded_len(limits)?;
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

    fn encoded_len(&self, limits: &PartialLimits) -> Result<usize, PartialError> {
        let mut budget = BundleBudget::new(&self.paths, limits)?;
        for object in &self.objects {
            budget.charge_object(object.canonical_bytes.len())?;
        }
        Ok(budget.encoded_bytes())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incremental_budget_matches_encoder_at_varint_boundaries() {
        let paths = vec![vec![b"a".to_vec()]];
        let objects = (0u8..128)
            .map(|index| {
                let mut id = [0; 32];
                id[31] = index;
                let bytes_len = match index {
                    0 => 127,
                    1 => 128,
                    _ => 1,
                };
                (id, vec![index; bytes_len])
            })
            .collect::<Vec<_>>();
        let default = PartialLimits::default();
        let encoded = PartialSnapshotBundle::new([9; 32], paths.clone(), objects.clone(), &default)
            .unwrap()
            .encode(&default)
            .unwrap();
        let exact = PartialLimits {
            max_bundle_bytes: encoded.len(),
            ..default
        };
        let exact_bundle =
            PartialSnapshotBundle::new([9; 32], paths.clone(), objects.clone(), &exact).unwrap();
        assert_eq!(exact_bundle.encode(&exact).unwrap().len(), encoded.len());

        let one_byte_short = PartialLimits {
            max_bundle_bytes: encoded.len() - 1,
            ..default
        };
        assert!(matches!(
            PartialSnapshotBundle::new([9; 32], paths, objects, &one_byte_short),
            Err(PartialError::WorkspaceTooLarge)
        ));
    }
}
