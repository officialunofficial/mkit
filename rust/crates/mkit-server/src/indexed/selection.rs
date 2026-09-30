//! Payload-free selection facts retained for every consumed pack, including
//! already-Verified packs. Facts are derived only from verified decoded bytes;
//! repository/global-store presence never changes the selection.

#[cfg(test)]
use std::collections::{BTreeMap, BTreeSet};

use mkit_core::hash::{Hash, Hasher};
use mkit_core::object::Object;
use mkit_core::ops::graph::{ClosureMode, children};
use serde::{Deserialize, Serialize};

#[cfg(test)]
use super::extract::Kind;
use crate::store::{StoreError, Value};

/// One decoded entry's projection for union selection. Stored in vc sub-4.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) enum SelectionFact {
    Blob { size: u64 },
    Manifest { size: u64, chunks: Vec<Hash> },
    Tree { files: Vec<Hash> },
    Other,
}

impl SelectionFact {
    pub(super) fn from_object(object: &Object) -> Self {
        match object {
            Object::Blob(blob) => Self::Blob {
                size: blob.data.len() as u64,
            },
            Object::ChunkedBlob(manifest) => Self::Manifest {
                size: manifest.total_size,
                chunks: manifest.chunks.clone(),
            },
            Object::Tree(_) => Self::Tree {
                files: children(object, ClosureMode::History),
            },
            _ => Self::Other,
        }
    }

    pub(super) fn content_len(&self) -> u64 {
        match self {
            Self::Blob { size } | Self::Manifest { size, .. } => *size,
            _ => 0,
        }
    }

    #[cfg(test)]
    pub(super) fn encode(&self) -> Value {
        let mut bytes = vec![1];
        serde_json::to_writer(&mut bytes, self).expect("selection DTO serializes");
        Value::new(bytes)
    }

    #[cfg(test)]
    pub(super) fn decode(value: &Value) -> Result<Self, StoreError> {
        let Some((&1, bytes)) = value.as_bytes().split_first() else {
            return Err(StoreError::Corrupt("bad selection fact version".into()));
        };
        serde_json::from_slice(bytes).map_err(|_| StoreError::Corrupt("bad selection fact".into()))
    }
}

/// Reference pages are deliberately small enough that ninety rows and their
/// guards fit the existing one-MiB batch envelope.
pub(super) const REFERENCES_PER_PAGE: usize = 128;

/// A frozen projection descriptor. All pages must be read in order and their
/// full reference digest checked before any group selection is committed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Projection {
    pub(super) owner: Hash,
    pub(super) kind: u8,
    pub(super) size: u64,
    pub(super) references: u32,
    pub(super) digest: Hash,
}

impl Projection {
    pub(super) fn from_fact(owner: Hash, fact: &SelectionFact) -> Self {
        let (kind, refs): (u8, &[Hash]) = match fact {
            SelectionFact::Blob { .. } => (0, &[]),
            SelectionFact::Manifest { chunks, .. } => (1, chunks),
            SelectionFact::Tree { files } => (2, files),
            SelectionFact::Other => (3, &[]),
        };
        let mut hash = Self::reference_hasher(&owner, kind);
        for id in refs {
            hash.update(id);
        }
        Self {
            owner,
            kind,
            size: fact.content_len(),
            references: u32::try_from(refs.len()).expect("decoded entry is bounded"),
            digest: hash.finalize(),
        }
    }

    /// Bound page geometry to the frozen job's verified frame before any
    /// reference-page query. The caller also checks the source/job guards and
    /// completes the reference digest scan before freezing group selection.
    pub(super) fn validate_frame(
        &self,
        frame: &super::checkpoint::FrameRow,
        pack_len: u64,
        decoded_bytes: u64,
    ) -> Result<(), StoreError> {
        use mkit_core::object::ObjectType;
        let size = frame.value.decoded_size;
        let refs = u64::from(self.references);
        let typed = match self.kind {
            0 => {
                frame.object_type == ObjectType::Blob as u8
                    && self.size.checked_add(10) == Some(size)
                    && refs == 0
            }
            1 => {
                frame.object_type == ObjectType::ChunkedBlob as u8
                    && refs.checked_mul(32).and_then(|n| n.checked_add(22)) == Some(size)
            }
            2 => {
                frame.object_type == ObjectType::Tree as u8
                    && self.size == 0
                    && refs <= u64::from(mkit_core::serialize::MAX_TREE_ENTRIES)
                    && refs
                        .checked_mul(38)
                        .and_then(|n| n.checked_add(10))
                        .is_some_and(|minimum| minimum <= size)
            }
            3 => matches!(frame.object_type, 3 | 4 | 7) && refs == 0 && self.size == 0,
            _ => false,
        };
        if !typed
            || size > decoded_bytes
            || frame.value.frame_length == 0
            || frame
                .value
                .frame_offset
                .checked_add(frame.value.frame_length)
                .is_none_or(|end| end > pack_len)
        {
            return Err(StoreError::Corrupt(
                "selection frame geometry mismatch".into(),
            ));
        }
        Ok(())
    }

    pub(super) fn reference_hasher(owner: &Hash, kind: u8) -> Hasher {
        let mut hash = Hasher::new();
        hash.update(b"mkit-selection-references:v2");
        hash.update(owner);
        hash.update(&[kind]);
        hash
    }

    pub(super) fn pages(&self) -> u32 {
        self.references.div_ceil(128)
    }

    pub(super) fn encode(&self) -> Value {
        let mut out = vec![2, self.kind];
        out.extend(self.owner);
        out.extend(self.size.to_be_bytes());
        out.extend(self.references.to_be_bytes());
        out.extend(self.pages().to_be_bytes());
        out.extend(self.digest);
        Value::new(out)
    }

    pub(super) fn decode(owner: &Hash, value: &Value) -> Result<Self, StoreError> {
        let b = value.as_bytes();
        if b.len() != 82 || b[0] != 2 || b[1] > 3 || &b[2..34] != owner {
            return Err(StoreError::Corrupt("bad selection projection".into()));
        }
        let result = Self {
            owner: *owner,
            kind: b[1],
            size: u64::from_be_bytes(
                b[34..42]
                    .try_into()
                    .map_err(|_| StoreError::Corrupt("bad selection geometry".into()))?,
            ),
            references: u32::from_be_bytes(
                b[42..46]
                    .try_into()
                    .map_err(|_| StoreError::Corrupt("bad selection geometry".into()))?,
            ),
            digest: b[50..82]
                .try_into()
                .map_err(|_| StoreError::Corrupt("bad selection geometry".into()))?,
        };
        if u32::from_be_bytes(
            b[46..50]
                .try_into()
                .map_err(|_| StoreError::Corrupt("bad selection geometry".into()))?,
        ) != result.pages()
            || (matches!(result.kind, 0 | 3) && result.references != 0)
            || (matches!(result.kind, 2 | 3) && result.size != 0)
        {
            return Err(StoreError::Corrupt(
                "bad selection projection geometry".into(),
            ));
        }
        Ok(result)
    }

    /// Page identities are domain separated from object identities, and every
    /// page carries its full owning object, kind, count, digest and index.
    pub(super) fn page_id(&self, index: u32) -> Hash {
        let mut hash = Hasher::new();
        hash.update(b"mkit-selection-reference-page:v2");
        hash.update(&self.owner);
        hash.update(&self.digest);
        hash.update(&[self.kind]);
        hash.update(&self.references.to_be_bytes());
        hash.update(&index.to_be_bytes());
        hash.finalize()
    }

    pub(super) fn encode_page(&self, index: u32, refs: &[Hash]) -> Value {
        let mut out = vec![3];
        out.extend(self.encode().as_bytes());
        out.extend(index.to_be_bytes());
        out.extend(
            u16::try_from(refs.len())
                .expect("bounded reference page")
                .to_be_bytes(),
        );
        for id in refs {
            out.extend(id);
        }
        Value::new(out)
    }

    pub(super) fn decode_page<'a>(
        &self,
        index: u32,
        value: &'a Value,
    ) -> Result<impl Iterator<Item = Hash> + 'a, StoreError> {
        let b = value.as_bytes();
        if index >= self.pages()
            || b.len() < 89
            || b[0] != 3
            || Self::decode(&self.owner, &Value::new(b[1..83].to_vec()))? != *self
            || u32::from_be_bytes(
                b[83..87]
                    .try_into()
                    .map_err(|_| StoreError::Corrupt("bad selection geometry".into()))?,
            ) != index
        {
            return Err(StoreError::Corrupt("bad selection reference page".into()));
        }
        let count =
            usize::from(u16::from_be_bytes(b[87..89].try_into().map_err(|_| {
                StoreError::Corrupt("bad selection geometry".into())
            })?));
        let expected = (self.references as usize - index as usize * REFERENCES_PER_PAGE)
            .min(REFERENCES_PER_PAGE);
        if count != expected || b.len() != 89 + count * 32 {
            return Err(StoreError::Corrupt(
                "bad selection reference page geometry".into(),
            ));
        }
        Ok(b[89..].as_chunks::<32>().0.iter().copied())
    }
}

impl SelectionFact {
    pub(super) fn references(&self) -> &[Hash] {
        match self {
            Self::Manifest { chunks, .. } => chunks,
            Self::Tree { files } => files,
            _ => &[],
        }
    }
}

/// The native union rule, operating without retaining decoded Blob payloads.
/// Group drivers may accumulate referenced identities in bounded persistent
/// rows; this function is also the native reference implementation.
#[cfg(test)]
pub(super) fn select_facts(
    facts: &BTreeMap<Hash, SelectionFact>,
    min_bytes: u64,
) -> BTreeMap<Hash, Kind> {
    let (mut chunks, mut files) = (BTreeSet::new(), BTreeSet::new());
    for fact in facts.values() {
        match fact {
            SelectionFact::Manifest { chunks: refs, .. } => chunks.extend(refs.iter().copied()),
            SelectionFact::Tree { files: refs } => files.extend(refs.iter().copied()),
            _ => {}
        }
    }
    facts
        .iter()
        .filter_map(|(id, fact)| match fact {
            SelectionFact::Manifest { .. } => Some((*id, Kind::Chunked)),
            SelectionFact::Blob { size }
                if *size >= min_bytes && (!chunks.contains(id) || files.contains(id)) =>
            {
                Some((*id, Kind::Blob))
            }
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod paging_tests {
    use super::*;

    #[test]
    fn legal_large_manifest_projection_fits_storage_values() {
        // Canonical references fit the existing decoded-entry allowance.
        let object = Object::ChunkedBlob(mkit_core::object::ChunkedBlob {
            total_size: 20_000 * 65_536,
            chunk_size: 65_536,
            chunks: (0_u32..20_000)
                .map(|i| {
                    let mut id = [0; 32];
                    id[..4].copy_from_slice(&i.to_be_bytes());
                    id
                })
                .collect(),
        });
        let canonical = mkit_core::serialize::serialize(&object).unwrap();
        assert!(canonical.len() < 1024 * 1024);
        let fact = SelectionFact::from_object(&object);
        let owner = [7; 32];
        let projection = Projection::from_fact(owner, &fact);
        assert_eq!(
            Projection::decode(&owner, &projection.encode()).unwrap(),
            projection
        );
        let mut hash = Projection::reference_hasher(&owner, projection.kind);
        let mut consumed = 0;
        for (index, refs) in fact.references().chunks(REFERENCES_PER_PAGE).enumerate() {
            let index = u32::try_from(index).unwrap();
            let value = projection.encode_page(index, refs);
            assert!(value.as_bytes().len() <= crate::store::MAX_VALUE_BYTES);
            for id in projection.decode_page(index, &value).unwrap() {
                hash.update(&id);
                consumed += 1;
            }
            assert!(projection.decode_page(index + 1, &value).is_err());
            let mut trailing = value.as_bytes().to_vec();
            trailing.push(0);
            assert!(
                projection
                    .decode_page(index, &Value::new(trailing))
                    .is_err()
            );
        }
        assert_eq!(consumed, 20_000);
        assert_eq!(hash.finalize(), projection.digest);
    }
    #[test]
    fn large_tree_projection_preserves_every_reference() {
        use mkit_core::object::{EntryMode, Tree, TreeEntry};
        let object = Object::Tree(Tree {
            entries: (0_u32..15_000)
                .map(|n| {
                    let mut id = [0; 32];
                    id[..4].copy_from_slice(&n.to_be_bytes());
                    TreeEntry {
                        name: format!("f{n:05}").into_bytes(),
                        mode: EntryMode::Blob,
                        object_hash: id,
                    }
                })
                .collect(),
        });
        let bytes = mkit_core::serialize::serialize(&object).unwrap();
        assert!(bytes.len() < 1024 * 1024);
        assert_eq!(mkit_core::serialize::deserialize(&bytes).unwrap(), object);
        let fact = SelectionFact::from_object(&object);
        let owner = object.id().unwrap();
        let projection = Projection::from_fact(owner, &fact);
        let mut recovered = Vec::new();
        for (index, refs) in fact.references().chunks(REFERENCES_PER_PAGE).enumerate() {
            let value = projection.encode_page(u32::try_from(index).unwrap(), refs);
            assert!(value.as_bytes().len() < 9 * 1024);
            recovered.extend(
                projection
                    .decode_page(u32::try_from(index).unwrap(), &value)
                    .unwrap(),
            );
        }
        assert_eq!(recovered, fact.references());
        assert_eq!(projection.kind, 2);
        assert_eq!(projection.references, 15_000);
    }
    #[test]
    fn page_batch_fits_even_with_largest_job_guard_and_keys() {
        use crate::store::{Batch, Key, Precondition, StoreCapabilities, Write};
        let fact = SelectionFact::Tree {
            files: vec![[1; 32]; REFERENCES_PER_PAGE],
        };
        let projection = Projection::from_fact([2; 32], &fact);
        let value = projection.encode_page(0, fact.references());
        let key = Key::new(vec![b'x'; crate::store::MAX_KEY_BYTES]);
        let mut batch = Batch::new()
            .require(Precondition::Equals(
                key.clone(),
                Value::new(vec![0; crate::store::MAX_VALUE_BYTES]),
            ))
            .require(Precondition::NotAfter(1));
        batch
            .writes
            .extend((0..90).map(|_| Write::Put(key.clone(), value.clone())));
        batch.validate(&StoreCapabilities::full()).unwrap();
    }
    #[test]
    fn frame_binding_rejects_unbounded_or_foreign_facts_before_page_queries() {
        use super::super::checkpoint::FrameRow;
        use crate::store::index::IndexValue;
        let frame = FrameRow {
            value: IndexValue {
                frame_offset: 12,
                frame_length: 59,
                wire_type: 0,
                decoded_size: 54,
                chain_depth: 0,
                delta_base: None,
            },
            object_type: 5,
            external: None,
        };
        let fact = SelectionFact::Manifest {
            size: 42,
            chunks: vec![[1; 32]],
        };
        let mut projection = Projection::from_fact([2; 32], &fact);
        projection.validate_frame(&frame, 1000, 54).unwrap();
        projection.references = u32::MAX;
        assert!(projection.validate_frame(&frame, 1000, 54).is_err());
        projection.references = 1;
        projection.kind = 0;
        assert!(projection.validate_frame(&frame, 1000, 54).is_err());
        projection.kind = 1;
        assert!(projection.validate_frame(&frame, 1000, 53).is_err());
        let mut outside = frame;
        outside.value.frame_offset = u64::MAX;
        assert!(projection.validate_frame(&outside, 1000, 54).is_err());
    }
}
