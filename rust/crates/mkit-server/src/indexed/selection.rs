//! Payload-free selection facts retained for every consumed pack, including
//! already-Verified packs. Facts are derived only from verified decoded bytes;
//! repository/global-store presence never changes the selection.

use std::collections::{BTreeMap, BTreeSet};

use mkit_core::hash::Hash;
use mkit_core::object::Object;
use mkit_core::ops::graph::{ClosureMode, children};
use serde::{Deserialize, Serialize};

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

    pub(super) fn encode(&self) -> Value {
        let mut bytes = vec![1];
        serde_json::to_writer(&mut bytes, self).expect("selection DTO serializes");
        Value::new(bytes)
    }

    pub(super) fn decode(value: &Value) -> Result<Self, StoreError> {
        let Some((&1, bytes)) = value.as_bytes().split_first() else {
            return Err(StoreError::Corrupt("bad selection fact version".into()));
        };
        serde_json::from_slice(bytes).map_err(|_| StoreError::Corrupt("bad selection fact".into()))
    }
}

/// The native union rule, operating without retaining decoded Blob payloads.
/// Group drivers may accumulate referenced identities in bounded persistent
/// rows; this function is also the native reference implementation.
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
