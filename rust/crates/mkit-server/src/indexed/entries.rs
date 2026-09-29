//! Pure index metadata derived from decoded pack entries.

use crate::ServerError;
use crate::store::index::{IndexEntry, IndexValue};
use mkit_core::hash::Hash;
use std::collections::BTreeMap;

/// Frame facts captured directly from `decode_entries_with`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameMeta {
    pub id: Hash,
    pub frame_offset: u64,
    pub frame_length: u64,
    pub wire_type: u8,
    pub delta_base: Option<Hash>,
    pub decoded_size: u64,
}

/// Derive write-once index rows from the frame list, retaining the first
/// occurrence of each object. No repository or storage observation enters
/// this function. External bases contribute one in-pack depth; the resolver
/// checks total depth separately.
pub fn index_entries(frames: &[FrameMeta], cap: u32) -> Result<Vec<IndexEntry>, ServerError> {
    let mut depths = BTreeMap::new();
    let mut entries = Vec::with_capacity(frames.len());
    for frame in frames {
        if depths.contains_key(&frame.id) {
            continue;
        }
        let depth = match frame.delta_base {
            None => 0,
            Some(base) => depths.get(&base).copied().unwrap_or(0u32).saturating_add(1),
        };
        if depth > cap {
            return Err(ServerError::invalid_argument("delta chain too deep"));
        }
        depths.insert(frame.id, depth);
        entries.push(IndexEntry {
            object: frame.id,
            value: IndexValue {
                frame_offset: frame.frame_offset,
                frame_length: frame.frame_length,
                wire_type: frame.wire_type,
                decoded_size: frame.decoded_size,
                chain_depth: depth,
                delta_base: frame.delta_base,
            },
        });
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(id: u8, base: Option<u8>, offset: u64) -> FrameMeta {
        FrameMeta {
            id: [id; 32],
            frame_offset: offset,
            frame_length: 10,
            wire_type: if base.is_some() { 0x02 } else { 0x00 },
            delta_base: base.map(|id| [id; 32]),
            decoded_size: 5,
        }
    }

    #[test]
    fn first_occurrence_and_depth_are_pure_from_frames() {
        let frames = [
            frame(1, None, 10),
            frame(2, Some(1), 20),
            frame(3, Some(2), 30),
            frame(1, Some(99), 40),
            frame(4, Some(99), 50),
        ];
        let once = index_entries(&frames, 50).unwrap();
        assert_eq!(once, index_entries(&frames, 50).unwrap());
        assert_eq!(once.len(), 4);
        assert_eq!(
            once.iter()
                .map(|entry| entry.value.chain_depth)
                .collect::<Vec<_>>(),
            [0, 1, 2, 1]
        );
        assert_eq!(once[0].value.frame_offset, 10);
        assert_eq!(
            index_entries(&frames, 1).unwrap_err().public_message(),
            "delta chain too deep"
        );
    }
}
