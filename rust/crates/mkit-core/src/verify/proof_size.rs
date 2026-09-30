//! Exact MKDP/MKDS lengths from metadata, without constructing Merkle or Bao
//! proofs. Chunk lengths describe canonical Blob content, excluding its ten
//! header bytes. All results enforce the 64 MiB wire cap.

use super::span::{RangeProofError, RangeProofKind};
use super::{MAX_BUNDLE_BYTES, MAX_COMMIT_BYTES, VerifyError};
use crate::merkle;

/// Metadata describing one authenticated tree path component.
#[derive(Debug, Clone, Copy)]
pub struct PrefixStep {
    /// Number of bytes in the entry name.
    pub name_len: usize,
    /// Entry position within its tree.
    pub position: u32,
    /// Number of entries in that tree.
    pub leaf_count: u32,
}

/// Exact format, chunk bounds and wire length selected by a chunked range.
#[derive(Debug, Clone, Copy)]
pub struct EncodedRangePlan {
    /// MKDP for one chunk; MKDS for a range crossing a boundary.
    pub kind: RangeProofKind,
    /// First requested chunk index.
    pub first: usize,
    /// Last requested chunk index.
    pub last: usize,
    /// Complete encoded response length, already checked against the cap.
    pub encoded_size: u64,
}

fn varint_size(mut value: u64) -> u128 {
    let mut size = 1;
    while value >= 128 {
        value >>= 7;
        size += 1;
    }
    size
}

fn vector_size(bytes: u64) -> u128 {
    varint_size(bytes) + u128::from(bytes)
}

fn capped(size: u128) -> Result<u64, RangeProofError> {
    if size > MAX_BUNDLE_BYTES as u128 {
        Err(RangeProofError::ProofTooLarge)
    } else {
        u64::try_from(size).map_err(|_| RangeProofError::ProofTooLarge)
    }
}

fn proof_size(count: u32, positions: &[u32]) -> Result<u128, RangeProofError> {
    merkle::proof_encoded_size(count, positions.iter().copied())
        .map(|size| size as u128)
        .map_err(|error| VerifyError::from(error).into())
}

fn prefix_size(commit_bytes: u64, steps: &[PrefixStep]) -> Result<u128, RangeProofError> {
    if commit_bytes > MAX_COMMIT_BYTES as u64 {
        return Err(RangeProofError::ProofTooLarge);
    }
    if steps.len() > crate::store::MAX_TREE_DEPTH {
        return Err(VerifyError::TooManySteps(steps.len()).into());
    }
    let mut size = 38 + vector_size(commit_bytes) + varint_size(steps.len() as u64);
    for step in steps {
        if step.name_len == 0 || step.name_len > 255 {
            return Err(VerifyError::Malformed.into());
        }
        size +=
            vector_size(step.name_len as u64) + 69 + proof_size(step.leaf_count, &[step.position])?;
    }
    capped(size)?;
    Ok(size)
}

/// Exact canonical Object bundle size, including manifest and root-tree
/// objects. `commit_bytes` and `object_bytes` are canonical encoded lengths.
///
/// # Errors
/// Invalid path metadata or an encoded bundle exceeding the cap.
pub fn object_proof_size(
    commit_bytes: u64,
    steps: &[PrefixStep],
    object_bytes: u64,
) -> Result<u64, RangeProofError> {
    capped(prefix_size(commit_bytes, steps)? + vector_size(object_bytes))
}

// Number of Bao parent pairs included for the selected inclusive chunk
// interval. Fully covered subtrees have leaves-1 parents; only boundary
// paths recurse, so sizing is logarithmic even for enormous lengths.
fn bao_parents(base: u64, leaves: u64, first: u64, last: u64) -> u64 {
    if first <= base && base + leaves - 1 <= last {
        return leaves - 1;
    }
    if leaves == 1 || last < base || first >= base + leaves {
        return 0;
    }
    let left = 1u64 << (63 - (leaves - 1).leading_zeros());
    1 + bao_parents(base, left, first, last) + bao_parents(base + left, leaves - left, first, last)
}

fn bao_slice_size(canonical_bytes: u64, offset: u64, len: u64) -> Result<u64, RangeProofError> {
    if len == 0 {
        return Err(RangeProofError::ZeroLength);
    }
    let end = offset
        .checked_add(len)
        .ok_or(RangeProofError::OffsetOverflow)?;
    if end > canonical_bytes {
        return Err(RangeProofError::OutOfBounds);
    }
    let first = offset / 1024;
    let last = (end - 1) / 1024;
    let covered_end = u128::from(last + 1) * 1024;
    let covered = covered_end.min(u128::from(canonical_bytes)) - u128::from(first) * 1024;
    let parents = bao_parents(0, canonical_bytes.div_ceil(1024), first, last);
    capped(8 + covered + u128::from(parents) * 64)
}

/// Exact MKDP range size for a plain canonical Blob.
///
/// # Errors
/// Invalid metadata, zero length, overflow, content bounds or wire cap.
pub fn blob_range_proof_size(
    commit_bytes: u64,
    steps: &[PrefixStep],
    canonical_blob_bytes: u64,
    offset: u64,
    len: u64,
) -> Result<u64, RangeProofError> {
    let bao_offset = offset
        .checked_add(10)
        .ok_or(RangeProofError::OffsetOverflow)?;
    let slice = bao_slice_size(canonical_blob_bytes, bao_offset, len)?;
    capped(prefix_size(commit_bytes, steps)? + 1 + 16 + vector_size(slice) + 1)
}

fn canonical_length(content: u64, index: usize) -> Result<u64, RangeProofError> {
    if content == 0 {
        return Err(RangeProofError::InvalidChunk { index });
    }
    content
        .checked_add(10)
        .ok_or(RangeProofError::OffsetOverflow)
}

/// Exact chunked MKDP/MKDS size from indexed lengths through the last
/// included chunk. Metadata after the span is unnecessary: `total_chunks`
/// alone fixes the Merkle shape. The caller checks the manifest's total
/// content bounds before collecting these lengths.
///
/// # Errors
/// Invalid metadata, zero length, overflow, insufficient length prefix,
/// content bounds or wire cap. No proof bytes or sibling hashes are built.
pub fn chunked_range_proof_size(
    commit_bytes: u64,
    steps: &[PrefixStep],
    total_chunks: u32,
    chunk_content_lengths: &[u64],
    offset: u64,
    len: u64,
) -> Result<EncodedRangePlan, RangeProofError> {
    if len == 0 {
        return Err(RangeProofError::ZeroLength);
    }
    let end = offset
        .checked_add(len)
        .ok_or(RangeProofError::OffsetOverflow)?;
    if total_chunks > crate::serialize::MAX_CHUNKS {
        return Err(VerifyError::TooManyChunks.into());
    }
    let count = total_chunks
        .checked_add(1)
        .ok_or(VerifyError::TooManyChunks)?;
    let prefix = prefix_size(commit_bytes, steps)?;
    let mut preceding = 0;
    let mut cursor = 0u64;
    let mut first = None;
    let mut container = 0;
    for (index, &content) in chunk_content_lengths.iter().enumerate() {
        let position = u32::try_from(index)
            .ok()
            .and_then(|n| n.checked_add(1))
            .filter(|&n| n < count)
            .ok_or(RangeProofError::OutOfBounds)?;
        let canonical = canonical_length(content, index)?;
        let next = cursor
            .checked_add(content)
            .ok_or(RangeProofError::OffsetOverflow)?;
        if first.is_none() && offset >= next {
            let slice = bao_slice_size(canonical, 0, 10)?;
            preceding += 36 + proof_size(count, &[position])? + vector_size(slice);
            capped(prefix + preceding)?;
        } else {
            let first_index = *first.get_or_insert(index);
            let chunk_proof = proof_size(count, &[0, position])?;
            if index == first_index {
                let single = end <= next;
                let (local_offset, selected_len) = if single {
                    (offset - cursor, len)
                } else {
                    (0, 1)
                };
                let slice = bao_slice_size(canonical, local_offset + 10, selected_len)?;
                let range_size = capped(
                    prefix
                        + 81
                        + chunk_proof
                        + 16
                        + vector_size(slice)
                        + varint_size(first_index as u64)
                        + preceding,
                )?;
                if single {
                    return Ok(EncodedRangePlan {
                        kind: RangeProofKind::Mkdp,
                        first: index,
                        last: index,
                        encoded_size: range_size,
                    });
                }
                container = 53 + vector_size(range_size);
            }
            let chunk_size = capped(prefix + 48 + chunk_proof + vector_size(canonical))?;
            container += vector_size(chunk_size);
            capped(container)?;
            if end <= next {
                return Ok(EncodedRangePlan {
                    kind: RangeProofKind::Mkds,
                    first: first_index,
                    last: index,
                    encoded_size: capped(
                        container + varint_size((index - first_index + 1) as u64),
                    )?,
                });
            }
        }
        cursor = next;
    }
    Err(RangeProofError::OutOfBounds)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::cast_possible_truncation)]
mod tests {
    use super::*;
    use crate::object::ChunkedBlob;
    use commonware_codec::EncodeSize;

    #[test]
    fn bao_sizing_matches_actual_extractors_at_chunk_and_tree_edges() {
        for canonical in [10, 11, 1023, 1024, 1025, 2048, 2049, 4097, 8193, 16383] {
            let bytes = vec![42; canonical];
            for offset in [0, 1, 9, 10, 1023, 1024, 2047, 2048, canonical - 1] {
                if offset >= canonical {
                    continue;
                }
                for len in [1, 10, 1024, canonical - offset] {
                    if offset + len > canonical {
                        continue;
                    }
                    let actual =
                        super::super::extract_bao_slice(&bytes, offset as u64, len as u64).unwrap();
                    assert_eq!(
                        bao_slice_size(canonical as u64, offset as u64, len as u64).unwrap(),
                        actual.len() as u64,
                        "canonical={canonical}, offset={offset}, len={len}"
                    );
                }
            }
        }
    }

    #[test]
    fn merkle_sizes_match_odd_even_and_power_of_two_shapes() {
        for chunks in 1..=70 {
            let manifest = ChunkedBlob {
                total_size: chunks as u64,
                chunk_size: 0,
                chunks: (0..chunks).map(|n| [n as u8; 32]).collect(),
            };
            for index in 0..chunks {
                let position = index as u32 + 1;
                assert_eq!(
                    proof_size(chunks as u32 + 1, &[position]).unwrap(),
                    merkle::build_chunk_proof(&manifest, position)
                        .unwrap()
                        .encode_size() as u128
                );
                assert_eq!(
                    proof_size(chunks as u32 + 1, &[0, position]).unwrap(),
                    merkle::build_chunks_multi_proof(&manifest, [0, position])
                        .unwrap()
                        .encode_size() as u128
                );
            }
        }
    }

    fn metadata(steps: &[super::super::Step]) -> Vec<PrefixStep> {
        steps
            .iter()
            .map(|step| PrefixStep {
                name_len: step.name.len(),
                position: step.position,
                leaf_count: step.proof.leaf_count,
            })
            .collect()
    }

    fn canonical_slice_length(slice: &[u8]) -> u64 {
        u64::from_le_bytes(slice[..8].try_into().unwrap())
    }

    #[test]
    fn canonical_object_and_range_goldens_have_exact_planned_lengths() {
        let goldens: &[&[u8]] = &[
            include_bytes!("../../../../tests/golden/disclosure/root_tree.bin"),
            include_bytes!("../../../../tests/golden/disclosure/shallow_file.bin"),
            include_bytes!("../../../../tests/golden/disclosure/nested_file_3levels.bin"),
            include_bytes!("../../../../tests/golden/disclosure/small_blob_range_whole.bin"),
            include_bytes!("../../../../tests/golden/disclosure/small_blob_range_first_block.bin"),
            include_bytes!(
                "../../../../tests/golden/disclosure/small_blob_range_last_partial_block.bin"
            ),
            include_bytes!("../../../../tests/golden/disclosure/chunked_range_with_offsets.bin"),
        ];
        for golden in goldens {
            let (_, commit, steps, payload) = super::super::decode_disclosure(golden).unwrap();
            let steps = metadata(&steps);
            let predicted = match payload {
                super::super::PayloadWire::Object { bytes } => {
                    object_proof_size(commit.len() as u64, &steps, bytes.len() as u64).unwrap()
                }
                super::super::PayloadWire::Range {
                    chunk: None,
                    offset_in_blob,
                    len,
                    slice,
                    ..
                } => blob_range_proof_size(
                    commit.len() as u64,
                    &steps,
                    canonical_slice_length(&slice),
                    offset_in_blob,
                    len,
                )
                .unwrap(),
                super::super::PayloadWire::Range {
                    chunk: Some(chunk),
                    offset_in_blob,
                    len,
                    slice,
                    chunk_len_proofs,
                } => {
                    let mut lengths: Vec<u64> = chunk_len_proofs
                        .iter()
                        .map(|proof| canonical_slice_length(&proof.slice) - 10)
                        .collect();
                    let offset = lengths.iter().sum::<u64>() + offset_in_blob;
                    lengths.push(canonical_slice_length(&slice) - 10);
                    chunked_range_proof_size(
                        commit.len() as u64,
                        &steps,
                        chunk.proof.leaf_count - 1,
                        &lengths,
                        offset,
                        len,
                    )
                    .unwrap()
                    .encoded_size
                }
                _ => panic!("fixture selector"),
            };
            assert_eq!(predicted, golden.len() as u64);
        }
    }

    #[test]
    fn huge_metadata_is_rejected_without_proof_allocation() {
        assert!(matches!(
            object_proof_size(MAX_COMMIT_BYTES as u64 + 1, &[], 1),
            Err(RangeProofError::ProofTooLarge)
        ));
        assert!(matches!(
            object_proof_size(200, &[], u64::MAX),
            Err(RangeProofError::ProofTooLarge)
        ));
        assert!(matches!(
            blob_range_proof_size(200, &[], u64::MAX, 0, u64::MAX),
            Err(RangeProofError::OffsetOverflow)
        ));
        assert!(matches!(
            chunked_range_proof_size(200, &[], 1, &[1], u64::MAX, 1),
            Err(RangeProofError::OffsetOverflow)
        ));
        assert!(matches!(
            chunked_range_proof_size(200, &[], 1, &[MAX_BUNDLE_BYTES as u64], 0, 1),
            Ok(_)
        ));
        assert!(matches!(
            chunked_range_proof_size(
                200,
                &[],
                2,
                &[MAX_BUNDLE_BYTES as u64, 1],
                0,
                MAX_BUNDLE_BYTES as u64 + 1
            ),
            Err(RangeProofError::ProofTooLarge)
        ));
    }

    #[test]
    fn preceding_cap_and_prefix_only_metadata_are_enforced() {
        let lengths = vec![65536; 40000];
        assert!(matches!(
            chunked_range_proof_size(200, &[], 50000, &lengths, 39999 * 65536, 1),
            Err(RangeProofError::ProofTooLarge)
        ));
        let result = chunked_range_proof_size(200, &[], 50000, &[100], 99, 1).unwrap();
        assert_eq!((result.first, result.last), (0, 0));
        assert!(matches!(result.kind, RangeProofKind::Mkdp));
    }
}
