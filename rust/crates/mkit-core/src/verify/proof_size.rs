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
    let left = 1u64 << (leaves - 1).ilog2();
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
    let mut sizer = ChunkedRangeSizer::new(
        commit_bytes,
        steps,
        total_chunks,
        offset,
        len,
        MAX_BUNDLE_BYTES as u64,
    )?;
    for &content in chunk_content_lengths {
        if let Some(plan) = sizer.push(content)? {
            return Ok(plan);
        }
    }
    Err(RangeProofError::OutOfBounds)
}

/// Incremental wire sizing with constant retained metadata. Feed only the
/// lengths through the selected span; caps stop collection as soon as the
/// encoded prefix alone proves the complete representation is too large.
#[derive(Debug)]
pub struct ChunkedRangeSizer {
    prefix: u128,
    count: u32,
    offset: u64,
    end: u64,
    cap: u64,
    preceding: u128,
    cursor: u64,
    index: usize,
    first: Option<usize>,
    container: u128,
    finished: bool,
}

impl ChunkedRangeSizer {
    /// Start metadata sizing with a deployment cap no greater than 64 MiB.
    ///
    /// # Errors
    /// Zero length, offset overflow, invalid prefix/count or oversized prefix.
    pub fn new(
        commit_bytes: u64,
        steps: &[PrefixStep],
        total_chunks: u32,
        offset: u64,
        len: u64,
        max_encoded_size: u64,
    ) -> Result<Self, RangeProofError> {
        if len == 0 {
            return Err(RangeProofError::ZeroLength);
        }
        let end = offset
            .checked_add(len)
            .ok_or(RangeProofError::OffsetOverflow)?;
        if total_chunks > crate::serialize::MAX_CHUNKS {
            return Err(VerifyError::TooManyChunks.into());
        }
        let mut sizer = Self {
            prefix: prefix_size(commit_bytes, steps)?,
            count: total_chunks
                .checked_add(1)
                .ok_or(VerifyError::TooManyChunks)?,
            offset,
            end,
            cap: max_encoded_size.min(MAX_BUNDLE_BYTES as u64),
            preceding: 0,
            cursor: 0,
            index: 0,
            first: None,
            container: 0,
            finished: false,
        };
        sizer.check(sizer.prefix)?;
        // A zero-chunk manifest cannot satisfy any nonempty range.
        sizer.finished = total_chunks == 0;
        Ok(sizer)
    }

    fn check(&self, size: u128) -> Result<u64, RangeProofError> {
        let size = capped(size)?;
        if size > self.cap {
            Err(RangeProofError::ProofTooLarge)
        } else {
            Ok(size)
        }
    }

    /// Add one canonical Blob content length, excluding its ten header bytes.
    /// Returns the exact final plan at the last selected chunk.
    ///
    /// # Errors
    /// Invalid length/count, overflow or a provably exceeded encoded cap.
    #[allow(clippy::too_many_lines)] // Mirrors the MKDP/MKDS wire fields in one sizing transition.
    pub fn push(&mut self, content: u64) -> Result<Option<EncodedRangePlan>, RangeProofError> {
        let index = self.index;
        let position = u32::try_from(index)
            .ok()
            .and_then(|n| n.checked_add(1))
            .filter(|&n| n < self.count && !self.finished)
            .ok_or(RangeProofError::OutOfBounds)?;
        let canonical = canonical_length(content, index)?;
        let next = self
            .cursor
            .checked_add(content)
            .ok_or(RangeProofError::OffsetOverflow)?;
        let plan = if self.first.is_none() && self.offset >= next {
            let slice = bao_slice_size(canonical, 0, 10)?;
            self.preceding += 36 + proof_size(self.count, &[position])? + vector_size(slice);
            self.check(self.prefix + self.preceding)?;
            None
        } else {
            let first_index = *self.first.get_or_insert(index);
            let chunk_proof = proof_size(self.count, &[0, position])?;
            if index == first_index {
                let single = self.end <= next;
                let (local_offset, selected_len) = if single {
                    (self.offset - self.cursor, self.end - self.offset)
                } else {
                    (0, 1)
                };
                let slice = bao_slice_size(canonical, local_offset + 10, selected_len)?;
                let range_size = self.check(
                    self.prefix
                        + 81
                        + chunk_proof
                        + 16
                        + vector_size(slice)
                        + varint_size(first_index as u64)
                        + self.preceding,
                )?;
                if single {
                    self.finished = true;
                    return Ok(Some(EncodedRangePlan {
                        kind: RangeProofKind::Mkdp,
                        first: index,
                        last: index,
                        encoded_size: range_size,
                    }));
                }
                self.container = 53 + vector_size(range_size);
            }
            let chunk_size = self.check(self.prefix + 48 + chunk_proof + vector_size(canonical))?;
            self.container += vector_size(chunk_size);
            let encoded_size =
                self.check(self.container + varint_size((index - first_index + 1) as u64))?;
            (self.end <= next).then_some(EncodedRangePlan {
                kind: RangeProofKind::Mkds,
                first: first_index,
                last: index,
                encoded_size,
            })
        };
        self.cursor = next;
        self.index += 1;
        self.finished = plan.is_some();
        Ok(plan)
    }
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
        for chunks in 1u32..=70 {
            let manifest = ChunkedBlob {
                total_size: u64::from(chunks),
                chunk_size: 0,
                chunks: (0..chunks).map(|n| [n as u8; 32]).collect(),
            };
            for index in 0..chunks {
                let position = index + 1;
                assert_eq!(
                    proof_size(chunks + 1, &[position]).unwrap(),
                    merkle::build_chunk_proof(&manifest, position)
                        .unwrap()
                        .encode_size() as u128
                );
                assert_eq!(
                    proof_size(chunks + 1, &[0, position]).unwrap(),
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
        assert!(chunked_range_proof_size(200, &[], 1, &[MAX_BUNDLE_BYTES as u64], 0, 1).is_ok());
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

    #[test]
    #[allow(clippy::too_many_lines)] // One fixture matrix compares metadata with both canonical builders.
    fn incremental_sizing_matches_builders_across_varint_and_merkle_edges() {
        use super::super::span::{RangeProof, build_range_proof_from, verify_disclosure_span};
        use crate::layout::RepoLayout;
        use crate::object::{Blob, Commit, EntryMode, Identity, Object, Tree, TreeEntry};
        use crate::serialize::serialize;
        use crate::sign::{KeyPair, sign_commit};
        use crate::store::ObjectStore;

        let temp = tempfile::TempDir::new().unwrap();
        let store = ObjectStore::init(&RepoLayout::single(temp.path())).unwrap();
        for (count, name_len) in [
            (2, 127),
            (3, 128),
            (7, 255),
            (8, 1),
            (9, 1),
            (127, 1),
            (128, 1),
            (129, 1),
        ] {
            let lengths: Vec<u64> = (0..count)
                .map(|i| [1, 1013, 1014, 1015, 2038][i % 5])
                .collect();
            let chunks: Vec<_> = lengths
                .iter()
                .enumerate()
                .map(|(i, &len)| {
                    store
                        .write(
                            &serialize(&Object::Blob(Blob {
                                data: vec![i as u8; len as usize],
                            }))
                            .unwrap(),
                        )
                        .unwrap()
                })
                .collect();
            let manifest = Object::ChunkedBlob(ChunkedBlob {
                total_size: lengths.iter().sum(),
                chunk_size: 0,
                chunks,
            });
            let leaf = store.write(&serialize(&manifest).unwrap()).unwrap();
            let name = vec![b'f'; name_len];
            let tree = Object::Tree(Tree {
                entries: vec![
                    TreeEntry {
                        name: b"a".to_vec(),
                        mode: EntryMode::Blob,
                        object_hash: leaf,
                    },
                    TreeEntry {
                        name: name.clone(),
                        mode: EntryMode::Blob,
                        object_hash: leaf,
                    },
                    TreeEntry {
                        name: b"z".to_vec(),
                        mode: EntryMode::Blob,
                        object_hash: leaf,
                    },
                ],
            });
            let root = store.write(&serialize(&tree).unwrap()).unwrap();
            let key = KeyPair::from_seed([3; 32]);
            let mut commit = Commit::new_unannotated(
                root,
                vec![],
                Identity::ed25519(key.public.0),
                key.public.0,
                vec![],
                1,
                [0; 64],
            );
            commit.signature = sign_commit(&commit, &key).unwrap().0;
            let canonical = serialize(&Object::Commit(commit)).unwrap();
            let id = store.write(&canonical).unwrap();
            let steps = [PrefixStep {
                name_len,
                position: 1,
                leaf_count: 3,
            }];
            let total = lengths.iter().sum::<u64>();
            for (offset, len) in [(0, total), (total - 1, 1), (1, total - 2)] {
                let plan = chunked_range_proof_size(
                    canonical.len() as u64,
                    &steps,
                    count as u32,
                    &lengths,
                    offset,
                    len,
                )
                .unwrap();
                let built =
                    build_range_proof_from(&store, &id, &[&name], offset, len, None).unwrap();
                let bytes = match built {
                    RangeProof::Mkdp(bytes) => {
                        assert_eq!(plan.kind, RangeProofKind::Mkdp);
                        super::super::verify_disclosure(&id, &bytes).unwrap();
                        bytes
                    }
                    RangeProof::Mkds(bytes) => {
                        assert_eq!(plan.kind, RangeProofKind::Mkds);
                        verify_disclosure_span(&id, &bytes).unwrap();
                        bytes
                    }
                };
                assert_eq!(
                    plan.encoded_size,
                    bytes.len() as u64,
                    "count={count}, offset={offset}, len={len}"
                );
                let mut sizer = ChunkedRangeSizer::new(
                    canonical.len() as u64,
                    &steps,
                    count as u32,
                    offset,
                    len,
                    plan.encoded_size - 1,
                )
                .unwrap();
                assert!(lengths.iter().any(|&length| matches!(
                    sizer.push(length),
                    Err(RangeProofError::ProofTooLarge)
                )));
            }
        }
    }
}
