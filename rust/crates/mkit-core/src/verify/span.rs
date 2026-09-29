//! MKDS v1 multi-chunk range proofs (SPEC-DISCLOSURE §8).
//!
//! The decoder borrows its inner bundles. Verification retains only small
//! summaries and the requested output, so it never keeps decoded chunks
//! from earlier bundles alive while checking later bundles.

use super::{
    ChunkHdr, CommitContext, DisclosedPayload, LenProof, PayloadWire, Selector, Step, VerifyError,
    encode_disclosure, extract_bao_slice, verify_disclosure, verify_disclosure_reusing_context,
};
use crate::hash::{Hash, hash};
use crate::merkle;
use crate::object::{EntryMode, MkitError, Object};
use crate::store::{ObjectSource, StoreError};
use commonware_codec::{EncodeSize, Write};

use super::MAX_BUNDLE_BYTES;

const MAGIC: &[u8; 4] = b"MKDS";
const VERSION: u8 = 1;
const MAX_CHUNK_BUNDLES: usize = 1_000_000;

/// An authenticated byte range spanning at least two chunks.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DisclosedSpan {
    /// Trusted commit id.
    pub commit_id: Hash,
    /// Root tree id from the signed commit.
    pub tree_hash: Hash,
    /// Authenticated path and entry modes.
    pub path: Vec<(Vec<u8>, EntryMode)>,
    /// `ChunkedBlob` leaf id.
    pub leaf_id: Hash,
    /// Public key embedded in the commit.
    pub signer: [u8; 32],
    /// Whether the embedded signature verifies; key trust is caller policy.
    pub signature_valid: bool,
    /// Absolute content offset.
    pub offset: u64,
    /// Verified content bytes in the requested range.
    pub bytes: Vec<u8>,
    /// First included chunk index.
    pub first: u32,
    /// Last included chunk index.
    pub last: u32,
    /// Authenticated absolute beginning of the first chunk.
    pub span_start: u64,
    /// Authenticated bare chunk BMT root.
    pub chunk_inner_root: Hash,
}

/// First failed MKDS check, in SPEC-DISCLOSURE §8.2 order.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SpanError {
    /// Container exceeds 64 MiB.
    #[error("span_too_large")]
    TooLarge,
    /// Wrong magic.
    #[error("span_magic")]
    Magic,
    /// Wrong version.
    #[error("span_version")]
    Version,
    /// Truncated field, invalid varint, or oversized vector.
    #[error("span_encoding")]
    Encoding,
    /// Extra bytes after the declared vectors.
    #[error("span_trailing_bytes")]
    TrailingBytes,
    /// Embedded commit id differs from the trusted id.
    #[error("span_commit")]
    Commit,
    /// Zero length or overflowed endpoint.
    #[error("span_range_arithmetic")]
    RangeArithmetic,
    /// Fewer than two chunk bundles.
    #[error("span_chunk_count")]
    ChunkCount,
    /// Anchor MKDP failed verification.
    #[error("span_anchor_invalid: {0}")]
    AnchorInvalid(#[source] VerifyError),
    /// Anchor is not a one-byte chunked Range at local offset zero.
    #[error("span_anchor_selector")]
    AnchorSelector,
    /// Anchor does not prove its absolute offset.
    #[error("span_anchor_offset")]
    AnchorOffset,
    /// An inner MKDP failed verification.
    #[error("span_inner_invalid: {0}")]
    InnerInvalid(#[source] VerifyError),
    /// An inner payload is not Chunk.
    #[error("span_chunk_selector")]
    ChunkSelector,
    /// Inner path or leaf differs from the anchor.
    #[error("span_leaf_context")]
    LeafContext,
    /// Inner chunk metadata or root differs from the anchor.
    #[error("span_chunk_context")]
    ChunkContext,
    /// Indices do not begin at the anchor and advance consecutively.
    #[error("span_chunk_order")]
    ChunkOrder,
    /// Chunk bytes are not a canonical nonempty Blob.
    #[error("span_chunk_bytes")]
    ChunkBytes,
    /// First chunk is not bound to the anchor byte and id.
    #[error("span_anchor_binding")]
    AnchorBinding,
    /// Range is outside the included, authenticated chunk content.
    #[error("span_range_outside")]
    RangeOutside,
    /// The final included chunk is unnecessary.
    #[error("span_last_unneeded")]
    LastUnneeded,
}

impl SpanError {
    /// Stable language-independent golden reject label.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        match self {
            Self::TooLarge => "span_too_large",
            Self::Magic => "span_magic",
            Self::Version => "span_version",
            Self::Encoding => "span_encoding",
            Self::TrailingBytes => "span_trailing_bytes",
            Self::Commit => "span_commit",
            Self::RangeArithmetic => "span_range_arithmetic",
            Self::ChunkCount => "span_chunk_count",
            Self::AnchorInvalid(_) => "span_anchor_invalid",
            Self::AnchorSelector => "span_anchor_selector",
            Self::AnchorOffset => "span_anchor_offset",
            Self::InnerInvalid(_) => "span_inner_invalid",
            Self::ChunkSelector => "span_chunk_selector",
            Self::LeafContext => "span_leaf_context",
            Self::ChunkContext => "span_chunk_context",
            Self::ChunkOrder => "span_chunk_order",
            Self::ChunkBytes => "span_chunk_bytes",
            Self::AnchorBinding => "span_anchor_binding",
            Self::RangeOutside => "span_range_outside",
            Self::LastUnneeded => "span_last_unneeded",
        }
    }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], SpanError> {
        if n > self.0.len() {
            return Err(SpanError::Encoding);
        }
        let (part, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(part)
    }

    fn u64(&mut self) -> Result<u64, SpanError> {
        let bytes: [u8; 8] = self.take(8)?.try_into().map_err(|_| SpanError::Encoding)?;
        Ok(u64::from_be_bytes(bytes))
    }

    /// Strict minimal LEB128, capped at u32 and at `limit`.
    fn length(&mut self, limit: usize) -> Result<usize, SpanError> {
        let mut value = 0u32;
        for i in 0..5 {
            let byte = self.take(1)?[0];
            if (i > 0 && byte == 0) || (i == 4 && byte > 15) {
                return Err(SpanError::Encoding);
            }
            value |= u32::from(byte & 0x7f) << (7 * i);
            if byte & 0x80 == 0 {
                let n = value as usize;
                return (n <= limit).then_some(n).ok_or(SpanError::Encoding);
            }
        }
        Err(SpanError::Encoding)
    }

    fn vector(&mut self) -> Result<&'a [u8], SpanError> {
        let n = self.length(self.0.len().min(MAX_BUNDLE_BYTES))?;
        self.take(n)
    }
}

struct Decoded<'a> {
    commit: Hash,
    offset: u64,
    len: u64,
    anchor: &'a [u8],
    chunks: Vec<&'a [u8]>,
}

fn decode(bytes: &[u8]) -> Result<Decoded<'_>, SpanError> {
    if bytes.len() > MAX_BUNDLE_BYTES {
        return Err(SpanError::TooLarge);
    }
    let mut reader = Reader(bytes);
    if reader.take(4)? != MAGIC {
        return Err(SpanError::Magic);
    }
    if reader.take(1)? != [VERSION] {
        return Err(SpanError::Version);
    }
    let commit = reader
        .take(32)?
        .try_into()
        .map_err(|_| SpanError::Encoding)?;
    let offset = reader.u64()?;
    let len = reader.u64()?;
    let anchor = reader.vector()?;
    let count = reader.length(MAX_CHUNK_BUNDLES)?;
    // Each vector takes at least one length byte. This bound is checked
    // before even an empty Vec is constructed from an untrusted count.
    if count > reader.0.len() {
        return Err(SpanError::Encoding);
    }
    let mut chunks = Vec::new();
    for _ in 0..count {
        chunks.push(reader.vector()?);
    }
    if !reader.0.is_empty() {
        return Err(SpanError::TrailingBytes);
    }
    Ok(Decoded {
        commit,
        offset,
        len,
        anchor,
        chunks,
    })
}

/// Encode an MKDS v1 container from already encoded MKDP v2 bundles.
///
/// Encoding does not authenticate or validate the supplied bundles. Callers
/// must verify the result against a trusted commit id before using it.
#[must_use]
pub fn encode_span(
    commit: Hash,
    offset: u64,
    len: u64,
    anchor: &[u8],
    chunks: &[&[u8]],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    commit.write(&mut out);
    offset.write(&mut out);
    len.write(&mut out);
    anchor.write(&mut out);
    let mut count = chunks.len();
    loop {
        #[allow(clippy::cast_possible_truncation)] // Mask keeps the value within seven bits.
        let byte = (count & 0x7f) as u8;
        count >>= 7;
        out.push(if count == 0 { byte } else { byte | 0x80 });
        if count == 0 {
            break;
        }
    }
    for chunk in chunks {
        (*chunk).write(&mut out);
    }
    out
}

struct Summary {
    selector_ok: bool,
    leaf_ok: bool,
    context_ok: bool,
    index: u32,
    content_len: Option<u64>,
    first_byte: Option<u8>,
    canonical_id: Hash,
}

// This seam lets unit tests exercise inconsistent decoded summaries that
// genuine authenticated MKDP bundles cannot produce.
fn check_summaries(
    summaries: &[Summary],
    first: u32,
    anchor_chunk_id: &Hash,
    anchor_byte: u8,
) -> Result<(), SpanError> {
    if summaries.iter().any(|s| !s.selector_ok) {
        return Err(SpanError::ChunkSelector);
    }
    if summaries.iter().any(|s| !s.leaf_ok) {
        return Err(SpanError::LeafContext);
    }
    if summaries.iter().any(|s| !s.context_ok) {
        return Err(SpanError::ChunkContext);
    }
    if summaries
        .iter()
        .enumerate()
        .any(|(i, s)| u32::try_from(i).ok().and_then(|i| first.checked_add(i)) != Some(s.index))
    {
        return Err(SpanError::ChunkOrder);
    }
    if summaries.iter().any(|s| s.content_len.is_none()) {
        return Err(SpanError::ChunkBytes);
    }
    if summaries[0].canonical_id != *anchor_chunk_id || summaries[0].first_byte != Some(anchor_byte)
    {
        return Err(SpanError::AnchorBinding);
    }
    Ok(())
}

/// Verify a multi-chunk range against a trusted commit id.
///
/// # Errors
///
/// Returns the first failed [`SpanError`] check in SPEC-DISCLOSURE §8.2
/// table order. No partial content escapes on any error.
#[allow(clippy::too_many_lines)] // Mirrors the normative ordered check table in one audit path.
pub fn verify_disclosure_span(trusted: &Hash, bytes: &[u8]) -> Result<DisclosedSpan, SpanError> {
    let decoded = decode(bytes)?;
    if &decoded.commit != trusted {
        return Err(SpanError::Commit);
    }
    let end = decoded
        .offset
        .checked_add(decoded.len)
        .filter(|_| decoded.len != 0)
        .ok_or(SpanError::RangeArithmetic)?;
    if decoded.chunks.len() < 2 {
        return Err(SpanError::ChunkCount);
    }
    let anchor = verify_disclosure(trusted, decoded.anchor).map_err(SpanError::AnchorInvalid)?;
    let DisclosedPayload::Range {
        blob_id,
        chunk: Some((first, total_size, chunk_size)),
        offset_in_blob: 0,
        absolute_offset,
        bytes: anchor_byte,
    } = &anchor.payload
    else {
        return Err(SpanError::AnchorSelector);
    };
    if anchor_byte.len() != 1 {
        return Err(SpanError::AnchorSelector);
    }
    let start = absolute_offset.ok_or(SpanError::AnchorOffset)?;
    let context = CommitContext::from_disclosed(&anchor);
    let mut summaries = Vec::new();
    let mut output = Vec::new();
    let mut cursor = start;
    let mut range_overflow = false;
    let mut last_start = start;
    for bundle in decoded.chunks {
        let inner = verify_disclosure_reusing_context(trusted, bundle, &context)
            .map_err(SpanError::InnerInvalid)?;
        let leaf_ok = inner.path == anchor.path && inner.leaf_id == anchor.leaf_id;
        let context_ok = inner.chunk_inner_root == anchor.chunk_inner_root;
        let mut summary = Summary {
            selector_ok: false,
            leaf_ok,
            context_ok,
            index: 0,
            content_len: None,
            first_byte: None,
            canonical_id: [0; 32],
        };
        if let DisclosedPayload::Chunk {
            total_size: inner_total,
            chunk_size: inner_size,
            index,
            bytes: chunk_bytes,
        } = inner.payload
        {
            summary.selector_ok = true;
            summary.context_ok &= inner_total == *total_size && inner_size == *chunk_size;
            summary.index = index;
            summary.canonical_id = hash(&chunk_bytes);
            if let Ok(Object::Blob(blob)) = crate::serialize::deserialize(&chunk_bytes)
                && !blob.data.is_empty()
            {
                summary.content_len = u64::try_from(blob.data.len()).ok();
                summary.first_byte = blob.data.first().copied();
                if let Some(length) = summary.content_len {
                    last_start = cursor;
                    if let Some(next) = cursor.checked_add(length) {
                        let from = decoded.offset.max(cursor);
                        let to = end.min(next);
                        if from < to {
                            let a = usize::try_from(from - cursor)
                                .map_err(|_| SpanError::RangeOutside)?;
                            let b = usize::try_from(to - cursor)
                                .map_err(|_| SpanError::RangeOutside)?;
                            output.extend_from_slice(&blob.data[a..b]);
                        }
                        cursor = next;
                    } else {
                        range_overflow = true;
                    }
                }
            }
        }
        summaries.push(summary);
    }
    check_summaries(&summaries, *first, blob_id, anchor_byte[0])?;
    let first_end = start
        .checked_add(summaries[0].content_len.ok_or(SpanError::ChunkBytes)?)
        .ok_or(SpanError::RangeOutside)?;
    if range_overflow
        || cursor > *total_size
        || decoded.offset < start
        || decoded.offset >= first_end
        || end > cursor
    {
        return Err(SpanError::RangeOutside);
    }
    if end <= last_start {
        return Err(SpanError::LastUnneeded);
    }
    if u64::try_from(output.len()) != Ok(decoded.len) {
        return Err(SpanError::RangeOutside);
    }
    let last = first
        .checked_add(u32::try_from(summaries.len() - 1).map_err(|_| SpanError::ChunkOrder)?)
        .ok_or(SpanError::ChunkOrder)?;
    Ok(DisclosedSpan {
        commit_id: *trusted,
        tree_hash: anchor.tree_hash,
        path: anchor.path,
        leaf_id: anchor.leaf_id,
        signer: anchor.signer,
        signature_valid: anchor.signature_valid,
        offset: decoded.offset,
        bytes: output,
        first: *first,
        last,
        span_start: start,
        chunk_inner_root: anchor.chunk_inner_root.ok_or(SpanError::ChunkContext)?,
    })
}

/// Encoded representation chosen for a requested range.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RangeProof {
    /// One MKDP v2 Range bundle.
    Mkdp(Vec<u8>),
    /// One MKDS v1 container.
    Mkds(Vec<u8>),
}

/// Proof format, independent of encoded bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RangeProofKind {
    /// The range lies within one chunk (or a plain Blob): one MKDP v2 bundle.
    Mkdp,
    /// The range crosses a chunk boundary: one MKDS v1 container.
    Mkds,
}

/// Pure prefetch plan for a chunked file. `needed_chunk_indices` contains
/// every preceding chunk needed for absolute length proofs and each span
/// chunk, in ascending order.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Plan {
    /// Proof format the range requires.
    pub kind: RangeProofKind,
    /// Index of the chunk containing the first requested byte.
    pub first: usize,
    /// Index of the chunk containing the last requested byte.
    pub last: usize,
    /// Every chunk index that must be read: `0..=last`.
    pub needed_chunk_indices: Vec<usize>,
}

/// Typed builder and planner failures.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RangeProofError {
    /// The requested length is zero.
    #[error("range length must be nonzero")]
    ZeroLength,
    /// `offset + len` (or a running chunk offset) overflows `u64`.
    #[error("range endpoint overflow")]
    OffsetOverflow,
    /// The range extends past the end of the file.
    #[error("range is outside the file")]
    OutOfBounds,
    /// Boundary hints are malformed, or were supplied for a plain Blob leaf
    /// (which has no chunk boundaries).
    #[error("boundary hints must start at zero, strictly increase, and end at total_size")]
    InvalidBoundaries,
    /// A boundary hint disagrees with the chunk's canonical Blob length.
    #[error("boundary hint differs from chunk {index}'s canonical Blob length")]
    HintMismatch {
        /// Index of the first chunk whose hint is wrong.
        index: usize,
    },
    /// A manifest chunk is not a canonical nonempty Blob.
    #[error("chunk {index} is not a canonical nonempty Blob")]
    InvalidChunk {
        /// Index of the offending chunk.
        index: usize,
    },
    /// The encoded proof would exceed the 64 MiB cap.
    #[error("encoded proof exceeds 64 MiB")]
    ProofTooLarge,
    /// The object source failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// A disclosure-building step failed.
    #[error(transparent)]
    Verify(#[from] VerifyError),
    /// A source object failed to decode.
    #[error(transparent)]
    Decode(#[from] MkitError),
}

/// Plan a range from canonical chunk content lengths. The end is exclusive;
/// an end exactly on a chunk boundary does not need the next chunk.
///
/// # Errors
///
/// Zero length, overflow, empty/zero chunks, or an out-of-file range.
pub fn plan_range_proof(
    chunk_lengths: &[u64],
    offset: u64,
    len: u64,
) -> Result<Plan, RangeProofError> {
    if len == 0 {
        return Err(RangeProofError::ZeroLength);
    }
    let end = offset
        .checked_add(len)
        .ok_or(RangeProofError::OffsetOverflow)?;
    let mut cursor = 0u64;
    let mut first = None;
    let mut last = None;
    for (i, &length) in chunk_lengths.iter().enumerate() {
        if length == 0 {
            return Err(RangeProofError::InvalidChunk { index: i });
        }
        let next = cursor
            .checked_add(length)
            .ok_or(RangeProofError::OffsetOverflow)?;
        if first.is_none() && offset < next {
            first = Some(i);
        }
        if first.is_some() && end <= next {
            last = Some(i);
            break;
        }
        cursor = next;
    }
    let first = first.ok_or(RangeProofError::OutOfBounds)?;
    let last = last.ok_or(RangeProofError::OutOfBounds)?;
    Ok(Plan {
        kind: if first == last {
            RangeProofKind::Mkdp
        } else {
            RangeProofKind::Mkds
        },
        first,
        last,
        needed_chunk_indices: (0..=last).collect(),
    })
}

fn build_prefix<S: ObjectSource + ?Sized>(
    source: &S,
    commit_id: &Hash,
    path: &[&[u8]],
) -> Result<(Vec<u8>, Vec<Step>, Hash), RangeProofError> {
    if path.len() > crate::store::MAX_TREE_DEPTH {
        return Err(VerifyError::TooManySteps(path.len()).into());
    }
    let commit_bytes = source.read(commit_id)?;
    let commit_obj = crate::serialize::deserialize(&commit_bytes)?;
    let tree_hash = match commit_obj {
        Object::Commit(c) => c.tree_hash,
        Object::Remix(r) => r.tree_hash,
        other => return Err(VerifyError::NotACommitOrRemix(other.object_type()).into()),
    };
    let mut steps = Vec::new();
    let mut current_tree_id = tree_hash;
    let mut leaf_id = tree_hash;
    for (i, &name) in path.iter().enumerate() {
        let Object::Tree(tree) = source.read_object(&current_tree_id)? else {
            return Err(VerifyError::PathThroughNonTree.into());
        };
        let position =
            merkle::tree_entry_position(&tree, name).ok_or(VerifyError::PathNotFound(i))?;
        let entry = tree.entries[position as usize].clone();
        steps.push(Step {
            name: name.to_vec(),
            mode: entry.mode,
            child_id: entry.object_hash,
            inner_root: merkle::tree_inner_root(&tree),
            position,
            proof: merkle::build_tree_entry_proof(&tree, position).map_err(VerifyError::from)?,
        });
        leaf_id = entry.object_hash;
        if entry.mode == EntryMode::Tree {
            current_tree_id = leaf_id;
        } else if i + 1 != path.len() {
            return Err(VerifyError::PathThroughNonTree.into());
        }
    }
    Ok((commit_bytes, steps, leaf_id))
}

fn range_payload(
    cb: &crate::object::ChunkedBlob,
    index: usize,
    bytes: &[u8],
    offset_in_blob: u64,
    len: u64,
    proofs: Vec<LenProof>,
) -> Result<PayloadWire, RangeProofError> {
    let index = u32::try_from(index).map_err(|_| VerifyError::TooManyChunks)?;
    let position = index.checked_add(1).ok_or(VerifyError::TooManyChunks)?;
    let chunk_id = cb.chunks[index as usize];
    let proof = merkle::build_chunks_multi_proof(cb, [0, position]).map_err(VerifyError::from)?;
    let bao_offset = offset_in_blob
        .checked_add(10)
        .ok_or(RangeProofError::OffsetOverflow)?;
    let slice = extract_bao_slice(bytes, bao_offset, len)?;
    Ok(PayloadWire::Range {
        chunk: Some(ChunkHdr {
            total_size: cb.total_size,
            chunk_size: cb.chunk_size,
            index,
            inner_root: merkle::chunked_inner_root(cb),
            chunk_id,
            proof,
        }),
        offset_in_blob,
        len,
        slice,
        chunk_len_proofs: proofs,
    })
}

fn chunk_payload(
    cb: &crate::object::ChunkedBlob,
    index: usize,
    bytes: Vec<u8>,
) -> Result<PayloadWire, RangeProofError> {
    let index = u32::try_from(index).map_err(|_| VerifyError::TooManyChunks)?;
    let position = index.checked_add(1).ok_or(VerifyError::TooManyChunks)?;
    Ok(PayloadWire::Chunk {
        total_size: cb.total_size,
        chunk_size: cb.chunk_size,
        index,
        inner_root: merkle::chunked_inner_root(cb),
        proof: merkle::build_chunks_multi_proof(cb, [0, position]).map_err(VerifyError::from)?,
        bytes,
    })
}

// Owning `bytes` makes the preceding chunk's lifetime end before the next
// source read; only the small Bao slice and Merkle proof escape this call.
fn preceding_proof(
    cb: &crate::object::ChunkedBlob,
    index: usize,
    id: Hash,
    bytes: Vec<u8>,
) -> Result<LenProof, RangeProofError> {
    #[cfg(test)]
    let bytes = TrackedPrecedingBytes::new(bytes);
    let index_u32 = u32::try_from(index).map_err(|_| VerifyError::TooManyChunks)?;
    let position = index_u32.checked_add(1).ok_or(VerifyError::TooManyChunks)?;
    #[cfg(test)]
    let slice = extract_bao_slice(&bytes.0, 0, 10)?;
    #[cfg(not(test))]
    let slice = extract_bao_slice(&bytes, 0, 10)?;
    drop(bytes);
    Ok(LenProof {
        index: index_u32,
        chunk_id: id,
        proof: merkle::build_chunk_proof(cb, position).map_err(VerifyError::from)?,
        slice,
    })
}

#[cfg(test)]
std::thread_local! {
    static PRECEDING_LIVE: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static PRECEDING_PEAK: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
struct TrackedPrecedingBytes(Vec<u8>);

#[cfg(test)]
impl TrackedPrecedingBytes {
    fn new(bytes: Vec<u8>) -> Self {
        PRECEDING_LIVE.with(|live| {
            let count = live.get() + 1;
            live.set(count);
            PRECEDING_PEAK.with(|peak| peak.set(peak.get().max(count)));
        });
        Self(bytes)
    }
}

#[cfg(test)]
impl Drop for TrackedPrecedingBytes {
    fn drop(&mut self) {
        PRECEDING_LIVE.with(|live| live.set(live.get() - 1));
    }
}

fn varint_size(mut n: usize) -> usize {
    let mut size = 1;
    while n >= 128 {
        n >>= 7;
        size += 1;
    }
    size
}

fn encoded_disclosure_size(
    commit_bytes: &[u8],
    steps: &[Step],
    payload: &PayloadWire,
) -> Result<usize, RangeProofError> {
    let payload_size = match payload {
        PayloadWire::Object { bytes } => bytes.as_slice().encode_size(),
        PayloadWire::Chunk { proof, bytes, .. } => {
            8 + 4 + 4 + 32 + proof.encode_size() + bytes.as_slice().encode_size()
        }
        PayloadWire::Range {
            chunk,
            slice,
            chunk_len_proofs,
            ..
        } => {
            chunk.encode_size()
                + 8
                + 8
                + slice.as_slice().encode_size()
                + chunk_len_proofs.encode_size()
        }
    };
    4usize
        .checked_add(1 + 32 + 1)
        .and_then(|n| n.checked_add(commit_bytes.encode_size()))
        .and_then(|n| n.checked_add(steps.encode_size()))
        .and_then(|n| n.checked_add(payload_size))
        .filter(|&n| n <= MAX_BUNDLE_BYTES)
        .ok_or(RangeProofError::ProofTooLarge)
}

/// Build the smallest representation for a range, reading each preceding
/// chunk once for its length proof and no chunk after the span. `boundaries`,
/// when supplied, are the `chunks.len() + 1` prefix content offsets,
/// beginning at zero and ending at the manifest's total size. Every hint
/// for a chunk actually read is checked against its canonical Blob length.
///
/// # Errors
///
/// Returns [`RangeProofError`] for invalid ranges, hints, source objects,
/// or an encoded result that exceeds the MKDP/MKDS 64 MiB cap.
#[allow(clippy::too_many_lines)] // The loop must keep each preceding chunk scoped to one iteration.
pub fn build_range_proof_from<S: ObjectSource + ?Sized>(
    source: &S,
    commit_id: &Hash,
    path: &[&[u8]],
    offset: u64,
    len: u64,
    boundaries: Option<&[u64]>,
) -> Result<RangeProof, RangeProofError> {
    if len == 0 {
        return Err(RangeProofError::ZeroLength);
    }
    let end = offset
        .checked_add(len)
        .ok_or(RangeProofError::OffsetOverflow)?;
    let (commit_bytes, steps, leaf_id) = build_prefix(source, commit_id, path)?;
    let leaf = source.read_object(&leaf_id)?;
    let cb = match leaf {
        Object::Blob(_) => {
            if boundaries.is_some() {
                return Err(RangeProofError::InvalidBoundaries);
            }
            let proof = super::build_disclosure_from(
                source,
                commit_id,
                path,
                Selector::Range {
                    offset,
                    len,
                    with_offsets: true,
                },
            )?;
            return Ok(RangeProof::Mkdp(proof));
        }
        Object::ChunkedBlob(cb) => cb,
        _ => return Err(VerifyError::SelectorLeafMismatch.into()),
    };
    if end > cb.total_size {
        return Err(RangeProofError::OutOfBounds);
    }
    let hinted_plan = if let Some(hints) = boundaries {
        if hints.len() != cb.chunks.len() + 1
            || hints.first() != Some(&0)
            || hints.last() != Some(&cb.total_size)
            || hints.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(RangeProofError::InvalidBoundaries);
        }
        let lengths: Vec<u64> = hints.windows(2).map(|pair| pair[1] - pair[0]).collect();
        Some(plan_range_proof(&lengths, offset, len)?)
    } else {
        None
    };
    let mut preceding = Vec::new();
    let mut preceding_size = 0usize;
    let mut encoded_container_size = 0usize;
    let mut cursor = 0u64;
    let mut first = None;
    let mut anchor = None;
    let mut chunks = Vec::new();
    for (i, id) in cb.chunks.iter().enumerate() {
        if hinted_plan.as_ref().is_some_and(|plan| i > plan.last) {
            break;
        }
        let (chunk_bytes, content_len) = checked_blob_source(source, id, i)?;
        let next = cursor
            .checked_add(content_len)
            .ok_or(RangeProofError::OffsetOverflow)?;
        if next > cb.total_size {
            return Err(RangeProofError::OutOfBounds);
        }
        if let Some(hints) = boundaries
            && (hints[i] != cursor || hints[i + 1] != next)
        {
            return Err(RangeProofError::HintMismatch { index: i });
        }
        if first.is_none() && offset >= next {
            let proof = preceding_proof(&cb, i, *id, chunk_bytes)?;
            preceding_size = preceding_size
                .checked_add(proof.encode_size())
                .filter(|&size| size <= MAX_BUNDLE_BYTES)
                .ok_or(RangeProofError::ProofTooLarge)?;
            preceding.push(proof);
            cursor = next;
            continue;
        }
        let first_index = *first.get_or_insert(i);
        if i == first_index {
            let local_offset = offset
                .checked_sub(cursor)
                .ok_or(RangeProofError::OffsetOverflow)?;
            if end <= next {
                let payload = range_payload(&cb, i, &chunk_bytes, local_offset, len, preceding)?;
                encoded_disclosure_size(&commit_bytes, &steps, &payload)?;
                let proof = encode_disclosure(commit_id, &commit_bytes, &steps, &payload);
                return Ok(RangeProof::Mkdp(proof));
            }
            let payload =
                range_payload(&cb, i, &chunk_bytes, 0, 1, std::mem::take(&mut preceding))?;
            let anchor_size = encoded_disclosure_size(&commit_bytes, &steps, &payload)?;
            encoded_container_size =
                4 + 1 + 32 + 8 + 8 + varint_size(anchor_size) + anchor_size + 1;
            if encoded_container_size > MAX_BUNDLE_BYTES {
                return Err(RangeProofError::ProofTooLarge);
            }
            anchor = Some(encode_disclosure(
                commit_id,
                &commit_bytes,
                &steps,
                &payload,
            ));
        }
        if chunk_bytes.len() > MAX_BUNDLE_BYTES {
            return Err(RangeProofError::ProofTooLarge);
        }
        let payload = chunk_payload(&cb, i, chunk_bytes)?;
        let bundle_size = encoded_disclosure_size(&commit_bytes, &steps, &payload)?;
        let new_count = chunks.len() + 1;
        encoded_container_size = encoded_container_size
            .checked_add(varint_size(new_count) - varint_size(chunks.len()))
            .and_then(|n| n.checked_add(varint_size(bundle_size)))
            .and_then(|n| n.checked_add(bundle_size))
            .filter(|&n| n <= MAX_BUNDLE_BYTES)
            .ok_or(RangeProofError::ProofTooLarge)?;
        let bundle = encode_disclosure(commit_id, &commit_bytes, &steps, &payload);
        chunks.push(bundle);
        cursor = next;
        if end <= next {
            break;
        }
    }
    let anchor = anchor.ok_or(RangeProofError::OutOfBounds)?;
    if cursor < end {
        return Err(RangeProofError::OutOfBounds);
    }
    let refs: Vec<&[u8]> = chunks.iter().map(Vec::as_slice).collect();
    let proof = encode_span(*commit_id, offset, len, &anchor, &refs);
    if proof.len() > MAX_BUNDLE_BYTES {
        return Err(RangeProofError::ProofTooLarge);
    }
    Ok(RangeProof::Mkds(proof))
}

fn checked_blob_source<S: ObjectSource + ?Sized>(
    source: &S,
    id: &Hash,
    index: usize,
) -> Result<(Vec<u8>, u64), RangeProofError> {
    let bytes = source.read(id)?;
    let Object::Blob(blob) = crate::serialize::deserialize(&bytes)? else {
        return Err(RangeProofError::InvalidChunk { index });
    };
    let len = u64::try_from(blob.data.len()).map_err(|_| RangeProofError::OffsetOverflow)?;
    if len == 0 {
        return Err(RangeProofError::InvalidChunk { index });
    }
    Ok((bytes, len))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::hash::ZERO;
    use crate::layout::RepoLayout;
    use crate::object::{Blob, ChunkedBlob, Commit, Identity, Tree, TreeEntry};
    use crate::sign::{KeyPair, sign_commit};
    use crate::store::{ObjectStore, StoreResult};
    use std::cell::RefCell;

    const VALID: &[u8] =
        include_bytes!("../../../../tests/golden/http-objects/span_two_chunks.bin");
    const FIRST_ZERO: &[u8] =
        include_bytes!("../../../../tests/golden/http-objects/span_first_zero.bin");

    fn valid() -> (Hash, Decoded<'static>) {
        let decoded = decode(VALID).unwrap();
        (decoded.commit, decoded)
    }

    fn verify(bytes: &[u8]) -> &'static str {
        let (trusted, _) = valid();
        verify_disclosure_span(&trusted, bytes)
            .unwrap_err()
            .reason()
    }

    #[test]
    fn structural_checks_precede_crypto_and_follow_table_order() {
        let (trusted, d) = valid();
        let mut trailing_and_bad_commit = VALID.to_vec();
        trailing_and_bad_commit[5] ^= 1;
        trailing_and_bad_commit.push(0);
        assert_eq!(verify(&trailing_and_bad_commit), "span_trailing_bytes");

        let mut wrong_magic = VALID.to_vec();
        wrong_magic[0] = b'X';
        wrong_magic[4] = 2;
        assert_eq!(verify(&wrong_magic), "span_magic");
        assert_eq!(verify(&VALID[..4]), "span_encoding");
        assert_eq!(verify(&[b'M', b'K', b'D', b'S', 2]), "span_version");

        let mut wrong_commit = VALID.to_vec();
        wrong_commit[5] ^= 1;
        assert_eq!(verify(&wrong_commit), "span_commit");
        assert_eq!(
            verify(&encode_span(trusted, d.offset, 0, d.anchor, &d.chunks)),
            "span_range_arithmetic"
        );
        assert_eq!(
            verify(&encode_span(trusted, u64::MAX, 2, d.anchor, &d.chunks)),
            "span_range_arithmetic"
        );
        assert_eq!(
            verify(&encode_span(
                trusted,
                d.offset,
                d.len,
                d.anchor,
                &d.chunks[..1]
            )),
            "span_chunk_count"
        );
        assert_eq!(
            verify(&encode_span(trusted, d.offset, d.len, &[], &d.chunks)),
            "span_anchor_invalid"
        );
    }

    #[test]
    fn every_spec_reason_has_its_own_stable_label() {
        let reasons = [
            SpanError::TooLarge,
            SpanError::Magic,
            SpanError::Version,
            SpanError::Encoding,
            SpanError::TrailingBytes,
            SpanError::Commit,
            SpanError::RangeArithmetic,
            SpanError::ChunkCount,
            SpanError::AnchorInvalid(VerifyError::BadMagic),
            SpanError::AnchorSelector,
            SpanError::AnchorOffset,
            SpanError::InnerInvalid(VerifyError::BadMagic),
            SpanError::ChunkSelector,
            SpanError::LeafContext,
            SpanError::ChunkContext,
            SpanError::ChunkOrder,
            SpanError::ChunkBytes,
            SpanError::AnchorBinding,
            SpanError::RangeOutside,
            SpanError::LastUnneeded,
        ];
        let labels = [
            "span_too_large",
            "span_magic",
            "span_version",
            "span_encoding",
            "span_trailing_bytes",
            "span_commit",
            "span_range_arithmetic",
            "span_chunk_count",
            "span_anchor_invalid",
            "span_anchor_selector",
            "span_anchor_offset",
            "span_inner_invalid",
            "span_chunk_selector",
            "span_leaf_context",
            "span_chunk_context",
            "span_chunk_order",
            "span_chunk_bytes",
            "span_anchor_binding",
            "span_range_outside",
            "span_last_unneeded",
        ];
        for (error, label) in reasons.into_iter().zip(labels) {
            assert_eq!(error.reason(), label);
        }
    }

    #[test]
    fn cross_bundle_reasons_include_defence_in_depth() {
        let id = [7; 32];
        let good = || Summary {
            selector_ok: true,
            leaf_ok: true,
            context_ok: true,
            index: 4,
            content_len: Some(5),
            first_byte: Some(42),
            canonical_id: id,
        };
        let mut cases = vec![good(), good()];
        cases[1].index = 5;
        assert!(check_summaries(&cases, 4, &id, 42).is_ok());

        cases[1].selector_ok = false;
        cases[0].leaf_ok = false;
        assert_eq!(
            check_summaries(&cases, 4, &id, 42).unwrap_err().reason(),
            "span_chunk_selector"
        );
        cases[1].selector_ok = true;
        assert_eq!(
            check_summaries(&cases, 4, &id, 42).unwrap_err().reason(),
            "span_leaf_context"
        );
        cases[0].leaf_ok = true;
        cases[0].context_ok = false;
        assert_eq!(
            check_summaries(&cases, 4, &id, 42).unwrap_err().reason(),
            "span_chunk_context"
        );
        cases[0].context_ok = true;
        cases[1].index = 6;
        assert_eq!(
            check_summaries(&cases, 4, &id, 42).unwrap_err().reason(),
            "span_chunk_order"
        );
        cases[1].index = 5;
        cases[1].content_len = None;
        assert_eq!(
            check_summaries(&cases, 4, &id, 42).unwrap_err().reason(),
            "span_chunk_bytes"
        );
        cases[1].content_len = Some(5);
        cases[0].canonical_id = [8; 32];
        assert_eq!(
            check_summaries(&cases, 4, &id, 42).unwrap_err().reason(),
            "span_anchor_binding"
        );
    }

    #[test]
    fn verified_bundle_failures_follow_selector_and_offset_checks() {
        let (trusted, d) = valid();
        let wrong_anchor = encode_span(trusted, d.offset, d.len, d.chunks[0], &d.chunks);
        assert_eq!(verify(&wrong_anchor), "span_anchor_selector");

        let (id, commit_bytes, steps, payload) = super::super::decode_disclosure(d.anchor).unwrap();
        let PayloadWire::Range {
            chunk,
            offset_in_blob,
            len,
            slice,
            ..
        } = payload
        else {
            panic!("anchor Range")
        };
        let no_offsets = encode_disclosure(
            &id,
            &commit_bytes,
            &steps,
            &PayloadWire::Range {
                chunk,
                offset_in_blob,
                len,
                slice,
                chunk_len_proofs: Vec::new(),
            },
        );
        assert!(verify_disclosure(&trusted, &no_offsets).is_ok());
        let missing_offset = encode_span(trusted, d.offset, d.len, &no_offsets, &d.chunks);
        assert_eq!(verify(&missing_offset), "span_anchor_offset");

        let bad_inner = encode_span(trusted, d.offset, d.len, d.anchor, &[b"MKDS", d.chunks[1]]);
        assert_eq!(verify(&bad_inner), "span_inner_invalid");
        let wrong_selector =
            encode_span(trusted, d.offset, d.len, d.anchor, &[d.anchor, d.chunks[1]]);
        assert_eq!(verify(&wrong_selector), "span_chunk_selector");

        let start = verify_disclosure_span(&trusted, VALID).unwrap().span_start;
        let outside = encode_span(trusted, start - 1, d.len, d.anchor, &d.chunks);
        assert_eq!(verify(&outside), "span_range_outside");
    }

    #[test]
    fn strict_varints_and_vector_bounds() {
        let (_, d) = valid();
        let anchor_len_at = 4 + 1 + 32 + 8 + 8;
        let mut nonminimal = VALID[..anchor_len_at].to_vec();
        nonminimal.extend_from_slice(&[0x80, 0]);
        nonminimal.extend_from_slice(&VALID[anchor_len_at + 2..]);
        assert_eq!(verify(&nonminimal), "span_encoding");

        let mut over_u32 = VALID[..anchor_len_at].to_vec();
        over_u32.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0x10]);
        assert_eq!(verify(&over_u32), "span_encoding");

        let mut length_over_remaining = VALID[..anchor_len_at].to_vec();
        length_over_remaining.extend_from_slice(&[0xff, 0xff, 0x03]);
        assert_eq!(verify(&length_over_remaining), "span_encoding");

        let mut count_over_remaining = encode_span(d.commit, d.offset, d.len, d.anchor, &[]);
        *count_over_remaining.last_mut().unwrap() = 2;
        assert_eq!(verify(&count_over_remaining), "span_encoding");
    }

    #[test]
    fn exact_boundaries_and_last_chunk_needed() {
        let d = decode(FIRST_ZERO).unwrap();
        let first = verify_disclosure(&d.commit, d.chunks[0]).unwrap();
        let DisclosedPayload::Chunk { bytes, .. } = first.payload else {
            panic!("chunk")
        };
        let Object::Blob(blob) = crate::serialize::deserialize(&bytes).unwrap() else {
            panic!("blob")
        };
        let edge = blob.data.len() as u64;
        let prior_only = encode_span(d.commit, edge - 1, 1, d.anchor, &d.chunks);
        assert_eq!(verify(&prior_only), "span_last_unneeded");
        let at_edge = encode_span(d.commit, edge - 1, 2, d.anchor, &d.chunks);
        assert_eq!(
            verify_disclosure_span(&d.commit, &at_edge)
                .unwrap()
                .bytes
                .len(),
            2
        );
        let last = verify_disclosure(&d.commit, d.chunks[1]).unwrap();
        let DisclosedPayload::Chunk { bytes, .. } = last.payload else {
            panic!("chunk")
        };
        let Object::Blob(blob) = crate::serialize::deserialize(&bytes).unwrap() else {
            panic!("blob")
        };
        let to_span_end = encode_span(
            d.commit,
            edge - 1,
            blob.data.len() as u64 + 1,
            d.anchor,
            &d.chunks,
        );
        assert_eq!(
            verify_disclosure_span(&d.commit, &to_span_end)
                .unwrap()
                .bytes
                .len() as u64,
            blob.data.len() as u64 + 1
        );
    }

    #[test]
    fn pure_plan_respects_exact_edges() {
        let one = plan_range_proof(&[10, 20, 30], 5, 5).unwrap();
        assert_eq!(
            (one.kind, one.first, one.last),
            (RangeProofKind::Mkdp, 0, 0)
        );
        let two = plan_range_proof(&[10, 20, 30], 9, 2).unwrap();
        assert_eq!(
            (two.kind, two.first, two.last),
            (RangeProofKind::Mkds, 0, 1)
        );
        let later = plan_range_proof(&[10, 20, 30], 12, 18).unwrap();
        assert_eq!(
            (later.kind, later.first, later.last),
            (RangeProofKind::Mkdp, 1, 1)
        );
        assert_eq!(later.needed_chunk_indices, vec![0, 1]);
        assert!(matches!(
            plan_range_proof(&[10], 0, 0),
            Err(RangeProofError::ZeroLength)
        ));
    }

    struct CountingSource<'a> {
        store: &'a ObjectStore,
        reads: RefCell<Vec<Hash>>,
    }

    impl ObjectSource for CountingSource<'_> {
        fn read(&self, h: &Hash) -> StoreResult<Vec<u8>> {
            PRECEDING_LIVE.with(|live| assert_eq!(live.get(), 0));
            self.reads.borrow_mut().push(*h);
            self.store.read(h)
        }
    }

    #[test]
    fn builder_reads_preceding_once_and_never_reads_after_span() {
        let temp = tempfile::TempDir::new().unwrap();
        let store = ObjectStore::init(&RepoLayout::single(temp.path())).unwrap();
        let mut chunk_ids = Vec::new();
        for i in 0u8..4 {
            let bytes = crate::serialize::serialize(&Object::Blob(Blob {
                data: vec![i + 1; 2048],
            }))
            .unwrap();
            chunk_ids.push(store.write(&bytes).unwrap());
        }
        let manifest = ChunkedBlob {
            total_size: 8192,
            chunk_size: 2048,
            chunks: chunk_ids.clone(),
        };
        let leaf_id = store
            .write(&crate::serialize::serialize(&Object::ChunkedBlob(manifest)).unwrap())
            .unwrap();
        let tree = Tree {
            entries: vec![TreeEntry {
                name: b"file".to_vec(),
                mode: EntryMode::Blob,
                object_hash: leaf_id,
            }],
        };
        let tree_hash = store
            .write(&crate::serialize::serialize(&Object::Tree(tree)).unwrap())
            .unwrap();
        let kp = KeyPair::from_seed([3; 32]);
        let mut commit = Commit {
            tree_hash,
            parents: vec![],
            author: Identity::ed25519(kp.public.0),
            signer: kp.public.0,
            message: b"span unit".to_vec(),
            timestamp: 1,
            message_hash: ZERO,
            content_digest: ZERO,
            signature: [0; 64],
        };
        commit.signature = sign_commit(&commit, &kp).unwrap().0;
        let commit_id = store
            .write(&crate::serialize::serialize(&Object::Commit(commit)).unwrap())
            .unwrap();
        let source = CountingSource {
            store: &store,
            reads: RefCell::new(Vec::new()),
        };
        PRECEDING_PEAK.with(|peak| peak.set(0));
        let RangeProof::Mkds(proof) =
            build_range_proof_from(&source, &commit_id, &[b"file"], 2047, 2, None).unwrap()
        else {
            panic!("expected MKDS")
        };
        assert_eq!(
            verify_disclosure_span(&commit_id, &proof).unwrap().bytes,
            [1, 2]
        );
        let reads = source.reads.borrow();
        assert_eq!(reads.iter().filter(|h| **h == chunk_ids[0]).count(), 1);
        assert_eq!(reads.iter().filter(|h| **h == chunk_ids[1]).count(), 1);
        assert!(!reads.contains(&chunk_ids[2]));
        assert!(!reads.contains(&chunk_ids[3]));
        drop(reads);
        PRECEDING_LIVE.with(|live| assert_eq!(live.get(), 0));
        // Reading through chunk 1 needs only chunk 0's length proof, so each
        // preceding chunk is live alone: the peak is exactly one, never more.
        PRECEDING_PEAK.with(|peak| peak.set(0));
        assert!(matches!(
            build_range_proof_from(&source, &commit_id, &[b"file"], 6200, 1, None).unwrap(),
            RangeProof::Mkdp(_)
        ));
        PRECEDING_PEAK.with(|peak| assert_eq!(peak.get(), 1));
        assert!(matches!(
            build_range_proof_from(
                &source,
                &commit_id,
                &[b"file"],
                2047,
                2,
                Some(&[0, 2000, 4048, 6096, 8192])
            ),
            Err(RangeProofError::HintMismatch { index: 0 })
        ));
    }
    #[test]
    fn inner_commit_bytes_must_hash_to_the_trusted_id() {
        let (trusted, d) = valid();
        let (id, commit_bytes, steps, payload) =
            super::super::decode_disclosure(d.chunks[1]).unwrap();
        let mut altered = commit_bytes.clone();
        altered.push(0);
        let forged = encode_disclosure(&id, &altered, &steps, &payload);
        let container = encode_span(trusted, d.offset, d.len, d.anchor, &[d.chunks[0], &forged]);
        let error = verify_disclosure_span(&trusted, &container).unwrap_err();
        assert_eq!(error.reason(), "span_inner_invalid");
        assert!(matches!(
            error,
            SpanError::InnerInvalid(VerifyError::CommitBytesHashMismatch)
        ));
    }

    #[test]
    fn invalid_boundary_hints_are_typed() {
        let temp = tempfile::TempDir::new().unwrap();
        let store = ObjectStore::init(&RepoLayout::single(temp.path())).unwrap();
        let chunk = |b: u8| {
            store
                .write(
                    &crate::serialize::serialize(&Object::Blob(Blob { data: vec![b; 10] }))
                        .unwrap(),
                )
                .unwrap()
        };
        let cb = ChunkedBlob {
            total_size: 20,
            chunk_size: 10,
            chunks: vec![chunk(1), chunk(2)],
        };
        let leaf = store
            .write(&crate::serialize::serialize(&Object::ChunkedBlob(cb)).unwrap())
            .unwrap();
        let blob = store
            .write(&crate::serialize::serialize(&Object::Blob(Blob { data: vec![9; 10] })).unwrap())
            .unwrap();
        let tree = Tree {
            entries: vec![
                TreeEntry {
                    name: b"blob".to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: blob,
                },
                TreeEntry {
                    name: b"chunked".to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: leaf,
                },
            ],
        };
        let tree_hash = store
            .write(&crate::serialize::serialize(&Object::Tree(tree)).unwrap())
            .unwrap();
        let kp = KeyPair::from_seed([4; 32]);
        let mut commit = Commit {
            tree_hash,
            parents: vec![],
            author: Identity::ed25519(kp.public.0),
            signer: kp.public.0,
            message: b"hints".to_vec(),
            timestamp: 1,
            message_hash: ZERO,
            content_digest: ZERO,
            signature: [0; 64],
        };
        commit.signature = sign_commit(&commit, &kp).unwrap().0;
        let commit_id = store
            .write(&crate::serialize::serialize(&Object::Commit(commit)).unwrap())
            .unwrap();
        for bad in [
            &[0u64, 20][..],
            &[1, 10, 20],
            &[0, 10, 19],
            &[0, 10, 10],
            &[0, 20, 10],
        ] {
            assert!(
                matches!(
                    build_range_proof_from(&store, &commit_id, &[b"chunked"], 0, 1, Some(bad)),
                    Err(RangeProofError::InvalidBoundaries)
                ),
                "{bad:?}"
            );
        }
        // A plain Blob has no boundaries, so any hint is invalid.
        assert!(matches!(
            build_range_proof_from(&store, &commit_id, &[b"blob"], 0, 1, Some(&[0, 10])),
            Err(RangeProofError::InvalidBoundaries)
        ));
    }
}
