//! Blob-content I/O: reading back what the worktree walker stored.
//!
//! A file's content lives either in a single inline [`Blob`](crate::object::Blob)
//! or behind a [`ChunkedBlob`](crate::object::ChunkedBlob) manifest. [`LoadedBlob`]
//! is the one-read-per-object view over both shapes; [`read_blob`] is the one-shot
//! full-content convenience on top of it. Extracted from `worktree.rs` (#633) —
//! this cluster reconstructs content and has nothing to do with walking a worktree.

use std::borrow::Cow;
use std::io;

use crate::hash::Hash;
use crate::object::{ChunkedBlob, Object};

use super::{WorktreeError, WorktreeResult};

/// Reassemble the full byte content of a `Blob` or `ChunkedBlob` object
/// addressed by `hash`.
///
/// A plain [`Blob`](crate::object::Blob) returns its bytes directly. A
/// [`ChunkedBlob`] manifest is reassembled
/// by concatenating each referenced chunk (every chunk must itself be a
/// `Blob`). This is the shared counterpart to [`store_file_object`](super::store_file_object) and
/// backs `mkit cat`, `mkit diff`, conflict rendering, and blame so they
/// all reconstruct large-file content the same way.
///
/// # Errors
/// - [`WorktreeError::Store`] if `hash` or any chunk is missing.
/// - [`WorktreeError::Io`] if `hash` (or a chunk) resolves to an object
///   that is neither a `Blob` nor a `ChunkedBlob` of `Blob`s.
/// - [`WorktreeError::Object`] if the concatenated chunks do not total
///   the manifest's `total_size` (SPEC-OBJECTS §7).
pub fn read_blob<S: crate::store::ObjectSource + ?Sized>(
    store: &S,
    hash: &Hash,
) -> WorktreeResult<Vec<u8>> {
    LoadedBlob::load(store, hash)?.into_content(store)
}

/// A blob's top-level object, read from the store exactly once and held so
/// a caller needing several views of the same blob — byte length, bounded
/// prefix, full content — pays a single top-level `read_object` instead of
/// one per view. `diff --stat` is the motivating caller: its text-vs-binary
/// sniff needs a prefix, then either the length (binary row) or the full
/// content (text row), and taking each view through a separate store-level
/// read re-read (and re-hash-verified) the same object two times per
/// changed file, a per-entry cost that dominates a many-small-files
/// diffstat (#624).
///
/// Chunk objects are still read on demand: [`Self::len`] reads none,
/// [`Self::prefix`] reads only leading chunks, [`Self::into_content`]
/// reads them all.
///
/// One read stays undeduped by design: [`Self::prefix`] on a chunked blob
/// reads the leading chunk(s) to sniff, and [`Self::into_content`] reads
/// every chunk (including that same leading one) to reassemble — a caller
/// doing both, as `diff --stat` does, reads the first chunk twice. Caching
/// it would need either interior mutability or a consuming-prefix API, to
/// save an O(1) read on an O(n-chunks) path; not worth it (#624).
#[derive(Debug)]
pub enum LoadedBlob {
    /// An inline [`Blob`](crate::object::Blob): its full content, already
    /// in hand.
    Inline(Vec<u8>),
    /// A [`ChunkedBlob`] manifest: content lives in chunk objects, read
    /// only when a view needs them.
    Chunked(ChunkedBlob),
}

impl LoadedBlob {
    /// Read the top-level object addressed by `hash` — one store read.
    ///
    /// # Errors
    /// - [`WorktreeError::Store`] if `hash` is missing.
    /// - [`WorktreeError::Io`] if `hash` resolves to an object that is
    ///   neither a `Blob` nor a `ChunkedBlob`.
    pub fn load<S: crate::store::ObjectSource + ?Sized>(
        store: &S,
        hash: &Hash,
    ) -> WorktreeResult<Self> {
        match store.read_object(hash)? {
            Object::Blob(b) => Ok(Self::Inline(b.data)),
            Object::ChunkedBlob(manifest) => Ok(Self::Chunked(manifest)),
            other => Err(not_a_blob("object", hash, &other)),
        }
    }

    /// Content byte length from what is already in hand — an inline blob's
    /// data length, a chunked blob's manifest `total_size` — no chunk
    /// reads. `total_size` is trustworthy without re-verifying against the
    /// chunks: every reassembly path enforces it via
    /// [`ChunkedBlob::check_reassembled_size`], so a manifest with a wrong
    /// `total_size` cannot have been durably written (#550).
    #[must_use]
    pub fn len(&self) -> u64 {
        match self {
            Self::Inline(data) => data.len() as u64,
            Self::Chunked(manifest) => manifest.total_size,
        }
    }

    /// Whether the content is zero bytes long.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Up to `max_len` leading content bytes. Inline data is borrowed (no
    /// copy, no reads); a chunked blob reads only as many leading chunks
    /// as it takes to cover `max_len`, then stops — one chunk in practice,
    /// since every chunk but possibly the last is at least
    /// [`crate::chunker::MIN_SIZE`] bytes, well above the sniff windows
    /// callers use (e.g. [`crate::ops::diff::BINARY_SNIFF_LEN`]).
    ///
    /// # Errors
    /// - [`WorktreeError::Store`] if a needed chunk is missing.
    /// - [`WorktreeError::Io`] if a needed chunk is not a `Blob`.
    pub fn prefix<S: crate::store::ObjectSource + ?Sized>(
        &self,
        store: &S,
        max_len: usize,
    ) -> WorktreeResult<Cow<'_, [u8]>> {
        match self {
            Self::Inline(data) => Ok(Cow::Borrowed(&data[..data.len().min(max_len)])),
            Self::Chunked(manifest) => {
                let cap = usize::try_from(manifest.total_size)
                    .unwrap_or(max_len)
                    .min(max_len);
                let mut data = Vec::with_capacity(cap);
                for chunk in &manifest.chunks {
                    if data.len() >= max_len {
                        break;
                    }
                    data.extend_from_slice(&read_chunk(store, chunk)?);
                }
                data.truncate(max_len);
                Ok(Cow::Owned(data))
            }
        }
    }

    /// The full content: inline data as-is (no further reads), a chunked
    /// blob reassembled by reading every chunk, with the result length
    /// enforced against the manifest's `total_size` (SPEC-OBJECTS §7).
    ///
    /// # Errors
    /// - [`WorktreeError::Store`] if a chunk is missing.
    /// - [`WorktreeError::Io`] if a chunk is not a `Blob`.
    /// - [`WorktreeError::Object`] if the concatenated chunks do not total
    ///   the manifest's `total_size`.
    pub fn into_content<S: crate::store::ObjectSource + ?Sized>(
        self,
        store: &S,
    ) -> WorktreeResult<Vec<u8>> {
        match self {
            Self::Inline(data) => Ok(data),
            Self::Chunked(manifest) => {
                let mut data =
                    Vec::with_capacity(usize::try_from(manifest.total_size).unwrap_or(0));
                for chunk in &manifest.chunks {
                    data.extend_from_slice(&read_chunk(store, chunk)?);
                }
                manifest.check_reassembled_size(data.len())?;
                Ok(data)
            }
        }
    }

    /// The empty blob: what a diff side with no object (an add's old side,
    /// a delete's new side) loads as. Zero length, empty prefix, empty
    /// content — no store reads.
    #[must_use]
    pub fn empty() -> Self {
        Self::Inline(Vec::new())
    }
}

/// One chunk of a [`ChunkedBlob`]: must deserialize to an inline `Blob`.
fn read_chunk<S: crate::store::ObjectSource + ?Sized>(
    store: &S,
    chunk: &Hash,
) -> WorktreeResult<Vec<u8>> {
    match store.read_object(chunk)? {
        Object::Blob(b) => Ok(b.data),
        other => Err(not_a_blob("chunk", chunk, &other)),
    }
}

/// The "expected a blob, found something else" error shared by every
/// [`LoadedBlob`] read path; `what` is `"object"` for a top-level hash and
/// `"chunk"` for a manifest chunk, preserving the historical wording of
/// both messages.
fn not_a_blob(what: &str, hash: &Hash, got: &Object) -> WorktreeError {
    WorktreeError::Io(io::Error::other(format!(
        "{what} {} is not a blob (got {})",
        crate::hash::to_hex(hash),
        got.object_type().name()
    )))
}
