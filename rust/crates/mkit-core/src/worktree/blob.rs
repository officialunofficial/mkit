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

/// Same as [`read_chunk`], returning [`crate::store::StoreError`] directly
/// instead of [`WorktreeError`] — for callers, like [`chunked_content_eq`],
/// that live entirely in `StoreError`'s error domain (matching
/// [`ContentCursor::remaining`]'s existing inline chunk-read match).
fn read_manifest_chunk<S: crate::store::ObjectSource + ?Sized>(
    store: &S,
    chunk: &Hash,
) -> Result<Vec<u8>, crate::store::StoreError> {
    match store.read_object(chunk)? {
        Object::Blob(b) => Ok(b.data),
        _ => Err(crate::store::StoreError::Io(io::Error::other(
            "manifest chunk is not a Blob",
        ))),
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

/// Representation-independent content identity: byte length and raw BLAKE3.
/// Reads each chunk once and verifies the complete manifest length. Memory is
/// bounded by the manifest and one chunk, independent of reassembled size.
///
/// # Errors
/// Missing, corrupt, wrong-type chunks and inconsistent lengths are errors.
pub fn content_fingerprint<S: crate::store::ObjectSource + ?Sized>(
    store: &S,
    hash: &Hash,
) -> Result<(u64, Hash), crate::store::StoreError> {
    use crate::store::StoreError;
    let mut hasher = crate::hash::Hasher::new();
    match store.read_object(hash)? {
        Object::Blob(b) => {
            hasher.update(&b.data);
            Ok((b.data.len() as u64, hasher.finalize()))
        }
        Object::ChunkedBlob(manifest) => {
            let mut size = 0usize;
            for chunk in &manifest.chunks {
                let Object::Blob(b) = store.read_object(chunk)? else {
                    return Err(StoreError::Io(io::Error::other(
                        "manifest chunk is not a Blob",
                    )));
                };
                size = size
                    .checked_add(b.data.len())
                    .ok_or(StoreError::ObjectTooLarge)?;
                hasher.update(&b.data);
            }
            manifest.check_reassembled_size(size)?;
            Ok((size as u64, hasher.finalize()))
        }
        _ => Err(StoreError::Io(io::Error::other(
            "content object is not a Blob or ChunkedBlob",
        ))),
    }
}

/// Compare file content independently of inline/chunked storage layout.
/// Equal object IDs are a fast path; different IDs require verified content.
///
/// A `ChunkedBlob`-vs-`ChunkedBlob` pair (the large-file case) takes the
/// further [`chunked_content_eq`] fast path, which skips reading any chunk
/// both sides reference by the same hash instead of reassembling and
/// byte-comparing every chunk of both blobs — see that function's doc for
/// what it trusts and what it still fully verifies. Any other pairing
/// (inline vs inline, or a mixed inline/chunked pair) keeps the exact
/// byte-cursor walk this function has always used.
///
/// # Errors
/// Propagates errors from [`content_fingerprint`].
pub fn content_eq<S: crate::store::ObjectSource + ?Sized>(
    store: &S,
    a: &Hash,
    b: &Hash,
) -> Result<bool, crate::store::StoreError> {
    if a == b {
        return Ok(true);
    }
    let obj_a = store.read_object(a)?;
    let obj_b = store.read_object(b)?;
    if let (Object::ChunkedBlob(ma), Object::ChunkedBlob(mb)) = (&obj_a, &obj_b) {
        return chunked_content_eq(store, ma, mb);
    }
    let mut left = ContentCursor::from_object(obj_a)?;
    let mut right = ContentCursor::from_object(obj_b)?;
    let mut equal = true;
    loop {
        let a = left.remaining(store)?;
        let b = right.remaining(store)?;
        if a.is_empty() && b.is_empty() {
            return Ok(equal);
        }
        if a.is_empty() || b.is_empty() {
            equal = false;
            let alen = a.len();
            let blen = b.len();
            left.offset += alen;
            right.offset += blen;
        } else {
            let count = a.len().min(b.len());
            equal &= a[..count] == b[..count];
            left.offset += count;
            right.offset += count;
        }
    }
}

/// Compare two [`ChunkedBlob`] manifests for content equality, skipping
/// any chunk both sides reference by the same content-addressed hash:
/// identical hash means identical bytes by construction — the same trust
/// [`content_eq`]'s own `a == b` whole-object fast path already relies
/// on, just applied per chunk instead of per object. Only chunks that
/// diverge (a different hash at the same aligned position) are actually
/// read and byte-compared, so a change confined to part of a large file
/// costs only that part on both sides, not the whole file. In
/// particular, an append needs zero chunk reads at all: every
/// pre-existing chunk still lines up by hash (`FastCDC`'s boundaries
/// never depend on bytes past them), so the walk skips straight to the
/// new chunks at the end and stops as soon as one side runs out.
///
/// `total_size` is trusted without re-summing actual chunk bytes — the
/// same trust [`LoadedBlob::len`] already documents: every reassembly
/// path enforces it via [`ChunkedBlob::check_reassembled_size`], so a
/// manifest with a wrong `total_size` cannot have been durably written
/// through mkit's own writers (#550). A manifest deliberately
/// constructed to violate that and whose *entire* chunk sequence still
/// lines up by hash with the side it's compared against slips through
/// this fast path unnoticed; one whose chunks diverge anywhere is still
/// fully read from the first divergent chunk onward (any store-level
/// corruption or missing chunk there still surfaces as an error) — it
/// just stops draining once both sides run out, rather than continuing
/// to re-verify chunks already known identical by id.
///
/// # Errors
/// [`crate::store::StoreError`] if a chunk that must be read (either
/// side has no matching chunk to skip against) is missing, corrupt, or
/// not a `Blob`.
fn chunked_content_eq<S: crate::store::ObjectSource + ?Sized>(
    store: &S,
    ma: &ChunkedBlob,
    mb: &ChunkedBlob,
) -> Result<bool, crate::store::StoreError> {
    if ma.total_size != mb.total_size {
        return Ok(false);
    }

    let mut ia = 0usize;
    let mut ib = 0usize;
    let mut buf_a: Vec<u8> = Vec::new();
    let mut buf_b: Vec<u8> = Vec::new();
    let mut pos_a = 0usize;
    let mut pos_b = 0usize;
    let mut equal = true;

    loop {
        // Both cursors sit at a chunk boundary: skip a run of chunks
        // that match by id, with no read on either side.
        while pos_a == buf_a.len()
            && pos_b == buf_b.len()
            && ia < ma.chunks.len()
            && ib < mb.chunks.len()
            && ma.chunks[ia] == mb.chunks[ib]
        {
            ia += 1;
            ib += 1;
        }

        if pos_a == buf_a.len() {
            buf_a = match ma.chunks.get(ia) {
                Some(h) => {
                    ia += 1;
                    read_manifest_chunk(store, h)?
                }
                None => Vec::new(),
            };
            pos_a = 0;
        }
        if pos_b == buf_b.len() {
            buf_b = match mb.chunks.get(ib) {
                Some(h) => {
                    ib += 1;
                    read_manifest_chunk(store, h)?
                }
                None => Vec::new(),
            };
            pos_b = 0;
        }

        let a_rest = &buf_a[pos_a..];
        let b_rest = &buf_b[pos_b..];
        if a_rest.is_empty() && b_rest.is_empty() {
            if ia >= ma.chunks.len() && ib >= mb.chunks.len() {
                return Ok(equal);
            }
            // A zero-length trailing chunk on one or both sides; loop
            // again to pull the next one via the boundary checks above.
            continue;
        }

        let count = a_rest.len().min(b_rest.len());
        if count == 0 {
            // One side has run out of chunks for good; drain the other
            // (matching the byte-cursor path's behavior) so a read
            // error later in its remaining chunks still surfaces.
            equal = false;
            pos_a = buf_a.len();
            pos_b = buf_b.len();
            continue;
        }
        if a_rest[..count] != b_rest[..count] {
            equal = false;
        }
        pos_a += count;
        pos_b += count;
    }
}

/// Compare stored content to bytes without reassembling chunked storage.
///
/// # Errors
/// Propagates errors from [`content_fingerprint`].
pub fn content_eq_bytes<S: crate::store::ObjectSource + ?Sized>(
    store: &S,
    object: &Hash,
    bytes: &[u8],
) -> Result<bool, crate::store::StoreError> {
    let mut cursor = ContentCursor::load(store, object)?;
    let mut offset = 0usize;
    let mut equal = true;
    loop {
        let chunk = cursor.remaining(store)?;
        if chunk.is_empty() {
            return Ok(equal && offset == bytes.len());
        }
        let end = offset
            .checked_add(chunk.len())
            .ok_or(crate::store::StoreError::ObjectTooLarge)?;
        equal &= bytes.get(offset..end) == Some(chunk);
        offset = end;
        cursor.offset += chunk.len();
    }
}

struct ContentCursor {
    data: Vec<u8>,
    offset: usize,
    chunks: std::vec::IntoIter<Hash>,
    expected: u64,
    loaded: u64,
}

impl ContentCursor {
    fn load<S: crate::store::ObjectSource + ?Sized>(
        store: &S,
        hash: &Hash,
    ) -> Result<Self, crate::store::StoreError> {
        Self::from_object(store.read_object(hash)?)
    }

    /// Build a cursor from an already-read top-level object, saving the
    /// caller a second `read_object` when it needed the object anyway
    /// (e.g. [`content_eq`] deciding whether the chunked fast path
    /// applies).
    fn from_object(object: Object) -> Result<Self, crate::store::StoreError> {
        let (data, chunks, expected) = match object {
            Object::Blob(b) => {
                let size = b.data.len() as u64;
                (b.data, Vec::new(), size)
            }
            Object::ChunkedBlob(m) => (Vec::new(), m.chunks, m.total_size),
            _ => {
                return Err(crate::store::StoreError::Io(io::Error::other(
                    "content object is not a Blob or ChunkedBlob",
                )));
            }
        };
        let loaded = data.len() as u64;
        Ok(Self {
            data,
            offset: 0,
            chunks: chunks.into_iter(),
            expected,
            loaded,
        })
    }

    fn remaining<S: crate::store::ObjectSource + ?Sized>(
        &mut self,
        store: &S,
    ) -> Result<&[u8], crate::store::StoreError> {
        while self.offset == self.data.len() {
            let Some(hash) = self.chunks.next() else {
                if self.loaded != self.expected {
                    return Err(crate::object::MkitError::ChunkedBlobSizeMismatch {
                        expected: self.expected,
                        actual: self.loaded,
                    }
                    .into());
                }
                return Ok(&[]);
            };
            let Object::Blob(blob) = store.read_object(&hash)? else {
                return Err(crate::store::StoreError::Io(io::Error::other(
                    "manifest chunk is not a Blob",
                )));
            };
            self.loaded = self
                .loaded
                .checked_add(blob.data.len() as u64)
                .ok_or(crate::store::StoreError::ObjectTooLarge)?;
            self.data = blob.data;
            self.offset = 0;
        }
        Ok(&self.data[self.offset..])
    }
}

#[cfg(test)]
mod equality_tests {
    use super::*;
    use crate::{layout::RepoLayout, object::Blob, serialize, store::ObjectStore};

    fn put(store: &ObjectStore, object: &Object) -> Hash {
        store.write(&serialize::serialize(object).unwrap()).unwrap()
    }

    #[test]
    fn large_inline_fixed_and_cdc_content_agree() {
        let dir = tempfile::tempdir().unwrap();
        let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
        let data = vec![7; usize::try_from(super::super::CHUNK_THRESHOLD + 17).unwrap()];
        let inline = put(&store, &Object::Blob(Blob { data: data.clone() }));
        let cdc = super::super::store_file_object(&store, &data).unwrap();
        let chunks = data
            .chunks(65_536)
            .map(|b| put(&store, &Object::Blob(Blob { data: b.to_vec() })))
            .collect();
        let fixed = put(
            &store,
            &Object::ChunkedBlob(ChunkedBlob {
                total_size: data.len() as u64,
                chunk_size: 65_536,
                chunks,
            }),
        );
        assert_ne!(inline, cdc);
        assert_ne!(fixed, cdc);
        assert!(content_eq(&store, &inline, &fixed).unwrap());
        assert!(content_eq(&store, &fixed, &cdc).unwrap());
        assert!(content_eq_bytes(&store, &fixed, &data).unwrap());
        assert_eq!(
            content_fingerprint(&store, &inline).unwrap(),
            content_fingerprint(&store, &cdc).unwrap()
        );
        let mut changed = data;
        changed[65_536] = 8;
        assert!(!content_eq_bytes(&store, &fixed, &changed).unwrap());
    }

    #[test]
    fn invalid_chunks_are_errors_even_after_content_differs() {
        let dir = tempfile::tempdir().unwrap();
        let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
        let a = put(
            &store,
            &Object::Blob(Blob {
                data: b"a".to_vec(),
            }),
        );
        let b = put(
            &store,
            &Object::Blob(Blob {
                data: b"b".to_vec(),
            }),
        );
        for (total_size, chunks) in [(2, vec![a]), (2, vec![a, [42; 32]])] {
            let bad = put(
                &store,
                &Object::ChunkedBlob(ChunkedBlob {
                    total_size,
                    chunk_size: 0,
                    chunks,
                }),
            );
            assert!(content_eq(&store, &bad, &b).is_err());
            assert!(content_eq_bytes(&store, &bad, b"b").is_err());
            assert!(content_fingerprint(&store, &bad).is_err());
        }
    }

    fn chunk(store: &ObjectStore, data: &[u8]) -> Hash {
        put(
            store,
            &Object::Blob(Blob {
                data: data.to_vec(),
            }),
        )
    }

    fn manifest(store: &ObjectStore, parts: &[&[u8]]) -> ChunkedBlob {
        let total_size: u64 = parts.iter().map(|p| p.len() as u64).sum();
        ChunkedBlob {
            total_size,
            chunk_size: 0,
            chunks: parts.iter().map(|p| chunk(store, p)).collect(),
        }
    }

    fn fresh_store() -> (tempfile::TempDir, ObjectStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
        (dir, store)
    }

    // Direct tests of `chunked_content_eq`'s merge logic against small,
    // hand-built manifests — fast and deterministic, independent of real
    // FastCDC boundaries, covering the id-skip fast path, the
    // read-and-resync fallback, and the documented total_size trust gap.

    #[test]
    fn chunked_fast_path_all_chunks_match_by_id() {
        let (_dir, store) = fresh_store();
        let x = chunk(&store, b"hello ");
        let y = chunk(&store, b"world");
        let ma = ChunkedBlob {
            total_size: 11,
            chunk_size: 0,
            chunks: vec![x, y],
        };
        let mb = ma.clone();
        assert!(super::chunked_content_eq(&store, &ma, &mb).unwrap());
    }

    #[test]
    fn chunked_fully_misaligned_but_equal_content() {
        let (_dir, store) = fresh_store();
        // "ab"+"cd" vs "a"+"bcd" — no chunk hash ever matches, so every
        // byte is read and compared through the resync fallback, yet the
        // reassembled content is identical.
        let ma = manifest(&store, &[b"ab", b"cd"]);
        let mb = manifest(&store, &[b"a", b"bcd"]);
        assert!(super::chunked_content_eq(&store, &ma, &mb).unwrap());
        assert!(super::chunked_content_eq(&store, &mb, &ma).unwrap());
    }

    #[test]
    fn chunked_shared_prefix_then_misaligned_equal_suffix() {
        let (_dir, store) = fresh_store();
        let x = chunk(&store, b"shared-prefix-");
        let ma = ChunkedBlob {
            total_size: 14 + 4,
            chunk_size: 0,
            chunks: [x]
                .into_iter()
                .chain(manifest(&store, &[b"ab", b"cd"]).chunks)
                .collect(),
        };
        let mb = ChunkedBlob {
            total_size: 14 + 4,
            chunk_size: 0,
            chunks: [x]
                .into_iter()
                .chain(manifest(&store, &[b"a", b"bcd"]).chunks)
                .collect(),
        };
        // `x` is skipped by id; "ab"+"cd" vs "a"+"bcd" is read and resynced.
        assert!(super::chunked_content_eq(&store, &ma, &mb).unwrap());
    }

    #[test]
    fn chunked_append_differs_via_total_size_without_reading() {
        let (_dir, store) = fresh_store();
        let x = chunk(&store, b"shared");
        let ma = ChunkedBlob {
            total_size: 6,
            chunk_size: 0,
            chunks: vec![x],
        };
        let y = chunk(&store, b"-more");
        let mb = ChunkedBlob {
            total_size: 11,
            chunk_size: 0,
            chunks: vec![x, y],
        };
        assert!(!super::chunked_content_eq(&store, &ma, &mb).unwrap());
        assert!(!super::chunked_content_eq(&store, &mb, &ma).unwrap());
    }

    #[test]
    fn chunked_same_total_size_different_content_after_shared_prefix() {
        let (_dir, store) = fresh_store();
        let x = chunk(&store, b"shared-");
        let ma = ChunkedBlob {
            total_size: 7 + 2,
            chunk_size: 0,
            chunks: vec![x, chunk(&store, b"ab")],
        };
        let mb = ChunkedBlob {
            total_size: 7 + 2,
            chunk_size: 0,
            chunks: vec![x, chunk(&store, b"ba")],
        };
        assert!(!super::chunked_content_eq(&store, &ma, &mb).unwrap());
    }

    #[test]
    fn chunked_split_differently_but_actually_different_content() {
        let (_dir, store) = fresh_store();
        let x = chunk(&store, b"shared-");
        let ma = ChunkedBlob {
            total_size: 7 + 4,
            chunk_size: 0,
            chunks: vec![x, chunk(&store, b"abcd")],
        };
        let mb = ChunkedBlob {
            total_size: 7 + 4,
            chunk_size: 0,
            chunks: vec![x, chunk(&store, b"ab"), chunk(&store, b"cX")],
        };
        assert!(!super::chunked_content_eq(&store, &ma, &mb).unwrap());
    }

    #[test]
    fn chunked_empty_manifests_are_equal() {
        let (_dir, store) = fresh_store();
        let ma = ChunkedBlob {
            total_size: 0,
            chunk_size: 0,
            chunks: vec![],
        };
        let mb = ma.clone();
        assert!(super::chunked_content_eq(&store, &ma, &mb).unwrap());
    }

    /// Documents the accepted trust gap: `total_size` is not re-summed
    /// from actual chunk bytes on the chunked fast path (mirroring
    /// `LoadedBlob::len`'s existing trust). Two manifests whose chunk
    /// sequence fully matches by id, but whose shared `total_size`
    /// field is wrong for that sequence, are reported equal without
    /// ever reading a chunk to notice. A manifest this malformed cannot
    /// be produced by any of mkit's own writers (`check_reassembled_size`
    /// gates every one); this can only arise from an object constructed
    /// directly, bypassing them, as this test does.
    #[test]
    fn chunked_wrong_shared_total_size_is_not_detected_when_ids_fully_match() {
        let (_dir, store) = fresh_store();
        let x = chunk(&store, b"ab"); // 2 real bytes
        let ma = ChunkedBlob {
            total_size: 999, // wrong on both sides, identically
            chunk_size: 0,
            chunks: vec![x],
        };
        let mb = ma.clone();
        assert!(super::chunked_content_eq(&store, &ma, &mb).unwrap());
    }

    /// End-to-end sanity check through the public `content_eq` entry
    /// point (not the private merge function directly) over real
    /// `FastCDC`-chunked content: an append, a single-byte in-place edit,
    /// and a truncation each produce a different manifest and must all
    /// compare unequal, exactly matching a ground-truth byte comparison.
    #[test]
    fn content_eq_real_chunked_mutations_match_ground_truth() {
        let (_dir, store) = fresh_store();
        let threshold = usize::try_from(super::super::CHUNK_THRESHOLD).unwrap();
        // Deterministic pseudo-random bytes so FastCDC sees real cut
        // points instead of one run-length-maxed chunk.
        let mut data = Vec::with_capacity(threshold * 3);
        let mut state: u64 = 0x1234_5678_9abc_def0;
        for _ in 0..threshold * 3 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            data.push((state >> 56) as u8);
        }

        let base = super::super::store_file_object(&store, &data).unwrap();

        let mut appended = data.clone();
        appended.extend_from_slice(b"appended tail bytes");
        let appended_hash = super::super::store_file_object(&store, &appended).unwrap();

        let mut edited = data.clone();
        let mid = edited.len() / 2;
        edited[mid] ^= 0xFF;
        let edited_hash = super::super::store_file_object(&store, &edited).unwrap();

        let truncated = &data[..data.len() - 500];
        let truncated_hash = super::super::store_file_object(&store, truncated).unwrap();

        let unchanged_hash = super::super::store_file_object(&store, &data).unwrap();

        assert_eq!(base, unchanged_hash, "identical content dedups to one id");
        assert!(content_eq(&store, &base, &unchanged_hash).unwrap());

        for (name, other, other_bytes) in [
            ("append", appended_hash, appended.as_slice()),
            ("edit", edited_hash, edited.as_slice()),
            ("truncate", truncated_hash, truncated),
        ] {
            assert_ne!(base, other, "{name}: expected a different object id");
            assert_eq!(
                content_eq(&store, &base, &other).unwrap(),
                data == other_bytes,
                "{name}: content_eq must match ground truth"
            );
            assert!(
                !content_eq(&store, &base, &other).unwrap(),
                "{name}: bytes differ"
            );
        }
    }
}
