//! The blob contract (PRD §5.3): content-addressed, immutable bytes.
//!
//! A [`BlobKey`] selects `packs/<hex>`, the upload marker namespace, or (WP-4.10)
//! the global object namespaces. Pack and marker keys require
//! `BLAKE3(bytes) == key`; an object key is an object id, so its bytes are
//! verified against a caller-supplied content root instead
//! ([`PackSink::commit_with_root`]). Pack RPCs construct only pack keys.
//! Resumable multipart uploads are a sub-trait (`MultipartBlobStore`, WP-1.11).

use core::fmt;
use core::future::Future;

use bytes::Bytes;
use mkit_core::hash::{Hash, to_hex_bytes};
use mkit_core::protocol::PackKey;
use mkit_core::upload_parts::PartPlan;

use super::error::StoreError;
use crate::rt::{BoxStream, MaybeSend, MaybeSync};

/// A blob's content hash and storage namespace. Pack RPCs construct only
/// `Pack` keys, so an upload marker cannot be fetched as a pack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlobKey {
    hash: Hash,
    namespace: BlobNamespace,
}

/// The physical namespace of a content-addressed blob.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BlobNamespace {
    /// Pack bytes.
    Pack,
    /// Proof that a ticket holder streamed and verified a pack.
    UploadMarker,
    /// The reassembled content of a Blob or `ChunkedBlob`, keyed by its object
    /// id and shared by the whole deployment (SPEC-SERVER §9.6).
    Object,
    /// The chunk-offset sidecar of an extracted `ChunkedBlob`, keyed by the
    /// manifest's object id.
    ObjectOffsets,
}

impl BlobKey {
    /// Construct a pack key.
    #[must_use]
    pub const fn pack(hash: Hash) -> Self {
        Self {
            hash,
            namespace: BlobNamespace::Pack,
        }
    }

    /// Construct an upload marker key.
    #[must_use]
    pub const fn upload_marker(hash: Hash) -> Self {
        Self {
            hash,
            namespace: BlobNamespace::UploadMarker,
        }
    }

    /// Construct a global object key: the extracted content of object `id`.
    #[must_use]
    pub const fn object(id: Hash) -> Self {
        Self {
            hash: id,
            namespace: BlobNamespace::Object,
        }
    }

    /// Construct an offsets sidecar key for the `ChunkedBlob` `manifest_id`.
    #[must_use]
    pub const fn object_offsets(manifest_id: Hash) -> Self {
        Self {
            hash: manifest_id,
            namespace: BlobNamespace::ObjectOffsets,
        }
    }

    /// The hash a sink verifies the bytes against: the key's own hash for
    /// `root = None` (pack and marker keys), or the caller's content root
    /// for an object key, whose hash is an object id rather than a content
    /// hash. An object key without a root, and a root on any other key, are
    /// refused, so no backend can publish bytes under an object id without
    /// checking them.
    ///
    /// # Errors
    /// [`StoreError::Invalid`] for either mismatch.
    pub fn expected_root(&self, root: Option<Hash>) -> Result<Hash, StoreError> {
        let object = matches!(
            self.namespace,
            BlobNamespace::Object | BlobNamespace::ObjectOffsets
        );
        match (object, root) {
            (false, None) => Ok(self.hash),
            (true, Some(root)) => Ok(root),
            (true, None) => Err(StoreError::Invalid(
                "an object key needs a root-verified commit".into(),
            )),
            (false, Some(_)) => Err(StoreError::Invalid(
                "a content root applies only to object keys".into(),
            )),
        }
    }

    /// Content hash bytes.
    #[must_use]
    pub const fn hash(&self) -> &Hash {
        &self.hash
    }

    /// Lowercase hexadecimal content hash.
    #[must_use]
    pub fn to_hex(&self) -> String {
        to_hex_bytes(&self.hash)
    }

    /// Path relative to a blob root, given the pack keyspace (which may
    /// include a deployment prefix). Markers and objects use its sibling
    /// namespaces.
    ///
    /// # Errors
    /// [`StoreError::Invalid`] for a namespace this backend does not support.
    pub fn relative_path(&self, pack_keyspace: &str) -> Result<String, StoreError> {
        // The fallback handles future BlobNamespace variants without a backend panic.
        #[allow(unreachable_patterns)]
        let sibling = |name: &str| {
            let parent = pack_keyspace
                .rsplit_once('/')
                .map_or("", |(parent, _)| parent);
            if parent.is_empty() {
                name.to_owned()
            } else {
                format!("{parent}/{name}")
            }
        };
        // The fallback handles future BlobNamespace variants without a backend panic.
        #[allow(unreachable_patterns)]
        let directory = match self.namespace {
            BlobNamespace::Pack => {
                // A pack keyspace named like a sibling namespace would let
                // unverified pack bytes be read back as an object or marker.
                let last = pack_keyspace.rsplit('/').next().unwrap_or(pack_keyspace);
                if matches!(last, "objects" | "object-offsets" | "upload-markers") {
                    return Err(StoreError::Invalid("reserved pack keyspace".into()));
                }
                pack_keyspace.to_owned()
            }
            BlobNamespace::UploadMarker => sibling("upload-markers/v1"),
            BlobNamespace::Object => sibling("objects"),
            BlobNamespace::ObjectOffsets => sibling("object-offsets/v1"),
            _ => return Err(StoreError::Invalid("unsupported blob namespace".into())),
        };
        Ok(format!("{directory}/{}", self.to_hex()))
    }

    /// Physical namespace.
    #[must_use]
    pub const fn namespace(&self) -> BlobNamespace {
        self.namespace
    }
}

impl From<PackKey> for BlobKey {
    fn from(key: PackKey) -> Self {
        Self::pack(key.0)
    }
}

/// An inclusive byte range, as in HTTP `Range`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteRange {
    /// First byte.
    pub start: u64,
    /// Last byte; clamped to the blob's last byte.
    pub end_inclusive: u64,
}

impl ByteRange {
    /// The `start..end` slice this range selects in a blob of `len` bytes.
    ///
    /// # Errors
    /// [`StoreError::Invalid`] when `start > end_inclusive` (malformed);
    /// [`StoreError::RangeNotSatisfiable`] when `start >= len`.
    pub fn resolve(self, len: u64) -> Result<core::ops::Range<u64>, StoreError> {
        if self.start > self.end_inclusive {
            return Err(StoreError::Invalid("byte range start after its end".into()));
        }
        if self.start >= len {
            return Err(StoreError::RangeNotSatisfiable { len });
        }
        Ok(self.start..self.end_inclusive.min(len - 1) + 1)
    }
}

/// Largest piece of a streamed [`BlobBody`], and the longest body a
/// [`BlobStore::get`] may return as one buffer.
pub const MAX_BLOB_PIECE_BYTES: usize = 1024 * 1024;

/// A blob's metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlobMeta {
    /// Length in bytes.
    pub len: u64,
}

/// A blob's bytes, whole or streamed.
pub enum BlobBody {
    /// All bytes in one buffer.
    Bytes(Bytes),
    /// A stream of chunks totaling `len` bytes.
    Stream {
        /// Total length.
        len: u64,
        /// The chunks, in order.
        stream: BoxStream<'static, Result<Bytes, StoreError>>,
    },
}

impl fmt::Debug for BlobBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bytes(b) => f.debug_tuple("Bytes").field(&b.len()).finish(),
            Self::Stream { len, .. } => f.debug_struct("Stream").field("len", len).finish(),
        }
    }
}

/// How a [`PackSink::commit`] ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitOutcome {
    /// The blob is new.
    Created,
    /// The blob was already there (identical bytes, by construction).
    /// Advisory: a concurrent writer of the same key may see `Created` too,
    /// and a backend that cannot tell cheaply may report `Created`. Nothing
    /// may depend on it for correctness or accounting.
    AlreadyPresent,
}

/// A content-addressed, immutable blob store. Writes are put-if-absent;
/// rewriting a present key with identical bytes is `AlreadyPresent`.
pub trait BlobStore: MaybeSend + MaybeSync {
    /// The upload handle [`Self::begin`] returns.
    type Sink: PackSink;

    /// Start writing blob `key` of `len` bytes.
    fn begin(
        &self,
        key: BlobKey,
        len: u64,
    ) -> impl Future<Output = Result<Self::Sink, StoreError>> + MaybeSend;

    /// The blob's bytes, or `range` of them. A body longer than
    /// [`MAX_BLOB_PIECE_BYTES`] MUST be a [`BlobBody::Stream`] whose pieces
    /// are each at most [`MAX_BLOB_PIECE_BYTES`] (an adapter re-chunks its
    /// backend's stream); a backend never buffers a whole pack. A range
    /// starting at or past the end is [`StoreError::RangeNotSatisfiable`].
    fn get(
        &self,
        key: &BlobKey,
        range: Option<ByteRange>,
    ) -> impl Future<Output = Result<Option<BlobBody>, StoreError>> + MaybeSend;

    /// The blob's metadata, if present.
    fn head(
        &self,
        key: &BlobKey,
    ) -> impl Future<Output = Result<Option<BlobMeta>, StoreError>> + MaybeSend;

    /// A cheap health check.
    fn probe(&self) -> impl Future<Output = Result<(), StoreError>> + MaybeSend;

    /// Remove a blob; returns whether it existed. Never called by the M0
    /// pipeline: reserved for GC and takedown (WP-5.3b, WP-5.6).
    fn delete(&self, key: &BlobKey) -> impl Future<Output = Result<bool, StoreError>> + MaybeSend;
}

/// An in-progress blob upload.
///
/// Memory is bounded by a backend constant (one part, e.g. an R2 multipart
/// part or a write buffer), never by the blob. Dropping a sink without
/// `commit` or `abort` leaves nothing visible; its staged bytes may leak
/// until the backend reclaims them (a temp-file sweep natively, R2's
/// abort-incomplete-multipart-upload lifecycle rule).
pub trait PackSink: MaybeSend {
    /// Append a chunk. Writing past the declared length is
    /// [`StoreError::Invalid`].
    fn write(&mut self, chunk: Bytes) -> impl Future<Output = Result<(), StoreError>> + MaybeSend;

    /// Make the blob visible, only if `BLAKE3(bytes) == key` and the total
    /// equals the declared length; otherwise [`StoreError::Invalid`] and
    /// nothing is visible (a streaming backend withholds its final part
    /// until the hash verifies).
    ///
    /// Object keys ([`BlobNamespace::Object`], [`BlobNamespace::ObjectOffsets`])
    /// refuse this form: use [`Self::commit_with_root`].
    fn commit(self) -> impl Future<Output = Result<CommitOutcome, StoreError>> + MaybeSend;

    /// Make an **object** blob visible, only if the total equals the
    /// declared length and `BLAKE3(bytes) == content_root` (the key is the
    /// object id, so it cannot be the hash of the bytes). Verification and
    /// visibility are as for [`Self::commit`]: a streaming backend withholds
    /// its final byte until the root verifies. A pack or marker key is
    /// [`StoreError::Invalid`]. A backend that cannot verify a root is
    /// [`StoreError::Unsupported`], which is the default.
    fn commit_with_root(
        self,
        _content_root: Hash,
    ) -> impl Future<Output = Result<CommitOutcome, StoreError>> + MaybeSend
    where
        Self: Sized,
    {
        async { Err(StoreError::Unsupported("root-verified commit".into())) }
    }

    /// Discard the upload; nothing becomes visible.
    fn abort(self) -> impl Future<Output = ()> + MaybeSend;
}

/// A stored part reference recovered from a server-authenticated receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartRef {
    /// Zero-based part index.
    pub index: u32,
    /// Number of part bytes.
    pub len: u64,
    /// Opaque backend tag, at most 128 bytes on the wire.
    pub tag: Vec<u8>,
}

/// A verified, staged part. `commit` makes only this part durable; the pack
/// remains invisible until [`MultipartBlobStore::complete`].
pub trait PartSink: MaybeSend {
    /// Append a non-empty chunk without exceeding the part's expected length.
    fn write(&mut self, chunk: Bytes) -> impl Future<Output = Result<(), StoreError>> + MaybeSend;

    /// Verify length and subtree CV, then return an opaque backend tag.
    /// A CV mismatch is [`StoreError::PartSubtreeMismatch`]; other invalid
    /// staged state is [`StoreError::Invalid`].
    fn commit(self) -> impl Future<Output = Result<Vec<u8>, StoreError>> + MaybeSend;

    /// Discard this attempted part.
    fn abort(self) -> impl Future<Output = ()> + MaybeSend;
}

/// A resumable blob store with opaque storage sessions and verified parts.
pub trait MultipartBlobStore: BlobStore {
    /// The upload handle returned by [`Self::begin_part`].
    type PartSink: PartSink;

    /// Maximum part count accepted by this backend.
    const MAX_PARTS: u32;

    /// Whether this backend can start a multipart upload now.
    fn supports_multipart(&self) -> bool {
        false
    }

    /// Open a new storage session for a pack.
    fn begin_multipart(
        &self,
        _key: BlobKey,
        _len: u64,
        _part_size: u64,
    ) -> impl Future<Output = Result<Vec<u8>, StoreError>> + MaybeSend {
        async { Err(StoreError::Unsupported("multipart uploads".into())) }
    }

    /// Open a session for a known ticket. Backends that do not use the
    /// ticket id as their storage session keep their existing session format.
    fn begin_multipart_for_ticket(
        &self,
        key: BlobKey,
        len: u64,
        part_size: u64,
        _ticket_id: [u8; 32],
    ) -> impl Future<Output = Result<Vec<u8>, StoreError>> + MaybeSend {
        self.begin_multipart(key, len, part_size)
    }

    /// Start one part in an existing storage session.
    fn begin_part(
        &self,
        _key: BlobKey,
        _session: &[u8],
        _plan: &PartPlan,
        _index: u32,
        _expected_cv: [u8; 32],
    ) -> impl Future<Output = Result<Self::PartSink, StoreError>> + MaybeSend {
        async { Err(StoreError::Unsupported("multipart uploads".into())) }
    }

    /// Atomically make the verified pack visible.
    fn complete(
        &self,
        _key: BlobKey,
        _session: &[u8],
        _plan: &PartPlan,
        _parts: &[PartRef],
    ) -> impl Future<Output = Result<CommitOutcome, StoreError>> + MaybeSend {
        async { Err(StoreError::Unsupported("multipart uploads".into())) }
    }

    /// Atomically make a verified **object** visible: the parts' merged BLAKE3
    /// root must equal `content_root` (the object key is an object id, not a
    /// content hash). Plain [`Self::complete`] refuses object keys, as
    /// [`PackSink::commit`] does. WP-4.10.
    fn complete_with_root(
        &self,
        _key: BlobKey,
        _session: &[u8],
        _plan: &PartPlan,
        _parts: &[PartRef],
        _content_root: Hash,
    ) -> impl Future<Output = Result<CommitOutcome, StoreError>> + MaybeSend {
        async { Err(StoreError::Unsupported("multipart uploads".into())) }
    }

    /// The most bytes one [`BlobStore::begin`] upload can carry, or `None`
    /// when unbounded. Objects longer than this are extracted in parts.
    fn single_put_limit(&self) -> Option<u64> {
        None
    }

    /// Reclaim an incomplete session. Repeated aborts succeed.
    fn abort(
        &self,
        _key: BlobKey,
        _session: &[u8],
    ) -> impl Future<Output = Result<(), StoreError>> + MaybeSend {
        async { Err(StoreError::Unsupported("multipart uploads".into())) }
    }
}

/// The sink type for backends whose multipart support arrives later.
#[derive(Debug)]
pub struct UnsupportedPartSink;

impl PartSink for UnsupportedPartSink {
    async fn write(&mut self, _chunk: Bytes) -> Result<(), StoreError> {
        Err(StoreError::Unsupported("multipart uploads".into()))
    }

    async fn commit(self) -> Result<Vec<u8>, StoreError> {
        Err(StoreError::Unsupported("multipart uploads".into()))
    }

    async fn abort(self) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_paths_are_sibling_namespaces() {
        let id = [0xab; 32];
        let hex = "ab".repeat(32);
        let keys = [
            BlobKey::pack(id),
            BlobKey::upload_marker(id),
            BlobKey::object(id),
            BlobKey::object_offsets(id),
        ];
        let plain = keys.map(|k| k.relative_path("packs").unwrap());
        assert_eq!(
            plain,
            [
                format!("packs/{hex}"),
                format!("upload-markers/v1/{hex}"),
                format!("objects/{hex}"),
                format!("object-offsets/v1/{hex}"),
            ]
        );
        let prefixed = keys.map(|k| k.relative_path("tenant/a/packs").unwrap());
        assert_eq!(
            prefixed,
            [
                format!("tenant/a/packs/{hex}"),
                format!("tenant/a/upload-markers/v1/{hex}"),
                format!("tenant/a/objects/{hex}"),
                format!("tenant/a/object-offsets/v1/{hex}"),
            ]
        );
    }

    #[test]
    fn a_pack_keyspace_cannot_alias_a_sibling_namespace() {
        let id = [7; 32];
        for reserved in [
            "objects",
            "object-offsets",
            "upload-markers",
            "tenant/a/objects",
        ] {
            assert!(matches!(
                BlobKey::pack(id).relative_path(reserved),
                Err(StoreError::Invalid(_))
            ));
        }
        assert!(BlobKey::pack(id).relative_path("packs").is_ok());
        assert!(
            BlobKey::pack(id)
                .relative_path("tenant/objects-a/packs")
                .is_ok()
        );
    }

    #[test]
    fn a_sink_verifies_object_keys_only_against_a_root() {
        let id = [1; 32];
        let root = [2; 32];
        for object in [BlobKey::object(id), BlobKey::object_offsets(id)] {
            assert_eq!(object.expected_root(Some(root)).unwrap(), root);
            assert!(matches!(
                object.expected_root(None),
                Err(StoreError::Invalid(_))
            ));
        }
        for plain in [BlobKey::pack(id), BlobKey::upload_marker(id)] {
            assert_eq!(plain.expected_root(None).unwrap(), id);
            assert!(matches!(
                plain.expected_root(Some(root)),
                Err(StoreError::Invalid(_))
            ));
        }
    }
}
