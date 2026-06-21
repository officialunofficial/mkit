//! mkit object types.
//!
//! Spec reference: `docs/SPEC-OBJECTS.md` §1–§9. Briefly:
//!
//! * Every stored object begins with the 6-byte v1 prologue
//!   `[u8 object_type][4B "MKT1"][u8 0x01]`.
//! * Hashes are 32-byte BLAKE3.
//! * Integers are little-endian. Timestamps are `u64` (widened from
//!   `u32` in the mkit-era).
//! * Tree entry names are 1..=255 bytes, forbid `\0 / \\` and the
//!   names `.` / `..`, and MUST be lex-sorted with no duplicates.
//! * Identity is a tagged union `[u8 kind][u16 LE len][payload]`;
//!   `len` is 1..=[`IDENTITY_MAX_LEN`], ed25519 MUST have `len == 32`.

use crate::hash::{Hash, ZERO};
use core::fmt;

/// Fixed 4-byte magic at offset 1 of every v1 object.
pub const MAGIC: [u8; 4] = *b"MKT1";
/// Current (and only) v1 schema version byte.
pub const SCHEMA_VERSION: u8 = 0x01;
/// Upper bound on [`Identity`] payload length. Rejected at decode time
/// as `IdentityTooLarge` for anything greater.
pub const IDENTITY_MAX_LEN: u16 = 4096;

/// Object type tag (1 byte, at offset 0 of the v1 prologue).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ObjectType {
    Blob = 0x01,
    Tree = 0x02,
    Commit = 0x03,
    Remix = 0x04,
    ChunkedBlob = 0x05,
    Delta = 0x06,
    /// Annotated / signed tag. New in v1 (issue #230). See
    /// `SPEC-OBJECTS.md` §6a and [`Tag`].
    Tag = 0x07,
}

impl ObjectType {
    /// `true` for the types content-addressed by a merkle BMT root
    /// (`Tree`, `ChunkedBlob`) rather than by `BLAKE3` of their bytes — see
    /// `crate::merkle` and [`Object::id`]. The single source of truth for
    /// the merkle-addressed set: the store's id dispatch and every write
    /// path consult this instead of re-spelling `Tree | ChunkedBlob`.
    #[must_use]
    pub fn is_merkle(self) -> bool {
        matches!(self, Self::Tree | Self::ChunkedBlob)
    }

    /// Spec-defined short name, usable in logs / CLI output.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Blob => "blob",
            Self::Tree => "tree",
            Self::Commit => "commit",
            Self::Remix => "remix",
            Self::ChunkedBlob => "chunked_blob",
            Self::Delta => "delta",
            Self::Tag => "tag",
        }
    }

    /// Decode the single-byte tag. Rejects reserved/future values.
    pub(crate) fn from_u8(b: u8) -> Result<Self, MkitError> {
        Ok(match b {
            0x01 => Self::Blob,
            0x02 => Self::Tree,
            0x03 => Self::Commit,
            0x04 => Self::Remix,
            0x05 => Self::ChunkedBlob,
            0x06 => Self::Delta,
            0x07 => Self::Tag,
            other => return Err(MkitError::InvalidObjectType(other)),
        })
    }
}

/// Tree entry mode (1 byte).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum EntryMode {
    Blob = 0x01,
    Tree = 0x02,
    Symlink = 0x03,
    /// Regular file with the POSIX executable bit set (0o755). New in
    /// v1 — the mkit-era silently lost this bit at commit time.
    Executable = 0x04,
}

impl EntryMode {
    pub(crate) fn from_u8(b: u8) -> Result<Self, MkitError> {
        Ok(match b {
            0x01 => Self::Blob,
            0x02 => Self::Tree,
            0x03 => Self::Symlink,
            0x04 => Self::Executable,
            other => return Err(MkitError::InvalidEntryMode(other)),
        })
    }
}

/// Tagged-union author identity. See `SPEC-OBJECTS.md` §9.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum IdentityKind {
    /// 32-byte raw Ed25519 public key.
    Ed25519 = 0x01,
    /// `did:key:` multibase-encoded key material (the `did:key:` scheme
    /// prefix is stripped — the payload is a multibase string, typically
    /// base58btc starting with `'z'`). Validated as non-empty printable
    /// ASCII so binary garbage can't masquerade as a DID (see
    /// [`Identity::is_valid`]).
    DidKey = 0x02,
    /// Arbitrary producer-defined bytes.
    Opaque = 0x03,
}

impl IdentityKind {
    pub(crate) fn from_u8(b: u8) -> Result<Self, MkitError> {
        Ok(match b {
            0x01 => Self::Ed25519,
            0x02 => Self::DidKey,
            0x03 => Self::Opaque,
            other => return Err(MkitError::UnknownIdentityKind(other)),
        })
    }
}

/// Tagged-union identity. Owned bytes, cheap to clone — payload is at
/// most [`IDENTITY_MAX_LEN`] = 4 KiB.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Identity {
    pub kind: IdentityKind,
    pub bytes: Vec<u8>,
}

impl Identity {
    /// Convenience constructor: Ed25519 from a fixed 32-byte pubkey.
    #[must_use]
    pub fn ed25519(pubkey: [u8; 32]) -> Self {
        Self {
            kind: IdentityKind::Ed25519,
            bytes: pubkey.to_vec(),
        }
    }

    /// Convenience constructor: opaque producer-defined bytes.
    #[must_use]
    pub fn opaque(bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            kind: IdentityKind::Opaque,
            bytes: bytes.into(),
        }
    }

    /// Structural validity check: payload len in `1..=IDENTITY_MAX_LEN`;
    /// Ed25519 is exactly 32 bytes; a `DidKey` payload must be a multibase
    /// string, i.e. all printable ASCII (no NUL/control/whitespace/high
    /// bytes) — so a binary blob can't be smuggled in under the DID kind.
    /// `Opaque` is producer-defined and accepts any non-empty bytes.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        if self.bytes.is_empty() || self.bytes.len() > IDENTITY_MAX_LEN as usize {
            return false;
        }
        match self.kind {
            IdentityKind::Ed25519 => self.bytes.len() == 32,
            // A multibase string is always printable ASCII; this rejects
            // garbage without committing to one multibase alphabet (the
            // payload may be base58btc `z…`, base64 `m…`, etc.).
            IdentityKind::DidKey => self.bytes.iter().all(u8::is_ascii_graphic),
            IdentityKind::Opaque => true,
        }
    }
}

/// A single entry in a [`Tree`] object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeEntry {
    /// Entry name. 1..=255 bytes, no `\0 / \\`, not `.` / `..`.
    pub name: Vec<u8>,
    pub mode: EntryMode,
    pub object_hash: Hash,
}

impl TreeEntry {
    /// Validate an entry name per §4.1.
    ///
    /// In addition to the base spec (no `\0 / \\`, not `.` / `..`, 1..=255
    /// bytes), this rejects names that alias repo metadata or exploit
    /// platform quirks:
    ///
    /// - `.mkit` / `.git` case-insensitively (Git CVE-2021-21300 family).
    /// - Trailing `.` or space, which Windows strips, causing aliasing.
    /// - Reserved Windows device names (`CON`, `PRN`, `AUX`, `NUL`,
    ///   `COM1`-`COM9`, `LPT1`-`LPT9`), with or without an extension,
    ///   case-insensitively.
    ///
    /// ASCII case-folding is sufficient because all other byte-level
    /// rules above are ASCII-only; names with non-ASCII bytes bypass
    /// these extra checks but remain constrained by the base rules.
    #[must_use]
    pub fn validate_name(name: &[u8]) -> bool {
        if name.is_empty() || name.len() > 255 {
            return false;
        }
        if name == b"." || name == b".." {
            return false;
        }
        if name.iter().any(|&b| matches!(b, 0 | b'/' | b'\\')) {
            return false;
        }
        // Trailing `.` or space — Windows strips these, causing aliasing
        // with another entry of the same bare name.
        if matches!(name.last(), Some(b'.' | b' ')) {
            return false;
        }
        // Case-insensitive `.mkit` / `.git`.
        if name.eq_ignore_ascii_case(b".mkit") || name.eq_ignore_ascii_case(b".git") {
            return false;
        }
        // Reserved Windows device names — the stem (before the first `.`)
        // is compared case-insensitively.
        let stem = match name.iter().position(|&b| b == b'.') {
            Some(i) => &name[..i],
            None => name,
        };
        if is_windows_reserved_stem(stem) {
            return false;
        }
        true
    }
}

/// Returns `true` when `stem` (ASCII bytes, case-insensitive) matches a
/// reserved Windows device name. The caller has already split on the
/// first `.` so an extension is ignored.
fn is_windows_reserved_stem(stem: &[u8]) -> bool {
    match stem.len() {
        3 => {
            stem.eq_ignore_ascii_case(b"CON")
                || stem.eq_ignore_ascii_case(b"PRN")
                || stem.eq_ignore_ascii_case(b"AUX")
                || stem.eq_ignore_ascii_case(b"NUL")
        }
        4 => {
            // COM1-COM9 / LPT1-LPT9 only. 0 is not reserved.
            let head = &stem[..3];
            let tail = stem[3];
            let is_digit_1_9 = matches!(tail, b'1'..=b'9');
            is_digit_1_9 && (head.eq_ignore_ascii_case(b"COM") || head.eq_ignore_ascii_case(b"LPT"))
        }
        _ => false,
    }
}

/// Remix source provenance. `upstream_id` is opaque 32-byte caller-
/// chosen content (e.g. `BLAKE3(repo_url)`); core never interprets it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RemixSource {
    pub upstream_id: Hash,
    pub commit_hash: Hash,
}

/// Blob: raw bytes, no interpretation. Max 1 GiB at the storage layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blob {
    pub data: Vec<u8>,
}

/// Tree: lex-sorted list of entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tree {
    pub entries: Vec<TreeEntry>,
}

impl Tree {
    /// Returns `true` when entries are strictly ascending by byte-wise
    /// name order (no duplicates).
    #[must_use]
    pub fn is_sorted(&self) -> bool {
        self.entries
            .windows(2)
            .all(|w| w[0].name.as_slice() < w[1].name.as_slice())
    }
}

/// Commit object. See `SPEC-OBJECTS.md` §5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commit {
    pub tree_hash: Hash,
    pub parents: Vec<Hash>,
    pub author: Identity,
    pub signer: [u8; 32],
    pub message: Vec<u8>,
    pub timestamp: u64,
    /// Optional off-chain annotation. Zero = absent. NOT part of the
    /// signing bytes — see SPEC-SIGNING §3.
    pub message_hash: Hash,
    /// Optional off-chain annotation. Zero = absent. NOT part of the
    /// signing bytes.
    pub content_digest: Hash,
    pub signature: [u8; 64],
}

impl Commit {
    /// Commit with both annotation slots zeroed out.
    #[must_use]
    pub fn new_unannotated(
        tree_hash: Hash,
        parents: Vec<Hash>,
        author: Identity,
        signer: [u8; 32],
        message: Vec<u8>,
        timestamp: u64,
        signature: [u8; 64],
    ) -> Self {
        Self {
            tree_hash,
            parents,
            author,
            signer,
            message,
            timestamp,
            message_hash: ZERO,
            content_digest: ZERO,
            signature,
        }
    }
}

/// Remix object. See `SPEC-OBJECTS.md` §6.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Remix {
    pub tree_hash: Hash,
    pub parents: Vec<Hash>,
    pub sources: Vec<RemixSource>,
    pub author: Identity,
    pub signer: [u8; 32],
    pub message: Vec<u8>,
    pub timestamp: u64,
    pub signature: [u8; 64],
}

impl Remix {
    /// Returns `true` when sources are sorted by `(upstream_id, commit_hash)`
    /// with no duplicate `(upstream_id, commit_hash)` pairs.
    #[must_use]
    pub fn sources_sorted(&self) -> bool {
        self.sources.windows(2).all(|w| {
            let a = &w[0];
            let b = &w[1];
            match a.upstream_id.cmp(&b.upstream_id) {
                core::cmp::Ordering::Less => true,
                core::cmp::Ordering::Greater => false,
                core::cmp::Ordering::Equal => a.commit_hash < b.commit_hash,
            }
        })
    }
}

/// Annotated / signed tag object. See `SPEC-OBJECTS.md` §6a and
/// `SPEC-SIGNING.md` §4a.
///
/// A tag binds a human-readable `name` to a `target` object (commit /
/// remix / tree / blob), records the `tagger` identity, a free-form
/// `message`, and a `timestamp`, and carries an Ed25519 `signature`
/// over the canonical signing bytes (see [`crate::sign::tag_signing_bytes`]).
///
/// The `target_type` byte records what kind of object `target` names
/// so a verifier need not fetch the target to display the tag. It is a
/// [`ObjectType`] tag and MUST be one of the storable types (not
/// `Delta`, which is pack-only).
///
/// `name` is 1..=[`TAG_NAME_MAX_LEN`] bytes. It is the short ref name
/// (e.g. `v1.0.0`), not a full `refs/tags/...` path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tag {
    pub target: Hash,
    pub target_type: ObjectType,
    pub name: Vec<u8>,
    pub tagger: Identity,
    pub signer: [u8; 32],
    pub message: Vec<u8>,
    pub timestamp: u64,
    pub signature: [u8; 64],
}

/// Upper bound on a [`Tag`] `name` payload. Rejected at decode time as
/// [`MkitError::TagNameInvalid`] for anything outside `1..=TAG_NAME_MAX_LEN`.
pub const TAG_NAME_MAX_LEN: u16 = 4096;

impl Tag {
    /// Structural validity of the `name`: non-empty, within the length
    /// bound, and free of the same forbidden bytes a ref name forbids
    /// (`\0`, `/`, `\\`). The full ref-name grammar is enforced by
    /// `refs::validate_ref_name` at write time; this is the
    /// object-layer floor that the serializer guards.
    #[must_use]
    pub fn name_is_valid(&self) -> bool {
        if self.name.is_empty() || self.name.len() > TAG_NAME_MAX_LEN as usize {
            return false;
        }
        !self.name.iter().any(|&b| matches!(b, 0 | b'/' | b'\\'))
    }
}

/// Chunked-blob manifest. See `SPEC-OBJECTS.md` §7.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkedBlob {
    pub total_size: u64,
    /// `0` = content-defined chunking (`FastCDC`), otherwise fixed-size.
    pub chunk_size: u32,
    pub chunks: Vec<Hash>,
}

/// Delta object (pack-only). See `SPEC-OBJECTS.md` §8.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delta {
    pub base_hash: Hash,
    pub result_size: u32,
    pub instructions: Vec<u8>,
}

/// Unified object union.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Object {
    Blob(Blob),
    Tree(Tree),
    Commit(Commit),
    Remix(Remix),
    ChunkedBlob(ChunkedBlob),
    Delta(Delta),
    Tag(Tag),
}

impl Object {
    /// Return this object's type tag.
    #[must_use]
    pub fn object_type(&self) -> ObjectType {
        match self {
            Self::Blob(_) => ObjectType::Blob,
            Self::Tree(_) => ObjectType::Tree,
            Self::Commit(_) => ObjectType::Commit,
            Self::Remix(_) => ObjectType::Remix,
            Self::ChunkedBlob(_) => ObjectType::ChunkedBlob,
            Self::Delta(_) => ObjectType::Delta,
            Self::Tag(_) => ObjectType::Tag,
        }
    }

    /// This object's content-address (storage id).
    ///
    /// Merkelized types are addressed by their Binary Merkle Tree root
    /// (`crate::merkle`): a `Tree` by [`crate::merkle::compute_tree_id`] and
    /// a `ChunkedBlob` by [`crate::merkle::compute_chunked_id`]. Every other
    /// type is addressed by `BLAKE3` of its canonical serialized bytes — the
    /// historical scheme. This is the single dispatch point the store, pack
    /// reader, and worktree all route through, so the two addressing schemes
    /// can never diverge across call sites.
    ///
    /// # Errors
    ///
    /// Propagates [`MkitError`] from serializing a non-merkelized object
    /// (merkelized ids are computed directly from the in-memory struct and
    /// never serialize, so they cannot fail).
    pub fn id(&self) -> Result<Hash, MkitError> {
        Ok(match self {
            Self::Tree(t) => crate::merkle::compute_tree_id(t),
            Self::ChunkedBlob(cb) => crate::merkle::compute_chunked_id(cb),
            other => crate::hash::hash(&crate::serialize::serialize(other)?),
        })
    }
}

/// Content id of an **already-decoded** object whose canonical encoding is
/// `bytes`. A merkelized type ([`Tree`] / [`ChunkedBlob`], per
/// [`ObjectType::is_merkle`]) is addressed by its BMT root, computed from the
/// decoded struct; every other type is `BLAKE3` of `bytes`, reusing the
/// caller's buffer (no re-serialize — `bytes` may be up to ~1 GiB).
///
/// This is the single content-addressing dispatch. Callers that already hold
/// a decoded object and its canonical bytes (the pack reader, the `mkit-wasm`
/// encoder) use it directly; the bytes-only twins `object_id_from_bytes` /
/// `object_id_from_parts` decode just the merkle types and delegate here,
/// so every path — native store and wasm alike — keys an object identically.
#[must_use]
pub fn id_from_object(obj: &Object, bytes: &[u8]) -> Hash {
    match obj {
        Object::Tree(t) => crate::merkle::compute_tree_id(t),
        Object::ChunkedBlob(cb) => crate::merkle::compute_chunked_id(cb),
        _ => crate::hash::hash(bytes),
    }
}

/// [`id_from_object`] for an object supplied only as its canonical **bytes**.
/// Used by the store and batch writer, whose input is bytes they are about to
/// persist (write) or have already persisted (read-verify).
///
/// Only the merkelized types are decoded — to find their BMT root; every
/// other type (incl. up-to-~1 GiB blobs) is hashed straight from `bytes`
/// without a decode. A merkle-typed buffer that fails to decode is byte-hashed
/// like any other: real writers never emit one, and on read-verify the
/// resulting id mismatch surfaces as `HashMismatch` rather than being masked.
#[must_use]
pub(crate) fn object_id_from_bytes(bytes: &[u8]) -> Hash {
    let is_merkle = bytes
        .first()
        .and_then(|b| ObjectType::from_u8(*b).ok())
        .is_some_and(ObjectType::is_merkle);
    if is_merkle && let Ok(obj) = crate::serialize::deserialize(bytes) {
        return id_from_object(&obj, bytes);
    }
    crate::hash::hash(bytes)
}

/// [`object_id_from_bytes`] for an object supplied as `parts` whose
/// concatenation is the canonical bytes — the shape every part-wise sink
/// (`EphemeralSink`, `WriteBatch`) receives.
///
/// A merkelized type needs its contiguous bytes to decode the BMT root, so
/// it is buffered once and dispatched. A byte-hashed type (a `Blob`/chunk —
/// the bulk of all bytes, up to ~1 GiB) is hashed **streaming**, never
/// materialising the concatenation. This keeps the "buffer or stream"
/// decision in one place instead of in every sink.
#[must_use]
pub(crate) fn object_id_from_parts(parts: &[&[u8]]) -> Hash {
    let merkle = parts
        .first()
        .and_then(|p| p.first())
        .and_then(|b| ObjectType::from_u8(*b).ok())
        .is_some_and(ObjectType::is_merkle);
    if merkle {
        return object_id_from_bytes(&parts.concat());
    }
    let mut hasher = crate::hash::Hasher::new();
    for p in parts {
        hasher.update(p);
    }
    hasher.finalize()
}

/// All decode / validation errors raised by the serialize module, plus
/// a small number of construction-time errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MkitError {
    #[error("input is shorter than the 6-byte v1 prologue")]
    EmptyData,
    #[error("object_type byte {0:#04x} is not in 0x01..=0x07")]
    InvalidObjectType(u8),
    #[error("magic at offset 1 is not \"MKT1\"")]
    InvalidMagic,
    #[error("schema_version byte is not 0x01")]
    UnsupportedObjectVersion,
    #[error("input ended before a complete field could be read")]
    UnexpectedEof,
    #[error("non-empty trailing bytes after a complete object")]
    TrailingData,
    #[error("tree.entry_count > 1_000_000")]
    TooManyEntries,
    #[error("tree entry name is empty, too long, or contains a forbidden byte")]
    InvalidEntryName,
    #[error("tree entry mode byte {0:#04x} is not one of 0x01..=0x04")]
    InvalidEntryMode(u8),
    #[error("tree entries are not lexicographically sorted / contain duplicates")]
    InvalidEntryOrder,
    #[error("parent_count > 1_000")]
    TooManyParents,
    #[error("remix.source_count > 10_000")]
    TooManySources,
    #[error("tag name is empty, too long, or contains a forbidden byte (\\0 / \\)")]
    TagNameInvalid,
    #[error("tag target_type byte {0:#04x} is not a storable object type")]
    TagTargetTypeInvalid(u8),
    #[error("remix sources are not sorted by (upstream_id, commit_hash)")]
    InvalidSourceOrder,
    #[error("chunked_blob.chunk_count > 1_000_000")]
    TooManyChunks,
    #[error("identity kind byte {0:#04x} is not 0x01..=0x03")]
    UnknownIdentityKind(u8),
    #[error("identity has zero-length payload, or is Ed25519 with len != 32")]
    InvalidIdentity,
    #[error("identity payload len > {}", IDENTITY_MAX_LEN)]
    IdentityTooLarge,
    /// A length-prefixed field exceeded the wire-format `u32` cap. Only
    /// raised by serialise; deserialise can never observe a value larger
    /// than `u32::MAX` because it reads the prefix first.
    #[error("oversized payload in field `{field}`: {len} bytes > u32::MAX")]
    OversizePayload { field: &'static str, len: usize },
    // ---- sign / key-management errors (Phase 6) ----
    /// Underlying secure-randomness source could not produce bytes.
    #[error("rng failed to produce key material")]
    RngFailure,
    /// Signature verification failed (bad signature, wrong key, tampered
    /// input, or wrong domain). The Ed25519 layer never tells us *why*.
    #[error("signature verification failed")]
    SignatureInvalid,
    /// Public-key bytes do not decode to a valid Edwards point.
    #[error("public key is not a valid Ed25519 point")]
    InvalidPublicKey,
    /// Key file on disk has a permission bit set that allows non-owner
    /// access (POSIX `mode & 0o077 != 0`). Refuses to load.
    #[error("key file mode {actual:#o} is broader than 0600")]
    InsecureKeyPermissions { actual: u32 },
    /// Key file is owned by a different uid than the calling process.
    /// Could mean a planted file from a tar extraction or a malicious
    /// bind mount. Refuse with the observed uid for diagnostics.
    #[error("key file owner uid {actual} does not match process euid {euid}")]
    InsecureKeyOwner { actual: u32, euid: u32 },
    /// Parent directory of the key file is group/world-accessible.
    /// `.mkit/keys/` MUST be 0700 to keep `inotify`-style swap attacks
    /// out of reach.
    #[error("key directory mode {actual:#o} is broader than 0700")]
    InsecureKeyDir { actual: u32 },
    /// Key path resolves through a symlink. We refuse symlinks at the
    /// open(2) layer (`O_NOFOLLOW`) — this variant fires when the
    /// kernel returns ELOOP. An attacker who can pre-create the path
    /// as a symlink could otherwise redirect us to a key they control.
    #[error("key path {0} is a symlink — refused")]
    KeyPathIsSymlink(String),
    /// Key file length is not exactly 32 bytes.
    #[error("key file size {actual} is not 32 bytes (raw Ed25519 seed)")]
    InvalidKeyLength { actual: usize },
    /// Wrapped I/O error from key load/save. Boxed to keep `MkitError`
    /// variant size small.
    #[error("key file I/O error: {0}")]
    KeyIo(String),
    /// Delta encode input exceeds the v1 wire-format `u32` length cap
    /// (base or result > 4 GiB - 1). SPEC-PACKFILE holds individual
    /// payloads under this bound, so this is a caller-programming
    /// error, not a normal runtime condition — but saturating instead
    /// of erroring silently produced a stream `decode()` would reject
    /// with a misleading "length mismatch".
    #[error("delta length {len} exceeds u32::MAX for field `{field}`")]
    DeltaLengthOverflow { field: &'static str, len: usize },
}

impl fmt::Display for Object {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Object::{}", self.object_type().name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_type_names() {
        assert_eq!(ObjectType::Blob.name(), "blob");
        assert_eq!(ObjectType::Tree.name(), "tree");
        assert_eq!(ObjectType::Commit.name(), "commit");
        assert_eq!(ObjectType::Remix.name(), "remix");
        assert_eq!(ObjectType::ChunkedBlob.name(), "chunked_blob");
        assert_eq!(ObjectType::Delta.name(), "delta");
        assert_eq!(ObjectType::Tag.name(), "tag");
    }

    #[test]
    fn object_type_from_u8_accepts_valid_range() {
        for b in 0x01u8..=0x07 {
            assert!(
                ObjectType::from_u8(b).is_ok(),
                "byte {b:#04x} should decode"
            );
        }
    }

    #[test]
    fn object_type_from_u8_rejects_zero_and_high() {
        assert!(matches!(
            ObjectType::from_u8(0x00),
            Err(MkitError::InvalidObjectType(0))
        ));
        assert!(matches!(
            ObjectType::from_u8(0xFF),
            Err(MkitError::InvalidObjectType(0xFF))
        ));
        assert!(matches!(
            ObjectType::from_u8(0x08),
            Err(MkitError::InvalidObjectType(0x08))
        ));
    }

    #[test]
    fn tag_name_validity() {
        let t = |name: &[u8]| Tag {
            target: ZERO,
            target_type: ObjectType::Commit,
            name: name.to_vec(),
            tagger: Identity::ed25519([0xaa; 32]),
            signer: [0; 32],
            message: vec![],
            timestamp: 0,
            signature: [0; 64],
        };
        assert!(t(b"v1.0.0").name_is_valid());
        assert!(!t(b"").name_is_valid());
        assert!(!t(b"a/b").name_is_valid());
        assert!(!t(b"a\\b").name_is_valid());
        assert!(!t(b"a\0b").name_is_valid());
        assert!(!t(&vec![b'a'; TAG_NAME_MAX_LEN as usize + 1]).name_is_valid());
    }

    #[test]
    fn tree_entry_name_rejects_empty() {
        assert!(!TreeEntry::validate_name(b""));
    }

    #[test]
    fn tree_entry_name_rejects_separators_and_null() {
        assert!(!TreeEntry::validate_name(b"foo/bar"));
        assert!(!TreeEntry::validate_name(b"foo\\bar"));
        assert!(!TreeEntry::validate_name(b"fo\0o"));
    }

    #[test]
    fn tree_entry_name_rejects_dot_and_dotdot() {
        assert!(!TreeEntry::validate_name(b"."));
        assert!(!TreeEntry::validate_name(b".."));
    }

    #[test]
    fn tree_entry_name_accepts_common() {
        assert!(TreeEntry::validate_name(b"file.txt"));
        assert!(TreeEntry::validate_name(b"a"));
        assert!(TreeEntry::validate_name(b"foo-bar_baz.rs"));
    }

    #[test]
    fn tree_entry_name_rejects_over_255() {
        let long = vec![b'a'; 256];
        assert!(!TreeEntry::validate_name(&long));
    }

    #[test]
    fn tree_entry_name_rejects_dot_mkit_and_dot_git_case_insensitive() {
        // Exact-case basics
        assert!(!TreeEntry::validate_name(b".mkit"));
        assert!(!TreeEntry::validate_name(b".git"));
        // Mixed/upper case — must also be rejected on case-insensitive FS.
        assert!(!TreeEntry::validate_name(b".MKIT"));
        assert!(!TreeEntry::validate_name(b".Mkit"));
        assert!(!TreeEntry::validate_name(b".GIT"));
        assert!(!TreeEntry::validate_name(b".Git"));
        // Unrelated names starting with `.m` or `.g` are fine.
        assert!(TreeEntry::validate_name(b".mkitignore"));
        assert!(TreeEntry::validate_name(b".gitignore"));
    }

    #[test]
    fn tree_entry_name_rejects_trailing_dot_or_space() {
        // Windows strips trailing `.` and ` `, causing aliasing with
        // another entry of the same bare name.
        assert!(!TreeEntry::validate_name(b"foo."));
        assert!(!TreeEntry::validate_name(b"foo "));
        assert!(!TreeEntry::validate_name(b"foo..."));
        assert!(!TreeEntry::validate_name(b"foo   "));
        // Trailing dot/space only at end — interior dots and spaces are OK.
        assert!(TreeEntry::validate_name(b"foo.bar"));
        assert!(TreeEntry::validate_name(b"foo bar"));
    }

    #[test]
    fn tree_entry_name_rejects_windows_reserved_device_names() {
        for n in [
            b"CON".as_slice(),
            b"PRN",
            b"AUX",
            b"NUL",
            b"COM1",
            b"COM9",
            b"LPT1",
            b"LPT9",
            // case-insensitive
            b"con",
            b"Nul",
            b"lpt3",
            // with extension
            b"CON.txt",
            b"nul.log",
            b"COM1.dat",
        ] {
            assert!(
                !TreeEntry::validate_name(n),
                "expected Windows reserved name rejected: {:?}",
                std::str::from_utf8(n).unwrap_or("?")
            );
        }
        // Non-reserved lookalikes must still be accepted.
        assert!(TreeEntry::validate_name(b"COM0"));
        assert!(TreeEntry::validate_name(b"LPT0"));
        assert!(TreeEntry::validate_name(b"COM10"));
        assert!(TreeEntry::validate_name(b"CONSOLE"));
        assert!(TreeEntry::validate_name(b"NULL"));
    }

    #[test]
    fn identity_rejects_empty_payload_all_kinds() {
        for kind in [
            IdentityKind::Ed25519,
            IdentityKind::DidKey,
            IdentityKind::Opaque,
        ] {
            assert!(
                !Identity {
                    kind,
                    bytes: Vec::new()
                }
                .is_valid()
            );
        }
    }

    #[test]
    fn identity_rejects_oversize() {
        let bytes = vec![0xaa; IDENTITY_MAX_LEN as usize + 1];
        assert!(
            !Identity {
                kind: IdentityKind::Opaque,
                bytes
            }
            .is_valid()
        );
    }

    #[test]
    fn identity_requires_32_bytes_for_ed25519() {
        assert!(
            !Identity {
                kind: IdentityKind::Ed25519,
                bytes: vec![0xaa; 16]
            }
            .is_valid()
        );
        assert!(Identity::ed25519([0xaa; 32]).is_valid());
    }

    #[test]
    fn didkey_requires_printable_ascii_multibase() {
        let didkey = |b: &[u8]| Identity {
            kind: IdentityKind::DidKey,
            bytes: b.to_vec(),
        };
        // A real did:key multibase payload (base58btc, scheme stripped).
        assert!(didkey(b"z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK").is_valid());
        // Other multibase prefixes are graphic ASCII too — accepted.
        assert!(didkey(b"mEiB1234").is_valid());
        // Binary garbage masquerading as a DID is rejected.
        assert!(!didkey(b"z\0\x01\x02").is_valid());
        assert!(!didkey(&[0xde, 0xad, 0xbe, 0xef]).is_valid());
        // Whitespace / control chars are not valid multibase.
        assert!(!didkey(b"z6Mk has space").is_valid());
        assert!(!didkey(b"z6Mk\n").is_valid());
    }

    #[test]
    fn tree_is_sorted_checks() {
        let e = |n: &[u8]| TreeEntry {
            name: n.to_vec(),
            mode: EntryMode::Blob,
            object_hash: ZERO,
        };
        let sorted = Tree {
            entries: vec![e(b"alpha"), e(b"beta"), e(b"gamma")],
        };
        assert!(sorted.is_sorted());
        let unsorted = Tree {
            entries: vec![e(b"beta"), e(b"alpha")],
        };
        assert!(!unsorted.is_sorted());
        let dup = Tree {
            entries: vec![e(b"alpha"), e(b"alpha")],
        };
        assert!(!dup.is_sorted());
    }

    #[test]
    fn remix_sources_sorted_checks() {
        let src = |u: u8, c: u8| RemixSource {
            upstream_id: [u; 32],
            commit_hash: [c; 32],
        };
        let r = |sources| Remix {
            tree_hash: ZERO,
            parents: vec![],
            sources,
            author: Identity::ed25519([0xaa; 32]),
            signer: [0; 32],
            message: vec![],
            timestamp: 0,
            signature: [0; 64],
        };
        assert!(r(vec![src(1, 1), src(1, 2), src(2, 1)]).sources_sorted());
        assert!(!r(vec![src(2, 1), src(1, 1)]).sources_sorted());
        assert!(!r(vec![src(1, 1), src(1, 1)]).sources_sorted());
    }
}
