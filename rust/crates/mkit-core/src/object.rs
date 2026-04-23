//! mkit object types — port of `src/object.zig`.
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
}

impl ObjectType {
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
    /// `did:key:` multibase-encoded key material (the scheme prefix is
    /// stripped — payload typically starts with `'z'`).
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

    /// Structural validity check: payload len in `1..=IDENTITY_MAX_LEN`,
    /// and for Ed25519 exactly 32 bytes.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        if self.bytes.is_empty() || self.bytes.len() > IDENTITY_MAX_LEN as usize {
            return false;
        }
        match self.kind {
            IdentityKind::Ed25519 => self.bytes.len() == 32,
            IdentityKind::DidKey | IdentityKind::Opaque => true,
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
    #[must_use]
    pub fn validate_name(name: &[u8]) -> bool {
        if name.is_empty() || name.len() > 255 {
            return false;
        }
        if name == b"." || name == b".." {
            return false;
        }
        !name.iter().any(|&b| matches!(b, 0 | b'/' | b'\\'))
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
        }
    }
}

/// All decode / validation errors raised by the serialize module, plus
/// a small number of construction-time errors. Mirrors the Zig error
/// set 1:1 so cross-implementation test vectors can pin specific kinds.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MkitError {
    #[error("input is shorter than the 6-byte v1 prologue")]
    EmptyData,
    #[error("object_type byte {0:#04x} is not in 0x01..=0x06")]
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
    }

    #[test]
    fn object_type_from_u8_accepts_valid_range() {
        for b in 0x01u8..=0x06 {
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
            ObjectType::from_u8(0x07),
            Err(MkitError::InvalidObjectType(0x07))
        ));
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
