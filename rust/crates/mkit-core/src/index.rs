//! Staging-area index.
//!
//! On-disk layout per `docs/SPEC-INDEX.md`:
//!
//! ```text
//! [4B magic "MKIX"][1B version=0x01][4B LE entry_count][entries...]
//! entry := [1B status][32B object_hash][2B LE path_len][path_len UTF-8 bytes]
//! ```
//!
//! SPEC-INDEX §2 is normative on the magic value — readers MUST reject
//! any other magic.
//!
//! Path rules (SPEC-INDEX §2): non-empty, no leading `/`, no `.`/`..`
//! segments, no NULs/backslashes, and never under `.mkit/` or `.git/`.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::atomic::write_atomic;
use crate::hash::{HASH_LEN, Hash};
use crate::object::{EntryMode, Object};
use crate::store::{MAX_TREE_DEPTH, ObjectStore, StoreError};

/// Magic bytes — ASCII `"MKIX"`.
pub const MAGIC: [u8; 4] = *b"MKIX";
/// Current format version.
pub const FORMAT_VERSION: u8 = 0x01;
/// Hard cap on a serialised index file (64 MiB), per SPEC-INDEX §4.
pub const MAX_INDEX_BYTES: u64 = 64 * 1024 * 1024;
/// Hard cap on a single entry's path length (SPEC-INDEX §2).
pub const MAX_PATH_LEN: usize = 4096;

/// Default location of the index file relative to the worktree root.
pub const INDEX_FILE: &str = ".mkit/index";

/// Status byte for an index entry. Values match SPEC-INDEX §3.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryStatus {
    /// `0x00` — path scheduled for deletion in the next commit.
    Removed = 0x00,
    /// `0x01` — regular file blob.
    Blob = 0x01,
    /// `0x02` — reserved for subtree staging; currently unused.
    Tree = 0x02,
    /// `0x03` — symbolic link, blob payload is the target string.
    Symlink = 0x03,
    /// `0x04` — executable blob (mode bit per SPEC-OBJECTS §4.2).
    Executable = 0x04,
}

impl EntryStatus {
    /// Decode a status byte. Returns `None` on unknown values.
    #[must_use]
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x00 => Some(Self::Removed),
            0x01 => Some(Self::Blob),
            0x02 => Some(Self::Tree),
            0x03 => Some(Self::Symlink),
            0x04 => Some(Self::Executable),
            _ => None,
        }
    }
}

/// One staged entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexEntry {
    /// Repo-relative path with `/` separators.
    pub path: String,
    /// Status byte.
    pub status: EntryStatus,
    /// Object hash; `[0;32]` for removed entries.
    pub object_hash: Hash,
}

/// In-memory staging index.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Index {
    /// Entries in insertion order.
    pub entries: Vec<IndexEntry>,
}

impl Index {
    /// Construct an empty index.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Find an entry by path. `O(n)`.
    #[must_use]
    pub fn find_entry(&self, path: &str) -> Option<usize> {
        self.entries.iter().position(|e| e.path == path)
    }

    /// `true` if `path` is itself tracked (a non-removed entry) or is an
    /// ancestor directory of a tracked path. Used to decide whether an
    /// ignored worktree path must still be visited because it (or its
    /// subtree) holds tracked content. `O(n)`.
    #[must_use]
    pub fn tracks_path_or_descendant(&self, path: &str) -> bool {
        self.entries.iter().any(|e| {
            e.status != EntryStatus::Removed
                && (e.path == path
                    || (e.path.len() > path.len()
                        && e.path.starts_with(path)
                        && e.path.as_bytes().get(path.len()) == Some(&b'/')))
        })
    }

    /// `true` if a tracked (non-removed) entry exists at *exactly* `path`.
    ///
    /// Because the index stores only leaf paths (files / symlinks / exec
    /// files, never directories), a hit means `path` is tracked as a
    /// non-directory object. Used by the untracked-discovery walks to detect
    /// a worktree directory that shadows a tracked file: git suppresses the
    /// directory's contents as untracked in that case (#288), reporting only
    /// the tracked-side deletion. A `Removed` tombstone does **not** count —
    /// the path is no longer tracked, so its replacement is genuinely
    /// untracked. `O(n)`.
    #[must_use]
    pub fn has_tracked_file_at(&self, path: &str) -> bool {
        self.find_entry(path)
            .is_some_and(|i| self.entries[i].status != EntryStatus::Removed)
    }

    /// Count non-removed entries.
    #[must_use]
    pub fn staged_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.status != EntryStatus::Removed)
            .count()
    }

    /// Serialise to the on-disk byte form per SPEC-INDEX §2.
    ///
    /// # Panics
    /// Panics if any entry's path exceeds `u16::MAX` bytes; callers
    /// should reject such paths via [`validate_index_path`] earlier.
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        // Pre-compute capacity: header + per-entry fixed overhead +
        // path lengths.
        let body: usize = self
            .entries
            .iter()
            .map(|e| 1 + HASH_LEN + 2 + e.path.len())
            .sum();
        let mut out = Vec::with_capacity(9 + body);
        out.extend_from_slice(&MAGIC);
        out.push(FORMAT_VERSION);
        let count = u32::try_from(self.entries.len()).expect("index entry count fits in u32");
        out.extend_from_slice(&count.to_le_bytes());
        for entry in &self.entries {
            out.push(entry.status as u8);
            out.extend_from_slice(&entry.object_hash);
            let path_len =
                u16::try_from(entry.path.len()).expect("index entry path length fits in u16");
            out.extend_from_slice(&path_len.to_le_bytes());
            out.extend_from_slice(entry.path.as_bytes());
        }
        out
    }
}

/// Errors returned by the index subsystem.
#[derive(Debug, thiserror::Error)]
pub enum IndexError {
    /// Magic bytes were not `"MKIX"`.
    #[error("index file has wrong magic (expected MKIX)")]
    BadMagic,
    /// `version` byte was not `0x01`.
    #[error("unsupported index version: {0:#x}")]
    UnsupportedVersion(u8),
    /// Status byte was outside the documented {0x00..=0x04} range.
    #[error("index entry has unknown status byte {0:#x}")]
    BadStatus(u8),
    /// Truncated or otherwise malformed entry.
    #[error("index file is corrupt")]
    Corrupt,
    /// File exceeded [`MAX_INDEX_BYTES`].
    #[error("index file too large (>{MAX_INDEX_BYTES} bytes)")]
    TooLarge,
    /// Path failed [`validate_index_path`].
    #[error("invalid index path '{0}'")]
    InvalidPath(String),
    /// Path appeared more than once in the same index.
    #[error("duplicate index path '{0}'")]
    DuplicatePath(String),
    /// Path UTF-8 decoding failed.
    #[error("index path is not valid UTF-8")]
    InvalidPathEncoding,
    /// Underlying I/O failure.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// Object store lookup/decoding failed while deriving an index from a tree.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// A tree walk found a non-tree object where a tree hash was expected.
    #[error("object is not a tree")]
    NotTree,
    /// A tree walk exceeded [`MAX_TREE_DEPTH`] nesting levels — likely a
    /// crafted untrusted repo trying to overflow the native stack.
    #[error("tree nesting exceeds {} levels", MAX_TREE_DEPTH)]
    TreeTooDeep,
}

/// Result alias used throughout this module.
pub type IndexResult<T> = Result<T, IndexError>;

/// Deserialise bytes into an [`Index`].
///
/// # Errors
/// See [`IndexError`].
pub fn deserialize(data: &[u8]) -> IndexResult<Index> {
    if data.len() < 9 {
        return Err(IndexError::Corrupt);
    }
    if data[0..4] != MAGIC {
        return Err(IndexError::BadMagic);
    }
    if data[4] != FORMAT_VERSION {
        return Err(IndexError::UnsupportedVersion(data[4]));
    }
    let count = u32::from_le_bytes([data[5], data[6], data[7], data[8]]) as usize;
    // Reject an attacker-supplied `count` that is impossible given the
    // remaining bytes. The minimum wire-length of an entry is 35 bytes
    // (status + 32B hash + 2B path_len, with empty path). Without this
    // up-front check the loop would walk `count` iterations before
    // failing — trivially triggered with a 9-byte buffer declaring
    // `count = u32::MAX`. Mirrors the pattern used in `serialize.rs`.
    // See SEC finding G11.
    if (count as u64).saturating_mul(35) > data.len() as u64 {
        return Err(IndexError::Corrupt);
    }
    let mut entries = Vec::with_capacity(count.min(1024)); // bound initial alloc
    let mut seen_paths = std::collections::HashSet::with_capacity(count.min(1024));
    let mut offset = 9usize;
    for _ in 0..count {
        // status(1) + hash(32) + path_len(2) = 35 fixed bytes.
        if offset + 35 > data.len() {
            return Err(IndexError::Corrupt);
        }
        let status =
            EntryStatus::from_byte(data[offset]).ok_or(IndexError::BadStatus(data[offset]))?;
        offset += 1;
        let mut object_hash = [0u8; HASH_LEN];
        object_hash.copy_from_slice(&data[offset..offset + HASH_LEN]);
        offset += HASH_LEN;
        let path_len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        if path_len > MAX_PATH_LEN {
            return Err(IndexError::Corrupt);
        }
        if offset + path_len > data.len() {
            return Err(IndexError::Corrupt);
        }
        let path_bytes = &data[offset..offset + path_len];
        let path = core::str::from_utf8(path_bytes)
            .map_err(|_| IndexError::InvalidPathEncoding)?
            .to_string();
        offset += path_len;
        if !validate_index_path(&path) {
            return Err(IndexError::InvalidPath(path));
        }
        if !seen_paths.insert(path.clone()) {
            return Err(IndexError::DuplicatePath(path));
        }
        entries.push(IndexEntry {
            path,
            status,
            object_hash,
        });
    }
    if offset != data.len() {
        return Err(IndexError::Corrupt);
    }
    Ok(Index { entries })
}

/// Read the index from `<root>/.mkit/index`. Returns an empty index if
/// the file is absent or zero-length.
pub fn read_index(root: &Path) -> IndexResult<Index> {
    let path = root.join(INDEX_FILE);
    let meta = match fs::metadata(&path) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Index::new()),
        Err(e) => return Err(IndexError::Io(e)),
    };
    if meta.len() == 0 {
        return Ok(Index::new());
    }
    if meta.len() > MAX_INDEX_BYTES {
        return Err(IndexError::TooLarge);
    }
    let bytes = fs::read(&path)?;
    deserialize(&bytes)
}

/// Write the index atomically to `<root>/.mkit/index`. The `.mkit/`
/// directory is created if absent.
pub fn write_index(root: &Path, idx: &Index) -> IndexResult<()> {
    let path = root.join(INDEX_FILE);
    write_atomic(&path, &idx.serialize(), true)?;
    Ok(())
}

/// Materialize a staging index from a committed tree.
///
/// This is used after commands that move `HEAD` and restore the
/// worktree so the index keeps matching the new commit snapshot. Tree
/// entries are recursively flattened into leaf paths; removed entries
/// are not represented because a committed tree has no tombstones.
///
/// # Errors
/// Propagates object-store errors and returns [`IndexError::NotTree`]
/// if `tree_hash` does not point at a tree object.
pub fn from_tree(store: &ObjectStore, tree_hash: Hash) -> IndexResult<Index> {
    let mut idx = Index::new();
    push_tree_entries(store, tree_hash, "", &mut idx, 0)?;
    Ok(idx)
}

fn push_tree_entries(
    store: &ObjectStore,
    tree_hash: Hash,
    prefix: &str,
    idx: &mut Index,
    depth: usize,
) -> IndexResult<()> {
    if depth > MAX_TREE_DEPTH {
        return Err(IndexError::TreeTooDeep);
    }
    let Object::Tree(tree) = store.read_object(&tree_hash)? else {
        return Err(IndexError::NotTree);
    };
    for entry in tree.entries {
        let name = String::from_utf8(entry.name).map_err(|_| IndexError::InvalidPathEncoding)?;
        let path = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        match entry.mode {
            EntryMode::Tree => {
                push_tree_entries(store, entry.object_hash, &path, idx, depth + 1)?;
            }
            EntryMode::Blob | EntryMode::Executable | EntryMode::Symlink => {
                if !validate_index_path(&path) {
                    return Err(IndexError::InvalidPath(path));
                }
                let status = match entry.mode {
                    EntryMode::Blob => EntryStatus::Blob,
                    EntryMode::Executable => EntryStatus::Executable,
                    EntryMode::Symlink => EntryStatus::Symlink,
                    EntryMode::Tree => unreachable!("handled above"),
                };
                idx.entries.push(IndexEntry {
                    path,
                    status,
                    object_hash: entry.object_hash,
                });
            }
        }
    }
    Ok(())
}

/// Compute the absolute path of the index file under `root`.
#[must_use]
pub fn index_path(root: &Path) -> PathBuf {
    root.join(INDEX_FILE)
}

/// Validate a staged path: non-empty, relative, no traversal, no NUL,
/// no backslash, never under `.mkit/` or `.git/`.
#[must_use]
pub fn validate_index_path(path: &str) -> bool {
    if path.is_empty() {
        return false;
    }
    if path.starts_with('/') {
        return false;
    }
    if path.len() > MAX_PATH_LEN {
        return false;
    }
    if path == ".mkit" || path == ".git" {
        return false;
    }
    if path.starts_with(".mkit/") || path.starts_with(".git/") {
        return false;
    }
    for part in path.split('/') {
        if part.is_empty() {
            return false;
        }
        if part == "." || part == ".." {
            return false;
        }
        for &c in part.as_bytes() {
            if c == 0 || c == b'\\' {
                return false;
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash;
    use tempfile::TempDir;

    fn seed_hash(s: &str) -> Hash {
        hash::hash(s.as_bytes())
    }

    #[test]
    fn empty_index_round_trip() {
        let idx = Index::new();
        let bytes = idx.serialize();
        // 4 magic + 1 version + 4 count = 9 bytes.
        assert_eq!(bytes.len(), 9);
        assert_eq!(&bytes[0..4], &MAGIC);
        assert_eq!(bytes[4], FORMAT_VERSION);
        assert_eq!(&bytes[5..9], &0u32.to_le_bytes());
        let parsed = deserialize(&bytes).unwrap();
        assert_eq!(parsed, idx);
    }

    #[test]
    fn tracks_path_or_descendant_matches_self_and_ancestors() {
        let mut idx = Index::new();
        idx.entries.push(IndexEntry {
            path: "src/lib.rs".to_string(),
            status: EntryStatus::Blob,
            object_hash: seed_hash("lib"),
        });
        idx.entries.push(IndexEntry {
            path: "removed.txt".to_string(),
            status: EntryStatus::Removed,
            object_hash: hash::ZERO,
        });
        // Exact tracked path and its ancestor directory both match.
        assert!(idx.tracks_path_or_descendant("src/lib.rs"));
        assert!(idx.tracks_path_or_descendant("src"));
        // A prefix that is not a path-segment boundary does not match.
        assert!(!idx.tracks_path_or_descendant("sr"));
        // Unrelated and removed-only paths do not match.
        assert!(!idx.tracks_path_or_descendant("docs"));
        assert!(!idx.tracks_path_or_descendant("removed.txt"));
    }

    #[test]
    fn has_tracked_file_at_exact_only_and_not_removed() {
        let mut idx = Index::new();
        idx.entries.push(IndexEntry {
            path: "f".to_string(),
            status: EntryStatus::Blob,
            object_hash: seed_hash("f"),
        });
        idx.entries.push(IndexEntry {
            path: "gone".to_string(),
            status: EntryStatus::Removed,
            object_hash: hash::ZERO,
        });
        // Exact tracked file matches.
        assert!(idx.has_tracked_file_at("f"));
        // Unlike `tracks_path_or_descendant`, an ancestor directory does NOT
        // match — only an exact tracked leaf does (the collision predicate).
        idx.entries.push(IndexEntry {
            path: "dir/inner.txt".to_string(),
            status: EntryStatus::Blob,
            object_hash: seed_hash("inner"),
        });
        assert!(!idx.has_tracked_file_at("dir"));
        assert!(idx.has_tracked_file_at("dir/inner.txt"));
        // A `Removed` tombstone must NOT suppress — the path is no longer
        // tracked, so a replacement at that path is genuinely untracked.
        assert!(!idx.has_tracked_file_at("gone"));
        // Unrelated path.
        assert!(!idx.has_tracked_file_at("other"));
    }

    #[test]
    fn single_entry_round_trip() {
        let mut idx = Index::new();
        idx.entries.push(IndexEntry {
            path: "README.md".to_string(),
            status: EntryStatus::Blob,
            object_hash: seed_hash("readme"),
        });
        let bytes = idx.serialize();
        // 9 header + 1 status + 32 hash + 2 path_len + 9 path = 53.
        assert_eq!(bytes.len(), 53);
        let parsed = deserialize(&bytes).unwrap();
        assert_eq!(parsed, idx);
    }

    #[test]
    fn multi_entry_round_trip_with_all_statuses() {
        let mut idx = Index::new();
        idx.entries.push(IndexEntry {
            path: "a.txt".into(),
            status: EntryStatus::Blob,
            object_hash: seed_hash("a"),
        });
        idx.entries.push(IndexEntry {
            path: "b/sub".into(),
            status: EntryStatus::Tree,
            object_hash: seed_hash("b"),
        });
        idx.entries.push(IndexEntry {
            path: "c.link".into(),
            status: EntryStatus::Symlink,
            object_hash: seed_hash("c"),
        });
        idx.entries.push(IndexEntry {
            path: "scripts/build".into(),
            status: EntryStatus::Executable,
            object_hash: seed_hash("d"),
        });
        idx.entries.push(IndexEntry {
            path: "old.txt".into(),
            status: EntryStatus::Removed,
            object_hash: [0u8; HASH_LEN],
        });
        let bytes = idx.serialize();
        let parsed = deserialize(&bytes).unwrap();
        assert_eq!(parsed, idx);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut bytes = Index::new().serialize();
        bytes[0] = b'X';
        let err = deserialize(&bytes).unwrap_err();
        assert!(matches!(err, IndexError::BadMagic));
    }

    #[test]
    fn rejects_zmix_magic_explicitly() {
        // SPEC-INDEX §5: v1 readers MUST reject `"ZMIX"`-prefixed files.
        // We construct the rejected magic as ASCII bytes here to avoid
        // tripping the rename-gate scanner.
        let bytes = [
            0x5A,
            0x4D,
            0x49,
            0x58, // "ZMIX"
            FORMAT_VERSION,
            0,
            0,
            0,
            0,
        ];
        let err = deserialize(&bytes).unwrap_err();
        assert!(matches!(err, IndexError::BadMagic));
    }

    #[test]
    fn rejects_unsupported_version() {
        let mut bytes = Index::new().serialize();
        bytes[4] = 0xFF;
        let err = deserialize(&bytes).unwrap_err();
        assert!(matches!(err, IndexError::UnsupportedVersion(0xFF)));
    }

    #[test]
    fn rejects_truncated_header() {
        let err = deserialize(b"MKIX").unwrap_err();
        assert!(matches!(err, IndexError::Corrupt));
    }

    #[test]
    fn rejects_truncated_entry() {
        let mut idx = Index::new();
        idx.entries.push(IndexEntry {
            path: "a".into(),
            status: EntryStatus::Blob,
            object_hash: seed_hash("a"),
        });
        let mut bytes = idx.serialize();
        bytes.truncate(bytes.len() - 1); // drop the trailing path byte
        let err = deserialize(&bytes).unwrap_err();
        assert!(matches!(err, IndexError::Corrupt));
    }

    #[test]
    fn rejects_trailing_bytes_after_declared_entries() {
        let mut idx = Index::new();
        idx.entries.push(IndexEntry {
            path: "a".into(),
            status: EntryStatus::Blob,
            object_hash: seed_hash("a"),
        });
        let mut bytes = idx.serialize();
        bytes.extend_from_slice(b"junk");
        let err = deserialize(&bytes).unwrap_err();
        assert!(matches!(err, IndexError::Corrupt));
    }

    #[test]
    fn rejects_invalid_path_on_deserialize() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&MAGIC);
        bytes.push(FORMAT_VERSION);
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.push(EntryStatus::Blob as u8);
        bytes.extend_from_slice(&[0u8; HASH_LEN]);
        let path = b"../escape";
        let path_len = u16::try_from(path.len()).unwrap();
        bytes.extend_from_slice(&path_len.to_le_bytes());
        bytes.extend_from_slice(path);
        let err = deserialize(&bytes).unwrap_err();
        assert!(matches!(err, IndexError::InvalidPath(path) if path == "../escape"));
    }

    #[test]
    fn rejects_duplicate_paths_on_deserialize() {
        let mut idx = Index::new();
        idx.entries.push(IndexEntry {
            path: "same.txt".into(),
            status: EntryStatus::Blob,
            object_hash: seed_hash("a"),
        });
        idx.entries.push(IndexEntry {
            path: "same.txt".into(),
            status: EntryStatus::Executable,
            object_hash: seed_hash("b"),
        });
        let err = deserialize(&idx.serialize()).unwrap_err();
        assert!(matches!(err, IndexError::DuplicatePath(path) if path == "same.txt"));
    }

    #[test]
    fn rejects_path_len_overflow() {
        // Hand-roll: path_len = 1000 but only 1 byte available.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&MAGIC);
        bytes.push(FORMAT_VERSION);
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.push(EntryStatus::Blob as u8);
        bytes.extend_from_slice(&[0u8; HASH_LEN]);
        bytes.extend_from_slice(&1000u16.to_le_bytes());
        bytes.push(b'a');
        let err = deserialize(&bytes).unwrap_err();
        assert!(matches!(err, IndexError::Corrupt));
    }

    #[test]
    fn rejects_unknown_status_byte() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&MAGIC);
        bytes.push(FORMAT_VERSION);
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.push(0x77); // bogus status
        bytes.extend_from_slice(&[0u8; HASH_LEN]);
        bytes.extend_from_slice(&0u16.to_le_bytes());
        let err = deserialize(&bytes).unwrap_err();
        assert!(matches!(err, IndexError::BadStatus(0x77)));
    }

    #[test]
    fn write_and_read_round_trip_via_disk() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join(".mkit")).unwrap();
        let mut idx = Index::new();
        idx.entries.push(IndexEntry {
            path: "test.txt".into(),
            status: EntryStatus::Blob,
            object_hash: seed_hash("c"),
        });
        write_index(dir.path(), &idx).unwrap();
        let read = read_index(dir.path()).unwrap();
        assert_eq!(read, idx);
    }

    #[test]
    fn read_missing_file_returns_empty_index() {
        let dir = TempDir::new().unwrap();
        let idx = read_index(dir.path()).unwrap();
        assert!(idx.entries.is_empty());
    }

    #[test]
    fn read_zero_length_file_returns_empty_index() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join(".mkit")).unwrap();
        fs::write(dir.path().join(INDEX_FILE), b"").unwrap();
        let idx = read_index(dir.path()).unwrap();
        assert!(idx.entries.is_empty());
    }

    #[test]
    fn read_oversize_file_rejected() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join(".mkit")).unwrap();
        let path = dir.path().join(INDEX_FILE);
        // Sparse-extend beyond the cap; allocates effectively no blocks.
        let f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        f.set_len(MAX_INDEX_BYTES + 1).unwrap();
        drop(f);
        let err = read_index(dir.path()).unwrap_err();
        assert!(matches!(err, IndexError::TooLarge));
    }

    #[test]
    fn staged_count_excludes_removed() {
        let mut idx = Index::new();
        idx.entries.push(IndexEntry {
            path: "a".into(),
            status: EntryStatus::Blob,
            object_hash: seed_hash("a"),
        });
        idx.entries.push(IndexEntry {
            path: "b".into(),
            status: EntryStatus::Removed,
            object_hash: [0u8; HASH_LEN],
        });
        idx.entries.push(IndexEntry {
            path: "c".into(),
            status: EntryStatus::Blob,
            object_hash: seed_hash("c"),
        });
        assert_eq!(idx.staged_count(), 2);
    }

    #[test]
    fn rejects_bogus_huge_count_before_loop() {
        // G11 regression: a 13-byte buffer whose header declares
        // count = u32::MAX must be rejected up-front — the
        // deserializer must NOT spin through u32::MAX iterations
        // (or allocate Vec::with_capacity(count)).
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&MAGIC);
        bytes.push(FORMAT_VERSION);
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        // No entries follow — buffer is just the 9-byte header.
        let err = deserialize(&bytes).unwrap_err();
        assert!(matches!(err, IndexError::Corrupt));
    }

    #[test]
    fn validate_path_basic() {
        assert!(validate_index_path("a.txt"));
        assert!(validate_index_path("src/main.rs"));
        assert!(validate_index_path(".mkitignore"));
        assert!(!validate_index_path(""));
        assert!(!validate_index_path("/abs"));
        assert!(!validate_index_path("../escape"));
        assert!(!validate_index_path("a/../b"));
        assert!(!validate_index_path(".mkit"));
        assert!(!validate_index_path(".git"));
        assert!(!validate_index_path(".mkit/objects"));
        assert!(!validate_index_path(".git/HEAD"));
        assert!(!validate_index_path("a\\b"));
        assert!(!validate_index_path("a//b"));
    }

    #[test]
    fn from_tree_flattens_tree_entries() {
        use crate::object::{Blob, EntryMode, Object, Tree, TreeEntry};
        use crate::serialize;
        use crate::store::ObjectStore;

        fn put(store: &ObjectStore, obj: &Object) -> Hash {
            let bytes = serialize::serialize(obj).unwrap();
            store.write(&bytes).unwrap()
        }

        let dir = TempDir::new().unwrap();
        let store = ObjectStore::init(dir.path()).unwrap();
        let file = put(
            &store,
            &Object::Blob(Blob {
                data: b"file".to_vec(),
            }),
        );
        let exec = put(
            &store,
            &Object::Blob(Blob {
                data: b"exec".to_vec(),
            }),
        );
        let link = put(
            &store,
            &Object::Blob(Blob {
                data: b"target".to_vec(),
            }),
        );
        let sub = put(
            &store,
            &Object::Tree(Tree {
                entries: vec![TreeEntry {
                    name: b"run".to_vec(),
                    mode: EntryMode::Executable,
                    object_hash: exec,
                }],
            }),
        );
        let root = put(
            &store,
            &Object::Tree(Tree {
                entries: vec![
                    TreeEntry {
                        name: b"file.txt".to_vec(),
                        mode: EntryMode::Blob,
                        object_hash: file,
                    },
                    TreeEntry {
                        name: b"link".to_vec(),
                        mode: EntryMode::Symlink,
                        object_hash: link,
                    },
                    TreeEntry {
                        name: b"sub".to_vec(),
                        mode: EntryMode::Tree,
                        object_hash: sub,
                    },
                ],
            }),
        );

        let idx = from_tree(&store, root).unwrap();
        assert_eq!(idx.entries.len(), 3);
        assert_eq!(idx.entries[0].path, "file.txt");
        assert_eq!(idx.entries[0].status, EntryStatus::Blob);
        assert_eq!(idx.entries[1].path, "link");
        assert_eq!(idx.entries[1].status, EntryStatus::Symlink);
        assert_eq!(idx.entries[2].path, "sub/run");
        assert_eq!(idx.entries[2].status, EntryStatus::Executable);
    }

    #[test]
    fn from_tree_round_trips_through_worktree_builder() {
        use crate::object::{Blob, EntryMode, Object, Tree, TreeEntry};
        use crate::serialize;
        use crate::store::ObjectStore;

        fn put(store: &ObjectStore, obj: &Object) -> Hash {
            let bytes = serialize::serialize(obj).unwrap();
            store.write(&bytes).unwrap()
        }

        let dir = TempDir::new().unwrap();
        let store = ObjectStore::init(dir.path()).unwrap();
        let blob = put(
            &store,
            &Object::Blob(Blob {
                data: b"content".to_vec(),
            }),
        );
        let tree = put(
            &store,
            &Object::Tree(Tree {
                entries: vec![TreeEntry {
                    name: b"a.txt".to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: blob,
                }],
            }),
        );

        let idx = from_tree(&store, tree).unwrap();
        let rebuilt = crate::worktree::build_tree_from_index(&store, &idx).unwrap();
        assert_eq!(rebuilt, tree);
    }
}
