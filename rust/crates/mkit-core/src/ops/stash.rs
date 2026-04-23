//! Stash — port of `src/stash.zig`.
//!
//! On-disk format (`<repo_root>/.mkit/stash`) is a tagged binary
//! manifest:
//!
//! ```text
//! magic   : 4   bytes  "MKST"
//! count   : u32 LE
//! entries : count *
//!     commit_hash  : 32 bytes
//!     parent_hash  : 32 bytes
//!     timestamp    : u32 LE (Unix seconds, saturating)
//!     msg_len      : u16 LE
//!     message      : msg_len bytes
//! ```
//!
//! New stashes are prepended (LIFO).
//!
//! ### Deviation from Zig
//!
//! `show()` in the Zig original returns a `diff::DiffResult` that
//! requires the diff/graph subsystem (sibling-track OPS1). This Rust
//! port omits `show()` for the moment; the on-disk manifest is
//! identical so it can be added later without a format change. Tests
//! that exercised `show()` are dropped from this port; everything else
//! mirrors the Zig coverage.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::atomic;
use crate::hash::{Hash, ZERO};
use crate::index::{self, Index};
use crate::object::{Commit, Identity, Object};
use crate::ops::restore::{self, RestoreOptions};
use crate::refs;
use crate::serialize;
use crate::store::{MKIT_DIR, ObjectStore};
use crate::worktree;

/// Magic bytes for the stash manifest: `MKST` ("`MKit` `STash`").
pub const MAGIC: [u8; 4] = *b"MKST";

/// Stash manifest path under the repo root.
pub const STASH_FILE: &str = ".mkit/stash";

/// Hard cap on manifest size (16 MiB).
pub const MAX_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;

/// Maximum stash message length (`u16` on the wire).
pub const MAX_MESSAGE_LEN: usize = u16::MAX as usize;

/// One entry in the stash stack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StashEntry {
    pub commit_hash: Hash,
    pub parent_hash: Hash,
    pub timestamp: u32,
    pub message: String,
}

/// The full stash stack (newest first).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StashList {
    pub entries: Vec<StashEntry>,
}

/// Errors raised by this module.
#[derive(Debug, thiserror::Error)]
pub enum StashError {
    #[error("stash index {0} is out of range")]
    IndexOutOfRange(usize),
    #[error("stash manifest exceeds the {MAX_MANIFEST_BYTES}-byte limit")]
    ManifestTooLarge,
    #[error("stash manifest format is invalid")]
    InvalidFormat,
    #[error("stash message exceeds {MAX_MESSAGE_LEN} bytes")]
    MessageTooLong,
    #[error("stash commit object is not a Commit")]
    NotACommit,
    #[error(transparent)]
    Object(#[from] crate::object::MkitError),
    #[error(transparent)]
    Store(#[from] crate::store::StoreError),
    #[error(transparent)]
    Refs(#[from] crate::refs::RefError),
    #[error(transparent)]
    Index(#[from] crate::index::IndexError),
    #[error(transparent)]
    Worktree(#[from] crate::worktree::WorktreeError),
    #[error(transparent)]
    Restore(#[from] crate::ops::restore::RestoreError),
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Result alias.
pub type StashResult<T> = Result<T, StashError>;

/// Save the worktree as a stash entry, then reset the worktree to
/// HEAD. Mirrors `src/stash.zig::save` exactly:
///
/// 1. Build a tree from `repo_root` (skipping `.mkit/`).
/// 2. Resolve HEAD to a parent (or none for first commit).
/// 3. Create an unsigned `Commit` over that tree with `Ed25519` zero
///    pubkey author and zeroed signer/signature.
/// 4. Prepend a new [`StashEntry`] to the manifest.
/// 5. Restore the worktree to HEAD's tree.
/// 6. Truncate the index.
pub fn save(store: &ObjectStore, repo_root: &Path, message: &str) -> StashResult<()> {
    if message.len() > MAX_MESSAGE_LEN {
        return Err(StashError::MessageTooLong);
    }
    let mkit_dir = repo_root.join(MKIT_DIR);

    let tree_hash = worktree::build_tree(store, repo_root)?;
    let head_hash = refs::resolve_head(&mkit_dir)?;

    let timestamp_u64 = unix_seconds_now();
    let parents = head_hash.into_iter().collect::<Vec<_>>();
    let zero_pk = [0u8; 32];
    let commit = Object::Commit(Commit::new_unannotated(
        tree_hash,
        parents,
        Identity::ed25519(zero_pk),
        [0u8; 32],
        message.as_bytes().to_vec(),
        timestamp_u64,
        [0u8; 64],
    ));
    let commit_bytes = serialize::serialize(&commit)?;
    let stash_hash = store.write(&commit_bytes)?;

    // Prepend the new entry.
    let mut list = read_list(repo_root)?;
    let ts_u32: u32 = timestamp_u64.try_into().unwrap_or(u32::MAX);
    let new_entry = StashEntry {
        commit_hash: stash_hash,
        parent_hash: head_hash.unwrap_or(ZERO),
        timestamp: ts_u32,
        message: message.to_string(),
    };
    list.entries.insert(0, new_entry);
    write_list(repo_root, &list)?;

    // Restore the worktree to HEAD's tree (if any).
    if let Some(hh) = head_hash {
        let head_obj = store.read_object(&hh)?;
        if let Object::Commit(c) = head_obj {
            restore::restore_tree(store, c.tree_hash, repo_root, &RestoreOptions::default())?;
        }
    }

    // Clear the index.
    let _ = index::write_index(repo_root, &Index::new());
    Ok(())
}

/// List all stashes (newest first).
///
/// # Errors
/// - [`StashError::ManifestTooLarge`] / [`StashError::InvalidFormat`]
///   for a corrupt or oversized manifest.
pub fn list(repo_root: &Path) -> StashResult<StashList> {
    read_list(repo_root)
}

/// Pop a stash: restore its tree into the worktree and remove the
/// entry. Index 0 = newest.
///
/// # Errors
/// - [`StashError::IndexOutOfRange`] if `index` is past the end.
pub fn pop(store: &ObjectStore, repo_root: &Path, idx: usize) -> StashResult<()> {
    let mut list = read_list(repo_root)?;
    if idx >= list.entries.len() {
        return Err(StashError::IndexOutOfRange(idx));
    }
    let entry = list.entries[idx].clone();
    let obj = store.read_object(&entry.commit_hash)?;
    let Object::Commit(commit) = obj else {
        return Err(StashError::NotACommit);
    };
    restore::restore_tree(
        store,
        commit.tree_hash,
        repo_root,
        &RestoreOptions::default(),
    )?;
    list.entries.remove(idx);
    write_list(repo_root, &list)?;
    Ok(())
}

/// Drop a stash without applying it.
///
/// # Errors
/// - [`StashError::IndexOutOfRange`] if `index` is past the end.
pub fn drop(repo_root: &Path, idx: usize) -> StashResult<()> {
    let mut list = read_list(repo_root)?;
    if idx >= list.entries.len() {
        return Err(StashError::IndexOutOfRange(idx));
    }
    list.entries.remove(idx);
    write_list(repo_root, &list)?;
    Ok(())
}

// -- Manifest IO -------------------------------------------------------------

fn stash_path(repo_root: &Path) -> PathBuf {
    repo_root.join(STASH_FILE)
}

fn read_list(repo_root: &Path) -> StashResult<StashList> {
    let path = stash_path(repo_root);
    let meta = match fs::metadata(&path) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(StashList::default()),
        Err(e) => return Err(StashError::Io(e)),
    };
    if meta.len() == 0 {
        return Ok(StashList::default());
    }
    if meta.len() > MAX_MANIFEST_BYTES {
        return Err(StashError::ManifestTooLarge);
    }
    let data = fs::read(&path)?;
    deserialize_list(&data)
}

fn write_list(repo_root: &Path, list: &StashList) -> StashResult<()> {
    let bytes = serialize_list(list)?;
    let path = stash_path(repo_root);
    atomic::write_atomic(&path, &bytes, true)?;
    Ok(())
}

/// Encode a [`StashList`] as the on-disk manifest. Public for goldens.
///
/// # Errors
/// - [`StashError::MessageTooLong`] if any entry message exceeds [`MAX_MESSAGE_LEN`].
pub fn serialize_list(list: &StashList) -> StashResult<Vec<u8>> {
    let mut total = 4 + 4;
    for e in &list.entries {
        if e.message.len() > MAX_MESSAGE_LEN {
            return Err(StashError::MessageTooLong);
        }
        total += 32 + 32 + 4 + 2 + e.message.len();
    }
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(
        &u32::try_from(list.entries.len())
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
    for e in &list.entries {
        out.extend_from_slice(&e.commit_hash);
        out.extend_from_slice(&e.parent_hash);
        out.extend_from_slice(&e.timestamp.to_le_bytes());
        let len_u16 = u16::try_from(e.message.len()).map_err(|_| StashError::MessageTooLong)?;
        out.extend_from_slice(&len_u16.to_le_bytes());
        out.extend_from_slice(e.message.as_bytes());
    }
    Ok(out)
}

/// Decode the on-disk manifest. Public for goldens.
///
/// # Errors
/// - [`StashError::InvalidFormat`] if the bytes are malformed.
///
/// # Panics
/// Panics only on internal invariant violation: each `try_into` on a
/// 4-byte / 2-byte slice we just bounds-checked cannot fail.
pub fn deserialize_list(data: &[u8]) -> StashResult<StashList> {
    if data.len() < 8 {
        return Err(StashError::InvalidFormat);
    }
    if &data[..4] != MAGIC.as_slice() {
        return Err(StashError::InvalidFormat);
    }
    let count = u32::from_le_bytes(data[4..8].try_into().unwrap()) as usize;
    let mut entries = Vec::with_capacity(count);
    let mut pos = 8usize;
    for _ in 0..count {
        if pos + 32 + 32 + 4 + 2 > data.len() {
            return Err(StashError::InvalidFormat);
        }
        let mut commit_hash = [0u8; 32];
        commit_hash.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;
        let mut parent_hash = [0u8; 32];
        parent_hash.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;
        let timestamp = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        pos += 4;
        let msg_len = u16::from_le_bytes(data[pos..pos + 2].try_into().unwrap()) as usize;
        pos += 2;
        if pos + msg_len > data.len() {
            return Err(StashError::InvalidFormat);
        }
        let msg = String::from_utf8(data[pos..pos + msg_len].to_vec())
            .map_err(|_| StashError::InvalidFormat)?;
        pos += msg_len;
        entries.push(StashEntry {
            commit_hash,
            parent_hash,
            timestamp,
            message: msg,
        });
    }
    Ok(StashList { entries })
}

fn unix_seconds_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash;

    #[test]
    fn manifest_roundtrip_two_entries() {
        let list = StashList {
            entries: vec![
                StashEntry {
                    commit_hash: hash::hash(b"commit1"),
                    parent_hash: hash::hash(b"parent1"),
                    timestamp: 1000,
                    message: "first stash".to_string(),
                },
                StashEntry {
                    commit_hash: hash::hash(b"commit2"),
                    parent_hash: ZERO,
                    timestamp: 2000,
                    message: "second stash".to_string(),
                },
            ],
        };
        let bytes = serialize_list(&list).unwrap();
        let back = deserialize_list(&bytes).unwrap();
        assert_eq!(back, list);
    }

    #[test]
    fn deserialize_rejects_short_data() {
        assert!(matches!(
            deserialize_list(&[0u8; 4]),
            Err(StashError::InvalidFormat)
        ));
    }

    #[test]
    fn deserialize_rejects_bad_magic() {
        assert!(matches!(
            deserialize_list(&[b'X', b'Y', b'Z', b'W', 0, 0, 0, 0]),
            Err(StashError::InvalidFormat)
        ));
    }
}
