//! Stash.
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

use std::fmt::Write as _;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::atomic;
use crate::hash::{Hash, ZERO};
use crate::index::{self, Index};
use crate::object::{Commit, Identity, Object};
use crate::ops::diff::{DiffKind, DiffResult, diff_trees};
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

/// Minimum on-wire entry size, used to sanity-check attacker-supplied
/// `count` up-front during deserialise (SEC finding G12). Layout:
/// `commit_hash` (32) + `parent_hash` (32) + `timestamp` (4) +
/// `msg_len` (2) + message (0).
const MIN_ENTRY_BYTES: u64 = 32 + 32 + 4 + 2;

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
    Diff(#[from] crate::store::StoreError),
    #[error(transparent)]
    Object(#[from] crate::object::MkitError),
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
/// HEAD:
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

    // One durability batch over the worktree snapshot + stash commit,
    // committed before the manifest write that references them.
    let batch = store.batch();
    let tree_hash = worktree::build_tree(&batch, repo_root)?;
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
    let stash_hash = batch.write(&commit_bytes)?;
    batch.commit()?;

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

/// Resolve the tree hash recorded by stash entry `idx` (newest = 0)
/// without mutating anything. Callers use this to run a restore-safety
/// pre-flight (the #176 guard) over the stash tree before [`pop`].
///
/// # Errors
/// - [`StashError::IndexOutOfRange`] if `idx` is past the end.
/// - [`StashError::NotACommit`] if the stored object is not a Commit.
pub fn entry_tree_hash(store: &ObjectStore, repo_root: &Path, idx: usize) -> StashResult<Hash> {
    let list = read_list(repo_root)?;
    if idx >= list.entries.len() {
        return Err(StashError::IndexOutOfRange(idx));
    }
    let obj = store.read_object(&list.entries[idx].commit_hash)?;
    let Object::Commit(commit) = obj else {
        return Err(StashError::NotACommit);
    };
    Ok(commit.tree_hash)
}

/// Pop a stash: restore its tree into the worktree and remove the
/// entry. Index 0 = newest.
///
/// # Safety against data loss
/// This restores **unconditionally** — it does not itself run the #176
/// destructive-restore guard, because that guard lives in the CLI layer
/// (`commands::ensure_restore_safe`). Callers that expose `pop` to users
/// **must** run [`entry_tree_hash`] + the guard first so uncommitted
/// edits on unrelated paths are never clobbered. The stash entry is
/// dropped only after a successful restore (restore failure short-
/// circuits via `?`, leaving the entry in place for a retry).
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

/// Apply a stash entry's tree to the worktree **without** removing the
/// entry. Index 0 = newest. This is the non-destructive complement to
/// [`pop`]: it leaves the stash stack untouched so the same entry can be
/// re-applied or popped later.
///
/// # Safety against data loss
/// Like [`pop`], this restores **unconditionally** — it does not run the
/// #176 destructive-restore guard itself. Callers exposing `apply` to
/// users **must** run [`entry_tree_hash`] + `ensure_restore_safe` first,
/// exactly as `pop` does, so uncommitted edits on unrelated paths are
/// never clobbered.
///
/// # Errors
/// - [`StashError::IndexOutOfRange`] if `idx` is past the end.
/// - [`StashError::NotACommit`] if the stored object is not a Commit.
pub fn apply(store: &ObjectStore, repo_root: &Path, idx: usize) -> StashResult<()> {
    let list = read_list(repo_root)?;
    if idx >= list.entries.len() {
        return Err(StashError::IndexOutOfRange(idx));
    }
    let entry = &list.entries[idx];
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
    Ok(())
}

/// Drop **all** stash entries, leaving an empty stack. Idempotent — a
/// missing or already-empty manifest is not an error.
///
/// # Errors
/// - [`StashError::Io`] if the manifest cannot be written.
pub fn clear(repo_root: &Path) -> StashResult<()> {
    write_list(repo_root, &StashList::default())
}

/// Render `stash show [<stash>]` output: header + unified-diff-style listing.
///
/// Output format:
/// ```text
/// stash@{<idx>}: <message>
/// Date: <unix-timestamp>
///
/// <A|M|D> <path>
/// ...
/// ```
///
/// # Errors
/// - [`StashError::IndexOutOfRange`] if `idx` is past the end.
/// - [`StashError::NotACommit`] if the stored object is not a Commit.
/// - Store/object errors if objects cannot be read.
pub fn render_stash_show(store: &ObjectStore, repo_root: &Path, idx: usize) -> StashResult<String> {
    let list = read_list(repo_root)?;
    if idx >= list.entries.len() {
        return Err(StashError::IndexOutOfRange(idx));
    }
    let entry = &list.entries[idx];

    // Load the stash commit to get its tree.
    let stash_obj = store.read_object(&entry.commit_hash)?;
    let Object::Commit(stash_commit) = stash_obj else {
        return Err(StashError::NotACommit);
    };

    // Resolve parent tree (None if parent is the zero hash or commit load fails).
    let parent_tree: Option<Hash> = if entry.parent_hash == ZERO {
        None
    } else {
        match store.read_object(&entry.parent_hash) {
            Ok(Object::Commit(parent_commit)) => Some(parent_commit.tree_hash),
            _ => None,
        }
    };

    let diff = diff_trees(store, parent_tree, Some(stash_commit.tree_hash))?;

    let mut out = String::new();
    let _ = writeln!(out, "stash@{{{idx}}}: {}", entry.message);
    let _ = writeln!(out, "Date: {}", entry.timestamp);
    let _ = writeln!(out);
    for e in &diff.entries {
        let tag = match e.kind {
            DiffKind::Added => "A",
            DiffKind::Removed => "D",
            DiffKind::Modified => "M",
            DiffKind::ModeChanged => "T",
        };
        let _ = writeln!(out, "{tag} {}", e.path);
    }
    Ok(out)
}

/// Show the diff for a stash entry (raw [`DiffResult`]).
///
/// # Errors
/// - [`StashError::IndexOutOfRange`] if `idx` is past the end.
/// - [`StashError::NotACommit`] if the stash commit object is not a Commit.
pub fn show_diff(store: &ObjectStore, repo_root: &Path, idx: usize) -> StashResult<DiffResult> {
    let list = read_list(repo_root)?;
    if idx >= list.entries.len() {
        return Err(StashError::IndexOutOfRange(idx));
    }
    let entry = &list.entries[idx];

    let stash_obj = store.read_object(&entry.commit_hash)?;
    let Object::Commit(stash_commit) = stash_obj else {
        return Err(StashError::NotACommit);
    };

    let parent_tree: Option<Hash> = if entry.parent_hash == ZERO {
        None
    } else {
        match store.read_object(&entry.parent_hash) {
            Ok(Object::Commit(parent_commit)) => Some(parent_commit.tree_hash),
            _ => None,
        }
    };

    Ok(diff_trees(
        store,
        parent_tree,
        Some(stash_commit.tree_hash),
    )?)
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

/// Write a [`StashList`] to disk. Public only for integration-test goldens.
///
/// # Panics
/// Panics if serialization or the write fails (test-only helper).
pub fn write_list_test_only(repo_root: &Path, list: &StashList) {
    write_list(repo_root, list).expect("write_list_test_only failed");
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
    // Reject an attacker-supplied `count` that cannot possibly fit in
    // the remaining body. With [`MIN_ENTRY_BYTES`] = 70 (empty message)
    // an 8-byte header declaring count = u32::MAX is rejected here
    // instead of driving `Vec::with_capacity(u32::MAX)`. See SEC
    // finding G12.
    if (count as u64).saturating_mul(MIN_ENTRY_BYTES) > data.len() as u64 {
        return Err(StashError::InvalidFormat);
    }
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
    use crate::object::{Blob, Commit, EntryMode, Identity, Object, Tree, TreeEntry};
    use crate::ops::diff::DiffKind;
    use crate::serialize;
    use crate::store::ObjectStore;
    use tempfile::TempDir;

    fn fresh_store() -> (TempDir, ObjectStore) {
        let dir = TempDir::new().unwrap();
        let store = ObjectStore::init(dir.path()).unwrap();
        (dir, store)
    }

    fn put_blob_data(store: &ObjectStore, data: &[u8]) -> Hash {
        let obj = Object::Blob(Blob {
            data: data.to_vec(),
        });
        store.write(&serialize::serialize(&obj).unwrap()).unwrap()
    }

    fn put_tree_entries(store: &ObjectStore, entries: Vec<TreeEntry>) -> Hash {
        let obj = Object::Tree(Tree { entries });
        store.write(&serialize::serialize(&obj).unwrap()).unwrap()
    }

    fn put_commit_obj(store: &ObjectStore, tree_h: Hash, parents: Vec<Hash>, ts: u64) -> Hash {
        let commit = Object::Commit(Commit::new_unannotated(
            tree_h,
            parents,
            Identity::ed25519([0u8; 32]),
            [0u8; 32],
            b"msg".to_vec(),
            ts,
            [0u8; 64],
        ));
        store
            .write(&serialize::serialize(&commit).unwrap())
            .unwrap()
    }

    /// Build a deterministic stash fixture: parent commit has `existing.txt`,
    /// stash commit adds `new.txt` and modifies `existing.txt`.
    fn build_stash_fixture(store: &ObjectStore, repo_root: &std::path::Path) {
        // Parent tree: one file "existing.txt"
        let blob_v1 = put_blob_data(store, b"original content");
        let parent_tree = put_tree_entries(
            store,
            vec![TreeEntry {
                name: b"existing.txt".to_vec(),
                mode: EntryMode::Blob,
                object_hash: blob_v1,
            }],
        );
        let parent_commit = put_commit_obj(store, parent_tree, vec![], 1_000_000);

        // Stash tree: existing.txt modified + new.txt added
        let blob_v2 = put_blob_data(store, b"modified content");
        let blob_new = put_blob_data(store, b"brand new file");
        let stash_tree = put_tree_entries(
            store,
            vec![
                TreeEntry {
                    name: b"existing.txt".to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: blob_v2,
                },
                TreeEntry {
                    name: b"new.txt".to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: blob_new,
                },
            ],
        );
        let stash_commit = put_commit_obj(store, stash_tree, vec![parent_commit], 1_000_001);

        let list = StashList {
            entries: vec![StashEntry {
                commit_hash: stash_commit,
                parent_hash: parent_commit,
                timestamp: 1_000_001_u32,
                message: "WIP: stash message".to_string(),
            }],
        };
        write_list(repo_root, &list).unwrap();
    }

    #[test]
    fn show_diff_returns_correct_entries() {
        let (tmp, store) = fresh_store();
        build_stash_fixture(&store, tmp.path());

        let diff = show_diff(&store, tmp.path(), 0).unwrap();
        assert_eq!(diff.entries.len(), 2, "expected 2 diff entries");

        let existing = diff.entries.iter().find(|e| e.path == "existing.txt");
        let new_f = diff.entries.iter().find(|e| e.path == "new.txt");
        assert!(existing.is_some(), "existing.txt must appear in diff");
        assert!(new_f.is_some(), "new.txt must appear in diff");
        assert_eq!(existing.unwrap().kind, DiffKind::Modified);
        assert_eq!(new_f.unwrap().kind, DiffKind::Added);
    }

    #[test]
    fn render_stash_show_header_and_entries() {
        let (tmp, store) = fresh_store();
        build_stash_fixture(&store, tmp.path());

        let output = render_stash_show(&store, tmp.path(), 0).unwrap();
        assert!(
            output.contains("stash@{0}:"),
            "missing stash header: {output}"
        );
        assert!(
            output.contains("WIP: stash message"),
            "missing message: {output}"
        );
        assert!(output.contains("Date:"), "missing date line: {output}");
        assert!(
            output.contains("M existing.txt"),
            "missing modified entry: {output}"
        );
        assert!(
            output.contains("A new.txt"),
            "missing added entry: {output}"
        );
    }

    #[test]
    fn apply_restores_tree_and_keeps_entry() {
        let (tmp, store) = fresh_store();
        build_stash_fixture(&store, tmp.path());
        assert_eq!(read_list(tmp.path()).unwrap().entries.len(), 1);

        apply(&store, tmp.path(), 0).unwrap();

        // The stash tree was materialised into the worktree.
        assert_eq!(
            fs::read(tmp.path().join("existing.txt")).unwrap(),
            b"modified content"
        );
        assert_eq!(
            fs::read(tmp.path().join("new.txt")).unwrap(),
            b"brand new file"
        );
        // ...and the entry is still on the stack (apply, not pop).
        assert_eq!(
            read_list(tmp.path()).unwrap().entries.len(),
            1,
            "apply must not drop the entry"
        );
    }

    #[test]
    fn apply_out_of_range_returns_error() {
        let (tmp, _store) = fresh_store();
        let store = ObjectStore::open(tmp.path()).unwrap();
        let err = apply(&store, tmp.path(), 0).unwrap_err();
        assert!(matches!(err, StashError::IndexOutOfRange(0)));
    }

    #[test]
    fn clear_empties_the_stack() {
        let (tmp, store) = fresh_store();
        build_stash_fixture(&store, tmp.path());
        assert_eq!(read_list(tmp.path()).unwrap().entries.len(), 1);

        clear(tmp.path()).unwrap();
        assert!(read_list(tmp.path()).unwrap().entries.is_empty());

        // Idempotent: clearing an already-empty stack is fine.
        clear(tmp.path()).unwrap();
        assert!(read_list(tmp.path()).unwrap().entries.is_empty());
    }

    #[test]
    fn show_diff_out_of_range_returns_error() {
        let (tmp, _store) = fresh_store();
        let store = ObjectStore::open(tmp.path()).unwrap();
        let err = show_diff(&store, tmp.path(), 0).unwrap_err();
        assert!(matches!(err, StashError::IndexOutOfRange(0)));
    }

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

    #[test]
    fn deserialize_rejects_bogus_huge_count() {
        // G12 regression: an 8-byte manifest whose header declares
        // count = u32::MAX must be rejected up-front — the decoder
        // must NOT call `Vec::with_capacity(u32::MAX)` nor loop that
        // many times.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC.as_slice());
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        // No entries follow.
        assert!(matches!(
            deserialize_list(&bytes),
            Err(StashError::InvalidFormat)
        ));
    }
}
